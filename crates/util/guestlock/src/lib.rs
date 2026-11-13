//! A lock Rust owns the state behind and a guest thread can be woken out of.
//!
//! `std::sync::Mutex` is not usable for anything a guest can block on. The only
//! interruptible wait in this kernel is `wait_for`, which records the sleeping
//! task's lock and condition variable so that delivering a signal can broadcast
//! them — a Rust condvar is invisible to that, and a guest asleep on one could
//! not be killed. And Rust cannot declare a `lock_t` either: its layout changes
//! with `LOCK_DEBUG`, so a mirrored definition would be a contract no compiler
//! checks.
//!
//! The primitive was `util/guestlock.c` until 2026-09-03, and the reason it
//! stayed there is in the paragraph above: Rust could not declare a `lock_t`
//! because the layout changes with `LOCK_DEBUG`. **Generating it is the answer
//! to that**, and it is the same answer `crates/util/waitfor` reached the same
//! day — a `#define` that changes a layout has to reach bindgen, and since
//! 2026-09-01 it does. What is left in C is `lock()`/`unlock()`, which are
//! macros, behind the `sync_*` shims every Rust caller of a `lock_t` uses.
//!
//! So this crate owns the whole thing now, and [`GuestLock<T>`] holds it by
//! value rather than through an opaque handle.
//!
//! **The `guest_lock_*` exports went on 2026-09-08.** They stayed because an
//! "embedder holds one of these across a call into the engine" -- and by then
//! no header declared them, no embedder-facing header ever took one as a
//! parameter, and `tests/integration/sbm_api_test.c` does not mention the name.
//! `util/guestlock.h` was the last declaration and its last reader was
//! `tests/unit/guestlock_test.c`, which is `tests/primitive.rs` now and calls
//! them as Rust. That is the thirtieth written-down blocker to turn out to be
//! about a tree that no longer exists; if ServerBox does hold one, the header
//! and the exports come back together and the example gains a case.
//!
//! `util/guestlock.h` declared the eight until 2026-09-08 and nothing included
//! it — the last reader was that test. **How many condition variables an object
//! carries is the caller's choice**, which is what `conds` is: a terminal takes
//! two, one for input produced and one for input consumed.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::ops::{Deref, DerefMut};
use core::time::Duration;

// The shared Rust types and constants are re-exported by kernel-taskview.
use util_synctypes as ffi;

/// A mutex and the condition variables that belong to it.
///
/// The C had a flexible array member — `cond_t cond[]` after the count — and
/// one `calloc` sized by hand. A boxed slice is the same allocation shape
/// without the arithmetic, and the addresses are what matter: a pthread object
/// may not move once initialised, and neither the `Box` nor its contents do.
/// `pub` with private fields since 2026-09-09, which is how Rust spells an
/// opaque handle. It was private and every entry point took a `*mut c_void`,
/// which is how *C* spells one — and that costs a `.cast()` in the body of each
/// and gives a caller nothing to get wrong loudly.
pub struct Primitive {
    lock: ffi::lock_t,
    conds: Box<[ffi::cond_t]>,
}

impl Primitive {
    /// Allocate a lock primitive with `conds` condition variables.
    pub fn new(conds: u32) -> Box<Primitive> {
        Box::new(Primitive {
            lock: ffi::lock_t::new(),
            conds: (0..conds).map(|_| ffi::cond_t::new()).collect(),
        })
    }

    /// One of this primitive's condition variables, or `None` for an index the
    /// guest made up.
    ///
    /// **It used to answer a `*mut ffi::cond_t`**, built out of `&self` with
    /// `c as *const _ as *mut _`, under a comment that said the object was
    /// "behind an `UnsafeCell`-shaped boundary *in practice*". It was not:
    /// `cond_t` held a plain `pthread_cond_t`, so `Primitive` was `Freeze` and
    /// rustc gave `&self` LLVM's `noalias readonly` while every method below
    /// wrote through it. `cond_t` and `lock_t` carry the `UnsafeCell` now and
    /// this is an ordinary borrow.
    fn cond(&self, i: u32) -> Option<&ffi::cond_t> {
        self.conds.get(i as usize)
    }

    /// Hold this primitive for a scope.
    ///
    /// A guard since 2026-10-01, where it was `acquire`, `try_acquire` and an
    /// `unsafe fn release` -- and an `unsafe fn wait` whose contract was "this
    /// thread holds it". Holding the guard is that contract, so the wait is a
    /// safe method of it.
    pub fn lock(&self) -> Held<'_> {
        Held { primitive: self, guard: locks::guard!(&self.lock) }
    }

    /// The same, without waiting. `None` means somebody else has it.
    pub fn try_lock(&self) -> Option<Held<'_>> {
        Some(Held { primitive: self, guard: locks::try_guard!(&self.lock)? })
    }

    /// Whether `other` is this primitive's own mutex — an identity question,
    /// which is why it is answered here rather than by handing the address out.
    fn is_my_lock(&self, other: &ffi::lock_t) -> bool {
        core::ptr::eq(&self.lock, other)
    }

    /// Wake all threads waiting on `cond`.
    pub fn notify(&self, cond: u32) {
        if let Some(c) = self.cond(cond) {
            waitfor::notify_all(c);
        }
    }
}

/// A [`Primitive`] held by this thread, released when dropped.
pub struct Held<'a> {
    primitive: &'a Primitive,
    guard: locks::mutex::Guard<'a>,
}

impl Held<'_> {
    /// Wait on a condition, releasing the primitive and taking it back.
    /// `EINVAL` for a condition the primitive does not have.
    pub fn wait(&mut self, cond: u32, timeout_ns: i64, ignore_signals: bool) -> c_int {
        let p = self.primitive;
        let Some(c) = p.cond(cond) else {
            return EINVAL;
        };
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let t = timeout_of(timeout_ns, &mut ts);
        if ignore_signals {
            waitfor::wait_for_ignore_signals(c, &self.guard, t)
        } else {
            waitfor::wait_for(c, &self.guard, t)
        }
    }

    pub fn notify(&self, cond: u32) {
        self.primitive.notify(cond);
    }
}

// `Send` and `Sync` are derived: `lock_t` and `cond_t` are both, and so is a
// `Box` of conditions. There were `unsafe impl`s and a `Drop` destroying the
// pthread objects by hand here until 2026-10-16; the objects destroy
// themselves, with the same `EBUSY` check.

/// A relative timeout as the `timespec` a wait takes, or `None` for "for ever".
///
/// Negative is "for ever", which is how every caller spells it. The answer was
/// a `*const libc::timespec` with null for that, which is the same sentinel one
/// type down.
fn timeout_of(timeout_ns: i64, ts: &mut libc::timespec) -> Option<&libc::timespec> {
    if timeout_ns < 0 {
        return None;
    }
    ts.tv_sec = (timeout_ns / 1_000_000_000) as _;
    ts.tv_nsec = (timeout_ns % 1_000_000_000) as _;
    Some(ts)
}

/// Guest errnos, negated as everywhere else in the tree.
use guest_errno::c_int_::{EINTR, EINVAL, ETIMEDOUT};

/// Why a sleep ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Woke {
    /// Something notified, or the wait was spurious. Recheck the condition.
    Notified,
    /// A signal arrived. The syscall should answer `EINTR`.
    Interrupted,
    /// The caller's timeout ran out.
    TimedOut,
}

impl Woke {
    fn of(result: c_int) -> Woke {
        match result {
            EINTR => Woke::Interrupted,
            ETIMEDOUT => Woke::TimedOut,
            _ => Woke::Notified,
        }
    }
}

/// A mutex whose primitive a guest thread can be woken out of, protecting `T`.
///
/// `conds` condition variables come with it, addressed by index — a terminal
/// has two, one for input produced and one for input consumed. They belong to
/// the lock rather than to the value because that is what a condition variable
/// is: a queue attached to one mutex.
pub struct GuestLock<T> {
    primitive: Box<Primitive>,
    value: UnsafeCell<T>,
}

// The whole point: `T` moves between guest threads under this lock.
unsafe impl<T: Send> Send for GuestLock<T> {}
unsafe impl<T: Send> Sync for GuestLock<T> {}

impl<T> GuestLock<T> {
    /// Infallible since 2026-10-01. It answered `Option` "for when the host
    /// cannot allocate the primitive", which a `Box` never reports -- it
    /// aborts -- so thirteen callers carried an `ENOMEM`/`ENOSPC` arm that
    /// could not run.
    pub fn new(value: T, conds: u32) -> GuestLock<T> {
        GuestLock {
            primitive: Primitive::new(conds),
            value: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> GuestGuard<'_, T> {
        GuestGuard { lock: self, held: self.primitive.lock() }
    }

    /// `None` when another thread holds it.
    ///
    /// For the one caller that must not block: a poll of one end of a pty asks
    /// the other end whether it has room, and blocking on that lock in one
    /// direction while another thread holds it in the other is the echo
    /// deadlock in `docs/changelog/2026-08-22-pty-echo-deadlock.md`.
    pub fn try_lock(&self) -> Option<GuestGuard<'_, T>> {
        Some(GuestGuard { lock: self, held: self.primitive.try_lock()? })
    }

    /// Wake everything waiting on `cond`. Safe to call without the lock held,
    /// and the callers that must not hold it do not.
    pub fn notify(&self, cond: u32) {
        self.primitive.notify(cond);
    }

    /// Whether `lock` is this guest lock's mutex.
    ///
    /// The address stays inside this abstraction. This matters for
    /// `signalfd`'s blocking read: asking sighand whether a signal is pending
    /// would recursively take the same mutex and deadlock, so the wait hook
    /// compares lock identity before it asks the queue.
    pub fn owns_lock(&self, lock: &ffi::lock_t) -> bool {
        self.primitive.is_my_lock(lock)
    }
}

pub struct GuestGuard<'a, T> {
    lock: &'a GuestLock<T>,
    held: Held<'a>,
}

impl<T> Deref for GuestGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for GuestGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> GuestGuard<'_, T> {
    /// Release the lock, sleep until `cond` is notified, and take it back.
    ///
    /// Takes the guard by `&mut` so the borrow checker knows the value may have
    /// changed underneath: the whole point is that someone else got to it.
    pub fn wait(&mut self, cond: u32, timeout: Option<Duration>) -> Woke {
        Woke::of(self.held.wait(cond, nanos(timeout), false))
    }

    /// The same, but a signal does not end it.
    ///
    /// For the waits a guest must not be able to observe as `EINTR` — the
    /// emulator's own handshakes rather than anything the guest asked for.
    pub fn wait_ignoring_signals(&mut self, cond: u32, timeout: Option<Duration>) -> Woke {
        Woke::of(self.held.wait(cond, nanos(timeout), true))
    }

    /// The lock this guard holds, so a caller can notify without dropping it.
    pub fn owner(&self) -> &GuestLock<T> {
        self.lock
    }
}

fn nanos(timeout: Option<Duration>) -> i64 {
    match timeout {
        // Saturating: a guest may ask for a wait longer than i64 nanoseconds,
        // which is 292 years. Clamping it there is not a behaviour anyone can
        // tell from the one they asked for.
        Some(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        None => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timeout_is_clamped_rather_than_wrapped() {
        assert_eq!(nanos(None), -1);
        assert_eq!(nanos(Some(Duration::from_secs(1))), 1_000_000_000);
        assert_eq!(nanos(Some(Duration::from_secs(u64::MAX))), i64::MAX);
    }

    #[test]
    fn the_wait_result_names_why_it_ended() {
        assert_eq!(Woke::of(0), Woke::Notified);
        assert_eq!(Woke::of(EINTR), Woke::Interrupted);
        assert_eq!(Woke::of(ETIMEDOUT), Woke::TimedOut);
    }
}
