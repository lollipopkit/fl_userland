//! The one interruptible wait.
//!
//! Every blocking syscall in this emulator ends here: a guest thread parks on a
//! condition variable and is woken either by whatever it was waiting for or by
//! a signal it has to go and take. `util/sync.c`'s until 2026-09-03.
//!
//! # Two questions that look like one
//!
//! "Is a signal pending" is asked twice — before parking and after waking — and
//! it deliberately excludes signals a `sigtimedwait` caller is waiting to
//! collect.
//!
//! That `waiting` term is `sigtimedwait`'s set: a thread that has asked for a
//! signal it has *blocked* wants to be woken for it, which is what the blocking
//! read and write paths use it for. Here the question is the opposite one —
//! whether to answer `EINTR` — and `sigtimedwait` is itself a caller of this.
//! Counting the signal it is waiting *for* as a reason to interrupt would make
//! `sigwaitinfo` return `EINTR` instead of the signal it was called to collect.
//!
//! It is woken anyway: `deliver_signal_unlocked` skips the early return for a
//! signal in `waiting` and notifies the task's condition variable, and
//! `sigtimedwait`'s loop then dequeues it. So the two tests differ because the
//! two questions do.
//!
//! # The caller may already hold the lock being compared against
//!
//! `signalfd`'s blocking read parks on `sighand`'s own mutex, and asking
//! `sighand` whether a signal is pending would take it a second time — a
//! deadlock. So when the lock being waited on *is* that mutex, the question
//! goes to the queue directly. That comparison is implemented by
//! `SigHand::owns_lock`, so waitfor does not need to know the internal lock
//! layout.
//!
//! # What stays in C
//!
//! Three things, and each has a reason rather than a shrug.
//!
//! `struct lock_debug` is a field of `lock_t` inside an `#if`, so a crate
//! cannot name it whatever bindgen generates in a build that has it —
//! The bookkeeping `lock_t` carries under `-DLOCK_DEBUG=1` is put down across
//! the wait and picked back up, through `crates/util/locks` -- which can name
//! the saved state as a *type* since `lock_debug` joined the shared set.

#![deny(unsafe_op_in_unsafe_fn)]

#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    clippy::all
)]
/// `lock_t`, `cond_t` and the `struct task` fields a wait touches.
///
/// Generated from `kernel/task.h` until 2026-09-08, for the reason
/// `crates/util/locks` states: `lock_t` changes size with `-DLOCK_DEBUG=1` and
/// `struct task` embeds three of them. That is a `cfg` on one definition now.
mod ffi {
    pub use util_synctypes::*;
}

pub use locks::mutex::Held;

/// Whether a signal should interrupt a wait on `lock`.
///
/// A hook, and the hook is the point. This crate is layer 0 and the answer is
/// the signal layer's, three layers up: `crates/kernel/sighand` ends a wait
/// through `crates/util/guestlock`, which is built on this crate, so a direct
/// call closes a cycle cargo refuses. It was three `extern "C"` declarations
/// under a marker saying the cycle was deliberate, until 2026-09-09 — the same call resolved by the
/// linker on name alone, with four `#[no_mangle]` doubles in this file's own
/// tests to make it link.
///
/// **This crate also stopped reading `struct task` when the hook landed**, and
/// that is what the change was for: `signal_pending` read `task.sighand` and
/// `task.signals`, which is a layer-0 crate needing the *definition* of the
/// task — the one thing pinning `struct task` to the foundation. See
/// `CLAUDE.md` on the 950 `.cast()` calls.
static SIGNAL_PENDING: OnceLock<fn(&ffi::lock_t) -> bool> = OnceLock::new();

/// Install it. `crates/kernel/sighand` does this when it makes the first
/// disposition table, which is inside `task_create_` — so it is installed
/// before any task can wait, and the first call wins.
///
/// **Before then the answer is `false`, and that is not a fallback**: with no
/// task there is no signal to be pending, which is exactly what the function
/// this replaced returned for a null `current()`. A test binary that links this
/// crate and never makes a task gets the same answer either way, which is why
/// the four `#[no_mangle]` doubles it used to need are gone.
pub fn set_signal_pending_hook(f: fn(&ffi::lock_t) -> bool) {
    let _ = SIGNAL_PENDING.set(f);
}

/// Whether either hook has been installed — for the tests in
/// `crates/kernel/sighand` and `crates/kernel/taskcalls` that assert the
/// install happens.
///
/// It needs saying why an accessor exists at all. **The two hooks are invisible
/// to every unit test in this crate**, because a test binary has no current
/// task: the real `signal_pending` answers `false` for a null task and an
/// absent hook answers `false` too, and nothing is recorded as parked either
/// way. That is what makes the tests here honest — they run the real wait —
/// and it is also what would let an install site be deleted with the whole
/// suite still green, until a guest could not be interrupted. So the property
/// a test can check is not the answer but the wiring.
pub fn hooks_installed() -> (bool, bool) {
    (SIGNAL_PENDING.get().is_some(), PARKED.get().is_some())
}

use std::ffi::c_int;
use std::sync::OnceLock;

/// Guest errnos, negated as everything in this tree reports them.
use guest_errno::c_int_::{EINTR, ETIMEDOUT};

/// Whether a signal should interrupt a wait on `lock`.
///
/// See the module comment for why the lock is a parameter.
///
fn signal_pending(lock: &ffi::lock_t) -> bool {
    SIGNAL_PENDING.get().is_some_and(|f| f(lock))
}

/// Park on `cond`, releasing `lock`, until it is notified, the timeout passes,
/// or a signal arrives.
///
/// `_EINTR`, `_ETIMEDOUT`, or 0 — and 0 includes a spurious wake, so **every
/// caller loops**. That is not a nicety: a `pthread_cond_wait` may return for
/// no reason at all, and the condition has to be re-read under the lock.
///
/// `timeout` is *relative*. `None` waits for ever.
///
/// `held`'s lock is released while parked and held again on return. Safe
/// since 2026-10-17: the contract "`lock` is held by this thread" was the
/// caller's word, and is now the [`Held`] it passes.
pub fn wait_for(cond: &ffi::cond_t, held: &impl Held, timeout: Option<&libc::timespec>) -> c_int {
    let lock = held.held();
    // Before parking: a signal that arrived while this thread was running has
    // to be taken now, or the wait could park for ever on something the signal
    // was meant to interrupt.
    if signal_pending(lock) {
        return EINTR;
    }
    let err = wait_for_ignore_signals(cond, held, timeout);
    if err < 0 {
        return ETIMEDOUT;
    }
    // And after: the wake may *be* the signal.
    if signal_pending(lock) {
        return EINTR;
    }
    0
}

/// As [`wait_for`], but a pending signal is not a reason to return.
///
/// `sigtimedwait` is the caller that needs this: it is waiting for a signal, so
/// being told one is pending is the answer rather than an interruption.
///
pub fn wait_for_ignore_signals(
    cond: &ffi::cond_t,
    held: &impl Held,
    timeout: Option<&libc::timespec>,
) -> c_int {
    let lock = held.held();
    // Publish which condition this thread is parked on, so that the group-exit
    // valve and the futex-stall diagnostic can find it. Under its own lock,
    // because the reader is another thread.
    set_parked(cond);

    // The lock is not held while parked, so the record of who holds it has to
    // be put down or the debug checks report this thread as the owner. Zero
    // bytes in a build without `-DLOCK_DEBUG=1`, where both calls are no-ops.
    // A type rather than a byte buffer and a maximum: the compiler knows the
    // size, so there is nothing for a `static_assert` to keep honest.
    // SAFETY: `held` is the proof this thread holds `lock`, here and below.
    let saved = unsafe { locks::mutex::debug_suspend(lock) };

    let m = lock.mutex();
    let c = cond.cond();
    let rc = match timeout {
        None => unsafe { libc::pthread_cond_wait(c, m) },
        // Apple's relative form takes the timeout as given; the absolute
        // deadline Linux wants is `crates/util/timeabi`'s arithmetic, which
        // is where the carry that made every timed wait spin was fixed. Darwin's
        // relative form, so no clock is read and no deadline can be denormalised.
        Some(t) => unsafe { libc::pthread_cond_timedwait_relative_np(c, m, t) },
    };

    unsafe { locks::mutex::debug_restore(lock, saved) };
    unset_parked();

    if rc == libc::ETIMEDOUT { ETIMEDOUT } else { 0 }
}

/// Publish which condition this thread is parked on — the second hook, and the
/// other half of what made this crate read `struct task`.
///
/// It wrote `task->waiting_cond` under `task->waiting_cond_lock` itself until
/// 2026-09-09. The field is `crates/kernel/taskcalls`'s: that crate initialises
/// it, destroys it, and is the *reader* — `task_wake_waiting` takes the same
/// lock from another thread to notify a parked one. A layer-0 crate writing one
/// field of a layer-3 struct, correctly, is still the layer-0 crate needing the
/// struct's definition.
///
/// So the whole operation is the hook, including finding the task: this crate
/// says "parked on `cond`" and "no longer parked", and nothing here knows what
/// records it. `None` before anything installs one, which is a host thread with
/// no task — the same case the null check used to cover.
static PARKED: OnceLock<fn(Option<&ffi::cond_t>)> = OnceLock::new();

/// Install it. `crates/kernel/taskcalls` does this when it makes a task, for
/// the reason [`set_signal_pending_hook`] gives.
pub fn set_parked_hook(f: fn(Option<&ffi::cond_t>)) {
    let _ = PARKED.set(f);
}

fn set_parked(cond: &ffi::cond_t) {
    if let Some(f) = PARKED.get() {
        f(Some(cond));
    }
}

/// The other half: no longer parked. A separate function rather than a null
/// argument, which is what `Option` costs and what it buys.
fn unset_parked() {
    if let Some(f) = PARKED.get() {
        f(None);
    }
}

// ---------------------------------------------------------------------------
// The condition variable itself
// ---------------------------------------------------------------------------
//
// `util/sync.c`'s until 2026-09-03, and **no C called any of these** — the four
// were reached only from Rust, three of them through `sync_cond_*` forwarders
// whose whole content was calling them. They keep their C symbol names because
// `util/sync.h` is where a descriptor's or a task's interface declares them.
//
// The `lock_t` half stays C for a reason that is *not* "it is a macro": every
// Rust caller of a lock goes through `sync_lock`, and that is what routes it
// through the same instrumented path the C uses — the `-DLOCK_DEBUG=1`
// recursive-lock check and the `LOCK_SLOW_TRACE` spin. Reimplementing the
// acquire in Rust would silently opt every crate out of the tree's main
// deadlock diagnostic. A condition variable has no such bookkeeping.

// `cond_init` and `cond_destroy` were here until 2026-10-16. `cond_t::new` is
// a ready condition and its `Drop` is the checked destroy. The init bound the
// condition to `CLOCK_MONOTONIC` on Linux only; Darwin has only the relative
// timed wait, which is the one `wait_for_ignore_signals` uses.

/// Wake **everything** parked on `cond`.
///
/// Safe, and named as `std::sync::Condvar`'s is: the borrow says the condition
/// variable is live, and a zeroed one answers `EINVAL` rather than doing
/// anything undefined. Every caller in this tree uses this.
pub fn notify_all(cond: &ffi::cond_t) {
    // SAFETY: `cond.cond()` is the `UnsafeCell` `cond_t` exists to expose.
    unsafe { libc::pthread_cond_broadcast(cond.cond()) };
}

/// The same, as the C symbol.
///
/// **Kept because this repository cannot decide it.** `notify` is one of the
/// five exports `tools/dead-exports.py` reports and does not fail on — the fact
/// that settles them is which symbols ServerBox links, which is not here. Every
/// Rust caller goes to [`notify_all`], so this has no in-tree caller and is the
/// interface or it is nothing.
///
/// # Safety
/// `cond` points at a live `cond_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn notify(cond: *mut ffi::cond_t) {
    // SAFETY: the caller's contract.
    notify_all(unsafe { &*cond });
}

/* Six `#[no_mangle]` test doubles were here until 2026-09-09: `task_self`,
 * the sighand lock and signal predicates, `sigqueue_interrupts_a_wait`,
 * `sync_lock` and `sync_unlock`. They existed because a wait asked the signal
 * layer a question by symbol, and a test binary links no signal layer -- so
 * this crate carried six second definitions of symbols its own dependencies
 * define, which is not a substitution but a duplicate `ld` picks between.
 *
 * The two hooks above are what removed them. There is no symbol to double now:
 * nothing is installed in a test, so a wait is not interrupted and nothing is
 * recorded as parked, which is the answer a test binary got from the stubs
 * anyway. See tools/dup-stubs.py, and CLAUDE.md on why a parallel
 * implementation tests the parallel implementation. */

#[cfg(test)]
mod tests {
    use super::*;

    /// The errnos, which are the guest's and are negative here.
    ///
    /// Worth pinning because they are the whole interface: a caller tests
    /// `< 0` and then which one, and getting `ETIMEDOUT` wrong turns a timed
    /// wait into an interrupted syscall.
    #[test]
    fn the_two_answers_are_the_guests_errnos() {
        assert_eq!(EINTR, -4);
        assert_eq!(ETIMEDOUT, -110);
    }

    ///
    /// The save area was a `[u8; LOCK_DEBUG_SAVE_MAX]` and this asserted that
    /// the constant had reached the crate — because a bindgen allowlist that
    /// stops matching leaves a zero-length array and a silent overrun. It is a
    /// type now, so the compiler knows the size and there is nothing to
    /// under-count; `crates/util/locks` asserts the property that replaced it.
    ///
    /// The pthread object is the first field, which is what lets `raw()` hand
    /// its address straight to `pthread_mutex_lock`.
    ///
    /// This test used to assert that `ffi::pthread_mutex_t` was the same *size*
    /// as `libc::pthread_mutex_t`, which was a real check for as long as there
    /// were two of them: bindgen rendered Darwin's `_opaque_pthread_mutex_t`
    /// into `crates/kernel/taskview` a second time, and a test to say the copy
    /// still matched is what a second rendering costs. Since 2026-09-08
    /// `taskview` names `libc`'s, so that assertion compares a type with
    /// itself — the shape CLAUDE.md calls a test that restates its subject.
    /// What is left is the part that can still be wrong.
    ///
    /// **And what can be wrong changed on 2026-09-16.** The offsets were what
    /// let a `*mut lock_t` be *cast* to a `*mut pthread_mutex_t`; there is no
    /// such cast now, because `mutex()` and `cond()` are field projections the
    /// compiler checks. So the assertion that earns its place is the one this
    /// file could not make before: that a **shared reference** is enough to
    /// reach them. It compiles only because the fields are `UnsafeCell` — the
    /// old spelling was `&raw const x as *mut _`, which compiles for any type
    /// at all and is undefined behaviour for a `Freeze` one.
    #[test]
    fn a_shared_reference_reaches_the_pthread_objects() {
        let l = ffi::lock_t::default();
        let c = ffi::cond_t::default();
        // Taken through `&l`, and equal to the struct's own address, which is
        // the first-field property this test has always checked — asked
        // through the accessor now, because the field is private.
        assert_eq!(l.mutex().cast::<u8>().cast_const(), (&raw const l).cast());
        assert_eq!(c.cond().cast::<u8>().cast_const(), (&raw const c).cast());
    }
}
