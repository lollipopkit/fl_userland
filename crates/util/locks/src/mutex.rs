//! `lock_t`: the plain mutex with owner tracking that everything in this tree
//! uses.
//!
//! # What the C did and why each part is here
//!
//! `util/sync.h`'s `__lock` was a `static inline` behind a `lock()` macro that
//! passed `__FILE__` and `__LINE__` — which is the only reason it was a macro,
//! and `file!()`/`line!()` are the same thing. Rust callers reached it through
//! `sync_lock` in `util/sync.c`, and the argument for keeping that shim was:
//!
//! > `sync_lock` is what routes a Rust caller through the same instrumented
//! > path the C uses, so a `-DLOCK_DEBUG=1` build still sees every lock a crate
//! > takes. Reimplementing the acquire in Rust would silently opt the whole
//! > tree out of its main deadlock diagnostic.
//!
//! Correct while there were two callers. By 2026-09-06 the C took a `lock_t`
//! **twice**, both of them `pids_lock`'s own wrappers, and both existed only so
//! that Rust could take it. There is no "path the C uses" left to share — so
//! this is the path, and it carries all three instruments rather than none:
//!
//! - **The checked return, in every build.** These are default mutexes, so
//!   there is no legitimate non-zero return: not `EDEADLK` (that is an
//!   error-checking mutex), not `EAGAIN` (a recursive one). What it does answer
//!   is `EINVAL`, for a mutex that was destroyed or never initialised — and a
//!   caller that carries on *without the lock* is a data race by construction.
//!   `do_clone` locked a task its vfork child had already freed; `task_destroy`
//!   zeroes the struct, pthread answered `EINVAL`, and the write went into dead
//!   memory with nothing reported.
//!
//!   The cost was measured at the time: one perfectly-predicted branch on a
//!   path that has just done an atomic compare-exchange. `dd bs=1
//!   count=200000` — 400k syscalls, several of these each — 0.28s with and
//!   0.28s without, against a syscall-free control that also did not move.
//!
//! - **`LOCK_SLOW_TRACE`**, which reports a wait over three seconds with the
//!   lock and the site waiting for it. A `cfg` now rather than a `#if`.
//!
//! - **`LOCK_DEBUG`**, which catches recursive locking and
//!   unlock-without-lock. Also a `cfg`, and the `lock_debug` struct it adds to
//!   `lock_t` is generated either way — which is what makes a `-DLOCK_DEBUG=1`
//!   build the one that exercises a second layout.

use crate::ffi;

pub use ffi::lock_t;
// `lock_t` is `crates/util/synctypes`', which is the one definition -- so the
// `&lock_t` this module takes is the same Rust type as the field in every
// struct that embeds one, with nothing to cast at a crate boundary. It was
// generated per crate until 2026-09-08 and lived in `crates/kernel/abi` until
// 2026-09-09; `build.rs` is what is left of the first, and turns `-DLOCK_DEBUG`
// into the `cfg` that changes the layout.

// `init` and `destroy` were here until 2026-10-16. `lock_t::new` is a ready
// mutex and its `Drop` is the checked destroy; see `crates/util/synctypes`.

/// Take it.
///
/// `file` and `line` are the caller's, for the two diagnostics; the
/// [`lock!`](crate::lock) macro fills them in the way `lock()` filled in
/// `__FILE__` and `__LINE__`.
///
/// **Safe since 2026-09-16**, which is what taking a `&lock_t` buys. The
/// obligation used to be "`l` is live and initialised": the borrow is the
/// first half, and the second is not an obligation at all, because a `lock_t`
/// a caller can name is at worst the zeroed one [`lock_t::default`] makes —
/// and `pthread_mutex_lock` answers `EINVAL` for that, which the line below
/// already turns into an abort rather than a silent unlocked critical section.
///
/// Recursive locking is still a caller's rule and still not undefined
/// behaviour: these are default mutexes, so it deadlocks, and `-DLOCK_DEBUG=1`
/// is what names the site.
///
/// **`file` must be NUL-terminated.** `lock_debug.file` is a `const char *`
/// that a hang report reads as a C string, and `file!()` alone is a `&str`
/// with no NUL — storing its pointer would read past the end of the literal.
/// The macro appends one; a hand-written call must too.
/// `pub`, not `pub(crate)`: `locks::lock!` expands to a call to this in
/// the *caller's* crate, so a macro is a cross-crate use that no scan of
/// identifiers can see.
pub fn lock_at(l: &lock_t, file: &'static str, line: u32) {
    // Slow-lock tracing: with `-DLOCK_SLOW_TRACE=1` **and** `IUL_LOCK_TRACE`
    // set, `lock()` spins with `trylock` and reports any wait longer than three
    // seconds, with the lock and its holder. That is how a lock-order inversion
    // gets found.
    //
    // A `cfg` and not a runtime `if`: the flag is a mutable global, so a plain
    // `if` could not be optimised away and every lock site carried the branch
    // and the inlined tracing body -- a needless icache cost across the very
    // many of them in this emulator. It also dragged `current_pid()` and the
    // flag into anything that merely takes a lock, which broke the link for
    // standalone tools like `crates/tools/fakefsify` that have no task state to
    // report.
    #[cfg(iul_lock_slow_trace)]
    if crate::slow_trace_on() {
        lock_slowly(l, file, line);
        // SAFETY: this thread now holds `l`.
        unsafe { note_held(l, file, line) };
        return;
    }

    // Checked in every build; see the module comment.
    // SAFETY: `l.mutex()` is the `UnsafeCell` this type exists to expose, and
    // the borrow says the storage is live.
    if unsafe { libc::pthread_mutex_lock(l.mutex()) } != 0 {
        std::process::abort();
    }
    l.set_owner(this_thread());
    // SAFETY: this thread now holds `l`.
    unsafe { note_held(l, file, line) };
    let _ = (file, line);
}

/// This thread's `pthread_t` as a word — the shape [`lock_t::owner`] keeps,
/// because Darwin's is a pointer and Linux's is a `c_ulong`.
fn this_thread() -> usize {
    // SAFETY: `pthread_self` reads this thread's own identity and takes nothing.
    unsafe { libc::pthread_self() as usize }
}

/// Whether this thread is `l`'s owner.
///
/// **Not for deciding anything.** A thread that has to ask whether it holds a
/// lock has lost track of its own protocol, and the answer would be a
/// `goto`-shaped "lock it if I have not already". It is for *asserting* a rule
/// whose violation is otherwise silent — `crates/kernel/exitcalls`' `Deferred`
/// asserts that nothing which waits runs under `pids_lock`, after a deadlock
/// that did.
///
/// The owner word is maintained in every build, not only under
/// `-DLOCK_DEBUG=1`, which is the point: the rule this checks was broken on a
/// path that a default build runs and a lock-debug build is not run by default.
///
/// Reading it without the lock is deliberate and the answer is only meaningful
/// for *this* thread: either we are the owner, in which case nobody else can be
/// writing it, or we are not, in which case whatever is there is not us. That
/// was a **data race** while the field was a plain `pthread_t` — a torn or
/// stale read of a word another thread stores on every acquire — and it is an
/// `AtomicUsize` now, which is why this function no longer needs an `unsafe`.
pub fn held_by_this_thread(l: &lock_t) -> bool {
    l.owner() == this_thread()
}

/// Give it back.
///
/// # Safety
/// This thread holds `l`. Unlike [`lock_at`] this cannot become safe: these are
/// default mutexes, and releasing one this thread does not hold is undefined
/// rather than an error code.
pub unsafe fn unlock(l: &lock_t) {
    // SAFETY: the caller's contract.
    unsafe { note_released(l) };
    l.set_owner(0);
    // SAFETY: as above.
    if unsafe { libc::pthread_mutex_unlock(l.mutex()) } != 0 {
        std::process::abort();
    }
}

/// Take it if it is free. Zero when taken, non-zero when not — the C's
/// `trylock`, whose callers test it against 0.
///
/// Safe for the same reason [`lock_at`] is.
pub fn trylock_at(l: &lock_t, file: &'static str, line: u32) -> std::ffi::c_int {
    // SAFETY: as `lock_at`.
    let rc = unsafe { libc::pthread_mutex_trylock(l.mutex()) };
    if rc == 0 {
        l.set_owner(this_thread());
        // SAFETY: this thread now holds it.
        unsafe { note_held(l, file, line) };
    }
    let _ = (file, line);
    rc
}

/// Record the holder, when this build keeps one.
///
/// # Safety
/// This thread holds `l`, which is what makes the `debug` fields this thread's
/// to read and write.
#[allow(unused_variables)]
unsafe fn note_held(l: &lock_t, file: &'static str, line: u32) {
    #[cfg(iul_lock_debug)]
    // SAFETY: the caller's contract.
    unsafe {
        let d = l.debug();
        assert!((*d).initialized, "locking an uninitialised lock");
        assert!(
            (*d).file.is_null(),
            "attempting to recursively lock (held at {}:{})",
            std::ffi::CStr::from_ptr((*d).file).to_string_lossy(),
            (*d).line
        );
        (*d).file = file.as_ptr().cast();
        (*d).line = line as _;
        (*d).pid = currentpid::current_pid();
    }
}

/// # Safety
/// As [`note_held`].
unsafe fn note_released(l: &lock_t) {
    #[cfg(iul_lock_debug)]
    // SAFETY: the caller's contract.
    unsafe {
        let d = l.debug();
        assert!((*d).initialized, "unlocking an uninitialised lock");
        assert!(!(*d).file.is_null(), "attempting to unlock an unlocked lock");
        *d = Default::default();
        (*d).initialized = true;
    }
    let _ = l;
}

/// Take it, reporting a wait over three seconds.
///
/// Spins on `trylock` rather than blocking, because a blocked thread cannot
/// report anything: the whole point is to name the lock and the site while the
/// wait is still happening.
///
#[cfg(iul_lock_slow_trace)]
fn lock_slowly(l: &lock_t, file: &'static str, line: u32) {
    let start = std::time::Instant::now();
    let mut reported = false;
    // SAFETY: as `lock_at`.
    while unsafe { libc::pthread_mutex_trylock(l.mutex()) } != 0 {
        std::thread::sleep(std::time::Duration::from_micros(200));
        if !reported && start.elapsed().as_millis() > 3000 {
            reported = true;
            eprintln!(
                "[lockslow] pid={} waiting >3s at {file}:{line} for lock={:p}",
                currentpid::current_pid(),
                std::ptr::from_ref(l)
            );
        }
    }
    l.set_owner(this_thread());
}

/// A held `lock_t`, released when dropped.
///
/// Since 2026-10-01. Four crates each wrote this type -- `fs/fdobj`'s
/// `FdGuard`, `asbestos/blockcache`'s `SyncGuard` and `Locked`,
/// `util/guestlock`'s guard -- and each wrote the `unsafe` unlock in its own
/// `Drop`. Built only by [`guard!`] and [`try_guard!`], so a `Guard` existing
/// is the proof the unlock asks for.
#[must_use = "dropping it releases the lock"]
///
/// `!Send`: a pthread mutex is unlocked by the thread that locked it, so the
/// guard may not move to another one. `SyncGuard`'s raw pointer used to say
/// that by accident; this says it on purpose.
pub struct Guard<'a>(&'a lock_t, core::marker::PhantomData<*const ()>);

impl<'a> Guard<'a> {
    /// See [`guard!`].
    pub fn take_at(l: &'a lock_t, file: &'static str, line: u32) -> Guard<'a> {
        lock_at(l, file, line);
        Guard(l, core::marker::PhantomData)
    }

    /// See [`try_guard!`]. **An `if`, not `then_some`**, which would build
    /// and drop a guard -- an unlock -- when the lock is not free.
    pub fn try_take_at(l: &'a lock_t, file: &'static str, line: u32) -> Option<Guard<'a>> {
        if trylock_at(l, file, line) == 0 {
            Some(Guard(l, core::marker::PhantomData))
        } else {
            None
        }
    }
}

/// Evidence that the calling thread holds a lock: what a condition wait asks
/// for before it releases and retakes one.
///
/// # Safety
/// While a `&Self` is live on a thread, that thread holds [`Held::held`]'s
/// lock. So an implementor is `!Sync`: a reference sent elsewhere would vouch
/// for a lock the receiving thread does not hold.
pub unsafe trait Held {
    fn held(&self) -> &lock_t;
}

// SAFETY: a `Guard` exists only on the thread holding its lock, and is `!Sync`.
unsafe impl Held for Guard<'_> {
    fn held(&self) -> &lock_t {
        self.0
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        // SAFETY: a `Guard` exists only while this thread holds the lock.
        unsafe { unlock(self.0) };
    }
}

/// `guard!(l)` -- take `l` for a scope, recording this call site.
#[macro_export]
macro_rules! guard {
    ($l:expr) => {
        $crate::mutex::Guard::take_at($l, concat!(file!(), "\0"), line!())
    };
}

/// `try_guard!(l)` -- `l` for a scope if it is free, `None` rather than a wait.
#[macro_export]
macro_rules! try_guard {
    ($l:expr) => {
        $crate::mutex::Guard::try_take_at($l, concat!(file!(), "\0"), line!())
    };
}

/// `lock!(l)` — take `l`, recording this call site.
///
/// The C's `lock()` macro, and for the same reason: `file!()` and `line!()` are
/// what `__FILE__` and `__LINE__` were, and a function cannot see its caller's.
/// The `\0` is what makes the recorded name readable as a C string; see
/// [`lock_at`].
///
/// They take a `&lock_t`, and `lock!` and `trylock!` are **safe calls** since
/// 2026-09-16 — see [`lock_at`] for what the borrow discharges. `unlock!` is
/// not, and expands to an `unsafe` **call** rather than an `unsafe` block, so
/// that the obligation ("this thread holds it") is written at each site:
/// `unsafe { locks::unlock!(&p.lock) }`.
///
/// Each used to end in `($l).cast()`, from the era when every crate generated
/// its own `lock_t` and a cross-crate pointer needed converting. There has been
/// one `lock_t` since 2026-09-08 and a cast is a conversion the compiler cannot
/// check, so the argument is now the reference itself.
#[macro_export]
macro_rules! lock {
    ($l:expr) => {
        $crate::mutex::lock_at($l, concat!(file!(), "\0"), line!())
    };
}

/// `trylock!(l)` — take `l` if it is free, recording this call site.
#[macro_export]
macro_rules! trylock {
    ($l:expr) => {
        $crate::mutex::trylock_at($l, concat!(file!(), "\0"), line!())
    };
}

/// `unlock!(l)` — give it back. A macro only so that it reads beside [`lock!`].
#[macro_export]
macro_rules! unlock {
    ($l:expr) => {
        $crate::mutex::unlock($l)
    };
}

// ---------------------------------------------------------------------------
// Suspending the debug bookkeeping across a wait
// ---------------------------------------------------------------------------

/// What `lock_t`'s debug fields held, for a caller that is about to drop the
/// lock and take it back.
///
/// **A type rather than a buffer and a size.** `util/sync.c` had
/// `lock_debug_suspend`, `lock_debug_restore` and `lock_debug_size`, and
/// `crates/util/waitfor` carried a `[u8; LOCK_DEBUG_SAVE_MAX]` with a
/// `static_assert` in the C keeping that constant honest — because
/// `struct lock_debug` is a field of `lock_t` inside an `#if`, and a crate
/// could not name it.
///
/// It can now, for two reasons that had to arrive together: the `#if` is a
/// `cfg`, and `lock_t_lock_debug` is `crates/util/synctypes`' --
/// bindgen names it for its parent, because `struct lock_debug` is declared
/// inside `lock_t`. It
/// belongs there under both halves of that list's rule rather than the unsafe
/// middle — in a `-DLOCK_DEBUG=1` build every crate generates it from one
/// header, and in a default build no header defines it at all.
///
/// The maximum, the assertion and the three functions all go away, because the
/// compiler knows the size.
#[derive(Clone, Copy)]
pub struct DebugSaved {
    #[cfg(iul_lock_debug)]
    inner: ffi::lock_t_lock_debug,
}

/// Take the bookkeeping off `l`, leaving it looking unlocked to the assertions.
///
/// `wait_for` drops the lock inside `pthread_cond_wait` and takes it back
/// before returning, and the bookkeeping has to be put down or the checks
/// report this thread as the owner of a lock it is not holding.
///
/// # Safety
/// This thread holds `l`.
pub unsafe fn debug_suspend(l: &lock_t) -> DebugSaved {
    #[cfg(iul_lock_debug)]
    // SAFETY: the caller's contract.
    unsafe {
        let d = l.debug();
        let inner = *d;
        *d = Default::default();
        (*d).initialized = inner.initialized;
        DebugSaved { inner }
    }
    #[cfg(not(iul_lock_debug))]
    {
        let _ = l;
        DebugSaved {}
    }
}

/// Put it back, after the lock has been retaken.
///
/// # Safety
/// This thread holds `l`, and `saved` came from [`debug_suspend`] on it.
pub unsafe fn debug_restore(l: &lock_t, saved: DebugSaved) {
    #[cfg(iul_lock_debug)]
    // SAFETY: the caller's contract.
    unsafe {
        *l.debug() = saved.inner;
    }
    let _ = (l, saved);
}

// ---------------------------------------------------------------------------
// A lock and the value it protects
// ---------------------------------------------------------------------------

/// A [`lock_t`] that owns what it protects, as `std::sync::Mutex` does, so the
/// value cannot be reached without the lock. The lock is still a `lock_t`, so
/// `-DLOCK_DEBUG=1` and `LOCK_SLOW_TRACE` see it like every other one.
///
/// Taken with [`locked!`](crate::locked), which records the call site.
pub struct Mutex<T: ?Sized> {
    raw: lock_t,
    value: core::cell::UnsafeCell<T>,
}

// SAFETY: the value is reached only through a `MutexGuard`, which exists only
// while this thread holds `raw`; that is `std::sync::Mutex`'s bound.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
// SAFETY: as `Send`.
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Mutex<T> {
        Mutex { raw: lock_t::new(), value: core::cell::UnsafeCell::new(value) }
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Mutex<T> {
        Mutex::new(T::default())
    }
}

impl<T: ?Sized> Mutex<T> {
    /// See [`locked!`](crate::locked).
    pub fn lock_at(&self, file: &'static str, line: u32) -> MutexGuard<'_, T> {
        MutexGuard { _held: Guard::take_at(&self.raw, file, line), value: &self.value }
    }

    /// See [`try_locked!`](crate::try_locked): `None` rather than a wait.
    pub fn try_lock_at(&self, file: &'static str, line: u32) -> Option<MutexGuard<'_, T>> {
        Guard::try_take_at(&self.raw, file, line).map(|held| MutexGuard { _held: held, value: &self.value })
    }

    /// No lock needed: `&mut self` says nothing else can reach it.
    pub fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }
}

/// The value of a held [`Mutex`]. `!Send`, as [`Guard`] is.
#[must_use = "dropping it releases the lock"]
pub struct MutexGuard<'a, T: ?Sized> {
    _held: Guard<'a>,
    value: &'a core::cell::UnsafeCell<T>,
}

impl<T: ?Sized> core::ops::Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: `_held` is the lock, and nothing reaches the value without it.
        unsafe { &*self.value.get() }
    }
}

impl<T: ?Sized> core::ops::DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as `deref`, and `&mut self` makes this the only borrow.
        unsafe { &mut *self.value.get() }
    }
}

/// `locked!(m)` -- take the [`Mutex`] `m` for a scope, recording this call site.
#[macro_export]
macro_rules! locked {
    ($m:expr) => {
        $crate::mutex::Mutex::lock_at($m, concat!(file!(), "\0"), line!())
    };
}

/// `try_locked!(m)` -- the [`Mutex`] `m` for a scope if it is free, `None`
/// rather than a wait.
#[macro_export]
macro_rules! try_locked {
    ($m:expr) => {
        $crate::mutex::Mutex::try_lock_at($m, concat!(file!(), "\0"), line!())
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property that replaced `LOCK_DEBUG_SAVE_MAX` and its
    /// `static_assert`: the saved state is exactly what this build's `lock_t`
    /// carries, and nothing in either language has to be told how big that is.
    ///
    /// A build without `-DLOCK_DEBUG=1` has no bookkeeping, so the type is
    /// **zero-sized** — which is what makes `debug_suspend` free on the wait
    /// path in a default build, where the C's version still called two
    /// functions across a language boundary to do nothing.
    #[test]
    fn the_saved_state_is_the_size_this_build_needs() {
        let n = size_of::<DebugSaved>();
        if cfg!(iul_lock_debug) {
            assert!(n > 0, "a -DLOCK_DEBUG=1 build has bookkeeping to save");
        } else {
            assert_eq!(n, 0, "a default build has none, and pays nothing for it");
        }
    }

    /// The value is reached only through the lock: two threads incrementing it
    /// lose no update.
    #[test]
    fn a_mutex_serialises_its_value() {
        let m = Mutex::new(0u32);
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..10_000 {
                        *crate::locked!(&m) += 1;
                    }
                });
            }
        });
        let mut m = m;
        assert_eq!(*m.get_mut(), 40_000);
    }
}
