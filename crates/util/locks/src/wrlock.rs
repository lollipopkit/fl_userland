//! The address-space reader-writer lock: taking it, and the fairness rule.
//!
//! # Why this is a crate and not four `static inline`s
//!
//! `util/sync.h` had `read_wrlock`, `read_wrunlock` and `__write_wrlock`, and
//! `kernel/memory.c` had four wrappers over them for `struct mem`'s lock. The
//! blocker was:
//!
//! > `read_wrlock` and its siblings carry the writer-preference spin, the bound
//! > on how long a reader stands aside for a waiting writer, and the
//! > `LOCK_DEBUG` bookkeeping. Reimplementing them in Rust would opt this lock
//! > out of the tree's deadlock diagnostics and put a **second copy of the
//! > fairness rule** in the tree.
//!
//! The second copy is the real half — and it is an argument for moving *all*
//! the callers, not for keeping the C. There are two locks in this shape,
//! `struct mem`'s and `struct asbestos`'s jetsam lock, and both are here, so
//! this is the only copy.
//!
//! The bookkeeping is not `LOCK_DEBUG`'s: `wrlock_t` carries `file`, `line` and
//! `pid` unconditionally, and `file!()`/`line!()` are what `__FILE__` and
//! `__LINE__` were — the macro that passed them is the only reason
//! `write_wrlock` was a macro over `__write_wrlock`.

use std::sync::atomic::Ordering;

pub use crate::ffi::wrlock_t;

/// How long a reader stands aside for a spinning writer, in total. 20 ms.
///
/// **Why a reader defers at all.** This lock prefers writers: a read lock
/// blocks while any writer is waiting. Without the deferral the writer starves
/// — `__write_wrlock` may not block (the deadlock its own comment explains is
/// real), so it spins on `trywrlock`, and a reader that never defers means the
/// trylock never finds the lock free. **One compute-bound guest thread was
/// enough to stall a `pthread_create` for three minutes and counting**, because
/// every JIT quantum re-takes the read lock with no gap.
///
/// **Why it is bounded.** Long enough for every reader already inside to finish
/// its quantum and leave — microseconds — with a wide margin for a slow core.
/// Short enough that a reader always makes progress, which is what keeps the
/// deadlock in `write()`'s comment from coming back: a reader that defers for
/// ever is a reader that never reaches the GC safepoint the writer is waiting
/// for.
///
/// `util/sync.h`'s `WRLOCK_READER_DEFER_NS` until 2026-09-08.
const READER_DEFER_NS: i64 = 20_000_000;

// `init` and `destroy` were here until 2026-10-16, and two byte-identical
// copies of `init` in `crates/asbestos/blockcache` and `crates/kernel/pagetable`
// before 2026-09-16. `wrlock_t::new` is a ready lock and its `Drop` is the
// checked destroy; see `crates/util/synctypes`.

/// A sleep of `ns`; `std` resumes one a signal interrupts, and every caller is in a loop
/// that rechecks its own condition.
fn nap(ns: i64) {
    std::thread::sleep(std::time::Duration::from_nanos(ns.max(0) as u64));
}

// `wrlock_t::val` and `writers_waiting` used to be reached from here through
// `AtomicI32::from_ptr`, at five sites between them. They are real `AtomicI32`
// fields now, so this module asks for them by name.
//
// The lock itself is `val` since 2026-11-13, a pthread rwlock before; see
// `wrlock_t` in `crates/util/synctypes` for the Darwin defect that ended it.

/// Take it for reading.
///
/// **Stand aside for a writer that is spinning, for a bounded time.**
///
/// The writer cannot block (see [`write_lock`]) and so cannot make readers
/// queue behind it. Left alone, that means it never gets in: the JIT re-takes
/// this lock at every quantum boundary with no gap, so a single compute-bound
/// guest thread starves every `mmap`, `munmap` and CoW in its address space —
/// which is what `pthread_create` needs to allocate a stack.
///
/// Deferring here is the other half. It is bounded, so a reader is never held
/// off indefinitely and the writer-preference deadlock cannot return; and it is
/// checked **before** acquiring rather than while holding, so a reader that
/// defers is holding nothing.
///
/// A reader waits only while a writer **holds** the lock, parked on the
/// lock's condition variable; a writer that is merely waiting never blocks it
/// past the deferral above.
///
/// **Safe since 2026-10-01**, for [`crate::mutex::lock_at`]'s reason: the
/// borrow says `l` is live. Taking it twice on one thread is not a deadlock:
/// no writer can get in while this thread holds the first.
pub fn read_lock(l: &wrlock_t) {
    let waiting = l.writers_waiting();
    if waiting.load(Ordering::Acquire) != 0 {
        let mut waited: i64 = 0;
        let mut ns: i64 = 20_000; // 20us, doubling
        while waited < READER_DEFER_NS && waiting.load(Ordering::Acquire) != 0 {
            nap(ns);
            waited += ns;
            if ns < 1_000_000 {
                ns *= 2;
            }
        }
    }
    let v = l.val();
    loop {
        let n = v.load(Ordering::Relaxed);
        if n >= 0 {
            if v.compare_exchange_weak(n, n + 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                break;
            }
            continue;
        }
        park_while_written(l);
    }
    #[cfg(iul_lock_debug)]
    read_held::push(l);
}

/// Sleep until no writer holds `l`.
///
/// `sleepers` is raised before `val` is read again, and the writer lowers
/// `val` before it reads `sleepers` -- both `SeqCst`, so at least one of the
/// two sees the other: either this thread sees the lock free, or the writer
/// sees a sleeper and wakes it under `park`, which this thread holds from its
/// check until `wait` releases it. A signal ending the wait early is a
/// recheck.
fn park_while_written(l: &wrlock_t) {
    let (park, wake) = l.parking();
    let mut held = park.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    l.sleepers().fetch_add(1, Ordering::SeqCst);
    while l.val().load(Ordering::SeqCst) < 0 {
        held = wake.wait(held).unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    l.sleepers().fetch_sub(1, Ordering::SeqCst);
}

/// Give the read side back.
///
/// # Safety
/// This thread holds `l` for reading.
pub unsafe fn read_unlock(l: &wrlock_t) {
    #[cfg(iul_lock_debug)]
    read_held::pop(l);
    let was = l.val().fetch_sub(1, Ordering::Release);
    debug_assert!(was > 0, "a read unlock of a lock nobody reads");
}

/// `-DLOCK_DEBUG=1`: the read sides this thread holds, and a report when the
/// thread ends with one still held.
///
/// A reader is counted but not named, so a read side left behind by a thread
/// that is gone looks like a writer spinning on a lock nobody holds. A guest thread leaves through `pthread_exit` without
/// unwinding (see `crates/kernel/taskcalls`' `run.rs`), so a `ReadGuard` on
/// its stack is never dropped. The report is printed from this thread-local's
/// destructor, which `pthread_exit` runs **on the exiting stack**: the frames
/// it abandoned are still below, so the backtrace names the guard's holder.
#[cfg(iul_lock_debug)]
mod read_held {
    use super::wrlock_t;
    use std::cell::RefCell;

    struct Held(Vec<usize>);

    impl Drop for Held {
        fn drop(&mut self) {
            if !self.0.is_empty() {
                eprintln!(
                    "[lockdebug] pid={} thread ended holding the read side of wrlock {:#x?}\n{}",
                    currentpid::current_pid(),
                    self.0,
                    std::backtrace::Backtrace::force_capture(),
                );
            }
        }
    }

    thread_local! {
        static HELD: RefCell<Held> = const { RefCell::new(Held(Vec::new())) };
    }

    pub(super) fn push(l: &wrlock_t) {
        let _ = HELD.try_with(|h| h.borrow_mut().0.push(std::ptr::from_ref(l) as usize));
    }

    pub(super) fn pop(l: &wrlock_t) {
        let at = std::ptr::from_ref(l) as usize;
        let _ = HELD.try_with(|h| {
            let mut h = h.borrow_mut();
            if let Some(i) = h.0.iter().rposition(|&p| p == at) {
                h.0.swap_remove(i);
            }
        });
    }
}

/// Record who holds it, for a hang report.
///
/// `file` is the **caller's**, NUL-terminated, exactly as [`crate::mutex`]
/// takes it -- see [`write_lock_at`] for what it used to be instead.
fn note_holder(l: &wrlock_t, file: &'static str, line: u32) {
    l.set_writer(Some((
        file.as_ptr().cast(),
        line as _,
        currentpid::current_pid(),
    )));
}

/// The holder, as a line for a report. "nobody" if the record is clear.
///
/// This is the **only reader** `wrlock_t`'s `file`, `line` and `pid` have ever
/// had: they were written on every write acquisition and read nowhere, so the
/// wrong filename below went unnoticed for as long as it was there.
///
/// Not behind `#[cfg(iul_lock_slow_trace)]`, though that is its only caller in
/// the product. A field with one reader inside a `cfg` nobody builds by default
/// is a field with no reader, which is how this got here; `pub` and testable is
/// the difference between the record being checked and being believed.
pub fn holder(l: &wrlock_t) -> String {
    let Some((file, line, pid)) = l.writer() else {
        return "nobody".to_string();
    };
    // SAFETY: the only writer is `note_holder`, and every caller reaches it
    // through `write_wrlock!`/`write_trywrlock!`, whose `concat!(file!(), "\0")`
    // is a NUL-terminated string literal with static storage. See the note on
    // `wrlock_t::writer` for why the three words may not agree with each other.
    let file = unsafe { std::ffi::CStr::from_ptr(file) };
    format!("pid={pid} at {}:{line}", file.to_string_lossy())
}

/// Take it for writing.
///
/// Acquire it **without letting a waiting writer freeze out readers**, which is
/// what macOS's writer-preferring `pthread_rwlock` did while this was one. This
/// spins on a try instead of queueing: while merely retrying, concurrent
/// readers can still take the lock.
///
/// This is load-bearing for the JIT. `task_run_current` holds `mem->lock` as a
/// **reader** for the duration of each JIT quantum and re-acquires it every
/// ~1024 blocks. Under a blocking writer-preferring `wrlock`, one thread
/// requesting the write lock (`mmap`/`munmap`/CoW, e.g. JSC's GC sweep) freezes
/// *every* other JIT thread at its next read lock — and if the writer is itself
/// waiting on those threads to reach a GC safepoint, the whole VM deadlocks.
/// Observed intermittently in claude-cli startup.
///
/// **Never make a waiting writer block readers.** A blocking
/// `pthread_rwlock_wrlock` did: writer-preferring on macOS and iOS, so the
/// moment this thread queued as a waiter, every subsequent reader blocked until
/// it ran. It reproduces far more
/// easily on-device, where slower cores mean JIT readers hold the lock across a
/// longer quantum, so any bounded spin budget is more likely to be exhausted
/// and hit the blocking fallback.
///
/// The original concern with an unbounded trylock-spin was burning a full core
/// while readers are continuously present. That is avoided **without ever
/// blocking**: the backoff grows to a steady sleep, so the spinning writer
/// yields the CPU each iteration rather than busy-spinning, and readers keep
/// making progress and releasing until the writer wins a trylock.
///
/// Announced **first**, so readers arriving from here on stand aside for a
/// bounded time. Spinning alone never won against a JIT that re-takes the read
/// lock every quantum.
///
/// # The call site, which this recorded wrongly until 2026-09-16
///
/// `wrlock_t` carries `file`, `line` and `pid` so that a hang report can name
/// the thread holding the lock, and `util/sync.h`'s `write_wrlock` was a macro
/// over `__write_wrlock` for **only** that reason -- the module comment above
/// says so. The Rust port dropped the macro and passed a constant:
///
/// ```text
/// note_holder(l, c"crates/util/wrlock/src/lib.rs", line!());
/// ```
///
/// Two things wrong with it, and a third that hid both. The path names a crate
/// that does not exist -- this module is `crates/util/locks/src/wrlock.rs`, and
/// `crates/util/wrlock` was folded into it. `line!()` there is *this* file's
/// line, so the record always named one of two lines inside the lock itself,
/// which is what the reader already knows. And **nothing read the three
/// fields**, so neither could be noticed.
///
/// [`write_wrlock!`](crate::write_wrlock) passes the caller's, and
/// [`holder`] is the reader.
///
/// Safe for [`read_lock`]'s reason.
pub fn write_lock_at(l: &wrlock_t, file: &'static str, line: u32) {
    let waiting = l.writers_waiting();
    waiting.fetch_add(1, Ordering::Release);
    let mut ns: i64 = 1_000; // 1us, growing to a 100us steady sleep
    #[cfg(iul_lock_slow_trace)]
    let start = std::time::Instant::now();
    #[cfg(iul_lock_slow_trace)]
    let mut reported = false;
    while !try_take(l) {
        nap(ns);
        if ns < 100_000 {
            ns *= 2;
        }
        // The report this lock had the fields for and no reader of. It is the
        // one whose starvation is written out at length above -- a
        // compute-bound guest thread holding the read side across every JIT
        // quantum -- and that was found by reading rather than by any
        // diagnostic saying so.
        #[cfg(iul_lock_slow_trace)]
        if !reported && crate::slow_trace_on() && start.elapsed().as_millis() > 3000 {
            reported = true;
            eprintln!(
                "[lockslow] pid={} waiting >3s at {file}:{line} for wrlock={:p}, held by {}, {} readers",
                currentpid::current_pid(),
                std::ptr::from_ref(l),
                holder(l),
                l.val().load(Ordering::Relaxed),
            );
        }
    }
    waiting.fetch_sub(1, Ordering::Release);
    note_holder(l, file, line);
}

/// Free to held-by-a-writer, or nothing.
fn try_take(l: &wrlock_t) -> bool {
    l.val().compare_exchange(0, -1, Ordering::Acquire, Ordering::Relaxed).is_ok()
}

/// Take it for writing if it is free. False if it is not.
///
/// Safe for [`read_lock`]'s reason.
pub fn write_trylock_at(l: &wrlock_t, file: &'static str, line: u32) -> bool {
    if !try_take(l) {
        return false;
    }
    note_holder(l, file, line);
    true
}

/// Give the write side back.
///
/// # Safety
/// This thread holds `l` for writing.
pub unsafe fn write_unlock(l: &wrlock_t) {
    l.set_writer(None);
    let was = l.val().swap(0, Ordering::SeqCst);
    debug_assert_eq!(was, -1, "a write unlock of a lock no writer holds");
    // See `park_while_written` for why this read cannot miss a sleeper.
    if l.sleepers().load(Ordering::SeqCst) != 0 {
        let (park, wake) = l.parking();
        let _held = park.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        wake.notify_all();
    }
}

/// `write_wrlock!(l)` — take `l` for writing, recording this call site.
///
/// `util/sync.h`'s macro of the same name, restored on 2026-09-16 for the
/// reason it was one: a function cannot see its caller's `__FILE__` and
/// `__LINE__`, and `file!()`/`line!()` are what those were. See
/// [`wrlock::write_lock_at`](crate::wrlock::write_lock_at) for what stood in
/// for it in between.
///
/// The `\0` is what makes the recorded name readable as a C string, as in
/// [`lock!`](crate::lock).
#[macro_export]
macro_rules! write_wrlock {
    ($l:expr) => {
        $crate::wrlock::write_lock_at($l, concat!(file!(), "\0"), line!())
    };
}

/// The write side, held for a scope; built by [`write_tryguard!`]. `!Send`
/// for [`crate::mutex::Guard`]'s reason.
#[must_use = "dropping it releases the lock"]
pub struct WriteGuard<'a>(&'a wrlock_t, core::marker::PhantomData<*const ()>);

impl<'a> WriteGuard<'a> {
    /// See [`write_tryguard!`]. An `if`, for the reason `mutex::Guard`'s is.
    pub fn try_take_at(l: &'a wrlock_t, file: &'static str, line: u32) -> Option<WriteGuard<'a>> {
        if write_trylock_at(l, file, line) {
            Some(WriteGuard(l, core::marker::PhantomData))
        } else {
            None
        }
    }
}

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: a `WriteGuard` exists only while this thread holds the write
        // side.
        unsafe { write_unlock(self.0) };
    }
}

/// `write_tryguard!(l)` -- the write side of `l` for a scope if it is free.
#[macro_export]
macro_rules! write_tryguard {
    ($l:expr) => {
        $crate::wrlock::WriteGuard::try_take_at($l, concat!(file!(), "\0"), line!())
    };
}

/// `write_trywrlock!(l)` — take `l` for writing if it is free, recording this
/// call site.
#[macro_export]
macro_rules! write_trywrlock {
    ($l:expr) => {
        $crate::wrlock::write_trylock_at($l, concat!(file!(), "\0"), line!())
    };
}
