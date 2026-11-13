//! `pidfd`: a descriptor that names a process, and the registry that finds one.
//!
//! The point of a pidfd is that it names a process without the race a pid has:
//! a pid can be reused between looking it up and signalling it, and a pidfd
//! cannot. `poll` on one becomes readable when the process ends.
//!
//! # The registry was a list, and every exit walked all of it
//!
//! Every live pidfd was on one intrusive list, and `pidfd_notify_exit(pid)`
//! walked the whole thing on **every process exit** comparing pids. That is
//! O(open pidfds) per exit, for a lookup that is keyed by pid — a build that
//! spawns a thousand processes while holding a hundred pidfds does a hundred
//! thousand comparisons to deliver a hundred wakeups.
//!
//! It is a map here, so an exit costs one lookup plus the number of descriptors
//! that actually name that pid. Nothing else changes: the same wakeup, in the
//! same order, under the same lock.
//!
//! # The exit flag is outside the lock on purpose
//!
//! `pidfd_poll` reads it lock-free, and must: `poll_wait` calls it with
//! `poll->lock` held, and the exit path takes `pids_lock` and then wakes pidfd
//! pollers, which takes `poll->lock`. A registry acquisition on the poll side
//! would close an ABBA cycle. So the flag lives in the descriptor's own state
//! and is published with a release store before the wakeup, which is what makes
//! a poll racing the wakeup still observe it.
//!
//! # A note for whoever runs `tools/lock-order.py`
//!
//! That analysis reads C. The lock below is Rust's and is invisible to it, so
//! the ordering it participates in is written down here instead: it is taken by
//! the exit path *inside* `pids_lock`. It calls out to nothing while held since
//! 2026-10-17 -- `poll_wakeup` runs after it is released -- so it is a leaf.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use kernel_pids::TaskRef;
use taskview::ffi;

/// `POLL_READ` from `fs/poll.h`.
pub const POLL_READ: i32 = 1;
/// `POLL_HUP`: what a pidfd whose task has been reaped adds.
pub const POLL_HUP: i32 = 16;

/// What has happened to the task a pidfd names, published by the exit path
/// and read lock-free by poll.
///
/// Two facts and not one, since 2026-11-11: Linux's `pidfd_poll` answers
/// `EPOLLIN` for a task that has exited and `EPOLLIN | EPOLLHUP` for one whose
/// `struct pid` no longer has a task -- reaped, or a thread, which is reaped
/// as it exits. A single "exited" flag could say only the first, so a poller
/// waiting for the pid to be free was never told.
#[derive(Default)]
struct Shared {
    /// [`EXITED`] and [`REAPED`].
    state: AtomicU8,
    /// The wait status recorded when the process became a zombie, for
    /// `PIDFD_INFO_EXIT`. Meaningful only with [`HAS_STATUS`] set.
    status: AtomicI32,
}

const EXITED: u8 = 1;
const REAPED: u8 = 2;
const HAS_STATUS: u8 = 4;

/// One pidfd's own state. Rust allocates it; C holds the pointer.
pub struct PidFd {
    /// The task, as a reference and not a number: a pidfd outlives the
    /// task it names, and the number is handed to another once that task is
    /// reaped. Linux's pidfd holds a `struct pid` for the same reason. The
    /// registry below is keyed by the number, because that is what an exit
    /// reports.
    pub target: TaskRef,
    /// `PIDFD_THREAD`: the descriptor names one thread, and is readable when
    /// that thread exits rather than when its whole process has.
    pub thread: bool,
    /// Shared with this pidfd's registry entry, which is how the exit path
    /// reaches it without a pointer back into this `Box`.
    shared: Arc<Shared>,
}

impl PidFd {
    /// Whether the named task has exited: the whole process for a process
    /// pidfd, the thread for a `PIDFD_THREAD` one. Lock-free, because
    /// `pidfd_poll` must not acquire the registry or poll locks.
    pub fn has_exited(&self) -> bool {
        self.shared.state.load(Ordering::Acquire) & EXITED != 0
    }

    /// Whether the task is gone altogether: reaped, or a thread that exited.
    pub fn is_reaped(&self) -> bool {
        self.shared.state.load(Ordering::Acquire) & REAPED != 0
    }

    /// The wait status, once the process has been reaped -- which is when
    /// Linux's `pidfs_exit` makes it available to `PIDFD_GET_INFO`, measured:
    /// a zombie's descriptor reports no `PIDFD_INFO_EXIT`, a reaped one's does.
    pub fn exit_status(&self) -> Option<i32> {
        let s = self.shared.state.load(Ordering::Acquire);
        (s & REAPED != 0 && s & HAS_STATUS != 0).then(|| self.shared.status.load(Ordering::Relaxed))
    }

    /// The poll bits this descriptor answers, as Linux's `pidfd_poll` does.
    pub fn poll_bits(&self) -> i32 {
        if self.is_reaped() {
            POLL_READ | POLL_HUP
        } else if self.has_exited() {
            POLL_READ
        } else {
            0
        }
    }
}

/// What an exit has to find: the flag to set, and the description to wake.
///
/// **Neither is a pointer since 2026-10-17.** `state` was a `NonNull<PidFd>`
/// into the descriptor's `Box` and `fd` an `ffi::FdId` borrowed back into the
/// description, under an `unsafe impl Send` and the argument that `PidFd::drop`
/// removes the entry under this lock. That held for the memory, not for the
/// borrow: the drop runs inside the description's finalizer, which `Drop for
/// fd` calls with a `&mut fd`, while an exit holding this lock could still be
/// lending a `&fd` of it to the wakeup. The flag is shared now and the
/// description is a `Weak` that a closing one does not upgrade.
struct Entry {
    shared: Arc<Shared>,
    /// Empty until [`Registration::attach`]: the description's `Arc` is
    /// built after its state, and a `Weak` taken before `NewFd::into_owned`
    /// would stop that from finding the description unshared.
    fd: Weak<ffi::fd>,
}

static REGISTRY: Mutex<Option<BTreeMap<i32, Vec<Entry>>>> = Mutex::new(None);

fn with_registry<R>(f: impl FnOnce(&mut BTreeMap<i32, Vec<Entry>>) -> R) -> R {
    let mut guard = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(BTreeMap::new))
}

/// Allocate a pidfd's state and put it in the registry, so that an exit from
/// here on sets its flag. [`PidFd::registration`] names the entry for
/// [`Registration::attach`], which gives it the description to wake.
///
/// `thread` is `PIDFD_THREAD`. A task that has already exited -- a zombie,
/// which `pidfd_open` accepts -- is not marked here; the caller says so with
/// [`PidFd::mark_exited`], because only it can see the task.
pub fn pidfd_new(target: TaskRef, thread: bool) -> Box<PidFd> {
    let shared = Arc::new(Shared::default());
    with_registry(|reg| {
        reg.entry(target.pid).or_default().push(Entry {
            shared: Arc::clone(&shared),
            fd: Weak::new(),
        })
    });
    Box::new(PidFd { target, thread, shared })
}

impl PidFd {
    /// The task had already exited when this descriptor was made: a zombie.
    /// Its exit was announced before the descriptor existed, so nothing else
    /// would set this.
    pub fn mark_exited(&self, status: i32) {
        self.shared.status.store(status, Ordering::Relaxed);
        self.shared.state.fetch_or(EXITED | HAS_STATUS, Ordering::Release);
    }
}

/// A pidfd's registry entry, kept by its maker while the state is moved into
/// the description.
pub struct Registration {
    pid: i32,
    shared: Arc<Shared>,
}

impl PidFd {
    pub fn registration(&self) -> Registration {
        Registration { pid: self.target.pid, shared: Arc::clone(&self.shared) }
    }
}

impl Registration {
    /// The description an exit wakes. Until this, an exit sets the flag and
    /// wakes nothing, which is right: nothing can be polling a pidfd that is
    /// not installed yet.
    pub fn attach(self, fd: Weak<ffi::fd>) {
        with_registry(|reg| {
            if let Some(e) = reg
                .get_mut(&self.pid)
                .and_then(|v| v.iter_mut().find(|e| Arc::ptr_eq(&e.shared, &self.shared)))
            {
                e.fd = fd;
            }
        });
    }
}

impl Drop for PidFd {
    fn drop(&mut self) {
        with_registry(|reg| {
            if let Some(v) = reg.get_mut(&self.target.pid) {
                v.retain(|e| !Arc::ptr_eq(&e.shared, &self.shared));
                // An empty vector is a pid nothing names any more. Left in place it
                // would make the map grow without bound in a process that opens and
                // closes pidfds for a long-running series of children.
                if v.is_empty() {
                    reg.remove(&self.target.pid);
                }
            }
        });
    }
}

/// The wakeup, installed by `crates/kernel/pidfdcalls` when it makes the first
/// pidfd.
///
/// # Why the indirection
///
/// The exit path is what has the news and the descriptor layer is what wants
/// it, so the direct call went `kernel-exitcalls` -> `kernel-pidfdcalls` ->
/// `fs-poll` -> `kernel-exitcalls`: a cycle, and a cycle because the middle
/// crate is the *syscall* half of a pidfd while the object and the registry
/// are here. This crate is a leaf, so the hook lives here and the crate that
/// owns the descriptors installs it.
///
/// Nothing is installed until the first `pidfd_open`, and nothing can be
/// registered before then, so an exit before that wakes nobody -- which is
/// what the registry lookup would have answered anyway.
static WAKE: OnceLock<fn(fd: &ffi::fd, types: i32)> = OnceLock::new();

/// Install the wakeup. The first call wins.
pub fn set_wake_hook(f: fn(fd: &ffi::fd, types: i32)) {
    let _ = WAKE.set(f);
}

/// A process has exited: its last thread is gone and it is a zombie with wait
/// status `status`. Every pidfd naming its pid -- the process's, and a
/// `PIDFD_THREAD` one on its leader -- becomes readable. Returns how many were
/// marked.
pub fn notify_exit(pid: i32, status: i32) -> i32 {
    pidfd_notify(pid, Some(status), EXITED, POLL_READ, WAKE.get().copied())
}

/// The task at `pid` is gone: reaped, or a thread that has exited, which is
/// reaped as it goes. Every pidfd naming it reads `POLL_READ | POLL_HUP` from
/// here on. Called from `task_destroy`, under `pids_lock`.
pub fn notify_gone(pid: i32) -> i32 {
    pidfd_notify(pid, None, EXITED | REAPED, POLL_READ | POLL_HUP, WAKE.get().copied())
}

/// Mark every pidfd naming `pid` with `bits` and wake its pollers with
/// `events`.
///
/// Returns how many were marked. The flags are set under the registry lock;
/// `wake` (`poll_wakeup`) runs after it is released, on descriptions upgraded
/// under it, and they are dropped last: one can be the last reference, and its
/// close takes this lock in `PidFd::drop`.
pub(crate) fn pidfd_notify(
    pid: i32,
    status: Option<i32>,
    bits: u8,
    events: i32,
    wake: Option<fn(fd: &ffi::fd, types: i32)>,
) -> i32 {
    let (marked, to_wake) = with_registry(|reg| {
        let Some(entries) = reg.get(&pid) else {
            return (0, Vec::new());
        };
        for e in entries {
            let mut bits = bits;
            if let Some(status) = status {
                e.shared.status.store(status, Ordering::Relaxed);
                bits |= HAS_STATUS;
            }
            // Published before the wakeup, so a poll that races it still sees
            // the bits.
            e.shared.state.fetch_or(bits, Ordering::Release);
        }
        let to_wake: Vec<Arc<ffi::fd>> = entries.iter().filter_map(|e| e.fd.upgrade()).collect();
        (entries.len() as i32, to_wake)
    });
    if let Some(w) = wake {
        for fd in &to_wake {
            w(fd, events);
        }
    }
    drop(to_wake);
    marked
}

/// The process-exit marking with an explicit hook, for the tests.
#[cfg(test)]
fn pidfd_notify_exit(pid: i32, wake: Option<fn(fd: &ffi::fd, types: i32)>) -> i32 {
    pidfd_notify(pid, Some(0), EXITED, POLL_READ, wake)
}

/// How many pidfds are registered. For the leak check in
/// `tests/guest/src/bin/eventfd_leak.rs`'s sibling; see /proc/iul/objects.
pub fn pidfd_live_count() -> i64 {
    with_registry(|reg| reg.values().map(|v| v.len() as i64).sum())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicI64;

    static WOKEN: AtomicI64 = AtomicI64::new(0);
    fn count_wake(_fd: &ffi::fd, _types: i32) {
        WOKEN.fetch_add(1, Ordering::Relaxed);
    }

    /// A descriptor the test owns.
    ///
    /// It was `std::ptr::dangling_mut::<ffi::fd>()` at every call below, which
    /// worked because `count_wake` ignores its argument — a test that depended
    /// on nobody dereferencing what it passed. An entry holds a `Weak` of it
    /// now, so it is a real `Arc`, one per test.
    fn descriptor() -> Arc<ffi::fd> {
        Arc::new(ffi::fd::default())
    }

    /// `pidfd_open`'s order: the state, then the description it wakes.
    fn open(target: TaskRef, fd: &Arc<ffi::fd>) -> Box<PidFd> {
        let state = pidfd_new(target, false);
        state.registration().attach(Arc::downgrade(fd));
        state
    }

    /// A reference to a process at `pid`; the generation does not matter
    /// here, since the registry is keyed by the number.
    fn named(pid: i32) -> TaskRef {
        TaskRef { pid, generation: 1 }
    }

    /// The whole registry, emptied, so the tests below do not see each other's
    /// entries. They run in one process and the registry is global.
    ///
    /// Only the entries: each state is the test's own `Box` since `pidfd_new`
    /// answers one, and its `drop` finds nothing to unlink. This freed the
    /// states too while they were leaked raw pointers.
    fn reset() {
        with_registry(BTreeMap::clear);
        WOKEN.store(0, Ordering::Relaxed);
    }

    #[test]
    fn an_exit_wakes_only_the_descriptors_that_name_it() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let (fa, fb, fc) = (descriptor(), descriptor(), descriptor());
        let a = open(named(100), &fa);
        let b = open(named(100), &fb);
        let c = open(named(200), &fc);

        let woken = pidfd_notify_exit(100, Some(count_wake));
        assert_eq!(woken, 2, "both descriptors naming 100");
        assert_eq!(WOKEN.load(Ordering::Relaxed), 2);
        assert!(a.has_exited());
        assert!(b.has_exited());
        assert!(!c.has_exited(), "200 has not exited");
        reset();
    }

    #[test]
    fn an_exit_nobody_named_wakes_nothing() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let f = descriptor();
        let _a = open(named(100), &f);
        assert_eq!(pidfd_notify_exit(999, Some(count_wake)), 0);
        assert_eq!(WOKEN.load(Ordering::Relaxed), 0);
        reset();
    }

    #[test]
    fn closing_removes_it_and_a_later_exit_finds_nothing() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let f = descriptor();
        let a = open(named(100), &f);
        assert_eq!(pidfd_live_count(), 1);
        drop(a);
        assert_eq!(pidfd_live_count(), 0);
        assert_eq!(pidfd_notify_exit(100, Some(count_wake)), 0);
        reset();
    }

    /// A pid whose last descriptor went must not leave an empty vector behind:
    /// a process that opens and closes a pidfd per child would otherwise grow
    /// the map by one entry per child, for ever.
    #[test]
    fn the_map_does_not_grow_without_bound() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        for pid in 0..500 {
            let f = descriptor();
            let s = open(named(pid), &f);
            drop(s);
        }
        let keys = with_registry(|reg| reg.len());
        assert_eq!(keys, 0, "{keys} pids left behind with no descriptors");
        reset();
    }

    /// Two descriptors on one pid, one closed: the other still hears.
    #[test]
    fn closing_one_of_two_leaves_the_other() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let (fa, fb) = (descriptor(), descriptor());
        let a = open(named(100), &fa);
        let b = open(named(100), &fb);
        drop(a);
        assert_eq!(pidfd_notify_exit(100, Some(count_wake)), 1);
        assert!(b.has_exited());
        reset();
    }

    /// A description whose last reference has gone is closing: its flag is
    /// still set, and it is not woken.
    #[test]
    fn a_closing_description_is_marked_and_not_woken() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let f = descriptor();
        let a = open(named(100), &f);
        drop(f);
        assert_eq!(pidfd_notify_exit(100, Some(count_wake)), 1);
        assert_eq!(WOKEN.load(Ordering::Relaxed), 0);
        assert!(a.has_exited());
        reset();
    }

    /// The wakeup runs after the registry lock is released: what it reaches
    /// can be a close, and a close takes that lock. This hung while the
    /// wakeup ran under it.
    #[test]
    fn the_wakeup_runs_outside_the_registry_lock() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        fn reenter(_fd: &ffi::fd, _types: i32) {
            WOKEN.fetch_add(pidfd_live_count(), Ordering::Relaxed);
        }
        let f = descriptor();
        let _a = open(named(100), &f);
        assert_eq!(pidfd_notify_exit(100, Some(reenter)), 1);
        assert_eq!(WOKEN.load(Ordering::Relaxed), 1);
        reset();
    }

    /// Exit makes a descriptor readable; being reaped adds `POLL_HUP` and is
    /// when the status becomes visible, which is Linux's order: a zombie's
    /// `PIDFD_GET_INFO` has no exit code and a reaped one's does.
    #[test]
    fn reaping_adds_hup_and_publishes_the_status() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let f = descriptor();
        let a = open(named(300), &f);
        assert_eq!(a.poll_bits(), 0);
        assert_eq!(pidfd_notify(300, Some(0x2a00), EXITED, POLL_READ, Some(count_wake)), 1);
        assert_eq!(a.poll_bits(), POLL_READ);
        assert_eq!(a.exit_status(), None, "a zombie's status is not reported");
        assert_eq!(pidfd_notify(300, None, EXITED | REAPED, POLL_READ | POLL_HUP, Some(count_wake)), 1);
        assert_eq!(a.poll_bits(), POLL_READ | POLL_HUP);
        assert_eq!(a.exit_status(), Some(0x2a00));
        reset();
    }

    /// A thread is reaped as it exits, with no zombie step and no status.
    #[test]
    fn a_thread_goes_straight_to_gone() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let f = descriptor();
        let state = pidfd_new(named(301), true);
        state.registration().attach(Arc::downgrade(&f));
        assert!(state.thread);
        pidfd_notify(301, None, EXITED | REAPED, POLL_READ | POLL_HUP, None);
        assert_eq!(state.poll_bits(), POLL_READ | POLL_HUP);
        assert_eq!(state.exit_status(), None);
        reset();
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());
}
