//! What a descriptor pokes to wake a transient poll set.
//!
//! A set is built, waited on and destroyed inside one syscall on one thread, so
//! the set itself needs no lock. The waiter is the one piece that crosses
//! threads: whoever makes a descriptor ready calls [`Watchers::notify`] from
//! their own thread, and that has to reach a thread sitting in `poll(2)`.
//!
//! Waking it means writing a byte to a pipe the sleeping thread is polling.
//! There is no cheaper portable answer — Darwin has no eventfd, and signalling
//! a condition variable cannot interrupt a host `poll()`.

use std::cell::Cell;
use std::ffi::c_int;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

/// The wake channel for one transient poll set.
///
/// The pipe is attached only while a thread is actually waiting:
/// [`Waiter::acquire`] takes one and [`Waiter::release`] gives it back. A notify
/// that arrives outside that window is dropped, which is correct because the
/// level scan at the top of every wait pass re-reads every member's readiness
/// anyway.
pub struct Waiter {
    pipe: Mutex<Pipe>,
}

struct Pipe {
    /// The read end and the write end, while a thread is waiting. `OwnedFd`s
    /// since 2026-09-29: they were two `c_int`s set to -1 in between, and a
    /// `close_fd` that refused 0, 1 and 2 in case a pipe end had "mistakenly
    /// been recorded as one" -- a guard for a value the type now cannot hold.
    ends: Option<Ends>,
    /// One transient set has one waiting thread today. Counted rather than
    /// flagged so that release stays correct if that ever stops being true —
    /// the group-exit safety valve already releases out of band.
    waiters: usize,
    /// Whether a wake byte is already in the pipe. A second notify would only
    /// say what the first one says, and the reader learns nothing from the
    /// count: what a wake *means* is decided by rescanning the members. So the
    /// second write is skipped, and the drain that follows a wake is skipped
    /// when nothing was written.
    pending: bool,
}

/// A pipe's two ends, read then write.
type Ends = (OwnedFd, OwnedFd);

fn drain_fd(fd: &OwnedFd) {
    let mut bytes = [0u8; 256];
    while matches!(rustix::io::read(fd, &mut bytes), Ok(n) if n > 0) {}
}

/// A nonblocking pipe, kept by the thread that last used one.
///
/// Every `poll()` and `select()` needs a wake channel and none of them needs a
/// *new* one: a thread waits on at most one transient set at a time, so the
/// pipe it used last is free by the time it makes the next call. Creating one
/// per call cost five host syscalls — `pipe`, two `fcntl`, two `close` — on
/// every `poll()` a guest made, including the very common one that finds a
/// descriptor ready and never waits at all. At one descriptor that was most of
/// what the call cost.
///
/// The cache holds one pair per thread, so its cost is bounded by the number of
/// threads that have ever polled rather than by anything a guest can drive.
struct Spare(Cell<Option<Ends>>);

thread_local! {
    static SPARE: Spare = const { Spare(Cell::new(None)) };
}

/// A pipe with both ends nonblocking, from this thread's cache or the host.
///
/// `map_errno` reads the host `errno`, so it is called straight after the call
/// that failed; what was made closes as it drops, after.
fn take_pipe(map_errno: impl FnOnce() -> c_int) -> Result<Ends, c_int> {
    if let Ok(Some(pair)) = SPARE.try_with(|spare| spare.0.take()) {
        return Ok(pair);
    }
    let Ok(pair) = rustix::pipe::pipe() else {
        return Err(map_errno());
    };
    for fd in [&pair.0, &pair.1] {
        // A wake that blocks is a wake that deadlocks: the writer is whoever
        // made the descriptor ready, and it may be the same thread that would
        // have to drain the pipe.
        let set = rustix::fs::fcntl_getfl(fd)
            .and_then(|flags| rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK));
        if set.is_err() {
            return Err(map_errno());
        }
    }
    Ok(pair)
}

/// Hand an empty pipe back for this thread's next wait.
fn give_pipe(pair: Ends) {
    // Whatever was in the slot is closed instead, as it drops — only reachable
    // if a thread ever waits on two sets at once, and one cached pair is enough
    // either way. Past this thread's teardown the slot is gone and the pair
    // closes here.
    let _ = SPARE.try_with(|spare| spare.0.replace(Some(pair)));
}

impl Waiter {
    pub fn new() -> Arc<Waiter> {
        Arc::new(Waiter {
            pipe: Mutex::new(Pipe {
                ends: None,
                waiters: 0,
                pending: false,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Pipe> {
        self.pipe
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Claim the wake channel, attaching a pipe for the first waiter.
    ///
    /// `map_errno` turns the host failure into the guest errno the syscall
    /// should answer with; it is the caller's because mapping `EPIPE` raises a
    /// guest signal, which only the task layer can do.
    pub fn acquire(&self, map_errno: impl FnOnce() -> c_int) -> c_int {
        let mut pipe = self.lock();
        pipe.waiters += 1;
        if pipe.waiters != 1 {
            return 0;
        }
        match take_pipe(map_errno) {
            Ok(ends) => {
                pipe.ends = Some(ends);
                pipe.pending = false;
                0
            }
            Err(error) => {
                pipe.waiters -= 1;
                error
            }
        }
    }

    /// Give up this thread's claim. The last one hands the pipe back, empty.
    pub fn release(&self) {
        let mut pipe = self.lock();
        if pipe.waiters == 0 {
            return;
        }
        pipe.waiters -= 1;
        if pipe.waiters != 0 {
            return;
        }
        // Empty before it is reused: a byte left behind would make the next
        // wait on this thread return at once for a readiness that is gone.
        // Only when one was written, which the common case is not.
        if pipe.pending
            && let Some((read, _)) = &pipe.ends
        {
            drain_fd(read);
        }
        pipe.pending = false;
        let ends = pipe.ends.take();
        drop(pipe);
        if let Some(ends) = ends {
            give_pipe(ends);
        }
    }

    /// Make the waiting thread's host `poll()` return.
    ///
    /// Under the mutex on purpose: without it a concurrent [`Waiter::release`]
    /// could take the descriptor away between the read of the field and the
    /// write, and the host may already have handed that number to something
    /// else.
    pub fn notify(&self) {
        let mut pipe = self.lock();
        let Some((_, write)) = &pipe.ends else {
            return;
        };
        if pipe.pending {
            return;
        }
        if rustix::io::write(write, &[0]) == Ok(1) {
            pipe.pending = true;
        }
    }

    /// Consume every pending wake. Bytes carry no information: what a wake
    /// means is decided by rescanning the members.
    pub fn drain(&self) {
        let mut pipe = self.lock();
        if !pipe.pending {
            return;
        }
        if let Some((read, _)) = &pipe.ends {
            drain_fd(read);
        }
        pipe.pending = false;
    }

    /// The read end's number for a host `poll`, or -1 with no thread waiting.
    pub fn read_fd(&self) -> c_int {
        self.lock().ends.as_ref().map_or(-1, |(read, _)| read.as_raw_fd())
    }
}

/// Everything watching one open file description for readiness.
///
/// This is the whole reverse edge, and there is one of it. It used to be an
/// intrusive C list of per-registration nodes linked into both the description
/// and the object waiting on it, so whichever tore down second found the node
/// freed and the loser of that race retried under `sched_yield`. There were two
/// such lists — one for `poll()`/`select()` and one for epoll — with a
/// descriptor lock ordering them against each other.
///
/// Here the description holds an `Arc` of this list and so does everything
/// registered in it, so neither side can free what the other is walking, in
/// either order. A transient set holds its wake channel strongly, because the
/// set cannot outlive the syscall that made it; a durable watcher — epoll — is
/// held weakly, because it outlives the wait that registered it and a set that
/// is going away should simply stop upgrading.
#[derive(Default)]
pub struct Watchers {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// One per transient `poll()`/`select()` set waiting on this description.
    waiters: Vec<Arc<Waiter>>,
    /// One per durable watcher, with the key that watcher knows this
    /// description by.
    watchers: Vec<(Weak<dyn Watcher>, u64)>,
}

/// Something that outlives the wait that registered it — epoll, today.
///
/// The trait is here rather than in `crates/kernel/epoll` so that the reverse
/// edge does not have to know what an epoll is: a description holds watchers,
/// and epoll is one kind. Both methods are called with this list's mutex held
/// and must not take a lock that is taken before it.
pub trait Watcher: Send + Sync {
    /// The description became ready. `key` is what the watcher registered it
    /// under.
    fn notify(&self, key: u64, events: u32);
    /// The description is gone. Everything the watcher holds naming it should
    /// go with it.
    fn detach(&self, key: u64);
}

impl Watchers {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Register one transient set. False only if the list could not grow.
    pub fn add_waiter(&self, waiter: &Arc<Waiter>) -> bool {
        let mut inner = self.lock();
        if inner.waiters.try_reserve(1).is_err() {
            return false;
        }
        inner.waiters.push(Arc::clone(waiter));
        true
    }

    /// Remove one registration of `waiter`. A descriptor named twice in one
    /// `poll()` is registered once — `crates/fs/pollindex` merges those — but a
    /// descriptor may legitimately appear in two sets on two threads, so this
    /// removes one entry rather than all of them.
    pub fn remove_waiter(&self, waiter: &Arc<Waiter>) {
        let mut inner = self.lock();
        if let Some(index) = inner
            .waiters
            .iter()
            .position(|other| Arc::ptr_eq(other, waiter))
        {
            inner.waiters.swap_remove(index);
        }
    }

    /// Hold the list locked while a watcher does the work that decides what to
    /// register.
    ///
    /// This exists because of the lock order: a watcher's own state is taken
    /// *inside* this list, and epoll only learns the key it wants to register
    /// under from inside its own state. Reserving the entry before that work
    /// starts and filling it in afterwards is what lets the registration be
    /// infallible once the work is committed, without ever taking the two locks
    /// the wrong way round.
    pub fn watchers_locked(&self) -> Locked<'_> {
        Locked { inner: self.lock() }
    }

    /// Drop the claims of watchers that are already gone.
    ///
    /// A watcher being *dropped* cannot name itself — there is no `Arc` left to
    /// make a `Weak` from — so its destructor asks each list it was registered
    /// in to reclaim whatever no longer upgrades. Nothing else can be in that
    /// state: a live watcher holds an `Arc` of itself through whatever owns it.
    pub fn drop_dead_watchers(&self) {
        self.lock()
            .watchers
            .retain(|(watcher, _)| watcher.strong_count() != 0);
    }

    /// Publish a readiness transition to everything watching this description.
    ///
    /// Lock order is this list, then whatever a watcher takes — the waiter's
    /// pipe, or an epoll's own state. Nothing takes them the other way round.
    /// The one rule a caller must keep is stated on `poll_wakeup`: not while
    /// holding a lock this description's own poll operation takes, because a
    /// watcher may ask for that.
    pub fn notify(&self, events: u32) {
        let inner = self.lock();
        for waiter in inner.waiters.iter() {
            waiter.notify();
        }
        for (watcher, key) in inner.watchers.iter() {
            // A watcher that is being dropped stops upgrading here, which is
            // the whole reason this half of the list is weak.
            if let Some(watcher) = watcher.upgrade() {
                watcher.notify(*key, events);
            }
        }
    }

    /// The description is closing. Every durable watcher loses what it holds
    /// naming it; the transient sets need nothing, because each holds its wake
    /// channel and will find the descriptor gone on its next pass.
    pub fn closed(&self) {
        // Taken out first and acted on after the mutex is released: `detach`
        // reaches a watcher's own teardown, which may need locks that are taken
        // before this one. Nothing can register again — the description has no
        // references left.
        let watchers = std::mem::take(&mut self.lock().watchers);
        for (watcher, key) in watchers {
            if let Some(watcher) = watcher.upgrade() {
                watcher.detach(key);
            }
        }
    }

    /// How many transient sets are waiting on this description.
    pub fn waiters(&self) -> usize {
        self.lock().waiters.len()
    }
}

/// The list, held. See [`Watchers::watchers_locked`].
pub struct Locked<'a> {
    inner: MutexGuard<'a, Inner>,
}

impl Locked<'_> {
    /// Make room for `watcher`, without publishing it. False only if the list
    /// could not grow, in which case nothing has changed.
    pub fn reserve(&mut self, watcher: &Arc<dyn Watcher>) -> bool {
        let weak = Arc::downgrade(watcher);
        if self
            .inner
            .watchers
            .iter()
            .any(|(existing, _)| weak_eq(existing, &weak))
        {
            return true;
        }
        self.inner.watchers.try_reserve(1).is_ok()
    }

    /// Publish `watcher` under `key`, or update the key it already has. Only
    /// valid after a [`Locked::reserve`] that answered true, on the same guard.
    pub fn commit(&mut self, watcher: &Arc<dyn Watcher>, key: u64) {
        let weak = Arc::downgrade(watcher);
        if let Some(entry) = self
            .inner
            .watchers
            .iter_mut()
            .find(|(existing, _)| weak_eq(existing, &weak))
        {
            entry.1 = key;
            return;
        }
        self.inner.watchers.push((weak, key));
    }

    /// Drop one watcher's claim, and any claim whose watcher is already gone.
    pub fn remove(&mut self, watcher: &Arc<dyn Watcher>) {
        let weak = Arc::downgrade(watcher);
        self.inner
            .watchers
            .retain(|(existing, _)| existing.strong_count() != 0 && !weak_eq(existing, &weak));
    }

    /// How many durable watchers are registered, live or not yet reclaimed.
    pub fn len(&self) -> usize {
        self.inner.watchers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A set of descriptions that are woken together.
///
/// A terminal has one: every descriptor open on it becomes readable at the same
/// moment, and until this existed the terminal kept a list of `struct fd *` and
/// a lock of its own to walk it. Holding the descriptions' reverse edges
/// instead means the walk needs no descriptor pointers and no descriptor lock,
/// and a description that closes while the walk is running is not a problem —
/// each entry is a strong reference to a list that outlives its description.
#[derive(Default)]
pub struct WakeSet {
    members: Mutex<Vec<Arc<Watchers>>>,
}

impl WakeSet {
    fn lock(&self) -> MutexGuard<'_, Vec<Arc<Watchers>>> {
        self.members
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// False only if the set could not grow.
    pub fn add(&self, watchers: &Arc<Watchers>) -> bool {
        let mut members = self.lock();
        if members.try_reserve(1).is_err() {
            return false;
        }
        members.push(Arc::clone(watchers));
        true
    }

    /// Remove one membership. One description may be in the set once per open,
    /// so this removes one entry rather than all of them.
    pub fn remove(&self, watchers: &Arc<Watchers>) {
        let mut members = self.lock();
        if let Some(index) = members
            .iter()
            .position(|other| Arc::ptr_eq(other, watchers))
        {
            members.swap_remove(index);
        }
    }

    /// Wake every description in the set.
    ///
    /// The members are taken out from under this set's mutex before any of
    /// them is notified: notifying reaches a watcher's own state, and holding
    /// two locks here would put this set into an order it does not otherwise
    /// appear in. The clones are the point of the `Arc`s.
    pub fn notify(&self, events: u32) {
        let members: Vec<Arc<Watchers>> = self.lock().clone();
        for watchers in members {
            watchers.notify(events);
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// `Weak::ptr_eq` compares fat pointers including the vtable, and two
/// `Arc<dyn Watcher>` made from the same object can carry different vtable
/// addresses across codegen units. The data half is the identity.
fn weak_eq(a: &Weak<dyn Watcher>, b: &Weak<dyn Watcher>) -> bool {
    std::ptr::eq(a.as_ptr().cast::<()>(), b.as_ptr().cast::<()>())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_errno() -> c_int {
        -5
    }

    #[test]
    fn the_pipe_exists_only_while_a_thread_is_waiting() {
        let waiter = Waiter::new();
        assert_eq!(waiter.read_fd(), -1);
        assert_eq!(waiter.acquire(no_errno), 0);
        let read = waiter.read_fd();
        assert!(read >= 0);
        waiter.release();
        assert_eq!(waiter.read_fd(), -1);
    }

    #[test]
    fn two_claims_share_one_pipe_and_the_last_release_closes_it() {
        let waiter = Waiter::new();
        assert_eq!(waiter.acquire(no_errno), 0);
        let read = waiter.read_fd();
        assert_eq!(waiter.acquire(no_errno), 0);
        assert_eq!(waiter.read_fd(), read);
        waiter.release();
        assert_eq!(waiter.read_fd(), read);
        waiter.release();
        assert_eq!(waiter.read_fd(), -1);
    }

    #[test]
    fn a_notify_outside_a_wait_is_dropped_rather_than_queued() {
        let waiter = Waiter::new();
        waiter.notify();
        waiter.drain();
        assert_eq!(waiter.acquire(no_errno), 0);
        assert!(!readable(waiter.read_fd()));
        waiter.release();
    }

    #[test]
    fn a_notify_during_a_wait_makes_the_read_end_readable_until_drained() {
        let waiter = Waiter::new();
        assert_eq!(waiter.acquire(no_errno), 0);
        waiter.notify();
        assert!(readable(waiter.read_fd()));
        waiter.drain();
        assert!(!readable(waiter.read_fd()));
        waiter.release();
    }

    #[test]
    fn a_descriptor_wakes_every_set_watching_it() {
        let waiters = Watchers::default();
        let first = Waiter::new();
        let second = Waiter::new();
        assert!(waiters.add_waiter(&first));
        assert!(waiters.add_waiter(&second));
        assert_eq!(first.acquire(no_errno), 0);
        assert_eq!(second.acquire(no_errno), 0);
        waiters.notify(1);
        for waiter in [&first, &second] {
            assert!(readable(waiter.read_fd()));
            waiter.release();
        }
    }

    #[test]
    fn removing_one_set_leaves_the_other_registered() {
        let waiters = Watchers::default();
        let first = Waiter::new();
        let second = Waiter::new();
        assert!(waiters.add_waiter(&first));
        assert!(waiters.add_waiter(&second));
        waiters.remove_waiter(&first);
        assert_eq!(waiters.waiters(), 1);
        waiters.remove_waiter(&first);
        assert_eq!(waiters.waiters(), 1);
        waiters.remove_waiter(&second);
        assert_eq!(waiters.waiters(), 0);
    }

    /// Whether a wait on `fd` would wake now.
    fn readable(fd: c_int) -> bool {
        let mut probe = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live `pollfd`.
        unsafe { libc::poll(&mut probe, 1, 0) == 1 }
    }

    /// How many bytes one read of `fd` takes, up to two.
    fn read_some(fd: c_int) -> isize {
        let mut byte = [0u8; 2];
        // SAFETY: `byte` is two writable bytes.
        unsafe { libc::read(fd, byte.as_mut_ptr().cast(), byte.len()) }
    }

    #[test]
    fn the_thread_keeps_its_pipe_between_waits() {
        let first = Waiter::new();
        assert_eq!(first.acquire(no_errno), 0);
        let fd = first.read_fd();
        first.release();
        let second = Waiter::new();
        assert_eq!(second.acquire(no_errno), 0);
        assert_eq!(second.read_fd(), fd, "the second wait made a new pipe");
        second.release();
    }

    #[test]
    fn a_wake_left_behind_does_not_reach_the_next_wait() {
        let first = Waiter::new();
        assert_eq!(first.acquire(no_errno), 0);
        // A notify that lands just as the wait gives up, and is never drained.
        first.notify();
        assert!(readable(first.read_fd()));
        first.release();
        let second = Waiter::new();
        assert_eq!(second.acquire(no_errno), 0);
        assert!(
            !readable(second.read_fd()),
            "the next wait started already awake"
        );
        second.release();
    }

    #[test]
    fn repeated_wakes_write_one_byte_until_the_waiter_drains() {
        let waiter = Waiter::new();
        assert_eq!(waiter.acquire(no_errno), 0);
        // More than a pipe holds. Every one of them says the same thing, so
        // only the first is written; without that this fills and then fails.
        for _ in 0..200_000 {
            waiter.notify();
        }
        assert_eq!(read_some(waiter.read_fd()), 1);
        waiter.drain();
        assert!(!readable(waiter.read_fd()));
        waiter.notify();
        assert!(readable(waiter.read_fd()), "a wake after a drain was lost");
        waiter.drain();
        waiter.release();
    }

    #[test]
    fn a_wake_set_reaches_every_description_in_it() {
        let set = WakeSet::default();
        let first = Arc::new(Watchers::default());
        let second = Arc::new(Watchers::default());
        assert!(set.add(&first));
        assert!(set.add(&second));
        let waiter = Waiter::new();
        assert!(first.add_waiter(&waiter));
        assert!(second.add_waiter(&waiter));
        assert_eq!(waiter.acquire(no_errno), 0);
        set.notify(1);
        assert!(readable(waiter.read_fd()));
        waiter.drain();
        // Removing one leaves the other, and one description may be in the set
        // once per open.
        set.remove(&first);
        assert_eq!(set.len(), 1);
        set.remove(&first);
        assert_eq!(set.len(), 1);
        set.remove(&second);
        assert!(set.is_empty());
        set.notify(1);
        assert!(!readable(waiter.read_fd()));
        waiter.release();
    }

    #[test]
    fn a_wake_set_outlives_a_description_that_closes() {
        let set = WakeSet::default();
        {
            let watchers = Arc::new(Watchers::default());
            assert!(set.add(&watchers));
        }
        // The description is gone and the set still holds its list, which is
        // what makes the walk need no descriptor lock.
        set.notify(1);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn a_set_outlives_the_descriptor_it_registered_on() {
        let waiter = Waiter::new();
        {
            let waiters = Watchers::default();
            assert!(waiters.add_waiter(&waiter));
        }
        // The descriptor is gone and the set is still usable: nothing about the
        // wake channel belonged to the descriptor.
        assert_eq!(waiter.acquire(no_errno), 0);
        waiter.notify();
        waiter.drain();
        waiter.release();
    }
}
