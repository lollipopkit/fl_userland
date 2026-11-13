//! Futex identity and wait queue model.
//!
//! # One queue, three kinds of waiter
//!
//! - a **plain** waiter is `FUTEX_WAIT`, `futex_wait` or `futex_waitv`, parked
//!   on one or more [`Entry`]s and woken by whichever matches first;
//! - a **PI** waiter is `FUTEX_LOCK_PI`, parked behind an owner it named, and
//!   handed the lock by the owner's `FUTEX_UNLOCK_PI` rather than woken to race
//!   for it;
//! - a **requeue-PI** waiter is `FUTEX_WAIT_REQUEUE_PI`: plain on the condition
//!   word until `FUTEX_CMP_REQUEUE_PI` either locks the mutex on its behalf or
//!   turns it into a PI waiter on the mutex.
//!
//! Linux refuses to mix them on one word -- a `FUTEX_WAKE` that reaches a PI or
//! requeue-PI waiter answers `EINVAL` -- and so does this.
//!
//! # How a waiter learns what happened to it
//!
//! A waker never removes a waiter. It writes an [`Outcome`] into it, under the
//! lock, and broadcasts; the waiter reads its own outcome and leaves. So "wake
//! one" means one -- a second waker skips a waiter that already has an outcome
//! -- and `futex_waitv` learns *which* of its words woke it, which removal
//! could not tell it.
//!
//! # Priority inheritance is the handoff, not the priority
//!
//! This kernel has no priorities to inherit: every guest thread is a host
//! thread at the same priority. What a PI futex promises a caller that *is*
//! observable is ownership: the word holds the owner's tid, `FUTEX_UNLOCK_PI`
//! hands the lock to the oldest waiter by writing that waiter's tid (with
//! `FUTEX_WAITERS`) rather than releasing it, and a waiter whose owner died is
//! given the lock. That is what is implemented. Linux orders PI waiters by
//! priority and then FIFO; at one priority that is FIFO.
//!
//! # The owner dying
//!
//! A PI waiter sleeps until somebody hands it the lock, and the only somebody
//! is the owner. So an owner that exits holding the lock has to say so, which
//! is [`Table::owner_exited`]: it wakes the oldest PI waiter behind it with
//! [`Outcome::OwnerGone`], and that waiter takes the lock over in its own
//! address space -- the dying thread may not have the waiter's, for a shared
//! futex.
//!
//! The race is the waiter that looked the owner up, found it alive, and
//! enqueues after the owner's notice went past. The lookup cannot be done under
//! this lock (it takes `pids_lock`, which the stall diagnostic holds while it
//! asks this table how many are parked), so the notice bumps an epoch under the
//! lock, and a waiter that saw a different epoch before its lookup looks again.

use std::ffi::c_int;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use util_guestlock::{GuestGuard, GuestLock, Woke};

use crate::{EAGAIN, EDEADLK, EFAULT, EINTR, EINVAL, ENOMEM, EPERM, ESRCH, ETIMEDOUT};

/// One address in one address space.
///
/// The address space is part of it because two processes can have the same
/// guest address mapped to different memory.
///
/// A **shared** futex — one without `FUTEX_PRIVATE_FLAG` — is not that. A
/// `MAP_SHARED` page survives `fork` uncopied, so one word is seen by two
/// processes with two different `struct mem`, and keying on the pair makes it
/// two futexes that cannot wake each other. Every `PTHREAD_PROCESS_SHARED`
/// mutex and every `sem_t` in shared memory is that shape, and a
/// `FUTEX_WAKE` from the other process was lost until 2026-08-31 —
/// `tests/guest/src/bin/futex_shared.rs` is what says so, and a real kernel
/// answers it.
///
/// So `space` is the address space for a private futex and **zero** for a
/// shared one, whose `addr` is the *host* address instead: the same host
/// memory reached from either process is the same number. That is the identity
/// Linux uses, by a different route — it keys on the inode and offset, or on
/// the physical page.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Key {
    /// The address space, or 0 for a futex keyed on the page.
    pub space: usize,
    /// The guest address for a private futex, the host address for a shared
    /// one. Never used to *read* the word — the caller closes over the guest
    /// address for that.
    pub addr: u64,
}

/// One word a waiter is parked on, and the bits it will be woken for.
///
/// `bitset` is `FUTEX_WAIT_BITSET`'s mask and futex2's `mask`; `!0` for a
/// plain wait, which is what Linux calls `FUTEX_BITSET_MATCH_ANY`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub key: Key,
    pub bitset: u32,
}

/// The PI futex word's three fields, as Linux's `futex.h` spells them.
pub const FUTEX_WAITERS: u32 = 0x8000_0000;
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
pub const FUTEX_TID_MASK: u32 = 0x3fff_ffff;

/// The PI futex word, as the caller reaches it. Called **with the queue
/// locked**, for the reason [`Table::wait_any`]'s `check` is.
pub trait PiWord {
    /// The word, or `None` when the address is not mapped.
    fn read(&self) -> Option<u32>;
    /// Compare-and-swap. `None` when the address is not mapped for writing,
    /// `Some(Err(actual))` when the word was not `old`.
    fn cmpxchg(&self, old: u32, new: u32) -> Option<Result<(), u32>>;
}

/// What a waker decided about a waiter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Outcome {
    /// Woken on this entry: `futex_waitv`'s answer.
    Woken(u32),
    /// The PI lock is this waiter's now; the word already says so.
    Handoff,
    /// The owner it was parked behind exited with the lock: take it over.
    OwnerGone(u32),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Plain,
    /// Parked behind `owner`, a tid, which [`Table::owner_exited`] matches.
    Pi { owner: u32 },
    /// `FUTEX_WAIT_REQUEUE_PI`, still on the condition word, bound for
    /// `target`.
    RequeuePi { target: Key },
}

/// One entry, or a `futex_waitv`'s many.
///
/// An enum so that the overwhelmingly common single wait allocates nothing.
enum Entries {
    One(Entry),
    Many(Box<[Entry]>),
}

impl Entries {
    fn as_slice(&self) -> &[Entry] {
        match self {
            Entries::One(e) => std::slice::from_ref(e),
            Entries::Many(v) => v,
        }
    }

    fn as_mut_slice(&mut self) -> &mut [Entry] {
        match self {
            Entries::One(e) => std::slice::from_mut(e),
            Entries::Many(v) => v,
        }
    }

    /// The index of the first entry on `key` whose bits overlap.
    fn matching(&self, key: Key, bitset: u32) -> Option<usize> {
        self.as_slice()
            .iter()
            .position(|e| e.key == key && e.bitset & bitset != 0)
    }

    fn on(&self, key: Key) -> bool {
        self.as_slice().iter().any(|e| e.key == key)
    }
}

/// A parked thread.
struct Waiter {
    id: u64,
    /// The guest tid, which a PI handoff writes into the word. 0 for a plain
    /// waiter, which never needs it.
    tid: u32,
    /// Changed by a requeue while this thread is asleep. It goes on waiting on
    /// the same condition, which is what makes a requeue a field assignment
    /// rather than a wakeup.
    entries: Entries,
    kind: Kind,
    /// Set by a waker, under the lock. A waiter with one is no longer waiting
    /// for anything and every other waker passes it by.
    outcome: Option<Outcome>,
}

impl Waiter {
    fn pending(&self) -> bool {
        self.outcome.is_none()
    }
}

#[derive(Default)]
struct Queue {
    /// Oldest first, which is the order `FUTEX_WAKE` takes them in: Linux wakes
    /// the longest-waiting first, and handing a lock to the newest arrival
    /// starves everything behind it.
    waiters: Vec<Waiter>,
    /// Bumped by every [`Table::owner_exited`]; see the module comment.
    exits: u64,
}

impl Queue {
    /// Give up to `max` pending waiters on `key` whose bits overlap an outcome.
    ///
    /// `Err` with the number already woken when a PI or requeue-PI waiter is
    /// on the word, which is Linux's `futex_wake`: the check is made per
    /// matching waiter, so those before it stay woken.
    fn take(&mut self, key: Key, max: u32, bitset: u32) -> (u32, Option<c_int>) {
        let mut n = 0;
        for w in self.waiters.iter_mut().filter(|w| w.pending()) {
            if n >= max {
                break;
            }
            if !w.entries.on(key) {
                continue;
            }
            if w.kind != Kind::Plain {
                return (n, Some(EINVAL));
            }
            if let Some(i) = w.entries.matching(key, bitset) {
                w.outcome = Some(Outcome::Woken(i as u32));
                n += 1;
            }
        }
        (n, None)
    }

    /// Move up to `max` pending plain waiters from `from` to `to`, without
    /// waking them. A requeue-PI waiter on `from` is `EINVAL`, as in `take`.
    fn move_to(&mut self, from: Key, to: Key, max: u32) -> Result<u32, c_int> {
        let mut n = 0;
        for w in self.waiters.iter_mut().filter(|w| w.pending()) {
            if n >= max {
                break;
            }
            if !w.entries.on(from) {
                continue;
            }
            if w.kind != Kind::Plain {
                return Err(EINVAL);
            }
            for e in w.entries.as_mut_slice().iter_mut().filter(|e| e.key == from) {
                e.key = to;
            }
            n += 1;
        }
        Ok(n)
    }

    fn count(&self, key: Key) -> usize {
        self.waiters
            .iter()
            .filter(|w| w.pending() && w.entries.on(key))
            .count()
    }

    /// The oldest pending PI waiter on `key`.
    fn first_pi(&mut self, key: Key) -> Option<&mut Waiter> {
        self.waiters
            .iter_mut()
            .find(|w| w.pending() && matches!(w.kind, Kind::Pi { .. }) && w.entries.on(key))
    }

    /// A PI waiter on `key` still parked behind `owner`, or told it died and
    /// not yet gone to take the lock over.
    fn has_pi_behind(&self, key: Key, owner: u32) -> bool {
        self.waiters.iter().any(|w| {
            w.entries.on(key)
                && match (w.kind, w.outcome) {
                    (Kind::Pi { owner: o }, None) => o == owner,
                    (Kind::Pi { .. }, Some(Outcome::OwnerGone(t))) => t == owner,
                    _ => false,
                }
        })
    }

    fn has_pi(&self, key: Key) -> bool {
        self.waiters
            .iter()
            .any(|w| w.pending() && matches!(w.kind, Kind::Pi { .. }) && w.entries.on(key))
    }

    /// Everybody parked behind the lock at `key` is parked behind `owner` now.
    fn set_pi_owner(&mut self, key: Key, owner: u32) {
        for w in self.waiters.iter_mut().filter(|w| w.pending() && w.entries.on(key)) {
            if let Kind::Pi { owner: o } = &mut w.kind {
                *o = owner;
            }
        }
    }

    fn position(&self, id: u64) -> usize {
        self.waiters
            .iter()
            .position(|w| w.id == id)
            .expect("a parked waiter is in the queue until it leaves")
    }

    fn remove(&mut self, id: u64) -> Waiter {
        let at = self.position(id);
        self.waiters.remove(at)
    }
}

/// The condition index. `GuestLock` numbers them; there is one.
const READY: u32 = 0;

/// How a park ended.
enum Parked {
    Done(Outcome),
    /// `ETIMEDOUT` or `EINTR`, and what the waiter was when it gave up -- a
    /// requeue-PI waiter answers differently once it has been requeued.
    Failed(c_int, Kind),
}

/// Whether a tid names a live thread, asked **without** the queue lock.
///
/// Remembered per iteration of the PI loops, so a retry that finds the same
/// owner under the same epoch does not ask again.
struct Liveness<'a> {
    alive: &'a dyn Fn(u32) -> bool,
    known: Option<(u32, u64, bool)>,
}

impl Liveness<'_> {
    /// `Some(answer)` if it is known for `owner` at `epoch`; `None` if the
    /// caller has to drop the lock and call [`Self::ask`].
    fn cached(&self, owner: u32, epoch: u64) -> Option<bool> {
        match self.known {
            Some((o, e, live)) if o == owner && e == epoch => Some(live),
            _ => None,
        }
    }

    fn ask(&mut self, owner: u32, epoch: u64) {
        self.known = Some((owner, epoch, (self.alive)(owner)));
    }
}

pub struct Table {
    queue: GuestLock<Queue>,
    next_id: AtomicU64,
}

impl Default for Table {
    fn default() -> Table {
        Table::new()
    }
}

impl Table {
    pub fn new() -> Table {
        Table {
            queue: GuestLock::new(Queue::default(), 1),
            next_id: AtomicU64::new(1),
        }
    }

    fn enqueue(q: &mut Queue, w: Waiter) -> Result<(), c_int> {
        if q.waiters.try_reserve(1).is_err() {
            return Err(ENOMEM);
        }
        q.waiters.push(w);
        Ok(())
    }

    fn new_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Sleep until a waker gives `id` an outcome, `deadline` passes, or a
    /// signal. The waiter leaves the queue either way.
    ///
    /// A deadline rather than a duration: a wakeup that was not this thread's
    /// is a normal event here, and re-arming a timeout on each one would make
    /// the call wait arbitrarily longer than it was asked to.
    fn park(q: &mut GuestGuard<'_, Queue>, id: u64, deadline: Option<Instant>) -> Parked {
        let err = loop {
            let remaining = match deadline {
                Some(d) => match d.checked_duration_since(Instant::now()) {
                    Some(left) if !left.is_zero() => Some(left),
                    _ => break ETIMEDOUT,
                },
                None => None,
            };
            let woke = q.wait(READY, remaining);
            // The outcome is asked **first**, whatever the wait said.
            //
            // A waker that gave this waiter an outcome has already counted it
            // in the number its own syscall returned. So a wake that raced the
            // deadline is still a wake: answering `ETIMEDOUT` here would leave
            // one side believing it woke somebody and the other believing
            // nobody woke it, and the token would be gone. The same for a
            // signal arriving in the same instant -- and for a PI handoff it
            // is not even a choice, because the word already names this thread.
            let at = q.position(id);
            if let Some(o) = q.waiters[at].outcome {
                q.waiters.remove(at);
                return Parked::Done(o);
            }
            match woke {
                Woke::Notified => {}
                Woke::TimedOut => break ETIMEDOUT,
                Woke::Interrupted => break EINTR,
            }
        };
        let w = q.remove(id);
        Parked::Failed(err, w.kind)
    }

    /// `FUTEX_WAIT` on one word. 0 when woken, or a negative errno.
    ///
    /// `read` is called **with the queue locked**, which is the whole
    /// correctness argument: a waker that changed the word and woke between
    /// the comparison and the enqueue would find nobody, and this thread would
    /// sleep for ever on a value that had already moved.
    pub fn wait(
        &self,
        key: Key,
        val: u32,
        bitset: u32,
        deadline: Option<Instant>,
        read: &dyn Fn() -> Option<u32>,
    ) -> c_int {
        let check = || match read() {
            None => Err(EFAULT),
            Some(seen) if seen != val => Err(EAGAIN),
            Some(_) => Ok(()),
        };
        match self.wait_any(&[Entry { key, bitset }], &check, deadline) {
            Ok(_) => 0,
            Err(e) => e,
        }
    }

    /// `futex_waitv`, and every wait: park on all of `entries` until one of
    /// them is woken. The index of that one, or a negative errno.
    ///
    /// `check` reads and compares every word, **with the queue locked**, for
    /// the reason [`Self::wait`] gives; its error is the answer.
    pub fn wait_any(
        &self,
        entries: &[Entry],
        check: &dyn Fn() -> Result<(), c_int>,
        deadline: Option<Instant>,
    ) -> Result<usize, c_int> {
        if entries.iter().any(|e| e.bitset == 0) {
            return Err(EINVAL);
        }
        let entries = match entries {
            [one] => Entries::One(*one),
            many => {
                let mut v = Vec::new();
                v.try_reserve_exact(many.len()).map_err(|_| ENOMEM)?;
                v.extend_from_slice(many);
                Entries::Many(v.into_boxed_slice())
            }
        };
        let id = self.new_id();
        let mut q = self.queue.lock();
        check()?;
        Self::enqueue(
            &mut q,
            Waiter {
                id,
                tid: 0,
                entries,
                kind: Kind::Plain,
                outcome: None,
            },
        )?;
        match Self::park(&mut q, id, deadline) {
            Parked::Done(Outcome::Woken(i)) => Ok(i as usize),
            // A plain waiter is only ever woken.
            Parked::Done(_) => Ok(0),
            Parked::Failed(e, _) => Err(e),
        }
    }

    /// `FUTEX_WAKE`: up to `max` waiters on `key` whose bitset overlaps. How
    /// many, or `EINVAL` for a PI waiter on the word -- after waking those
    /// before it, which is Linux's order.
    pub fn wake(&self, key: Key, max: u32, bitset: u32) -> Result<u32, c_int> {
        self.wake_inner(key, max, bitset, || {})
    }

    /// The body, with a hook that runs **with the queue locked** before the
    /// take. Production passes nothing; the test uses it to hold the lock past
    /// a waiter's deadline, which is the one interleaving that cannot be raced
    /// for reliably.
    fn wake_inner(
        &self,
        key: Key,
        max: u32,
        bitset: u32,
        before_take: impl FnOnce(),
    ) -> Result<u32, c_int> {
        let mut q = self.queue.lock();
        before_take();
        let (n, err) = q.take(key, max, bitset);
        drop(q);
        if n > 0 {
            self.queue.notify(READY);
        }
        match err {
            Some(e) => Err(e),
            None => Ok(n),
        }
    }

    /// [`Self::wake`], holding the queue lock for `hold` first.
    #[cfg(test)]
    pub fn wake_after_holding(&self, key: Key, max: u32, hold: std::time::Duration) -> u32 {
        self.wake_inner(key, max, !0, || std::thread::sleep(hold)).unwrap()
    }

    /// `FUTEX_REQUEUE` / `FUTEX_CMP_REQUEUE` / `futex_requeue`: wake up to
    /// `wake_max` on `from`, then move up to `requeue_max` of the rest to `to`.
    ///
    /// `check`, when given, compares the first word **under the queue lock**:
    /// done before taking it, a waiter could arrive with the new value between
    /// the comparison and the move and be moved onto a mutex it was never
    /// meant to wait on.
    ///
    /// The move does not wake anything. That is the point of the call — a
    /// `pthread_cond_broadcast` moves every waiter to the mutex's futex instead
    /// of waking them all onto a lock only one can hold.
    pub fn requeue(
        &self,
        from: Key,
        to: Key,
        wake_max: u32,
        requeue_max: u32,
        check: Option<&dyn Fn() -> Result<(), c_int>>,
    ) -> Result<u32, c_int> {
        let mut q = self.queue.lock();
        if let Some(check) = check {
            check()?;
        }
        let (woken, err) = q.take(from, wake_max, !0);
        let moved = match err {
            Some(e) => Err(e),
            None => q.move_to(from, to, requeue_max),
        };
        drop(q);
        if woken > 0 {
            self.queue.notify(READY);
        }
        moved.map(|m| woken + m)
    }

    /// How many are parked on `key`.
    pub fn waiters_on(&self, key: Key) -> usize {
        self.queue.lock().count(key)
    }

    // -------------------------------------------------------------- PI

    /// `FUTEX_LOCK_PI`, `FUTEX_LOCK_PI2` and (`try_only`) `FUTEX_TRYLOCK_PI`.
    /// 0 with the lock held, or a negative errno.
    ///
    /// `alive` answers whether a tid names a live thread; it is called with
    /// the queue **unlocked**, see the module comment.
    pub fn lock_pi(
        &self,
        key: Key,
        tid: u32,
        word: &dyn PiWord,
        alive: &dyn Fn(u32) -> bool,
        deadline: Option<Instant>,
        try_only: bool,
    ) -> c_int {
        self.acquire_pi(key, tid, word, &mut Liveness { alive, known: None }, deadline, try_only, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn acquire_pi(
        &self,
        key: Key,
        tid: u32,
        word: &dyn PiWord,
        live: &mut Liveness<'_>,
        deadline: Option<Instant>,
        try_only: bool,
        mut dead: Option<u32>,
    ) -> c_int {
        loop {
            let mut q = self.queue.lock();
            let Some(v) = word.read() else { return EFAULT };
            let owner = v & FUTEX_TID_MASK;
            // Free, or held by the owner this thread was told has died.
            if owner == 0 || Some(owner) == dead {
                let waiters = if owner != 0 || q.has_pi(key) { FUTEX_WAITERS } else { 0 };
                match word.cmpxchg(v, tid | (v & FUTEX_OWNER_DIED) | waiters) {
                    None => return EFAULT,
                    Some(Err(_)) => continue,
                    Some(Ok(())) => {
                        q.set_pi_owner(key, tid);
                        return 0;
                    }
                }
            }
            if owner == tid {
                return EDEADLK;
            }
            let Some(owner_alive) = live.cached(owner, q.exits) else {
                let epoch = q.exits;
                drop(q);
                live.ask(owner, epoch);
                continue;
            };
            // Linux sets the bit before it looks the owner up, a trylock
            // included, so a dead owner and a refused trylock both leave it
            // set -- `futex2_probe` reads the word after each.
            if v & FUTEX_WAITERS == 0 {
                match word.cmpxchg(v, v | FUTEX_WAITERS) {
                    None => return EFAULT,
                    Some(Err(_)) => continue,
                    Some(Ok(())) => {}
                }
            }
            if try_only {
                return if owner_alive { EAGAIN } else { ESRCH };
            }
            // A dead owner with threads already parked behind it is a lock
            // that is being handed on: Linux attaches to the existing PI state
            // and queues. Only a dead owner nobody waits behind is `ESRCH`.
            if !owner_alive && !q.has_pi_behind(key, owner) {
                return ESRCH;
            }
            let id = self.new_id();
            let parked = Waiter {
                id,
                tid,
                entries: Entries::One(Entry { key, bitset: !0 }),
                kind: Kind::Pi { owner },
                outcome: None,
            };
            if let Err(e) = Self::enqueue(&mut q, parked) {
                return e;
            }
            match Self::park(&mut q, id, deadline) {
                Parked::Done(Outcome::Handoff) => return 0,
                Parked::Done(Outcome::OwnerGone(t)) => dead = Some(t),
                Parked::Done(Outcome::Woken(_)) => {}
                Parked::Failed(e, _) => return e,
            }
        }
    }

    /// `FUTEX_UNLOCK_PI`: hand the lock to the oldest waiter, or release it.
    pub fn unlock_pi(&self, key: Key, tid: u32, word: &dyn PiWord) -> c_int {
        loop {
            let mut q = self.queue.lock();
            let Some(v) = word.read() else { return EFAULT };
            if v & FUTEX_TID_MASK != tid {
                return EPERM;
            }
            let next = q.first_pi(key).map(|w| w.tid);
            // Linux always leaves `FUTEX_WAITERS` on a handoff, and drops
            // `FUTEX_OWNER_DIED`: the new owner did not inherit a dead one.
            let new = next.map_or(0, |t| t | FUTEX_WAITERS);
            match word.cmpxchg(v, new) {
                None => return EFAULT,
                Some(Err(_)) => continue,
                Some(Ok(())) => {}
            }
            if let Some(t) = next {
                q.first_pi(key).expect("still first").outcome = Some(Outcome::Handoff);
                q.set_pi_owner(key, t);
                drop(q);
                self.queue.notify(READY);
            }
            return 0;
        }
    }

    /// `FUTEX_WAIT_REQUEUE_PI`: wait on `key` for `val`, to be handed the PI
    /// lock at `target` by a `FUTEX_CMP_REQUEUE_PI`.
    #[allow(clippy::too_many_arguments)]
    pub fn wait_requeue_pi(
        &self,
        key: Key,
        val: u32,
        target: Key,
        tid: u32,
        read: &dyn Fn() -> Option<u32>,
        word: &dyn PiWord,
        alive: &dyn Fn(u32) -> bool,
        deadline: Option<Instant>,
    ) -> c_int {
        let id = self.new_id();
        let mut q = self.queue.lock();
        match read() {
            None => return EFAULT,
            Some(seen) if seen != val => return EAGAIN,
            Some(_) => {}
        }
        let parked = Waiter {
            id,
            tid,
            entries: Entries::One(Entry { key, bitset: !0 }),
            kind: Kind::RequeuePi { target },
            outcome: None,
        };
        if let Err(e) = Self::enqueue(&mut q, parked) {
            return e;
        }
        match Self::park(&mut q, id, deadline) {
            Parked::Done(Outcome::Handoff) => 0,
            Parked::Done(Outcome::OwnerGone(t)) => {
                drop(q);
                let mut live = Liveness { alive, known: None };
                self.acquire_pi(target, tid, word, &mut live, deadline, false, Some(t))
            }
            // A plain wake cannot reach it: `take` answers EINVAL instead.
            Parked::Done(Outcome::Woken(_)) => EAGAIN,
            // Linux: interrupted once requeued is `EWOULDBLOCK`, because a
            // restart would find the condition word changed anyway.
            Parked::Failed(EINTR, Kind::Pi { .. }) => EAGAIN,
            Parked::Failed(e, _) => e,
        }
    }

    /// `FUTEX_CMP_REQUEUE_PI`: lock `to` on behalf of the oldest waiter on
    /// `from` if it is free, and move the rest behind it. Woken plus requeued,
    /// or a negative errno.
    ///
    /// The bound is on the **total**, `1 + requeue_max` (`nr_wake` is always
    /// 1 here): a top waiter that could not be given the lock is requeued
    /// within the one it would have been woken under. Linux counts it so --
    /// three waiters behind a held mutex with `nr_requeue` 2 answer 3, which
    /// `futex2_abi` measured.
    pub fn cmp_requeue_pi(
        &self,
        from: Key,
        to: Key,
        requeue_max: u32,
        check: &dyn Fn() -> Result<(), c_int>,
        word: &dyn PiWord,
        alive: &dyn Fn(u32) -> bool,
    ) -> Result<u32, c_int> {
        let mut live = Liveness { alive, known: None };
        loop {
            let mut q = self.queue.lock();
            check()?;
            let top = match q.waiters.iter().find(|w| w.pending() && w.entries.on(from)) {
                None => return Ok(0),
                Some(w) => match w.kind {
                    Kind::RequeuePi { target } if target == to => (w.id, w.tid),
                    _ => return Err(EINVAL),
                },
            };
            let v = word.read().ok_or(EFAULT)?;
            let mut owner = v & FUTEX_TID_MASK;
            let mut woken = 0;
            if owner == 0 {
                match word.cmpxchg(v, top.1 | (v & FUTEX_OWNER_DIED) | FUTEX_WAITERS) {
                    None => return Err(EFAULT),
                    Some(Err(_)) => continue,
                    Some(Ok(())) => {}
                }
                let at = q.position(top.0);
                q.waiters[at].outcome = Some(Outcome::Handoff);
                q.set_pi_owner(to, top.1);
                owner = top.1;
                woken = 1;
            } else if owner == top.1 {
                return Err(EDEADLK);
            } else {
                let Some(owner_alive) = live.cached(owner, q.exits) else {
                    let epoch = q.exits;
                    drop(q);
                    live.ask(owner, epoch);
                    continue;
                };
                if !owner_alive {
                    return Err(ESRCH);
                }
                // The top waiter at least is moved behind the owner (the bound
                // below is one more than `requeue_max`), so the owner's unlock
                // has to come to the kernel.
                if v & FUTEX_WAITERS == 0 {
                    match word.cmpxchg(v, v | FUTEX_WAITERS) {
                        None => return Err(EFAULT),
                        Some(Err(_)) => continue,
                        Some(Ok(())) => {}
                    }
                }
            }
            let limit = requeue_max.saturating_add(1) - woken;
            let mut moved = 0;
            let mut refused = false;
            for w in q.waiters.iter_mut().filter(|w| w.pending() && w.entries.on(from)) {
                if moved >= limit {
                    break;
                }
                // Linux's requeue loop refuses a waiter bound elsewhere, or not
                // a requeue-PI waiter at all, with `EINVAL` -- after what it has
                // already done, so the top waiter given the lock is still woken.
                match w.kind {
                    Kind::RequeuePi { target } if target == to => {}
                    _ => {
                        refused = true;
                        break;
                    }
                }
                w.kind = Kind::Pi { owner };
                for e in w.entries.as_mut_slice().iter_mut().filter(|e| e.key == from) {
                    e.key = to;
                }
                moved += 1;
            }
            drop(q);
            if woken > 0 {
                self.queue.notify(READY);
            }
            return if refused { Err(EINVAL) } else { Ok(woken + moved) };
        }
    }

    /// A thread is exiting: whoever is parked behind it on a PI lock has to
    /// be told, or will sleep for ever. See the module comment.
    pub fn owner_exited(&self, tid: u32) {
        let mut q = self.queue.lock();
        q.exits += 1;
        // **Every** waiter behind it, not the oldest: one that fails to take
        // the lock over (its mapping gone, say) would otherwise leave the rest
        // parked behind a tid nobody will ever report again. The first to
        // retry takes it and names itself the owner; the rest find a live
        // owner and park again.
        let mut told = false;
        for w in q.waiters.iter_mut().filter(|w| w.pending()) {
            if w.kind == (Kind::Pi { owner: tid }) {
                w.outcome = Some(Outcome::OwnerGone(tid));
                told = true;
            }
        }
        drop(q);
        if told {
            self.queue.notify(READY);
        }
    }
}
