//! The futex wait queue.
//!
//! A rewrite rather than a port, because the C did not wait. `struct
//! futex_wait` carried a `cond_t` that nothing ever signalled; what
//! `futex_wait` actually did was create a **pipe per thread**, park in `poll()`
//! with a **100 ms timeout**, and on every expiry re-read the group-exit flag,
//! the pending signals and the futex word:
//!
//! ```c
//! poll_ms = 100; // 100ms safety-net timeout for signal/stall checks
//! ...
//! int ret = poll(&pfd, 1, poll_ms);
//! ```
//!
//! So every blocked thread woke ten times a second for ever, and a Go or Rust
//! runtime with a few dozen blocked threads paid that continuously. It also
//! cost two file descriptors per thread that ever called `futex`, and made
//! `FUTEX_WAKE` a `write(2)` per waiter.
//!
//! Here a waiter parks on a condition variable and costs nothing until
//! something happens. Interruption is `wait_for`'s, which is what every other
//! wait in this kernel is built on: a signal, or the `SIGKILL` that group exit
//! delivers, ends it — so the two flags the C polled for do not need polling.
//!
//! ## One lock, and how a waiter knows the wakeup was for it
//!
//! `FUTEX_WAKE` wakes **n** waiters and a condition variable wakes all of them,
//! so the waker *chooses*: it gives the ones it picked an outcome, under the
//! lock, and broadcasts. A waiter that wakes and finds it has **no outcome**
//! goes back to sleep, having cost one recheck. (It removed them from the queue
//! until 2026-11-11; an outcome is what lets `futex_waitv` learn which of its
//! words woke it and a PI waiter learn it was handed the lock. See `model`.)
//!
//! That is one lock for every futex in the process, which sounds worse than the
//! C's 4096 hash buckets and is not: those were all under one global
//! `futex_lock`, so they bought lookup and no concurrency whatsoever. What this
//! changes is the *waiting*, and against a design where every blocked thread
//! wakes ten times a second regardless, a broadcast per wake is strictly less
//! work.
//!
//! Sharding it is the obvious next step and is deliberately **not** taken here,
//! because `FUTEX_REQUEUE` moves a waiter to another address while it is
//! parked. With one condition that is a field assignment; with a condition per
//! shard the waiter is left parked on the shard it no longer belongs to, and
//! fixing that needs a per-waiter wakeup — which is what the pipe was. If a
//! measurement ever shows the broadcast costing more than the pipe did, the
//! answer is a `Waiter` behind an `Arc` with its own state, not a shard.
//!
//! ## What is not here
//!
//! Reading the futex word. It needs `mem->lock` held across the dereference —
//! otherwise an `munmap` on another thread can unmap the page between the
//! lookup and the load — and it has to be an **atomic** load, because a futex
//! word is the one word in a program other threads are certainly CAS-ing.
//! Both are `emu/`'s to do, so the caller passes a reader in -- [`Space`], and
//! for the PI operations its compare-and-swap.

use std::ffi::c_int;
use std::sync::OnceLock;
use std::time::Instant;

#[cfg(test)]
mod tests;

/// Guest errnos, negated as everywhere else in the tree.
pub use guest_errno::c_int_::{
    EAGAIN, EDEADLK, EFAULT, EINTR, EINVAL, ENOMEM, EPERM, ESRCH, ETIMEDOUT,
};

mod model;
pub use model::{Entry, FUTEX_OWNER_DIED, FUTEX_TID_MASK, FUTEX_WAITERS, Key, PiWord, Table};

static TABLE: OnceLock<Table> = OnceLock::new();

fn table() -> &'static Table {
    TABLE.get_or_init(Table::new)
}

/// What a guest address is backed by, as far as a futex key is concerned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Backing {
    /// Nothing is mapped there.
    Unmapped,
    /// A private (copy-on-write) page.
    Private,
    /// A genuinely shared page, at this host address.
    Shared(u64),
}

/// What this crate needs of an address space, which it deliberately knows
/// nothing else about.
///
/// # A trait passed in, and why not an installed hook
///
/// These were `GuestOps`, three function pointers installed once by the first
/// `sys_futex` and read back from a `OnceLock`, each taking the address space
/// as a `*mut mem` -- so every entry point here was an `unsafe fn` for a
/// pointer this crate never dereferenced, only forwarded. And the installation
/// had an ordering to get wrong, which it did once: read with `get_or_init`,
/// the exit path's `clear_child_tid` wake installed the empty answers before
/// any `sys_futex` ran, and a shared futex keyed on the private key -- two
/// processes waiting on one word were two futexes
/// (`tests/guest/src/bin/futex_shared.rs`). A caller that passes its address
/// space in has nothing to install and nothing to order, and the pointer and
/// its `unsafe` stay in the crate that owns the memory.
pub trait Space {
    /// The address space's identity, which a private futex is keyed on. Only
    /// compared, never dereferenced.
    fn id(&self) -> usize;

    /// The guest word at `addr`, under the address-space lock and atomically.
    /// `None` when the address is not mapped.
    fn read_word(&self, addr: u64) -> Option<u32>;

    /// Compare-and-swap on the guest word at `addr`, atomically. `None` when
    /// it is not mapped for writing; `Some(Err(actual))` when it was not
    /// `old`. What the PI operations need.
    fn cmpxchg_word(&self, addr: u64, old: u32, new: u32) -> Option<Result<(), u32>>;

    /// Where a guest address *is*. A host address only for a page that is
    /// genuinely shared -- a private mapping is copy-on-write, so its host
    /// address moves the first time the word is written, and a futex word is
    /// written by definition.
    fn backing(&self, addr: u64) -> Backing;

    /// `IUL_FUTEX_WATCH`'s wake half: what a wake on `addr` did, and under
    /// which key's space. Nothing by default.
    fn woke(&self, _addr: u64, _n: c_int, _private: bool, _space: u64) {}
}

/// A futex word as a caller names it: where, and whether `FUTEX_PRIVATE_FLAG`
/// (futex2's `FUTEX2_PRIVATE`) was given.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Word {
    pub addr: u64,
    pub private: bool,
}

/// The identity of the futex at `w`.
///
/// A private futex is the address space and the guest address; a shared one
/// is the host address the two spaces have in common, with the space left at
/// zero so a private and a shared futex at the same number are never confused.
///
/// A shared address on a private page falls back to the private key, which is
/// Linux's rule: `get_futex_key` uses the mm key unless the mapping is
/// `VM_MAYSHARE`. A shared address with **nothing** mapped is `EFAULT`, because
/// Linux has to find the page to key it -- `futex2_probe`'s "wake, unmapped,
/// shared" answers that, where a private one answers 0. This fell back to the
/// private key and answered 0 too, until 2026-11-11.
fn key_of(space: &impl Space, w: Word) -> Result<Key, c_int> {
    if !w.private {
        match space.backing(w.addr) {
            Backing::Shared(host) => return Ok(Key { space: 0, addr: host }),
            Backing::Unmapped => return Err(EFAULT),
            Backing::Private => {}
        }
    }
    Ok(Key {
        space: space.id(),
        addr: w.addr,
    })
}

/// The word at `w`, as a [`PiWord`] for the queue to read and swap under its
/// lock.
struct GuestWord<'a, S: Space>(&'a S, u64);

impl<S: Space> PiWord for GuestWord<'_, S> {
    fn read(&self) -> Option<u32> {
        self.0.read_word(self.1)
    }
    fn cmpxchg(&self, old: u32, new: u32) -> Option<Result<(), u32>> {
        self.0.cmpxchg_word(self.1, old, new)
    }
}

/// Park until woken, `deadline` passes, or a signal. 0, or a negative errno.
///
/// The word is read at a *guest* address, through `space`, rather than derived
/// from the key: a shared futex's key holds the host address instead.
///
/// A guest thread, because the wait is `wait_for`, which reads `current`.
pub fn wait(space: &impl Space, w: Word, val: u32, bitset: u32, deadline: Option<Instant>) -> c_int {
    // Before the key, as Linux's `__futex_wait` does: an empty mask is the
    // caller's mistake whatever the address.
    if bitset == 0 {
        return EINVAL;
    }
    let key = match key_of(space, w) {
        Ok(k) => k,
        Err(e) => return e,
    };
    table().wait(key, val, bitset, deadline, &|| space.read_word(w.addr))
}

/// `futex_waitv`: park on every `(word, value)` until one is woken. Its index,
/// or a negative errno. Every word is compared before anything is parked, in
/// order, and the first fault or mismatch is the answer.
pub fn waitv(space: &impl Space, words: &[(Word, u32)], deadline: Option<Instant>) -> Result<usize, c_int> {
    let mut entries = Vec::new();
    entries.try_reserve_exact(words.len()).map_err(|_| ENOMEM)?;
    for &(w, _) in words {
        entries.push(Entry {
            key: key_of(space, w)?,
            bitset: !0,
        });
    }
    let check = || {
        for &(w, val) in words {
            match space.read_word(w.addr) {
                None => return Err(EFAULT),
                Some(seen) if seen != val => return Err(EAGAIN),
                Some(_) => {}
            }
        }
        Ok(())
    };
    table().wait_any(&entries, &check, deadline)
}

/// How many were woken.
pub fn wake(space: &impl Space, w: Word, max: u32, bitset: u32) -> Result<u32, c_int> {
    if bitset == 0 {
        return Err(EINVAL);
    }
    let key = key_of(space, w)?;
    let n = table().wake(key, max, bitset);
    // A no-op unless IUL_FUTEX_WATCH names this address. The key goes with it
    // because "woke nobody" has two causes and they are not the same bug.
    space.woke(w.addr, n.as_ref().map_or(0, |&n| n as c_int), w.private, key.space as u64);
    n
}

/// Woken plus requeued. With `expect`, the word at `from` is compared first,
/// under the queue's lock.
pub fn requeue(
    space: &impl Space,
    from: Word,
    to: Word,
    wake_max: u32,
    requeue_max: u32,
    expect: Option<u32>,
) -> Result<u32, c_int> {
    let (k1, k2) = (key_of(space, from)?, key_of(space, to)?);
    let check = |val: u32| match space.read_word(from.addr) {
        None => Err(EFAULT),
        Some(seen) if seen != val => Err(EAGAIN),
        Some(_) => Ok(()),
    };
    match expect {
        Some(val) => table().requeue(k1, k2, wake_max, requeue_max, Some(&|| check(val))),
        None => table().requeue(k1, k2, wake_max, requeue_max, None),
    }
}

/// `FUTEX_LOCK_PI`/`FUTEX_LOCK_PI2`, or with `try_only` `FUTEX_TRYLOCK_PI`.
/// `tid` is the caller's; `alive` says whether a tid is a live thread.
pub fn lock_pi(
    space: &impl Space,
    w: Word,
    tid: u32,
    alive: &dyn Fn(u32) -> bool,
    deadline: Option<Instant>,
    try_only: bool,
) -> c_int {
    match key_of(space, w) {
        Ok(key) => table().lock_pi(key, tid, &GuestWord(space, w.addr), alive, deadline, try_only),
        Err(e) => e,
    }
}

/// `FUTEX_UNLOCK_PI`.
pub fn unlock_pi(space: &impl Space, w: Word, tid: u32) -> c_int {
    match key_of(space, w) {
        Ok(key) => table().unlock_pi(key, tid, &GuestWord(space, w.addr)),
        Err(e) => e,
    }
}

/// `FUTEX_WAIT_REQUEUE_PI`: wait on `w` for `val`, ending up owning `pi`.
pub fn wait_requeue_pi(
    space: &impl Space,
    w: Word,
    val: u32,
    pi: Word,
    tid: u32,
    alive: &dyn Fn(u32) -> bool,
    deadline: Option<Instant>,
) -> c_int {
    let (key, target) = match (key_of(space, w), key_of(space, pi)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    table().wait_requeue_pi(
        key,
        val,
        target,
        tid,
        &|| space.read_word(w.addr),
        &GuestWord(space, pi.addr),
        alive,
        deadline,
    )
}

/// `FUTEX_CMP_REQUEUE_PI`.
pub fn cmp_requeue_pi(
    space: &impl Space,
    from: Word,
    to: Word,
    requeue_max: u32,
    expect: u32,
    alive: &dyn Fn(u32) -> bool,
) -> Result<u32, c_int> {
    let (k1, k2) = (key_of(space, from)?, key_of(space, to)?);
    let check = || match space.read_word(from.addr) {
        None => Err(EFAULT),
        Some(seen) if seen != expect => Err(EAGAIN),
        Some(_) => Ok(()),
    };
    table().cmp_requeue_pi(k1, k2, requeue_max, &check, &GuestWord(space, to.addr), alive)
}

/// The thread `tid` is exiting; see [`Table::owner_exited`].
pub fn owner_exited(tid: u32) {
    table().owner_exited(tid);
}

/// For the futex-stall diagnostic: how many threads are parked on this address.
///
/// `space` is the private futex's address-space identity, [`Space::id`].
pub fn waiters(space: usize, addr: u64) -> usize {
    // The diagnostic only ever asks about a thread of the caller's own group,
    // so the private key is the one it wants.
    table().waiters_on(Key { space, addr })
}
