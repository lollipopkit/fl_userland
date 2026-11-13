//! The descriptor references a syscall holds until it returns.
//!
//! `f_get` takes a reference under the same lock `fdtable_close` clears the
//! slot with, so a descriptor cannot be freed between the lookup and the use.
//! The reference is released when the syscall ends rather than by each caller —
//! there are sixty-odd of those, most with several ways out, and one missed
//! release is a descriptor that never closes while one too many is the
//! use-after-free the whole thing exists to prevent.
//!
//! # The dedup, and what it cost `poll`
//!
//! They are deduplicated so a syscall that looks one descriptor up repeatedly —
//! `recvmmsg` calling `recvmsg` over a count the guest chose — cannot grow the
//! list without bound. The C did that with a **linear scan of everything held
//! so far**, on the grounds that "n is one in almost every syscall".
//!
//! `poll` is the exception: `sys_poll` calls `f_get` once per descriptor, so N
//! distinct ones cost 0+1+…+N-1 comparisons, and `poll()` over 1800 pipes took
//! 2.7 ms. The dedup bought poll nothing either, its descriptors being
//! distinct.
//!
//! # Why it is a set
//!
//! A syscall that looks the same descriptor up repeatedly must not take a
//! reference each time: `recvmmsg` calling `recvmsg` in a loop over a count the
//! guest chose would grow the list without bound. So the entries are
//! deduplicated, which bounds the list by the number of open descriptors.
//!
//! The C did that with a **linear scan** of everything held so far, on the
//! grounds that "n is one in almost every syscall". `poll` is the exception,
//! and it is not a small one: `sys_poll` calls `f_get` once per descriptor, so
//! N distinct descriptors meant 0+1+2+…+N−1 comparisons. Measured on the
//! emulator, `poll()` over N pipes with nothing in them:
//!
//! | N | per poll |
//! | --- | --- |
//! | 250 | 242 µs |
//! | 500 | 517 µs |
//! | 1000 | 1256 µs |
//! | 1800 | 2719 µs |
//!
//! Doubling N more than doubled the cost. And the dedup bought `poll` nothing
//! at all, because its descriptors are distinct — it paid the scan and the list
//! grew to N regardless.
//!
//! A hash set answers the same question in constant time. The insertion order
//! is kept alongside it because the release walks the entries, and doing that in
//! a stable order makes a failure reproducible.

use std::collections::HashSet;
use std::hash::Hash;

/// One task's held references.
///
/// Generic over what identifies a descriptor because this crate sits below the
/// one that defines `struct fd`. It was a `usize` until 2026-09-29, which is
/// the same pointer with the type taken off and a cast at each end to put it
/// back.
///
/// `V` is what is kept per entry. `crates/fs/fdobj` keeps the reference
/// itself, an owning handle keyed by the description's address, so dropping
/// an entry is releasing it -- since 2026-10-16, where it kept the bare
/// pointer and retained and closed it by hand. `V` defaults to the key, for
/// a set of plain identities.
pub struct Refs<K, V = K> {
    seen: HashSet<K>,
    order: Vec<V>,
}

impl<K, V> Default for Refs<K, V> {
    fn default() -> Self {
        Refs {
            seen: HashSet::new(),
            order: Vec::new(),
        }
    }
}

impl<K: Copy + Eq + Hash> Refs<K> {
    /// Record a descriptor. Returns true if it was not already held, which is
    /// when the caller must take the reference.
    pub fn hold(&mut self, fd: K) -> bool {
        self.hold_with(fd, || fd)
    }
}

impl<K: Copy + Eq + Hash, V> Refs<K, V> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `key`, keeping what `value` makes if it was not already held.
    /// Returns whether it was new; when it was not, `value` is not called.
    pub fn hold_with(&mut self, key: K, value: impl FnOnce() -> V) -> bool {
        if !self.seen.insert(key) {
            return false;
        }
        self.order.push(value());
        true
    }

    /// Empty it, returning what was held in the order it was taken.
    ///
    /// Emptied *before* the caller releases anything: the group-exit safety
    /// valve calls the release for a task that is not the caller, and leaving
    /// the entries visible while closing them would let that task's own drain
    /// close them a second time.
    pub fn take_all(&mut self) -> Vec<V> {
        self.seen.clear();
        std::mem::take(&mut self.order)
    }

    /// Empty the set, calling `close` for each entry in the order it was
    /// taken, and answer how many there were.
    ///
    /// A callback rather than a buffer, so there is nothing for the caller to
    /// size and nothing that can be too small: being handed fewer references
    /// than it is now responsible for releasing is the one mistake this must
    /// not allow. The set is emptied **before** the first callback, so a
    /// `close` that somehow reached back in here would find nothing rather
    /// than the entries it is in the middle of releasing.
    pub fn drain(&mut self, close: impl FnMut(V)) -> usize {
        let taken = self.take_all();
        let n = taken.len();
        taken.into_iter().for_each(close);
        n
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_descriptor_is_held_once() {
        let mut r = Refs::<usize>::new();
        assert!(r.hold(1), "the first time");
        assert!(!r.hold(1), "and not again");
        assert!(!r.hold(1));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn different_descriptors_are_all_held() {
        let mut r = Refs::new();
        for i in 1..=100 {
            assert!(r.hold(i), "descriptor {i}");
        }
        assert_eq!(r.len(), 100);
    }

    /// The release walks them, and a stable order makes a failure there
    /// reproducible rather than dependent on a hash.
    #[test]
    fn they_come_back_in_the_order_they_were_taken() {
        let mut r = Refs::new();
        for i in [7, 3, 9, 3, 1, 7] {
            r.hold(i);
        }
        assert_eq!(r.take_all(), vec![7, 3, 9, 1]);
    }

    /// Emptied before the caller releases anything: the group-exit valve
    /// releases for a task that is not the caller, and entries still visible
    /// would be closed twice.
    #[test]
    fn taking_empties_it() {
        let mut r = Refs::new();
        r.hold(1);
        r.hold(2);
        assert_eq!(r.take_all().len(), 2);
        assert!(r.is_empty());
        assert_eq!(r.take_all().len(), 0, "and taking again gives nothing");
        // And a descriptor held before may be held again afterwards.
        assert!(r.hold(1));
    }

    /// The drain hands every entry to the callback, in order, and empties
    /// itself first.
    #[test]
    fn draining_releases_every_entry_in_order() {
        let mut seen = Vec::new();
        let mut r = Refs::new();
        for i in [5usize, 2, 9, 2] {
            r.hold(i);
        }
        let n = r.drain(|fd| seen.push(fd));
        assert_eq!(n, 3);
        assert_eq!(seen, vec![5, 2, 9]);
        assert!(r.is_empty(), "emptied before the first callback");
        assert_eq!(r.drain(|_| unreachable!("nothing is left")), 0);
    }

    /// The shape the C could not do: membership without reading everything.
    /// Not a timing test -- it checks that a large set still answers, which is
    /// what a linear scan makes slow rather than wrong.
    #[test]
    fn a_large_set_still_answers() {
        let mut r = Refs::new();
        for i in 0..50_000 {
            assert!(r.hold(i));
        }
        for i in 0..50_000 {
            assert!(!r.hold(i), "already held: {i}");
        }
        assert_eq!(r.len(), 50_000);
        assert_eq!(r.take_all().len(), 50_000);
    }
}
