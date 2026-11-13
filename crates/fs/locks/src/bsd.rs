//! BSD advisory locks — `flock(2)` — with no kernel in them.
//!
//! Whole-file, unlike a POSIX record lock, and owned by the *open file
//! description* rather than by the descriptor table. That distinction is the
//! whole reason both kinds exist: two `open`s of one file get two independent
//! flock owners, while `dup` and `fork` share one, which is the opposite of
//! how POSIX record locks divide.
//!
//! Only the filesystems with no host file behind them need this. realfs and
//! fakefs hand `flock` to the host, because a host file may be shared with a
//! host process and the host's lock is then the real one.

/// The crate's [`crate::Owner`]. Every owner a BSD lock set holds is an
/// `Owner::Description` — `flock(2)` is a lock on the open file description
/// and has no other kind — and this module never builds one, so the variant is
/// a fact about its callers rather than something it has to enforce.
///
/// It was a second `pub type Owner = usize` beside `posix`'s until 2026-09-16.
pub use crate::Owner;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Mode {
    Shared,
    Exclusive,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Held {
    pub owner: Owner,
    pub mode: Mode,
    /// Who took it, which `/proc/<pid>/fdinfo` reports.
    pub pid: i32,
}

#[derive(Default, Debug)]
pub struct Set {
    held: Vec<Held>,
}

#[derive(PartialEq, Eq, Debug)]
pub enum Applied {
    /// Granted. `released` is true when this changed what someone else could
    /// take, so a waiter should be woken.
    Granted { released: bool },
    /// Another description holds an incompatible lock.
    Blocked,
}

impl Set {
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    fn would_block(&self, owner: Owner, mode: Mode) -> bool {
        self.held
            .iter()
            .any(|h| h.owner != owner && (mode == Mode::Exclusive || h.mode == Mode::Exclusive))
    }

    /// Take or convert a lock.
    ///
    /// Converting is not atomic, and is not meant to be: `flock(2)` says the
    /// existing lock is removed first and the new one taken after, so a
    /// request from another description may be granted in between and the
    /// conversion then blocks — or fails, and leaves the caller holding
    /// nothing. Reproduced here rather than improved on, because a program
    /// that has read the manual page is entitled to that behaviour.
    pub fn acquire(&mut self, owner: Owner, mode: Mode, pid: i32) -> Applied {
        let released = self.release(owner);
        if self.would_block(owner, mode) {
            return Applied::Blocked;
        }
        self.held.push(Held { owner, mode, pid });
        Applied::Granted { released }
    }

    /// Record a lock the host has already granted, for a description whose
    /// file is a host file: the host's lock is the one that excludes, and this
    /// copy is what `/proc/<pid>/fdinfo` lists.
    pub fn record(&mut self, owner: Owner, mode: Option<Mode>, pid: i32) {
        self.release(owner);
        if let Some(mode) = mode {
            self.held.push(Held { owner, mode, pid });
        }
    }

    pub fn held(&self) -> &[Held] {
        &self.held
    }

    /// Drop this description's lock. Returns true if it had one.
    pub fn release(&mut self, owner: Owner) -> bool {
        let before = self.held.len();
        self.held.retain(|h| h.owner != owner);
        self.held.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Owner = Owner::Description(1);
    const B: Owner = Owner::Description(2);
    const C: Owner = Owner::Description(3);

    fn ok(released: bool) -> Applied {
        Applied::Granted { released }
    }

    #[test]
    fn an_exclusive_lock_excludes_another_description() {
        let mut s = Set::default();
        assert_eq!(s.acquire(A, Mode::Exclusive, 0), ok(false));
        assert_eq!(s.acquire(B, Mode::Exclusive, 0), Applied::Blocked);
        assert_eq!(s.acquire(B, Mode::Shared, 0), Applied::Blocked);
    }

    #[test]
    fn shared_locks_stack() {
        let mut s = Set::default();
        assert_eq!(s.acquire(A, Mode::Shared, 0), ok(false));
        assert_eq!(s.acquire(B, Mode::Shared, 0), ok(false));
        assert_eq!(s.acquire(C, Mode::Shared, 0), ok(false));
        // And still exclude an exclusive one.
        assert_eq!(s.acquire(A, Mode::Exclusive, 0), Applied::Blocked);
    }

    #[test]
    fn releasing_the_last_shared_lock_lets_an_exclusive_one_in() {
        let mut s = Set::default();
        s.acquire(A, Mode::Shared, 0);
        s.acquire(B, Mode::Shared, 0);
        assert!(s.release(A));
        assert_eq!(s.acquire(C, Mode::Exclusive, 0), Applied::Blocked);
        assert!(s.release(B));
        assert_eq!(s.acquire(C, Mode::Exclusive, 0), ok(false));
    }

    #[test]
    fn re_locking_the_same_way_is_not_a_conflict_with_itself() {
        let mut s = Set::default();
        s.acquire(A, Mode::Exclusive, 0);
        assert_eq!(s.acquire(A, Mode::Exclusive, 0), ok(true));
        assert_eq!(s.held.len(), 1, "one description holds one lock");
    }

    #[test]
    fn an_uncontended_conversion_succeeds_both_ways() {
        let mut s = Set::default();
        s.acquire(A, Mode::Shared, 0);
        assert_eq!(s.acquire(A, Mode::Exclusive, 0), ok(true));
        assert_eq!(s.acquire(A, Mode::Shared, 0), ok(true));
    }

    #[test]
    fn a_contended_upgrade_leaves_the_caller_holding_nothing() {
        // The documented flock(2) quirk: the old lock is dropped before the
        // new one is attempted, so a failed upgrade is not a no-op.
        let mut s = Set::default();
        s.acquire(A, Mode::Shared, 0);
        s.acquire(B, Mode::Shared, 0);
        assert_eq!(s.acquire(A, Mode::Exclusive, 0), Applied::Blocked);
        assert!(!s.release(A), "A's shared lock is gone, not restored");
        // B is unaffected.
        assert_eq!(s.acquire(C, Mode::Exclusive, 0), Applied::Blocked);
    }

    #[test]
    fn releasing_a_lock_that_was_never_taken_reports_nothing() {
        let mut s = Set::default();
        assert!(!s.release(A));
        assert!(s.is_empty());
    }

    #[test]
    fn the_set_empties_out_so_the_inode_can_forget_about_it() {
        let mut s = Set::default();
        s.acquire(A, Mode::Shared, 0);
        s.acquire(B, Mode::Exclusive, 0);
        s.release(A);
        s.release(B);
        assert!(s.is_empty());
    }
}
