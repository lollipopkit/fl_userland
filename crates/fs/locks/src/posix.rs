//! POSIX record locks: the algebra, with no kernel in it.
//!
//! A record lock covers a byte range of an inode and belongs to an *owner* —
//! the descriptor table, so that threads sharing one do not lock each other
//! out and a forked child does. The awkward part is not deciding whether a
//! request conflicts; it is what the set of locks has to become once it is
//! granted, because a request may at the same time merge with an adjacent
//! lock of its own type, override part of one of a different type, and split
//! a third down the middle.
//!
//! The C did that by walking an intrusive list and mutating it in place, and
//! relied on the loop variable still pointing at something usable after the
//! loop ended in order to decide where to insert. Here the set is a `Vec` and
//! the transformation is written as one: gather what changes, then apply it.

/// The crate's [`crate::Owner`]: a record lock's is the descriptor table for a
/// POSIX lock and the description for an `F_OFD_*` one. It was a
/// `pub type Owner = usize` here, documented as the first of those only.
pub use crate::Owner;

/// `F_RDLCK`, `F_WRLCK`, `F_UNLCK` as the guest spells them.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    Read,
    Write,
}


#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// First byte covered.
    pub start: i64,
    /// Last byte covered, inclusive. `i64::MAX` for "to the end of the file",
    /// which is what a zero length means in a `struct flock`.
    pub end: i64,
    pub kind: Kind,
    pub owner: Owner,
    pub pid: i32,
    /// The description it was taken through, compared and never
    /// dereferenced: `/proc/<pid>/fdinfo` lists a POSIX lock on that
    /// description only, as Linux's `fl_file` does.
    pub file: usize,
}

impl Record {
    fn overlaps(&self, other: &Record) -> bool {
        self.end >= other.start && other.end >= self.start
    }

    /// Adjacent ranges of the same type merge, so that locking 0..4 and then
    /// 5..9 leaves one lock and not two.
    fn adjacent(&self, other: &Record) -> bool {
        self.end.checked_add(1) == Some(other.start) || other.end.checked_add(1) == Some(self.start)
    }

    fn conflicts(&self, other: &Record) -> bool {
        if self.owner == other.owner {
            return false;
        }
        if !self.overlaps(other) {
            return false;
        }
        // Two read locks coexist; anything involving a write lock does not.
        self.kind == Kind::Write || other.kind == Kind::Write
    }
}

/// Every record lock on one inode.
#[derive(Default, Debug)]
pub struct Set {
    records: Vec<Record>,
}

/// What `apply` did, so the caller knows whether to wake anyone.
#[derive(PartialEq, Eq, Debug)]
pub enum Applied {
    /// The request was granted. `released` is true when some region lost a
    /// lock, which is the only case a waiter can make progress from.
    Granted { released: bool },
    /// Somebody else holds a conflicting lock.
    Blocked,
}

#[path = "apply.rs"]
mod apply;

#[cfg(test)]
mod tests {
    use super::*;

    const A: Owner = Owner::Table(1);
    const B: Owner = Owner::Table(2);

    fn rec(start: i64, end: i64, kind: Kind, owner: Owner) -> Record {
        Record {
            start,
            end,
            kind,
            owner,
            pid: match owner {
                Owner::Table(a) | Owner::Description(a) => a as i32,
            },
            file: 0,
        }
    }

    fn granted(set: &mut Set, r: Record) -> Applied {
        let kind = Some(r.kind);
        set.apply(&r, kind)
    }

    #[test]
    fn two_read_locks_coexist() {
        let mut s = Set::default();
        assert_eq!(
            granted(&mut s, rec(0, 9, Kind::Read, A)),
            Applied::Granted { released: false }
        );
        assert_eq!(
            granted(&mut s, rec(0, 9, Kind::Read, B)),
            Applied::Granted { released: false }
        );
    }

    #[test]
    fn a_write_lock_excludes_another_owner() {
        let mut s = Set::default();
        granted(&mut s, rec(0, 9, Kind::Write, A));
        assert_eq!(granted(&mut s, rec(5, 20, Kind::Read, B)), Applied::Blocked);
        assert_eq!(
            granted(&mut s, rec(5, 20, Kind::Write, B)),
            Applied::Blocked
        );
        // Not overlapping, so not a conflict.
        assert_eq!(
            granted(&mut s, rec(10, 20, Kind::Write, B)),
            Applied::Granted { released: false }
        );
    }

    #[test]
    fn an_owner_never_conflicts_with_itself() {
        let mut s = Set::default();
        granted(&mut s, rec(0, 9, Kind::Write, A));
        assert_eq!(
            granted(&mut s, rec(0, 9, Kind::Write, A)),
            Applied::Granted { released: false }
        );
    }

    #[test]
    fn adjacent_locks_of_one_type_merge() {
        let mut s = Set::default();
        granted(&mut s, rec(0, 4, Kind::Read, A));
        granted(&mut s, rec(5, 9, Kind::Read, A));
        assert_eq!(s.records.len(), 1, "{:?}", s.records);
        assert_eq!((s.records[0].start, s.records[0].end), (0, 9));
    }

    #[test]
    fn locking_a_file_a_record_at_a_time_does_not_grow_the_set() {
        let mut s = Set::default();
        for i in 0..1000 {
            granted(&mut s, rec(i * 10, i * 10 + 9, Kind::Read, A));
        }
        assert_eq!(s.records.len(), 1, "{} records", s.records.len());
        assert_eq!((s.records[0].start, s.records[0].end), (0, 9999));
    }

    #[test]
    fn a_different_type_splits_a_lock_it_lands_in_the_middle_of() {
        let mut s = Set::default();
        granted(&mut s, rec(0, 99, Kind::Read, A));
        let applied = granted(&mut s, rec(40, 59, Kind::Write, A));
        assert_eq!(applied, Applied::Granted { released: true });
        assert_eq!(s.records.len(), 3, "{:?}", s.records);
        let ranges: Vec<_> = s.records.iter().map(|r| (r.start, r.end, r.kind)).collect();
        assert_eq!(
            ranges,
            vec![
                (0, 39, Kind::Read),
                (40, 59, Kind::Write),
                (60, 99, Kind::Read),
            ]
        );
    }

    #[test]
    fn a_different_type_trims_a_lock_it_overlaps_at_one_end() {
        let mut s = Set::default();
        granted(&mut s, rec(0, 99, Kind::Read, A));
        granted(&mut s, rec(80, 200, Kind::Write, A));
        let ranges: Vec<_> = s.records.iter().map(|r| (r.start, r.end)).collect();
        assert_eq!(ranges, vec![(0, 79), (80, 200)]);

        let mut s = Set::default();
        granted(&mut s, rec(100, 199, Kind::Read, A));
        granted(&mut s, rec(0, 149, Kind::Write, A));
        let ranges: Vec<_> = s.records.iter().map(|r| (r.start, r.end)).collect();
        assert_eq!(ranges, vec![(0, 149), (150, 199)]);
    }

    #[test]
    fn a_covering_lock_of_another_type_replaces_it_entirely() {
        let mut s = Set::default();
        granted(&mut s, rec(10, 20, Kind::Read, A));
        granted(&mut s, rec(0, 99, Kind::Write, A));
        assert_eq!(s.records.len(), 1);
        assert_eq!((s.records[0].start, s.records[0].end), (0, 99));
        assert_eq!(s.records[0].kind, Kind::Write);
    }

    #[test]
    fn unlocking_removes_only_the_range_asked_for() {
        let mut s = Set::default();
        granted(&mut s, rec(0, 99, Kind::Write, A));
        let applied = s.apply(&rec(40, 59, Kind::Write, A), None);
        assert_eq!(applied, Applied::Granted { released: true });
        let ranges: Vec<_> = s.records.iter().map(|r| (r.start, r.end)).collect();
        assert_eq!(ranges, vec![(0, 39), (60, 99)]);
    }

    #[test]
    fn unlocking_never_blocks_even_against_another_owner() {
        let mut s = Set::default();
        granted(&mut s, rec(0, 99, Kind::Write, B));
        assert_eq!(
            s.apply(&rec(0, 99, Kind::Write, A), None),
            Applied::Granted { released: false },
            "unlocking a range this owner does not hold is a no-op, not a block"
        );
        assert_eq!(s.records.len(), 1, "B's lock must survive");
    }

    #[test]
    fn re_locking_a_sub_range_does_not_shrink_the_lock_around_it() {
        // The whole file, then one byte of it, both write locks by the same
        // owner. The second must be absorbed, not replace the first: an
        // implementation that drops the overlapping lock and then merges what
        // is left ends up holding byte 0 alone.
        let mut s = Set::default();
        granted(&mut s, rec(0, 999, Kind::Write, A));
        granted(&mut s, rec(0, 0, Kind::Write, A));
        assert_eq!(s.records.len(), 1, "{:?}", s.records);
        assert_eq!((s.records[0].start, s.records[0].end), (0, 999));
    }

    #[test]
    fn locking_a_file_a_record_at_a_time_backwards_also_collapses() {
        // Descending order is what needs the merge to run to a fixed point:
        // each new record extends the range leftwards past one the previous
        // pass had already walked over.
        let mut s = Set::default();
        for i in (0..500).rev() {
            granted(&mut s, rec(i * 10, i * 10 + 9, Kind::Read, A));
        }
        assert_eq!(s.records.len(), 1, "{} records", s.records.len());
        assert_eq!((s.records[0].start, s.records[0].end), (0, 4999));
    }

    #[test]
    fn a_lock_to_the_end_of_the_file_does_not_overflow() {
        // A zero length in struct flock means "to the end", which is i64::MAX
        // here. Merging an adjacent lock must not compute MAX + 1.
        let mut s = Set::default();
        granted(&mut s, rec(0, i64::MAX, Kind::Write, A));
        granted(&mut s, rec(0, 9, Kind::Write, A));
        assert_eq!(s.records.len(), 1);
        assert_eq!(s.records[0].end, i64::MAX);
    }

    #[test]
    fn removing_an_owner_leaves_the_others() {
        let mut s = Set::default();
        granted(&mut s, rec(0, 9, Kind::Read, A));
        granted(&mut s, rec(0, 9, Kind::Read, B));
        assert!(s.remove_owner(A));
        assert_eq!(s.records.len(), 1);
        assert_eq!(s.records[0].owner, B);
        assert!(!s.remove_owner(A), "removing nothing reports nothing");
    }

    #[test]
    fn conflict_reports_the_lowest_lock_that_blocks() {
        // Ranges with a gap, so they stay two records: adjacent ones of the
        // same type and owner merge, which the merge tests cover.
        let mut s = Set::default();
        granted(&mut s, rec(200, 299, Kind::Write, B));
        granted(&mut s, rec(0, 99, Kind::Write, B));
        let found = s.conflict(&rec(0, 500, Kind::Read, A)).copied();
        assert_eq!(found.map(|r| (r.start, r.end)), Some((0, 99)));
    }
}
