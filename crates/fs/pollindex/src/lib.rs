//! The duplicate-description merge used by one poll() call.
//!
//! A poll array can name one open file description several times. Merging those
//! entries before building the transient C set makes registration linear. The
//! persistent epoll indexes that originally lived here moved with epoll state to
//! `crates/kernel/epoll`.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Merging one poll() call's entries
// ---------------------------------------------------------------------------

/// First index seen for each description, for `sys_poll`'s merge.
///
/// A `poll()` array may name one description more than once — the same
/// descriptor twice, or two numbers for it after a `dup` — and the events asked
/// for have to be OR'd together so it is registered once. `sys_poll` did that
/// with a nested loop over the whole array, under a comment saying "the merge
/// is quadratic and it does not matter", measured at 256 entries.
///
/// At 256 it does not. At 1800 the same loop is 49 times the work, and it is
/// what a `poll()` over 1800 descriptors that need no host registration spends
/// its time on: 1.16 ms, growing per descriptor as the array grows.
///
/// One pass with a map is linear.
#[derive(Default)]
pub struct Merge {
    first: BTreeMap<usize, usize>,
}

impl Merge {
    pub fn new() -> Merge {
        Merge::default()
    }

    /// The index this description was first seen at, or `None` if this is it.
    pub fn find_or_insert(&mut self, fd: usize, index: usize) -> Option<usize> {
        match self.first.entry(fd) {
            alloc::collections::btree_map::Entry::Occupied(e) => Some(*e.get()),
            alloc::collections::btree_map::Entry::Vacant(e) => {
                e.insert(index);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_entry_for_a_description_wins() {
        let mut m = Merge::new();
        assert_eq!(m.find_or_insert(0x100, 0), None, "the first time");
        assert_eq!(m.find_or_insert(0x200, 1), None);
        assert_eq!(m.find_or_insert(0x100, 2), Some(0), "folds into index 0");
        assert_eq!(m.find_or_insert(0x100, 5), Some(0), "and still index 0");
        assert_eq!(m.find_or_insert(0x200, 9), Some(1));
    }

    /// Every entry distinct: nothing merges, and each is its own first.
    #[test]
    fn distinct_descriptions_never_merge() {
        let mut m = Merge::new();
        for i in 0..2000 {
            assert_eq!(m.find_or_insert(0x1000 + i, i), None, "entry {i}");
        }
    }
}
