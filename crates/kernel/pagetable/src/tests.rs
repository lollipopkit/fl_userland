//! Unit tests for page-table accounting and mapping behavior.

use super::*;
use crate::mapping::charged;
use crate::tree::{Interior, Leaf, PT_ENTRIES, index};

/// The anonymous-page budget counts a page the guest can reach, and the
/// same test decides the charge and the refund.
///
/// The two were different questions before 2026-09-04: the charge asked
/// whether the protection was `PROT_NONE` and the refund asked only whether
/// the page was anonymous, so glibc's per-thread malloc arena — a
/// `mmap(64 MB, PROT_NONE)` — gave back 16384 pages it had never taken. Two
/// of those and the total is negative, which makes `sysinfo` and
/// `/proc/meminfo` report half the machine and **raises** the budget,
/// because `anon_pages_try_add` compares against a number below zero.
#[test]
fn the_budget_counts_a_page_the_guest_can_reach() {
    let anon = ffi::P_ANONYMOUS;
    assert!(charged(anon | ffi::P_READ));
    assert!(charged(anon | ffi::P_WRITE));
    assert!(charged(anon | ffi::P_READ | ffi::P_WRITE | ffi::P_EXEC));
    // A guard region: address space and nothing else, which is what Linux
    // maps VM_NORESERVE.
    assert!(!charged(anon | ffi::P_NOACCESS));
    // File-backed is never counted, reachable or not.
    assert!(!charged(ffi::P_READ | ffi::P_WRITE));
    assert!(!charged(ffi::P_NOACCESS));
    assert!(!charged(0));
    // The bits that say nothing about either question do not change it.
    assert!(charged(anon | ffi::P_WRITE | ffi::P_COW | ffi::P_GROWSDOWN));
}

/// `mprotect` is a transition, and the difference of the two answers is
/// what `pt_set_flags` adds up — so an `mmap(PROT_NONE)` followed by an
/// `mprotect(PROT_READ|PROT_WRITE)` and a `munmap` nets to zero.
#[test]
fn an_mprotect_charges_the_difference() {
    let anon = ffi::P_ANONYMOUS;
    let delta = |old: u32, new: u32| i64::from(charged(new)) - i64::from(charged(old));
    let none = anon | ffi::P_NOACCESS;
    let rw = anon | ffi::P_READ | ffi::P_WRITE;
    assert_eq!(delta(none, rw), 1, "committing a guard page charges");
    assert_eq!(delta(rw, none), -1, "revoking it gives the page back");
    assert_eq!(delta(rw, anon | ffi::P_READ), 0, "still reachable");
    assert_eq!(delta(none, none), 0);
    // The whole life of a glibc arena: reserve, commit, unmap.
    let mut total = 0i64;
    total += 0; // mmap(PROT_NONE) charges nothing
    total += delta(none, rw); // mprotect the piece it wants
    total -= i64::from(charged(rw)); // munmap
    assert_eq!(total, 0);
}

#[test]
fn the_four_levels_index_nine_bits_each() {
    // A 36-bit page number, nine bits per level, most significant first.
    // Getting the shift backwards makes the tree work and the walk skip
    // the wrong subtree, which mem_next_page turns into a lost mapping.
    let page = 0b111111111_000000001_000000010_000000011u64;
    assert_eq!(index(page, 0), 0b111111111);
    assert_eq!(index(page, 1), 0b000000001);
    assert_eq!(index(page, 2), 0b000000010);
    assert_eq!(index(page, 3), 0b000000011);
}

#[test]
fn page_zero_indexes_zero_at_every_level() {
    for level in 0..4 {
        assert_eq!(index(0, level), 0);
    }
}

#[test]
fn the_whole_low_four_gigabytes_is_one_l0_child_and_four_l1_children() {
    // Which is why the stack and mmap live there: a walk for a low address
    // touches one L0 node and one of four L1 nodes, and those five stay
    // hot. `kernel/memory.h` says "the first two levels are always index
    // 0", and that is true of the low **gigabyte** -- an L1 child covers
    // 2^18 pages. The looser claim is what matters and is what this
    // asserts; the tighter one is what the first version of this test
    // asserted, and it failed.
    let pages_in_4gb = (4u64 << 30) >> 12;
    let mut l1_seen = std::collections::BTreeSet::new();
    for page in [0, 1, 1 << 17, 1 << 18, pages_in_4gb - 1] {
        assert_eq!(index(page, 0), 0, "page {page:#x}");
        l1_seen.insert(index(page, 1));
    }
    assert_eq!(l1_seen, [0, 1, 3].into_iter().collect());
    assert_eq!(index(pages_in_4gb - 1, 1), 3, "the last of the four");
    assert_eq!(index(pages_in_4gb, 1), 4, "and the first one past it");
}

#[test]
fn an_interior_node_is_five_hundred_and_twelve_null_pointers() {
    // Which is what makes it the same shape as the C's calloc'd
    // `void *children[512]`: an Option<Box<T>> is null when it is None.
    assert_eq!(PT_ENTRIES, 512);
    assert_eq!(
        size_of::<Interior<Leaf>>(),
        PT_ENTRIES * size_of::<*mut ()>()
    );
    assert_eq!(size_of::<Option<Box<Leaf>>>(), size_of::<*mut ()>());
}
