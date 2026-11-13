//! The leaf-at-a-time walks over a range: `Space::extents`, `Space::covered`
//! and `SpaceMut::set_flags`.
//!
//! They replaced a root-to-leaf lookup per page, and what they must keep is the
//! answer that lookup gave. So each case is checked against that lookup, over a
//! layout with the shapes a leaf walk can get wrong: a mapping crossing a leaf
//! boundary, two mappings touching, a hole inside a leaf, and a range running
//! through subtrees that were never allocated.

use std::ffi::c_uint;

use guest_errno::Errno;
use pagetable::memlock::{self, Held};
use taskview::ffi;

const RW: c_uint = ffi::P_READ | ffi::P_WRITE;

fn fresh_mem() -> *mut ffi::mem {
    let mem: *mut ffi::mem = Box::into_raw(Box::new(ffi::mem::default()));
    unsafe { pagetable::mem_init(mem) };
    mem
}

/// The extents as `(start, pages, flags)`.
fn extents(held: &impl Held, start: u64, pages: u64) -> Vec<(u64, u64, u32)> {
    held.extents(start, pages).map(|x| (x.start, x.pages, x.flags)).collect()
}

/// The same answer from one lookup per page, which is what the walk replaced.
fn extents_by_lookup(held: &impl Held, start: u64, pages: u64) -> Vec<(u64, u64, u32)> {
    let mut out: Vec<(u64, u64, u32, *const pagetable::Data)> = Vec::new();
    for page in start..start + pages {
        let Some(entry) = held.pt(page) else { continue };
        let data = std::sync::Arc::as_ptr(entry.data().unwrap());
        match out.last_mut() {
            Some(last) if last.0 + last.1 == page && last.2 == entry.flags() && last.3 == data => last.1 += 1,
            _ => out.push((page, 1, entry.flags(), data)),
        }
    }
    out.into_iter().map(|(s, p, f, _)| (s, p, f)).collect()
}

#[test]
fn a_walk_by_leaf_answers_what_a_lookup_per_page_did() {
    let mem = fresh_mem();
    // SAFETY: `fresh_mem` just made it and this thread holds neither side.
    let mut g = unsafe { memlock::WriteGuard::new(mem) };
    let anon = RW | ffi::P_ANONYMOUS;
    // 600 pages from a leaf boundary, so it ends 88 pages into the next leaf.
    g.map_nothing(0x1000, 600, anon).unwrap();
    // A second mapping touching the first: the same flags, another extent.
    g.map_nothing(0x1258, 8, anon).unwrap();
    // A hole of 160 pages, then a page in the same leaf.
    g.map_nothing(0x1300, 1, anon).unwrap();
    // And one in an L0 subtree of its own, past a range of nothing.
    let far = 1u64 << 30;
    g.map_nothing(far, 3, anon).unwrap();

    let want = vec![(0x1000, 600, anon), (0x1258, 8, anon), (0x1300, 1, anon), (far, 3, anon)];
    assert_eq!(extents(&g, 0x1000, far + 3 - 0x1000), want);
    // The lookup per page is too slow for a billion pages; the near half is
    // where every leaf-boundary case is.
    assert_eq!(extents(&g, 0, 0x2000), extents_by_lookup(&g, 0, 0x2000));
    // A range that starts and ends inside extents cuts them.
    assert_eq!(extents(&g, 0x1100, 0x15c), vec![(0x1100, 0x158, anon), (0x1258, 4, anon)]);
    assert_eq!(extents(&g, 0x1260, 0xa0), vec![], "the hole alone");
    // One mapping on both sides of leaves that were never allocated: the
    // last page of a leaf, and a duplicate of it two leaves on. Adjacent in
    // the walk and not in the address space, so two extents.
    g.map_nothing(0x15ff, 1, anon).unwrap();
    g.duplicate_pages(0x15ff, 0x1a00, 1);
    assert_eq!(extents(&g, 0x1500, 0x600), vec![(0x15ff, 1, anon), (0x1a00, 1, anon)]);

    // A change of flags in the middle of one mapping splits its extent.
    g.set_flags(0x1100, 0x160, ffi::P_READ as i32).unwrap();
    let ro = ffi::P_READ | ffi::P_ANONYMOUS;
    assert_eq!(
        extents(&g, 0x1000, 0x400),
        vec![(0x1000, 0x100, anon), (0x1100, 0x158, ro), (0x1258, 8, ro), (0x1300, 1, anon)]
    );
    assert_eq!(extents(&g, 0, 0x2000), extents_by_lookup(&g, 0, 0x2000));

    // Covered: a hole is not, until it is reserved.
    assert!(g.covered(0x1000, 0x260));
    assert!(!g.covered(0x1000, 0x301), "the hole at 0x1260");
    assert!(!g.covered(0x1300, 2), "the page after the last one");
    g.map_lazy(0x1260, 0xa0, 0).unwrap();
    assert!(g.covered(0x1000, 0x301));
    assert!(!g.covered(far - 1, 4), "nothing before the far mapping");
    assert!(g.covered(far, 3));

    drop(g);
    unsafe { pagetable::mem_destroy(mem) };
}

/// `set_flags` stops at a page that is neither mapped nor reserved, having
/// changed the pages before it, and commits a reserved hole on the way.
#[test]
fn set_flags_changes_up_to_a_hole_and_commits_a_reservation() {
    let mem = fresh_mem();
    // SAFETY: as above.
    let mut g = unsafe { memlock::WriteGuard::new(mem) };
    let anon = ffi::P_READ | ffi::P_ANONYMOUS;
    g.map_nothing(0x2000, 4, anon).unwrap();
    g.map_lazy(0x2004, 4, 0).unwrap();
    g.map_nothing(0x2008, 4, anon).unwrap();
    // 0x200c..0x2010 is nothing at all.
    g.map_nothing(0x2010, 4, anon).unwrap();

    assert_eq!(g.set_flags(0x2000, 0x14, RW as i32), Err(Errno::ENOMEM));
    let rw = RW | ffi::P_ANONYMOUS;
    assert_eq!(
        extents(&g, 0x2000, 0x14),
        vec![(0x2000, 4, rw), (0x2004, 4, rw), (0x2008, 4, rw), (0x2010, 4, anon)],
        "the reservation is committed, and the pages past the hole are not changed"
    );
    // The change reached the host: every committed page takes a write.
    for page in 0x2000..0x200c {
        let host = g.pt(page).unwrap().host().unwrap();
        unsafe { host.write_volatile(1) };
    }

    drop(g);
    unsafe { pagetable::mem_destroy(mem) };
}
