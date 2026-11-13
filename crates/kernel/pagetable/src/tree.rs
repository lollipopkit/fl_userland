//! The typed radix tree backing guest page mappings.

use std::ffi::c_int;
use std::sync::Arc;

use crate::PtEntry;
use taskview::ffi;

/// Nine bits per level, four levels.
pub(crate) const PT_BITS: u32 = 9;
pub(crate) const PT_ENTRIES: usize = 1 << PT_BITS;

pub(crate) fn index(page: u64, level: u32) -> usize {
    ((page >> (PT_BITS * (3 - level))) & (PT_ENTRIES as u64 - 1)) as usize
}

// ---------------------------------------------------------------------------
// The tree
// ---------------------------------------------------------------------------

/// An interior node: L0, L1 or L2.
///
/// `Option<Box<_>>` is a null pointer when it is `None`, which is what makes
/// this the same shape in memory as the C's `void *children[512]` — and the
/// C's `calloc` produced exactly that.
pub(crate) struct Interior<T> {
    pub(crate) children: [Option<Box<T>>; PT_ENTRIES],
}

impl<T> Interior<T> {
    pub(crate) fn new() -> Box<Interior<T>> {
        Box::new(Interior {
            children: [const { None }; PT_ENTRIES],
        })
    }
}

/// The leaves: 512 entries, allocated together.
pub(crate) struct Leaf {
    entries: [PtEntry; PT_ENTRIES],
}

pub(crate) type L2 = Interior<Leaf>;
pub(crate) type L1 = Interior<L2>;
pub(crate) type L0 = Interior<L1>;

/// The slot for `page` in an allocated leaf, mapped or not.
///
/// **`None` above the address space.** The index takes nine bits a level, so a
/// page number of 2^36 or more selects the slot its low 36 bits name: a guest
/// load from 0x0001_xxxx_xxxx_xxxx read the page at 0x0000_xxxx_xxxx_xxxx
/// rather than faulting, as it does on a real kernel, and a branch there was
/// judged fetchable. Until 2026-10-18 (`tests/guest` bad_pc_addr).
fn slot(l0: &L0, page: u64) -> Option<&PtEntry> {
    if page >= ffi::MEM_PAGES {
        return None;
    }
    let l1 = l0.children[index(page, 0)].as_deref()?;
    let l2 = l1.children[index(page, 1)].as_deref()?;
    let leaf = l2.children[index(page, 2)].as_deref()?;
    Some(&leaf.entries[index(page, 3)])
}

/// As [`slot`], for writing.
fn slot_mut(l0: &mut L0, page: u64) -> Option<&mut PtEntry> {
    if page >= ffi::MEM_PAGES {
        return None;
    }
    let l1 = l0.children[index(page, 0)].as_deref_mut()?;
    let l2 = l1.children[index(page, 1)].as_deref_mut()?;
    let leaf = l2.children[index(page, 2)].as_deref_mut()?;
    Some(&mut leaf.entries[index(page, 3)])
}

/// The entry for `page`, or `None` when nothing is mapped there.
pub(crate) fn lookup(l0: &L0, page: u64) -> Option<&PtEntry> {
    // An entry with no `data` is a slot in an allocated leaf, not a mapping.
    slot(l0, page).filter(|entry| entry.data().is_some())
}

/// The entry for `page`, creating the levels above it. `pgdir_used` counts the
/// L1 nodes, which is what `struct mem` reports it as.
pub(crate) fn entry_new<'a>(l0: &'a mut L0, pgdir_used: &mut c_int, page: u64) -> &'a mut PtEntry {
    // A mapping is made only after its range was checked against the address
    // space; one above it would alias a low page, as `slot` explains.
    debug_assert!(page < ffi::MEM_PAGES, "a mapping above the address space: page {page:#x}");
    let l1 = l0.children[index(page, 0)].get_or_insert_with(|| {
        *pgdir_used += 1;
        Interior::new()
    });
    let l2 = l1.children[index(page, 1)].get_or_insert_with(Interior::new);
    // `PtEntry::default()` is the unmapped state that the former C `calloc`
    // produced, while keeping the leaf allocation typed and safe. `from_fn`
    // rather than a repeated `Default`: an entry holds an atomic and so is not
    // `Copy`.
    let leaf = l2.children[index(page, 2)].get_or_insert_with(|| {
        Box::new(Leaf {
            entries: std::array::from_fn(|_| PtEntry::default()),
        })
    });
    &mut leaf.entries[index(page, 3)]
}

/// Forget the mapping at `page`, leaving the leaf allocated.
///
/// **Answers the reference the entry held**, rather than dropping it here: the
/// caller decides where the teardown runs, and for an unmap that is one line
/// later with a comment saying which lock is held. Dropping the result is what
/// can run [`crate::Data::drop`].
#[must_use = "this is the entry's reference; dropping it is the unmap"]
pub(crate) fn entry_del(l0: &mut L0, page: u64) -> Option<Arc<crate::Data>> {
    slot_mut(l0, page)?.take_data()
}

/// The leaf holding `page`, or the first page past the absent subtree it is
/// in -- an L0 child covers 2^27 pages, an L1 child 2^18, an L2 child 512.
fn leaf_of(l0: &L0, page: u64) -> Result<&Leaf, u64> {
    let past = |level: u32| ((page >> (PT_BITS * (3 - level))) + 1) << (PT_BITS * (3 - level));
    let l1 = l0.children[index(page, 0)].as_deref().ok_or_else(|| past(0))?;
    let l2 = l1.children[index(page, 1)].as_deref().ok_or_else(|| past(1))?;
    l2.children[index(page, 2)].as_deref().ok_or_else(|| past(2))
}

/// Step to the next page that could hold a mapping, skipping whole unallocated
/// subtrees.
pub(crate) fn next_page(root: Option<&L0>, page: &mut u64) {
    let mem_pages = ffi::MEM_PAGES;
    *page += 1;
    let Some(l0) = root else {
        *page = (*page).max(mem_pages);
        return;
    };
    while *page < mem_pages {
        match leaf_of(l0, *page) {
            // A populated leaf: a mapping may be here.
            Ok(_) => return,
            Err(past) => *page = past,
        }
    }
}

/// The mapped pages of a range, in order.
///
/// Leaf by leaf: the tree is descended once per 512 pages and an absent
/// subtree is skipped whole. A [`lookup`] per page descends all four levels
/// every time, and `mprotect` asked that of every page of its range four
/// times over -- 7 ns a page in a release build, where the call itself costs
/// 450 ns (`tests/guest/src/bin/mprotect_scaling.rs`).
pub struct Mapped<'a> {
    l0: Option<&'a L0>,
    /// The rest of the current leaf's slots in the range; the first is `page`.
    slots: std::slice::Iter<'a, PtEntry>,
    page: u64,
    end: u64,
}

impl<'a> Mapped<'a> {
    pub(crate) fn new(l0: Option<&'a L0>, start: u64, pages: u64) -> Mapped<'a> {
        let end = start.saturating_add(pages).min(ffi::MEM_PAGES);
        Mapped { l0, slots: [].iter(), page: start, end }
    }
}

impl Mapped<'_> {
    /// Point `slots` at the leaf `page` is in, from `page` to the end of the
    /// leaf or the range, skipping absent subtrees. False at the end.
    fn refill(&mut self) -> bool {
        let Some(l0) = self.l0 else {
            return false;
        };
        while self.page < self.end {
            match leaf_of(l0, self.page) {
                Ok(leaf) => {
                    let at = index(self.page, 3);
                    let len = (PT_ENTRIES - at).min((self.end - self.page) as usize);
                    self.slots = leaf.entries[at..at + len].iter();
                    return true;
                }
                Err(past) => self.page = past,
            }
        }
        false
    }
}

impl<'a> Iterator for Mapped<'a> {
    type Item = (u64, &'a PtEntry);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            for entry in self.slots.by_ref() {
                let page = self.page;
                self.page += 1;
                if entry.data().is_some() {
                    return Some((page, entry));
                }
            }
            if !self.refill() {
                return None;
            }
        }
    }
}

/// Consecutive mapped pages that point at one mapping with one set of flags:
/// the nearest thing this page table has to a Linux VMA, and the unit a check
/// that Linux makes per VMA is made over.
#[derive(Clone, Copy)]
pub struct Extent<'a> {
    pub start: u64,
    pub pages: u64,
    pub flags: u32,
    pub data: &'a Arc<crate::Data>,
}

/// The extents of a range, in order. The walk is per page, inside this crate
/// and a leaf's slots at a time; what a caller does with each answer is per
/// extent.
pub struct Extents<'a> {
    pages: Mapped<'a>,
}

impl<'a> Extents<'a> {
    pub(crate) fn new(pages: Mapped<'a>) -> Extents<'a> {
        Extents { pages }
    }
}

impl<'a> Iterator for Extents<'a> {
    type Item = Extent<'a>;

    fn next(&mut self) -> Option<Extent<'a>> {
        let (start, first) = self.pages.next()?;
        let data = first.data()?;
        let mut extent = Extent { start, pages: 1, flags: first.flags(), data };
        loop {
            let rest = self.pages.slots.as_slice();
            // An empty slot has no data and ends the extent as a different
            // mapping does; `Mapped` then skips it.
            let same = rest
                .iter()
                .take_while(|e| e.flags() == extent.flags && e.data().is_some_and(|d| Arc::ptr_eq(d, data)))
                .count();
            self.pages.slots = rest[same..].iter();
            self.pages.page += same as u64;
            extent.pages += same as u64;
            if same < rest.len() || !self.pages.refill() || self.pages.page != extent.start + extent.pages {
                return Some(extent);
            }
        }
    }
}
