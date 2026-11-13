//! Lazy address-space reservations and hole finding.

use std::ffi::c_uint;

use guest_errno::Errno;
use taskview::ffi;

use crate::space::{Space, SpaceMut};
use crate::tree::{PT_BITS, index};

// ---------------------------------------------------------------------------
// Reservations
// ---------------------------------------------------------------------------

impl SpaceMut<'_> {
    /// An address range promised but not yet backed -- V8's heap cage,
    /// reserved `PROT_NONE` and committed a chunk at a time.
    pub fn map_lazy(&mut self, start: u64, pages: u64, flags: c_uint) -> Result<(), Errno> {
        if self.reservations.try_reserve(1).is_err() {
            return Err(Errno::ENOMEM);
        }
        self.reservations.push(ffi::Reservation {
            start,
            pages,
            flags: flags | ffi::P_ANONYMOUS,
        });
        self.changed();
        Ok(())
    }

    /// Drop, or split, every reservation the range touches.
    pub(crate) fn remove_reservations(&mut self, start: u64, pages: u64) {
        let end = start + pages;
        // In place. A range that punches a hole in the middle of one
        // reservation leaves two pieces of it, and that is the only way to gain
        // an entry: reservations do not overlap each other, so one removal
        // splits at most one of them.
        let mut split_off = None;
        self.reservations.retain_mut(|r| {
            if !r.overlaps(start, pages) {
                return true;
            }
            let r_end = r.start + r.pages;
            // Whatever is left of it, either side of the hole.
            let head = start.saturating_sub(r.start).min(r.pages);
            let tail = (r_end > end).then(|| ffi::Reservation {
                start: end,
                pages: r_end - end,
                ..*r
            });
            match (head > 0, tail) {
                (true, tail) => {
                    r.pages = head;
                    split_off = tail;
                    true
                }
                (false, Some(tail)) => {
                    *r = tail;
                    true
                }
                (false, None) => false,
            }
        });
        // The one allocation, and a refusal loses the tail -- which is what a
        // failed `malloc` of the node did before, and all a reservation is is a
        // promise the guest has not yet taken up.
        if let Some(tail) = split_off
            && self.reservations.try_reserve(1).is_ok()
        {
            self.reservations.push(tail);
        }
        self.changed();
    }

    /// Somewhere to put `size` pages, or `BAD_PAGE`.
    ///
    /// **Here and not on the read view**, since 2026-09-30: the search moves
    /// `mmap_hint`, and it was reachable through a trait both guards
    /// implemented, so a caller holding only the read lock could have written
    /// the hint. None did; the type now says none can.
    pub fn find_hole(&mut self, size: u64) -> u64 {
        self.find_hole_and_hint(size, false)
    }

    /// As [`SpaceMut::find_hole`], for a lazy reservation, which prefers an
    /// address above 4 GB.
    pub fn find_hole_for_reservation(&mut self, size: u64) -> u64 {
        self.find_hole_and_hint(size, true)
    }

    fn find_hole_and_hint(&mut self, size: u64, prefer_high: bool) -> u64 {
        let (result, hint) = self.space().find_hole(size, prefer_high, *self.mmap_hint);
        if let Some(hint) = hint {
            *self.mmap_hint = hint;
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Finding somewhere to put a mapping
// ---------------------------------------------------------------------------

/// The largest page a subtree at `level` covers, and the base of the one `page`
/// is in.
fn subtree_base(page: u64, level: u32) -> u64 {
    let bits = PT_BITS * (3 - level);
    (page >> bits) << bits
}

/// The search reads the tree and the reservations and answers the new hint
/// rather than storing it; [`SpaceMut::find_hole`] stores it.
impl Space<'_> {
    fn is_mapped(&self, page: u64) -> bool {
        self.pt(page).is_some()
    }

    /// The first level, 0 to 2, with no node for `page`, or `None` when the
    /// leaf exists.
    fn first_empty_level(&self, page: u64) -> Option<u32> {
        let Some(l0) = self.root else {
            return Some(0);
        };
        let Some(l1) = &l0.children[index(page, 0)] else {
            return Some(0);
        };
        let Some(l2) = &l1.children[index(page, 1)] else {
            return Some(1);
        };
        if l2.children[index(page, 2)].is_none() {
            return Some(2);
        }
        None
    }

    /// Scan **downward** from `start` for `size` free pages, skipping whole
    /// unallocated subtrees — an L0 child covers 2^27 pages, an L1 child
    /// 2^18, an L2 child 512.
    fn find_hole_from(&self, size: u64, start: u64) -> u64 {
        let hole_end_floor = ffi::MMAP_HOLE_END as u64;
        let mut hole_end = 0u64;
        let mut in_hole = false;
        let mut page = start;

        while page > hole_end_floor {
            // Which level, if any, has no node for this page.
            if let Some(level) = self.first_empty_level(page) {
                let base = subtree_base(page, level);
                if !in_hole {
                    in_hole = true;
                    hole_end = page + 1;
                }
                // The search never goes below MMAP_HOLE_END, so a subtree that
                // starts under it is only free from there up.
                let effective = base.max(hole_end_floor + 1);
                if hole_end.saturating_sub(effective) >= size {
                    return hole_end - size;
                }
                if base == 0 {
                    break;
                }
                page = base - 1;
                continue;
            }
            // A populated leaf: ask page by page.
            if self.is_mapped(page) {
                in_hole = false;
            } else {
                if !in_hole {
                    in_hole = true;
                    hole_end = page + 1;
                }
                if hole_end - page >= size {
                    return page;
                }
            }
            if page == 0 {
                break;
            }
            page -= 1;
        }
        ffi::BAD_PAGE
    }

    /// Scan **upward** above 4 GB, for an allocation too large to fit below.
    ///
    /// A subtree with no page-table nodes can still be covered by a lazy
    /// reservation — JSC's 512 GB gigacage, V8's heap cage — which creates no
    /// nodes. So a reserved subtree counts as occupied: without that this
    /// hands back a hole that the reservation check then rejects, and the
    /// `mmap` answers `ENOMEM` with plenty of free address space above the
    /// reservation.
    fn find_hole_high(&self, size: u64) -> u64 {
        let max = ffi::USER_ADDR_MAX_PAGE;
        let l0_size = 1u64 << (PT_BITS * 3);
        let mut page = 0x100000u64; // 4 GB
        let mut hole_start = page;
        let mut hole_size = 0u64;

        while page < max {
            let base = subtree_base(page, 0);
            let end = (base + l0_size).min(max);
            let mapped = self
                .root
                .is_some_and(|l0| l0.children[index(page, 0)].is_some());
            if mapped || self.overlaps_reservation(base, l0_size) {
                hole_size = 0;
            } else {
                if hole_size == 0 {
                    hole_start = base.max(page);
                }
                hole_size = end - hole_start;
                if hole_size >= size {
                    return hole_start;
                }
            }
            page = end;
        }
        ffi::BAD_PAGE
    }

    /// Somewhere to put `size` pages, and the new `mmap_hint` when the low
    /// search found it.
    ///
    /// `prefer_high` asks for addresses above 4 GB, which is what a large V8
    /// heap-cage reservation wants: node's V8 without pointer compression
    /// stores full 64-bit tagged pointers, so a heap placed in the low 4 GB
    /// makes a garbage 24-bit slot value like `0x00c39b1b` indistinguishable
    /// from a real heap pointer, and V8's later dereference lands on an
    /// unmapped page. Above 4 GB such a value is obviously not canonical and
    /// V8's own null checks catch it.
    fn find_hole(&self, size: u64, prefer_high: bool, hint: u64) -> (u64, Option<u64>) {
        let bad = ffi::BAD_PAGE;
        if prefer_high {
            let result = self.find_hole_high(size);
            if result != bad && !self.overlaps_reservation(result, size) {
                return (result, None);
            }
            // Fall through to the low search as a last resort.
        }

        let hole_start = ffi::MMAP_HOLE_START as u64;
        let hole_end = ffi::MMAP_HOLE_END as u64;
        let mut start = if hint == 0 || hint > hole_start || hint <= hole_end + size {
            hole_start
        } else {
            hint
        };

        // Twice: once from the hint, and once from the top if the hint was
        // below it. A candidate that overlaps a reservation is retried below
        // that reservation, up to ten times.
        for round in 0..2 {
            if round == 1 {
                if start >= hole_start {
                    break;
                }
                start = hole_start;
            }
            for _ in 0..10 {
                let result = self.find_hole_from(size, start);
                if result == bad {
                    break;
                }
                // Skip below the reservation that got in the way, or take it.
                match self.reservations.iter().find(|r| r.overlaps(result, size)) {
                    None => return (result, Some(result.saturating_sub(1))),
                    Some(r) => start = r.start.saturating_sub(1),
                }
            }
        }

        // The low 4 GB is exhausted; try above it.
        if !prefer_high {
            let result = self.find_hole_high(size);
            if result != bad && !self.overlaps_reservation(result, size) {
                return (result, None);
            }
        }
        (bad, None)
    }
}
