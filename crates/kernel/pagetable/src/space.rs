//! What `mem->lock` protects, borrowed.
//!
//! **One `unsafe` per acquisition, and none per operation.** Every page-table
//! function used to take a `*mut ffi::mem` and say "the caller holds
//! `mem->lock`" in its `# Safety` section, so each of the tree's reads was an
//! `unsafe` block restating the lock. A view is that statement made once: it is
//! built from the raw address space by the thing that holds the lock -- a guard
//! in `memlock`, or the fault path's [`ReadHeld`] -- and every operation on it
//! is a safe method whose answers borrow the view.
//!
//! **Field projections, never a `&mem`.** Other threads read `mem.mmu` without
//! the lock -- the gadgets reach `mmu.changes` and `mmu.writers_waiting` on
//! every block. What the lock protects is `mem.locked`, an `UnsafeCell` since
//! 2026-10-17, so a `&mem` is sound and the views borrow the cell's fields
//! (`pgdir`, `pgdir_used`, `mmap_hint`, `reservations`, `image`), and
//! reach `mmu.changes` only through its atomic view.

use std::ffi::c_int;
use std::sync::atomic::{AtomicU64, Ordering};

use taskview::ffi;

use crate::PtEntry;
use crate::tree::{self, Extents, L0, Mapped};

/// The tree and the reservations, for a thread holding `mem->lock` on either
/// side.
#[derive(Clone, Copy)]
pub struct Space<'a> {
    pub(crate) root: Option<&'a L0>,
    pub(crate) reservations: &'a [ffi::Reservation],
    /// What `execve` put where, which the same lock covers.
    pub image: &'a ffi::Image,
}

impl<'a> Space<'a> {
    /// # Safety
    /// `mem` is live and this thread holds its lock, on either side, for `'a`.
    pub(crate) unsafe fn from_raw(mem: *mut ffi::mem) -> Space<'a> {
        // SAFETY: the caller's contract. What `locked` holds is written only
        // under the write lock, which excludes this thread's side, and `pgdir`
        // only by `mem_init` and `mem_destroy`.
        let locked = unsafe { &*(*mem).locked.get() };
        Space {
            // SAFETY: as above; the root lives as long as the space.
            root: unsafe { locked.pgdir.cast::<L0>().as_ref() },
            reservations: &locked.reservations,
            image: &locked.image,
        }
    }

    /// The entry for `page`, or `None` when nothing is mapped there.
    pub fn pt(self, page: u64) -> Option<&'a PtEntry> {
        tree::lookup(self.root?, page)
    }

    /// Step to the next page that could hold a mapping.
    pub fn next_page(self, page: &mut u64) {
        tree::next_page(self.root, page)
    }

    /// The mapped pages of a range with their entries, in order. What a walk
    /// over a range uses rather than [`Space::pt`] per page; see [`Mapped`].
    pub fn mapped(self, start: u64, pages: u64) -> Mapped<'a> {
        Mapped::new(self.root, start, pages)
    }

    /// The extents of a range: what a check per mapping rather than per page
    /// walks; see [`Extent`].
    pub fn extents(self, start: u64, pages: u64) -> Extents<'a> {
        Extents::new(self.mapped(start, pages))
    }

    /// The first mapped page of a range with any of `mask` in its flags.
    pub fn first_with_flags(self, start: u64, pages: u64, mask: u32) -> Option<u64> {
        self.extents(start, pages).find(|x| x.flags & mask != 0).map(|x| x.start)
    }

    /// Is every page of the range mapped or reserved?
    pub fn covered(self, start: u64, pages: u64) -> bool {
        let end = start.saturating_add(pages);
        let mut expect = start;
        for x in self.extents(start, pages) {
            if x.start != expect && !self.reserved(expect, x.start) {
                return false;
            }
            expect = x.start + x.pages;
        }
        self.reserved(expect, end)
    }

    /// Is every page of `[start, end)` inside some reservation?
    pub fn reserved(self, start: u64, end: u64) -> bool {
        self.reserved_until(start, end) == end
    }

    /// The first page of `[start, end)` that no reservation covers, or `end`.
    pub fn reserved_until(self, start: u64, end: u64) -> u64 {
        let mut page = start;
        while page < end {
            match self.find_reservation(page) {
                Some(r) => page = r.start + r.pages,
                None => return page,
            }
        }
        end
    }

    /// The first mapped page above `page`, or `None`.
    pub(crate) fn next_mapped(self, page: u64) -> Option<u64> {
        let mem_pages = ffi::MEM_PAGES;
        let mut p = page;
        self.next_page(&mut p);
        while p < mem_pages && self.pt(p).is_none() {
            self.next_page(&mut p);
        }
        (p < mem_pages).then_some(p)
    }

    /// The reservation `page` is in, as a copy.
    ///
    /// A copy, where it was a pointer into the list -- which an unmap could
    /// free, so the one caller that dropped the lock read the flags out first
    /// and said why. A value has no such window.
    pub fn find_reservation(self, page: u64) -> Option<ffi::Reservation> {
        self.reservations
            .iter()
            .copied()
            .find(|r| r.overlaps(page, 1))
    }

    /// Whether any reservation touches the range.
    pub(crate) fn overlaps_reservation(self, start: u64, pages: u64) -> bool {
        self.reservations.iter().any(|r| r.overlaps(start, pages))
    }

    /// Is every page in the range unmapped and unreserved?
    pub fn is_hole(self, start: u64, pages: u64) -> bool {
        if pages == 0 {
            return true;
        }
        let mem_pages = ffi::MEM_PAGES;
        let mut end = start + pages;
        // A range that runs off the end of the address space, or wraps: neither
        // can hold a mapping, and the lookup would alias high pages onto low
        // ones.
        if end > mem_pages || end < start {
            end = mem_pages;
        }
        // `next_page` increments before it skips, so the first page is checked
        // here rather than in the loop.
        if start < end && self.pt(start).is_some() {
            return false;
        }
        let mut page = start;
        while page < end {
            self.next_page(&mut page);
            if page >= end {
                break;
            }
            if self.pt(page).is_some() {
                return false;
            }
        }
        !self.overlaps_reservation(start, pages)
    }

    /// Does the host have a physical page behind this guest page?
    ///
    /// `mincore`'s answer, and the one thing about a mapping this emulator
    /// cannot work out for itself: `map_nothing` mmaps the whole range up
    /// front, so every mapped guest page looks backed from here while the
    /// *host* has not faulted in the ones nothing has touched. Telling the two
    /// apart is the entire point of the call -- an allocator uses it to decide
    /// which pages are worth returning.
    ///
    /// -1 if the page is not mapped at all.
    pub fn page_resident(self, page: u64) -> c_int {
        let Some(entry) = self.pt(page) else {
            return -1;
        };
        // A guard page has no page behind it on Linux: installing the guard
        // zapped it.
        if entry.flags() & ffi::P_GUARD != 0 {
            return 0;
        }
        // A mapping with no host memory behind it has nothing to ask about.
        if entry.data().is_none_or(|data| data.host().is_null()) {
            return -1;
        }
        let host = entry.host().unwrap();
        let mut vec: u8 = 0;
        // Darwin declares the vector `char *` and Linux `unsigned char *`, and
        // only the low bit is read either way.
        // SAFETY: `host` is one mapped guest page, which the lock keeps mapped,
        // and `vec` is the one byte a single page's answer needs.
        if unsafe { libc::mincore(host.cast(), ffi::PAGE_SIZE as usize, (&raw mut vec).cast()) } < 0
        {
            return -1;
        }
        (vec & 1) as c_int
    }

    /// Whether a refused access to `addr` is `SIGBUS`/`BUS_ADRERR` rather than
    /// `SIGSEGV`: the protection allows it and the page is past the end of
    /// its file. The same order `mem_ptr` refuses in.
    pub fn bus_error(self, addr: u64, write: bool) -> bool {
        self.pt(addr >> ffi::PAGE_BITS).is_some_and(|entry| {
            let flags = entry.flags();
            flags & (ffi::P_NOACCESS | ffi::P_GUARD | ffi::P_ANONYMOUS) == 0
                && (!write || flags & ffi::P_WRITE != 0)
                && entry.past_eof()
        })
    }

    /// The `si_code` of the `SIGSEGV` an access to `addr` earns: `SEGV_MAPERR`
    /// for an address with no mapping at all, `SEGV_ACCERR` for one whose
    /// protection refused it.
    ///
    /// A page inside a lazy reservation counts as mapped. A `PROT_NONE`
    /// `MAP_NORESERVE` region is a reservation here and has no page-table entry
    /// until something materialises one, but the guest asked for it and a
    /// fault inside it is the protection refusing the access -- `SEGV_ACCERR`,
    /// as Linux reports for a `PROT_NONE` VMA -- and not an address nothing is
    /// mapped at.
    ///
    /// **Generated, not written down.** The first version of this returned 0
    /// and 1, which are `SI_USER` and `SEGV_MAPERR`: every fault would have
    /// reported itself as sent by `kill`, and every protection fault as an
    /// unmapped address. `tests/guest/src/bin/signal_probe.rs` prints both
    /// codes.
    pub fn segv_reason(self, addr: u64) -> c_int {
        let page = addr >> ffi::PAGE_BITS;
        if self.pt(page).is_some() || self.find_reservation(page).is_some() {
            ffi::SEGV_ACCERR_ as c_int
        } else {
            ffi::SEGV_MAPERR_ as c_int
        }
    }
}

/// The same, for a thread holding `mem->lock` for writing: everything a change
/// to the address space touches.
pub struct SpaceMut<'a> {
    pub(crate) root: &'a mut L0,
    pub(crate) pgdir_used: &'a mut c_int,
    pub(crate) mmap_hint: &'a mut u64,
    pub(crate) reservations: &'a mut Vec<ffi::Reservation>,
    /// As [`Space::image`], to change.
    pub image: &'a mut ffi::Image,
    changes: &'a AtomicU64,
    /// The block cache, whose pages an unmap or a store invalidates. It is set
    /// by `mem_init` and cleared by `mem_destroy`, neither of which can run
    /// while the write lock is held by someone else.
    asbestos: Option<&'a asbestos_blockcache::Asbestos>,
}

impl<'a> SpaceMut<'a> {
    /// # Safety
    /// `mem` is live and initialised, and this thread holds its lock for
    /// writing for `'a`.
    pub(crate) unsafe fn from_raw(mem: *mut ffi::mem) -> SpaceMut<'a> {
        // SAFETY: the caller's contract. A `&mem` is sound -- what other
        // threads write is atomic or inside `locked` -- and the write lock
        // makes this the only borrow of `locked`.
        let mem = unsafe { &*mem };
        let locked = unsafe { &mut *mem.locked.get() };
        SpaceMut {
            // SAFETY: the root `mem_init` made, owned by the space.
            root: unsafe { locked.pgdir.cast::<L0>().as_mut() }.expect("a live address space has a root"),
            pgdir_used: &mut locked.pgdir_used,
            mmap_hint: &mut locked.mmap_hint,
            reservations: &mut locked.reservations,
            image: &mut locked.image,
            changes: &mem.mmu.changes,
            // SAFETY: `mem_init`'s, or null; freed only by `mem_destroy`,
            // which the write lock excludes.
            asbestos: unsafe { asbestos_blockcache::Asbestos::of(mem.mmu.asbestos) },
        }
    }

    /// The read view of the same address space.
    pub fn space(&self) -> Space<'_> {
        Space {
            root: Some(self.root),
            reservations: self.reservations,
            image: self.image,
        }
    }

    /// Bump the change generation, so another thread's TLB coherence check
    /// forces a re-translate.
    pub(crate) fn changed(&self) {
        self.changes.fetch_add(1, Ordering::Release);
    }

    /// Any compiled blocks for `page` are about to be wrong.
    pub(crate) fn invalidate(&self, page: u64) {
        if let Some(asbestos) = self.asbestos {
            asbestos.invalidate_page(page);
        }
    }

    /// The entry for `page`, creating the levels above it.
    pub(crate) fn entry_new(&mut self, page: u64) -> &mut PtEntry {
        tree::entry_new(self.root, self.pgdir_used, page)
    }
}

/// The read lock on `mem`, held by this thread's caller -- the fault path's
/// proof, which has no guard to borrow because the lock was taken several
/// frames up on the interpreter's hot path.
///
/// [`ReadHeld::upgraded`] takes `&mut self`, so a [`Space`] borrowed from it
/// cannot be alive across the window where the lock is down. That was a
/// comment on each of the two callers.
pub struct ReadHeld(*mut ffi::mem);

impl ReadHeld {
    /// # Safety
    /// `mem` is live and this thread holds its read lock, and no other side of
    /// it, for as long as the answer is alive.
    pub unsafe fn assume(mem: *mut ffi::mem) -> ReadHeld {
        ReadHeld(mem)
    }

    pub fn space(&self) -> Space<'_> {
        // SAFETY: `assume`'s contract.
        unsafe { Space::from_raw(self.0) }
    }

    /// Swap the read lock for the write lock, run `f`, and take the read lock
    /// back -- on the way out **and** on an unwind. See
    /// [`crate::memlock::upgraded`].
    ///
    /// **The window is real and is not this function's to close**: another
    /// thread may map the same page while the lock is down, which is why every
    /// caller re-reads the entry inside `f`. Linux's `handle_mm_fault` does the
    /// same thing with `mmap_lock` and the same re-read.
    pub fn upgraded<T>(&mut self, f: impl FnOnce(&mut SpaceMut<'_>) -> T) -> T {
        let mem = self.0;
        // SAFETY: `assume`'s contract is the read lock `upgraded` asks for,
        // and inside the closure the write lock is held.
        unsafe { crate::memlock::upgraded(mem, || f(&mut SpaceMut::from_raw(mem))) }
    }

    /// Bump the change generation, for a change made under the read lock --
    /// the W^X clear, whose flag is atomic.
    pub(crate) fn changed(&self) {
        // SAFETY: the live address space this handle names; one atomic field.
        unsafe { (*self.0).mmu.changes.fetch_add(1, Ordering::Release) };
    }

    /// As [`SpaceMut::invalidate`], which the read lock also permits: the
    /// cache has its own lock.
    pub(crate) fn invalidate(&self, page: u64) {
        // SAFETY: as `SpaceMut::from_raw`; the read lock also excludes
        // `mem_destroy`.
        if let Some(asbestos) = unsafe { asbestos_blockcache::Asbestos::of((*self.0).mmu.asbestos) } {
            asbestos.invalidate_page(page);
        }
    }
}
