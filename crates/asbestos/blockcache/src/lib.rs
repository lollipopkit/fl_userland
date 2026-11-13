//! Which compiled blocks exist, where to find one, and which ones a mapping
//! change has to throw away.
//!
//! Three collections out of `asbestos/asbestos.c`: the table keyed by guest
//! address, the index keyed by guest *page* — so an `munmap` can find what it
//! invalidates without walking every block — and the jetsam list, which is
//! what a block goes on when it has been disconnected but may still be
//! executing on another thread.
//!
//! # The struct could change, which is why this is possible at all
//!
//! `struct fiber_block`'s layout is a contract with the gadgets, but only for
//! two fields: `entry.S` does `add _pc, x0, #FIBER_BLOCK_code`, and
//! `asbestos/offsets.c` **computes** `FIBER_BLOCK_code` at build time rather
//! than writing it down. So removing the three list nodes this crate replaces —
//! `chain`, `page[2]` and `jetsam` — moved `code` and nothing had to be told.
//!
//! # The chaining graph
//!
//! A block's last gadget holds the address of the next block, and chaining
//! overwrites it with that block's `code` pointer so the two run without
//! returning to the dispatch loop; disconnecting a block has to find everything
//! that jumped to it and put the address back. That was two intrusive lists per
//! slot in every block header, kept in C-shaped Rust on the argument that a
//! `list_add` ran on every dispatch; it runs once per new edge, and the graph is
//! [`Cache`]'s map since 2026-10-17. The header lost the four list nodes, and
//! `code` moved again with nothing told.
//!
//! # Ownership
//!
//! The compiler allocates a block and hands it over; this owns it from
//! [`Cache::insert`] until it is freed, either directly or by way of the jetsam
//! list. Nothing else frees one.


pub mod chain;

#[path = "cache.rs"]
mod cache;
pub use cache::Cache;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// The shared Rust types and constants are re-exported by kernel-taskview.
use emu_abi as ffi;

type Block = ffi::fiber_block;


// ---------------------------------------------------------------------------
// `struct asbestos`
// ---------------------------------------------------------------------------

/// A JIT for one address space: its block cache, and the two locks that order
/// access to it against reclamation.
///
/// **This crate's type since 2026-10-17.** It was `emu_abi::asbestos`, a
/// `#[repr(C)]` struct in a lower crate with the cache behind a
/// `*mut c_void`, so every reach for the cache was `(*a).cache.cast::<Shared>()`
/// and a `cache_mut` whose contract -- "the caller holds `asbestos->lock`" --
/// nothing checked: the lock and the value it guards were two fields. They are
/// one [`locks::mutex::Mutex`] now, and holding its guard is the only way to
/// the cache. `struct mmu` keeps an opaque `*mut emu_abi::asbestos`, which
/// [`Asbestos::of`] turns back into this; nothing in the assembly reads it.
pub struct Asbestos {
    pub mmu: *mut ffi::mmu,
    /// Bumped under the cache lock when a block is invalidated; read with no
    /// lock by every JIT thread on every dispatch, to know its per-thread
    /// block cache is stale. `Relaxed` both ways -- what keeps a stale block
    /// from being freed under a thread is `jetsam_lock`, not this.
    pub invalidate_gen: AtomicU32,
    /// Threads inside the JIT.
    pub active_threads: AtomicU32,
    /// Held for reading by every thread in the JIT for its whole quantum, and
    /// tried for writing by whoever frees the jetsam list.
    pub jetsam_lock: locks::wrlock::wrlock_t,
    cache: locks::mutex::Mutex<Cache>,
    /// The cache's occupancy bits, for the one question asked **without** the
    /// lock: [`Asbestos::page_has_blocks`].
    occupied: Arc<[AtomicBool]>,
}

/// A block inside the cache is reached only under its lock; the raw `mmu` is
/// the address space this JIT belongs to, which outlives it.
// SAFETY: every field another thread touches is an atomic or a lock; `mmu` is
// read, never written, after construction.
unsafe impl Sync for Asbestos {}
// SAFETY: as `Sync`.
unsafe impl Send for Asbestos {}

impl Asbestos {
    /// A JIT for the address space whose MMU is `mmu`, as the opaque pointer
    /// `struct mmu` keeps. Freed with [`Asbestos::free`].
    pub fn create(mmu: *mut ffi::mmu) -> *mut ffi::asbestos {
        let cache = Cache::new();
        let occupied = cache.occupancy();
        Box::into_raw(Box::new(Asbestos {
            mmu,
            invalidate_gen: AtomicU32::new(0),
            active_threads: AtomicU32::new(0),
            jetsam_lock: Default::default(),
            cache: locks::mutex::Mutex::new(cache),
            occupied,
        }))
        .cast()
    }

    /// Free every block, live and jetsam alike, and then the locks, which
    /// trap on `EBUSY`: a JIT thread still parked in `jetsam_lock` is a thread
    /// about to run code in a block this is freeing.
    ///
    /// # Safety
    /// `p` is null or came from [`Asbestos::create`]; nothing is executing any of
    /// its blocks and no thread is inside either lock.
    pub unsafe fn free(p: *mut ffi::asbestos) {
        if !p.is_null() {
            // SAFETY: the caller's contract.
            drop(unsafe { Box::from_raw(p.cast::<Asbestos>()) });
        }
    }

    /// The JIT `struct mmu` points at, borrowed.
    ///
    /// # Safety
    /// `p` is null or came from [`Asbestos::create`] and is not freed for `'a`.
    pub unsafe fn of<'a>(p: *mut ffi::asbestos) -> Option<&'a Asbestos> {
        // SAFETY: the caller's contract.
        unsafe { p.cast::<Asbestos>().as_ref() }
    }

    /// The cache, locked. It serialises a compile and an insert against an
    /// invalidation.
    pub fn cache(&self) -> locks::mutex::MutexGuard<'_, Cache> {
        locks::locked!(&self.cache)
    }

    /// The cache if it is free. The `chain` path, which will not wait: a chain
    /// is an optimisation, and blocking for it would put the dispatch loop
    /// behind whatever is compiling.
    pub fn try_cache(&self) -> Option<locks::mutex::MutexGuard<'_, Cache>> {
        locks::try_locked!(&self.cache)
    }

    /// Does a block touch this page? **The fast path**, with no lock: a racy
    /// false positive costs the slow path and nothing else; a false negative
    /// is impossible, because a block is indexed before anything can reach it
    /// and the bit is set with it.
    pub fn page_has_blocks(&self, page: u64) -> bool {
        self.occupied[cache::bucket(page)].load(Ordering::Relaxed)
    }

    /// Throw away every block touching a page in `start .. end`. The caller
    /// does not hold the cache lock.
    pub fn invalidate_range(&self, start: u64, end: u64) {
        let mut cache = self.cache();
        let doomed = cache.blocks_in(start, end);
        for &block in &doomed {
            cache.retire(block);
        }
        if !doomed.is_empty() {
            self.invalidate_gen.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// One page. **The hot one**: `mem_ptr`'s write path calls this for every
    /// store to a mapped page, so the empty case is an index and a load, with
    /// no lock.
    pub fn invalidate_page(&self, page: u64) {
        if self.page_has_blocks(page) {
            self.invalidate_range(page, page + 1);
        }
    }

    /// Free the blocks waiting to be freed, if this thread is the one that
    /// gets to.
    ///
    /// The write side of `jetsam_lock` is what establishes that no thread is
    /// still inside a block: every JIT thread holds the read side for its
    /// whole quantum. It is **tried** rather than taken, so exactly one thread
    /// cleans and the rest carry straight on -- many `node` worker threads all
    /// reaching for it at once is a multi-writer pattern that has been observed
    /// to wedge macOS's psynch rwlock, and the list is drained by whoever wins.
    ///
    /// The caller holds neither lock.
    pub fn collect_jetsam(&self) {
        if !self.cache().has_jetsam() {
            return;
        }
        if let Some(_quiet) = locks::write_tryguard!(&self.jetsam_lock) {
            // SAFETY: the write side of `jetsam_lock` is held, so no thread is
            // inside a block.
            unsafe { self.cache().free_jetsam() };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block with nothing in its code, which is all these tests need: the
    /// cache never reads `code`, only the gadgets do.
    fn block(addr: u64, end: u64) -> *mut Block {
        let header = Block { addr, end_addr: end, ..Default::default() };
        Block::alloc(header, &[0; 8]).expect("allocation").as_ptr()
    }

    #[test]
    fn a_block_is_found_by_the_address_it_starts_at() {
        let mut c = Cache::new();
        let b = block(0x1000, 0x1020);
        unsafe { c.insert(b) };
        assert_eq!(c.lookup(0x1000), b);
        assert!(c.lookup(0x1004).is_null(), "not by an address inside it");
        assert_eq!(c.size(), (1, 8));
    }

    #[test]
    fn a_block_that_spans_two_pages_is_indexed_under_both() {
        // Which is what the C's two `page` list nodes were for: an munmap of
        // either page has to find it.
        let mut c = Cache::new();
        let b = unsafe { c.insert(block(0x1ff0, 0x2010)) };
        assert_eq!(c.blocks_in(1, 2), vec![b], "the page it starts in");
        assert_eq!(c.blocks_in(2, 3), vec![b], "and the one it ends in");
        assert!(c.blocks_in(3, 4).is_empty());
    }

    #[test]
    fn invalidating_takes_it_out_of_both_indexes_but_does_not_free_it() {
        // The whole point of the jetsam list: another thread may be executing
        // the block right now, and what makes the wait is jetsam_lock.
        let mut c = Cache::new();
        let b = unsafe { c.insert(block(0x1ff0, 0x2010)) };
        c.retire(b);
        assert!(c.lookup(0x1ff0).is_null());
        assert!(c.blocks_in(1, 3).is_empty(), "out of both pages");
        assert_eq!(c.size(), (0, 0));
        assert!(
            unsafe { (*b.as_ptr()).is_jetsam.load(Ordering::Relaxed) },
            "and marked, which the chaining reads"
        );
        unsafe { c.free_jetsam() };
    }

    /// The lock-free answer follows the locked one: set by an insert on
    /// either page a block spans, cleared when the last block in the bucket
    /// goes. A false negative here is a store to code that the JIT keeps
    /// running stale.
    #[test]
    fn the_lock_free_page_answer_follows_the_index() {
        let a = Asbestos::create(std::ptr::null_mut());
        // SAFETY: just made, freed below.
        let asb = unsafe { Asbestos::of(a) }.unwrap();
        let b = block(0x1ff0, 0x2010);
        assert!(!asb.page_has_blocks(1));
        unsafe { asb.cache().insert(b) };
        assert!(asb.page_has_blocks(1) && asb.page_has_blocks(2), "both pages");
        assert!(!asb.page_has_blocks(3));
        asb.invalidate_page(1);
        assert!(!asb.page_has_blocks(1) && !asb.page_has_blocks(2), "and cleared");
        assert_eq!(asb.invalidate_gen.load(Ordering::Relaxed), 1, "and the generation moved");
        asb.collect_jetsam();
        assert!(!asb.cache().has_jetsam(), "and freed, with no thread in the JIT");
        unsafe { Asbestos::free(a) };
    }

    #[test]
    fn a_second_block_for_one_address_stays_until_its_page_is_invalidated() {
        // IUL_NO_BLOCK_CACHE=2 compiles a fresh block on every dispatch. The
        // previous one is unreachable by lookup and a thread may still be
        // executing it, so it stays in `by_page` for an invalidation to find --
        // which is what the C did by leaving it in the hash chain.
        //
        // The first version of this retired it straight to jetsam while
        // `by_page` still pointed at it, so `free_jetsam` freed something an
        // invalidation was about to walk. This test is why that did not ship.
        let mut c = Cache::new();
        let first = block(0x1000, 0x1020);
        let second = block(0x1000, 0x1020);
        unsafe { c.insert(first) };
        unsafe { c.insert(second) };
        assert_eq!(c.lookup(0x1000), second, "a dispatch runs the newest");
        assert!(
            !unsafe { (*first).is_jetsam.load(Ordering::Relaxed) },
            "and the older one is still live"
        );
        assert_eq!(c.size(), (2, 16), "both are owned and both are counted");
        assert_eq!(c.blocks_in(1, 2).len(), 2, "and an invalidation finds both");
        for b in c.blocks_in(1, 2) {
            c.retire(b);
        }
        assert_eq!(c.size(), (0, 0));
        unsafe { c.free_jetsam() };
    }

    /// A chain patches the predecessor's slot to the successor's code, and
    /// disconnecting either end undoes exactly its half: the successor going
    /// puts the predecessor's original word back; the predecessor going takes
    /// it out of the successor's list, so a later disconnect of the successor
    /// writes into nothing that has been freed.
    #[test]
    fn a_chain_is_undone_from_either_end() {
        const FAKE: u64 = 1 << 63;
        let mut c = Cache::new();
        let (a, b) = (block(0x1000, 0x1020), block(0x2000, 0x2020));
        let (ha, hb);
        // `a` exits to 0x2000 through slot 0, as `gen_end` would leave it.
        let slot = unsafe { (&raw mut (*a).code).cast::<u64>() };
        unsafe {
            *slot = FAKE | 0x2000;
            (*a).jump_ip[0] = slot;
            (*a).old_jump_ip[0] = FAKE | 0x2000;
            ha = c.insert(a);
            hb = c.insert(b);
            c.try_chain(a, b);
            assert_eq!(*slot, (*b).code.as_ptr() as u64, "patched to b's code");
            c.try_chain(a, b);
            assert_eq!(c.preds.get(&(b as usize)).map(cache::Preds::len), Some(1), "once, however often asked");

            c.disconnect(hb);
            assert_eq!(*slot, FAKE | 0x2000, "b going restores a's exit");
            assert!(c.preds.is_empty());

            c.try_chain(a, b);
            c.disconnect(ha);
            assert!(c.preds.is_empty(), "a going leaves nothing in b's list");
            c.retire(ha);
            c.retire(hb);
            c.free_jetsam();
        }
    }

    #[test]
    fn a_range_bigger_than_the_index_walks_the_index() {
        // asbestos_invalidate_range is called with one page by the store path
        // and with the whole address space by nothing -- but pt_unmap_always
        // asks for 0..MEM_PAGES on teardown, and iterating 2^36 pages to find
        // three blocks would not return.
        let mut c = Cache::new();
        let b = unsafe { c.insert(block(0x1000, 0x1020)) };
        assert_eq!(c.blocks_in(0, 1 << 36), vec![b]);
        c.retire(b);
        unsafe { c.free_jetsam() };
    }

    #[test]
    fn everything_is_freed_when_the_address_space_goes() {
        // Both lists: live blocks and jetsam. Reached from asbestos_free.
        let mut c = Cache::new();
        unsafe { c.insert(block(0x1000, 0x1020)) };
        unsafe { c.insert(block(0x2000, 0x2020)) };
        let doomed = unsafe { c.insert(block(0x3000, 0x3020)) };
        c.retire(doomed);
        assert_eq!(c.size().0, 2);
        drop(c); // and valgrind or ASan is what checks the rest
    }
}
