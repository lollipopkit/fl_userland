//! The guest's page table: a four-level radix tree over a 48-bit address
//! space, and every operation that changes what is mapped where.
//!
//! `L0[512] → L1[512] → L2[512] → L3[512]`, nine bits each — a 36-bit page
//! number and a 12-bit offset. The first two levels are always index 0 for
//! anything in the low 4 GB, which is where the stack and `mmap` live, so a
//! walk stays in cache. **The 48-bit infrastructure is still there** for an
//! explicit high-address hint: V8 asks for its CodeRange above 4 GB so that a
//! heap pointer is non-canonical in its low 32 bits, and `pt_find_hole`
//! prefers a high address for a reservation that size.
//!
//! # Two things that are not entries
//!
//! **A `MAP_NORESERVE` region is a reservation, not a mapping.** The JSC heap
//! cage and Go's page summaries ask for gigabytes of `PROT_NONE`; the range and
//! its permissions are recorded and the pages are materialised on the fault
//! that first touches them, because filling in a page table for four gigabytes
//! nobody reads is the cost this avoids.
//!
//! **`pt_find_hole` starts below the last successful allocation**, not at
//! `MMAP_HOLE_START`, and the hint is reset by an `munmap` that frees pages
//! above it. Without that, `mmap(addr=0)` rescans everything already allocated
//! on every call.
//!
//! # What a `struct pt_entry` is, and why moving one moves a mapping
//!
//! A pointer to a `struct data` and an offset into it. `struct data` owns the
//! host mapping and is refcounted, so several guest pages — in one address
//! space or in two, after `fork` — can name the same host memory. That is why
//! [`pt_move`] copies nothing and why `mremap` works for a file-backed mapping
//! as well as an anonymous one.
//!
//! # What stays in `kernel/memory.c`
//!
//! `mem_ptr` and the two `mmu_ops` entries around it: the *fault* path, which
//! resolves a miss, grows a stack down, breaks a copy-on-write and upgrades
//! `mem->lock` from read to write to do it. That is step 6, with `emu/`.
//!
//! Measured before and after the split (`mem_bench`, release, medians of
//! three): the page-table walk being a call rather than inlined into `mem_ptr`
//! costs nothing — `read sequential` 36.8 → 36.9 ns with `mem_pt` marked
//! `noinline` in the C, which is the same question asked before the move.
//!
//! # The tree is typed here, and was `void *` in C
//!
//! `struct pt_node` was `void *children[512]`, meaning `pt_node *` at levels
//! 0–2 and a `pt_entry[512]` at level 3, with a recursive free that took the
//! level as a parameter and had to be told which was which. The two are
//! separate types here, so the free is a `Drop` and the level is in the type.

use std::ffi::{c_int, c_uint, c_void};
use std::sync::atomic::Ordering;

pub mod memlock;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

pub mod anonbudget;
mod copies;
mod eof;
pub use eof::file_shrunk;
pub mod fault;

mod entry;
pub use entry::{Data, PtEntry, mapping_live_count};

mod hooks;
mod hostmap;
mod reservations;
mod tree;
pub use tree::{Extent, Extents, Mapped};

mod lifecycle;
pub use lifecycle::{mem_destroy, mem_init};

mod mmu;
pub use mmu::{mmu_code_page_intact, mmu_mark_code_page};

mod mapping;

mod space;
pub use space::{ReadHeld, Space, SpaceMut};

#[cfg(test)]
mod tests;

use hooks::shared_mapping_gone;
pub use hooks::{SharedMappingGoneFn, set_shared_mapping_gone_hook};
pub use hostmap::host_map_failures;
use hostmap::note_host_map_failure;
use tree::L0;

/// Point `pages` guest pages at `memory`, for a filesystem's `mmap`, which the
/// VFS hands a `*mut mem` because `FdOps` is defined below this crate and
/// cannot name a guard. 0 or a negative guest errno.
///
/// # Safety
/// `mem` is live and this thread holds its lock for writing; `memory` is a
/// host mapping of at least `pages * PAGE_SIZE + offset` bytes, which the page
/// table then owns.
pub unsafe fn pt_map(
    mem: *mut ffi::mem,
    start: u64,
    pages: u64,
    memory: *mut c_void,
    offset: usize,
    flags: c_uint,
) -> c_int {
    // SAFETY: the caller's contract, both halves.
    match unsafe { SpaceMut::from_raw(mem).map(start, pages, memory, offset, flags) } {
        Ok(()) => 0,
        Err(e) => e.as_c_int(),
    }
}

/// The vdso image is not a mapping made by this page table and must never be
/// unmapped with the guest's ordinary mappings.
fn vdso_data() -> *mut c_void {
    kernel_vdso::image().as_ptr() as *mut c_void
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Flags that track what a mapping *is* rather than what a guest may do with
/// it, and so survive an `mprotect`.
///
/// `P_CODE` is in the set deliberately: making a compiled code page writable
/// does not remove the need to invalidate its blocks on the first store.
///
/// So are the five that `mseal`, `madvise` and `mlock` set: a seal, a guard,
/// a lock and the two fork dispositions are properties `mprotect` leaves
/// alone on Linux too.
const P_META: u32 = ffi::P_ANONYMOUS
    | ffi::P_GROWSDOWN
    | ffi::P_COW
    | ffi::P_SHARED
    | ffi::P_CODE
    | ffi::P_SEALED
    | ffi::P_GUARD
    | ffi::P_LOCKED
    | ffi::P_DONTFORK
    | ffi::P_WIPEONFORK;

/// [`mem_changed_pub`] for the calling task's own address space, which is
/// live for as long as the task runs; nothing on a thread with no task.
pub fn mem_changed_current() {
    let mem = taskview::current_mem();
    if !mem.is_null() {
        // SAFETY: the calling task's own address space; see above.
        unsafe { mem_changed_pub(mem) };
    }
}

/// For a path that changes what backs a page without going through
/// [`pt_map`]/[`pt_unmap`] — `madvise(MADV_DONTNEED)` zeroing one in place.
///
/// # Safety
/// `mem` is live.
pub unsafe fn mem_changed_pub(mem: *mut ffi::mem) {
    // SAFETY: the caller's contract; one atomic field.
    unsafe { (*mem).mmu.changes.fetch_add(1, Ordering::Release) };
}

// ---------------------------------------------------------------------------
// The read-write lock `struct mem` embeds
// ---------------------------------------------------------------------------
//
// `kernel/memory.c`'s until 2026-09-03. `wrlock_init` is a `static inline`, so
// bindgen emits nothing for it — but what it *does* is four stores and a
// `pthread_rwlock_init`, and the layout is generated, so there is nothing here
// a crate cannot do.
//
// The **acquire** side stays C, and not because it is inline: `read_wrlock` and
// its three siblings carry the writer-preference spin, the bound on how long a
// reader stands aside, and the `LOCK_DEBUG` bookkeeping. Reimplementing them
// would silently opt this lock out of the tree's deadlock diagnostics and put a
// second copy of the fairness rule in the tree.

