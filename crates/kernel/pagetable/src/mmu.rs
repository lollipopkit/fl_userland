//! MMU-facing code-page and fault reason queries.

use std::ffi::c_int;
use std::sync::atomic::Ordering;

use taskview::ffi;

use crate::space::ReadHeld;

// ---------------------------------------------------------------------------
// What the JIT asks
// ---------------------------------------------------------------------------

/// Mark a page as holding compiled code, so the next store to it invalidates
/// the blocks.
///
/// **Three answers, and the caller reads all three**: -1 for a page that is not
/// mapped, 0 for one that was already marked, 1 for one this call marked. The
/// change generation is bumped only for the last — bumping it every time forces
/// every thread's TLB to re-translate, and the JIT then recompiles the block it
/// has just marked, for ever. That is a hang, and it is what the first version
/// of this did.
///
/// # Safety
/// `mmu` belongs to a live address space whose read lock this thread holds --
/// which a guest thread in the dispatch loop does for its whole quantum.
pub unsafe fn mmu_mark_code_page(mmu: *mut ffi::mmu, page: u64) -> c_int {
    // SAFETY: the caller's contract.
    let held = unsafe { ReadHeld::assume(mem_of(mmu)) };
    let Some(entry) = held.space().pt(page) else {
        return -1;
    };
    let old = entry.flags.fetch_or(ffi::P_CODE, Ordering::AcqRel);
    if old & ffi::P_CODE != 0 {
        return 0;
    }
    held.changed();
    1
}

/// Is the mark [`mmu_mark_code_page`] placed still there — has nothing written
/// to the page since? A store that raced with compilation went through
/// `mem_ptr` and cleared it.
///
/// # Safety
/// As [`mmu_mark_code_page`].
pub unsafe fn mmu_code_page_intact(mmu: *mut ffi::mmu, page: u64) -> bool {
    // SAFETY: the caller's contract.
    let held = unsafe { ReadHeld::assume(mem_of(mmu)) };
    held.space()
        .pt(page)
        .is_some_and(|entry| entry.flags.load(Ordering::Acquire) & ffi::P_CODE != 0)
}

/// The `struct mem` a `struct mmu` is embedded in.
///
/// # Safety
/// `mmu` is the `mmu` member of a live `struct mem`.
pub(crate) unsafe fn mem_of(mmu: *mut ffi::mmu) -> *mut ffi::mem {
    let offset = std::mem::offset_of!(ffi::mem, mmu);
    unsafe { mmu.cast::<u8>().sub(offset).cast() }
}
