//! Address space page-table initialization and teardown.

use super::*;

// ---------------------------------------------------------------------------
// The address space's life
// ---------------------------------------------------------------------------

/// # Safety
/// `mem` is a `mem::default()` nothing else holds. Not uninitialised storage,
/// which is what this said until 2026-09-29 and was false of both callers --
/// `alloc_mm` writes a whole `struct mm` first -- and is unsound now that a
/// field has a destructor: assigning over garbage drops the garbage.
pub unsafe fn mem_init(mem: *mut ffi::mem) {
    emu_tlb::install_translator(fault::TRANSLATOR);
    unsafe {
        let locked = (*mem).locked.get_mut();
        locked.pgdir = Box::into_raw(L0::new()).cast();
        locked.pgdir_used = 0;
        locked.mmap_hint = 0;
        locked.reservations = Vec::new();
        (*mem).mmu.asbestos = asbestos_blockcache::Asbestos::create(&raw mut (*mem).mmu);
        (*mem).mmu.changes = std::sync::atomic::AtomicU64::new(0);
        // `lock` is ready from `Default` and writer-preferring, which Apple's
        // rwlock is. The MMU keeps the *address* of its writers-waiting
        // counter, so the JIT's dispatch loop can see a writer waiting without
        // taking the lock itself -- see `struct mmu`.
        (*mem).mmu.writers_waiting = (*mem).lock.writers_waiting();
        crate::eof::space_created(&raw const (*mem).mmu);
    }
}

/// # Safety
/// Nothing holds `mem` any more.
pub unsafe fn mem_destroy(mem: *mut ffi::mem) {
    unsafe {
        crate::eof::space_destroyed(&raw const (*mem).mmu);
        let mut held = crate::memlock::WriteGuard::new(mem);
        // The JIT goes first, every block with it: nothing runs in this space
        // any more, so the unmap below need not disconnect and retire blocks
        // one page at a time only for the free to follow. Nulled after the
        // free so that a racing second cleanup path cannot dereference a stale
        // pointer -- and so the unmap finds no JIT to tell.
        asbestos_blockcache::Asbestos::free((*mem).mmu.asbestos);
        (*mem).mmu.asbestos = std::ptr::null_mut();
        held.unmap_always(0, ffi::MEM_PAGES);
        let locked = (*mem).locked.get();
        (*locked).reservations = Vec::new();
        drop(Box::from_raw((*locked).pgdir.cast::<L0>()));
        (*locked).pgdir = std::ptr::null_mut();
        // Released here; the lock itself is destroyed when the `mm` holding
        // this `mem` is dropped, and that destroy traps on a lock somebody
        // still holds.
        drop(held);
    }
}
