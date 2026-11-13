//! The block-chaining graph: two blocks patched to run into each other without
//! returning to the dispatch loop.
//!
//! A block that ends in a branch emits its destination as a *value* with bit 63
//! set. Chaining overwrites that word with a pointer to the destination block's
//! `code`, so the last gadget jumps straight there. Undoing it means finding
//! everything that jumped into a block and putting the original word back.
//!
//! The graph itself is [`crate::Cache`]'s since 2026-10-17 -- a map from each
//! block to its predecessors, under the cache lock -- where it was two
//! intrusive lists per slot threaded through every block header. See
//! [`crate::Cache::try_chain`]. What is left here is the encoding.

use crate::ffi;

type Block = ffi::fiber_block;

/// The bits of an unchained slot that are the guest pc: the low 48, which is
/// the guest's address width (`MEM_PAGES` is 2^36 pages of 2^12). The rest is
/// the fake-ip marker. `control.S` masks with the same `0xffffffffffff` when it
/// reads a pc back out of one.
pub(crate) const FAKE_IP_PC_MASK: u64 = (1 << 48) - 1;

/// The block whose `code` a chained slot points at.
pub(crate) fn block_of_code(slot: u64) -> usize {
    slot as usize - std::mem::offset_of!(Block, code)
}

/// Free a block **no index ever held**: the W^X compile protocol throws away
/// the ones whose page changed underneath them, and those were never inserted,
/// so nothing chained to or from them.
///
/// # Safety
/// `block` came from the compiler, was never inserted, and nothing is
/// executing it.
pub unsafe fn free_orphan(block: *mut Block) {
    // SAFETY: the caller's contract.
    unsafe { Block::free(block) };
}
