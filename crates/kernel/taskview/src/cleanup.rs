//! Pthread cleanup handoff layout.

use super::host_threads_state;
use fsinfo::FsInfo;
use iul_abi::{fdtable, mm, tlb};
use kernel_sighand::SigHand;

/// What a dying thread's pthread cleanup handler is handed, so that it does
/// not have to reach through a task the reaper may already have freed.
///
/// The **five** `AtomicPtr` are written by the group-exit valve on another
/// thread and read by this one. `sighand` joined them on 2026-09-09 and was the
/// one the valve *released* instead, on the argument that "the disposition
/// table is not something a blocked syscall dereferences" — which is false,
/// because a thread parked in `crates/util/waitfor` reads it to decide whether
/// a signal ended its wait. Handing it over **transfers** the reference instead
/// of dropping it, so a reader that captured the pointer before the store still
/// has a live object — a property of the transfer rather than of when the
/// exiting thread happens to release its own. They were `_Atomic` in the C and plain words here, with
/// `tools/atomic-fields.py` grepping for an access that was not
/// `AtomicPtr::from_ptr`; they are `AtomicPtr` themselves now, so there is no
/// plain access to find. **That tool lost sight of them the moment this struct
/// stopped being C's** — it reads C headers, and it went from 13 atomic fields
/// to 8 without failing. Making the field the atomic is what replaces it.
#[repr(C)]
#[derive(Debug)]
pub struct task_cleanup {
    /// The software TLB this thread runs on, which the handler frees.
    ///
    /// A `usize` until 2026-09-12, from the days when naming `struct tlb` here
    /// meant a header — so every one of the three users cast it back. `emu` is
    /// below `kernel`, so the type has been nameable for as long as this
    /// struct has been Rust.
    pub tlb: *mut tlb,
    pub mm: util_arcslot::ArcSlot<mm>,
    pub files: util_arcslot::ArcSlot<fdtable>,
    pub fs: util_arcslot::ArcSlot<FsInfo>,
    pub sighand: util_arcslot::ArcSlot<SigHand>,
    pub hosts: util_arcslot::ArcSlot<host_threads_state>,
}
