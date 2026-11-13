//! The emulator's own types: the address space, the software TLB, and the CPU.
//!
//! **A crate of its own since 2026-09-09, and the reason is layering.**
//! `struct cpu_state`, `struct tlb` and `struct mmu` lived in
//! `crates/kernel/abi` with everything else the headers used to define — so
//! `crates/emu/tlb` and three `asbestos` crates, layers 1 and 2, named a
//! `kernel` crate for the CPU they emulate. That is what is left of the reason
//! `tools/crate-layers.py` exempts `kernel-abi` everywhere, and an exemption is
//! a gate covering nothing.
//!
//! `crates/kernel/abi` re-exports all of it, so `struct task` still embeds a
//! `cpu_state` and every consumer still writes `taskview::ffi::tlb`.
//!
//! Depends on `libc` and nothing else.
//!
//! # `cpu_state`'s layout is a contract with the assembly
//!
//! `crates/tools/cpuoffsets` generates `cpu-offsets.h` from this type and the
//! gadgets index every field through it, so `#[repr(C)]` here is not a style
//! choice and neither are the offset assertions. `union arm64_vreg`'s 128-bit
//! lanes are why `struct task` carries `#[repr(align(16))]`.
//!
//! `tlb_entry` is the sharper case: the assembly indexes the entry array by
//! `lsl #5`, so its size is 32 bytes and an added field is a silent
//! miscalculation rather than a compile error. The assertion below is the
//! check.

#![allow(non_camel_case_types, non_upper_case_globals)]

pub use libc::pthread_t;

// The block cache holds one of each, and `struct mmu` a `wrlock_t`.
// `crates/util/synctypes` is layer 0 and owns them; see its module comment.
pub use util_synctypes::{cond_t, lock_t, wrlock_t};

/// The invalid-page marker, beyond the 36-bit page-number range.
pub const BAD_PAGE: u64 = 68719476736;

/// An upper bound for iteration, not an array size: nothing allocates this
/// many.
pub const MEM_PAGES: u64 = 68719476736;

pub const PAGE_BITS: u32 = 12;

pub const PAGE_SIZE: u32 = 4096;

pub const MEM_READ: u32 = 0;

pub const MEM_WRITE: u32 = 1;

pub const MEM_WRITE_PTRACE: u32 = 2;

pub const STACK_TOP_PAGE: u32 = 1048574;

pub const STACK_INIT_PAGE: u32 = 1048573;

pub const STACK_TOP_ADDR: u32 = 4294959104;

pub const MMAP_HOLE_START: u32 = 983037;

pub const MMAP_HOLE_END: u32 = 256;

pub const USER_ADDR_MAX_PAGE: u64 = 68719476735;

/// The context passed to a symbol-level offload handler.
///
/// This belongs beside the CPU and TLB pointers it carries. `kernel-abi`
/// re-exports it for consumers that still use the aggregate ABI namespace.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct nsym_ctx {
    pub cpu: *mut cpu_state,
    pub tlb: *mut tlb,
    pub resume: nsym_resume,
    pub resume_pc: addr_t,
}

pub type nsym_result = std::ffi::c_uint;
pub const nsym_result_NSYM_HANDLED: nsym_result = 0;
pub const nsym_result_NSYM_DECLINED: nsym_result = 1;
pub type nsym_resume = std::ffi::c_uint;
pub const nsym_resume_NSYM_RESUME_RET: nsym_resume = 0;
pub const nsym_resume_NSYM_RESUME_PC: nsym_resume = 1;

const _: () = {
    assert!(std::mem::size_of::<nsym_ctx>() == 32, "Size of nsym_ctx");
    assert!(
        std::mem::align_of::<nsym_ctx>() == 8,
        "Alignment of nsym_ctx"
    );
    assert!(
        std::mem::offset_of!(nsym_ctx, cpu) == 0,
        "Offset of field: nsym_ctx::cpu"
    );
    assert!(
        std::mem::offset_of!(nsym_ctx, tlb) == 8,
        "Offset of field: nsym_ctx::tlb"
    );
    assert!(
        std::mem::offset_of!(nsym_ctx, resume) == 16,
        "Offset of field: nsym_ctx::resume"
    );
    assert!(
        std::mem::offset_of!(nsym_ctx, resume_pc) == 24,
        "Offset of field: nsym_ctx::resume_pc"
    );
};

impl Default for nsym_ctx {
    fn default() -> Self {
        Self {
            cpu: std::ptr::null_mut(),
            tlb: std::ptr::null_mut(),
            resume: nsym_resume_NSYM_RESUME_RET,
            resume_pc: 0,
        }
    }
}

pub const P_READ: u32 = 1;

pub const P_WRITE: u32 = 2;

pub const P_EXEC: u32 = 4;

pub const P_RWX: u32 = 7;

pub const P_GROWSDOWN: u32 = 8;

pub const P_COW: u32 = 16;

pub const P_ANONYMOUS: u32 = 64;

pub const P_SHARED: u32 = 128;

/// **W^X for the JIT**: the page holds guest code that has been compiled into
/// fiber blocks. While it is set no TLB entry may be stamped writable for the
/// page — `translate_write_nofault` refuses — so every guest store to it takes
/// the `mem_ptr` write-miss path, which invalidates the page's compiled blocks
/// and clears this flag (bumping `mmu->changes`) before the store is allowed to
/// land. Set by `mmu_mark_code_page` when a block is compiled from the page.
pub const P_CODE: u32 = 256;

/// The mapping was made `PROT_NONE` and every access to it must fault.
///
/// **A bit of its own, rather than testing for the absence of
/// `P_READ`/`P_WRITE`/`P_EXEC`**, because those are not maintained: `P_READ`
/// and `P_EXEC` are ignored, and the initial stack and the brk are both mapped
/// with no permission bits at all and read constantly. "No flags" therefore
/// cannot mean "no access"; this can.
///
/// Set where a guest `PROT_*` becomes page flags — `do_mmap` and `sys_mprotect`
/// — and nowhere else, so any `mprotect` that grants something clears it. It is
/// not a `P_META_FLAG` for that reason: `pt_set_flags` must be able to drop it.
pub const P_NOACCESS: u32 = 512;

/// `mseal(2)`: the mapping may not be unmapped, moved, re-protected or
/// discarded. Linux keeps it as `VM_SEALED` on the vma; this kernel has one
/// flags word per page, so it is here, and it survives `mprotect` (which it
/// forbids anyway) and `fork`. Only the syscall paths ask: `exit` and
/// `execve` tear a sealed mapping down as Linux does.
pub const P_SEALED: u32 = 1 << 10;

/// `MADV_GUARD_INSTALL`: every access to the page faults, until
/// `MADV_GUARD_REMOVE` or a new mapping over it. Linux keeps this as a page
/// table marker rather than on the vma, which is what it is here too: it does
/// not split `/proc/<pid>/maps`, it survives `mprotect` and `fork`.
pub const P_GUARD: u32 = 1 << 11;

/// `mlock`: Linux's `VM_LOCKED`. Nothing here is ever paged out, so the bit
/// changes no residency; what it changes is what `madvise` may do -- a
/// discarding advice on locked memory is `EINVAL`, and `MADV_DONTNEED_LOCKED`
/// exists to get past that. Not inherited across `fork`.
pub const P_LOCKED: u32 = 1 << 12;

/// `MADV_DONTFORK`: a `fork`ed child does not get the page at all.
pub const P_DONTFORK: u32 = 1 << 13;

/// `MADV_WIPEONFORK`: a `fork`ed child gets the page zero-filled, and keeps
/// the bit.
pub const P_WIPEONFORK: u32 = 1 << 14;

pub const ANON_MMAP_LIMIT_PAGES: u32 = 1048576;

pub const TLB_BITS: u32 = 13;

pub const TLB_SIZE: u32 = 8192;

pub const TLB_PAGE_EMPTY: u32 = 1;

pub type addr_t = u64;

/// A page number: the bits of an address above `PAGE_BITS`. AArch64's address
/// space is 48 bits, so a page number is 36.
pub type page_t = u64;

pub type pages_t = u64;

mod types;
pub use types::*;

mod cpustate;
pub use cpustate::*;

mod slow;
pub use slow::*;
