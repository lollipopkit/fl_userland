//! The address-space calls that do not place a mapping.
//!
//! `munmap`, `mprotect`, `madvise`, the `mlock` family, `msync` and
//! `membarrier`, from `kernel/mmap.c`. Which `prot` bits and which `madvise`
//! advices exist is `crates/kernel/mmapabi`; the page table itself is still
//! the page-table layer, reached through `pt_*` and two predicates that keep
//! `struct pt_entry` on that side.
//!
//! `mmap`, `mremap` and `brk` stay for now: each carries placement heuristics
//! — the V8 heap cage, Go's arena assumptions, `MAP_NORESERVE` alignment —
//! that are load-bearing for real workloads and want their own step.
//!
//! # The lock
//!
//! Every one of these takes `mem->lock` and releases it, and the C spelled that
//! as a matching pair at each exit. [`MemRead`] and [`MemWrite`] are guards, so
//! a path that returns early cannot leave it held.


use std::ffi::{c_int, c_uint, c_void};

use kernel_mmapabi as mmapabi;
use pagetable::memlock::{Held, ReadGuard, WriteGuard};
use strace::strace;

use guest_errno::Errno;

/// The `#define`s from `kernel/memory.h` and `emu/mmu.h`, generated.
///
/// **Not written down.** This crate first shipped `P_NOACCESS` as `1 << 5`
/// where it is `1 << 9`, so `mprotect(PROT_NONE)` set a bit nothing reads and
/// revoked nothing. Generating them makes that class of mistake
/// inexpressible; see `build.rs`.
// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

mod advise;
mod mincore;
mod misc;
pub mod mm;
pub mod mmflags;
mod placement;
mod pkey;
mod refile;
pub mod remap;
pub use pkey::{sys_pkey_alloc, sys_pkey_free, sys_pkey_mprotect};
pub use refile::sys_remap_file_pages;
pub use advise::{advise_remote, sys_madvise, sys_mseal};
pub use mincore::sys_mincore;
#[cfg(test)]
use misc::*;
#[cfg(test)]
mod tests;
pub use misc::{
    sys_membarrier, sys_mlock, sys_mlock2, sys_mlockall, sys_msync, sys_munlock,
    sys_munlockall,
};
pub use mm::prctl;
use mm::*;
pub use placement::{share, sys_brk, sys_mmap64, sys_mremap};
/// `usermem` moved to `crates/kernel/usercopy` on 2026-09-06: reading guest
/// memory is below the mmap syscalls, not above them, and the dependency ran
/// the wrong way -- `usercopy` reached back up through a hand-written
/// `extern "C"` block to call it.
pub use usercopy::usermem;

const PAGE_BITS: u32 = ffi::PAGE_BITS;
const PAGE_SIZE: u64 = 1 << PAGE_BITS;
/// Page numbers are 36 bits, so an address above that **aliases** onto a lower
/// page rather than falling out of the table.
const USER_ADDR_MAX_PAGE: u64 = ffi::USER_ADDR_MAX_PAGE;

/// `P_READ | P_WRITE | P_EXEC`, and the marker for a mapping with none of them.
const P_RWX: c_int = ffi::P_RWX as c_int;
const P_NOACCESS: c_int = ffi::P_NOACCESS as c_int;
const P_SHARED: c_int = ffi::P_SHARED as c_int;
const P_READ: c_int = ffi::P_READ as c_int;
const P_WRITE: c_int = ffi::P_WRITE as c_int;
const P_EXEC: c_int = ffi::P_EXEC as c_int;

const MEM_WRITE: c_int = ffi::MEM_WRITE as c_int;

fn page_of(addr: u64) -> u64 {
    addr >> PAGE_BITS
}

fn page_offset(addr: u64) -> u64 {
    addr & (PAGE_SIZE - 1)
}

/// Pages spanned by `len`, rounding up. **Saturating**, because the C's
/// `PAGE_ROUND_UP` is documented to overflow to zero.
fn page_round_up(len: u64) -> u64 {
    len.saturating_add(PAGE_SIZE - 1) >> PAGE_BITS
}

/// Is `[addr, addr+len)` inside the guest address space?
///
/// Page numbers are 36 bits and the page table masks each level's index, so a
/// page above that does not fall *out* of the table — it **aliases** onto a
/// lower one. `munmap`, `mprotect`, `madvise` and `mremap` took the address as
/// given, so `munmap(p + (1 << 48), 4096)` named the same entry as `p` and
/// unmapped the mapping there, reporting success. Linux answers `EINVAL` for
/// anything outside the user address space.
///
/// The length is checked here too: a length near 2^64 silently became "no
/// pages" and reported success where Linux gives `EINVAL`.
fn user_range_ok(addr: u64, len: u64) -> bool {
    let start = page_of(addr);
    if start > USER_ADDR_MAX_PAGE {
        return false;
    }
    let pages = page_round_up(len);
    if len != 0 && pages == 0 {
        return false;
    }
    pages <= USER_ADDR_MAX_PAGE + 1 - start
}

/// `mem->lock` over the calling task's address space, held for reading.
///
/// A function answering the page table's own guard. It was a `MemRead`
/// newtype over it until 2026-09-30, from when the guard was a crate-private
/// copy; every use then read `guard.0.mem()` and handed the pointer to an
/// `unsafe fn` whose contract the guard already proved.
fn mem_read() -> ReadGuard<'static> {
    ReadGuard::current().expect("a memory syscall runs in an address space")
}

/// `mem->lock` over the calling task's address space, held for writing.
fn mem_write() -> WriteGuard<'static> {
    WriteGuard::current().expect("a memory syscall runs in an address space")
}

/// Every page of a range is part of a mapping.
///
/// Linux answers `ENOMEM` if any is not, and that is load-bearing rather than
/// pedantry: musl's `pthread_getattr_np` probes the main-thread stack extent
/// one page at a time with `madvise(MADV_NORMAL)` and relies on `ENOMEM` at the
/// first unmapped page. Always returning success made it report the stack as
/// `RLIMIT_STACK`-sized — 128 MB — and bun then moved SP to that "bottom" and
/// zeroed the whole range, faulting at the rlimit boundary. A deterministic
/// startup `SIGSEGV` at `stack_top - 128MB`.
fn range_is_mapped(addr: u64, len: u64) -> bool {
    let guard = mem_read();
    guard.covered(page_of(addr), page_round_up(len))
}

pub fn sys_munmap(addr: u64, len: u64) -> Result<(), Errno> {
    strace!("munmap({addr:#x}, {len:#x})");
    mmap_trace(0, addr, len, 0);
    if page_offset(addr) != 0 || len == 0 || !user_range_ok(addr, len) {
        return Err(Errno::EINVAL);
    }
    let pages = page_round_up(len);
    // A range with nothing mapped in it is not an error, which is Linux's
    // rule. An `err < 0` test answering `EINVAL` stood here until 2026-09-30,
    // on an unmap that answers 0 whatever it finds.
    let mut guard = mem_write();
    // All or nothing: a sealed page anywhere in the range refuses the whole
    // call, which is what the reference kernel's up-front gather does.
    advise::refuse_sealed(&guard, page_of(addr), pages)?;
    guard.unmap_always(page_of(addr), pages);
    Ok(())
}

pub fn sys_mprotect(addr: u64, len: u64, prot: c_int) -> Result<(), Errno> {
    strace!("mprotect({addr:#x}, {len:#x}, {prot:#x})");
    mmap_trace(1, addr, len, prot);
    if page_offset(addr) != 0 {
        return Err(Errno::EINVAL);
    }
    // mprotect is the strict one; see mmapabi. mmap does *not* validate prot
    // and this does, which is Linux's split: arch_validate_prot is called from
    // do_mprotect_pkey and not from do_mmap.
    if !mmapabi::prot_ok_for_mprotect(prot as u32) {
        return Err(Errno::EINVAL);
    }
    if !user_range_ok(addr, len) {
        return Err(Errno::EINVAL);
    }
    let mut guard = mem_write();
    let (first, pages) = (page_of(addr), page_round_up(len));
    // Linux's order: the VMAs ahead of the one refused are changed and stay
    // so, and the call answers the refusal. It refused before changing
    // anything until 2026-11-12; `mmfault_probe` measured the difference for
    // a hole, a read-only shared file and a seal.
    let stop = survey(&guard, first, pages, prot);
    if stop.at > first {
        // The same marking `mmap` does. `pt_set_flags` replaces the permission
        // bits, so an mprotect that grants anything clears P_NOACCESS.
        let flags = if prot & P_RWX == 0 { P_NOACCESS } else { prot };
        guard.set_flags(first, stop.at - first, flags)?;
    }
    stop.refused.map_or(Ok(()), Err)
}

/// Where `mprotect` stops changing a range, and why.
struct Stop {
    /// The first page left as it was; the end of the range if none is.
    at: u64,
    refused: Option<Errno>,
}

/// One walk over the extents of the range, which is what `mprotect` costs per
/// page: it was four walks -- the seal, the memfd write seal, the holes and
/// the change -- each asking the page table for every page from the root, and
/// the first three now are this one.
///
/// Per extent, in Linux's order: a hole before it (`ENOMEM`, the loop's
/// `vm_start != tmp`), then the protection its file allows (`EACCES`), then a
/// seal (`EPERM`, which 7.x asks in `mprotect_fixup`, after the loop's
/// checks). A reserved page is a `PROT_NONE` VMA and no hole.
fn survey(held: &impl Held, first: u64, pages: u64, prot: c_int) -> Stop {
    let space = held.space();
    let end = first + pages;
    let mm_flags = current_flags();
    let mut expect = first;
    for x in space.extents(first, pages) {
        if x.start != expect {
            let hole = space.reserved_until(expect, x.start);
            if hole != x.start {
                return Stop { at: hole, refused: Some(Errno::ENOMEM) };
            }
        }
        // Under MDWE, an executable result is refused if it is also writable,
        // or if any page of the range was not executable before -- Linux's
        // `map_deny_write_exec`, asked of each mapping in the range.
        //
        // And a shared mapping that may never be written: Linux clears
        // VM_MAYWRITE for one of a descriptor not open for writing, or of a
        // memfd under F_SEAL_WRITE, and mprotect answers EACCES for a VMA
        // without it. Without this the host's own refusal answered, after the
        // guest's flags had already been changed.
        let eacces = (prot & P_EXEC != 0 && mmflags::deny_write_exec(mm_flags, x.flags, prot as u32))
            || (prot & P_WRITE != 0
                && x.data.shared()
                && x.data.fd().is_some_and(|fd| !mm::shared_may_write(fd)));
        if eacces {
            return Stop { at: x.start, refused: Some(Errno::EACCES) };
        }
        if x.flags & ffi::P_SEALED != 0 {
            return Stop { at: x.start, refused: Some(Errno::EPERM) };
        }
        expect = x.start + x.pages;
    }
    let hole = space.reserved_until(expect, end);
    Stop { at: hole, refused: (hole != end).then_some(Errno::ENOMEM) }
}
