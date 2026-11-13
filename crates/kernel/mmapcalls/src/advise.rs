//! `madvise`, `mseal`, and what a seal refuses.
//!
//! Linux keeps a seal, a lock and the fork dispositions on the vma and a guard
//! as a page-table marker; this kernel has one flags word per page, so all of
//! them are page flags (`P_SEALED`, `P_LOCKED`, `P_DONTFORK`, `P_WIPEONFORK`,
//! `P_GUARD`, see `crates/emu/abi`). Every rule below was measured against an
//! arm64 7.2 kernel by `tests/guest/src/bin/mm_modern_probe.rs`.
//!
//! # What a seal refuses
//!
//! `munmap`, `mremap` and `mmap(MAP_FIXED)` over a sealed page are `EPERM`
//! with nothing changed. `mprotect` is `EPERM` too, but 7.x checks each vma as
//! it walks, so the pages *before* the first sealed one are re-protected and
//! stay that way -- the probe's "the first page is still writable" is a
//! `SIGSEGV`. `madvise` refuses only the discarding advices, and only on a
//! read-only private anonymous mapping: discarding a page there is a write the
//! seal says cannot happen, where a writable one could have been written to
//! zero anyway and a shared or file mapping keeps its bytes elsewhere.

use super::*;

pub(crate) const MADV_DONTNEED: c_uint = 4;
const MADV_FREE: c_uint = 8;
const MADV_REMOVE: c_uint = 9;
const MADV_DONTFORK: c_uint = 10;
const MADV_DOFORK: c_uint = 11;
const MADV_WIPEONFORK: c_uint = 18;
const MADV_KEEPONFORK: c_uint = 19;
const MADV_POPULATE_READ: c_uint = 22;
const MADV_POPULATE_WRITE: c_uint = 23;
const MADV_DONTNEED_LOCKED: c_uint = 24;
const MADV_GUARD_INSTALL: c_uint = 102;
const MADV_GUARD_REMOVE: c_uint = 103;

/// Linux's `is_discard`: the advices a seal can refuse.
fn is_discard(advice: c_uint) -> bool {
    matches!(
        advice,
        MADV_FREE
            | MADV_DONTNEED
            | MADV_DONTNEED_LOCKED
            | MADV_REMOVE
            | MADV_DONTFORK
            | MADV_WIPEONFORK
            | MADV_GUARD_INSTALL
    )
}

/// A private anonymous page nothing may write: the one kind a seal keeps
/// from being discarded.
fn read_only_private_anon(flags: u32) -> bool {
    flags & ffi::P_ANONYMOUS != 0 && flags & ffi::P_SHARED == 0 && flags & ffi::P_WRITE == 0
}

fn private_anon(flags: u32) -> bool {
    flags & ffi::P_ANONYMOUS != 0 && flags & ffi::P_SHARED == 0
}

fn sealed(flags: u32) -> bool {
    flags & ffi::P_SEALED != 0
}

/// The first sealed page of a range, if there is one.
pub(crate) fn first_sealed(held: &impl Held, first: u64, pages: u64) -> Option<u64> {
    held.space().first_with_flags(first, pages, ffi::P_SEALED)
}

/// `EPERM` if anything in the range is sealed: what `munmap`, `mremap` and
/// `mmap(MAP_FIXED)` ask before they change anything.
pub(crate) fn refuse_sealed(held: &impl Held, first: u64, pages: u64) -> Result<(), Errno> {
    match first_sealed(held, first, pages) {
        Some(_) => Err(Errno::EPERM),
        None => Ok(()),
    }
}

/// `mseal(2)`.
///
/// The order is the reference kernel's: the flags, the alignment, a length
/// that wraps the address space (`EINVAL`), a zero length (success), and then
/// a range with anything unmapped in it, which is `ENOMEM` and seals nothing.
pub fn sys_mseal(addr: u64, len: u64, flags: u64) -> Result<(), Errno> {
    strace!("mseal({addr:#x}, {len:#x}, {flags:#x})");
    if flags != 0 || page_offset(addr) != 0 {
        return Err(Errno::EINVAL);
    }
    let Some(aligned) = len.checked_add(PAGE_SIZE - 1).map(|l| l & !(PAGE_SIZE - 1)) else {
        return Err(Errno::ENOMEM);
    };
    if addr.checked_add(aligned).is_none() {
        return Err(Errno::EINVAL);
    }
    if aligned == 0 {
        return Ok(());
    }
    if !user_range_ok(addr, aligned) {
        return Err(Errno::ENOMEM);
    }
    let (first, pages) = (page_of(addr), aligned >> PAGE_BITS);
    let mut guard = mem_write();
    if !guard.covered(first, pages) {
        return Err(Errno::ENOMEM);
    }
    guard.change_meta(first, pages, ffi::P_SEALED, 0);
    Ok(())
}

/// `madvise(2)` on the calling task's own address space.
///
/// `len` is a `size_t` on aarch64 and must be 64-bit; see `sys_mremap`.
pub fn sys_madvise(addr: u64, len: u64, advice: c_uint) -> Result<(), Errno> {
    strace!("madvise({addr:#x}, {len:#x}, {advice})");
    mmap_trace(2, addr, len, advice as c_int);
    check_range(addr, len, advice, &mem_read())?;
    advise(addr, len, advice)
}

/// What `madvise` refuses before it does anything, against any address space:
/// `process_madvise` asks this of another process's.
///
/// `EINVAL` for an unknown advice or an unaligned start, `ENOMEM` for a range
/// with a hole in it. The unknown advice is refused first: whether the advice
/// exists is a question about the call, and the address only about where.
pub(crate) fn check_range(addr: u64, len: u64, advice: c_uint, held: &impl Held) -> Result<(), Errno> {
    // MADV_REMOVE is a real advice whose refusal depends on the mapping --
    // `advice_known` records the private-anonymous sweep, where it is EINVAL
    // -- and a seal is asked about before that refusal, so it is let through
    // here and decided in `advise`.
    if !mmapabi::advice_known(advice) && advice != MADV_REMOVE {
        return Err(Errno::EINVAL);
    }
    if page_offset(addr) != 0 || !user_range_ok(addr, len) {
        return Err(Errno::EINVAL);
    }
    let first = page_of(addr);
    if !held.covered(first, page_round_up(len)) {
        return Err(Errno::ENOMEM);
    }
    Ok(())
}

/// An advice whose range [`check_range`] has accepted, on the calling task.
fn advise(addr: u64, len: u64, advice: c_uint) -> Result<(), Errno> {
    let (first, pages) = (page_of(addr), page_round_up(len));
    if pages == 0 {
        return Ok(());
    }
    {
        let guard = mem_read();
        let any = |pred: &dyn Fn(u32) -> bool| any_mapped_page(&guard, first, pages, pred);
        if is_discard(advice) && any(&|f| sealed(f) && read_only_private_anon(f)) {
            return Err(Errno::EPERM);
        }
        match advice {
            // Locked memory may not be discarded; DONTNEED_LOCKED is the
            // advice that exists to do it anyway.
            MADV_DONTNEED | MADV_FREE | MADV_GUARD_INSTALL if any(&|f| f & ffi::P_LOCKED != 0) => {
                return Err(Errno::EINVAL);
            }
            // `madvise_free_single_vma`: anonymous memory only, and a shared
            // anonymous mapping is shmem.
            MADV_FREE if any(&|f| !private_anon(f)) => return Err(Errno::EINVAL),
            MADV_WIPEONFORK if any(&|f| !private_anon(f)) => return Err(Errno::EINVAL),
            // Punching a hole is shmem's: a private mapping has no object to
            // punch it in (EINVAL), and a shared file here is a host file this
            // kernel does not punch holes in, which is what a filesystem
            // without `fallocate(PUNCH_HOLE)` answers.
            MADV_REMOVE if any(&|f| f & ffi::P_SHARED == 0) => return Err(Errno::EINVAL),
            MADV_REMOVE if any(&|f| f & ffi::P_ANONYMOUS == 0) => return Err(Errno::EOPNOTSUPP),
            _ => {}
        }
    }
    match advice {
        // Purely advisory: the kernel MAY reclaim the pages under memory
        // pressure, but until then reads still return the old contents.
        // Eagerly zeroing them is both wrong -- a read racing the reclaim must
        // see old-or-zero, never a torn mix -- and dangerous under threads,
        // since another thread aliasing the page through a live TLB entry
        // would watch it turn to zero mid-computation. JSC's scavenger uses
        // MADV_FREE heavily, and keeping the memory is what it means.
        MADV_FREE => Ok(()),
        MADV_DONTNEED | MADV_DONTNEED_LOCKED => {
            if !mmap_no_dontneed() {
                discard(addr, len);
            }
            Ok(())
        }
        // Shared anonymous memory: the hole is in the object, so every process
        // sharing it reads zero afterwards.
        MADV_REMOVE => {
            zero_shared(addr, len);
            Ok(())
        }
        MADV_DONTFORK => meta(first, pages, ffi::P_DONTFORK, 0),
        MADV_DOFORK => meta(first, pages, 0, ffi::P_DONTFORK),
        MADV_WIPEONFORK => meta(first, pages, ffi::P_WIPEONFORK, 0),
        MADV_KEEPONFORK => meta(first, pages, 0, ffi::P_WIPEONFORK),
        // Installing a guard zaps the page, which for private memory is the
        // discard DONTNEED does: after GUARD_REMOVE the page reads zero, as the
        // probe shows. The guard goes on after the zeroing, which needs to
        // reach the page.
        MADV_GUARD_INSTALL => {
            discard(addr, len);
            meta(first, pages, ffi::P_GUARD, 0)
        }
        MADV_GUARD_REMOVE => meta(first, pages, 0, ffi::P_GUARD),
        MADV_POPULATE_READ | MADV_POPULATE_WRITE => populate(first, pages, advice == MADV_POPULATE_WRITE),
        // Every other advice this kernel knows is a hint about paging, and
        // nothing here pages.
        _ => Ok(()),
    }
}

fn meta(first: u64, pages: u64, set: u32, clear: u32) -> Result<(), Errno> {
    mem_write().change_meta(first, pages, set, clear);
    Ok(())
}

/// `MADV_POPULATE_*`: fault the range in, which here means asking each page
/// whether a fault would succeed. Every page of the range is already backed,
/// so there is nothing to bring in; what is observable is the refusal, page by
/// page in order as Linux faults them: `EINVAL` for a page the access is not
/// allowed on (`PROT_NONE`, or a write to a read-only page), `EFAULT` for a
/// guard. `P_READ` is not asked: the stack and the brk carry write alone and
/// are read constantly; `P_NOACCESS` is what says a page cannot be read.
fn populate(first: u64, pages: u64, write: bool) -> Result<(), Errno> {
    let guard = mem_read();
    for p in first..first + pages {
        let Some(f) = guard.pt(p).map(|e| e.flags()) else {
            // A reserved page with no entry yet: faulting it in is allowed
            // exactly when its reservation's protection allows it, and a
            // reservation is PROT_NONE.
            return Err(Errno::EINVAL);
        };
        if f & ffi::P_NOACCESS != 0 || (write && f & ffi::P_WRITE == 0) {
            return Err(Errno::EINVAL);
        }
        if f & ffi::P_GUARD != 0 {
            return Err(Errno::EFAULT);
        }
    }
    Ok(())
}

/// Drop the contents of a range, as `MADV_DONTNEED` does: a private
/// anonymous page reads zero afterwards, a private file page reads the file
/// again, and a shared page keeps its bytes because they live in the object.
///
/// `MADV_DONTNEED` means different things by mapping type:
///
/// - **anonymous private**: the next access must see zero-fill, so the
///   backing is zeroed in place.
/// - **file-backed private**: DONTNEED discards the private copy so the next
///   access re-reads the *original file contents* -- not zero. bun does
///   exactly this to reclaim the physical pages of its 164 MB embedded
///   bytecode cache after decoding, expecting the bytes to page back in.
///   Zeroing them corrupted the cache mid-decode: numCalleeLocals read as 0,
///   an llint prologue stack-frame underflow, a SIGSEGV. A page nobody has
///   written is the file's already and is left alone; a written one is a
///   private copy that remembers its file page, and goes back to it.
///
/// It is issued on huge mappings -- bun DONTNEEDs ~248 MB on exit, about 60k
/// pages -- so the per-page cost dominates. Two rules keep it cheap, both
/// established by history:
///
/// 1. Walk under a **read** lock, and take the write lock only for the rare
///    page that needs zeroing. A per-page write lock over 60k pages contends
///    hard with the JIT reader threads and shows up on-device as a
///    multi-second exit stall.
/// 2. Skip a page that needs no work, which the predicate decides.
///
/// Deliberately *not* done: preading each page to emulate the dirty-page
/// revert. That reintroduced a 60k-synchronous-read exit hang.
fn discard(addr: u64, len: u64) {
    let mut any = false;
    let mut p = addr;
    while p < addr + len {
        let mut guard = mem_read();
        match mmap_discard(&guard, page_of(p)) {
            Discard::Nothing => {}
            Discard::Zero => {
                let ptr = guard.resolve(p, MEM_WRITE);
                if !ptr.is_null() {
                    unsafe { std::ptr::write_bytes(ptr, 0, PAGE_SIZE as usize) };
                    any = true;
                }
            }
            // `revert_copy` bumps the change generation itself.
            Discard::Revert => {
                drop(guard);
                mem_write().revert_copy(page_of(p));
                p += PAGE_SIZE;
                continue;
            }
        }
        drop(guard);
        p += PAGE_SIZE;
    }
    if any {
        pagetable::mem_changed_current();
    }
}

/// Zero a shared range in place, which every mapping of it sees.
fn zero_shared(addr: u64, len: u64) {
    let mut p = addr;
    while p < addr + len {
        let mut guard = mem_read();
        let ptr = guard.resolve(p, MEM_WRITE);
        if !ptr.is_null() {
            unsafe { std::ptr::write_bytes(ptr, 0, PAGE_SIZE as usize) };
        }
        drop(guard);
        p += PAGE_SIZE;
    }
}

/// `madvise` on **another** process's address space, for `process_madvise`:
/// Linux allows only the advices that change no contents there (`COLD`,
/// `PAGEOUT`, `WILLNEED`, `COLLAPSE`), and every one of those is a paging hint
/// this kernel has nothing to do for. What is left is the range check.
pub fn advise_remote(mm: &mm::MmRef, addr: u64, len: u64, advice: c_uint) -> Result<(), Errno> {
    check_range(addr, len, advice, &mm.read())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RW: u32 = ffi::P_READ | ffi::P_WRITE;

    /// The reference kernel's list, from mm_modern_probe: every discarding
    /// advice EPERM on a sealed read-only page, and these four not.
    #[test]
    fn the_discarding_advices_are_the_measured_ones() {
        for a in [MADV_DONTNEED, MADV_FREE, MADV_DONTNEED_LOCKED, MADV_REMOVE, MADV_WIPEONFORK, MADV_GUARD_INSTALL, MADV_DONTFORK] {
            assert!(is_discard(a), "{a}");
        }
        for a in [0, MADV_DOFORK, 20, 21, MADV_POPULATE_READ] {
            assert!(!is_discard(a), "{a}");
        }
    }

    /// Only read-only *private anonymous* memory is protected from a discard:
    /// writable memory could have been zeroed by a store, and shared memory
    /// keeps its bytes in the object.
    #[test]
    fn a_seal_guards_read_only_private_anonymous_memory_only() {
        let anon = ffi::P_ANONYMOUS;
        assert!(read_only_private_anon(ffi::P_READ | anon));
        assert!(read_only_private_anon(ffi::P_NOACCESS | anon));
        assert!(!read_only_private_anon(RW | anon));
        assert!(!read_only_private_anon(ffi::P_READ | anon | ffi::P_SHARED));
        assert!(!read_only_private_anon(ffi::P_READ));
    }
}
