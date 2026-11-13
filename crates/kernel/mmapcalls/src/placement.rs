//! Mapping placement, remapping, shared attachments, and the program break.

use super::*;

// ---------------------------------------------------------------------------
// Placing a mapping
// ---------------------------------------------------------------------------

use guest_errno::Errno;
use guest_errno::i64_::{EINVAL, ENOMEM};

const MMAP_SHARED: c_uint = ffi::MMAP_SHARED;
const MMAP_PRIVATE: c_uint = ffi::MMAP_PRIVATE;
const MMAP_ANONYMOUS: c_uint = ffi::MMAP_ANONYMOUS;
const MMAP_NORESERVE: c_uint = ffi::MMAP_NORESERVE;
/// `BAD_PAGE` from `emu/mmu.h`: beyond the 36-bit page range.
const BAD_PAGE: u64 = ffi::BAD_PAGE;
/// Where the mmap search ends, above the guard pages.
const MMAP_HOLE_END: u64 = ffi::MMAP_HOLE_END as u64;
/// The guard page below the stack; a low hint must not run into it.
///
/// **Generated.** This was written by hand as `0xf7ffe` and is `0xffffe` — the
/// fourth constant guessed wrong in two days, and the reason `build.rs`
/// generates every one that has a header to come from.
const STACK_TOP_PAGE: u64 = ffi::STACK_TOP_PAGE as u64;
/// `MMAPABI_HINT` — the placement that may be moved.
const PLACEMENT_HINT: c_int = 2;

/// `offset` is 64-bit all the way down: aarch64 `mmap` takes it in a register
/// and `fd_ops.mmap` takes an `off_t`. It used to be 32 bits here, and
/// `sys_mmap64` cast to it — so a mapping at 4 GiB + 4096 handed back the bytes
/// at 4096, with no error and nothing in `/proc/<pid>/maps` to say so.
///
fn do_mmap(
    guard: &mut WriteGuard,
    mut addr: u64,
    len: u64,
    mut prot: c_int,
    flags: c_uint,
    fd_no: c_int,
    offset: i64,
) -> Result<i64, Errno> {
    let pages = page_round_up(len);
    if pages == 0 {
        return Err(Errno::EINVAL);
    }
    mmap_exec_trace(addr, len, prot as c_uint, flags, fd_no);

    let mut page = 0u64;
    if addr != 0 {
        // An unaligned *hint* is rounded down rather than refused: Linux's
        // arch_get_unmapped_area page-aligns one, and a caller that passes it
        // is not making an error. Only MAP_FIXED and MAP_FIXED_NOREPLACE
        // require alignment. This answered EINVAL for all three.
        addr = kernel_mmapabi::resolve_addr(addr, flags, PAGE_SIZE).map_err(Errno::from_negative_or_eio)?;
        page = page_of(addr);
        let movable = kernel_mmapabi::mmapabi_placement(flags) == PLACEMENT_HINT;
        // A hint inside the low 4 GB must not run into the stack; one above it
        // is honoured where asked. Go's arena hints at 0x4000000000 and
        // 0x14000000000 need to land exactly there, because the runtime's
        // scavengeIndex metadata is laid out on the assumption that they did.
        // V8's Wasm guard regions use the low ones.
        let limit = if page < 0x100000 {
            STACK_TOP_PAGE
        } else {
            USER_ADDR_MAX_PAGE
        };
        if page + pages > limit {
            if !movable {
                return Err(Errno::ENOMEM);
            }
            addr = 0;
            page = 0;
        }
    }

    // A writable, executable mapping under MDWE. After the address has been
    // judged and before the range is, which is where Linux's do_mmap asks:
    // get_unmapped_area's EINVAL and ENOMEM come first, mmap_region's EEXIST
    // after.
    if mmflags::deny_write_exec(current_flags(), prot as u32, prot as u32) {
        return Err(Errno::EACCES);
    }

    // MAP_FIXED_NOREPLACE is what a program uses to reserve a range
    // safely: the point of it is that it cannot clobber a mapping it did
    // not know about. The flag was ignored, so the mapping *was* replaced
    // -- worse than not supporting it, because a caller that checks for
    // EEXIST and gets success has been told its range was free.
    if addr != 0 && !guard.is_hole(page, pages) {
        match kernel_mmapabi::mmapabi_placement(flags) {
            1 => return Err(Errno::EEXIST), // FixedNoReplace
            PLACEMENT_HINT => addr = 0,
            // MAP_FIXED replaces what is there, and a seal says it may not.
            _ => advise::refuse_sealed(guard, page, pages)?,
        }
    }

    if addr == 0 {
        // V8 reserves its heap cage with a PROT_NONE, private, anonymous
        // mapping of 128 MB or more, then mprotects sub-regions RW as it
        // allocates. Node 22 is built without pointer compression, so V8 stores
        // full 64-bit tagged pointers into heap slots: if the cage lives in the
        // low 4 GB, a slot that happens to hold a small integer looks like a
        // valid heap pointer and V8 dereferences it into unmapped memory.
        // Placing the cage above 4 GB makes such stray values obviously
        // non-canonical, so V8's own tag checks catch them before the deref.
        //
        // The shape is matched conservatively -- Go's arenas default to 64 MB
        // and need to stay in the low 4 GB, because the runtime's arenaIndex
        // and scavengeIndex metadata assume it.
        let is_v8_cage = prot == 0
            && flags & (MMAP_PRIVATE | MMAP_ANONYMOUS) == (MMAP_PRIVATE | MMAP_ANONYMOUS)
            && flags & MMAP_SHARED == 0
            && pages >= 0x8000; // 128 MB
        page = if is_v8_cage {
            guard.find_hole_for_reservation(pages)
        } else {
            guard.find_hole(pages)
        };
        if page == BAD_PAGE {
            return Err(Errno::ENOMEM);
        }
    }

    if flags & MMAP_SHARED != 0 {
        prot |= P_SHARED;
    }
    // PROT_NONE, marked explicitly. Every access to a page carrying this is
    // refused; without it a guard page was indistinguishable from the pages
    // this kernel maps without setting any permission bits, and reads ran
    // straight into a host mapping that had none either.
    if prot & P_RWX == 0 {
        prot |= P_NOACCESS;
    }

    if flags & MMAP_ANONYMOUS != 0 {
        // A PROT_NONE mapping is a guard region and consumes no real memory,
        // so it is not counted against the anonymous page budget.
        let is_prot_none = prot & (P_READ | P_WRITE | P_EXEC) == 0;

        if flags & MMAP_NORESERVE != 0 && pages > 0x10000 {
            let align = pages.min(0x40000);
            let aligned = (page / align) * align;
            if aligned >= MMAP_HOLE_END
                && guard.is_hole(aligned, pages)
            {
                page = aligned;
            }
            guard.map_lazy(page, pages, prot as c_uint)?;
            return Ok((page << PAGE_BITS) as i64);
        }
        // A large PROT_NONE reservation is lazily mapped even without
        // MAP_NORESERVE, for the V8 cage above: allocating all 128 MB of host
        // memory up front would waste some 640 MB per node process. It is
        // tracked as a reservation and each page demand-mapped on first
        // mprotect or touch.
        if is_prot_none && pages >= 0x8000 {
            guard.map_lazy(page, pages, prot as c_uint)?;
            return Ok((page << PAGE_BITS) as i64);
        }
        // Asked, not charged: `pt_map_nothing` is the one place an anonymous
        // page is charged, against `pt_unmap_always` as the one place it is
        // given back.
        if !is_prot_none && !pagetable::anonbudget::anon_pages_would_fit(pages) {
            return Err(Errno::ENOMEM);
        }
        guard.map_nothing(page, pages, prot as c_uint)?;
    } else {
        let err = mmap_map_file(guard, fd_no, page, pages, offset, prot as c_uint, flags);
        if err < 0 {
            return Err(Errno::from_negative_or_eio(err));
        }
    }
    Ok((page << PAGE_BITS) as i64)
}

/// aarch64 `mmap`: the offset is passed directly, in bytes, in a register.
///
/// The x86-era entry points went with the x86 backend — `sys_mmap`, taking a
/// pointer to a six-word struct, and `sys_mmap2`, taking the offset in pages.
/// Neither was in the aarch64 syscall table, and `sys_mmap2`'s
/// `offset << PAGE_BITS` overflowed at 4 GiB anyway.
pub fn sys_mmap64(
    addr: u64,
    len: u64,
    prot: c_uint,
    flags: c_uint,
    fd_no: c_int,
    offset: u64,
) -> Result<i64, Errno> {
    strace!("mmap64({addr:#x}, {len:#x}, {prot:#x}, {flags:#x}, {fd_no}, {offset:#x})");
    if len == 0 {
        return Err(Errno::EINVAL);
    }
    // mmap does *not* validate prot, and mprotect does. Measured both ways:
    // Linux's arch_validate_prot is called from do_mprotect_pkey and not from
    // do_mmap, so mmap(..., 0x1000, ...) maps something and mprotect(...,
    // 0x1000) is EINVAL. This refused both, and refusing more than Linux does
    // is not the safe direction -- it is a program that works everywhere else
    // failing here. The bits this kernel does not record are dropped.
    let prot = mmapabi::prot_for_mmap(prot) as c_int;
    // The descriptor is checked before the sharing flags, which is Linux's
    // order and is observable: mmap(NULL, len, prot, 0, -1, 0) is EBADF there
    // and would be EINVAL if the flags were judged first. ksys_mmap_pgoff does
    // the fget, and do_mmap's `switch (flags & MAP_TYPE)` comes after it.
    if flags & MMAP_ANONYMOUS == 0 && fs_fdobj::f_get(fd_no).is_none() {
        return Err(Errno::EBADF);
    }
    // Exactly one of MAP_SHARED and MAP_PRIVATE. Both was checked; *neither*
    // was not, so mmap(NULL, len, prot, MAP_ANONYMOUS, -1, 0) mapped something
    // here and is EINVAL on Linux.
    if !mmapabi::sharing_ok(flags) {
        return Err(Errno::EINVAL);
    }
    // The offset has to be a whole number of pages, and Linux checks it in the
    // architecture entry point before anything else looks at it -- anonymous
    // mappings included. Without the check, realfs rounded it down and applied
    // a correction, so mmap(fd, offset=1) returned a mapping of the page at
    // offset 0 rather than the EINVAL a caller is entitled to.
    if page_offset(offset) != 0 {
        return Err(Errno::EINVAL);
    }

    // A `Result` since 2026-09-30. It was an address or a negative errno in one
    // `i64`, split here, with a comment saying `share::map` shared it -- which
    // it did not: that calls `map_file_pages`.
    do_mmap(&mut mem_write(), addr, len, prot, flags, fd_no, offset as i64)
}

/// The mapping operations another crate performs on a descriptor it holds
/// rather than a number in the caller's table: System V shared memory
/// (`crates/kernel/sysvshm`) attaches a segment's file this way.
pub mod share {
    use super::*;

    /// Map `len` bytes of `fd` shared at `addr`, or wherever there is room
    /// when `addr` is 0. Where an address is given it has to be free unless
    /// `replace` says otherwise -- `shmat`'s rule, which is `EINVAL` for an
    /// occupied range where `mmap(MAP_FIXED_NOREPLACE)` says `EEXIST`. The
    /// address mapped, or a negative errno. The mapping keeps a reference of
    /// its own to `fd`.
    pub fn map(fd: &fs_fdobj::Owned, addr: u64, len: u64, prot: c_int, replace: bool) -> i64 {
        let pages = page_round_up(len);
        if pages == 0 || page_offset(addr) != 0 {
            return EINVAL;
        }
        let mut guard = mem_write();
        let page = if addr != 0 {
            if !user_range_ok(addr, len) {
                return EINVAL;
            }
            let page = page_of(addr);
            if !replace && !guard.is_hole(page, pages) {
                return EINVAL;
            }
            page
        } else {
            let page = guard.find_hole(pages);
            if page == BAD_PAGE {
                return ENOMEM;
            }
            page
        };
        let err = map_file_pages(
            &mut guard,
            fd,
            page,
            pages,
            0,
            (prot | P_SHARED) as c_uint,
            MMAP_SHARED,
        );
        if err < 0 {
            return err as i64;
        }
        (page << PAGE_BITS) as i64
    }

    /// The descriptor behind the shared file mapping whose page is at
    /// `addr`, and the file offset that page maps -- `shmdt` needs the first
    /// to know whose segment it is and the second to be zero, which is what
    /// says `addr` is where the segment was attached. `None` for anything
    /// else at that address, or nothing.
    ///
    /// A reference of the caller's own since 2026-10-17. It answered the
    /// mapping's pointer, read under a lock this function then released, so
    /// another thread's `munmap` of the segment could free the descriptor
    /// before `shmdt` compared it -- found by reading, not observed.
    pub fn mapped_at(addr: u64) -> Option<(fs_fdobj::Owned, u64)> {
        let guard = mem_read();
        let entry = guard.pt(page_of(addr))?;
        let data = entry.data()?;
        if !data.shared() {
            return None;
        }
        let fd = data.fd()?.clone();
        let first = data.file_offset() as u64 + entry.offset as u64;
        Some((fd, first))
    }

    /// Unmap whatever of `pages` pages at `addr` is mapped.
    ///
    /// It answered an `i64` documented as "a negative errno if nothing was
    /// there" until 2026-09-30, and could not: the unmap it made answers 0
    /// whatever it finds, so the `EINVAL` arm was a branch nothing took.
    pub fn unmap(addr: u64, pages: u64) {
        mem_write().unmap_always(page_of(addr), pages);
    }
}

const MREMAP_MAYMOVE: c_uint = 1;
const MREMAP_FIXED: c_uint = 2;
/// Move the pages and leave the old range mapped, empty: zero-fill for private
/// anonymous memory, the same object again for a shared or file mapping.
/// `EINVAL` until 2026-11-11.
const MREMAP_DONTUNMAP: c_uint = 4;

/// **Five arguments.** `mremap(2)` is variadic and reads `new_addr` only when
/// `MREMAP_FIXED` is set; it was declared with four until 2026-09-06, which is
/// why that flag answered `EINVAL`.
///
/// Every length here is a `size_t` on aarch64 and must be 64-bit. This,
/// `madvise`, `msync`, `mincore` and `mlock` took a `dword_t`, so anything at
/// or above 4 GiB was truncated to its low 32 bits -- and for `mremap` that
/// turned a grow into a **shrink**, which unmapped live pages and reported
/// success.
pub fn sys_mremap(
    addr: u64,
    old_len: u64,
    new_len: u64,
    flags: c_uint,
    new_addr: u64,
) -> Result<i64, Errno> {
    mremap(addr, old_len, new_len, flags, new_addr)
}

/// `mremap`'s body.
///
/// It answered an address or a negative errno in one `i64` until 2026-09-30,
/// under a note saying that was because the four page-table operations it
/// calls did, and that converting them was the page-table layer's step. They
/// answer `Result`s now, and every one of the twenty returns below is a `?` or
/// an `Err`.
fn mremap(addr: u64, old_len: u64, new_len: u64, flags: c_uint, new_addr: u64) -> Result<i64, Errno> {
    strace!("mremap({addr:#x}, {old_len:#x}, {new_len:#x}, {flags}, {new_addr:#x})");
    if page_offset(addr) != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 {
        return Err(Errno::EINVAL);
    }
    // Linux's `check_mremap_params`: DONTUNMAP is a move of the same length.
    if flags & MREMAP_DONTUNMAP != 0 && (flags & MREMAP_MAYMOVE == 0 || old_len != new_len) {
        return Err(Errno::EINVAL);
    }
    // `MREMAP_FIXED` answered `EINVAL` until 2026-09-06, under a FIXME saying
    // it was missing -- and the reason it was missing is one line above: this
    // took **four** arguments, so `new_addr` never arrived. `mremap(2)` is
    // variadic and reads a fifth only for this flag; the dispatcher hands every
    // implementation six registers, so declaring it is the whole of getting it.
    //
    // Linux requires MAYMOVE with FIXED, because FIXED is a move by
    // definition, and refuses overlapping ranges. `differential.sh` is what
    // says these are its rules rather than the man page's.
    if flags & MREMAP_FIXED != 0 {
        if flags & MREMAP_MAYMOVE == 0 || page_offset(new_addr) != 0 {
            return Err(Errno::EINVAL);
        }
        if !user_range_ok(new_addr, new_len) {
            return Err(Errno::EINVAL);
        }
    }
    // Rounded up, which is what mremap(2) does with both lengths: a request to
    // grow from 4097 to 8192 bytes is two pages to two pages, not one to two.
    // Truncating left a mapping alone when asked to grow it by less than a
    // page, and left the tail mapped when asked to shrink a length that was
    // not a whole number of pages.
    let old_pages = page_round_up(old_len);
    let new_pages = page_round_up(new_len);
    if new_pages == 0 {
        return Err(Errno::EINVAL);
    }
    // An old length of zero asks for the mapping to be duplicated, which is
    // only defined for shared mappings and is not implemented here.
    if old_pages == 0 {
        return Err(Errno::EINVAL);
    }
    if !user_range_ok(addr, old_len) || !user_range_ok(addr, new_len) {
        return Err(Errno::EINVAL);
    }

    // Every other call in this family holds the address-space lock while it
    // touches the page table; this one held nothing at all, and it both unmaps
    // and maps. Taken for writing across the whole call, because the check that
    // the old range is uniform and the mapping that follows it have to see the
    // same address space.
    let mut guard = mem_write();
    let start = page_of(addr);

    // A seal refuses the move, the shrink and the growth alike, and a sealed
    // destination refuses being replaced -- before anything changes.
    advise::refuse_sealed(&guard, start, old_pages)?;
    if flags & MREMAP_FIXED != 0 {
        advise::refuse_sealed(&guard, page_of(new_addr), new_pages)?;
    }

    if flags & MREMAP_DONTUNMAP != 0 {
        let dest = if flags & MREMAP_FIXED != 0 {
            let dest = page_of(new_addr);
            if dest < start + old_pages && start < dest + new_pages {
                return Err(Errno::EINVAL);
            }
            dest
        } else {
            guard.find_hole(old_pages)
        };
        return dont_unmap(&mut guard, start, dest, old_pages).map(|()| (dest << PAGE_BITS) as i64);
    }

    if flags & MREMAP_FIXED != 0 {
        let dest = page_of(new_addr);
        // Overlapping ranges are `EINVAL`: the destination is unmapped before
        // the move, so an overlap would unmap part of what is being moved.
        if dest < start + old_pages && start < dest + new_pages {
            return Err(Errno::EINVAL);
        }
        let moved = old_pages.min(new_pages);
        // Shrinking: the tail goes before the move, so what is moved is
        // exactly the new length.
        if new_pages < old_pages {
            guard.unmap(start + new_pages, old_pages - new_pages).map_err(|_| Errno::EFAULT)?;
        }
        // The destination is replaced, as `MAP_FIXED` replaces, and a hole
        // there is not an error. This was `unmap`, which refuses a range with
        // any page unmapped -- the opposite of what the comment above it said
        // -- so a move into free address space answered EFAULT until
        // 2026-11-11; mm_seal_guard's "MREMAP_FIXED into a hole" is the check.
        guard.unmap_always(dest, new_pages);
        guard.move_pages(start, dest, moved);
        if new_pages > old_pages {
            // Growing: the added pages are made the same way the non-fixed
            // path makes them, out of the mapping's own kind.
            let Some(mapping) = uniform_flags(&guard, dest, old_pages) else {
                return Err(Errno::EFAULT);
            };
            let Some(ext) = extension_of(&guard, dest + old_pages - 1, mapping)
            else {
                return Err(Errno::ENOMEM);
            };
            if let Err(e) = extend(&mut guard, dest + old_pages, new_pages - old_pages, mapping, &ext) {
                guard.unmap_always(dest, old_pages);
                return Err(e);
            }
        }
        return Ok(new_addr as i64);
    }

    // Shrinking always works.
    if new_pages <= old_pages {
        return guard
            .unmap(start + new_pages, old_pages - new_pages)
            .map(|()| addr as i64)
            .map_err(|_| Errno::EFAULT);
    }

    // One mapping, and which: the *mapping* bits of every page agree. The
    // per-page bits -- copy-on-write after a fork, compiled code -- are not a
    // boundary, and reading them as one is what made apt's first cache growth
    // EFAULT. crates/kernel/mmapcalls/src/remap.rs has the rule and the test.
    // `mapping`, not `flags`: the syscall's `flags` is MREMAP_MAYMOVE, and
    // the first version of this shadowed it -- the MAYMOVE test then read
    // P_READ and every growth was allowed to move. mem_probe's "grow
    // without MAYMOVE into its own next page" is what caught it.
    let Some(mapping) = uniform_flags(&guard, start, old_pages) else {
        return Err(Errno::EFAULT);
    };
    // What the added pages are made of: fresh zero pages for an anonymous
    // range, and for a file range the file's *next* pages -- the vma keeps
    // its file and its offset runs on. This used to map anonymous pages
    // behind a file mapping and say Linux did; a grown file mapping read
    // zeroes where the file had bytes.
    let Some(ext) = extension_of(&guard, start + old_pages - 1, mapping) else {
        return Err(Errno::ENOMEM);
    };
    let extra_start = start + old_pages;
    let extra_pages = new_pages - old_pages;

    if guard.is_hole(extra_start, extra_pages) {
        // Room where it is, so the mapping does not move.
        return extend(&mut guard, extra_start, extra_pages, mapping, &ext).map(|()| addr as i64);
    }

    // No room. **This used to be the end of it** -- MREMAP_MAYMOVE was accepted
    // as a flag and then never acted on, so growing a mapping with anything
    // after it answered ENOMEM. That is not an edge case: it is what realloc()
    // does with a large block and what a Go heap does when it grows, and the
    // address space fills up from the bottom here, so there usually *is*
    // something after it.
    if flags & MREMAP_MAYMOVE == 0 {
        return Err(Errno::ENOMEM);
    }
    let dest = guard.find_hole(new_pages);
    if dest == BAD_PAGE {
        return Err(Errno::ENOMEM);
    }
    // Moved, not copied: a page-table entry is a pointer to the backing and an
    // offset, so the pages themselves stay where they are and a file-backed
    // mapping moves as easily as an anonymous one.
    guard.move_pages(start, dest, old_pages);
    if let Err(e) = extend(&mut guard, dest + old_pages, extra_pages, mapping, &ext) {
        // The old range is gone and the new one is short. Report the failure
        // rather than half a mapping: the caller's old address is no longer
        // valid either way, and leaving the moved pages mapped at `dest` with
        // no way to name them would leak them for the life of the process.
        guard.unmap_always(dest, old_pages);
        return Err(e);
    }
    Ok((dest << PAGE_BITS) as i64)
}

/// `MREMAP_DONTUNMAP`'s move: `pages` from `start` to `dest`, the old range
/// left mapped and empty.
///
/// What "empty" means is the mapping's kind, which is why the range has to be
/// one mapping (`EFAULT` otherwise, as for any `mremap`). A private anonymous
/// range gets fresh zero pages, which is what the reference kernel's old range
/// reads. A shared range keeps reaching the same object, so both ranges name
/// the same backing. A private file range would refault from the file on
/// Linux; here both ranges keep the pages it had and are marked
/// copy-on-write, so neither sees the other's stores -- what differs is only a
/// page this process had already written, which reads its written bytes in the
/// old range rather than the file's.
fn dont_unmap(guard: &mut WriteGuard, start: u64, dest: u64, pages: u64) -> Result<(), Errno> {
    let Some(mapping) = uniform_flags(guard, start, pages) else {
        return Err(Errno::EFAULT);
    };
    if dest == BAD_PAGE {
        return Err(Errno::ENOMEM);
    }
    // The destination is replaced, as MAP_FIXED replaces; a hole is fine.
    guard.unmap_always(dest, pages);
    if mapping & ffi::P_ANONYMOUS != 0 && mapping & ffi::P_SHARED == 0 {
        guard.move_pages(start, dest, pages);
        if let Err(e) = guard.map_nothing(start, pages, mapping as c_uint) {
            // Put the pages back rather than leave the old range a hole the
            // caller was promised would stay mapped.
            guard.move_pages(dest, start, pages);
            return Err(e);
        }
    } else {
        guard.duplicate_pages(start, dest, pages);
        if mapping & ffi::P_SHARED == 0 {
            guard.change_meta(start, pages, ffi::P_COW, 0);
            guard.change_meta(dest, pages, ffi::P_COW, 0);
        }
    }
    Ok(())
}

/// The name `/proc/<pid>/maps` gives the heap, as Linux does.
static HEAP_NAME: &std::ffi::CStr = c"[heap]";

/// The break, and it **cannot fail**: every failure answers the *current*
/// break rather than an errno, which is what `brk(2)` does -- a caller compares
/// the result against what it asked for.
pub fn sys_brk(new_brk: u64) -> i64 {
    strace!("brk({new_brk:#x})");
    // A hand-paired lock/unlock until 2026-09-06, which is the shape
    // `MemWrite` exists to remove: correct as written, and one early return
    // away from not being.
    let mut guard = crate::mem_write();
    brk_locked(&mut guard, new_brk)
}

/// `brk` with the lock held. Every failure answers the *current* break rather
/// than an errno, which is what `brk(2)` does: a caller compares the result
/// against what it asked for.
///
/// `brk` and `start_brk` are `mem.image`'s, reached through `guard`.
fn brk_locked(guard: &mut WriteGuard, new_brk: u64) -> i64 {
    let (start_brk, old_brk) = (guard.image().start_brk, guard.image().brk);
    if new_brk < start_brk {
        return old_brk as i64;
    }

    if new_brk > old_brk {
        // Rounded up because of what brk means: "the first location after the
        // end of the uninitialized data segment". If the break is 0x2000, page
        // 0x2000 is not mapped; if it is 0x2001, it is.
        let start = page_round_up(old_brk);
        let size = page_round_up(new_brk) - start;
        if !guard.is_hole(start, size) {
            return old_brk as i64;
        }
        if !pagetable::anonbudget::anon_pages_would_fit(size) {
            return old_brk as i64;
        }
        // P_READ too. The heap was mapped write-only, so /proc/<pid>/maps
        // described it as `-w-p` -- a combination no kernel produces, on the
        // one region every allocator in the guest reads from constantly. The
        // bits are recorded rather than enforced, so this changes what the
        // guest is told and nothing about what it may do.
        if guard.map_nothing(start, size, (P_READ | P_WRITE) as c_uint).is_err() {
            return old_brk as i64;
        }
        guard.name_region(start, HEAP_NAME);
    } else if new_brk < old_brk {
        // Unmap only the pages entirely above the new break: the page holding
        // it may still have live data below it.
        let first = page_round_up(new_brk);
        let last = page_round_up(old_brk);
        if first < last {
            // A sealed heap page cannot be given back; the break stays.
            if advise::first_sealed(guard, first, last - first).is_some() {
                return old_brk as i64;
            }
            guard.unmap_always(first, last - first);
        }
    }

    guard.image_mut().brk = new_brk;
    new_brk as i64
}
