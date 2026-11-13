//! The ELF header and program header table, as read from a file a guest can
//! write.
//!
//! `execve` will parse any file the guest points it at, so every field here is
//! untrusted input. Three defects have been found in the C this replaces:
//!
//! - a `PT_INTERP` segment with no NUL read past the end of its allocation and
//!   used whatever followed as a path
//!   (`docs/changelog/2026-08-22-elf-interp-heap-overread.md`);
//! - `e_phentsize` was never read, so a file declaring any entry size was
//!   parsed as though it had declared the right one, and ran;
//! - `e_phnum` was unbounded, so a crafted file asked for a 3.6 MB allocation
//!   per `execve`, and a count of zero produced a program with nothing mapped
//!   that was jumped to anyway.
//!
//! What lives here is bytes → validated values. What stays in `kernel/exec.c`
//! is the file reads, the mappings, and the stack the new program starts on.
//! The split is the one `fs/dirent-rs` and `fs/cmsg-rs` use, for the same
//! reason: the format is where the bugs were.
//!
//! Everything is decoded from a slice with the length checked, so reading past
//! the end is not expressible, and every arithmetic combination a caller will
//! go on to do — `vaddr + memsize`, `offset + filesize` — is checked here for
//! overflow rather than there.

use std::ffi::c_int;

/// Bytes of ELF header, and of one program header entry, on this ABI.
const EHDR_SIZE: usize = 64;
/// One ELF64 program header. `AT_PHENT` is this number, and it is here rather
/// than written out beside the auxiliary vector so there is one definition:
/// `parse_segments` reads it out of the file's own `e_phentsize` and refuses a
/// file that disagrees, which is only a check if both sides mean the same 56.
pub mod dynsym;

pub const PHDR_SIZE: usize = 56;

// Field offsets in the 64-bit header.
const E_TYPE: usize = 16;
const E_MACHINE: usize = 18;
const E_ENTRY: usize = 24;
const E_PHOFF: usize = 32;
const E_PHENTSIZE: usize = 54;
const E_PHNUM: usize = 56;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELF_CLASS64: u8 = 2;
const ELF_LITTLE_ENDIAN: u8 = 1;
const ELF_VERSION: u8 = 1;
const EM_AARCH64: u16 = 183;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

pub const PT_LOAD: u32 = 1;
pub const PT_INTERP: u32 = 3;

use guest_errno::c_int_::ENOEXEC;

/// Pages are 4 KiB, here as everywhere else in this tree.
const PAGE_BITS: u32 = 12;
use guest_errno::c_int_::ENOMEM;

/// What 64 KB of program headers holds. Linux's bound, and it caps the
/// allocation as a consequence rather than as a separate rule.
const MAX_PHNUM: u16 = (65536 / PHDR_SIZE) as u16;

pub(crate) fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
pub(crate) fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
pub(crate) fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// The header's fields, once they have been checked.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderInfo {
    pub entry: u64,
    pub phoff: u64,
    pub phnum: u16,
    /// `ET_DYN`, which is loaded at a base of this loader's choosing.
    pub dynamic: u8,
    _pad: [u8; 5],
}

/// One program header, once it has been checked.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesize: u64,
    pub memsize: u64,
    pub align: u64,
}

pub fn parse_header(bytes: &[u8]) -> Result<HeaderInfo, c_int> {
    if bytes.len() < EHDR_SIZE {
        return Err(ENOEXEC);
    }
    if bytes[0..4] != ELF_MAGIC
        || bytes[4] != ELF_CLASS64
        || bytes[5] != ELF_LITTLE_ENDIAN
        || bytes[6] != ELF_VERSION
    {
        return Err(ENOEXEC);
    }
    let kind = u16_at(bytes, E_TYPE);
    if kind != ET_EXEC && kind != ET_DYN {
        return Err(ENOEXEC);
    }
    if u16_at(bytes, E_MACHINE) != EM_AARCH64 {
        return Err(ENOEXEC);
    }
    // The shape of the program header table, which the file describes and
    // which used to be taken on trust.
    if u16_at(bytes, E_PHENTSIZE) as usize != PHDR_SIZE {
        return Err(ENOEXEC);
    }
    let phnum = u16_at(bytes, E_PHNUM);
    if !(1..=MAX_PHNUM).contains(&phnum) {
        return Err(ENOEXEC);
    }
    Ok(HeaderInfo {
        entry: u64_at(bytes, E_ENTRY),
        phoff: u64_at(bytes, E_PHOFF),
        phnum,
        dynamic: (kind == ET_DYN) as u8,
        _pad: [0; 5],
    })
}

/// The bytes a caller must read for `phnum` program headers. Cannot overflow:
/// `phnum` is bounded by `parse_header`.
pub fn phdr_bytes(phnum: u16) -> usize {
    phnum as usize * PHDR_SIZE
}

/// Decodes and checks the program header table.
///
/// The checks are the ones that stop a caller's later arithmetic from being
/// nonsense: a segment whose memory is smaller than its file contents cannot
/// be laid out, and one whose address or offset range wraps would be mapped
/// somewhere other than where it says.
pub fn parse_segments(bytes: &[u8], phnum: u16, page_size: u64) -> Result<Vec<Segment>, c_int> {
    let want = phdr_bytes(phnum);
    if bytes.len() < want {
        return Err(ENOEXEC);
    }
    let mut out = Vec::new();
    if out.try_reserve(phnum as usize).is_err() {
        return Err(ENOMEM);
    }
    for i in 0..phnum as usize {
        let e = &bytes[i * PHDR_SIZE..(i + 1) * PHDR_SIZE];
        let seg = Segment {
            kind: u32_at(e, 0),
            flags: u32_at(e, 4),
            offset: u64_at(e, 8),
            vaddr: u64_at(e, 16),
            // p_paddr at 24 is ignored, as it is on every system with an MMU.
            filesize: u64_at(e, 32),
            memsize: u64_at(e, 40),
            align: u64_at(e, 48),
        };
        // Only PT_LOAD is laid out in memory; the rest are descriptive and a
        // strange size in one of those is not this loader's business.
        if seg.kind == PT_LOAD {
            if seg.memsize < seg.filesize {
                return Err(ENOEXEC);
            }
            if seg.vaddr.checked_add(seg.memsize).is_none()
                || seg.offset.checked_add(seg.filesize).is_none()
            {
                return Err(ENOEXEC);
            }
            // `p_align` is decoded and deliberately not validated.
            //
            // Linux's elf_map never looks at it: it maps from
            // ELF_PAGESTART(p_vaddr) at a file offset of
            // p_offset - ELF_PAGEOFFSET(p_vaddr), so what has to hold is
            // congruence modulo the *page*, and a p_align of three is simply
            // ignored. Requiring a power of two, and congruence modulo p_align
            // rather than modulo the page, refused binaries a real kernel runs
            // -- which is what the first differential comparison of
            // exec_semantics found. kernel/exec.c maps exactly the way Linux
            // does, so the page is the only modulus that means anything, and
            // it is also what stops that subtraction underflowing.
            if page_size > 1 && seg.vaddr % page_size != seg.offset % page_size {
                return Err(ENOEXEC);
            }
        }
        out.push(seg);
    }
    Ok(out)
}

/// Do all the `PT_LOAD` segments fit in an address space whose highest page is
/// `max_page`?
///
/// [`parse_segments`] has already refused a `p_vaddr + p_memsz` that overflows,
/// so the subtraction here cannot wrap. What it cannot know is how wide an
/// address is on the target, which is why this takes the bound rather than
/// assuming one.
///
/// **The bias is not a parameter, deliberately.** The loader picks it after the
/// point where this answer is still useful — for a dynamic image it comes from
/// a hole in an address space that does not exist yet. A bias is only ever
/// *added*, so a segment that does not fit at bias 0 cannot fit at any bias,
/// and for a non-dynamic image the bias is 0, which is the case a crafted file
/// controls.
///
/// Without this, a `p_vaddr` above the top of the address space did not fail:
/// page numbers are masked on the way into the page table, so the segment
/// *aliased* onto a lower page and was mapped over whatever was there.
pub fn segments_fit(segments: &[Segment], max_page: u64) -> bool {
    segments.iter().all(|seg| {
        seg.kind != PT_LOAD
            || seg.memsize == 0
            || (seg.vaddr + seg.memsize - 1) >> PAGE_BITS <= max_page
    })
}

/// Where one `PT_LOAD` segment goes, once the bias is known.
///
/// Every field here has had a defect, and every one of them arrives from the
/// *file* rather than from a syscall argument — which is why they are computed
/// somewhere they can be asserted rather than inline in the loader:
///
/// - `vaddr + bias` and `addr + memsize` were added without checking for
///   overflow, and page numbers are masked on the way into the page table, so a
///   `p_vaddr` near the top **aliased** onto a low page and the segment was
///   mapped over whatever was there.
/// - `bss` was a 32-bit difference of two 64-bit addresses, so a segment
///   declaring four gigabytes of it got none: the difference truncated to zero
///   and the mapping was skipped.
/// - `tail_len` is the part of the last file page past the file contents, and
///   it is **zero when the file ends exactly on a page boundary** — the
///   subtraction gives a whole page there, which would zero a page of the next
///   segment.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    /// The first page of the file mapping.
    pub map_page: u64,
    /// How many pages it covers. Zero for a segment with no file contents.
    pub map_pages: u64,
    /// Where in the file that mapping starts, rounded down with the address.
    pub file_offset: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    /// The bytes to zero in the last page of the file mapping, and where.
    /// `tail_len` is zero when there is nothing to zero.
    pub tail_at: u64,
    pub tail_len: u64,
    /// Whole pages of `bss` after that, if any.
    pub bss_page: u64,
    pub bss_pages: u64,
}

/// `PF_R`, `PF_W`, `PF_X` in a program header's `p_flags`.
pub const PH_R: u32 = 4;
pub const PH_W: u32 = 2;
pub const PH_X: u32 = 1;

/// Where `segment` goes at `bias`, or `ENOEXEC`.
///
/// `max_page` is the highest page the address space has. A segment that does
/// not fit is refused here rather than mapped somewhere else.
pub fn place(
    segment: &Segment,
    bias: u64,
    page_size: u64,
    max_page: u64,
) -> Result<Placement, c_int> {
    let page_bits = page_size.trailing_zeros() as u64;
    let page_of = |a: u64| a >> page_bits;
    let offset_in = |a: u64| a & (page_size - 1);
    let round_up_pages = |n: u64| (n + page_size - 1) >> page_bits;

    let addr = segment.vaddr.checked_add(bias).ok_or(ENOEXEC)?;
    let end = addr.checked_add(segment.memsize).ok_or(ENOEXEC)?;
    if segment.memsize != 0 && page_of(end - 1) > max_page {
        return Err(ENOEXEC);
    }
    // The file mapping is rounded up *with the page offset added*, which is its
    // own chance to leave the address space.
    let file_end = addr.checked_add(segment.filesize).ok_or(ENOEXEC)?;
    if segment.filesize != 0 && page_of(file_end - 1) > max_page {
        return Err(ENOEXEC);
    }

    // Every one of the three, not just the writable bit. `P_EXEC` was never
    // set, so every text segment appeared in /proc/<pid>/maps as `r--p` rather
    // than `r-xp` — and a JIT locating its own code, a crash handler
    // symbolising a backtrace and a profiler attributing samples all find
    // executable mappings by scanning that column.
    let mut readable = segment.flags & PH_R != 0;
    let writable = segment.flags & PH_W != 0;
    let executable = segment.flags & PH_X != 0;
    // A segment with no bits at all would otherwise be indistinguishable from
    // PROT_NONE, which is a page every access to must fault.
    if !readable && !writable && !executable {
        readable = true;
    }

    // The tail: from the end of the file contents to the end of that page.
    // Zero when the contents end exactly on a boundary — there is no partial
    // page then, and zeroing "a page's worth" would reach into the next one.
    let bss = segment.memsize.saturating_sub(segment.filesize);
    // Only a segment that *has* a bss, which is Linux: `load_elf_binary` calls
    // `padzero(elf_bss)` once, for the segment the bss belongs to. A segment
    // with `memsz == filesz` keeps whatever the file has in the rest of its
    // last page — and it is usually read-only, so zeroing it is an `EFAULT`
    // rather than a courtesy. That is what the first version of this fix did,
    // and every `execve` failed at boot with -14.
    let tail_len = if bss == 0 || offset_in(file_end) == 0 {
        0
    } else {
        page_size - offset_in(file_end)
    };

    // **To the end of the page, not to the end of the bss.** Linux's `padzero`
    // zeroes `ELF_MIN_ALIGN - (elf_bss & (ELF_MIN_ALIGN - 1))` bytes — the rest
    // of the page, unconditionally — and it is not being generous: the bytes
    // between `memsz` and the page end are inside a mapping the process can
    // read, so what is there is observable, and on Linux it is zero.
    //
    // Capping this at `bss` left the file's own bytes there, and glibc walks
    // straight into them. Its early allocator is a bump over `brk`, `brk`
    // starts at the end of the loader's image, and `_dl_new_object` reaches it
    // through a `calloc` that assumes fresh pages are zero. The main
    // `link_map` therefore landed eight bytes past `.bss` — on
    // `"GCC: (GNU) 11.5.0 …"`, which is what the file has at that offset — and
    // `dl_main` faulted adjusting `l_info[DT_HASH]`, a field that had never
    // been written. **No dynamically-linked glibc program ran at all.**
    //
    // musl is unaffected, which is why every alpine suite passed throughout: it
    // does not allocate before it has a real `mmap`.
    let after_tail = bss.saturating_sub(tail_len);
    Ok(Placement {
        map_page: page_of(addr),
        map_pages: if segment.filesize == 0 {
            0
        } else {
            round_up_pages(segment.filesize + offset_in(addr))
        },
        file_offset: segment.offset.checked_sub(offset_in(addr)).ok_or(ENOEXEC)?,
        readable,
        writable,
        executable,
        tail_at: file_end,
        tail_len,
        bss_page: round_up_pages(file_end),
        bss_pages: round_up_pages(after_tail),
    })
}

/// How many pages the whole image spans, from the first `PT_LOAD` to the last.
///
/// What a position-independent executable needs a hole of. `None` when the
/// arithmetic leaves the address space — `PAGE_ROUND_UP(vaddr + memsize)` was
/// computed without checking, and a file chooses both numbers.
pub fn span_pages(segments: &[Segment], page_size: u64) -> Option<u64> {
    let page_bits = page_size.trailing_zeros() as u64;
    let loads: Vec<&Segment> = segments.iter().filter(|s| s.kind == PT_LOAD).collect();
    let (first, last) = (loads.first()?, loads.last()?);
    let end = last.vaddr.checked_add(last.memsize)?;
    let top = (end.checked_add(page_size - 1)?) >> page_bits;
    top.checked_sub(first.vaddr >> page_bits)
}

/// The path in a `PT_INTERP` segment's contents.
///
/// The segment is a NUL-terminated string, and a file may simply not put the
/// NUL there. Reading it as a C string then ran off the end of the allocation
/// — 27 bytes read from a 26-byte one — and used whatever followed as a path.
/// Here the terminator has to be inside the bytes that were read.
pub fn interp_path(segment: &[u8]) -> Result<&[u8], c_int> {
    // An empty path, or one that is only its terminator, names nothing.
    if segment.len() < 2 {
        return Err(ENOEXEC);
    }
    match segment.iter().position(|&b| b == 0) {
        // Anything after the terminator is padding the loader does not read.
        Some(0) => Err(ENOEXEC),
        Some(end) => Ok(&segment[..end]),
        None => Err(ENOEXEC),
    }
}

// ---- the C ABI ----------------------------------------------------------

#[cfg(test)]
mod tests;
