//! Unit tests for validated ELF parsing and placement.

use super::*;

/// The layout the C declares, asserted from this side too.
///
/// `struct elf_placement` is written out in kernel/elf.h and this is the
/// struct it is a copy of. Two declarations of one layout is what
/// crates/fs/cmsg exists for -- there every field after the first was at
/// the wrong offset, and nothing said so.
#[test]
fn the_placement_layout_is_the_one_the_c_declares() {
    assert_eq!(std::mem::size_of::<Placement>(), 64);
    let p = Placement {
        map_page: 0,
        map_pages: 0,
        file_offset: 0,
        readable: false,
        writable: false,
        executable: false,
        tail_at: 0,
        tail_len: 0,
        bss_page: 0,
        bss_pages: 0,
    };
    let base = &p as *const _ as usize;
    assert_eq!(&p.readable as *const _ as usize - base, 24);
    assert_eq!(&p.tail_at as *const _ as usize - base, 32);
    assert_eq!(&p.bss_pages as *const _ as usize - base, 56);
}

/// The placement of an ordinary text segment: page-aligned, read and
/// execute, no bss.
#[test]
fn a_text_segment_maps_its_pages_and_nothing_else() {
    let seg = Segment {
        kind: PT_LOAD,
        flags: PH_R | PH_X,
        offset: 0,
        vaddr: 0x10000,
        filesize: 0x2000,
        memsize: 0x2000,
        align: 0x1000,
    };
    let p = place(&seg, 0, 0x1000, 0xffff_ffff).expect("fits");
    assert_eq!(p.map_page, 0x10);
    assert_eq!(p.map_pages, 2);
    assert_eq!(p.file_offset, 0);
    assert!(p.readable && p.executable && !p.writable);
    assert_eq!((p.tail_len, p.bss_pages), (0, 0), "no bss at all");
}

/// A segment whose contents do not start on a page boundary: the mapping
/// is rounded **down** to a page and the file offset with it, and the
/// length grows by what was rounded off.
#[test]
fn an_unaligned_segment_rounds_the_address_and_the_offset_together() {
    let seg = Segment {
        kind: PT_LOAD,
        flags: PH_R,
        offset: 0x1234,
        vaddr: 0x20234,
        filesize: 0x100,
        memsize: 0x100,
        align: 0x1000,
    };
    let p = place(&seg, 0, 0x1000, 0xffff_ffff).expect("fits");
    assert_eq!(p.map_page, 0x20, "rounded down");
    assert_eq!(p.file_offset, 0x1000, "and the offset by the same amount");
    assert_eq!(p.map_pages, 1, "0x234 + 0x100 still fits one page");
    // The rounding has to be the same on both sides, or the file lands at
    // the wrong address inside the page.
    assert_eq!(seg.vaddr - (p.map_page << 12), seg.offset - p.file_offset);
}

/// The tail is the part of the last file page past the contents, and it is
/// **zero on an exact boundary** — the subtraction gives a whole page
/// there, which would zero a page belonging to the next segment.
#[test]
fn a_file_ending_on_a_page_boundary_has_no_tail() {
    let exact = Segment {
        kind: PT_LOAD,
        flags: PH_R | PH_W,
        offset: 0,
        vaddr: 0x30000,
        filesize: 0x1000,
        memsize: 0x3000,
        align: 0x1000,
    };
    let p = place(&exact, 0, 0x1000, 0xffff_ffff).expect("fits");
    assert_eq!(p.tail_len, 0);
    assert_eq!(p.bss_page, 0x31, "whole pages start right after");
    assert_eq!(p.bss_pages, 2);

    // And one byte short of the boundary has a tail of one byte less than
    // a page.
    let mut short = exact;
    short.filesize = 0xfff;
    let p = place(&short, 0, 0x1000, 0xffff_ffff).expect("fits");
    assert_eq!((p.tail_at, p.tail_len), (0x30fff, 1));
}

/// Four gigabytes of bss. It was a 32-bit difference of two 64-bit
/// addresses, so this truncated to zero and the mapping was skipped —
/// leaving a program's whole bss unmapped.
#[test]
fn a_bss_larger_than_four_gigabytes_is_not_truncated() {
    let seg = Segment {
        kind: PT_LOAD,
        flags: PH_R | PH_W,
        offset: 0,
        vaddr: 0x1_0000,
        filesize: 0x1000,
        memsize: 0x1_0000_1000,
        align: 0x1000,
    };
    let p = place(&seg, 0, 0x1000, 0xffff_ffff_ffff).expect("fits");
    assert_eq!(p.bss_pages, 0x10_0000, "four gigabytes of pages");
    assert_ne!(p.bss_pages, 0);
}

/// A bss shorter than the rest of its page: the zeroing goes to the **page
/// end**, not to the end of the bss.
///
/// This asserted the opposite until 2026-09-03 — `tail_len` was capped at
/// the bss — and the bytes it left were the file's own. Linux's `padzero`
/// clears `ELF_MIN_ALIGN - (elf_bss & (ELF_MIN_ALIGN - 1))`, which is the
/// whole rest of the page unconditionally, and that is not generosity: the
/// page is mapped, so what is in it is observable.
///
/// glibc walks straight into it. Its early allocator bumps `brk`, `brk`
/// starts at the end of the loader's image, and `_dl_new_object` reaches it
/// through a `calloc` that assumes fresh memory is zero — so the main
/// `link_map` landed on `"GCC: (GNU) 11.5.0 …"` and `dl_main` faulted.
/// **No dynamically-linked glibc program ran at all.**
#[test]
fn a_bss_is_zeroed_to_the_end_of_its_page() {
    let seg = Segment {
        kind: PT_LOAD,
        flags: PH_R | PH_W,
        offset: 0,
        vaddr: 0x40000,
        filesize: 0x800,
        memsize: 0x900,
        align: 0x1000,
    };
    let p = place(&seg, 0, 0x1000, 0xffff_ffff).expect("fits");
    assert_eq!(
        p.tail_len, 0x800,
        "to the end of the page, not to the end of the bss"
    );
    assert_eq!(p.bss_pages, 0, "and no whole pages after it");
}

/// A segment with **no** bss is left alone, which is Linux again:
/// `padzero` is called for the segment the bss belongs to and no other.
///
/// It matters because such a segment is usually read-only — a text
/// segment — so zeroing the rest of its page is an `EFAULT` rather than a
/// courtesy. The first version of the fix above dropped this condition and
/// every `execve` failed at boot with -14.
#[test]
fn a_segment_with_no_bss_has_no_tail() {
    let seg = Segment {
        kind: PT_LOAD,
        flags: PH_R | PH_X,
        offset: 0,
        vaddr: 0x40000,
        filesize: 0x800,
        memsize: 0x800,
        align: 0x1000,
    };
    let p = place(&seg, 0, 0x1000, 0xffff_ffff).expect("fits");
    assert_eq!(p.tail_len, 0, "nothing to zero, and nowhere to write it");
    assert_eq!(p.bss_pages, 0);
}

/// A `p_vaddr` near the top of the range is refused rather than aliased.
///
/// Page numbers are masked on the way into the page table, so this used to
/// map the segment over whatever was at the low page it wrapped to.
#[test]
fn a_segment_past_the_address_space_is_refused() {
    let seg = Segment {
        kind: PT_LOAD,
        flags: PH_R,
        offset: 0,
        vaddr: 0xffff_ffff_ffff_f000,
        filesize: 0x1000,
        memsize: 0x1000,
        align: 0x1000,
    };
    assert_eq!(place(&seg, 0, 0x1000, 0xffff_ffff), Err(ENOEXEC));
    // And with a bias that overflows rather than merely exceeding.
    let mut low = seg;
    low.vaddr = 0x1000;
    assert_eq!(place(&low, u64::MAX, 0x1000, 0xffff_ffff), Err(ENOEXEC));
    // A memsize that overflows past the vaddr.
    let mut huge = seg;
    huge.vaddr = 0x1000;
    huge.memsize = u64::MAX;
    assert_eq!(place(&huge, 0, 0x1000, 0xffff_ffff), Err(ENOEXEC));
}

/// A segment with no permission bits reads, rather than being a page every
/// access to faults.
#[test]
fn a_segment_with_no_flags_is_readable() {
    let seg = Segment {
        kind: PT_LOAD,
        flags: 0,
        offset: 0,
        vaddr: 0x1000,
        filesize: 0x1000,
        memsize: 0x1000,
        align: 0x1000,
    };
    let p = place(&seg, 0, 0x1000, 0xffff_ffff).expect("fits");
    assert!(p.readable && !p.writable && !p.executable);
}

/// The span a position-independent image needs a hole of: first `PT_LOAD`
/// to last, in pages, and `None` when the arithmetic leaves the space.
#[test]
fn the_span_is_from_the_first_load_to_the_last() {
    let load = |vaddr, memsize| Segment {
        kind: PT_LOAD,
        flags: PH_R,
        offset: 0,
        vaddr,
        filesize: 0,
        memsize,
        align: 0x1000,
    };
    let mut interp = load(0, 0);
    interp.kind = PT_INTERP;
    // Two loads three pages apart, the second one page long.
    let segs = [load(0x1000, 0x1000), interp, load(0x4000, 0x1000)];
    assert_eq!(span_pages(&segs, 0x1000), Some(4));
    // No loads at all: nothing to place.
    assert_eq!(span_pages(&[interp], 0x1000), None);
    assert_eq!(span_pages(&[], 0x1000), None);
    // An end that overflows is refused rather than wrapping to a small
    // hole the image does not fit in.
    assert_eq!(span_pages(&[load(0x1000, u64::MAX)], 0x1000), None);
}

/// The highest page of a 48-bit address space, which is what this tree has.
const MAX_PAGE: u64 = 0xF_FFFF_FFFF;

fn load(vaddr: u64, memsize: u64) -> Segment {
    Segment {
        kind: PT_LOAD,
        flags: 0,
        offset: 0,
        vaddr,
        filesize: 0,
        memsize,
        align: 0,
    }
}

#[test]
fn an_ordinary_segment_fits() {
    assert!(segments_fit(&[], MAX_PAGE));
    assert!(segments_fit(&[load(0x400000, 0x1000)], MAX_PAGE));
    assert!(segments_fit(&[load(0, 1)], MAX_PAGE));
}

/// The boundary, from both sides. A check written with `<` instead of `<=`
/// refuses the last legal page, and one written against the address rather
/// than the page accepts a segment that ends one byte over.
#[test]
fn the_last_page_fits_and_the_next_one_does_not() {
    let top = (MAX_PAGE + 1) << PAGE_BITS; // one past the end
    assert!(segments_fit(&[load(top - 0x1000, 0x1000)], MAX_PAGE));
    assert!(segments_fit(&[load(top - 1, 1)], MAX_PAGE));
    assert!(!segments_fit(&[load(top, 1)], MAX_PAGE));
    assert!(!segments_fit(&[load(top - 0x1000, 0x1001)], MAX_PAGE));
}

/// A zero-size segment occupies nothing, so its vaddr is not a claim about
/// anything -- and `vaddr + memsize - 1` would wrap if it were checked.
#[test]
fn a_segment_of_no_size_is_not_a_claim() {
    assert!(segments_fit(&[load(u64::MAX, 0)], MAX_PAGE));
    assert!(segments_fit(&[load(0, 0)], 0));
}

/// Only PT_LOAD is laid out in memory. The others carry addresses that mean
/// something else entirely, and refusing a file for one of those would
/// reject binaries that run everywhere.
#[test]
fn only_pt_load_is_checked() {
    let mut seg = load(u64::MAX - 0x1000, 0x1000);
    seg.kind = PT_LOAD + 1;
    assert!(segments_fit(&[seg], MAX_PAGE));
}

/// One bad segment is enough, wherever it is in the table.
#[test]
fn every_segment_has_to_fit() {
    let top = (MAX_PAGE + 1) << PAGE_BITS;
    let ok = load(0x400000, 0x1000);
    let bad = load(top, 0x1000);
    assert!(!segments_fit(&[bad, ok], MAX_PAGE));
    assert!(!segments_fit(&[ok, bad], MAX_PAGE));
    assert!(!segments_fit(&[ok, bad, ok], MAX_PAGE));
    assert!(segments_fit(&[ok, ok], MAX_PAGE));
}

/// Monotone in the bound: a set that fits a small address space fits every
/// larger one. Sweeping rather than sampling, because a comparison written
/// the wrong way round passes the cases above and fails this.
#[test]
fn fitting_is_monotone_in_the_bound() {
    for vaddr in [0u64, 0x1000, 0x400000, 1 << 32, 1 << 47] {
        for memsize in [1u64, 0x1000, 0x100000] {
            let segs = [load(vaddr, memsize)];
            let mut fitted = false;
            for shift in 0..=48 {
                let bound = (1u64 << shift) - 1;
                let fits = segments_fit(&segs, bound);
                if fitted {
                    assert!(fits, "{vaddr:#x}+{memsize:#x} stopped fitting at 2^{shift}");
                }
                fitted |= fits;
            }
        }
    }
}

/// A header that passes, to change one field of at a time.
fn good_header() -> Vec<u8> {
    let mut h = vec![0u8; EHDR_SIZE];
    h[0..4].copy_from_slice(&ELF_MAGIC);
    h[4] = ELF_CLASS64;
    h[5] = ELF_LITTLE_ENDIAN;
    h[6] = ELF_VERSION;
    h[E_TYPE..E_TYPE + 2].copy_from_slice(&ET_EXEC.to_le_bytes());
    h[E_MACHINE..E_MACHINE + 2].copy_from_slice(&EM_AARCH64.to_le_bytes());
    h[E_ENTRY..E_ENTRY + 8].copy_from_slice(&0x400000u64.to_le_bytes());
    h[E_PHOFF..E_PHOFF + 8].copy_from_slice(&64u64.to_le_bytes());
    h[E_PHENTSIZE..E_PHENTSIZE + 2].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
    h[E_PHNUM..E_PHNUM + 2].copy_from_slice(&2u16.to_le_bytes());
    h
}

/// The guest's page size, which is what the caller passes.
const PAGE: u64 = 1 << PAGE_BITS;

fn segment(kind: u32, offset: u64, vaddr: u64, filesize: u64, memsize: u64, align: u64) -> Vec<u8> {
    let mut e = vec![0u8; PHDR_SIZE];
    e[0..4].copy_from_slice(&kind.to_le_bytes());
    e[4..8].copy_from_slice(&4u32.to_le_bytes()); // PF_R
    e[8..16].copy_from_slice(&offset.to_le_bytes());
    e[16..24].copy_from_slice(&vaddr.to_le_bytes());
    e[32..40].copy_from_slice(&filesize.to_le_bytes());
    e[40..48].copy_from_slice(&memsize.to_le_bytes());
    e[48..56].copy_from_slice(&align.to_le_bytes());
    e
}

#[test]
fn a_good_header_parses() {
    let info = parse_header(&good_header()).unwrap();
    assert_eq!(info.entry, 0x400000);
    assert_eq!(info.phoff, 64);
    assert_eq!(info.phnum, 2);
    assert_eq!(info.dynamic, 0);
}

#[test]
fn a_dynamic_header_is_marked() {
    let mut h = good_header();
    h[E_TYPE..E_TYPE + 2].copy_from_slice(&ET_DYN.to_le_bytes());
    assert_eq!(parse_header(&h).unwrap().dynamic, 1);
}

#[test]
fn a_truncated_header_is_refused() {
    let h = good_header();
    for len in 0..EHDR_SIZE {
        assert_eq!(parse_header(&h[..len]), Err(ENOEXEC), "length {len}");
    }
}

#[test]
fn the_identification_bytes_are_checked() {
    for (at, value) in [(0usize, 0u8), (1, b'X'), (4, 1), (5, 2), (6, 0)] {
        let mut h = good_header();
        h[at] = value;
        assert_eq!(parse_header(&h), Err(ENOEXEC), "byte {at} = {value}");
    }
}

#[test]
fn another_machine_or_type_is_refused() {
    let mut h = good_header();
    h[E_MACHINE..E_MACHINE + 2].copy_from_slice(&62u16.to_le_bytes()); // x86-64
    assert_eq!(parse_header(&h), Err(ENOEXEC));
    let mut h = good_header();
    h[E_TYPE..E_TYPE + 2].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
    assert_eq!(parse_header(&h), Err(ENOEXEC));
}

/// The field that was never read, so a file could say anything.
#[test]
fn an_entry_size_that_is_not_the_entry_size_is_refused() {
    for bad in [0u16, 1, 32, 55, 57, 4096, 65535] {
        let mut h = good_header();
        h[E_PHENTSIZE..E_PHENTSIZE + 2].copy_from_slice(&bad.to_le_bytes());
        assert_eq!(parse_header(&h), Err(ENOEXEC), "e_phentsize {bad}");
    }
}

/// The count that was unbounded, so a file could ask for 3.6 MB.
#[test]
fn the_program_header_count_is_bounded() {
    for bad in [0u16, MAX_PHNUM + 1, 4096, 65535] {
        let mut h = good_header();
        h[E_PHNUM..E_PHNUM + 2].copy_from_slice(&bad.to_le_bytes());
        assert_eq!(parse_header(&h), Err(ENOEXEC), "e_phnum {bad}");
    }
    for ok in [1u16, 2, MAX_PHNUM] {
        let mut h = good_header();
        h[E_PHNUM..E_PHNUM + 2].copy_from_slice(&ok.to_le_bytes());
        assert!(parse_header(&h).is_ok(), "e_phnum {ok}");
    }
    // And whatever it accepts, the byte count it implies is bounded.
    assert!(phdr_bytes(MAX_PHNUM) <= 65536);
}

#[test]
fn segments_decode_in_order() {
    let mut b = segment(PT_LOAD, 0, 0x400000, 0x1000, 0x2000, 0x1000);
    b.extend_from_slice(&segment(PT_INTERP, 0x200, 0x400200, 0x20, 0x20, 1));
    let segs = parse_segments(&b, 2, PAGE).unwrap();
    assert_eq!(segs.len(), 2);
    assert_eq!(segs[0].kind, PT_LOAD);
    assert_eq!(segs[0].vaddr, 0x400000);
    assert_eq!(segs[0].memsize, 0x2000);
    assert_eq!(segs[1].kind, PT_INTERP);
    assert_eq!(segs[1].offset, 0x200);
}

#[test]
fn a_short_table_is_refused() {
    let b = segment(PT_LOAD, 0, 0x400000, 0x1000, 0x2000, 0x1000);
    assert_eq!(
        parse_segments(&b, 2, PAGE),
        Err(ENOEXEC),
        "two asked for, one given"
    );
    assert_eq!(parse_segments(&b[..PHDR_SIZE - 1], 1, PAGE), Err(ENOEXEC));
}

#[test]
fn a_load_smaller_in_memory_than_on_disk_is_refused() {
    let b = segment(PT_LOAD, 0, 0x400000, 0x2000, 0x1000, 0x1000);
    assert_eq!(parse_segments(&b, 1, PAGE), Err(ENOEXEC));
}

/// The caller goes on to compute `vaddr + memsize` and `offset + filesize`.
#[test]
fn a_range_that_wraps_is_refused() {
    let b = segment(PT_LOAD, 0, u64::MAX - 4, 0, 16, 0);
    assert_eq!(parse_segments(&b, 1, PAGE), Err(ENOEXEC), "vaddr + memsize");
    let b = segment(PT_LOAD, u64::MAX - 4, 0x400000, 16, 16, 0);
    assert_eq!(
        parse_segments(&b, 1, PAGE),
        Err(ENOEXEC),
        "offset + filesize"
    );
}

/// `p_align` is not validated, because Linux does not look at it and a
/// loader that refuses one refuses a binary a real kernel runs. A
/// differential comparison of exec_semantics found this: the container
/// executed a file with `p_align = 3` and the emulator answered ENOEXEC.
#[test]
fn an_alignment_that_is_not_a_power_of_two_is_accepted() {
    let b = segment(PT_LOAD, 0, 0x400000, 0x1000, 0x1000, 3);
    assert!(parse_segments(&b, 1, PAGE).is_ok());
    // And zero, which every ELF writer uses for "no requirement".
    let b = segment(PT_LOAD, 0, 0x400000, 0x1000, 0x1000, 0);
    assert!(parse_segments(&b, 1, PAGE).is_ok());
}

/// What does have to hold is congruence modulo the *page*: the mapping is
/// from `PAGE(vaddr)` at `offset - PGOFFSET(vaddr)`, and that subtraction
/// has to land on a page boundary.
#[test]
fn an_offset_and_address_that_disagree_modulo_the_page_are_refused() {
    // Congruent: fine, whatever p_align claims.
    let b = segment(PT_LOAD, 0x1234, 0x401234, 0x10, 0x10, 0x1000);
    assert!(parse_segments(&b, 1, PAGE).is_ok());
    let b = segment(PT_LOAD, 0x1234, 0x401234, 0x10, 0x10, 3);
    assert!(
        parse_segments(&b, 1, PAGE).is_ok(),
        "p_align is not the modulus"
    );
    // Not congruent.
    let b = segment(PT_LOAD, 0x1234, 0x401235, 0x10, 0x10, 0x1000);
    assert_eq!(parse_segments(&b, 1, PAGE), Err(ENOEXEC));
    // Congruent mod the page but not mod a larger p_align, which is how an
    // aarch64 toolchain's 64K-aligned segments look in a 4K-page file.
    // Linux maps these; requiring congruence modulo p_align refused them.
    let b = segment(PT_LOAD, 0x1000, 0x401000, 0x10, 0x10, 0x10000);
    assert!(parse_segments(&b, 1, PAGE).is_ok());
}

/// Only PT_LOAD is laid out, so a strange size elsewhere is descriptive.
#[test]
fn a_strange_non_load_segment_is_left_alone() {
    let b = segment(PT_INTERP, u64::MAX, u64::MAX, u64::MAX, 0, 3);
    assert!(parse_segments(&b, 1, PAGE).is_ok());
}

#[test]
fn an_interpreter_path_ends_at_its_terminator() {
    assert_eq!(interp_path(b"/lib/ld.so\0").unwrap(), b"/lib/ld.so");
    // Padding after the terminator is not part of the path.
    assert_eq!(interp_path(b"/lib/ld.so\0\0\0\0").unwrap(), b"/lib/ld.so");
}

/// The overread: a segment whose contents run to the end with no NUL.
#[test]
fn an_unterminated_interpreter_path_is_refused() {
    assert_eq!(interp_path(b"/lib/ld-musl-aarch64.so.1"), Err(ENOEXEC));
    assert_eq!(
        interp_path(b"/"),
        Err(ENOEXEC),
        "shorter than a path and a NUL"
    );
    assert_eq!(interp_path(b""), Err(ENOEXEC));
    assert_eq!(interp_path(b"\0\0"), Err(ENOEXEC), "an empty path");
}
