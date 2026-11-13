//! `mremap`, `mprotect` and the edges of `mmap`.
//!
//! Nothing covered `mremap` at all. It is the one call in the family that
//! rearranges an existing mapping rather than making or destroying one, so it
//! is the one that has to agree with the page table about what is already
//! there — and the cases where it does not are the ones a program hits when it
//! grows a heap over something.
//!
//! Every check names the errno Linux gives, because a program that gets
//! EINVAL where it expected ENOMEM will retry forever.

use guest_tests::{Harness, check, check_fails, sys};

const PAGE: usize = 4096;

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn anon(pages: usize) -> *mut libc::c_void {
    unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            pages * PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    }
}

fn mremap(addr: *mut libc::c_void, old: usize, new: usize, flags: i32) -> *mut libc::c_void {
    // Straight to the syscall: musl's wrapper is variadic on the new address
    // and the checks below are about what the kernel does with the arguments.
    unsafe { libc::syscall(libc::SYS_mremap, addr, old, new, flags, 0usize) as *mut libc::c_void }
}

/// The same with a destination, which is the fifth argument `MREMAP_FIXED`
/// reads and the only reason `mremap(2)` is variadic.
fn mremap_to(
    addr: *mut libc::c_void,
    old: usize,
    new: usize,
    flags: i32,
    dest: *mut libc::c_void,
) -> *mut libc::c_void {
    unsafe { libc::syscall(libc::SYS_mremap, addr, old, new, flags, dest) as *mut libc::c_void }
}

/// Is `addr` mapped, according to the process's own view of itself?
fn mapped(addr: *mut libc::c_void) -> bool {
    let a = addr as u64;
    std::fs::read_to_string("/proc/self/maps")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (range, _) = l.split_once(' ')?;
            let (s, e) = range.split_once('-')?;
            Some((u64::from_str_radix(s, 16).ok()?, u64::from_str_radix(e, 16).ok()?))
        })
        .any(|(s, e)| s <= a && a < e)
}

fn t_arguments(h: &mut Harness) {
    h.group("mremap-args");
    let p = anon(2);
    if p == libc::MAP_FAILED {
        check!(h, false, "mmap for the argument checks");
        return;
    }

    check_fails!(
        h,
        mremap(unsafe { p.byte_add(1) }, PAGE, 2 * PAGE, 0) as i64,
        libc::EINVAL,
        "an address that is not page-aligned"
    );
    check_fails!(
        h,
        mremap(p, PAGE, 2 * PAGE, 1 << 20) as i64,
        libc::EINVAL,
        "an unknown flag"
    );
    // MREMAP_FIXED is not implemented and says so; the errno is what a caller
    // sees, and EINVAL is what Linux gives for MREMAP_FIXED without
    // MREMAP_MAYMOVE anyway.
    check_fails!(
        h,
        mremap(p, PAGE, 2 * PAGE, 2) as i64,
        libc::EINVAL,
        "MREMAP_FIXED"
    );
    check_fails!(
        h,
        mremap(std::ptr::null_mut(), PAGE, 2 * PAGE, 0) as i64,
        libc::EFAULT,
        "an address that is not mapped"
    );
    check_fails!(
        h,
        mremap(p, 2 * PAGE, 0, 0) as i64,
        libc::EINVAL,
        "a new length of zero"
    );
    check!(h, mapped(p), "which left the mapping alone");
    check_fails!(
        h,
        mremap(p, 0, 2 * PAGE, 0) as i64,
        libc::EINVAL,
        "an old length of zero (duplicating a shared mapping is not implemented)"
    );

    unsafe { libc::munmap(p, 2 * PAGE) };
}

/// Both lengths round *up* to a page, which decides whether a call grows or
/// shrinks at all. Truncating instead turns "grow by one byte" into "do
/// nothing" and "shrink by one byte" into the same.
fn t_lengths_round_up(h: &mut Harness) {
    h.group("mremap-rounding");

    let p = anon(2);
    if p == libc::MAP_FAILED {
        check!(h, false, "mmap for the rounding checks");
        return;
    }
    // Two pages to two pages and one byte: three pages.
    let r = mremap(p, 2 * PAGE, 2 * PAGE + 1, 0);
    if r == p {
        check!(
            h,
            mapped(unsafe { p.byte_add(2 * PAGE) }),
            "growing by one byte past a page boundary maps another page"
        );
        unsafe { libc::munmap(p, 3 * PAGE) };
    } else {
        // Something in the way is a legitimate answer; the rounding is still
        // what decided this was a grow rather than a no-op.
        check!(
            h,
            sys::errno() == libc::ENOMEM,
            "or fails with ENOMEM when there is something in the way, got {}",
            sys::errno()
        );
        unsafe { libc::munmap(p, 2 * PAGE) };
    }

    let q = anon(3);
    if q == libc::MAP_FAILED {
        check!(h, false, "mmap for the shrink-rounding check");
        return;
    }
    // Three pages less one byte, down to one: the old length rounds up to
    // three, so pages 1 and 2 go.
    let r = mremap(q, 3 * PAGE - 1, PAGE, 0);
    check!(h, r == q, "shrinking a rounded-up length returns the address");
    check!(
        h,
        !mapped(unsafe { q.byte_add(2 * PAGE) }),
        "and the last page of the rounded-up range is gone"
    );
    unsafe { libc::munmap(q, PAGE) };
}

fn t_shrink(h: &mut Harness) {
    h.group("mremap-shrink");
    let p = anon(4);
    if p == libc::MAP_FAILED {
        check!(h, false, "mmap for the shrink checks");
        return;
    }
    unsafe { std::ptr::write_bytes(p.cast::<u8>(), 0xab, 4 * PAGE) };

    let r = mremap(p, 4 * PAGE, 2 * PAGE, 0);
    check!(h, r == p, "shrinking in place returns the same address");
    check!(
        h,
        !mapped(unsafe { p.byte_add(3 * PAGE) }),
        "the pages it gave up are unmapped"
    );
    check!(
        h,
        mapped(p) && unsafe { *p.cast::<u8>() } == 0xab,
        "and what is left still holds its contents"
    );
    unsafe { libc::munmap(p, 2 * PAGE) };
}

fn t_grow(h: &mut Harness) {
    h.group("mremap-grow");
    let p = anon(2);
    if p == libc::MAP_FAILED {
        check!(h, false, "mmap for the grow checks");
        return;
    }
    unsafe { std::ptr::write_bytes(p.cast::<u8>(), 0xcd, 2 * PAGE) };

    let r = mremap(p, 2 * PAGE, 4 * PAGE, 0);
    if r == p {
        check!(h, true, "growing in place returns the same address");
        check!(
            h,
            mapped(unsafe { p.byte_add(3 * PAGE) }),
            "and the new pages are mapped"
        );
        check!(
            h,
            unsafe { *p.cast::<u8>() } == 0xcd,
            "and the old contents survive"
        );
        // The new pages read as zero, like any fresh anonymous mapping.
        check!(
            h,
            unsafe { *p.byte_add(3 * PAGE).cast::<u8>() } == 0,
            "the new pages are zero"
        );
        unsafe { libc::munmap(p, 4 * PAGE) };
    } else {
        // Growing in place is allowed to fail when there is something in the
        // way; without MREMAP_MAYMOVE that is ENOMEM.
        check!(
            h,
            r == libc::MAP_FAILED && sys::errno() == libc::ENOMEM,
            "growing in place failed with ENOMEM, got {r:?} errno {}",
            sys::errno()
        );
        unsafe { libc::munmap(p, 2 * PAGE) };
    }
}

/// A hole in the range being grown.
///
/// This is the case that reads the flags of every page in the old range to
/// check they agree. A page that is not mapped has no flags to read, and
/// Linux answers EFAULT.
fn t_grow_over_a_hole(h: &mut Harness) {
    h.group("mremap-hole");
    let p = anon(4);
    if p == libc::MAP_FAILED {
        check!(h, false, "mmap for the hole checks");
        return;
    }
    // Punch out the middle. The first page stays, so the flags the check
    // compares against are readable and the walk reaches the hole.
    unsafe { libc::munmap(p.byte_add(PAGE), PAGE) };
    check!(
        h,
        !mapped(unsafe { p.byte_add(PAGE) }),
        "the middle page is unmapped"
    );

    check_fails!(
        h,
        mremap(p, 4 * PAGE, 8 * PAGE, 0) as i64,
        libc::EFAULT,
        "growing a range with a hole in it"
    );
    // Getting this far at all is the check: reading the flags of a page that
    // is not there is a null dereference in the emulator, not an errno.
    check!(h, true, "and the emulator is still running");

    unsafe {
        libc::munmap(p, PAGE);
        libc::munmap(p.byte_add(2 * PAGE), 2 * PAGE);
    }
}

/// A file-backed mapping cannot be grown here, and says so rather than
/// growing into something wrong.
fn t_grow_a_file_mapping(h: &mut Harness) {
    h.group("mremap-file");
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp".into());
    let path = format!("{dir}/mremap-probe");
    if std::fs::write(&path, vec![0u8; 4 * PAGE]).is_err() {
        check!(h, false, "writing {path}");
        return;
    }
    let fd = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        check!(h, false, "opening {path}");
        return;
    }
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            2 * PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            fd,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        check!(h, false, "mapping {path}");
        unsafe { libc::close(fd) };
        return;
    }
    let r = mremap(p, 2 * PAGE, 4 * PAGE, 0);
    check!(
        h,
        r == libc::MAP_FAILED,
        "growing a file mapping fails rather than silently not growing"
    );
    check!(
        h,
        mapped(p),
        "and the original mapping is still there afterwards"
    );

    unsafe {
        libc::munmap(p, 2 * PAGE);
        libc::close(fd);
        libc::unlink(cstr(&path).as_ptr());
    }
}

/// A file mapping that does not start at offset 0, grown and cut from the
/// front. Both read the file offset the page table records, which until
/// 2026-11-11 was the requested one where readers add each page's offset into
/// the host mapping -- realfs maps from a 16K boundary, so a mapping at 4096
/// grew into the file's page at 12288, and a mapping whose first page was
/// unmapped still printed offset 0 in /proc/self/maps.
fn t_file_offsets(h: &mut Harness) {
    h.group("file-offsets");
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp".into());
    let path = format!("{dir}/mmap-offsets");
    let bytes: Vec<u8> = (0..4u8).flat_map(|i| [b'a' + i; PAGE]).collect();
    if std::fs::write(&path, &bytes).is_err() {
        check!(h, false, "writing {path}");
        return;
    }
    let fd = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_RDWR) };
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    let p = unsafe { libc::mmap(std::ptr::null_mut(), PAGE, rw, libc::MAP_SHARED, fd, PAGE as i64) };
    check!(h, p != libc::MAP_FAILED, "one page at offset 4096");
    let q = mremap(p, PAGE, 2 * PAGE, libc::MREMAP_MAYMOVE);
    check!(h, q != libc::MAP_FAILED, "grown to two");
    if q != libc::MAP_FAILED {
        let (first, second) = unsafe { (*(q as *const u8), *(q as *const u8).add(PAGE)) };
        check!(h, first == b'b' && second == b'c', "the new page is the file's next: {} {}", first as char, second as char);
        unsafe { libc::munmap(q, 2 * PAGE) };
    }
    let p = unsafe { libc::mmap(std::ptr::null_mut(), 3 * PAGE, rw, libc::MAP_SHARED, fd, 0) } as *mut u8;
    unsafe { libc::munmap(p.cast(), PAGE) };
    let want = format!("{:08x}-", p as usize + PAGE);
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    let offset = maps.lines().find(|l| l.starts_with(&want)).and_then(|l| l.split_whitespace().nth(2)).unwrap_or("none").to_string();
    check!(h, offset == "00001000", "after unmapping its first page, maps says offset 4096: {offset}");
    unsafe {
        libc::munmap(p.add(PAGE).cast(), 2 * PAGE);
        libc::close(fd);
        libc::unlink(cstr(&path).as_ptr());
    }
}

/// Growing into a range that is already occupied.
fn t_grow_into_something(h: &mut Harness) {
    h.group("mremap-occupied");
    // Two adjacent mappings, made adjacent by mapping one big one and
    // splitting it, so the second really is in the way of the first.
    let p = anon(4);
    if p == libc::MAP_FAILED {
        check!(h, false, "mmap for the occupied checks");
        return;
    }
    // The first two pages are the mapping to grow; the last two are in the way.
    check_fails!(
        h,
        mremap(p, 2 * PAGE, 4 * PAGE, 0) as i64,
        libc::ENOMEM,
        "growing into pages that are already mapped"
    );
    check!(
        h,
        mapped(unsafe { p.byte_add(3 * PAGE) }),
        "and what was in the way is untouched"
    );
    unsafe { libc::munmap(p, 4 * PAGE) };
}

/// A file offset past 4 GiB.
///
/// aarch64 `mmap` takes the offset in a 64-bit register and it goes all the
/// way down to the host `mmap`. Anything in the middle that narrows it to 32
/// bits maps a different part of the file and says nothing about it — the
/// caller gets a mapping, of the wrong bytes.
///
/// The file is sparse: ftruncate to 4 GiB + 3 pages costs nothing on disk, and
/// the two markers are one page apart modulo 2^32 so a truncated offset lands
/// on the other one.
fn t_offset_past_four_gigabytes(h: &mut Harness) {
    h.group("mmap-offset");
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp".into());
    let path = format!("{dir}/mmap-bigoffset");
    unsafe { libc::unlink(cstr(&path).as_ptr()) };
    let fd = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600) };
    if fd < 0 {
        check!(h, false, "creating {path}: errno {}", sys::errno());
        return;
    }

    const FOUR_GIB: i64 = 4 * 1024 * 1024 * 1024;
    let high = FOUR_GIB + PAGE as i64; // truncates to exactly `low`
    let low = PAGE as i64;
    if unsafe { libc::ftruncate(fd, high + PAGE as i64) } != 0 {
        // A filesystem that cannot hold a sparse file this big is not what is
        // being tested; say so rather than failing.
        println!("  SKIP  [mmap-offset] ftruncate to 4GiB failed: errno {}", sys::errno());
        unsafe {
            libc::close(fd);
            libc::unlink(cstr(&path).as_ptr());
        }
        return;
    }
    let mark_low = [b'L'; 16];
    let mark_high = [b'H'; 16];
    let wrote_low = unsafe { libc::pwrite(fd, mark_low.as_ptr().cast(), 16, low) };
    let wrote_high = unsafe { libc::pwrite(fd, mark_high.as_ptr().cast(), 16, high) };
    check!(
        h,
        wrote_low == 16 && wrote_high == 16,
        "writing both markers: {wrote_low} and {wrote_high}"
    );

    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            high as libc::off_t,
        )
    };
    if p == libc::MAP_FAILED {
        check!(h, false, "mapping at 4GiB+4096: errno {}", sys::errno());
    } else {
        let got = unsafe { std::slice::from_raw_parts(p.cast::<u8>(), 16) };
        check!(
            h,
            got == mark_high,
            "the mapping holds what is at that offset, not at offset & 0xffffffff: {:?}",
            std::str::from_utf8(got).unwrap_or("<binary>")
        );
        unsafe { libc::munmap(p, PAGE) };
    }

    // An offset that is not a whole number of pages, through the raw syscall:
    // musl's mmap wrapper rejects it before the kernel ever sees it, so going
    // through the wrapper would be testing musl.
    let r = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            std::ptr::null_mut::<libc::c_void>(),
            PAGE,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            1i64,
        )
    };
    check!(
        h,
        r == -1 || (r as u64) > (1u64 << 63) - 4096,
        "an offset that is not page-aligned fails: got {r:#x}"
    );

    unsafe {
        libc::close(fd);
        libc::unlink(cstr(&path).as_ptr());
    }
}

/// Addresses above the 36-bit page number the page table can hold.
///
/// `mem_pt` masks each level's index, so a page number with bits above 36 set
/// does not fall out of the tree — it *aliases* onto a lower page. `do_mmap`
/// bounds-checks its hint; munmap, mprotect, madvise and mremap did not, so an
/// address 2^48 higher than a real one names the same page-table entry.
///
/// Linux answers EINVAL for anything outside the user address space. Silently
/// operating on a different mapping is the failure this is looking for.
/// `MREMAP_FIXED`: move a mapping to an address the caller names.
///
/// It answered `EINVAL` for every argument until 2026-09-06, and the reason was
/// that `sys_mremap` took four arguments -- so the destination never arrived.
/// Nothing here noticed, because nothing asked.
fn t_fixed(h: &mut Harness) {
    h.group("mremap-fixed");

    // One six-page region with its middle two unmapped, so the source and the
    // destination are **two pages apart with a hole between them**. Two
    // separate `mmap`s put them adjacent, and adjacent is what made the first
    // version of this check answer differently on a real kernel depending on
    // the binary's layout: adding a word to the failure message was enough to
    // turn three failures into three passes. A check whose answer moves with
    // the allocator is not a check.
    //
    // The two are filled with different bytes, so what is asserted is that the
    // destination's contents were *replaced* rather than that an address came
    // back.
    let region = anon(6);
    if region == libc::MAP_FAILED {
        check!(h, false, "mmap for the fixed-remap region");
        return;
    }
    let p = region;
    let dest = unsafe { region.byte_add(4 * PAGE) };
    unsafe { libc::munmap(region.byte_add(2 * PAGE), 2 * PAGE) };
    unsafe { std::ptr::write_bytes(dest.cast::<u8>(), 0xee, 2 * PAGE) };
    unsafe { std::ptr::write_bytes(p.cast::<u8>(), 0xcd, 2 * PAGE) };

    // FIXED without MAYMOVE is EINVAL: a fixed remap is a move by definition.
    let r = mremap_to(p, 2 * PAGE, 2 * PAGE, libc::MREMAP_FIXED, dest);
    check!(
        h,
        r == libc::MAP_FAILED && sys::errno() == libc::EINVAL,
        "MREMAP_FIXED without MREMAP_MAYMOVE is EINVAL, got {r:?} errno {}",
        sys::errno()
    );

    // An unaligned destination is EINVAL.
    let r = mremap_to(
        p,
        2 * PAGE,
        2 * PAGE,
        libc::MREMAP_FIXED | libc::MREMAP_MAYMOVE,
        unsafe { dest.byte_add(1) },
    );
    check!(
        h,
        r == libc::MAP_FAILED && sys::errno() == libc::EINVAL,
        "an unaligned destination is EINVAL, got {r:?} errno {}",
        sys::errno()
    );

    // Overlapping source and destination is EINVAL: the destination is
    // unmapped before the move, so an overlap would unmap what is moving.
    let r = mremap_to(
        p,
        2 * PAGE,
        2 * PAGE,
        libc::MREMAP_FIXED | libc::MREMAP_MAYMOVE,
        unsafe { p.byte_add(PAGE) },
    );
    check!(
        h,
        r == libc::MAP_FAILED && sys::errno() == libc::EINVAL,
        "overlapping ranges are EINVAL, got {r:?} errno {}",
        sys::errno()
    );

    // The move itself, and it is the check that carries the group: backing the
    // implementation out and answering `EINVAL` for every `MREMAP_FIXED` leaves
    // the three refusals above **passing**, because a blanket refusal satisfies
    // each of them. Only this one tells a correct rejection from a stub.
    let r = mremap_to(p, 2 * PAGE, 2 * PAGE, libc::MREMAP_FIXED | libc::MREMAP_MAYMOVE, dest);
    check!(h, r == dest, "the mapping lands where it was told, got {r:?}");
    if r == dest {
        check!(
            h,
            unsafe { *dest.cast::<u8>() } == 0xcd
                && unsafe { *dest.byte_add(2 * PAGE - 1).cast::<u8>() } == 0xcd,
            "and brings its contents, replacing what was there"
        );
        let covering = std::fs::read_to_string("/proc/self/maps")
            .unwrap_or_default()
            .lines()
            .filter(|l| {
                let Some((r, _)) = l.split_once(' ') else { return false };
                let Some((a, b)) = r.split_once('-') else { return false };
                let (a, b) = (u64::from_str_radix(a, 16).unwrap_or(0), u64::from_str_radix(b, 16).unwrap_or(0));
                a <= p as u64 && (p as u64) < b
            })
            .collect::<Vec<_>>()
            .join(" | ");
        check!(
            h,
            !mapped(p),
            "the old address is unmapped, p={p:?} dest={dest:?} covering={covering}"
        );
        unsafe { libc::munmap(dest, 2 * PAGE) };
    } else {
        unsafe { libc::munmap(p, 2 * PAGE) };
        unsafe { libc::munmap(dest, 2 * PAGE) };
    }
}

fn t_addresses_out_of_range(h: &mut Harness) {
    h.group("out-of-range");
    let p = anon(1);
    if p == libc::MAP_FAILED {
        check!(h, false, "mmap for the out-of-range checks");
        return;
    }
    unsafe { std::ptr::write_bytes(p.cast::<u8>(), 0x5a, PAGE) };

    // 2^48 higher: same low 36 page-number bits, so the same entry.
    const ALIAS: usize = 1usize << 48;
    let alias = (p as usize + ALIAS) as *mut libc::c_void;

    let r = unsafe { libc::munmap(alias, PAGE) };
    check!(
        h,
        r != 0,
        "munmap of an address outside the address space fails, got {r}"
    );
    check!(
        h,
        mapped(p) && unsafe { *p.cast::<u8>() } == 0x5a,
        "and the real mapping it aliases is untouched"
    );

    let r = unsafe { libc::mprotect(alias, PAGE, libc::PROT_READ) };
    check!(
        h,
        r != 0,
        "mprotect of an out-of-range address fails, got {r}"
    );
    // Still writable: an aliased mprotect would have made it read-only, and
    // the store below would fault.
    let kept = unsafe { *p.cast::<u8>() } == 0x5a;
    unsafe { std::ptr::write_volatile(p.cast::<u8>(), 0x5b) };
    let writable = unsafe { std::ptr::read_volatile(p.cast::<u8>()) } == 0x5b;
    check!(
        h,
        kept && writable,
        "and the mapping it aliases keeps its contents and stays writable"
    );

    let r = mremap(alias, PAGE, 2 * PAGE, 0);
    check!(
        h,
        r == libc::MAP_FAILED,
        "mremap of an out-of-range address fails, got {r:?}"
    );

    unsafe { libc::munmap(p, PAGE) };
}

/// msync(2).
///
/// It used to return 0 for everything, which is a lie a program cannot detect
/// until its data is not there. Whether the flush *happens* is not observable
/// from inside the guest — a shared file mapping is a host mmap of the host
/// file, so a read of the file sees the writes with or without the flush.
/// What is observable is the errnos, and they were all wrong.
fn t_msync(h: &mut Harness) {
    h.group("msync");
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp".into());
    let path = format!("{dir}/msync-probe");
    if std::fs::write(&path, vec![0u8; 4 * PAGE]).is_err() {
        check!(h, false, "writing {path}");
        return;
    }
    let fd = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        check!(h, false, "opening {path}");
        return;
    }
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            2 * PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        check!(h, false, "mapping {path} shared: errno {}", sys::errno());
        unsafe { libc::close(fd) };
        return;
    }

    unsafe { std::ptr::write_bytes(p.cast::<u8>(), b'M', 2 * PAGE) };
    check!(
        h,
        unsafe { libc::msync(p, 2 * PAGE, libc::MS_SYNC) } == 0,
        "msync of a shared file mapping succeeds: errno {}",
        sys::errno()
    );
    check!(
        h,
        unsafe { libc::msync(p, 2 * PAGE, libc::MS_ASYNC) } == 0,
        "MS_ASYNC succeeds too"
    );

    // And the writes are in the file.
    let mut buf = [0u8; 8];
    let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), 8, 0) };
    check!(
        h,
        n == 8 && buf == [b'M'; 8],
        "the file holds what was written through the mapping"
    );

    check_fails!(
        h,
        unsafe { libc::msync(p, 2 * PAGE, libc::MS_SYNC | libc::MS_ASYNC) } as i64,
        libc::EINVAL,
        "MS_SYNC and MS_ASYNC together"
    );
    check_fails!(
        h,
        unsafe { libc::msync(p, 2 * PAGE, 1 << 20) } as i64,
        libc::EINVAL,
        "an unknown flag"
    );
    check_fails!(
        h,
        unsafe { libc::msync(p.byte_add(1), PAGE, libc::MS_SYNC) } as i64,
        libc::EINVAL,
        "an address that is not page-aligned"
    );

    // A range that is not entirely mapped.
    let gap = anon(2);
    if gap != libc::MAP_FAILED {
        unsafe { libc::munmap(gap, 2 * PAGE) };
        check_fails!(
            h,
            unsafe { libc::msync(gap, 2 * PAGE, libc::MS_SYNC) } as i64,
            libc::ENOMEM,
            "a range that is not mapped"
        );
    }

    // A private mapping has nothing to flush, and says so by succeeding.
    let priv_map = anon(1);
    if priv_map != libc::MAP_FAILED {
        check!(
            h,
            unsafe { libc::msync(priv_map, PAGE, libc::MS_SYNC) } == 0,
            "msync of an anonymous mapping succeeds"
        );
        unsafe { libc::munmap(priv_map, PAGE) };
    }

    unsafe {
        libc::munmap(p, 2 * PAGE);
        libc::close(fd);
        libc::unlink(cstr(&path).as_ptr());
    }
}

fn main() {
    let mut h = Harness::new();
    t_arguments(&mut h);
    t_lengths_round_up(&mut h);
    t_shrink(&mut h);
    t_grow(&mut h);
    t_grow_over_a_hole(&mut h);
    t_grow_a_file_mapping(&mut h);
    t_file_offsets(&mut h);
    t_grow_into_something(&mut h);
    t_offset_past_four_gigabytes(&mut h);
    t_fixed(&mut h);
    t_addresses_out_of_range(&mut h);
    t_msync(&mut h);
    std::process::exit(h.finish());
}
