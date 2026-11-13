//! The memory syscalls' lengths are `size_t`, and this kernel declared several
//! of them 32-bit.
//!
//! `sys_mremap`, `sys_madvise`, `sys_msync`, `sys_mincore` and `sys_mlock` took
//! `dword_t len`. aarch64 passes a register; anything at or above 4 GiB is
//! truncated to its low 32 bits.
//!
//! For `mremap` that is destructive rather than merely wrong. A grow whose new
//! length truncates below the old one becomes the *shrink* branch, which
//! `pt_unmap`s the difference and reports success — so a guest asking to grow a
//! mapping loses the pages it already had.

use guest_tests::{Harness, check};

const PAGE: usize = 4096;
const FOUR_GIB: usize = 1 << 32;

/// Is `addr` readable? Asked through a syscall rather than by dereferencing:
/// an unmapped read is a fault the probe would not survive, but `write` from
/// guest memory answers `EFAULT` and returns.
fn readable(pipe_w: i32, addr: *const u8) -> bool {
    let n = unsafe { libc::write(pipe_w, addr.cast(), 8) };
    n == 8
}

fn main() {
    let mut h = Harness::new();
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    // A reader, so the 8-byte writes never fill the pipe.
    let (pr, pw) = (fds[0], fds[1]);
    std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        loop {
            if unsafe { libc::read(pr, buf.as_mut_ptr().cast(), buf.len()) } <= 0 {
                break;
            }
        }
    });

    h.group("mremap-length-is-64-bit");
    let base = unsafe {
        libc::mmap(std::ptr::null_mut(), 5 * PAGE, libc::PROT_READ | libc::PROT_WRITE,
                   libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    };
    check!(h, base != libc::MAP_FAILED, "five anonymous pages");
    if base == libc::MAP_FAILED {
        std::process::exit(h.finish());
    }
    let p = base.cast::<u8>();
    for i in 0..5 {
        unsafe { *p.add(i * PAGE) = 0xA5 };
    }
    // The control: all three pages are readable before anything is asked of
    // mremap, so a later EFAULT means mremap did it.
    for i in 0..5 {
        check!(h, readable(pw, unsafe { p.add(i * PAGE) }),
            "page {i} is readable before the mremap");
    }

    // A grow, expressed with lengths whose low 32 bits are in the *opposite*
    // order: 4 GiB + 5 pages to 8 GiB + 3 pages is a grow, and truncated to 32
    // bits it is 5 pages to 3 pages -- a shrink, which unmaps the difference.
    //
    // Both lengths truncating the same way is not enough, which is what the
    // first version of this probe did: 4 GiB + 3 pages to 4 GiB + 5 pages
    // stays a grow either way and the mapping survives whatever the width.
    let old_len = FOUR_GIB + 5 * PAGE;
    let new_len = 2 * FOUR_GIB + 3 * PAGE;
    let r = unsafe { libc::mremap(base, old_len, new_len, 0) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == libc::MAP_FAILED,
        "mremap over a range that is not mapped fails: got {r:?} errno={e}");

    // Whatever it answered, it must not have thrown away pages the caller
    // still had. This is the check that matters.
    for i in 0..5 {
        check!(h, readable(pw, unsafe { p.add(i * PAGE) }),
            "page {i} survived the mremap");
    }
    for i in 0..5 {
        let v = if readable(pw, unsafe { p.add(i * PAGE) }) {
            unsafe { *p.add(i * PAGE) }
        } else { 0 };
        check!(h, v == 0xA5, "page {i} still holds its marker: {v:#x}");
    }

    h.group("mremap-still-works");
    // The controls. The checks above must not be satisfied by an mremap that
    // refuses everything.
    // This implementation grows in place or not at all, so the grow needs a
    // hole after it: take eight pages and give the last four back.
    let eight = unsafe {
        libc::mmap(std::ptr::null_mut(), 8 * PAGE, libc::PROT_READ | libc::PROT_WRITE,
                   libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    };
    check!(h, eight != libc::MAP_FAILED, "eight anonymous pages");
    unsafe {
        libc::munmap(eight.cast::<u8>().add(4 * PAGE).cast(), 4 * PAGE);
        *eight.cast::<u8>() = 0x5A;
    }
    let grown = unsafe { libc::mremap(eight, 4 * PAGE, 6 * PAGE, 0) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    // ENOMEM here is the machine, not the kernel's semantics.
    //
    // An in-place grow has to commit two more pages, and Linux's may_expand_vm
    // refuses when it cannot -- so under memory pressure this fails on a real
    // kernel while saying nothing about whether mremap works. It reproduced two
    // times in six with six containers running at once, and never once
    // standalone, which is why it looked like a flake for two sweeps before
    // anyone caught the errno.
    //
    // Tolerated, not skipped: the group is a *control* -- the checks above it
    // must not be satisfied by an mremap that refuses everything -- so when the
    // grow cannot be committed the control moves to the shrink, which needs no
    // new memory and must still work.
    let out_of_memory = grown == libc::MAP_FAILED && e == libc::ENOMEM;
    check!(
        h,
        grown != libc::MAP_FAILED || out_of_memory,
        "an ordinary grow into a hole still works: errno={e}"
    );
    // Whichever way it went, the mapping is live and the same three things are
    // checked -- deliberately the same *number* of things, because the sweep
    // compares how many checks ran on each side and a branch that checks fewer
    // reads as a gap.
    let (live, len) = if grown != libc::MAP_FAILED {
        (grown, 6 * PAGE)
    } else {
        (eight, 4 * PAGE)
    };
    check!(h, unsafe { *live.cast::<u8>() } == 0x5A, "and keeps its contents");
    // A shrink frees memory rather than asking for it, so it cannot fail for
    // the reason the grow just did.
    let shrunk = unsafe { libc::mremap(live, len, 1 * PAGE, 0) };
    let se = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, shrunk != libc::MAP_FAILED, "an ordinary shrink still works: errno={se}");

    h.group("madvise-length-is-64-bit");
    // A length above 4 GiB over a small mapping must be refused rather than
    // silently applied to a truncated prefix: 4 GiB + 2 pages truncated to 32
    // bits is 2 pages, which is exactly this mapping and would succeed.
    //
    // **The advice is MADV_NORMAL and that is not a detail.** Linux's
    // `madvise_walk_vmas` records ENOMEM when it meets a gap and *keeps going*
    // -- it applies the advice to every VMA in the range and returns the error
    // at the end. So this call reaches four gigabytes of other people's
    // mappings, and with MADV_DONTNEED it discarded the heap and the thread
    // stacks: the process printed all 23 checks and then took SIGSEGV inside
    // exit(), in four runs out of twelve on a real kernel. It looked like a
    // container flake in the differential sweep three times before anyone ran
    // it in a loop.
    //
    // MADV_NORMAL discriminates just as well -- a truncated length is two
    // mapped pages and succeeds, an untruncated one meets unmapped space and
    // answers ENOMEM -- and all it does to what it reaches is set the
    // read-ahead behaviour it already had.
    let m = unsafe {
        libc::mmap(std::ptr::null_mut(), 2 * PAGE, libc::PROT_READ | libc::PROT_WRITE,
                   libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    };
    unsafe { *m.cast::<u8>() = 0x3C };
    let r = unsafe { libc::madvise(m, FOUR_GIB + 2 * PAGE, libc::MADV_NORMAL) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r != 0, "madvise over an unmapped range is refused: r={r} errno={e}");
    // And a real one still works.
    let r2 = unsafe { libc::madvise(m, 2 * PAGE, libc::MADV_DONTNEED) };
    check!(h, r2 == 0, "control: an ordinary madvise still works: r={r2}");

    std::process::exit(h.finish());
}
