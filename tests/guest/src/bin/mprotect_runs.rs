//! `mprotect` over a range whose pages are not all in the same state.
//!
//! The emulator applies a guest `mprotect` to the host mapping underneath, and
//! it used to do that **one host call per 4 KB guest page**. Coalescing runs of
//! host-contiguous pages into one call took V8's 128 MB heap cage from 10.4 ms
//! to 55 µs. This is the correctness half of that change.
//!
//! Two things a run must not do, and they pull in opposite directions:
//!
//! - it must **cover** every page whose protection is being raised, or a write
//!   to a page in the middle of a large range faults;
//! - it must **not sweep in** a page that needs nothing. The host protection is
//!   `PROT_READ` plus `PROT_WRITE` only when the new flags have write, so
//!   applying it to a page that already had write would take it away.
//!
//! The second is why the runs are built from raising pages only, and why the
//! mixed-state cases below exist. A range where every page is in the same state
//! is one long run and proves neither.
//!
//! Everything here is ordinary POSIX and is compared against a real kernel.

use guest_tests::{Harness, check, sys};

const PAGE: usize = 4096;

fn map(pages: usize) -> *mut libc::c_void {
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

/// Write a byte at page `i` in a forked child, so a fault is a signal the
/// parent sees rather than the end of the test. True if the write went through.
fn writable(base: *mut libc::c_void, i: usize) -> bool {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            let p = (base as *mut u8).add(i * PAGE);
            std::ptr::write_volatile(p, 0x5A);
            libc::_exit(0);
        }
    }
    let mut st = 0i32;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
}

/// The same for a read.
fn readable(base: *mut libc::c_void, i: usize) -> bool {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            let p = (base as *const u8).add(i * PAGE);
            let v = std::ptr::read_volatile(p);
            libc::_exit(if v == v { 0 } else { 1 });
        }
    }
    let mut st = 0i32;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
}

fn main() {
    let mut h = Harness::new();
    const N: usize = 64;

    h.group("raising-a-whole-range");
    let m = map(N);
    check!(h, m != libc::MAP_FAILED, "mapped {N} pages");
    if m == libc::MAP_FAILED {
        std::process::exit(h.finish());
    }
    unsafe { libc::memset(m, 1, N * PAGE) };
    check!(h, unsafe { libc::mprotect(m, N * PAGE, libc::PROT_READ) } == 0, "lower the lot");
    check!(h, !writable(m, 0), "the first page is read-only");
    check!(h, !writable(m, N / 2), "and so is one in the middle");
    check!(h, !writable(m, N - 1), "and the last");
    check!(
        h,
        unsafe { libc::mprotect(m, N * PAGE, libc::PROT_READ | libc::PROT_WRITE) } == 0,
        "raise the lot"
    );
    // The one a run that stopped short would fail: the middle and the end, not
    // just the page the range starts at.
    for i in [0usize, 1, N / 2, N - 2, N - 1] {
        check!(h, writable(m, i), "page {i} of {N} is writable again");
    }

    h.group("a-range-whose-pages-are-not-all-the-same");
    // Raise only the odd pages first, then raise the whole range. Every other
    // page then needs nothing, so a naive "one run for the whole range" would
    // be built out of pages that must not be in it -- and a run that breaks at
    // every gap has to still cover the pages between the gaps.
    check!(h, unsafe { libc::mprotect(m, N * PAGE, libc::PROT_READ) } == 0, "lower the lot again");
    for i in (1..N).step_by(2) {
        let p = unsafe { (m as *mut u8).add(i * PAGE) as *mut libc::c_void };
        check!(
            h,
            unsafe { libc::mprotect(p, PAGE, libc::PROT_READ | libc::PROT_WRITE) } == 0,
            "raise page {i} on its own"
        );
    }
    check!(h, writable(m, 1), "an odd page is writable");
    check!(h, !writable(m, 2), "an even page is not");
    check!(
        h,
        unsafe { libc::mprotect(m, N * PAGE, libc::PROT_READ | libc::PROT_WRITE) } == 0,
        "now raise the whole range over the top"
    );
    for i in [0usize, 1, 2, 3, N / 2, N / 2 + 1, N - 1] {
        check!(h, writable(m, i), "page {i} is writable after the whole-range raise");
    }

    h.group("lowering-does-not-leak-across-the-gaps");
    // The other direction over a mixed range: every page ends read-only,
    // including the ones that were already read-only and the ones that were
    // not. A run built from the wrong set shows up here as a page that kept
    // its write permission.
    check!(h, unsafe { libc::mprotect(m, N * PAGE, libc::PROT_READ) } == 0, "lower over the top");
    for i in [0usize, 1, 2, N / 2, N - 1] {
        check!(h, !writable(m, i), "page {i} is read-only");
        check!(h, readable(m, i), "and still readable");
    }

    h.group("prot-none-in-the-middle");
    // A page that loses read as well. It ends the run on both sides, and the
    // pages either side of it must still be raised.
    check!(
        h,
        unsafe { libc::mprotect(m, N * PAGE, libc::PROT_READ | libc::PROT_WRITE) } == 0,
        "raise the lot"
    );
    let mid = unsafe { (m as *mut u8).add((N / 2) * PAGE) as *mut libc::c_void };
    check!(h, unsafe { libc::mprotect(mid, PAGE, libc::PROT_NONE) } == 0, "one page to PROT_NONE");
    check!(h, !readable(m, N / 2), "which is not readable");
    check!(h, readable(m, N / 2 - 1), "the page before it is");
    check!(h, writable(m, N / 2 + 1), "the page after it is writable");
    check!(
        h,
        unsafe { libc::mprotect(mid, PAGE, libc::PROT_READ | libc::PROT_WRITE) } == 0,
        "and it comes back"
    );
    check!(h, writable(m, N / 2), "writable again");

    h.group("two-mappings-under-one-call");
    // Adjacent in the guest's address space and separate host allocations, so
    // the run has to break in the middle even though the guest pages are
    // consecutive. Built by mapping a block and replacing its second half.
    unsafe { libc::munmap(m, N * PAGE) };
    let a = map(N);
    check!(h, a != libc::MAP_FAILED, "a block of {N} pages");
    if a != libc::MAP_FAILED {
        let half = unsafe { (a as *mut u8).add((N / 2) * PAGE) as *mut libc::c_void };
        let b = unsafe {
            libc::mmap(
                half,
                (N / 2) * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        check!(h, b == half, "second half replaced in place: {b:?} vs {half:?}");
        unsafe { libc::memset(a, 2, N * PAGE) };
        check!(h, unsafe { libc::mprotect(a, N * PAGE, libc::PROT_READ) } == 0, "lower both");
        check!(
            h,
            unsafe { libc::mprotect(a, N * PAGE, libc::PROT_READ | libc::PROT_WRITE) } == 0,
            "raise both in one call"
        );
        for i in [0usize, N / 2 - 1, N / 2, N / 2 + 1, N - 1] {
            check!(h, writable(a, i), "page {i} spans the join and is writable");
        }
        unsafe { libc::munmap(a, N * PAGE) };
    }

    h.group("the-refusals-are-unchanged");
    let m = map(4);
    if m != libc::MAP_FAILED {
        // Through the raw syscall, not libc: musl's mprotect wrapper rounds the
        // address down and the length up before it makes the call, so
        // `libc::mprotect` can never hand the kernel an unaligned one. The
        // first version of this check asserted EINVAL, and a real kernel
        // answered 0 -- because it was measuring musl.
        sys::clear_errno();
        let r = unsafe {
            libc::syscall(libc::SYS_mprotect, (m as usize + 1) as u64, PAGE as u64,
                          libc::PROT_READ)
        };
        check!(
            h,
            r == -1 && sys::errno() == libc::EINVAL,
            "an unaligned address is EINVAL: r={r} errno={}",
            sys::errno()
        );
        // And the aligned one right beside it is not, so that is about the
        // alignment and not about the range.
        sys::clear_errno();
        let r = unsafe {
            libc::syscall(libc::SYS_mprotect, m as u64, PAGE as u64, libc::PROT_READ)
        };
        check!(h, r == 0, "the aligned address is accepted: r={r} errno={}", sys::errno());
        unsafe { libc::munmap(m, 4 * PAGE) };
    }
    // A range with nothing mapped in it.
    sys::clear_errno();
    let r = unsafe {
        libc::mprotect(0x7000_0000_0000usize as *mut libc::c_void, PAGE, libc::PROT_READ)
    };
    check!(h, r == -1, "an unmapped range is refused: r={r} errno={}", sys::errno());

    std::process::exit(h.finish());
}
