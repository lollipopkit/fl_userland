//! `mincore`, and `close_range`'s flag validation.
//!
//! `mincore` answered 0 for everything: it never looked at whether the address
//! was page-aligned, never looked at whether the range was mapped, and wrote a
//! 1 into every byte of the vector regardless. Linux answers `EINVAL` for a
//! misaligned address and `ENOMEM` when the range contains unmapped memory,
//! and "is this address mapped?" is a real use of it — allocators and JITs
//! probe with it rather than installing a SIGSEGV handler.
//!
//! `close_range` accepted any flag word. Linux rejects unknown bits, which is
//! how a caller discovers that `CLOSE_RANGE_UNSHARE` is unavailable instead of
//! believing it worked.

use guest_tests::{Harness, check, check_fails, sys};

const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

fn page() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// A mapping we own, and an address that is definitely not mapped.
fn map_one() -> (*mut libc::c_void, usize) {
    let len = page();
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    (p, len)
}

fn t_mincore(h: &mut Harness) {
    h.group("mincore");
    let (p, len) = map_one();
    if p == libc::MAP_FAILED {
        check!(h, false, "mmap for the probe");
        return;
    }
    let mut vec = [0u8; 8];

    // A page that has never been touched is **not** resident. This asserted
    // the opposite, on the reasoning that there is no swap here so mapped and
    // resident are the same thing -- and `mem_probe` measured a real arm64
    // kernel answering 0, because residency is about whether a physical page
    // has been faulted in and a fresh anonymous mapping has none.
    //
    // It passed for as long as sys_mincore wrote 1 for every mapped page,
    // which is the answer it was written from.
    let r = unsafe { libc::mincore(p, len, vec.as_mut_ptr().cast()) };
    check!(h, r == 0, "mincore on a mapped page returned {r} errno {}", sys::errno());
    check!(h, vec[0] & 1 == 0, "an untouched page is not resident, got {:#x}", vec[0]);

    // Touch it, and it is.
    unsafe { *(p as *mut u8) = 1 };
    let r = unsafe { libc::mincore(p, len, vec.as_mut_ptr().cast()) };
    check!(h, r == 0, "mincore after touching returned {r} errno {}", sys::errno());
    check!(h, vec[0] & 1 == 1, "a page that was written is resident, got {:#x}", vec[0]);

    // Misaligned: EINVAL. Checked before the mapping is looked at, as on Linux.
    check_fails!(
        h,
        unsafe { libc::mincore(p.byte_add(1), len, vec.as_mut_ptr().cast()) },
        libc::EINVAL,
        "mincore on an unaligned address"
    );

    // Unmapped: ENOMEM. This is the check the "is it mapped?" idiom rests on,
    // and answering 0 told every caller that every address is mapped.
    unsafe { libc::munmap(p, len) };
    check_fails!(
        h,
        unsafe { libc::mincore(p, len, vec.as_mut_ptr().cast()) },
        libc::ENOMEM,
        "mincore on a range that was just unmapped"
    );

    // And a range that is half mapped is also ENOMEM: Linux requires the whole
    // range, not the first page. Without this a check of only `addr` would
    // pass the one above.
    let two = page() * 2;
    let p2 = unsafe {
        libc::mmap(std::ptr::null_mut(), two, libc::PROT_READ,
                   libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    };
    if p2 != libc::MAP_FAILED {
        unsafe { libc::munmap(p2.byte_add(page()), page()) };
        check_fails!(
            h,
            unsafe { libc::mincore(p2, two, vec.as_mut_ptr().cast()) },
            libc::ENOMEM,
            "mincore over a range whose second page is gone"
        );
        unsafe { libc::munmap(p2, page()) };
    }
}

fn t_close_range(h: &mut Harness) {
    h.group("close-range");

    // An unknown flag is EINVAL, so a caller can tell an unsupported request
    // from one that was honoured.
    check_fails!(
        h,
        unsafe { libc::syscall(libc::SYS_close_range, 3u32, 3u32, 0x8000u32) },
        libc::EINVAL,
        "close_range with an unknown flag"
    );

    // CLOSE_RANGE_UNSHARE asks for the descriptor table to be split before the
    // closing. Nothing here can split one, so the request is honoured only when
    // it is already satisfied — a table this process is the sole holder of,
    // which is the usual case, since glibc's posix_spawn and Python's
    // subprocess both pass the flag from a freshly forked child.
    let r = unsafe { libc::syscall(libc::SYS_close_range, 3u32, 3u32, CLOSE_RANGE_UNSHARE) };
    check!(
        h,
        r == 0,
        "close_range(UNSHARE) on an unshared table succeeds, got {r} errno {}",
        sys::errno()
    );

    // With a thread alive the table *is* shared, and the flag is what says
    // what to do about it: split the table, then close in the copy. This
    // asserted EINVAL, because that is what the implementation did -- it
    // refused rather than splitting, and carried a TODO saying so. Measured:
    // a real arm64 kernel returns 0.
    //
    // The descriptor the other thread holds has to survive, which is the half
    // that makes the difference between splitting and ignoring the flag
    // visible at all.
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let keep = unsafe { libc::dup(0) };
    let t = std::thread::spawn(move || {
        done_tx.send(()).unwrap();
        let _ = rx.recv();
        // Still usable after the other thread's close_range: the split means
        // that close happened in a table this one no longer shares.
        unsafe { libc::fcntl(keep, libc::F_GETFD) }
    });
    done_rx.recv().unwrap();
    let r = unsafe { libc::syscall(libc::SYS_close_range, 3u32, 3u32, CLOSE_RANGE_UNSHARE) };
    check!(
        h,
        r == 0,
        "close_range(UNSHARE) with a thread sharing the table, got {r} errno {}",
        sys::errno()
    );
    tx.send(()).unwrap();
    let still_there = t.join().unwrap();
    check!(
        h,
        still_there == 0,
        "the other thread's descriptor survived the split, F_GETFD gave {still_there}"
    );
    unsafe { libc::close(keep) };

    // The flags that do work still work.
    unsafe {
        let a = libc::dup(0);
        let b = libc::dup(0);
        check!(h, a >= 0 && b >= 0, "two descriptors to close");
        let lo = a.min(b) as u32;
        let hi = a.max(b) as u32;

        let r = libc::syscall(libc::SYS_close_range, lo, hi, CLOSE_RANGE_CLOEXEC);
        check!(h, r == 0, "close_range(CLOEXEC) returned {r}");
        check!(
            h,
            libc::fcntl(a, libc::F_GETFD) & libc::FD_CLOEXEC != 0,
            "and marked them close-on-exec rather than closing them"
        );

        let r = libc::syscall(libc::SYS_close_range, lo, hi, 0);
        check!(h, r == 0, "close_range(0) returned {r}");
        check!(
            h,
            libc::fcntl(a, libc::F_GETFD) == -1 && libc::fcntl(b, libc::F_GETFD) == -1,
            "and closed them"
        );
    }
}

fn main() {
    let mut h = Harness::new();
    t_mincore(&mut h);
    t_close_range(&mut h);
    std::process::exit(h.finish());
}
