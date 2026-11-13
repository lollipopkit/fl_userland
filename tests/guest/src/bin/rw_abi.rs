//! `read`/`write`/`pread`/`pwrite`: the count is a `size_t`, and the kernel
//! sized a host buffer from it.
//!
//! `sys_pread` and `sys_pwrite` did `malloc(size + 1)` with `size` declared
//! `dword_t`. `0xFFFFFFFF + 1` wraps to 0 in 32-bit unsigned arithmetic, so the
//! allocation is empty and the read that follows it is not.

use guest_tests::{Harness, check, cpath};

fn main() {
    let mut h = Harness::new();
    let path = "/tmp/rw_abi_file";
    let payload = vec![0xC3u8; 16384];
    std::fs::write(path, &payload).expect("write the fixture");

    h.group("pread-huge-count");
    let fd = unsafe { libc::open(cpath(path).as_ptr(), libc::O_RDWR) };
    check!(h, fd >= 0, "opening the fixture");
    if fd < 0 {
        std::process::exit(h.finish());
    }
    let mut buf = vec![0u8; 16384];

    // The count that makes `size + 1` wrap. Whatever this kernel decides to do
    // with a count that large -- clamp it as Linux does, or refuse it -- it
    // must not size a buffer from it and then overrun that buffer.
    let n = unsafe {
        libc::pread(fd, buf.as_mut_ptr().cast(), 0xFFFFFFFF, 0)
    };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    // EFAULT is tolerated and is the machine, not the kernel's semantics: under
    // memory pressure Linux cannot fault the destination in and refuses. It
    // reproduced two times in sixteen with sixteen containers at once and never
    // standalone. Refusing still satisfies what this checks -- that the count
    // is not used to size a buffer that is then overrun.
    check!(h, n == 16384 || (n == -1 && (e == libc::EINVAL || e == libc::EFAULT)),
        "pread with a count of 0xFFFFFFFF reads the file or refuses: n={n} errno={e}");
    // Either way, one check -- deliberately the same *number* of checks on both
    // paths, because the sweep compares how many ran on each side and a branch
    // that checks fewer reads as a gap.
    check!(
        h,
        if n > 0 { buf[..n as usize].iter().all(|&b| b == 0xC3) } else { n == -1 },
        "and the bytes are the file's, or it refused: n={n}"
    );

    // The same shape one byte lower, which does not wrap: it must behave the
    // same way. If only the wrapping value is handled the fix is a special
    // case rather than a width.
    let n2 = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), 0xFFFFFFFE, 0) };
    let e2 = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, n2 == 16384 || (n2 == -1 && (e2 == libc::EINVAL || e2 == libc::EFAULT)),
        "pread with 0xFFFFFFFE behaves the same: n={n2} errno={e2}");

    // A count of exactly 4 GiB. This is the one that needs the *width*: as a
    // `dword_t` it is 0, so the read transfers nothing and reports EOF, which
    // a caller reads as end-of-file rather than as "ask for less". Clamping
    // alone does not catch it -- 0 is a perfectly good count to clamp.
    let n4 = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), 1usize << 32, 0) };
    let e4 = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, n4 == 16384 || (n4 == -1 && e4 == libc::EFAULT),
        "pread with a count of exactly 4GiB is not truncated to zero: n={n4} errno={e4}");

    h.group("pwrite-huge-count");
    // pwrite reads *from* guest memory into the same undersized buffer. The
    // guest side is only 16 KB, so a correct kernel answers EFAULT; the point
    // is that it does so without having overrun a host allocation first.
    let n3 = unsafe { libc::pwrite(fd, buf.as_ptr().cast(), 0xFFFFFFFF, 0) };
    let e3 = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    // Either an error or a short count -- but *not* exactly the buffer's
    // length, which is what this used to demand.
    //
    // A kernel copies until it reaches something it cannot read, and what
    // follows a 16 KB allocation is up to the allocator: Linux wrote 36864
    // bytes here, having run on into the pages after it, and the check failed
    // there while passing against this emulator. Whether the spill is 0 pages
    // or 5 is not the ABI. What is, and what this is about, is that a count
    // that does not fit in 32 bits is not silently truncated and does not
    // overrun a host allocation on the way.
    check!(h, n3 == -1 || (n3 > 0 && n3 < (1 << 24)),
        "pwrite with a count of 0xFFFFFFFF does not claim to have written 4GiB: n={n3} errno={e3}");

    h.group("count-past-the-end-of-the-buffer");
    // Nothing above 4 GiB, and no width involved: a plain write whose count
    // runs off the end of its buffer. The copy walks page by page and the page
    // after a musl allocation is the guard page musl leaves there --
    //
    //     0000effee000-0000efff3000 rw-p      <- the buffer
    //     0000efff3000-0000efff4000 ---p      <- PROT_NONE
    //
    // -- which mem_ptr handed out a pointer to, because only writes checked
    // permission. The memcpy took SIGBUS and killed the *emulator*: any guest
    // with an off-by-something in a write count took the whole process down,
    // which for an embedder is the application.
    for count in [65536usize, 1 << 20, 8 << 20] {
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), count) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        check!(h, n == -1 || (n as usize) <= count,
            "write past the end of the buffer answers instead of crashing: \
count={count} n={n} errno={e}");
    }
    // Reads too: the same walk, the other direction.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), 1 << 20) };
    check!(h, n == -1 || (n as usize) <= (1 << 20),
        "and a read past the end of the buffer: n={n}");
    // A PROT_NONE page the guest made itself, read directly through a syscall.
    let guard = unsafe {
        libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_NONE,
                   libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    };
    check!(h, guard != libc::MAP_FAILED, "a PROT_NONE page");
    if guard != libc::MAP_FAILED {
        let w = unsafe { libc::write(fd, guard.cast(), 4096) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        check!(h, w == -1 && e == libc::EFAULT,
            "writing from a PROT_NONE page is EFAULT: w={w} errno={e}");
        // And it becomes readable when the guest says so -- the flag must not
        // outlive the protection it records.
        unsafe { libc::mprotect(guard, 4096, libc::PROT_READ | libc::PROT_WRITE) };
        unsafe { *guard.cast::<u8>() = 0x77 };
        let w2 = unsafe { libc::write(fd, guard.cast(), 4096) };
        check!(h, w2 == 4096, "and readable again after mprotect: w2={w2}");
        unsafe { libc::munmap(guard, 4096) };
    }

    h.group("ordinary-io-still-works");
    // The controls. None of the above may be satisfied by an io layer that
    // refuses everything.
    //
    // The fixture is written again first, and the offset put back. The groups
    // above move the file offset and write through it, so how much of the
    // payload survives depends on how far they got -- and when one of them
    // took an unusual path this group failed on bytes it had not written
    // itself. A control that depends on the state its subject left is not a
    // control.
    std::fs::write(path, &payload).expect("rewrite the fixture");
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    let mut small = [0u8; 64];
    let k = unsafe { libc::pread(fd, small.as_mut_ptr().cast(), 64, 0) };
    check!(h, k == 64 && small.iter().all(|&b| b == 0xC3), "an ordinary pread works: k={k}");
    let out = [0x5Au8; 32];
    let w = unsafe { libc::pwrite(fd, out.as_ptr().cast(), 32, 0) };
    check!(h, w == 32, "an ordinary pwrite works: w={w}");
    let k2 = unsafe { libc::pread(fd, small.as_mut_ptr().cast(), 32, 0) };
    check!(h, k2 == 32 && small[..32].iter().all(|&b| b == 0x5A), "and lands: k={k2}");
    unsafe { libc::close(fd) };
    let _ = std::fs::remove_file(path);

    std::process::exit(h.finish());
}
