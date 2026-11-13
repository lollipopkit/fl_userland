//! Vectored and bulk file I/O: readv, writev, the positional forms, sendfile,
//! copy_file_range and fallocate.
//!
//! These are the data paths. A bug in the argument handling of a normal read
//! shows up as an error; a bug in these shows up as a file with the wrong
//! bytes in it, which nothing reports.
//!
//! Nothing covered any of them. `sock_net` exercises `sendmsg` across iovecs,
//! which is a different implementation.

use guest_tests::{Harness, check, check_fails, sys};

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn make(path: &str, body: &[u8]) -> i32 {
    let _ = std::fs::remove_file(path);
    let fd = unsafe {
        libc::open(cstr(path).as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o644)
    };
    if fd >= 0 && !body.is_empty() {
        sys::write(fd, body);
        unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    }
    fd
}

fn read_all(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

fn iov(b: &[u8]) -> libc::iovec {
    libc::iovec { iov_base: b.as_ptr() as *mut _, iov_len: b.len() }
}

fn iov_mut(b: &mut [u8]) -> libc::iovec {
    libc::iovec { iov_base: b.as_mut_ptr().cast(), iov_len: b.len() }
}

fn t_vectored(h: &mut Harness, dir: &str) {
    h.group("readv-writev");
    let path = format!("{dir}/vec");
    let fd = make(&path, b"");
    if fd < 0 {
        check!(h, false, "creating {path}");
        return;
    }

    // Three pieces go out as one stream, in order.
    let (a, b, c) = (b"one".as_slice(), b"two".as_slice(), b"three".as_slice());
    let vecs = [iov(a), iov(b), iov(c)];
    let n = unsafe { libc::writev(fd, vecs.as_ptr(), 3) };
    check!(h, n == 11, "writev of three pieces wrote them all: {n}");
    check!(
        h,
        read_all(&path) == b"onetwothree",
        "and in order: {:?}",
        String::from_utf8_lossy(&read_all(&path))
    );

    // And come back split at the reader's boundaries, not the writer's.
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    let (mut p, mut q) = ([0u8; 4], [0u8; 7]);
    let mut rvecs = [iov_mut(&mut p), iov_mut(&mut q)];
    let n = unsafe { libc::readv(fd, rvecs.as_mut_ptr(), 2) };
    check!(
        h,
        n == 11 && &p == b"onet" && &q == b"wothree",
        "readv fills its vectors in order: n={n} {:?} {:?}",
        std::str::from_utf8(&p),
        std::str::from_utf8(&q)
    );

    // An empty vector list is legal and moves nothing.
    let n = unsafe { libc::writev(fd, std::ptr::null(), 0) };
    check!(h, n == 0, "writev of nothing returns 0, got {n}");

    // A zero-length piece in the middle is skipped, not an error.
    unsafe { libc::ftruncate(fd, 0) };
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    let empty: &[u8] = b"";
    let vecs = [iov(a), iov(empty), iov(c)];
    let n = unsafe { libc::writev(fd, vecs.as_ptr(), 3) };
    check!(
        h,
        n == 8 && read_all(&path) == b"onethree",
        "a zero-length vector is skipped: n={n}"
    );

    check_fails!(
        h,
        unsafe { libc::writev(fd, vecs.as_ptr(), -1) },
        libc::EINVAL,
        "a negative vector count"
    );
    sys::close(fd);
}

/// A short readv must not touch the bytes past what it returned.
///
/// The emulator reads into one scratch buffer and then scatters it out. If it
/// scatters the vectors' full lengths rather than the length it actually read,
/// everything past the return value is whatever was in that buffer — which
/// came from `malloc` and belongs to the emulator, not the guest.
fn t_short_readv(h: &mut Harness) {
    h.group("short-readv");
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        check!(h, false, "pipe");
        return;
    }
    let (r, w) = (fds[0], fds[1]);
    sys::write(w, b"abc");

    // Three vectors, 64 bytes each, pre-filled with a pattern the guest owns.
    let mut a = [0x5Au8; 64];
    let mut b = [0x5Au8; 64];
    let mut c = [0x5Au8; 64];
    let mut vecs = [iov_mut(&mut a), iov_mut(&mut b), iov_mut(&mut c)];
    let n = unsafe { libc::readv(r, vecs.as_mut_ptr(), 3) };
    check!(h, n == 3, "a short readv returns what it read: {n}");
    check!(h, &a[..3] == b"abc", "into the front of the first vector");
    check!(
        h,
        a[3..].iter().all(|&x| x == 0x5A),
        "and leaves the rest of that vector alone: {:02x?}",
        &a[3..12]
    );
    check!(
        h,
        b.iter().all(|&x| x == 0x5A) && c.iter().all(|&x| x == 0x5A),
        "and does not touch the vectors it never reached: {:02x?} {:02x?}",
        &b[..8],
        &c[..8]
    );
    sys::close(r);
    sys::close(w);
}

/// Positional I/O on descriptors that have no position.
///
/// An eventfd, a socket, a signalfd, a timerfd and an inotify descriptor all
/// implement `read` and neither `pread` nor `lseek`. The emulator's pread fell
/// back to seeking without checking that seeking was possible, so
/// `pread(eventfd(0, 0), buf, 8, 0)` called through a null function pointer and
/// took the whole emulator down -- every other guest process with it -- from an
/// unprivileged program. The answer is ESPIPE.
fn t_no_position(h: &mut Harness) {
    h.group("espipe");
    let mut buf = [0u8; 8];

    let e = unsafe { libc::eventfd(0, 0) };
    check!(h, e >= 0, "eventfd");
    if e >= 0 {
        check_fails!(
            h,
            unsafe { libc::pread(e, buf.as_mut_ptr().cast(), 8, 0) } as i64,
            libc::ESPIPE,
            "pread on an eventfd"
        );
        check_fails!(
            h,
            unsafe { libc::pwrite(e, buf.as_ptr().cast(), 8, 0) } as i64,
            libc::ESPIPE,
            "pwrite on an eventfd"
        );
        sys::close(e);
    }

    let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    check!(h, s >= 0, "socket");
    if s >= 0 {
        check_fails!(
            h,
            unsafe { libc::pread(s, buf.as_mut_ptr().cast(), 8, 0) } as i64,
            libc::ESPIPE,
            "pread on a socket"
        );
        sys::close(s);
    }

    // And the vectored forms take the same path.
    let e = unsafe { libc::eventfd(0, 0) };
    if e >= 0 {
        let mut v = [iov_mut(&mut buf)];
        check_fails!(
            h,
            unsafe { libc::preadv(e, v.as_mut_ptr(), 1, 0) } as i64,
            libc::ESPIPE,
            "preadv on an eventfd"
        );
        sys::close(e);
    }
}

fn t_positional(h: &mut Harness, dir: &str) {
    h.group("positional");
    let path = format!("{dir}/pos");
    let fd = make(&path, b"0123456789");
    if fd < 0 {
        check!(h, false, "creating {path}");
        return;
    }

    // pread does not move the file offset.
    unsafe { libc::lseek(fd, 3, libc::SEEK_SET) };
    let mut buf = [0u8; 4];
    let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), 4, 6) };
    check!(h, n == 4 && &buf == b"6789", "pread reads from its offset: {n}");
    check!(
        h,
        unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) } == 3,
        "and leaves the file offset alone"
    );

    // pwrite likewise.
    let n = unsafe { libc::pwrite(fd, b"AB".as_ptr().cast(), 2, 0) };
    check!(h, n == 2, "pwrite wrote {n}");
    check!(
        h,
        unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) } == 3,
        "and left the offset alone too"
    );
    check!(h, read_all(&path) == b"AB23456789", "at the right place");

    // The vectored forms.
    let (x, y) = (b"XY".as_slice(), b"Z".as_slice());
    let vecs = [iov(x), iov(y)];
    let n = unsafe { libc::pwritev(fd, vecs.as_ptr(), 2, 4) };
    check!(h, n == 3, "pwritev wrote {n}");
    check!(h, read_all(&path) == b"AB23XYZ789", "at its offset");
    check!(
        h,
        unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) } == 3,
        "and still left the offset alone"
    );

    let (mut u, mut v) = ([0u8; 2], [0u8; 3]);
    let mut rvecs = [iov_mut(&mut u), iov_mut(&mut v)];
    let n = unsafe { libc::preadv(fd, rvecs.as_mut_ptr(), 2, 4) };
    check!(
        h,
        n == 5 && &u == b"XY" && &v == b"Z78",
        "preadv reads from its offset into its vectors: n={n}"
    );

    check_fails!(
        h,
        unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), 4, -1) },
        libc::EINVAL,
        "a negative offset"
    );
    sys::close(fd);
}

fn t_sendfile(h: &mut Harness, dir: &str) {
    h.group("sendfile");
    let src_path = format!("{dir}/sf-src");
    let dst_path = format!("{dir}/sf-dst");
    let src = make(&src_path, b"abcdefghij");
    let dst = make(&dst_path, b"");
    if src < 0 || dst < 0 {
        check!(h, false, "creating the sendfile files");
        return;
    }

    // With no offset argument, sendfile reads from and advances the input's
    // own file offset.
    unsafe { libc::lseek(src, 2, libc::SEEK_SET) };
    let n = unsafe { libc::sendfile(dst, src, std::ptr::null_mut(), 4) };
    if n < 0 && sys::errno() == libc::ENOSYS {
        println!("  SKIP  [sendfile] not implemented");
        sys::close(src);
        sys::close(dst);
        return;
    }
    check!(h, n == 4, "sendfile moved four bytes: {n} errno {}", sys::errno());
    check!(h, read_all(&dst_path) == b"cdef", "the right four");
    check!(
        h,
        unsafe { libc::lseek(src, 0, libc::SEEK_CUR) } == 6,
        "and advanced the input offset"
    );

    // With an offset argument, it reads from there and leaves the input's own
    // offset alone, updating the argument instead.
    unsafe { libc::ftruncate(dst, 0) };
    unsafe { libc::lseek(dst, 0, libc::SEEK_SET) };
    let mut off: libc::off_t = 0;
    let n = unsafe { libc::sendfile(dst, src, &mut off, 3) };
    check!(h, n == 3, "sendfile with an offset moved three: {n}");
    check!(h, read_all(&dst_path) == b"abc", "from the start");
    check!(h, off == 3, "and advanced the offset argument, got {off}");
    check!(
        h,
        unsafe { libc::lseek(src, 0, libc::SEEK_CUR) } == 6,
        "leaving the input's own offset where it was"
    );

    // Reading past the end gives what there is.
    let mut off: libc::off_t = 8;
    let n = unsafe { libc::sendfile(dst, src, &mut off, 100) };
    check!(h, n == 2, "a count past the end copies what is there: {n}");

    sys::close(src);
    sys::close(dst);
}

fn t_copy_file_range(h: &mut Harness, dir: &str) {
    h.group("copy_file_range");
    let src_path = format!("{dir}/cfr-src");
    let dst_path = format!("{dir}/cfr-dst");
    let src = make(&src_path, b"0123456789");
    let dst = make(&dst_path, b"");
    if src < 0 || dst < 0 {
        check!(h, false, "creating the files");
        return;
    }
    let mut soff: libc::off64_t = 3;
    let mut doff: libc::off64_t = 0;
    let n = unsafe {
        libc::syscall(
            libc::SYS_copy_file_range,
            src,
            &mut soff,
            dst,
            &mut doff,
            4usize,
            0u32,
        )
    };
    if n < 0 && (sys::errno() == libc::ENOSYS || sys::errno() == libc::EXDEV) {
        println!("  SKIP  [copy_file_range] not implemented: errno {}", sys::errno());
    } else {
        check!(h, n == 4, "copy_file_range moved four bytes: {n} errno {}", sys::errno());
        check!(h, read_all(&dst_path) == b"3456", "the right four");
        check!(h, soff == 7 && doff == 4, "and advanced both offsets: {soff} {doff}");
        check!(
            h,
            unsafe { libc::lseek(src, 0, libc::SEEK_CUR) } == 0,
            "without moving the descriptors' own offsets"
        );

        // `len` is a `size_t` and this kernel's transfer loop counts in 32
        // bits, so a length of exactly 2^32 used to arrive as zero and this
        // reported that it had copied nothing. A caller reads a zero as end of
        // input and stops -- `cp` does -- so the whole copy silently produced
        // an empty file. Measured against a real arm64 kernel: ten bytes there
        // for a ten-byte source, nothing here.
        //
        // The second is the pair that says it is a *truncation* and not some
        // other limit: 2^32+4 behaved exactly as 4.
        let big_path = format!("{dir}/cfr-big");
        for (len, what) in [(1u64 << 32, "2^32"), ((1u64 << 32) | 4, "2^32+4")] {
            let big = make(&big_path, b"");
            if big < 0 {
                check!(h, false, "creating {big_path}");
                break;
            }
            let mut s: libc::off64_t = 0;
            let mut d: libc::off64_t = 0;
            let n = unsafe {
                libc::syscall(
                    libc::SYS_copy_file_range,
                    src,
                    &mut s,
                    big,
                    &mut d,
                    len as usize,
                    0u32,
                )
            };
            check!(
                h,
                n == 10,
                "a length of {what} copies the whole ten-byte file rather than \
                 its low 32 bits: {n} errno {}",
                sys::errno()
            );
            sys::close(big);
        }
    }
    sys::close(src);
    sys::close(dst);
}

fn t_size_changes(h: &mut Harness, dir: &str) {
    h.group("size");
    let path = format!("{dir}/size");
    let fd = make(&path, b"abcdefgh");
    if fd < 0 {
        check!(h, false, "creating {path}");
        return;
    }

    // Shrinking discards, extending zero-fills.
    check!(h, unsafe { libc::ftruncate(fd, 3) } == 0, "ftruncate down");
    check!(h, read_all(&path) == b"abc", "keeps the front");
    check!(h, unsafe { libc::ftruncate(fd, 6) } == 0, "ftruncate up");
    check!(
        h,
        read_all(&path) == b"abc\0\0\0",
        "and the new bytes are zero: {:?}",
        read_all(&path)
    );

    check_fails!(
        h,
        unsafe { libc::ftruncate(fd, -1) } as i64,
        libc::EINVAL,
        "a negative length"
    );

    // fallocate with mode 0 makes the file at least that big.
    let r = unsafe { libc::fallocate(fd, 0, 0, 100) };
    if r < 0 && (sys::errno() == libc::ENOSYS || sys::errno() == libc::EOPNOTSUPP) {
        println!("  SKIP  [size] fallocate not implemented: errno {}", sys::errno());
    } else {
        check!(h, r == 0, "fallocate returned {r}");
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        unsafe { libc::fstat(fd, &mut st) };
        check!(h, st.st_size >= 100, "and the file is at least 100 bytes: {}", st.st_size);
        check!(
            h,
            read_all(&path)[..3] == *b"abc",
            "with the contents intact"
        );
    }

    // Writing past the end leaves a hole that reads as zero.
    unsafe { libc::ftruncate(fd, 0) };
    let n = unsafe { libc::pwrite(fd, b"Z".as_ptr().cast(), 1, 20) };
    check!(h, n == 1, "writing past the end: {n}");
    let body = read_all(&path);
    check!(
        h,
        body.len() == 21 && body[..20].iter().all(|&b| b == 0) && body[20] == b'Z',
        "the gap reads as zeroes: len={} ",
        body.len()
    );
    sys::close(fd);
}

/// `fallocate`'s modes, which do different things to the same range.
///
/// The mode argument used to be ignored outright, so every one of these
/// behaved like plain allocation: `FALLOC_FL_PUNCH_HOLE`, which zeroes a range
/// and keeps the size, instead *extended* the file. A database or a log
/// rotator punching a hole got a bigger file with its data intact where it had
/// asked for zeroes.
fn t_fallocate_modes(h: &mut Harness, dir: &str) {
    h.group("fallocate");
    const KEEP_SIZE: i32 = 0x01;
    const PUNCH_HOLE: i32 = 0x02;
    const ZERO_RANGE: i32 = 0x10;

    let path = format!("{dir}/falloc");
    let fd = make(&path, b"0123456789abcdef");
    if fd < 0 {
        check!(h, false, "creating {path}");
        return;
    }

    // KEEP_SIZE must not change the size.
    let r = unsafe { libc::fallocate(fd, KEEP_SIZE, 0, 4096) };
    if r < 0 && (sys::errno() == libc::ENOSYS || sys::errno() == libc::EOPNOTSUPP) {
        println!("  SKIP  [fallocate] modes not implemented: errno {}", sys::errno());
        sys::close(fd);
        return;
    }
    check!(h, r == 0, "fallocate with FALLOC_FL_KEEP_SIZE: {r} errno {}", sys::errno());
    check!(
        h,
        read_all(&path).len() == 16,
        "leaves the size alone, got {}",
        read_all(&path).len()
    );

    // PUNCH_HOLE zeroes a range and keeps the size.
    let r = unsafe { libc::fallocate(fd, PUNCH_HOLE | KEEP_SIZE, 4, 6) };
    check!(h, r == 0, "punching a hole: {r} errno {}", sys::errno());
    let body = read_all(&path);
    check!(h, body.len() == 16, "the size is unchanged, got {}", body.len());
    check!(
        h,
        &body[..4] == b"0123" && body[4..10].iter().all(|&b| b == 0) && &body[10..] == b"abcdef",
        "and the range reads as zeroes: {:?}",
        String::from_utf8_lossy(&body)
    );

    // EOPNOTSUPP, not EINVAL. vfs_fallocate rejects the combination before it
    // reaches a filesystem and uses that errno; this asserted EINVAL, which
    // the man page's silence made look like the obvious guess, and a real
    // kernel disagreed (tests/integration/differential.sh).
    check_fails!(
        h,
        unsafe { libc::fallocate(fd, PUNCH_HOLE, 0, 4) },
        libc::EOPNOTSUPP,
        "PUNCH_HOLE without KEEP_SIZE"
    );

    // ZERO_RANGE zeroes, and may extend.
    let r = unsafe { libc::fallocate(fd, ZERO_RANGE, 12, 8) };
    check!(h, r == 0, "zeroing a range: {r} errno {}", sys::errno());
    let body = read_all(&path);
    check!(
        h,
        body.len() == 20 && body[12..20].iter().all(|&b| b == 0),
        "which extends and zeroes: len {} {:?}",
        body.len(),
        &body[10..]
    );

    // A negative length is EINVAL.
    check_fails!(
        h,
        unsafe { libc::fallocate(fd, 0, 0, -1) },
        libc::EINVAL,
        "a negative length"
    );
    check_fails!(
        h,
        unsafe { libc::fallocate(fd, 0, -1, 4) },
        libc::EINVAL,
        "a negative offset"
    );
    // A mode this does not implement is refused rather than silently treated
    // as plain allocation.
    let r = unsafe { libc::fallocate(fd, 0x08 /* COLLAPSE_RANGE */, 0, 8) };
    check!(
        h,
        r < 0 && (sys::errno() == libc::EOPNOTSUPP || sys::errno() == libc::EINVAL),
        "FALLOC_FL_COLLAPSE_RANGE is refused clearly: {r} errno {}",
        sys::errno()
    );
    sys::close(fd);
}

/// A buffer size a caller names but cannot have.
///
/// `readlinkat` built a stack array of exactly the size the guest asked for,
/// so `readlinkat(fd, path, buf, 3000000000)` took the emulator down. A link's
/// target is a path, so nothing longer than MAX_PATH can ever be produced.
fn t_absurd_readlink_size(h: &mut Harness, dir: &str) {
    h.group("absurd-size");
    let target = format!("{dir}/rl-target");
    let link = format!("{dir}/rl-link");
    let _ = std::fs::write(&target, b"t");
    let _ = std::fs::remove_file(&link);
    unsafe { libc::symlink(cstr(&target).as_ptr(), cstr(&link).as_ptr()) };

    // A real buffer, with only the *declared* size absurd. The first version
    // of this passed a one-byte buffer and claimed three gigabytes, so the
    // answer -- correctly the whole target -- ran over the test's own stack
    // and killed it. The emulator was doing what it was told.
    //
    // The second version expected it to answer with the target's length, on
    // the reasoning that a large request is harmless. Linux's bufsiz is an
    // `int` and it answers EINVAL for anything not positive, so three billion
    // is not a large request there -- it is a negative one.
    let mut room = vec![0u8; 8192];
    let huge = unsafe {
        libc::syscall(libc::SYS_readlinkat, libc::AT_FDCWD, cstr(&link).as_ptr(),
                      room.as_mut_ptr(), 3_000_000_000usize) as isize
    };
    check!(
        h,
        huge == -1 && sys::errno() == libc::EINVAL,
        "readlinkat with a three-gigabyte size is EINVAL: {huge} errno {}",
        sys::errno()
    );
    check_fails!(
        h,
        unsafe {
            libc::syscall(libc::SYS_readlinkat, libc::AT_FDCWD, cstr(&link).as_ptr(),
                          room.as_mut_ptr(), 0usize) as isize
        },
        libc::EINVAL,
        "readlinkat with a zero size"
    );
    // A size Linux will take: at most what the caller's buffer holds, and
    // asking for more room than a path needs does not change the length.
    let r = unsafe {
        libc::syscall(libc::SYS_readlinkat, libc::AT_FDCWD, cstr(&link).as_ptr(),
                      room.as_mut_ptr(), 8192usize) as isize
    };
    check!(
        h,
        r as usize == target.len(),
        "and reports the target's length, got {r} for {} characters",
        target.len()
    );

    // The emulator is still here.
    let mut buf = [0u8; 256];
    let n = unsafe {
        libc::readlink(cstr(&link).as_ptr(), buf.as_mut_ptr().cast(), buf.len())
    };
    check!(
        h,
        n == target.len() as isize,
        "an ordinary readlink still works afterwards: {n}"
    );
}

/// `preadv2`/`pwritev2` reject flags they do not implement.
///
/// Linux answers `EOPNOTSUPP` for a flag it does not know, which is how a
/// caller finds out its request was dropped. `preadv2` did; `pwritev2`
/// validated only `RWF_APPEND` and let every other bit through.
fn t_rwf_flags(h: &mut Harness, dir: &str) {
    h.group("rwf-flags");
    let path = format!("{dir}/rwf");
    let fd = unsafe {
        libc::open(
            std::ffi::CString::new(path.clone()).unwrap().as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
    };
    if fd < 0 {
        check!(h, false, "opening {path}");
        return;
    }
    let mut buf = [0u8; 16];
    let iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    const UNKNOWN: libc::c_int = 0x4000;

    check_fails!(
        h,
        unsafe { libc::syscall(libc::SYS_preadv2, fd, &iov, 1, 0i64, 0i64, UNKNOWN) },
        libc::EOPNOTSUPP,
        "preadv2 with a flag it does not implement"
    );
    check_fails!(
        h,
        unsafe { libc::syscall(libc::SYS_pwritev2, fd, &iov, 1, 0i64, 0i64, UNKNOWN) },
        libc::EOPNOTSUPP,
        "pwritev2 with a flag it does not implement"
    );

    // The control: with no flags at all both still work, so the checks above
    // are pinning the validation rather than a call that always fails.
    let r = unsafe { libc::syscall(libc::SYS_pwritev2, fd, &iov, 1, 0i64, 0i64, 0) };
    check!(h, r == buf.len() as _, "pwritev2 with no flags wrote {r}");
    let r = unsafe { libc::syscall(libc::SYS_preadv2, fd, &iov, 1, 0i64, 0i64, 0) };
    check!(h, r == buf.len() as _, "preadv2 with no flags read {r}");
    sys::close(fd);
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/fileio".into());
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { libc::mkdir(cstr(&dir).as_ptr(), 0o755) };
    let mut h = Harness::new();
    t_vectored(&mut h, &dir);
    t_short_readv(&mut h);
    t_no_position(&mut h);
    t_positional(&mut h, &dir);
    t_sendfile(&mut h, &dir);
    t_copy_file_range(&mut h, &dir);
    t_size_changes(&mut h, &dir);
    t_fallocate_modes(&mut h, &dir);
    t_absurd_readlink_size(&mut h, &dir);
    t_rwf_flags(&mut h, &dir);
    std::process::exit(h.finish());
}
