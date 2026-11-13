//! What the vectored and transfer syscalls answer at their edges.
//!
//! **A report, not a check** — the sixth in the shape `mmap_probe` established.
//! One line per case, never fails, diffed against an arm64 container by
//! `tests/integration/probe_diff.sh`.
//!
//! `kernel/fs.c` is 1991 lines and nothing in `tests/` had asked it any of
//! these questions. The subject is everything that moves bytes without naming
//! a path: `readv` and its five relatives, `sendfile`, `splice`, `tee`,
//! `copy_file_range`, and the two calls that change a file's length.
//!
//! It also settles a question left open in `fs/iovec.h`. `sendmsg`'s iovec
//! bound was measured and moved to `crates/fs/msghdr`, where a length past the
//! cap is `EFAULT` — but Linux *clamps* the total to `MAX_RW_COUNT` for
//! `readv`/`writev` rather than refusing it, which is a third answer again, and
//! the note there says so rather than assuming. These cases are that
//! measurement.

use std::os::fd::{AsRawFd, IntoRawFd};

/// The guest's `struct iovec`: a pointer and a length. Built by hand for the
/// same reason `msg_probe` builds its header by hand — the interesting lengths
/// do not fit in what the libc type will hold.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Iovec {
    base: u64,
    len: u64,
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn name(e: i32) -> String {
    let s = match e {
        libc::EINVAL => "EINVAL",
        libc::EFAULT => "EFAULT",
        libc::EBADF => "EBADF",
        libc::EISDIR => "EISDIR",
        libc::ESPIPE => "ESPIPE",
        libc::EAGAIN => "EAGAIN",
        libc::EPIPE => "EPIPE",
        libc::ENOSYS => "ENOSYS",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::EOVERFLOW => "EOVERFLOW",
        libc::EFBIG => "EFBIG",
        libc::ENOMEM => "ENOMEM",
        libc::EXDEV => "EXDEV",
        // No `ENOTSUP` arm: these binaries are built only for
        // `aarch64-unknown-linux-musl`, where it *is* `EOPNOTSUPP`. The guard
        // that used to stand in for the platforms where they differ was a
        // comparison of two constants, so rustc evaluated it and said the arm
        // was unreachable -- which is a warning on every build of the guest
        // tests, for a case this target does not have.
        _ => return format!("errno {e}"),
    };
    s.into()
}

fn report(what: &str, r: i64) {
    if r < 0 {
        println!("{what:<54} -> {}", name(errno()));
    } else {
        println!("{what:<54} -> {r}");
    }
}

fn value(what: &str, v: i64) {
    println!("{what:<54} -> {v}");
}

/// A fresh file with `content` in it. Every destructive case gets its own:
/// `fs_probe`'s first run reported eight differences that were one, because
/// its cases shared a file and an early one deleted it.
fn file(tag: &str, content: &[u8]) -> i32 {
    let path = format!("/tmp/io_probe.{tag}\0");
    let fd = unsafe {
        libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    assert!(fd >= 0, "could not create {path}");
    if !content.is_empty() {
        unsafe { libc::write(fd, content.as_ptr() as *const libc::c_void, content.len()) };
        unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    }
    unsafe { libc::unlink(path.as_ptr() as *const libc::c_char) };
    fd
}

/// A pipe, non-blocking on both ends so that a full or empty one answers
/// rather than parking the probe.
fn pipe() -> (i32, i32) {
    let mut fds = [0i32; 2];
    assert!(unsafe { libc::pipe(fds.as_mut_ptr()) } == 0);
    for f in fds {
        unsafe { libc::fcntl(f, libc::F_SETFL, libc::O_NONBLOCK) };
    }
    (fds[0], fds[1])
}

const SYS_PREADV2: libc::c_long = 286;
const SYS_PWRITEV2: libc::c_long = 287;

fn main() {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

    println!("## readv and writev: the vector count");
    // The count is a syscall argument, so unlike msg_iovlen it arrives in a
    // register. Linux declares it `unsigned long` and compares the whole
    // thing; a kernel that takes it as `int` sees something else entirely.
    let src = *b"0123456789";
    for (n, cnt) in [
        ("0", 0u64),
        ("1", 1),
        ("1024 (UIO_MAXIOV)", 1024),
        ("1025", 1025),
        ("0x1_0000_0001", 0x1_0000_0001),
        ("~0", u64::MAX),
    ] {
        let fd = file("wv", b"");
        let iovs = vec![Iovec { base: src.as_ptr() as u64, len: 1 }; 1025];
        report(&format!("writev(iovcnt={n})"), unsafe {
            libc::syscall(libc::SYS_writev, fd, iovs.as_ptr(), cnt)
        });
        unsafe { libc::close(fd) };

        let fd = file("rv", &src);
        let mut dst = [0u8; 32];
        let riovs = vec![Iovec { base: dst.as_mut_ptr() as u64, len: 1 }; 1025];
        report(&format!("readv(iovcnt={n})"), unsafe {
            libc::syscall(libc::SYS_readv, fd, riovs.as_ptr(), cnt)
        });
        unsafe { libc::close(fd) };
    }

    println!("## readv and writev: one vector's length");
    for (n, len) in [
        ("0", 0u64),
        ("10", 10),
        ("0x7fff_ffff (INT_MAX)", 0x7fff_ffff),
        ("0x8000_0000 (INT_MAX+1)", 0x8000_0000),
        ("0x7fff_ffff_ffff_ffff (SSIZE_MAX)", 0x7fff_ffff_ffff_ffff),
        ("~0", u64::MAX),
    ] {
        let fd = file("wl", b"");
        let iov = Iovec { base: src.as_ptr() as u64, len };
        report(&format!("writev(one vector, iov_len={n})"), unsafe {
            libc::syscall(libc::SYS_writev, fd, &iov as *const Iovec, 1u64)
        });
        unsafe { libc::close(fd) };
    }

    println!("## a total past what one call may move");
    {
        // Linux clamps a readv/writev total at MAX_RW_COUNT rather than
        // refusing it -- which is a different answer from the one sendmsg
        // gives, and the whole reason this block exists.
        let fd = file("tot", b"");
        // Three pages mapped and the last one taken away, so the readable
        // extent is **exactly two pages** whatever else is nearby.
        //
        // This was `vec![0u8; 4096]`, and how far past it the kernel could read
        // before faulting was whatever the allocator happened to leave there --
        // so the two sides agreed on some runs and not others, and the
        // allowlist entry for the difference looked stale about a third of the
        // time. A probe whose answer depends on the allocator makes the gate
        // flaky rather than making a finding.
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                3 * 4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(map, libc::MAP_FAILED, "three pages");
        unsafe { libc::mprotect(map.add(2 * 4096), 4096, libc::PROT_NONE) };
        let iovs = [
            Iovec { base: map as u64, len: 0x7fff_f000 },
            Iovec { base: map as u64, len: 0x7fff_f000 },
        ];
        // Reported as "did it write anything" rather than how much: what a
        // kernel that clamps writes is the distance to the guard page, and the
        // finding is the clamp rather than the count.
        let r = unsafe { libc::syscall(libc::SYS_writev, fd, iovs.as_ptr(), 2u64) };
        if r < 0 {
            report("writev(two vectors summing past INT_MAX)", r);
        } else {
            println!("{:<54} -> wrote something", "writev(two vectors summing past INT_MAX)");
        }
        unsafe { libc::munmap(map, 3 * 4096) };
        unsafe { libc::close(fd) };
    }

    println!("## the vector array itself");
    {
        let fd = file("ptr", b"x");
        report("writev(iov unmapped)", unsafe {
            libc::syscall(libc::SYS_writev, fd, 0x1000usize, 1u64)
        });
        report("writev(iov=NULL, iovcnt=0)", unsafe {
            libc::syscall(libc::SYS_writev, fd, 0usize, 0u64)
        });
        report("writev(iov=NULL, iovcnt=1)", unsafe {
            libc::syscall(libc::SYS_writev, fd, 0usize, 1u64)
        });
        let iov = Iovec { base: 0x1000, len: 8 };
        report("writev(iov_base unmapped)", unsafe {
            libc::syscall(libc::SYS_writev, fd, &iov as *const Iovec, 1u64)
        });
        // A first vector that works and a second that faults: does the good one
        // still land? **It does not** -- Linux answers `EFAULT` and writes
        // nothing, which is the opposite of what this comment used to assert.
        // Its write path copies into the page cache in page-sized batches and
        // rolls a batch back when it faults partway, so a fault in the first
        // batch loses the bytes before it too. Measured, after a change built on
        // the old reading fixed one case here and broke three.
        let iovs = [
            Iovec { base: src.as_ptr() as u64, len: 4 },
            Iovec { base: 0x1000, len: 8 },
        ];
        report("writev(a good vector then a faulting one)", unsafe {
            libc::syscall(libc::SYS_writev, fd, iovs.as_ptr(), 2u64)
        });
        unsafe { libc::close(fd) };
    }

    println!("## preadv and pwritev: the offset");
    // Two calling shapes, because the syscall takes the offset in two
    // registers and the two libcs disagree about what to put in them.
    //
    // Linux's `pos_from_hilo(high, low)` is
    // `(((loff_t)high << 32) << 32) | low`, and on a 64-bit long that first
    // expression is zero -- so **`pos_h` is ignored** and `pos_l` carries the
    // whole offset. glibc relies on that: `LO_HI_LONG(x)` expands to one
    // argument on 64-bit, leaving the sixth register holding whatever was in
    // it. musl passes `(long)ofs` and `(long)(ofs >> 32)`, which is also
    // correct because the low half is the whole value.
    //
    // A kernel that *combines* the two works for musl and fails for glibc.
    for (n, off) in [
        ("0", 0i64),
        ("5", 5),
        ("-1", -1),
        ("-2", -2),
        ("0x7fff_ffff_ffff_ffff", 0x7fff_ffff_ffff_ffff),
    ] {
        let fd = file("pv", &src);
        let mut dst = [0u8; 8];
        let iov = Iovec { base: dst.as_mut_ptr() as u64, len: 4 };
        report(&format!("preadv(offset={n}, glibc's shape)"), unsafe {
            // Four arguments: the offset whole, pos_h left alone.
            libc::syscall(libc::SYS_preadv, fd, &iov as *const Iovec, 1u64, off)
        });
        unsafe { libc::close(fd) };

        let fd = file("pv2", &src);
        let mut dst2 = [0u8; 8];
        let iov2 = Iovec { base: dst2.as_mut_ptr() as u64, len: 4 };
        report(&format!("preadv(offset={n}, musl's shape)"), unsafe {
            libc::syscall(libc::SYS_preadv, fd, &iov2 as *const Iovec, 1u64, off, off >> 32)
        });
        unsafe { libc::close(fd) };
    }
    {
        // pos_h set and pos_l zero. Linux reads offset 0; a kernel that
        // combines them reads from four gigabytes in, which on a ten-byte
        // file is past the end.
        let fd = file("ph", &src);
        let mut dst = [0u8; 8];
        let iov = Iovec { base: dst.as_mut_ptr() as u64, len: 4 };
        report("preadv(pos_l=0, pos_h=1 -- pos_h is ignored)", unsafe {
            libc::syscall(libc::SYS_preadv, fd, &iov as *const Iovec, 1u64, 0i64, 1i64)
        });
        value("  the first byte read", dst[0] as i64);
        unsafe { libc::close(fd) };
    }
    {
        // The file offset must not move: that is what distinguishes preadv
        // from readv, and nothing here had ever checked it.
        let fd = file("pvo", &src);
        let mut dst = [0u8; 8];
        let iov = Iovec { base: dst.as_mut_ptr() as u64, len: 4 };
        unsafe { libc::syscall(libc::SYS_preadv, fd, &iov as *const Iovec, 1u64, 5i64) };
        value("preadv left the file offset at", unsafe {
            libc::lseek(fd, 0, libc::SEEK_CUR)
        });
        value("  and read", dst[0] as i64);
        unsafe { libc::close(fd) };
    }
    {
        // On a pipe, which has no offset at all.
        let (r, w) = pipe();
        unsafe { libc::write(w, src.as_ptr() as *const libc::c_void, 4) };
        let mut dst = [0u8; 8];
        let iov = Iovec { base: dst.as_mut_ptr() as u64, len: 4 };
        report("preadv(a pipe, offset=0)", unsafe {
            libc::syscall(libc::SYS_preadv, r, &iov as *const Iovec, 1u64, 0i64)
        });
        report("preadv(a pipe, offset=-1)", unsafe {
            libc::syscall(libc::SYS_preadv, r, &iov as *const Iovec, 1u64, -1i64)
        });
        unsafe {
            libc::close(r);
            libc::close(w);
        }
    }

    println!("## preadv2 and pwritev2: the flags nobody validated");
    for (n, f) in [
        ("0", 0i64),
        ("RWF_HIPRI (0x1)", 0x1),
        ("RWF_DSYNC (0x2)", 0x2),
        ("RWF_SYNC (0x4)", 0x4),
        ("RWF_NOWAIT (0x8)", 0x8),
        ("RWF_APPEND (0x10)", 0x10),
        ("0x20 (undefined)", 0x20),
        ("0x8000_0000", -0x8000_0000i64),
        ("every bit", -1),
    ] {
        let fd = file("p2", &src);
        let mut dst = [0u8; 8];
        let iov = Iovec { base: dst.as_mut_ptr() as u64, len: 4 };
        report(&format!("preadv2(flags={n})"), unsafe {
            libc::syscall(SYS_PREADV2, fd, &iov as *const Iovec, 1u64, 0i64, 0i64, f)
        });
        unsafe { libc::close(fd) };
    }
    {
        // RWF_APPEND on a write is the one with an observable effect.
        let fd = file("app", &src);
        let iov = Iovec { base: src.as_ptr() as u64, len: 3 };
        report("pwritev2(offset=0, RWF_APPEND)", unsafe {
            libc::syscall(SYS_PWRITEV2, fd, &iov as *const Iovec, 1u64, 0i64, 0i64, 0x10i64)
        });
        value("  the file is now this long", unsafe {
            libc::lseek(fd, 0, libc::SEEK_END)
        });
        unsafe { libc::close(fd) };
    }
    {
        // offset = -1 means "use the file offset", which is preadv2's whole
        // reason for existing over preadv.
        let fd = file("p2o", &src);
        unsafe { libc::lseek(fd, 6, libc::SEEK_SET) };
        let mut dst = [0u8; 8];
        let iov = Iovec { base: dst.as_mut_ptr() as u64, len: 4 };
        report("preadv2(offset=-1, meaning the file offset)", unsafe {
            // musl passes `(long)ofs` and `(long)(ofs>>32)`, which for -1 is
            // -1 in both -- so this is what a real program's registers hold.
            libc::syscall(SYS_PREADV2, fd, &iov as *const Iovec, 1u64, -1i64, -1i64, 0i64)
        });
        value("  the first byte read", dst[0] as i64);
        value("  the file offset is now", unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) });
        unsafe { libc::close(fd) };
    }

    println!("## reading and writing things that are not files");
    {
        let d = unsafe { libc::open(c"/tmp".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        let mut dst = [0u8; 8];
        let iov = Iovec { base: dst.as_mut_ptr() as u64, len: 4 };
        report("readv(a directory)", unsafe {
            libc::syscall(libc::SYS_readv, d, &iov as *const Iovec, 1u64)
        });
        unsafe { libc::close(d) };
        let fd = file("rd", &src);
        let ro = unsafe { libc::open(c"/tmp".as_ptr(), libc::O_RDONLY) };
        let iov = Iovec { base: src.as_ptr() as u64, len: 4 };
        report("writev(a descriptor opened read-only)", unsafe {
            libc::syscall(libc::SYS_writev, ro, &iov as *const Iovec, 1u64)
        });
        unsafe {
            libc::close(ro);
            libc::close(fd);
        }
        report("readv(fd=-1)", unsafe {
            libc::syscall(libc::SYS_readv, -1, &iov as *const Iovec, 1u64)
        });
    }

    println!("## sendfile");
    for (n, count) in [
        ("0", 0u64),
        ("4", 4),
        ("1000 (more than there is)", 1000),
        ("0x7fff_ffff", 0x7fff_ffff),
        ("0x8000_0000", 0x8000_0000),
        // Exactly 2^32: zero in the low half. The one value a kernel that
        // takes this argument as 32 bits cannot answer like one that does not
        // -- see the section below, which asks the same of splice and
        // copy_file_range and found two.
        ("0x1_0000_0000", 0x1_0000_0000),
        ("~0", u64::MAX),
    ] {
        let inf = file("sfi", &src);
        let out = file("sfo", b"");
        report(&format!("sendfile(count={n})"), unsafe {
            libc::syscall(libc::SYS_sendfile, out, inf, std::ptr::null_mut::<i64>(), count)
        });
        unsafe {
            libc::close(inf);
            libc::close(out);
        }
    }
    {
        let inf = file("sfp", &src);
        let out = file("sfq", b"");
        let mut off: i64 = 3;
        report("sendfile(offset=3)", unsafe {
            libc::syscall(libc::SYS_sendfile, out, inf, &mut off as *mut i64, 4u64)
        });
        value("  the offset now says", off);
        value("  the input's own offset is", unsafe { libc::lseek(inf, 0, libc::SEEK_CUR) });
        let mut neg: i64 = -1;
        report("sendfile(offset=-1)", unsafe {
            libc::syscall(libc::SYS_sendfile, out, inf, &mut neg as *mut i64, 4u64)
        });
        report("sendfile(offset unmapped)", unsafe {
            libc::syscall(libc::SYS_sendfile, out, inf, 0x1000usize, 4u64)
        });
        unsafe {
            libc::close(inf);
            libc::close(out);
        }
    }
    {
        // A pipe cannot be seeked, so it cannot be sendfile's input with an
        // offset -- and Linux refuses it as an input at all.
        let (r, w) = pipe();
        unsafe { libc::write(w, src.as_ptr() as *const libc::c_void, 4) };
        let out = file("sfr", b"");
        report("sendfile(in = a pipe)", unsafe {
            libc::syscall(libc::SYS_sendfile, out, r, std::ptr::null_mut::<i64>(), 4u64)
        });
        let inf = file("sfs", &src);
        report("sendfile(out = a pipe)", unsafe {
            libc::syscall(libc::SYS_sendfile, w, inf, std::ptr::null_mut::<i64>(), 4u64)
        });
        report("sendfile(in = out)", unsafe {
            libc::syscall(libc::SYS_sendfile, inf, inf, std::ptr::null_mut::<i64>(), 4u64)
        });
        unsafe {
            libc::close(r);
            libc::close(w);
            libc::close(out);
            libc::close(inf);
        }
    }

    println!("## splice and tee");
    {
        let (r, w) = pipe();
        let inf = file("spi", &src);
        report("splice(file -> pipe)", unsafe {
            libc::syscall(
                libc::SYS_splice,
                inf,
                std::ptr::null_mut::<i64>(),
                w,
                std::ptr::null_mut::<i64>(),
                4usize,
                0u32,
            )
        });
        report("splice(file -> file)", unsafe {
            let out = file("spo", b"");
            let r = libc::syscall(
                libc::SYS_splice,
                inf,
                std::ptr::null_mut::<i64>(),
                out,
                std::ptr::null_mut::<i64>(),
                4usize,
                0u32,
            );
            libc::close(out);
            r
        });
        report("splice(len=0)", unsafe {
            libc::syscall(
                libc::SYS_splice,
                inf,
                std::ptr::null_mut::<i64>(),
                w,
                std::ptr::null_mut::<i64>(),
                0usize,
                0u32,
            )
        });
        report("splice(an undefined flag 0x40)", unsafe {
            libc::syscall(
                libc::SYS_splice,
                inf,
                std::ptr::null_mut::<i64>(),
                w,
                std::ptr::null_mut::<i64>(),
                4usize,
                0x40u32,
            )
        });
        // An offset on the pipe side is what Linux refuses with ESPIPE.
        let mut off: i64 = 0;
        report("splice(an offset on the pipe end)", unsafe {
            libc::syscall(
                libc::SYS_splice,
                inf,
                std::ptr::null_mut::<i64>(),
                w,
                &mut off as *mut i64,
                4usize,
                0u32,
            )
        });
        let (r2, w2) = pipe();
        report("tee(pipe -> pipe)", unsafe {
            libc::syscall(libc::SYS_tee, r, w2, 4usize, 0u32)
        });
        report("tee(pipe -> a file)", unsafe {
            let out = file("teo", b"");
            let v = libc::syscall(libc::SYS_tee, r, out, 4usize, 0u32);
            libc::close(out);
            v
        });
        report("tee(the same pipe both ways)", unsafe {
            libc::syscall(libc::SYS_tee, r, w, 4usize, 0u32)
        });
        unsafe {
            libc::close(r);
            libc::close(w);
            libc::close(r2);
            libc::close(w2);
            libc::close(inf);
        }
    }

    println!("## copy_file_range");
    {
        let inf = file("cfi", &src);
        let out = file("cfo", b"");
        report("copy_file_range(4 bytes)", unsafe {
            libc::syscall(
                libc::SYS_copy_file_range,
                inf,
                std::ptr::null_mut::<i64>(),
                out,
                std::ptr::null_mut::<i64>(),
                4usize,
                0u32,
            )
        });
        value("  the output is now this long", unsafe {
            libc::lseek(out, 0, libc::SEEK_END)
        });
        report("copy_file_range(flags=1)", unsafe {
            libc::syscall(
                libc::SYS_copy_file_range,
                inf,
                std::ptr::null_mut::<i64>(),
                out,
                std::ptr::null_mut::<i64>(),
                4usize,
                1u32,
            )
        });
        let mut off: i64 = -1;
        report("copy_file_range(a negative offset)", unsafe {
            libc::syscall(
                libc::SYS_copy_file_range,
                inf,
                &mut off as *mut i64,
                out,
                std::ptr::null_mut::<i64>(),
                4usize,
                0u32,
            )
        });
        // Overlapping ranges of the same file: Linux refuses.
        report("copy_file_range(the same file, overlapping)", unsafe {
            let mut a: i64 = 0;
            let mut b: i64 = 2;
            libc::syscall(
                libc::SYS_copy_file_range,
                inf,
                &mut a as *mut i64,
                inf,
                &mut b as *mut i64,
                4usize,
                0u32,
            )
        });
        let (r, w) = pipe();
        report("copy_file_range(in = a pipe)", unsafe {
            libc::syscall(
                libc::SYS_copy_file_range,
                r,
                std::ptr::null_mut::<i64>(),
                out,
                std::ptr::null_mut::<i64>(),
                4usize,
                0u32,
            )
        });
        unsafe {
            libc::close(r);
            libc::close(w);
            libc::close(inf);
            libc::close(out);
        }
    }

    // The three transfer calls take their length as `size_t`, which is 64 bits
    // on aarch64 -- `SYSCALL_DEFINE6(splice, ..., size_t, len, unsigned int,
    // flags)` and the same shape for `copy_file_range`. A kernel that narrows
    // one to 32 bits somewhere in its body answers every one of these
    // differently, and the difference is *silent*: a copy of 2^32 bytes from a
    // ten-byte file is ten bytes on Linux and nothing at all after a `as u32`,
    // which a caller reads as end-of-file and stops.
    //
    // Each length is paired with a small one whose low half is the same, so a
    // narrowing shows as a *pair* that agrees rather than as one odd line: 2^32
    // and 0 behave alike under truncation, as do 2^32+4 and 4.
    //
    // Every length here is positive as an `ssize_t`. The two calls disagree
    // about the ones that are not, and that disagreement is about a different
    // rule: `splice` reaches `rw_verify_area`, whose first line refuses a count
    // that is negative as a signed value, and `copy_file_range` has no such
    // check at all. `~0` is `EINVAL` for the first and copies the file for the
    // second -- measured, and the splice half is below. The copy_file_range
    // half is left out on purpose: this kernel answers `EOVERFLOW` for it, from
    // an offset-overflow rule written as `pos + len > i64::MAX` where Linux's
    // is an *unsigned* wrap (`pos_in + count < pos_in`, with count a
    // `uint64_t`). That is a real difference and it is not this section's
    // subject; it wants its own measurement, because the neighbouring case
    // `off=SSIZE_MAX` is `EFBIG` from the output filesystem's `s_maxbytes`,
    // which is a property of the mount rather than of the kernel.
    println!("## a transfer length above 32 bits");
    for (n, len) in [
        ("0x1_0000_0000 (0 in the low half)", 0x1_0000_0000u64),
        ("0x1_0000_0004 (4 in the low half)", 0x1_0000_0004),
        ("0x2_0000_0000", 0x2_0000_0000),
        ("0x7fff_ffff_ffff_ffff (SSIZE_MAX)", 0x7fff_ffff_ffff_ffff),
    ] {
        {
            let inf = file("bli", &src);
            let out = file("blo", b"");
            report(&format!("copy_file_range(len={n})"), unsafe {
                libc::syscall(
                    libc::SYS_copy_file_range,
                    inf,
                    std::ptr::null_mut::<i64>(),
                    out,
                    std::ptr::null_mut::<i64>(),
                    len,
                    0u32,
                )
            });
            value("  the output is now this long", unsafe {
                libc::lseek(out, 0, libc::SEEK_END)
            });
            unsafe {
                libc::close(inf);
                libc::close(out);
            }
        }
        {
            let inf = file("blp", &src);
            let (r, w) = pipe();
            report(&format!("splice(len={n}, file -> pipe)"), unsafe {
                libc::syscall(
                    libc::SYS_splice,
                    inf,
                    std::ptr::null_mut::<i64>(),
                    w,
                    std::ptr::null_mut::<i64>(),
                    len,
                    0u32,
                )
            });
            unsafe {
                libc::close(r);
                libc::close(w);
                libc::close(inf);
            }
        }
    }
    // The splice half of the paragraph above: `rw_verify_area` refuses a length
    // that is negative as an `ssize_t`, which is the same rule `sendfile` has
    // and which the clamp alone would not produce.
    for (n, len) in [
        ("0x8000_0000_0000_0000", 0x8000_0000_0000_0000u64),
        ("~0", u64::MAX),
    ] {
        let inf = file("blq", &src);
        let (r, w) = pipe();
        report(&format!("splice(len={n}, file -> pipe)"), unsafe {
            libc::syscall(
                libc::SYS_splice,
                inf,
                std::ptr::null_mut::<i64>(),
                w,
                std::ptr::null_mut::<i64>(),
                len,
                0u32,
            )
        });
        unsafe {
            libc::close(r);
            libc::close(w);
            libc::close(inf);
        }
    }

    println!("## ftruncate");
    for (n, len) in [
        ("0", 0i64),
        ("100", 100),
        ("-1", -1),
        ("0x7fff_ffff_ffff_ffff", 0x7fff_ffff_ffff_ffff),
    ] {
        let fd = file("tr", &src);
        report(&format!("ftruncate(len={n})"), unsafe {
            libc::syscall(libc::SYS_ftruncate, fd, len)
        });
        unsafe { libc::close(fd) };
    }
    {
        let (r, w) = pipe();
        report("ftruncate(a pipe)", unsafe {
            libc::syscall(libc::SYS_ftruncate, w, 0i64)
        });
        let d = unsafe { libc::open(c"/tmp".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        report("ftruncate(a directory)", unsafe {
            libc::syscall(libc::SYS_ftruncate, d, 0i64)
        });
        let ro = unsafe { libc::open(c"/tmp".as_ptr(), libc::O_RDONLY) };
        report("ftruncate(read-only descriptor)", unsafe {
            libc::syscall(libc::SYS_ftruncate, ro, 0i64)
        });
        unsafe {
            libc::close(r);
            libc::close(w);
            libc::close(d);
            libc::close(ro);
        }
    }

    println!("## the file offset after a short read");
    {
        // Four vectors, ten bytes of file: the third is where it runs out,
        // and where the offset ends up says whether the loop stopped at the
        // right place.
        let fd = file("so", &src);
        let mut a = [0u8; 4];
        let mut b = [0u8; 4];
        let mut c = [0u8; 4];
        let mut d = [0u8; 4];
        let iovs = [
            Iovec { base: a.as_mut_ptr() as u64, len: 4 },
            Iovec { base: b.as_mut_ptr() as u64, len: 4 },
            Iovec { base: c.as_mut_ptr() as u64, len: 4 },
            Iovec { base: d.as_mut_ptr() as u64, len: 4 },
        ];
        report("readv(4x4 bytes from a 10-byte file)", unsafe {
            libc::syscall(libc::SYS_readv, fd, iovs.as_ptr(), 4u64)
        });
        value("  the offset is now", unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) });
        value("  the third vector's first byte", c[0] as i64);
        value("  the fourth vector's first byte", d[0] as i64);
        unsafe { libc::close(fd) };
    }

    // Keep the two `IntoRawFd`/`AsRawFd` imports honest: a std File is the
    // only thing here that opens a path through the ordinary API, and it is
    // what proves the /tmp used above is writable on both sides.
    let f = std::fs::File::create("/tmp/io_probe.std").unwrap();
    value("a std::fs::File has a descriptor", (f.as_raw_fd() >= 0) as i64);
    let raw = f.into_raw_fd();
    unsafe { libc::close(raw) };
    unsafe { libc::unlink(c"/tmp/io_probe.std".as_ptr()) };
}
