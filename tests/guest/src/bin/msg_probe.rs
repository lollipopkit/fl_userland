//! What `sendmsg`, `recvmsg` and their vector forms answer at their edges.
//!
//! **A report, not a check** — the fifth in the shape `mmap_probe` established.
//! One line per case, never fails, run here and in an arm64 container and
//! diffed by `tests/integration/probe_diff.sh`.
//!
//! The subject is a **wire format read from guest memory**, which is the shape
//! that has produced the most defects in this tree: `struct cmsghdr_` was the
//! i386 layout so every field after the first came from the wrong offset, and
//! `getdents64` computed one record length in two places that disagreed. A
//! `msghdr` is 56 bytes with seven fields, three of which are lengths the guest
//! chooses, and each of those three is a bound someone has to get right.
//!
//! So the header is built here as **raw bytes**, not as `libc::msghdr`. musl
//! declares `msg_iovlen` as an `int` with padding, which makes the interesting
//! values — the ones that do not fit in 32 bits — unexpressible through the
//! type. Those are exactly the cases worth asking about.

use std::mem::size_of;

/// The guest's `struct msghdr`: 56 bytes, `msg_iov` at 16, `msg_control` at 32,
/// `msg_flags` at 48.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Msghdr {
    name: u64,
    namelen: u32,
    _pad0: u32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
    flags: i32,
    _pad1: i32,
}

/// The guest's `struct iovec`: 16 bytes.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Iovec {
    base: u64,
    len: u64,
}

/// `struct mmsghdr`: a header and the length it reports back, 64 bytes.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Mmsghdr {
    hdr: Msghdr,
    len: u32,
    _pad: u32,
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn name(e: i32) -> String {
    let s = match e {
        libc::EINVAL => "EINVAL",
        libc::EFAULT => "EFAULT",
        libc::EMSGSIZE => "EMSGSIZE",
        libc::ENOBUFS => "ENOBUFS",
        libc::EBADF => "EBADF",
        libc::ENOTSOCK => "ENOTSOCK",
        libc::EAGAIN => "EAGAIN",
        libc::EPIPE => "EPIPE",
        libc::ECONNRESET => "ECONNRESET",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::ENOTCONN => "ENOTCONN",
        libc::EPERM => "EPERM",
        libc::ENOMEM => "ENOMEM",
        libc::EINTR => "EINTR",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        libc::ERANGE => "ERANGE",
        _ => return format!("errno {e}"),
    };
    s.into()
}

/// A result line. A negative return is an errno; a non-negative one is the
/// count, which for these calls is the byte count and is part of the answer.
fn report(what: &str, r: i64) {
    if r < 0 {
        println!("{what:<52} -> {}", name(errno()));
    } else {
        println!("{what:<52} -> {r}");
    }
}

fn value(what: &str, v: i64) {
    println!("{what:<52} -> {v}");
}

/// A connected `AF_UNIX` `SOCK_STREAM` pair. Every case gets a fresh one: the
/// first run of `fs_probe` reported eight differences that were one, because
/// its cases shared a file and an early one deleted it.
fn pair() -> (i32, i32) {
    let mut fds = [0i32; 2];
    let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert!(r == 0, "socketpair failed");
    (fds[0], fds[1])
}

fn close2(a: i32, b: i32) {
    unsafe {
        libc::close(a);
        libc::close(b);
    }
}

unsafe fn sendmsg(fd: i32, h: &Msghdr, flags: i32) -> i64 {
    unsafe { libc::syscall(libc::SYS_sendmsg, fd, h as *const Msghdr, flags) }
}

unsafe fn recvmsg(fd: i32, h: &mut Msghdr, flags: i32) -> i64 {
    unsafe { libc::syscall(libc::SYS_recvmsg, fd, h as *mut Msghdr, flags) }
}

/// A header naming one buffer, which is the ordinary case every bound is
/// measured against.
fn one_iov(iov: &Iovec) -> Msghdr {
    Msghdr {
        iov: iov as *const Iovec as u64,
        iovlen: 1,
        ..Default::default()
    }
}

fn main() {
    // Both sides ignore it, so a case that writes to a closed peer reports
    // EPIPE rather than dying. Nothing else about the comparison changes.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

    println!("## the shape of the header");
    value("sizeof(msghdr)", size_of::<Msghdr>() as i64);
    value("sizeof(iovec)", size_of::<Iovec>() as i64);
    value("sizeof(mmsghdr)", size_of::<Mmsghdr>() as i64);

    println!("## msg_iovlen");
    let buf = *b"hello";
    let iov = Iovec { base: buf.as_ptr() as u64, len: 5 };
    for (n, len) in [
        ("0", 0u64),
        ("1", 1),
        ("UIO_MAXIOV (1024)", 1024),
        ("1025", 1025),
        // Truncation: the low 32 bits of each of these is a count that would
        // be accepted. Linux compares the whole 64-bit field.
        ("0x1_0000_0001", 0x1_0000_0001),
        ("0x1_0000_0000", 0x1_0000_0000),
        ("~0", u64::MAX),
    ] {
        let (a, b) = pair();
        // A count above 1 would read iovecs past the one that exists, so the
        // pointer names an array big enough for the bounded cases and the
        // unbounded ones are meant to be refused before it is read.
        let iovs = vec![iov; 1024];
        let h = Msghdr {
            iov: iovs.as_ptr() as u64,
            iovlen: len,
            ..Default::default()
        };
        report(&format!("sendmsg(msg_iovlen={n})"), unsafe { sendmsg(a, &h, 0) });
        close2(a, b);
    }

    println!("## msg_iovlen on recvmsg");
    for (n, len) in [("0", 0u64), ("1025", 1025), ("0x1_0000_0001", 0x1_0000_0001)] {
        let (a, b) = pair();
        unsafe { libc::write(b, buf.as_ptr() as *const libc::c_void, 5) };
        let mut got = [0u8; 8];
        let riov = vec![Iovec { base: got.as_mut_ptr() as u64, len: 8 }; 1024];
        let mut h = Msghdr {
            iov: riov.as_ptr() as u64,
            iovlen: len,
            ..Default::default()
        };
        report(&format!("recvmsg(msg_iovlen={n})"), unsafe {
            recvmsg(a, &mut h, libc::MSG_DONTWAIT)
        });
        close2(a, b);
    }

    println!("## msg_controllen");
    for (n, len) in [
        ("0", 0u64),
        ("2048", 2048),
        ("2049", 2049),
        ("0x7fff_ffff (INT_MAX)", 0x7fff_ffff),
        ("0x8000_0000 (INT_MAX+1)", 0x8000_0000),
        // Truncates to 0 in 32 bits: "no control data" rather than a refusal.
        ("0x1_0000_0000", 0x1_0000_0000),
        ("~0", u64::MAX),
    ] {
        let (a, b) = pair();
        let ctl = vec![0u8; 4096];
        let h = Msghdr {
            iov: &iov as *const Iovec as u64,
            iovlen: 1,
            control: ctl.as_ptr() as u64,
            controllen: len,
            ..Default::default()
        };
        report(&format!("sendmsg(msg_controllen={n})"), unsafe { sendmsg(a, &h, 0) });
        close2(a, b);
    }

    println!("## msg_controllen on recvmsg");
    // The same three lengths on the receiving side, where the field is a
    // capacity rather than a payload. Asked separately because a kernel is
    // entitled to answer them differently, and guessing which is how the
    // `clock_nanosleep` flag rule got written wrong.
    for (n, len) in [
        ("2049", 2049u64),
        ("0x7fff_ffff (INT_MAX)", 0x7fff_ffff),
        ("0x1_0000_0000", 0x1_0000_0000),
        ("~0", u64::MAX),
    ] {
        let (a, b) = pair();
        unsafe { libc::write(b, buf.as_ptr() as *const libc::c_void, 5) };
        let mut got = [0u8; 8];
        let riov = Iovec { base: got.as_mut_ptr() as u64, len: 8 };
        let ctl = vec![0u8; 4096];
        let mut h = Msghdr {
            iov: &riov as *const Iovec as u64,
            iovlen: 1,
            control: ctl.as_ptr() as u64,
            controllen: len,
            ..Default::default()
        };
        report(&format!("recvmsg(msg_controllen={n})"), unsafe {
            recvmsg(a, &mut h, libc::MSG_DONTWAIT)
        });
        close2(a, b);
    }
    {
        let (a, b) = pair();
        unsafe { libc::write(b, buf.as_ptr() as *const libc::c_void, 5) };
        let mut got = [0u8; 8];
        let riov = Iovec { base: got.as_mut_ptr() as u64, len: 8 };
        let mut h = Msghdr {
            iov: &riov as *const Iovec as u64,
            iovlen: 1,
            control: 0,
            controllen: 64,
            ..Default::default()
        };
        report("recvmsg(control=NULL, controllen=64)", unsafe {
            recvmsg(a, &mut h, libc::MSG_DONTWAIT)
        });
        value("  msg_controllen after", h.controllen as i64);
        close2(a, b);
    }

    println!("## what recvmsg writes into msg_namelen");
    for (n, namelen) in [("0", 0u32), ("16", 16), ("128", 128), ("0xffffffff", 0xffff_ffff)] {
        let (a, b) = pair();
        unsafe { libc::write(b, buf.as_ptr() as *const libc::c_void, 5) };
        let mut got = [0u8; 8];
        let riov = Iovec { base: got.as_mut_ptr() as u64, len: 8 };
        let mut sa = [0u8; 256];
        let mut h = Msghdr {
            name: sa.as_mut_ptr() as u64,
            namelen,
            iov: &riov as *const Iovec as u64,
            iovlen: 1,
            ..Default::default()
        };
        report(&format!("recvmsg(name=set, namelen={n})"), unsafe {
            recvmsg(a, &mut h, libc::MSG_DONTWAIT)
        });
        value("  msg_namelen after", h.namelen as i64);
        value("  the first two bytes written", u16::from_ne_bytes([sa[0], sa[1]]) as i64);
        close2(a, b);
    }

    println!("## msg_control that is null");
    {
        let (a, b) = pair();
        // A length with no buffer. Linux looks at the pointer first.
        let h = Msghdr {
            iov: &iov as *const Iovec as u64,
            iovlen: 1,
            control: 0,
            controllen: 64,
            ..Default::default()
        };
        report("sendmsg(control=NULL, controllen=64)", unsafe { sendmsg(a, &h, 0) });
        close2(a, b);
    }

    println!("## msg_name on a connected socket");
    for (n, namelen, has_name) in [
        ("name=NULL, namelen=0", 0u32, false),
        ("name=NULL, namelen=16", 16, false),
        ("name=set, namelen=0", 0, true),
        ("name=set, namelen=16", 16, true),
        ("name=set, namelen=128", 128, true),
        ("name=set, namelen=0xffffffff", 0xffff_ffff, true),
    ] {
        let (a, b) = pair();
        let mut sa = [0u8; 128];
        sa[0] = libc::AF_UNIX as u8;
        let h = Msghdr {
            name: if has_name { sa.as_ptr() as u64 } else { 0 },
            namelen,
            iov: &iov as *const Iovec as u64,
            iovlen: 1,
            ..Default::default()
        };
        report(&format!("sendmsg({n})"), unsafe { sendmsg(a, &h, 0) });
        close2(a, b);
    }

    println!("## iov_len");
    for (n, len) in [
        ("0", 0u64),
        ("5", 5),
        ("0x7fff_ffff_ffff_ffff (SSIZE_MAX)", 0x7fff_ffff_ffff_ffff),
        ("0x8000_0000_0000_0000", 0x8000_0000_0000_0000),
        ("~0", u64::MAX),
    ] {
        let (a, b) = pair();
        let iv = Iovec { base: buf.as_ptr() as u64, len };
        let h = one_iov(&iv);
        report(&format!("sendmsg(iov_len={n})"), unsafe { sendmsg(a, &h, 0) });
        close2(a, b);
    }

    println!("## two iovecs whose lengths sum past SSIZE_MAX");
    {
        let (a, b) = pair();
        let iovs = [
            Iovec { base: buf.as_ptr() as u64, len: 0x7fff_ffff_ffff_ffff },
            Iovec { base: buf.as_ptr() as u64, len: 2 },
        ];
        let h = Msghdr {
            iov: iovs.as_ptr() as u64,
            iovlen: 2,
            ..Default::default()
        };
        report("sendmsg(two iovecs, total > SSIZE_MAX)", unsafe { sendmsg(a, &h, 0) });
        close2(a, b);
    }

    println!("## a pointer that is not mapped");
    {
        let (a, b) = pair();
        let h = Msghdr { iov: 0x1000, iovlen: 1, ..Default::default() };
        report("sendmsg(msg_iov unmapped)", unsafe { sendmsg(a, &h, 0) });
        let iv = Iovec { base: 0x1000, len: 5 };
        let h = one_iov(&iv);
        report("sendmsg(iov_base unmapped)", unsafe { sendmsg(a, &h, 0) });
        report("sendmsg(the msghdr itself unmapped)", unsafe {
            libc::syscall(libc::SYS_sendmsg, a, 0x1000usize, 0)
        });
        close2(a, b);
    }

    println!("## msg_flags");
    // sendmsg ignores the field in the struct -- the flags argument is what it
    // reads. recvmsg *writes* it, and never reads it.
    {
        let (a, b) = pair();
        let mut h = one_iov(&iov);
        h.flags = -1;
        report("sendmsg(msg_flags=-1 in the struct)", unsafe { sendmsg(a, &h, 0) });
        close2(a, b);
    }
    // One bit at a time. `flags = -1` answered EINVAL here and 5 on Linux, and
    // a whole word says nothing about *which* bit did it -- so every flag the
    // guest ABI defines gets its own line. Linux ignores the ones that mean
    // nothing to the protocol; anything refused here is a bit this kernel is
    // handing to a host that has its own opinion.
    for (n, f) in [
        ("0", 0i32),
        ("MSG_OOB (0x01)", 0x01),
        ("MSG_PEEK (0x02)", 0x02),
        ("MSG_DONTROUTE (0x04)", 0x04),
        ("MSG_CTRUNC (0x08)", 0x08),
        ("MSG_PROXY (0x10)", 0x10),
        ("MSG_TRUNC (0x20)", 0x20),
        ("MSG_DONTWAIT (0x40)", 0x40),
        ("MSG_EOR (0x80)", 0x80),
        ("MSG_WAITALL (0x100)", 0x100),
        ("MSG_FIN (0x200)", 0x200),
        ("MSG_SYN (0x400)", 0x400),
        ("MSG_CONFIRM (0x800)", 0x800),
        ("MSG_RST (0x1000)", 0x1000),
        ("MSG_ERRQUEUE (0x2000)", 0x2000),
        ("MSG_NOSIGNAL (0x4000)", 0x4000),
        ("MSG_MORE (0x8000)", 0x8000),
        ("MSG_WAITFORONE (0x10000)", 0x10000),
        ("MSG_BATCH (0x40000)", 0x40000),
        ("MSG_ZEROCOPY (0x4000000)", 0x400_0000),
        ("MSG_FASTOPEN (0x20000000)", 0x2000_0000),
        ("MSG_CMSG_CLOEXEC (0x40000000)", 0x4000_0000),
        ("an unknown bit (0x0080_0000)", 0x0080_0000),
        ("every bit", -1),
    ] {
        let (a, b) = pair();
        let h = one_iov(&iov);
        report(&format!("sendmsg(flags={n})"), unsafe { sendmsg(a, &h, f) });
        close2(a, b);
    }

    println!("## what recvmsg reports in msg_flags");
    {
        // A datagram longer than the buffer: MSG_TRUNC comes back, and the
        // return is the truncated length unless MSG_TRUNC was asked for.
        let mut fds = [0i32; 2];
        let r =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        if r == 0 {
            let (a, b) = (fds[0], fds[1]);
            let big = [7u8; 64];
            unsafe { libc::write(b, big.as_ptr() as *const libc::c_void, 64) };
            let mut got = [0u8; 8];
            let riov = Iovec { base: got.as_mut_ptr() as u64, len: 8 };
            let mut h = one_iov(&riov);
            h.flags = 0x1234; // must be overwritten
            let n = unsafe { recvmsg(a, &mut h, libc::MSG_DONTWAIT) };
            report("recvmsg(a 64-byte datagram into 8 bytes)", n);
            value("  msg_flags has MSG_TRUNC", ((h.flags & libc::MSG_TRUNC) != 0) as i64);
            value("  msg_flags has anything else", (h.flags & !libc::MSG_TRUNC) as i64);
            // And with MSG_TRUNC asked for: the datagram's whole length.
            // Darwin answers what fitted, which is what this kernel answered
            // until 2026-11-17.
            unsafe { libc::write(b, big.as_ptr() as *const libc::c_void, 64) };
            let mut h = one_iov(&riov);
            let n = unsafe { recvmsg(a, &mut h, libc::MSG_DONTWAIT | libc::MSG_TRUNC) };
            report("recvmsg(64 bytes into 8, MSG_TRUNC)", n);
            value("  msg_flags has MSG_TRUNC", ((h.flags & libc::MSG_TRUNC) != 0) as i64);
            unsafe { libc::write(b, big.as_ptr() as *const libc::c_void, 64) };
            let n = unsafe { libc::recv(a, got.as_mut_ptr().cast(), 8, libc::MSG_DONTWAIT | libc::MSG_TRUNC) };
            report("recv(64 bytes into 8, MSG_TRUNC)", n as i64);
            unsafe { libc::write(b, big.as_ptr() as *const libc::c_void, 64) };
            let n = unsafe { libc::recv(a, std::ptr::null_mut(), 0, libc::MSG_DONTWAIT | libc::MSG_TRUNC) };
            report("recv(64 bytes into NULL/0, MSG_TRUNC)", n as i64);
            unsafe { libc::write(b, big.as_ptr() as *const libc::c_void, 64) };
            let n = unsafe { libc::recv(a, got.as_mut_ptr().cast(), 8, libc::MSG_DONTWAIT | libc::MSG_TRUNC | libc::MSG_PEEK) };
            report("recv(MSG_TRUNC|MSG_PEEK)", n as i64);
            let n = unsafe { libc::recv(a, got.as_mut_ptr().cast(), 8, libc::MSG_DONTWAIT) };
            report("  then recv without MSG_TRUNC", n as i64);
            close2(a, b);
        } else {
            println!("recvmsg(a 64-byte datagram into 8 bytes)         -> no SOCK_DGRAM pair");
        }
    }
    {
        let (a, b) = pair();
        let mut got = [0u8; 8];
        let riov = Iovec { base: got.as_mut_ptr() as u64, len: 8 };
        let mut h = one_iov(&riov);
        h.namelen = 99;
        h.controllen = 99;
        unsafe { libc::write(b, buf.as_ptr() as *const libc::c_void, 5) };
        report("recvmsg(a stream, name/control null)", unsafe {
            recvmsg(a, &mut h, libc::MSG_DONTWAIT)
        });
        // Linux zeroes msg_namelen when there is no name to report, and
        // msg_controllen to what it actually wrote.
        value("  msg_namelen after", h.namelen as i64);
        value("  msg_controllen after", h.controllen as i64);
        value("  msg_flags after", h.flags as i64);
        close2(a, b);
    }

    println!("## recvmsg on an empty socket");
    {
        let (a, b) = pair();
        let mut got = [0u8; 8];
        let riov = Iovec { base: got.as_mut_ptr() as u64, len: 8 };
        let mut h = one_iov(&riov);
        report("recvmsg(nothing there, MSG_DONTWAIT)", unsafe {
            recvmsg(a, &mut h, libc::MSG_DONTWAIT)
        });
        // The peer is gone: end of stream, which is 0 rather than an error.
        unsafe { libc::close(b) };
        report("recvmsg(the peer closed)", unsafe {
            recvmsg(a, &mut h, libc::MSG_DONTWAIT)
        });
        unsafe { libc::close(a) };
    }

    println!("## sendmsg and recvmsg on things that are not sockets");
    {
        let f = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
        let h = one_iov(&iov);
        report("sendmsg(a character device)", unsafe { sendmsg(f, &h, 0) });
        let mut h2 = one_iov(&iov);
        report("recvmsg(a character device)", unsafe { recvmsg(f, &mut h2, 0) });
        unsafe { libc::close(f) };
        report("sendmsg(a descriptor that is not open)", unsafe {
            sendmsg(f, &h, 0)
        });
        report("sendmsg(fd=-1)", unsafe { sendmsg(-1, &h, 0) });
    }

    println!("## sendmmsg and recvmmsg");
    for (n, vlen) in [
        ("0", 0u32),
        ("1", 1),
        ("UIO_MAXIOV (1024)", 1024),
        ("1025", 1025),
        ("0xffff_ffff", 0xffff_ffff),
    ] {
        let (a, b) = pair();
        // UIO_MAXIOV + 1 entries, whatever `vlen` says. A kernel that clamps
        // an over-large `vlen` to UIO_MAXIOV then reads 1024 of them, and a
        // shorter array would make it read whatever is past the end -- which
        // is what the first run of this probe did, and it reported "7
        // messages sent" from uninitialised stack.
        //
        // Every message names an **unmapped** buffer, so each fails the same
        // way and the answer does not depend on how much a socket buffer
        // holds. Sending 1024 real messages blocked on Linux: 5 KB of payload
        // but 1024 skbs, whose overhead is what counts against `sk_sndbuf`.
        // What is being asked here is only whether `vlen` itself is refused,
        // and EFAULT rather than EINVAL says it was not.
        let bad = Iovec { base: 0x1000, len: 5 };
        let mut vec = vec![
            Mmsghdr {
                hdr: Msghdr {
                    iov: &bad as *const Iovec as u64,
                    iovlen: 1,
                    ..Default::default()
                },
                ..Default::default()
            };
            1025
        ];
        report(&format!("sendmmsg(vlen={n}, each unmapped)"), unsafe {
            libc::syscall(libc::SYS_sendmmsg, a, vec.as_mut_ptr(), vlen, 0)
        });
        close2(a, b);
    }
    {
        // The reported length per message: two of three sent, and what the
        // third leaves behind.
        let (a, b) = pair();
        let bufs = [*b"one", *b"two"];
        let iv = [
            Iovec { base: bufs[0].as_ptr() as u64, len: 3 },
            Iovec { base: bufs[1].as_ptr() as u64, len: 3 },
        ];
        let mut vec = [
            Mmsghdr {
                hdr: Msghdr { iov: &iv[0] as *const Iovec as u64, iovlen: 1, ..Default::default() },
                len: 0xdead,
                _pad: 0,
            },
            Mmsghdr {
                hdr: Msghdr { iov: &iv[1] as *const Iovec as u64, iovlen: 1, ..Default::default() },
                len: 0xbeef,
                _pad: 0,
            },
        ];
        report("sendmmsg(two 3-byte messages)", unsafe {
            libc::syscall(libc::SYS_sendmmsg, a, vec.as_mut_ptr(), 2u32, 0)
        });
        value("  vec[0].msg_len", vec[0].len as i64);
        value("  vec[1].msg_len", vec[1].len as i64);
        close2(a, b);
    }
    for (n, vlen) in [("0", 0u32), ("1025", 1025), ("0xffff_ffff", 0xffff_ffff)] {
        let (a, b) = pair();
        let mut got = [0u8; 8];
        let riov = Iovec { base: got.as_mut_ptr() as u64, len: 8 };
        let mut vec = vec![
            Mmsghdr {
                hdr: Msghdr {
                    iov: &riov as *const Iovec as u64,
                    iovlen: 1,
                    ..Default::default()
                },
                ..Default::default()
            };
            1025
        ];
        report(&format!("recvmmsg(vlen={n})"), unsafe {
            libc::syscall(
                libc::SYS_recvmmsg,
                a,
                vec.as_mut_ptr(),
                vlen,
                libc::MSG_DONTWAIT,
                std::ptr::null::<libc::timespec>(),
            )
        });
        close2(a, b);
    }
    {
        // A timeout that is not a valid time. Linux checks it before it does
        // any receiving.
        let (a, b) = pair();
        let mut got = [0u8; 8];
        let riov = Iovec { base: got.as_mut_ptr() as u64, len: 8 };
        let mut vec = [Mmsghdr {
            hdr: Msghdr { iov: &riov as *const Iovec as u64, iovlen: 1, ..Default::default() },
            ..Default::default()
        }];
        for (n, ts) in [
            ("tv_nsec = 1_000_000_000", libc::timespec { tv_sec: 0, tv_nsec: 1_000_000_000 }),
            ("tv_nsec = -1", libc::timespec { tv_sec: 0, tv_nsec: -1 }),
            ("tv_sec = -1", libc::timespec { tv_sec: -1, tv_nsec: 0 }),
        ] {
            report(&format!("recvmmsg({n})"), unsafe {
                libc::syscall(
                    libc::SYS_recvmmsg,
                    a,
                    vec.as_mut_ptr(),
                    1u32,
                    libc::MSG_DONTWAIT,
                    &ts as *const libc::timespec,
                )
            });
        }
        report("recvmmsg(timeout unmapped)", unsafe {
            libc::syscall(libc::SYS_recvmmsg, a, vec.as_mut_ptr(), 1u32, libc::MSG_DONTWAIT, 0x1000usize)
        });
        close2(a, b);
    }
}
