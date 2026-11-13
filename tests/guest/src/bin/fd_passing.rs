//! Passing descriptors over a unix socket with `SCM_RIGHTS`.
//!
//! This is how a process hands an open file, socket or pipe to another one:
//! socket activation, a supervisor giving a worker its listening socket, X11
//! and Wayland handing over buffers, dbus, and every "pass the connection to
//! the child" design.
//!
//! `sock_race` sends descriptors this way and passed throughout, which is worth
//! knowing about: it checks that the emulator survives concurrent sends and
//! that any descriptor which *does* arrive is the right one. It never checked
//! that one arrives. `sendmsg` returned success and the receiver got
//! `MSG_CTRUNC` and nothing else.

use guest_tests::{Harness, check, sys};

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn socketpair() -> Option<(i32, i32)> {
    let mut sv = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        return None;
    }
    Some((sv[0], sv[1]))
}

/// Sends `fds` alongside one byte of payload.
fn send_fds(sock: i32, fds: &[i32]) -> isize {
    let space = unsafe { libc::CMSG_SPACE((fds.len() * 4) as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    let mut data = b'x';
    let mut io = libc::iovec { iov_base: (&raw mut data).cast(), iov_len: 1 };
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &raw mut io;
    m.msg_iovlen = 1;
    m.msg_control = cbuf.as_mut_ptr().cast();
    m.msg_controllen = space as _;
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&m);
        if c.is_null() {
            return -1;
        }
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN((fds.len() * 4) as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c).cast::<i32>(), fds.len());
        libc::sendmsg(sock, &m, 0)
    }
}

/// Receives whatever descriptors arrive, plus the payload byte count and the
/// message flags the kernel reported.
fn recv_fds(sock: i32, room_for: usize) -> (isize, Vec<i32>, i32) {
    let space = unsafe { libc::CMSG_SPACE((room_for * 4) as u32) } as usize;
    recv_fds_bytes(sock, space)
}

/// The same, with the control buffer named in bytes rather than descriptors --
/// `CMSG_SPACE(n * 4)` rounds up, so asking for room for one descriptor
/// actually leaves room for two, and a truncation check has to say what it
/// means.
fn recv_fds_bytes(sock: i32, space: usize) -> (isize, Vec<i32>, i32) {
    recv_fds_flags(sock, space, 0)
}

/// The same again, with the recvmsg flags spelled out.
fn recv_fds_flags(sock: i32, space: usize, flags: libc::c_int) -> (isize, Vec<i32>, i32) {
    let mut cbuf = vec![0u8; space];
    let mut buf = [0u8; 8];
    let mut io = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &raw mut io;
    m.msg_iovlen = 1;
    m.msg_control = cbuf.as_mut_ptr().cast();
    m.msg_controllen = space as _;
    let n = unsafe { libc::recvmsg(sock, &mut m, flags) };
    let mut out = Vec::new();
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&m);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let payload = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let count = payload / 4;
                let p = libc::CMSG_DATA(c).cast::<i32>();
                for i in 0..count {
                    out.push(p.add(i).read_unaligned());
                }
            }
            c = libc::CMSG_NXTHDR(&m, c);
        }
    }
    (n, out, m.msg_flags)
}

/// How many descriptors this process has open, from /proc/self/fd.
///
/// A receiver whose control buffer is too small must not end up holding
/// descriptors it was never told the numbers of: they would be open, counted
/// against its limit, and impossible to close.
fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0)
}

/// What a descriptor refers to, so a received one can be compared with what
/// was sent rather than merely being a number.
fn ident(fd: i32) -> Option<(u64, u64)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } == 0 {
        Some((st.st_dev as u64, st.st_ino as u64))
    } else {
        None
    }
}

fn t_one_descriptor(h: &mut Harness, dir: &str) {
    h.group("one-fd");
    let Some((a, b)) = socketpair() else {
        check!(h, false, "socketpair");
        return;
    };
    let path = format!("{dir}/passed");
    let _ = std::fs::write(&path, b"contents!");
    let f = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_RDONLY, 0) };
    if f < 0 {
        check!(h, false, "opening the file to pass");
        return;
    }
    let want = ident(f);

    let n = send_fds(a, &[f]);
    check!(h, n == 1, "sendmsg with SCM_RIGHTS sent the payload: {n} errno {}", sys::errno());

    let (r, fds, flags) = recv_fds(b, 1);
    check!(h, r == 1, "recvmsg got the payload: {r}");
    check!(
        h,
        flags & libc::MSG_CTRUNC == 0,
        "and did not report the control message truncated, flags {flags:#x}"
    );
    check!(h, fds.len() == 1, "one descriptor arrived, got {}", fds.len());

    if let Some(&got) = fds.first() {
        check!(h, got != f, "and it is a new descriptor number, got {got} vs {f}");
        check!(
            h,
            ident(got) == want,
            "referring to the same file: {:?} vs {:?}",
            ident(got),
            want
        );
        // And it actually reads.
        let mut buf = [0u8; 9];
        let k = sys::read(got, &mut buf);
        check!(
            h,
            k == 9 && &buf == b"contents!",
            "and it reads the file's contents: {k} {:?}",
            String::from_utf8_lossy(&buf)
        );
        sys::close(got);
    }
    sys::close(f);
    sys::close(a);
    sys::close(b);
}

fn t_several_descriptors(h: &mut Harness, dir: &str) {
    h.group("several-fds");
    let Some((a, b)) = socketpair() else {
        check!(h, false, "socketpair");
        return;
    };
    let mut sent = Vec::new();
    let mut wanted = Vec::new();
    for i in 0..4 {
        let path = format!("{dir}/multi{i}");
        let _ = std::fs::write(&path, format!("file{i}"));
        let f = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_RDONLY, 0) };
        if f < 0 {
            check!(h, false, "opening {path}");
            return;
        }
        wanted.push(ident(f));
        sent.push(f);
    }

    let n = send_fds(a, &sent);
    check!(h, n == 1, "sending four descriptors at once: {n} errno {}", sys::errno());

    let (_, fds, flags) = recv_fds(b, 4);
    check!(
        h,
        flags & libc::MSG_CTRUNC == 0,
        "nothing was truncated, flags {flags:#x}"
    );
    check!(h, fds.len() == 4, "four arrived, got {}", fds.len());
    if fds.len() == 4 {
        let got: Vec<_> = fds.iter().map(|&f| ident(f)).collect();
        check!(
            h,
            got == wanted,
            "and in the order they were sent: {got:?} vs {wanted:?}"
        );
    }
    for f in fds {
        sys::close(f);
    }
    for f in sent {
        sys::close(f);
    }
    sys::close(a);
    sys::close(b);
}

/// A socket passed over a socket still works, which is the case the whole
/// mechanism exists for.
fn t_pass_a_socket(h: &mut Harness) {
    h.group("pass-a-socket");
    let Some((a, b)) = socketpair() else {
        check!(h, false, "socketpair");
        return;
    };
    let Some((x, y)) = socketpair() else {
        check!(h, false, "the socketpair to pass");
        return;
    };

    check!(h, send_fds(a, &[y]) == 1, "sending a socket");
    let (_, fds, _) = recv_fds(b, 1);
    check!(h, fds.len() == 1, "it arrived, got {}", fds.len());
    if let Some(&got) = fds.first() {
        // Write into the original half, read out of the received one.
        sys::write(x, b"through");
        let mut buf = [0u8; 7];
        let n = sys::read(got, &mut buf);
        check!(
            h,
            n == 7 && &buf == b"through",
            "and the received socket carries traffic: {n} {:?}",
            String::from_utf8_lossy(&buf)
        );
        sys::close(got);
    }
    sys::close(x);
    sys::close(y);
    sys::close(a);
    sys::close(b);
}

/// Too little room for the descriptors sent: what fits arrives and the message
/// is flagged truncated, rather than the receiver being told everything
/// arrived.
fn t_truncation(h: &mut Harness, dir: &str) {
    h.group("truncation");
    let Some((a, b)) = socketpair() else {
        check!(h, false, "socketpair");
        return;
    };
    let mut sent = Vec::new();
    for i in 0..3 {
        let path = format!("{dir}/trunc{i}");
        let _ = std::fs::write(&path, b"t");
        let f = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_RDONLY, 0) };
        if f < 0 {
            check!(h, false, "opening {path}");
            return;
        }
        sent.push(f);
    }
    check!(h, send_fds(a, &sent) == 1, "sending three");

    // CMSG_LEN(4) exactly: a header and one descriptor, no more.
    let one = unsafe { libc::CMSG_LEN(4) } as usize;
    let before = open_fd_count();
    let (_, fds, flags) = recv_fds_bytes(b, one);
    check!(
        h,
        flags & libc::MSG_CTRUNC != 0,
        "a receiver with room for one of three is told it was truncated, flags {flags:#x}"
    );
    check!(
        h,
        fds.len() == 1,
        "and gets exactly the one it had room for, got {}",
        fds.len()
    );
    // The two that did not fit must not have been installed. They would be
    // open descriptors the receiver was never told the numbers of -- counted
    // against its limit and impossible to close. The old receive path
    // installed every descriptor and then truncated the buffer.
    let after = open_fd_count();
    check!(
        h,
        after == before + fds.len(),
        "and the ones that did not fit were not installed: {before} -> {after} with {} reported",
        fds.len()
    );

    // A control buffer with room for no descriptor at all still reports the
    // truncation rather than silently dropping them.
    let Some((c, d)) = socketpair() else {
        check!(h, false, "socketpair");
        return;
    };
    let f = unsafe { libc::open(cstr(&format!("{dir}/trunc0")).as_ptr(), libc::O_RDONLY, 0) };
    if f >= 0 {
        check!(h, send_fds(c, &[f]) == 1, "sending one descriptor");
        let (_, none, flags) = recv_fds_bytes(d, 8);
        check!(
            h,
            none.is_empty() && flags & libc::MSG_CTRUNC != 0,
            "no room at all: nothing arrives and MSG_CTRUNC is set, got {} flags {flags:#x}",
            none.len()
        );
        sys::close(f);
    }
    sys::close(c);
    sys::close(d);
    for f in fds {
        sys::close(f);
    }
    for f in sent {
        sys::close(f);
    }
    sys::close(a);
    sys::close(b);
}

/// A descriptor that is not open must not be passable, and must not take the
/// emulator down on the way.
fn t_bad_descriptor(h: &mut Harness) {
    h.group("bad-fd");
    let Some((a, b)) = socketpair() else {
        check!(h, false, "socketpair");
        return;
    };
    let n = send_fds(a, &[9999]);
    check!(
        h,
        n < 0 && sys::errno() == libc::EBADF,
        "sending a descriptor that is not open is EBADF: {n} errno {}",
        sys::errno()
    );
    // And the socket still works afterwards.
    sys::write(a, b"ok");
    let mut buf = [0u8; 2];
    check!(
        h,
        sys::read(b, &mut buf) == 2 && &buf == b"ok",
        "and the socket still carries traffic"
    );
    sys::close(a);
    sys::close(b);
}

/// A descriptor sent before anyone has accepted the connection.
///
/// Peers are linked at accept in this emulator, so between `connect` and
/// `accept` a socket has no peer to queue a control message onto. `sendmsg`
/// waited for one, and a listener that simply stops accepting never ends that
/// wait -- the socket race probe hung in six runs out of eight once passing a
/// descriptor started working at all. Linux queues the message and lets
/// whoever accepts receive it.
fn t_send_before_accept(h: &mut Harness, dir: &str) {
    h.group("before-accept");
    let path = format!("{dir}/sock");
    let _ = std::fs::remove_file(&path);

    let listener = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    for (i, b) in path.as_bytes().iter().enumerate() {
        addr.sun_path[i] = *b as _;
    }
    let alen = std::mem::size_of::<libc::sockaddr_un>() as u32;
    if unsafe { libc::bind(listener, (&raw const addr).cast(), alen) } != 0
        || unsafe { libc::listen(listener, 8) } != 0
    {
        check!(h, false, "bind/listen on {path}: errno {}", sys::errno());
        return;
    }

    let client = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    check!(
        h,
        unsafe { libc::connect(client, (&raw const addr).cast(), alen) } == 0,
        "connect: errno {}",
        sys::errno()
    );

    // Nothing has accepted yet. This must not block.
    let payload = format!("{dir}/before-accept-file");
    let _ = std::fs::write(&payload, b"early");
    let f = unsafe { libc::open(cstr(&payload).as_ptr(), libc::O_RDONLY, 0) };
    let want = ident(f);
    let n = send_fds(client, &[f]);
    check!(
        h,
        n == 1,
        "sending a descriptor before accept returns rather than blocking: {n} errno {}",
        sys::errno()
    );

    // And neither must asking for the peer's credentials. getsockopt has no
    // blocking contract; this used to sleep on the same condition sendmsg did.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut clen = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            client,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut clen,
        )
    };
    check!(
        h,
        r == 0,
        "SO_PEERCRED before accept returns rather than blocking: {r} errno {}",
        sys::errno()
    );

    // Now accept, and the descriptor is there waiting.
    let server = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
    check!(h, server >= 0, "accept: errno {}", sys::errno());
    if server >= 0 {
        let (r, fds, flags) = recv_fds(server, 1);
        check!(h, r == 1, "the payload arrived: {r}");
        check!(
            h,
            fds.len() == 1,
            "and so did the descriptor sent before the accept, got {}",
            fds.len()
        );
        check!(
            h,
            flags & libc::MSG_CTRUNC == 0,
            "untruncated, flags {flags:#x}"
        );
        if let Some(&got) = fds.first() {
            check!(
                h,
                ident(got) == want,
                "referring to the right file: {:?} vs {:?}",
                ident(got),
                want
            );
            sys::close(got);
        }
        // Once both ends exist the credentials are known, which is the case
        // that matters and the one the wait was there for.
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut clen = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(
                server,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast(),
                &mut clen,
            )
        };
        check!(
            h,
            r == 0 && cred.pid == unsafe { libc::getpid() },
            "SO_PEERCRED after accept names the connecting process: {r} pid {} vs {}",
            cred.pid,
            unsafe { libc::getpid() }
        );
        sys::close(server);
    }
    sys::close(f);
    sys::close(client);
    sys::close(listener);
    let _ = std::fs::remove_file(&path);
}

/// The same shape with nobody ever accepting: the send must still return, and
/// closing must not leave the descriptors it carried held for ever.
fn t_never_accepted(h: &mut Harness, dir: &str) {
    h.group("never-accepted");
    let path = format!("{dir}/sock2");
    let _ = std::fs::remove_file(&path);
    let listener = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    for (i, b) in path.as_bytes().iter().enumerate() {
        addr.sun_path[i] = *b as _;
    }
    let alen = std::mem::size_of::<libc::sockaddr_un>() as u32;
    if unsafe { libc::bind(listener, (&raw const addr).cast(), alen) } != 0
        || unsafe { libc::listen(listener, 8) } != 0
    {
        check!(h, false, "bind/listen: errno {}", sys::errno());
        return;
    }

    let before = open_fd_count();
    for _ in 0..8 {
        let client = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if unsafe { libc::connect(client, (&raw const addr).cast(), alen) } != 0 {
            check!(h, false, "connect: errno {}", sys::errno());
            sys::close(client);
            break;
        }
        let f = unsafe { libc::open(cstr("/etc/hostname").as_ptr(), libc::O_RDONLY, 0) };
        // The point of the check: this returns.
        send_fds(client, &[f]);
        sys::close(f);
        sys::close(client);
    }
    let after = open_fd_count();
    check!(
        h,
        after <= before,
        "eight unaccepted sends leave nothing behind: {before} -> {after}"
    );
    sys::close(listener);
    let _ = std::fs::remove_file(&path);
}

/// `MSG_CMSG_CLOEXEC` asks for the descriptors this message carries to arrive
/// with the close-on-exec bit already set.
///
/// The gap it closes is a race, not a convenience: without it a receiver has to
/// call `fcntl(F_SETFD)` afterwards, and a `fork`+`exec` on another thread
/// between the two leaks the descriptor into the child. Every program that
/// passes descriptors for privilege separation asks for it -- systemd, dbus,
/// container runtimes -- because leaking the descriptor is the thing the
/// separation exists to prevent.
///
/// `sys_recvmsg` installed every received descriptor with `f_install(fd, 0)`
/// and never looked at the flag. It cannot be left to the host: the guest
/// descriptor number is this kernel's own, so the host's copy of the bit says
/// nothing about it.
fn t_cmsg_cloexec(h: &mut Harness) {
    h.group("cmsg-cloexec");
    const MSG_CMSG_CLOEXEC: libc::c_int = 0x4000_0000;

    let cloexec_of = |fd: i32| -> i32 {
        let r = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if r < 0 { -1 } else { r & libc::FD_CLOEXEC }
    };

    // The descriptor being passed deliberately does NOT have the bit set, so a
    // bit seen on the receiving side can only have come from the flag.
    let pass = |h: &mut Harness, flags: libc::c_int| -> Option<i32> {
        let (a, b) = socketpair()?;
        let (x, y) = socketpair()?;
        check!(h, cloexec_of(y) == 0, "the descriptor to pass has no FD_CLOEXEC");
        check!(h, send_fds(a, &[y]) == 1, "sending it");
        let space = unsafe { libc::CMSG_SPACE(4) } as usize;
        let (_, fds, _) = recv_fds_flags(b, space, flags);
        check!(h, fds.len() == 1, "it arrived, got {}", fds.len());
        sys::close(x);
        sys::close(y);
        sys::close(a);
        sys::close(b);
        fds.first().copied()
    };

    if let Some(got) = pass(h, MSG_CMSG_CLOEXEC) {
        check!(
            h,
            cloexec_of(got) == libc::FD_CLOEXEC,
            "received with MSG_CMSG_CLOEXEC has FD_CLOEXEC, F_GETFD says {}",
            unsafe { libc::fcntl(got, libc::F_GETFD) }
        );
        sys::close(got);
    }

    // The control: without the flag the bit must be clear, so the check above
    // is pinning the flag rather than a receiver that sets it unconditionally.
    if let Some(got) = pass(h, 0) {
        check!(
            h,
            cloexec_of(got) == 0,
            "received without it has no FD_CLOEXEC, F_GETFD says {}",
            unsafe { libc::fcntl(got, libc::F_GETFD) }
        );
        sys::close(got);
    }
}

/// A receiver whose descriptor table is full, which is where the install fails
/// **after** the message has been dequeued.
///
/// **The double release.** `f_install` consumes the reference however it ends —
/// it installs, or it releases and answers a negative errno — and the receive
/// path used to record `to_install = i` on that failure and then release from
/// index `i` onward, which is the one `f_install` had just released. So a
/// description the *sender* still holds had its count taken down twice:
/// finalized early, its host descriptor closed, and the sender left naming
/// freed memory.
///
/// What makes it observable is that the sender keeps its own copy. After the
/// failed receive it reads the file it passed; with the double release that
/// description has been finalized and the host descriptor closed.
///
/// **The table is filled with `dup`, not with `setrlimit`.** The first attempt
/// lowered `RLIMIT_NOFILE` to `open_fd_count()` and installed three anyway — a
/// limit is on descriptor *numbers* and there are free slots below the highest
/// one, so the table was not full at all. Both sides of `differential.sh`
/// failed it, by different amounts, which is what said the probe was wrong
/// rather than the kernel.
///
/// One slot is left open deliberately: that makes the first install succeed and
/// the second fail, so the run covers the failure *and* the tail the drain has
/// to release, rather than only the empty case.
fn t_receiver_with_no_room(h: &mut Harness, dir: &str) {
    h.group("no room");
    let Some((a, b)) = socketpair() else {
        check!(h, false, "socketpair");
        return;
    };

    let path = format!("{dir}/noroom");
    let _ = std::fs::write(&path, b"payload");
    let f = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_RDONLY, 0) };
    if f < 0 {
        check!(h, false, "opening {path}");
        return;
    }
    check!(h, send_fds(a, &[f, f, f]) == 1, "sending three of one file");

    // Fill it. `dup` of a descriptor that is already open needs no file.
    let mut filler = Vec::new();
    loop {
        let d = unsafe { libc::dup(f) };
        if d < 0 {
            break;
        }
        filler.push(d);
        if filler.len() > 100_000 {
            check!(h, false, "the table would not fill");
            break;
        }
    }
    if filler.len() < 2 {
        check!(h, false, "could not fill the table, only {} dups", filler.len());
        return;
    }
    // Room for exactly one.
    unsafe { libc::close(filler.pop().unwrap()) };

    let room = unsafe { libc::CMSG_LEN(12) } as usize;
    let (_, fds, flags) = recv_fds_bytes(b, room);

    check!(
        h,
        fds.len() == 1,
        "a table with one free slot installs one of three, got {}",
        fds.len()
    );
    check!(
        h,
        flags & libc::MSG_CTRUNC != 0,
        "and says the control message was truncated, flags {flags:#x}"
    );

    for d in fds {
        unsafe { libc::close(d) };
    }
    for d in filler {
        unsafe { libc::close(d) };
    }

    // The point. The sender's own descriptor must still be a descriptor.
    let mut buf = [0u8; 7];
    let n = unsafe { libc::read(f, buf.as_mut_ptr().cast(), buf.len()) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(
        h,
        n == 7 && &buf == b"payload",
        "the sender's copy survived a receive that could not install them all: \
         read {n} errno {e} {buf:?}"
    );
    unsafe { libc::close(f) };
    unsafe { libc::close(a) };
    unsafe { libc::close(b) };
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/fdpass".into());
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { libc::mkdir(cstr(&dir).as_ptr(), 0o755) };
    let mut h = Harness::new();
    t_one_descriptor(&mut h, &dir);
    t_several_descriptors(&mut h, &dir);
    t_pass_a_socket(&mut h);
    t_truncation(&mut h, &dir);
    t_bad_descriptor(&mut h);
    t_send_before_accept(&mut h, &dir);
    t_never_accepted(&mut h, &dir);
    t_cmsg_cloexec(&mut h);
    t_receiver_with_no_room(&mut h, &dir);
    std::process::exit(h.finish());
}
