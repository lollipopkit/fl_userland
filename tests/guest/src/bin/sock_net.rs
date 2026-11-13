//! TCP, UDP and socketpair, over loopback.
//!
//! `sock_semantics` covers AF_UNIX and the option table. This covers what a
//! server actually does: bind an ephemeral port, listen, accept, exchange
//! bytes, and get the errnos right when it cannot. ServerBox is a server, and
//! `fs/sock.c` is the largest file in the tree with the least coverage per
//! line.
//!
//! Every port is ephemeral — bind to 0 and read it back with `getsockname` —
//! so nothing here collides with the host or with a second run.

use guest_tests::{Harness, check, check_fails, sys};

const SOCK_NONBLOCK: i32 = 0o4000;
const SOCK_CLOEXEC: i32 = 0o2000000;

fn loopback(port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) },
        sin_zero: [0; 8],
    }
}

fn addr_len() -> libc::socklen_t {
    size_of::<libc::sockaddr_in>() as libc::socklen_t
}

/// Bind to an ephemeral port and report which one the kernel chose.
fn bind_ephemeral(fd: i32) -> Option<u16> {
    let a = loopback(0);
    if unsafe { libc::bind(fd, (&raw const a).cast(), addr_len()) } != 0 {
        return None;
    }
    let mut got: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = addr_len();
    if unsafe { libc::getsockname(fd, (&raw mut got).cast(), &mut len) } != 0 {
        return None;
    }
    Some(u16::from_be(got.sin_port))
}

/// A connected TCP pair over loopback: (server side, client side, listener).
fn tcp_pair() -> Option<(i32, i32, i32)> {
    let listener = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if listener < 0 {
        return None;
    }
    let one: i32 = 1;
    unsafe {
        libc::setsockopt(
            listener,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&raw const one).cast(),
            4,
        )
    };
    let port = bind_ephemeral(listener)?;
    if unsafe { libc::listen(listener, 8) } != 0 {
        unsafe { libc::close(listener) };
        return None;
    }
    let client = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let a = loopback(port);
    if unsafe { libc::connect(client, (&raw const a).cast(), addr_len()) } != 0 {
        unsafe {
            libc::close(client);
            libc::close(listener);
        }
        return None;
    }
    let server = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
    if server < 0 {
        unsafe {
            libc::close(client);
            libc::close(listener);
        }
        return None;
    }
    Some((server, client, listener))
}

fn t_socket_flags(h: &mut Harness) {
    h.group("socket-flags");
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | SOCK_CLOEXEC, 0) };
    check!(
        h,
        fd >= 0 && unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC != 0,
        "SOCK_CLOEXEC sets FD_CLOEXEC"
    );
    sys::close(fd);

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | SOCK_NONBLOCK, 0) };
    check!(
        h,
        fd >= 0 && unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0,
        "SOCK_NONBLOCK sets O_NONBLOCK"
    );
    sys::close(fd);

    // SO_TYPE reports what the socket was made as.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    let mut ty: i32 = -1;
    let mut len: libc::socklen_t = 4;
    let r = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE, (&raw mut ty).cast(), &mut len)
    };
    check!(
        h,
        r == 0 && ty == libc::SOCK_DGRAM,
        "SO_TYPE reports SOCK_DGRAM: r={r} type={ty}"
    );
    sys::close(fd);

    check_fails!(
        h,
        unsafe { libc::socket(libc::AF_INET, 0x1234, 0) } as i64,
        libc::EINVAL,
        "an unknown socket type"
    );
}

fn t_tcp_roundtrip(h: &mut Harness) {
    h.group("tcp");
    let Some((server, client, listener)) = tcp_pair() else {
        check!(h, false, "setting up a TCP pair");
        return;
    };

    check!(h, sys::write(client, b"ping") == 4, "client writes");
    let mut buf = [0u8; 16];
    let n = sys::read(server, &mut buf);
    check!(h, n == 4 && &buf[..4] == b"ping", "server reads it back: {n} {:?}", &buf[..4.min(n.max(0) as usize)]);
    check!(h, sys::write(server, b"pong") == 4, "server writes");
    let n = sys::read(client, &mut buf);
    check!(h, n == 4 && &buf[..4] == b"pong", "client reads it back");

    // getsockname and getpeername have to be each other's mirror.
    let mut sn: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut pn: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut l1 = addr_len();
    let mut l2 = addr_len();
    let a = unsafe { libc::getsockname(client, (&raw mut sn).cast(), &mut l1) };
    let b = unsafe { libc::getpeername(server, (&raw mut pn).cast(), &mut l2) };
    check!(h, a == 0 && b == 0, "getsockname and getpeername succeed: {a} {b}");
    check!(
        h,
        sn.sin_port == pn.sin_port && sn.sin_addr.s_addr == pn.sin_addr.s_addr,
        "the client's own address is the server's peer address: {} vs {}",
        u16::from_be(sn.sin_port),
        u16::from_be(pn.sin_port)
    );
    check!(
        h,
        l1 as usize == size_of::<libc::sockaddr_in>(),
        "and the length is written back, got {l1}"
    );

    // MSG_PEEK leaves the data where it was.
    sys::write(client, b"peek");
    let mut p1 = [0u8; 8];
    let n1 = unsafe { libc::recv(server, p1.as_mut_ptr().cast(), 8, libc::MSG_PEEK) };
    let mut p2 = [0u8; 8];
    let n2 = unsafe { libc::recv(server, p2.as_mut_ptr().cast(), 8, 0) };
    check!(
        h,
        n1 == 4 && n2 == 4 && p1[..4] == p2[..4],
        "MSG_PEEK does not consume: {n1} then {n2}"
    );

    // shutdown(SHUT_WR) is end-of-file for the peer, and the other direction
    // still works.
    check!(h, unsafe { libc::shutdown(client, libc::SHUT_WR) } == 0, "shutdown(SHUT_WR)");
    check!(h, sys::read(server, &mut buf) == 0, "the peer reads end of file");
    check!(h, sys::write(server, b"still") == 5, "and can still write the other way");
    check!(h, sys::read(client, &mut buf) == 5, "which the shut-down side reads");

    sys::close(server);
    sys::close(client);
    sys::close(listener);
}

fn t_tcp_errnos(h: &mut Harness) {
    h.group("tcp-errnos");

    // Connecting to a port nothing is listening on.
    let probe = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let port = bind_ephemeral(probe).unwrap_or(0);
    sys::close(probe); // and now nothing is there
    if port != 0 {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        let a = loopback(port);
        check_fails!(
            h,
            unsafe { libc::connect(fd, (&raw const a).cast(), addr_len()) } as i64,
            libc::ECONNREFUSED,
            "connecting to a closed port"
        );
        sys::close(fd);
    }

    // Two sockets on the same address without SO_REUSEADDR.
    let a1 = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if let Some(port) = bind_ephemeral(a1) {
        unsafe { libc::listen(a1, 4) };
        let a2 = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        let a = loopback(port);
        check_fails!(
            h,
            unsafe { libc::bind(a2, (&raw const a).cast(), addr_len()) } as i64,
            libc::EADDRINUSE,
            "binding a port that is already listening"
        );
        sys::close(a2);
    } else {
        check!(h, false, "binding for the EADDRINUSE check");
    }
    sys::close(a1);

    // Reading from a socket that was never connected.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let mut buf = [0u8; 4];
    check_fails!(
        h,
        unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), 4, 0) },
        libc::ENOTCONN,
        "receiving on an unconnected stream socket"
    );
    check_fails!(
        h,
        unsafe { libc::shutdown(fd, libc::SHUT_RDWR) } as i64,
        libc::ENOTCONN,
        "shutting down an unconnected socket"
    );
    // getpeername has nothing to report.
    let mut pn: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut l = addr_len();
    check_fails!(
        h,
        unsafe { libc::getpeername(fd, (&raw mut pn).cast(), &mut l) } as i64,
        libc::ENOTCONN,
        "getpeername on an unconnected socket"
    );
    // listen() needs a bound socket to be useful but not to succeed; accept
    // on one that never listened is EINVAL.
    check_fails!(
        h,
        unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) } as i64,
        libc::EINVAL,
        "accepting on a socket that is not listening"
    );
    sys::close(fd);
}

fn t_repeated_listen(h: &mut Harness) {
    h.group("repeated-listen");
    for round in 0..64 {
        let listener = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        let Some(_) = bind_ephemeral(listener) else {
            check!(h, false, "round {round}: bind listener");
            sys::close(listener);
            return;
        };
        check!(h, unsafe { libc::listen(listener, 1) } == 0,
            "round {round}: first listen: errno {}", sys::errno());
        check!(h, unsafe { libc::listen(listener, 16) } == 0,
            "round {round}: second listen updates backlog: errno {}", sys::errno());
        sys::close(listener);
    }
}

fn t_accept4(h: &mut Harness) {
    h.group("accept4");
    let listener = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let Some(port) = bind_ephemeral(listener) else {
        check!(h, false, "binding for accept4");
        return;
    };
    unsafe { libc::listen(listener, 4) };
    let client = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let a = loopback(port);
    check!(
        h,
        unsafe { libc::connect(client, (&raw const a).cast(), addr_len()) } == 0,
        "connecting"
    );
    let server = unsafe {
        libc::syscall(
            libc::SYS_accept4,
            listener,
            std::ptr::null_mut::<libc::sockaddr>(),
            std::ptr::null_mut::<libc::socklen_t>(),
            SOCK_NONBLOCK | SOCK_CLOEXEC,
        ) as i32
    };
    check!(h, server >= 0, "accept4 returned {server} errno {}", sys::errno());
    if server >= 0 {
        check!(
            h,
            unsafe { libc::fcntl(server, libc::F_GETFL) } & libc::O_NONBLOCK != 0,
            "SOCK_NONBLOCK reached the accepted socket"
        );
        check!(
            h,
            unsafe { libc::fcntl(server, libc::F_GETFD) } & libc::FD_CLOEXEC != 0,
            "and so did SOCK_CLOEXEC"
        );
        // Non-blocking: nothing to read yet.
        let mut buf = [0u8; 4];
        check_fails!(
            h,
            sys::read(server, &mut buf) as i64,
            libc::EAGAIN,
            "and it is really non-blocking"
        );
        sys::close(server);
    }
    sys::close(client);
    sys::close(listener);
}

fn t_udp(h: &mut Harness) {
    h.group("udp");
    let rx = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    let Some(port) = bind_ephemeral(rx) else {
        check!(h, false, "binding a UDP socket");
        return;
    };
    let tx = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    let to = loopback(port);

    // Two datagrams, and their boundaries survive.
    let n = unsafe {
        libc::sendto(tx, b"one".as_ptr().cast(), 3, 0, (&raw const to).cast(), addr_len())
    };
    check!(h, n == 3, "sending the first datagram: {n}");
    let n = unsafe {
        libc::sendto(tx, b"twotwo".as_ptr().cast(), 6, 0, (&raw const to).cast(), addr_len())
    };
    check!(h, n == 6, "sending the second: {n}");

    let mut buf = [0u8; 64];
    let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut flen = addr_len();
    let n = unsafe {
        libc::recvfrom(rx, buf.as_mut_ptr().cast(), 64, 0, (&raw mut from).cast(), &mut flen)
    };
    check!(
        h,
        n == 3 && &buf[..3] == b"one",
        "the first datagram arrives whole: {n}"
    );
    check!(
        h,
        from.sin_addr.s_addr == u32::from_ne_bytes([127, 0, 0, 1]) && from.sin_port != 0,
        "recvfrom reports the sender"
    );
    let n = unsafe { libc::recvfrom(rx, buf.as_mut_ptr().cast(), 64, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
    check!(
        h,
        n == 6 && &buf[..6] == b"twotwo",
        "and the second is a separate datagram, not appended: {n}"
    );

    sys::close(tx);
    sys::close(rx);
}

fn t_socketpair(h: &mut Harness) {
    h.group("socketpair");
    let mut sv = [0i32; 2];
    let r = unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr())
    };
    check!(h, r == 0, "socketpair returned {r}");
    if r != 0 {
        return;
    }
    check!(h, sys::write(sv[0], b"a") == 1, "writing one way");
    let mut buf = [0u8; 4];
    check!(h, sys::read(sv[1], &mut buf) == 1 && buf[0] == b'a', "reading it");
    check!(h, sys::write(sv[1], b"b") == 1, "and the other way");
    check!(h, sys::read(sv[0], &mut buf) == 1 && buf[0] == b'b', "reading that");
    sys::close(sv[0]);
    sys::close(sv[1]);

    let mut sv = [0i32; 2];
    let r = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    };
    check!(
        h,
        r == 0
            && unsafe { libc::fcntl(sv[0], libc::F_GETFD) } & libc::FD_CLOEXEC != 0
            && unsafe { libc::fcntl(sv[1], libc::F_GETFD) } & libc::FD_CLOEXEC != 0,
        "SOCK_CLOEXEC sets it on both ends"
    );
    if r == 0 {
        sys::close(sv[0]);
        sys::close(sv[1]);
    }

    check_fails!(
        h,
        unsafe { libc::socketpair(libc::AF_INET, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } as i64,
        libc::EOPNOTSUPP,
        "socketpair of an AF_INET pair"
    );
}

/// sendmsg and recvmsg with more than one iovec: the bytes are one stream and
/// the vectors are just where they come from and go to.
fn t_scatter_gather(h: &mut Harness) {
    h.group("iovec");
    let Some((server, client, listener)) = tcp_pair() else {
        check!(h, false, "setting up a TCP pair");
        return;
    };

    let a = b"hello";
    let b = b"world";
    let mut iov = [
        libc::iovec { iov_base: a.as_ptr() as *mut _, iov_len: 5 },
        libc::iovec { iov_base: b.as_ptr() as *mut _, iov_len: 5 },
    ];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_mut_ptr();
    msg.msg_iovlen = 2;
    let n = unsafe { libc::sendmsg(client, &msg, 0) };
    check!(h, n == 10, "sendmsg of two vectors sends both: {n}");

    let mut r1 = [0u8; 4];
    let mut r2 = [0u8; 6];
    let mut riov = [
        libc::iovec { iov_base: r1.as_mut_ptr().cast(), iov_len: 4 },
        libc::iovec { iov_base: r2.as_mut_ptr().cast(), iov_len: 6 },
    ];
    let mut rmsg: libc::msghdr = unsafe { std::mem::zeroed() };
    rmsg.msg_iov = riov.as_mut_ptr();
    rmsg.msg_iovlen = 2;
    let n = unsafe { libc::recvmsg(server, &mut rmsg, libc::MSG_WAITALL) };
    check!(
        h,
        n == 10 && &r1 == b"hell" && &r2 == b"oworld",
        "recvmsg fills the vectors in order: {n} {:?} {:?}",
        std::str::from_utf8(&r1),
        std::str::from_utf8(&r2)
    );

    sys::close(server);
    sys::close(client);
    sys::close(listener);
}

/// The way an event loop connects: set O_NONBLOCK, call connect, expect
/// EINPROGRESS, wait for POLLOUT, then ask SO_ERROR whether it worked.
///
/// Getting this wrong does not slow a program down, it hangs it — libuv,
/// Go's net package and every reactor do exactly this and nothing else.
fn t_nonblocking_connect(h: &mut Harness) {
    h.group("connect-nonblock");

    let listener = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let Some(port) = bind_ephemeral(listener) else {
        check!(h, false, "binding a listener");
        return;
    };
    unsafe { libc::listen(listener, 8) };

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | SOCK_NONBLOCK, 0) };
    let a = loopback(port);
    let r = unsafe { libc::connect(fd, (&raw const a).cast(), addr_len()) };
    let e = sys::errno();
    // Loopback can complete immediately; both are correct.
    check!(
        h,
        r == 0 || (r == -1 && e == libc::EINPROGRESS),
        "a non-blocking connect is 0 or EINPROGRESS: r={r} errno={e}"
    );

    let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
    let n = unsafe { libc::poll(&mut p, 1, 2000) };
    check!(
        h,
        n == 1 && p.revents & libc::POLLOUT != 0,
        "it becomes writable: n={n} revents={:#x}",
        p.revents
    );

    let mut err: i32 = -1;
    let mut len: libc::socklen_t = 4;
    let g = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, (&raw mut err).cast(), &mut len)
    };
    check!(
        h,
        g == 0 && err == 0,
        "SO_ERROR says it succeeded: g={g} err={err}"
    );
    // And SO_ERROR is consumed by the read, as on Linux.
    let mut again: i32 = -1;
    unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, (&raw mut again).cast(), &mut len)
    };
    check!(h, again == 0, "and stays clear, got {again}");

    // Connecting again once connected.
    //
    // The first of these returns *0*, not EISCONN. Linux's
    // inet_stream_connect moves the socket from SS_CONNECTING to SS_CONNECTED
    // on the call that finds it established, and that call succeeds -- which
    // is why calling connect() again is a documented way to collect the result
    // of a non-blocking connect, alongside getsockopt(SO_ERROR). Only the call
    // after it gets EISCONN.
    //
    // This asserted EISCONN for the first one, which is what Darwin answers,
    // and passed here for that reason. Code that uses the idiom reads EISCONN
    // as a failure and gives up on a connection that was fine.
    let collect = unsafe { libc::connect(fd, (&raw const a).cast(), addr_len()) };
    check!(h, collect == 0,
        "connecting again collects the non-blocking result: {collect} errno {}",
        sys::errno());
    check_fails!(
        h,
        unsafe { libc::connect(fd, (&raw const a).cast(), addr_len()) } as i64,
        libc::EISCONN,
        "and the call after that is EISCONN"
    );

    let server = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
    check!(h, server >= 0, "the connection was really accepted");
    sys::close(server);
    sys::close(fd);
    sys::close(listener);
}

/// A non-blocking connect that fails has to report it through SO_ERROR, not
/// through the connect call, because the call already returned.
fn t_nonblocking_connect_refused(h: &mut Harness) {
    h.group("connect-refused");
    let probe = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let Some(port) = bind_ephemeral(probe) else {
        check!(h, false, "finding a free port");
        return;
    };
    sys::close(probe);

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | SOCK_NONBLOCK, 0) };
    let a = loopback(port);
    let r = unsafe { libc::connect(fd, (&raw const a).cast(), addr_len()) };
    let e = sys::errno();
    check!(
        h,
        r == -1 && (e == libc::EINPROGRESS || e == libc::ECONNREFUSED),
        "connect to a closed port: r={r} errno={e}"
    );
    if e == libc::EINPROGRESS {
        // The failure arrives later, and the socket becomes writable to say so.
        let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
        let n = unsafe { libc::poll(&mut p, 1, 2000) };
        check!(h, n == 1, "it becomes ready to report the failure: n={n}");
        let mut err: i32 = 0;
        let mut len: libc::socklen_t = 4;
        unsafe {
            libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, (&raw mut err).cast(), &mut len)
        };
        check!(
            h,
            err == libc::ECONNREFUSED,
            "and SO_ERROR names the failure, got {err}"
        );
    }
    sys::close(fd);
}

fn t_nonblocking_accept_and_recv(h: &mut Harness) {
    h.group("nonblock-misc");
    let listener = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | SOCK_NONBLOCK, 0) };
    if bind_ephemeral(listener).is_none() {
        check!(h, false, "binding");
        return;
    }
    unsafe { libc::listen(listener, 4) };
    check_fails!(
        h,
        unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) } as i64,
        libc::EAGAIN,
        "accept with nothing pending on a non-blocking listener"
    );
    sys::close(listener);

    // MSG_DONTWAIT on a blocking socket.
    let Some((server, client, l)) = tcp_pair() else {
        check!(h, false, "TCP pair");
        return;
    };
    let mut buf = [0u8; 4];
    check_fails!(
        h,
        unsafe { libc::recv(server, buf.as_mut_ptr().cast(), 4, libc::MSG_DONTWAIT) },
        libc::EAGAIN,
        "MSG_DONTWAIT on an empty socket"
    );
    sys::close(server);
    sys::close(client);
    sys::close(l);
}

/// A connected datagram socket: send/recv without an address, and datagrams
/// from anyone else are not delivered.
fn t_udp_connected(h: &mut Harness) {
    h.group("udp-connected");
    let rx = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    let Some(rx_port) = bind_ephemeral(rx) else {
        check!(h, false, "binding the receiver");
        return;
    };
    let tx = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    let Some(_) = bind_ephemeral(tx) else {
        check!(h, false, "binding the sender");
        return;
    };
    let to = loopback(rx_port);
    check!(
        h,
        unsafe { libc::connect(tx, (&raw const to).cast(), addr_len()) } == 0,
        "connecting a datagram socket"
    );
    check!(h, sys::write(tx, b"conn") == 4, "send without an address");
    let mut buf = [0u8; 16];
    let n = sys::read(rx, &mut buf);
    check!(h, n == 4 && &buf[..4] == b"conn", "it arrives: {n}");

    // getpeername now has an answer.
    let mut pn: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut l = addr_len();
    check!(
        h,
        unsafe { libc::getpeername(tx, (&raw mut pn).cast(), &mut l) } == 0
            && u16::from_be(pn.sin_port) == rx_port,
        "getpeername reports the connected address"
    );

    sys::close(tx);
    sys::close(rx);
}

fn t_buffers(h: &mut Harness) {
    h.group("sockbuf");
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    for (opt, name) in [(libc::SO_SNDBUF, "SO_SNDBUF"), (libc::SO_RCVBUF, "SO_RCVBUF")] {
        let mut v: i32 = 0;
        let mut len: libc::socklen_t = 4;
        let r = unsafe {
            libc::getsockopt(fd, libc::SOL_SOCKET, opt, (&raw mut v).cast(), &mut len)
        };
        check!(h, r == 0 && v > 0, "{name} reports a size: r={r} v={v}");
    }
    let one: i32 = 1;
    let r = unsafe {
        libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, (&raw const one).cast(), 4)
    };
    check!(h, r == 0, "TCP_NODELAY can be set: {r}");
    let mut v: i32 = 0;
    let mut len: libc::socklen_t = 4;
    let g = unsafe {
        libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, (&raw mut v).cast(), &mut len)
    };
    check!(h, g == 0 && v != 0, "and reads back set: g={g} v={v}");
    sys::close(fd);
}

/// IPv6 over loopback. A server that binds `::` and a client that reaches it
/// on `::1` is the default shape of anything modern.
fn t_ipv6(h: &mut Harness) {
    h.group("ipv6");
    let listener = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    if listener < 0 {
        println!("  SKIP  [ipv6] AF_INET6 is not available: errno {}", sys::errno());
        return;
    }
    let mut a: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    a.sin6_family = libc::AF_INET6 as u16;
    a.sin6_addr = libc::in6_addr { s6_addr: [0; 16] };
    a.sin6_addr.s6_addr[15] = 1; // ::1
    let alen = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    let r = unsafe { libc::bind(listener, (&raw const a).cast(), alen) };
    check!(h, r == 0, "binding ::1 with an ephemeral port: {r} errno {}", sys::errno());
    if r != 0 {
        sys::close(listener);
        return;
    }
    let mut got: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut glen = alen;
    check!(
        h,
        unsafe { libc::getsockname(listener, (&raw mut got).cast(), &mut glen) } == 0
            && got.sin6_family == libc::AF_INET6 as u16,
        "getsockname reports an AF_INET6 address"
    );
    check!(h, unsafe { libc::listen(listener, 4) } == 0, "listen");

    let client = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    let mut to = a;
    to.sin6_port = got.sin6_port;
    check!(
        h,
        unsafe { libc::connect(client, (&raw const to).cast(), alen) } == 0,
        "connecting over IPv6: errno {}",
        sys::errno()
    );
    let server = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
    check!(h, server >= 0, "accepting it");
    if server >= 0 {
        check!(h, sys::write(client, b"v6") == 2, "writing");
        let mut buf = [0u8; 4];
        check!(h, sys::read(server, &mut buf) == 2 && &buf[..2] == b"v6", "reading");
        sys::close(server);
    }
    sys::close(client);
    sys::close(listener);
}

/// The Linux abstract namespace: a sun_path whose first byte is NUL names a
/// socket with no filesystem entry, and the name is the remaining bytes of the
/// address as given — embedded NULs and all, and *not* NUL-terminated.
fn t_abstract_unix(h: &mut Harness) {
    h.group("unix-abstract");
    let listener = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if listener < 0 {
        check!(h, false, "AF_UNIX socket");
        return;
    }
    let name = b"\0shellbox-abstract-probe";
    let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    a.sun_family = libc::AF_UNIX as u16;
    for (slot, &b) in a.sun_path.iter_mut().zip(name.iter()) {
        *slot = b as libc::c_char;
    }
    // The length is what says where the name ends: sizeof(sun_family) + len.
    let alen = (2 + name.len()) as libc::socklen_t;
    let r = unsafe { libc::bind(listener, (&raw const a).cast(), alen) };
    if r != 0 {
        println!("  SKIP  [unix-abstract] bind failed: errno {}", sys::errno());
        sys::close(listener);
        return;
    }
    check!(h, true, "binding an abstract name");
    check!(h, unsafe { libc::listen(listener, 4) } == 0, "listen");

    let client = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    check!(
        h,
        unsafe { libc::connect(client, (&raw const a).cast(), alen) } == 0,
        "connecting to it: errno {}",
        sys::errno()
    );
    let server = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
    check!(h, server >= 0, "accepting");
    if server >= 0 {
        check!(h, sys::write(client, b"abs") == 3, "writing");
        let mut buf = [0u8; 8];
        check!(h, sys::read(server, &mut buf) == 3 && &buf[..3] == b"abs", "reading");
        sys::close(server);
    }
    // No filesystem entry was made for it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    check!(
        h,
        unsafe { libc::stat(c"/shellbox-abstract-probe".as_ptr(), &mut st) } != 0,
        "an abstract name leaves nothing on the filesystem"
    );
    sys::close(client);
    sys::close(listener);
}

/// More bytes than fit in the socket buffer, so the write is partial and the
/// reader has to keep up.
fn t_large_transfer(h: &mut Harness) {
    h.group("bulk");
    let Some((server, client, listener)) = tcp_pair() else {
        check!(h, false, "TCP pair");
        return;
    };
    const TOTAL: usize = 1 << 20; // 1 MiB, well past any socket buffer

    let reader = std::thread::spawn(move || {
        let mut got = 0usize;
        let mut buf = vec![0u8; 64 * 1024];
        let mut ok = true;
        while got < TOTAL {
            let n = sys::read(server, &mut buf);
            if n <= 0 {
                break;
            }
            for (i, &b) in buf[..n as usize].iter().enumerate() {
                if b != ((got + i) % 251) as u8 {
                    ok = false;
                }
            }
            got += n as usize;
        }
        (got, ok)
    });

    let mut sent = 0usize;
    let chunk: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    while sent < TOTAL {
        // The pattern is position-dependent, so each chunk starts where the
        // last left off.
        let start = sent % 251;
        let body: Vec<u8> = (0..chunk.len().min(TOTAL - sent))
            .map(|i| ((start + i) % 251) as u8)
            .collect();
        let n = sys::write(client, &body);
        if n <= 0 {
            break;
        }
        sent += n as usize;
    }
    check!(h, sent == TOTAL, "wrote a megabyte: {sent}");
    let (got, ok) = reader.join().unwrap_or((0, false));
    check!(h, got == TOTAL, "and read it all back: {got}");
    check!(h, ok, "with every byte where it belongs");

    sys::close(client);
    sys::close(listener);
}

/// How short an address may be.
///
/// Linux checks a *minimum* per family and it is not `sizeof` in either case
/// that matters here:
///
/// - `inet_bind` refuses below `sizeof(struct sockaddr_in)`, 16.
/// - `inet6_bind` refuses below `SIN6_LEN_RFC2133`, **24** -- the size the
///   original IPv6 API had, before `sin6_scope_id` was added. A caller passing
///   24 is passing an address without a scope id, which is a whole address for
///   anything that is not link-local.
///
/// This kernel required `sizeof(struct sockaddr_in6)`, 28, for the second, so
/// a program built against the older shape was refused.
fn t_address_length(h: &mut Harness) {
    h.group("sockaddr-length");
    unsafe {
        // IPv4: 15 is short, 16 is enough.
        let mut a4: libc::sockaddr_in = std::mem::zeroed();
        a4.sin_family = libc::AF_INET as _;
        a4.sin_addr.s_addr = u32::to_be(0x7f000001);
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        check_fails!(
            h,
            libc::bind(fd, (&raw const a4).cast(), 15),
            libc::EINVAL,
            "an IPv4 address one byte short"
        );
        let r = libc::bind(fd, (&raw const a4).cast(), 16);
        check!(h, r == 0, "and sixteen bytes is enough: errno {}", sys::errno());
        libc::close(fd);

        // IPv6: 23 is short, 24 -- SIN6_LEN_RFC2133, without sin6_scope_id --
        // is enough, and so is the full 28.
        let mut a6: libc::sockaddr_in6 = std::mem::zeroed();
        a6.sin6_family = libc::AF_INET6 as _;
        a6.sin6_addr = libc::in6addr_loopback;
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        if fd >= 0 {
            check_fails!(
                h,
                libc::bind(fd, (&raw const a6).cast(), 23),
                libc::EINVAL,
                "an IPv6 address below SIN6_LEN_RFC2133"
            );
            let r = libc::bind(fd, (&raw const a6).cast(), 24);
            check!(h, r == 0, "and twenty-four is enough: errno {}", sys::errno());
            libc::close(fd);
            let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
            let r = libc::bind(fd, (&raw const a6).cast(), 28);
            check!(h, r == 0, "as is the whole struct: errno {}", sys::errno());
            libc::close(fd);
        }

        // Longer than the struct is fine too: Linux checks a minimum and
        // ignores the rest. Darwin does not -- in_pcbbind refuses `sa_len !=
        // sizeof` -- so the translation has to normalise, which is the other
        // half of the same rule.
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let r = libc::bind(fd, (&raw const a4).cast(), 20);
        check!(h, r == 0, "an IPv4 address with trailing bytes: errno {}", sys::errno());
        libc::close(fd);

        // Two bytes is the family and nothing else, which is EINVAL for an
        // internet address in either family -- unlike AF_UNIX, where bind
        // reads it as an autobind.
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        check_fails!(
            h,
            libc::bind(fd, (&raw const a4).cast(), 2),
            libc::EINVAL,
            "the family alone, for AF_INET"
        );
        libc::close(fd);
    }
}

/// The buffer `getsockopt` is given, when it is not exactly the option's size.
///
/// Linux's `sock_getsockopt` computes the option's own length `lv`, then
/// `if (len > lv) len = lv;` and copies `len` bytes — so a **larger** buffer is
/// filled to the option's size and told so, and a **smaller** one gets a
/// truncated value and is told that. The only refusal is a negative length.
///
/// This kernel answered `EINVAL` for anything that was not exactly the size,
/// in both directions. `getsockopt(fd, SOL_SOCKET, SO_TYPE, &buf, &len)` with
/// `len = sizeof(long)` — which is what a caller reusing one buffer for several
/// options does — failed.
fn t_getsockopt_lengths(h: &mut Harness) {
    h.group("getsockopt-length");
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            check!(h, false, "a socket to ask about");
            return;
        }

        // Bigger than the option: filled to four bytes and told four.
        let mut buf = [0u8; 32];
        let mut len: libc::socklen_t = 8;
        let r = libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE,
                                 buf.as_mut_ptr().cast(), &mut len);
        check!(h, r == 0, "SO_TYPE into an eight-byte buffer: errno {}", sys::errno());
        check!(h, len == 4, "and the length comes back as the option's: {len}");
        check!(
            h,
            i32::from_ne_bytes(buf[..4].try_into().unwrap()) == libc::SOCK_STREAM,
            "with the right value"
        );

        // Smaller: truncated, and told how much.
        let mut len: libc::socklen_t = 2;
        let r = libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE,
                                 buf.as_mut_ptr().cast(), &mut len);
        check!(
            h,
            r == 0 && len == 2,
            "SO_TYPE into two bytes is truncated, not refused: r={r} len={len} errno {}",
            sys::errno()
        );

        // SO_ERROR the same way.
        let mut len: libc::socklen_t = 8;
        let r = libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR,
                                 buf.as_mut_ptr().cast(), &mut len);
        check!(h, r == 0 && len == 4, "SO_ERROR into eight bytes: r={r} len={len}");

        // And a negative length is the one refusal: `socklen_t` is unsigned
        // here and signed in the kernel, so this arrives as -1.
        let mut len: libc::socklen_t = u32::MAX;
        check_fails!(
            h,
            libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE,
                             buf.as_mut_ptr().cast(), &mut len),
            libc::EINVAL,
            "a length that reads as negative"
        );
        libc::close(fd);
    }

    // SO_PEERCRED, which is twelve bytes and has the same rule.
    unsafe {
        let mut pair = [0i32; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) != 0 {
            return;
        }
        let mut buf = [0u8; 64];
        let mut len: libc::socklen_t = 32;
        let r = libc::getsockopt(pair[0], libc::SOL_SOCKET, libc::SO_PEERCRED,
                                 buf.as_mut_ptr().cast(), &mut len);
        check!(h, r == 0, "SO_PEERCRED into a large buffer: errno {}", sys::errno());
        check!(h, len == 12, "and told the struct's size: {len}");
        libc::close(pair[0]);
        libc::close(pair[1]);
    }
}

fn main() {
    let mut h = Harness::new();
    t_address_length(&mut h);
    t_getsockopt_lengths(&mut h);
    t_socket_flags(&mut h);
    t_tcp_roundtrip(&mut h);
    t_tcp_errnos(&mut h);
    t_repeated_listen(&mut h);
    t_accept4(&mut h);
    t_udp(&mut h);
    t_socketpair(&mut h);
    t_scatter_gather(&mut h);
    t_nonblocking_connect(&mut h);
    t_nonblocking_connect_refused(&mut h);
    t_nonblocking_accept_and_recv(&mut h);
    t_udp_connected(&mut h);
    t_buffers(&mut h);
    t_ipv6(&mut h);
    t_abstract_unix(&mut h);
    t_large_transfer(&mut h);
    t_netlink(&mut h);
    std::process::exit(h.finish());
}

/// `AF_NETLINK`: the interface dump, which is how a Linux program enumerates.
///
/// `socket(AF_NETLINK, ...)` answered `EAFNOSUPPORT` until 2026-09-08, so
/// **`net.Interfaces()` in Go failed outright** — the runtime has no fallback.
/// What is checked here is the dump's shape, because that is what a reader
/// parses: a header whose length includes itself, `NLM_F_MULTI` on every
/// message, and an `NLMSG_DONE` at the end. A dump without the last one leaves
/// a reader waiting for a message that never comes.
fn t_netlink(h: &mut Harness) {
    const PF_NETLINK: i32 = 16;
    const NETLINK_ROUTE: i32 = 0;
    const RTM_GETLINK: u16 = 18;
    const RTM_NEWLINK: u16 = 16;
    const NLMSG_DONE: u16 = 3;
    const NLMSG_ERROR: u16 = 2;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_MULTI: u16 = 2;
    const NLM_F_DUMP: u16 = 0x300;

    h.group("netlink");

    let fd = unsafe { libc::socket(PF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
    check!(h, fd >= 0, "socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE): {fd}");
    if fd < 0 {
        return;
    }
    // The same with SOCK_CLOEXEC, which is what Go asks for -- and what the
    // first version of this refused, because it masked the type with the
    // complement of the type mask rather than the mask.
    let fd2 = unsafe { libc::socket(PF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_ROUTE) };
    check!(h, fd2 >= 0, "and with SOCK_CLOEXEC, which is what Go sends: {fd2}");
    if fd2 >= 0 {
        unsafe { libc::close(fd2) };
    }
    // A protocol number **nobody** defines -- Linux's MAX_LINKS is 32 -- rather
    // than one this kernel merely does not carry. The first version used 15,
    // NETLINK_KOBJECT_UEVENT, and a real kernel accepted it: that check was
    // asserting this kernel's limitation as if it were the ABI, which is the
    // shape `CLAUDE.md` calls a test restating its subject. What is worth
    // asserting is that an unknown protocol is *refused* rather than accepted
    // and silent, because a program that opens one and waits would wait for
    // ever.
    sys::clear_errno();
    let bad = unsafe { libc::socket(PF_NETLINK, libc::SOCK_RAW, 99) };
    check!(h, bad < 0, "a netlink protocol nobody defines is refused: {bad}");
    if bad >= 0 {
        unsafe { libc::close(bad) };
    }

    // sockaddr_nl: family, pad, pid, groups.
    let mut sa = [0u8; 12];
    sa[..2].copy_from_slice(&(PF_NETLINK as u16).to_le_bytes());
    let bound = unsafe { libc::bind(fd, sa.as_ptr().cast(), sa.len() as u32) };
    check!(h, bound == 0, "bind a sockaddr_nl: {bound}");

    // RTM_GETLINK as a dump: nlmsghdr then an ifinfomsg of zeros.
    let mut req = [0u8; 16 + 16];
    let req_len = req.len() as u32;
    req[0..4].copy_from_slice(&req_len.to_le_bytes());
    req[4..6].copy_from_slice(&RTM_GETLINK.to_le_bytes());
    req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_le_bytes());
    req[8..12].copy_from_slice(&1u32.to_le_bytes());
    let sent = unsafe { libc::send(fd, req.as_ptr().cast(), req.len(), 0) };
    check!(h, sent == req.len() as isize, "send the request: {sent}");

    // Read until NLMSG_DONE, as a reader does.
    let mut links = 0;
    let mut done = false;
    let mut multi_on_all = true;
    for _ in 0..64 {
        let mut buf = [0u8; 65536];
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            break;
        }
        let mut at = 0usize;
        while at + 16 <= n as usize {
            let len = u32::from_le_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
            if len < 16 || at + len > n as usize {
                break;
            }
            let kind = u16::from_le_bytes(buf[at + 4..at + 6].try_into().unwrap());
            let flags = u16::from_le_bytes(buf[at + 6..at + 8].try_into().unwrap());
            if flags & NLM_F_MULTI == 0 {
                multi_on_all = false;
            }
            if kind == RTM_NEWLINK {
                links += 1;
            }
            if kind == NLMSG_DONE {
                done = true;
            }
            at += (len + 3) & !3;
        }
        if done {
            break;
        }
    }
    check!(h, links >= 1, "the dump has at least one interface: {links}");
    check!(h, done, "and ends with NLMSG_DONE, which is what stops a reader");
    check!(h, multi_on_all, "every message carries NLM_F_MULTI");

    // The sender is the kernel, and a reader checks it: busybox `ip` refuses a
    // dump whose sender address is not a 12-byte sockaddr_nl.
    let mut from = [0u8; 32];
    let mut from_len = from.len() as u32;
    let mut buf = [0u8; 4096];
    let sent = unsafe { libc::send(fd, req.as_ptr().cast(), req.len(), 0) };
    check!(h, sent > 0, "a second request");
    let n = unsafe {
        libc::recvfrom(fd, buf.as_mut_ptr().cast(), buf.len(), 0,
                       from.as_mut_ptr().cast(), &mut from_len)
    };
    check!(h, n > 0, "and its reply: {n}");
    check!(h, from_len == 12, "whose sender is a sockaddr_nl: {from_len}");
    check!(
        h,
        u16::from_le_bytes(from[..2].try_into().unwrap()) == PF_NETLINK as u16,
        "of family AF_NETLINK"
    );

    // ---------------------------------------------------------------- routes
    //
    // `ip route` answered `RTNETLINK answers: Not supported` and `route -n`
    // could not open /proc/net/route, which did not exist. Both read the same
    // table through different interfaces, so both are checked.

    const RTM_GETROUTE: u16 = 26;
    const RTM_NEWROUTE: u16 = 24;
    const RTA_DST: u16 = 1;
    const RTA_OIF: u16 = 4;
    const RTA_PREFSRC: u16 = 7;

    // **A fresh socket.** The link dump above was sent twice and only its first
    // datagram read back, so the rest is still queued -- and a route dump on
    // the same socket reads those first, counts no routes and stops at the
    // link dump's NLMSG_DONE. Against a real kernel that reported "0 routes"
    // for a table with seven in it; a separate probe of the same request shape
    // answered all seven, which is what said the fault was here.
    let rfd = unsafe { libc::socket(PF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
    check!(h, rfd >= 0, "a second netlink socket, for the route dump: {rfd}");
    if rfd < 0 {
        return;
    }
    let bound = unsafe { libc::bind(rfd, sa.as_ptr().cast(), sa.len() as u32) };
    check!(h, bound == 0, "bind it: {bound}");
    // **A receive timeout.** A kernel that refuses the dump answers an
    // NLMSG_ERROR and never an NLMSG_DONE, and a loop that waits for the
    // second blocks for ever -- which is what a back-out of the feature did,
    // hanging the whole suite instead of failing one check. Two seconds: this
    // is a local socket answering from memory.
    let tv = libc::timeval { tv_sec: 2, tv_usec: 0 };
    unsafe {
        libc::setsockopt(
            rfd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as u32,
        )
    };

    // The dump. `rtmsg` is 12 bytes and its first is the family: AF_INET here,
    // so a machine's IPv6 routes do not arrive among its IPv4 ones.
    let mut req = [0u8; 16 + 12];
    let req_len = req.len() as u32;
    req[0..4].copy_from_slice(&req_len.to_le_bytes());
    req[4..6].copy_from_slice(&RTM_GETROUTE.to_le_bytes());
    req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_le_bytes());
    req[8..12].copy_from_slice(&7u32.to_le_bytes());
    req[16] = libc::AF_INET as u8;
    let sent = unsafe { libc::send(rfd, req.as_ptr().cast(), req.len(), 0) };
    check!(h, sent == req.len() as isize, "send RTM_GETROUTE as a dump: {sent}");

    let (mut routes, mut done, mut all_v4) = (0, false, true);
    for _ in 0..64 {
        let mut buf = [0u8; 65536];
        let n = unsafe { libc::recv(rfd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            break;
        }
        let mut at = 0usize;
        while at + 16 <= n as usize {
            let len = u32::from_le_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
            if len < 16 || at + len > n as usize {
                break;
            }
            let kind = u16::from_le_bytes(buf[at + 4..at + 6].try_into().unwrap());
            if kind == RTM_NEWROUTE {
                routes += 1;
                // rtm_family, the first byte of the body. A dump that ignores
                // the request's family sends v6 routes here, and a reader
                // taking four bytes of a sixteen-byte address gets a route to
                // somewhere else entirely.
                if buf[at + 16] != libc::AF_INET as u8 {
                    all_v4 = false;
                }
            }
            // NLMSG_ERROR ends a dump as surely as NLMSG_DONE: a reader that
            // waits for the second after the first has already arrived waits
            // for ever, which is the shape busybox's `ip` gets right and this
            // test did not.
            if kind == NLMSG_DONE || kind == NLMSG_ERROR {
                done = true;
            }
            at += (len + 3) & !3;
        }
        if done {
            break;
        }
    }
    check!(h, routes >= 1, "the route dump has at least one route: {routes}");
    check!(h, done, "and ends with NLMSG_DONE");
    check!(h, all_v4, "and holds only the family that was asked for");

    // `ip route get <addr>`: **not** a dump, one route and no NLMSG_DONE. The
    // request that exposed the bug this checks -- a sendmsg whose msg_name is a
    // sockaddr_nl, which `read_addr` refused with EINVAL because
    // `family_to_real(AF_NETLINK)` is NONE. `ip route` carries no name and
    // worked throughout, so only the query saw it.
    let mut q = [0u8; 16 + 12 + 8];
    let q_len = q.len() as u32;
    q[0..4].copy_from_slice(&q_len.to_le_bytes());
    q[4..6].copy_from_slice(&RTM_GETROUTE.to_le_bytes());
    q[6..8].copy_from_slice(&NLM_F_REQUEST.to_le_bytes());
    q[8..12].copy_from_slice(&8u32.to_le_bytes());
    q[16] = libc::AF_INET as u8;
    q[17] = 32; // rtm_dst_len
    q[28..30].copy_from_slice(&8u16.to_le_bytes()); // rta_len
    q[30..32].copy_from_slice(&RTA_DST.to_le_bytes());
    q[32..36].copy_from_slice(&[8, 8, 8, 8]);

    // Through `sendmsg` with a `msg_name`, which is what `ip` uses and what
    // failed: `send` alone would not have caught it.
    let mut nl = [0u8; 12];
    nl[..2].copy_from_slice(&(PF_NETLINK as u16).to_le_bytes());
    let iov = libc::iovec { iov_base: q.as_ptr() as *mut _, iov_len: q.len() };
    // Zeroed and filled, because `msghdr` has private padding fields on musl
    // and cannot be built with a struct literal.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = nl.as_ptr() as *mut _;
    msg.msg_namelen = nl.len() as u32;
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    sys::clear_errno();
    let sent = unsafe { libc::sendmsg(rfd, &msg, 0) };
    check!(h, sent == q.len() as isize,
        "sendmsg a netlink request with a sockaddr_nl msg_name: {sent} errno={}", sys::errno());

    let mut buf = [0u8; 4096];
    let n = unsafe { libc::recv(rfd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    check!(h, n > 0, "and its reply: {n}");
    if n > 16 {
        let kind = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        check!(h, kind == RTM_NEWROUTE, "which is one RTM_NEWROUTE: type={kind}");
        // The two attributes `ip` prints: which interface, and what source
        // address it would use. Without the second it prints the route with no
        // `src`, which is the field a program binding a socket reads.
        let len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        let (mut oif, mut prefsrc) = (false, false);
        let mut at = 16 + 12;
        while at + 4 <= len.min(n as usize) {
            let alen = u16::from_le_bytes(buf[at..at + 2].try_into().unwrap()) as usize;
            if alen < 4 || at + alen > len {
                break;
            }
            match u16::from_le_bytes(buf[at + 2..at + 4].try_into().unwrap()) {
                RTA_OIF => oif = true,
                RTA_PREFSRC => prefsrc = true,
                _ => {}
            }
            at += (alen + 3) & !3;
        }
        check!(h, oif, "carrying RTA_OIF, which is the interface it would leave by");
        check!(h, prefsrc, "and RTA_PREFSRC, which is what `ip` prints as src");
    }

    // /proc/net/route: the same table, and what `route -n` reads.
    let text = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    let mut lines = text.lines();
    let header = lines.next().unwrap_or("");
    check!(h, header.starts_with("Iface\tDestination\tGateway \tFlags"),
        "/proc/net/route's header: {header:?}");
    check!(h, header.len() == 127, "padded to 127 columns: {}", header.len());
    let rows: Vec<&str> = lines.collect();
    check!(h, !rows.is_empty(), "and at least one route");
    let mut fields_ok = true;
    let mut default_gw: Option<u32> = None;
    for row in &rows {
        let f: Vec<&str> = row.trim_end().split('\t').collect();
        if f.len() != 11 {
            fields_ok = false;
            continue;
        }
        if f[1] == "00000000" && default_gw.is_none() {
            default_gw = u32::from_str_radix(f[2], 16).ok();
        }
    }
    check!(h, fields_ok, "every row has eleven tab-separated fields");
    // The one number a reader of this file is after. The first default route
    // must be one with a next hop: this machine has four and only one has a
    // gateway, so an order that put another first answered 0.0.0.0.
    check!(h, default_gw.is_some(), "there is a default route");
    check!(h, default_gw != Some(0),
        "and the first one listed has a gateway: {default_gw:?}");

    // ------------------------------------------------------- the ARP cache
    //
    // Two readers of one table: `/proc/net/arp`, which `arp -a` parses, and an
    // RTM_GETNEIGH dump, which `ip neigh` reads. The **cross-check** is what
    // holds whether or not this machine has any neighbours, which is the case
    // where a "has at least one entry" check would be vacuous -- a container's
    // cache is usually empty.
    //
    // A *subset*, not an equality. The first version asserted one row per
    // message and a real kernel failed it: `arp_seq_show` walks the table with
    // `NEIGH_SEQ_SKIP_NOARP` and the netlink dump does not, so an entry on a
    // device that does no ARP is in `ip neigh` and not in the text file. The
    // container had exactly one such entry and no rows.

    const RTM_GETNEIGH: u16 = 30;
    const RTM_NEWNEIGH: u16 = 28;

    let mut nreq = [0u8; 16 + 12];
    let nlen = nreq.len() as u32;
    nreq[0..4].copy_from_slice(&nlen.to_le_bytes());
    nreq[4..6].copy_from_slice(&RTM_GETNEIGH.to_le_bytes());
    nreq[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_le_bytes());
    nreq[8..12].copy_from_slice(&9u32.to_le_bytes());
    nreq[16] = libc::AF_INET as u8;
    let sent = unsafe { libc::send(rfd, nreq.as_ptr().cast(), nreq.len(), 0) };
    check!(h, sent == nreq.len() as isize, "send RTM_GETNEIGH as a dump: {sent}");

    const NDA_DST: u16 = 1;
    let (mut neigh, mut ndone) = (0usize, false);
    let mut dumped: Vec<String> = Vec::new();
    for _ in 0..64 {
        let mut buf = [0u8; 65536];
        let n = unsafe { libc::recv(rfd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n <= 0 {
            break;
        }
        let mut at = 0usize;
        while at + 16 <= n as usize {
            let len = u32::from_le_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
            if len < 16 || at + len > n as usize {
                break;
            }
            match u16::from_le_bytes(buf[at + 4..at + 6].try_into().unwrap()) {
                RTM_NEWNEIGH => {
                    neigh += 1;
                    // NDA_DST, so the addresses can be compared with the text
                    // file's. The attributes start after the 12-byte ndmsg.
                    let mut a = at + 16 + 12;
                    while a + 4 <= at + len {
                        let al =
                            u16::from_le_bytes(buf[a..a + 2].try_into().unwrap()) as usize;
                        if al < 4 || a + al > at + len {
                            break;
                        }
                        let kind = u16::from_le_bytes(buf[a + 2..a + 4].try_into().unwrap());
                        if kind == NDA_DST && al == 8 {
                            dumped.push(format!(
                                "{}.{}.{}.{}",
                                buf[a + 4], buf[a + 5], buf[a + 6], buf[a + 7]
                            ));
                        }
                        a += (al + 3) & !3;
                    }
                }
                NLMSG_DONE | NLMSG_ERROR => ndone = true,
                _ => {}
            }
            at += (len + 3) & !3;
        }
        if ndone {
            break;
        }
    }
    check!(h, ndone, "the neighbour dump ends with NLMSG_DONE");

    let arp = std::fs::read_to_string("/proc/net/arp").unwrap_or_default();
    let mut alines = arp.lines();
    let aheader = alines.next().unwrap_or("");
    check!(
        h,
        aheader == "IP address       HW type     Flags       HW address            Mask     Device",
        "/proc/net/arp's header, byte for byte: {aheader:?}"
    );
    let arows: Vec<&str> = alines.collect();
    let missing: Vec<&str> = arows
        .iter()
        .map(|r| r.split_whitespace().next().unwrap_or(""))
        .filter(|ip| !dumped.iter().any(|d| d == ip))
        .collect();
    check!(h, missing.is_empty(),
        "every /proc/net/arp row is in the RTM_GETNEIGH dump: {} rows, {neigh} messages,          missing {missing:?}", arows.len());
    // Every row has a six-byte hardware address field, whether or not the
    // neighbour answered: Linux writes zeroes for one that has not, and an
    // empty field slides the two columns after it left.
    let mut widths_ok = true;
    for row in &arows {
        let f: Vec<&str> = row.split_whitespace().collect();
        if f.len() != 6 || f[3].len() != 17 || f[4] != "*" {
            widths_ok = false;
        }
    }
    check!(h, widths_ok, "and every row has six columns with a 17-character address");

    unsafe { libc::close(rfd) };

    // The SIOCGIF* family, which is the other half of "what interfaces are
    // there" -- `ifconfig` uses it and `ip` asks for SIOCGIFTXQLEN even with a
    // netlink dump in hand.
    //
    // Nothing here names an interface: the host's are `lo0` and `en0` and a
    // container's are `lo` and `eth0`, so the checks are a **round trip**
    // instead, which is a statement about the kernel rather than the machine.
    const SIOCGIFCONF: u64 = 0x8912;
    const SIOCGIFNAME: u64 = 0x8910;
    const SIOCGIFINDEX: u64 = 0x8933;
    const SIOCGIFMTU: u64 = 0x8921;
    const IFREQ: usize = 40;

    let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    check!(h, s >= 0, "a socket to ask the ioctls on");
    if s >= 0 {
        // `struct ifconf`: length, pad, pointer. A null buffer is the sizing
        // call, which is what `ifconfig` does first.
        let mut ifc = [0u8; 16];
        let r = unsafe { libc::syscall(libc::SYS_ioctl, s, SIOCGIFCONF, ifc.as_mut_ptr()) };
        let want = i32::from_le_bytes(ifc[0..4].try_into().unwrap()) as usize;
        check!(h, r == 0, "SIOCGIFCONF sizing call: {r}");
        check!(h, want > 0, "reports a length: {want}");
        check!(h, want % IFREQ == 0, "which is a whole number of ifreqs: {want}");

        let mut buf = vec![0u8; want];
        ifc[0..4].copy_from_slice(&(want as i32).to_le_bytes());
        ifc[8..16].copy_from_slice(&(buf.as_mut_ptr() as u64).to_le_bytes());
        let r = unsafe { libc::syscall(libc::SYS_ioctl, s, SIOCGIFCONF, ifc.as_mut_ptr()) };
        check!(h, r == 0, "SIOCGIFCONF filling call: {r}");
        let got = i32::from_le_bytes(ifc[0..4].try_into().unwrap()) as usize;
        check!(h, got == want, "and fills what it said: {got} of {want}");

        // The first entry's name, and the round trip through its index.
        let end = buf[..16].iter().position(|b| *b == 0).unwrap_or(16);
        check!(h, end > 0, "the first entry has a name");
        let mut req = [0u8; IFREQ];
        req[..end].copy_from_slice(&buf[..end]);
        let r = unsafe { libc::syscall(libc::SYS_ioctl, s, SIOCGIFINDEX, req.as_mut_ptr()) };
        check!(h, r == 0, "SIOCGIFINDEX on it: {r}");
        let index = u32::from_le_bytes(req[16..20].try_into().unwrap());
        check!(h, index > 0, "gives an index: {index}");

        let mut back = [0u8; IFREQ];
        back[16..20].copy_from_slice(&index.to_le_bytes());
        let r = unsafe { libc::syscall(libc::SYS_ioctl, s, SIOCGIFNAME, back.as_mut_ptr()) };
        check!(h, r == 0, "SIOCGIFNAME on that index: {r}");
        check!(
            h,
            back[..end] == buf[..end] && back[end] == 0,
            "and answers the name it came from"
        );

        let mut req = [0u8; IFREQ];
        req[..end].copy_from_slice(&buf[..end]);
        let r = unsafe { libc::syscall(libc::SYS_ioctl, s, SIOCGIFMTU, req.as_mut_ptr()) };
        check!(h, r == 0, "SIOCGIFMTU: {r}");
        let mtu = u32::from_le_bytes(req[16..20].try_into().unwrap());
        check!(h, mtu >= 68, "an MTU no smaller than IPv4's minimum: {mtu}");

        // A name nothing has. ENODEV, not a zeroed answer -- a caller that got
        // 0 and an MTU of 0 would believe the interface exists.
        let mut req = [0u8; IFREQ];
        req[..7].copy_from_slice(b"nope999");
        sys::clear_errno();
        let r = unsafe { libc::syscall(libc::SYS_ioctl, s, SIOCGIFMTU, req.as_mut_ptr()) };
        check!(
            h,
            r == -1 && sys::errno() == libc::ENODEV,
            "an interface that is not there is ENODEV, got {r} errno {}",
            sys::errno()
        );
        unsafe { libc::close(s) };
    }

    unsafe { libc::close(fd) };
}
