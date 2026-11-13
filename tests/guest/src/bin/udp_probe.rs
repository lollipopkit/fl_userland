//! `connect(2)` on a UDP socket, and what a connected one does.
//!
//! **A report, not a check**, diffed against a real kernel by
//! `tests/integration/probe_diff.sh`.
//!
//! A resolver connects its UDP socket to the name server so that `send` needs
//! no address and only that server's answers arrive; busybox `nc -u` does the
//! same. Here `nc -u 127.0.0.1 <port>` failed with "can't connect to remote
//! host: Invalid argument" until 2026-10-18 -- the *listening* side, which
//! is an IPv6 socket: busybox `nc -l` peeks the first datagram with
//! `recvmsg(MSG_PEEK)` and connects back to its source, and the peek returned
//! 0 at once on an empty socket. The section after the IPv4 one is that path.

use std::mem::size_of;

fn errname(e: i32) -> String {
    match e {
        libc::EINVAL => "EINVAL".into(),
        libc::EAFNOSUPPORT => "EAFNOSUPPORT".into(),
        libc::ENOTCONN => "ENOTCONN".into(),
        libc::EDESTADDRREQ => "EDESTADDRREQ".into(),
        libc::ECONNREFUSED => "ECONNREFUSED".into(),
        libc::EAGAIN => "EAGAIN".into(),
        libc::EISCONN => "EISCONN".into(),
        e => format!("errno {e}"),
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn line(what: &str, v: &str) {
    println!("{what:<50} -> {v}");
}

fn rc(r: isize) -> String {
    if r < 0 { errname(errno()) } else { r.to_string() }
}

fn sin(ip: [u8; 4], port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as _,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(ip) },
        sin_zero: [0; 8],
    }
}

fn udp() -> i32 {
    // SAFETY: no pointers.
    unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) }
}

fn bind(fd: i32, a: &libc::sockaddr_in) -> isize {
    // SAFETY: a sockaddr_in and its size.
    unsafe { libc::bind(fd, (a as *const libc::sockaddr_in).cast(), size_of::<libc::sockaddr_in>() as u32) as isize }
}

fn connect(fd: i32, a: &libc::sockaddr_in) -> isize {
    // SAFETY: as `bind`.
    unsafe { libc::connect(fd, (a as *const libc::sockaddr_in).cast(), size_of::<libc::sockaddr_in>() as u32) as isize }
}

fn port_of(fd: i32) -> u16 {
    let mut a = sin([0; 4], 0);
    let mut len = size_of::<libc::sockaddr_in>() as u32;
    // SAFETY: a buffer of `len` bytes.
    unsafe { libc::getsockname(fd, (&mut a as *mut libc::sockaddr_in).cast(), &mut len) };
    u16::from_be(a.sin_port)
}

fn main() {
    // A receiver to connect to.
    let r = udp();
    bind(r, &sin([127, 0, 0, 1], 0));
    let port = port_of(r);
    let to = sin([127, 0, 0, 1], port);

    println!("## connect");
    let s = udp();
    line("unbound socket to 127.0.0.1", &rc(connect(s, &to)));
    line("  and it was given a port", &(port_of(s) != 0).to_string());
    let b = udp();
    bind(b, &sin([0; 4], 0));
    line("bound to 0.0.0.0, to 127.0.0.1", &rc(connect(b, &to)));
    let l = udp();
    bind(l, &sin([127, 0, 0, 1], 0));
    line("bound to 127.0.0.1, to 127.0.0.1", &rc(connect(l, &to)));
    line("connect again, elsewhere", &rc(connect(l, &sin([127, 0, 0, 1], 9))));
    line("connect again, back", &rc(connect(l, &to)));
    let z = udp();
    line("to 0.0.0.0", &rc(connect(z, &sin([0; 4], port))));

    println!("## a connected socket");
    // SAFETY: plain I/O.
    line("send without an address", &rc(unsafe { libc::send(s, b"x".as_ptr().cast(), 1, 0) }));
    let mut buf = [0u8; 8];
    let mut tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
    // SAFETY: a timeval and its size.
    unsafe { libc::setsockopt(r, libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&mut tv as *mut libc::timeval).cast(), size_of::<libc::timeval>() as u32) };
    line("it arrives", &rc(unsafe { libc::recv(r, buf.as_mut_ptr().cast(), 8, 0) }));
    let mut peer = sin([0; 4], 0);
    let mut len = size_of::<libc::sockaddr_in>() as u32;
    // SAFETY: a buffer of `len` bytes.
    let g = unsafe { libc::getpeername(s, (&mut peer as *mut libc::sockaddr_in).cast(), &mut len) };
    line("getpeername", &if g < 0 { errname(errno()) } else { format!("port matches {}", u16::from_be(peer.sin_port) == port) });

    // busybox `nc -u` shuts its write side at the end of its input and then
    // polls for the reply until `-w` runs out. Nothing has arrived, so the
    // socket is not readable; here it was, and nc blocked in a read for ever.
    let sh = udp();
    connect(sh, &to);
    // SAFETY: no pointers.
    line("shutdown(SHUT_WR) on a connected socket", &rc(unsafe { libc::shutdown(sh, libc::SHUT_WR) } as isize));
    let mut p = libc::pollfd { fd: sh, events: libc::POLLIN | libc::POLLOUT, revents: 0 };
    // SAFETY: one pollfd.
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    line("  then poll(IN|OUT) reports", &format!("{n} {:#x}", p.revents));

    println!("## disconnect");
    let unspec = libc::sockaddr { sa_family: libc::AF_UNSPEC as _, sa_data: [0; 14] };
    // SAFETY: a sockaddr and its size.
    let d = unsafe { libc::connect(s, &unspec, size_of::<libc::sockaddr>() as u32) };
    line("connect AF_UNSPEC", &rc(d as isize));
    // SAFETY: as above.
    let g = unsafe { libc::getpeername(s, (&mut peer as *mut libc::sockaddr_in).cast(), &mut len) };
    line("getpeername after", &if g < 0 { errname(errno()) } else { "connected".into() });
    // SAFETY: plain I/O.
    line("send without an address after", &rc(unsafe { libc::send(s, b"x".as_ptr().cast(), 1, 0) }));

    dual_stack();
    ancillary();
}

/// One datagram from an IPv4 socket to `port` on 127.0.0.1, received on `fd`,
/// described by its control messages: level/type/payload length, and for the
/// two pktinfo kinds what they say.
fn cmsgs_after(fd: i32, port: u16) -> String {
    let v4 = udp();
    let to = sin([127, 0, 0, 1], port);
    // SAFETY: plain I/O to a sockaddr_in.
    unsafe { libc::sendto(v4, b"m".as_ptr().cast(), 1, 0, (&to as *const libc::sockaddr_in).cast(), size_of::<libc::sockaddr_in>() as u32) };
    let mut buf = [0u8; 8];
    let mut ctl = [0u64; 64];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    // SAFETY: plain data.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctl.as_mut_ptr().cast();
    msg.msg_controllen = size_of_val(&ctl) as _;
    // SAFETY: every pointer in `msg` is to a live local.
    if unsafe { libc::recvmsg(fd, &mut msg, 0) } < 0 {
        return errname(errno());
    }
    let mut out = Vec::new();
    // SAFETY: the kernel's walk over the buffer it filled.
    let mut c = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !c.is_null() {
        // SAFETY: as above.
        let (h, data) = unsafe { (&*c, libc::CMSG_DATA(c)) };
        let n = h.cmsg_len as usize - (data as usize - c as usize);
        let mut what = format!("{}/{}/{n}", h.cmsg_level, h.cmsg_type);
        if h.cmsg_level == libc::IPPROTO_IP && h.cmsg_type == libc::IP_PKTINFO {
            // SAFETY: an in_pktinfo, which is what this type carries.
            let p = unsafe { data.cast::<libc::in_pktinfo>().read_unaligned() };
            what += &format!("(if>0 {}, addr {:?})", p.ipi_ifindex > 0, p.ipi_addr.s_addr.to_ne_bytes());
        }
        if h.cmsg_level == libc::IPPROTO_IPV6 && h.cmsg_type == libc::IPV6_PKTINFO {
            // SAFETY: an in6_pktinfo.
            let p = unsafe { data.cast::<libc::in6_pktinfo>().read_unaligned() };
            what += &format!("(if>0 {}, addr {:?})", p.ipi6_ifindex > 0, &p.ipi6_addr.s6_addr[10..]);
        }
        if h.cmsg_level == libc::IPPROTO_IP && (h.cmsg_type == libc::IP_TTL || h.cmsg_type == libc::IP_TOS) {
            what += &format!("(first byte nonzero {})", unsafe { *data } != 0 || h.cmsg_type == libc::IP_TOS);
        }
        out.push(what);
        // SAFETY: the next header within the same buffer, or null.
        c = unsafe { libc::CMSG_NXTHDR(&msg, c) };
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        out.push("MSG_CTRUNC".into());
    }
    if out.is_empty() { "none".into() } else { out.join(" ") }
}

/// Which control messages arrive for which options, and in what order.
fn ancillary() {
    println!("## control messages on a received datagram");
    let on: i32 = 1;
    let set = |fd: i32, level, name| {
        // SAFETY: an int and its size.
        unsafe { libc::setsockopt(fd, level, name, (&on as *const i32).cast(), 4) };
    };
    let bound4 = || {
        let fd = udp();
        bind(fd, &sin([127, 0, 0, 1], 0));
        fd
    };
    let bound6 = || {
        // SAFETY: no pointers.
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
        let any = sin6_any(0);
        // SAFETY: a sockaddr_in6 and its size.
        unsafe { libc::bind(fd, (&any as *const libc::sockaddr_in6).cast(), size_of::<libc::sockaddr_in6>() as u32) };
        fd
    };
    let port6 = |fd: i32| {
        let mut a = sin6_any(0);
        let mut len = size_of::<libc::sockaddr_in6>() as u32;
        // SAFETY: a buffer of `len` bytes.
        unsafe { libc::getsockname(fd, (&mut a as *mut libc::sockaddr_in6).cast(), &mut len) };
        u16::from_be(a.sin6_port)
    };

    let fd = bound4();
    line("IPv4, nothing asked", &cmsgs_after(fd, port_of(fd)));
    let fd = bound4();
    set(fd, libc::IPPROTO_IP, libc::IP_PKTINFO);
    line("IPv4, IP_PKTINFO", &cmsgs_after(fd, port_of(fd)));
    let fd = bound4();
    set(fd, libc::IPPROTO_IP, libc::IP_RECVTTL);
    set(fd, libc::IPPROTO_IP, libc::IP_RECVTOS);
    line("IPv4, IP_RECVTTL and IP_RECVTOS", &cmsgs_after(fd, port_of(fd)));
    let fd = bound4();
    set(fd, libc::SOL_SOCKET, libc::SO_TIMESTAMP);
    line("IPv4, SO_TIMESTAMP", &cmsgs_after(fd, port_of(fd)));
    let fd = bound6();
    set(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO);
    line("IPv6 on ::, IPV6_RECVPKTINFO, from IPv4", &cmsgs_after(fd, port6(fd)));
    let fd = bound6();
    set(fd, libc::IPPROTO_IP, libc::IP_PKTINFO);
    line("IPv6 on ::, IP_PKTINFO, from IPv4", &cmsgs_after(fd, port6(fd)));
    let fd = bound6();
    set(fd, libc::IPPROTO_IP, libc::IP_PKTINFO);
    set(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO);
    line("IPv6 on ::, both, from IPv4", &cmsgs_after(fd, port6(fd)));
}

fn sin6_any(port: u16) -> libc::sockaddr_in6 {
    // SAFETY: plain data; every field is set or zero.
    let mut a: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    a.sin6_family = libc::AF_INET6 as _;
    a.sin6_port = port.to_be();
    a
}

/// What `nc -lu` does: an IPv6 socket on `::`, the two pktinfo options, a
/// peek at the first datagram, and a connect back to where it came from.
fn dual_stack() {
    println!("## an IPv6 socket on ::, as nc -l makes one");
    // SAFETY: no pointers.
    let v6 = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    let on: i32 = 1;
    let opt = |level, name| {
        // SAFETY: an int and its size.
        rc(unsafe { libc::setsockopt(v6, level, name, (&on as *const i32).cast(), 4) } as isize)
    };
    line("setsockopt IPPROTO_IP IP_PKTINFO", &opt(libc::IPPROTO_IP, libc::IP_PKTINFO));
    line("setsockopt IPPROTO_IPV6 IPV6_RECVPKTINFO", &opt(libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO));
    let any = sin6_any(0);
    // SAFETY: a sockaddr_in6 and its size.
    let b = unsafe { libc::bind(v6, (&any as *const libc::sockaddr_in6).cast(), size_of::<libc::sockaddr_in6>() as u32) };
    line("bind ::", &rc(b as isize));
    let mut a = sin6_any(0);
    let mut len = size_of::<libc::sockaddr_in6>() as u32;
    // SAFETY: a buffer of `len` bytes.
    unsafe { libc::getsockname(v6, (&mut a as *mut libc::sockaddr_in6).cast(), &mut len) };
    let port = u16::from_be(a.sin6_port);

    let mut tv = libc::timeval { tv_sec: 0, tv_usec: 300_000 };
    // SAFETY: a timeval and its size.
    unsafe { libc::setsockopt(v6, libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&mut tv as *mut libc::timeval).cast(), size_of::<libc::timeval>() as u32) };
    let mut buf = [0u8; 16];
    let mut from = sin6_any(0);
    let mut ctl = [0u8; 128];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    // SAFETY: plain data.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&mut from as *mut libc::sockaddr_in6).cast();
    msg.msg_namelen = size_of::<libc::sockaddr_in6>() as u32;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctl.as_mut_ptr().cast();
    msg.msg_controllen = ctl.len() as _;
    // SAFETY: every pointer in `msg` is to a live local.
    let empty = unsafe { libc::recvmsg(v6, &mut msg, libc::MSG_PEEK) };
    line("recvmsg MSG_PEEK on an empty socket, 300ms timeout", &rc(empty));
    // busybox nc peeks with an empty buffer: it wants to wait for the first
    // datagram and learn its source, not read it.
    let mut none = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: 0 };
    msg.msg_iov = &mut none;
    msg.msg_controllen = ctl.len() as _;
    // SAFETY: as above.
    let zero = unsafe { libc::recvmsg(v6, &mut msg, libc::MSG_PEEK) };
    line("  the same with a zero-length buffer", &rc(zero));
    msg.msg_iov = &mut iov;

    // From an IPv4 socket to 127.0.0.1: a dual-stack socket on :: hears it.
    let v4 = udp();
    // SAFETY: plain I/O to a sockaddr_in.
    let to = sin([127, 0, 0, 1], port);
    let sent = unsafe { libc::sendto(v4, b"hey".as_ptr().cast(), 3, 0, (&to as *const libc::sockaddr_in).cast(), size_of::<libc::sockaddr_in>() as u32) };
    line("sendto 127.0.0.1 from IPv4", &rc(sent));
    msg.msg_namelen = size_of::<libc::sockaddr_in6>() as u32;
    msg.msg_controllen = ctl.len() as _;
    // SAFETY: as above.
    let got = unsafe { libc::recvmsg(v6, &mut msg, libc::MSG_PEEK) };
    line("recvmsg MSG_PEEK", &rc(got));
    line("  the source is ::ffff:127.0.0.1", &(from.sin6_addr.s6_addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]).to_string());
    line("  the source's port is the sender's", &(u16::from_be(from.sin6_port) == port_of(v4)).to_string());
    line("  a control message came with it", &(msg.msg_controllen > 0).to_string());
    // SAFETY: a sockaddr_in6 from recvmsg, and its size.
    let c = unsafe { libc::connect(v6, (&from as *const libc::sockaddr_in6).cast(), size_of::<libc::sockaddr_in6>() as u32) };
    line("connect back to the source", &rc(c as isize));
    // SAFETY: plain I/O.
    let n = unsafe { libc::recv(v6, buf.as_mut_ptr().cast(), buf.len(), 0) };
    line("recv after connect, the peeked datagram", &rc(n));
}
