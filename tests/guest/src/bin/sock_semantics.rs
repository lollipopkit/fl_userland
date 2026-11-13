//! Socket semantics that are not filesystem semantics, so they do not belong
//! in fs_conformance: AF_UNIX addressing, and the rule that a connect must
//! always be able to end.
//!
//! Takes one argument, a directory it may create socket files under.

use guest_tests::{Harness, check, check_fails, cpath, sys};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

fn sockaddr_un(path: &str) -> (libc::sockaddr_un, libc::socklen_t) {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;
    assert!(path.len() < addr.sun_path.len(), "test path too long");
    for (slot, &byte) in addr.sun_path.iter_mut().zip(path.as_bytes()) {
        *slot = byte as libc::c_char;
    }
    (addr, size_of::<libc::sockaddr_un>() as libc::socklen_t)
}

extern "C" fn on_alarm(_: libc::c_int) {}

fn arm_alarm(seconds: u32) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_alarm as *const () as usize;
        // Deliberately not SA_RESTART: the point is that the wait ends.
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
        libc::alarm(seconds);
    }
}

/// A bound, listening AF_UNIX socket at `path`.
fn listening(path: &str) -> i32 {
    unsafe {
        libc::unlink(cpath(path).as_ptr());
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (addr, len) = sockaddr_un(path);
        if libc::bind(fd, (&raw const addr).cast(), len) != 0 || libc::listen(fd, 8) != 0 {
            libc::close(fd);
            return -1;
        }
        fd
    }
}

/// Binding a unix socket needs a socket node, and creating one is what a
/// passthrough mount could not do: `mknod(S_IFSOCK)` needs root on the host,
/// so realfs answered EPERM and AF_UNIX did not work at all there.
fn t_bind_and_talk(h: &mut Harness, dir: &str) {
    h.group("unix-socket");
    let path = format!("{dir}/s1");
    let srv = listening(&path);
    check!(h, srv >= 0, "bind and listen on {path}");
    if srv < 0 {
        return;
    }

    // The node the guest can see is a socket, not a regular file standing in
    // for one.
    match sys::stat(&path) {
        Some(st) => check!(
            h,
            st.st_mode & libc::S_IFMT == libc::S_IFSOCK,
            "the bound path is a socket: mode {:o}",
            st.st_mode
        ),
        None => check!(h, false, "stat of the bound path"),
    }

    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            let cli = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            let (addr, len) = sockaddr_un(&path);
            let ok = libc::connect(cli, (&raw const addr).cast(), len) == 0
                && libc::write(cli, b"ping".as_ptr().cast(), 4) == 4;
            libc::close(cli);
            libc::_exit(i32::from(ok));
        }
        let client = libc::accept(srv, std::ptr::null_mut(), std::ptr::null_mut());
        check!(h, client >= 0, "accept");
        let mut buf = [0u8; 4];
        let n = libc::read(client, buf.as_mut_ptr().cast(), 4);
        check!(h, n == 4 && &buf == b"ping", "reading what the client sent");
        libc::close(client);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        check!(h, (status >> 8) & 0xff == 1, "the client connected and wrote");
        libc::close(srv);
        libc::unlink(cpath(&path).as_ptr());
    }
}

/// An abstract address: the leading NUL is part of the name, and so is any NUL
/// after it. The length is the caller's, since there is no terminator.
fn sockaddr_abstract(name: &[u8]) -> (libc::sockaddr_un, libc::socklen_t) {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;
    assert!(name.len() <= addr.sun_path.len(), "test name too long");
    for (slot, &byte) in addr.sun_path.iter_mut().zip(name) {
        *slot = byte as libc::c_char;
    }
    const OFF: usize = 2; // offsetof(struct sockaddr_un, sun_path)
    (addr, (OFF + name.len()) as libc::socklen_t)
}

/// Binding a name something else already holds is EADDRINUSE, in both
/// namespaces.
///
/// Linux's `unix_bind_abstract` returns `-EADDRINUSE`, the same as the
/// filesystem path. The abstract namespace here answered `EEXIST`, which says
/// something different to a caller: an `EEXIST` from `bind` reads as "a stale
/// socket file is in the way, unlink it and retry", and an abstract name is not
/// a file and cannot be unlinked. A server restarting into a name its previous
/// instance still holds got an errno whose remedy does not exist.
fn t_bind_in_use(h: &mut Harness, dir: &str) {
    h.group("unix-bind-in-use");
    let path = format!("{dir}/s-inuse");
    let srv = listening(&path);
    check!(h, srv >= 0, "bind and listen on {path}");
    if srv < 0 {
        return;
    }
    unsafe {
        let second = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (addr, len) = sockaddr_un(&path);
        // The call goes inside check_fails!, which clears errno before
        // evaluating it. Passing an already-computed result reported errno 0
        // for every failure, which reads as "the call did not set one".
        check_fails!(
            h,
            libc::bind(second, (&raw const addr).cast(), len),
            libc::EADDRINUSE,
            "binding a path another socket holds"
        );
        libc::close(second);
        libc::close(srv);
        libc::unlink(cpath(&path).as_ptr());
    }

    // The same, in the abstract namespace. The name is per-process here but
    // global on Linux, so it is picked to be unlikely to collide with anything
    // else in the container the differential run uses.
    let name = b"\0shellbox-bind-in-use\0probe";
    unsafe {
        let first = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (addr, len) = sockaddr_abstract(name);
        let r = libc::bind(first, (&raw const addr).cast(), len);
        check!(h, r == 0, "bind to an abstract name, errno {}", sys::errno());
        if r == 0 {
            let second = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            check_fails!(
                h,
                libc::bind(second, (&raw const addr).cast(), len),
                libc::EADDRINUSE,
                "binding an abstract name another socket holds"
            );
            libc::close(second);
        }
        libc::close(first);
    }

    // And once the holder is gone the name is free again. A close is what
    // releases an abstract name; there is nothing to unlink.
    unsafe {
        let (addr, len) = sockaddr_abstract(name);
        let again = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let r = libc::bind(again, (&raw const addr).cast(), len);
        check!(
            h,
            r == 0,
            "the abstract name is free once its socket closes, errno {}",
            sys::errno()
        );
        libc::close(again);
    }
}

/// A second `bind` on a socket that already has a name.
///
/// `EINVAL`, and — this is the half that was wrong — **it must leave the first
/// name alone**. Linux checks `u->addr` under the socket's `bindlock` *before*
/// it takes the new name, so a refused bind claims nothing. This claimed the
/// new name first and stored it over the old one, so the old name was never
/// released and stayed taken for the life of the process: a later bind to it
/// answered `EADDRINUSE` for a socket that had been closed.
///
/// Both namespaces, because they are two different fields on the socket —
/// `unix_name_abstract` and `unix_name_inode` — set by two different arms of
/// the same function.
fn t_bind_twice(h: &mut Harness, dir: &str) {
    h.group("unix-bind-twice");

    // The abstract namespace. `first` is the name that must survive the
    // refusal; `second` is the one the refused call names.
    let first = b"\0shellbox-bind-twice-a\0probe";
    let second = b"\0shellbox-bind-twice-b\0probe";
    unsafe {
        let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (a1, l1) = sockaddr_abstract(first);
        let r = libc::bind(s, (&raw const a1).cast(), l1);
        check!(h, r == 0, "bind to an abstract name, errno {}", sys::errno());

        let (a2, l2) = sockaddr_abstract(second);
        check_fails!(
            h,
            libc::bind(s, (&raw const a2).cast(), l2),
            libc::EINVAL,
            "a second bind on a socket that already has a name"
        );
        libc::close(s);

        // The socket is gone, so both names are free: the one it held, and the
        // one the refused call named and must never have taken.
        for (name, what) in [(first, "the name it held"), (second, "the name it was refused")] {
            let (addr, len) = sockaddr_abstract(name);
            let again = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            let r = libc::bind(again, (&raw const addr).cast(), len);
            check!(
                h,
                r == 0,
                "after a refused second bind, {what} is free, errno {}",
                sys::errno()
            );
            libc::close(again);
        }
    }

    // The filesystem namespace, where the refused call must also not create a
    // socket file for the name it was refused.
    let held = format!("{dir}/bind-twice-a");
    let refused = format!("{dir}/bind-twice-b");
    unsafe {
        libc::unlink(cpath(&held).as_ptr());
        libc::unlink(cpath(&refused).as_ptr());
        let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (a1, l1) = sockaddr_un(&held);
        let r = libc::bind(s, (&raw const a1).cast(), l1);
        check!(h, r == 0, "bind to {held}, errno {}", sys::errno());

        let (a2, l2) = sockaddr_un(&refused);
        check_fails!(
            h,
            libc::bind(s, (&raw const a2).cast(), l2),
            libc::EINVAL,
            "a second bind on a socket already bound to a path"
        );
        check!(
            h,
            libc::access(cpath(&refused).as_ptr(), libc::F_OK) != 0,
            "a refused second bind creates no socket file"
        );
        libc::close(s);
        libc::unlink(cpath(&held).as_ptr());
        libc::unlink(cpath(&refused).as_ptr());
    }
}

/// The rules for an address that names nothing, or names nothing yet.
///
/// Three of them, and each answers a different errno on Linux for what looks
/// like one condition — "there is no socket there":
///
///   - `connect` to an unbound *abstract* name is `ECONNREFUSED`, because the
///     namespace has no directory to report a missing entry from. The
///     filesystem namespace is `ENOENT`, from the path lookup.
///   - `bind` with the family and nothing else is an *autobind*: Linux picks
///     an unused abstract name and returns 0.
///   - `connect` with the family and nothing else is `EINVAL`, because
///     `unix_validate_addr` requires at least one byte of name and only `bind`
///     special-cases the shorter length before reaching it.
///
/// This kernel answered `ENOENT` to all three.
fn t_unnamed_addresses(h: &mut Harness, dir: &str) {
    h.group("unix-no-such-name");

    // Nothing has ever bound this, in either namespace.
    let missing_path = format!("{dir}/s-never-bound");
    unsafe {
        libc::unlink(cpath(&missing_path).as_ptr());
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (addr, len) = sockaddr_un(&missing_path);
        check_fails!(
            h,
            libc::connect(fd, (&raw const addr).cast(), len),
            libc::ENOENT,
            "connect to a path nothing bound"
        );
        libc::close(fd);
    }
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (addr, len) = sockaddr_abstract(b"\0shellbox-never-bound");
        check_fails!(
            h,
            libc::connect(fd, (&raw const addr).cast(), len),
            libc::ECONNREFUSED,
            "connect to an abstract name nothing bound"
        );
        libc::close(fd);
    }

    // The family and nothing else: `sizeof(sa_family_t)`, which is
    // offsetof(sun_path).
    const FAMILY_ONLY: libc::socklen_t = 2;
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (addr, _) = sockaddr_abstract(b"");
        let r = libc::bind(fd, (&raw const addr).cast(), FAMILY_ONLY);
        check!(h, r == 0, "bind with no name autobinds, errno {}", sys::errno());
        if r == 0 {
            // What it picked: an abstract name, so the first byte is a NUL and
            // there is at least one byte after it.
            let mut sa: libc::sockaddr_un = std::mem::zeroed();
            let mut len: libc::socklen_t = size_of::<libc::sockaddr_un>() as _;
            let g = libc::getsockname(fd, (&raw mut sa).cast(), &mut len);
            check!(
                h,
                g == 0 && len > FAMILY_ONLY && sa.sun_path[0] == 0,
                "the autobound name is an abstract one: len {len}, first byte {}",
                sa.sun_path[0]
            );
        }
        libc::close(fd);
    }
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (addr, _) = sockaddr_abstract(b"");
        check_fails!(
            h,
            libc::connect(fd, (&raw const addr).cast(), FAMILY_ONLY),
            libc::EINVAL,
            "connect with no name at all"
        );
        libc::close(fd);
    }
}

/// A connect that cannot complete must still end.
///
/// The server here listens and never accepts, which on Linux is fine — the
/// client gets a backlog slot and connect returns at once. This kernel makes
/// connect wait for the accept side to claim its handshake, which is a
/// deliberate deviation, and the wait used to be `wait_for_ignore_signals`
/// with no timeout: the client blocked for ever and no signal could reach it,
/// so the task could not even be killed.
fn t_connect_is_interruptible(h: &mut Harness, dir: &str) {
    h.group("unix-connect");
    let path = format!("{dir}/s2");
    let srv = listening(&path);
    check!(h, srv >= 0, "bind and listen on {path}");
    if srv < 0 {
        return;
    }

    unsafe {
        let cli = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (addr, len) = sockaddr_un(&path);
        arm_alarm(1);
        let start = Instant::now();
        let r = libc::connect(cli, (&raw const addr).cast(), len);
        let waited = start.elapsed();
        libc::alarm(0);
        check!(
            h,
            waited.as_secs() < 5,
            "connect to a listening-but-not-accepting server ended, after {waited:?}"
        );
        check!(h, r == 0, "and reported the connection succeeded");
        libc::close(cli);
        libc::close(srv);
        libc::unlink(cpath(&path).as_ptr());
    }
}

/// A receive timeout has to be settable, and has to apply.
///
/// `fs/sock.h` mapped `SO_RCVTIMEO` only at 66, the number the 64-bit time_t
/// transition introduced; musl on aarch64 sends 20, the classic one. Unmapped,
/// `sys_setsockopt` answered EINVAL, so no program could set a socket timeout
/// — and `sock_get_timeout_ms`, which reads the option back off the host to
/// bound the wait in `sock_wait_for`, had nothing to read.
fn t_receive_timeout(h: &mut Harness) {
    h.group("so-rcvtimeo");
    let mut sv = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        check!(h, false, "socketpair");
        return;
    }
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 300_000,
    };
    let r = unsafe {
        libc::setsockopt(
            sv[0],
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    check!(h, r == 0, "setsockopt(SO_RCVTIMEO)");

    let mut back = libc::timeval { tv_sec: 0, tv_usec: 0 };
    let mut len = size_of::<libc::timeval>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            sv[0],
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw mut back).cast(),
            &mut len,
        )
    };
    check!(h, r == 0, "getsockopt(SO_RCVTIMEO)");
    check!(
        h,
        back.tv_sec == 0 && back.tv_usec == 300_000,
        "it reads back as it was set: {}s {}us",
        back.tv_sec,
        back.tv_usec
    );

    // And it applies, to every way of reading from a socket. Nothing is ever
    // written to the other end, so each of these can only end by timing out.
    let mut buf = [0u8; 4];
    for name in ["read", "recv", "recvmsg"] {
        let start = std::time::Instant::now();
        sys::clear_errno();
        let n = unsafe {
            match name {
                "read" => libc::read(sv[0], buf.as_mut_ptr().cast(), 4),
                "recv" => libc::recv(sv[0], buf.as_mut_ptr().cast(), 4, 0),
                _ => {
                    let mut iov = libc::iovec {
                        iov_base: buf.as_mut_ptr().cast(),
                        iov_len: 4,
                    };
                    let mut msg: libc::msghdr = std::mem::zeroed();
                    msg.msg_iov = &mut iov;
                    msg.msg_iovlen = 1;
                    libc::recvmsg(sv[0], &mut msg, 0)
                }
            }
        };
        let e = sys::errno();
        let waited = start.elapsed();
        check!(
            h,
            n == -1 && (e == libc::EAGAIN || e == libc::EWOULDBLOCK),
            "{name} on a socket with a timeout: returned {n} errno {e}"
        );
        check!(
            h,
            waited.as_millis() >= 200 && waited.as_millis() < 3000,
            "{name} waited {waited:?}, wanted about 300ms"
        );
    }
    sys::close(sv[0]);
    sys::close(sv[1]);
}

/// The socket options a program actually sets have to be settable.
///
/// `fs/sock.h` maps each guest option number to a host one, and an unmapped
/// number used to be `EINVAL`. A sweep found ten refused, including
/// `SO_RCVTIMEO` — mapped only at the number the 64-bit `time_t` transition
/// introduced, while the guest's libc sends the classic one.
fn t_socket_options(h: &mut Harness) {
    h.group("sockopt");
    let tcp = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let udp = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    let tcp6 = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    if tcp < 0 || udp < 0 {
        check!(h, false, "creating sockets");
        return;
    }

    let set = |fd: i32, level: i32, opt: i32, v: i32| unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            (&raw const v).cast(),
            size_of::<i32>() as libc::socklen_t,
        )
    };

    for (name, fd, level, opt, v) in [
        ("SO_REUSEADDR", tcp, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1),
        ("SO_KEEPALIVE", tcp, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1),
        ("SO_BROADCAST", udp, libc::SOL_SOCKET, libc::SO_BROADCAST, 1),
        ("SO_OOBINLINE", tcp, libc::SOL_SOCKET, libc::SO_OOBINLINE, 1),
        ("SO_DONTROUTE", tcp, libc::SOL_SOCKET, libc::SO_DONTROUTE, 0),
        ("SO_PRIORITY", tcp, libc::SOL_SOCKET, libc::SO_PRIORITY, 0),
        ("TCP_NODELAY", tcp, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1),
        ("TCP_QUICKACK", tcp, libc::IPPROTO_TCP, 12, 1),
        ("TCP_USER_TIMEOUT", tcp, libc::IPPROTO_TCP, 18, 5000),
        ("IP_TTL", udp, libc::IPPROTO_IP, libc::IP_TTL, 64),
        ("IP_PKTINFO", udp, libc::IPPROTO_IP, libc::IP_PKTINFO, 1),
        ("IP_MULTICAST_TTL", udp, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, 1),
        ("IP_MULTICAST_LOOP", udp, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, 1),
    ] {
        let r = set(fd, level, opt, v);
        check!(h, r == 0, "setsockopt({name}) returned {r} errno {}", sys::errno());
    }
    if tcp6 >= 0 {
        // On an IPv6 socket, which is the only place it means anything.
        let r = set(tcp6, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1);
        check!(h, r == 0, "setsockopt(IPV6_V6ONLY) returned {r}");
        sys::close(tcp6);
    }

    // An option no level knows is ENOPROTOOPT, which is what Linux answers and
    // what a program with a fallback tests for. It used to be EINVAL, which a
    // caller cannot tell from its own mistake.
    check_fails!(
        h,
        set(tcp, libc::SOL_SOCKET, 9999, 1),
        libc::ENOPROTOOPT,
        "an option no level knows"
    );

    // getsockopt has the same rule and used to answer EINVAL, so a program
    // probing for an option could not tell "this kernel does not have it" from
    // "you called me wrongly".
    let mut v: libc::c_int = 0;
    let mut vlen = size_of::<libc::c_int>() as libc::socklen_t;
    // Called inside the macro, not before it: check_fails! clears errno and
    // then evaluates what it is given, so handing it an already-computed
    // result reports errno 0 whatever the call actually did.
    check_fails!(
        h,
        unsafe { libc::getsockopt(tcp, libc::SOL_SOCKET, 9999, (&raw mut v).cast(), &mut vlen) },
        libc::ENOPROTOOPT,
        "getsockopt of an option no level knows"
    );

    // An option this kernel accepts and drops has to be readable, or a program
    // that sets it successfully cannot read back what it just set. These went
    // to the host as option number *zero*: the sentinel for "ignored" was
    // handled in setsockopt and passed straight through in getsockopt.
    for (name, level, opt) in [
        ("SO_PRIORITY", libc::SOL_SOCKET, libc::SO_PRIORITY),
        ("TCP_QUICKACK", libc::IPPROTO_TCP, libc::TCP_QUICKACK),
    ] {
        let mut v: libc::c_int = -1;
        let mut vlen = size_of::<libc::c_int>() as libc::socklen_t;
        let r = unsafe { libc::getsockopt(tcp, level, opt, (&raw mut v).cast(), &mut vlen) };
        check!(
            h,
            r == 0,
            "getsockopt({name}) succeeds, got {r} errno {}",
            sys::errno()
        );
    }

    sys::close(tcp);
    sys::close(udp);
}

static SIGPIPES: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_sigpipe(_: libc::c_int) {
    SIGPIPES.fetch_add(1, Ordering::Relaxed);
}

/// `MSG_NOSIGNAL` is the caller saying "answer EPIPE, do not signal me".
///
/// The emulator ignores SIGPIPE on the host and synthesises the guest's one in
/// `errno_map` whenever a host call sets EPIPE — which it did for every send,
/// because `sock_flags_to_real` had no entry for MSG_NOSIGNAL and dropped it.
/// So a program that had asked not to be signalled was, and SIGPIPE's default
/// action is to terminate: writing to a closed connection killed servers that
/// use the flag precisely so it cannot.
fn t_nosignal(h: &mut Harness) {
    h.group("msg-nosignal");
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigpipe as *const () as usize;
        libc::sigaction(libc::SIGPIPE, &sa, std::ptr::null_mut());
    }

    // A stream pair whose peer is gone: every send is EPIPE from here on.
    let broken = || unsafe {
        let mut sv = [0i32; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) != 0 {
            return -1;
        }
        libc::close(sv[1]);
        sv[0]
    };

    let fd = broken();
    check!(h, fd >= 0, "socketpair");
    if fd < 0 {
        return;
    }
    let before = SIGPIPES.load(Ordering::Relaxed);
    let r = unsafe { libc::send(fd, b"x".as_ptr().cast(), 1, libc::MSG_NOSIGNAL) };
    check!(
        h,
        r == -1 && sys::errno() == libc::EPIPE,
        "send(MSG_NOSIGNAL) to a closed peer is EPIPE, got {r} errno {}",
        sys::errno()
    );
    // The signal is delivered synchronously by the sending thread, so it has
    // already arrived if it is coming at all.
    check!(
        h,
        SIGPIPES.load(Ordering::Relaxed) == before,
        "and raises no SIGPIPE, got {}",
        SIGPIPES.load(Ordering::Relaxed) - before
    );
    sys::close(fd);

    // Without the flag the signal is required, so this pins that the fix
    // suppresses it rather than losing it.
    let fd = broken();
    if fd >= 0 {
        let before = SIGPIPES.load(Ordering::Relaxed);
        let r = unsafe { libc::send(fd, b"x".as_ptr().cast(), 1, 0) };
        check!(
            h,
            r == -1 && sys::errno() == libc::EPIPE,
            "send without the flag is still EPIPE, got {r}"
        );
        check!(
            h,
            SIGPIPES.load(Ordering::Relaxed) == before + 1,
            "and does raise SIGPIPE, got {}",
            SIGPIPES.load(Ordering::Relaxed) - before
        );
        sys::close(fd);
    }

    // sendmsg takes the same flag by the same route.
    let fd = broken();
    if fd >= 0 {
        let before = SIGPIPES.load(Ordering::Relaxed);
        let iov = libc::iovec { iov_base: b"x".as_ptr() as *mut _, iov_len: 1 };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = (&raw const iov) as *mut _;
        msg.msg_iovlen = 1;
        let r = unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) };
        check!(
            h,
            r == -1 && sys::errno() == libc::EPIPE,
            "sendmsg(MSG_NOSIGNAL) is EPIPE, got {r} errno {}",
            sys::errno()
        );
        check!(
            h,
            SIGPIPES.load(Ordering::Relaxed) == before,
            "and raises no SIGPIPE, got {}",
            SIGPIPES.load(Ordering::Relaxed) - before
        );
        sys::close(fd);
    }

    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
}

fn main() -> std::process::ExitCode {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: sock_semantics <scratch-directory>");
        return std::process::ExitCode::from(2);
    };
    if sys::mkdir(&dir, 0o755) != 0 && sys::errno() != libc::EEXIST {
        eprintln!("cannot create {dir}: {}", sys::strerror(sys::errno()));
        return std::process::ExitCode::from(2);
    }

    let mut h = Harness::new();
    t_bind_and_talk(&mut h, &dir);
    t_bind_in_use(&mut h, &dir);
    t_bind_twice(&mut h, &dir);
    t_unnamed_addresses(&mut h, &dir);
    t_connect_is_interruptible(&mut h, &dir);
    t_receive_timeout(&mut h);
    t_socket_options(&mut h);
    t_nosignal(&mut h);
    std::process::ExitCode::from(h.finish() as u8)
}
