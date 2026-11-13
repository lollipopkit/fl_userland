//! The address length `getsockname`/`getpeername` report for a unix socket.
//!
//! Linux computes it from the name, not from what the caller passed to `bind`:
//! `unix_bind_bsd` records `strlen(sun_path) + offsetof(sun_path) + 1`. An
//! abstract name is different — it may contain NULs and is not terminated — so
//! there the length the caller gave is the length.
//!
//! This recorded the caller's length in both cases. Since `sizeof(struct
//! sockaddr_un)` is what almost everything passes, a socket bound to
//! `/tmp/x.sock` reported an address length of 110 rather than 16.
//!
//! It matters for what a caller does with the number. The C idiom is
//! `path[len - offsetof(sun_path)] = '\0'`, which at 110 writes index 108 of a
//! 108-byte array — a one-byte overflow in the *guest*, caused by this kernel
//! handing back a length that does not describe the name.

use guest_tests::{Harness, check, sys};

const OFF: usize = 2; // offsetof(struct sockaddr_un, sun_path)

/// `getpeername`, returning the reported length and the name bytes.
fn peername(fd: i32) -> (usize, Vec<u8>) {
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_un>() as _;
    if unsafe { libc::getpeername(fd, (&raw mut sa).cast(), &mut len) } != 0 {
        return (usize::MAX, Vec::new());
    }
    let n = (len as usize).saturating_sub(OFF);
    let bytes: Vec<u8> = sa.sun_path.iter().take(n).map(|&c| c as u8).collect();
    (len as usize, bytes)
}

/// `getsockname`, returning the reported length and the name bytes.
fn sockname(fd: i32) -> (usize, Vec<u8>) {
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_un>() as _;
    if unsafe { libc::getsockname(fd, (&raw mut sa).cast(), &mut len) } != 0 {
        return (usize::MAX, Vec::new());
    }
    let n = (len as usize).saturating_sub(OFF);
    let bytes: Vec<u8> = sa.sun_path.iter().take(n).map(|&c| c as u8).collect();
    (len as usize, bytes)
}

fn main() {
    let mut h = Harness::new();

    h.group("pathname");
    let path = "/tmp/unix_addrlen.sock";
    let _ = std::fs::remove_file(path);
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    a.sun_family = libc::AF_UNIX as _;
    for (i, &c) in path.as_bytes().iter().enumerate() {
        a.sun_path[i] = c as _;
    }
    // The whole struct, which is what almost every caller passes.
    let whole = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    let r = unsafe { libc::bind(fd, (&raw const a).cast(), whole) };
    check!(h, r == 0, "bind to {path}, errno {}", sys::errno());

    let (len, name) = sockname(fd);
    check!(
        h,
        len == OFF + path.len() + 1,
        "the length describes the name: got {len}, wanted {}",
        OFF + path.len() + 1
    );
    check!(
        h,
        name.iter().filter(|&&c| c == 0).count() == 1,
        "and covers exactly one NUL, the terminator: {} of {}",
        name.iter().filter(|&&c| c == 0).count(),
        name.len()
    );
    check!(
        h,
        &name[..path.len()] == path.as_bytes(),
        "and the bytes are the path"
    );
    sys::close(fd);
    let _ = std::fs::remove_file(path);

    h.group("abstract");
    // An abstract name has no terminator and may contain NULs, so the length
    // the caller gave *is* the length -- trimming it would lose the name.
    let abs = b"\0shellbox\0abstract";
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    a.sun_family = libc::AF_UNIX as _;
    for (i, &c) in abs.iter().enumerate() {
        a.sun_path[i] = c as _;
    }
    let r = unsafe { libc::bind(fd, (&raw const a).cast(), (OFF + abs.len()) as libc::socklen_t) };
    check!(h, r == 0, "bind to an abstract name, errno {}", sys::errno());
    let (len, name) = sockname(fd);
    check!(
        h,
        len == OFF + abs.len(),
        "the length is the one given: got {len}, wanted {}",
        OFF + abs.len()
    );
    check!(h, name == abs, "and the name survives its embedded NUL: {name:?}");
    sys::close(fd);

    h.group("peer");
    // What a connected pair reports about each other.
    //
    // Linux answers from the peer's bound name. A client that never bound has
    // none, so the family alone; a client that *did* bind is reported by the
    // path it bound to.
    //
    // Not covered here, and a known gap: the client's own `getpeername`, which
    // on Linux is the path it connected to. This kernel establishes the peer
    // pointer inside `accept`, and `connect` returns before that, so at the
    // moment a client could ask there is nothing yet to answer from. Closing it
    // means recording the connect target on the client, which is a field
    // `struct fd` does not have.
    let srv_path = "/tmp/unix_addrlen_srv.sock";
    let cli_path = "/tmp/unix_addrlen_cli.sock";
    let _ = std::fs::remove_file(srv_path);
    let _ = std::fs::remove_file(cli_path);
    let whole = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    let un = |p: &str| -> libc::sockaddr_un {
        let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        a.sun_family = libc::AF_UNIX as _;
        for (i, &c) in p.as_bytes().iter().enumerate() {
            a.sun_path[i] = c as _;
        }
        a
    };

    let sa = un(srv_path);
    let srv = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    unsafe {
        libc::bind(srv, (&raw const sa).cast(), whole);
        libc::listen(srv, 8);
    }

    // First: a client that never bound.
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            let c = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            libc::connect(c, (&raw const sa).cast(), whole);
            libc::sleep(3);
            libc::_exit(0);
        }
    }
    let cfd = unsafe { libc::accept(srv, std::ptr::null_mut(), std::ptr::null_mut()) };
    check!(h, cfd >= 0, "accept an unbound client, errno {}", sys::errno());
    if cfd >= 0 {
        let (len, _) = peername(cfd);
        check!(h, len == OFF, "an unbound peer reports just the family: got {len}");
        sys::close(cfd);
    }
    unsafe {
        libc::kill(child, libc::SIGKILL);
        let mut st = 0;
        libc::waitpid(child, &mut st, 0);
    }

    // Then: a client that bound to a path of its own.
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            let c = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            let ca = un(cli_path);
            libc::bind(c, (&raw const ca).cast(), whole);
            libc::connect(c, (&raw const sa).cast(), whole);
            libc::sleep(3);
            libc::_exit(0);
        }
    }
    let cfd = unsafe { libc::accept(srv, std::ptr::null_mut(), std::ptr::null_mut()) };
    check!(h, cfd >= 0, "accept a bound client, errno {}", sys::errno());
    if cfd >= 0 {
        let (len, name) = peername(cfd);
        check!(
            h,
            len == OFF + cli_path.len() + 1,
            "a bound peer is reported by its path: got {len}, wanted {}",
            OFF + cli_path.len() + 1
        );
        check!(
            h,
            name.len() >= cli_path.len() && &name[..cli_path.len()] == cli_path.as_bytes(),
            "and the bytes are that path: {:?}",
            String::from_utf8_lossy(&name)
        );
        sys::close(cfd);
    }
    unsafe {
        libc::kill(child, libc::SIGKILL);
        let mut st = 0;
        libc::waitpid(child, &mut st, 0);
    }
    sys::close(srv);
    let _ = std::fs::remove_file(srv_path);
    let _ = std::fs::remove_file(cli_path);

    h.group("unbound");
    // Nothing bound: the family and nothing else.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    let (len, _) = sockname(fd);
    check!(h, len == OFF, "an unbound socket reports just the family: got {len}");
    sys::close(fd);

    std::process::exit(h.finish());
}
