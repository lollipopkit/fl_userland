//! Socket bind and connect operations.

use super::*;

// ---------------------------------------------------------------------------
// Reading an address, and the two calls that resolve one
// ---------------------------------------------------------------------------

pub fn sys_bind(sock_fd: c_int, addr: u64, len: c_uint) -> Result<(), Errno> {
    strace!("bind({sock_fd}, {addr:#x}, {len})");
    let sock = Sock::get(sock_fd)?;
    // A netlink socket's address is a `sockaddr_nl`: a port id the caller picks
    // (or 0 for "the kernel assigns one") and a multicast group mask. There is
    // nothing to bind to -- the pair is already connected -- and Linux accepts
    // any well-formed one, so this does too. Refusing it would stop `ip addr`,
    // which binds before it asks.
    if sock.is_netlink() {
        return if len as usize >= 8 {
            Ok(())
        } else {
            Err(Errno::EINVAL)
        };
    }
    // An autobind on a socket that already has a name: zero, and nothing
    // changes. It is the one second-bind Linux does not refuse, and the host
    // would refuse it — see [`autobind_on_named_socket`].
    if autobind_on_named_socket(&sock, addr, len) {
        return Ok(());
    }
    let (bytes, host_len) = read_addr_for(addr, len, AddrFor::Bind(&sock))?;
    if let Err(e) = bind_service(&sock, addr) {
        sock.drop_names();
        return Err(e);
    }
    if let Err(e) = sock.real().and_then(|h| host::bind(h, &bytes[..host_len as usize]).map_err(rx_err)) {
        // The address reading already put the inode and the abstract name on
        // the socket; the real bind then failing -- AF_UNIX bind on a sandboxed
        // /tmp is EPERM -- must give both back. Clearing as well as releasing is
        // what makes it idempotent: the descriptor's close runs the same two
        // releases, and doing them twice corrupted the allocator's free list.
        sock.drop_names();
        return Err(e);
    }
    Ok(())
}

/// `inet_port_requires_bind_service`: a port below 1024
/// (`ip_unprivileged_port_start`) is `CAP_NET_BIND_SERVICE`'s, `EACCES`
/// after the address itself has been judged. The host may not be asked: on
/// macOS a user process may bind most of them, so the host's answer was the
/// only one this gave (`caps_probe`). `sin_port` and `sin6_port` are both at
/// offset 2, big-endian.
fn bind_service(sock: &Sock, addr: u64) -> Result<(), Errno> {
    const UNPRIVILEGED_PORT_START: u16 = 1024;
    if !matches!(sock.domain(), guest::PF_INET | guest::PF_INET6) {
        return Ok(());
    }
    let mut port = [0u8; 2];
    if GuestMem.read(addr + 2, &mut port) != 0 {
        return Err(Errno::EFAULT);
    }
    let port = u16::from_be_bytes(port);
    if port != 0 && port < UNPRIVILEGED_PORT_START && !taskview::capable(taskview::caps::CAP_NET_BIND_SERVICE) {
        return Err(Errno::EACCES);
    }
    Ok(())
}

pub fn sys_connect(sock_fd: c_int, addr: u64, len: c_uint) -> Result<(), Errno> {
    strace!("connect({sock_fd}, {addr:#x}, {len})");
    let sock = Sock::get(sock_fd)?;
    // `AF_UNSPEC` dissolves a datagram socket's association: `getpeername` is
    // ENOTCONN after it and `send` without an address EDESTADDRREQ. The
    // address translation refused the family, so it was EINVAL and the socket
    // stayed connected (`tests/guest` udp_probe).
    if sock.ty() == guest::SOCK_DGRAM && matches!(sock.domain(), guest::PF_INET | guest::PF_INET6) && len >= 2 {
        let mut family = [0u8; 2];
        if GuestMem.read(addr, &mut family) != 0 {
            return Err(Errno::EFAULT);
        }
        // Linux's AF_UNSPEC, 0 in every family table.
        if u16::from_le_bytes(family) == 0 {
            return host::disconnect(sock.real()?).map_err(rx_err);
        }
    }
    let (bytes, host_len) = read_addr_for(addr, len, AddrFor::Connect(&sock))?;

    if let Err(e) = host::connect(sock.real()?, &bytes[..host_len as usize]) {
        let ce = e.raw_os_error();
        // The connect that reports a *completed* non-blocking connect.
        //
        // Linux's inet_stream_connect moves the socket from SS_CONNECTING to
        // SS_CONNECTED on the call that finds it established, and that call
        // returns 0. Only the one after it gets EISCONN. Calling connect() again
        // is therefore a documented way to collect the result of a non-blocking
        // connect, alongside getsockopt(SO_ERROR), and code that uses it reads
        // EISCONN as a failure.
        //
        // Darwin has no such state: it answers EISCONN as soon as the connection
        // is up, so the first collecting call already failed. One bit per socket
        // is enough to tell the two apart -- set by the EINPROGRESS that started
        // the connect and cleared by the call that reports it.
        //
        // A `swap` rather than a read and a store: a second `connect` on the
        // same socket is exactly how this bit is collected, so the two calls
        // that race for it must not both see it set.
        if ce == libc::EISCONN
            && sock.state().connect_in_progress.swap(false, Ordering::Relaxed)
        {
            return Ok(());
        }
        if ce == libc::EINPROGRESS {
            sock.state().connect_in_progress.store(true, Ordering::Relaxed);
        }
        if ce != libc::EINPROGRESS && ce != libc::EALREADY {
            strace!("connect({sock_fd}) failed, errno={ce}");
        }
        return Err(rx_err(e));
    }
    // A connect that completed outright leaves nothing to collect.
    sock.state().connect_in_progress.store(false, Ordering::Relaxed);

    if sock.is_unix() {
        // The credentials are refreshed here: a process that connects after
        // changing its ids is what the peer is told about.
        let cred = caller_cred();
        unixpeer::with_table(|t| t.set_cred(sock.peer(), cred));

        // Publish an id for ourselves, and send that -- not our address. See
        // UNIX_HANDSHAKE_MAGIC.
        let Some(id) = unixpeer::with_table(|t| t.publish(sock.peer())) else {
            return Err(Errno::ENOMEM);
        };
        let mut hs = [0u8; 16];
        hs[..8].copy_from_slice(&UNIX_HANDSHAKE_MAGIC.to_le_bytes());
        hs[8..].copy_from_slice(&id.to_le_bytes());
        if io_full(sock.real()?, &mut hs, true) != Some(hs.len()) {
            // Nothing was sent, so nothing can ever claim it.
            unixpeer::with_table(|t| t.unpublish(id));
        }
        // And that is all connect does. It used to wait here for the accept
        // side to claim the handshake, which Linux does not do and which had no
        // reliable end. The pending entry stays for accept to claim; the close
        // path removes it if this socket goes away first.
    }
    Ok(())
}
