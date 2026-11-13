//! Socket creation and guest to host socket parameter translation.

use super::*;
use std::os::fd::AsFd;

// ---------------------------------------------------------------------------
// Creating one
// ---------------------------------------------------------------------------

/// Wraps a host socket in a `struct fd`.
///
/// **Consumes `host` however it ends** -- an `OwnedFd` since 2026-09-29, so
/// that is a signature rather than a sentence. On success the `struct fd` owns
/// it; on every failure it closes as it drops. The question "who owns this
/// number now" had three answers before the sentence: the
/// allocation failing left the descriptor with the caller, the `unixpeer` open
/// closed it because `fd_close` runs `sock_close` which ends in
/// `realfs_close`, and `f_install` closed it too, on the `EMFILE` path that any
/// program opening enough sockets reaches.
pub(crate) fn fd_new(
    host: OwnedFd,
    domain: c_int,
    ty: c_int,
    protocol: c_int,
) -> Option<fs_fdobj::Owned> {
    let mut fd = fs_adhoc::adhoc_new(socket_fdops_get(), fs_adhoc::Kind::Socket);
    // Before the descriptor is reachable, so `state_of` never sees a null:
    // `sock_close` is the only thing that gives it back, and it runs for every
    // socket descriptor including the ones this function goes on to abandon.
    let state = Box::new(SocketState {
        domain,
        type_: ty & SOCKET_TYPE_MASK,
        protocol,
        ..SocketState::default()
    });
    fd.stat.mode = (libc::S_IFSOCK | 0o666) as u32;
    fd.real_fd = Some(host);
    fd.set_driver_state(state);
    // Published before the peer is opened, so that a failure below closes it
    // through `sock_close` as every other socket is closed.
    let owned = fd.into_owned();
    if domain == guest::PF_LOCAL {
        // Everything about the other end is crates/fs/unixpeer, keyed by this
        // handle. The credentials are the *effective* ids, as Linux's
        // init_peercred takes them.
        let cred = caller_cred();
        let handle = unixpeer::with_table(|t| t.open(cred)).unwrap_or(0);
        if handle == 0 {
            // `owned` goes, which runs `sock_close` and closes `host`.
            return None;
        }
        // Written through the shared reference, before the descriptor is
        // reachable: there is no second writer, and the atomic is what makes
        // the *shared* reference enough to write through.
        if let Some(state) = state_of(&owned) {
            state.unix_peer.store(handle, Ordering::Relaxed);
        }
    }
    Some(owned)
}



/// A guest descriptor number for a fresh host socket. Consumes `host`.
pub(crate) fn fd_create(
    host: OwnedFd,
    domain: c_int,
    ty: c_int,
    protocol: c_int,
) -> Result<c_int, Errno> {
    match fd_new(host, domain, ty, protocol) {
        None => Err(Errno::ENOMEM),
        // `f_install` still answers a descriptor number or a negative errno.
        Some(fd) => Errno::split(fs_fdobj::f_install(fd, ty & !SOCKET_TYPE_MASK) as i64)
            .map(|n| n as c_int),
    }
}

/// The host `(domain, type, protocol)` a guest triple asks for.
fn to_real(
    domain: c_int,
    ty: c_int,
    protocol: c_int,
) -> Result<(c_int, c_int, c_int), Errno> {
    // Bits outside the type and its two flags are EINVAL, which nothing
    // checked: socket(AF_UNIX, SOCK_STREAM | 0x1000000, 0) was a plain stream
    // socket and the caller was told its request had been honoured.
    if !sockabi::type_flags_ok(ty) {
        return Err(Errno::EINVAL);
    }
    let real_domain = sockabi::family_to_real(domain);
    if real_domain == sockabi::NONE {
        return Err(Errno::EAFNOSUPPORT);
    }
    // The domain decides which protocols and types are allowed: AF_UNIX takes 0
    // or PF_UNIX and every type including SOCK_RAW, which Linux maps to
    // SOCK_DGRAM. Judging it by the internet families' tables refused
    // socket(AF_UNIX, SOCK_STREAM, 1) and socket(AF_UNIX, SOCK_RAW, 0), both of
    // which a real kernel accepts.
    let real_type = sockabi::type_to_real_for(domain, ty, protocol);
    if real_type == sockabi::NONE {
        return Err(Errno::EINVAL);
    }
    // AF_UNIX's only non-zero protocol is PF_UNIX, which Linux accepts and
    // Darwin does not -- the host answers EPROTONOSUPPORT for it. It names the
    // same thing as 0 does, so 0 is what the host is asked for.
    let real_protocol = if domain == guest::PF_LOCAL {
        0
    } else {
        protocol
    };
    Ok((real_domain, real_type, real_protocol))
}

pub fn sys_socket(domain: c_uint, ty: c_uint, protocol: c_uint) -> Result<c_int, Errno> {
    strace!("socket({domain}, {ty}, {protocol})");
    let (domain, ty, protocol) = (domain as c_int, ty as c_int, protocol as c_int);
    // Before `to_real`, which has no host family to map this one to: see
    // `netlink_socket`.
    if domain == guest::PF_NETLINK {
        return netlink_socket(ty, protocol);
    }
    let (real_domain, real_type, mut real_protocol) = to_real(domain, ty, protocol)?;
    // `inet_create` and `inet6_create`: a raw socket is CAP_NET_RAW's, once
    // the family and type are known to exist. The host would make one for a
    // root host user and refuse it to anyone else, whoever the guest is.
    if ty & 0xf == guest::SOCK_RAW
        && matches!(domain, guest::PF_INET | guest::PF_INET6)
        && !taskview::capable(taskview::caps::CAP_NET_RAW)
    {
        return Err(Errno::EPERM);
    }
    // this hack makes mtr work
    if ty == guest::SOCK_RAW && protocol == libc::IPPROTO_RAW {
        real_protocol = libc::IPPROTO_ICMP;
    }

    let host = host::socket(real_domain, real_type, real_protocol).map_err(rx_err)?;

    if domain == guest::PF_INET && ty == guest::SOCK_DGRAM {
        // in some cases, such as ICMP, datagram sockets on mac can default to
        // including the IP header like raw sockets. Best effort: a socket
        // that refuses it is one that never had the header.
        const IP_STRIPHDR: c_int = 23;
        let _ = host::setsockopt_int(host.as_fd(), libc::IPPROTO_IP, IP_STRIPHDR, 1);
    }

    // fd_create consumes `host` whatever happens; see fd_new.
    fd_create(host, domain, ty, protocol)
}

pub fn sys_socketpair(
    domain: c_uint,
    ty: c_uint,
    protocol: c_uint,
    sockets_addr: u64,
) -> Result<(), Errno> {
    strace!("socketpair({domain}, {ty}, {protocol}, {sockets_addr:#x})");
    let (domain, ty, protocol) = (domain as c_int, ty as c_int, protocol as c_int);

    // The flags on the type come first -- `__sys_socketpair` opens with them,
    // above everything else, so `socketpair(AF_UNIX, 999, 0, NULL)` is `EINVAL`
    // and not `EFAULT`.
    if !sockabi::type_flags_ok(ty) {
        return Err(Errno::EINVAL);
    }

    // Then the place the two descriptors go, **before** anything is created.
    // Linux does this and the reason is visible in what it costs not to: a pair
    // made and then not reportable has to be closed again, and every version of
    // that unwind is a chance to leak one. Measured -- `socketpair(99, 0, 0,
    // NULL)` is `EFAULT` on a real kernel, not `EAFNOSUPPORT`, so the pointer is
    // looked at before the family that cannot exist.
    //
    // Read and write back, rather than a range test, because that is the only
    // way to ask this address space whether eight bytes are both readable and
    // writable. The bytes are unchanged, so nothing observable happens.
    let mut probe = [0u8; 8];
    if GuestMem.read(sockets_addr, &mut probe) != 0 || GuestMem.write(sockets_addr, &probe) != 0 {
        return Err(Errno::EFAULT);
    }

    let (real_domain, real_type, real_protocol) = to_real(domain, ty, protocol)?;

    let (a, b) = host::socketpair(real_domain, real_type, real_protocol).map_err(rx_err)?;

    // Each of these consumes its socket, and the other closes as it drops, so
    // what is left to undo is only what has been installed.
    let first = fd_create(a, domain, ty, protocol)?;
    let second = match fd_create(b, domain, ty, protocol) {
        Ok(n) => n,
        Err(e) => {
            // Unwinding a half-made pair. The close cannot fail for a
            // descriptor this function installed a moment ago, and if it did
            // there would be nothing to say about it -- the failure being
            // reported is the one from `fd_create`.
            let _ = fdcalls::sys_close(first);
            return Err(e);
        }
    };

    // The pair is linked after both descriptors exist, which is safe now that
    // the edge is a handle rather than a pointer: a close in between leaves one
    // side's handle out of the table and the link simply does not happen, where
    // a pointer would have been stored into a freed struct. The whole creation
    // used to run under peer_lock to prevent exactly that -- which meant
    // f_install, and the descriptor table's own lock, inside it.
    if let (Ok(a), Ok(b)) = (Sock::get(first), Sock::get(second)) {
        unixpeer::with_table(|t| t.link(a.peer(), b.peer()));
    }

    let pair = [(first as u32).to_le_bytes(), (second as u32).to_le_bytes()].concat();
    if GuestMem.write(sockets_addr, &pair) != 0 {
        {
            // Same: the answer to the caller is EFAULT, and a close that
            // failed here would have nowhere to be reported.
            let _ = fdcalls::sys_close(second);
            let _ = fdcalls::sys_close(first);
        }
        return Err(Errno::EFAULT);
    }
    strace!(" [{first}, {second}]");
    Ok(())
}
