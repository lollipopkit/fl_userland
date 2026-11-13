//! Netlink socket emulation and packet reply framing.
//!
//! The host has no `AF_NETLINK`, so this module translates route queries into
//! replies sent over a private datagram pair.

use std::ffi::c_int;

use sockabi::guest;

use super::{Errno, SOCKET_TYPE_MASK, Sock, fd_create, ffi, host, rx_err, state_of};

/// `socket(AF_NETLINK, SOCK_RAW|SOCK_DGRAM, NETLINK_ROUTE)`.
///
/// Answered `EAFNOSUPPORT` until 2026-09-08, and that stopped `ip addr` and
/// **every Go program that calls `net.Interfaces()`** — the Go runtime
/// enumerates interfaces with netlink on Linux and has no fallback, so the call
/// fails rather than answering a short list.
///
/// A `SOCK_DGRAM` `AF_UNIX` pair, one end kept: see [`SocketState::netlink_end`]
/// for why a pair rather than a queue. Message boundaries matter here — a
/// netlink reader takes one datagram at a time and walks the messages in it —
/// which is the other reason `SOCK_DGRAM` and not `SOCK_STREAM`.
pub(super) fn netlink_socket(ty: c_int, protocol: c_int) -> Result<c_int, Errno> {
    // Linux takes either type for netlink and treats them the same. Anything
    // else is EPROTONOSUPPORT rather than EINVAL, which is what a caller asking
    // for a protocol this kernel does not carry gets.
    // `& SOCKET_TYPE_MASK` is the type; `& !` is the *flags*, and using the
    // second here refused `SOCK_RAW|SOCK_CLOEXEC` -- which is exactly what Go's
    // `netlinkrib` asks for, so the first version of this answered
    // `socket type not supported` to the caller it was written for.
    let bare = ty & SOCKET_TYPE_MASK;
    if bare != guest::SOCK_RAW && bare != guest::SOCK_DGRAM {
        return Err(Errno::ESOCKTNOSUPPORT);
    }
    if protocol != netlink::NETLINK_ROUTE {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let (a, b) = host::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0).map_err(rx_err)?;
    let pair = [a, b];
    // A dump of every interface on a machine with many is larger than the
    // default datagram buffer, and a send that does not fit is EMSGSIZE rather
    // than a short write. Asked for rather than assumed: the reply is split at
    // message boundaries below if the host refuses it.
    let want = 1 << 20;
    for fd in &pair {
        let _ = rustix::net::sockopt::set_socket_send_buffer_size(fd, want);
        let _ = rustix::net::sockopt::set_socket_recv_buffer_size(fd, want);
    }
    // fd_create consumes the guest's end whatever happens, and the kernel's
    // end closes as it drops on either refusal.
    let [guest_end, kernel_end] = pair;
    let num = fd_create(guest_end, guest::PF_NETLINK, ty, protocol)?;
    let Some(fd) = fs_fdobj::f_get(num) else {
        return Err(Errno::EBADF);
    };
    let fd = &*fd;
    // The socket was made a line ago, so it has a state and the cell is
    // empty: `set` hands the value back only to a second setter.
    if let Some(state) = state_of(fd) {
        let _ = state.netlink_end.set(kernel_end);
    }
    Ok(num)
}

/// The netlink socket `fd` is, for a caller outside this crate that will hand
/// it a datagram: `mq_notify(SIGEV_THREAD)`, whose registration names one.
///
/// Linux's `netlink_getsockbyfilp`, and its two refusals as a real arm64
/// kernel answers them (`tests/guest` mqueue_probe): `ENOTSOCK` for a
/// descriptor that is not a socket, and `EINVAL` -- not `ECONNREFUSED` -- for
/// a socket of another family.
pub fn netlink_of(fd: &ffi::fd) -> Result<(), Errno> {
    match state_of(fd) {
        Some(state) if state.domain == guest::PF_NETLINK && state.netlink().is_some() => Ok(()),
        Some(_) => Err(Errno::EINVAL),
        None if fd.type_ as u32 & libc::S_IFMT as u32 == libc::S_IFSOCK as u32 => Err(Errno::EINVAL),
        None => Err(Errno::ENOTSOCK),
    }
}

/// Queue `datagram` for the guest to read from the netlink socket `fd`, as a
/// kernel-originated message: written into the kernel's end of the pair,
/// which is where every reply this crate composes goes too.
///
/// Non-blocking: the caller is a send that must not wait on a reader. A full
/// socket answers `EAGAIN` and the datagram is not queued, which is what
/// `netlink_sendskb` does to a receive queue past its limit.
pub fn netlink_deliver(fd: &ffi::fd, datagram: &[u8]) -> Result<(), Errno> {
    netlink_of(fd)?;
    let Some(end) = state_of(fd).and_then(|s| s.netlink()) else {
        return Err(Errno::EBADF);
    };
    match rustix::net::send(end, datagram, rustix::net::SendFlags::DONTWAIT) {
        Ok(_) => Ok(()),
        Err(e) => Err(Errno::from_negative_or_eio(kernel_errno::raised(e.raw_os_error()))),
    }
}

/// Answer one buffer of netlink requests, writing the replies into the kernel's
/// end of the pair.
///
/// Returns what `send` should answer: the whole length, because netlink accepts
/// the request and reports a refusal *in the reply* — an `NLMSG_ERROR`. A
/// caller that got an error from `send` would report "cannot talk to the
/// kernel" rather than "the kernel does not do that".
pub(super) fn netlink_send(sock: Sock<'_>, buffer: &[u8]) -> c_int {
    let Some(end) = sock.state().netlink() else {
        return Errno::EBADF.as_c_int();
    };
    let mut reply = Vec::new();
    for req in netlink::parse(buffer) {
        match req.kind {
            netlink::RTM_GETLINK => {
                reply.extend_from_slice(&netlink::links(&netlink::host_ifaces(), req.seq, req.pid))
            }
            netlink::RTM_GETADDR => {
                reply.extend_from_slice(&netlink::addrs(&netlink::host_ifaces(), req.seq, req.pid))
            }
            // A dump, and only a dump. `ip route get 8.8.8.8` sends the same
            // message *without* NLM_F_DUMP and wants the single route that
            // would be used -- a different answer, and one this cannot give
            // without a longest-prefix match of its own. Answering with the
            // whole table made `ip` say "can't talk to rtnetlink: Invalid
            // argument", which reads as a broken kernel rather than an
            // unimplemented query.
            netlink::RTM_GETROUTE if req.flags & netlink::NLM_F_DUMP != 0 => {
                let table = netlink::route::host_routes();
                reply.extend_from_slice(&netlink::routes(&table, req.family, req.seq, req.pid))
            }
            netlink::RTM_GETNEIGH if req.flags & netlink::NLM_F_DUMP != 0 => {
                let ns = netlink::route::host_neighbours();
                let ifaces = netlink::host_ifaces();
                reply.extend_from_slice(&netlink::neighbours(&ns, &ifaces, req.seq, req.pid))
            }
            // `ip route get <addr>`: one route rather than the table, and no
            // NLMSG_DONE after it. A query with no destination, or one nothing
            // matches, is the ordinary error -- ENETUNREACH, which is what a
            // real kernel answers and what `ip` prints as "Network is
            // unreachable" rather than as a broken kernel.
            netlink::RTM_GETROUTE => {
                let table = netlink::route::host_routes();
                let ifaces = netlink::host_ifaces();
                match netlink::route_get(&table, &ifaces, &req, req.seq, req.pid) {
                    Some(one) => reply.extend_from_slice(&one),
                    None => netlink::error(&mut reply, 101, req.seq, req.pid, &req.header),
                }
            }
            // Everything else, including a request that would *change* the
            // host's network. Refused in the reply rather than by closing the
            // socket, because a caller reads the errno out of it.
            _ => netlink::error(&mut reply, 95, req.seq, req.pid, &req.header),
        }
    }
    if reply.is_empty() {
        return buffer.len() as c_int;
    }
    // One datagram if it fits, else split at message boundaries: a reader takes
    // whole messages out of each and loops until NLMSG_DONE, so several
    // datagrams are what a real kernel sends for a large dump too. Splitting
    // anywhere else would hand it half a header.
    for chunk in netlink_chunks(&reply) {
        if let Err(e) = rustix::net::send(end, chunk, rustix::net::SendFlags::empty()) {
            return Errno::from_negative_or_eio(kernel_errno::raised(e.raw_os_error())).as_c_int();
        }
    }
    buffer.len() as c_int
}

/// Split a reply at message boundaries, into pieces a datagram can hold.
fn netlink_chunks(reply: &[u8]) -> Vec<&[u8]> {
    const LIMIT: usize = 32 * 1024;
    let mut out = Vec::new();
    let (mut start, mut at) = (0usize, 0usize);
    while at + netlink::NLMSG_HDRLEN <= reply.len() {
        let len = u32::from_le_bytes(reply[at..at + 4].try_into().unwrap()) as usize;
        if len < netlink::NLMSG_HDRLEN {
            break;
        }
        let step = netlink::align4(len).min(reply.len() - at);
        if at > start && at + step - start > LIMIT {
            out.push(&reply[start..at]);
            start = at;
        }
        at += step;
    }
    if start < reply.len() {
        out.push(&reply[start..]);
    }
    out
}
