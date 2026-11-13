//! Socket name and peer query operations.

use super::*;

// ---------------------------------------------------------------------------
// Addresses out
// ---------------------------------------------------------------------------

pub fn sys_getsockname(sock_fd: c_int, addr: u64, len_addr: u64) -> Result<(), Errno> {
    strace!("getsockname({sock_fd}, {addr:#x}, {len_addr:#x})");
    let sock = Sock::get(sock_fd)?;
    let buffer_len = get_u32(len_addr)?;

    // A netlink socket's name is a `sockaddr_nl`: family, two bytes of pad, the
    // port id and the group mask. Zero for both, which is what an unbound one
    // reports and what a caller that did not choose a port sees.
    if sock.is_netlink() {
        let mut bytes = [0u8; 12];
        bytes[..2].copy_from_slice(&(guest::PF_NETLINK as u16).to_le_bytes());
        return put_addr(addr, len_addr, &bytes, bytes.len() as u32, buffer_len);
    }
    // A unix socket answers with the same string that was passed to bind, which
    // the host cannot be asked for: the host socket is bound to a path in /tmp.
    if sock.is_unix() {
        let (bytes, report) = unix_addr(sock.peer(), false);
        return put_addr(addr, len_addr, &bytes, report, buffer_len);
    }

    let name = host::sockname(sock.real()?).map_err(rx_err)?;
    let report = write_host_addr(addr, name.as_slice(), buffer_len)?;
    put_u32(len_addr, report)
}

pub fn sys_getpeername(sock_fd: c_int, addr: u64, len_addr: u64) -> Result<(), Errno> {
    strace!("getpeername({sock_fd}, {addr:#x}, {len_addr:#x})");
    let sock = Sock::get(sock_fd)?;
    let buffer_len = get_u32(len_addr)?;

    // A unix socket's peer is named by whatever *it* passed to bind, which the
    // peer edge makes reachable. A peer that never bound has no name, and then
    // the family alone is the answer -- which is the host path below, whose
    // PF_LOCAL arm reports exactly that.
    if sock.is_unix() {
        let (bytes, report) = unix_addr(sock.peer(), true);
        if report > 2 {
            return put_addr(addr, len_addr, &bytes, report, buffer_len);
        }
    }

    let peer = host::peername(sock.real()?).map_err(rx_err)?;
    let report = write_host_addr(addr, peer.as_slice(), buffer_len)?;
    put_u32(len_addr, report)
}
