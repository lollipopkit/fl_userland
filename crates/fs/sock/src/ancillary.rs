//! A received datagram's control messages, from the host's terms to Linux's.
//!
//! Only `SCM_RIGHTS` reached a guest until 2026-10-18; every other message
//! the host delivered was dropped, and the one-descriptor buffer it was read
//! into made Darwin report `MSG_CTRUNC` as well. A resolver or a DHCP or QUIC
//! server that asks `IP_PKTINFO` which local address a datagram came in on
//! got nothing (`tests/guest` udp_probe).
//!
//! What differs between the two:
//!
//! - the numbers: Darwin's `IP_PKTINFO` is 26, `IPV6_PKTINFO` 46, its
//!   `SOL_SOCKET` 0xffff;
//! - what a TTL and a TOS arrive as: Darwin sends `IP_RECVTTL`/`IP_RECVTOS`
//!   with a byte each, Linux `IP_TTL` with an `int` and `IP_TOS` with a byte;
//! - a timestamp's `tv_usec`, an `int` there and a `long` here;
//! - `IP_PKTINFO` on an IPv6 socket, which Darwin refuses and Linux applies
//!   to the IPv4 datagrams a dual-stack socket receives. The socket asks the
//!   host for `IPV6_RECVPKTINFO` instead, and [`to_guest`] makes the IPv4
//!   message from the IPv6 one for a v4-mapped address.
//!
//! The payload structs that are kept (`in_pktinfo`, `in6_pktinfo`) have the
//! same layout on both.

use std::ffi::c_int;

use crate::host::HostCmsg;

mod guest {
    pub const SOL_SOCKET: i32 = 1;
    pub const SO_TIMESTAMP: i32 = 29;
    pub const IPPROTO_IP: i32 = 0;
    pub const IP_TOS: i32 = 1;
    pub const IP_TTL: i32 = 2;
    pub const IP_PKTINFO: i32 = 8;
    pub const IPPROTO_IPV6: i32 = 41;
    pub const IPV6_PKTINFO: i32 = 50;
}

/// Which pktinfo an IPv6 socket's guest asked for: the host was asked for
/// `IPV6_RECVPKTINFO` if either was.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct V6Wants {
    pub(crate) ip_pktinfo: bool,
    pub(crate) ipv6_pktinfo: bool,
}

/// The guest's messages for `host`'s, in the order Linux's `udp_recvmsg` and
/// `udpv6_recvmsg` put them: the timestamp, then IPv6 pktinfo, then the IPv4
/// ones (pktinfo, TTL, TOS). `v6` is `Some` for an IPv6 socket.
pub(crate) fn to_guest(host: &[HostCmsg], v6: Option<V6Wants>) -> Vec<u8> {
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut push = |rank, level, ty, payload: &[u8]| out.push((rank, cmsg::build(level, ty, payload)));
    for m in host {
        match (m.level, m.ty) {
            (libc::SOL_SOCKET, libc::SCM_TIMESTAMP) if m.data.len() >= 12 => {
                let sec = i64::from_ne_bytes(m.data[0..8].try_into().unwrap());
                let usec = i64::from(i32::from_ne_bytes(m.data[8..12].try_into().unwrap()));
                let tv: Vec<u8> = sec.to_le_bytes().into_iter().chain(usec.to_le_bytes()).collect();
                push(0, guest::SOL_SOCKET, guest::SO_TIMESTAMP, &tv);
            }
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) if m.data.len() >= 20 => {
                let wants = v6.unwrap_or(V6Wants { ip_pktinfo: false, ipv6_pktinfo: true });
                if wants.ipv6_pktinfo {
                    push(1, guest::IPPROTO_IPV6, guest::IPV6_PKTINFO, &m.data[..20]);
                }
                let mapped = m.data[..10].iter().all(|&b| b == 0) && m.data[10..12] == [0xff, 0xff];
                if wants.ip_pktinfo && mapped {
                    // `in_pktinfo`: the interface, then the local address
                    // twice -- the one the datagram was sent to and the one a
                    // reply would come from, which are the same for a unicast
                    // datagram to this host.
                    let addr = &m.data[12..16];
                    let mut p = m.data[16..20].to_vec();
                    p.extend_from_slice(addr);
                    p.extend_from_slice(addr);
                    push(2, guest::IPPROTO_IP, guest::IP_PKTINFO, &p);
                }
            }
            (libc::IPPROTO_IP, libc::IP_PKTINFO) if m.data.len() >= 12 => {
                push(2, guest::IPPROTO_IP, guest::IP_PKTINFO, &m.data[..12]);
            }
            (libc::IPPROTO_IP, libc::IP_RECVTTL) if !m.data.is_empty() => {
                push(3, guest::IPPROTO_IP, guest::IP_TTL, &c_int::from(m.data[0]).to_le_bytes());
            }
            (libc::IPPROTO_IP, libc::IP_RECVTOS) if !m.data.is_empty() => {
                push(4, guest::IPPROTO_IP, guest::IP_TOS, &m.data[..1]);
            }
            // Anything else has no Linux counterpart a guest asked for.
            _ => {}
        }
    }
    out.sort_by_key(|(rank, _)| *rank);
    out.into_iter().flat_map(|(_, m)| m).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(level: c_int, ty: c_int, data: &[u8]) -> HostCmsg {
        HostCmsg { level, ty, data: data.to_vec() }
    }

    /// (level, type, payload) of each guest message, read back.
    fn read(buf: &[u8]) -> Vec<(i32, i32, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + 16 <= buf.len() {
            let len = u64::from_le_bytes(buf[at..at + 8].try_into().unwrap()) as usize;
            let level = i32::from_le_bytes(buf[at + 8..at + 12].try_into().unwrap());
            let ty = i32::from_le_bytes(buf[at + 12..at + 16].try_into().unwrap());
            out.push((level, ty, buf[at + 16..at + len].to_vec()));
            at += (len + 7) & !7;
        }
        out
    }

    fn in6_mapped(ifindex: u32) -> Vec<u8> {
        let mut d = vec![0u8; 10];
        d.extend_from_slice(&[0xff, 0xff, 127, 0, 0, 1]);
        d.extend_from_slice(&ifindex.to_ne_bytes());
        d
    }

    #[test]
    fn ttl_and_tos_become_linux_types_and_widths_in_linux_order() {
        let got = read(&to_guest(&[host(libc::IPPROTO_IP, libc::IP_RECVTOS, &[0x10]), host(libc::IPPROTO_IP, libc::IP_RECVTTL, &[64])], None));
        assert_eq!(got, vec![(0, 2, 64i32.to_le_bytes().to_vec()), (0, 1, vec![0x10])]);
    }

    #[test]
    fn a_timestamp_widens_usec() {
        let mut d = 5i64.to_ne_bytes().to_vec();
        d.extend_from_slice(&7i32.to_ne_bytes());
        d.extend_from_slice(&[0; 4]);
        let got = read(&to_guest(&[host(libc::SOL_SOCKET, libc::SCM_TIMESTAMP, &d)], None));
        let mut want = 5i64.to_le_bytes().to_vec();
        want.extend_from_slice(&7i64.to_le_bytes());
        assert_eq!(got, vec![(1, 29, want)]);
    }

    #[test]
    fn an_ipv6_socket_gets_the_pktinfo_it_asked_for_v6_first() {
        let m = [host(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &in6_mapped(1))];
        let only4 = read(&to_guest(&m, Some(V6Wants { ip_pktinfo: true, ipv6_pktinfo: false })));
        let mut in4 = 1u32.to_ne_bytes().to_vec();
        in4.extend_from_slice(&[127, 0, 0, 1, 127, 0, 0, 1]);
        assert_eq!(only4, vec![(0, 8, in4.clone())]);
        let both = read(&to_guest(&m, Some(V6Wants { ip_pktinfo: true, ipv6_pktinfo: true })));
        assert_eq!(both, vec![(41, 50, in6_mapped(1)), (0, 8, in4)]);
        let only6 = read(&to_guest(&m, Some(V6Wants { ip_pktinfo: false, ipv6_pktinfo: true })));
        assert_eq!(only6, vec![(41, 50, in6_mapped(1))]);
    }

    /// Darwin's layout: a 32-bit length, level and type, then the payload,
    /// each message 4-byte aligned; a length past the buffer ends the walk.
    #[test]
    fn host_messages_are_read_from_darwins_layout() {
        let mut buf = Vec::new();
        for (level, ty, data) in [(0i32, 24i32, vec![64u8]), (41, 46, vec![9u8; 20])] {
            buf.extend_from_slice(&(12 + data.len() as u32).to_ne_bytes());
            buf.extend_from_slice(&level.to_ne_bytes());
            buf.extend_from_slice(&ty.to_ne_bytes());
            buf.extend_from_slice(&data);
            buf.resize((buf.len() + 3) & !3, 0);
        }
        let got = crate::host::parse_host_cmsgs(&buf);
        assert_eq!(got, vec![host(0, 24, &[64]), host(41, 46, &[9; 20])]);
        buf.extend_from_slice(&100u32.to_ne_bytes());
        buf.extend_from_slice(&[0; 8]);
        assert_eq!(crate::host::parse_host_cmsgs(&buf).len(), 2, "an overlong one is not read");
    }

    #[test]
    fn a_kind_with_no_linux_counterpart_is_dropped() {
        assert!(to_guest(&[host(libc::IPPROTO_IP, libc::IP_RECVDSTADDR, &[127, 0, 0, 1])], None).is_empty());
    }
}
