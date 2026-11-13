//! The guest's own socket constants.
//!
//! These are the aarch64 Linux ABI and are fixed by it. They deliberately do
//! not come from the host's headers: the host is Darwin, most of these numbers
//! differ there, and the ones that happen to agree agree by accident.
//!
//! Every bug this table has had was a missing or wrong entry on *this* side.
//! `SO_RCVTIMEO` was listed only at 66, the number the 64-bit `time_t`
//! transition introduced, so musl's 20 was unmapped and no socket timeout could
//! be set. `MSG_NOSIGNAL` was absent, so a send on a dropped connection killed
//! the caller. `MSG_CMSG_CLOEXEC` was absent, so received descriptors leaked
//! into children. None was reachable by a test, because the table was
//! `static inline` in a header.

#![allow(dead_code)]

use std::ffi::c_int;

// Address and protocol families.
pub const PF_LOCAL: c_int = 1;
pub const PF_INET: c_int = 2;
pub const PF_INET6: c_int = 10;
/// `AF_NETLINK`. The host has no such family — `crates/fs/netlink` answers the
/// two requests an interface enumerator sends, so `family_to_real` deliberately
/// does *not* map it and `sys_socket` catches it before asking the host.
pub const PF_NETLINK: c_int = 16;

// Socket types. The low byte is the type; the rest are flags that `socket()`
// and `socketpair()` apply to the descriptor rather than to the socket.
pub const TYPE_MASK: c_int = 0xff;
pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const SOCK_RAW: c_int = 3;
pub const SOCK_SEQPACKET: c_int = 5;

/// The two flags a `type` may carry beside the type itself.
pub const SOCK_NONBLOCK: c_int = 0o4000;
pub const SOCK_CLOEXEC: c_int = 0o2000000;

// Message flags.
pub const MSG_OOB: c_int = 0x1;
pub const MSG_PEEK: c_int = 0x2;
pub const MSG_CTRUNC: c_int = 0x8;
pub const MSG_TRUNC: c_int = 0x20;
pub const MSG_DONTWAIT: c_int = 0x40;
pub const MSG_EOR: c_int = 0x80;
pub const MSG_WAITALL: c_int = 0x100;
pub const MSG_NOSIGNAL: c_int = 0x4000;
pub const MSG_CMSG_CLOEXEC: c_int = 0x4000_0000;

// Option levels.
pub const SOL_SOCKET: c_int = 1;

// SOL_SOCKET options.
pub const SO_REUSEADDR: c_int = 2;
pub const SO_TYPE: c_int = 3;
pub const SO_ERROR: c_int = 4;
pub const SO_DONTROUTE: c_int = 5;
pub const SO_BROADCAST: c_int = 6;
pub const SO_SNDBUF: c_int = 7;
pub const SO_RCVBUF: c_int = 8;
pub const SO_KEEPALIVE: c_int = 9;
pub const SO_OOBINLINE: c_int = 10;
pub const SO_PRIORITY: c_int = 12;
pub const SO_LINGER: c_int = 13;
pub const SO_REUSEPORT: c_int = 15;
pub const SO_PASSCRED: c_int = 16;
pub const SO_PEERCRED: c_int = 17;
/// aarch64 Linux carries both numberings for the timeouts. The `_OLD` pair is
/// from before the 64-bit `time_t` transition, and a libc whose `time_t` is
/// already 64 bits keeps using them -- musl on aarch64 sends 20 and 21.
pub const SO_RCVTIMEO_OLD: c_int = 20;
pub const SO_SNDTIMEO_OLD: c_int = 21;
pub const SO_TIMESTAMP: c_int = 29;
/// `SO_SNDBUF` and `SO_RCVBUF` past `wmem_max`/`rmem_max`, `CAP_NET_ADMIN`'s,
/// and only for `setsockopt`: `getsockopt` does not know them.
pub const SO_SNDBUFFORCE: c_int = 32;
pub const SO_RCVBUFFORCE: c_int = 33;
pub const SO_PROTOCOL: c_int = 38;
pub const SO_DOMAIN: c_int = 39;
pub const SO_RCVTIMEO_NEW: c_int = 66;
pub const SO_SNDTIMEO_NEW: c_int = 67;

// IPPROTO_IP options.
pub const IP_TOS: c_int = 1;
pub const IP_TTL: c_int = 2;
pub const IP_HDRINCL: c_int = 3;
pub const IP_RETOPTS: c_int = 7;
pub const IP_PKTINFO: c_int = 8;
pub const IP_MTU_DISCOVER: c_int = 10;
pub const IP_RECVERR: c_int = 11;
pub const IP_RECVTTL: c_int = 12;
pub const IP_RECVTOS: c_int = 13;
pub const IP_MULTICAST_TTL: c_int = 33;
pub const IP_MULTICAST_LOOP: c_int = 34;

// IPPROTO_TCP options.
pub const TCP_NODELAY: c_int = 1;
pub const TCP_MAXSEG: c_int = 2;
pub const TCP_KEEPIDLE: c_int = 4;
pub const TCP_KEEPINTVL: c_int = 5;
pub const TCP_KEEPCNT: c_int = 6;
pub const TCP_DEFER_ACCEPT: c_int = 9;
pub const TCP_INFO: c_int = 11;
pub const TCP_QUICKACK: c_int = 12;
pub const TCP_CONGESTION: c_int = 13;
pub const TCP_USER_TIMEOUT: c_int = 18;

// IPPROTO_IPV6 options.
pub const IPV6_UNICAST_HOPS: c_int = 16;
pub const IPV6_RECVPKTINFO: c_int = 49;
pub const IPV6_RECVERR: c_int = 25;

/// `IPPROTO_ICMPV6`'s only option here. Settable on a real `SOCK_RAW` alone.
pub const ICMP6_FILTER: c_int = 1;
pub const IPV6_V6ONLY: c_int = 26;
pub const IPV6_TCLASS: c_int = 67;

/// Protocol numbers. These are the IANA assignments and are the same
/// everywhere, which is why the levels above `SOL_SOCKET` need no translation.
pub const IPPROTO_IP: c_int = 0;
pub const IPPROTO_ICMP: c_int = 1;
pub const IPPROTO_TCP: c_int = 6;
pub const IPPROTO_UDP: c_int = 17;
pub const IPPROTO_IPV6: c_int = 41;
pub const IPPROTO_ICMPV6: c_int = 58;
pub const IPPROTO_RAW: c_int = 255;
