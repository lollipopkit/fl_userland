//! Guest to host family, type, flag, and option mappings.

use super::*;

// ---------------------------------------------------------------- families

pub fn family_to_real(fake: c_int) -> c_int {
    match fake {
        guest::PF_LOCAL => libc::PF_LOCAL,
        guest::PF_INET => libc::PF_INET,
        guest::PF_INET6 => libc::PF_INET6,
        _ => NONE,
    }
}

pub fn family_from_real(real: c_int) -> c_int {
    match real {
        libc::PF_LOCAL => guest::PF_LOCAL,
        libc::PF_INET => guest::PF_INET,
        libc::PF_INET6 => guest::PF_INET6,
        _ => NONE,
    }
}

// ------------------------------------------------------------------- types

/// Whether `type`'s bits outside the type itself are ones this call defines.
///
/// Linux: `if (type & ~(SOCK_TYPE_MASK | SOCK_CLOEXEC | SOCK_NONBLOCK)) return
/// -EINVAL;`, at the top of `sys_socket`. Nothing checked here, so
/// `socket(AF_UNIX, SOCK_STREAM | 0x1000000, 0)` was a plain stream socket and
/// the caller was told its request had been honoured. Measured against a real
/// arm64 kernel, which answers `EINVAL`.
pub fn type_flags_ok(ty: c_int) -> bool {
    ty & !(guest::TYPE_MASK | guest::SOCK_NONBLOCK | guest::SOCK_CLOEXEC) == 0
}

/// Whether a protocol is one this family accepts.
///
/// `AF_UNIX` takes 0 or `PF_UNIX`, which is 1 — Linux's `unix_create` is
/// `if (protocol && protocol != PF_UNIX) return -EPROTONOSUPPORT;`. That is not
/// the same set as the internet families', and treating them alike refused
/// `socket(AF_UNIX, SOCK_STREAM, 1)`, which a real kernel accepts and
/// `socketpair` with it too.
pub(crate) fn protocol_ok(domain: c_int, protocol: c_int) -> bool {
    if domain == guest::PF_LOCAL {
        protocol == 0 || protocol == guest::PF_LOCAL
    } else {
        true // the internet families are judged per type below
    }
}

/// The host type for a guest `(domain, type, protocol)`, or [`NONE`].
///
/// `domain` matters: `AF_UNIX` accepts every type including `SOCK_RAW`, which
/// Linux maps to `SOCK_DGRAM` —
///
/// ```c
/// case SOCK_RAW:
///         sock->type = SOCK_DGRAM;
///         fallthrough;
/// case SOCK_DGRAM: ...
/// ```
///
/// — and its protocol rule is `protocol_ok` above rather than the per-type
/// tables the internet families need. `socket(AF_UNIX, SOCK_RAW, 0)` was
/// `EINVAL` here and works on Linux.
pub fn type_to_real_for(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    if !protocol_ok(domain, protocol) {
        return NONE;
    }
    if domain == guest::PF_LOCAL {
        return match ty & guest::TYPE_MASK {
            guest::SOCK_STREAM => libc::SOCK_STREAM,
            // Darwin has no SOCK_SEQPACKET; for AF_UNIX a stream is equivalent
            // in every respect but message boundaries.
            guest::SOCK_SEQPACKET => libc::SOCK_STREAM,
            guest::SOCK_DGRAM | guest::SOCK_RAW => libc::SOCK_DGRAM,
            _ => NONE,
        };
    }
    type_to_real(ty, protocol)
}

pub(crate) fn type_to_real(ty: c_int, protocol: c_int) -> c_int {
    match ty & guest::TYPE_MASK {
        guest::SOCK_STREAM => {
            if protocol == 0 || protocol == guest::IPPROTO_TCP {
                libc::SOCK_STREAM
            } else {
                NONE
            }
        }
        guest::SOCK_DGRAM => match protocol {
            0 | guest::IPPROTO_UDP | guest::IPPROTO_ICMP | guest::IPPROTO_ICMPV6 => {
                libc::SOCK_DGRAM
            }
            _ => NONE,
        },
        // A raw socket needs privileges iOS does not grant, so this is a
        // datagram socket instead. A guest asking for IPPROTO_RAW does not get
        // header control; it gets something that carries its packets.
        guest::SOCK_RAW => match protocol {
            guest::IPPROTO_RAW
            | guest::IPPROTO_UDP
            | guest::IPPROTO_ICMP
            | guest::IPPROTO_ICMPV6 => libc::SOCK_DGRAM,
            _ => NONE,
        },
        // Darwin has no SOCK_SEQPACKET. For AF_UNIX a stream is equivalent in
        // every respect but message boundaries, and Rust's std uses seqpacket
        // for the pipes it sets up around a spawn.
        //
        // TODO: a Linux host has the real thing and could be given it, but this
        // tree has no way to run its guest tests there, so the substitution is
        // unconditional rather than untested on one side.
        guest::SOCK_SEQPACKET => {
            if protocol == 0 {
                libc::SOCK_STREAM
            } else {
                NONE
            }
        }
        _ => NONE,
    }
}

// ------------------------------------------------------------------- flags

/// Guest flags that mean something, whether or not they map to a host bit.
const KNOWN_FLAGS: c_int = guest::MSG_OOB
    | guest::MSG_PEEK
    | guest::MSG_CTRUNC
    | guest::MSG_TRUNC
    | guest::MSG_DONTWAIT
    | guest::MSG_EOR
    | guest::MSG_WAITALL
    | guest::MSG_NOSIGNAL
    | guest::MSG_CMSG_CLOEXEC;

pub fn flags_to_real(fake: c_int) -> Flags {
    let mut real = 0;
    let pairs = [
        (guest::MSG_OOB, libc::MSG_OOB),
        (guest::MSG_PEEK, libc::MSG_PEEK),
        (guest::MSG_CTRUNC, libc::MSG_CTRUNC),
        (guest::MSG_TRUNC, libc::MSG_TRUNC),
        (guest::MSG_DONTWAIT, libc::MSG_DONTWAIT),
        (guest::MSG_EOR, libc::MSG_EOR),
        (guest::MSG_WAITALL, libc::MSG_WAITALL),
    ];
    for (from, to) in pairs {
        if fake & from != 0 {
            real |= to;
        }
    }
    // Two flags are handled by this kernel rather than translated.
    //
    // MSG_NOSIGNAL suppresses the *guest's* SIGPIPE, which `errno_map`
    // synthesises -- the host's own is ignored process-wide -- so `sock.c`
    // reads the guest bit directly. Darwin has no such flag and numbers
    // MSG_RCVMORE 0x4000, so passing it through would say something else
    // entirely.
    //
    // MSG_CMSG_CLOEXEC applies to the guest descriptor number, which this
    // kernel allocates, so the host's copy of the bit is about a different
    // descriptor and would be no answer at all. `sys_recvmsg` applies it when
    // it installs.
    Flags {
        real,
        unknown: fake & !KNOWN_FLAGS,
    }
}

pub fn flags_from_real(real: c_int) -> Flags {
    let mut fake = 0;
    let pairs = [
        (libc::MSG_OOB, guest::MSG_OOB),
        (libc::MSG_PEEK, guest::MSG_PEEK),
        (libc::MSG_CTRUNC, guest::MSG_CTRUNC),
        (libc::MSG_TRUNC, guest::MSG_TRUNC),
        (libc::MSG_DONTWAIT, guest::MSG_DONTWAIT),
        (libc::MSG_EOR, guest::MSG_EOR),
        (libc::MSG_WAITALL, guest::MSG_WAITALL),
    ];
    let mut known = 0;
    for (from, to) in pairs {
        known |= from;
        if real & from != 0 {
            fake |= to;
        }
    }
    Flags {
        real: fake,
        unknown: real & !known,
    }
}

// ----------------------------------------------------------------- options

/// Whether this is a level any protocol here answers for.
///
/// Linux answers `EOPNOTSUPP` for a level it does not have and `ENOPROTOOPT`
/// for an *option* a level it does have does not know. Both were
/// `ENOPROTOOPT` here, so a program probing for a socket family's options
/// could not tell "no such level" from "no such option" — which is the
/// distinction the two errnos exist for. Measured: `getsockopt(fd, 99, 1, ...)`
/// is `EOPNOTSUPP` on a real arm64 kernel.
pub fn level_known(level: c_int) -> bool {
    matches!(
        level,
        guest::SOL_SOCKET | guest::IPPROTO_IP | guest::IPPROTO_TCP | guest::IPPROTO_IPV6
    )
}

pub fn level_to_real(fake: c_int) -> c_int {
    if fake == guest::SOL_SOCKET {
        libc::SOL_SOCKET
    } else {
        // Everything else is a protocol number, and those are IANA's on both
        // sides.
        fake
    }
}

fn opt_socket(fake: c_int) -> OptMap {
    match fake {
        guest::SO_REUSEADDR => OptMap::real(libc::SO_REUSEADDR),
        guest::SO_TYPE => OptMap::real(libc::SO_TYPE),
        guest::SO_ERROR => OptMap::real(libc::SO_ERROR),
        guest::SO_DONTROUTE => OptMap::real(libc::SO_DONTROUTE),
        guest::SO_BROADCAST => OptMap::real(libc::SO_BROADCAST),
        guest::SO_SNDBUF => OptMap::real(libc::SO_SNDBUF),
        guest::SO_RCVBUF => OptMap::real(libc::SO_RCVBUF),
        guest::SO_KEEPALIVE => OptMap::real(libc::SO_KEEPALIVE),
        guest::SO_OOBINLINE => OptMap::real(libc::SO_OOBINLINE),
        guest::SO_LINGER => OptMap::real(libc::SO_LINGER),
        guest::SO_REUSEPORT => OptMap::real(libc::SO_REUSEPORT),
        guest::SO_TIMESTAMP => OptMap::real(libc::SO_TIMESTAMP),
        // Both numbering schemes reach the one host option.
        guest::SO_RCVTIMEO_OLD | guest::SO_RCVTIMEO_NEW => OptMap::real(libc::SO_RCVTIMEO),
        guest::SO_SNDTIMEO_OLD | guest::SO_SNDTIMEO_NEW => OptMap::real(libc::SO_SNDTIMEO),
        // An advisory scheduling hint with no Darwin equivalent, which Linux
        // stores and reads back.
        guest::SO_PRIORITY => OptMap::store(STORE_PRIORITY),
        _ => OptMap::unknown(),
    }
}

fn opt_tcp(fake: c_int) -> OptMap {
    match fake {
        guest::TCP_NODELAY => OptMap::real(libc::TCP_NODELAY),
        guest::TCP_KEEPINTVL => OptMap::real(libc::TCP_KEEPINTVL),
        guest::TCP_KEEPCNT => OptMap::real(libc::TCP_KEEPCNT),
        guest::TCP_MAXSEG => OptMap::real(libc::TCP_MAXSEG),
        // Darwin's name for Linux's TCP_KEEPIDLE.
        guest::TCP_KEEPIDLE => OptMap::real(libc::TCP_KEEPALIVE),
        // Linux-only and advisory: one asks for acknowledgements to be sent
        // promptly, one shortens a retransmit deadline, one delays handing over
        // an accepted connection. Dropping a hint is not failing a request --
        // but two of the three read back what was set on Linux, and the
        // third is derived from the connection's state, which for a socket
        // that is not connected reads as what was set anyway.
        guest::TCP_QUICKACK => OptMap::ignore(),
        guest::TCP_USER_TIMEOUT => OptMap::store(STORE_USER_TIMEOUT),
        guest::TCP_DEFER_ACCEPT => OptMap::store(STORE_DEFER_ACCEPT),
        _ => OptMap::unknown(),
    }
}

fn opt_ip(fake: c_int) -> OptMap {
    match fake {
        guest::IP_TOS => OptMap::real(libc::IP_TOS),
        guest::IP_TTL => OptMap::real(libc::IP_TTL),
        guest::IP_HDRINCL => OptMap::real(libc::IP_HDRINCL),
        guest::IP_RETOPTS => OptMap::real(host::IP_RETOPTS),
        guest::IP_RECVTTL => OptMap::real(libc::IP_RECVTTL),
        guest::IP_RECVTOS => OptMap::real(libc::IP_RECVTOS),
        guest::IP_PKTINFO => OptMap::real(libc::IP_PKTINFO),
        guest::IP_MULTICAST_TTL => OptMap::real(libc::IP_MULTICAST_TTL),
        guest::IP_MULTICAST_LOOP => OptMap::real(libc::IP_MULTICAST_LOOP),
        // IP_RECVERR: Darwin has no error queue and no such option.
        // `sys_setsockopt` swallows it rather than letting it come through
        // here, so that a resolver sees a working socket with no error reports
        // rather than a socket it could not configure.
        _ => OptMap::unknown(),
    }
}

fn opt_ipv6(fake: c_int) -> OptMap {
    match fake {
        guest::IPV6_UNICAST_HOPS => OptMap::real(libc::IPV6_UNICAST_HOPS),
        guest::IPV6_TCLASS => OptMap::real(libc::IPV6_TCLASS),
        guest::IPV6_V6ONLY => OptMap::real(libc::IPV6_V6ONLY),
        guest::IPV6_RECVPKTINFO => OptMap::real(libc::IPV6_RECVPKTINFO),
        _ => OptMap::unknown(),
    }
}

pub fn opt_to_real(fake: c_int, level: c_int) -> OptMap {
    match level {
        guest::SOL_SOCKET => opt_socket(fake),
        guest::IPPROTO_TCP => opt_tcp(fake),
        guest::IPPROTO_IP => opt_ip(fake),
        guest::IPPROTO_IPV6 => opt_ipv6(fake),
        _ => OptMap::unknown(),
    }
}
