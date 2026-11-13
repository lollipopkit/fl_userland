//! Socket option translation.
//!
//! Guest option lengths and unsupported-option behavior are kept here, while
//! descriptor lookup and socket lifecycle remain in the parent module.

use std::ffi::{c_int, c_uint};

use sockabi::guest;
use strace::strace;
use usercopy::GuestMem;

use super::{Errno, Sock, get_u32, host, put_u32, rx_err};

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// A socket option value is small: the largest this translates is
/// `struct tcp_info_` at about a hundred bytes, and `ICMP6_FILTER` is
/// thirty-two. The length used to come from the guest and size a VLA, so there
/// was no bound on it at all. Linux answers `EINVAL` for an implausible optlen
/// rather than allocating it.
const SOCKOPT_VALUE_MAX: usize = 256;

const DEFAULT_TCP_CONGESTION: &[u8] = b"cubic";

pub fn sys_setsockopt(
    sock_fd: c_int,
    level: c_uint,
    option: c_uint,
    value_addr: u64,
    value_len: c_uint,
) -> Result<(), Errno> {
    strace!("setsockopt({sock_fd}, {level}, {option}, {value_addr:#x}, {value_len})");
    let sock = Sock::get(sock_fd)?;
    let (level, mut option) = (level as c_int, option as c_int);
    if value_len as usize > SOCKOPT_VALUE_MAX {
        return Err(Errno::EINVAL);
    }
    // The host's own limit stands in for `rmem_max`, so past the capability
    // check the two are the plain options (`caps_probe`).
    if level == guest::SOL_SOCKET && matches!(option, guest::SO_SNDBUFFORCE | guest::SO_RCVBUFFORCE) {
        if !taskview::capable(taskview::caps::CAP_NET_ADMIN) {
            return Err(Errno::EPERM);
        }
        option = if option == guest::SO_SNDBUFFORCE { guest::SO_SNDBUF } else { guest::SO_RCVBUF };
    }
    let mut value = [0u8; SOCKOPT_VALUE_MAX];
    if GuestMem.read(value_addr, &mut value[..value_len as usize]) != 0 {
        return Err(Errno::EFAULT);
    }

    // ICMP6_FILTER can only be set on real SOCK_RAW.
    if level == libc::IPPROTO_ICMPV6 && option == guest::ICMP6_FILTER {
        return Ok(());
    }
    // IP_MTU_DISCOVER has no equivalent on Darwin.
    if level == libc::IPPROTO_IP && option == guest::IP_MTU_DISCOVER {
        return Ok(());
    }
    {
        // IP_RECVERR asks for ICMP errors to be queued on the socket's error
        // queue, which Darwin does not have. Answering EINVAL stopped every
        // glibc distribution from resolving a name at all: glibc's resolver
        // sets it on the UDP socket before it sends anything, and treats the
        // failure as fatal -- socket, setsockopt, close, and not one query on
        // the wire. Reported as accepted; the effect is that ICMP errors go
        // unreported, which is what a resolver already has to cope with, rather
        // than that DNS does not work.
        //
        // Only here. On Linux the option exists, opt_to_real maps it, and
        // swallowing it would turn a working error queue into a silent no-op.
        if level == libc::IPPROTO_IP && option == guest::IP_RECVERR {
            return Ok(());
        }
        if level == libc::IPPROTO_IPV6 && option == guest::IPV6_RECVERR {
            return Ok(());
        }
        // TCP_CONGESTION also has no equivalent on Darwin.
        if level == libc::IPPROTO_TCP && option == guest::TCP_CONGESTION {
            let asked = &value[..value_len as usize];
            let asked = &asked[..asked.iter().position(|&b| b == 0).unwrap_or(asked.len())];
            return if asked == DEFAULT_TCP_CONGESTION {
                Ok(())
            } else {
                Err(Errno::ENOENT)
            };
        }
    }

    if let Some(which) = V6Pktinfo::of(&sock, level, option) {
        if (value_len as usize) < std::mem::size_of::<i32>() {
            return Err(Errno::EINVAL);
        }
        let on = i32::from_le_bytes(value[..4].try_into().unwrap()) != 0;
        let mut wants = sock.state().v6_wants();
        which.set(&mut wants, on);
        let either = i32::from(wants.ip_pktinfo || wants.ipv6_pktinfo);
        host::setsockopt(sock.real()?, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, &either.to_ne_bytes())
            .map_err(rx_err)?;
        sock.state().set_v6_wants(wants);
        return Ok(());
    }

    // A level nothing answers for is EOPNOTSUPP; an unknown option of a level
    // that exists is ENOPROTOOPT. Both were the latter, so a program probing for
    // a family's options could not tell them apart -- and EINVAL, which this
    // answered before, says the arguments were wrong, which a caller cannot
    // distinguish from its own mistake.
    if !sockabi::level_known(level) {
        return Err(Errno::EOPNOTSUPP);
    }
    let opt = sockabi::opt_to_real(option, level);
    match opt.kind {
        sockabi::OPT_UNKNOWN => return Err(Errno::ENOPROTOOPT),
        // Accepted and dropped. The option is a hint the host cannot take, and
        // failing the call would fail the program at setup over something it is
        // not depending on.
        sockabi::OPT_IGNORE => return Ok(()),
        // Accepted and kept, so that a get reads it back: Linux stores these,
        // and a program that compares what it set with what it reads -- which
        // is how a program checks its own setup -- was told 0 here.
        sockabi::OPT_STORE => {
            if (value_len as usize) < std::mem::size_of::<i32>() {
                return Err(Errno::EINVAL);
            }
            sock.set_stored(opt.real, i32::from_le_bytes(value[..4].try_into().unwrap()));
            return Ok(());
        }
        _ => {}
    }

    host::setsockopt(sock.real()?, sockabi::level_to_real(level), opt.real, &value[..value_len as usize])
        .map_err(rx_err)
}

/// `IP_PKTINFO` or `IPV6_RECVPKTINFO` on an IPv6 socket, which are answered
/// here rather than by the host: see `SocketState::v6_ip_pktinfo`.
#[derive(Clone, Copy)]
enum V6Pktinfo {
    Ip,
    Ipv6,
}

impl V6Pktinfo {
    fn of(sock: &Sock<'_>, level: c_int, option: c_int) -> Option<V6Pktinfo> {
        if sock.domain() != guest::PF_INET6 {
            return None;
        }
        match (level, option) {
            (guest::IPPROTO_IP, guest::IP_PKTINFO) => Some(V6Pktinfo::Ip),
            (guest::IPPROTO_IPV6, guest::IPV6_RECVPKTINFO) => Some(V6Pktinfo::Ipv6),
            _ => None,
        }
    }

    fn get(self, w: crate::ancillary::V6Wants) -> bool {
        match self {
            V6Pktinfo::Ip => w.ip_pktinfo,
            V6Pktinfo::Ipv6 => w.ipv6_pktinfo,
        }
    }

    fn set(self, w: &mut crate::ancillary::V6Wants, on: bool) {
        match self {
            V6Pktinfo::Ip => w.ip_pktinfo = on,
            V6Pktinfo::Ipv6 => w.ipv6_pktinfo = on,
        }
    }
}

pub fn sys_getsockopt(
    sock_fd: c_int,
    level: c_uint,
    option: c_uint,
    value_addr: u64,
    len_addr: u64,
) -> Result<(), Errno> {
    strace!("getsockopt({sock_fd}, {level}, {option}, {value_addr:#x}, {len_addr:#x})");
    let sock = Sock::get(sock_fd)?;
    let (level, option) = (level as c_int, option as c_int);
    let asked = get_u32(len_addr)?;
    // Linux reads optlen as a signed int and refuses exactly one thing: a
    // negative one. A length *larger* than the option is clamped to the
    // option's size and reported back, and a *smaller* one gets a truncated
    // value and its own length.
    //
    // This was `asked > SOCKOPT_VALUE_MAX` answering EINVAL, which caught the
    // negative case only because -1 is a huge unsigned, and refused a
    // large-but-legitimate buffer that Linux would have filled.
    if (asked as i32) < 0 {
        return Err(Errno::EINVAL);
    }
    let mut value_len = (asked as usize).min(SOCKOPT_VALUE_MAX);
    // Not read back from the guest. This is the *output* buffer, and Linux
    // never reads it -- doing so made a write-only or not-yet-faulted-in optval
    // fail with EFAULT, on top of the unbounded VLA the length sized.
    let mut value = [0u8; SOCKOPT_VALUE_MAX];

    // Linux's `sock_getsockopt` computes the option's own length, then
    // `if (len > lv) len = lv;` and copies that much. Each arm below demanded
    // exact equality instead and answered EINVAL otherwise, so a caller reusing
    // one `long`-sized buffer across several options failed on this kernel and
    // nothing else.
    macro_rules! fits {
        ($want:expr) => {
            value_len = value_len.min($want)
        };
    }

    if let Some(which) = V6Pktinfo::of(&sock, level, option) {
        fits!(4);
        value[..4].copy_from_slice(&i32::from(which.get(sock.state().v6_wants())).to_le_bytes());
    } else if level == guest::SOL_SOCKET
        && (option == guest::SO_DOMAIN || option == guest::SO_TYPE || option == guest::SO_PROTOCOL)
    {
        fits!(4);
        let answer = if option == guest::SO_DOMAIN {
            sock.domain()
        } else if option == guest::SO_TYPE {
            sock.ty()
        } else {
            sock.protocol()
        };
        value[..4].copy_from_slice(&(answer as u32).to_le_bytes());
    } else if level == guest::SOL_SOCKET && option == guest::SO_PEERCRED {
        fits!(12);
        // Answers with what is known rather than waiting for it. This used to
        // wait for the peer, whose wait a listener that stops accepting never
        // ends -- so a client that connected and asked for its peer's
        // credentials before anyone accepted hung for ever. getsockopt has no
        // blocking contract in POSIX or in Linux, there is no errno for "would
        // block" on it, and nothing expects it to sleep.
        //
        // A client asking before the accept is told the listener's
        // credentials, recorded on it at connect the way Linux's
        // `unix_stream_connect` copies them -- see `AddrFor::Connect`. It
        // used to be told pid 0 and uid -1, under a TODO saying so. A peer
        // that is not one of ours is still nobody.
        let cred = if sock.is_unix() {
            unixpeer::with_table(|t| t.peer_cred(sock.peer()))
        } else {
            None
        };
        let cred = cred.unwrap_or(unixpeer::Ucred {
            pid: 0,
            uid: u32::MAX,
            gid: u32::MAX,
        });
        value[..4].copy_from_slice(&cred.pid.to_le_bytes());
        value[4..8].copy_from_slice(&cred.uid.to_le_bytes());
        value[8..12].copy_from_slice(&cred.gid.to_le_bytes());
    } else if level == guest::SOL_SOCKET && option == guest::SO_ERROR {
        fits!(4);
        let real_error =
            host::getsockopt_int(sock.real()?, libc::SOL_SOCKET, libc::SO_ERROR).map_err(rx_err)?;
        let mapped = if real_error == 0 {
            0
        } else {
            -kernel_errno::err_map(real_error)
        };
        value[..4].copy_from_slice(&(mapped as u32).to_le_bytes());
    } else if level == libc::IPPROTO_TCP && option == guest::TCP_CONGESTION {
        // Truncated to what the guest asked for, not expanded to the name's
        // length: this branch used to overwrite the length with strlen() and
        // copy that many bytes into a buffer the guest had sized smaller.
        let n = DEFAULT_TCP_CONGESTION.len().min(value_len);
        value[..n].copy_from_slice(&DEFAULT_TCP_CONGESTION[..n]);
        value_len = n;
    } else {
        // A level nothing answers for is EOPNOTSUPP; see sys_setsockopt.
        if !sockabi::level_known(level) {
            return Err(Errno::EOPNOTSUPP);
        }
        let opt = sockabi::opt_to_real(option, level);
        if opt.kind == sockabi::OPT_UNKNOWN {
            return Err(Errno::ENOPROTOOPT);
        }
        if opt.kind == sockabi::OPT_IGNORE {
            // Whatever setsockopt swallowed reads back as zero, which `value`
            // already is. Asking the host would be asking about option number
            // zero: the sentinel used to be passed straight through, so every
            // one of these failed a get after succeeding at its set.
        } else if opt.kind == sockabi::OPT_STORE {
            // What setsockopt kept, which is what Linux reads back for these.
            fits!(4);
            value[..4].copy_from_slice(&sock.stored(opt.real).to_le_bytes());
        } else {
            value_len = host::getsockopt(
                sock.real()?,
                sockabi::level_to_real(level),
                opt.real,
                &mut value[..value_len],
            )
            .map_err(rx_err)?;
        }
    }

    put_u32(len_addr, value_len as u32)?;
    // Exactly `value_len`, not the whole fixed buffer -- which is what a write
    // of `sizeof(value)` would have done once the VLA became an array.
    if GuestMem.write(value_addr, &value[..value_len]) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}
