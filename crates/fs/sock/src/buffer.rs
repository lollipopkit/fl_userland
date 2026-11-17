//! Buffered send and receive syscall handling.

use std::ffi::{c_int, c_uint};

use sockabi::guest;
use strace::strace;
use usercopy::GuestMem;

use rustix::io::Errno as HostErrno;

use crate::{
    AddrFor, Errno, Sock, get_u32, host, netlink_send, put_addr, put_u32, read_addr_for, rx_err,
    sock_wait_readable_for_rs, write_host_addr,
};

// ---------------------------------------------------------------------------
// Sending and receiving on a buffer
// ---------------------------------------------------------------------------

/// The flags a *send* on this socket may hand the host.
///
/// `MSG_EOR` marks a record boundary, which a stream does not have. Linux
/// ignores it there — `unix_stream_sendmsg` never looks at it — and Darwin's
/// `sosend` answers `EINVAL`, so a guest setting it on a stream socket got an
/// error from a kernel it is not running on. Measured:
/// `sendmsg(flags = MSG_EOR)` sends five bytes on a real arm64 kernel and was
/// `EINVAL` here.
///
/// `MSG_OOB` is deliberately *not* dropped. A stream's urgent byte is a real
/// thing that a receiver can ask for separately, and a host unix socket has no
/// way to carry one, so dropping the flag would send the data as ordinary bytes
/// and silently lose the distinction. `EOPNOTSUPP` is the honest answer until
/// there is somewhere to put it.
/// A bit nothing here implements is **traced and dropped**, not refused.
///
/// Measured: `sendmsg(flags = MSG_MORE)` sends five bytes on a real arm64
/// kernel, and so do `MSG_DONTROUTE`, `MSG_CONFIRM`, `MSG_ZEROCOPY` and every
/// other bit a unix socket has no use for -- Linux's `unix_stream_sendmsg`
/// looks at `MSG_OOB` and passes the rest by. Thirteen of `msg_probe`'s cases
/// say so.
///
/// The C had `if (real_flags < 0) return _EINVAL;` and it was **dead**:
/// `sock_flags_to_real` returns a bit set, which is never negative. Writing the
/// check as live code is what a translation does and a rewrite must not.
pub(crate) fn send_flags(sock: &Sock<'_>, flags: c_int) -> c_int {
    let mut real = to_real_flags(flags);
    if sock.ty() == guest::SOCK_STREAM {
        real &= !libc::MSG_EOR;
    }
    real
}

/// The host bits of a guest flag word. See [`send_flags`] for the unknown ones.
pub(crate) fn to_real_flags(flags: c_int) -> c_int {
    let f = sockabi::flags_to_real(flags);
    if f.unknown != 0 {
        strace!("unimplemented socket flags {:#x}", f.unknown);
    }
    f.real
}

/// `EPIPE` from a send, for a caller that may have passed `MSG_NOSIGNAL`.
///
/// [`rx_err`] raises the guest's `SIGPIPE` for every `EPIPE`, which is right
/// for `write()` and wrong for a send that asked not to be signalled — and
/// `SIGPIPE`'s default action is to terminate, so a server writing to a
/// connection the peer dropped was killed by the very thing the flag exists to
/// prevent. Only the calls that take flags need this.
pub(crate) fn send_err(e: HostErrno, flags: c_int) -> Errno {
    if e == HostErrno::PIPE && flags & guest::MSG_NOSIGNAL != 0 {
        return Errno::from_negative_or_eio(kernel_errno::err_map(libc::EPIPE));
    }
    rx_err(e)
}

/// Reads the address argument of a send: the same as a `connect`'s, without
/// the part that only a `bind` may do.
pub(crate) fn read_addr(addr: u64, len: u32) -> Result<(Vec<u8>, u32), Errno> {
    read_addr_for(addr, len, AddrFor::Other)
}

pub fn sys_sendto(
    sock_fd: c_int,
    buffer_addr: u64,
    len: u64,
    flags: c_uint,
    sockaddr_addr: u64,
    sockaddr_len: c_uint,
) -> Result<i64, Errno> {
    let sock = Sock::get(sock_fd)?;
    let flags = flags as c_int;
    // Clamped as well as widened. `len` is a `size_t`: it used to be a 32-bit
    // guest length, so `len + 1` wrapped to zero at `UINT32_MAX` and the copy
    // then read four gigabytes into it. The clamp is because this bounces
    // through a host buffer the guest sizes, the same amplification the read
    // and write paths have -- and a short send is what a socket does anyway.
    let want = rwabi::bounce_clamp(len);
    let mut buffer = Vec::new();
    if buffer.try_reserve(want).is_err() {
        return Err(Errno::ENOMEM);
    }
    buffer.resize(want, 0u8);
    if GuestMem.read(buffer_addr, &mut buffer) != 0 {
        return Err(Errno::EFAULT);
    }
    strace!(
        "sendto({sock_fd}, {:?}, {want}, {flags}, {sockaddr_addr:#x}, {sockaddr_len})",
        String::from_utf8_lossy(&buffer[..want.min(100)])
    );

    // Netlink is answered here rather than sent: the host has no such family,
    // and the destination a caller names is the kernel, which is this.
    if sock.is_netlink() {
        // The whole length, or a negative errno: `netlink_send` is also the
        // driver's `write`, so it keeps that convention.
        return Errno::split(netlink_send(sock, &buffer) as i64);
    }
    let real_flags = send_flags(&sock, flags);
    let addr = if sockaddr_addr != 0 {
        Some(read_addr(sockaddr_addr, sockaddr_len)?)
    } else {
        None
    };

    let to = addr.as_ref().map(|(bytes, n)| &bytes[..*n as usize]);
    match host::send_to(sock.real()?, &buffer, real_flags, to) {
        Ok(n) => Ok(n as i64),
        Err(e) => Err(send_err(e, flags)),
    }
}

pub fn sys_recvfrom(
    sock_fd: c_int,
    buffer_addr: u64,
    len: u64,
    flags: c_uint,
    sockaddr_addr: u64,
    sockaddr_len_addr: u64,
) -> Result<i64, Errno> {
    strace!(
        "recvfrom({sock_fd}, {buffer_addr:#x}, {len}, {flags}, \
         {sockaddr_addr:#x}, {sockaddr_len_addr:#x})"
    );
    let sock = Sock::get(sock_fd)?;
    let real_flags = to_real_flags(flags as c_int);
    let buffer_len = if sockaddr_len_addr != 0 {
        get_u32(sockaddr_len_addr)?
    } else {
        0
    };

    // Clamped for the same reason as sendto, and a short recv is normal.
    let want = rwabi::bounce_clamp(len);
    let mut buffer = Vec::new();
    if buffer.try_reserve(want.max(1)).is_err() {
        return Err(Errno::ENOMEM);
    }
    buffer.resize(want, 0u8);

    let real = sock.real()?;
    // What the host said the sender was, from the first read that asked. The
    // address is only asked for when the guest gave somewhere to put it.
    let want_addr = sockaddr_addr != 0 && sockaddr_len_addr != 0;
    let mut from: Option<host::AddrBuf> = None;
    // `MSG_TRUNC` on a message socket answers the datagram's whole length,
    // which Linux does and Darwin does not (it answers what fitted): the
    // length is asked of the host just before the receive that takes it.
    // On a stream the flag means "discard", which the host does the same.
    let datagram_len = real_flags & libc::MSG_TRUNC != 0 && sock.ty() != guest::SOCK_STREAM;
    let mut full_len: Option<usize> = None;
    let mut receive = |buf: &mut [u8], flags: c_int, first: bool| {
        let pending = if datagram_len && first { Some(host::pending_datagram_len(real)?) } else { None };
        let n = if want_addr && first {
            host::recv_from(real, buf, flags).map(|(n, addr)| {
                from = Some(addr);
                n
            })
        } else {
            host::recv(real, buf, flags)
        }?;
        if let Some(p) = pending {
            full_len = Some(p.max(n));
        }
        Ok(n)
    };

    // Whether this call should wait:
    //   * guest flags MSG_DONTWAIT -> never wait (explicit)
    //   * fd has O_NONBLOCK set    -> never wait (fd-level nonblock)
    //
    // The second case is critical: musl's res_msend creates UDP sockets with
    // SOCK_NONBLOCK and then calls recv(fd, buf, len, 0). It relies on the
    // kernel returning EAGAIN immediately on an empty buffer to terminate its
    // "drain all pending responses" loop. If we wait when the fd itself is
    // nonblock, musl loops for ever and DNS resolution appears to hang. Both
    // the guest fd flags and the host fd's are checked, in case they diverge --
    // fcntl on the host descriptor sets only the latter.
    let host_nonblock = sock.host_nonblocking();
    let guest_nonblock = sock.flags() & O_NONBLOCK_GUEST != 0;
    let should_wait = real_flags & libc::MSG_DONTWAIT == 0 && !guest_nonblock && !host_nonblock;

    let res: isize = if should_wait {
        // MSG_WAITALL asks for the whole length, and the wait loop forcing
        // MSG_DONTWAIT took that away: the first partial read satisfied
        // `res >= 0` and returned. Only stream sockets can be partially filled,
        // so only they accumulate; on a datagram socket a message arrives whole
        // and MSG_WAITALL has nothing to add.
        let wait_all = real_flags & libc::MSG_WAITALL != 0 && sock.ty() == guest::SOCK_STREAM;
        let mut got = 0usize;
        loop {
            // The address belongs to the first message read; later reads must
            // not overwrite it.
            let first = got == 0;
            match receive(&mut buffer[got..], real_flags | libc::MSG_DONTWAIT, first) {
                Ok(0) => break, // orderly shutdown; a short result is the right answer
                Ok(n) => {
                    got += n;
                    if !wait_all || got == want {
                        break;
                    }
                    continue;
                }
                Err(HostErrno::INTR) => continue,
                // EWOULDBLOCK is EAGAIN on every host this builds for.
                Err(HostErrno::AGAIN) => {}
                Err(e) => {
                    // Whatever was already received is the result; the error
                    // belongs to the next call.
                    if got > 0 {
                        break;
                    }
                    return Err(rx_err(e));
                }
            }
            // No data yet. Wait (bounded) for readability or a guest signal,
            // then retry.
            let wr = sock_wait_readable_for_rs(real);
            if wr < 0 {
                if got > 0 {
                    break;
                }
                return Err(Errno::from_negative_or_eio(wr));
            }
        }
        got as isize
    } else {
        receive(&mut buffer, real_flags, true).map_err(rx_err)? as isize
    };

    let answer = full_len.map_or(res, |n| n as isize);

    // `res` bytes were received, `want` were asked for. Copying `want` back
    // overwrote whatever the guest had after a short read with the tail of an
    // uninitialised buffer.
    if GuestMem.write(buffer_addr, &buffer[..res as usize]) != 0 {
        return Err(Errno::EFAULT);
    }

    // Both pointers or neither: the host was only asked to fill an address when
    // `sockaddr_len_addr` was given, so writing it out on the strength of
    // `sockaddr_addr` alone handed the guest an uninitialised buffer.
    if sockaddr_addr != 0 && sockaddr_len_addr != 0 {
        // A netlink message comes from the kernel, and a reader checks that:
        // `ip` refuses anything whose sender is not a 12-byte `sockaddr_nl`
        // with "sender address length == 2", which is the unnamed unix end the
        // pair reports. Answered here rather than translated, because the
        // sender is this kernel and the pair is an implementation detail.
        if sock.is_netlink() {
            let mut nl = [0u8; 12];
            nl[..2].copy_from_slice(&(guest::PF_NETLINK as u16).to_le_bytes());
            put_addr(
                sockaddr_addr,
                sockaddr_len_addr,
                &nl,
                nl.len() as u32,
                buffer_len,
            )?;
            return Ok(answer as i64);
        }
        // And only if the host filled one in at all. It does not on a connected
        // socket, and the accumulating loop above only asks on its first pass --
        // so a wait that ended at `got == 0` never asked either. Writing it out
        // regardless was worse than a disclosure of stack bytes: the translation
        // does not recognise AF_UNSPEC and answers EINVAL, failing the whole
        // call after the data had been delivered.
        let mut out_len = 0u32;
        if let Some(from) = from.filter(host::AddrBuf::is_some) {
            out_len = write_host_addr(sockaddr_addr, from.as_slice(), buffer_len)?;
        }
        put_u32(sockaddr_len_addr, out_len)?;
    }
    Ok(answer as i64)
}

/// The guest's `O_NONBLOCK`, from `fs/fd.h`. 0o4000 on aarch64.
pub(crate) const O_NONBLOCK_GUEST: c_uint = 0o4000;

// `send` and `recv` are not syscalls on aarch64 -- there are no numbers for
// them, and libc implements both by calling `sendto` and `recvfrom` with a null
// address. `sys_send` and `sys_recv` existed here as one-line forwards that
// nothing in the tree referenced, in C for as long as this file has existed.
// They became visible only when they moved: `dead_exports` reads Rust exports,
// and the C ones were in nobody's sight.

// ---------------------------------------------------------------------------
// sendmsg and recvmsg
// ---------------------------------------------------------------------------
