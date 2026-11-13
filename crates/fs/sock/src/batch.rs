//! Batched message syscalls.

use std::ffi::{c_int, c_uint};

use strace::strace;
use usercopy::GuestMem;

use crate::{Errno, Sock, put_u32, sys_recvmsg, sys_sendmsg};

// ---------------------------------------------------------------------------
// The batched forms
// ---------------------------------------------------------------------------

/* `now_ns` was defined here until 2026-09-15 — one of five private copies,
 * all asking `CLOCK_MONOTONIC` and answering `u64` nanoseconds. It is
 * `util_timeabi::monotonic_ns` now, which saturates where three of the five
 * multiplied plainly. */
use util_timeabi::monotonic_ns as now_ns;

pub fn sys_recvmmsg(
    sock_fd: c_int,
    msg_vec: u64,
    vec_len: c_uint,
    flags: c_int,
    timeout_addr: u64,
) -> Result<i64, Errno> {
    // Clamped, not refused: `if (vlen > UIO_MAXIOV) vlen = UIO_MAXIOV;` is what
    // Linux does, and answering EINVAL meant a caller that had not bounded its
    // own count got an error where Linux receives the first thousand. Measured
    // -- recvmmsg(vlen = 0xffff_ffff) on an empty socket is EAGAIN there and
    // was EINVAL here. Bounding it at all still matters: the loop below runs a
    // full recvmsg per entry.
    let vec_len = msghdr::mmsg_vlen(vec_len);
    strace!("recvmmsg({sock_fd}, {msg_vec:#x}, {vec_len}, {flags})");

    // The timeout used to be accepted and dropped, so a guest asking to wait at
    // most n milliseconds for a batch waited as long as the socket did.
    //
    // It bounds the whole call, and is checked after each datagram -- which is
    // exactly as far as Linux takes it, quirk included: if vlen-1 datagrams
    // arrive before it expires and then nothing does, the receive of the last
    // one blocks past it. recvmmsg(2) documents that. Linux does not write the
    // remaining time back either.
    let deadline_ns = if timeout_addr != 0 {
        let mut ts = [0u8; 16];
        if GuestMem.read(timeout_addr, &mut ts) != 0 {
            return Err(Errno::EFAULT);
        }
        // Read signed. The guest's `struct timespec` is signed on this layout,
        // so comparing the fields as unsigned is a tautology.
        let sec = i64::from_le_bytes(ts[..8].try_into().unwrap());
        let nsec = i64::from_le_bytes(ts[8..].try_into().unwrap());
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return Err(Errno::EINVAL);
        }
        // Saturating, both steps. There is no upper bound on `tv_sec` here for
        // the same reason there is none on a real kernel -- Linux saturates --
        // so `LLONG_MAX` overflowed the multiply, which is an abort with
        // overflow checks on and an arbitrary deadline without them.
        Some(
            now_ns().saturating_add(
                (sec as u64)
                    .saturating_mul(1_000_000_000)
                    .saturating_add(nsec as u64),
            ),
        )
    } else {
        None
    };

    // The descriptor is judged before the count and after the timeout, which is
    // the order the syscall wrapper and `__sys_recvmmsg` are written in.
    // Measured both ways: `recvmmsg(-1, NULL, 0, 0, <bad pointer>)` is `EFAULT`
    // and `recvmmsg(open("/dev/null"), NULL, 0, 0, NULL)` is `ENOTSOCK`. This
    // used to answer **0** for the second -- reporting that it had received
    // nothing from something that is not a socket at all -- because the loop was
    // the whole implementation and a zero count runs it zero times.
    Sock::get(sock_fd)?;

    let mut num_recv = 0;
    for i in 0..vec_len as u64 {
        let hdr = msg_vec + i * msghdr::MMSG_SIZE as u64;
        let res = sys_recvmsg(sock_fd, hdr, flags)
            .and_then(|n| put_u32(hdr + msghdr::MMSG_LEN_OFFSET as u64, n as u32).map(|()| n));
        let res = match res {
            Ok(n) => n,
            Err(e) => {
                if num_recv > 0 {
                    break;
                }
                return Err(e);
            }
        };
        num_recv += 1;
        if res == 0 {
            break;
        }
        if let Some(deadline) = deadline_ns
            && now_ns() >= deadline
        {
            break; // fewer than vec_len datagrams, which is a valid answer
        }
    }
    Ok(num_recv)
}

pub fn sys_sendmmsg(
    sock_fd: c_int,
    msg_vec: u64,
    vec_len: c_uint,
    flags: c_int,
) -> Result<i64, Errno> {
    // As for recvmmsg: clamped at UIO_MAXIOV, and this loop calls a full
    // sendmsg per entry.
    let vec_len = msghdr::mmsg_vlen(vec_len);
    strace!("sendmmsg({sock_fd}, {msg_vec:#x}, {vec_len}, {flags})");
    // As for recvmmsg: the descriptor before the count, so a zero `vlen` on a
    // non-socket is `ENOTSOCK` rather than a report of nothing sent.
    Sock::get(sock_fd)?;
    let mut num_sent = 0;
    for i in 0..vec_len as u64 {
        let hdr = msg_vec + i * msghdr::MMSG_SIZE as u64;
        let res = sys_sendmsg(sock_fd, hdr, flags)
            .and_then(|n| put_u32(hdr + msghdr::MMSG_LEN_OFFSET as u64, n as u32).map(|()| n));
        let res = match res {
            Ok(n) => n,
            Err(e) => {
                // From the man page: if an error occurs after at least one
                // message has been sent, the call succeeds and returns the
                // number sent. The error code is lost.
                if num_sent > 0 {
                    break;
                }
                return Err(e);
            }
        };
        num_sent += 1;
        if res == 0 {
            // The socket is non-blocking and cannot be written to any more.
            break;
        }
    }
    Ok(num_sent)
}
