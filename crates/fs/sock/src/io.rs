//! Blocking descriptor I/O and host error translation.

use std::ffi::c_int;

use strace::strace;

use crate::{Sock, ffi, host, host_of, netlink_send, rx_err};

// ---------------------------------------------------------------------------
// The descriptor operations
// ---------------------------------------------------------------------------

/// `ENOTCONN` on iOS means the device went to sleep.
///
/// All connected sockets are killed then, and reads and writes answer
/// `ENOTCONN`, which is not what POSIX says that means. `getpeername` failing
/// with `EINVAL` is how the two are told apart; the guest is given
/// `ECONNRESET`, which is what actually happened to its connection.
fn translate_err(fd: &ffi::fd, err: c_int) -> c_int {
    if err != -107 {
        // not ENOTCONN
        return err;
    }
    let reset = host_of(fd).is_ok_and(|h| host::peername(h).err() == Some(rustix::io::Errno::INVAL));
    if reset {
        return -104; // ECONNRESET
    }
    err
}

/// A single host read or write, with no poll and no flag change.
///
/// The `EINTR` rule is the current task's signal hook rather than two copies of
/// `pending & ~blocked`. It was written for sockets first: retrying past
/// `EINTR` swallows the `SIGUSR1` wake the emulator uses to deliver a guest
/// signal into a blocked host syscall, and on iOS — where signal delivery is
/// sometimes deferred by thread suspension on backgrounding — that hung git
/// over HTTPS, `nc` and `telnet` indefinitely.
///
/// The same fix was not made to realfs, so a guest blocked reading a *pipe* had
/// the same hang until 2026-08-23. One rule, one place to read it. Neither
/// covered the signal that arrives *before* the host call, which is what
/// `realfs_interrupted_before_blocking` asks and both now ask first.
/// The two directions, so that one loop serves both without a pointer that
/// is mutable for one and read-only for the other.
enum Buf<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

fn sock_io(fd: &ffi::fd, mut buf: Buf<'_>) -> isize {
    let writing = matches!(buf, Buf::Write(_));
    let events = if writing { libc::POLLOUT } else { libc::POLLIN };
    if realfs::realfs_interrupted_before_blocking(fd, events as c_int) {
        return -4; // EINTR
    }
    let Ok(real) = host_of(fd) else {
        return guest_errno::isize_::EBADF;
    };
    let mut eintr = 0;
    let err = loop {
        let res = match &mut buf {
            Buf::Read(b) => rustix::io::read(real, &mut **b),
            Buf::Write(b) => rustix::io::write(real, b),
        };
        let e = match res {
            Ok(n) => break n as c_int,
            Err(e) => e,
        };
        if e != rustix::io::Errno::INTR {
            break rx_err(e).as_c_int();
        }
        eintr += 1;
        // Only surface it when a guest signal is actually waiting; anything
        // else is the emulator's own business and the call is retried.
        if taskview::current_signal_pending() {
            break -4; // EINTR
        }
    };
    if eintr >= 3 {
        strace!(
            "sock {} interrupted {eintr} times, err={err}",
            if writing { "write" } else { "read" }
        );
    }
    translate_err(fd, err) as isize
}

pub(super) fn sock_read(fd: &ffi::fd, buf: &mut [u8]) -> isize {
    sock_io(fd, Buf::Read(buf))
}

pub(super) fn sock_write(fd: &ffi::fd, buf: &[u8]) -> isize {
    // `write` on a netlink socket is `send` with no flags, and a caller that
    // uses it -- `ip` does not, but a shell redirect would -- must get the same
    // answer as one that does not.
    let Some(sock) = Sock::of(fd) else {
        return guest_errno::isize_::ENOTSOCK;
    };
    if sock.is_netlink() {
        return netlink_send(sock, buf) as isize;
    }
    sock_io(fd, Buf::Write(buf))
}
