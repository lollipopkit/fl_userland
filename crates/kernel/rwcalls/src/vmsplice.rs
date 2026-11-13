//! `vmsplice(2)`: the caller's memory into a pipe, or a pipe into it.
//!
//! A copy both ways. Linux moves user pages into the pipe's slots, and with
//! `SPLICE_F_GIFT` may keep them; guest memory here is reached only through
//! `user_read`/`user_write`, so there are no pages to hand over, and Linux
//! promises only the bytes -- `SPLICE_F_GIFT` and `SPLICE_F_MOVE` are hints a
//! kernel may ignore.
//!
//! The rules, as `rarecalls_probe` measured them on a 7.2 arm64 kernel:
//!
//! - unknown flags are `EINVAL` before the descriptor is looked at, and the
//!   descriptor is `EBADF` before an empty iovec answers 0;
//! - the direction is the description's access mode -- writable means into
//!   the pipe, so an `O_RDWR` FIFO or `/proc/self/fd` reopen is written to;
//! - `nr_segs` is `unsigned long` and `import_iovec` takes an `unsigned int`,
//!   so `1 << 32 | 1` is one segment;
//! - nothing to move is 0 even on a descriptor that is not a pipe; with
//!   something to move, a non-pipe is `EBADF`;
//! - only `SPLICE_F_NONBLOCK` makes it non-blocking: both directions wait on a
//!   description with `O_NONBLOCK` set;
//! - into a pipe, it waits for room once and moves what fits (64K of a 128K
//!   iovec into an empty default pipe), and an unreadable vector after a good
//!   one is a short count; out of one, an unwritable destination is `EFAULT`
//!   and the bytes stay queued.

use std::ffi::{c_int, c_uint};

use guest_errno::Errno;
use strace::strace;

use crate::iov::{gather_prefix, read_iovec, scatter};
use crate::syscalls::deliverable_iov;
use crate::transfer::{SPLICE_F_KNOWN, SPLICE_F_NONBLOCK, fd_is_fifo};
use crate::{Fd, bounce, descriptor, ffi};

pub fn sys_vmsplice(fd_no: c_int, iov_addr: u64, nr_segs: u64, flags: c_uint) -> Result<i64, Errno> {
    strace!("vmsplice({fd_no}, {iov_addr:#x}, {nr_segs}, {flags:#x})");
    if flags & !SPLICE_F_KNOWN != 0 {
        return Err(Errno::EINVAL);
    }
    let fd = Fd::get_io(fd_no)?;
    let to_pipe = match fd.flags() & ffi::O_ACCMODE_ {
        m if m == ffi::O_WRONLY_ || m == ffi::O_RDWR_ => true,
        m if m == ffi::O_RDONLY_ => false,
        _ => return Err(Errno::EBADF),
    };
    let (vectors, total) = read_iovec(iov_addr, nr_segs as c_uint)?;
    if total == 0 {
        return Ok(0);
    }
    if !fd_is_fifo(&fd) {
        return Err(Errno::EBADF);
    }
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;
    if to_pipe {
        // At most what the pipe can hold, since one write is all this makes.
        let cap = pipecalls::capacity(&fd).unwrap_or(rwabi::bounce_clamp(total as u64));
        let mut buf = bounce(total.min(cap))?;
        let got = gather_prefix(&vectors, &mut buf);
        if got == 0 {
            return Err(Errno::EFAULT);
        }
        let res = match pipecalls::vmsplice_write(&fd, &buf[..got], nonblock) {
            Some(n) => n as i64,
            // A FIFO this kernel does not own (realfs passes the host's
            // through): its own write, so the description's O_NONBLOCK
            // rules there and `SPLICE_F_NONBLOCK` is not seen.
            None => descriptor::fd_write(&fd, &buf[..got]),
        };
        Errno::split(res)
    } else {
        let want = deliverable_iov(&fd, &vectors, rwabi::bounce_clamp(total as u64), nonblock)?;
        let mut buf = bounce(want)?;
        let res = match pipecalls::vmsplice_read(&fd, &mut buf, nonblock) {
            Some(n) => n as i64,
            None => descriptor::fd_read(&fd, &mut buf),
        };
        let res = Errno::split(res)?;
        scatter(&vectors, &buf, res as usize)?;
        Ok(res)
    }
}
