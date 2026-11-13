//! `io_submit_one`: one iocb, refused or run.
//!
//! The order of the refusals is Linux's, and each is measured by
//! `aio_probe`: the copy (`EFAULT`), `aio_reserved2` and the `aio_nbytes`
//! overflow guard (`EINVAL`), a slot (`EAGAIN`), the descriptor (`EBADF`), the
//! `IOCB_FLAG_RESFD` eventfd (`EBADF`/`EINVAL`), the write of `aio_key`
//! (`EFAULT`), and only then the opcode -- so an unknown opcode on a bad
//! descriptor is `EBADF`, and on an iocb in read-only memory `EFAULT`.
//!
//! What follows the opcode splits in two, and the split is the ABI: a refusal
//! fails `io_submit` and leaves no event, while everything a transfer itself
//! answers -- a fault on the buffer, `EAGAIN` from an empty non-blocking pipe,
//! `EPIPE` -- is the event's `res`. Buffered I/O on Linux runs to completion
//! inside `io_submit`, and so does it here, through `crates/kernel/rwcalls`;
//! only `IOCB_CMD_POLL` stays pending.

use std::ffi::c_int;
use std::sync::Arc;

use guest_errno::Errno;
use taskview::ffi;
use usercopy::GuestMem;

use crate::abi::{self, IoEvent, Iocb, Opcode};
use crate::context::{Context, Slot};

/// `O_ACCMODE` and the two bits it can grant.
fn readable(fd: &ffi::fd) -> bool {
    fd.flags() & ffi::O_ACCMODE_ != ffi::O_WRONLY_
}

fn writable(fd: &ffi::fd) -> bool {
    fd.flags() & ffi::O_ACCMODE_ != ffi::O_RDONLY_
}

fn is_dir(fd: &ffi::fd) -> bool {
    fd.type_ as u32 & 0o170000 == 0o040000
}

fn is_eventfd(fd: &ffi::fd) -> bool {
    fd.driver_state::<kernel_eventfd::Descriptor>().is_some()
}

pub(crate) fn submit_one(ctx: &Arc<Context>, user_iocb: u64) -> Result<(), Errno> {
    let mut raw = [0u8; abi::IOCB_SIZE];
    if GuestMem.read(user_iocb, &mut raw) != 0 {
        return Err(Errno::EFAULT);
    }
    let cb = Iocb::decode(&raw);
    if cb.reserved2 != 0 {
        return Err(Errno::EINVAL);
    }
    if (cb.nbytes as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    let slot = ctx.reserve()?;
    // `fget`, which does not hand out an `O_PATH` file.
    let fd_no = cb.fildes as c_int;
    let fd = fs_fdobj::f_get(fd_no).filter(|fd| !fd.is_path_only()).ok_or(Errno::EBADF)?;
    let resfd = if cb.flags & abi::FLAG_RESFD != 0 {
        let e = fs_fdobj::f_get(cb.resfd as c_int).ok_or(Errno::EBADF)?;
        if !is_eventfd(&e) {
            return Err(Errno::EINVAL);
        }
        Some(e.retain())
    } else {
        None
    };
    // `KIOCB_KEY`, which `io_cancel` checks for.
    if GuestMem.write(user_iocb + abi::KEY_OFFSET, &0u32.to_le_bytes()) != 0 {
        return Err(Errno::EFAULT);
    }
    let op = Opcode::of(cb.opcode).ok_or(Errno::EINVAL)?;
    let done = |slot: Slot<'_>, resfd: Option<fs_fdobj::Owned>, res: i64| {
        slot.complete(&IoEvent { data: cb.data, obj: user_iocb, res, res2: 0 });
        if let Some(e) = &resfd {
            crate::signal(e);
        }
    };
    match op {
        Opcode::Pread | Opcode::Preadv | Opcode::Pwrite | Opcode::Pwritev => {
            let res = transfer(&fd, fd_no, &cb, op)?;
            done(slot, resfd, res);
        }
        Opcode::Fsync | Opcode::Fdsync => {
            if cb.buf != 0 || cb.offset != 0 || cb.nbytes != 0 || cb.rw_flags != 0 {
                return Err(Errno::EINVAL);
            }
            // Run now; Linux queues it and its answer arrives a moment later.
            // `sys_fsync`'s only `EINVAL` is `!file->f_op->fsync`, which
            // `aio_fsync` refuses at submission.
            let res = match fdattr::sys_fsync(fd_no) {
                Ok(()) => 0,
                Err(Errno::EINVAL) => return Err(Errno::EINVAL),
                Err(e) => e.as_i64(),
            };
            done(slot, resfd, res);
        }
        Opcode::Poll => {
            if cb.buf > u64::from(u16::MAX) || cb.offset != 0 || cb.nbytes != 0 || cb.rw_flags != 0 {
                return Err(Errno::EINVAL);
            }
            crate::poll::submit(ctx, slot, fd.retain(), resfd, user_iocb, cb.data, cb.buf as u16);
        }
    }
    Ok(())
}

/// `aio_read`/`aio_write`: refuse what Linux refuses at submission, then run
/// the transfer and answer its result for the event.
fn transfer(fd: &fs_fdobj::FdRef, fd_no: c_int, cb: &Iocb, op: Opcode) -> Result<i64, Errno> {
    let write = matches!(op, Opcode::Pwrite | Opcode::Pwritev);
    let vectored = matches!(op, Opcode::Preadv | Opcode::Pwritev);

    // `aio_prep_rw`.
    if cb.flags & abi::FLAG_IOPRIO != 0 {
        kernel_procattr::ioprio_check(u32::from(cb.reqprio as u16), taskview::capable(taskview::caps::CAP_SYS_NICE) || taskview::capable(taskview::caps::CAP_SYS_ADMIN))
            .map_err(Errno::from_negative_or_eio)?;
    }
    let flags = cb.rw_flags as u32;
    let rwf = rwabi::rw_flags(flags, write).map_err(Errno::from_negative_or_eio)?;

    // `FMODE_READ`/`FMODE_WRITE`, then whether the file has `read_iter` or
    // `write_iter` at all. A directory has neither; an eventfd reads through
    // `read_iter` and writes through plain `write`, so it is `EINVAL` one way
    // only; epoll and pidfd move no bytes.
    let caps = fd.ops.map_or(ffi::Caps::NONE, |ops| ops.caps());
    if write {
        if !writable(fd) {
            return Err(Errno::EBADF);
        }
        if !(caps.write || caps.write_at) || is_eventfd(fd) {
            return Err(Errno::EINVAL);
        }
    } else {
        if !readable(fd) {
            return Err(Errno::EBADF);
        }
        if !(caps.read || caps.read_at) || is_dir(fd) {
            return Err(Errno::EINVAL);
        }
    }

    // `aio_setup_rw`: the iovec array is read now, a flat buffer only has to
    // be inside the address space.
    let count = if vectored {
        rwcalls::iovec_size(cb.buf, cb.nbytes)? as u64
    } else {
        let len = cb.nbytes.min(rwabi::MAX_RW_COUNT);
        if !usercopy::range_ok(cb.buf, len as usize, ffi::USER_ADDR_MAX_PAGE) {
            return Err(Errno::EFAULT);
        }
        len
    };
    // `rw_verify_area`, against `ki_pos`, which is the iocb's offset even for
    // a pipe -- a negative one is refused there too.
    rwabi::verify_area(cb.offset, count).map_err(Errno::from_negative_or_eio)?;

    // The transfer. A descriptor with positional access gets the offset; a
    // stream ignores it, as a pipe's `read_iter` does.
    let positional = if write { caps.write_at } else { caps.read_at };
    let ran = if write {
        // The transfer runs here, on the submitting thread, so the scope
        // covers the SIGPIPE a pipe or socket with no reader would raise.
        let _quiet = rwf.nosignal.then(kernel_errno::NoSigpipe::new);
        let (at, append) = (cb.offset, rwf.append);
        match (vectored, positional) {
            (false, true) => rwcalls::pwrite_placed(fd_no, cb.buf, cb.nbytes, at, append),
            (false, false) => rwcalls::write(fd_no, cb.buf, cb.nbytes),
            (true, true) => rwcalls::pwritev_placed(fd_no, cb.buf, cb.nbytes as u32, at, append),
            (true, false) => rwcalls::writev(fd_no, cb.buf, cb.nbytes as u32),
        }
    } else {
        let ready = if rwf.nowait { rwcalls::nowait_read(fd_no) } else { Ok(()) };
        ready.and_then(|()| match (vectored, positional) {
            (false, true) => rwcalls::pread(fd_no, cb.buf, cb.nbytes, cb.offset),
            (false, false) => rwcalls::read(fd_no, cb.buf, cb.nbytes),
            (true, true) => rwcalls::preadv(fd_no, cb.buf, cb.nbytes as u32, cb.offset as u64, 0),
            (true, false) => rwcalls::readv(fd_no, cb.buf, cb.nbytes as u32),
        })
    };
    // `aio_rw_done`: an interrupted transfer is an `EINTR` event, not a
    // failed submission, and so is every other answer.
    Ok(ran.unwrap_or_else(Errno::as_i64))
}
