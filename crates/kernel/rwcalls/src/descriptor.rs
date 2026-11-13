//! Descriptor operation dispatch and positional I/O fallbacks.

use super::*;

// ---------------------------------------------------------------------------
// The descriptor-level operations
// ---------------------------------------------------------------------------

/// One read through the descriptor's own operation.
///
/// A filesystem may implement `read`, or only `pread` — in which case the file
/// position is applied here and advanced afterwards.
pub(crate) fn fd_read(fd: &Fd, buf: &mut [u8]) -> i64 {
    let (ops, caps) = (fd.driver(), fd.caps());
    if caps.read {
        ops.read(fd, buf) as i64
    } else if caps.read_at {
        let off = fd.offset();
        let res = ops.pread(fd, buf, off) as i64;
        if res > 0 && caps.seek {
            ops.lseek(fd, res, ffi::LSEEK_CUR as c_int);
        }
        res
    } else {
        no_method(fd, false)
    }
}

/// What to answer when the descriptor's file has no `read` or `write` method.
///
/// Linux separates two cases and this used to answer `EBADF` for both:
///
/// - not open for it — `f_mode` has no `FMODE_READ`/`FMODE_WRITE` — is `EBADF`;
/// - open for it, but the file has no such method, is `EINVAL`.
///
/// The second is every anonymous descriptor: an epoll set, an inotify instance,
/// a timerfd. `evfd_probe` measures it on the timerfd, where a `write` is
/// `EINVAL` on a real kernel and was `EBADF` here — which sends a caller looking
/// at a descriptor that is perfectly good.
///
/// The **first** is why this reads the access mode rather than answering
/// `EINVAL` unconditionally, which was the first version of this fix. A
/// directory is opened `O_RDONLY` and `crates/fs/devpts` has neither a `write`
/// nor a `pwrite`, so writing to one would have become `EINVAL` where Linux
/// says `EBADF`. A fix whose own blast radius is every descriptor type needs
/// the distinction the kernel it is copying makes.
pub(crate) fn no_method(fd: &Fd, writing: bool) -> i64 {
    let mode = fd.flags() & ffi::O_ACCMODE_;
    let allowed = if writing {
        mode == ffi::O_WRONLY_ || mode == ffi::O_RDWR_
    } else {
        mode == ffi::O_RDONLY_ || mode == ffi::O_RDWR_
    };
    if allowed {
        guest_errno::i64_::EINVAL
    } else {
        guest_errno::i64_::EBADF
    }
}

pub(crate) fn fd_write(fd: &Fd, buf: &[u8]) -> i64 {
    let (ops, caps) = (fd.driver(), fd.caps());
    let res = if caps.write {
        ops.write(fd, buf) as i64
    } else if caps.write_at {
        let off = fd.offset();
        let res = ops.pwrite(fd, buf, off) as i64;
        if res > 0 && caps.seek {
            ops.lseek(fd, res, ffi::LSEEK_CUR as c_int);
        }
        res
    } else {
        return no_method(fd, true);
    };
    // The path is already on the descriptor, put there when it was opened for
    // writing, so this costs a `None` check when nothing is watching.
    if res > 0
        && let Some(path) = &fd.inotify_path
    {
        // The leaf, not `kernel-inotifycalls`: the event model is where the
        // hook lives, and going through the syscall crate is what made
        // `kernel-rwcalls` -> `kernel-inotifycalls` -> `kernel-pathcalls` ->
        // `kernel-fdattr` -> `kernel-rwcalls` a cycle.
        inotify::notify_path(path.to_bytes(), inotify::IN_MODIFY, 0);
    }
    res
}

/// Positional I/O on a descriptor whose filesystem may not implement it.
///
/// A file with no `pread` is read by seeking, reading and seeking back, which
/// is what `pread` has always had to do here. What was missing is the case
/// where there is no `lseek` either: an eventfd, a socket, a signalfd, a
/// timerfd and an inotify descriptor all have `read` and neither of the other
/// two, so `sys_pread` called through a null function pointer —
/// `pread(eventfd(0,0), b, 8, 0)` from an unprivileged guest killed the
/// emulator. A descriptor with no position to seek to has no positional read
/// either: the answer is `ESPIPE`.
///
/// The caller holds `fd->lock`. The seek-read-seek sequence is only atomic
/// against another syscall on the same descriptor while it is held.
pub(crate) fn pread_at(fd: &Fd, buf: &mut [u8], off: i64) -> i64 {
    fd_pread_slice(fd, buf, off)
}

// `fd_pread` was exported here for `sendfile`, `splice` and `copy_file_range`
// while those were C; they are this crate's now and call `pread_at`, and
// nothing else ever did. The export and its prototype in `fs/fd.h` went on
// 2026-09-04.
pub(crate) fn fd_pread_slice(fd: &ffi::fd, buf: &mut [u8], off: i64) -> i64 {
    let ops = crate::driver(fd);
    let caps = ops.caps();
    if caps.read_at {
        return ops.pread(fd, buf, off) as i64;
    }
    if !(caps.seek && caps.read) {
        return guest_errno::i64_::ESPIPE;
    }
    let saved = ops.lseek(fd, 0, ffi::LSEEK_CUR as c_int);
    if saved < 0 {
        return saved;
    }
    let moved = ops.lseek(fd, off, ffi::LSEEK_SET as c_int);
    if moved < 0 {
        return moved;
    }
    let res = ops.read(fd, buf) as i64;
    // Restoring cannot fail: EBADF and ESPIPE are ruled out by the seek that
    // just succeeded, EOVERFLOW does not apply to LSEEK_SET, and `saved` came
    // from the file so it is not negative.
    let back = ops.lseek(fd, saved, ffi::LSEEK_SET as c_int);
    debug_assert!(back >= 0);
    res
}

pub(crate) fn pwrite_at(fd: &Fd, buf: &[u8], off: i64) -> i64 {
    fd_pwrite_slice(fd, buf, off)
}

/// Positional write through a descriptor whose filesystem may not implement
/// it, for `crates/kernel/fdattr`'s `fallocate` zero-fill. A Rust call: it was
/// a `#[no_mangle]` export with a prototype in `fs/fd.h` for as long as
/// `fallocate` was C, and kept both for four days after it was not.
///
/// The caller holds `fd->lock`: the seek-write-seek fallback is only atomic
/// against another syscall on the same descriptor while it is held.
pub fn fd_pwrite(fd: &ffi::fd, buf: &[u8], off: i64) -> isize {
    fd_pwrite_slice(fd, buf, off) as isize
}

pub(crate) fn fd_pwrite_slice(fd: &ffi::fd, buf: &[u8], off: i64) -> i64 {
    let ops = crate::driver(fd);
    let caps = ops.caps();
    if caps.write_at {
        return ops.pwrite(fd, buf, off) as i64;
    }
    if !(caps.seek && caps.write) {
        return guest_errno::i64_::ESPIPE;
    }
    let saved = ops.lseek(fd, 0, ffi::LSEEK_CUR as c_int);
    if saved < 0 {
        return saved;
    }
    let moved = ops.lseek(fd, off, ffi::LSEEK_SET as c_int);
    if moved < 0 {
        return moved;
    }
    let res = ops.write(fd, buf) as i64;
    let back = ops.lseek(fd, saved, ffi::LSEEK_SET as c_int);
    debug_assert!(back >= 0);
    res
}
