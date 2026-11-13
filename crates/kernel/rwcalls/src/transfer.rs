//! Descriptor-to-descriptor transfers: sendfile, copy_file_range, and splice.

use std::os::raw::{c_int, c_uint};

use strace::strace;
use usercopy::GuestMem;

use guest_errno::Errno;

use crate::{Fd, ffi, pread_at, pwrite_at};
use kernel_copyloop as copyloop;

// ---------------------------------------------------------------------------
// Moving bytes between two descriptors
// ---------------------------------------------------------------------------

/// Puts `n` bytes back on a descriptor whose read moved it.
///
/// Whichever way the position was advanced is the way it comes back: the `read`
/// path moved the mount's own idea of it and needs a seek, and the `pread`
/// fallback moved `fd->offset` here.
///
/// The one thing in this transfer that the crate's arithmetic cannot do,
/// because it is about a descriptor rather than about numbers.
fn fd_unread(fd: &Fd, n: u32) {
    if n == 0 {
        return;
    }
    let (ops, caps) = (fd.driver(), fd.caps());
    if caps.read && caps.seek {
        ops.lseek(fd, -(n as i64), ffi::LSEEK_CUR as c_int);
    } else {
        let off = fd.offset();
        if off >= n as i64 {
            fd.set_offset(off - n as i64);
        }
    }
}

/// Asks the mount for a descriptor's `stat`.
fn fd_stat(fd: &Fd) -> Option<ffi::statbuf> {
    let mount = fd.mount()?;
    // The other caller the trait's doc named as wanting an `Option<statbuf>`;
    // both of its `None`s -- no such method, and a failure -- are "no answer"
    // here, which is what `.ok()` says.
    mount.fs.and_then(|fs| fs.fstat(fd))?.ok()
}

/// Whether a descriptor is a pipe or a FIFO, which is what `splice` requires of
/// at least one of its two.
///
/// Asked through `fstat` rather than read off `fd->stat`, because only an adhoc
/// descriptor keeps its mode there — a FIFO opened by name lives on a real
/// mount.
pub(crate) fn fd_is_fifo(fd: &Fd) -> bool {
    fd_kind(fd) == Some(0o10000)
}

/// The file-type bits, asked the same way and for the same reason.
fn fd_kind(fd: &Fd) -> Option<u32> {
    fd_stat(fd).map(|st| st.mode & 0o170000)
}

/// Whether two descriptors name the same file.
///
/// `copy_file_range`'s overlap rule is about the *inode*, not the descriptor:
/// Linux compares `file_inode(file_in) == file_inode(file_out)`, so two separate
/// opens of one path overlap just as much as one descriptor used twice.
/// Answered by `(dev, ino)`, which is what a guest can observe.
///
/// A mount with no `fstat` cannot be asked, and answers "not the same" — the
/// conservative direction is arguable either way, and this one keeps a call
/// that would have worked working.
fn fd_inode_same(a: &Fd, b: &Fd) -> bool {
    // The same *description*, which is an identity of addresses -- `Fd` is a
    // borrow of one, so this is `ptr::eq` rather than the integer comparison
    // the `usize` handle used to make.
    if a.0.as_ptr() == b.0.as_ptr() {
        return true;
    }
    match (fd_stat(a), fd_stat(b)) {
        (Some(sa), Some(sb)) => sa.dev == sb.dev && sa.inode == sb.inode,
        _ => false,
    }
}

/// Move up to `len` bytes from one descriptor to another through a bounce
/// buffer, honouring an explicit offset on either side.
///
/// Shared by `sendfile`, `splice` and `copy_file_range`, because they are one
/// operation here: neither `splice` nor `copy_file_range` can move pages the way
/// Linux does — a guest file's contents are host files reached through `read`
/// and `write` — so all three come down to reading and writing. There were two
/// copies of this once and the same defect was found in both an hour apart.
///
/// The arithmetic is `crates/kernel/copyloop`: which cursor advances by how
/// much, what a short write puts back, and when an errno is worth reporting.
/// What is left here is the descriptors, the buffer, and the seek back.
///
/// **`len` counts in 32 bits and every caller must clamp before it gets here.**
/// The three syscalls above it take a `size_t`, which is 64 bits on aarch64, so
/// an unclamped length of exactly 2^32 arrives as `0` and this reports that it
/// moved nothing — an end-of-file answer to a request for four gigabytes.
/// `sendfile` clamped; `splice` and `copy_file_range` did not, until
/// 2026-09-11. Each of the three has its own rule in `crates/kernel/rwabi`
/// (`sendfile_count`, `splice_count`, `copy_file_range_len`), because the two
/// that refuse a negative length and the one that does not are three measured
/// answers and not one.
fn copy_between(in_fd: &Fd, in_off: &mut i64, out_fd: &Fd, out_off: &mut i64, len: u32) -> i64 {
    let cursor = |off: i64| {
        if off < 0 {
            copyloop::Cursor::Position
        } else {
            copyloop::Cursor::Offset(off)
        }
    };
    let mut c = copyloop::Copier::new(cursor(*in_off), cursor(*out_off), len);
    let mut buf = [0u8; 4096];

    while let Some(chunk) = c.next_chunk(buf.len() as u32) {
        let chunk = chunk as usize;
        // No retry on EINTR. It used to loop, which was right while EINTR here
        // only ever meant a host signal that was the emulator's own business --
        // but since realfs stopped swallowing the wake that delivers a *guest*
        // signal, it means the guest has one waiting. sendfile, splice and
        // copy_file_range are interruptible on Linux, and copyloop already knows
        // what to do with it: report the errno if nothing has moved, and the
        // running total if something has.
        let nread = match c.read_at() {
            // pread_at, not a plain read: reading from the descriptor's own
            // position would copy the wrong bytes and move a descriptor the
            // caller never asked it to move.
            Some(at) => pread_at(in_fd, &mut buf[..chunk], at),
            None => {
                let ops = in_fd.driver();
                if in_fd.caps().read {
                    ops.read(in_fd, &mut buf[..chunk]) as i64
                } else {
                    debug_assert!(in_fd.caps().read_at, "checked by copy_ends");
                    let off = in_fd.offset();
                    let n = ops.pread(in_fd, &mut buf[..chunk], off) as i64;
                    if n > 0 {
                        in_fd.set_offset(off + n);
                    }
                    n
                }
            }
        };

        let mut nwritten = 0i64;
        if nread > 0 {
            let n = nread as usize;
            nwritten = match c.write_at() {
                Some(to) => pwrite_at(out_fd, &buf[..n], to),
                None => {
                    let ops = out_fd.driver();
                    if out_fd.caps().write {
                        ops.write(out_fd, &buf[..n]) as i64
                    } else {
                        debug_assert!(out_fd.caps().write_at, "checked by copy_ends");
                        let off = out_fd.offset();
                        let w = ops.pwrite(out_fd, &buf[..n], off) as i64;
                        if w > 0 {
                            out_fd.set_offset(off + w);
                        }
                        w
                    }
                }
            };
        }

        // Only an input reading from its own position has anything to give
        // back; the crate answers 0 for the offset case, so this needs no second
        // opinion about which it is holding.
        match c.after(nread, nwritten) {
            copyloop::Step::Continue => {}
            copyloop::Step::Stop { put_back } => {
                fd_unread(in_fd, put_back);
                break;
            }
            copyloop::Step::Fail { errno, put_back } => {
                fd_unread(in_fd, put_back);
                return errno as i64;
            }
        }
    }

    if let Some(off) = c.in_offset() {
        *in_off = off;
    }
    if let Some(off) = c.out_offset() {
        *out_off = off;
    }
    c.total() as i64
}

/// Both ends, checked for the operations the transfer needs.
fn copy_ends(
    in_no: c_int,
    out_no: c_int,
    need_out_write: bool,
) -> Result<(Fd, Fd), Errno> {
    let in_fd = Fd::get(in_no)?;
    let out_fd = Fd::get(out_no)?;
    // Asked before the offset argument is read out of guest memory, so a bad
    // pair is `EINVAL` and not `EFAULT` — which is the order Linux has and the
    // reason `FdOps::caps` exists rather than the operations simply answering
    // "unsupported" when called.
    let (i, o) = (in_fd.caps(), out_fd.caps());
    if !i.readable() {
        return Err(Errno::EINVAL);
    }
    // `sendfile` needs the plain `write`: Linux requires `->write_iter` on the
    // output and will not seek-and-write in its place.
    if need_out_write {
        if !o.write {
            return Err(Errno::EINVAL);
        }
    } else if !o.writable() {
        return Err(Errno::EINVAL);
    }
    Ok((in_fd, out_fd))
}

/// Reads an offset argument, or `-1` when the caller passed NULL.
fn read_off_arg(addr: u64) -> Result<i64, Errno> {
    if addr == 0 {
        return Ok(-1);
    }
    let mut word = [0u8; 8];
    if GuestMem.read(addr, &mut word) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(i64::from_le_bytes(word))
}

fn write_off_arg(addr: u64, value: i64) -> Result<(), Errno> {
    if addr == 0 {
        return Ok(());
    }
    if GuestMem.write(addr, &value.to_le_bytes()) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

fn sendfile64(
    out_no: c_int,
    in_no: c_int,
    offset_addr: u64,
    count: u64,
) -> Result<i64, Errno> {
    strace!("sendfile64({out_no}, {in_no}, {offset_addr:#x}, {count})");
    let (in_fd, out_fd) = copy_ends(in_no, out_no, true)?;
    // The input must be seekable. `splice_direct_to_actor`:
    //
    //     /*
    //      * We require the input to be seekable, as we don't want to randomly
    //      * drop data for eg socket -> socket splicing.
    //      */
    //     if (unlikely(!(in->f_mode & FMODE_LSEEK)))
    //         return -EINVAL;
    //
    // Measured: sendfile from a pipe is EINVAL on a real arm64 kernel and copied
    // here. `lseek` alone does not answer it -- a pipe here is a host pipe
    // reached through realfs's table, which has one -- so the question has to be
    // asked of the file type.
    if !in_fd.caps().seek || fd_is_fifo(&in_fd) {
        return Err(Errno::EINVAL);
    }

    let mut offset = -1i64;
    if offset_addr != 0 {
        offset = read_off_arg(offset_addr)?;
        if offset < 0 {
            return Err(Errno::EINVAL);
        }
    }

    // Two rules about the same number, and this only had one. A count above
    // MAX_RW_COUNT is *shortened* -- which the loop's 32-bit length would
    // otherwise do silently -- but a count that is negative as a signed value is
    // refused. Measured: sendfile(out, in, NULL, ~0) is EINVAL on a real arm64
    // kernel and copied the whole file here.
    let moved = rwabi::sendfile_count(count).map_err(Errno::from_negative_or_eio)?;

    let mut out_off = -1i64;
    let res = Errno::split(copy_between(
        &in_fd,
        &mut offset,
        &out_fd,
        &mut out_off,
        moved as u32,
    ));
    if offset_addr != 0 && res.is_ok() {
        write_off_arg(offset_addr, offset)?;
    }
    res
}

fn copy_file_range(
    in_no: c_int,
    in_off_addr: u64,
    out_no: c_int,
    out_off_addr: u64,
    len: u64,
    flags: c_uint,
) -> Result<i64, Errno> {
    strace!(
        "copy_file_range({in_no}, {in_off_addr:#x}, {out_no}, \
         {out_off_addr:#x}, {len}, {flags})"
    );
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let (in_fd, out_fd) = copy_ends(in_no, out_no, false)?;
    let (mut in_off, mut out_off) = (read_off_arg(in_off_addr)?, read_off_arg(out_off_addr)?);

    // Regular files only, and that is the whole rule -- Linux's
    // `generic_copy_file_checks` is `EISDIR` for a directory and `EINVAL` for
    // anything else that is not `S_ISREG`, and it applies **before** the length
    // is looked at. A pipe answered EAGAIN here, from the copy loop finding
    // nothing to read, where a real kernel says EINVAL before it starts -- and
    // the difference matters because EAGAIN reads as "try again" and this would
    // never succeed. Spelling it as "not a FIFO" left every other kind through:
    // `copy_file_range` between two `/dev/null`s with a length of zero reported
    // that it had copied nothing, rather than that neither end is a file.
    //
    // After the offsets, which is where the syscall reads them: the check is in
    // `vfs_copy_file_range`, below the `copy_from_user`s. Measured --
    // `copy_file_range(/dev/null, <bad pointer>, /dev/null, NULL, 1, 0)` is
    // `EFAULT` and not `EINVAL`.
    for end in [&in_fd, &out_fd] {
        match fd_kind(end) {
            Some(0o40000) => return Err(Errno::EISDIR),
            Some(0o100000) => {}
            _ => return Err(Errno::EINVAL),
        }
    }

    // The offsets and the length, and whether they name overlapping parts of one
    // file. That last one can destroy data: the read sees bytes the same call
    // has already written, so the result is neither the old contents nor the
    // new. Nothing checked it, and nothing checked a negative offset either.
    //
    // `read_off_arg` gives -1 for an absent offset argument, meaning "use the
    // descriptor's own position"; the checks apply to the ones that are there.
    let check_in = if in_off_addr != 0 { in_off } else { 0 };
    let check_out = if out_off_addr != 0 { out_off } else { 0 };
    let same = in_no == out_no || fd_inode_same(&in_fd, &out_fd);
    let overlapping = same && in_off_addr != 0 && out_off_addr != 0;
    rwabi::copy_file_range_checks(check_in, check_out, len, overlapping)
        .map_err(Errno::from_negative_or_eio)?;

    // Clamped on the *64-bit* value, because the loop counts in 32 bits and
    // `len` arrives in a 64-bit register. `len = 1 << 32` went in as zero and
    // this answered "copied nothing", which a caller reads as end of file and
    // stops on; a real arm64 kernel copies the file. There is no refusal to go
    // with the clamp -- measured, `copy_file_range(..., ~0, 0)` copies where
    // `sendfile` with the same count is `EINVAL`.
    let moved = rwabi::copy_file_range_len(len);
    let total = copy_between(&in_fd, &mut in_off, &out_fd, &mut out_off, moved as u32);
    // Written back whatever the copy answered, and before it is read: an
    // unwritable offset argument is EFAULT even for a transfer that moved
    // bytes, which is the order this had before the Result.
    write_off_arg(in_off_addr, in_off)?;
    write_off_arg(out_off_addr, out_off)?;
    Errno::split(total)
}

const SPLICE_F_MOVE: c_uint = 1;
pub(crate) const SPLICE_F_NONBLOCK: c_uint = 2;
const SPLICE_F_MORE: c_uint = 4;
const SPLICE_F_GIFT: c_uint = 8;
pub(crate) const SPLICE_F_KNOWN: c_uint = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;

/// `splice(2)`.
///
/// This answered `EINVAL` for every call while being registered in the syscall
/// table, so a guest was told the call exists and then that its arguments were
/// wrong. Callers that check for that fall back to a read/write loop through
/// userspace — which is what this does anyway, one page at a time, so the
/// fallback was strictly worse: the same copies plus two extra syscalls per
/// chunk crossing the emulator boundary.
///
/// Not zero-copy, and cannot be: a guest file's contents are host files reached
/// through `read` and `write`, so there are no pages to move. Linux does not
/// promise zero-copy either, only the semantics — `SPLICE_F_MOVE` has been a
/// no-op there since 2.6.21.
///
/// `SPLICE_F_MORE` is a hint to the network stack and is ignored, as it is on a
/// filesystem that cannot use it. `SPLICE_F_GIFT` applies to `vmsplice`, where
/// it is ignored too: see `crate::vmsplice`.
pub fn sys_splice(
    in_no: c_int,
    in_off_addr: u64,
    out_no: c_int,
    out_off_addr: u64,
    count: u64,
    flags: c_uint,
) -> Result<i64, Errno> {
    strace!(
        "splice({in_no}, {in_off_addr:#x}, {out_no}, {out_off_addr:#x}, \
         {count}, {flags:#x})"
    );
    // Nothing to move is not an error, and Linux says so *before* it looks at
    // anything else -- including the flags: `splice(-1, NULL, -1, NULL, 0, 0xff)`
    // is 0 there. This answered `EBADF`, so a caller looping until a length ran
    // out was told its descriptors had gone bad on the last pass.
    //
    // `tee` is the opposite way round and it was measured, not assumed: its
    // flags are judged first, so `tee(-1, -1, 0, 0xff)` is `EINVAL`.
    if count == 0 {
        return Ok(0);
    }
    if flags & !SPLICE_F_KNOWN != 0 {
        return Err(Errno::EINVAL);
    }
    let (in_fd, out_fd) = copy_ends(in_no, out_no, false)?;

    // At least one end must be a pipe. Without this, splice would be a second
    // spelling of copy_file_range and a program using it to detect pipe support
    // would be told the wrong thing.
    let (in_fifo, out_fifo) = (fd_is_fifo(&in_fd), fd_is_fifo(&out_fd));
    if !in_fifo && !out_fifo {
        return Err(Errno::EINVAL);
    }
    // An offset for the pipe side is ESPIPE: a pipe has no position to seek.
    if (in_fifo && in_off_addr != 0) || (out_fifo && out_off_addr != 0) {
        return Err(Errno::ESPIPE);
    }
    // Both ends being pipes is what tee() is for; splice refuses it.
    if in_fifo && out_fifo {
        return Err(Errno::EINVAL);
    }

    let (mut in_off, mut out_off) = (read_off_arg(in_off_addr)?, read_off_arg(out_off_addr)?);

    // Two rules about the same number, and this had neither. `count` is a
    // `size_t` and the loop below counts in 32 bits, so `1 << 32` went in as
    // zero and this answered 0 -- end of input, to a caller draining a file.
    // And a count that is negative as an `ssize_t` is `EINVAL`, from
    // `rw_verify_area` inside `do_splice_to`; this spliced the file instead.
    // Both measured against a real arm64 kernel.
    //
    // After the descriptor and pipe checks, which is where Linux asks: the
    // verify happens inside `do_splice_to`, below `fdget` and below the "one
    // end must be a pipe" test.
    let moved = rwabi::splice_count(count).map_err(Errno::from_negative_or_eio)?;
    let total = copy_between(&in_fd, &mut in_off, &out_fd, &mut out_off, moved as u32);
    write_off_arg(in_off_addr, in_off)?;
    write_off_arg(out_off_addr, out_off)?;
    Errno::split(total)
}

pub fn sys_sendfile64(out_no: c_int, in_no: c_int, offset_addr: u64, count: u64) -> Result<i64, Errno> {
    crate::syscalls::counted_both(sendfile64(out_no, in_no, offset_addr, count))
}

pub fn sys_copy_file_range(
    in_no: c_int,
    in_off_addr: u64,
    out_no: c_int,
    out_off_addr: u64,
    len: u64,
    flags: c_uint,
) -> Result<i64, Errno> {
    crate::syscalls::counted_both(copy_file_range(in_no, in_off_addr, out_no, out_off_addr, len, flags))
}
