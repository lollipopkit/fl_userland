//! Read, write, and seek syscall entry points.

use super::*;

// ---------------------------------------------------------------------------
// read and write
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Consume only what can be delivered
// ---------------------------------------------------------------------------
//
// A read here bounces through a host buffer and copies to the guest *after* the
// driver has run, so by the time the copy can fail the driver has already given
// the bytes up. Linux's drivers copy to the caller themselves and consume
// exactly what landed, and the difference was measurable:
// `tests/guest/src/bin/faultread_probe.rs` asks a real kernel, and a `read` into
// an unmapped buffer leaves a pipe's bytes queued and leaves a regular file's
// offset where it was. Both were lost here — one `read` with a bad pointer.
//
// **The two halves need different answers, because only one of the losses is
// irrecoverable.** A pipe's bytes are gone: nothing can ask for them again. A
// file's are not — they are still in the file, and all that moved is the
// position. So:
//
// - A descriptor with **no `lseek`** is asked about the destination *before* the
//   driver runs ([`deliverable`]), because there is no undo.
// - A descriptor **with** one is read as before and its position is put back if
//   the delivery fails ([`rewind`]), which costs nothing until it happens.
//
// That split is not a convenience, it is where the cost is. Asking first means a
// page-table walk per page under the address space's lock, and the seekable half
// is the hot one: measured on `syscall_bench`, release, eight interleaved runs a
// side with `getpid` as the control, checking a file read too cost **7% of an
// 8 KB read** and about 2% of a 64-byte one. Checking only the descriptors that
// cannot undo costs nothing there, and those reads are small — a pipe, a socket,
// an eventfd.
//
// A **write** needs neither: the guest's bytes are read before anything is done
// with them, so a fault costs nothing.

/// How many of `want` bytes at `addr` a read may take, or `EFAULT` for none.
///
/// Clamping the request to what is writable gets both halves of Linux's
/// behaviour out of one question. Nothing writable is `EFAULT` **before** the
/// driver is called, so nothing is consumed. A short prefix is a short read: a
/// `read(fd, buf, 1 << 20)` from a pipe holding eight bytes answers 8 on Linux
/// however little of that span is mapped, because the copy stops where the data
/// does — so refusing the whole call would be a regression, and the same probe
/// measures it across a mapped/unmapped page boundary.
fn deliverable(fd: &Fd, addr: u64, want: usize) -> Result<usize, Errno> {
    if want == 0 {
        return Ok(0);
    }
    match GuestMem.writable_prefix(addr, want) {
        // Not a range a guest could name. That is `access_ok`, which Linux
        // applies before it waits, so it is `EFAULT` even for a descriptor with
        // nothing to give.
        n if n < 0 => Err(Errno::EFAULT),
        0 => Err(nothing_writable(fd, fd.flags() & ffi::O_NONBLOCK_ != 0)),
        n => Ok(n as usize),
    }
}

/// The errno for a read whose destination is entirely unwritable.
///
/// Not simply `EFAULT`, because Linux faults **after** it has data: a read of an
/// empty non-blocking pipe into a bad pointer is `EAGAIN` there, and the same
/// pipe with eight bytes in it is `EFAULT`. Asking the descriptor whether it has
/// anything to give is what tells the two apart, and it consumes nothing.
///
/// A descriptor with no `poll` of its own — a regular file — counts as readable,
/// which is what Linux's always-ready file poll amounts to.
///
/// # The one case this does not reproduce
///
/// A **blocking** descriptor with nothing to give. Linux waits there, possibly
/// for ever, and reports the fault when data finally arrives; this answers
/// `EFAULT` at once. Reproducing it means parking a thread in order to deliver
/// an error to a buffer that cannot receive anything either way, and the caller
/// has already passed a pointer it does not own. `probe_diff.sh` carries the
/// difference as `read-blocking-into-unwritable` rather than hiding it.
fn nothing_writable(fd: &Fd, nonblock: bool) -> Errno {
    let ready = match fd.driver().poll(fd) {
        Some(types) => types & fs_poll::bits::READ as c_int != 0,
        // No opinion, which this reads as ready: the point is to answer
        // `EFAULT` for an unwritable buffer rather than pretend the read would
        // have blocked.
        None => true,
    };
    if !ready && nonblock {
        return Errno::EAGAIN;
    }
    Errno::EFAULT
}

/// [`deliverable`] over a vector list: the bytes a scatter could place, counting
/// from the first vector and stopping at the first one that is short.
///
/// Stops early once `want` is covered, so a `readv` whose first vector is large
/// enough asks about one vector however many follow it.
pub(crate) fn deliverable_iov(
    fd: &Fd,
    vectors: &[Vector],
    want: usize,
    nonblock: bool,
) -> Result<usize, Errno> {
    if want == 0 {
        return Ok(0);
    }
    let mut ok = 0usize;
    for v in vectors {
        if ok >= want {
            break;
        }
        let ask = v.len.min(want - ok);
        if ask == 0 {
            continue;
        }
        let got = GuestMem.writable_prefix(v.base, ask);
        if got < 0 {
            // A vector outside the address space is `EFAULT` whatever came
            // before it, the way `access_ok` is: `readv` validates the whole
            // array up front. See [`deliverable`].
            return Err(Errno::EFAULT);
        }
        ok += got as usize;
        if (got as usize) < ask {
            break;
        }
    }
    if ok == 0 {
        Err(nothing_writable(fd, nonblock))
    } else {
        Ok(ok)
    }
}

/// Whether a failed delivery can be undone by putting the position back.
///
/// The presence of `lseek` is the question, not a proxy for it: a descriptor
/// that can be seeked is one whose bytes are still there to be read again, and
/// the only thing a read moved was where the next one starts.
fn rewindable(fd: &Fd) -> bool {
    fd.caps().seek
}

/// Put a seekable descriptor's position back after a delivery that failed, and
/// answer `EFAULT`.
///
/// Relative, so there is nothing to capture on the path that succeeds. It races
/// with another thread reading the same open file description, which shares the
/// position — but so does the read itself, and Linux serialises both under
/// `f_pos_lock` where this crate holds `fd->lock` only for the positional calls.
/// The alternative is asking about the destination up front, which is what the
/// non-seekable half does and what costs 7% of an 8 KB read.
fn rewind(fd: &Fd, by: i64) -> Errno {
    if by > 0 && fd.caps().seek {
        fd.driver().lseek(fd, -by, ffi::LSEEK_CUR as c_int);
    }
    Errno::EFAULT
}

/// The descriptor a stream read reads from, or the errno it answers instead.
///
/// Separate from the read so a caller can get this far, and no further, before
/// asking about the destination: the descriptor is judged first, which is what
/// Linux does and what `tests/guest/src/bin/faultread_probe.rs` checks — a
/// `read(-1, badptr, n)` is `EBADF` and a `read(dirfd, badptr, n)` is `EISDIR`,
/// neither of them `EFAULT`.
fn read_fd_ref(fd: fs_fdobj::FdRef) -> Result<Fd, Errno> {
    let fd = Fd::from_io_ref(fd)?;
    // S_ISDIR: reading a directory through `read` is EISDIR; `getdents64` is
    // how a guest lists one.
    if fd.type_ & 0o170000 == 0o40000 {
        return Err(Errno::EISDIR);
    }
    Ok(fd)
}

fn read_fd(fd_no: c_int) -> Result<Fd, Errno> {
    read_fd_ref(Fd::get(fd_no)?.0)
}

fn read_with(fd: Fd, buf_addr: u64, size: u64) -> Result<i64, Errno> {
    let undo = rewindable(&fd);
    let want = if undo {
        rwabi::bounce_clamp(size)
    } else {
        deliverable(&fd, buf_addr, rwabi::bounce_clamp(size))?
    };
    let mut buf = bounce(want)?;
    // The driver still answers a count or a negative errno -- that is
    // `FdOps`, which a mount implements -- so `split` is what reads the one
    // out of the other.
    let res = Errno::split(fd_read(&fd, &mut buf))?;
    if GuestMem.write(buf_addr, &buf[..res as usize]) != 0 {
        return Err(rewind(&fd, res));
    }
    strace!(
        " {:?}",
        String::from_utf8_lossy(&buf[..(res as usize).min(100)])
    );
    Ok(res)
}

pub fn read(fd_no: c_int, buf_addr: u64, size: u64) -> Result<i64, Errno> {
    strace!("read({fd_no}, {buf_addr:#x}, {size:#x})");
    read_with(read_fd(fd_no)?, buf_addr, size)
}

/// The stream write, from a buffer this owns.
fn write_buf(fd_no: c_int, buf: &[u8]) -> Result<i64, Errno> {
    // V8 chatter on its way to a fatal abort is swallowed; see
    // `crates/kernel/v8mute`, which owns both the signatures and the sticky
    // abort mode they put the thread group into.
    if v8mute::muted(fd_no, buf) {
        return Ok(buf.len() as i64);
    }
    let fd = Fd::get_io(fd_no)?;
    Errno::split(fd_write(&fd, buf))
}

#[derive(Clone, Copy)]
enum WriteTarget<'a> {
    Number(c_int),
    Desc(&'a Fd),
    Positional(&'a Fd, i64),
}

/// A write larger than one bounce buffer, looped.
///
/// `done` is what has already gone out, so an error after the first chunk
/// reports the bytes written rather than the error — which is what Linux does
/// and what a caller resuming from the returned count needs.
fn write_chunked(
    target: WriteTarget<'_>,
    buf_addr: u64,
    size: u64,
) -> Result<i64, Errno> {
    let total = size.min(rwabi::MAX_RW_COUNT);
    // A write of nothing still reaches the file, as Linux's `vfs_write` does:
    // the descriptor is checked -- `write(-1, p, 0)` is `EBADF` -- and the
    // driver decides what nothing means. `/proc/<pid>/comm` takes it as an
    // empty name; a pipe answers 0. The loop below never ran for it, so this
    // answered 0 for any descriptor number at all.
    if total == 0 {
        return match target {
            WriteTarget::Positional(fd, off) => {
                let _guard = fd.locked();
                Errno::split(pwrite_at(fd, &[], off))
            }
            WriteTarget::Desc(fd) => Errno::split(fd_write(fd, &[])),
            WriteTarget::Number(fd_no) => write_buf(fd_no, &[]),
        };
    }
    let cap = rwabi::bounce_clamp(total);
    let mut buf = bounce(cap)?;
    let mut done = 0u64;
    while done < total {
        let chunk = ((total - done) as usize).min(cap);
        if GuestMem.read(buf_addr + done, &mut buf[..chunk]) != 0 {
            return partial(done, Errno::EFAULT);
        }
        let wrote = match target {
            WriteTarget::Positional(fd, off) => {
                let _guard = fd.locked();
                Errno::split(pwrite_at(fd, &buf[..chunk], off + done as i64))
            }
            WriteTarget::Desc(fd) => Errno::split(fd_write(fd, &buf[..chunk])),
            WriteTarget::Number(fd_no) => {
                strace!(
                    "write({fd_no}, {:?}, {chunk})",
                    String::from_utf8_lossy(&buf[..chunk.min(100)])
                );
                write_buf(fd_no, &buf[..chunk])
            }
        };
        let n = match wrote {
            Ok(n) => n,
            Err(e) => return partial(done, e),
        };
        done += n as u64;
        // A short write means the destination will not take more right now.
        if (n as usize) < chunk {
            break;
        }
    }
    Ok(done as i64)
}

/// The rule both chunked writers follow: what has already gone out is the
/// answer, and the errno only when nothing has.
fn partial(done: u64, e: Errno) -> Result<i64, Errno> {
    if done > 0 { Ok(done as i64) } else { Err(e) }
}

pub fn write(fd_no: c_int, buf_addr: u64, size: u64) -> Result<i64, Errno> {
    write_chunked(WriteTarget::Number(fd_no), buf_addr, size)
}

fn pread_with(fd: Fd, buf_addr: u64, size: u64, off: i64) -> Result<i64, Errno> {
    // A negative offset is EINVAL on Linux whatever the file is. It used to be
    // passed down, where realfs happened to reject it and tmpfs answered EPERM.
    if off < 0 {
        return Err(Errno::EINVAL);
    }
    // No question about the destination here, and none about putting anything
    // back: a positional read consumes nothing. The offset is the caller's
    // argument rather than the descriptor's state, and a descriptor with no
    // position answers `ESPIPE` before reaching this.
    let want = rwabi::bounce_clamp(size);
    let mut buf = bounce(want)?;
    let res = Errno::split({
        let _guard = fd.locked();
        pread_at(&fd, &mut buf, off)
    })?;
    if GuestMem.write(buf_addr, &buf[..res as usize]) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(res)
}

pub fn pread(fd_no: c_int, buf_addr: u64, size: u64, off: i64) -> Result<i64, Errno> {
    strace!("pread({fd_no}, {buf_addr:#x}, {size:#x}, {off})");
    pread_with(Fd::get_io(fd_no)?, buf_addr, size, off)
}

fn pwrite(fd_no: c_int, buf_addr: u64, size: u64, off: i64) -> Result<i64, Errno> {
    pwrite_placed(fd_no, buf_addr, size, off, rwabi::Append::AsOpened)
}

fn pwrite_placed_with(
    fd: &Fd,
    buf_addr: u64,
    size: u64,
    off: i64,
    append: rwabi::Append,
) -> Result<i64, Errno> {
    if off < 0 {
        return Err(Errno::EINVAL);
    }
    let at = placed(fd, off, append)?;
    write_chunked(WriteTarget::Positional(fd, at), buf_addr, size)
}

/// `pwrite` with the placement a flags word decided, for `crates/kernel/aio`'s
/// `IOCB_CMD_PWRITE`.
pub fn pwrite_placed(
    fd_no: c_int,
    buf_addr: u64,
    size: u64,
    off: i64,
    append: rwabi::Append,
) -> Result<i64, Errno> {
    strace!("pwrite({fd_no}, {buf_addr:#x}, {size:#x}, {off})");
    let fd = Fd::get_io(fd_no)?;
    pwrite_placed_with(&fd, buf_addr, size, off, append)
}

/// Where a positional write goes: `off`, or the end of the file when the call
/// appends -- which an `O_APPEND` description does unless `RWF_NOAPPEND` said
/// otherwise.
///
/// **`pwrite` on an `O_APPEND` file appends on Linux**, offset or no offset
/// (`generic_write_checks` moves `ki_pos` to the size for any `IOCB_APPEND`),
/// and Darwin's `pwrite` writes at the offset. This passed the offset to the
/// host, so `pwrite(fd, "xyz", 3, 2)` on a ten-byte `O_APPEND` file overwrote
/// bytes 2..5 where Linux leaves the file thirteen bytes long (`rwf_probe`).
///
/// A descriptor with no end -- a pipe, a socket -- has nothing to append at,
/// and its positional write answers `ESPIPE` further down whatever this says.
fn placed(fd: &Fd, off: i64, append: rwabi::Append) -> Result<i64, Errno> {
    if fd.caps().seek && append.at_end(fd.flags() & ffi::O_APPEND_ != 0) {
        return end_of(fd);
    }
    Ok(off)
}

/// The size of the file: where an appending write starts.
///
/// `fstat`'s, not `lseek(SEEK_END)`'s, which is what `RWF_APPEND` asked until
/// 2026-11-11 -- and that *moves* the position, where a positional write on
/// Linux leaves it where it was (`fs_conformance`).
fn end_of(fd: &Fd) -> Result<i64, Errno> {
    let st = fs_fdobj::fd_fstat(fd).map_err(Errno::from_negative_or_eio)?;
    Ok(st.size as i64)
}

pub fn sys_lseek64(fd_no: c_int, off: i64, whence: c_uint) -> Result<i64, Errno> {
    let fd = Fd::get(fd_no)?;
    // An O_PATH descriptor has no file position, because it was never opened
    // for access -- there is nothing for a seek to move. Every other call that
    // reaches through one is refused; this one was missed, so seeking an O_PATH
    // fd succeeded and reported an offset into a file the caller may not even
    // be allowed to read. Measured: EBADF on a real arm64 kernel.
    if fd.is_path_only() {
        return Err(Errno::EBADF);
    }
    if !fd.caps().seek {
        return Err(Errno::ESPIPE);
    }
    strace!("lseek64({fd_no}, {off}, {whence})");
    let _guard = fd.locked();
    let res = fd.driver().lseek(&fd, off, whence as c_int);
    strace!(" -> {res}");
    // An offset is a *value* and this syscall is in `returns_64bit`, so only
    // the errno range is an error -- which is the same rule the dispatcher
    // applies and the reason `lseek` past 2^63 works at all.
    Errno::split(res)
}

/// The write half of a chunked vectored write.
///
/// A write to a regular file must not be short, so an error after the first
/// chunk reports the bytes that went out rather than the error — the same rule
/// [`write_chunked`] follows for the non-vectored path.
fn writev_chunked(
    vectors: &[Vector],
    io_size: usize,
    cap: usize,
    mut write_chunk: impl FnMut(&[u8]) -> Result<i64, Errno>,
) -> Result<i64, Errno> {
    let mut buf = bounce(cap)?;
    let mut done = 0usize;
    while done < io_size {
        let chunk = (io_size - done).min(cap);
        if let Err(e) = gather(vectors, &mut buf[..chunk], done) {
            return partial(done as u64, e);
        }
        let n = match write_chunk(&buf[..chunk]) {
            Ok(n) => n,
            Err(e) => return partial(done as u64, e),
        };
        done += n as usize;
        if (n as usize) < chunk {
            break; // a short write ends it, and what went out is the answer
        }
    }
    Ok(done as i64)
}

fn readv_with(fd: Fd, iovec_addr: u64, count: c_uint) -> Result<i64, Errno> {
    let (vectors, io_size) = read_iovec(iovec_addr, count)?;
    let undo = rewindable(&fd);
    let want = if undo {
        rwabi::bounce_clamp(io_size as u64)
    } else {
        deliverable_iov(&fd, &vectors, rwabi::bounce_clamp(io_size as u64), fd.flags() & ffi::O_NONBLOCK_ != 0)?
    };
    let mut buf = bounce(want)?;
    let res = Errno::split(fd_read(&fd, &mut buf))?;
    match scatter(&vectors, &buf, res as usize) {
        Err(_) => Err(rewind(&fd, res)),
        Ok(()) => Ok(res),
    }
}

pub fn readv(fd_no: c_int, iovec_addr: u64, count: c_uint) -> Result<i64, Errno> {
    strace!("readv({fd_no}, {iovec_addr:#x}, {count})");
    readv_with(read_fd(fd_no)?, iovec_addr, count)
}

pub fn writev(fd_no: c_int, iovec_addr: u64, count: c_uint) -> Result<i64, Errno> {
    strace!("writev({fd_no}, {iovec_addr:#x}, {count})");
    let (vectors, io_size) = read_iovec(iovec_addr, count)?;
    let cap = rwabi::bounce_clamp(io_size as u64);
    writev_chunked(&vectors, io_size, cap, |buf| write_buf(fd_no, buf))
}

// `preadv`/`pwritev` — the offset arrives in two registers, and on a 64-bit
// guest **the second one is ignored**. Linux:
//
//     static inline loff_t pos_from_hilo(unsigned long high, unsigned long low)
//     {
//     #define HALF_LONG_BITS (BITS_PER_LONG / 2)
//         return (((loff_t)high << HALF_LONG_BITS) << HALF_LONG_BITS) | low;
//     }
//
// `HALF_LONG_BITS` is 32 here, so the first term is a 64-bit value shifted 64
// bits: zero. `low` is the whole offset.
//
// This used to compute `((qword_t)pos_h << 32) | pos_l` with `pos_l` narrowed
// to 32 bits, which is not what any kernel does. It worked for musl, whose
// pwritev.c passes `(long)ofs` and `(long)(ofs>>32)` so that the halves happen
// to line up -- and failed for **glibc**, whose `LO_HI_LONG(x)` is a single
// argument on 64-bit and leaves `pos_h` holding whatever the register had. A
// glibc program's preadv answered EINVAL, or read from four gigabytes into the
// file, depending on the garbage. Measured: `preadv(fd, iov, 1, 0)` with four
// arguments returns 4 on a real arm64 kernel and returned EINVAL here.

fn preadv_with(
    fd: Fd,
    iovec_addr: u64,
    count: c_uint,
    pos_l: u64,
    _pos_h: u64,
) -> Result<i64, Errno> {
    let off = pos_l as i64;
    let (vectors, io_size) = read_iovec(iovec_addr, count)?;
    // Whether the offset and the total name a range at all. The `off < 0` test
    // that used to be here was half of it: an offset that is positive and a
    // count that pushes it past LLONG_MAX is also EINVAL, and this answered 0 --
    // an end-of-file report for a range that cannot exist.
    rwabi::verify_area(off, io_size as u64).map_err(Errno::from_negative_or_eio)?;
    // Clamped, not the guest's total: this used to allocate whatever the
    // vectors added up to, which after the iovec bound became a two-gigabyte
    // host allocation from a number the guest picked. A short read is always
    // legal, so shortening the buffer is a conformant answer where shortening a
    // write would not be.
    //
    // Nothing is asked about the destination and nothing is put back: as in
    // [`sys_pread`], a positional read consumes nothing.
    let want = rwabi::bounce_clamp(io_size as u64);
    let mut buf = bounce(want)?;
    let res = Errno::split({
        let _guard = fd.locked();
        pread_at(&fd, &mut buf, off)
    })?;
    scatter(&vectors, &buf, res as usize)?;
    Ok(res)
}

/// `pos_l` carries the whole offset and `pos_h` is ignored. Both are 64-bit
/// for that reason: `pos_l` used to be a `dword_t`, which threw away the top
/// half of a register the caller had filled.
pub fn preadv(
    fd_no: c_int,
    iovec_addr: u64,
    count: c_uint,
    pos_l: u64,
    pos_h: u64,
) -> Result<i64, Errno> {
    strace!("preadv({fd_no}, {iovec_addr:#x}, {count}, {})", pos_l as i64);
    preadv_with(Fd::get_io(fd_no)?, iovec_addr, count, pos_l, pos_h)
}

fn pwritev(
    fd_no: c_int,
    iovec_addr: u64,
    count: c_uint,
    pos_l: u64,
    _pos_h: u64,
) -> Result<i64, Errno> {
    pwritev_placed(fd_no, iovec_addr, count, pos_l as i64, rwabi::Append::AsOpened)
}

fn pwritev_placed_with(
    fd: &Fd,
    iovec_addr: u64,
    count: c_uint,
    off: i64,
    append: rwabi::Append,
) -> Result<i64, Errno> {
    let (vectors, io_size) = read_iovec(iovec_addr, count)?;
    rwabi::verify_area(off, io_size as u64).map_err(Errno::from_negative_or_eio)?;
    let cap = rwabi::bounce_clamp(io_size as u64);
    // Chunked, with the offset advancing: a write must not be short, so a total
    // above the bounce buffer is looped rather than truncated.
    let mut at = placed(fd, off, append)?;
    writev_chunked(&vectors, io_size, cap, |buf| {
        let n = Errno::split({
            let _guard = fd.locked();
            pwrite_at(fd, buf, at)
        })?;
        if n > 0 {
            at += n;
        }
        Ok(n)
    })
}

/// `pwritev` with the placement a flags word decided: [`sys_pwritev2`]'s and
/// `crates/kernel/aio`'s `IOCB_CMD_PWRITEV`.
pub fn pwritev_placed(
    fd_no: c_int,
    iovec_addr: u64,
    count: c_uint,
    off: i64,
    append: rwabi::Append,
) -> Result<i64, Errno> {
    strace!("pwritev({fd_no}, {iovec_addr:#x}, {count}, {off})");
    let fd = Fd::get_io(fd_no)?;
    pwritev_placed_with(&fd, iovec_addr, count, off, append)
}

// `preadv2`/`pwritev2` — the same plus a per-call flags word. `pos == -1` means
// "use the current file position", which is the stream form.
//
// Bun reads tty and pipe stdin through `preadv2(fd, iov, n, -1, 0)` and treats
// a raw ENOSYS as a dead stream -- it tears down stdin and Claude Code's UI
// stops seeing keys -- so these must exist even though the flags they add are
// mostly hints for us.
//
// Which flags exist, and what each direction does with them, is
// crates/kernel/rwabi. Both directions were wrong here and in opposite ways: a
// *read* refused RWF_DSYNC, RWF_SYNC and RWF_APPEND, which a real kernel
// accepts and ignores because a read has neither durability nor placement; and
// a *write* refused RWF_APPEND with an explicit offset, which is exactly the
// case the flag exists for -- it means "ignore the offset, put this at the
// end". Measured: pwritev2(fd, iov, 1, 0, 0, RWF_APPEND) leaves a ten-byte file
// thirteen bytes long on a real arm64 kernel.

/// `RWF_NOWAIT` on a read: `EAGAIN` when the descriptor has nothing to give
/// right now, the way Linux answers a NOWAIT read that would sleep. Linux
/// answers EOPNOTSUPP instead when the *filesystem* has no FMODE_NOWAIT, which
/// is a property of the mount rather than a rule -- so this and a container can
/// legitimately differ, and probe_diff.sh says so.
///
/// Public because `crates/kernel/aio` applies the same flags word to an
/// `IOCB_CMD_PREAD`, whose buffer is not an iovec this file could be handed.
pub fn nowait_read(fd_no: c_int) -> Result<(), Errno> {
    let fd = Fd::get(fd_no)?;
    if let Some(types) = fd.driver().poll(&fd)
        && types & fs_poll::bits::READ as c_int == 0
    {
        return Err(Errno::EAGAIN);
    }
    Ok(())
}

fn preadv2(
    fd_no: c_int,
    iovec_addr: u64,
    count: c_uint,
    pos_l: u64,
    pos_h: u64,
    flags: c_uint,
) -> Result<i64, Errno> {
    let off = pos_l as i64;
    strace!("preadv2({fd_no}, {iovec_addr:#x}, {count}, {off}, {flags:#x})");
    let rwf = rwabi::rw_flags(flags, false).map_err(Errno::from_negative_or_eio)?;
    if rwf.nowait {
        nowait_read(fd_no)?;
    }
    if off == -1 {
        return readv(fd_no, iovec_addr, count);
    }
    preadv(fd_no, iovec_addr, count, pos_l, pos_h)
}

fn pwritev2(
    fd_no: c_int,
    iovec_addr: u64,
    count: c_uint,
    pos_l: u64,
    _pos_h: u64,
    flags: c_uint,
) -> Result<i64, Errno> {
    let off = pos_l as i64;
    strace!("pwritev2({fd_no}, {iovec_addr:#x}, {count}, {off}, {flags:#x})");
    let rwf = rwabi::rw_flags(flags, true).map_err(Errno::from_negative_or_eio)?;
    let _quiet = rwf.nosignal.then(kernel_errno::NoSigpipe::new);
    if off != -1 {
        return pwritev_placed(fd_no, iovec_addr, count, off, rwf.append);
    }
    // The stream form. The driver applies the description's own O_APPEND, so
    // only a call whose placement differs from it -- `RWF_APPEND` on a plain
    // description, `RWF_NOAPPEND` on an O_APPEND one -- is written here: at the
    // end or at the position, positionally, and the position then moves past
    // it as a stream write would have moved it.
    let fd = Fd::get_io(fd_no)?;
    let o_append = fd.flags() & ffi::O_APPEND_ != 0;
    let at_end = rwf.append.at_end(o_append);
    if !fd.caps().seek || at_end == o_append {
        return writev(fd_no, iovec_addr, count);
    }
    let at = if at_end {
        end_of(&fd)?
    } else {
        Errno::split({
            let _guard = fd.locked();
            fd.driver().lseek(&fd, 0, ffi::LSEEK_CUR as c_int)
        })?
    };
    let n = pwritev_placed(fd_no, iovec_addr, count, at, rwabi::Append::Never)?;
    let _guard = fd.locked();
    Errno::split(fd.driver().lseek(&fd, at + n, ffi::LSEEK_SET as c_int))?;
    Ok(n)
}

// ---------------------------------------------------------------------------
// /proc/<pid>/io
// ---------------------------------------------------------------------------

/// Which counters a call moves.
#[derive(Clone, Copy)]
enum Side {
    Read,
    Write,
}

/// `inc_syscr`/`add_rchar` and their write halves, for one call.
///
/// `vfs_read` counts once the descriptor is open for reading, which a bad
/// descriptor (`EBADF`) and a positional call on a pipe (`ESPIPE`) are not;
/// `do_readv` and its relatives count every call, whatever it answered
/// (`whatever`). A transfer is counted by what it returned. The counters are
/// the calling task's and only it writes them; see `kernel_observe`.
fn counted(side: Side, whatever: bool, r: Result<i64, Errno>) -> Result<i64, Errno> {
    if whatever || !matches!(r, Err(Errno::EBADF | Errno::ESPIPE)) {
        let n = r.map_or(0, |n| n.max(0) as u64);
        taskview::with_current_task(|t| match side {
            Side::Read => t.io.read(n),
            Side::Write => t.io.wrote(n),
        });
    }
    r
}

pub fn sys_read(fd_no: c_int, buf_addr: u64, size: u64) -> Result<i64, Errno> {
    counted(Side::Read, false, read(fd_no, buf_addr, size))
}

pub fn sys_write(fd_no: c_int, buf_addr: u64, size: u64) -> Result<i64, Errno> {
    counted(Side::Write, false, write(fd_no, buf_addr, size))
}

pub fn sys_pread(fd_no: c_int, buf_addr: u64, size: u64, off: i64) -> Result<i64, Errno> {
    counted(Side::Read, false, pread(fd_no, buf_addr, size, off))
}

pub fn sys_pwrite(fd_no: c_int, buf_addr: u64, size: u64, off: i64) -> Result<i64, Errno> {
    counted(Side::Write, false, pwrite(fd_no, buf_addr, size, off))
}

pub fn sys_readv(fd_no: c_int, iovec_addr: u64, count: c_uint) -> Result<i64, Errno> {
    counted(Side::Read, true, readv(fd_no, iovec_addr, count))
}

pub fn sys_writev(fd_no: c_int, iovec_addr: u64, count: c_uint) -> Result<i64, Errno> {
    counted(Side::Write, true, writev(fd_no, iovec_addr, count))
}

pub fn sys_preadv(fd_no: c_int, iovec_addr: u64, count: c_uint, pos_l: u64, pos_h: u64) -> Result<i64, Errno> {
    counted(Side::Read, true, preadv(fd_no, iovec_addr, count, pos_l, pos_h))
}

pub fn sys_pwritev(fd_no: c_int, iovec_addr: u64, count: c_uint, pos_l: u64, pos_h: u64) -> Result<i64, Errno> {
    counted(Side::Write, true, pwritev(fd_no, iovec_addr, count, pos_l, pos_h))
}

pub fn sys_preadv2(
    fd_no: c_int,
    iovec_addr: u64,
    count: c_uint,
    pos_l: u64,
    pos_h: u64,
    flags: c_uint,
) -> Result<i64, Errno> {
    counted(Side::Read, true, preadv2(fd_no, iovec_addr, count, pos_l, pos_h, flags))
}

pub fn sys_pwritev2(
    fd_no: c_int,
    iovec_addr: u64,
    count: c_uint,
    pos_l: u64,
    pos_h: u64,
    flags: c_uint,
) -> Result<i64, Errno> {
    counted(Side::Write, true, pwritev2(fd_no, iovec_addr, count, pos_l, pos_h, flags))
}

pub fn read_desc(fd: fs_fdobj::FdRef, buf_addr: u64, size: u64) -> Result<i64, Errno> {
    counted(Side::Read, false, read_fd_ref(fd).and_then(|d| read_with(d, buf_addr, size)))
}

pub fn write_desc(fd: fs_fdobj::FdRef, buf_addr: u64, size: u64) -> Result<i64, Errno> {
    counted(
        Side::Write,
        false,
        Fd::from_io_ref(fd).and_then(|d| write_chunked(WriteTarget::Desc(&d), buf_addr, size)),
    )
}

pub fn pread_desc(fd: fs_fdobj::FdRef, buf_addr: u64, size: u64, off: i64) -> Result<i64, Errno> {
    counted(
        Side::Read,
        false,
        Fd::from_io_ref(fd).and_then(|d| pread_with(d, buf_addr, size, off)),
    )
}

pub fn pwrite_desc(fd: fs_fdobj::FdRef, buf_addr: u64, size: u64, off: i64) -> Result<i64, Errno> {
    counted(
        Side::Write,
        false,
        Fd::from_io_ref(fd)
            .and_then(|d| pwrite_placed_with(&d, buf_addr, size, off, rwabi::Append::AsOpened)),
    )
}

pub fn readv_desc(fd: fs_fdobj::FdRef, iovec_addr: u64, count: c_uint) -> Result<i64, Errno> {
    counted(
        Side::Read,
        true,
        read_fd_ref(fd).and_then(|d| readv_with(d, iovec_addr, count)),
    )
}

pub fn writev_desc(fd: fs_fdobj::FdRef, iovec_addr: u64, count: c_uint) -> Result<i64, Errno> {
    counted(Side::Write, true, || -> Result<i64, Errno> {
        let fd = Fd::from_io_ref(fd)?;
        let (vectors, io_size) = read_iovec(iovec_addr, count)?;
        let cap = rwabi::bounce_clamp(io_size as u64);
        writev_chunked(&vectors, io_size, cap, |buf| Errno::split(fd_write(&fd, buf)))
    }())
}

pub fn preadv_desc(
    fd: fs_fdobj::FdRef,
    iovec_addr: u64,
    count: c_uint,
    pos_l: u64,
    pos_h: u64,
) -> Result<i64, Errno> {
    counted(
        Side::Read,
        true,
        Fd::from_io_ref(fd).and_then(|d| preadv_with(d, iovec_addr, count, pos_l, pos_h)),
    )
}

pub fn pwritev_desc(
    fd: fs_fdobj::FdRef,
    iovec_addr: u64,
    count: c_uint,
    pos_l: u64,
    _pos_h: u64,
) -> Result<i64, Errno> {
    counted(
        Side::Write,
        true,
        Fd::from_io_ref(fd).and_then(|d| {
            pwritev_placed_with(&d, iovec_addr, count, pos_l as i64, rwabi::Append::AsOpened)
        }),
    )
}

/// `sendfile` and `copy_file_range`: one of each, by what was moved, once the
/// two descriptors were accepted.
pub(crate) fn counted_both(r: Result<i64, Errno>) -> Result<i64, Errno> {
    if let Ok(n) = r {
        taskview::with_current_task(|t| {
            t.io.read(n as u64);
            t.io.wrote(n as u64);
        });
    }
    r
}
