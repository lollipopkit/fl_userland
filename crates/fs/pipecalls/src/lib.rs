//! `pipe2`, `tee`, and the descriptor at each end of a pipe.
//!
//! The buffer, the capacity, the two open counts, `PIPE_BUF` atomicity,
//! `O_DIRECT` packet mode and `F_SETPIPE_SZ` are `crates/fs/pipe` — this
//! kernel's own object, after `fs/pipe.c` spent its life as 81 lines that
//! called the host's `pipe(2)` and answered every question with macOS's answer.
//! What is here is the descriptor: the `fd_ops` table, the inode-like
//! attributes a guest reads back through `fstat`, and the one thing the crate
//! cannot do for itself — raise `SIGPIPE` in the calling thread.
//!
//! # The end is consumed however the creation ends
//!
//! `install` takes a `*mut End` and frees it on every failure path, so no
//! caller ever frees one and "who owns this now" has one answer.
//!
//! It had three. `adhoc_fd_create_for` failing left the end with the caller;
//! `f_install` failing freed it, because `f_install` calls `fd_close` — and
//! that path is `EMFILE`, which any program that opens enough pipes reaches.
//! The caller could not tell the two apart and freed it either way.


use std::ffi::c_int;

use fs_pipe as pipe;
use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

/// A pipe's driver.
///
/// No seek: a pipe has no position, which is what makes `sendfile` from one
/// `EINVAL` — see the note in `crates/kernel/rwcalls`, where that is checked
/// against the file type as well because a pipe reached through realfs does
/// have an `lseek`.
struct PipeOps;

static PIPE_FDOPS: PipeOps = PipeOps;

fn pipe_fdops() -> Option<&'static dyn ffi::FdOps> {
    Some(&PIPE_FDOPS)
}

impl ffi::FdOps for PipeOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::STREAM
    }
    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        pipe_fd_read(fd, buf)
    }
    fn write(&self, fd: &ffi::fd, buf: &[u8]) -> isize {
        pipe_fd_write(fd, buf)
    }
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        Some(pipe_fd_poll(fd))
    }
    fn ioctl_size(&self, cmd: c_int) -> isize {
        pipe_fd_ioctl_size(cmd)
    }
    fn ioctl(&self, fd: &ffi::fd, cmd: c_int, arg: ffi::IoctlArg<'_>) -> c_int {
        pipe_fd_ioctl(fd, cmd, arg)
    }
    fn close(&self, fd: &mut ffi::fd) -> c_int {
        pipe_fd_close(fd)
    }
    fn setflags(&self, fd: &ffi::fd, flags: u32) -> c_int {
        pipe_fd_setflags(fd, flags)
    }
    fn reopen(&self, fd: &ffi::fd, flags: c_int) -> Result<ffi::FdOwned, c_int> {
        pipe_fd_reopen(fd, flags)
    }
}

/// This description's end, or `None` if it is not a pipe: its driver state
/// since 2026-09-29, where it was a union arm read after checking the
/// operations table -- and handed, null or not, to functions that
/// dereferenced it.
fn end_of(fd: &ffi::fd) -> Option<&pipe::End> {
    fd.driver_state()
}

fn nonblocking(fd: &ffi::fd) -> bool {
    (fd.flags() & ffi::O_NONBLOCK_) != 0
}

// ---------------------------------------------------------------------------
// The descriptor's operations
// ---------------------------------------------------------------------------

fn pipe_fd_read(fd: &ffi::fd, buf: &mut [u8]) -> isize {
    end_of(fd).map_or(pipe::EBADF, |end| end.read(buf, nonblocking(fd)))
}

fn pipe_fd_write(fd: &ffi::fd, buf: &[u8]) -> isize {
    let res = end_of(fd).map_or(pipe::EBADF, |end| end.write(buf, nonblocking(fd)));
    // The one thing the crate cannot do for itself: a write to a pipe with no
    // readers raises SIGPIPE as well as answering EPIPE, and which task to
    // raise it in is `current`. `errno_map` used to do this from the host's
    // EPIPE, and there is no host errno on this path any more. Through the
    // same door as that one, so `RWF_NOSIGNAL` silences both.
    if res == guest_errno::isize_::EPIPE {
        kernel_errno::raise_sigpipe();
    }
    res
}

fn pipe_fd_poll(fd: &ffi::fd) -> c_int {
    end_of(fd).map_or(0, pipe::End::poll)
}

fn pipe_fd_ioctl_size(cmd: c_int) -> isize {
    if cmd == ffi::FIONREAD_ as c_int {
        4
    } else {
        -1
    }
}

fn pipe_fd_ioctl(fd: &ffi::fd, cmd: c_int, mut arg: ffi::IoctlArg<'_>) -> c_int {
    if cmd != ffi::FIONREAD_ as c_int {
        return guest_errno::c_int_::ENOTTY;
    }
    let queued = end_of(fd).map_or(0, pipe::End::queued) as u32;
    if arg.write(queued) { 0 } else { guest_errno::c_int_::EINVAL }
}

/// `F_SETFL`, once the VFS has decided the new flags: the one with a side
/// effect on a pipe is `O_DIRECT`, which is packet mode, and it is the write
/// end's -- Linux reads it from the writing file at each write, so setting it on
/// the read end is recorded and changes nothing, here as there.
fn pipe_fd_setflags(fd: &ffi::fd, flags: u32) -> c_int {
    let Some(end) = end_of(fd) else {
        return -9; // EBADF
    };
    if end.is_write_end() {
        end.set_packet_mode(flags & ffi::O_DIRECT_ != 0);
    }
    0
}

fn pipe_fd_close(fd: &mut ffi::fd) -> c_int {
    if let Some(end) = fd.take_driver_state::<pipe::End>() {
        // The list goes before the object: freeing the end may wake the *other*
        // end's pollers, and this description's own list is about to be freed
        // by `fd_free`. Taking it off first is what stops a wake reaching a
        // list that is being torn down.
        end.unwatch(&fd.poll_watchers);
        drop(end);
    }
    0
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

/// Give `end` a descriptor. On success the `struct fd` owns it; on failure it
/// goes with the call.
fn install(end: Box<pipe::End>, flags: c_int, writing: bool, inode: u64) -> c_int {
    // Unpublished until `f_install` below takes it.
    let mut fd = fs_adhoc::adhoc_new(pipe_fdops(), fs_adhoc::Kind::Pipe);
    {
        // One inode for both ends, as Linux's `get_pipe_inode` makes one
        // inode for the pipe: it is what `fstat` reports and what
        // `/proc/<pid>/fd` shows as `pipe:[ino]`, and a pair of ends with
        // the same number is how `lsof` says which end goes with which.
        fd.stat.inode = inode;
        // The access mode, which `f_install` does not set -- it handles only
        // O_CLOEXEC and O_NONBLOCK. A host pipe carried this on the real
        // descriptor and the host enforced it; now the two ends are one object
        // and nothing else would say which is which, so F_GETFL reported
        // O_RDONLY for both. The object refuses the wrong direction itself as
        // well; this is what a guest reads back. O_DIRECT too, on the write
        // end only: create_pipe_files is
        //
        //     f->f_flags = O_WRONLY | (flags & (O_NONBLOCK | O_DIRECT | O_NOTIFICATION_PIPE));
        //     ...
        //     res[0]->f_flags = O_RDONLY | (flags & (O_NONBLOCK | O_NOTIFICATION_PIPE));
        //
        // and F_GETFL reports it there -- measured by fcntl_probe, which also
        // measured the read end *not* reporting it, after a first version here
        // had given it to both.
        fd.set_flags(if writing {
            ffi::O_WRONLY_ | (flags as u32 & ffi::O_DIRECT_)
        } else {
            ffi::O_RDONLY_
        });
        // 0600, not 0660. `get_pipe_inode` is
        //
        //     inode->i_mode = S_IFIFO | S_IRUSR | S_IWUSR;
        //
        // Nothing can open a pipe by name, so the bits are only ever read back
        // through fstat -- but that is exactly where a program looks to decide
        // what it is holding, and 0660 said a group that does not exist may
        // write. A pipe's inode has one link, not zero.
        fd.stat.mode = ffi::S_IFIFO | 0o600;
        fd.stat.nlink = 1;
        // The **effective** ids, as Linux's `get_pipe_inode` does with
        // `current_fsuid()`. This was the real uid, and the only creation path
        // in the tree that used it -- fakefs, tmpfs and devpts all stamp the
        // effective ids. Invisible while the two could not differ.
        // `.cast()` on both lines until 2026-09-16, between two names for one
        // type -- `taskview` re-exports the crate this came from.
        let (uid, gid) = taskview::with_current_creds(|c| (c.euid(), c.egid())).unwrap_or((0, 0));
        fd.stat.uid = uid;
        fd.stat.gid = gid;
        attach(&mut fd, end);
        fs_fdobj::f_install(fd.into_owned(), flags)
    }
}

/// Make `end` the description's: its state, and the reverse edge so that a
/// write on one side wakes a poll on the other. `pipe_fd_close` takes the
/// edge back before the description is freed.
fn attach(fd: &mut fs_fdobj::NewFd, end: Box<pipe::End>) {
    end.watch(&fd.poll_watchers);
    fd.set_driver_state(end);
}

/// Opening `/proc/<pid>/fd/<n>` on a pipe: a new description on the same
/// pipe, open for the access `flags` names -- `O_RDWR` included, as Linux's
/// `fifo_open` allows -- whichever end `fd` was. Same inode, owner and mode,
/// because it is the same pipe.
fn pipe_fd_reopen(fd: &ffi::fd, flags: c_int) -> Result<ffi::FdOwned, c_int> {
    let end = end_of(fd).ok_or(pipe::EBADF as c_int)?;
    let acc = flags as u32 & ffi::O_ACCMODE_;
    let (reading, writing) = match acc {
        a if a == ffi::O_WRONLY_ => (false, true),
        a if a == ffi::O_RDWR_ => (true, true),
        _ => (true, false),
    };
    let mut new = fs_adhoc::adhoc_new(pipe_fdops(), fs_adhoc::Kind::Pipe);
    new.stat = fd.stat;
    new.set_flags(acc);
    attach(&mut new, Box::new(end.reopen(reading, writing)));
    Ok(new.into_owned())
}

pub fn sys_pipe2(pipe_addr: u64, flags: c_int) -> Result<(), Errno> {
    strace!("pipe2({pipe_addr:#x}, {flags:#x})");
    let known = (ffi::O_CLOEXEC_ | ffi::O_NONBLOCK_ | ffi::O_DIRECT_) as c_int;
    if flags & !known != 0 {
        return Err(Errno::EINVAL);
    }

    let (rd, wr) = pipe::new(flags & ffi::O_DIRECT_ as c_int != 0);

    let inode = fs_adhoc::adhoc_next_inode();
    let mut fp = [0i32; 2];
    fp[0] = install(rd, flags, false, inode);
    if fp[0] < 0 {
        return Err(Errno::from_negative_or_eio(fp[0]));
    }
    fp[1] = install(wr, flags, true, inode);
    if fp[1] < 0 {
        fs_fdobj::f_close(fp[0]);
        return Err(Errno::from_negative_or_eio(fp[1]));
    }

    if GuestMem::current().write_value(pipe_addr, &fp) != 0 {
        {
            fs_fdobj::f_close(fp[1]);
            fs_fdobj::f_close(fp[0]);
        }
        return Err(Errno::EFAULT);
    }
    strace!(" [{} {}]", fp[0], fp[1]);
    Ok(())
}

// ---------------------------------------------------------------------------
// The two pipe-only fcntl commands, and tee
// ---------------------------------------------------------------------------

/// `EBADF`, not `EINVAL`, for a descriptor that is not a pipe.
///
/// Linux routes both commands into `pipe_fcntl`, which begins
///
/// ```c
/// pipe = get_pipe_info(file, false);
/// if (!pipe)
///         return -EBADF;
/// ```
///
/// and `EBADF` is a strange answer for a descriptor that is open — which is
/// exactly why it has to be the one given. A program probing which pipe
/// facilities it has reads the errno, and `EINVAL` says "this kernel knows the
/// command and refused the argument" where `EBADF` says "not a pipe".
pub fn pipe_fcntl_get_size(fd: &ffi::fd) -> c_int {
    end_of(fd).map_or(-9, |end| end.capacity() as c_int) // EBADF
}

/// `F_SETPIPE_SZ`; see [`pipe_fcntl_get_size`] for the errno.
pub fn pipe_fcntl_set_size(fd: &ffi::fd, size: u32, privileged: bool) -> c_int {
    end_of(fd).map_or(-9, |end| end.set_capacity(size, privileged) as c_int) // EBADF
}

/// `vmsplice`'s write into this kernel's pipe, or `None` for a description that
/// is not one.
///
/// `nonblock` is the call's `SPLICE_F_NONBLOCK` and nothing else: Linux's
/// `vmsplice_to_pipe` waits in `wait_for_space` whatever the description's
/// `O_NONBLOCK` says (measured by `rarecalls_probe`). One `End::write`, which
/// waits for room once and then puts in what fits, is that function's shape.
pub fn vmsplice_write(fd: &ffi::fd, buf: &[u8], nonblock: bool) -> Option<isize> {
    let res = end_of(fd)?.write(buf, nonblock);
    if res == guest_errno::isize_::EPIPE {
        kernel_errno::raise_sigpipe();
    }
    Some(res)
}

/// `vmsplice`'s read out of this kernel's pipe, or `None` for a description
/// that is not one. `O_NONBLOCK` is ignored for the reason
/// [`vmsplice_write`] gives.
pub fn vmsplice_read(fd: &ffi::fd, buf: &mut [u8], nonblock: bool) -> Option<isize> {
    Some(end_of(fd)?.read(buf, nonblock))
}

/// The pipe's capacity, or `None` for a description that is not one.
pub fn capacity(fd: &ffi::fd) -> Option<usize> {
    end_of(fd).map(pipe::End::capacity)
}

/// `tee(2)`: copy bytes from one pipe to another without consuming them.
///
/// This was `syscall_stub` — `ENOSYS` — and could not have been anything else
/// while a pipe was the host's, because there is no way to read a host pipe
/// without taking the bytes out of it.
///
pub fn sys_tee(in_fd: c_int, out_fd: c_int, len: u64, flags: u32) -> Result<i64, Errno> {
    strace!("tee({in_fd}, {out_fd}, {len}, {flags:#x})");
    // SPLICE_F_MOVE|NONBLOCK|MORE|GIFT, the same set splice() takes.
    //
    // **Before the length, where `splice` is the other way round.** Measured:
    // `tee(-1, -1, 0, 0xff)` is `EINVAL` on a real kernel and
    // `splice(-1, NULL, -1, NULL, 0, 0xff)` is 0. The two syscalls are one page
    // apart in the manual and the same four lines apart in the source, and they
    // do not agree about which of their arguments they judge first.
    if flags & !0xf != 0 {
        return Err(Errno::EINVAL);
    }
    // Nothing to duplicate is not an error, and Linux answers before it looks
    // at the descriptors: `tee(-1, -1, 0, 0)` is 0 there and was `EINVAL` here.
    if len == 0 {
        return Ok(0);
    }
    let (Some(i), Some(o)) = (fs_fdobj::f_get(in_fd), fs_fdobj::f_get(out_fd)) else {
        return Err(Errno::EINVAL);
    };
    let (Some(ie), Some(oe)) = (end_of(&i), end_of(&o)) else {
        return Err(Errno::EINVAL);
    };
    let nonblock = flags & 2 != 0 || nonblocking(&i) || nonblocking(&o);
    // `tee` answers a byte count or a negative errno. The `as c_int` that
    // used to be here was the return type doing the narrowing; the dispatcher
    // narrows syscall 77 to 32 bits either way, so dropping it changes nothing
    // a guest sees.
    Errno::split(ie.tee(oe, len as usize, nonblock) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `FIONREAD` answers into four bytes and nothing else is answered at all.
    /// The size is what the VFS allocates before calling the ioctl, so a wrong
    /// one is a write past a buffer the caller sized.
    #[test]
    fn the_only_ioctl_is_fionread() {
        assert_eq!(pipe_fd_ioctl_size(ffi::FIONREAD_ as c_int), 4);
        assert_eq!(pipe_fd_ioctl_size(0), -1);
        assert_eq!(pipe_fd_ioctl_size(0x5401), -1); // TCGETS
    }

    /// A pipe's inode is `S_IFIFO | 0600` with one link. 0660 said a group that
    /// does not exist may write, and a program reads these back through
    /// `fstat` to decide what it is holding.
    #[test]
    fn a_pipes_mode_is_the_one_linux_gives_it() {
        assert_eq!(ffi::S_IFIFO | 0o600, 0o010600);
    }

    /// `pipe2(O_DIRECT)`'s flag is kept on both descriptors, as Linux's
    /// `create_pipe_files` keeps it, and `F_GETFL` reports it. A comment here
    /// used to say the opposite -- that leaving it in would let `F_SETFL` clear
    /// it -- and `F_SETFL` clearing it is exactly what Linux allows: packet mode
    /// is the write end's `O_DIRECT` at each write.
    #[test]
    fn o_direct_stays_in_the_write_ends_flags() {
        let flags = (ffi::O_CLOEXEC_ | ffi::O_NONBLOCK_ | ffi::O_DIRECT_) as c_int;
        let stored = |writing: bool| -> u32 {
            if writing {
                ffi::O_WRONLY_ | (flags as u32 & ffi::O_DIRECT_)
            } else {
                ffi::O_RDONLY_
            }
        };
        assert_eq!(stored(true), ffi::O_WRONLY_ | ffi::O_DIRECT_);
        assert_eq!(
            stored(false),
            ffi::O_RDONLY_,
            "the read end does not carry it"
        );
        // O_CLOEXEC and O_NONBLOCK are `f_install`'s and not stored here.
        assert_eq!(stored(true) & (ffi::O_CLOEXEC_ | ffi::O_NONBLOCK_), 0);
    }
}
