//! Moving bytes to and from a descriptor.
//!
//! `read`, `write`, their vectored and positional forms, and `lseek` — the
//! syscalls in `kernel/fs.c` that take a descriptor and no path. Every *rule*
//! they enforce is already `crates/kernel/rwabi`: whether an offset and a count
//! name a range, the `RWF_*` set, and the iovec clamp. What is here is the code
//! that applies them.
//!
//! # The bounce buffer, and why a read may be short and a write may not
//!
//! Guest memory is not host memory — it is reached only through
//! `user_read`/`user_write`, which take the address space's lock — so every one
//! of these copies through a host buffer sized by a number the guest picked.
//! [`rwabi::bounce_clamp`] bounds that at 8 MiB.
//!
//! A **read** is then allowed to be short, because a short read is always legal:
//! it is what the same guest would get from a pipe, and any caller that does not
//! loop on one is already broken against pipes and sockets.
//!
//! A **write** is not. `write()` to a regular file returns the full count on
//! Linux and a great deal of code relies on it, so a request larger than one
//! buffer is *looped* rather than truncated. The bytes and the count the guest
//! sees are the same either way; only the peak allocation differs.


use std::ffi::{c_int, c_uint};

use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

mod iov;
use iov::{Vector, gather, read_iovec, scatter};

mod transfer;
pub use transfer::{sys_copy_file_range, sys_sendfile64, sys_splice};

mod vmsplice;
pub use vmsplice::sys_vmsplice;

mod descriptor;
pub use descriptor::fd_pwrite;
use descriptor::{fd_read, fd_write, pread_at, pwrite_at};

mod syscalls;
pub use syscalls::{
    nowait_read, pread, pread_desc, preadv, preadv_desc, pwrite_desc, pwrite_placed, pwritev_desc,
    pwritev_placed, read, read_desc, readv, readv_desc, sys_lseek64, sys_pread, sys_preadv,
    sys_preadv2, sys_pwrite, sys_pwritev, sys_pwritev2, sys_read, sys_readv, sys_write, sys_writev,
    write, write_desc, writev, writev_desc,
};

/// How many bytes the guest iovec array at `addr` names, or the errno reading
/// it answers: `EINVAL` for more than `UIO_MAXIOV` entries or a bad length,
/// `EFAULT` for an array that is not readable.
///
/// For a caller that has to refuse a bad array *before* it does anything else
/// and run the transfer later: `IOCB_CMD_PREADV` is refused at `io_submit`,
/// while the transfer's own errors are the completion's. `count` is 64-bit
/// because `aio_nbytes` is, and a count past `u32` is `EINVAL` rather than
/// truncated into range.
pub fn iovec_size(addr: u64, count: u64) -> Result<usize, Errno> {
    let count = c_uint::try_from(count).map_err(|_| Errno::EINVAL)?;
    read_iovec(addr, count).map(|(_, total)| total)
}

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

/// A descriptor with no driver, which answers "cannot" to everything.
///
/// One implementation of "there is nothing behind this" rather than a `None`
/// test at each of the dozen call sites below — the shape the tty tables'
/// eighteen `map_or`s turned into an `Unbound` for on 2026-09-09.
struct Unbound;

impl ffi::FdOps for Unbound {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::NONE
    }
}

static UNBOUND: Unbound = Unbound;

/// A description's driver, or [`Unbound`]; see [`Fd::driver`].
fn driver(fd: &ffi::fd) -> &'static dyn ffi::FdOps {
    fd.ops.unwrap_or(&UNBOUND)
}

/// A borrowed descriptor, with the questions this crate asks of one.
///
/// **It held a `usize`** until 2026-09-16 — `f_get`'s pointer with the type
/// taken off and put back by `self.0 as *mut ffi::fd` at every use, so `Fd`
/// was constructible from any integer and every field read was a deref of a
/// raw pointer inside an `unsafe` block, and then a `&'a` whose lifetime the
/// caller chose. It is an [`fs_fdobj::FdRef`] since 2026-09-30, and has no
/// `unsafe` at all.
///
/// `Copy`, because it owns nothing: `f_get` records the reference on the task
/// and `syscall_refs_drain` releases it when the syscall returns.
#[derive(Clone, Copy)]
struct Fd(fs_fdobj::FdRef);

/// Reading the fields is reading the description, so this is the whole of what
/// the old `desc()` and the casts around it were: `fd.offset()`, `fd.flags()`
/// and `fd.type_` read through, and an `Fd` coerces wherever an `FdOps` method
/// wants its `&ffi::fd`.
///
/// The inherent methods are named so that none of them shadows a field —
/// [`Fd::driver`] beside `fd.ops` and [`Fd::locked`] beside `fd.lock`, which
/// would otherwise be two spellings a line apart meaning different things.
impl std::ops::Deref for Fd {
    type Target = ffi::fd;
    fn deref(&self) -> &ffi::fd {
        &self.0
    }
}

impl Fd {
    /// `f_get`, as a handle. `EBADF` for a number the table does not hold.
    ///
    /// # The lifetime
    ///
    /// There is none to choose any more. `'a` was the caller's, an unbounded
    /// lifetime made from `f_get`'s pointer -- the one thing here that was a
    /// promise rather than a check. It is an [`fs_fdobj::FdRef`] now, which
    /// is live until the syscall returns and cannot leave the thread.
    fn get(num: c_int) -> Result<Fd, Errno> {
        fs_fdobj::f_get(num).map(Fd).ok_or(Errno::EBADF)
    }

    /// The same, refusing an `O_PATH` descriptor.
    ///
    /// An `O_PATH` descriptor names a file and cannot be read or written
    /// through — that is the whole distinction, and without it `O_PATH` would
    /// be a way to read a file the caller has no permission for. `EBADF` is
    /// Linux's answer, not `EACCES`: the descriptor is not one you can do this
    /// with.
    fn get_io(num: c_int) -> Result<Fd, Errno> {
        Self::from_io_ref(Fd::get(num)?.0)
    }

    fn from_io_ref(raw: fs_fdobj::FdRef) -> Result<Fd, Errno> {
        let fd = Fd(raw);
        if fd.is_path_only() {
            return Err(Errno::EBADF);
        }
        Ok(fd)
    }

    /// The descriptor's driver.
    ///
    /// Every caller here has already been through `f_get`, which cannot answer
    /// a descriptor with no driver: `fd_create`'s callers all pass one, and the
    /// `None` the field starts at is only ever seen between `calloc` and the
    /// assignment two lines later. `Unbound` rather than a panic so that a
    /// future path which *can* reach one answers an errno instead of taking
    /// the process down from inside a syscall.
    fn driver(&self) -> &'static dyn ffi::FdOps {
        driver(self)
    }

    fn caps(&self) -> ffi::Caps {
        self.driver().caps()
    }

    /// `fd->lock`, held for the length of a scope. The positional calls hold it
    /// across a seek-read-seek sequence, which is the only thing that makes
    /// that sequence atomic against another syscall on the same descriptor.
    fn locked(&self) -> fs_fdobj::FdGuard<'_> {
        fs_fdobj::FdGuard::new(self)
    }
}

/// The largest scratch buffer a thread holds on to between syscalls.
///
/// Above this the allocation is returned to the allocator when the transfer
/// ends, so one `read(fd, buf, 8 MiB)` does not pin eight megabytes per thread
/// for the life of the process. 256 KiB is above every buffer size real code
/// picks — stdio takes kilobytes, Go 32 KB, `cp` up to 256 KB — so the reuse
/// covers everything that happens often.
const SCRATCH_RETAIN: usize = 256 * 1024;

thread_local! {
    /// One scratch buffer per thread, grown to the largest transfer it has
    /// seen and reused.
    ///
    /// It is *taken* rather than borrowed, so a transfer that somehow reaches
    /// another one allocates its own instead of failing or aliasing.
    static SCRATCH: std::cell::Cell<Vec<u8>> = const { std::cell::Cell::new(Vec::new()) };
}

/// A host bounce buffer of `want` bytes, or `ENOMEM`.
///
/// **Not zeroed on every call**, and that is the whole point. This was
/// `Vec::new()` + `try_reserve(want)` + `resize(want, 0)`, which allocates and
/// memsets the guest's entire requested size once per syscall — for a read
/// that is pure waste twice over, because the bytes are either overwritten by
/// the transfer or never looked at, and a read is allowed to be short. A
/// `read(fd, buf, 8192)` that returns 64 bytes memset 8 KB to hand back 64,
/// and `syscall_bench`'s 8 KB read went from 981 ns to 6417 ns because of it.
///
/// Reusing one buffer per thread fixes both halves: `resize` only ever zeroes
/// the part that is newly grown, so the steady state costs no memset at all,
/// and there is no `malloc`/`free` pair per syscall either — which the C did
/// pay. The bytes left over from the previous transfer are this process's own
/// and are never handed to the guest: a read reports what the transfer
/// returned, and every other caller fills what it reads.
///
/// `try_reserve`, because Rust aborts on an allocation failure and this length
/// comes from the guest. See the `panic = "abort"` note in CLAUDE.md.
pub(crate) struct Bounce {
    buf: Vec<u8>,
    want: usize,
}

impl Bounce {
    fn new(want: usize) -> Result<Bounce, Errno> {
        let mut buf = SCRATCH.with(|s| s.take());
        if buf.len() < want {
            if buf.try_reserve(want - buf.len()).is_err() {
                // Put it back: the failure is about this request's size, not
                // about the buffer, and the next transfer may be small.
                SCRATCH.with(|s| s.set(buf));
                return Err(Errno::ENOMEM);
            }
            // Only the newly grown tail is zeroed. What was there before was
            // initialised by an earlier call.
            buf.resize(want, 0u8);
        }
        Ok(Bounce { buf, want })
    }
}

impl Drop for Bounce {
    fn drop(&mut self) {
        let buf = std::mem::take(&mut self.buf);
        if buf.capacity() <= SCRATCH_RETAIN {
            SCRATCH.with(|s| s.set(buf));
        }
    }
}

impl std::ops::Deref for Bounce {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf[..self.want]
    }
}

impl std::ops::DerefMut for Bounce {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.want]
    }
}

pub(crate) fn bounce(want: usize) -> Result<Bounce, Errno> {
    Bounce::new(want)
}
