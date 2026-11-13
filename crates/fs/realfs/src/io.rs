//! Host-backed read, write, and interrupted blocking operations.

use std::os::fd::BorrowedFd;
use std::os::raw::{c_int, c_void};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::OFlags;

use crate::errno::{Result, flat, rx};
use crate::{errno, ffi, record};

// ---------------------------------------------------------------------------
// Reading and writing
// ---------------------------------------------------------------------------

/// Retry the interrupted-call cases the guest should never see — and only
/// those.
///
/// A host signal that is purely the emulator's business must not surface as
/// EINTR on a guest read the guest never asked to be interruptible. But SIGUSR1
/// is also how a thread is told it has a *guest* signal to take, and this used
/// to retry past that one too: a guest blocked in `read()` on a pipe or a
/// socket never noticed a signal until the read finished on its own, so
/// `kill -TERM` on a process waiting for input did nothing until the input
/// arrived.
///
/// Measured with `tests/guest/src/bin/setpgid_rules.rs`: a `kill(-pgid,
/// SIGTERM)` to a group of two processes blocked on a pipe killed one of them
/// about half the time, depending on which had reached the host `read` first.
///
/// So the question after an EINTR is whether *this task* has something pending.
/// If it does, the guest gets `EINTR` and the syscall layer delivers the signal
/// — restarting the call afterwards if the handler asked for `SA_RESTART`.
fn retrying<T>(mut call: impl FnMut() -> rustix::io::Result<T>) -> Result<T> {
    loop {
        match call() {
            Err(rustix::io::Errno::INTR) if !taskview::current_signal_pending() => {}
            res => return rx(res),
        }
    }
}

/// Whether a guest signal that is *already* waiting should stop a transfer
/// before it starts.
///
/// [`retrying`] handles the signal that arrives while the thread is inside the
/// host call: SIGUSR1 interrupts it and the pending check turns that into
/// EINTR. It cannot handle the one that arrives just before. SIGUSR1 only does
/// anything to a thread that is *in* a blocking call, and between the syscall
/// layer's last pending check and the host call there are tens of guest
/// instructions to execute — a signal landing in that window is delivered to a
/// thread with nothing to interrupt, and the call then blocks with the signal
/// still pending, for as long as the peer takes.
///
/// Measured with `tests/guest/src/bin/setpgid_rules.rs`, where a
/// `kill(-pgid, SIGTERM)` to two processes blocked reading one pipe reached
/// only one of them in about one run in ten. The survivor also ignored a
/// *direct* SIGTERM, which is what says the fault is here and not in how a
/// process group's members are found.
///
/// Three conditions, all needed, cheapest first:
///
/// - The descriptor is one POSIX lets answer EINTR. A read of a regular file
///   does not block and must never answer EINTR, whatever is pending.
/// - A guest signal is actually waiting. This takes the task's signal lock, so
///   it comes after the free check.
/// - The transfer would in fact wait. Linux hands over data that is already
///   there and delivers the signal afterwards, and a nonblocking descriptor
///   answers EAGAIN rather than waiting at all. Both cost a host call, and
///   only on the rare path where a signal is pending.
///
pub fn realfs_interrupted_before_blocking(fd: &ffi::fd, events: c_int) -> bool {
    let mode = fd.stat.mode & libc::S_IFMT as u32;
    if mode != libc::S_IFIFO as u32
        && mode != libc::S_IFSOCK as u32
        && mode != libc::S_IFCHR as u32
    {
        return false;
    }
    if !taskview::current_signal_pending() {
        return false;
    }
    let Some(host) = fd.host() else {
        return false;
    };
    match rustix::fs::fcntl_getfl(host) {
        Ok(flags) if !flags.contains(OFlags::NONBLOCK) => {}
        _ => return false,
    }
    let mut probe = [PollFd::from_borrowed_fd(host, PollFlags::from_bits_retain(events as _))];
    matches!(poll(&mut probe, Some(&Timespec::default())), Ok(0))
}

/// The host descriptor, or `EBADF` for a description with none -- which a
/// description this driver answers never is.
fn host_of(fd: &ffi::fd) -> Result<BorrowedFd<'_>> {
    fd.host().ok_or(errno::EBADF)
}

/// Tell the change ring about a write, for a description that is watched.
fn record_write(fd: &ffi::fd) {
    if let Some(path) = &fd.change_path {
        record(path, ffi::FAKEFS_CHANGE_OP_WRITE);
    }
}

pub fn realfs_read(fd: &ffi::fd, buf: &mut [u8]) -> isize {
    if realfs_interrupted_before_blocking(fd, libc::POLLIN as c_int) {
        return errno::EINTR as isize;
    }
    let res = host_of(fd).and_then(|host| retrying(|| rustix::io::read(host, &mut *buf)));
    flat(res.map(|n| n as isize))
}

/// The C entry point, which `iul.h` declares and an embedder may call.
///
/// **The one of the four that keeps a pointer and a length**, because that
/// signature is the interface: `ssize_t realfs_write(struct fd *, const void *,
/// size_t)`. It is one `from_raw_parts` with the contract stated, which is
/// where such a conversion belongs -- rather than thirty of them spread over
/// the implementations, which is what this was.
///
/// # Safety
/// `buf` points to `size` readable bytes, and `fd` is live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn realfs_write(fd: &ffi::fd, buf: *const c_void, size: usize) -> isize {
    // SAFETY: the caller's, as declared in `iul.h`.
    realfs_write_bytes(fd, unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), size) })
}

pub fn realfs_write_bytes(fd: &ffi::fd, buf: &[u8]) -> isize {
    if realfs_interrupted_before_blocking(fd, libc::POLLOUT as c_int) {
        return errno::EINTR as isize;
    }
    let res = host_of(fd).and_then(|host| retrying(|| rustix::io::write(host, buf)));
    if res.is_ok() {
        record_write(fd);
    }
    flat(res.map(|n| n as isize))
}

/// A negative offset is `EINVAL`, which the host answered when it was handed
/// one; `rustix` takes a `u64`, so the refusal is here.
fn offset(off: i64) -> Result<u64> {
    u64::try_from(off).map_err(|_| errno::EINVAL)
}

pub fn realfs_pread(fd: &ffi::fd, buf: &mut [u8], off: i64) -> isize {
    let res = host_of(fd).and_then(|host| {
        let off = offset(off)?;
        retrying(|| rustix::io::pread(host, &mut *buf, off))
    });
    flat(res.map(|n| n as isize))
}

pub fn realfs_pwrite(fd: &ffi::fd, buf: &[u8], off: i64) -> isize {
    let res = host_of(fd).and_then(|host| {
        let off = offset(off)?;
        retrying(|| rustix::io::pwrite(host, buf, off))
    });
    if res.is_ok() {
        record_write(fd);
    }
    flat(res.map(|n| n as isize))
}
