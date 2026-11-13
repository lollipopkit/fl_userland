//! `process_vm_readv` and `process_vm_writev`: moving bytes between two
//! processes' address spaces without a stop, a descriptor or a shared mapping.
//!
//! Both were `syscall_stub`. `strace` calls the first to read a tracee's memory
//! and falls back to `PTRACE_PEEKDATA` — eight bytes and two context switches
//! per word — when it is refused, which is what made this worth writing after
//! `strace` started running at all.
//!
//! # The decisions are in [`plan`] and the copying is here
//!
//! Every rule this syscall has is arithmetic over the argument numbers: how
//! many elements are too many, which lengths are refusable, how two lists of
//! different shapes line up. None of it needs a task or a byte of guest memory,
//! so all of it is in [`plan`] with unit tests, and what is left here is a loop
//! that copies.
//!
//! The rules were **measured** against an arm64 container rather than read off
//! the man page — `tests/guest/src/bin/procvm_probe.rs` — and four of them are
//! not in the page: `pid` 0 is `ESRCH` and not "myself", 1024 elements are
//! accepted and 1025 refused, a bad *length* refuses the whole call while a bad
//! *address* answers the partial count, and the transfer is the shorter of the
//! two totals rather than an error when they differ.
//!
//! # The address space is pinned, not locked
//!
//! The target's `mm` is taken under `pids_lock`, retained, and the lock
//! dropped before any copying. `/proc/<pid>/mem` holds `pids_lock` across its
//! read instead, which is fine for the one page a reader asks for and would not
//! be here: a transfer is bounded by `MAX_RW_COUNT`, which is just under 2 GiB,
//! and holding the pid registry for that would stop every fork, exit and wait
//! in the system. Linux's `mm_access` pins the same way and for the same
//! reason.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_int;

use kernel_pids::PidsGuard;
use strace::strace;

mod advise;
pub mod plan;

pub use advise::{sys_process_madvise, sys_process_mrelease};

use plan::{Errno, Iov, Piece};

/// How much is moved through the kernel at once.
///
/// A bounce buffer rather than a direct page-to-page copy, because the two
/// address spaces are two `struct mem`s with independent page tables and there
/// is no "map both" primitive here. 64 KiB is large enough that the per-piece
/// cost disappears against the copy and small enough to allocate on every call
/// without asking whether the caller is hostile -- a 2 GiB transfer is 32768
/// iterations of this, not a 2 GiB allocation.
const CHUNK: usize = 64 * 1024;

/// A target address space, pinned for as long as this lives.
struct PinnedMm(mmapcalls::mm::MmRef);

impl PinnedMm {
    /// The address space of the task at `pid`, if the caller may reach it.
    ///
    /// One rule for both directions, which is Linux's: `process_vm_rw` asks
    /// `PTRACE_MODE_ATTACH_REALCREDS` whether it is reading or writing.
    ///
    /// The lookup, the permission check and the retain are one hold of
    /// `pids_lock`: a task found through the registry can be reaped the moment
    /// it is dropped, and the retain is what keeps the address space after
    /// that.
    fn of(pid: i32) -> Result<PinnedMm, Errno> {
        let guard = PidsGuard::take();
        let Some(t) = guard.find_live(pid) else {
            return Err(Errno::ESRCH);
        };
        if !t.may_ptrace(kernel_creds::PtraceMode::AttachReal) {
            return Err(Errno::EPERM);
        }
        let task = t.task();
        // `general_lock`, and it is not optional: `pids_lock` keeps the *task*
        // alive but `execve` and `do_exit` swap `task->mm` without holding it,
        // so a read followed by a retain can resurrect an `mm` whose count
        // has already reached zero. `crates/fs/proc` learned this first and
        // the guard is `taskcalls`' now, so the rule is one rule.
        let mm = taskcalls::GeneralGuard::of(task).mm();
        drop(guard);
        // None: mid-exit, or a kernel task. Linux's `mm_access` answers ESRCH
        // rather than a short transfer, which is the rule `/proc/<pid>/mem`
        // follows here.
        mm.map(PinnedMm).ok_or(Errno::ESRCH)
    }
}

/// Which way the bytes go. The two syscalls differ in this and nothing else.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    /// `process_vm_readv`: the remote address space is the source.
    Read,
    /// `process_vm_writev`: it is the destination.
    Write,
}

/// Read a `struct iovec` array out of the *caller's* memory.
///
/// The count is checked first, so 2000 elements at an unreadable address is
/// `EINVAL` and not `EFAULT` -- which is the order Linux checks in and the
/// probe confirmed.
fn read_iovs(addr: u64, count: u64) -> Result<Vec<Iov>, Errno> {
    let n = plan::check_count(count)?;
    let mut out = vec![Iov::default(); n];
    if n == 0 {
        return Ok(out);
    }
    let err = usercopy::usermem::read_current(addr, plain::slice_bytes_mut(&mut out));
    if err != 0 {
        return Err(Errno::EFAULT);
    }
    plan::check_lengths(&out)?;
    Ok(out)
}

/// Move one piece, and say how many bytes made it.
///
/// A short answer ends the transfer: the count so far is what the syscall
/// returns, which is the partial-transfer rule a bad *address* gets. `buf` is
/// the caller's bounce buffer, reused across pieces.
///
/// Two copies rather than one, because the two address spaces are two page
/// tables with no primitive that maps both -- so the bytes go through this
/// process's own memory on the way. The read is done first and the write only
/// if it succeeded, so a bad source leaves the destination alone.
fn move_piece(mm: &PinnedMm, how: Access, piece: &Piece, buf: &mut [u8]) -> u64 {
    let mut moved = 0u64;
    while moved < piece.len {
        let n = ((piece.len - moved) as usize).min(buf.len());
        let local = piece.local.wrapping_add(moved);
        let remote = piece.remote.wrapping_add(moved);
        let (src, dst) = match how {
            Access::Read => (Side::Remote(remote), Side::Local(local)),
            Access::Write => (Side::Local(local), Side::Remote(remote)),
        };
        // SAFETY: `buf[..n]` is `n` bytes of this process's own memory; `mm` is
        // pinned for its lifetime and the caller's space is this thread's.
        let ok = src.read(mm, &mut buf[..n]) == 0 && dst.write(mm, &buf[..n]) == 0;
        if !ok {
            break;
        }
        moved += n as u64;
    }
    moved
}

/// Which address space an end of the copy is in. The two syscalls are the same
/// loop with these two swapped, which is the whole of the difference between
/// them.
#[derive(Clone, Copy)]
enum Side {
    /// The calling thread's own space, reached without naming it.
    Local(u64),
    /// The pinned one.
    Remote(u64),
}

impl Side {
    // Safe since 2026-10-01: `mm` is pinned, which is what keeps the remote
    // address space live, and the buffers are slices.
    fn read(self, mm: &PinnedMm, out: &mut [u8]) -> c_int {
        match self {
            Side::Local(a) => usercopy::usermem::read_current(a, out),
            Side::Remote(a) => usercopy::usermem::read_held(&mut mm.0.read(), a, out),
        }
    }

    fn write(self, mm: &PinnedMm, data: &[u8]) -> c_int {
        match self {
            Side::Local(a) => usercopy::usermem::write_current(a, data),
            Side::Remote(a) => usercopy::usermem::write_held(&mut mm.0.read(), a, data),
        }
    }
}

/// The body of both syscalls.
fn rw(
    pid: c_int,
    local_addr: u64,
    liovcnt: u64,
    remote_addr: u64,
    riovcnt: u64,
    flags: u64,
    how: Access,
) -> Result<i64, Errno> {
    plan::check_flags(flags)?;
    // **The order is the observable part**, and it was wrong until
    // `table_probe`'s all-zero sweep found it: `process_vm_readv(0,0,0,0,0,0)`
    // is **0** on a real kernel and was `ESRCH` here.
    //
    // Linux imports the local vector and returns the moment it is empty --
    // before the remote array is read at all, so an unreadable one is not
    // EFAULT -- and `process_vm_rw_core` returns before
    // `find_get_task_by_vpid` when the remote side has no pages. So an empty
    // transfer on *either* side answers 0 without the pid being looked at,
    // and only a transfer with something to move can be ESRCH. Every step of
    // that is a case in `procvm_probe` now.
    let local = read_iovs(local_addr, liovcnt)?;
    if local.iter().all(|i| i.len == 0) {
        return Ok(0);
    }
    let remote = read_iovs(remote_addr, riovcnt)?;
    let pieces = plan::pairs(&local, &remote);
    if pieces.is_empty() {
        return Ok(0);
    }
    let mm = PinnedMm::of(plan::check_pid(pid)?)?;

    let mut buf = vec![0u8; CHUNK.min(pieces.iter().map(|p| p.len).sum::<u64>() as usize)];
    let mut done = 0u64;
    for piece in &pieces {
        let n = move_piece(&mm, how, piece, &mut buf);
        done += n;
        if n < piece.len {
            break;
        }
    }
    // A transfer that moved nothing because the very first address was bad is
    // EFAULT; one that moved something and then stopped is the count. That is
    // the difference from a bad length, which refuses the whole call above.
    if done == 0 {
        Err(Errno::EFAULT)
    } else {
        Ok(done as i64)
    }
}

/// Safe, like the other 191 `sys_*`: every argument is a guest value, and the
/// guest memory it names is reached through the checked helpers.
pub fn sys_process_vm_readv(
    pid: c_int,
    local_iov: u64,
    liovcnt: u64,
    remote_iov: u64,
    riovcnt: u64,
    flags: u64,
) -> Result<i64, Errno> {
    strace!(
        "process_vm_readv({pid}, {local_iov:#x}, {liovcnt}, {remote_iov:#x}, {riovcnt}, {flags})"
    );
    rw(
        pid,
        local_iov,
        liovcnt,
        remote_iov,
        riovcnt,
        flags,
        Access::Read,
    )
}

/// As [`sys_process_vm_readv`].
pub fn sys_process_vm_writev(
    pid: c_int,
    local_iov: u64,
    liovcnt: u64,
    remote_iov: u64,
    riovcnt: u64,
    flags: u64,
) -> Result<i64, Errno> {
    strace!(
        "process_vm_writev({pid}, {local_iov:#x}, {liovcnt}, {remote_iov:#x}, {riovcnt}, {flags})"
    );
    rw(
        pid,
        local_iov,
        liovcnt,
        remote_iov,
        riovcnt,
        flags,
        Access::Write,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout the guest writes, which is what `read_iovs` reads back. A
    /// mismatch here would be silent: the second element would be read from
    /// the middle of the first.
    #[test]
    fn an_iovec_is_two_words() {
        assert_eq!(size_of::<Iov>(), 16);
        assert_eq!(align_of::<Iov>(), 8);
    }
}
