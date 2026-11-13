//! What you can ask of an open file without naming it.
//!
//! `fchmod`, `fchown`, `ftruncate`, `fallocate`, `fsync`, `syncfs`, `flock`,
//! `fstatfs`, `fadvise64` and `readahead` — the syscalls in `kernel/fs.c` that
//! take a descriptor and change or report something about the file behind it,
//! as against `crates/kernel/rwcalls`, which moves its bytes.
//!
//! Two of them do nothing and exist for their **argument handling**, which is
//! the part a caller can observe. `fadvise64` and `readahead` are advisory and
//! this kernel does no caching of its own, so acting on the hint is a no-op —
//! but answering success for an advice value Linux does not know, or for a
//! descriptor Linux refuses, tells a caller probing its own argument handling
//! that nothing is wrong with a number that means nothing.


use std::ffi::{c_int, c_uint};

use guest_errno::Errno;
use strace::strace;

// Hand-written, so no bindgen excuses: the block that used to be here named
// `clippy::all` and `non_camel_case_types`, which are the generated module's
// needs and not this one's. The same misplacement `crates/fs/proc` had on its
// `net` module -- an `#[allow]` one line above the wrong item is invisible,
// because the module it *should* cover compiles clean either way.
mod advice;
mod cachestat;
mod fileattr;
mod statfs;
pub mod xattr;
pub use cachestat::sys_cachestat;
pub use fileattr::{sys_file_getattr, sys_file_setattr};
pub use advice::{sys_fadvise64, sys_readahead};
pub use statfs::{statfs_mount, sys_fstatfs_arm64};

// The shared C types and `#define`s, which are `crates/kernel/taskview`'s.
// This crate generated a file whose whole content was the import line; see
// crates/kernel/taskview.
pub use taskview::ffi;

/// A borrowed descriptor; `f_get`'s reference is released by the syscall exit.
///
/// **It held a `usize`** until 2026-09-16, the same shape
/// `crates/kernel/rwcalls` carried: `f_get`'s pointer with the type taken off,
/// so the handle was constructible from any integer and every field read was an
/// `unsafe` deref. An [`fs_fdobj::FdRef`] since 2026-09-30, which is the
/// same syscall-long borrow with nothing left to promise.
#[derive(Clone, Copy)]
struct Fd(fs_fdobj::FdRef);

/// The fields, read through: `fd.type_`, `fd.mount`, `fd.flags()`. Nothing here
/// shadows a field, so there is no inherent method to confuse with one.
impl std::ops::Deref for Fd {
    type Target = ffi::fd;
    fn deref(&self) -> &ffi::fd {
        &self.0
    }
}

impl Fd {
    fn get(num: c_int) -> Result<Fd, Errno> {
        fs_fdobj::f_get(num).map(Fd).ok_or(Errno::EBADF)
    }

    fn fs(&self) -> Option<&'static dyn ffi::FsOps> {
        self.mount()?.fs
    }

    fn stat(&self) -> Option<ffi::statbuf> {
        // The second of the three adapters. Both of the trait's ways of not
        // answering are `None` here, which is what `.ok()` says.
        self.fs()?.fstat(self)?.ok()
    }

    fn kind(&self) -> c_uint {
        self.type_ as c_uint
    }
}

/// The file-type bits of a mode.
const S_IFMT: c_uint = 0o170000;
const S_IFREG: c_uint = 0o100000;
const S_IFDIR: c_uint = 0o40000;
const S_IFBLK: c_uint = 0o60000;
const S_IFLNK: c_uint = 0o120000;
const S_IFIFO: c_uint = 0o10000;

// ---------------------------------------------------------------------------
// Setting an attribute
// ---------------------------------------------------------------------------

/// One attribute change, permission-checked.
///
/// The rules are `crates/kernel/creds`, reached through `setattr_check`, which
/// reads the caller's ids off the task. There was no check of any kind here
/// once, which with set-id exec working was a local root.
fn set_attr(fd: &Fd, a: ffi::Attr) -> Result<(), Errno> {
    let Some(fs) = fd.fs() else {
        return Err(Errno::EPERM);
    };
    let stat = fd.stat();
    let a = match stat {
        Some(st) => fs_perm::setattr_check(&st, a).map_err(Errno::from_negative_or_eio)?,
        None => a,
    };
    done(fs.fsetattr(fd, a))?;
    if let Some(st) = stat
        && matches!(a, ffi::Attr::Uid(_) | ffi::Attr::Gid(_))
    {
        // A change of ownership takes the set-id bits with it -- see
        // creds::mode_after_chown for which ones and why S_IXGRP decides
        // the setgid half -- and the file's capabilities, `ATTR_KILL_PRIV`.
        // Best effort: the ownership change has already happened and
        // reporting a failure here would be reporting the wrong thing.
        if st.mode & 0o170000 != 0o040000 {
            fs.fxattr(fd, ffi::XattrCall::Remove { name: c"security.capability" });
        }
        if let Some(reduced) = kernel_creds::mode_after_chown(st.mode) {
            // The mode bits fit: `mode_after_chown` only clears.
            fs.fsetattr(fd, ffi::Attr::Mode(reduced as ffi::mode_t_));
        }
    }
    Ok(())
}

/// What a filesystem operation here answers: 0, or a negative guest errno.
///
/// The same helper `crates/kernel/pathcalls` has, for the same reason: none of
/// these operations has a success that carries a number.
fn done(err: c_int) -> Result<(), Errno> {
    if err < 0 {
        Err(Errno::from_negative_or_eio(err))
    } else {
        Ok(())
    }
}

pub fn sys_fchmod(num: c_int, mode: c_uint) -> Result<(), Errno> {
    strace!("fchmod({num}, {mode:o})");
    let fd = Fd::get(num)?;
    // Truncated to the guest's `mode_t`, as the union's 16-bit arm did.
    set_attr(&fd, ffi::Attr::Mode((mode & !S_IFMT) as ffi::mode_t_))
}

pub fn sys_fchown32(num: c_int, owner: c_uint, group: c_uint) -> Result<(), Errno> {
    strace!("fchown({num}, {owner}, {group})");
    let fd = Fd::get(num)?;
    if owner != u32::MAX {
        set_attr(&fd, ffi::Attr::Uid(owner))?;
    }
    if group != u32::MAX {
        set_attr(&fd, ffi::Attr::Gid(group))?;
    }
    Ok(())
}

pub fn sys_ftruncate64(num: c_int, size: i64) -> Result<(), Errno> {
    strace!("ftruncate64({num}, {size})");
    let fd = Fd::get(num)?;
    // Only a regular file has a length to set. A directory already answered
    // `EINVAL` because no `fs_ops` would take the attribute, but a character
    // device answered **0** and did nothing -- so `ftruncate` on `/dev/null`
    // reported that it had truncated it. Linux is `EINVAL` for every one of
    // these, where the *path* form is `EISDIR` for a directory; that asymmetry
    // is real and is measured by `tests/guest/src/bin/atcall_probe.rs`.
    if fd.kind() & S_IFMT != S_IFREG {
        return Err(Errno::EINVAL);
    }
    set_attr(&fd, ffi::Attr::Size(size))
}

// ---------------------------------------------------------------------------
// fallocate
// ---------------------------------------------------------------------------

// The modes do different things to the same range, and `mode` used to be
// UNUSED -- so every one of them behaved like plain allocation.
// FALLOC_FL_PUNCH_HOLE, which zeroes a range and keeps the file's size, instead
// extended the file and left the data alone: a database or a log rotator
// punching a hole got a bigger file with its contents intact where it had asked
// for zeroes, and no error to say so.
const FALLOC_FL_KEEP_SIZE: c_uint = 0x01;
const FALLOC_FL_PUNCH_HOLE: c_uint = 0x02;
const FALLOC_FL_ZERO_RANGE: c_uint = 0x10;
const FALLOC_FL_KNOWN: c_uint = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE;

/// Zeroes `[offset, end)` by writing, in pieces, so the length is not the
/// guest's to turn into an allocation.
///
/// Nothing here makes a file sparse — the range reads as zeroes, which is what
/// the interface promises; the blocks it might have released are a property of
/// the host filesystem this does not reach.
fn zero_range(fd: &Fd, mut offset: i64, end: i64) -> Result<(), Errno> {
    const CHUNK: usize = 64 * 1024;
    let mut zeros = Vec::new();
    if zeros.try_reserve(CHUNK).is_err() {
        return Err(Errno::ENOMEM);
    }
    zeros.resize(CHUNK, 0u8);
    // `fd->lock`, for the length of this function: `fd_pwrite`'s fallback is a
    // seek, a write and a seek back, which is only atomic against another
    // syscall on the same descriptor while it is held.
    //
    // It was a `fd_lock_for_rs` here and a `fd_unlock_for_rs` after the loop,
    // with a comment saying the release was "outside the loop, so the lock is
    // released on every path out" -- which is the obligation a guard discharges
    // instead of restating. Every early `return` this function grows from now
    // on releases it too, which that shape could not promise.
    let _guard = fs_fdobj::FdGuard::new(fd);
    loop {
        if offset >= end {
            break Ok(());
        }
        let n = ((end - offset) as usize).min(CHUNK);
        let written = rwcalls::fd_pwrite(fd, &zeros[..n], offset) as i64;
        if written < 0 {
            break Err(Errno::from_negative_or_eio(written as c_int));
        }
        // A write that moved nothing would loop for ever, and there is no
        // shorter answer to give than "this did not work".
        if written == 0 {
            break Err(Errno::EIO);
        }
        offset += written;
    }
}

pub fn sys_fallocate(num: c_int, mode: c_uint, offset: i64, len: i64) -> Result<(), Errno> {
    strace!("fallocate({num}, {mode:#x}, {offset}, {len})");
    let fd = Fd::get(num)?;
    if offset < 0 || len <= 0 {
        return Err(Errno::EINVAL);
    }
    // PUNCH_HOLE has to say it is keeping the size, because that is the only
    // thing it does with it.
    //
    // EOPNOTSUPP, not EINVAL: vfs_fallocate rejects this combination before it
    // reaches a filesystem, and that is the errno it uses. Measured against a
    // real arm64 kernel rather than read off the man page, which does not
    // distinguish the two.
    if mode & FALLOC_FL_PUNCH_HOLE != 0 && mode & FALLOC_FL_KEEP_SIZE == 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    // COLLAPSE_RANGE and INSERT_RANGE shift a file's contents, which nothing
    // here can do; a filesystem that cannot answers EOPNOTSUPP rather than doing
    // something else. This used to accept them and allocate instead.
    if mode & !FALLOC_FL_KNOWN != 0 {
        return Err(Errno::EOPNOTSUPP);
    }

    let Some(st) = fd.stat() else {
        return Err(Errno::EBADF);
    };
    let Some(end) = offset.checked_add(len) else {
        return Err(Errno::EFBIG);
    };
    let size = st.size as i64;

    if mode & FALLOC_FL_PUNCH_HOLE != 0 {
        // Bounded by the file: a hole past the end is nothing to punch, and
        // punching must not make the file longer.
        if offset >= size {
            return Ok(());
        }
        return zero_range(&fd, offset, end.min(size));
    }
    if mode & FALLOC_FL_ZERO_RANGE != 0 {
        // Zeroes, and grows if the range runs past the end -- unless the caller
        // also said to keep the size, in which case it stops there.
        let mut end = end;
        if mode & FALLOC_FL_KEEP_SIZE != 0 && end > size {
            if offset >= size {
                return Ok(());
            }
            end = size;
        }
        return zero_range(&fd, offset, end);
    }
    // Plain allocation. KEEP_SIZE asks for the blocks without the length, and
    // nothing here reserves blocks, so there is nothing to do -- which is a
    // weaker promise than Linux's and the honest one: a later write may still
    // fail for want of space. The file is not extended, which is the part a
    // caller can observe.
    if mode & FALLOC_FL_KEEP_SIZE != 0 {
        return Ok(());
    }
    if end > size {
        return set_attr(&fd, ffi::Attr::Size(end as ffi::off_t_));
    }
    Ok(())
}

#[path = "sync.rs"]
mod sync;
pub use sync::{sys_flock, sys_fsync, sys_sync_file_range, sys_syncfs};

#[cfg(test)]
mod tests {
    use super::sync::{
        SYNC_FILE_RANGE_WAIT_AFTER, SYNC_FILE_RANGE_WAIT_BEFORE, SYNC_FILE_RANGE_WRITE, SyncRange,
        sync_file_range_request,
    };
    use super::*;

    #[test]
    fn a_flag_outside_the_three_is_einval_before_anything_else() {
        assert_eq!(sync_file_range_request(0, 0, 8), Err(Errno::EINVAL));
        assert_eq!(sync_file_range_request(0, 0, 0x100), Err(Errno::EINVAL));
        // And a negative offset would be too, but the flag is judged first.
        assert_eq!(sync_file_range_request(-1, 0, 8), Err(Errno::EINVAL));
    }

    #[test]
    fn a_range_that_does_not_exist_is_einval() {
        assert_eq!(sync_file_range_request(-1, 0, 0), Err(Errno::EINVAL));
        assert_eq!(sync_file_range_request(0, -1, 0), Err(Errno::EINVAL));
        // offset + nbytes overflows: Linux computes `endbyte = offset + nbytes`
        // and refuses a negative one.
        assert_eq!(sync_file_range_request(i64::MAX, 1, 0), Err(Errno::EINVAL));
    }

    #[test]
    fn only_a_wait_does_any_work() {
        // dpkg's call: WRITE alone, on every unpacked file.
        assert_eq!(
            sync_file_range_request(0, 0, SYNC_FILE_RANGE_WRITE),
            Ok(SyncRange::StartOnly)
        );
        assert_eq!(sync_file_range_request(0, 0, 0), Ok(SyncRange::StartOnly));
        for waits in [
            SYNC_FILE_RANGE_WAIT_BEFORE,
            SYNC_FILE_RANGE_WAIT_AFTER,
            SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER,
        ] {
            assert_eq!(sync_file_range_request(4096, 0, waits), Ok(SyncRange::Wait));
        }
    }
}
