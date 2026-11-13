//! POSIX record lock operations and descriptor ownership.

use super::*;

// ---------------------------------------------------------------------------
// POSIX record locks
// ---------------------------------------------------------------------------

fn kind_from_guest(ty: u16) -> Result<Option<posix::Kind>, c_int> {
    match ty as u32 {
        ffi::F_RDLCK_ => Ok(Some(posix::Kind::Read)),
        ffi::F_WRLCK_ => Ok(Some(posix::Kind::Write)),
        ffi::F_UNLCK_ => Ok(None),
        _ => Err(EINVAL),
    }
}

/// Where a `struct flock`'s `l_whence` puts the origin.
///
fn origin(fd: &ffi::fd, whence: u16) -> Result<i64, c_int> {
    match whence as u32 {
        ffi::LSEEK_SET => Ok(0),
        ffi::LSEEK_CUR => {
            let Some(ops) = fd.ops.filter(|ops| ops.caps().seek) else {
                return Ok(0);
            };
            // `fd->lock` across the seek, as every positional operation holds
            // it. A guard rather than the pair this had: `lseek` below returns
            // through two arms and neither of them may skip the release.
            let _guard = fs_fdobj::FdGuard::new(fd);
            let pos = ops.lseek(fd, 0, ffi::LSEEK_CUR as c_int);
            if pos < 0 { Err(pos as c_int) } else { Ok(pos) }
        }
        ffi::LSEEK_END => {
            let mount = fd.mount().ok_or(EINVAL)?;
            let stat = mount.fs.and_then(|fs| fs.fstat(fd)).ok_or(EINVAL)??;
            Ok(stat.size as i64)
        }
        _ => Err(EINVAL),
    }
}

/// A guest `struct flock` as a byte range.
///
/// Every arithmetic step here is checked. The C added `start + len - 1` in
/// `off_t_` and let it wrap: a guest asking to lock a length that runs past
/// the end of the address space got a range whose end was below its start, and
/// every comparison downstream then meant the opposite of what it said.
///
fn range(fd: &ffi::fd, flock: &ffi::flock_) -> Result<(i64, i64), c_int> {
    {
        let base = origin(fd, flock.whence)?;
        let start = base.checked_add(flock.start).ok_or(EOVERFLOW)?;
        let len = flock.len;

        let (start, end) = match len.cmp(&0) {
            // Zero length means "from start to the end of the file", however
            // long the file becomes.
            std::cmp::Ordering::Equal => (start, i64::MAX),
            std::cmp::Ordering::Greater => {
                let end = start.checked_add(len - 1).ok_or(EOVERFLOW)?;
                (start, end)
            }
            // A negative length means the range *before* start.
            std::cmp::Ordering::Less => {
                let end = start.checked_sub(1).ok_or(EOVERFLOW)?;
                let begin = end
                    .checked_add(len)
                    .and_then(|v| v.checked_add(1))
                    .ok_or(EOVERFLOW)?;
                (begin, end)
            }
        };

        // Linux refuses a range that starts before the beginning of the file.
        if start < 0 {
            return Err(EINVAL);
        }
        Ok((start, end))
    }
}

/// The inode a lock request applies to, or the errno for a descriptor that
/// cannot carry one.
///
/// Only `generic_openat` sets `fd->inode`; pipes, sockets, eventfds, timerfds
/// and epoll descriptors never have one. The C dereferenced it unconditionally,
/// so `fcntl(pipe_write_end, F_SETLK, {F_WRLCK})` — three lines from any guest
/// program — took the emulator down with a null dereference inside `__lock`.
/// Linux answers EBADF for a descriptor that cannot hold a record lock.
///
pub(crate) fn inode_of(fd: &ffi::fd) -> Result<&ffi::inode_data, c_int> {
    fd.inode().ok_or(EBADF)
}

/// Who a lock belongs to.
///
/// A POSIX record lock is owned by the descriptor table, so threads sharing
/// one do not lock each other out and a forked child does. An open file
/// description lock — `F_OFD_SETLK` and friends — is owned by the description
/// instead: two `open`s of one file get two owners, `dup` and `fork` share
/// one, and it is released when the description goes rather than when the
/// process does. SQLite asks for these by preference on Linux.
///
fn owner_of(fd: &ffi::fd, ofd: bool) -> Owner {
    if ofd {
        Owner::of_description(fd)
    } else {
        Owner::Table(taskview::current_lock_owner() as usize)
    }
}

/// What `F_GETLK` reports as the holder's pid. An open-file-description lock
/// belongs to a description and not a process, and Linux reports **-1** for
/// one -- from either `F_GETLK` or `F_OFD_GETLK`. This reported the pid of
/// whoever took it until 2026-09-04, which is a process that may have closed
/// the description or exited while the lock lives on.
fn record_pid(ofd: bool) -> i32 {
    if ofd { -1 } else { taskview::current_pid() }
}

/// Called by `sys_fcntl` with a live descriptor and a valid `struct flock_`.
/// Not `#[unsafe(no_mangle)]` since 2026-09-06. No C source calls it, no
/// `ffi::` reaches it, and no header the embedder example compiles against
/// declares it -- so the export was a second interface with nobody on the
/// other side, and an optimisation barrier: LTO must emit an externally
/// visible function as written and cannot specialise the call.
pub fn fcntl_getlk(fd: &ffi::fd, flock: &mut ffi::flock_) -> c_int {
    fcntl_getlk_owned(fd, flock, false)
}

pub fn fcntl_getlk_owned(fd: &ffi::fd, flock: &mut ffi::flock_, ofd: bool) -> c_int {
    let Ok(Some(kind)) = kind_from_guest(flock.type_) else {
        // F_UNLCK is not a question worth asking.
        return EINVAL;
    };
    let inode = match inode_of(fd) {
        Ok(i) => i,
        Err(e) => return e,
    };

    let mut guard = InodeGuard::new(inode);
    let (start, end) = match range(fd, flock) {
        Ok(r) => r,
        Err(e) => return e,
    };
    // An open-file-description request names no process: Linux's
    // `fcntl_getlk` refuses a non-zero `l_pid` for `F_OFD_GETLK`, after the
    // range has been checked.
    if ofd && flock.pid != 0 {
        return EINVAL;
    }
    let request = posix::Record {
        start,
        end,
        kind,
        owner: owner_of(fd, ofd),
        pid: record_pid(ofd),
        file: std::ptr::from_ref(fd) as usize,
    };

    match guard.locks().posix.conflict(&request) {
        Some(held) => {
            flock.type_ = match held.kind {
                posix::Kind::Read => ffi::F_RDLCK_ as u16,
                posix::Kind::Write => ffi::F_WRLCK_ as u16,
            };
            flock.whence = ffi::LSEEK_SET as u16;
            flock.start = held.start;
            flock.len = if held.end == i64::MAX {
                0
            } else {
                held.end - held.start + 1
            };
            flock.pid = held.pid;
        }
        None => flock.type_ = ffi::F_UNLCK_ as u16,
    }
    0
}

/// `F_SETLK`/`F_SETLKW` for a process-owned lock. Called by `sys_fcntl`.
pub fn fcntl_setlk(fd: &ffi::fd, flock: &mut ffi::flock_, blocking: bool) -> c_int {
    fcntl_setlk_owned(fd, flock, blocking, false)
}

/// [`fcntl_setlk`], with `ofd` choosing an open-file-description lock
/// (`F_OFD_SETLK`) over a process-owned one.
pub fn fcntl_setlk_owned(
    fd: &ffi::fd,
    flock: &mut ffi::flock_,
    blocking: bool,
    ofd: bool,
) -> c_int {
    let kind = match kind_from_guest(flock.type_) {
        Ok(k) => k,
        Err(e) => return e,
    };

    // A read lock needs a readable descriptor and a write lock a writable
    // one. Unlocking needs neither.
    //
    // The `if mode >= 0` that was here guarded against a negative from
    // `fd_getflags`, which was `fd.flags() as c_int` -- reachable only with
    // bit 31 of the flags word set, and no `O_*` comes near it. The field is a
    // `u32` and is read as one.
    let accmode = fd.flags() & ffi::O_ACCMODE_;
    match kind {
        Some(posix::Kind::Read) if accmode == ffi::O_WRONLY_ => return EBADF,
        Some(posix::Kind::Write) if accmode == ffi::O_RDONLY_ => return EBADF,
        _ => {}
    }

    let inode = match inode_of(fd) {
        Ok(i) => i,
        Err(e) => return e,
    };

    let mut guard = InodeGuard::new(inode);
    let (start, end) = match range(fd, flock) {
        Ok(r) => r,
        Err(e) => return e,
    };
    // As in `fcntl_getlk_owned`: Linux's `fcntl_setlk` refuses a non-zero
    // `l_pid` for the OFD commands once the range has been checked.
    if ofd && flock.pid != 0 {
        return EINVAL;
    }
    let request = posix::Record {
        start,
        end,
        kind: kind.unwrap_or(posix::Kind::Read),
        owner: owner_of(fd, ofd),
        pid: record_pid(ofd),
        file: std::ptr::from_ref(fd) as usize,
    };

    loop {
        let locks = guard.locks();
        match locks.posix.apply(&request, kind) {
            posix::Applied::Granted { released } => {
                if released {
                    guard.notify();
                }
                return 0;
            }
            posix::Applied::Blocked => {
                if !blocking {
                    return EAGAIN;
                }
                // Whose lock this would wait for, and whether that owner is --
                // through any chain -- waiting for this one. See `deadlock`.
                // The record of the wait lives exactly as long as the wait.
                let blocker = locks.posix.conflict(&request).map(|held| held.owner);
                let _waiting = match blocker {
                    Some(blocker) if !ofd => {
                        if deadlock::closes_cycle(blocker, request.owner) {
                            return EDEADLK;
                        }
                        Some(deadlock::Waiting::new(request.owner, blocker))
                    }
                    _ => None,
                };
                if let Err(e) = guard.wait() {
                    return e;
                }
            }
        }
    }
}

/// Drop every record lock held by `owner` on this descriptor's inode, when a
/// table releases the descriptor.
pub fn file_lock_remove_owned_by(fd: &ffi::fd, owner: *mut ffi::fdtable) {
    let Ok(inode) = inode_of(fd) else { return };
    let mut guard = InodeGuard::new(inode);
    if guard.has_locks() && guard.locks().posix.remove_owner(Owner::Table(owner as usize)) {
        guard.notify();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **An `F_OFD_*` lock belongs to the description; a POSIX one belongs to
    /// the table.** That is the whole of what `ofd` selects, and until
    /// 2026-09-16 both answers were a bare `usize`, so there was nothing to
    /// assert: making the OFD branch answer the table's kind changed no type
    /// and broke no test. It was backed out to check that, and did not.
    ///
    /// The address is the same either way here — it is the description's — so
    /// what this pins is the *kind*, which is the half that was invisible.
    #[test]
    fn an_ofd_lock_belongs_to_the_description_and_a_posix_one_to_the_table() {
        let fd = ffi::fd::default();
        assert_eq!(owner_of(&fd, true), Owner::of_description(&fd));
        assert!(
            matches!(owner_of(&fd, false), Owner::Table(_)),
            "a POSIX record lock is owned by the descriptor table"
        );
    }
}
