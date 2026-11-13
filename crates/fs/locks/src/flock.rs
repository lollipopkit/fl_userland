//! BSD whole-file lock operations.

use super::*;

// ---------------------------------------------------------------------------
// BSD locks
// ---------------------------------------------------------------------------

/// What a `flock(2)` operation word asks for.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Flock {
    Shared,
    Exclusive,
    Unlock,
}

/// The operation word, as an operation and whether to block.
///
/// Exactly one of the three, optionally with `LOCK_NB`, and nothing else. The C
/// tested each bit separately, so `LOCK_SH|LOCK_EX` asked the host for both.
///
/// It is a function of its own because `sys_flock` applies it **before** it
/// looks the descriptor up: Linux answers `EINVAL` for `flock(-1, 0)`, where
/// this answered `EBADF` and named the wrong argument. The decode is here, and
/// not duplicated there, so the two cannot come to disagree about which
/// operations exist.
pub fn decode_flock(operation: c_int) -> Result<(Flock, bool), c_int> {
    let op = operation as u32;
    let blocking = op & ffi::LOCK_NB_ == 0;
    let mode = match op & !ffi::LOCK_NB_ {
        x if x == ffi::LOCK_SH_ => Flock::Shared,
        x if x == ffi::LOCK_EX_ => Flock::Exclusive,
        x if x == ffi::LOCK_UN_ => Flock::Unlock,
        _ => return Err(EINVAL),
    };
    Ok((mode, blocking))
}

/// `flock(2)` for the filesystems with no host file to delegate to.
///
/// Called by `sys_flock`.
pub fn flock_generic(fd: &ffi::fd, operation: c_int) -> c_int {
    let (mode, blocking) = match decode_flock(operation) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let mode = match mode {
        Flock::Shared => Some(bsd::Mode::Shared),
        Flock::Exclusive => Some(bsd::Mode::Exclusive),
        Flock::Unlock => None,
    };

    // Unlike a record lock, a BSD lock is held by the open file description,
    // and every descriptor has one of those — there is no inode requirement in
    // flock(2). But the set has to live somewhere, and the inode is where it
    // belongs, so a descriptor without one has nowhere to put it.
    let inode = match inode_of(fd) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let owner = Owner::of_description(fd);

    let mut guard = InodeGuard::new(inode);
    loop {
        let locks = guard.locks();
        let Some(mode) = mode else {
            if locks.bsd.release(owner) {
                guard.notify();
            }
            return 0;
        };
        match locks.bsd.acquire(owner, mode, taskview::current_pid()) {
            bsd::Applied::Granted { released } => {
                if released {
                    guard.notify();
                }
                return 0;
            }
            bsd::Applied::Blocked => {
                // acquire() dropped the old lock before finding out, which is
                // what flock(2) specifies, so a waiter may be able to proceed
                // even though this call did not.
                guard.notify();
                if !blocking {
                    return EAGAIN;
                }
                if let Err(e) = guard.wait() {
                    return e;
                }
            }
        }
    }
}

/// A `flock(2)` the host granted, on a host file: kept beside the inode's
/// own set so `/proc/<pid>/fdinfo` can list it. Called by `sys_flock` once
/// the filesystem's own `flock` succeeded.
pub fn flock_granted_by_host(fd: &ffi::fd, operation: c_int) {
    let Ok((mode, _)) = decode_flock(operation) else { return };
    let Ok(inode) = inode_of(fd) else { return };
    let mode = match mode {
        Flock::Shared => Some(bsd::Mode::Shared),
        Flock::Exclusive => Some(bsd::Mode::Exclusive),
        Flock::Unlock => None,
    };
    let mut guard = InodeGuard::new(inode);
    if mode.is_none() && !guard.has_locks() {
        return;
    }
    guard.locks().bsd.record(Owner::of_description(fd), mode, taskview::current_pid());
}

/// The locks `/proc/<pid>/fdinfo/<n>` lists for `fd`, in Linux's
/// `show_fd_locks` order: the BSD lock first, then the record locks.
///
/// A BSD or open-file-description lock is listed on the description that
/// owns it; a POSIX lock on the description it was taken through, and only
/// for the process whose table owns it (`table`), so a forked child sharing
/// the description lists none.
pub fn held_by(fd: &ffi::fd, table: *const ffi::fdtable) -> Vec<fs_fdobj::HeldLock> {
    use fs_fdobj::{HeldLock, LockClass};
    let Ok(inode) = inode_of(fd) else { return Vec::new() };
    let mut guard = InodeGuard::new(inode);
    if !guard.has_locks() {
        return Vec::new();
    }
    let me = Owner::of_description(fd);
    let file = std::ptr::from_ref(fd) as usize;
    let locks = guard.locks();
    let flocks = locks.bsd.held().iter().filter(|h| h.owner == me).map(|h| HeldLock {
        class: LockClass::Flock,
        write: h.mode == bsd::Mode::Exclusive,
        pid: h.pid,
        start: 0,
        end: None,
    });
    let records = locks.posix.records().iter().filter_map(|r| {
        let class = match r.owner {
            Owner::Description(_) if r.owner == me => LockClass::Ofd,
            Owner::Table(t) if t == table as usize && r.file == file => LockClass::Posix,
            _ => return None,
        };
        Some(HeldLock {
            class,
            write: r.kind == posix::Kind::Write,
            pid: r.pid,
            start: r.start,
            end: (r.end != i64::MAX).then_some(r.end),
        })
    });
    flocks.chain(records).collect()
}

/// Drop the BSD lock held by a descriptor that is going away.
///
/// Called by `fd_close` on the last reference.
pub fn flock_release(fd: &ffi::fd) {
    let Ok(inode) = inode_of(fd) else { return };
    let mut guard = InodeGuard::new(inode);
    // Nothing was ever locked on this inode, so there is nothing to release.
    // It was tested before taking the lock until 2026-10-01, a racy read of a
    // field another thread writes under it; an uncontended lock is cheap.
    if !guard.has_locks() {
        return;
    }
    // Both kinds this description owns: its BSD lock, and any record locks it
    // took with F_OFD_SETLK — which belong to the description and so go with
    // it, unlike POSIX ones, which the descriptor table outlives.
    let owner = Owner::of_description(fd);
    let locks = guard.locks();
    let released = locks.bsd.release(owner);
    let records = locks.posix.remove_owner(owner);
    if released || records {
        guard.notify();
    }
}
