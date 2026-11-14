//! Linux's `file_remove_privs`: a write or a truncation of a regular file
//! takes away its set-id bits (`fs_perm::mode_after_write` says which, by
//! who is writing) and its `security.capability`, whoever is writing.
//!
//! Nothing did until 2026-11-13: a set-user-ID-root program any user could
//! write stayed set-user-ID with the user's bytes in it, and a file
//! capability survived its file being replaced in place. `killpriv_probe`
//! measured where Linux does it: every write of at least one byte, `truncate`
//! and `ftruncate` even to the same size, `open(O_TRUNC)`, `fallocate`, and
//! the destination of `sendfile` and `copy_file_range`; not an empty write,
//! not a store through a shared mapping.
//!
//! The check is a `fstat` and an xattr removal, so an inode that had nothing
//! to remove is marked (`S_NOSEC`, `fs_inode::mark_nosec`) and the next write
//! skips both. Whatever changes the mode, the owner or an xattr through this
//! kernel clears the mark (`fs_inode::privs_changed`). One the host makes
//! behind it -- a realfs file `chmod`ed by another host process -- is not
//! seen until the inode is next opened afresh, as on a network filesystem.

use super::*;

use guest_errno::c_int_::{EACCES, ENODATA, EOPNOTSUPP, ERANGE};

const CAPABILITY: &CStr = c"security.capability";
const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;

/// Avoid `removexattr` when `security.capability` is absent: on Darwin's
/// `realfs`, `fremovexattr` on a newly-created 0444/0000 file fails with EACCES
/// even through a writable descriptor. Fall back to `remove` on EACCES
/// (e.g. a 0200 write-only file where `realfs_xattr` could not open O_RDONLY),
/// and treat an EACCES from `remove` as absent when `get` also saw EACCES.
fn cap_remove(
    get: impl FnOnce(&mut [u8]) -> c_int,
    remove: impl FnOnce() -> c_int,
) -> c_int {
    let mut empty = [0u8; 0];
    let probe = get(&mut empty);
    if probe == ENODATA || probe == EOPNOTSUPP {
        return ENODATA;
    }
    if probe < 0 && probe != ERANGE && probe != EACCES {
        return probe;
    }
    let res = remove();
    if probe == EACCES && res == EACCES {
        return ENODATA;
    }
    res
}

/// Before a write or a truncation through `fd`. A negative guest errno if
/// removing failed, which the operation answers instead, as Linux's does.
pub fn remove_privs(fd: &ffi::fd) -> c_int {
    if !is(fd.type_ as u32 & S_IFMT, S_IFREG) {
        return 0;
    }
    let generation = match &fd.inode {
        Some(inode) => match fs_inode::privs_generation(inode) {
            Some(g) => Some(g),
            None => return 0,
        },
        None => None,
    };
    let Some(fs) = fd.mount().and_then(|m| m.fs) else {
        return 0;
    };
    let stat = match fs.fstat(fd) {
        Some(Ok(st)) => st,
        Some(Err(e)) => return e,
        None => return 0,
    };
    let cap = if fd.created {
        ENODATA
    } else {
        cap_remove(
            |out| fs.fxattr(fd, ffi::XattrCall::Get { name: CAPABILITY, out }) as c_int,
            || fs.fxattr(fd, ffi::XattrCall::Remove { name: CAPABILITY }) as c_int,
        )
    };
    let err = remove(stat, cap, |m| fs.fsetattr(fd, ffi::Attr::Mode(m as ffi::mode_t_)));
    if let (Some(inode), Some(g)) = (&fd.inode, generation) {
        if err == 0 && cap < 0 && stat.mode & (S_ISUID | S_ISGID) == 0 {
            fs_inode::mark_nosec(inode, g);
        } else {
            fs_inode::privs_changed(inode);
        }
    }
    err
}

/// The mode, the owner or an xattr of the file behind `fd` changed.
pub fn privs_changed(fd: &ffi::fd) {
    if let Some(inode) = &fd.inode {
        fs_inode::privs_changed(inode);
    }
}

/// The same for `truncate(2)`, which has a path and no descriptor.
pub(crate) fn remove_privs_at(mount: &Mount, path: &PathBuf, stat: ffi::statbuf, follow: bool) -> c_int {
    if !is(stat.mode & S_IFMT, S_IFREG) {
        return 0;
    }
    let fs = mount.fs();
    let cap = cap_remove(
        |out| fs.xattr(mount.get(), path.as_cstr(), ffi::XattrCall::Get { name: CAPABILITY, out }, follow) as c_int,
        || fs.xattr(mount.get(), path.as_cstr(), ffi::XattrCall::Remove { name: CAPABILITY }, follow) as c_int,
    );
    let err = remove(stat, cap, |m| fs.setattr(mount.get(), path.as_cstr(), ffi::Attr::Mode(m as ffi::mode_t_)));
    fs_inode::privs_changed_at(mount.get(), stat.inode);
    err
}

/// What is left to do once the capability's removal has answered `cap`:
/// reduce the mode through `set_mode`.
fn remove(stat: ffi::statbuf, cap: c_int, set_mode: impl FnOnce(u32) -> c_int) -> c_int {
    // Absent, or a filesystem with no xattrs: nothing was there to remove.
    if cap < 0 && cap != ENODATA && cap != EOPNOTSUPP {
        return cap;
    }
    match fs_perm::mode_after_write(&stat) {
        Some(m) => set_mode(m).min(0),
        None => 0,
    }
}
