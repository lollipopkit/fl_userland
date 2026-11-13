//! Generic path lookup, access, link, unlink, and stat operations.

use super::*;

// ---------------------------------------------------------------------------
// The operations that name a file
// ---------------------------------------------------------------------------

/// `access` by path. `follow` is `faccessat`'s `AT_SYMLINK_NOFOLLOW`, which
/// was not passed down until 2026-11-11: the walk always followed, so asking
/// about a dangling symlink itself answered ENOENT where Linux answers 0.
pub fn generic_accessat(at: ffi::At<'_>, name: &CStr, mode: c_int, follow: bool) -> c_int {
    let mut path = match normalize(at, name, crate::ops::symlink_flag(follow)) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let full = path.clone_buf();
    let mount = Mount::of(&mut path);
    match mount.stat(&path) {
        Err(e) => e,
        Ok(st) => match path::access(full.as_cstr().to_bytes(), &st, mode) {
            Ok(()) => 0,
            Err(e) => e,
        },
    }
}

pub fn generic_linkat(
    src_at: ffi::At<'_>,
    src_name: &CStr,
    dst_at: ffi::At<'_>,
    dst_name: &CStr,
    follow_src: bool,
) -> c_int {
    // `AT_SYMLINK_FOLLOW` is the one `*at` flag whose *absence* is the special
    // case: a hard link is made to the symlink itself unless the caller asks
    // for the target. This took no flag at all until 2026-09-03, so
    // `linkat(..., AT_SYMLINK_FOLLOW)` linked the wrong file.
    // `N_SYMLINK_FOLLOW` and `N_SYMLINK_NOFOLLOW` are separate bits and neither
    // is the default: zero means "whatever the walk does by default", which is
    // not to follow. Asking for the target takes the *positive* flag.
    let src_flags = if follow_src {
        ffi::N_SYMLINK_FOLLOW as c_int
    } else {
        ffi::N_SYMLINK_NOFOLLOW as c_int
    };
    let mut src = match normalize(src_at, src_name, src_flags) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut dst = match normalize(
        dst_at,
        dst_name,
        (ffi::N_SYMLINK_NOFOLLOW | ffi::N_PARENT_DIR_WRITE_CREATE) as c_int,
    ) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mount = Mount::of(&mut src);
    let dst_mount = Mount::of(&mut dst);
    if mount.as_ptr() != dst_mount.as_ptr() {
        return errno::EXDEV;
    }
    let fs = mount.fs();
    // protected_hardlinks, after the mounts agree and before anything is made.
    // `src` has been trimmed to be relative to its mount, so this stats it
    // through the mount rather than by path.
    let src_stat = match mount.stat(&src) {
        Ok(st) => st,
        Err(e) => return e,
    };
    if let Err(e) = fs_perm::link_check(&src_stat) {
        return e;
    }
    fs.link(
mount.get(), src.as_cstr(), dst.as_cstr())
}

pub fn generic_unlinkat(at: ffi::At<'_>, name: &CStr) -> c_int {
    // N_PARENT_DIR_WRITE_DELETE so the walk checks write permission on the
    // parent directory. That is what makes a read-only bind mount -- whose
    // top-level directory is mode 0555 in meta.db -- refuse `rm` with EACCES
    // without any special case in fakefs.
    let mut path = match normalize(
        at,
        name,
        (ffi::N_SYMLINK_NOFOLLOW | ffi::N_PARENT_DIR_WRITE_DELETE) as c_int,
    ) {
        Ok(p) => p,
        Err(e) => return e,
    };
    // The guest path an inotify watch is keyed on, kept before the mount lookup
    // rewrites the buffer.
    let full = path.clone_buf();
    if let Err(e) = sticky_check(&full) {
        return e;
    }
    let mount = Mount::of(&mut path);
    let err = mount.fs().unlink(
mount.get(), path.as_cstr());
    if err >= 0 {
        notify(&full, inotify::IN_DELETE, 0);
        notify(&full, inotify::IN_DELETE_SELF, 0);
    }
    err
}

/// `stat` a path.
///
/// It was the last operation still in `fs/stat.c` after the format moved.
pub fn generic_statat(
    at: ffi::At<'_>,
    name: &CStr,
    stat: &mut ffi::statbuf,
    follow_links: bool,
) -> c_int {
    match generic_statat_root(at, name, follow_links) {
        Ok((st, _)) => {
            *stat = st;
            0
        }
        Err(e) => e,
    }
}

/// [`generic_statat`], and whether what it names is the root of its mount --
/// `statx`'s `STATX_ATTR_MOUNT_ROOT`. Free to answer here: the mount lookup
/// trims the path to be relative to the mount, and a mount's root trims to
/// nothing.
pub fn generic_statat_root(
    at: ffi::At<'_>,
    name: &CStr,
    follow_links: bool,
) -> Result<(ffi::statbuf, bool), c_int> {
    let flags = if follow_links {
        ffi::N_SYMLINK_FOLLOW
    } else {
        ffi::N_SYMLINK_NOFOLLOW
    };
    let resolved = crate::normalize::resolve(at, name.to_bytes(), flags as c_int)?;
    // A link onto an open file with no name: that file's own stat, as
    // `fstat` reports it. It is on no mount anything can be the root of.
    if let Some(file) = &resolved.magic {
        return fs_fdobj::fd_fstat(file).map(|st| (st, false));
    }
    let mut path = PathBuf::new();
    path.set(&resolved.path)?;
    let mount = Mount::of(&mut path);
    // Zeroed first, as the C did: a mount that fills in only some fields
    // must not leave the caller's stack in the rest.
    let mut st = mount.stat(&path)?;
    // Which mount and its device, which no filesystem knows about itself.
    // `Mount` holds a reference, so the mount is live.
    mount.get().stamp(&mut st);
    Ok((st, path.len() == 0))
}

/// Whether a descriptor's file is the root of the mount it is on: the
/// descriptor form of [`generic_statat_root`]'s answer, which has no path to
/// trim and asks the mount for its root's inode instead.
pub fn generic_fd_is_mount_root(fd: &ffi::fd, st: &ffi::statbuf) -> bool {
    let Some(mount) = fd.mount() else {
        return false;
    };
    let root = mount.fs.and_then(|fs| fs.stat(mount, c""));
    matches!(root, Some(Ok(r)) if r.inode == st.inode && st.mount_id == mount.id)
}
