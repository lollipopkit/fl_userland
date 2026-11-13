//! Tmpfs name and directory operations.

use super::*;

// ============================================================
// fs_ops: names
// ============================================================

pub(crate) fn tmpfs_open(mount: &ffi::mount,
    path: &CStr,
    flags: c_int,
    mode: c_int,
) -> std::result::Result<Box<ffi::fd>, guest_errno::Errno> {
    let Some(root) = mount_root(mount) else {
        return Err(guest_errno::Errno::EINVAL);
    };
    let path = path.to_bytes();

    let dirent = if flags & ffi::O_CREAT_ as c_int != 0 {
        create(root, path, mode as u32, flags & ffi::O_EXCL_ as c_int != 0)
    } else {
        lookup(root, path)
    }
    .map_err(guest_errno::Errno::from_negative_or_eio)?;

    // O_TRUNC. Without this `>` left the tail of whatever was there before,
    // which is what the C did: it had no setattr either, so the VFS could not
    // truncate on its behalf.
    if flags & ffi::O_TRUNC_ as c_int != 0 {
        let mut body = lock(&dirent.inode.body);
        if body.is_dir() {
            return Err(guest_errno::Errno::EISDIR);
        }
        dirent.inode.set_size(&mut body, 0).map_err(guest_errno::Errno::from_negative_or_eio)?;
        body.touch_mtime();
    }

    let fd = Box::new(ffi::fd::with_ops(Some(&TMPFS_FDOPS)));
    fd.set_fs_data(FdState {
        dirent,
        // A scan starts at ".", not at the first child.
        dir_pos: Mutex::new(DirPos::Dot),
    });
    Ok(fd)
}

/// `O_TMPFILE`: an inode in no directory, which `tmpfs_link_unnamed` may
/// name later. The directory has been checked by the generic layer; it is
/// looked up here only to be sure it is this mount's.
pub(crate) fn tmpfs_tmpfile(mount: &ffi::mount,
    dir: &CStr,
    _flags: c_int,
    mode: c_int,
) -> std::result::Result<Box<ffi::fd>, guest_errno::Errno> {
    let Some(root) = mount_root(mount) else {
        return Err(guest_errno::Errno::EINVAL);
    };
    let parent = lookup(root, dir.to_bytes()).map_err(guest_errno::Errno::from_negative_or_eio)?;
    if !parent.is_dir() {
        return Err(guest_errno::Errno::ENOTDIR);
    }
    let (uid, gid) = current_ids();
    let dirent = Dirent::detached(Inode::new(S_IFREG | (mode as u32 & 0o7777), uid, gid, 0));
    let mut fd = Box::new(ffi::fd::with_ops(Some(&TMPFS_FDOPS)));
    fd.set_fs_data(FdState {
        dirent,
        dir_pos: Mutex::new(DirPos::Dot),
    });
    fd.unnamed = Some(Box::default());
    Ok(fd)
}

/// `linkat` naming an `O_TMPFILE` file: its inode, linked at `dst`.
pub(crate) fn tmpfs_link_unnamed(fd: &ffi::fd, mount: &ffi::mount, dst: &CStr) -> c_int {
    let (Some(root), Some(state)) = (mount_root(mount), fd_state(fd)) else {
        return guest_errno::c_int_::EINVAL;
    };
    let (parent, name) = match lookup_parent(root, dst.to_bytes()) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match link_into(&parent, name, Arc::clone(&state.dirent.inode)) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

/// `open(O_CREAT)`: return the existing entry, or make a regular file.
fn create(root: &Arc<Dirent>, path: &[u8], mode: u32, excl: bool) -> Result<Arc<Dirent>> {
    let (parent, name) = lookup_parent(root, path)?;
    if let Some(existing) = parent.children().lookup(name) {
        return if excl { Err(EEXIST) } else { Ok(existing) };
    }
    let (uid, gid) = current_ids();
    link_into(
        &parent,
        name,
        Inode::new(S_IFREG | (mode & 0o7777), uid, gid, 0),
    )
}

pub(crate) fn tmpfs_mkdir(mount: &ffi::mount,
    path: &CStr,
    mode: ffi::mode_t_,
) -> c_int {
    let path = path.to_bytes();
    with_root(mount, |root| {
            let (parent, name) = lookup_parent(root, path)?;
            let (uid, gid) = current_ids();
            link_into(
                &parent,
                name,
                Inode::new(S_IFDIR | (mode as u32 & 0o7777), uid, gid, 0),
            )?;
            Ok(())
        })
}

pub(crate) fn tmpfs_unlink(mount: &ffi::mount, path: &CStr) -> c_int {
    let path = path.to_bytes();
    with_root(mount, |root| {
            let (parent, name) = lookup_parent(root, path)?;
            unlink_from(&parent, name, false)
        })
}

pub(crate) fn tmpfs_rmdir(mount: &ffi::mount, path: &CStr) -> c_int {
    let path = path.to_bytes();
    with_root(mount, |root| {
            let (parent, name) = lookup_parent(root, path)?;
            unlink_from(&parent, name, true)
        })
}

pub(crate) fn tmpfs_rename(mount: &ffi::mount,
    src: &CStr,
    dst: &CStr,
    flags: u32,
) -> c_int {
    let (src, dst) = (src.to_bytes(), dst.to_bytes());
    with_root(mount, |root| {
            let (old_parent, old_name) = lookup_parent(root, src)?;
            let (new_parent, new_name) = lookup_parent(root, dst)?;
            tree_rename(&old_parent, old_name, &new_parent, new_name, flags)
        })
}

pub(crate) fn tmpfs_link(mount: &ffi::mount,
    src: &CStr,
    dst: &CStr,
) -> c_int {
    let (src, dst) = (src.to_bytes(), dst.to_bytes());
    with_root(mount, |root| {
            let source = lookup(root, src)?;
            if source.is_dir() {
                return Err(EPERM); // no hardlinks to directories
            }
            let (parent, name) = lookup_parent(root, dst)?;
            link_into(&parent, name, Arc::clone(&source.inode))?;
            Ok(())
        })
}

pub(crate) fn tmpfs_symlink(mount: &ffi::mount,
    target: &CStr,
    link: &CStr,
) -> c_int {
    let (target, link) = (target.to_bytes(), link.to_bytes());
    with_root(mount, |root| {
            let (parent, name) = lookup_parent(root, link)?;
            let (uid, gid) = current_ids();
            // A symlink's target is its contents, and its size is that
            // target's length — which is what readlink and stat report.
            let inode = Inode::new(S_IFLNK | 0o777, uid, gid, 0);
            lock(&inode.body).data = target.to_vec().into();
            link_into(&parent, name, inode)?;
            Ok(())
        })
}

pub(crate) fn tmpfs_readlink(mount: &ffi::mount,
    path: &CStr,
    buf: &mut [u8],
) -> ssize_t {
    let Some(root) = mount_root(mount) else {
        return EINVAL as ssize_t;
    };
    let dirent = match lookup(root, path.to_bytes()) {
        Ok(d) => d,
        Err(e) => return e as ssize_t,
    };
    let body = lock(&dirent.inode.body);
    if !body.is_lnk() {
        return EINVAL as ssize_t;
    }
    // readlink truncates rather than failing, and does not NUL-terminate.
    let target = body.data.in_memory().unwrap_or_default();
    let n = target.len().min(buf.len());
    buf[..n].copy_from_slice(&target[..n]);
    n as ssize_t
}

pub(crate) fn tmpfs_mknod(mount: &ffi::mount,
    path: &CStr,
    mode: ffi::mode_t_,
    dev: ffi::dev_t_,
) -> c_int {
    let path = path.to_bytes();
    let mode = mode as u32;
    with_root(mount, |root| {
            // A mode with no type bits means a regular file, as mknod(2) says.
            let file_type = match mode & S_IFMT {
                0 => S_IFREG,
                t @ (S_IFREG | S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK) => t,
                _ => return Err(EINVAL),
            };
            let (parent, name) = lookup_parent(root, path)?;
            let (uid, gid) = current_ids();
            link_into(
                &parent,
                name,
                Inode::new(file_type | (mode & 0o7777), uid, gid, dev as u64),
            )?;
            Ok(())
        })
}
