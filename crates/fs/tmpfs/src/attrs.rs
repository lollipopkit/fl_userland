//! Inode metadata operations for tmpfs.

use super::*;

pub(crate) fn tmpfs_stat(mount: &ffi::mount, path: &CStr) -> Result<ffi::statbuf> {
    let path = path.to_bytes();
    let mut stat = ffi::statbuf::default();
    // `with_root` flattens to a guest errno, which is its own shape and its
    // other five callers'; this is the one place that unflattens it.
    match with_root(mount, |root| {
        let dirent = lookup(root, path)?;
        fill_stat(&dirent, &mut stat);
        Ok(())
    }) {
        0 => Ok(stat),
        e => Err(e),
    }
}

pub(crate) fn tmpfs_fstat(fd: &ffi::fd) -> Result<ffi::statbuf> {
    let Some(state) = fd_state(fd) else {
        return Err(EBADF);
    };
    let mut stat = ffi::statbuf::default();
    fill_stat(&state.dirent, &mut stat);
    Ok(stat)
}

fn apply_attr(dirent: &Dirent, attr: ffi::Attr) -> Result<()> {
    let mut body = lock(&dirent.inode.body);
    match attr {
        ffi::Attr::Uid(uid) => body.uid = uid,
        ffi::Attr::Gid(gid) => body.gid = gid,
        ffi::Attr::Mode(mode) => {
            // Only the permission bits are settable; the file type is not.
            body.mode = (body.mode & S_IFMT) | (u32::from(mode) & 0o7777);
        }
        ffi::Attr::Size(size) => {
            if body.is_dir() {
                return Err(EISDIR);
            }
            let size = u64::try_from(size).map_err(|_| EINVAL)?;
            dirent.inode.set_size(&mut body, size)?;
        }
    }
    body.ctime = Timespec::now();
    Ok(())
}

pub(crate) fn tmpfs_setattr(mount: &ffi::mount,
    path: &CStr,
    attr: ffi::Attr,
) -> c_int {
    let path = path.to_bytes();
    with_root(mount, |root| {
            let dirent = lookup(root, path)?;
            apply_attr(&dirent, attr)
        })
}

pub(crate) fn tmpfs_fsetattr(fd: &ffi::fd, attr: ffi::Attr) -> c_int {
    let Some(state) = fd_state(fd) else {
        return EBADF;
    };
    match apply_attr(&state.dirent, attr) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub(crate) fn tmpfs_utime(mount: &ffi::mount,
    path: &CStr,
    atime: ffi::timespec,
    mtime: ffi::timespec,
    // The path arrives already resolved by generic_utime, which honoured the
    // flag when it normalized; tmpfs holds no symlink it could follow a second
    // time. Present because it is part of the operation.
    _follow_links: bool,
) -> c_int {
    let path = path.to_bytes();
    with_root(mount, |root| {
            let dirent = lookup(root, path)?;
            let mut body = lock(&dirent.inode.body);
            let now = Timespec::now();
            let resolve = |ts: ffi::timespec, current: Timespec| -> Option<Timespec> {
                match ts.tv_nsec {
                    // sys_utimensat resolves both before calling a
                    // filesystem, so neither should arrive here any more.
                    // Kept because the operation takes a guest timespec and
                    // interpreting one wrongly is what went wrong elsewhere.
                    UTIME_OMIT => None,
                    UTIME_NOW => Some(now),
                    nsec => Some(Timespec {
                        sec: ts.tv_sec,
                        nsec,
                    }),
                }
                .or(Some(current))
            };
            if let Some(t) = resolve(atime, body.atime) {
                body.atime = t;
            }
            if let Some(t) = resolve(mtime, body.mtime) {
                body.mtime = t;
            }
            body.ctime = now;
            Ok(())
        })
}
