//! File and directory creation operations for fakefs.

use std::ffi::{CStr, c_int};

use crate::{
    EIO, EROFS, ffi, fix_path, root, rx_err, is_under_readonly_bind_mount, mount_db, translate,
};

// ------------------------------------------------------------ creation

use guest_errno::c_int_::{EEXIST, EPERM};

/// A new row's owner: the **fs** ids, which is what Linux stamps a creation
/// with — every creation path there is `inode->i_uid = current_fsuid()`.
///
/// The four creation paths here used the *effective* ids, so a fakefs file made
/// after a `setfsuid` was owned by the wrong one; tmpfs has always asked
/// `task_current_fsids`, which is this pair.
pub(crate) fn new_row(mode: u32, rdev: u32) -> fakedb::IulStat {
    let (uid, gid) = taskview::current_fsids();
    fakedb::IulStat {
        mode,
        uid,
        gid,
        rdev,
    }
}

/// A host path as bytes, as `std::fs` takes it.
fn host_path(bytes: &[u8]) -> &std::path::Path {
    <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(bytes).as_ref()
}

/// Tells the embedder's change ring that this guest path was written.
pub(crate) fn record_write(path: &CStr) {
    fakechange::record_change(path, ffi::FAKEFS_CHANGE_OP_WRITE as c_int);
}

/// # Safety
///
/// `mount` is live with a `fakefs` database and `path` is NUL-terminated.
pub fn fakefs_rs_mkdir(mount: &ffi::mount,
    path: &CStr,
    mode: u16,
) -> c_int {
    let path_c = path;
    if is_under_readonly_bind_mount(path_c) {
        return EROFS;
    }
    let bind = translate(path_c);
    // A hook-routed path has no meta.db row, so the host directory is all
    // there is to make.
    if let Some((host, true)) = &bind {
        if let Err(e) = std::fs::create_dir(host_path(host)) {
            return kernel_errno::raised(e.raw_os_error().unwrap_or(libc::EIO));
        }
        record_write(path_c);
        return 0;
    }

    // The transaction is opened before the host directory is made, so that a
    // commit that goes back can take the directory with it.
    let db = mount_db(mount);
    let mut tx = db.write();
    let via_bind = bind.is_some();
    let err = match &bind {
        Some((host, _)) => match std::fs::create_dir(host_path(host)) {
            Ok(()) => 0,
            Err(e) => kernel_errno::raised(e.raw_os_error().unwrap_or(libc::EIO)),
        },
        None => realfs::realfs_mkdir(mount, path, 0o777),
    };
    if err < 0 {
        tx.rollback();
        return err;
    }
    tx.path_create(
        path_c.to_bytes(),
        &new_row(mode as u32 | libc::S_IFDIR as u32, 0),
    );
    if !tx.commit() {
        // The host directory is there and nothing describes it, so the guest
        // would see neither the directory nor a way to remove it.
        realfs::realfs_rmdir(mount, path);
        return EIO;
    }
    if via_bind {
        record_write(path_c);
    }
    0
}

/// # Safety
///
/// `mount` is live with a `fakefs` database; `target` and `link` are
/// NUL-terminated.
pub fn fakefs_rs_symlink(mount: &ffi::mount,
    target: &CStr,
    link: &CStr,
) -> c_int {
    let (target_c, link_c) = (target, link);
    if is_under_readonly_bind_mount(link_c) {
        return EROFS;
    }
    // fakefs's symlink is a regular file holding the target plus an S_IFLNK
    // mode bit in meta.db. A hook-routed path has no row, so that
    // representation cannot round-trip -- and creating the file anyway would
    // leave something no later stat or readlink could recognise as a link.
    if matches!(translate(link_c), Some((_, true))) {
        return EPERM;
    }

    let db = mount_db(mount);
    let mut tx = db.write();
    let rel = fix_path(link_c);
    let root = match root(mount) {
        Ok(root) => root,
        Err(e) => {
            tx.rollback();
            return e;
        }
    };
    use rustix::fs::{AtFlags, Mode, OFlags, openat, unlinkat};
    let fd = match openat(
        root,
        rel,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        Mode::from_raw_mode(0o666),
    ) {
        Ok(fd) => fd,
        Err(e) => {
            tx.rollback();
            return rx_err(e);
        }
    };

    // Written in a loop, because a short write is not an error and this is a
    // *path*. write(2) may return fewer bytes than asked -- a signal after it
    // has copied some, or the volume filling mid-call -- and a target that is
    // one byte short is not a shorter answer, it is a different one:
    // "/usr/lib/libfoo.so" truncated to "/usr/lib/libfoo.s" names nothing, and
    // "/a/b/c" truncated to "/a/b" names the directory above.
    //
    // `write_all` is that loop: it retries a short write and an `EINTR`, and a
    // zero return -- a device that will not take the rest -- is `WriteZero`,
    // which is `ENOSPC` here.
    let written = std::io::Write::write_all(&mut std::fs::File::from(fd), target_c.to_bytes());
    if let Err(e) = written {
        let saved = match e.kind() {
            std::io::ErrorKind::WriteZero => libc::ENOSPC,
            _ => e.raw_os_error().unwrap_or(libc::EIO),
        };
        // The file is closed (it dropped with the statement above) and goes;
        // the errno was taken by value, so the unlink cannot replace it.
        let _ = unlinkat(root, rel, AtFlags::empty());
        tx.rollback();
        return kernel_errno::err_map(saved);
    }

    // The mode is what makes it a link. Symlinks always have full permissions.
    tx.path_create(link_c.to_bytes(), &new_row(libc::S_IFLNK as u32 | 0o777, 0));
    if !tx.commit() {
        // The host file is already made. Without its row, stat answers ENOENT
        // for a path that exists on the host -- a file the guest cannot see and
        // cannot remove.
        realfs::realfs_unlink(mount, link);
        return EIO;
    }
    0
}

/// # Safety
///
/// `mount` is live with a `fakefs` database and `path` is NUL-terminated.
pub fn fakefs_rs_mknod(mount: &ffi::mount,
    path: &CStr,
    mode: u16,
    dev: u32,
) -> c_int {
    let path_c = path;
    if is_under_readonly_bind_mount(path_c) {
        return EROFS;
    }
    // What the *host* gets. A block, character or socket node has no host
    // representation, so a placeholder regular file stands in for it and the
    // meta.db row is what the guest sees.
    let fmt = mode as u32 & libc::S_IFMT as u32;
    let is_dev = fmt == libc::S_IFBLK as u32 || fmt == libc::S_IFCHR as u32;
    let host_mode = 0o666
        | if is_dev || fmt == libc::S_IFSOCK as u32 {
            libc::S_IFREG as u32
        } else {
            fmt
        };

    // The transaction is opened first so the check and the create are one
    // step: a name that exists is EEXIST, and mknod(2) has no flag that makes
    // it anything else.
    //
    // This returned 0 for a name already in use. The host EEXIST was tolerated
    // deliberately -- a device node is only its meta.db row, and the host
    // placeholder may be left over from a fakefs that was copied -- but the row
    // was then only created when the lookup found nothing, so the *guest
    // visible* case fell through the same hole and answered success.
    // mkfifo(3) over an existing name reported that it had made one.
    let db = mount_db(mount);
    let mut tx = db.write();
    if tx.path_stat(path_c.to_bytes()).is_some() {
        tx.rollback();
        return EEXIST;
    }
    let err = realfs::realfs_mknod(mount, path, host_mode as u16, 0);
    if err < 0 && err != EEXIST {
        tx.rollback();
        return err;
    }
    tx.path_create(
        path_c.to_bytes(),
        &new_row(mode as u32, if is_dev { dev } else { 0 }),
    );
    // A device node is *only* its meta.db row -- the host has no way to hold
    // one, which is why the row exists. A commit that went back leaves nothing,
    // so there is nothing to undo and everything to report.
    if !tx.commit() { EIO } else { 0 }
}
