//! Metadata mutation for fakefs files and descriptors.

use std::ffi::{CStr, c_int};
use std::os::unix::ffi::OsStrExt;

use crate::{
    EIO, ENOENT, EROFS, ensure_inode, ffi, is_under_bind_mount,
    fd_db, is_under_readonly_bind_mount, mount_db, translate,
};

// ----------------------------------------------------------------- setattr

/// The one field this attribute changes, applied to a `meta.db` row.
///
/// `attr_size` is not one of them: realfs owns the size and `meta.db` stores
/// none. Both callers route it away before reaching here, so arriving is an
/// internal invariant — and it used to be a `die()`, which turned a missed
/// route into an aborted application rather than a size set on the host and
/// recorded nowhere.
fn apply(iul: &mut fakedb::IulStat, attr: ffi::Attr) -> bool {
    match attr {
        ffi::Attr::Uid(uid) => iul.uid = uid,
        ffi::Attr::Gid(gid) => iul.gid = gid,
        ffi::Attr::Mode(mode) => {
            let fmt = libc::S_IFMT as u32;
            iul.mode = (iul.mode & fmt) | (u32::from(mode) & !fmt);
        }
        ffi::Attr::Size(_) => return false,
    }
    true
}

/// What a hook-routed path does instead, and what an `fsetattr` with no row
/// does: apply the change to the host and accept that ownership will not take.
///
/// A `chown` here is a silent success rather than an error. The emulator runs
/// as an ordinary user, so the host refuses it with `EPERM` — and `realfs`
/// swallows that for the same reason, so refusing here would make fakefs the
/// only mount where `chown` fails.
fn host_setattr(attr: ffi::Attr, apply_mode: impl FnOnce(u32) -> c_int) -> c_int {
    match attr {
        ffi::Attr::Mode(mode) => apply_mode(mode.into()),
        _ => 0,
    }
}

/// # Safety
///
/// `mount` is live with a `fakefs` database and `path` is NUL-terminated.
pub fn fakefs_rs_setattr(mount: &ffi::mount,
    path: &CStr,
    attr: ffi::Attr,
) -> c_int {
    let path_c = path;
    if is_under_readonly_bind_mount(path_c) {
        return EROFS;
    }

    // A hook-routed path has no meta.db row, so the change goes to the host.
    if let Some((host, true)) = translate(path_c) {
        let host = std::path::Path::new(std::ffi::OsStr::from_bytes(&host));
        if let ffi::Attr::Size(size) = attr {
            // `truncate(2)` by path rather than an open and `set_len`: opening
            // a FIFO for writing waits for a reader, and truncating one is an
            // answer, not a wait.
            let Ok(c) = std::ffi::CString::new(host.as_os_str().as_bytes()) else {
                return ENOENT;
            };
            return realfs::host_truncate_path(&c, size);
        }
        return host_setattr(attr, |mode| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(host, std::fs::Permissions::from_mode(mode))
                .map_or_else(crate::io_err, |()| 0)
        });
    }

    // realfs owns the size.
    if let ffi::Attr::Size(_) = attr {
        return realfs::realfs_setattr(mount, path, attr);
    }

    let db = mount_db(mount);
    if let Some(err) = write_row(db, path_c, attr) {
        return err;
    }
    // No row. A path under a bind mount gets one made and the change applied
    // to it; anything else does not exist.
    if !is_under_bind_mount(path_c) {
        return ENOENT;
    }
    if ensure_inode(mount, path_c) == 0 {
        return ENOENT;
    }
    write_row(db, path_c, attr).unwrap_or(ENOENT)
}

/// One write transaction around the read-modify-write. `None` when there is no
/// row for the path.
///
/// **One transaction, with the read inside it.** This read the row in one
/// transaction, committed, and opened a second to write it back — so two
/// threads changing the same inode both read the old struct and the second
/// overwrote the first's field. It was split because writing inside a *read*
/// transaction leaves the update to an implicit upgrade that can sit BUSY
/// against another writer; `write()` is `begin immediate`, which takes the
/// write lock up front, so there is no upgrade to wait for.
fn write_row(db: &fakedb::Db, path: &CStr, attr: ffi::Attr) -> Option<c_int> {
    let mut tx = db.write();
    let (mut iul, inode) = match tx.path_stat(path.to_bytes()) {
        Some(pair) => pair,
        None => {
            tx.rollback();
            return None;
        }
    };
    apply(&mut iul, attr);
    tx.inode_write_stat(inode, &iul);
    // EIO rather than 0: the update went back, so the mode the caller asked
    // for is not the mode the file has, and a chmod that reports success and
    // changed nothing is worse than one that fails.
    Some(if tx.commit() { 0 } else { EIO })
}

/// Panics on a descriptor whose mount is not a fakefs, which only a table
/// wired to the wrong filesystem can hand it.
pub fn fakefs_rs_fsetattr(fd: &ffi::fd, attr: ffi::Attr) -> c_int {
    // The read-only check belongs here too, not only in setattr: this path took
    // the descriptor's word for it and handed attr_size straight to realfs, so
    // an ftruncate through a descriptor opened before the mount was marked
    // read-only went through.
    if fd.change_path.as_deref().is_some_and(is_under_readonly_bind_mount) {
        return EROFS;
    }
    if let ffi::Attr::Size(_) = attr {
        return realfs::realfs_fsetattr(fd, attr);
    }

    let (db, inode) = (fd_db(fd), fd.fake_inode);
    let mut tx = db.write();
    let Some(mut iul) = tx.inode_stat(inode) else {
        // No row: this descriptor was opened on a hook-routed path, whose
        // inode is the host's and is never stored. The change goes to the
        // host descriptor.
        tx.rollback();
        return host_setattr(attr, |mode| {
            let Some(host) = fd.host() else {
                return EIO;
            };
            rustix::fs::fchmod(host, rustix::fs::Mode::from_raw_mode(mode as libc::mode_t))
                .map_or_else(crate::rx_err, |()| 0)
        });
    };
    apply(&mut iul, attr);
    tx.inode_write_stat(inode, &iul);
    // Checked, as setattr's is. This one was missed: an fchmod through a
    // descriptor whose transaction went back reported success and left the
    // mode where it was.
    if tx.commit() { 0 } else { EIO }
}
