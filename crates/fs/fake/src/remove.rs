//! Unlink and rmdir operations for fakefs.

use std::ffi::{CStr, c_int};

use crate::{
    EROFS, ensure_inode, ffi, is_under_bind_mount,
    is_under_readonly_bind_mount, mount_db, translate,
};

// ------------------------------------------------------------- removal

/// `unlink` and `rmdir` are the same function with a different host call, and
/// were two copies of it.
///
/// The order matters and is the same in both: the host name goes first and the
/// row second, inside a transaction opened before either. A row removed while
/// the host name is still there is a file the guest cannot see and cannot
/// delete; a host name removed while the row is still there is a row pointing
/// at nothing.
///
/// `mount` is a fakefs: [`mount_db`] panics on anything else.
fn remove(mount: &ffi::mount,
    path: &CStr,
    what: Remove,
) -> c_int {
    let path_c = path;
    if is_under_readonly_bind_mount(path_c) {
        return EROFS;
    }
    let bind = translate(path_c);
    // A hook-routed path has no meta.db row to remove.
    if let Some((host, true)) = &bind {
        if let Err(e) = what.host(host) {
            return e;
        }
        record_unlink(path_c);
        return 0;
    }

    // A path under a bind mount may have no row yet -- the host tree is
    // grafted in rather than copied -- and removing a name with no row would
    // leave the database with nothing to take out.
    if is_under_bind_mount(path_c) {
        ensure_inode(mount, path_c);
    }

    let db = mount_db(mount);
    let mut tx = db.write();
    let via_bind = bind.is_some();
    let err = match &bind {
        Some((host, _)) => what.host(host).err().unwrap_or(0),
        None => what.realfs(mount, path),
    };
    if err < 0 {
        tx.rollback();
        return err;
    }
    let ino = tx.unlink(path_c.to_bytes());
    tx.commit();
    if via_bind {
        record_unlink(path_c);
    }
    // The last name for this inode may have gone, in which case whatever holds
    // it open is told.
    fs_inode::inode_check_orphaned(mount, ino);
    0
}

/// Tells the embedder's change ring that this guest path was removed.
fn record_unlink(path: &CStr) {
    fakechange::record_change(path, ffi::FAKEFS_CHANGE_OP_UNLINK as c_int);
}

pub fn fakefs_rs_unlink(mount: &ffi::mount, path: &CStr) -> c_int {
    remove(mount, path, Remove::Unlink)
}

pub fn fakefs_rs_rmdir(mount: &ffi::mount, path: &CStr) -> c_int {
    remove(mount, path, Remove::Rmdir)
}

/// Which of the two removals, at the host and through realfs. Two function
/// pointers until 2026-10-01, one of them `libc::unlink` or `libc::rmdir`
/// called in an `unsafe` block with errno read back afterwards.
#[derive(Clone, Copy)]
enum Remove {
    Unlink,
    Rmdir,
}

impl Remove {
    /// The host name itself, for a bind-mounted path.
    fn host(self, path: &[u8]) -> Result<(), c_int> {
        let r = match self {
            Remove::Unlink => rustix::fs::unlink(path),
            Remove::Rmdir => rustix::fs::rmdir(path),
        };
        r.map_err(|e| kernel_errno::raised(e.raw_os_error()))
    }

    fn realfs(self, mount: &ffi::mount, path: &CStr) -> c_int {
        match self {
            Remove::Unlink => realfs::realfs_unlink(mount, path),
            Remove::Rmdir => realfs::realfs_rmdir(mount, path),
        }
    }
}
