//! Rename operations for fakefs paths and metadata rows.

use std::ffi::{CStr, c_int};

use crate::{
    EINVAL, EROFS, EXDEV, fakefs_paths_changed_pub, ffi,
    is_under_readonly_bind_mount, mount_db, translate,
};

// ------------------------------------------------------------------ rename

/// The guest's `RENAME_EXCHANGE`.
const RENAME_EXCHANGE: u32 = 1 << 1;

/// # Safety
///
/// `mount` is live with a `fakefs` database; both paths are NUL-terminated.
pub fn fakefs_rs_rename(mount: &ffi::mount,
    src: &CStr,
    dst: &CStr,
    flags: u32,
) -> c_int {
    // RENAME_EXCHANGE was EINVAL here until 2026-11-11 -- Linux's answer for a
    // flag a filesystem does not implement, and true of fakefs alone: realfs
    // and tmpfs swap, so `fsat_probe` answered 0 on `-r` and EINVAL on `-f`.
    //
    // The metadata is a table of path blobs and a rename is a *prefix
    // substitution* over it, so an exchange is three of them through a
    // temporary prefix inside the write transaction (`Tx::exchange`). The two
    // conditions that made it worth refusing are both answered: the temporary
    // prefix starts with a NUL, which no guest path holds, and neither path
    // may be under the other -- refused here, before any row moves, with the
    // EINVAL Linux gives that exchange.
    let exchange = flags & RENAME_EXCHANGE != 0;
    if exchange
        && (fakedb::is_under(src.to_bytes(), dst.to_bytes()) || fakedb::is_under(dst.to_bytes(), src.to_bytes()))
    {
        return EINVAL;
    }
    // A rename moves guest paths, including those of directories somebody has
    // open, so the cached directory paths are stale from here on. Bumped
    // before the work rather than after: a reader that races this is entitled
    // to either answer, but not to one from before the bump that it caches
    // afterwards.
    fakefs_paths_changed_pub();

    let (src_c, dst_c) = (src, dst);
    if is_under_readonly_bind_mount(src_c) || is_under_readonly_bind_mount(dst_c) {
        return EROFS;
    }
    let (src_t, dst_t) = (translate(src_c), translate(dst_c));
    // Both sides must be the same kind of path. A rename between a bind mount
    // and the fakefs proper is a move between two filesystems, and so is one
    // between a hook-routed path and anything else.
    if src_t.is_some() != dst_t.is_some()
        || matches!(src_t, Some((_, true))) != matches!(dst_t, Some((_, true)))
    {
        return EXDEV;
    }

    // RENAME_NOREPLACE goes to the host, whose own atomic create-if-absent is
    // the one that runs. The guest's flags and Darwin's use the same names for
    // different numbers, which is why the translation is realfs's and not
    // written out again here.
    let Some(host_flags) = realfs::rename_flags(flags) else {
        return EINVAL;
    };
    // Both are absolute host paths, so the directory they are relative to is
    // never read.
    let host_rename = |a: &[u8], b: &[u8]| -> c_int {
        use rustix::fs::{CWD, renameat, renameat_with};
        let r = if host_flags.is_empty() {
            renameat(CWD, a, CWD, b)
        } else {
            renameat_with(CWD, a, CWD, b, host_flags)
        };
        r.map_or_else(crate::rx_err, |()| 0)
    };

    // A hook-routed path has no meta.db row to move.
    if let (Some((a, true)), Some((b, true))) = (&src_t, &dst_t) {
        let err = host_rename(a, b);
        if err < 0 {
            return err;
        }
        record_rename(dst_c);
        return 0;
    }

    let db = mount_db(mount);
    let mut tx = db.write();
    if exchange {
        tx.exchange(src_c.to_bytes(), dst_c.to_bytes());
    } else {
        tx.rename(src_c.to_bytes(), dst_c.to_bytes());
    }
    let via_bind = src_t.is_some();
    let err = match (&src_t, &dst_t) {
        (Some((a, _)), Some((b, _))) => host_rename(a, b),
        _ => realfs::realfs_rename(mount, src, dst, flags),
    };
    if err < 0 {
        tx.rollback();
        return err;
    }
    tx.commit();
    if via_bind {
        record_rename(dst_c);
    }
    0
}

fn record_rename(path: &CStr) {
    fakechange::record_change(path, ffi::FAKEFS_CHANGE_OP_RENAME as c_int);
}
