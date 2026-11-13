//! File descriptor creation and host open flag translation.

use std::ffi::{CStr, c_int};

use crate::{ ensure_inode, fakefs_fdops_get, ffi, is_under_bind_mount,
    is_under_readonly_bind_mount, mount_db, new_row, record_write, translate,
};

// --------------------------------------------------------------------- open

use guest_errno::Errno;

/// The guest open flags this reads, from `kernel/fs.h`.
mod oflags {
    pub const WRONLY: c_int = 1 << 0;
    pub const RDWR: c_int = 1 << 1;
    pub const CREAT: c_int = 1 << 6;
    pub const EXCL: c_int = 1 << 7;
    pub const TRUNC: c_int = 1 << 9;
    pub const APPEND: c_int = 1 << 10;
    pub const NONBLOCK: c_int = 1 << 11;
    pub const NOFOLLOW: c_int = 1 << 15;
    use std::ffi::c_int;

    /// Every flag that means the caller intends to change the file.
    pub const WRITING: c_int = WRONLY | RDWR | CREAT | TRUNC | APPEND;
}

/// The guest's open flags as the host's.
fn host_open_flags(flags: c_int) -> c_int {
    let mut out = 0;
    for (guest, host) in [
        (oflags::WRONLY, libc::O_WRONLY),
        (oflags::RDWR, libc::O_RDWR),
        (oflags::CREAT, libc::O_CREAT),
        (oflags::EXCL, libc::O_EXCL),
        (oflags::TRUNC, libc::O_TRUNC),
        (oflags::APPEND, libc::O_APPEND),
        (oflags::NONBLOCK, libc::O_NONBLOCK),
        (oflags::NOFOLLOW, libc::O_NOFOLLOW),
    ] {
        if flags & guest != 0 {
            out |= host;
        }
    }
    out
}

/// # Safety
///
/// `mount` is live with a `fakefs` database and `path` is NUL-terminated.
pub fn fakefs_rs_open(mount: &ffi::mount,
    path: &CStr,
    flags: c_int,
    mode: c_int,
) -> Result<Box<ffi::fd>, Errno> {
    let path_c = path;

    // A write-intent open under a read-only bind mount is refused here rather
    // than by the mode bits: the guest runs as root and bypasses the DAC
    // check, so the 0555 on the mount directory blocks nothing.
    if flags & oflags::WRITING != 0 && is_under_readonly_bind_mount(path_c) {
        return Err(Errno::EROFS);
    }

    let bind = translate(path_c);
    let via_hook = matches!(bind, Some((_, true)));
    let mut fd = match &bind {
        // A bind-mounted path is opened by its host path directly rather than
        // by walking the graft symlink, which the iOS sandbox may refuse.
        Some((host, _)) => {
            let host_fd = rustix::fs::open(
                host.as_slice(),
                rustix::fs::OFlags::from_bits_retain(host_open_flags(flags) as _),
                rustix::fs::Mode::from_raw_mode(0o666),
            )
            .map_err(|e| Errno::from_negative_or_eio(crate::rx_err(e)))?;
            // This bypasses realfs_open, so the change event it would have
            // recorded has to be recorded here -- without it the bind-mount
            // fast path was the one way to open a file whose later writes
            // produced no events.
            if flags & oflags::WRITING != 0 {
                record_write(path_c);
            }
            let mut fd = Box::new({
                let mut f = ffi::fd::default();
                f.ops = Some(&realfs::REALFS_FDOPS);
                f.real_fd = Some(host_fd);
                f
            });
            // The same path realfs_open records, for the same reason: this
            // descriptor carries REALFS_FDOPS, so realfs_write reports through
            // it.
            if flags & oflags::WRITING != 0 {
                fd.change_path = Some(path.to_owned());
            }
            fd
        }
        None => realfs::realfs_open_at(mount, path, flags, 0o666)?
            ,
    };
    // Unpublished, so a refusal below drops it -- and the host descriptor
    // with it.

    // A hook-routed path bypasses meta.db: the `paths` table is keyed by guest
    // path globally, while the hook can map one guest path to a different host
    // file per context, so storing it would be one row for N files. The fake
    // inode is synthesised from the host's so that operations within one
    // descriptor stay consistent.
    if via_hook {
        fd.fake_inode = match fd.host().map(rustix::fs::fstat) {
            Some(Ok(st)) => st.st_ino,
            _ => 1, // non-zero, so the ENOENT below is skipped
        };
        return Ok(fd);
    }

    let db = mount_db(mount);
    let mut tx = db.write();
    let mut inode = tx.path_stat(path_c.to_bytes()).map(|(_, i)| i).unwrap_or(0);
    if flags & oflags::CREAT != 0 && inode == 0 {
        // The create's own answer, rather than a second lookup: it returns the
        // inode it made and 0 when it made none. Asking again cost two
        // statements on every O_CREAT open and could not tell a create that
        // was refused from one that worked.
        inode = tx.path_create(
            path_c.to_bytes(),
            &new_row(mode as u32 | libc::S_IFREG as u32, 0),
        );
    }
    // A commit that went back leaves no row, so the inode above names nothing
    // and every later stat of this path answers ENOENT. Reported here instead.
    if !tx.commit() {
        inode = 0;
    }
    if inode == 0 {
        if is_under_bind_mount(path_c) {
            inode = ensure_inode(mount, path_c);
        }
        if inode == 0 {
            return Err(Errno::ENOENT);
        }
    }
    fd.fake_inode = inode;
    fd.ops = fakefs_fdops_get();
    Ok(fd)
}

// `err_ptr` and `is_err_ptr` were defined here until 2026-09-14 -- the second
// was the one rendering of the predicate that disagreed with `iul.h`, by the
// value -4095. Then the encoding itself went: this file answers a `Result` and
// the two functions in the tree that still speak `ERR_PTR` are the two that
// `iul.h` declares.
