//! Stat and fstat operations, merging host metadata with `meta.db`.

use std::ffi::{CStr, c_int};

use crate::{
    ENOENT, ensure_inode, ffi,
    fd_db, is_under_bind_mount, mount_db, translate,
};

// -------------------------------------------------------------------- stat

/// `dev_fake_from_real`: the guest's device number for a host one.
pub(crate) fn dev_from_host(dev: libc::dev_t) -> u32 {
    let major = libc::major(dev) as u32;
    let minor = libc::minor(dev) as u32;
    // `dev_make` in fs/dev.h: the major in the top sixteen bits.
    (major << 8) | (minor & 0xff) | ((minor & 0xfff00) << 12)
}

/// The fields fakefs takes from the host rather than from `meta.db`.
///
/// `dev`, `blksize` and `blocks` are here for a reason worth keeping: this is
/// the answer `fstat` gets from `realfs` for the same file, and coreutils
/// compares the two. `psame_inode(stat, fstat)` on a `dev` that one call fills
/// and the other leaves alone reports "the file was replaced while being
/// copied".
pub(crate) fn host_fields(out: &mut ffi::statbuf, host: &libc::stat) {
    out.dev = dev_from_host(host.st_dev) as u64;
    out.size = host.st_size as u64;
    out.nlink = host.st_nlink as u32;
    out.blksize = host.st_blksize as u32;
    out.blocks = host.st_blocks as u64;
    out.atime = host.st_atime as i64;
    out.atime_nsec = host.st_atime_nsec as u32;
    out.mtime = host.st_mtime as i64;
    out.mtime_nsec = host.st_mtime_nsec as u32;
    // Creation time comes from the host file, like the other three: a fakefs
    // keeps contents as host files, and `meta.db` holds only what iOS gives an
    // app no real ones of -- ownership, modes and device nodes.
    {
        out.btime = host.st_birthtime;
        out.btime_nsec = host.st_birthtime_nsec as u32;
        out.has_btime = 1;
    }
    out.ctime = host.st_ctime as i64;
    out.ctime_nsec = host.st_ctime_nsec as u32;
}

/// What `meta.db` overrides: the five fields fakefs is entitled to disagree
/// with the host about.
pub(crate) fn db_fields(out: &mut ffi::statbuf, inode: u64, s: &fakedb::IulStat) {
    out.inode = inode;
    out.mode = s.mode;
    out.uid = s.uid;
    out.gid = s.gid;
    out.rdev = s.rdev as u64;
}

/// A hook-routed path has no `meta.db` row by design, so the mode is
/// synthesised from the host's type: 0755 for a directory and 0644 for
/// anything else, owned by root.
pub(crate) fn synthesise_mode(out: &mut ffi::statbuf, host_mode: u32) {
    let is_dir = host_mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32;
    out.mode = (host_mode & libc::S_IFMT as u32) | if is_dir { 0o755 } else { 0o644 };
    out.uid = 0;
    out.gid = 0;
    out.rdev = 0;
}

/// # Safety
///
/// `mount` is live with a `fakefs` database, `path` is NUL-terminated and `out`
/// is writable.
pub fn fakefs_rs_stat(mount: &ffi::mount, path: &CStr) -> Result<ffi::statbuf, c_int> {
    let (db, path_c) = (mount_db(mount), path);
    let mut stat = ffi::statbuf::default();
    let out = &mut stat;

    // A hook-routed path bypasses meta.db, so it is answered from the host
    // alone. Asked first, because the answer decides whether the database is
    // consulted at all.
    if let Some((host, true)) = translate(path_c) {
        let Some(host_stat) = host_lstat(&host, false) else {
            return Err(kernel_errno::errno_map());
        };
        host_fields(out, &host_stat);
        out.inode = host_stat.st_ino;
        synthesise_mode(out, host_stat.st_mode as u32);
        return Ok(stat);
    }

    // The row, and then the transaction ends -- **before** any host call.
    //
    // It used to be held across realfs.stat and the direct host stat below,
    // which are blocking syscalls, so every stat in the process serialised
    // behind whichever one was in the host. Nothing here needs the row and the
    // host's answer to be consistent with each other: the fields are merged
    // afterwards and each is authoritative for its own.
    let mut looked = db.lookup_path(path_c.to_bytes());
    if looked.is_none() {
        // A path under a bind mount gets its row made on first access, so that
        // the host tree can be grafted in without copying it.
        if !is_under_bind_mount(path_c) {
            return Err(ENOENT);
        }
        if ensure_inode(mount, path_c) == 0 {
            return Err(ENOENT);
        }
        looked = db.lookup_path(path_c.to_bytes());
        if looked.is_none() {
            return Err(ENOENT);
        }
    }
    let (iul, inode) = looked.expect("checked above");

    // The host half. A bind-mounted path is stat'ed directly rather than
    // through realfs: realfs uses AT_SYMLINK_NOFOLLOW, which for the mount
    // point itself answers about the symlink that implements the graft rather
    // than about the directory it names.
    if let Some((host, _)) = translate(path_c) {
        let Some(host_stat) = host_lstat(&host, true) else {
            return Err(kernel_errno::errno_map());
        };
        host_fields(out, &host_stat);
    } else {
        *out = realfs::realfs_stat(mount, path)?;
    }
    db_fields(out, inode, &iul);
    Ok(stat)
}

/// `lstat` or `stat` of a host path. `follow` is what the two callers differ
/// on: the mount point is stat'ed through the graft, and a hook-routed path is
/// not.
pub(crate) fn host_lstat(path: &[u8], follow: bool) -> Option<libc::stat> {
    if follow {
        rustix::fs::stat(path).ok()
    } else {
        rustix::fs::lstat(path).ok()
    }
}

/// Panics on a descriptor whose mount is not a fakefs, as
/// [`crate::fakefs_rs_fsetattr`] does.
pub fn fakefs_rs_fstat(fd: &ffi::fd) -> Result<ffi::statbuf, c_int> {
    let mut host = realfs::realfs_fstat(fd)?;
    let out = &mut host;
    let (db, inode) = (fd_db(fd), fd.fake_inode);
    if let Some(iul) = db.lookup_stat(inode) {
        db_fields(out, inode, &iul);
        return Ok(host);
    }

    // No row. If this descriptor's path routes through the embedder's hook the
    // absence is by design -- hook-routed paths never get one -- and the host's
    // answer stands with a synthesised mode. Otherwise the missing row is a
    // real ENOENT, and reporting it is what stops an unrelated defect being
    // masked.
    //
    // MAX_PATH + 1: an answer is the path and its terminator. The comment here
    // used to have to say so -- "realfs_getpath accepts a path of exactly
    // MAX_PATH characters and writes the NUL at buf[MAX_PATH]" -- because the
    // length was not in the signature. It is, so this is just a buffer.
    let mut buf = vec![0u8; ffi::MAX_PATH as usize + 1];
    if realfs::realfs_getpath(fd, &mut buf) == 0 {
        let len = ffi::path_bytes(&buf).len();
        if let Ok(p) = CStr::from_bytes_with_nul(&buf[..=len])
            && matches!(translate(p), Some((_, true)))
        {
            let host_mode = out.mode;
            synthesise_mode(out, host_mode);
            return Ok(host);
        }
    }
    Err(ENOENT)
}
