//! `O_TMPFILE` on fakefs: an inode with no path in `meta.db`, whose data is a
//! host file under `<fakefs>/unnamed/<inode>` -- beside `data/`, so no guest
//! path reaches it, and on the same volume, so `linkat` naming the file is a
//! host hard link into `data/` and a `paths` row: the same inode, as on Linux.
//!
//! The hidden name is the host's extra link, which the guest's link count
//! leaves out (`realfs::stat::hide_link`). It goes when the description
//! closes; a file no path names is then gone from the host, and its `stats`
//! row goes with the inode (`inode_orphaned`). What a crash leaves in
//! `unnamed/` is cleared at the next mount.

use std::ffi::{CStr, CString, c_int};
use std::os::fd::BorrowedFd;

use crate::{fakefs_fdops_get, ffi, is_under_bind_mount, mount_db, new_row, record_write, translate};
use guest_errno::Errno;

const DIR: &CStr = c"../unnamed";

fn rx_err(e: rustix::io::Errno) -> c_int {
    kernel_errno::raised(e.raw_os_error())
}

fn hidden_name(inode: u64) -> CString {
    CString::new(format!("../unnamed/{inode}")).expect("no NUL in a number")
}

/// `FsOps::tmpfile` for fakefs.
pub fn fakefs_tmpfile(mount: &ffi::mount, dir: &CStr, flags: c_int, mode: c_int) -> Result<Box<ffi::fd>, Errno> {
    // A bind mount's files are host files at host paths; there is no hidden
    // place beside them.
    if translate(dir).is_some() || is_under_bind_mount(dir) {
        return Err(Errno::EOPNOTSUPP);
    }
    let root = mount.root().ok_or(Errno::EIO)?;
    let db = mount_db(mount);
    let mut tx = db.write();
    let inode = tx.inode_create(&new_row((mode as u32 & 0o7777) | libc::S_IFREG as u32, 0));
    if inode == 0 {
        tx.rollback();
        return Err(Errno::EIO);
    }
    match rustix::fs::mkdirat(root, DIR, rustix::fs::Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(e) => {
            tx.rollback();
            return Err(Errno::from_negative_or_eio(rx_err(e)));
        }
    }
    let name = hidden_name(inode);
    // An inode number a crash left a file for: that file is nobody's.
    let _ = rustix::fs::unlinkat(root, name.as_c_str(), rustix::fs::AtFlags::empty());
    let host_flags = realfs::flags::to_host(flags as u32) | libc::O_CREAT | libc::O_EXCL;
    let host = match rustix::fs::openat(
        root,
        name.as_c_str(),
        rustix::fs::OFlags::from_bits_retain(host_flags as _),
        rustix::fs::Mode::from_raw_mode(0o600),
    ) {
        Ok(h) => h,
        Err(e) => {
            tx.rollback();
            return Err(Errno::from_negative_or_eio(rx_err(e)));
        }
    };
    if !tx.commit() {
        let _ = rustix::fs::unlinkat(root, name.as_c_str(), rustix::fs::AtFlags::empty());
        return Err(Errno::EIO);
    }
    if let Ok(st) = rustix::fs::fstat(&host) {
        realfs::stat::hide_link(&st);
    }
    let mut fd = Box::new(ffi::fd::default());
    fd.ops = fakefs_fdops_get();
    fd.real_fd = Some(host);
    fd.fake_inode = inode;
    fd.unnamed = Some(Box::new(ffi::Unnamed { host: Some(name), ..Default::default() }));
    Ok(fd)
}

/// `FsOps::link_unnamed` for fakefs: the hidden file, hard linked to `dst`,
/// and `dst`'s row naming the inode.
pub fn fakefs_link_unnamed(fd: &ffi::fd, mount: &ffi::mount, dst: &CStr) -> c_int {
    let Some(name) = fd.unnamed.as_ref().and_then(|u| u.host.as_ref()) else {
        return guest_errno::c_int_::EOPNOTSUPP;
    };
    if translate(dst).is_some() || is_under_bind_mount(dst) {
        return guest_errno::c_int_::EXDEV;
    }
    let Some(root) = mount.root() else {
        return guest_errno::c_int_::EIO;
    };
    let host_dst = realfs::at_path(dst);
    if let Err(e) = rustix::fs::linkat(root, name.as_c_str(), root, host_dst, rustix::fs::AtFlags::empty()) {
        return rx_err(e);
    }
    let db = mount_db(mount);
    let mut tx = db.write();
    if !tx.link_inode(dst.to_bytes(), fd.fake_inode) || !tx.commit() {
        let _ = rustix::fs::unlinkat(root, host_dst, rustix::fs::AtFlags::empty());
        return guest_errno::c_int_::EIO;
    }
    record_write(dst);
    0
}

/// The description is closing: its hidden name goes.
pub fn fakefs_close_unnamed(fd: &ffi::fd) {
    let (Some(name), Some(root)) = (fd.unnamed.as_ref().and_then(|u| u.host.as_ref()), fd.mount().and_then(|m| m.root())) else {
        return;
    };
    if let Some(Ok(st)) = fd.host().map(rustix::fs::fstat) {
        realfs::stat::unhide_link(st.st_dev as u64, st.st_ino);
    }
    let _ = rustix::fs::unlinkat(root, name.as_c_str(), rustix::fs::AtFlags::empty());
}

/// What a crash left in `unnamed/`: no description can be open on any of it
/// at mount time, so every file goes, and the `stats` row of an inode no path
/// names goes with it.
pub fn clear_unnamed(root: BorrowedFd<'_>, db: &fakedb::Db) {
    let Ok(dir) = rustix::fs::openat(root, DIR, rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY, rustix::fs::Mode::empty()) else {
        return;
    };
    let Ok(mut entries) = rustix::fs::Dir::read_from(&dir) else {
        return;
    };
    let mut gone = Vec::new();
    while let Some(Ok(e)) = entries.read() {
        let n = e.file_name().to_bytes();
        if n == b"." || n == b".." {
            continue;
        }
        if rustix::fs::unlinkat(&dir, e.file_name(), rustix::fs::AtFlags::empty()).is_ok()
            && let Some(inode) = std::str::from_utf8(n).ok().and_then(|s| s.parse::<u64>().ok())
        {
            gone.push(inode);
        }
    }
    for inode in gone {
        db.inode_orphaned(inode);
    }
}
