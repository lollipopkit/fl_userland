//! Host filesystem metadata and guest path reporting.

use std::ffi::{CStr, c_int};

use rustix::fs::{self as host_fs, AtFlags};

use crate::errno::{Result, rx};
use crate::{at_path, dev, ffi, host, mountpath, root, stat};

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

pub fn realfs_stat(mount: &ffi::mount, path: &CStr) -> Result<ffi::statbuf> {
    {
        let host = rx(host_fs::statat(root(mount)?, at_path(path), AtFlags::SYMLINK_NOFOLLOW))?;
        let mut out = stat::convert(&host);
        // A host directory has no device nodes in it; the placeholder file
        // standing in for one is described as the device it stands for.
        if let Some(devnum) = dev::for_path(path.to_bytes()) {
            out.mode = (libc::S_IFCHR | 0o666) as u32;
            out.rdev = devnum as u64;
        }
        Ok(out)
    }
}

pub fn realfs_fstat(fd: &ffi::fd) -> Result<ffi::statbuf> {
    Ok(stat::convert(&rx(host_fs::fstat(host(fd)?))?))
}

pub fn realfs_statfs(mount: &ffi::mount) -> Result<ffi::statfsbuf> {
    {
        // The C discarded this result. A failed fstatvfs leaves the buffer
        // zeroed, which describes a filesystem with no blocks and none free —
        // a guest that checks for space before writing concludes the disk is
        // full, and `df` agrees with it. A `?` says it now.
        let vfs = rx(host_fs::fstatvfs(root(mount)?))?;
        Ok(ffi::statfsbuf {
            bsize: Some(vfs.f_bsize as i64),
            blocks: vfs.f_blocks as u64,
            bfree: vfs.f_bfree as u64,
            bavail: vfs.f_bavail as u64,
            files: vfs.f_files as u64,
            ffree: vfs.f_ffree as u64,
            namelen: Some(vfs.f_namemax as i64),
            frsize: vfs.f_frsize as i64,
            // The host says nothing about the *guest* mount's flags, which is
            // what the caller completes from `mount.flags`.
            ..Default::default()
        })
    }
}

pub fn realfs_getpath(fd: &ffi::fd, buf: &mut [u8]) -> c_int {
    let host_c = match host(fd).and_then(|host| rx(host_fs::getpath(host))) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let host_path = host_c.to_bytes();

    // A bind mount grafts a host directory in somewhere the mount source
    // does not cover, and F_GETPATH resolves symlinks, so the host path
    // has to be looked up in the bind-mount table before the mount source
    // is tried at all.
    if let Some(linux) = bindmount::bindmount_resolve(&host_c, ffi::MAX_PATH as usize + 1) {
        return ffi::fill_path(buf, linux.to_bytes());
    }

    let source = fd.mount().map_or(&b""[..], |m| m.source.to_bytes());
    ffi::fill_path(buf, &mountpath::guest_path(host_path, source))
}

pub fn realfs_readlink(mount: &ffi::mount, path: &CStr, buf: &mut [u8]) -> isize {
    let read = root(mount).and_then(|root| {
        rx(host_fs::readlinkat_raw(root, at_path(path), &mut *buf))
    });
    match read {
        Ok(n) => n as isize,
        Err(e) => e as isize,
    }
}
