//! Filesystem statistics for a path.

use super::*;

// ---------------------------------------------------------------------------
// statfs
// ---------------------------------------------------------------------------

/// `statfs` answers about the filesystem, but it is still reached through a
/// path, and a path that names nothing is `ENOENT`.
///
/// Only the normalisation used to run, which does not require the file to
/// exist, and the mount lookup then answered with whichever mount contains the
/// name — always at least the root — so `statfs("/does/not/exist")` reported
/// the root filesystem and returned success.
pub fn sys_statfs_arm64(path_addr: u64, buf_addr: u64) -> Result<(), Errno> {
    let raw = Path::read(path_addr)?;
    strace!("statfs({:?}, {buf_addr:#x})", raw.as_str());
    let mut st = ffi::statbuf::default();
    done(fs_generic::generic_statat(ffi::At::Pwd, raw.as_cstr(), &mut st, true))?;
    let resolved = fs_generic::normalize::resolve(
        ffi::At::Pwd,
        raw.as_cstr().to_bytes(),
        ffi::N_SYMLINK_NOFOLLOW as c_int,
    )
    .map_err(Errno::from_negative_or_eio)?;
    let path = std::ffi::CString::new(resolved.path).map_err(|_| Errno::EINVAL)?;
    let mount = fs_mounttable::mount_find(&path);
    // fstatfs's answer for the same mount, as a Rust call: it was a C ABI
    // export of fdattr's that only this crate reached.
    fdattr::statfs_mount(&mount, buf_addr)
}
