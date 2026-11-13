//! Normalize the host path recorded for the root filesystem.

use std::ffi::CString;

use crate::ffi;

/// The path a root mount is recorded under: the **directory** resolved, the
/// last component kept as written.
///
/// A fakefs finds `meta.db` beside its `data/` directory, so the last
/// component is load-bearing -- and it may be a symlink. `realpath` on the
/// whole path replaced a `data` that pointed at `/srv/ubuntu` with
/// `/srv/ubuntu`, the database was then looked for at `/srv/meta.db`.
/// Resolving the parent and re-appending the name gives an absolute path with
/// no symlinks above the mount, while leaving the name that identifies the
/// database directory.
///
/// A trailing slash is dropped first, so `alpine/data/` and `alpine/data` are
/// the same mount.
pub(super) fn resolved_source(given: &[u8]) -> Result<CString, i32> {
    let trimmed = match given.iter().rposition(|b| *b != b'/') {
        Some(last) => &given[..=last],
        None => given,
    };
    let (dir, name): (&[u8], &[u8]) = match trimmed.iter().rposition(|b| *b == b'/') {
        Some(0) => (b"/", &trimmed[1..]),
        Some(slash) => (&trimmed[..slash], &trimmed[slash + 1..]),
        None => (b".", trimmed),
    };
    if name.is_empty() || name == b"." || name == b".." {
        return realpath(trimmed);
    }
    let dir = realpath(dir)?;
    let mut out = dir.into_bytes();
    if out.last() != Some(&b'/') {
        out.push(b'/');
    }
    out.extend_from_slice(name);
    if out.len() > ffi::MAX_PATH as usize {
        return Err(-36); // ENAMETOOLONG
    }
    CString::new(out).map_err(|_| -22)
}

fn realpath(path: &[u8]) -> Result<CString, i32> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    if path.contains(&0) {
        return Err(-22);
    }
    // `std`'s is `realpath(3)`. err_map rather than errno_map: realpath
    // cannot answer EPIPE and does not need a task to raise it in.
    let real = std::fs::canonicalize(std::ffi::OsStr::from_bytes(path))
        .map_err(|e| kernel_errno::err_map(e.raw_os_error().unwrap_or(libc::EIO)))?;
    CString::new(real.into_os_string().into_vec()).map_err(|_| -22)
}
