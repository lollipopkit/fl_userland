//! Generic path and descriptor extended-attribute dispatch.

use super::*;

/// "This filesystem does not support extended attributes." `crates/kernel/errno`
/// maps a Darwin number onto it; this is the guest's own, negative, as
/// `crates/util/errno` spells it.
use guest_errno::c_int_::EOPNOTSUPP;

/// One extended-attribute operation, by path.
///
/// The twelve syscalls are four verbs crossed with three ways of naming the
/// target, and this is the path half of it — `crates/kernel/fdattr` has applied
/// `crates/fs/xattrabi`'s rules by the time it calls, so what is left is the
/// resolution and the mount's own answer.
///
/// **A mount with no `xattr` entry answers `_EOPNOTSUPP`**, which is Linux's
/// "this filesystem does not support extended attributes". Not `_EPERM`, which
/// is the answer a *namespace* rule gives — a caller distinguishes the two:
/// the first means stop asking and the second means ask as somebody else.
///
/// As [`generic_openat`]. `call`'s pointers are as [`ffi::XattrCall`]
/// describes them.
///
/// Neither `#[unsafe(no_mangle)]` nor `extern "C"`: `crates/kernel/fdattr`
/// calls it as Rust and no C names it. An export nobody can reach is a second
/// interface and an optimisation barrier — `tools/dead-exports.py` is the
/// gate — and the calling convention was what pinned the request to six loose
/// pointers, because an `extern "C" fn` may not take a type that is not
/// FFI-safe.
pub fn generic_xattr(
    at: ffi::At<'_>,
    name: &CStr,
    call: ffi::XattrCall,
    follow_links: bool,
) -> isize {
    let nflags = if follow_links {
        ffi::N_SYMLINK_FOLLOW
    } else {
        ffi::N_SYMLINK_NOFOLLOW
    };
    let mut path = match normalize(at, name, nflags as c_int) {
        Ok(p) => p,
        Err(e) => return e as isize,
    };
    let mount = Mount::of(&mut path);
    mount
            .fs()
            .xattr(
mount.get(), path.as_cstr(), call, follow_links)
}

/// The same on an open descriptor. As [`generic_xattr`].
pub fn generic_fxattr(fd: &ffi::fd, call: ffi::XattrCall) -> isize {
    // Through the mount, and **null-checked**: an adhoc descriptor -- a pipe, a
    // socket, an eventfd -- has no mount at all, and Linux answers EOPNOTSUPP
    // for one rather than faulting. `generic_fstat` two functions down reaches
    // the same chain without the check, because every caller of that one has
    // already established the descriptor is a file's.
    let Some(fs) = fd.mount().and_then(|mount| mount.fs) else {
        return EOPNOTSUPP as isize;
    };
    fs.fxattr(fd, call)
}
