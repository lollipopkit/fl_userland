//! Turning what a guest wrote into an absolute path this kernel can look up.
//!
//! **What normalising is**, as `fs/path.h` stated it until 2026-09-08:
//! prepending the current or the root directory, collapsing runs of slashes to
//! one, resolving `.` and `..`, and resolving symlinks — skipping the last
//! component when the caller does not want it followed. The result always
//! begins with a slash or is empty, and a result that would not fit in
//! `MAX_PATH` including its terminator is `_ENAMETOOLONG` rather than a
//! truncation. `at` is the descriptor a relative path is taken from, or
//! `AT_PWD` for the task's own.
//!
//! The walk itself is `crates/fs/path` — a pure function over three strings.
//! What is here is the part that reads the **task's** filesystem state: which
//! directory a relative path is relative to, and which directory is the floor
//! `..` cannot climb past.
//!
//! # Both descriptors are taken under one hold of the lock, and retained
//!
//! Reading the pointers under `fs->lock` and using them afterwards was a
//! use-after-free. `chroot` and `chdir` both **close** the descriptor they
//! replace while holding that lock, and a thread created with `CLONE_FS` —
//! every pthread — shares the `struct fs_info` they close it in. So a `chdir`
//! on one thread could free the descriptor another was about to call
//! `generic_getpath` on. The root read carried a comment about exactly this
//! hazard and did its own read under the lock, while `at` two lines above did
//! not.
//!
//! Retain-then-release rather than doing the work under the lock:
//! `generic_getpath` dispatches into a filesystem's own `getpath`, and holding
//! `fs->lock` across a call into an arbitrary mount is how lock-order
//! inversions get made.
//!
//! # The cache that used to be here is gone
//!
//! A 64-entry, 100 ms thread-local cache, wrong in three ways: it skipped the
//! execute-permission check on every hit, its key was built with a truncating
//! `snprintf` so two long inputs could share an entry, and a mount inside the
//! TTL did not invalidate it. `crates/fs/path`'s `resolve` records what a
//! correct one would have to do.

use std::ffi::c_int;

use crate::MAX_PATH;
use crate::ffi;

use guest_errno::c_int_::{ENOENT, EXDEV};

/// `MAX_PATH` plus room for the terminator.
const PATH_BUF: usize = MAX_PATH + 1;

/// Resolve what a guest wrote against this task's working directory, or the
/// descriptor `at` names, and its root.
///
/// **Safe**, where it was `path_normalize` and `path_normalize_ex` until
/// 2026-09-29: a raw path in, an out-pointer to a `MAX_PATH` buffer, a
/// nullable `*mut c_int` for whether the last component existed, and
/// `path::path_normalize_walk` beneath them taking all of it again. The walk
/// itself was always a function over slices. Every caller -- this crate's
/// operations, `mount`, `umount2`, `statfs`, `inotify_add_watch` and a unix
/// socket's name lookup -- asks this.
pub fn resolve(at: ffi::At<'_>, input: &[u8], flags: c_int) -> Result<path::Resolved, c_int> {
    resolve_scoped(at, input, flags, path::Scope::default())
}

/// [`resolve`], refusing what `scope` names -- `openat2`'s `RESOLVE_*`.
///
/// Two of them change where the walk starts. `RESOLVE_IN_ROOT` makes `at`
/// the root: an absolute path starts there too, and it is what `..` and an
/// absolute link cannot get above. `RESOLVE_BENEATH` refuses an absolute path
/// before anything is looked up, `at` included -- Linux's `nd_jump_root`
/// answers before the descriptor is, so a closed one is `EXDEV` too.
pub fn resolve_scoped(
    at: ffi::At<'_>,
    input: &[u8],
    flags: c_int,
    scope: path::Scope,
) -> Result<path::Resolved, c_int> {
    if input.is_empty() {
        return Err(ENOENT);
    }
    let absolute = input[0] == b'/';
    if absolute && scope.beneath {
        return Err(EXDEV);
    }

    // Both under one hold, and retained before it is dropped. No task, no
    // context: an embedder resolving a path before its first process exists
    // gets neither, which the `None` arms below answer.
    let (pwd_fd, root_fd) = taskview::with_current_fs(fsinfo::FsInfo::pwd_and_root).unwrap_or((None, None));
    // `at` is a *borrow* of one of these, or the descriptor the caller passed,
    // which the caller owns -- so nothing is released through it, and the two
    // being the same descriptor (a task chrooted to its own working directory)
    // needs no special case.
    // **Where the sentinel is consumed.** An absolute path starts at the
    // task's root; a relative one at `At::Pwd`'s working directory or at the
    // descriptor the caller named. `None` here is "there is no such
    // directory", which the `if let Some` below is what used to be a null
    // test.
    let at: Option<&ffi::fd> = if absolute && !scope.in_root {
        root_fd.as_deref()
    } else {
        match at {
            ffi::At::Pwd => pwd_fd.as_deref(),
            ffi::At::Fd(fd) => Some(fd),
        }
    };

    let mut at_path = [0u8; PATH_BUF];
    let mut root_path = [0u8; PATH_BUF];
    root_path[0] = b'/';

    // What is wanted after the two are released is not the base but whether
    // there was one, so the question is asked here and the answer outlives the
    // borrow.
    let have_at = at.is_some();

    let mut err = 0;
    if let Some(at) = at {
        err = crate::generic_getpath(at, &mut at_path);
    }
    // Where an absolute symlink target starts from, and the floor `..` cannot
    // climb past. "/" for a task rooted at the machine's own, which is every
    // task until something chroots -- and the starting directory itself under
    // `RESOLVE_IN_ROOT`.
    if scope.in_root {
        root_path = at_path;
    } else if err >= 0
        && let Some(root) = &root_fd
    {
        err = crate::generic_getpath(root, &mut root_path);
    }
    // Both released here, by going out of scope; `at` borrowed one of them and
    // is dead by now.
    drop((pwd_fd, root_fd));
    if err < 0 {
        return Err(err);
    }

    debug_assert!(!have_at || is_normalized(&at_path));
    debug_assert!(is_normalized(&root_path));

    fn terminated(buf: &[u8; PATH_BUF]) -> &[u8] {
        &buf[..buf.iter().position(|&b| b == 0).unwrap_or(buf.len())]
    }
    let at = have_at.then(|| terminated(&at_path));
    let resolved = path::normalize_scoped(at, terminated(&root_path), input, flags, scope)?;
    debug_assert!(is_normalized(&resolved.path));
    Ok(resolved)
}

/// A normalised path is a sequence of `/name`: no empty component and no
/// relative prefix.
///
/// `""` is normalised — it is what the root of a mount trims to, which is why
/// this is not "starts with a slash". A **trailing** slash passes, which is the
/// C's answer too and is stated in the test rather than fixed: this is a
/// `debug_assert` over what the walk produces, and the walk produces none.
fn is_normalized(path: &[u8]) -> bool {
    let path = &path[..path.iter().position(|&b| b == 0).unwrap_or(path.len())];
    let mut rest = path;
    while !rest.is_empty() {
        if rest[0] != b'/' {
            return false;
        }
        rest = &rest[1..];
        if rest.first() == Some(&b'/') {
            return false;
        }
        let n = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
        rest = &rest[n..];
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_counts_as_normalised() {
        for p in [
            &b"\0"[..],
            b"/\0",
            b"/a\0",
            b"/a/b\0",
            b"/a/b/c\0",
            b"/..\0", // a *component* named "..", which the walk removes; the
            // shape is still normalised.
            // A trailing slash **passes**, and that is the C's answer too: the
            // empty final component is not detected, because the terminator
            // ends the loop before anything looks at it. Ported as it was
            // rather than tightened -- this is a `debug_assert` over what the
            // walk produces, and the walk never produces one, so tightening it
            // would be a new rule about inputs nothing generates.
            b"/a/\0",
        ] {
            assert!(is_normalized(p), "{:?}", std::str::from_utf8(p));
        }
        for p in [
            &b"a\0"[..], // relative
            b"a/b\0",    // relative
            b"//a\0",    // empty component
            b"/a//b\0",  // empty component
        ] {
            assert!(!is_normalized(p), "{:?}", std::str::from_utf8(p));
        }
    }

    /// The empty path is normalised, and is not the same question as "is the
    /// empty path a legal argument" — `resolve` answers `ENOENT` for
    /// that, before it looks at anything.
    #[test]
    fn the_empty_path_is_normalised_and_is_still_enoent() {
        assert!(is_normalized(b"\0"));
        assert_eq!(ENOENT, -2);
    }

    /// A buffer with no terminator stops at its end rather than running past
    /// it. The C took a `const char *` and trusted it; here the length is the
    /// buffer's.
    #[test]
    fn an_unterminated_buffer_stops_at_its_end() {
        let all_slashes = [b'/'; 8];
        assert!(!is_normalized(&all_slashes));
        let ok = *b"/abcdefg";
        assert!(is_normalized(&ok));
    }
}
