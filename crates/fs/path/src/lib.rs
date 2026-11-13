//! Guest path resolution: the walk that turns a path the guest handed us into
//! a normalized absolute one, following symlinks as it goes.
//!
//! Reading the task's filesystem state was `fs/path.c`'s until 2026-09-05, on
//! the grounds that `current` was a `__thread` variable and the descriptors
//! behind it need `fs->lock` held while retained — "neither of which stable
//! Rust can reach". Both went: `crates/fs/generic`'s `normalize` owns the walk
//! and `current` is `crates/kernel/taskview`'s `thread_local!`.
//!
//! Everything here operates on bytes. A guest path is a NUL-terminated blob
//! with no declared encoding.

#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

mod walk;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

use libc::c_int;

pub use walk::{MAX_PATH, access};

/// What `rmdir`'s last component is, before normalisation flattens it.
///
/// Linux's `do_rmdir` looks at the parsed last component and refuses three of
/// them outright:
///
/// ```c
/// switch (last_type) {
/// case LAST_DOTDOT: error = -ENOTEMPTY; goto exit3;
/// case LAST_DOT:    error = -EINVAL;    goto exit3;
/// case LAST_ROOT:   error = -EBUSY;     goto exit3;
/// }
/// ```
///
/// The check has to happen **before** the path is normalised, because that is
/// exactly what makes it invisible: `dir/.` normalises to `dir`, and this
/// kernel then removed `dir`. Measured — `rmdir("dir/.")` is `EINVAL` on a real
/// arm64 kernel and removed the directory here.
///
/// 0 fine, -22 EINVAL (`.`), -39 ENOTEMPTY (`..`), -16 EBUSY (`/`).
pub fn rmdir_last_component(path: &str) -> i32 {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return -16; // the root, however many slashes it was written with
    }
    match trimmed.rsplit('/').next() {
        Some(".") => -22,
        Some("..") => -39,
        _ => 0,
    }
}

/// [`rmdir_last_component`] for the bytes a guest wrote.
///
/// It was `path_rmdir_last_component(*const c_char)` until 2026-09-29, an
/// `unsafe fn` for the `CStr::from_ptr` its caller could do itself.
pub fn rmdir_last_component_bytes(path: &[u8]) -> i32 {
    match std::str::from_utf8(path) {
        Ok(s) => rmdir_last_component(s),
        // Not UTF-8, so it cannot be `.` or `..` either.
        Err(_) => 0,
    }
}

pub use walk::{Resolved, Scope};

/// Resolve `input` against `at`, following symlinks per `flags` -- the `N_*`
/// word the VFS passes.
///
/// `at` is the directory a relative path starts from, or `None` when there is
/// none. `root` is the task's own root: the floor `..` cannot climb past, and
/// what an absolute symlink target is resolved against. A result that would
/// not fit in `MAX_PATH` with its terminator is `ENAMETOOLONG`.
///
/// Safe, over slices. It was `path_normalize_walk`, taking three
/// `*const c_char`, an out-pointer to a `MAX_PATH` buffer and a nullable
/// `*mut c_int`, until 2026-09-29 -- a C-shaped adapter around [`walk`]'s
/// `resolve`, which never needed any of them.
pub fn normalize(
    at: Option<&[u8]>,
    root: &[u8],
    input: &[u8],
    flags: c_int,
) -> Result<Resolved, c_int> {
    normalize_scoped(at, root, input, flags, Scope::default())
}

/// [`normalize`], refusing what `scope` names: `openat2`'s `RESOLVE_*` flags.
/// Under `RESOLVE_IN_ROOT` the caller passes the starting directory as both
/// `at` and `root`.
pub fn normalize_scoped(
    at: Option<&[u8]>,
    root: &[u8],
    input: &[u8],
    flags: c_int,
    scope: Scope,
) -> Result<Resolved, c_int> {
    let follow = flags & ffi::N_SYMLINK_FOLLOW as c_int != 0;
    // Three flags rather than one, because the *existence* answer comes before
    // the permission one and that ordering is observable -- see ParentWrite.
    let parent_dir_write = if flags & ffi::N_PARENT_DIR_WRITE_CREATE as c_int != 0 {
        walk::ParentWrite::IfMissing
    } else if flags & ffi::N_PARENT_DIR_WRITE_DELETE as c_int != 0 {
        walk::ParentWrite::IfPresent
    } else if flags & ffi::N_PARENT_DIR_WRITE as c_int != 0 {
        walk::ParentWrite::Always
    } else {
        walk::ParentWrite::No
    };
    let resolved = walk::resolve(at, root, input, follow, parent_dir_write, scope)?;
    // The walk keeps its own result inside MAX_PATH; the check is here because
    // a caller copies it into a buffer of that size.
    if resolved.path.len() >= MAX_PATH {
        return Err(walk::ENAMETOOLONG);
    }
    Ok(resolved)
}

#[cfg(test)]
mod rmdir_tests {
    use super::*;

    // ------------------------------------------------- rmdir's last component

    #[test]
    fn rmdir_refuses_dot_and_dotdot() {
        // Measured: EINVAL and ENOTEMPTY on a real arm64 kernel. `dir/.`
        // normalises to `dir`, so without this check the directory was removed.
        assert_eq!(rmdir_last_component("dir/."), -22);
        assert_eq!(rmdir_last_component("."), -22);
        assert_eq!(rmdir_last_component("/a/b/."), -22);
        assert_eq!(rmdir_last_component("dir/.."), -39);
        assert_eq!(rmdir_last_component(".."), -39);
    }

    #[test]
    fn rmdir_refuses_the_root() {
        assert_eq!(rmdir_last_component("/"), -16);
        assert_eq!(rmdir_last_component("//"), -16);
        assert_eq!(rmdir_last_component(""), -16);
    }

    #[test]
    fn an_ordinary_name_is_fine() {
        assert_eq!(rmdir_last_component("dir"), 0);
        assert_eq!(rmdir_last_component("/a/b/dir"), 0);
        assert_eq!(
            rmdir_last_component("dir/"),
            0,
            "a trailing slash is not a component"
        );
        // Names that merely begin with a dot are names.
        assert_eq!(rmdir_last_component(".hidden"), 0);
        assert_eq!(rmdir_last_component("..."), 0);
        assert_eq!(rmdir_last_component("a/..b"), 0);
    }
}
