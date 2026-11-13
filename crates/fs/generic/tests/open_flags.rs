//! `O_DIRECTORY` and `O_NOFOLLOW`, against a mounted root.
//!
//! `tests/unit/openflags_test.c`'s four behavioural checks until 2026-09-08.
//! The flag *values* are in this crate's own `#[cfg(test)]` module, where they
//! need nothing; these need the boot path, and an **integration** test is what
//! keeps that from linking a second copy of `fs_generic` -- once with
//! `cfg(test)` and once as `kernel_boot`'s dependency. On macOS `ld` warns and
//! picks one. A `tests/` binary links the plain rlib and cargo unifies it.

// The product, so the boot path and the gadget archive resolve. `_` because
// nothing here calls it: an `--extern` nothing mentions is not loaded.
use iul as _;

use fs_generic::generic_open;
use std::ffi::c_int;
use taskview::ffi;

// -------------------------------------- and what the two checks then do
//
// These four need a mounted root, which is what kept them in
// `tests/unit/openflags_test.c`: the checks live in `generic_openat`, above
// any mount, and realfs needs no metadata database to stand up.
//
// One `#[test]`, because `become_first_process` is process-wide -- it calls
// `umask(0)` and makes the first task -- and cargo runs a crate's tests as
// threads.

/// The product, so the boot path's symbols resolve. `_` because nothing
/// here calls them: an `--extern` nothing mentions is not loaded.
use asbestos_gadgets as _;

fn open_err(path: &std::ffi::CStr, flags: c_int) -> c_int {
    // SAFETY: a NUL-terminated guest path; the descriptor is closed here.
    let fd = unsafe { generic_open(path.as_ptr(), flags, 0) };
    let err = fd as isize;
    if (-4095..0).contains(&err) {
        return err as c_int;
    }
    unsafe { fs_fdobj::fd_close(fd) };
    0
}

#[test]
fn o_directory_and_o_nofollow_are_honoured() {
    // A tree of one file, one directory and a symlink to each.
    let root = std::env::temp_dir().join(format!("iul-openflags-{}", std::process::id()));
    std::fs::create_dir_all(root.join("dir")).unwrap();
    std::fs::write(root.join("file"), b"").unwrap();
    let _ = std::os::unix::fs::symlink("file", root.join("link"));
    let _ = std::os::unix::fs::symlink("dir", root.join("dirlink"));

    let source = std::ffi::CString::new(root.to_str().unwrap()).unwrap();
    // SAFETY: `realfs` is a static table and `source` a NUL-terminated path.
    let err = unsafe { kernel_boot::mount_root(&realfs::realfs, source.as_ptr()) };
    assert_eq!(err, 0, "mount_root");
    assert_eq!(kernel_boot::become_first_process(), 0);

    let (dir, nofollow, direct) = (
        ffi::O_DIRECTORY_ as c_int,
        ffi::O_NOFOLLOW_ as c_int,
        ffi::O_DIRECT_ as c_int,
    );

    // The check the wrong constant disabled: with `O_DIRECTORY_` at 1<<16 a
    // guest asking for a directory got whatever was there.
    assert_eq!(open_err(c"/file", dir), -20, "ENOTDIR");
    assert_eq!(open_err(c"/dir", dir), 0);

    // The other half of the same bug, and the one users hit: `O_DIRECT` on
    // a regular file must open it. Nothing forwards `O_DIRECT` to the host
    // -- Darwin has no equivalent -- so all that is under test is that it
    // is not misread.
    assert_eq!(open_err(c"/file", direct), 0);

    // `O_NOFOLLOW` cannot be handed to the host `open()`: `path_normalize`
    // resolves the final component itself, so by the time any mount's
    // `open` runs the symlink is gone and the host sees the target. It has
    // to change the *resolution*, which is what makes ELOOP reachable.
    assert_eq!(open_err(c"/link", nofollow), -40, "ELOOP");
    // Without it the same path opens the target, so the check above is
    // about the flag and not about the link being broken.
    assert_eq!(open_err(c"/link", 0), 0);
    // A non-link is unaffected: `O_NOFOLLOW` is about the final component
    // being a symlink, not about refusing to resolve anything.
    assert_eq!(open_err(c"/file", nofollow), 0);

    // `O_NOFOLLOW` is checked first in Linux too: ELOOP, not ENOTDIR.
    assert_eq!(open_err(c"/dirlink", nofollow | dir), -40, "ELOOP");

    let _ = std::fs::remove_dir_all(&root);
}
