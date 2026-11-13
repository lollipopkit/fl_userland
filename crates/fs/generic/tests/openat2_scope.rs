//! `openat2`'s `RESOLVE_*` refusals, enforced by the walk, against a mounted
//! root: `generic_openat2` with each `Scope` flag tried on the escape it
//! exists to stop and on the ordinary path it must still allow.
//!
//! The guest-side half is `tests/guest/src/bin/fs_at_calls.rs`, which measures
//! the same rules through the syscall on realfs and fakefs; this is the half a
//! `cargo test` runs. A test binary of its own, because `become_first_process`
//! is process-wide.

use iul as _;
use asbestos_gadgets as _;

use std::ffi::{CStr, CString, c_int};

use fs_generic::{OpenHow, generic_openat2};
use taskview::ffi;

fn open(name: &CStr, flags: c_int, scope: path::Scope) -> Result<(), i32> {
    match generic_openat2(ffi::At::Pwd, name, flags, 0, OpenHow { scope, ..OpenHow::default() }) {
        Ok(fd) => {
            drop(fd);
            Ok(())
        }
        Err(e) => Err(e.as_c_int()),
    }
}

#[test]
fn each_resolve_flag_refuses_its_escape() {
    let root = std::env::temp_dir().join(format!("iul-openat2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("jail/sub")).unwrap();
    std::fs::write(root.join("jail/f"), b"").unwrap();
    std::fs::write(root.join("outside"), b"").unwrap();
    std::os::unix::fs::symlink("sub", root.join("jail/rel")).unwrap();
    std::os::unix::fs::symlink("..", root.join("jail/up")).unwrap();
    std::os::unix::fs::symlink("/f", root.join("jail/abs")).unwrap();

    let source = CString::new(root.to_str().unwrap()).unwrap();
    // SAFETY: `realfs` is a static table and `source` a NUL-terminated path.
    assert_eq!(unsafe { kernel_boot::mount_root(&realfs::realfs, source.as_ptr()) }, 0);
    assert_eq!(kernel_boot::become_first_process(), 0);
    // Relative paths below start in the jail.
    let jail = fs_generic::generic_openat(ffi::At::Pwd, c"/jail", ffi::O_RDONLY_ as c_int, 0).unwrap();
    taskview::with_current_fs(|fs| fs.chdir(jail)).unwrap();

    let none = path::Scope::default();
    let beneath = path::Scope { beneath: true, ..none };
    let in_root = path::Scope { in_root: true, ..none };
    let no_symlinks = path::Scope { no_symlinks: true, ..none };
    const EXDEV: i32 = -18;
    const ENOENT: i32 = -2;
    const ELOOP: i32 = -40;
    let rd = ffi::O_RDONLY_ as c_int;

    assert_eq!(open(c"up/outside", rd, none), Ok(()), "without a flag the link climbs");
    assert_eq!(open(c"up/outside", rd, beneath), Err(EXDEV));
    assert_eq!(open(c"../outside", rd, beneath), Err(EXDEV));
    assert_eq!(open(c"/outside", rd, beneath), Err(EXDEV));
    assert_eq!(open(c"abs", rd, beneath), Err(EXDEV), "an absolute link");
    assert_eq!(open(c"rel/../f", rd, beneath), Ok(()));
    assert_eq!(open(c"missing/../f", rd, none), Err(ENOENT), "a missing name before ..");

    assert_eq!(open(c"abs", rd, none), Err(ENOENT), "/f is not at the machine's root");
    assert_eq!(open(c"abs", rd, in_root), Ok(()), "and is at the jail's");
    assert_eq!(open(c"/f", rd, in_root), Ok(()));
    assert_eq!(open(c"up/outside", rd, in_root), Err(ENOENT), ".. stops at the jail");

    assert_eq!(open(c"rel", rd, no_symlinks), Err(ELOOP));
    let path_nofollow = (ffi::O_PATH_ | ffi::O_NOFOLLOW_) as c_int;
    assert_eq!(open(c"rel", path_nofollow, no_symlinks), Ok(()), "the link itself");

    let _ = std::fs::remove_dir_all(&root);
}
