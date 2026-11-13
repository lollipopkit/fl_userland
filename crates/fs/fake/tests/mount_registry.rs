//! A bind mount goes to the fakefs that owns its path, not the last one
//! mounted.
//!
//! **What this is the reproducer for.** `crates/fs/fake` kept `FAKEFS_MOUNT`,
//! one `Mutex<Option<MountId>>` slot that `fakefs_rs_mount` wrote
//! unconditionally, so every fakefs mounted after the first replaced what
//! `fakefs_rs_mount_info` reported — and that is where `fakefs_bind_mount`
//! took its root descriptor and its `meta.db` handle. An embedder's bind mount
//! therefore landed in whichever fakefs was mounted last. Fixed 2026-09-16;
//!
//! **It was the ordinary case rather than an edge.** `crates/tools/iul`'s
//! `mount_shm` mounts a fakefs at `/dev/shm` on every boot and `-r` mounts
//! another at `/dev`, so a CLI run has two or three.
//! `crates/fs/fake/tests/bind_mounts.rs` mounts exactly one, which is why it
//! never saw this — and why the second mount below is the whole point of this
//! file.
//!
//! Its own test binary: `become_first_process` is process-wide and cargo runs
//! a crate's tests as threads of one process, so this cannot share with
//! `bind_mounts.rs`.

// The product, so the gadget archive's crypto helpers and the boot path
// resolve. See `bind_mounts.rs` for why a `tests/` binary and not a
// `#[cfg(test)] mod`.
use asbestos_gadgets as _;
use iul as _;

use fs_fake::{fakefs, fakefs_bind_mount};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use taskview::ffi;

/// An empty fakefs: a `data/` directory and a `meta.db` beside it.
///
/// What `crates/tools/fakefsify` makes from a tarball, minus the tarball —
/// fakefs stores the root as the empty blob and nothing else is needed here.
fn make_fakefs(base: &Path) -> PathBuf {
    let data = base.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let c = CString::new(base.to_str().unwrap()).unwrap();
    assert_eq!(fakedb::db::create_at(&c), Ok(()));
    data
}

fn bind(guest: &str, host: &Path) -> i32 {
    let g = CString::new(guest).unwrap();
    let h = CString::new(host.to_str().unwrap()).unwrap();
    // SAFETY: two NUL-terminated paths.
    unsafe { fakefs_bind_mount(g.as_ptr(), h.as_ptr(), false) }
}

/// `fakefs_bind_mount` writes its mount point into the **root's** fakefs,
/// whatever else is mounted.
///
/// The mount point is a symlink in the fakefs `data/` directory, named after
/// the guest path with its leading `/` stripped, so the check is which
/// directory it appeared in.
#[test]
fn a_bind_mount_lands_in_the_root_fakefs_not_the_last_one_mounted() {
    let base = std::env::temp_dir().join(format!("iul-fakefs-registry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let root = base.join("root");
    let second = base.join("second");
    let host_a = base.join("host-a");
    let host_b = base.join("host-b");
    std::fs::create_dir_all(&host_a).unwrap();
    std::fs::create_dir_all(&host_b).unwrap();
    let root_data = make_fakefs(&root);
    let second_data = make_fakefs(&second);

    let root_c = CString::new(root_data.to_str().unwrap()).unwrap();
    // SAFETY: `fakefs` is a static table and the path is NUL-terminated.
    assert_eq!(
        unsafe { kernel_boot::mount_root(&fakefs, root_c.as_ptr()) },
        0
    );
    assert_eq!(kernel_boot::become_first_process(), 0);

    // The control: with one fakefs mounted this is what `bind_mounts.rs`
    // already covers, and it has to keep working.
    assert_eq!(bind("/bound-a", &host_a), 0);
    assert!(
        root_data.join("bound-a").symlink_metadata().is_ok(),
        "the mount point should be in the root fakefs with only one mounted"
    );

    // Now a second fakefs, exactly as `mount_shm` does at boot.
    fs_generic::mkdir_at(ffi::At::Pwd, c"/second", 0o755);
    let source = CString::new(second_data.to_str().unwrap()).unwrap();
    let err = fs_mount::mount(fakefs.0, &source, c"/second", c"", 0);
    assert_eq!(err, Ok(()), "the second fakefs did not mount");

    // The subject. The root is still the root and the bind is at an absolute
    // guest path that has nothing to do with `/second`, so the fakefs that
    // owns it is the root's.
    assert_eq!(bind("/bound-b", &host_b), 0);
    assert!(
        root_data.join("bound-b").symlink_metadata().is_ok(),
        "the mount point went to the last fakefs mounted, not the root: \
         {} exists = {}",
        second_data.join("bound-b").display(),
        second_data.join("bound-b").symlink_metadata().is_ok()
    );

    let _ = std::fs::remove_dir_all(&base);
}
