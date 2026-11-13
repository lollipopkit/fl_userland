//! A mount's root directory descriptor is given back when it is unmounted.
//!
//! Neither realfs nor fakefs closed it until 2026-09-29: realfs has no
//! `umount`, fakefs's freed only its database, and `mount_destroy` freed the
//! struct around an `int`. So every `do_umount` of either kind left one host
//! descriptor open for the life of the process.

use std::ffi::CString;
use std::fs::File;
use std::os::fd::AsRawFd;

/// The lowest free descriptor number, which climbs if something is kept.
fn lowest_free() -> i32 {
    File::open("/dev/null").unwrap().as_raw_fd()
}

#[test]
fn unmounting_a_realfs_mount_closes_its_root() {
    let dir = std::env::temp_dir().join(format!("root-fd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = CString::new(dir.to_str().unwrap()).unwrap();
    let point = c"/root-fd-test";

    let cycle = || {
        assert_eq!(fs_mount::mount(realfs::realfs.0, &source, point, c"", 0), Ok(()));
        assert_eq!(fs_mount::umount(point), Ok(()));
    };
    // One round first, so any one-off allocation is already made.
    cycle();
    let before = lowest_free();
    for _ in 0..16 {
        cycle();
    }
    assert_eq!(lowest_free(), before, "each unmount kept a descriptor");
    std::fs::remove_dir(&dir).unwrap();
}
