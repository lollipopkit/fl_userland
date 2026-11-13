//! `st_dev` tells mounts apart, and a file's `stat` and `fstat` agree on it.
//!
//! Every mount reported the host's device until 2026-10-18, and the root,
//! `/dev` and `/dev/shm` are directories on one host disk -- so `df /tmp`
//! named `/dev/shm`, and `find -xdev`, `du -x` and `cp -x` crossed mounts
//! they were told not to.

use std::os::unix::fs::MetadataExt;

use guest_tests::{Harness, check};

fn dev(path: &str) -> u64 {
    std::fs::metadata(path).map_or(0, |m| m.dev())
}

fn main() {
    let mut h = Harness::new();

    h.group("each-mount-has-its-own-device");
    let mounts = ["/", "/proc", "/dev", "/dev/shm"];
    let devs: Vec<u64> = mounts.iter().map(|m| dev(m)).collect();
    for (i, a) in mounts.iter().enumerate() {
        for (j, b) in mounts.iter().enumerate().skip(i + 1) {
            check!(h, devs[i] != devs[j], "{a} and {b}: both {:#x}", devs[i]);
        }
    }

    h.group("a-directory-shares-its-mounts-device");
    check!(h, dev("/tmp") == dev("/"), "/tmp {:#x}, / {:#x}", dev("/tmp"), dev("/"));

    h.group("stat-and-fstat-agree");
    for path in ["/tmp", "/proc/self/status", "/dev/shm"] {
        let by_path = dev(path);
        let by_fd = std::fs::File::open(path).and_then(|f| f.metadata()).map_or(1, |m| m.dev());
        check!(h, by_path == by_fd, "{path}: stat {by_path:#x}, fstat {by_fd:#x}");
    }

    std::process::exit(h.finish());
}
