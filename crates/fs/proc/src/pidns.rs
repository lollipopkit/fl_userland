//! `/proc/<pid>/ns`: one link per namespace the task is in.
//!
//! This kernel has one namespace of each kind and every task is in it (see
//! `crates/kernel/forkcalls`' `share` module: `unshare` and `setns` refuse
//! every namespace flag), so each link reads the same for every task, and two
//! processes compare equal the way two processes in one namespace do on
//! Linux. The numbers are Linux's initial namespaces': the six fixed ones in
//! `include/linux/proc_ns.h` and, for the network and mount namespaces, which
//! Linux numbers from `proc_alloc_inum`, the first two that hands out, which
//! is what a host's own `/proc/1/ns` shows.
//!
//! Reading or following a link asks `PTRACE_MODE_READ_FSCREDS`
//! (`proc_ns_readlink`, `proc_ns_get_link`): the row's `guard`. Following one
//! opens the namespace as an `nsfs` file (`fs_adhoc::adhoc_ns`), which
//! `setns` does not accept: there is nothing to join. The directory itself is
//! `dr-x--x--x` and lists without asking, as Linux's does.

use std::ffi::{CStr, c_int};

use crate::ffi;
use crate::pidentry::ptrace_guard;
use crate::root::blank;

struct Ns {
    entry: &'static CStr,
    file: fs_adhoc::NsFile,
    inum: u64,
}

const fn ns(entry: &'static CStr, kind: &'static CStr, inum: u64) -> Ns {
    Ns { entry, file: fs_adhoc::NsFile { kind }, inum }
}

/// In `ns_entries` order, which is the order Linux lists them in.
static NAMESPACES: [Ns; 10] = [
    ns(c"net", c"net", 0xF000_0000),
    ns(c"uts", c"uts", 0xEFFF_FFFE),
    ns(c"ipc", c"ipc", 0xEFFF_FFFF),
    ns(c"pid", c"pid", 0xEFFF_FFFC),
    ns(c"pid_for_children", c"pid", 0xEFFF_FFFC),
    ns(c"user", c"user", 0xEFFF_FFFD),
    ns(c"mnt", c"mnt", 0xF000_0001),
    ns(c"cgroup", c"cgroup", 0xEFFF_FFFB),
    ns(c"time", c"time", 0xEFFF_FFFA),
    ns(c"time_for_children", c"time", 0xEFFF_FFFA),
];

fn of(entry: &ffi::proc_entry) -> Option<&'static Ns> {
    let name = entry.meta?.name?;
    NAMESPACES.iter().find(|n| n.entry == name)
}

fn ns_readlink(entry: &mut ffi::proc_entry, buf: &mut [u8]) -> c_int {
    let Some(ns) = of(entry) else {
        return guest_errno::c_int_::ENOENT;
    };
    let text = format!("{}:[{}]", ns.file.kind.to_string_lossy(), ns.inum);
    ffi::fill_path(buf, text.as_bytes())
}

fn ns_magic(entry: &mut ffi::proc_entry) -> Result<Option<ffi::FdOwned>, c_int> {
    Ok(of(entry).map(|ns| fs_adhoc::adhoc_ns(&ns.file, ns.inum)))
}

const fn link(name: &'static CStr) -> ffi::proc_dir_entry {
    ffi::proc_dir_entry {
        name: Some(name),
        mode: libc::S_IFLNK,
        readlink: Some(ns_readlink),
        magic: Some(ns_magic),
        jumps: true,
        guard: Some(ptrace_guard),
        ..blank()
    }
}

pub(crate) static NS_CHILDREN: [ffi::proc_dir_entry; 10] = [
    link(c"net"),
    link(c"uts"),
    link(c"ipc"),
    link(c"pid"),
    link(c"pid_for_children"),
    link(c"user"),
    link(c"mnt"),
    link(c"cgroup"),
    link(c"time"),
    link(c"time_for_children"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_link_has_a_namespace() {
        for (e, n) in NS_CHILDREN.iter().zip(NAMESPACES.iter()) {
            assert_eq!(e.name, Some(n.entry));
        }
    }
}
