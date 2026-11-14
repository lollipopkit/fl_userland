//! `/proc/<pid>/ns`: one link per namespace the task is in.
//!
//! Each reads `<kind>:[<number>]` from the task's own namespaces
//! (`crates/kernel/nsproxy`), so two tasks compare equal exactly when they
//! share one. `pid_for_children` and `time_for_children` are the task's `pid`
//! and `time` ones: neither kind can be made new here.
//!
//! Reading or following a link asks `PTRACE_MODE_READ_FSCREDS`
//! (`proc_ns_readlink`, `proc_ns_get_link`): the row's `guard`. Following one
//! opens the namespace as an `nsfs` file (`fs_adhoc::adhoc_ns`), which holds
//! the namespace and which `setns` joins. The directory itself is
//! `dr-x--x--x` and lists without asking, as Linux's does.

use std::ffi::{CStr, c_int};

use taskview::nsproxy::{Kind, Ns};

use crate::ffi;
use crate::pidentry::ptrace_guard;
use crate::pidsnap::Found;
use crate::root::blank;

/// In `ns_entries` order, which is the order Linux lists them in.
static ENTRIES: [(&CStr, Kind); 10] = [
    (c"net", Kind::Net),
    (c"uts", Kind::Uts),
    (c"ipc", Kind::Ipc),
    (c"pid", Kind::Pid),
    (c"pid_for_children", Kind::Pid),
    (c"user", Kind::User),
    (c"mnt", Kind::Mnt),
    (c"cgroup", Kind::Cgroup),
    (c"time", Kind::Time),
    (c"time_for_children", Kind::Time),
];

/// The namespace this entry's task is in; `None` for a task that is gone.
fn of(entry: &mut ffi::proc_entry) -> Option<Ns> {
    let name = entry.meta?.name?;
    let kind = ENTRIES.iter().find(|(n, _)| *n == name)?.1;
    let proxy = Found::get(entry)?.task().task().nsproxy();
    Some(proxy.get(kind))
}

fn ns_readlink(entry: &mut ffi::proc_entry, buf: &mut [u8]) -> c_int {
    let Some(ns) = of(entry) else {
        return guest_errno::c_int_::ENOENT;
    };
    let text = format!("{}:[{}]", ns.kind().name().to_string_lossy(), ns.inum());
    ffi::fill_path(buf, text.as_bytes())
}

fn ns_magic(entry: &mut ffi::proc_entry) -> Result<Option<ffi::FdOwned>, c_int> {
    Ok(of(entry).map(fs_adhoc::adhoc_ns))
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
        for (e, (n, _)) in NS_CHILDREN.iter().zip(ENTRIES.iter()) {
            assert_eq!(e.name, Some(*n));
        }
    }
}
