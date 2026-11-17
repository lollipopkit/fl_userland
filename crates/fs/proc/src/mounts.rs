//! `/proc/mounts` and `/proc/<pid>/mountinfo` formatting.

use super::*;

/// The filesystem's name, as `/proc/mounts` and `/proc/<pid>/mountinfo` print
/// it in the `fstype` column.
///
/// Empty for a filesystem that has none, which is what the ad-hoc mounts
/// behind pipes, sockets and anonymous inodes answer. None of them is ever in
/// the mount table, so this reads as a guard rather than a case — it was a
/// `cstr()` over a `name` field that those filesystems left null, and that
/// answered the same empty slice.
fn fs_name(mount: &ffi::mount) -> &'static [u8] {
    match mount.fs.and_then(|fs| fs.name()) {
        Some(name) => name.to_bytes(),
        None => b"",
    }
}

/// `\t`, ` ` and `\\` are the separators of the mounts format, so a path
/// containing one is escaped rather than allowed to split a field.
pub(crate) fn escaped(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        match b {
            b'\t' | b' ' | b'\\' => s += &format!("\\{b:03o}"),
            _ => s.push(b as char),
        }
    }
    s
}

/// The mount table `/proc/<pid>/mounts` lists: the task's namespace's. The
/// ones at the top of `/proc` are the reader's, as `self/mounts` is.
///
/// The namespaces are cloned under `pids_lock` and the guard is dropped
/// before the table is read: the task can exit meanwhile, and then this
/// reader holds the last reference, so it -- and any filesystem teardown it
/// leads to -- must drop without the lock (`map` consumes `found` first).
fn with_table<T>(e: &mut ffi::proc_entry, f: impl FnOnce(&[&ffi::mount]) -> T) -> T {
    let theirs = (e.pid != 0)
        .then(|| crate::pidsnap::Found::get(e).map(|found| found.task().task().nsproxy()))
        .flatten();
    match theirs {
        Some(ns) => fs_mounttable::with_mounts_in(&fs_mounttable::mounts_of(&ns.mnt), f),
        None => fs_mounttable::with_mounts(f),
    }
}

pub(crate) fn proc_mounts_show(e: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    let mut s = String::new();
    // The table is crates/fs/mounttable and it owns its own lock, held across
    // the whole walk -- so the listing is one snapshot and, more importantly,
    // a mount this is halfway through formatting cannot be freed under it.
    //
    // The first version of this took the mounts one at a time by index, on the
    // reasoning that each was "read and used inside one acquisition". It was
    // read inside and *used* outside: `mount_race` aborted on a null
    // dereference within seconds. Holding it across the walk is what the C list
    // walk did and is the reason that one was safe.
    with_table(e, |mounts| {
        for mount in mounts {
            let point = mount.point.to_bytes();
            let point: &[u8] = if point.is_empty() { b"/" } else { point };
            s += &escaped(mount.source.to_bytes());
            s.push(' ');
            s += &escaped(point);
            s.push(' ');
            s += &String::from_utf8_lossy(fs_name(mount));
            s.push(' ');

            let flags = mount.flags as u32;
            let mut opts = vec![
                if flags & ffi::MS_READONLY_ != 0 {
                    "ro"
                } else {
                    "rw"
                }
                .to_string(),
            ];
            if flags & ffi::MS_NOSUID_ != 0 {
                opts.push("nosuid".into());
            }
            if flags & ffi::MS_NODEV_ != 0 {
                opts.push("nodev".into());
            }
            if flags & ffi::MS_NOEXEC_ != 0 {
                opts.push("noexec".into());
            }
            let info = mount.info.to_bytes();
            if !info.is_empty() {
                opts.push(String::from_utf8_lossy(info).into_owned());
            }
            s += &opts.join(",");
            s += " 0 0\n";
        }
    });
    out(buf, &s);
    0
}

/// `/proc/<pid>/mountinfo`, and the root's own.
///
/// The format `findmnt`, `df`, systemd and every container runtime read, and
/// the reason they prefer it to `/proc/mounts`: it carries the mount **id** and
/// the id of the mount it is under, so a caller can tell one mount of a
/// filesystem from another and see the tree rather than a list.
///
/// ```text
/// 36 35 98:0 / /mnt rw,noatime - ext3 /dev/root rw
/// (1)(2)(3) (4)(5)   (6)     (7)(8)     (9)     (10)
/// ```
///
/// 1 is the mount id, 2 its parent's, 3 the device, 4 the subtree of the
/// filesystem that is mounted -- always `/` here, since this kernel has no
/// bind mount of a subtree at the VFS level -- 5 the mount point, 6 the
/// options, 7 the optional fields (none, and the `-` that ends them is
/// mandatory), 8 the filesystem type, 9 the source and 10 the super options.
///
/// The **parent** is the mount whose point is the longest proper prefix of
/// this one's, which is the same rule `crates/fs/mounttable` uses to decide
/// which mount owns a path. The root is its own parent, as Linux's is.
pub(crate) fn proc_mountinfo_show(
    e: &mut ffi::proc_entry,
    buf: &mut ffi::proc_data,
) -> c_int {
    // One acquisition for the whole walk; see proc_mounts_show for why. What
    // is read out of each mount is copied into a `Mount` here, so the
    // formatting below is a pure function of plain values and can be tested
    // without a mount table.
    let rows: Vec<MountRow> = with_table(e, |mounts| {
        mounts
            .iter()
            .map(|mount| {
                let point = mount.point.to_bytes();
                // The device every file on this mount reports, from the one
                // place `stat` takes it: a mount that reports one `st_dev`
                // for its files and another here makes `df` attribute a
                // file to the wrong line.
                let dev = mount.dev() as u32;
                MountRow {
                    id: mount.id,
                    point: if point.is_empty() { b"/".to_vec() } else { point.to_vec() },
                    source: mount.source.to_bytes().to_vec(),
                    fstype: fs_name(mount).to_vec(),
                    flags: mount.flags as u32,
                    dev,
                }
            })
            .collect()
    });
    out(buf, &mountinfo(&rows));
    0
}

/// What one line of `mountinfo` is made of, read out of a `struct mount` while
/// the table's lock is held.
pub(crate) struct MountRow {
    pub(crate) id: u32,
    pub(crate) point: Vec<u8>,
    pub(crate) source: Vec<u8>,
    pub(crate) fstype: Vec<u8>,
    pub(crate) flags: u32,
    pub(crate) dev: u32,
}

/// The whole file, as a pure function of the table.
pub(crate) fn mountinfo(rows: &[MountRow]) -> String {
    let mut s = String::new();
    for row in rows {
        let parent = parent_of(&row.point, rows).unwrap_or(row.id);
        let opts = options(row.flags);
        s += &format!(
            "{} {parent} {}:{} / {} {opts} - {} {} {opts}\n",
            row.id,
            fs_devices::dev_major(row.dev),
            fs_devices::dev_minor(row.dev),
            escaped(&row.point),
            String::from_utf8_lossy(&row.fstype),
            escaped(&row.source),
        );
    }
    s
}

/// The mount options both `/proc/mounts` and `mountinfo` print, in the order
/// Linux prints them.
pub(crate) fn options(flags: u32) -> String {
    let mut opts = vec![if flags & ffi::MS_READONLY_ != 0 {
        "ro"
    } else {
        "rw"
    }];
    for (bit, name) in [
        (ffi::MS_NOSUID_, "nosuid"),
        (ffi::MS_NODEV_, "nodev"),
        (ffi::MS_NOEXEC_, "noexec"),
    ] {
        if flags & bit != 0 {
            opts.push(name);
        }
    }
    opts.join(",")
}

/// The id of the mount `point` sits under: the longest *proper* prefix of it
/// that ends on a component boundary. `None` for the root, which has none.
pub(crate) fn parent_of(point: &[u8], all: &[MountRow]) -> Option<u32> {
    let mut best: Option<(usize, u32)> = None;
    for other in all {
        if other.point.len() >= point.len() || !point.starts_with(&other.point) {
            continue;
        }
        // "/a" is under "/", and "/ab" is not under "/a".
        let boundary = other.point == b"/" || point.get(other.point.len()) == Some(&b'/');
        if boundary && best.is_none_or(|(len, _)| other.point.len() > len) {
            best = Some((other.point.len(), other.id));
        }
    }
    best.map(|(_, id)| id)
}

