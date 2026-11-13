//! devpts: the filesystem behind `/dev/pts`.
//!
//! One directory of character devices, one per pty slave, named by number.
//! The ptys themselves and the table holding them stay in `fs/pty.c`, which
//! owns `ttys_lock`; this reaches them through the `pty_slave_*` accessors,
//! each of which completes under that lock.
//!
//! Not holding the lock across a decision is what closes the window
//! `devpts_stat_num` had: it checked that a pty existed, dropped the lock,
//! took it again, and asserted the pty was still there.

#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

use std::ffi::CStr;

use libc::{c_char, c_int};

use guest_errno::Errno;
use guest_errno::c_int_::{EINVAL, ENOENT, ENOTDIR, EROFS};

const S_IFDIR: u32 = 0o040000;
const S_IFCHR: u32 = 0o020000;

/// From `fs/devices.h`. A `#define`, so not in the bindings.
const TTY_PSEUDO_SLAVE_MAJOR: u32 = 136;

/// What a path in this filesystem names.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum Node {
    /// The mount point itself.
    Root,
    /// `/N`, for a pty that exists.
    Pty(i32),
}

impl Node {
    /// Inode numbers. The root is 1; ptys start at 3, leaving 2 unused, which
    /// is what the C did and what any `/dev/pts` on disk already reports.
    fn inode(self) -> u64 {
        match self {
            Node::Root => 1,
            Node::Pty(n) => n as u64 + 3,
        }
    }
}

/// Parse a mount-relative path into a pty number, without consulting the
/// table. `Ok(None)` is the mount point itself.
///
/// Separate from [`resolve`] so it can be tested: the table lives in C, and a
/// unit test has no emulator to ask.
fn parse_path(path: &[u8]) -> Result<Option<i32>, c_int> {
    if path.is_empty() {
        return Ok(None);
    }
    // One component, which had better be a number.
    let Some(name) = path.strip_prefix(b"/") else {
        return Err(ENOENT);
    };
    if name.is_empty() || name.contains(&b'/') {
        return Err(ENOENT);
    }
    if !name.iter().all(|b| b.is_ascii_digit()) {
        return Err(ENOENT);
    }
    // Parsed as i64 first: a run of digits can be longer than any pty number,
    // and the C reached for atol specifically because atoi could not say so.
    let num: i64 = std::str::from_utf8(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(ENOENT)?;
    if num < 0 || num > i32::MAX as i64 {
        return Err(ENOENT);
    }
    Ok(Some(num as i32))
}

/// Resolve a mount-relative path to a node that exists.
///
/// The C returned this as an `int` that was a pty number, -1 for the root, or
/// a negative errno, with a comment noting it was "lucky that ENOENT is -2 and
/// not -1". A pty number and an error are different things.
fn resolve(path: &[u8]) -> Result<Node, c_int> {
    match parse_path(path)? {
        None => Ok(Node::Root),
        Some(num) if fs_tty::abi::pty_slave_exists(num) => Ok(Node::Pty(num)),
        Some(_) => Err(ENOENT),
    }
}

/// The per-fd state: which node this descriptor was opened on.
///
/// `struct fd` used to carry a `devpts` union member holding an `int`. It is
/// behind `fs_data` now, like every other filesystem's.
struct DevptsFd {
    /// Which node this descriptor was opened on. Written by `devpts_open`
    /// before the descriptor is reachable and read-only afterwards.
    node: Node,
    /// `readdir` cursor: the next pty number to consider.
    ///
    /// **Behind a lock**, and it was a plain `i32` handed out through a
    /// `&mut DevptsFd` until 2026-09-14. `sys_getdents64` takes no `fd->lock`,
    /// so two threads listing one `/dev/pts` descriptor -- by `dup`, or by
    /// `CLONE_FILES`, which every pthread is -- held two live `&mut` to this
    /// object and raced on the cursor. `crates/fs/proc` had the same shape
    /// with a `Vec` in it and aborted the emulator;
    /// `tests/guest/src/bin/proc_read_race.rs` is that one. Here the damage is
    /// a listing that skips or repeats, which is smaller and is the same bug.
    next: std::sync::Mutex<i32>,
}

/// # Safety
/// `fd` must be a live descriptor this filesystem opened.
fn state(fd: &ffi::fd) -> Option<&DevptsFd> {
    fd.fs_data::<DevptsFd>()
}

// `cstr(p: *const c_char) -> &'a [u8]` was here until 2026-09-14, as it was in
// `fs/proc` and `fs/tmpfs` -- three copies of a `CStr::from_ptr` with an
// unbounded lifetime and a null guard. `FsOps` hands over a `&CStr` now.

fn fill_stat(node: Node, out: &mut ffi::statbuf) -> c_int {
    let stat = &mut *out;
    *stat = ffi::statbuf::default();
    stat.inode = node.inode();
    match node {
        Node::Root => {
            stat.mode = S_IFDIR | 0o755;
            stat.nlink = 2;
            0
        }
        Node::Pty(num) => {
            // `None`: gone between resolving and asking. The C asserted here.
            let Some((uid, gid, perms)) = fs_tty::abi::pty_slave_info(num) else {
                return ENOENT;
            };
            stat.mode = S_IFCHR | perms;
            stat.uid = uid;
            stat.gid = gid;
            stat.nlink = 1;
            stat.rdev = dev_make(TTY_PSEUDO_SLAVE_MAJOR, num as u32);
            0
        }
    }
}

/// One definition, in `crates/fs/devices`: there were four hand-copies of this
/// `static inline` and one of them had the wrong encoding.
fn dev_make(major: u32, minor: u32) -> u64 {
    u64::from(fs_devices::dev_make(major, minor))
}

fn apply_attr(node: Node, attr: ffi::Attr) -> c_int {
    let Node::Pty(num) = node else {
        // Nothing about the mount point is settable.
        return EROFS;
    };
    let (which, value) = match attr {
        ffi::Attr::Uid(uid) => (ffi::PTY_ATTR_UID, uid),
        ffi::Attr::Gid(gid) => (ffi::PTY_ATTR_GID, gid),
        ffi::Attr::Mode(mode) => (ffi::PTY_ATTR_MODE, u32::from(mode) & 0o7777),
        // A character device has no size to set.
        ffi::Attr::Size(_) => return EINVAL,
    };
    if fs_tty::abi::pty_slave_set(num, which as c_int, value) {
        0
    } else {
        ENOENT
    }
}

// ============================================================
// fs_ops
// ============================================================

fn devpts_open(_mount: &ffi::mount,
    path: &CStr,
    _flags: c_int,
    _mode: c_int,
) -> Result<Box<ffi::fd>, Errno> {
    let node = resolve(path.to_bytes()).map_err(Errno::from_negative_or_eio)?;
    let fd = Box::new(ffi::fd::with_ops(Some(&DEVPTS_FDOPS)));
    fd.set_fs_data(DevptsFd {
        node,
        next: std::sync::Mutex::new(0),
    });
    Ok(fd)
}

fn devpts_getpath(fd: &ffi::fd, buf: &mut [u8]) -> c_int {
    let Some(state) = state(fd) else {
        return EINVAL;
    };
    let path = match state.node {
        Node::Root => String::new(),
        Node::Pty(num) => format!("/{num}"),
    };
    ffi::fill_path(buf, path.as_bytes())
}

fn devpts_stat(_mount: &ffi::mount, path: &CStr) -> Result<ffi::statbuf, c_int> {
    let node = resolve(path.to_bytes())?;
    let mut stat = ffi::statbuf::default();
    match fill_stat(node, &mut stat) {
        0 => Ok(stat),
        e => Err(e),
    }
}

fn devpts_fstat(fd: &ffi::fd) -> Result<ffi::statbuf, c_int> {
    let Some(s) = state(fd) else {
        return Err(EINVAL);
    };
    let mut stat = ffi::statbuf::default();
    match fill_stat(s.node, &mut stat) {
        0 => Ok(stat),
        e => Err(e),
    }
}

fn devpts_setattr(_mount: &ffi::mount,
    path: &CStr,
    attr: ffi::Attr,
) -> c_int {
    // The result is returned, not discarded: the C called through and then
    // `return 0`, so chmod on the mount point reported success where it should
    // have said EROFS.
    match resolve(path.to_bytes()) {
        Ok(node) => apply_attr(node, attr),
        Err(e) => e,
    }
}

fn devpts_fsetattr(fd: &ffi::fd, attr: ffi::Attr) -> c_int {
    match state(fd) {
        Some(s) => apply_attr(s.node, attr),
        None => EINVAL,
    }
}

fn devpts_readdir(fd: &ffi::fd) -> Result<Option<ffi::dir_entry>, c_int> {
    let Some(state) = state(fd) else {
        return Err(EINVAL);
    };
    if state.node != Node::Root {
        // The C asserted this. There is nothing to list but the root, but a
        // guest can ask, and an assert is not an answer.
        return Err(ENOTDIR);
    }

    // One call per entry, each scanning under a single hold of the lock. The C
    // took and released it once per number — 4096 times to list a directory
    // with two entries in it.
    let mut next = state.next.lock().unwrap_or_else(|p| p.into_inner());
    let num = fs_tty::abi::pty_slave_next(*next);
    if num < 0 {
        return Ok(None);
    }
    *next = num + 1;
    drop(next);

    let name = format!("{num}");
    let mut entry = ffi::dir_entry::default();
    if name.len() >= entry.name.len() {
        // A pty number too long to name. Not an error and not an entry: the
        // listing simply ends, which is what `0` said.
        return Ok(None);
    }
    entry.inode = Node::Pty(num).inode();
    entry.type_ = 2; // DT_CHR: everything this lists is a pty
    for (slot, byte) in entry.name.iter_mut().zip(name.bytes()) {
        *slot = byte as c_char;
    }
    entry.name[name.len()] = 0;
    Ok(Some(entry))
}

// ============================================================
// The tables
// ============================================================

/// A `/dev/pts` descriptor, which is only ever the directory itself: the slave
/// nodes in it are opened through `crates/fs/devices`.
///
/// Two operations, where the table this replaced had to write `None` thirteen
/// times to say so.
struct DevptsDriver;

static DEVPTS_FDOPS: DevptsDriver = DevptsDriver;

impl ffi::FdOps for DevptsDriver {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::NONE
    }
    fn readdir(&self, fd: &ffi::fd) -> Result<Option<ffi::dir_entry>, c_int> {
        devpts_readdir(fd)
    }
}

/// devpts: one directory of pty slaves, nothing that makes or removes names.
///
/// Seven operations out of twenty-three. The other sixteen are the trait's
/// defaults — which used to be sixteen `None`s here and an errno chosen at
/// each call site — and they are the right ones: `_EPERM` for everything that
/// would create or rename, since only opening `/dev/ptmx` makes a pty.
///
/// **No extended attributes.** Linux's devpts and procfs have none either, and
/// the default is `_EOPNOTSUPP`: "this filesystem does not support extended
/// attributes", which is a different answer from the `_EPERM` a namespace rule
/// gives.
pub struct Devptsfs;

impl ffi::FsOps for Devptsfs {
    fn name(&self) -> Option<&'static CStr> {
        Some(c"devpts")
    }
    fn magic(&self) -> u32 {
        0x1cd1
    }
    fn open(&self,
        mount: &ffi::mount,
        path: &CStr,
        flags: c_int,
        mode: c_int,
    ) -> Result<Box<ffi::fd>, Errno> {
        devpts_open(mount, path, flags, mode)
    }
    fn stat(
        &self,
        mount: &ffi::mount,
        path: &CStr,
    ) -> Option<Result<ffi::statbuf, c_int>> {
        Some(devpts_stat(mount, path))
    }
    fn fstat(&self, fd: &ffi::fd) -> Option<Result<ffi::statbuf, c_int>> {
        Some(devpts_fstat(fd))
    }
    fn setattr(&self,
        mount: &ffi::mount,
        path: &CStr,
        attr: ffi::Attr,
    ) -> c_int {
        devpts_setattr(mount, path, attr)
    }
    fn fsetattr(&self, fd: &ffi::fd, attr: ffi::Attr) -> c_int {
        devpts_fsetattr(fd, attr)
    }
    fn getpath(&self, fd: &ffi::fd, buf: &mut [u8]) -> c_int {
        devpts_getpath(fd, buf)
    }
}

/// The filesystem, and `iul.h`'s `extern const struct fs_ops devptsfs`.
#[unsafe(no_mangle)]
pub static devptsfs: ffi::FsHandle = ffi::FsHandle(&Devptsfs);

#[cfg(test)]
mod tests {
    use super::*;

    // parse_path does not consult the table, so it can be tested without an
    // emulator around it; resolve() adds only the existence check.

    #[test]
    fn the_empty_path_is_the_root() {
        assert_eq!(parse_path(b""), Ok(None));
    }

    #[test]
    fn anything_that_is_not_one_number_is_enoent() {
        for path in [
            &b"noslash"[..],          // no leading slash
            b"/",                     // empty component
            b"/a",                    // not a number
            b"/1/2",                  // two components
            b"/1a",                   // trailing junk
            b"/-1",                   // the minus is not a digit
            b"/99999999999999999999", // longer than any integer
        ] {
            assert_eq!(parse_path(path), Err(ENOENT), "{path:?}");
        }
    }

    #[test]
    fn inode_numbers_do_not_collide_with_the_root() {
        assert_eq!(Node::Root.inode(), 1);
        assert_eq!(Node::Pty(0).inode(), 3);
        assert_ne!(Node::Pty(0).inode(), Node::Root.inode());
    }

    #[test]
    fn dev_make_packs_the_way_dev_h_does() {
        // major 136 is TTY_PSEUDO_SLAVE_MAJOR; minor is the pty number.
        assert_eq!(dev_make(136, 0), 136 << 8);
        assert_eq!(dev_make(136, 5), (136 << 8) | 5);
    }
}
