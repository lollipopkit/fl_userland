//! tmpfs: an in-memory filesystem, as a VFS mount.
//!
//! Registered in `fs/mount.c`, so a guest reaches it with `mount -t tmpfs`.
//! The two tables at the bottom are the interface; everything above them is
//! ordinary Rust.
//!
//! Paths arriving here are relative to the mount point and either empty (the
//! mount root) or leading-slash, matching what `path_next_component` in
//! `fs/path.c` consumes. Like that function, this gives `.` and `..` no special
//! meaning — the layer above resolves them.
//!
//! The C this replaces implemented eight operations. Everything else in
//! `struct fs_ops` was left null, which the VFS reports as `EPERM`, so on a
//! tmpfs mount `rm`, `rmdir`, `chmod`, `chown`, `touch`, `ln -s` and `mv` all
//! failed and `>` did not truncate. That is not a Linux tmpfs, so the table
//! below is filled in.

#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

#[path = "attrs.rs"]
mod attrs;
mod contents;
mod errno;
mod names;
use names::{
    tmpfs_link, tmpfs_mkdir, tmpfs_mknod, tmpfs_open, tmpfs_readlink, tmpfs_rename, tmpfs_rmdir,
    tmpfs_symlink, tmpfs_unlink,
};
mod lookup;
mod state;
mod tree;
#[cfg(test)]
use lookup::components;
use lookup::{lookup, lookup_parent};
mod xattr_ops;
use attrs::{tmpfs_fsetattr, tmpfs_fstat, tmpfs_setattr, tmpfs_stat, tmpfs_utime};

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

use std::sync::{Arc, Mutex, MutexGuard};

use libc::{c_char, c_int, c_uint, c_ulong, size_t, ssize_t};

use errno::{EBADF, EEXIST, EINVAL, EISDIR, ENAMETOOLONG, ENOENT, ENOTDIR, EPERM, Result};
use state::{DirPos, FdState, fd_state, mount_root, readable, writable};
mod io;
use io::{
    tmpfs_getpath, tmpfs_lseek, tmpfs_read, tmpfs_readdir, tmpfs_seekdir,
    tmpfs_pwrite, tmpfs_telldir, tmpfs_write,
};
use tree::{
    Dirent, Inode, MAX_NAME, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG,
    S_IFSOCK, Timespec, link_into, rename as tree_rename, unlink_from,
};

pub(crate) use xattr_ops::{tmpfs_fxattr, tmpfs_xattr};

/// `utimensat` reads these in `tv_nsec`.
const UTIME_NOW: i64 = 1_073_741_823;
const UTIME_OMIT: i64 = 1_073_741_822;

/// Lock without caring about poisoning: a panic while holding one of these
/// leaves the tree structurally intact, and refusing every later operation on
/// the mount would be worse than continuing.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn current_ids() -> (u32, u32) {
    taskview::current_fsids()
}

fn fill_stat(dirent: &Dirent, out: &mut ffi::statbuf) {
    let body = lock(&dirent.inode.body);
    let stat = ffi::statbuf {
        dev: 0,
        inode: dirent.inode.ino,
        mode: body.mode,
        nlink: body.nlink,
        uid: body.uid,
        gid: body.gid,
        rdev: body.rdev,
        size: body.size(),
        blksize: 4096,
        blocks: body.size().div_ceil(512),
        // The seconds are i64 and signed; a timestamp before 1970 is a
        // negative one and narrowing it to u32 made it a distant future date.
        atime: body.atime.sec,
        atime_nsec: body.atime.nsec as u32,
        mtime: body.mtime.sec,
        mtime_nsec: body.mtime.nsec as u32,
        ctime: body.ctime.sec,
        ctime_nsec: body.ctime.nsec as u32,
        // A tmpfs inode is made here, so its creation time is known exactly --
        // unlike a passthrough mount, which has to ask the host.
        btime: body.btime.sec,
        btime_nsec: body.btime.nsec as u32,
        has_btime: 1,
        // The VFS fills this in; a filesystem does not know which
        // mount it is.
        mount_id: 0,
    };
    *out = stat;
}

/// Run `op` against the mount root, flattening the result to a guest errno.
fn with_root(mount: &ffi::mount, op: impl FnOnce(&Arc<Dirent>) -> Result<()>) -> c_int {
    match mount_root(mount) {
        Some(root) => match op(root) {
            Ok(()) => 0,
            Err(e) => e,
        },
        None => EINVAL,
    }
}

// ============================================================
// fs_ops: mount lifetime
// ============================================================

fn tmpfs_mount(mount: &mut ffi::mount) -> c_int {
    let (uid, gid) = current_ids();
    let root = Dirent::new_root(Inode::new(S_IFDIR | 0o777, uid, gid, 0));
    mount.state = ffi::mount_state::Data(Box::new(root));
    0
}

fn tmpfs_umount(mount: &mut ffi::mount) -> c_int {
    // Actually frees the tree. In C both directions of the parent/child link
    // were strong references, so nothing was released and this could only be
    // a TODO.
    mount.state = ffi::mount_state::None;
    0
}

/// The capacity tmpfs reports: half of host memory, which is what Linux's
/// tmpfs defaults to, falling back to 1 GiB if the host will not say.
fn tmpfs_capacity() -> u64 {
    // SAFETY: `sysconf` reads a host property; there is no pointer.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    if pages > 0 {
        (pages as u64 / 2).saturating_mul(rustix::param::page_size() as u64)
    } else {
        1024 * 1024 * 1024
    }
}

fn tmpfs_statfs(_mount: &ffi::mount) -> ffi::statfsbuf {
    // This used to report TMPFS_MAGIC and a zeroed capacity, on the reasoning
    // that a filesystem bounded by host memory has no block count worth
    // reporting. What it produced was f_blocks of zero: `df` divides by that,
    // and a program checking for room to write is told there is none. Linux's
    // tmpfs reports half of memory and its real usage, and so does this.
    //
    // It also wrote `type_ = 0x01021994`, which is what `magic()` above
    // answers -- one number, two owners, in two files. The field is gone and
    // `magic()` is the owner; see `statfsbuf`'s comment.
    //
    // Infallible, so it answers the struct rather than a `Result`: nothing
    // here can fail, and the trait impl is the one line that says so.
    const BSIZE: u64 = 4096;
    let capacity = tmpfs_capacity();
    let used = crate::tree::TMPFS_BYTES.load(std::sync::atomic::Ordering::Relaxed);
    let free = capacity.saturating_sub(used);

    ffi::statfsbuf {
        bsize: Some(BSIZE as _),
        frsize: BSIZE as _,
        blocks: (capacity / BSIZE) as _,
        bfree: (free / BSIZE) as _,
        bavail: (free / BSIZE) as _,
        // Inodes are allocated on demand, so the count is nominal in the same
        // way the block count is. Reporting zero free would say the filesystem
        // is full.
        files: (capacity / BSIZE) as _,
        ffree: (free / BSIZE) as _,
        namelen: Some(MAX_NAME as _),
        ..Default::default()
    }
}

// ============================================================
// fs_ops: attributes
// ============================================================

// ============================================================
// Helpers
// ============================================================

pub(crate) use std::ffi::CStr;

// `cstr(p: *const c_char) -> &'a [u8]` was here until 2026-09-14, as it was in
// `fs/devpts` and `fs/proc`. `FsOps` hands over a `&CStr`.

// `err_ptr` was defined here until 2026-09-14 and then imported from
// `crates/kernel/abi` for a few hours. Neither is needed: `tmpfs_open` answers
// a `Result` and nothing else in this crate encodes an errno in a pointer.

// ============================================================
// The tables
// ============================================================


/// tmpfs: this crate's own tree, in memory.
///
/// Everything but `flock` and `inode_orphaned`. `flock` is the interesting
/// absence: it stays the trait's `None` so that `crates/kernel/fdattr` falls
/// back to `fs_locks::flock_generic`, this kernel's own implementation over
/// the descriptor — a filesystem with nothing on a host to lock does not want
/// an errno there, it wants the generic one.
pub struct Tmpfs;

impl ffi::FsOps for Tmpfs {
    fn name(&self) -> Option<&'static std::ffi::CStr> {
        Some(c"tmpfs")
    }
    fn magic(&self) -> u32 {
        0x01021994
    }
    /// A link's text is a field of its node.
    fn links_in_memory(&self) -> bool {
        true
    }

    fn mount(&self, mount: &mut ffi::mount) -> c_int {
        tmpfs_mount(mount)
    }
    fn umount(&self, mount: &mut ffi::mount) -> c_int {
        tmpfs_umount(mount)
    }
    fn statfs(&self, mount: &ffi::mount) -> std::result::Result<ffi::statfsbuf, c_int> {
        Ok(tmpfs_statfs(mount))
    }

    fn open(&self,
        mount: &ffi::mount,
        path: &CStr,
        flags: c_int,
        mode: c_int,
    ) -> std::result::Result<Box<ffi::fd>, guest_errno::Errno> {
        tmpfs_open(mount, path, flags, mode)
    }
    fn readlink(&self,
        mount: &ffi::mount,
        path: &CStr,
        buf: &mut [u8],
    ) -> isize {
        tmpfs_readlink(mount, path, buf)
    }
    fn link(&self,
        mount: &ffi::mount,
        src: &CStr,
        dst: &CStr,
    ) -> c_int {
        tmpfs_link(mount, src, dst)
    }
    fn unlink(&self, mount: &ffi::mount, path: &CStr) -> c_int {
        tmpfs_unlink(mount, path)
    }
    fn rmdir(&self, mount: &ffi::mount, path: &CStr) -> c_int {
        tmpfs_rmdir(mount, path)
    }
    fn rename(&self,
        mount: &ffi::mount,
        src: &CStr,
        dst: &CStr,
        flags: c_uint,
    ) -> c_int {
        tmpfs_rename(mount, src, dst, flags)
    }
    fn symlink(&self,
        mount: &ffi::mount,
        target: &CStr,
        link: &CStr,
    ) -> c_int {
        tmpfs_symlink(mount, target, link)
    }
    fn mknod(&self,
        mount: &ffi::mount,
        path: &CStr,
        mode: ffi::mode_t_,
        dev: ffi::dev_t_,
    ) -> c_int {
        tmpfs_mknod(mount, path, mode, dev)
    }
    fn mkdir(&self,
        mount: &ffi::mount,
        path: &CStr,
        mode: ffi::mode_t_,
    ) -> c_int {
        tmpfs_mkdir(mount, path, mode)
    }

    fn stat(
        &self,
        mount: &ffi::mount,
        path: &CStr,
    ) -> Option<std::result::Result<ffi::statbuf, c_int>> {
        Some(tmpfs_stat(mount, path))
    }
    fn fstat(&self, fd: &ffi::fd) -> Option<std::result::Result<ffi::statbuf, c_int>> {
        Some(tmpfs_fstat(fd))
    }
    fn setattr(&self,
        mount: &ffi::mount,
        path: &CStr,
        attr: ffi::Attr,
    ) -> c_int {
        tmpfs_setattr(mount, path, attr)
    }
    fn fsetattr(&self, fd: &ffi::fd, attr: ffi::Attr) -> c_int {
        tmpfs_fsetattr(fd, attr)
    }
    fn utime(&self,
        mount: &ffi::mount,
        path: &CStr,
        atime: ffi::timespec,
        mtime: ffi::timespec,
        follow_links: bool,
    ) -> c_int {
        tmpfs_utime(mount, path, atime, mtime, follow_links)
    }
    fn getpath(&self, fd: &ffi::fd, buf: &mut [u8]) -> c_int {
        tmpfs_getpath(fd, buf)
    }

    fn xattr(&self,
        mount: &ffi::mount,
        path: &CStr,
        call: ffi::XattrCall,
        follow_links: bool,
    ) -> isize {
        tmpfs_xattr(mount, path, call, follow_links)
    }
    fn fxattr(&self, fd: &ffi::fd, call: ffi::XattrCall) -> isize {
        tmpfs_fxattr(fd, call)
    }
}

/// The filesystem. Not in `iul.h` — an embedder mounts tmpfs by name through
/// `mount(2)`, not by address — but `#[no_mangle]` is kept for now because
/// removing an export is `tools/dead-exports.py`'s question rather than this
/// change's.
#[unsafe(no_mangle)]
pub static tmpfs: ffi::FsHandle = ffi::FsHandle(&Tmpfs);

/// tmpfs's descriptor driver: the contents are this crate's own tree, so
/// everything is answered here and nothing is forwarded to a host descriptor.
/// The one exception is `mmap`, which moves a file's bytes into a host file
/// and maps that (`crate::contents`).
///
/// No `close`: the state is the description's `fs_data` and goes with it.
///
/// No `pread`/`pwrite`: a positional read is served by seeking and reading,
/// which is what `crates/kernel/rwcalls` does when [`ffi::Caps`] says `seek`
/// and `read` but not `read_at`.
pub struct TmpfsFd;

/// `#[no_mangle]` until 2026-09-11, and nothing outside this workspace named
/// it.
pub static TMPFS_FDOPS: TmpfsFd = TmpfsFd;

impl ffi::FdOps for TmpfsFd {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps {
            read: true,
            write: true,
            seek: true,
            read_at: false,
            write_at: true,
        }
    }
    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        tmpfs_read(fd, buf)
    }
    fn write(&self, fd: &ffi::fd, buf: &[u8]) -> isize {
        tmpfs_write(fd, buf)
    }
    fn pwrite(&self, fd: &ffi::fd, buf: &[u8], off: i64) -> isize {
        tmpfs_pwrite(fd, buf, off)
    }
    fn lseek(&self, fd: &ffi::fd, off: i64, whence: c_int) -> i64 {
        tmpfs_lseek(fd, off, whence)
    }
    fn readdir(&self, fd: &ffi::fd) -> std::result::Result<Option<ffi::dir_entry>, c_int> {
        tmpfs_readdir(fd)
    }
    fn telldir(&self, fd: &ffi::fd) -> c_ulong {
        tmpfs_telldir(fd)
    }
    fn seekdir(&self, fd: &ffi::fd, ptr: c_ulong) {
        tmpfs_seekdir(fd, ptr)
    }

    /// `None` for anything but a regular file, which is `mmap(2)`'s
    /// `ENODEV`, as Linux answers for a directory.
    unsafe fn mmap(&self, fd: &ffi::fd,
        mem: *mut ffi::mem,
        start: ffi::page_t,
        pages: ffi::pages_t,
        offset: i64,
        prot: c_int,
        flags: c_int,
    ) -> Option<c_int> {
        let inode = &fd_state(fd)?.dirent.inode;
        if inode.mode() & S_IFMT != S_IFREG {
            return None;
        }
        Some(match inode.host_file() {
            // SAFETY: the VFS's contract, which is `map_host`'s.
            Ok(host) => unsafe { realfs::map::map_host(host, mem, start, pages, offset, prot, flags) },
            Err(e) => e,
        })
    }

    fn mapped_file<'a>(&self, fd: &'a ffi::fd) -> Option<std::os::fd::BorrowedFd<'a>> {
        fd_state(fd)?.dirent.inode.host()
    }
}

#[cfg(test)]
mod tests;
