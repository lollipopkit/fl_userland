//! The passthrough filesystem: guest operations forwarded to the host.
//!
//! This is what a mount made with `-r` uses, and it is also the back end for
//! fakefs, which stores its file *contents* as ordinary host files and calls
//! into here for every read, write and seek. So most of what runs through this
//! crate is not from a `-r` mount at all.
//!
//! **`crates/fs/fake` reaches these by Rust path, not by symbol** — since
//! 2026-09-11, when the `fs_ops` and `fd_ops` tables became traits and each
//! borrowed operation became a `realfs::realfs_read(…)` written out in
//! `Fakefs`'s impl. This comment used to say `fs/fake.c` "links against these
//! symbols by name", which was true of the C and stopped being true when that
//! crate became Rust; what actually kept the `#[no_mangle]`s alive after that
//! was `pread: Some(realfs_pread)` in a table, which is the reachability rule
//! `tools/dead-exports.py` models. With the tables gone, the attribute had no
//! reader and forty of them came off across this crate and `crates/fs/fake`.
//!
//! `iul.h` still declares exactly two of them — `realfs_open` and
//! `realfs_write` — and those keep theirs, because a declaration in `iul.h` is
//! the embedder contract and ServerBox calls things this tree never does.
//!
//! Almost every function is a host call with its errors translated. The parts
//! that are not — the mount-source arithmetic in `mountpath`, the flag
//! translation in `flags`, the device table in `dev`, and the mapping logic in
//! `map` — are pure functions with their own tests, because those are the
//! parts that were wrong.

use std::ffi::CStr;
use std::os::fd::BorrowedFd;
use std::os::raw::{c_char, c_int, c_uint, c_ulong, c_void};

mod dev;
pub mod dir;
mod errno;
mod flags;
mod io;
pub mod ioctl;
pub mod map;
mod metadata;
mod ops;
pub use ops::{
    host_ftruncate, host_truncate_path, rename_flags, unlinked_host_file, realfs_flock, realfs_fsetattr, realfs_fsync, realfs_link, realfs_mkdir,
    realfs_mknod, realfs_mount, realfs_rename, realfs_rmdir, realfs_setattr, realfs_setflags,
    realfs_symlink, realfs_unlink, realfs_utime,
};
mod mountpath;
mod stat;
pub mod xattr;

use errno::{Result, ck};
pub use io::{
    realfs_interrupted_before_blocking, realfs_pread, realfs_pwrite, realfs_read,
    realfs_write_bytes,
};
pub use metadata::{realfs_fstat, realfs_getpath, realfs_readlink, realfs_stat, realfs_statfs};

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

/* `fakefs_bind_mount_resolve_path` was declared here in an `extern "C"` block
 * until 2026-09-09, under a marker saying fakefs keeps its file contents as
 * host files and forwards every read to this crate, so `fs/fake` depends on
 * `fs/realfs` and the reverse closes a cycle.
 *
 * That is true of `fs/fake` and was never true of the *answer*. The function is
 * a four-line wrapper over `bindmount::bindmount_resolve`, and
 * `crates/fs/bindmount` depends on one leaf crate and nothing else. The second
 * such case found the same day; see `crates/fs/fdobj`, where `poll_cleanup_fd`
 * was a wrapper over `crates/fs/pollset`. **Before writing a hook, check
 * whether the function you want is a wrapper over something below you.** */


// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// The path to give `openat` and friends, relative to the mount's root
/// descriptor.
///
/// `fix_path` in C, and the reason it exists: an absolute path leaves the
/// directory descriptor with nothing to do, so the leading slash has to come
/// off or every lookup escapes the mount.
///
/// **Not `crates/fs/fakeschema`'s [`fix`](fakeschema::fix), though the rule is
/// the same.** That one decides which host file a *fakefs* inode's contents
/// live in, and it is shared because `fakefsify` writes those files and
/// `crates/fs/fake` reads them. This maps a guest path onto a **passthrough
/// mount's** root descriptor: a separate contract that nothing about a fakefs
/// constrains, and tying them would mean a change to one silently changing the
/// other.
///
/// The path as the host's `*at` calls want it: relative to the mount's
/// `root_fd`, so the leading `/` comes off and an empty path becomes `.`.
///
/// A `&CStr` since 2026-09-29, a suffix of the one it was given: the calls
/// that take it are `rustix`'s, which take the string rather than a pointer.
pub(crate) fn at_path(path: &CStr) -> &CStr {
    match path.to_bytes_with_nul() {
        [0] => c".",
        [b'/', rest @ ..] => CStr::from_bytes_with_nul(rest).unwrap_or(c"."),
        _ => path,
    }
}

/// A mount's root directory, which every `*at` call here is relative to.
///
/// `realfs_mount` opens it before the mount is published and it is closed when
/// the mount is freed, so it is open for as long as anything can hold a
/// `&mount`.
///
/// `EIO` for a mount with none, which a mounted realfs or fakefs never is --
/// but the field is an `Option` because tmpfs's mounts have none, and the
/// type is shared.
pub(crate) fn root(mount: &ffi::mount) -> Result<BorrowedFd<'_>> {
    mount.root().ok_or(errno::EIO)
}

/// The host descriptor behind a description, or `EBADF` for one with none --
/// which a description this driver answers never is.
///
/// Safe since 2026-09-29, when `real_fd` became an `OwnedFd`: it was an
/// `unsafe fn` borrowing an `int` on the caller's word that it was open, and
/// nine functions here were `unsafe` for no other reason.
pub(crate) fn host(fd: &ffi::fd) -> Result<BorrowedFd<'_>> {
    fd.host().ok_or(errno::EBADF)
}

/// Tell the embedder's change-event ring that a guest path was touched.
///
pub(crate) fn record(path: &CStr, op: u32) {
    fakechange::record_change(path, op as c_int)
}


// ---------------------------------------------------------------------------
// Opening and closing
// ---------------------------------------------------------------------------

/// The C entry point, which `iul.h` declares and an embedder may call.
///
/// **The `ERR_PTR` encoding lives here, at `generic_open` and at
/// `pty_open_fake`, and nowhere else**: `iul.h` says
/// `struct fd *realfs_open(...)` and an embedder reads the answer with
/// `IS_ERR`, so this signature is the interface. The implementation below
/// answers a `Result`, as `FsOps::open` does since 2026-09-14.
///
/// "and nowhere else" said *two* until 2026-09-16 and was wrong about the
/// count, because `crates/fs/ttydev`'s spelled the same expression out by hand
/// instead of calling [`err_ptr`]. `tools/err-ptr.py` counts them now.
///
/// # Safety
/// Called with a live mount and a valid path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn realfs_open(
    mount: *mut ffi::mount,
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> *mut ffi::fd {
    // **A `*const c_char`, not a `&CStr`.** `iul.h` says `const char *`, and
    // `improper_ctypes_definitions` is what says so at compile time -- the
    // sweep that made every path a `&CStr` converted this one too and the lint
    // caught it in the same minute. The conversion is here, once, with the
    // contract on it.
    //
    // SAFETY: the caller's contract, as declared in `iul.h`.
    match unsafe { realfs_open_at(&*mount, CStr::from_ptr(path), flags, mode) } {
        Ok(fd) => fs_fdobj::NewFd::from(fd).publish(),
        Err(e) => err_ptr(e.as_c_int()),
    }
}

pub fn realfs_open_at(mount: &ffi::mount,
    path: &CStr,
    flags: c_int,
    mode: c_int,
) -> std::result::Result<Box<ffi::fd>, guest_errno::Errno> {
    let mut host_flags = flags::to_host(flags as u32);

    // `O_PATH | O_NOFOLLOW` names the **symlink itself**, and it is how
    // Go's `os.Root`, systemd and every container runtime walk a tree
    // without following a link out of it. The host's `O_NOFOLLOW` refuses
    // one instead, so this answered `ELOOP` for a call Linux serves.
    //
    // Darwin has exactly the right flag for it: `O_SYMLINK` opens the link
    // rather than its target, and an `fstat` of the result reports
    // `S_IFLNK`, which is what `crates/fs/generic` needs to type the
    // descriptor. The comment there said realfs had "no portable way to
    // ask a host for" this -- true of a portable one and not of the host
    // this runs on.
    //
    // Only together: `O_NOFOLLOW` without `O_PATH` still refuses, which is
    // Linux's rule and what `fs_probe`'s neighbouring case checks.
    const O_PATH_NOFOLLOW: u32 = ffi::O_PATH_ | ffi::O_NOFOLLOW_;
    if flags as u32 & O_PATH_NOFOLLOW == O_PATH_NOFOLLOW {
        host_flags = (host_flags & !libc::O_NOFOLLOW) | libc::O_SYMLINK;
    }

    let host_fd = errno::rx(rustix::fs::openat(
        root(mount).map_err(guest_errno::Errno::from_negative_or_eio)?,
        at_path(path),
        rustix::fs::OFlags::from_bits_retain(host_flags as _),
        rustix::fs::Mode::from_raw_mode(mode as libc::mode_t),
    ))
    .map_err(guest_errno::Errno::from_negative_or_eio)?;

    let mut fd = Box::new({
        let mut f = ffi::fd::default();
        f.ops = Some(&REALFS_FDOPS);
        f.real_fd = Some(host_fd);
        f
    });

    // The bind-mount change tracker. Opening is not modifying, so the
    // path is kept and `realfs_write` reports the writes themselves: a
    // descriptor opened once and written to for the rest of a process'
    // life produced exactly one event and never another, and the consumer
    // saw none of the changes.
    if flags::may_modify(flags as u32) {
        record(path, ffi::FAKEFS_CHANGE_OP_WRITE);
        fd.change_path = Some(path.to_owned());
    }
    Ok(fd)
}

/// `ERR_PTR`: a negative guest errno smuggled through a pointer.
/// `crates/kernel/abi`'s, and `iul.h`'s -- `realfs_open` is one of the three
/// declarations that answers one.
use ffi::err_ptr;

/// The description's own close: the directory stream, then the host
/// descriptor, taken so that the close reports what `close(2)` said -- a drop
/// would say nothing. `&mut`, which both `close` operations are handed.
pub fn realfs_close(fd: &mut ffi::fd) -> c_int {
    // The stream closes the dup it was made on, not real_fd.
    drop(fd.dir.take());
    let Some(real) = fd.real_fd.take() else {
        return 0;
    };
    // SAFETY: `into_raw_fd` hands the descriptor over, so it is closed once.
    match ck(unsafe { libc::close(std::os::fd::IntoRawFd::into_raw_fd(real)) }) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// The tables
// ---------------------------------------------------------------------------

/// The host passthrough, as a filesystem.
///
/// Every operation but `umount` and `inode_orphaned` is here; those two are
/// the trait's defaults, and what each default does is written beside it
/// rather than being a `None` a reader has to chase to a call site. A mount
/// with nothing of its own to release has nothing to do at `umount`, and there
/// is no per-inode state for an orphan notification to free.
pub struct Realfs;

impl ffi::FsOps for Realfs {
    fn name(&self) -> Option<&'static std::ffi::CStr> {
        Some(c"real")
    }
    fn magic(&self) -> u32 {
        0x7265616c
    }

    fn mount(&self, mount: &mut ffi::mount) -> c_int {
        realfs_mount(mount)
    }
    fn statfs(&self, mount: &ffi::mount) -> std::result::Result<ffi::statfsbuf, c_int> {
        realfs_statfs(mount)
    }

    fn open(&self,
        mount: &ffi::mount,
        path: &CStr,
        flags: c_int,
        mode: c_int,
    ) -> std::result::Result<Box<ffi::fd>, guest_errno::Errno> {
        realfs_open_at(mount, path, flags, mode)
    }
    fn readlink(&self,
        mount: &ffi::mount,
        path: &CStr,
        buf: &mut [u8],
    ) -> isize {
        realfs_readlink(mount, path, buf)
    }

    fn link(&self,
        mount: &ffi::mount,
        src: &CStr,
        dst: &CStr,
    ) -> c_int {
        realfs_link(mount, src, dst)
    }
    fn unlink(&self, mount: &ffi::mount, path: &CStr) -> c_int {
        realfs_unlink(mount, path)
    }
    fn rmdir(&self, mount: &ffi::mount, path: &CStr) -> c_int {
        realfs_rmdir(mount, path)
    }
    fn rename(&self,
        mount: &ffi::mount,
        src: &CStr,
        dst: &CStr,
        flags: c_uint,
    ) -> c_int {
        realfs_rename(mount, src, dst, flags)
    }
    fn symlink(&self,
        mount: &ffi::mount,
        target: &CStr,
        link: &CStr,
    ) -> c_int {
        realfs_symlink(mount, target, link)
    }
    fn mknod(&self,
        mount: &ffi::mount,
        path: &CStr,
        mode: ffi::mode_t_,
        dev: ffi::dev_t_,
    ) -> c_int {
        realfs_mknod(mount, path, mode, dev)
    }
    fn mkdir(&self,
        mount: &ffi::mount,
        path: &CStr,
        mode: ffi::mode_t_,
    ) -> c_int {
        realfs_mkdir(mount, path, mode)
    }

    fn close(&self, fd: &mut ffi::fd) -> c_int {
        realfs_close(fd)
    }

    fn stat(
        &self,
        mount: &ffi::mount,
        path: &CStr,
    ) -> Option<std::result::Result<ffi::statbuf, c_int>> {
        Some(realfs_stat(mount, path))
    }
    fn fstat(&self, fd: &ffi::fd) -> Option<std::result::Result<ffi::statbuf, c_int>> {
        Some(realfs_fstat(fd))
    }
    fn setattr(&self,
        mount: &ffi::mount,
        path: &CStr,
        attr: ffi::Attr,
    ) -> c_int {
        realfs_setattr(mount, path, attr)
    }
    fn fsetattr(&self, fd: &ffi::fd, attr: ffi::Attr) -> c_int {
        realfs_fsetattr(fd, attr)
    }
    fn utime(&self,
        mount: &ffi::mount,
        path: &CStr,
        atime: ffi::timespec,
        mtime: ffi::timespec,
        follow_links: bool,
    ) -> c_int {
        realfs_utime(mount, path, atime, mtime, follow_links)
    }
    fn getpath(&self, fd: &ffi::fd, buf: &mut [u8]) -> c_int {
        realfs_getpath(fd, buf)
    }

    fn flock(&self, fd: &ffi::fd, operation: c_int) -> Option<c_int> {
        Some(realfs_flock(fd, operation))
    }

    fn xattr(&self,
        mount: &ffi::mount,
        path: &CStr,
        call: ffi::XattrCall,
        follow_links: bool,
    ) -> isize {
        xattr::realfs_xattr(mount, path, call, follow_links)
    }
    fn fxattr(&self, fd: &ffi::fd, call: ffi::XattrCall) -> isize {
        xattr::realfs_fxattr(fd, call)
    }
}

/// The driver, and `iul.h`'s `extern const struct fs_ops realfs`.
///
/// An embedder writes `mount_root(&realfs, source)`; what it gets the address
/// of is a [`ffi::FsHandle`], which is the `&dyn FsOps` and nothing else. The
/// symbol name is the contract, so this keeps `#[no_mangle]` where
/// `REALFS_FDOPS` lost it.
#[unsafe(no_mangle)]
pub static realfs: ffi::FsHandle = ffi::FsHandle(&Realfs);

/// realfs's descriptor driver: a host file, everything forwarded to the
/// `real_fd` the description was opened on.
///
/// The only driver that implements every operation, which is why the others
/// borrow from it — `crates/fs/fake` and `crates/fs/sock` both delegate here
/// rather than copying a function pointer out of a table, which is what they
/// did while this was one.
pub struct RealfsFd;

/// The driver, as a static so a descriptor can borrow it for `'static`.
///
/// `#[no_mangle]` until 2026-09-11, and nothing outside this workspace ever
/// named it: no C source, no assembly, and not `iul.h`. An export no C can
/// reach is an optimisation barrier on whatever path it sits on.
pub static REALFS_FDOPS: RealfsFd = RealfsFd;

impl ffi::FdOps for RealfsFd {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::FILE
    }

    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        realfs_read(fd, buf)
    }

    fn write(&self, fd: &ffi::fd, buf: &[u8]) -> isize {
        realfs_write_bytes(fd, buf)
    }

    fn pread(&self, fd: &ffi::fd, buf: &mut [u8], off: i64) -> isize {
        realfs_pread(fd, buf, off)
    }

    fn pwrite(&self, fd: &ffi::fd, buf: &[u8], off: i64) -> isize {
        realfs_pwrite(fd, buf, off)
    }

    fn lseek(&self, fd: &ffi::fd, off: i64, whence: c_int) -> i64 {
        unsafe { dir::realfs_lseek(fd, off, whence) }
    }

    fn readdir(&self, fd: &ffi::fd) -> std::result::Result<Option<ffi::dir_entry>, c_int> {
        dir::realfs_readdir(fd)
    }

    /// The host's, not `fd->offset`: a `DIR *`'s `telldir` is not a byte
    /// offset into anything, which is the case the trait's default is written
    /// against.
    fn telldir(&self, fd: &ffi::fd) -> c_ulong {
        dir::realfs_telldir(fd)
    }

    fn seekdir(&self, fd: &ffi::fd, ptr: c_ulong) {
        dir::realfs_seekdir(fd, ptr)
    }

    /// The host descriptor's position, which a read through it moves and
    /// `fd->offset` does not follow; for a directory, the stream's cookie, as
    /// `lseek(SEEK_CUR)` answers it. Neither query moves anything.
    fn position(&self, fd: &ffi::fd) -> i64 {
        if fd.dir.get().is_some() {
            return dir::realfs_telldir(fd) as i64;
        }
        fd.host()
            .and_then(|host| rustix::fs::seek(host, rustix::fs::SeekFrom::Current(0)).ok())
            .map_or(0, |pos| pos as i64)
    }

    unsafe fn mmap(&self, fd: &ffi::fd,
        mem: *mut ffi::mem,
        start: ffi::page_t,
        pages: ffi::pages_t,
        offset: i64,
        prot: c_int,
        flags: c_int,
    ) -> Option<c_int> {
        Some(unsafe { map::realfs_mmap(fd, mem, start, pages, offset, prot, flags) })
    }

    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        Some(map::realfs_poll(fd))
    }

    /// Yes: this driver asks the host about `real_fd`, which is what
    /// `crates/fs/poll` used to establish by comparing `poll`'s address
    /// against `realfs_poll`'s.
    fn poll_follows_host_fd(&self) -> bool {
        true
    }

    /// A host descriptor with no name here -- the CLI's stdio on a pipe --
    /// reopened through `/proc/<pid>/fd`, which is `cat /dev/stdin`: a `dup`
    /// of it. The host description keeps the access it was opened with, so a
    /// reopen asking for more than that fails its reads or writes with EBADF
    /// where Linux would have opened the pipe again; the uses that matter ask
    /// for what the descriptor already has.
    fn reopen(&self, fd: &ffi::fd, _flags: c_int) -> std::result::Result<ffi::FdOwned, c_int> {
        let kind = fs_adhoc::Kind::of(fd).ok_or(guest_errno::c_int_::ENXIO)?;
        let host = fd.real_fd.as_ref().ok_or(guest_errno::c_int_::ENXIO)?;
        let dup = errno::io(host.try_clone())?;
        let mut new = fs_adhoc::adhoc_new(Some(&REALFS_FDOPS), kind);
        new.stat = fd.stat;
        new.real_fd = Some(dup);
        Ok(new.into_owned())
    }

    fn ioctl_size(&self, cmd: c_int) -> isize {
        ioctl::realfs_ioctl_size(cmd)
    }

    fn ioctl(&self, fd: &ffi::fd, cmd: c_int, arg: ffi::IoctlArg<'_>) -> c_int {
        ioctl::realfs_ioctl(fd, cmd, arg)
    }

    fn fsync(&self, fd: &ffi::fd) -> c_int {
        realfs_fsync(fd)
    }

    fn close(&self, fd: &mut ffi::fd) -> c_int {
        realfs_close(fd)
    }

    /// This driver's `close` **is** the mount's: both were `realfs_close`, and
    /// `fd_close` skipped the second call by comparing the two addresses.
    fn close_covers_mount(&self) -> bool {
        true
    }

    fn setflags(&self, fd: &ffi::fd, flags: u32) -> c_int {
        realfs_setflags(fd, flags)
    }
}
