//! The fakefs mount: what a file *is* when the host will not let you say.
//!
//! A fakefs file's contents are a host file, and every read, write, seek and
//! lock goes to [`realfs`]. What this adds is `meta.db` — the mode, the owner
//! and the device number iOS gives an app no way to have — and the bind mounts
//! that graft a host directory into the guest tree.
//!
//! # The three crates it is built on are already Rust
//!
//! [`fakedb`] is `meta.db`, [`realfs`] is the host file underneath, and
//! `bindmount` is the table of grafts. Calling them from here is an ordinary
//! Rust call: an `extern "C"` function is only `extern "C"` for the *caller
//! that is C*, and a Rust caller pays nothing for it. So this replaces C that
//! was a thin layer over Rust with Rust that is a thin layer over Rust, and the
//! C ABI crossings on the hot path go away rather than being added to.
//!
//! `stat` is the hottest thing a fakefs sees — a node or npm run makes millions
//! — which is why it moved first.
//!
//! # What stays in C
//!
//! `fs/fake.c` keeps the `fs_ops` table, the bind-mount registration and
//! unmount paths, and the change ring's dispatch source. The table is what lets
//! this move an operation at a time: it is an array of function pointers, so an
//! entry can name a Rust function while the one beside it still names a C one.

//! # `as i64` on a host `libc` field is not redundant
//!
//! `clippy::unnecessary_cast` reports the `time_t` and `suseconds_t` casts
//! here because those are already `i64` on this target. They are `i32` on a
//! 32-bit host, which this tree compiles on — `differential.sh` runs the
//! guest tests in a Linux container and the host tools build wherever they
//! are. The lint sees one target.
#![allow(clippy::unnecessary_cast)]
#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

mod stat;
#[cfg(test)]
use stat::{db_fields, synthesise_mode};
use stat::{fakefs_rs_fstat, fakefs_rs_stat, host_lstat};

mod create;
use create::{fakefs_rs_mkdir, fakefs_rs_mknod, fakefs_rs_symlink, new_row, record_write};
mod remove;
use remove::{fakefs_rs_rmdir, fakefs_rs_unlink};
mod link;
use link::{fakefs_rs_link, fakefs_rs_readlink};
mod rename;
use rename::fakefs_rs_rename;
mod readdir;
use readdir::fakefs_rs_readdir;
mod open;
use open::fakefs_rs_open;
mod mount;
pub use mount::{FakefsMount, any_fakefs_mounted, fakefs_rs_mount_db};
use mount::{fakefs_rs_inode_orphaned, fakefs_rs_mount, fakefs_rs_umount};
mod bind_mount;
pub use bind_mount::{fakefs_bind_mount, fakefs_bind_unmount};

mod setattr;
mod unnamed;
use setattr::{fakefs_rs_fsetattr, fakefs_rs_setattr};

// `fakefs_path_generation_get` and `fakefs_fdops_get` were declared here
// through bindgen until 2026-09-08 -- both are defined in this very file,
// so the declaration was a round trip through C to reach a Rust function
// sixteen hundred lines down. The calls name them directly now.

use std::ffi::{CStr, c_char, c_int, c_ulong};

/// What a path can be, on either side. Darwin's `PATH_MAX` is 1024 and Linux's
/// is 4096; this is the larger, so a buffer sized by it holds either.
const PATH_MAX: usize = 4096;

use guest_errno::c_int_::{EINVAL, EIO, ENAMETOOLONG, ENOENT, EROFS, EXDEV};

// ------------------------------------------------------- the bind-mount edge

/// The calling thread group's opaque filesystem context, which the embedder's
/// path hook is given so that one guest path can map to a different host file
/// per context.
///
/// The field is read through the generated `struct tgroup` rather than a C
/// accessor, and since 2026-09-06 `current` itself is Rust's too.
fn fs_context() -> u64 {
    taskview::current_fs_context()
}

/// The embedder's spelling of [`translate`], published in `fs/fake.h`.
///
/// ServerBox and the native-offload handlers call it by this name, which is why
/// it keeps the C symbol: it is an interface rather than a leftover. It was the
/// last thing in `fs/fake.c` that read `current`.
///
/// Answers whether a bind mount claimed the path. `out_path` is written only on
/// a hit, and never past `out_size`.
///
/// Where a bind mount sends this path, of at most `MAX_PATH` bytes -- the
/// guest's bound, where [`translate`] keeps to the host's. It wrote into a
/// caller's buffer through a pointer until 2026-09-30.
pub fn fakefs_bind_mount_translate_path(path: &CStr) -> Option<std::ffi::CString> {
    bindmount::bindmount_translate(path, fs_context(), ffi::MAX_PATH as usize).map(|(host, _)| host)
}

/// Where a bind mount sends this path, and whether the embedder's hook was what
/// answered.
///
/// **The hook flag is load-bearing.** A hook-routed path must not be written to
/// `meta.db`: the `paths` table is keyed by guest path globally, while the hook
/// can map one guest path to a different host file per context, so storing it
/// would be one row for N files.
pub fn translate(path: &CStr) -> Option<(Vec<u8>, bool)> {
    bindmount::bindmount_translate(path, fs_context(), PATH_MAX).map(|(host, via_hook)| (host.into_bytes(), via_hook))
}

/// Whether this path is under any bind mount.
pub(crate) fn is_under_bind_mount(path: &CStr) -> bool {
    bindmount::bindmount_is_under(path)
}

/// Whether a write to `path` must be refused with `EROFS`.
///
/// Root bypasses the `access_check` path, so the `meta.db` 0555 mode bits alone
/// are not enough to stop a write under a read-only mount.
pub(crate) fn is_under_readonly_bind_mount(path: &CStr) -> bool {
    bindmount::bindmount_is_read_only(path)
}

/// The `meta.db` this mount is backed by.
///
/// It lives in an anonymous union with `void *data`, which bindgen spells
/// `__bindgen_anon_1`, and it is a `*mut fakedb` there — an opaque C type,
/// because `kernel/fs.h` is compiled by every consumer of this header and the
/// database's layout is not theirs to know. Here it is the real thing.
///
/// # Safety
///
/// The mount's database. The borrow is the mount's, which the VFS holds a
/// reference to across every operation.
///
/// Safe since 2026-09-29: an `unsafe fn` reading a union arm on the promise
/// that `mount` was a fakefs. Every caller is a fakefs operation the VFS
/// dispatched on a fakefs mount, so anything else is a bug here, and a panic
/// is the answer to it rather than a read of the wrong type.
fn mount_db(mount: &ffi::mount) -> &fakedb::Db {
    mount.state.fakefs().expect("a fakefs operation on a mount that is not a fakefs")
}

/// The database of the fakefs a descriptor was opened on.
fn fd_db(fd: &ffi::fd) -> &fakedb::Db {
    mount_db(fd.mount().expect("a fakefs descriptor without its mount"))
}

// `as_realfs_mount`, `as_realfs_fd` and `as_realfs_statbuf` were here until
// 2026-09-14, each a `.cast()` with the reason "realfs generates its own
// bindings from the same headers, so its `struct mount` is a different Rust
// type with an identical layout".
//
// **That stopped being true when the shared types moved**: `crates/fs/realfs`
// says `pub use taskview::ffi;` and so does this crate, so the three were
// identity functions between a type and itself. A `.cast()` is a conversion
// the compiler cannot check, and these were thirty of them standing between
// two names for one definition -- the "one thing rendered twice" shape, from
// the other end: the renderings had already merged and the casts had not.

// ------------------------------------- the directory-path cache generation

/// Bumped whenever a rename or a bind-mount change moves guest paths.
///
/// A cached directory path from an older generation is thrown away. It starts
/// at 1 so that a freshly allocated cache — which is zeroed — can never look
/// current.
static PATH_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The generation a cached directory path was resolved at.
pub(crate) fn fakefs_path_generation_get() -> u64 {
    PATH_GENERATION.load(std::sync::atomic::Ordering::Acquire)
}

/// Invalidates every cached directory path.
///
/// A rename moves guest paths, including those of directories somebody has
/// open, so the cache is stale from the moment one starts. Bumped *before* the
/// work rather than after: a reader that races it is entitled to either
/// answer, but not to one from before the bump that it caches afterwards.
pub(crate) fn fakefs_paths_changed_pub() {
    PATH_GENERATION.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
}

/// The descriptor operations a fakefs file gets: realfs's, with `readdir` and
/// `close` answered here.
///
/// A fakefs keeps file *contents* as ordinary host files, so everything except
/// the directory listing and the cache teardown is the passthrough's.
///
/// # It used to copy realfs's table and overwrite two fields
///
/// `let mut ops = REALFS_FDOPS.0; ops.readdir = ...` — which had one property
/// this does not: an operation added to realfs arrived here with nobody
/// remembering to add it. That property is worth less than it reads. Silently
/// inheriting realfs's `close` is exactly the shape of the bug recorded on
/// `fakefs_does_not_claim_the_mounts_close_and_realfs_does`: this table's `close` stopped being the same *function*
/// as the mount's, the identity `fd_close` relied on went with it, and
/// `realfs_close` ran twice on every closed descriptor. Delegating by name
/// makes each inherited operation a line somebody wrote.
pub(crate) struct FakefsFd;

static FAKEFS_FDOPS: FakefsFd = FakefsFd;

pub(crate) fn fakefs_fdops_get() -> Option<&'static dyn ffi::FdOps> {
    Some(&FAKEFS_FDOPS)
}

impl ffi::FdOps for FakefsFd {
    fn caps(&self) -> ffi::Caps {
        realfs::REALFS_FDOPS.caps()
    }
    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        realfs::REALFS_FDOPS.read(fd, buf)
    }
    fn write(&self, fd: &ffi::fd, buf: &[u8]) -> isize {
        realfs::REALFS_FDOPS.write(fd, buf)
    }
    fn pread(&self, fd: &ffi::fd, buf: &mut [u8], off: i64) -> isize {
        realfs::REALFS_FDOPS.pread(fd, buf, off)
    }
    fn pwrite(&self, fd: &ffi::fd, buf: &[u8], off: i64) -> isize {
        realfs::REALFS_FDOPS.pwrite(fd, buf, off)
    }
    fn lseek(&self, fd: &ffi::fd, off: i64, whence: c_int) -> i64 {
        realfs::REALFS_FDOPS.lseek(fd, off, whence)
    }
    /// The one that is not realfs's: a fakefs directory's names come from
    /// `meta.db` rather than from the host tree.
    fn readdir(&self, fd: &ffi::fd) -> Result<Option<ffi::dir_entry>, c_int> {
        fakefs_rs_readdir(fd)
    }
    fn telldir(&self, fd: &ffi::fd) -> c_ulong {
        realfs::REALFS_FDOPS.telldir(fd)
    }
    fn position(&self, fd: &ffi::fd) -> i64 {
        realfs::REALFS_FDOPS.position(fd)
    }
    fn seekdir(&self, fd: &ffi::fd, ptr: c_ulong) {
        realfs::REALFS_FDOPS.seekdir(fd, ptr)
    }
    unsafe fn mmap(&self, fd: &ffi::fd,
        mem: *mut ffi::mem,
        start: ffi::page_t,
        pages: ffi::pages_t,
        offset: i64,
        prot: c_int,
        flags: c_int,
    ) -> Option<c_int> {
        unsafe { realfs::REALFS_FDOPS.mmap(fd, mem, start, pages, offset, prot, flags) }
    }
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        realfs::REALFS_FDOPS.poll(fd)
    }
    /// Yes, and it is the case the address comparison in `crates/fs/poll` was
    /// written for: a fakefs descriptor has a driver of its own and forwards
    /// `poll` to realfs, so asking whether the *driver* was realfs's answered
    /// no for every file in a fakefs.
    fn poll_follows_host_fd(&self) -> bool {
        realfs::REALFS_FDOPS.poll_follows_host_fd()
    }
    fn ioctl_size(&self, cmd: c_int) -> isize {
        realfs::REALFS_FDOPS.ioctl_size(cmd)
    }
    fn ioctl(&self, fd: &ffi::fd, cmd: c_int, arg: ffi::IoctlArg<'_>) -> c_int {
        realfs::REALFS_FDOPS.ioctl(fd, cmd, arg)
    }
    fn fsync(&self, fd: &ffi::fd) -> c_int {
        realfs::REALFS_FDOPS.fsync(fd)
    }
    // No `close`: the directory cache is the description's `fs_data` and
    // goes with it. The mount's close is realfs's and still has to run,
    // which is why `close_covers_mount` stays at its default of `false`
    // while realfs's own answers `true`.
    fn setflags(&self, fd: &ffi::fd, flags: u32) -> c_int {
        realfs::REALFS_FDOPS.setflags(fd, flags)
    }
}

// ------------------------------------------------------- open by inode

// --------------------------------------------------------- the auto-created row

/// A `meta.db` row for a path under a bind mount, made on first access.
///
/// The host tree is grafted in rather than copied, so nothing created these
/// rows when the mount was registered; the first operation that needs one makes
/// it. Returns the inode, or 0.
///
/// # Safety
///
/// `mount` is live with a `fakefs` database.
fn ensure_inode(mount: &ffi::mount, path: &CStr) -> u64 {
    let db = mount_db(mount);
    let existing = db.lookup_inode(path.to_bytes());
    if existing != 0 {
        return existing;
    }

    // What the host has there. **lstat, not stat**: stat follows the link, so
    // the S_ISLNK test below was never true for a bind path and every host
    // symlink was recorded as a regular file.
    let host_stat = match translate(path) {
        Some((host, _)) => match host_lstat(&host, false) {
            Some(s) => s,
            None => return 0,
        },
        None => {
            // fix_path: an empty path is ".", and a leading slash is dropped
            // because the descriptor is the root.
            use rustix::fs::{AtFlags, statat};
            let rel = fix_path(path);
            let Ok(root) = root(mount) else { return 0 };
            match statat(root, rel, AtFlags::SYMLINK_NOFOLLOW)
                .or_else(|_| statat(root, rel, AtFlags::empty()))
            {
                Ok(st) => st,
                Err(_) => return 0,
            }
        }
    };

    let fmt = host_stat.st_mode as u32 & libc::S_IFMT as u32;
    let mode = if fmt == libc::S_IFDIR as u32 {
        libc::S_IFDIR as u32 | 0o755
    } else if fmt == libc::S_IFLNK as u32 {
        libc::S_IFLNK as u32 | 0o777
    } else {
        libc::S_IFREG as u32 | 0o644
    };
    let iul = fakedb::IulStat {
        mode,
        uid: 0,
        gid: 0,
        rdev: 0,
    };

    let mut tx = db.write();
    let ino = tx.path_create(path.to_bytes(), &iul);
    // A commit that went back leaves no row, so the inode above names nothing.
    if !tx.commit() {
        return 0;
    }
    ino
}

/// What a path relative to the mount's `data/` descriptor looks like, as a
/// NUL-terminated buffer for the `*at()` calls below.
///
/// The rule itself is `crates/fs/fakeschema`'s, which is also what
/// `crates/tools/fakefsify` writes a fakefs with -- see that crate's module
/// comment for why one definition rather than one per crate. What is this
/// crate's is the terminator.
fn fix_path(path: &CStr) -> &CStr {
    fakeschema::fix_c(path)
}

/// The mount's `data/` directory. `EIO` for a mount with none, which a
/// mounted fakefs never is: `fakefs_rs_mount` refuses to finish without one.
fn root(mount: &ffi::mount) -> Result<std::os::fd::BorrowedFd<'_>, c_int> {
    mount.root().ok_or(EIO)
}

/// A failed host call's errno as the guest's, with the `SIGPIPE` that goes
/// with `EPIPE`.
fn rx_err(e: rustix::io::Errno) -> c_int {
    kernel_errno::raised(e.raw_os_error())
}

/// The same for `std::io`, where an error `std` made up itself is `EIO`.
fn io_err(e: std::io::Error) -> c_int {
    kernel_errno::raised(e.raw_os_error().unwrap_or(libc::EIO))
}

// ---------------------------------------------------------------------------
// The embedder's interface
//
// `fs/fake.h` publishes these and ServerBox calls them. They were one-line C
// forwarders in `fs/fake.c` over the crate's `fakefs_rs_*` names until
// 2026-09-03; the crate exports the published names directly now, so an
// embedder's call lands in Rust rather than in C that immediately calls Rust.
//
// What could not move is the pair that reads `current` -- which task's
// filesystem context a translation is for -- because `current` is a C
// `__thread` variable.
// ---------------------------------------------------------------------------

/// Ask an embedder to translate a guest path before the bind-mount table does.
/// `None` removes the hook.
#[unsafe(no_mangle)]
pub extern "C" fn fakefs_set_path_translate_hook(hook: Option<bindmount::TranslateHook>) {
    bindmount::bindmount_set_translate_hook(hook);
}

/// The other direction: a host path back to the guest path it came from.
#[unsafe(no_mangle)]
pub extern "C" fn fakefs_set_path_reverse_hook(hook: Option<bindmount::ReverseHook>) {
    bindmount::bindmount_set_reverse_hook(hook);
}

/// Where the fakefs's `data/` directory is on the host, so that a bind mount
/// pointing back inside it can be recognised.
///
/// # Safety
/// `abs_host_path` is NUL-terminated or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fakefs_set_rootfs_data_path(abs_host_path: *const c_char) {
    // SAFETY: the caller's contract.
    let path = (!abs_host_path.is_null()).then(|| unsafe { CStr::from_ptr(abs_host_path) });
    bindmount::bindmount_set_rootfs_data_path(path);
}

/* `fakefs_bind_mount_resolve_path` was here: a four-line `#[no_mangle]`
 * wrapper over `bindmount::bindmount_resolve`, and its one caller was
 * `crates/fs/realfs`, which declared it in an `extern "C"` block because
 * `fs/fake` depends on `fs/realfs` and the reverse would be a cycle. It calls
 * `crates/fs/bindmount` directly now — that crate depends on one leaf and is
 * below both — so the wrapper had no caller and `tools/dead-exports.py` said
 * so. Removed 2026-09-09. */

/// Make an empty `meta.db` under `dir`.
///
/// The schema itself is `crates/fs/fakeschema`, its one definition:
/// `crates/tools/fakefsify` calls the same crate, and a second copy would be a
/// database two tools disagree about.
///
/// # Safety
/// `dir` is NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fake_db_create(dir: *const c_char) -> c_int {
    if dir.is_null() {
        return EINVAL;
    }
    // SAFETY: the caller's contract.
    db_create(unsafe { CStr::from_ptr(dir) }).err().unwrap_or(0)
}

/// [`fake_db_create`] for a Rust caller; `Err` is a negative errno.
pub fn db_create(dir: &CStr) -> Result<(), c_int> {
    fakedb::db::create_at(dir)
}

/// The fakefs mount's operations, which `xX_main_Xx.h` and `kernel/fs.h` name.
///
/// A fakefs: `meta.db` for the metadata, ordinary host files for the contents.
///
/// **Eight operations are realfs's**, and the split is the whole design: the
/// metadata is `meta.db`'s and the bytes are not, so anything that only
/// touches the bytes forwards. Each is a delegation by name rather than a
/// function pointer copied out of realfs's table, which is what it was while
/// that table existed.
///
/// `rmdir`, `mkdir`, `stat` and the rest that are this crate's own go through
/// the database.
pub struct Fakefs;

impl ffi::FsOps for Fakefs {
    fn name(&self) -> Option<&'static CStr> {
        Some(c"fake")
    }
    fn magic(&self) -> u32 {
        0x6661_6b65
    }

    fn mount(&self, mount: &mut ffi::mount) -> c_int {
        fakefs_rs_mount(mount)
    }
    fn umount(&self, mount: &mut ffi::mount) -> c_int {
        fakefs_rs_umount(mount)
    }
    fn statfs(&self, mount: &ffi::mount) -> Result<ffi::statfsbuf, c_int> {
        realfs::realfs_statfs(mount)
    }

    fn open(&self,
        mount: &ffi::mount,
        path: &CStr,
        flags: c_int,
        mode: c_int,
    ) -> Result<Box<ffi::fd>, guest_errno::Errno> {
        fakefs_rs_open(mount, path, flags, mode)
    }
    fn readlink(&self,
        mount: &ffi::mount,
        path: &CStr,
        buf: &mut [u8],
    ) -> isize {
        fakefs_rs_readlink(mount, path, buf)
    }
    fn link(&self,
        mount: &ffi::mount,
        src: &CStr,
        dst: &CStr,
    ) -> c_int {
        fakefs_rs_link(mount, src, dst)
    }
    fn unlink(&self, mount: &ffi::mount, path: &CStr) -> c_int {
        fakefs_rs_unlink(mount, path)
    }
    fn rmdir(&self, mount: &ffi::mount, path: &CStr) -> c_int {
        fakefs_rs_rmdir(mount, path)
    }
    fn rename(&self,
        mount: &ffi::mount,
        src: &CStr,
        dst: &CStr,
        flags: std::ffi::c_uint,
    ) -> c_int {
        fakefs_rs_rename(mount, src, dst, flags)
    }
    fn symlink(&self,
        mount: &ffi::mount,
        target: &CStr,
        link: &CStr,
    ) -> c_int {
        fakefs_rs_symlink(mount, target, link)
    }
    fn mknod(&self,
        mount: &ffi::mount,
        path: &CStr,
        mode: ffi::mode_t_,
        dev: ffi::dev_t_,
    ) -> c_int {
        fakefs_rs_mknod(mount, path, mode, dev)
    }
    fn mkdir(&self,
        mount: &ffi::mount,
        path: &CStr,
        mode: ffi::mode_t_,
    ) -> c_int {
        fakefs_rs_mkdir(mount, path, mode)
    }

    fn close(&self, fd: &mut ffi::fd) -> c_int {
        unnamed::fakefs_close_unnamed(fd);
        realfs::realfs_close(fd)
    }
    fn tmpfile(&self, mount: &ffi::mount, dir: &CStr, flags: c_int, mode: c_int) -> Result<Box<ffi::fd>, guest_errno::Errno> {
        unnamed::fakefs_tmpfile(mount, dir, flags, mode)
    }
    fn link_unnamed(&self, fd: &ffi::fd, mount: &ffi::mount, dst: &CStr) -> c_int {
        unnamed::fakefs_link_unnamed(fd, mount, dst)
    }

    fn stat(
        &self,
        mount: &ffi::mount,
        path: &CStr,
    ) -> Option<Result<ffi::statbuf, c_int>> {
        Some(fakefs_rs_stat(mount, path))
    }
    fn fstat(&self, fd: &ffi::fd) -> Option<Result<ffi::statbuf, c_int>> {
        Some(fakefs_rs_fstat(fd))
    }
    fn flock(&self, fd: &ffi::fd, operation: c_int) -> Option<c_int> {
        Some(realfs::realfs_flock(fd, operation))
    }
    fn setattr(&self,
        mount: &ffi::mount,
        path: &CStr,
        attr: ffi::Attr,
    ) -> c_int {
        fakefs_rs_setattr(mount, path, attr)
    }
    fn fsetattr(&self, fd: &ffi::fd, attr: ffi::Attr) -> c_int {
        fakefs_rs_fsetattr(fd, attr)
    }
    fn getpath(&self, fd: &ffi::fd, buf: &mut [u8]) -> c_int {
        realfs::realfs_getpath(fd, buf)
    }
    fn utime(&self,
        mount: &ffi::mount,
        path: &CStr,
        atime: ffi::timespec,
        mtime: ffi::timespec,
        follow_links: bool,
    ) -> c_int {
        realfs::realfs_utime(mount, path, atime, mtime, follow_links)
    }

    /// Extended attributes go on the host file, like the contents do: a fakefs
    /// keeps `meta.db` for what iOS gives an app no real ones of — ownership,
    /// modes and device nodes — and everything else is the file underneath.
    /// `data/` paths are the guest's with the leading slash stripped, which is
    /// exactly what realfs resolves against a root descriptor, so this is the
    /// same forward as `statfs` above rather than a translation.
    fn xattr(&self,
        mount: &ffi::mount,
        path: &CStr,
        call: ffi::XattrCall,
        follow_links: bool,
    ) -> isize {
        realfs::xattr::realfs_xattr(mount, path, call, follow_links)
    }
    fn fxattr(&self, fd: &ffi::fd, call: ffi::XattrCall) -> isize {
        realfs::xattr::realfs_fxattr(fd, call)
    }

    fn inode_orphaned(&self, mount: &ffi::mount, inode: ffi::ino_t) {
        fakefs_rs_inode_orphaned(mount, inode)
    }
}

/// The filesystem, and `iul.h`'s `extern const struct fs_ops fakefs`.
#[unsafe(no_mangle)]
pub static fakefs: ffi::FsHandle = ffi::FsHandle(&Fakefs);

// Ten type aliases and five `transmute`s stood here until 2026-09-06. They
// existed because this crate and `crates/fs/realfs` each generated their own
// `mount`, `fd`, `statfsbuf` and `timespec` from the same headers -- identical
// layouts under different Rust names -- so five of realfs's operations could
// not be named in this table without one.
//
// `crates/kernel/taskview` blocklists all four names in both crates and imports
// them from `crates/kernel/taskview`, so they are one type and the transmutes
// were the identity. `clippy::useless_transmute` is what said so.
//
// What went with them is the hazard: a `transmute` between two *function
// pointers* is the one place a signature mismatch is completely silent, and
// there were five.


#[cfg(test)]
mod tests {
    use super::*;
    use ffi::FdOps as _;

    /// fakefs's driver must **not** claim the mount's close, and realfs's
    /// must.
    ///
    /// `fd_close` calls the descriptor's close and then the mount's, unless
    /// the driver says the first already did what the second would. realfs's
    /// `close` *is* `realfs_close`, which is also this mount's `fs_ops::close`
    /// — so it says yes. fakefs's descriptor close is the default, which does
    /// nothing, and the mount's `realfs_close` still has to run, so it says
    /// no.
    ///
    /// **Getting this pair wrong is silent**, which is why it is pinned here
    /// rather than left to the default. Until 2026-09-11 the rule was
    /// `fn_addr_eq(driver_close, fs_close)` — skip the mount's close when it
    /// is literally the same function pointer — and introducing
    /// a fakefs descriptor close that freed the directory cache broke that coincidence: `realfs_close` ran twice
    /// and closed the host descriptor twice, which on a busy process closes
    /// whatever unrelated file has since been opened at that number. It
    /// surfaced as the guest's own `closedir` answering `EBADF`, nowhere near
    /// the cause. Swap either answer below and this goes red.
    #[test]
    fn fakefs_does_not_claim_the_mounts_close_and_realfs_does() {
        assert!(
            !FAKEFS_FDOPS.close_covers_mount(),
            "the mount's realfs_close would be skipped and the cache never freed by it"
        );
        assert!(
            realfs::REALFS_FDOPS.close_covers_mount(),
            "realfs_close would run twice and close the host descriptor twice"
        );
    }

    #[test]
    fn fix_path_terminates_what_the_rule_returns() {
        // The rule is `crates/fs/fakeschema`'s and tested there. What is tested
        // here is this crate's half: that the result is NUL-terminated, which
        // is what the `*at()` calls below need.
        assert_eq!(fix_path(c""), c".");
        assert_eq!(fix_path(c"/"), c"");
        assert_eq!(fix_path(c"/etc/passwd"), c"etc/passwd");
    }

    #[test]
    fn a_synthesised_mode_keeps_the_type_and_replaces_the_bits() {
        let mut st = ffi::statbuf {
            mode: libc::S_IFDIR as u32 | 0o700,
            ..Default::default()
        };
        let host = st.mode;
        synthesise_mode(&mut st, host);
        assert_eq!(st.mode, libc::S_IFDIR as u32 | 0o755);
        st.mode = libc::S_IFREG as u32 | 0o600;
        let host = st.mode;
        synthesise_mode(&mut st, host);
        assert_eq!(st.mode, libc::S_IFREG as u32 | 0o644);
        assert_eq!(st.uid, 0);
        assert_eq!(st.gid, 0);
    }

    #[test]
    fn the_database_overrides_exactly_five_fields() {
        // The other side of the same rule: everything the host says about size
        // and times survives, and only these five come from meta.db. A sixth
        // would be a field fakefs cannot actually control.
        let mut st = ffi::statbuf {
            size: 1234,
            nlink: 7,
            blksize: 4096,
            mtime: 99,
            ..Default::default()
        };
        let iul = fakedb::IulStat {
            mode: 0o100644,
            uid: 501,
            gid: 20,
            rdev: 0,
        };
        db_fields(&mut st, 42, &iul);
        assert_eq!(
            (st.inode, st.mode, st.uid, st.gid, st.rdev),
            (42, 0o100644, 501, 20, 0)
        );
        assert_eq!(
            (st.size, st.nlink, st.blksize, st.mtime),
            (1234, 7, 4096, 99)
        );
    }
}
