//! The VFS operations: a guest path in, a mount's own operation out.
//!
//! Every one of `kernel/fs.c`'s path syscalls comes here, and every one of
//! these does the same four things — normalise the path, find the mount it
//! belongs to and trim the path to be relative to it, ask that mount, and tell
//! `inotify` what happened. What is left over is the permission rules that are
//! *not* the mount's business, and those are the interesting part of the file:
//! the sticky bit, `protected_hardlinks`, and who may make a device node.
//!
//! The path, permission, mount-table, and inode operations are Rust now. The
//! remaining pointer-shaped calls below are typed compatibility boundaries for
//! the shared filesystem ABI; they do not indicate a C implementation.


use std::ffi::{CStr, c_char, c_int, c_uint};

pub mod normalize;
mod open;

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use open::{O_EMPTYPATH, O_PATH_FLAGS, OpenHow, generic_open, generic_openat, generic_openat2};
mod lookup;
pub use lookup::{
    generic_accessat, generic_fd_is_mount_root, generic_linkat, generic_statat, generic_statat_root,
    generic_unlinkat,
};

#[path = "xattr.rs"]
mod xattr;
pub use xattr::{generic_fxattr, generic_xattr};
mod killpriv;
pub use killpriv::{privs_changed, remove_privs};

#[path = "ops.rs"]
mod ops;
pub use ops::{
    generic_mkdirat, generic_mknodat, generic_readlinkat, generic_renameat, generic_rmdirat,
    generic_seek, generic_setattrat, generic_symlinkat, generic_utime,
};
// The Rust halves of the three `iul.h` declarations. A Rust caller uses these;
// the `generic_*` above are the shims that convert `struct fd *at`.
//
// **Named `_at` and not `mkdirat`**, which is what they were called for one
// build. `#[unsafe(no_mangle)]` was left on them by the edit that split the
// shim off, so they exported the symbols `mkdirat`, `mknodat` and `symlinkat`
// -- and on macOS the linker picks one definition, so **`crates/fs/realfs`'s
// `libc::mkdirat` reached this crate** and every `mkdir` at boot recursed into
// the path walk with a host descriptor number as its `*at` base.
pub use ops::{mkdir_at, mknod_at, symlink_at};
pub use taskview::ffi;

mod errno {
    pub use guest_errno::c_int_::{
        EBADF, EBUSY, EINVAL, EISDIR, ELOOP, ENAMETOOLONG, ENOTDIR, ENXIO, EPERM, ETXTBSY,
        EXDEV,
    };
}

const MAX_PATH: usize = 4096;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o40000;
const S_IFCHR: u32 = 0o20000;
const S_IFBLK: u32 = 0o60000;
const S_IFLNK: u32 = 0o120000;
const S_IFREG: u32 = 0o100000;
const S_IFSOCK: u32 = 0o140000;
const S_ISVTX: u32 = 0o1000;

fn is(mode: u32, kind: u32) -> bool {
    mode & S_IFMT == kind
}

/* `dev_major`, `dev_minor` and a `#[cfg(test)]` `dev_make` were here until
 * 2026-09-15. They are `crates/fs/devices`', whose own comment records that
 * this exact consolidation was already done on 2026-09-01 -- "one definition
 * because there were four, and one of them was the wrong encoding" -- and
 * this crate has depended on that one the whole time. The test copy even
 * disagreed with the owner (no `& 0xfff` on the major), which nothing could
 * see because the cases stop at `0xfff`. See
 * `docs/changelog/2026-09-01-proc-stat-packed-its-terminal-number-wrong.md`. */

/// A `MAX_PATH` buffer that a mount's operation can be handed.
///
/// The C did this with `char path[MAX_PATH]` and `strcpy`, which is where two
/// of this tree's data-destroying bugs came from — a truncated path is not a
/// shorter answer, it is a *different* one, and one that usually exists. This
/// carries its length and refuses to overflow.
struct PathBuf([u8; MAX_PATH]);

impl PathBuf {
    fn new() -> PathBuf {
        PathBuf([0u8; MAX_PATH])
    }

    /// The path as a C string, which it always is.
    ///
    /// **No `unsafe`**: the buffer starts zeroed, [`PathBuf::set`] refuses
    /// anything that would fill it, and the mount lookup's trim only moves
    /// the contents down -- so there is always a NUL in it and
    /// `from_bytes_until_nul` finds it. The empty path for the case that
    /// cannot happen is the same answer the five `cstr(path)` helpers this
    /// replaces gave for a null pointer.
    fn as_cstr(&self) -> &CStr {
        CStr::from_bytes_until_nul(&self.0).unwrap_or(c"")
    }

    fn len(&self) -> usize {
        self.0.iter().position(|&b| b == 0).unwrap_or(self.0.len())
    }

    fn bytes(&self) -> &[u8] {
        &self.0[..self.len()]
    }

    /// A copy, for the guest path an inotify watch is keyed on:
    /// `find_mount_and_trim_path` rewrites its argument in place.
    fn clone_buf(&self) -> PathBuf {
        PathBuf(self.0)
    }

    fn set(&mut self, bytes: &[u8]) -> Result<(), c_int> {
        if bytes.len() >= MAX_PATH {
            return Err(errno::ENAMETOOLONG);
        }
        self.0 = [0u8; MAX_PATH];
        self.0[..bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

/// Normalises a guest path into a fresh buffer.
fn normalize(at: ffi::At<'_>, name: &CStr, flags: c_int) -> Result<PathBuf, c_int> {
    let resolved = crate::normalize::resolve(at, name.to_bytes(), flags)?;
    let mut out = PathBuf::new();
    out.set(&resolved.path)?;
    Ok(out)
}

/// A mount with no filesystem, which refuses everything.
///
/// One implementation of "there is nothing behind this" rather than a `None`
/// test at each of the eighteen call sites below.
struct Unbound;

impl ffi::FsOps for Unbound {
    fn name(&self) -> Option<&'static std::ffi::CStr> {
        None
    }
    fn magic(&self) -> u32 {
        0
    }
}

static UNBOUND: Unbound = Unbound;

/// The mount a normalised path belongs to. **Trims the path in place** to be
/// relative to it, which is what the mount's operations expect.
///
/// The returned mount carries a reference, released when it goes out of scope.
struct Mount(fs_mounttable::MountRef);

impl Mount {
    fn of(path: &mut PathBuf) -> Mount {
        Mount(fs_mounttable::find_mount_and_trim_path(&mut path.0))
    }

    fn as_ptr(&self) -> *mut ffi::mount {
        self.0.as_ptr()
    }

    /// The mount itself. Every `FsOps` method but `mount` and `umount` takes
    /// one of these; see `struct mount` for why a shared reference is enough.
    fn get(&self) -> &ffi::mount {
        &self.0
    }

    /// Hands the reference on — to a descriptor, which releases it on close.
    fn into_ref(self) -> fs_mounttable::MountRef {
        self.0
    }

    /// The mount's filesystem.
    ///
    /// Every caller here reached the mount through `find_mount_and_trim_path`,
    /// which only answers mounts the table holds and every one of those was
    /// made by `do_mount` with a filesystem. `Unbound` rather than a panic so
    /// that a path which *can* reach one answers an errno instead of taking
    /// the process down from inside a syscall — the same choice
    /// `crates/kernel/rwcalls` makes about a descriptor with no driver.
    fn fs(&self) -> &'static dyn ffi::FsOps {
        self.get().fs.unwrap_or(&UNBOUND)
    }

    fn stat(&self, path: &PathBuf) -> Result<ffi::statbuf, c_int> {
        // The third of the three adapters the old signature needed, and now a
        // `?` over what the trait answers: `EPERM` for a filesystem that
        // cannot stat, which is this caller's reading of `None` and differs
        // from the path walk's three sites.
        self.fs()
            .stat(self.get(), path.as_cstr())
            .ok_or(errno::EPERM)?
    }
}

/// 0 with no task, as `taskview::current_fsids` answers; every path a
/// filesystem operation reaches has one.
fn fsuid() -> u32 {
    taskview::with_current_creds(kernel_creds::Creds::fsuid).unwrap_or(0)
}

fn capable(cap: u32) -> bool {
    taskview::capable(cap)
}

fn notify(path: &PathBuf, mask: c_uint, cookie: c_uint) {
    inotify::notify_path(path.bytes(), mask, cookie);
}

// ---------------------------------------------------------------------------
// The sticky bit
// ---------------------------------------------------------------------------

/// In a directory with `S_ISVTX`, an entry may only be removed or renamed by
/// the owner of the entry, the owner of the directory, or a privileged caller.
///
/// `/tmp` is mode 1777 exactly so that this applies: without the rule, write
/// permission on the directory — which is everyone's — is permission to delete
/// anyone else's files. Nothing here looked at the bit; the removal paths
/// checked write permission on the parent and stopped.
///
/// `full` is an already-normalised absolute guest path. A stat that fails is
/// **not** treated as a refusal: the operation about to run will report the
/// real reason, and answering `EPERM` here would mask an `ENOENT`.
fn sticky_check(full: &PathBuf) -> Result<(), c_int> {
    // `CAP_FOWNER`, which is in the set `setfsuid` drops: a root guest with
    // setfsuid set to someone else may not remove anyone's file out of /tmp,
    // which is exactly what this check exists to stop.
    if capable(taskview::caps::CAP_FOWNER) {
        return Ok(());
    }

    let bytes = full.bytes();
    let Some(slash) = bytes.iter().rposition(|&b| b == b'/') else {
        return Ok(());
    };
    let dir_bytes = if slash == 0 {
        b"/".as_slice()
    } else {
        &bytes[..slash]
    };

    let mut dir = PathBuf::new();
    if dir.set(dir_bytes).is_err() {
        return Ok(());
    }
    let dir_mount = Mount::of(&mut dir);
    let Ok(dir_stat) = dir_mount.stat(&dir) else {
        return Ok(());
    };
    drop(dir_mount);
    if dir_stat.mode & S_ISVTX == 0 || dir_stat.uid == fsuid() {
        return Ok(());
    }

    let mut target = full.clone_buf();
    let target_mount = Mount::of(&mut target);
    let target_stat = target_mount.stat(&target);
    drop(target_mount);
    match target_stat {
        Err(_) => Ok(()),
        Ok(st) if st.uid == fsuid() => Ok(()),
        Ok(_) => Err(errno::EPERM),
    }
}

/// The guest path a descriptor names: the mount's own answer with the mount
/// point put back in front of it.
///
/// Safe, and takes a borrow. Its `# Safety` said "`fd` is a live descriptor",
/// which is what the reference says -- and
/// [`fs_fdobj::as_ptr_or_null`]'s doc claimed this function "understands
/// null", which it never did: the first line dereferences. One of `sys_getcwd`'s
/// two calls guarded against that and the other did not, which is what a
/// nullable argument nobody is sure about looks like.
///
/// The buffer's length is its own since 2026-09-14 and both halves of this
/// answer are measured against it.
pub fn generic_getpath(fd: &ffi::fd, buf: &mut [u8]) -> c_int {
    // A description with no mount -- a pipe, a socket -- has no path, which is
    // the same answer as a filesystem with none. This dereferenced the field
    // without testing it until 2026-10-17, beside `generic_fxattr`, which
    // did test it.
    let Some(mount) = fd.mount() else {
        return errno::EPERM;
    };
    let err = match mount.fs {
        Some(fs) => fs.getpath(fd, buf),
        None => return errno::EPERM,
    };
    if err < 0 {
        return err;
    }
    let inner = ffi::path_bytes(buf).to_vec();
    let point = mount.point.to_bytes();
    if inner.len() + point.len() >= MAX_PATH {
        return errno::ENAMETOOLONG;
    }
    // "/" for a task at the machine's own root, where both halves are empty.
    let mut out = Vec::with_capacity(point.len() + inner.len() + 1);
    out.extend_from_slice(point);
    out.extend_from_slice(&inner);
    // A mount's **root** answers `/` from the filesystem, so joining it to the
    // mount point gave `/dev/` where Linux gives `/dev`: `readlink
    // /proc/self/fd/<n>` said so, and `path_normalize` then appended a
    // component to it and produced `/dev//shm`. A trailing slash is not part
    // of a path anywhere else here either — the walk strips one from the
    // caller's, and `crates/fs/path` has the rule.
    while out.len() > 1 && out.last() == Some(&b'/') {
        out.pop();
    }
    if out.is_empty() {
        out.push(b'/');
    }
    ffi::fill_path(buf, &out)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
