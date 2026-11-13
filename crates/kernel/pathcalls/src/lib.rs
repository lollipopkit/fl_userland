//! The syscalls that name a file by **path**.
//!
//! `open`, `stat`'s neighbours, `link`, `rename`, `chdir` and the rest of
//! `kernel/fs.c`, as against `crates/kernel/rwcalls` and
//! `crates/kernel/fdattr`, which take a descriptor and never resolve anything.
//!
//! Every one of them is the same three steps: read the path out of guest
//! memory, work out what a relative path is relative to, and hand both to the
//! operation in `fs-generic`. What is interesting is in the corners — which
//! `*at` descriptor applies, whose ids the check runs as, and what the umask
//! does — so those are what the comments are about.
//!
//! The VFS operation layer is Rust now. The remaining `extern "C"` calls in
//! this crate are only ABI boundaries for the embedder-facing descriptor and
//! filesystem interfaces.


use std::ffi::{c_int, c_uint};

use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

mod context;
pub use context::{sys_chdir, sys_chroot, sys_fchdir, sys_getcwd, sys_umask};

mod names;
pub use names::*;

mod openat2;
pub use openat2::sys_openat2;

mod handles;
pub use handles::{sys_name_to_handle_at, sys_open_by_handle_at};

mod attributes;
pub(crate) use attributes::follows;
pub use attributes::*;

mod timestamps;
pub use timestamps::*;

mod statfs;
pub use statfs::*;

mod swapquota;
pub use swapquota::{sys_quotactl, sys_quotactl_fd, sys_swapoff, sys_swapon};

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

/// `MAX_PATH`, from `kernel/fs.h`.
const MAX_PATH: usize = 4096;

/// A path read out of guest memory, NUL-terminated for the C below.
struct Path([u8; MAX_PATH]);

impl Path {
    /// Reads a guest string. `ENAMETOOLONG` for one that does not fit,
    /// `EFAULT` for one that is not mapped.
    fn read(addr: u64) -> Result<Path, Errno> {
        // Zeroed, where the C's `char path[MAX_PATH]` was not. Measured before
        // reaching for MaybeUninit: `syscall_bench`'s `stat, 20-byte path` is
        // 3079 ns either way, so the 4 KiB memset is below the noise here and
        // the unsafe buys nothing. It is not always below the noise -- see
        // crates/kernel/rwcalls' scratch buffer, where the same shape cost 6x
        // -- so the question is worth asking and worth answering by measuring.
        let mut buf = [0u8; MAX_PATH];
        let err = mmapcalls::usermem::read_current_string(addr, &mut buf);
        done(err)?;
        Ok(Path(buf))
    }

    /// The path as a C string. `read` refuses one with no terminator inside
    /// the buffer, so there always is one; the empty string for the case that
    /// cannot happen.
    fn as_cstr(&self) -> &std::ffi::CStr {
        std::ffi::CStr::from_bytes_until_nul(&self.0).unwrap_or(c"")
    }

    fn as_str(&self) -> std::borrow::Cow<'_, str> {
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(self.0.len());
        String::from_utf8_lossy(&self.0[..end])
    }
}

/// What a relative path is relative to.
///
/// `AT_FDCWD` and an absolute path both mean the working directory, which is
/// why the path is a parameter: the descriptor is ignored for an absolute one,
/// and Linux does not even check that it is open.
///
/// An [`fs_fdobj::AtRef`] rather than an `At<'a>`: the lifetime was the
/// caller's to name, so this safe function lent a borrow of any length.
fn at_of(at_f: c_int, path: &Path) -> Result<fs_fdobj::AtRef, Errno> {
    // `at_fd` answers `None` only for a genuinely bad descriptor: the working
    // directory is `At::Pwd`, which is a variant rather than a sentinel
    // pointer -- it was `AT_PWD`, `(struct fd *) -2`, and this comment used to
    // have to say so.
    fs_fdobj::at_fd(at_f, path.as_cstr()).ok_or(Errno::EBADF)
}

/// What `AT_EMPTY_PATH` with an empty path names: the `*at` descriptor's own
/// file, or for `AT_FDCWD` the working directory.
enum Itself {
    /// By path, as `"."` against this base -- which the walk answers with the
    /// base's own path and does not follow. That is Linux's `LOOKUP_EMPTY`:
    /// the descriptor may be `O_PATH`, and one onto a symlink names the link.
    Named(fs_fdobj::AtRef),
    /// A file with no name -- a pipe, a socket -- which only its descriptor
    /// reaches.
    Nameless(fs_fdobj::FdRef),
}

impl Itself {
    fn of(at_f: c_int) -> Result<Itself, Errno> {
        if at_f == ffi::AT_FDCWD_ {
            return Ok(Itself::Named(fs_fdobj::AtRef::Pwd));
        }
        let fd = fs_fdobj::f_get(at_f).ok_or(Errno::EBADF)?;
        let mut buf = [0u8; MAX_PATH + 1];
        Ok(if fs_generic::generic_getpath(&fd, &mut buf) >= 0 && buf[0] == b'/' {
            Itself::Named(fs_fdobj::AtRef::Fd(fd))
        } else {
            Itself::Nameless(fd)
        })
    }
}

/// What every `fs-generic` operation answers: 0, or a negative guest errno.
///
/// One place rather than twenty. Each of those twenty was a `as i64` on the
/// end of the call, which is the cast that makes a *value* and an *error* the
/// same type -- and the VFS layer has no operation here whose success carries
/// a number, so there is nothing to lose by saying so.
fn done(err: c_int) -> Result<(), Errno> {
    if err < 0 {
        Err(Errno::from_negative_or_eio(err))
    } else {
        Ok(())
    }
}

/// Run `f` on the calling task's path context.
///
/// A syscall runs on a task, and every task has one from `task_create_` on.
/// It was `fn context() -> &'static FsInfo`, a dereference of
/// `current_fs_info()` with no null test and a lifetime the function chose;
/// [`taskview::with_current_fs`] scopes the borrow and answers `None` for the
/// case it skipped.
fn with_context<R>(f: impl FnOnce(&fsinfo::FsInfo) -> R) -> R {
    taskview::with_current_fs(f).expect("a syscall runs on a task with a path context")
}

/// Removes the calling task's umask bits from a mode a create is about to use.
fn apply_umask(mode: c_uint) -> c_uint {
    with_context(|fs| fs.apply_umask(mode))
}
