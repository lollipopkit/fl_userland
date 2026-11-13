//! What a mounted filesystem can do: [`FsOps`].
//!
//! # It was a `#[repr(C)]` table of twenty-five fields until 2026-09-11
//!
//! `struct fs_ops` held a name, a magic number and twenty-three nullable
//! function pointers; `struct mount` held a `*const fs_ops`; ten filesystems
//! each built one. The same three things went with it that went with
//! [`crate::FdOps`] the commit before — see `fd_ops.rs` for the argument, which
//! is the same one — and one more that is particular to this table:
//!
//! - **Twenty-three defaults, each written at a call site.** Eighteen of them
//!   agreed on `_EPERM`, `_EINVAL` or `_EOPNOTSUPP` and are default method
//!   bodies here, stated once beside the operation. Three did not agree, and
//!   that disagreement is what says nobody chose: `fstat` absent is `_EINVAL`
//!   in `crates/fs/statcalls`, `_ENOMEM` in `crates/fs/inode` and "no answer"
//!   in two more; `stat` absent is `_EPERM` in one place and "carry on" in the
//!   three path-walk sites; `flock` absent falls back to
//!   `fs_locks::flock_generic`, which is a whole implementation. Those three
//!   return `Option`, so each caller still says what absence means for it.
//!
//! - **`name` and `magic` were data, so a filesystem could forget them.** They
//!   are required methods: `crates/fs/adhoc` and `crates/kernel/memfdcalls`
//!   answer `None` for the name on purpose — neither is a registered
//!   filesystem and neither appears in `/proc/filesystems` — and saying so is
//!   a line rather than a field left at null.
//!
//! # What C still sees, which is why this is not simply a trait
//!
//! `iul.h` is the whole of the embedder interface and it has **six**
//! declarations that name this type:
//!
//! ```c
//! struct fs_ops;                                  /* opaque */
//! extern const struct fs_ops realfs;
//! extern const struct fs_ops fakefs;
//! extern const struct fs_ops procfs;
//! extern const struct fs_ops devptsfs;
//! int mount_root(const struct fs_ops *fs, const char *source);
//! int do_mount(const struct fs_ops *fs, const char *source, ...);
//! ```
//!
//! That is a **symbol and pointer** contract, not a layout one: `struct
//! fs_ops` is declared in the section of `iul.h` headed "the objects, all
//! opaque" and nothing defines it, so a C embedder cannot read a field, take
//! `sizeof` or make one. All it can do is take the address of one of the four
//! and hand it back. ServerBox does exactly that.
//!
//! So the four stay as exported statics, of type [`FsHandle`] — a
//! `#[repr(transparent)]` wrapper around the `&'static dyn FsOps`, which is
//! what `&realfs` is the address of. Two things it must be and is:
//!
//! - **Not zero-sized.** Two distinct zero-sized statics are allowed to share
//!   an address, so `&realfs == &procfs` would have been a possibility. A fat
//!   pointer is sixteen bytes.
//! - **Distinct per filesystem**, which follows.
//!
//! `mount_root` and `do_mount` take a `*const FsHandle`; from C that is the
//! same pointer it always was.

use crate::{Attr, dev_t_, fd, ino_t, mode_t_, mount, statbuf, statfsbuf, timespec};
use std::ffi::{CStr, c_int, c_uint};

/// `_EPERM` is the operation this filesystem does not implement; `_EINVAL` is
/// what `readlink` on a thing that is not a symlink is; `_EOPNOTSUPP` is the
/// xattr answer -- Linux's for a filesystem with no `i_op->listxattr`, and what
/// `crates/fs/xattrabi`'s rules expect; and `_ENAMETOOLONG` is
/// [`fill_path`]'s, for a path the caller's buffer cannot hold.
use guest_errno::c_int_::{EINVAL, ENAMETOOLONG, EOPNOTSUPP, EPERM};
use guest_errno::Errno;

/// Which of the four extended-attribute verbs, and what only that verb needs.
///
/// It was an `op: c_int` against four constants — `XATTR_OP_GET` and its three
/// neighbours in `crates/kernel/abi`'s `constants.rs`, plus a **second, private
/// copy of the same four** in `crates/kernel/fdattr` — matched in two
/// filesystems as `x if x == ffi::XATTR_OP_GET as c_int`. A guard chain is not
/// a match: the compiler cannot check it for exhaustiveness, so the `_ =>
/// EINVAL` arm at the bottom of each was the only thing standing between a
/// fifth value and an operation nobody wrote, and it read as deliberate.
///
/// `flags` travelled beside it on all four verbs and means something on
/// exactly one, which is why it is carried here rather than passed alongside:
/// `check_flags` was applied to a word three of the four callers pass as zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrOp {
    Get,
    /// `XATTR_CREATE`/`XATTR_REPLACE`, which no other verb reads.
    Set { flags: c_int },
    List,
    Remove,
}

/// One extended-attribute operation, with the buffer it acts on.
///
/// The buffer is the **kernel's**, never a guest address: `crates/kernel/fdattr`
/// copies in before a set and out after the other three, which is the rule
/// every syscall in this tree follows and matters more than usual here —
/// a filesystem writing a guest address would be writing it without the page
/// table's checks.
///
/// # The direction is in the type
///
/// It was a `*const c_char` name, a `*mut c_void` buffer and a `usize`, with
/// three things carried out of band: the name is *absent* for a list and was a
/// null pointer; the buffer is *read* for a set and *written* for the other
/// three, which only `op` said; and a remove has no buffer at all but was
/// handed one anyway.
///
/// `crates/fs/tmpfs` had a function whose entire job was to unpack that — it
/// answered a `&mut [u8]` and a `&[u8]` **taken from the same pointer**, with
/// a comment saying "only one is used per call". Two live slices over one
/// allocation, kept apart by a convention. There is no such function now,
/// because there is nothing to unpack.
///
/// # No C crosses this
///
/// Which is what lets it be an enum with a lifetime rather than a `#[repr(C)]`
/// struct of pointers. Measured against `iul.h`, the five `.S` files and
/// `tests/integration/sbm_api_test.c`: neither `XattrCall` nor [`XattrOp`]
/// appears in any of them, and a guest reaches all six of the functions that
/// take one through the [`FsOps`] trait object rather than by symbol. The six
/// were `extern "C" fn` until 2026-09-11, and that is exactly what kept the
/// request as eight loose parameters — an `extern "C" fn` may not take a type
/// that is not FFI-safe.
///
/// This was an entry in `abi.rs`'s `NOT_REPR_C` until 2026-09-15. That list
/// only covers `pub struct` and `pub union`, so the moment this became an
/// enum the entry named nothing, and the test that asserts no exemption is
/// stale is what said so.
pub enum XattrCall<'a> {
    /// Read the named attribute. An empty `out` asks for the length and writes
    /// nothing, which is how `getxattr(…, NULL, 0)` arrives.
    Get { name: &'a CStr, out: &'a mut [u8] },
    /// Write it. `flags` is `XATTR_CREATE`/`XATTR_REPLACE`, which no other
    /// verb reads — see [`XattrOp`].
    Set {
        name: &'a CStr,
        value: &'a [u8],
        flags: c_int,
    },
    /// Every name this file has, NUL-separated. An empty `out` asks for the
    /// length. It names no attribute, which is why there is no `name` here and
    /// why there used to be a null pointer.
    List { out: &'a mut [u8] },
    Remove { name: &'a CStr },
}

impl XattrCall<'_> {
    /// Which verb this is, for the rules that are about the verb alone.
    ///
    /// Derived rather than stored, so the two cannot disagree.
    pub fn op(&self) -> XattrOp {
        match self {
            XattrCall::Get { .. } => XattrOp::Get,
            XattrCall::Set { flags, .. } => XattrOp::Set { flags: *flags },
            XattrCall::List { .. } => XattrOp::List,
            XattrCall::Remove { .. } => XattrOp::Remove,
        }
    }

    /// The attribute's name. `None` for a list, which names none.
    pub fn name(&self) -> Option<&CStr> {
        match self {
            XattrCall::Get { name, .. }
            | XattrCall::Set { name, .. }
            | XattrCall::Remove { name } => Some(name),
            XattrCall::List { .. } => None,
        }
    }

    /// How many bytes the caller has room for, which is what every one of
    /// these answers when it is zero: the length, with nothing written.
    pub fn room(&self) -> usize {
        match self {
            XattrCall::Get { out, .. } | XattrCall::List { out } => out.len(),
            XattrCall::Set { value, .. } => value.len(),
            XattrCall::Remove { .. } => 0,
        }
    }
}

/// The C-visible handle: what `extern const struct fs_ops realfs` is.
///
/// See the module comment. `#[repr(transparent)]` so that the exported symbol
/// *is* the `&dyn FsOps`, and taking its address in C gives back something this
/// side can read the trait object out of.
#[repr(transparent)]
pub struct FsHandle(pub &'static dyn FsOps);

impl FsHandle {
    /// The filesystem behind a handle a C caller passed back.
    ///
    /// # Safety
    /// `p` is null, or an address `iul.h` handed out — one of the four
    /// exported statics, or a handle this workspace made that outlives the
    /// mount.
    pub unsafe fn deref(p: *const FsHandle) -> Option<&'static dyn FsOps> {
        if p.is_null() {
            return None;
        }
        Some(unsafe { (*p).0 })
    }
}

/// What a mounted filesystem can do.
///
/// One implementation per filesystem, held by `struct mount` as
/// `Option<&'static dyn FsOps>`.
///
/// # The mount is a reference, and which mount it is, is structural
///
/// Every method takes `&mount` — `&mut mount` for the two that write it —
/// rather than the `*mut mount` it was until 2026-09-15, and the trait
/// carried a `# Safety` section saying "a live, non-null pointer to a mount
/// whose filesystem is this one". The first half is what a reference *is*.
/// The second half is the one that still bites, because an implementation
/// reads its own state out of `mount.state`, which is a union: hand tmpfs a
/// realfs mount and `state.data` is read as an `Arc<Dirent>` that was never
/// there.
///
/// That is not a caller obligation, because **no caller chooses the pair**.
/// The only way to reach a method is through `mount.fs`, which is the
/// filesystem the mount was built with — `fd.mount().fs.and_then(|fs|
/// fs.fstat(fd, …))` is the shape at every dispatch site — and `fs` is set in
/// exactly three places (`fs-mount`'s `do_mount`, `fs-adhoc` and
/// `kernel-memfdcalls`), each of them constructing the mount it sets it on.
/// A mismatched pair is unreachable rather than forbidden, so the methods are
/// safe `fn` and there is nothing for a `# Safety` section to say.
///
/// `mount` and `umount` take `&mut mount` because they are the only two that
/// write one, and each runs while nothing else can reach it: `do_mount` calls
/// `mount` **before** `mounts_insert`, and `fs_mount::destroy` calls `umount`
/// after the table has handed the mount over with its refcount at zero. See
/// [`mount::as_ptr`] for the same argument written from the other side.
///
/// Exactly one method is left an `unsafe fn` and it says why on itself:
/// [`FsOps::fsetattr`].
///
/// **A path is a `&CStr` and never was part of that contract.** It was a
/// `*const c_char` with "NUL-terminated, mount-relative" written here until
/// 2026-09-14, and each of the five filesystems opened with a `cstr(path)`
/// helper of its own — `if p.is_null() { return b"" }` and a `CStr::from_ptr`,
/// fifty-odd times. The dispatchers all hold a `PathBuf`, whose buffer starts
/// zeroed and which refuses to `set` anything that would fill it, so the
/// conversion is `CStr::from_bytes_until_nul` and needs no `unsafe` at all.
pub trait FsOps: Send + Sync + 'static {
    /// What `/proc/filesystems` and `/proc/mounts` call this, and what
    /// `mount(2)`'s `filesystemtype` has to match.
    ///
    /// `None` for a filesystem that is not registered and never appears in
    /// either — the ad-hoc mounts behind pipes, sockets and anonymous inodes,
    /// and memfd's. Required rather than defaulted, so that a new filesystem
    /// has to say which it is; it was a `*const c_char` field that a table
    /// could leave null without meaning to.
    fn name(&self) -> Option<&'static CStr>;

    /// `f_type` in `statfs`, and what a program uses to tell tmpfs from a real
    /// disk.
    fn magic(&self) -> u32;

    // ---- the mount itself ------------------------------------------------

    /// Bring the mount up. The default has nothing to do, which is what a
    /// filesystem with no state of its own needs.
    fn mount(&self, _mount: &mut mount) -> c_int {
        0
    }

    /// Take it down again. The default has nothing to release.
    fn umount(&self, _mount: &mut mount) -> c_int {
        0
    }

    /// What this filesystem knows about its own space.
    ///
    /// The default answers a `statfsbuf::default()`, which says **nothing**:
    /// every completable field is `None` and the counts are zero.
    /// `crates/kernel/fdattr` supplies `f_type` from [`FsOps::magic`], a 4096
    /// block size, `MAX_NAME` and the mount's flags afterwards, for exactly
    /// this case. Leaving those at zero is what made `du /proc` count nothing
    /// and made `statvfs()->f_flag` report a read-only bind mount as writable.
    ///
    /// It took `&mut statfsbuf` and answered `c_int` until 2026-09-16, which
    /// left the caller unable to tell "answered zero" from "did not answer" —
    /// see `statfsbuf`'s own comment for what that cost.
    fn statfs(&self, _mount: &mount) -> Result<statfsbuf, c_int> {
        Ok(statfsbuf::default())
    }

    // ---- names -----------------------------------------------------------

    /// Open a path.
    ///
    /// It answered `*mut fd` with a negative errno smuggled through the pointer
    /// until 2026-09-14 — `ERR_PTR`, which `iul.h` states and `generic_open`
    /// and `realfs_open` still answer, because those two are the embedder's.
    /// Everything between them and the five implementations is a `Result`, so
    /// the encoding exists at two functions rather than throughout.
    ///
    /// The `Ok` arm is the description **unpublished**: nobody else can see
    /// it, and `generic_openat` finishes it -- mount, inode, flags -- before
    /// it gives anyone a reference. It was a published `*mut fd` with a
    /// reference taken until 2026-10-01, which every one of those writes then
    /// went through as `unsafe { (*fd).x = .. }`.
    fn open(
        &self,
        _mount: &mount,
        _path: &CStr,
        _flags: c_int,
        _mode: c_int,
    ) -> Result<Box<fd>, Errno> {
        Err(Errno::EPERM)
    }

    /// Read a symbolic link.
    ///
    /// The default is `_EINVAL`, which is also the answer for a path that is
    /// not a symlink — so a path walk over a filesystem with no links treats
    /// it as an ordinary name, which is what it did when this was `None`.
    ///
    /// `buf` is a slice, not a pointer and a length: the two always travelled
    /// together and were put back together with `from_raw_parts` inside each
    /// of the five implementations.
    fn readlink(&self, _mount: &mount, _path: &CStr, _buf: &mut [u8]) -> isize {
        EINVAL as isize
    }

    /// The open file a symlink stands for, when following it means that file
    /// rather than the name its text spells: `/proc/<pid>/fd/<n>` onto a pipe,
    /// a socket or an anonymous inode, whose link reads `pipe:[123]`. The path
    /// walk asks this before reading the link. `Ok(None)` for every other
    /// link, which the walk follows by its text as before; an errno for a
    /// link that may be read but not followed (`/proc/<pid>/map_files/*`
    /// without `CAP_SYS_ADMIN`).
    fn magic_link(&self, _mount: &mount, _path: &CStr) -> Result<Option<crate::FdOwned>, std::ffi::c_int> {
        Ok(None)
    }

    /// Whether the link at `path` is a **magic link**: one that stands for an
    /// open file or a task's directory rather than for its text --
    /// `/proc/<pid>/fd/<n>`, `cwd`, `root` and `exe`, whether or not the file
    /// it reaches has a name. `openat2`'s `RESOLVE_NO_MAGICLINKS` refuses to
    /// follow one, and the two scoping flags refuse because it jumps out of
    /// whatever subtree the walk was kept in. `/proc/self` is not one: its
    /// text is the whole of what it means.
    fn is_magic_link(&self, _mount: &mount, _path: &CStr) -> bool {
        false
    }

    /// Whether reading a symlink here needs no I/O, because the link lives in
    /// this process's memory. `RESOLVE_CACHED` follows only these: a link on
    /// a host filesystem is a host syscall, which is the blocking step that
    /// flag exists to refuse.
    fn links_in_memory(&self) -> bool {
        false
    }

    fn link(&self, _mount: &mount, _src: &CStr, _dst: &CStr) -> c_int {
        EPERM
    }

    fn unlink(&self, _mount: &mount, _path: &CStr) -> c_int {
        EPERM
    }

    fn rmdir(&self, _mount: &mount, _path: &CStr) -> c_int {
        EPERM
    }

    fn rename(
        &self,
        _mount: &mount,
        _src: &CStr,
        _dst: &CStr,
        _flags: c_uint,
    ) -> c_int {
        EPERM
    }

    fn symlink(
        &self,
        _mount: &mount,
        _target: &CStr,
        _link: &CStr,
    ) -> c_int {
        EPERM
    }

    fn mknod(
        &self,
        _mount: &mount,
        _path: &CStr,
        _mode: mode_t_,
        _dev: dev_t_,
    ) -> c_int {
        EPERM
    }

    fn mkdir(&self, _mount: &mount, _path: &CStr, _mode: mode_t_) -> c_int {
        EPERM
    }

    /// The mount's half of closing a descriptor.
    ///
    /// `fd_close` calls the driver's [`crate::FdOps::close`] and then this one,
    /// unless the driver says it already did — see
    /// [`crate::FdOps::close_covers_mount`]. The default has nothing to do.
    fn close(&self, _fd: &mut fd) -> c_int {
        0
    }

    // ---- attributes ------------------------------------------------------

    /// `stat` by path. **Three answers, three states**, as [`FsOps::fstat`].
    ///
    /// | | |
    /// | --- | --- |
    /// | `None` | this filesystem cannot answer `stat` |
    /// | `Some(Err(e))` | it tried and failed |
    /// | `Some(Ok(stat))` | here it is |
    ///
    /// The callers disagree about `None` on purpose, and the disagreement is
    /// the reason the case is a variant rather than an errno:
    /// `crates/fs/generic` refuses with `_EPERM`, while the three path-walk
    /// sites in `crates/fs/path` treat it as "carry on treating this as a
    /// name" — a walk over a filesystem that cannot stat is not an error, it
    /// just finds no symlink to follow.
    ///
    /// It was `(…, stat: &mut statbuf) -> Option<c_int>` until 2026-09-16; see
    /// `docs/changelog/2026-09-16-a-return-type-that-could-not-say-what-happened.md`
    /// for what that cost at `fstat`'s call sites.
    fn stat(&self, _mount: &mount, _path: &CStr) -> Option<Result<statbuf, c_int>> {
        None
    }

    /// Whether this filesystem grants `want` (`AC_*` bits) on `path` although
    /// the mode [`FsOps::stat`] reported refused it. Asked only after that
    /// refusal, so a filesystem pays nothing for the ordinary case.
    ///
    /// Linux's `inode_operations.permission` in the one shape this kernel
    /// needs: procfs's `proc_fd_permission`, which lets a process into its
    /// own `/proc/<pid>/fd` even once that directory is root's. The default
    /// grants nothing.
    fn permits_despite_mode(&self, _mount: &mount, _path: &CStr, _want: c_int) -> bool {
        false
    }

    /// `stat` by descriptor. **Three answers, three states.**
    ///
    /// | | |
    /// | --- | --- |
    /// | `None` | this filesystem does not answer `fstat` at all |
    /// | `Some(Err(e))` | it tried and failed, with a negative guest errno |
    /// | `Some(Ok(stat))` | here it is |
    ///
    /// It was `fn fstat(&self, fd: &fd, stat: &mut statbuf) -> Option<c_int>`
    /// until 2026-09-16 — an out parameter for the answer and an errno beside
    /// it, so "no answer", "failed" and "succeeded" were two of them in the
    /// return and one in a buffer the caller had to have zeroed first.
    ///
    /// The doc that stood here said the shape was wrong and named the proof:
    /// *"absent is `_EINVAL` in `crates/fs/statcalls`, `_ENOMEM` in
    /// `crates/fs/inode`'s orphan bookkeeping, and 'no answer at all' in
    /// `crates/kernel/rwcalls` and `crates/kernel/fdcalls`, both of which want
    /// an `Option<statbuf>` back."* Three callers had built three *different*
    /// adapters over it — `Result<statbuf, c_int>` in `crates/kernel/execcalls`,
    /// `Option<statbuf>` in `crates/kernel/fdattr`, and
    /// `Result<statbuf, c_int>` again in `crates/fs/generic` — which is what a
    /// return type that cannot say what happened costs.
    ///
    /// Safe, where every other method here is `unsafe fn`: this one takes no
    /// mount, and its parameter is a reference. The descriptor's own `mount`
    /// field is what an implementation reaches, and that is `struct fd`'s
    /// invariant rather than this caller's.
    fn fstat(&self, _fd: &fd) -> Option<Result<statbuf, c_int>> {
        None
    }

    fn setattr(&self, _mount: &mount, _path: &CStr, _attr: Attr) -> c_int {
        EPERM
    }

    /// Change an attribute the descriptor itself holds.
    ///
    /// **A `*mut fd` and an `unsafe fn` until 2026-09-15**, alone among this
    /// trait's methods, because `crates/fs/adhoc` wrote `fd.stat`'s `uid`,
    /// `gid` and `mode` through it — an `fchmod` on an eventfd or a pipe,
    /// which has no inode to put them on — while `adhoc_fstat` copied the
    /// whole `statbuf` out. Five of the six implementations opened with
    /// `&*fd`; the pointer was there for the sixth's three writes.
    ///
    /// Those three are `AtomicU32` on the descriptor now — see
    /// [`fd::attr_mode`] — so this is a `&fd` like the rest and the trait has
    /// no `unsafe fn` left.
    fn fsetattr(&self, _fd: &fd, _attr: Attr) -> c_int {
        EPERM
    }

    fn utime(
        &self,
        _mount: &mount,
        _path: &CStr,
        _atime: timespec,
        _mtime: timespec,
        _follow_links: bool,
    ) -> c_int {
        EPERM
    }

    /// `futimens` -- `utimensat(fd, NULL, ...)` -- answered by the descriptor
    /// itself, for a filesystem whose descriptors have no path the walk could
    /// resolve back to them. `None` is "resolve the descriptor's path", which
    /// is right for every filesystem that has one and is the default.
    ///
    /// The sentinels are resolved: `None` for a field is `UTIME_OMIT`, and
    /// `touch` says both were `UTIME_NOW` (or there were no times), which
    /// Linux lets a writer do where an explicit time needs the owner. The
    /// permission check is the implementation's, because it holds the owner.
    ///
    /// For POSIX message queues: a queue descriptor's path is `/<name>`, which
    /// the walk would resolve on the root filesystem -- so `futimens` on one
    /// set the times of whatever file there had that name.
    fn futime(
        &self,
        _fd: &fd,
        _atime: Option<timespec>,
        _mtime: Option<timespec>,
        _touch: bool,
    ) -> Option<c_int> {
        None
    }

    /// The guest path a descriptor was opened by, for `/proc/<pid>/fd`.
    ///
    /// Answered into `buf`, NUL-terminated, with [`fill_path`] — which is the
    /// whole of the length rule and is why this takes a slice. It was a
    /// `*mut c_char` and "the caller supplies `MAX_PATH + 1` bytes" written in
    /// eight `# Safety` sections until 2026-09-14; two callers supplied
    /// `MAX_PATH`, and two of the eight accepted a path of exactly `MAX_PATH`
    /// and wrote the terminator one past it.
    fn getpath(&self, _fd: &fd, _buf: &mut [u8]) -> c_int {
        EPERM
    }

    /// `flock`, if this filesystem has one of its own.
    ///
    /// `None` rather than a default, because the default is not an errno: a
    /// filesystem with no `flock` gets `fs_locks::flock_generic`, this
    /// kernel's own implementation over the descriptor. That lives a layer
    /// above and cannot be reached from here, so the caller keeps it.
    fn flock(&self, _fd: &fd, _operation: c_int) -> Option<c_int> {
        None
    }

    // ---- extended attributes ---------------------------------------------

    /// `_EOPNOTSUPP` by default, which is Linux's answer for a filesystem with
    /// no xattr support and is what `crates/fs/xattrabi`'s rules are written
    /// against.
    fn xattr(
        &self,
        _mount: &mount,
        _path: &CStr,
        _call: XattrCall<'_>,
        _follow_links: bool,
    ) -> isize {
        EOPNOTSUPP as isize
    }

    fn fxattr(&self, _fd: &fd, _call: XattrCall<'_>) -> isize {
        EOPNOTSUPP as isize
    }

    // ---- notification ----------------------------------------------------

    /// The last link to an inode has gone and nothing holds it open.
    ///
    /// A notification, so the default is to do nothing: only a filesystem that
    /// keeps something per inode has anything to release.
    fn inode_orphaned(&self, _mount: &mount, _inode: ino_t) {}
}

/// Answer a path into a caller's buffer, NUL-terminated: `0`, or
/// `_ENAMETOOLONG` if it does not fit.
///
/// **It has to fit *with* its terminator**, which is the byte six copies of
/// this disagreed about. `crates/fs/proc`, `crates/fs/tmpfs` and
/// `crates/fs/devpts` refused a path of `MAX_PATH`; `crates/fs/realfs` and
/// `crates/kernel/memfdcalls` accepted one and wrote a terminator at
/// `buf[MAX_PATH]`, and `crates/fs/adhoc` checked nothing at all and was
/// bounded only by the length of the six names it can produce. None of the six
/// was told how large the buffer was — the length was a sentence in a
/// `# Safety` section, and two callers had a buffer one byte short of it.
///
/// So this takes the slice and asks it. There is one copy of the rule, and a
/// caller that gets its buffer wrong now gets `_ENAMETOOLONG` for a path it
/// could not have held anyway.
pub fn fill_path(buf: &mut [u8], path: &[u8]) -> c_int {
    // `>=`, because the terminator needs a byte of its own.
    if path.len() >= buf.len() {
        return ENAMETOOLONG;
    }
    buf[..path.len()].copy_from_slice(path);
    buf[path.len()] = 0;
    0
}

/// The bytes before the first NUL in a buffer [`fill_path`] filled.
///
/// The other half of the same rule: every reader of one of these buffers wrote
/// its own `CStr::from_ptr` or `iter().position(|&c| c == 0)`, and a buffer
/// with no NUL in it — which a failed call leaves — read past the end in the
/// first spelling and answered the whole buffer in the second.
pub fn path_bytes(buf: &[u8]) -> &[u8] {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    &buf[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Nothing;
    impl FsOps for Nothing {
        fn name(&self) -> Option<&'static CStr> {
            None
        }
        fn magic(&self) -> u32 {
            0
        }
    }

    static NOTHING: Nothing = Nothing;
    static HANDLE: FsHandle = FsHandle(&NOTHING);

    /// The defaults the call sites used to apply, one by one.
    #[test]
    fn a_filesystem_that_implements_nothing_refuses_the_right_way() {
        let fs: &dyn FsOps = &NOTHING;
        // A mount the test owns. It used to be `std::ptr::null_mut()`, which
        // worked only because none of these implementations dereferences it —
        // a fact the caller could not see and the type did not state. Now that
        // the trait takes `&mount`, a null is not expressible.
        let mut p = mount::default();
        let p = &mut p;
        // Eighteen sites said `_EPERM` for a missing name operation.
        assert_eq!(fs.unlink(p, c""), EPERM);
        assert_eq!(fs.mkdir(p, c"", 0), EPERM);
        assert_eq!(fs.getpath(&fd::default(), &mut []), EPERM);
        // `readlink` is `_EINVAL`, which a path walk reads as "not a symlink".
        assert_eq!(fs.readlink(p, c"", &mut []), EINVAL as isize);
        // xattr is `_EOPNOTSUPP`, Linux's answer for a filesystem without it.
        let call = XattrCall::Get {
            name: c"user.x",
            out: &mut [],
        };
        assert_eq!(fs.fxattr(&fd::default(), call), EOPNOTSUPP as isize);
        // Mounting and unmounting a filesystem with no state succeed. These
        // two are the only `&mut mount` in the trait: they are the only
        // methods that write the mount, and each runs while nothing else can
        // reach it.
        assert_eq!(fs.mount(p), 0);
        assert_eq!(fs.umount(p), 0);
        // And `statfs` fills in nothing, which `crates/kernel/fdattr` then
        // completes from `magic`.
        assert!(fs.statfs(p).is_ok_and(|b| b.bsize.is_none()));
        // The three whose callers disagree answer "no", not an errno.
        assert!(fs.stat(p, c"").is_none());
        assert!(fs.fstat(&fd::default()).is_none());
        assert!(fs.flock(&fd::default(), 0).is_none());
    }

    /// The byte the six hand-written copies disagreed about.
    #[test]
    fn a_path_answer_has_to_fit_with_its_terminator() {
        let mut buf = [0xAAu8; 8];
        assert_eq!(
            fill_path(&mut buf, b"12345678"),
            ENAMETOOLONG,
            "8 + NUL > 8"
        );
        assert_eq!(buf, [0xAA; 8], "a refusal writes nothing");

        // And the one that fits exactly, which is the case the two callers
        // with a `MAX_PATH` buffer used to overrun by a byte.
        assert_eq!(fill_path(&mut buf, b"1234567"), 0);
        assert_eq!(&buf, b"1234567\0");

        assert_eq!(fill_path(&mut buf, b"123456"), 0);
        assert_eq!(&buf[..7], b"123456\0");
        assert_eq!(buf[7], b'\0', "the byte the longer answer left");

        // The empty path is a terminator and nothing else, and a zero-length
        // buffer cannot even hold that -- which is what the trait's default
        // implementation is handed by the test above.
        assert_eq!(fill_path(&mut buf, b""), 0);
        assert_eq!(buf[0], 0);
        assert_eq!(fill_path(&mut [], b""), ENAMETOOLONG);
    }

    #[test]
    fn reading_one_back_stops_at_the_terminator_and_at_the_end() {
        let mut buf = [0u8; 8];
        assert_eq!(fill_path(&mut buf, b"/dev"), 0);
        assert_eq!(path_bytes(&buf), b"/dev");
        // No terminator: what a caller sees when it reads a buffer a failed
        // call never filled.
        assert_eq!(path_bytes(&[b'x'; 4]), b"xxxx");
        assert_eq!(path_bytes(&[]), b"");
    }

    /// What `iul.h`'s four `extern const struct fs_ops` are, and the property
    /// that makes taking their address meaningful.
    ///
    /// A fat pointer, so sixteen bytes rather than zero: two distinct
    /// zero-sized statics may share an address, and `&realfs == &procfs`
    /// would have made `do_mount` unable to tell them apart.
    #[test]
    fn a_handle_is_a_distinct_address_per_filesystem() {
        assert_eq!(size_of::<FsHandle>(), 2 * size_of::<usize>());
        let back = unsafe { FsHandle::deref(&HANDLE) }.expect("a handle is not null");
        assert!(back.name().is_none());
        assert!(unsafe { FsHandle::deref(std::ptr::null()) }.is_none());
    }
}
