//! `struct fd` — an open file description. Rust's, since 2026-09-05.
//!
//! # Why it is here
//!
//! The same reason `struct task` is, and the same order: no C reads a field of
//! it. The last two were the fakefs stat test reaching
//! `fd->mount->fs->fstat` and `tests/integration/sbm_api_test.c` asking
//! `S_ISCHR(fd->type)`, and each got an accessor — `fd_fstat` and `fd_type` in
//! `crates/fs/fdobj`. `fs/fd.h` forward-declares the struct now.
//!
//! It lives in `taskview` rather than in `crates/fs/fdobj`, which owns
//! descriptors, because a shared type has to sit **below** everything that
//! uses it and `fdobj` does not: forty-five crates name a `struct fd`, and
//! `fdobj` depends on several of them. The crate's name is historical.
//!
//! # There is no union
//!
//! What a description *is* was a union of one raw pointer per kind, read on
//! the promise that the arm matched the operations table. It is
//! `driver_state` now, an owned `Box<dyn Any>` each driver downcasts; see the
//! field. Every kind keeps its state in the crate that understands it, with
//! no exception, and `struct fd` names none of their types.

#![allow(non_camel_case_types)]

use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicI64, AtomicU32, Ordering,
};

use crate::{
    cond_t, ino_t, lock_t, mode_t_, mount, off_t_, poll_watchers, statbuf,
};

/// A terminal: the real type since 2026-09-29, which `tty_types.rs`'s driver
/// table names.
///
/// The descriptor kinds' own states -- an eventfd's counter, a pipe's end,
/// an epoll set, a timerfd, a pidfd, a socket -- were re-exported here too,
/// two of them as placeholders because their owners depend on this crate.
/// None is named any more: `fd.driver_state` holds each as an `Any`.
pub use fs_tty::tty::Tty as tty;

/// The real `struct inode_data`, not a placeholder.
///
/// It was one until 2026-09-08, with a comment saying `fs/inode.h` "*does*
/// define this one" and that a caller reading `fd.inode` "writes a `.cast()`".
/// There were eight such casts, and every one of them was an unchecked
/// conversion between two renderings of the same type — the shape
/// `clippy::useless_transmute` found eight of on 2026-09-06. `src/abi.rs`
/// holds the definition now, so the field has the type it always meant.
use crate::inode_types::inode_data;

/// The `*at` base that means "the calling task's working directory".
///
/// `iul.h` states it — `#define AT_PWD (struct fd *) -2` — so it is the
/// embedder interface and the value cannot change. What it can stop being is
/// **eight definitions**, which is what it was until 2026-09-14: `fs/fdobj`,
/// `fs/generic`, `fs/sock`, `kernel/pathcalls`, `kernel/execcalls`,
/// `kernel/inotifycalls`, `fs/mountcalls` and `tools/iul` each had one, and
/// the comment above the first of them read "A macro, so this is the one
/// copy."
///
/// # It is inside the error range, and that is not an accident anything checks
///
/// `-2` is what [`crate::is_err`] calls an errno, and
/// [`crate::ptr_err`] reads it back as 2 — `ENOENT`. Nothing confuses the two
/// today because the functions that answer an `ERR_PTR` and the functions that
/// accept an `*at` base are disjoint sets, which is a property of the call
/// graph rather than of the values. The fix for that is a type: an enum with
/// a `Pwd` arm and an `Fd` arm, converted at the three `iul.h` declarations
/// that take a `struct fd *at` and nowhere else. That is step 9.6 of
/// `docs/object-model-arc.md` and is not this.
pub const AT_PWD: *mut fd = -2isize as *mut fd;

/// What a `*at` path is resolved against.
///
/// **This is [`AT_PWD`] as a type**, and it is step 9.6 of
/// `docs/object-model-arc.md`, designed on 2026-09-12 and done on 2026-09-16.
/// Every `generic_*at` took a `*mut fd` that was one of three things — the
/// sentinel, a live description, or null — and the reason that was safe is
/// written above: the functions that answer an `ERR_PTR` and the functions
/// that accept an `*at` base are disjoint sets, *which is a property of the
/// call graph rather than of the values*. `-2` is `ENOENT` to
/// [`crate::ptr_err`], and nothing in the type said which reading applied.
///
/// Two states, named, and the third — null — is the `Option`/`Result` the
/// converter answers rather than a value of this type.
///
/// `Copy`, because it owns nothing: the borrow is `f_get`'s reference, which
/// `syscall_refs_drain` releases when the syscall returns.
#[derive(Clone, Copy)]
pub enum At<'a> {
    /// The calling task's working directory — `AT_FDCWD`, and what an
    /// absolute path resolves against too.
    Pwd,
    /// A directory descriptor the guest named.
    Fd(&'a fd),
}

impl<'a> At<'a> {
    /// From `iul.h`'s `struct fd *at`.
    ///
    /// The **three** declarations in that header take one — `generic_mkdirat`,
    /// `generic_mknodat` and `generic_symlinkat` — and they are the only place
    /// this conversion happens. `None` is a null, which those three answer
    /// `EBADF` for.
    ///
    /// # Safety
    /// `at` is [`AT_PWD`], a live description, or null.
    pub unsafe fn from_raw(at: *mut fd) -> Option<At<'a>> {
        if at == AT_PWD {
            return Some(At::Pwd);
        }
        // SAFETY: the caller's contract.
        unsafe { at.as_ref() }.map(At::Fd)
    }

    /// The descriptor, or `None` for the working directory.
    pub fn fd(self) -> Option<&'a fd> {
        match self {
            At::Pwd => None,
            At::Fd(fd) => Some(fd),
        }
    }
}

/// A descriptor named as an **identity**, not as a reference: "is this the
/// same description" for `crates/fs/sockrestart`'s accept waiters.
///
/// **Never turned back into the description since 2026-10-17.** It had a
/// `with` that borrowed the description it named, under the contract "the
/// entry is still in its registry". The three registries that used it --
/// `crates/kernel/signalfdcalls`' and `crates/kernel/inotifycalls`' wake lists
/// and `crates/kernel/pidfd`'s exit list -- keep a `Weak<fd>` now. Two of them
/// copied ids out under their lock and woke them after releasing it, and a
/// close on another thread freed the description in between:
/// `tests/guest/src/bin/signalfd_close_race.rs` under `MallocScribble=1`
/// crashed in `poll_wakeup` three runs of three.
///
/// An address and nothing else, so it is `Send` without an `unsafe impl`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FdId(usize);

impl FdId {
    pub fn of(fd: &fd) -> FdId {
        FdId(std::ptr::from_ref(fd).addr())
    }
}

/// What an `O_TMPFILE` description knows about its file, which no path names.
#[derive(Default, Debug)]
pub struct Unnamed {
    /// The guest directory it was made in, absolute: `/proc/<pid>/fd` reads
    /// `<dir>/#<inode> (deleted)`, as Linux's dentry for one does.
    pub dir: std::ffi::CString,
    /// Not `O_EXCL`: `linkat` may name it.
    pub linkable: bool,
    /// fakefs: the file's host name, relative to the mount's root directory,
    /// which keeps it linkable on a host that cannot link a descriptor.
    pub host: Option<std::ffi::CString>,
    /// realfs: a host descriptor that can read the file, for a description
    /// that cannot -- `O_TMPFILE|O_WRONLY` -- which naming it has to copy.
    pub source: Option<std::os::fd::OwnedFd>,
}

/// An open file description: what `f_get` answers and what a descriptor number
/// in the table points at.
#[repr(C)]
#[derive(Default)]
pub struct fd {
    /// What runs when the last reference goes: the descriptor layer's
    /// finalizer, installed when the description is published. `None` for one
    /// that never was, which is dropped without any driver's `close`.
    ///
    /// It was `owner`, a pointer to `crates/fs/fd`'s control block, until
    /// 2026-10-17, when the count became the `Arc` around this struct; see
    /// [`FdOwned`] and `Drop for fd`.
    pub finalizer: Option<fn(&mut fd) -> std::ffi::c_int>,
    /// The status flags: `O_NONBLOCK` and the rest that `F_SETFL` can change.
    ///
    /// Atomic, like every field below that a **live** description's own
    /// operations write: see the note on this struct. Read with [`fd::flags`].
    pub flags: AtomicU32,
    /// Just the `S_IFMT` part — what kind of thing this is open on. It cannot
    /// change.
    pub type_: mode_t_,
    /// The driver: which filesystem or device this description is answered by.
    ///
    /// A `*const fd_ops` — a table of fifteen nullable function pointers —
    /// until 2026-09-11. `None` is a descriptor with no driver yet, which is
    /// what `fd_create` makes and what `Default` gives.
    pub ops: Option<&'static dyn crate::FdOps>,
    /// The guest path this was opened by, kept only for a writable descriptor
    /// and only so close can report `IN_CLOSE_WRITE` without asking the
    /// filesystem to reconstruct it. `None` otherwise, which is every
    /// read-only descriptor.
    ///
    /// Written by `generic_openat` before the description is published, so a
    /// plain field. It was an `AtomicPtr` to a `strdup`, which the criterion
    /// on this struct's atomics does not ask for, and which `fd_finalize`
    /// `free`d by hand.
    pub inotify_path: Option<std::ffi::CString>,
    /// Everything watching this description for readiness: the transient
    /// `poll()`/`select()` sets and the durable watchers — epoll. Rust-owned
    /// and independently refcounted, so neither side has to be alive for the
    /// other to tear down. It was two intrusive C lists with a descriptor lock
    /// ordering them against each other; see `crates/fs/pollset`.
    ///
    /// An `Arc` since 2026-09-30: it was `Arc::into_raw`, made in `fd_create`
    /// and taken back in `fd_finalize`, and every reader rebuilt a
    /// `ManuallyDrop<Arc>` from it to borrow.
    pub poll_watchers: std::sync::Arc<poll_watchers>,
    /// Signed, as Linux's `loff_t` is. It was `unsigned long`, which made a
    /// negative offset unrepresentable and therefore silent: `generic_seek`'s
    /// `LSEEK_SET` stored one without checking, and `lseek(fd, -4096,
    /// SEEK_SET)` on tmpfs answered -4096 and left the descriptor positioned
    /// at 0xfffffffffffff000. A signed field is what lets `offset < 0` be a
    /// question the code can ask.
    ///
    /// Atomic: `lseek`, a stream read and `getdents64` all move it, and none
    /// of them holds a lock across the whole sequence.
    pub offset: AtomicI64,
    /// The driver's state for the description: a pipe's end, an eventfd's
    /// counter, an epoll set, a socket, and the rest. Read with
    /// [`fd::driver_state`].
    ///
    /// **Owned, and typed at the read**, since 2026-09-29, like `fs_data`
    /// beside it -- a slot of its own because a terminal opened on devpts or
    /// fakefs carries both. It was `union fd_state`, a raw pointer per kind:
    /// every read was an `unsafe` union access on the promise that the arm
    /// matched the operations table, and every `close` freed its arm by hand
    /// and nulled it against a second free. A wrong-kind read is a `None`
    /// now, and the value drops with the description. Two of the arms named
    /// placeholders -- `pidfd_state` and `socket_state` -- because their
    /// owners depend on this crate; an `Any` needs no name, so they went too.
    ///
    /// Written at creation, before the description is installed, and taken
    /// only by `close`, through `&mut`. So it needs no lock and no
    /// `OnceLock`: nothing can read it while either happens.
    pub driver_state: Option<Box<dyn std::any::Any + Send + Sync>>,
    /// Per-filesystem descriptor state: tmpfs's, procfs's, devpts's, a
    /// memfd's, and fakefs's directory cache. Read with [`fd::fs_data`].
    ///
    /// **Owned, and typed at the read**, since 2026-09-29. It was an
    /// `AtomicPtr<c_void>`: each filesystem stored a `Box::into_raw`, cast it
    /// back on every read on the promise that the description was its own,
    /// and freed it by hand in its `close`. The `Box` is this field's now and
    /// goes with the description; a read is a `downcast_ref`, which checks the
    /// type the cast assumed.
    ///
    /// A `OnceLock` because two of the five fill it on **first use** rather
    /// than at open, which is a store on a live description -- a race the
    /// compare-exchange this replaced had to be written for, and that
    /// `get_or_init` does not have.
    pub fs_data: std::sync::OnceLock<Box<dyn std::any::Any + Send + Sync>>,
    /// The mount this was opened through.
    pub mount: *mut mount,
    /// The host descriptor behind it, for a realfs or fakefs file, a socket or
    /// a memfd. Seeks on it need the lock. Read with [`fd::host`].
    ///
    /// An `OwnedFd` since 2026-09-29, when the description stopped being
    /// `calloc`ed: it was an `int` that `realfs_close` closed by hand, and
    /// every reader of it -- forty, most of them `unsafe fn` for no reason but
    /// this field -- took on trust that it was open. `realfs_close` takes it
    /// to report `close(2)`'s answer; anything left closes when the
    /// description drops.
    pub real_fd: Option<std::os::fd::OwnedFd>,
    /// What this description holds of its inode's `writers`, so that close can
    /// give it back: a write-capable open took one, an exec took a denial.
    pub holds_write_access: bool,
    /// The other half of that: an exec's denial.
    ///
    /// **Atomic, unlike `holds_write_access` beside it**, and the difference is
    /// this struct's stated criterion rather than a preference. That one is
    /// written by `generic_open` on the construction path, which holds the only
    /// pointer there is. This one is written by `crates/kernel/execcalls`'
    /// `checked_for_exec`, which runs on two kinds of descriptor: a fresh one
    /// it opened, and -- for `execveat(fd, "", AT_EMPTY_PATH)` -- **the
    /// caller's**, which is published and can be shared by a `dup` or a `fork`.
    /// Two threads exec'ing one descriptor both stored to this byte.
    ///
    /// The value cannot be wrong (both stores write `true`, and the reader is
    /// `fd_finalize` at a strong count of zero, which cannot run while
    /// `from_descriptor`'s own `fd_retain` is held), so nothing was observed.
    /// It is a data race all the same, and one byte of `AtomicBool` is free.
    pub denies_write: AtomicBool,
    /// Whether the open that made this description created the file — Linux's
    /// `FMODE_CREATED`, which `fcntl(F_CREATED_QUERY)` reports.
    pub created: bool,
    /// Linux's `f_owner`: who is told when this description becomes ready.
    ///
    /// A **negative** owner is a process group, which is Linux's encoding and
    /// is why this is signed. Zero is nobody.
    ///
    /// **Recorded and reported; nothing raises the signal yet.** Refusing
    /// these instead was the position until 2026-09-04, and the measurement
    /// that replaced that reasoning is that nginx's master calls
    /// `ioctl(FIOASYNC)` and `fcntl(F_SETOWN)` on its worker channel and
    /// treats either failure as fatal — so nginx did not start at all.
    pub owner_pid: AtomicI32,
    /// Which signal, from `F_SETSIG`. Zero means `SIGIO`.
    pub owner_sig: AtomicI32,
    /// The host directory stream a listing walks, for realfs and the fakefs
    /// descriptors that forward to it.
    ///
    /// Installed on the first listing, on a live description, so two threads
    /// may race to make it: the loser's stream is dropped, and closed with it.
    /// It was an `AtomicPtr<DIR>` compare-exchanged by hand until 2026-09-29,
    /// and closed by hand in `realfs_close`. Boxed because every description
    /// carries the field and few are directories anyone lists: inline, the
    /// stream's mutex cost each one twenty-four bytes more.
    pub dir: std::sync::OnceLock<Box<util_hostdir::HostDir>>,
    /// The path a fakefs change event reports, for a description that may
    /// modify its file. Written at open, before the description is published.
    ///
    /// A `strdup`ed `char *` that `fd_finalize` `free`d until 2026-09-29.
    pub change_path: Option<std::ffi::CString>,
    /// The inode this description is open on, for the filesystems that have
    /// an inode table. An `Arc` since 2026-10-01; it was a `*mut` holding a
    /// reference that `fd_finalize` gave back with `inode_release`.
    pub inode: Option<std::sync::Arc<inode_data>>,
    /// The fakefs inode number, which is `meta.db`'s and not the host's.
    pub fake_inode: ino_t,
    /// An `O_TMPFILE` file: one with no name, which `linkat` may give it.
    /// Written before the description is published.
    pub unnamed: Option<Box<Unnamed>>,
    /// The cached stat a fakefs descriptor answers `fstat` from.
    pub stat: statbuf,
    /// The three attributes a driver may change **after the descriptor is
    /// published**, held atomically because `stat` cannot be.
    ///
    /// `crates/fs/adhoc` is the only writer: an `fchmod` or `fchown` on a pipe,
    /// a socket or an anonymous inode, which has no inode to put them on. It
    /// wrote `stat.uid`, `stat.gid` and `stat.mode` directly until 2026-09-15,
    /// racing `adhoc_fstat`'s `*stat = fd.stat` — a hundred-byte non-atomic
    /// copy — so a concurrent `fchown` and `fstat` on one pipe could answer an
    /// old uid beside a new gid. That is why `FsOps::fsetattr` took `*mut fd`
    /// where every other method of that trait takes a reference.
    ///
    /// `stat` keeps its creation-time value and stays authoritative for
    /// everything else, including the **type** bits: `adhoc_fsetattr`
    /// preserves `S_IFMT`, so a reader asking `stat.mode & S_IFMT` — which is
    /// what `crates/fs/realfs`'s mmap path does — is right either way.
    pub attr_mode: AtomicU32,
    /// See [`fd::attr_mode`].
    pub attr_uid: AtomicU32,
    /// See [`fd::attr_mode`].
    pub attr_gid: AtomicU32,
    /// The descriptor's own lock, and the condition a blocking read parks on.
    pub lock: lock_t,
    /// See [`fd::lock`].
    pub cond: cond_t,
}

/// The fields a **live** description's own operations read and write.
///
/// Seven of `fd`'s fields are atomic, and the criterion is not "could two
/// threads reach it" — every field of a shared description can be reached by
/// two threads — but **is it written after the descriptor is published**. The
/// construction path writes the rest through an exclusive reference, because
/// `FsOps::open` is handed the descriptor before anything can look it up.
///
/// The accessors below are what a caller writes, so that `Relaxed` is decided
/// once rather than at ninety call sites. `Relaxed` is right for all of them:
/// each is a single value that nothing else is ordered against. Where two of
/// them have to agree — `lseek`'s read-modify-write of `offset` — the answer is
/// a lock (`fd->lock`, which `crates/kernel/rwcalls`' `FdGuard` takes), not a
/// stronger ordering, and that is a separate question from this one.
impl fd {
    /// The same descriptor as a pointer, for a callee that has not been
    /// converted to take a reference yet.
    ///
    /// A shared reference to a `*mut`, which is only sound because nothing
    /// writes a description's fields through such a pointer any more — the
    /// seven a live description writes are atomics above, and the rest are
    /// written on the construction path, which holds the only pointer there
    /// is. **The number of calls to this is the size of the remaining
    /// conversion**, and it should reach zero:
    ///
    /// ```text
    /// rg -o '\.as_ptr\(\)' --glob '*.rs' crates | wc -l
    /// ```
    ///
    /// (That grep over-reports — `as_ptr` is also `slice`'s and `CStr`'s — so
    /// the honest count is `rg -c 'fd\.as_ptr\(\)'`.)
    pub fn as_ptr(&self) -> *mut fd {
        (&raw const *self).cast_mut()
    }

    pub fn flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    /// A description answered by `ops`, every other field at its default.
    ///
    /// The struct-update form `fd { ops, ..Default::default() }` stopped
    /// compiling on 2026-10-17, when `struct fd` gained a `Drop`: a value of a
    /// type with one cannot be taken apart to fill the rest.
    pub fn with_ops(ops: Option<&'static dyn crate::FdOps>) -> fd {
        let mut fd = fd::default();
        fd.ops = ops;
        fd
    }

    /// The host descriptor behind this description, borrowed for as long as
    /// the description is. `None` for one that has none: a pipe, an eventfd,
    /// anything on tmpfs or procfs.
    pub fn host(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd as _;
        self.real_fd.as_ref().map(|fd| fd.as_fd())
    }
    /// Whether this descriptor names a file without being able to read or
    /// write it.
    ///
    /// That is the whole of what `O_PATH` is, and without the check it would be
    /// a way to read a file the caller has no permission for. The answer to
    /// using one is `EBADF` and not `EACCES`: it is not a descriptor you can do
    /// this with.
    ///
    /// Here rather than in `crates/fs/fdobj`, where it was an
    /// `unsafe fn(*mut fd)` until 2026-09-16: it is one read of the field above
    /// it, so a pointer and a contract bought nothing. Its null check was dead
    /// at **all five** call sites -- every one of them tests `f_get`'s answer
    /// for null on the line before.
    pub fn is_path_only(&self) -> bool {
        self.flags() & crate::O_PATH_ != 0
    }

    pub fn set_flags(&self, v: u32) {
        self.flags.store(v, Ordering::Relaxed);
    }

    pub fn offset(&self) -> off_t_ {
        self.offset.load(Ordering::Relaxed)
    }
    pub fn set_offset(&self, v: off_t_) {
        self.offset.store(v, Ordering::Relaxed);
    }

    pub fn denies_write(&self) -> bool {
        self.denies_write.load(Ordering::Relaxed)
    }
    /// Record that this description holds an inode's write denial, so that
    /// `fd_finalize` gives it back.
    pub fn set_denies_write(&self, v: bool) {
        self.denies_write.store(v, Ordering::Relaxed);
    }

    /// The mount this was opened through, if it has one.
    ///
    /// Safe because a description **holds a reference** on its mount: taken
    /// by `NewFd::set_mount` before the description is published and given back
    /// by `fd_finalize` after the last reference to the description goes. So
    /// the mount outlives any borrow of the description, and a mount is only
    /// written through `&mut` while its count is zero -- at `do_mount`, before
    /// it is in the table, and at `fs_mount::destroy`, after.
    pub fn mount(&self) -> Option<&mount> {
        // SAFETY: as above.
        unsafe { self.mount.as_ref() }
    }

    /// The inode this was opened on, if its filesystem has an inode table.
    pub fn inode(&self) -> Option<&inode_data> {
        self.inode.as_deref()
    }

    /// The driver's state for the description, if it is a `T`.
    pub fn driver_state<T: std::any::Any>(&self) -> Option<&T> {
        self.driver_state.as_deref()?.downcast_ref()
    }

    /// Install the driver's state at creation. A `Box` rather than a value
    /// so that an object whose address is already known -- a timer callback
    /// holds one -- does not move.
    pub fn set_driver_state<T: std::any::Any + Send + Sync>(&mut self, value: Box<T>) {
        debug_assert!(self.driver_state.is_none(), "a description's driver state installed twice");
        self.driver_state = Some(value);
    }

    /// Take the driver's state back, for `close`. `None`, and the state left
    /// where it is, if it is not a `T`.
    pub fn take_driver_state<T: std::any::Any>(&mut self) -> Option<Box<T>> {
        match self.driver_state.take()?.downcast() {
            Ok(state) => Some(state),
            Err(other) => {
                self.driver_state = Some(other);
                None
            }
        }
    }

    /// This filesystem's state for the description, if it is a `T`.
    pub fn fs_data<T: std::any::Any>(&self) -> Option<&T> {
        self.fs_data.get()?.downcast_ref()
    }

    /// Install the state at open. Construction owns the description, so
    /// nothing else can have installed one; if something has, that is a bug
    /// and the first value stays.
    pub fn set_fs_data<T: std::any::Any + Send + Sync>(&self, value: T) {
        let installed = self.fs_data.set(Box::new(value)).is_ok();
        debug_assert!(installed, "a description's state installed twice");
    }

    /// The state, made by `init` on the first call. Two threads racing here
    /// both get the one that won -- which is the whole of what the
    /// compare-exchange and its loser-frees-its-own-box used to do. `None` if
    /// the state is some other type, which only a bug makes.
    pub fn fs_data_or_init<T: std::any::Any + Send + Sync>(
        &self,
        init: impl FnOnce() -> T,
    ) -> Option<&T> {
        self.fs_data.get_or_init(|| Box::new(init())).downcast_ref()
    }

    pub fn owner_pid(&self) -> ::std::os::raw::c_int {
        self.owner_pid.load(Ordering::Relaxed)
    }
    pub fn set_owner_pid(&self, v: ::std::os::raw::c_int) {
        self.owner_pid.store(v, Ordering::Relaxed);
    }

    /// See [`fd::attr_mode`]. `Relaxed`: the three are independent values a
    /// guest reads one `fstat` at a time, and nothing orders anything else
    /// against them.
    pub fn attr_mode(&self) -> u32 {
        self.attr_mode.load(Ordering::Relaxed)
    }
    pub fn set_attr_mode(&self, v: u32) {
        self.attr_mode.store(v, Ordering::Relaxed);
    }
    pub fn attr_uid(&self) -> u32 {
        self.attr_uid.load(Ordering::Relaxed)
    }
    pub fn set_attr_uid(&self, v: u32) {
        self.attr_uid.store(v, Ordering::Relaxed);
    }
    pub fn attr_gid(&self) -> u32 {
        self.attr_gid.load(Ordering::Relaxed)
    }
    pub fn set_attr_gid(&self, v: u32) {
        self.attr_gid.store(v, Ordering::Relaxed);
    }

    pub fn owner_sig(&self) -> ::std::os::raw::c_int {
        self.owner_sig.load(Ordering::Relaxed)
    }
    pub fn set_owner_sig(&self, v: ::std::os::raw::c_int) {
        self.owner_sig.store(v, Ordering::Relaxed);
    }
}

/// The description's last reference has gone: run its finalizer, in place.
///
/// **In place is the point.** Registries key on a description's address --
/// sockrestart, inotify, signalfd and pidfd deregister by the description's
/// address from inside `close` -- and `lock` and `cond` are pthread objects, so the value
/// must never move between publish and here. `Arc::into_inner` would move it;
/// a `Drop` runs where it lies, and the allocation goes after.
impl Drop for fd {
    fn drop(&mut self) {
        if let Some(finalize) = self.finalizer.take() {
            let err = finalize(self);
            closing::report(self, err);
        }
    }
}

/// The driver's close error, carried from `Drop for fd` back to the
/// [`FdOwned::close`] that gave up the last reference.
///
/// Only the release that ends a description reports, and only `close(2)` asks:
/// every other release discards it, as `crates/fs/fd`'s count did. A
/// thread-local keyed by the description, so a finalizer that closes some
/// other descriptor on the way cannot overwrite the outer answer, and a close
/// on this thread whose last reference went on another answers 0.
mod closing {
    use std::cell::Cell;
    use std::ffi::c_int;

    thread_local! {
        static SLOT: Cell<(usize, c_int)> = const { Cell::new((0, 0)) };
    }

    /// Run `release` -- the drop of one reference to `key` -- and answer what
    /// the finalizer reported if it ran here.
    pub(super) fn around(key: *const super::fd, release: impl FnOnce()) -> c_int {
        let saved = SLOT.replace((key.addr(), 0));
        release();
        SLOT.replace(saved).1
    }

    pub(super) fn report(fd: &super::fd, err: c_int) {
        let key = std::ptr::from_ref(fd).addr();
        let _ = SLOT.try_with(|s| {
            if s.get().0 == key {
                s.set((key, err));
            }
        });
    }
}

// SAFETY: every field a published description's operations write is an
// atomic, a lock or a `OnceLock`; `mount` is a raw pointer written only before
// publication (`NewFd::set_mount`) and read after, and `finalizer` is a plain
// `fn` written only by the owner of an unpublished description and taken by
// `Drop`, which has the only reference left.
unsafe impl Send for fd {}
// SAFETY: as `Send`.
unsafe impl Sync for fd {}

/// An owned reference to an open file description: an `Arc<fd>`.
///
/// **An `Arc` since 2026-10-17.** It was `crates/fs/fd`'s hand-rolled count --
/// a control block of a strong count, the payload's address and a finalizer,
/// reached through `struct fd`'s `owner` field -- because a descriptor had to
/// be dropped by a table that could not name it. The table is generic since
/// step 1 of the move, and this crate defines both, so the count is the `Arc`
/// and the finalizer is `Drop for fd`.
#[must_use = "dropping this releases the descriptor; a retain whose handle is \
              thrown away is a leak"]
#[derive(Clone)]
#[repr(transparent)]
pub struct FdOwned(std::sync::Arc<fd>);

impl FdOwned {
    /// A published description with its first reference -- `NewFd`'s, which
    /// installed the finalizer while it held the only one.
    pub fn new(fd: std::sync::Arc<fd>) -> Self {
        FdOwned(fd)
    }

    /// Another reference to a descriptor the caller already holds one for.
    ///
    /// # Safety
    ///
    /// `fd` came from an `FdOwned` and is live, and the caller holds a
    /// reference or a lock that stops the last one going.
    pub unsafe fn retain(fd: *mut fd) -> Self {
        // SAFETY: the caller's contract: an `Arc`'s data pointer, count > 0.
        unsafe {
            std::sync::Arc::increment_strong_count(fd.cast_const());
            FdOwned(std::sync::Arc::from_raw(fd.cast_const()))
        }
    }

    /// Adopts a reference handed out with [`FdOwned::into_raw`] -- a
    /// `#[repr(C)]` field, or across the C ABI.
    ///
    /// # Safety
    ///
    /// `fd` came from `into_raw`, and that reference is not used again.
    pub unsafe fn from_raw(fd: *mut fd) -> Self {
        // SAFETY: the caller's contract.
        FdOwned(unsafe { std::sync::Arc::from_raw(fd.cast_const()) })
    }

    /// Hands the reference to a `#[repr(C)]` field or across the C ABI, where
    /// something else gives it back with [`FdOwned::from_raw`] or `fd_close`.
    pub fn into_raw(self) -> *mut fd {
        std::sync::Arc::into_raw(self.0).cast_mut()
    }

    /// The description's address, which is its identity.
    pub fn as_ptr(&self) -> *mut fd {
        std::sync::Arc::as_ptr(&self.0).cast_mut()
    }

    /// A reference that does not keep the description alive, for a registry
    /// that must find it without owning it: [`FdOwned::upgrade`] answers `None`
    /// once the last strong reference has gone, finalizer running or not.
    pub fn downgrade(&self) -> std::sync::Weak<fd> {
        std::sync::Arc::downgrade(&self.0)
    }

    pub fn upgrade(weak: &std::sync::Weak<fd>) -> Option<Self> {
        weak.upgrade().map(FdOwned)
    }

    /// Gives the reference back and answers the finalizer's errno — 0 unless
    /// this was the last one and the driver's `close` failed.
    ///
    /// This is what `sys_close` returns to the guest.
    pub fn close(self) -> std::ffi::c_int {
        let key = self.as_ptr().cast_const();
        closing::around(key, || drop(self))
    }
}

impl std::ops::Deref for FdOwned {
    type Target = fd;
    fn deref(&self) -> &fd {
        &self.0
    }
}

impl std::fmt::Debug for FdOwned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FdOwned({:p})", self.as_ptr())
    }
}

impl ::fdtable::Descriptor for FdOwned {
    fn close(self) -> std::ffi::c_int {
        FdOwned::close(self)
    }
}
