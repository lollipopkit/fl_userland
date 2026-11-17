//! The open file description itself: its allocation, its finalizer, and the two
//! calls that join one to a task.
//!
//! The *strong count* is the `Arc` in `kernel-abi`'s `FdOwned` and the
//! *table* is `crates/fs/fdtable`, which is generic over what it holds. This is
//! `fs/fd.c`: what a description is made of, what has to be given back when the
//! last reference goes, and `f_get`/`f_install`, which are the only two places a
//! description meets `current`.
//!
//! The count was `crates/fs/fd`, a hand-rolled control block reached through
//! `struct fd`'s `owner` field, until 2026-10-17 -- separate because the table
//! could not name a descriptor. Steps 1 to 3 of that move made the table
//! generic, put the typed handle in `kernel-abi`, and made it an `Arc`.
//!
//! # The finalizer runs exactly once, and only then
//!
//! `Drop for fd` guarantees that: it runs where the last `Arc` goes, with the
//! finalizer `publish` installed. What matters here is the *order*, which is the
//! whole content of the function:
//!
//! 1. every epoll set watching this description loses its registration — the
//!    transient poll sets need nothing, because each holds a reference to the
//!    wake channel and it outlives the description if it has to;
//! 2. the BSD lock, which belongs to the **description** and not to a
//!    descriptor sharing it, which is why it is here and not in a close;
//! 3. the driver's `close`, then the mount's if it is a different function;
//! 4. `IN_CLOSE_WRITE`, which is what most inotify watchers actually wait for —
//!    an editor writes a file and closes it, and that event is what says the
//!    file is complete. Reported here rather than per write, because a write
//!    would have to ask the filesystem for the path every time and this asks
//!    once, when the path is already known;
//! 5. the inode, the mount, the wake channel and the pthread objects.
//!
//! # `f_get` hands its reference to the syscall, not to the caller
//!
//! The lookup and the retain are one `fdtable` transaction, and the reference it
//! produces goes into the calling task's per-syscall set — released in one place
//! when the syscall returns. So a caller must not close an `f_get` result. The
//! set deduplicates: one entry per description however many times the syscall
//! looks it up, because a loop over a guest count (`recvmmsg` calling `recvmsg`,
//! `poll` over a large set) would otherwise grow it by an entry per iteration.

#![deny(unsafe_op_in_unsafe_fn)]

mod locks;
pub use locks::FdGuard;
mod syscall_refs;
pub(crate) use syscall_refs::syscall_ref_hold;
pub use syscall_refs::syscall_refs_drain;

use std::sync::atomic::Ordering;
use std::ffi::c_int;

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

/// What a descriptor's *locks* need told when it goes away.
///
/// One trait rather than two `fn` hooks because the two always arrive together:
/// `crates/fs/locks` installs both or neither, and a type says so where two
/// separate `OnceLock`s would only hope.
///
/// It was an `extern "C"` block until 2026-09-09, with a marker saying a file
/// lock is owned by a descriptor so `fs/locks` depends on this crate and either
/// direct call is a cycle. That is still true; what the hook changes is that
/// the edge no longer has to be a symbol the linker resolves — and with it went
/// the `[dev-dependencies]` on `fs-locks` and `fs-poll` that a test needed
/// purely to make `_flock_release` resolve.
///
/// **Nothing to install is the right answer, not a fallback.** Both operations
/// return immediately when the inode has no lock set, and `fs/locks` installs
/// this when it makes the first one — so before that, "no hook" and "the real
/// hook" do the same nothing.
///
/// **Not an `unsafe trait`** since 2026-09-30. It was one, with no `# Safety`
/// section, and its methods' docs said the trait's `unsafe` was for the
/// callers' obligation -- which is what an `unsafe fn` is. An `unsafe trait`
/// is a promise the *implementor* makes that callers may rely on, and nothing
/// here relies on one.
pub trait FdLocks: Sync {
    /// Release the BSD (`flock`) lock this *description* holds.
    ///
    /// Safe since 2026-09-30, as is the method below: their `# Safety`
    /// sections asked that `fd`'s inode be live, which a live description
    /// already says -- it holds a reference to its inode -- and both
    /// implementations were calls to safe functions.
    fn flock_release(&self, fd: &ffi::fd);
    /// Drop the POSIX record locks `owner` holds on this file. Owned by the
    /// *process*, unlike the BSD lock above, which is why it is a separate
    /// operation on a separate path. `owner` is an identity, compared and
    /// never dereferenced.
    fn remove_owned_by(&self, fd: &ffi::fd, owner: *mut ffi::fdtable);
    /// The locks `/proc/<pid>/fdinfo` lists for this description, for the
    /// process whose descriptor table is `table`.
    fn held_by(&self, fd: &ffi::fd, table: *const ffi::fdtable) -> Vec<HeldLock>;
}

/// Which of Linux's three kinds a lock is, as `/proc/<pid>/fdinfo` names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockClass {
    /// `flock(2)`.
    Flock,
    /// A process-owned record lock, `F_SETLK`.
    Posix,
    /// An open-file-description record lock, `F_OFD_SETLK`.
    Ofd,
}

/// One lock a description holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldLock {
    pub class: LockClass,
    pub write: bool,
    /// The taker's pid; -1 for an open-file-description lock.
    pub pid: i32,
    pub start: i64,
    /// The last byte, or `None` for "to the end of the file".
    pub end: Option<i64>,
}

/// The locks `fd` holds, as [`FdLocks::held_by`] answers; none before the
/// first lock set exists, which is when the hook is installed.
pub fn locks_held_by(fd: &ffi::fd, table: *const ffi::fdtable) -> Vec<HeldLock> {
    FD_LOCKS.get().map_or_else(Vec::new, |locks| locks.held_by(fd, table))
}

static FD_LOCKS: std::sync::OnceLock<&'static dyn FdLocks> = std::sync::OnceLock::new();

/// Install them. `crates/fs/locks` does this when it makes an inode's first
/// lock set, which is the earliest point either can have anything to do.
pub fn set_fd_locks_hook(hooks: &'static dyn FdLocks) {
    let _ = FD_LOCKS.set(hooks);
}

/// Whether they have been installed — for the test in `crates/fs/locks` that
/// asserts the install happens. Neither operation is visible to an
/// answer-checking test: with no hook a closing descriptor drops no locks, and
/// with the real hook a descriptor that holds none drops none either.
pub fn fd_locks_hook_installed() -> bool {
    FD_LOCKS.get().is_some()
}

use guest_errno::c_int_::{EBADF, EINVAL};

/// The description is going away. See the module comment for the order.
fn fd_finalize(m: &mut ffi::fd) -> c_int {
    let mut err: c_int = 0;
    // `&mut`, from `Drop for fd` at a strong count of zero: nothing else can
    // reach the description, and the `Arc` frees it -- with whatever its
    // fields still own, the host descriptor, the change path, the lock and the
    // condition -- after this returns. Until 2026-10-17 this took the payload
    // pointer, borrowed `&mut` from it once, and ended in the `Box::from_raw`
    // that freed it.
    unsafe {
        // `poll_cleanup_fd` was a third C ABI call here until 2026-09-09 and
        // needed no hook at all: its whole body is this line, and
        // `crates/fs/pollset` — which owns the watcher list — is already an
        // ordinary dependency. What made it look like a cycle was that the
        // *wrapper* lives in `crates/fs/poll`, which does depend on this crate.
        pollset::poll_watchers_closed(&m.poll_watchers);
        if let Some(locks) = FD_LOCKS.get() {
            locks.flock_release(m);
        }

        let ops = m.ops;
        if let Some(ops) = ops {
            err = ops.close(m);
        }
        // The mount's close as well, unless the driver's close already is it.
        //
        // That used to be `!fn_addr_eq(driver_close, fs_close)` -- skip the
        // second call when it is literally the same function pointer -- and
        // the coincidence it depended on was broken once already: `fakefs`
        // gave its descriptors a cache-freeing `close` of its own, the
        // identity with `realfs_close` went with it, and `realfs_close` ran
        // twice and closed the host descriptor twice. On a busy process that
        // closes whatever unrelated file has since been opened at that
        // number; it showed up as the guest's `closedir` answering `EBADF`.
        // `FdOps::close_covers_mount` is the driver saying so itself.
        let mount = m.mount;
        if !mount.is_null()
            && let Some(fs) = (*mount).fs
            && !ops.is_some_and(|ops| ops.close_covers_mount())
        {
            let new_err = fs.close(m);
            if new_err < 0 {
                err = new_err;
            }
        }

        if let Some(path) = m.inotify_path.take() {
            // Through the hook `crates/kernel/inotifycalls` installs: a direct
            // call would be this layer depending on the syscall layer, which
            // is a dependency cycle and the wrong direction.
            inotify::notify_path(path.to_bytes(), inotify::IN_CLOSE_WRITE, 0);
        }
        if let Some(inode) = m.inode.take() {
            // What this descriptor held of the inode's writer count goes back
            // before the reference does: a write-capable open took one, an
            // exec took a denial, and the count is what makes the next exec or
            // the next write-open of the file answer ETXTBSY or not.
            if m.holds_write_access {
                fs_inode::inode_put_write_access(&inode);
            }
            if m.denies_write() {
                fs_inode::inode_allow_write_access(&inode);
            }
        }
        if !mount.is_null() {
            // Taken back out of `(*fd).mount`, where `adhoc_fd_create_for` and
            // the mount's own `open` put it with `into_raw`.
            drop(fs_mounttable::MountRef::from_raw(mount));
        }
    }
    LIVE.fetch_sub(1, Ordering::Relaxed);
    err
}

/// Open file descriptions allocated and not yet finalized.
static LIVE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// How many `struct fd` exist right now, for `/proc/iul/objects`.
///
/// Added 2026-09-29, when the refusals inside `generic_openat` stopped
/// releasing by hand and started releasing by returning. A refusal that leaked
/// its description leaked a *host* descriptor too, and nothing a guest could
/// ask would show either: the description is in no table, so neither
/// `/proc/self/fd` nor `RLIMIT_NOFILE` sees it. Backing one release out passed
/// the whole guest suite. `tests/guest/src/bin/eventfd_leak.rs` is what asks.
pub fn fd_live_count() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

/// A description being built: not published yet, so nothing else can see it
/// and `&mut` is honest. [`NewFd::publish`] hands it out with one reference.
///
/// Since 2026-10-01. Every driver's `open` called `fd_create`, tested the
/// answer for a null that reported one of three allocations, and then filled
/// fields in through `unsafe { (*fd).x = .. }` on the raw pointer; it fills
/// them in through this instead, before the description exists for anyone
/// else.
///
/// Dropped unpublished -- a driver's `open` that fails after making one -- it
/// gives back the mount reference [`NewFd::set_mount`] took, and every owning
/// field drops with it. No driver or filesystem `close` runs: nothing was
/// opened as far as anyone outside this function can tell, and the finalizer
/// that would is installed by `publish`.
///
/// **The `Arc` exists from the start**, so the description's address is final
/// before it is published: `crates/kernel/pidfdcalls` registers a `NewFd`'s
/// address before publishing it, and every registry keyed on a description's
/// address assumes it does not move.
pub struct NewFd(Option<std::sync::Arc<ffi::fd>>);

impl NewFd {
    pub fn new(ops: Option<&'static dyn ffi::FdOps>) -> NewFd {
        NewFd(Some(std::sync::Arc::new(ffi::fd::with_ops(ops))))
    }

    /// Records the mount this descriptor belongs to, taking its reference;
    /// [`fd_finalize`] gives it back.
    pub fn set_mount(&mut self, mount: fs_mounttable::MountRef) {
        debug_assert!(self.mount.is_null(), "a description's mount set twice");
        self.mount = mount.into_raw();
    }

    /// The description, with one reference held, which `fd_close` (or an
    /// [`Owned`] adopting it) gives back.
    ///
    pub fn publish(self) -> *mut ffi::fd {
        self.into_owned().into_raw()
    }
}

impl NewFd {
    /// [`NewFd::publish`], with the reference held by an [`Owned`].
    ///
    /// Seeds the three attributes a driver may change afterwards -- mode,
    /// owner, group -- from `stat`, while this is still the only reference:
    /// every creator has filled `stat` by now, and nothing can write it after.
    /// They were seeded in `f_install_start` until 2026-10-18, which is also
    /// where `dup`, `F_DUPFD` and a received `SCM_RIGHTS` descriptor go -- so
    /// each of those put back the mode a `fchmod` had changed -- and which the
    /// CLI's stdio never reaches, so its mode was 0 (`tests/guest`
    /// adhoc_attrs).
    pub fn into_owned(mut self) -> Owned {
        let mut fd = self.0.take().expect("published once");
        fd.set_attr_mode(fd.stat.mode);
        fd.set_attr_uid(fd.stat.uid);
        fd.set_attr_gid(fd.stat.gid);
        std::sync::Arc::get_mut(&mut fd).expect("an unpublished description has one owner").finalizer =
            Some(fd_finalize);
        LIVE.fetch_add(1, Ordering::Relaxed);
        Owned::new(fd)
    }
}

/// A description a filesystem's `open` built, which is unpublished by
/// construction: `FsOps::open` answers a `Box`.
///
/// **This moves it**, into the `Arc`'s allocation. Safe because nothing has
/// its address yet: the two callers -- `realfs_open` and `generic_openat` --
/// convert the driver's answer on the next line, and every registry keyed on
/// a description's address is filled later, from a `NewFd` or a published one.
impl From<Box<ffi::fd>> for NewFd {
    fn from(fd: Box<ffi::fd>) -> NewFd {
        NewFd(Some(std::sync::Arc::from(fd)))
    }
}

impl std::ops::Deref for NewFd {
    type Target = ffi::fd;
    fn deref(&self) -> &ffi::fd {
        self.0.as_deref().expect("not yet published")
    }
}

impl std::ops::DerefMut for NewFd {
    fn deref_mut(&mut self) -> &mut ffi::fd {
        std::sync::Arc::get_mut(self.0.as_mut().expect("not yet published"))
            .expect("an unpublished description has one owner")
    }
}

impl Drop for NewFd {
    fn drop(&mut self) {
        if let Some(fd) = self.0.take()
            && !fd.mount.is_null()
        {
            // SAFETY: `set_mount` stored a `MountRef::into_raw`, and nothing
            // else has seen this description.
            drop(unsafe { fs_mounttable::MountRef::from_raw(fd.mount) });
        }
    }
}

/// An owned reference to an open file description: `kernel-abi`'s
/// [`ffi::FdOwned`] since 2026-10-17, where it was this crate's own wrapper
/// over an untyped handle the table and the path context held instead.
pub use ffi::FdOwned as Owned;

/// Give back one reference; the last one finalizes the description and
/// answers the driver's `close`.
///
/// # Safety
/// `fd` came from a reference handed out across the C ABI (`generic_open`,
/// `realfs_open`, `fdtable_replace_range`'s displaced slots), the caller owns
/// it, and does not use `fd` afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fd_close(fd: *mut ffi::fd) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { Owned::from_raw(fd) }.close()
}

/// `iul.h`'s `fdtable_replace_range`, which is how an embedder points the
/// guest's stdio at a pty.
///
/// **Here rather than in `crates/fs/fdtable` since 2026-09-12.** That crate's
/// entries own their references now, and a `void *` payload address cannot be
/// turned back into one -- the control block is reached through `struct fd`'s
/// `owner`, whose layout it deliberately does not know. This crate does, so the
/// shim is here and the operation is `fdtable::replace_range`. The symbol, the
/// signature and `tests/integration/sbm_api_test.c` are unchanged.
///
/// # Safety
///
/// `table` is live, `source` carries one transferable reference, and
/// `out_displaced` is writable for `count` entries.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fdtable_replace_range(
    table: *mut ffi::fdtable,
    source: *mut std::ffi::c_void,
    first: c_int,
    count: usize,
    cloexec: c_int,
    limit: usize,
    out_displaced: *mut *mut std::ffi::c_void,
) -> c_int {
    if source.is_null() || out_displaced.is_null() {
        return EBADF;
    }
    let source: *mut ffi::fd = source.cast();
    // SAFETY: the caller's contract.
    let owned = unsafe { Owned::from_raw(source) };
    let mut displaced = Vec::new();
    // SAFETY: the caller's contract; null is `EBADF`, as the table answered.
    let Some(table) = (unsafe { table.as_ref() }) else {
        let _ = owned.close();
        return EBADF;
    };
    let err = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        table.replace_range(owned, first, count, cloexec != 0, limit, &mut displaced)
    })) {
        Ok(Ok(())) => 0,
        // The reference comes back when the table refuses, which is what the C
        // contract says: the caller closes what it handed over. Releasing it
        // here would be the double release `f_close` and `dup3` both had for
        // one run; see this crate's `fd_release_owned`.
        Ok(Err((error, fd))) => {
            let _ = fd.close();
            error
        }
        Err(_) => EINVAL,
    };
    // Whatever it managed, handed back as raw payloads for the caller to close
    // -- which is what the C contract says and why the release is not here.
    for (offset, slot) in displaced.into_iter().enumerate() {
        let raw = slot.map_or(std::ptr::null_mut(), |o| o.into_raw().cast());
        unsafe { out_displaced.add(offset).write(raw) };
    }
    err
}

// ------------------------------------------------------- the table's vtable



/// A process's record locks on this file go when the table drops it — record
/// locks are owned by the *process*, unlike the BSD lock the finalizer releases.
///
/// The driver's [`ffi::FdOps::flush`] first: this is the one place every way a
/// table lets go of an entry passes through, which is what `filp_close` is.
fn table_remove_locks(file: &ffi::fd, owner: &ffi::fdtable) {
    if let Some(ops) = file.ops {
        ops.flush(file);
    }
    if file.inode.is_some()
        && let Some(locks) = FD_LOCKS.get()
    {
        // The table is the identity a record lock is held by, compared and
        // never written through.
        locks.remove_owned_by(file, std::ptr::from_ref(owner).cast_mut());
    }
}

/// [`table_remove_locks`], for `fdtable::Ops`. It was handed the untyped
/// handle and cast its payload back until 2026-10-17; a table holds the typed
/// one now.
fn ops_remove_locks(fd: &Owned, owner: &ffi::fdtable) {
    table_remove_locks(fd, owner);
}

/// The one table, of the type the crate that *consumes* it defines.
///
/// It was a `taskview::ffi::fdtable_ops` until 2026-09-09 and
/// `fdtable::Table::new` takes a `fdtable::Ops`, so the two were the same three function pointers
/// rendered twice, meeting through a `.cast()` in `crates/kernel/boot` that
/// checked nothing — the shape `crates/kernel/taskview` exists to prevent, and
/// the fourth of its kind found this month after `siginfo_`, `pollset_ops` and
/// `epoll_state_ops`. The owner is the consumer, which is the rule the epoll
/// one settled.
pub static FDTABLE_OPS: fdtable::Ops<Owned> = fdtable::Ops {
    remove_locks: Some(ops_remove_locks),
};

/// Drops a descriptor a table was holding: the record locks first, then the
/// reference. `crates/kernel/fdcalls` has `close`, `dup3` and `close_range`.
///
/// **By value**, and that is not style. It took a `*mut ffi::fd` for one run on
/// 2026-09-12 and both callers handed it `Owned::payload()` — a *borrow* — so
/// the handle they still held dropped as well and released a second time. It
/// surfaced as a SIGSEGV in `sock_race`. A raw pointer cannot say "I am taking
/// this from you" and an `Owned` by value can, so the mistake is a compile
/// error now rather than a use-after-free.
///
/// The errno is the driver's, and `sys_close` returns it to the guest — which
/// is why this ends in [`Owned::close`] rather than in a drop.
pub fn fd_release_owned(table: &ffi::fdtable, fd: Owned) -> c_int {
    table_remove_locks(&fd, table);
    fd.close()
}

// ------------------------------------------------------ joining a task

// The description a descriptor number names, with a reference recorded on the
// calling syscall. `NULL` for a number the table does not hold.
/// The directory an `*at` path is resolved against.
///
/// **`path` is a parameter for a reason**: an *absolute* path ignores the
/// descriptor entirely, and Linux does not even check that it is valid — so
/// `openat(-1, "/etc/passwd", ...)` succeeds. Answering `AT_PWD` for one is how
/// that is expressed here, and taking a reference on a descriptor nobody is
/// going to use is what it avoids.
///
/// `kernel/fs.c`'s until 2026-09-03.
///
/// **It answered a `*mut ffi::fd` until 2026-09-16**, and that pointer had
/// three readings: `AT_PWD` — the sentinel `(struct fd *) -2` — a live
/// description, or null for a descriptor number the table does not hold. The
/// first two are [`ffi::At`]'s two arms and the third is the `None`, so a
/// caller that forgot the null test now does not compile rather than
/// dereferencing a bad number.
///
/// **Safe since 2026-10-01.** It took a raw path and answered an `At<'a>` with
/// a lifetime the caller picked, so every wrapper that returned one --
/// `pathcalls`' `at_of`, `path_and_at`, `two_paths` -- was a safe function
/// handing out a borrow of unbounded life. The answer is an [`AtRef`] now, and
/// the `At` it lends cannot outlive it.
pub fn at_fd(f: c_int, path: &std::ffi::CStr) -> Option<AtRef> {
    if path.to_bytes().first() == Some(&b'/') || f == ffi::AT_FDCWD_ {
        return Some(AtRef::Pwd);
    }
    f_get(f).map(AtRef::Fd)
}

/// What [`at_fd`] answers: the working directory, or a description held by
/// the calling syscall. `!Send`, like the [`FdRef`] it may hold.
#[derive(Clone, Copy)]
pub enum AtRef {
    Pwd,
    Fd(FdRef),
}

impl AtRef {
    /// The base, borrowed from `self`.
    pub fn at(&self) -> ffi::At<'_> {
        match self {
            AtRef::Pwd => ffi::At::Pwd,
            AtRef::Fd(fd) => ffi::At::Fd(fd),
        }
    }
}

/// A description the calling syscall looked up, borrowed for the rest of it.
///
/// `f_get`'s reference goes into the task's per-syscall set, which is drained
/// when the syscall returns -- or, for one that never returns, by the
/// thread's own exit handler; the group-exit valve moves the set to the task's
/// cleanup record without touching what is in it. So the description is live
/// for as long as *this thread* is still inside the syscall that looked it up,
/// and that is exactly what this type can reach:
///
/// - it is `!Send` and `!Sync`, so it cannot leave the thread, and no
///   `static`, `Mutex` or `Arc` a second thread could read can hold it;
/// - only [`f_get`] makes one, so there is no route to it from a pointer that
///   was not recorded in the set.
///
/// What it does not rule out is a `thread_local!` that keeps one past the
/// syscall's return; nothing in the tree has a reason to, and a reviewer should
/// treat one as a use-after-free.
///
/// `Copy`, like the `&` it stands for. It was a `*mut ffi::fd` with a doc
/// comment, and thirty-one call sites each wrote `unsafe { f_get(n).as_ref() }`
/// or a null test and a dereference to restate the paragraph above.
#[derive(Clone, Copy)]
pub struct FdRef {
    fd: std::ptr::NonNull<ffi::fd>,
    _this_thread: std::marker::PhantomData<*const ()>,
}

impl FdRef {
    /// The description, for a call that still takes a pointer. Live for as
    /// long as the `FdRef` is.
    pub fn as_ptr(self) -> *mut ffi::fd {
        self.fd.as_ptr()
    }

    /// A reference of the caller's own, which outlives the syscall.
    ///
    /// Safe where [`Owned::retain`] is not, and the difference is the count:
    /// a borrow proves the memory is live but not that the count is above
    /// zero, and retaining a description on its way to its finalizer
    /// resurrects it. An `FdRef` is one the per-syscall set holds a count on,
    /// so it cannot be on its way out.
    pub fn retain(self) -> Owned {
        // SAFETY: as above.
        unsafe { Owned::retain(self.as_ptr()) }
    }
}

impl std::ops::Deref for FdRef {
    type Target = ffi::fd;
    fn deref(&self) -> &ffi::fd {
        // SAFETY: see the type -- the per-syscall set holds a reference until
        // this thread leaves the syscall, which it cannot do while `self` is
        // borrowed here.
        unsafe { self.fd.as_ref() }
    }
}

/// The description at `f`, borrowed for the rest of the calling syscall, or
/// `None` for a number the table does not hold. Do not close it; see the
/// module comment.
pub fn f_get(f: c_int) -> Option<FdRef> {
    let task = taskview::current();
    if task.is_null() {
        return None;
    }
    let held = taskview::with_current_fdtable(|table| table.lookup_retain(f)).flatten()?;
    let fd: *mut ffi::fd = held.as_ptr();
    // The lookup's reference is kept for the rest of the syscall, or dropped
    // if the syscall already holds one to the same description.
    syscall_ref_hold(held);
    Some(FdRef {
        fd: std::ptr::NonNull::new(fd)?,
        _this_thread: std::marker::PhantomData,
    })
}

/// Installs at the lowest free number at or above `start`, consuming `fd`
/// however it ends.
///
/// Takes the reference as an [`Owned`] since 2026-09-29. Both of these took a
/// `*mut fd` and a doc comment saying they consumed a reference, so every
/// creation site held a raw pointer until the last line and released it by
/// hand on each way out before that -- seven of them, one per syscall that
/// makes a descriptor.
pub fn f_install_start(fd: Owned, start: c_int, cloexec: bool) -> c_int {
    // The mode, owner and group are seeded by `NewFd::into_owned`, not here:
    // a `dup` reaches this too, and must not undo a `fchmod`.
    let limit = kernel_rlimit::current_soft(ffi::RLIMIT_NOFILE_ as c_int as u32) as usize;
    // The table gives the reference back when it refuses, which is what makes
    // the close below right rather than a double release. It was a sentence in
    // `fdtable_install_lowest`'s doc comment and is the `Err` arm now.
    //
    // A task with no table -- one on its way out -- was a null dereference
    // here, one line above an `fdtable_install_lowest` that tested for null;
    // it is `EBADF` now. Not reachable from a guest: a task loses its table in
    // `do_exit`, after its last syscall.
    // Moved into the closure: with no table it is dropped there, which is the
    // release.
    let installed = taskview::with_current_fdtable(move |table| table.install_lowest(fd, start, cloexec, limit));
    match installed {
        Some(Ok(number)) => number,
        Some(Err((error, fd))) => {
            let _ = fd.close();
            error
        }
        None => EBADF,
    }
}

/// [`f_install_start`] at 0, with `open`'s `O_NONBLOCK` and `O_CLOEXEC`.
pub fn f_install(fd: Owned, flags: c_int) -> c_int {
    // O_NONBLOCK is open-file-description state. Set it before publishing the
    // descriptor number so another thread cannot observe a half-installed fd.
    //
    // *Added to* what the description already has, not set alone: fd_setflags
    // is F_SETFL and replaces the whole settable mask, so asking it for
    // O_NONBLOCK by itself took O_APPEND, O_DIRECT and O_NOATIME off a file
    // that had just been opened with them. fcntl_probe measured an open with
    // every flag at once reporting no O_NOATIME, and only when O_NONBLOCK was
    // among them.
    if flags as u32 & ffi::O_NONBLOCK_ != 0 {
        let want = fd.flags() | ffi::O_NONBLOCK_;
        if fd_setflags(&fd, want as c_int) < 0 {
            // `fd` goes here, and nothing has seen it yet.
            return EINVAL;
        }
    }
    f_install_start(fd, 0, flags as u32 & ffi::O_CLOEXEC_ != 0)
}

pub fn f_close(f: c_int) -> c_int {
    taskview::with_current_fdtable(|table| match table.take(f) {
        Some(fd) => fd_release_owned(table, fd),
        None => EBADF,
    })
    .unwrap_or(EBADF)
}

// ------------------------------------------------------------------ flags

#[path = "status.rs"]
pub mod status;

/// The `S_IFMT` bits: what kind of thing this description is open on.
///
/// Immutable once the descriptor exists. Exported because C wants it and
/// should not need the layout: `tests/integration/sbm_api_test.c` checks that
/// what it opened is a character device, and that was one of the last two
/// places C read a `struct fd` field.
///
/// # Safety
/// `fd` is live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fd_type(fd: *mut ffi::fd) -> ffi::mode_t_ {
    unsafe { (*fd).type_ }
}

/// The mount's `fstat`, called on this description.
///
/// The other of those two places: `tests/unit/fakefs_stat_test.c` reached
/// `fd->mount->fs->fstat` to ask a *filesystem* rather than the syscall layer,
/// which is the point of that test — `sys_fstat` would answer from the inode
/// table and hide the disagreement it is about.
///
/// Safe since 2026-10-01: it took a raw pointer and dereferenced it twice.
pub fn fd_fstat(fd: &ffi::fd) -> Result<ffi::statbuf, c_int> {
    // `EINVAL` for a filesystem that does not answer `fstat`, which is this
    // caller's reading of the trait's `None` and differs from the three
    // others'. That is why the trait keeps the case distinct.
    // Stamped here, the one door every `fstat` goes through, so a path's
    // `stat` and a descriptor's agree on the mount and its device; see
    // `ffi::mount::dev`.
    let mount = fd.mount();
    match mount.and_then(|m| m.fs).and_then(|fs| fs.fstat(fd)) {
        Some(answer) => answer.map(|mut st| {
            if let Some(m) = mount {
                m.stamp(&mut st);
            }
            st
        }),
        None => Err(EINVAL),
    }
}

// `fd_getflags` was here until 2026-09-16. It was
// `unsafe { (*fd).flags() as c_int }` -- a raw pointer and an `unsafe fn`
// around the safe accessor `ffi::fd::flags`, plus a cast to the signedness
// its callers did not want. Six call sites say `fd.flags()`.

/// `F_SETFL`, and what `f_install` and `FIONBIO` do with `O_NONBLOCK`.
///
/// The rule decides the new set, the driver applies whatever of it has a side
/// effect, and the set is stored only if the driver agreed -- so a host
/// descriptor that could not be made non-blocking is not recorded as one.
///
/// Safe, and takes a borrow: every field it touches it reads through the
/// reference, and `set_flags` is an atomic store on `&self`.
pub fn fd_setflags(fd: &ffi::fd, flags: c_int) -> c_int {
    let kind = status::Kind::of_mode(fd.type_ as u32);
    let new = match status::setfl(kind, fd.flags(), flags as u32) {
        Ok(new) => new,
        Err(e) => return e,
    };
    if let Some(ops) = fd.ops {
        let err = ops.setflags(fd, new);
        if err < 0 {
            return err;
        }
    }
    fd.set_flags(new);
    0
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
