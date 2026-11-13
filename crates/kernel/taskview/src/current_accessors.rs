//! Accessors for fields owned by the calling task and thread group.

use std::sync::atomic::Ordering;
use crate::{ffi, with_current_task};

/// The calling task's credential set, or null.
///
/// `crates/kernel/creds` owns every rule about who may do what; this is the one
/// thing it does not know, because it knows nothing about `current`.
#[inline]
pub fn current_creds() -> *mut kernel_creds::Creds {
    with_current_task(|t| t.creds.get()).unwrap_or(std::ptr::null_mut())
}

/// The calling task's credential set, lent for `f`, or `None` before there is
/// a task.
///
/// No lock, and sound without one: every writer of a task's `creds` runs on
/// that task's own thread -- the `set*id` calls, `faccessat`'s fs-id swap, a
/// setuid `execve` -- or before the task is published, which is `fork`'s.
/// `f` runs on this thread, so nothing writes the set while it is lent unless
/// `f` is itself one of those writers, and those are syscall bodies rather
/// than anything a permission check calls. The other writers' `pids_lock` is
/// for the *other* threads that read this set, and they hold it.
///
/// A closure rather than a `&'a Creds`, which was `crates/fs/perm`'s shape: a
/// reference of unbounded lifetime could be held across the very `setuid` the
/// argument above excludes.
#[inline]
pub fn with_current_creds<R>(f: impl FnOnce(&kernel_creds::Creds) -> R) -> Option<R> {
    // SAFETY: null or the address of a field of this thread's live task; see
    // above for why nothing writes it while `f` runs.
    unsafe { current_creds().cast_const().as_ref() }.map(f)
}

/// The calling task's thread group, or null.
///
/// Null for a task on its way out, which is why the group is read through this
/// rather than assumed.
#[inline]
pub fn current_group() -> *mut ffi::tgroup {
    with_current_task(|t| t.group.load(Ordering::Acquire)).unwrap_or(std::ptr::null_mut())
}

/// The calling task's thread group, lent for `f`, or `None` for a thread with
/// no task or no group.
///
/// Sound, and without a lock, for two reasons that are both needed. The
/// group outlives the call: a group is freed at reaping, after its last
/// thread has exited, and `task.group` is written only before the task is
/// published. And a `&tgroup` asserts nothing untrue: every field another
/// thread writes is atomic, a lock or a cell -- see [`ffi::tgroup`]'s comment.
///
/// A closure rather than a `&'static`, because "for as long as this thread
/// runs" is not a lifetime.
#[inline]
pub fn with_current_group<R>(f: impl FnOnce(&ffi::tgroup) -> R) -> Option<R> {
    // SAFETY: see above.
    unsafe { current_group().as_ref() }.map(f)
}

/// The status the calling thread has to leave with, if it has to: its group
/// is exiting, or another thread's `execve` is ending it. What the run loop,
/// the syscall return and a host wait check to let a thread go.
pub fn current_must_leave() -> Option<u32> {
    let tid = crate::current_pid();
    with_current_group(|g| g.exit.must_leave(tid)).flatten()
}

/// The calling task's address space, or null.
///
/// Null before the first process is constructed and for a task on its way out,
/// which is why it is read through this rather than assumed — the same reason
/// as [`current_group`].
///
/// Safe, and that is the point: five crates wrote `unsafe { (*current()).mem }`
/// with the obligation nowhere. `current()` is a `thread_local!` in this crate,
/// so the only thing to prove is that it is non-null, and this is where that
/// proof is. What the caller gets is still a raw pointer: a `&mem` would assert
/// that nothing writes the address space, and the calling thread does, on every
/// guest instruction.
#[inline]
pub fn current_mem() -> *mut ffi::mem {
    mem_in(current_mm())
}

/// The calling task's memory-management object, or null. The `mem` inside it is
/// [`current_mem`].
#[inline]
pub fn current_mm() -> *mut ffi::mm {
    with_current_task(|t| t.mm.as_ptr().cast_mut()).unwrap_or(std::ptr::null_mut())
}

/// The calling task's address space, lent for `f`; `None` for a thread with no
/// task or a task whose space has gone.
///
/// A `&mm` is sound: what other threads write in it is atomic or inside
/// `mem.locked`'s cell. And the space outlives `f`: only this thread's own
/// `execve` and `do_exit` take it out of the slot, and the group-exit valve
/// *moves* it to this thread's cleanup record, which is dropped on this thread
/// when it ends.
pub fn with_current_mm<R>(f: impl FnOnce(&ffi::mm) -> R) -> Option<R> {
    // SAFETY: as above.
    with_current_task(|t| unsafe { t.mm.as_ptr().as_ref() }.map(f)).flatten()
}

/// `task`'s **address space**: `struct mm` embeds a `struct mem` and this is
/// the inner one. Null for a task with none.
///
/// One `Acquire` load: the group-exit safety valve can null `task.mm` from
/// *another* thread while this one is inside `brk`, `mmap` or a guest memory
/// copy. See the field comment on `task.mm` for why the atomic is not a
/// substitute for `general_lock` and vice versa.
///
/// `struct task` carried a `mem` field that cached exactly this expression
/// until 2026-09-11 — every writer of it was literally
/// `(&raw mut (*new_mm).mem)`. It was deleted because two fields, one of them
/// an interior pointer into the other's allocation, are two things to keep in
/// step and were not: the valve nulled `mem` atomically and `do_exit` never
/// nulled it at all, so after `mm_release` it addressed freed memory while a
/// cross-thread diagnostic could still read it.
///
/// The derivation is **one load and one constant add**, because `mem` is
/// embedded by value rather than pointed at — there is no second dereference
/// here and there never was one to save. Measured with `mem_bench`; the numbers
/// are in `docs/changelog/2026-09-11-task-mem-was-a-second-copy-of-an-offset.md`.
///
/// Safe since 2026-10-17: it reads one field of a task the caller has
/// borrowed, and dereferences nothing. `mm_of`, the raw-pointer half it was
/// built on, went with its `unsafe`.
#[inline]
pub fn mem_of(task: &ffi::task) -> *mut ffi::mem {
    mem_in(task.mm.as_ptr().cast_mut())
}

/// The `mem` embedded in `mm`, or null. A cast rather than a field projection:
/// `mem` is `mm`'s first field, which `crates/kernel/abi` asserts, so the
/// address is the same and no place is formed.
#[inline]
pub fn mem_in(mm: *mut ffi::mm) -> *mut ffi::mem {
    const _: () = assert!(std::mem::offset_of!(ffi::mm, mem) == 0);
    mm.cast()
}

// ---------------------------------------------------------------------------
// The fields the syscall crates read
// ---------------------------------------------------------------------------
//
// Every one of these was a function in `kernel/task.c` until 2026-09-03, and
// every one had the same body: read `current`, read one field. They are Rust
// now and the C is gone.
//
// **This costs nothing, measured rather than argued.** A caller made one
// cross-language call before (`task_fs_info`), then one to `ffi::task_self`
// inside `current`, and as of 2026-09-06 makes none. That last step was
// expected to be visible in `syscall_bench` and is not; see the module comment
// for the numbers.
//
// They are a plain Rust API rather than `#[unsafe(no_mangle)]` shims keeping
// the old symbol names, because a Rust export no C can reach is what
// `tools/dead-exports.py` exists to report: the boundary is the thing step 5
// deletes, and moving a body across it without deleting it is the shape that
// grew the C by 58 lines on 2026-08-29.

/// The calling task's path context — its working directory, root and umask.
///
/// The shared `ffi::fs_info` handle is opaque to this crate; the object and
/// its rules belong to `crates/kernel/fsinfo`.
#[inline]
pub fn current_fs_info() -> *mut ffi::fs_info {
    with_current_task(|t| t.fs.as_ptr().cast_mut()).unwrap_or(std::ptr::null_mut())
}

/// Run `f` with the calling task's path context borrowed; `None` when there is
/// no task or its context is gone.
///
/// Safe for [`with_current_fdtable`]'s reason: the field is an `ArcSlot`
/// holding one count, and every way to give it back is a `take` through a raw
/// task pointer -- this thread's `do_exit`, a failed fork's undo before the
/// task runs, and the cleanup the valve moves it to, which runs on this thread
/// as it ends. None is reachable from `f`.
#[inline]
pub fn with_current_fs<R>(f: impl FnOnce(&ffi::fs_info) -> R) -> Option<R> {
    // SAFETY: as above -- null, or an object this thread's `fs` holds a count
    // on, which nothing reachable from `f` gives back.
    unsafe { current_fs_info().as_ref() }.map(f)
}

/// Run `f` with the calling task's descriptor table borrowed; `None` when there
/// is no task or its table is gone -- a task on its way out.
///
/// Safe, and scoped to the closure, because of who can end the borrow. The
/// field is an `ArcSlot` holding one count (see `struct task`'s `files`), and
/// every way to give that count back is `unsafe` to reach: a `take` through a
/// raw task pointer, or [`replace_current_fdtable`], whose contract excludes a
/// live borrow from here. They are this thread's `do_exit`,
/// `close_range(CLOSE_RANGE_UNSHARE)` after publishing the copy, and the
/// cleanup the group-exit valve hands a thread's table to -- which runs **on
/// that thread**, in its `pthread_exit` handler. The valve itself moves the
/// count and does not drop it. The borrow cannot outlive the closure.
///
/// This was a `*mut ffi::fdtable` from [`current_fdtable`] handed to an
/// `unsafe fn` per operation until 2026-09-30.
#[inline]
pub fn with_current_fdtable<R>(f: impl FnOnce(&ffi::fdtable) -> R) -> Option<R> {
    let table = current_fdtable();
    // SAFETY: as above -- non-null, an `Arc::into_raw`'d table this thread's
    // `files` holds a count on, and nothing reachable from `f` gives it back.
    (!table.is_null()).then(|| f(unsafe { &*table }))
}

/// The calling task's descriptor table.
///
/// `*mut ffi::fdtable`, which **is** `crates/fs/fdtable`'s `Table` since
/// 2026-09-09 rather than an opaque placeholder — so a caller that hands it
/// back to that crate no longer writes a `.cast()`. It answered
/// `*mut c_void` while the type was opaque, which erased it twice.
#[inline]
pub fn current_fdtable() -> *mut ffi::fdtable {
    with_current_task(|t| t.files.as_ptr().cast_mut()).unwrap_or(std::ptr::null_mut())
}

/// The calling process's own process group, for `kill(0, sig)`.
///
/// `kill(0, sig)` is this process's group, and it must not be re-encoded as
/// `kill(-pgid, sig)` on the way there — it was, and -1 is not a process group,
/// it is *every* process.
#[inline]
pub fn current_pgid() -> std::ffi::c_int {
    with_current_group(ffi::tgroup::pgid).unwrap_or(0)
}

/// The calling task's signal dispositions, `crates/kernel/sighand`'s. Null
/// before a task exists.
///
/// Here rather than in `crates/kernel/signaldeliver`, where it was, because a
/// one-line read of a `struct task` field is what this crate is for and
/// delivery is not: `signalfdcalls` needs the two pointers to *register* a
/// waiter, `signaldeliver` needs `signalfd_notify` to wake one, and with the
/// accessors on the delivery side those two edges were a cycle cargo refused
/// once each was a Rust call rather than a C one.
/// A `SigHand` since 2026-09-06 -- it was `*mut c_void`, so this crate erased
/// the type of a field it owns and every caller had to put it back.
///
/// **This does not read `(*current()).sighand`**, since 2026-09-12. It reads
/// the strong reference this thread took when it was bound, which is step 8 of
/// `docs/object-model-arc.md` and is written up in `current.rs` beside
/// `set_current`.
///
/// The short of it: there were eight readers of that field on the task's own
/// thread holding no lock — this accessor, `execve`, the offloaded `execve`,
/// the `BRK` handler, `signal_is_ignored_by_current`, `crates/fs/sock`'s wait
/// loop, `signal_pending` and `current_signal_pending` — and the group-exit
/// valve stores to the same word from another thread. Making each load atomic
/// (2026-09-12, the commit before this one) removes the data race and leaves
/// the *liveness* argument hand-written. Owning a reference removes both, and
/// the field then has no reader outside `pids_lock` at all.
#[inline]
pub(crate) fn current_sighand() -> *mut kernel_sighand::SigHand {
    crate::task_types::current_sighand_ref()
}

/// The calling task's signal dispositions, lent for `f`; `None` before a task
/// exists or once its table is gone.
///
/// Safe for [`with_current_queue`]'s reason: the hand is the thread's own
/// cached reference, released only by `set_current` on this thread.
pub fn with_current_sighand<R>(f: impl FnOnce(&kernel_sighand::SigHand) -> R) -> Option<R> {
    // SAFETY: as above.
    unsafe { current_sighand().as_ref() }.map(f)
}

/// As [`with_current_sighand`], for the pending queue and the blocked masks —
/// `crates/kernel/sigqueue`'s `SigqueueState`, locked by the same
/// `sighand->lock`.
#[inline]
pub fn current_sigqueue() -> *mut kernel_sigqueue::Signals {
    with_current_task(|t| t.signals.get()).unwrap_or(std::ptr::null_mut())
}

/// Run `f` with the calling task's signal state -- its group's dispositions
/// and its own queue -- as one [`kernel_sighand::Queue`]; `None` before a task
/// exists, or once the group-exit valve has taken the thread's table.
///
/// Nine callers in six crates paired [`with_current_sighand`] with the task's
/// `signals` field themselves, each in an `unsafe` block saying both were the
/// thread's own, until 2026-09-30. The pairing is this crate's to state: the
/// hand is the thread's own cached reference, released only by `set_current`
/// on this thread -- an `unsafe fn` nothing a closure can call safely reaches
/// -- and the queue lives as long as the task. The closure is what stops the
/// `Queue` outliving either.
pub fn with_current_queue<R>(f: impl FnOnce(kernel_sighand::Queue<'_>) -> R) -> Option<R> {
    // The group's shared set lives as long as the group, which outlives the
    // call for `with_current_group`'s reasons.
    let shared = with_current_group(|g| g.shared_signals.get()).unwrap_or(std::ptr::null_mut());
    // SAFETY: as above.
    unsafe { kernel_sighand::Queue::from_raw(current_sighand(), current_sigqueue(), shared) }.map(f)
}

/// Publish a replacement table, answering the one it replaced.
///
/// One caller: `close_range(CLOSE_RANGE_UNSHARE)`, which splits a shared table.
/// Nothing else in the tree replaces a live task's. On a thread with no task
/// there is nothing to publish on, and `table` is dropped.
///
/// # Safety
/// No [`with_current_fdtable`] borrow is alive: the answer may be the last
/// reference to the table that borrow points into.
#[inline]
pub unsafe fn replace_current_fdtable(
    table: std::sync::Arc<ffi::fdtable>,
) -> Option<std::sync::Arc<ffi::fdtable>> {
    with_current_task(|t| t.files.swap(Some(table))).flatten()
}

/// Publish a replacement filesystem context -- cwd, root, umask -- answering
/// the one it replaced: `unshare(CLONE_FS)`, the only thing that replaces a
/// live task's.
///
/// # Safety
/// No borrow of the calling task's current context is alive: the answer may
/// be the last reference to it. The caller holds `pids_lock`, which a reader
/// of *another* task's context holds across the read and the retain.
#[inline]
pub unsafe fn replace_current_fs(
    fs: std::sync::Arc<ffi::fs_info>,
) -> Option<std::sync::Arc<ffi::fs_info>> {
    with_current_task(|t| t.fs.swap(Some(fs))).flatten()
}

/// What owns a POSIX record lock: the descriptor **table**, not the task.
///
/// Threads sharing one do not lock each other out and a forked child, which
/// gets a copy, does. Compared, never dereferenced.
#[inline]
pub fn current_lock_owner() -> *mut ffi::fdtable {
    current_fdtable()
}

/// The calling task's filesystem context — its cwd and root — for C.
///
/// The one C caller is the embedder example in
/// `tests/integration/sbm_api_test.c`, and that is the point of it: an
/// embedder should not need `struct task`'s layout to chdir. Null before the
/// first process is constructed.
#[unsafe(no_mangle)]
pub extern "C" fn current_fs() -> *mut std::ffi::c_void {
    current_fs_info().cast()
}

/// The calling task's descriptor table, for C. As [`current_fs`].
#[unsafe(no_mangle)]
pub extern "C" fn current_files() -> *mut std::ffi::c_void {
    current_fdtable().cast()
}

/// The calling task's thread-group id — what a guest's `getpid` answers.
///
/// Zero before the first process is constructed, like [`crate::current_pid`].
pub fn current_tgid() -> i32 {
    with_current_task(|t| t.tgid.load(Ordering::Relaxed)).unwrap_or(0)
}

/// Run `f` with the calling task's syscall-restart state, lent mutably; `None`
/// before the first process is constructed.
///
/// `&mut` and sound: every reader and writer of `restart` runs on the task's
/// own thread -- the dispatcher entering and leaving a syscall, signal
/// delivery deciding on a rewind, and a socket wait reclassifying the call it
/// is inside. No other thread has a reason to look, and none does.
pub fn with_current_restart<R>(f: impl FnOnce(&mut kernel_syscallrestart::SyscallRestart) -> R) -> Option<R> {
    // SAFETY: only this thread touches `restart`, and the borrow ends with `f`.
    with_current_task(|t| f(unsafe { &mut *t.restart.get() }))
}

/// Run `f` with the calling task's tracing state; `None` before the first
/// process is constructed.
///
/// A closure rather than a returned reference: the state lives as long as the
/// task, and nothing a safe caller writes can outlive that on this thread --
/// but a returned `&'static` could be stored and read after the task is
/// reaped. It was a `*const` every caller dereferenced itself.
pub fn with_current_ptrace<R>(f: impl FnOnce(&ffi::ptrace_state) -> R) -> Option<R> {
    with_current_task(|t| t.ptrace.as_deref().map(f)).flatten()
}

// ---------------------------------------------------------------------------
// The calling task's own atomic flags and its registers
// ---------------------------------------------------------------------------
//
// Through [`with_current_task`]: the flags are atomics and `cpu` is a cell, so
// a `&task` is sound whoever else stores to them.

/// The calling task's registers, or null for a thread with no task.
///
/// A raw pointer for [`current_mem`]'s reason: the JIT on this thread writes
/// them, so a reference would assert something untrue.
#[inline]
pub fn current_cpu() -> *mut iul_abi::cpu_state {
    with_current_task(|t| t.cpu.get()).unwrap_or(std::ptr::null_mut())
}

/// The calling task's registers, lent for `f`; `None` for a thread with no
/// task.
///
/// A `&cpu_state` is sound since `_poked` -- the one byte another thread
/// writes -- is atomic, and nothing else writes the registers while this
/// thread is here rather than in the JIT. Writes still go through
/// [`current_cpu`]'s pointer: a `&mut` would not be sound.
#[inline]
pub fn with_current_cpu<R>(f: impl FnOnce(&iul_abi::cpu_state) -> R) -> Option<R> {
    // SAFETY: null, or this thread's live task's registers; see above.
    unsafe { current_cpu().as_ref() }.map(f)
}

/// Whether the calling task has exited or is on its way out; `false` for a
/// thread with no task. The valve sets `exiting` from another thread, which is
/// why both are atomics.
#[inline]
pub fn current_is_gone() -> bool {
    with_current_task(|t| t.zombie.get() || t.exiting.get()).unwrap_or(false)
}

/// Whether the calling task has been told to stop -- by its own `do_exit` or
/// by the group-exit valve; `false` for a thread with no task.
#[inline]
pub fn current_is_exiting() -> bool {
    with_current_task(|t| t.exiting.get()).unwrap_or(false)
}

/// Publish the host pid the calling task is proxying for, or clear it. See
/// [`ffi::ProxyPid`]. A no-op on a thread with no task.
#[inline]
pub fn set_current_native_proxy_pid(pid: Option<libc::pid_t>) {
    with_current_task(|t| t.native_pid.set(pid));
}

/// The offload handler the calling task is inside, published for as long as
/// the returned guard lives, so a signal can find its abort callback only
/// while the handler really runs.
///
/// A guard rather than a set/clear pair: the clear cannot be forgotten on an
/// early return, and it runs if the handler unwinds.
#[must_use = "the entry is cleared when the guard drops"]
pub fn enter_native_offload(entry: &'static offloadreg::Entry) -> NativeOffloadGuard {
    store_native_offload_entry(Some(entry));
    NativeOffloadGuard(std::marker::PhantomData)
}

/// See [`enter_native_offload`]. `!Send`: it clears the field of the task on
/// the thread that made it.
pub struct NativeOffloadGuard(std::marker::PhantomData<*const ()>);

impl Drop for NativeOffloadGuard {
    fn drop(&mut self) {
        store_native_offload_entry(None);
    }
}

fn store_native_offload_entry(entry: Option<&'static offloadreg::Entry>) {
    with_current_task(|t| t.native_offload_entry.set(entry));
}
