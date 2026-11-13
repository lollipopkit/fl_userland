//! Accessors for individual task and thread-group objects.

use std::sync::atomic::Ordering;
use crate::ffi;

// The accessors below took an opaque `*mut c_void` rather than `*mut ffi::task`
// until 2026-09-06, and the reason given had two halves that had both stopped
// being true:
//
//   > every caller holds a task as an opaque pointer, and a signature naming
//   > the generated struct would make each of them see it — which is the
//   > recompile cascade the per-crate bindgen rule exists to avoid.
//
// A caller holds a `*mut ffi::task`: it reads one out of `proctree::Task`, out
// of `crates/kernel/pids`' guard, or out of a field of another task. And it
// already sees the struct — every consumer imports `task` from `taskview` and
// consumer's bindgen and imports it *from here*, which is what makes `.cast()`
// between crates unnecessary. There is no cascade to avoid, because the
// dependency is already there.
//
// What the erasure cost was casts, in both directions and at every layer:
// `crates/kernel/rescalls` had an `as_task` helper whose whole doc comment was
// this reason, `crates/kernel/groupcalls` had `type Task = *mut c_void` and
// nine `.cast::<ffi::task>()` in its accessors, and
// `crates/kernel/signaldeliver`'s `sig_state` existed to erase two types so it
// could feed signatures that had erased them. All of that is gone, and what
// replaced it is one cast in `crates/kernel/pids`, where a registry that holds
// pids as keys turns an identity back into a type.

// `pid_of`, `tgid_of` and `is_zombie` were here until 2026-10-17: a reader
// with a `&task` reads the field, and one under `pids_lock` has
// `kernel_pids::Task`. `sighand_of` went from `current_accessors` the same day.

/// A task's thread group.
///
/// # Safety
/// `task` is live, which for a task that is not `current` means `pids_lock` is
/// held: one found through the registry can be freed the moment it is dropped.
#[inline]
pub unsafe fn group_of(task: *mut ffi::task) -> *mut ffi::tgroup {
    unsafe { (*task).group.load(Ordering::Acquire) }
}

/// A task's credential set. The object is `crates/kernel/creds`'.
///
/// # Safety
/// As [`group_of`].
#[inline]
pub unsafe fn creds_of(task: *mut ffi::task) -> *mut kernel_creds::Creds {
    unsafe { (*task).creds.get() }
}

/// A task's tracing state; `None` for a null task, or one on its way out.
///
/// A reference since 2026-09-30. It was a `*const` described as "opaque;
/// `crates/kernel/ptrace` casts it back", which had stopped being true when the
/// type became `kernel_ptracestate::Ptrace` -- and every caller then handed the
/// pointer to an `unsafe` adapter that tested it for null and called a method.
///
/// # Safety
/// As [`group_of`], for as long as the answer is used: the state lives as long
/// as the task.
#[inline]
pub unsafe fn ptrace_of<'a>(task: *mut ffi::task) -> Option<&'a ffi::ptrace_state> {
    if task.is_null() {
        return None;
    }
    unsafe { (*task).ptrace.as_deref() }
}

// `comm_of` was here until 2026-10-16, a raw-pointer twin of
// `kernel_pids::Task::comm`; its last caller, `waitcalls`' reap trace, had a
// `Task` in hand.

/// The calling thread's name, for a log line; empty before there is a task.
///
/// Takes the attribute lock, so not from inside [`with_current_attr`].
pub fn current_comm() -> String {
    with_current_attr(|a| String::from_utf8_lossy(a.name()).into_owned()).unwrap_or_default()
}

/// The calling thread's per-thread attributes — its name, its pdeath signal —
/// lent for `f` under their lock; `None` before there is a task. The rules are
/// `crates/kernel/procattr`'s; this is where they are kept.
pub fn with_current_attr<R>(f: impl FnOnce(&mut kernel_procattr::ThreadAttr) -> R) -> Option<R> {
    crate::with_current_task(|t| f(&mut locks::locked!(&t.attr)))
}

/// Where this thread's tid is cleared when it exits: `clear_child_tid`, set by
/// `CLONE_CHILD_CLEARTID` and `set_tid_address`. `PR_GET_TID_ADDRESS` reports
/// it. Only ever written by the thread itself, so reading it from the thread
/// needs no lock.
#[inline]
pub fn current_clear_tid() -> u64 {
    crate::with_current_task(|t| t.clear_tid.load(Ordering::Relaxed)).unwrap_or(0)
}

/// Mark this thread as parked, for `/proc`'s `S` and for the futex-stall
/// diagnostic that prints every thread's state.
///
/// `blocking` is the one field `tools/unread-fields.py` deliberately does not
/// report as unread, because that diagnostic is how a futex hang gets named.
#[inline]
pub fn set_blocking(blocking: bool) {
    crate::with_current_task(|t| t.blocking.store(blocking, Ordering::Relaxed));
}

/// `capable(cap)`: whether the calling task's effective set holds `cap`.
///
/// The one question every permission check asks of the caller, filesystem
/// ones included -- `setfsuid` takes the filesystem capabilities out of the
/// effective set, so there is no second, fsuid-based answer to keep in step.
/// It replaced `superuser()`, an effective uid of 0, on 2026-11-13: a root
/// process that dropped a capability kept every one of them.
#[inline]
pub fn capable(cap: u32) -> bool {
    crate::with_current_creds(|c| c.capable(cap)).unwrap_or(false)
}

/// The ids a filesystem stamps on a node the caller creates.
///
/// The **fs** ids, not the effective ones. They are the same until a guest
/// calls `setfsuid`, which is what makes this look like a rename — but a file
/// server that sets its fsuid to a caller's expects the file it then creates to
/// be stamped with that one.
#[inline]
pub fn current_fsids() -> (u32, u32) {
    crate::with_current_creds(|c| (c.fsuid(), c.fsgid())).unwrap_or((0, 0))
}

/// The filesystem context this thread group runs in — an embedder's token,
/// which a bind mount's translation hook is given so that it can answer
/// differently per process. 0 when there is no group.
#[inline]
pub fn current_fs_context() -> u64 {
    crate::with_current_group(|g| g.fs_context).unwrap_or(0)
}

/// Run `f` with the accumulators this thread group's exited threads and reaped
/// children add to; `None` for a thread with no task or no group, which is
/// what a host thread that is not running a guest has, and what a task on its
/// way out has.
///
/// Safe for the reason [`crate::with_current_group`] is.
#[inline]
pub fn with_current_group_times<R>(f: impl FnOnce(&ffi::group_rusage) -> R) -> Option<R> {
    crate::with_current_group(|g| f(&g.times))
}
