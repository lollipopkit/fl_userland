//! The calling thread's task binding and embedder entrypoints.

use super::task;
use kernel_sighand::SigHand;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// The calling thread's task
// ---------------------------------------------------------------------------
//
// Beside the type since 2026-09-09 and in `crates/kernel/abi` before that: the
// thread-local holding a `*mut task` is the same fact as the type, and moving
// one without the other would have left a crate that names `task` only to hold
// a pointer to it.

// `const` initialiser and a type that is not `Drop`, which together are what
// make this the same mechanism `__thread` was: no lazy-initialisation flag to
// test on every read and no destructor to register. What remains is Darwin's
// `_tlv_get_addr`, which the C went through too.
//
// A `Cell`, not a `static mut`: the whole point is that this is per-thread, and
// `Cell` is how a `thread_local!` holds something writable without `unsafe`.
thread_local! {
    static CURRENT: std::cell::Cell<*mut task> =
        const { std::cell::Cell::new(std::ptr::null_mut()) };
}

/// The calling task, or null.
///
/// Null before the first process is constructed, and inside a host thread that
/// is not running a guest — `crates/util/timer`'s service thread is one. Every
/// caller has to expect it, which is why this answers a pointer rather than a
/// reference.
#[inline]
pub fn current() -> *mut task {
    CURRENT.with(|c| c.get())
}

/// The calling task, lent for `f`; `None` on a thread with none.
///
/// **Sound since 2026-10-16**, when the last plain field another thread could
/// write while the task runs became a cell: every field is now immutable after
/// publication, an atomic, a lock, an `UnsafeCell` or an `ArcSlot` (see
/// `struct task`), so a `&task` asserts nothing untrue. Until then each
/// accessor borrowed one field through the raw pointer, in an `unsafe` block
/// of its own. The task lives while its thread runs it, and the closure is what
/// stops the borrow outliving that.
#[inline]
pub fn with_current_task<R>(f: impl FnOnce(&task) -> R) -> Option<R> {
    // SAFETY: null, or this thread's live task; see above.
    unsafe { current().as_ref() }.map(f)
}

// ---------------------------------------------------------------------------
// The running thread's own reference to its signal dispositions
// ---------------------------------------------------------------------------
//
// This is step 8 of `docs/object-model-arc.md`, and it is the *reader side* of
// `task.sighand` being an `Arc`. The naive conversion is worse than the raw
// pointer it replaces: the group-exit valve takes a stuck thread's table away
// from another thread, so a reader that did `(*task).sighand.clone()` would be
// racing a `take()` with a load **and an increment** -- on a pointer that may
// already have been moved. That is a harder race to lose than the one it
// replaces, not an easier one.
//
// So the reader never touches the field. A thread holds a strong reference for
// as long as it is running a guest task, and `signal_pending` -- which runs
// inside `wait_for`, on this thread, holding whatever arbitrary lock the caller
// had -- reads that.
//
// **What this depends on and nothing checks**: nothing replaces a live thread's
// `sighand` after publication. See the field's own comment for the grep. What
// *can* happen is that the field is emptied -- by `detach_and_notify` on this
// thread, or by the valve from another -- and the cache then keeps the object
// alive a moment longer than the field does. That is the point rather than a
// leak: it is what makes the read lockless and correct.

thread_local! {
    /// Unlike [`CURRENT`] this one **has a destructor**, which is the whole
    /// mechanism: a thread that dies without passing through `do_exit` --
    /// which is what the valve leaves behind -- gives its reference back from
    /// here.
    ///
    /// It therefore registers a `pthread_key_create` destructor on first use,
    /// which `CURRENT` deliberately does not. That is a second reason the
    /// module's existing rule holds rather than a new one: the first touch is
    /// `set_current`, from `crates/kernel/taskcalls`' `task_thread`, **with
    /// `SIGUSR1` blocked** -- registering a destructor allocates, and `malloc`
    /// is not async-signal-safe.
    static CURRENT_SIGHAND: std::cell::RefCell<Option<Arc<SigHand>>> =
        const { std::cell::RefCell::new(None) };
}

/// The calling thread's own reference to its task's disposition table, as the
/// raw handle `crates/kernel/sighand`'s entry points take. Null for a thread
/// that is not running a guest.
///
/// **No clone.** The pointer is borrowed from the reference the thread-local
/// holds, which outlives every caller here, so this is a load and nothing else.
/// A `clone()` would put an `Arc` drop on the `wait_for` path, under the
/// caller's arbitrary lock, and the last such drop destroys a `GuestLock` --
/// `Primitive::drop` calls `cond_destroy`, which **aborts** on `EBUSY`. That is
/// the one new hazard this conversion could have introduced and the reason the
/// reader is a borrow.
///
/// `try_with`, not `with`: this is reachable from inside another thread-local's
/// destructor -- `crates/kernel/taskcalls`' `run_tlb_cleanup` closes
/// descriptors, and a driver's close can wait -- and `with` panics once this
/// one's own destructor has run. "No table" is the same answer an unbound
/// thread gets and is the right one for a thread that is already unwinding.
pub(crate) fn current_sighand_ref() -> *mut SigHand {
    CURRENT_SIGHAND
        .try_with(|c| {
            c.borrow()
                .as_ref()
                .map_or(std::ptr::null_mut(), |a| Arc::as_ptr(a).cast_mut())
        })
        .unwrap_or(std::ptr::null_mut())
}

/// This thread is no longer running a guest task.
///
/// Separate from [`set_current`] since 2026-09-12, and not merely for the
/// spelling: `set_current` reads a field of the task it is given and is
/// therefore `unsafe`, while "there is no task" carries no pointer and no
/// obligation. The four callers are the exit paths, and each of them ran
/// `set_current(null)` inside an `unsafe` block that bought nothing.
///
/// It gives back the reference to the signal dispositions this thread held.
pub fn clear_current() {
    // SAFETY: null is the one argument `set_current` needs nothing for.
    unsafe { set_current(std::ptr::null_mut()) }
}

/// Make `task` the calling thread's.
///
/// **This must be the thread's first touch of `CURRENT`, with `SIGUSR1`
/// blocked.** A thread-local's first use allocates, and a signal handler that
/// got there first re-entered `malloc`.
///
/// A thread that is about to *run* a guest calls `bind_current` instead, which
/// also installs the wait hook; a thread that has stopped calls
/// [`clear_current`].
///
/// # Safety
///
/// `task` is live, or null. It was a safe function until 2026-09-12 and the
/// signature was right then: it stored the pointer and read nothing. It reads
/// `task.sighand` now, so a caller handing it a freed task has a
/// use-after-free where it used to have a stale `current` — which is a real
/// narrowing and is why `clippy::not_unsafe_ptr_arg_deref` is a deny lint.
///
/// **It maintains the cached reference above**, and this is the one place
/// `current` changes, which is what makes the boot transient in
/// `crates/kernel/boot`'s `construct_task` fall out rather than need a rule:
/// that binds a half-built task for one `generic_open` and restores afterwards,
/// and both halves go through here.
///
/// Where the old reference is dropped, and whether it can be the last:
///
/// | site | thread | holding | last? |
/// | --- | --- | --- | --- |
/// | a rebind replacing a previous binding | the binding thread | the caller's | no — the previous task still names it, or its cleanup struct does |
/// | `set_current(null)` in `do_exit_group`'s leaked-thread bail | the exiting thread | nothing | no — the valve handed it to the cleanup struct |
/// | `set_current(null)` in `do_exit`, twice | the exiting thread | **`pids_lock`** | **yes** |
/// | the thread-local's destructor at thread exit | the dying thread | nothing | **yes** |
///
/// The third row is the one the design for this step did not have, and it is
/// **not a new hazard**: `detach_and_notify` releases the task's own reference
/// twenty lines earlier under that same `pids_lock`, so the last drop of a
/// group's table has always happened there. What this moves is which of two
/// adjacent statements on one thread runs the destructor.
///
/// The fourth row is provable rather than hoped. References to one `SigHand`
/// are held by the tasks of its thread group, by their cleanup structs, and by
/// the threads running them; a `fork` without `CLONE_SIGHAND` makes a new
/// object. So this is the last one only when no other task of the group exists
/// — and therefore when nobody can be parked on its condition variable, which
/// is what `cond_destroy`'s abort is about. `tools/lock-order.py --calls` does
/// not see this and cannot: the destruction is inside a `Drop`, one level below
/// any call it follows. This table is the record.
pub unsafe fn set_current(task: *mut task) {
    // Read the field **before** `CURRENT` changes, so that a failure here
    // leaves the two in step. It is a plain read of an `Option<Arc<_>>`: the
    // only cross-thread writer is the group-exit valve, which holds
    // `pids_lock` and the task's `general_lock`, and every caller of this is
    // either on the task's own thread before it has been published or is
    // writing null.
    let next = if task.is_null() {
        None
    } else {
        // SAFETY: the caller's contract -- `task` is the task this thread is
        // about to run, which is live. A shared reference to the whole task
        // would not be sound here; this borrows the one field.
        unsafe { (*task).sighand.clone_arc() }
    };
    // The previous reference leaves the cell before it is dropped, so the
    // `RefCell` is not borrowed while a destructor runs. A `GuestLock`'s drop
    // is two pthread destroys and could not re-enter this, but a borrow held
    // across an arbitrary `Drop` is the shape that has bitten this tree before.
    let previous = CURRENT_SIGHAND.with(|c| std::mem::replace(&mut *c.borrow_mut(), next));
    CURRENT.with(|c| c.set(task));
    drop(previous);
}

/// Whether this thread is holding a reference to a disposition table.
///
/// For the wiring test in `lib.rs`, which is the only thing that can catch the
/// maintenance above disappearing: in a test binary there is no current task,
/// so a cache that is never filled reads exactly like one that is.
pub fn current_sighand_is_held() -> bool {
    !current_sighand_ref().is_null()
}

/// [`current`], for an **embedder**, which is C.
///
/// This is the one C reader the survey for the 2026-09-06 move missed, and it
/// is not in `kernel/` — `tests/integration/sbm_api_test.c` writes
/// `task_start(current)`, and so does ServerBox's `ios/Runner/ish/sbm_ish.c`.
/// `iul.h` keeps `#define current (task_self())` for them, because the header
/// is a delivery contract and not this tree's to change.
///
/// It costs one call, on a path that runs once per session. The 3–5% the
/// 2026-08-29 measurement found was 758 of these on syscall paths.
#[unsafe(no_mangle)]
pub extern "C" fn task_self() -> *mut task {
    current()
}

/// The calling task's thread id, or **-1** for a host thread that is not
/// running a guest. What `F_GETLK` reports as a lock's holder, among others.
///
/// Exported, because C wants it too: the lock-debug macros put a pid in every
/// `lock_t` and a trace line is prefixed with one.
///
/// It answered 0 for no task to a Rust caller and -1 to a C one, which was two
/// spellings of the same question; -1 is the one the macros have always printed
/// and the one every Rust caller wanted anyway — each compares against a real
/// pid, and 0 is not one.
#[unsafe(no_mangle)]
pub extern "C" fn current_pid() -> std::ffi::c_int {
    with_current_task(|t| t.pid()).unwrap_or(-1)
}
