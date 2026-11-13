//! A task's life: making one, running it, and giving the struct back.
//!
//! # What stays in C, and why
//!
//! `current` went to `crates/kernel/taskview` on 2026-09-06, once the
//! measurement that kept it in C turned out to be about 758 C readers that no
//! longer existed, and `task_run_with_cleanup` followed it the same day — see
//! [`OnExit`]. What stays in `kernel/task.c` is `pids_lock` and
//! `lock_init`/`cond_init` on the objects `struct task` embeds, which are
//! `static inline`. Everything else about a task is here.
//!
//! [`task_thread`] sets `current` before it unblocks the wake signal, and that
//! order is load-bearing: a thread-local's first touch allocates. The handler
//! is an empty function as of 2026-09-06 and touches nothing, so it can no
//! longer be the one that gets there first.
//!
//! # A destroyed task's struct is poisoned and freed late
//!
//! [`task_destroy`] zeroes the struct and puts it on a short list rather than
//! freeing it. A leaked pthread — one the group-exit valve gave up on — may
//! still be inside `task_run_current` holding a stale `current`, and a zeroed
//! struct makes it crash on a NULL `group` or `mem` instead of quietly
//! corrupting whatever `malloc` puts at the same address next.
//!
//! That is a mitigation, not a fix, and the comment in C said so. What it buys
//! is that the failure is loud and at the right place.
//!
//! # The cleanup handler must not read the task
//!
//! [`run_tlb_cleanup`] runs during `pthread_exit`, and `task_destroy` can free
//! the task while it does — the parent reaps as the child unwinds. So
//! everything it needs comes out of `struct task_cleanup`, which the thread
//! allocates for itself and the handler frees. Reading the task there was a
//! use-after-free, reported by AddressSanitizer as a one-byte read.


use std::ffi::{c_char, c_int, c_uint};
use std::sync::Mutex;
use std::sync::atomic::{AtomicPtr, Ordering};

use strace::strace;

// The shared Rust types and constants are re-exported by kernel-taskview.
use std::sync::OnceLock;

use taskview::ffi;

#[path = "lifecycle.rs"]
mod lifecycle;
mod run;
pub use run::{task_cleanup_live_count, task_run_current};
mod pids;
#[cfg(test)]
pub(crate) use lifecycle::DEFERRED_MAX;
pub use lifecycle::{blank_task, task_create_, task_create_at, task_destroy, task_live_count, NewTask, Unstarted};
pub use pids::{
    pid_get_task, pid_get_task_zombie, sys_set_tid_address, task_next_listed_pid,
    task_next_live_pid,
};

/// The two things the guest run loop needs from above it.
///
/// `crates/kernel/exitcalls` and `crates/kernel/syscalldispatch` both depend on
/// this crate — the second through the syscall table, which names every family
/// — so **neither edge can exist in cargo at all**, whichever way round. That
/// is what makes these hooks rather than calls, and it is a different case from
/// the rest of this tree's: converting the others removed an edge the graph
/// could then check, and here there is no such edge to gain. What is gained is
/// the `#[no_mangle]` coming off two functions, one of which is on every
/// interrupt.
///
/// They were an `extern "C"` block until 2026-09-09, and the note above it said
/// `task_init_locks` and `task_destroy_locks` had been in it too, both defined
/// in this file — a round trip through the linker to reach a function seven
/// hundred lines down.
///
/// `crates/kernel/boot`'s `become_first_process` installs both, which is where
/// the filesystem registry is seeded for the same reason: there is no "first
/// object" here, and that function is the point at which the kernel is
/// assembled and before which no guest thread exists.
static RUN_HOOKS: OnceLock<RunHooks> = OnceLock::new();

/// What [`RUN_HOOKS`] holds. A struct rather than two `OnceLock`s: both are
/// installed by the same line, and one missing would be as quiet as the other.
#[derive(Clone, Copy)]
pub struct RunHooks {
    /// This thread has to leave -- its group is exiting, or another
    /// thread's `execve` is ending it -- with this status. Does not return.
    pub leave_group: fn(std::ffi::c_int) -> !,
    /// Dispatch an interrupt the CPU left the gadget loop for.
    ///
    /// # Safety
    /// Called on a guest thread with `current` set.
    pub handle_interrupt: unsafe fn(std::ffi::c_int),
}

/// Install them. See [`RUN_HOOKS`].
pub fn set_run_hooks(hooks: RunHooks) {
    let _ = RUN_HOOKS.set(hooks);
}

/// Whether they are installed — for the test in `crates/kernel/boot`.
///
/// **Nothing else can check them.** A task that reaches the run loop without
/// them cannot make progress at all, so there is no wrong answer to assert on;
/// the failure is `run_hooks()`'s panic, and that is deliberate. See there.
pub fn run_hooks_installed() -> bool {
    RUN_HOOKS.get().is_some()
}

/// The hooks, or a panic naming what is missing.
///
/// **A panic and not a default**, which is the opposite of every other hook in
/// this tree. Elsewhere "not installed" is a meaningful answer — no signal is
/// pending, no lock is held, no filesystem is registered. Here it is not: a
/// guest thread that cannot dispatch an interrupt cannot run, and a task that
/// cannot exit cannot be reaped. Falling back to a no-op would spin the CPU
/// for ever on the first syscall, which is the shape `CLAUDE.md` records as
/// the worst kind of failure — silent, and far from its cause.
#[inline]
fn run_hooks() -> RunHooks {
    *RUN_HOOKS.get().expect(
        "crates/kernel/taskcalls: the run-loop hooks were never installed.          `become_first_process` does it; an embedder that starts a task without          calling that has skipped the kernel's assembly.",
    )
}

use guest_errno::Errno;

fn current() -> *mut ffi::task {
    taskview::current()
}

/// `pids_lock`, for a scope.
///
/// `crates/kernel/pids` owns the lock and the guard; this was a fourth private
/// copy of the same type until 2026-09-06, reaching the lock through the C ABI
/// -- which is why cargo never saw the dependency.
use kernel_pids::PidsGuard as Pids;

use logline::die;

/// The body a new guest thread starts in.
///
/// `SIGUSR1` is blocked here — [`task_start`] blocks it around the spawn
/// and a new thread inherits the mask — so that [`taskview::set_current`] and
/// the allocations in [`task_run_current`] are the first touch of this thread's
/// thread-locals rather than a signal handler being.
///
/// The handler cannot get there first any more: it is an empty function in
/// `crates/kernel/boot` as of 2026-09-06 and touches nothing. `sync_thread_init`
/// was here to pre-touch the two thread-locals it used to read, and went with
/// them.
///
/// `extern "C"` though nothing calls it from C: a panic that reaches it aborts
/// the process, as it did when this was `pthread_create`'s start routine. A
/// `std` thread would otherwise catch it and end the thread quietly, leaving
/// its task half run.
extern "C" fn task_thread(task: *mut ffi::task) -> ! {
    unsafe {
        taskview::bind_current(task);
        unblock_wake_signal();
        update_thread_name();
        task_run_current();
    }
    die("task_thread returned")
}

/// The wake signal, once this thread can take one.
fn unblock_wake_signal() {
    util_hostsig::unblock(&[libc::SIGUSR1]);
}

/// A task handed to the thread that will run it.
struct Starting(*mut ffi::task);
// SAFETY: the task is not started yet, so nothing else runs it; the new
// thread is the one that will.
unsafe impl Send for Starting {}

impl Starting {
    /// By value, so a closure captures the `Send` wrapper rather than the
    /// field inside it.
    fn task(self) -> *mut ffi::task {
        self.0
    }
}

/// Start a task on a host thread of its own.
///
/// # Safety
/// `task` is a fully built task that has not been started.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_start(task: *mut ffi::task) {
    use std::os::unix::thread::JoinHandleExt;
    // The new thread inherits this mask and unblocks the wake signal itself
    // once its thread-locals exist. Restored here whatever happens: a caller
    // that is itself a guest thread still needs to be interruptible.
    let saved = util_hostsig::block(&[libc::SIGUSR1]);
    let starting = Starting(task);
    let spawned = std::thread::Builder::new().spawn(move || task_thread(starting.task()));
    util_hostsig::restore(&saved);
    // Detached by dropping the handle: nothing joins a guest thread. What a
    // group exit waits for is crates/kernel/hostthreads' count, notified by
    // the cleanup handler.
    match spawned {
        // SAFETY: the caller's contract; the thread may already be running it,
        // and `thread` is a cell for exactly that.
        Ok(handle) => unsafe { (*task).thread.set(handle.as_pthread_t()) },
        Err(_) => die("could not create thread"),
    }
    // The task runs on that thread now, not this one. An embedder starts a
    // session with `task_start(current)` -- `become_new_init_child` bound it
    // to this thread to set it up -- and until 2026-09-29 the binding stayed.
    // Everything after that asked "is this task the caller?" and was told yes:
    // a signal the embedder then sent it was recorded and **not woken**, because
    // `wake_for_signal` leaves the current task to notice on its own way out of
    // a syscall, which this thread is never going to make. A session hung up
    // with SIGHUP from the thread that started it slept on through it.
    // `tests/integration/sbm_api_test.c`'s
    // `closing_a_running_session_hangs_it_up` is the check.
    //
    // Only this case: a guest thread starting a child is never its child.
    if taskview::current() == task {
        taskview::clear_current();
    }
}

// ---------------------------------------------------------------------------
// Odds and ends the syscall layer asks for
// ---------------------------------------------------------------------------

pub fn sys_sched_yield() -> u32 {
    strace!("sched_yield()");
    std::thread::yield_now();
    0
}

/// The name a host thread carries: `comm`, a dash and the pid, in the fifteen
/// characters and a terminator Linux allows.
///
/// The truncation is `crates/kernel/procattr`'s, where it has tests. What is
/// here is `current` and the platform's two spellings of `pthread_setname_np`.
///
pub fn update_thread_name() {
    let pid = taskview::current_pid();
    let Some(name) = taskview::with_current_attr(|a| a.host_thread_name(pid)) else {
        return;
    };
    // SAFETY: the name is always NUL-terminated -- the rule keeps a byte for
    // it -- which is what the host naming call requires.
    unsafe { libc::pthread_setname_np(name.as_ptr().cast::<c_char>()) };
}

// ---------------------------------------------------------------------------
// vfork's other half
// ---------------------------------------------------------------------------

/// The child telling its `vfork` parent it may run again: it has reached
/// `execve`, `exit`, or a native offload handoff, so the address space they
/// were sharing is no longer the parent's problem.
///
/// **The child clears the pointer, not the parent.** It used to be the other
/// way round — `do_clone` woke, then took `task->general_lock` to null it — and
/// by then the task could be gone. This is called from `do_exit` a dozen lines
/// above `task_destroy`, so a child whose parent ignores `SIGCHLD` runs the
/// auto-reap path and frees its own task while the parent is on its way to that
/// lock. The parent had already been given a saved pid for exactly this reason
/// ("task might be destroyed by the time we finish"), and then dereferenced the
/// task anyway.
///
/// It did not crash, which is why it lasted: `task_destroy` zeroes the struct
/// and defers the free, and `pthread_mutex_lock` on a zeroed mutex answers
/// `EINVAL`, which `lock()` does not check. So the parent wrote a NULL into a
/// dead task and carried on. Under `-DLOCK_DEBUG=1` the same run aborts on
/// `assert(lock->debug.initialized)`.
///
/// **Here rather than in `crates/kernel/forkcalls`.** It is a task-lifecycle
/// operation -- take `general_lock`, take the handle out of the task, hand it
/// to `crates/kernel/vforkhandoff` -- and this crate is the one that owns
/// `general_lock`. `do_exit` calls it, and reaching into the *fork* syscalls
/// from the exit path made `kernel-exitcalls` -> `kernel-forkcalls` ->
/// `kernel-taskcalls` -> `kernel-exitcalls` a cycle.
///
/// Always the calling task's: `execve`, an offloaded exec and `do_exit` are the
/// three callers, and each is the child letting its own parent go.
pub fn vfork_notify_current() {
    // Taken out under general_lock, and used outside it. The lock is what
    // orders this against a second caller -- execve notifies, and so does the
    // do_exit that follows it -- so exactly one of them ends up with the handle
    // and the other finds NULL. Nothing else about the handoff needs a lock of
    // this task's: it is its own object with its own.
    let vfork = taskview::with_current_task(|t| {
        let _held = GeneralGuard::of(t);
        t.vfork.take()
    })
    .flatten();
    if let Some(vfork) = vfork {
        vfork.notify();
    }
}

// ---------------------------------------------------------------------------
// The pthread objects `struct task` embeds
// ---------------------------------------------------------------------------
//
// `general_lock`, `waiting_cond` and `pause` are ready from their
// `Default` and destroyed with the task since 2026-10-16. `task_init_locks`
// and `task_destroy_locks` were here; what is left of the first is the hook.

/// Install the parking hook, for every task including the first, so it is in
/// place before anything can park -- the same reason `sighand_new` installs the
/// signal one. `crates/util/waitfor` is layer 0 and the field it writes is this
/// crate's, so the write has to arrive from above.
pub(crate) fn install_parked_hook() {
    waitfor::set_parked_hook(set_parked);
}

// `task_general_lock` and `task_general_unlock` were here until 2026-10-01, an
// `unsafe fn` pair whose only caller was `GeneralGuard`.

/// `task->general_lock` held for a scope; see its definition, which is in
/// `crates/kernel/mmapcalls` since 2026-10-17 so that `crates/kernel/ptrace`,
/// which this crate depends on, can retain a tracee's address space with it.
pub use mmapcalls::mm::GeneralGuard;

/// Give the calling task `new` as its address space and point the gadgets at
/// it, under `general_lock`; answers the old one.
///
/// **The caller drops the answer**, after this has released the lock: the
/// last reference tears the page table down under `mem->lock`, and `execve`
/// did that inside `general_lock` until 2026-10-16 -- an order (general, then
/// mem) that `crates/fs/proc` is written to avoid creating.
pub fn replace_current_mm(new: std::sync::Arc<ffi::mm>) -> Option<std::sync::Arc<ffi::mm>> {
    taskview::with_current_task(|t| {
        // `general_lock` excludes the group-exit valve, the slot's other
        // writer.
        let _held = GeneralGuard::of(t);
        // SAFETY: this thread's own register file, which nothing else writes
        // while it is in a syscall.
        unsafe { (*t.cpu.get()).mmu = (&raw const new.mem.mmu).cast_mut() };
        t.mm.swap(Some(new))
    })
    .expect("an address space is replaced by a task")
}

/// Take the calling task's address space away, under `general_lock`; `None`
/// when the group-exit valve already has. As [`replace_current_mm`], the
/// caller drops it outside the lock.
pub fn take_current_mm() -> Option<std::sync::Arc<ffi::mm>> {
    taskview::with_current_task(|t| {
        let _held = GeneralGuard::of(t);
        t.mm.take()
    })
    .expect("an address space is taken from a task")
}

/// Wake whatever condition this task is parked on, if any.
///
/// The field's lock is held across the notify: `crates/util/waitfor`
/// publishes the condition before it parks and clears it after it wakes, so
/// while the lock is held a published condition is one the parked thread is
/// still inside.
pub fn task_wake_waiting(task: &ffi::task) {
    let parked = locks::locked!(&task.waiting_cond);
    if let Some(cond) = *parked {
        // SAFETY: live until its thread clears the field, which needs the
        // lock `parked` holds.
        waitfor::notify_all(unsafe { cond.as_ref() });
    }
}

/// Record that the calling thread has parked on `cond`, or (null) that it has
/// woken — the other side of [`task_wake_waiting`], and the hook
/// `crates/util/waitfor` calls at each end of a park.
///
/// `waitfor` wrote this field itself until 2026-09-09, which meant a layer-0
/// crate holding the definition of `struct task` to reach two of its members.
/// The lock protocol is unchanged and is stated once, above `task_wake_waiting`:
/// the parking thread writes the field and the notifying thread reads it, both
/// under its lock.
///
/// A host thread with no task records nothing, which is what the null check is.
///
/// `None` is "no longer parked", which the hook used to spell as a null
/// pointer. The field holds a `NonNull`, because it is published by the
/// parking thread and read by another one, and a `&` cannot be carried across
/// that.
///
/// A park is also what `/proc` reports as asleep (`S`), so it sets `blocking`
/// as the host sleeps (`nanosleep`, `poll`) do. Clearing it on wake inside a
/// caller that set it too is right: the thread is running again.
fn set_parked(cond: Option<&ffi::cond_t>) {
    taskview::with_current_task(|t| {
        *locks::locked!(&t.waiting_cond) = cond.map(std::ptr::NonNull::from);
        t.blocking.store(cond.is_some(), std::sync::atomic::Ordering::Relaxed);
    });
}

/// Interrupt a host call in another task's thread.
///
/// `SIGUSR1` is the signal every blocking host call here is prepared to be
/// woken by — `sigusr1_handler` in `util/sync.c` is what catches it, and
/// `crates/fs/sockrestart`'s resume path uses this to get every thread inside a
/// host `accept()` to come back and look again.
///
/// `kernel/task.c`'s until 2026-09-03, and it was the last thing in that file
/// that could move: everything left there is a `__thread` variable, a macro, a
/// `static inline`, a weak symbol, or a `static_assert` pinning an ABI.
///
/// # Safety
/// `task` is live, which for a task that is not `current` means `pids_lock` is
/// held: one found through the registry can be freed the moment it is dropped,
/// and `thread` would then be a pthread id that has been reused.
pub unsafe fn task_interrupt_host_call(task: *mut ffi::task) {
    if task.is_null() {
        return;
    }
    // SAFETY: the caller's contract. A task whose thread has not started has
    // no host call to interrupt; this sent the signal to thread id 0 before.
    if let Some(thread) = unsafe { (*task).thread.get() } {
        unsafe { libc::pthread_kill(thread, libc::SIGUSR1) };
    }
}

#[cfg(test)]
#[path = "task_tests.rs"]
mod tests;
