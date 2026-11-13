//! Getting a signal to a task: which thread takes it, what happens when it
//! arrives, and — in [`receive`] — how the thread takes it: the frame written
//! onto the guest's stack, the CPU pointed at the handler, and `rt_sigreturn`
//! reading it all back. **All of `kernel/signal.c`, which is gone.**
//!
//! The receiving half waited for `struct task` to move because it reads and
//! writes `struct cpu_state`; bindgen generates that with the rest of the task,
//! and the two `static inline` helpers it needed are in [`receive`].
//!
//! # `kill` addresses a process, not a thread
//!
//! Any thread that has not blocked the signal may take it. This delivered to
//! the group leader unconditionally, so the signal was **lost** whenever the
//! leader was the thread that had blocked it: it went pending on a thread that
//! would never take it, and nothing reported anything.
//!
//! That is not an unusual arrangement. It is the shape of every program with a
//! dedicated signal thread — block the signal in every thread, and have one
//! thread `sigwait` for it. Go's runtime, the JVM and anything built on
//! `signalfd(2)` all do it, and none of them worked unless the thread that
//! could take the signal happened to be the leader.
//!
//! It waits in the process's shared set (`tgroup::shared_signals`), and
//! `routing`'s `signal_thread` follows Linux's `complete_signal` in choosing
//! the thread to tell: the one the sender named if it can take it, then
//! whoever else can. Until 2026-11-12 the signal was queued on that thread
//! rather than told to it, and the caller was preferred; `raise()` and
//! `abort()` are `tgkill`, which names its thread, and need no preference.
//!
//! # A fatal signal is decided when it is sent
//!
//! Linux's `complete_signal` ends the whole process from the sender when the
//! signal's disposition is the default, the default terminates without a
//! core, and the thread chosen for it does not block it: the group's exit
//! word takes the signal as its status under sighand's lock, every thread
//! gets `SIGKILL`, and a later signal finds the process dying and is dropped
//! (`prepare_signal`). Until 2026-11-13 this was decided by the thread that
//! took the signal, so the process went on doing things meanwhile -- a
//! thread that `kill`ed its own process returned from `kill` and could
//! `exit_group(3)`, and the parent saw 3 (`sigfatal_probe`). What stays with
//! delivery is what Linux leaves there: core-dumping signals, a traced
//! process, a stopped one, and a signal that was blocked when it came.
//!
//! # The wakeup happens outside sighand's lock
//!
//! [`Target::wake`] is a function of its own for that reason. The C did it
//! from inside the lock and had to drop and retake it around the broadcast —
//!
//! ```c
//! // must release the sighand lock while going insane, to avoid a deadlock
//! unlock(&task->sighand->lock);
//! ```
//!
//! — a window in which the queue the caller had just written could change under
//! a decision it was in the middle of. `crates/kernel/sighand` answers what to
//! do instead, and this does it after the lock is gone.


use std::ffi::{c_int, c_uint};

use kernel_sighand::{Queue, Recipient};
use kernel_sigqueue::SigInfo;

// The shared Rust types and constants are re-exported by kernel-taskview.
use std::sync::OnceLock;

use taskview::ffi;

/// End the whole thread group — what a fatal signal does.
///
/// A hook. `crates/kernel/exitcalls` calls four functions out of this crate for
/// the signals an exit sends, so a Rust call the other way is a cycle; it was
/// an `extern "C"` declaration until 2026-09-09.
///
/// **Answer 3 does not fit here**, and it is worth saying why: `CLAUDE.md`'s
/// third answer is to return the decision instead of acting on it, which is
/// what `poll_wait`'s `Waited` enum does. The three call sites are inside
/// `die_of_signal`, `ptrace_syscall_boundary` and `notify_tracer_of_stop` —
/// deep in signal delivery, and the point of `do_exit_group` is that it does
/// not return. Threading a "this was fatal" result up through every one of
/// those would be a bigger change to the delivery path than the edge is worth.
///
/// Installed by `become_first_process`, and **`expect` rather than a default**:
/// a fatal signal that does not end the process leaves a task running code it
/// was killed for. See `crates/kernel/taskcalls`'s `run_hooks` for the same
/// argument at length.
static EXIT_GROUP: OnceLock<fn(c_int)> = OnceLock::new();

/// Install it. See [`EXIT_GROUP`].
pub fn set_exit_group_hook(f: fn(c_int)) {
    let _ = EXIT_GROUP.set(f);
}

/// Whether it has been installed — for the test in `crates/kernel/boot`.
pub fn exit_group_hook_installed() -> bool {
    EXIT_GROUP.get().is_some()
}

pub(crate) fn do_exit_group(status: c_int) {
    (EXIT_GROUP.get().expect(
        "crates/kernel/signaldeliver: the exit-group hook was never installed. \
         `become_first_process` does it; without it a fatal signal would leave \
         the task running the code it was killed for.",
    ))(status)
}

/// Forward a signal to the host process running a natively-offloaded binary,
/// answering whether it took it.
///
/// A hook, and `crates/kernel/offloadexec` installs it when it registers the
/// first offload binary — which is the only way a task can be running one, so
/// there is no window where a signal could miss it.
///
/// It was declared in the block above until 2026-09-09, and the marker there
/// said the pair was genuinely mutual: `offloadexec` ends a finished offload
/// with `do_exit`, so it depends on `kernel-exitcalls`, which depends on this
/// crate for the five signals an exit sends. That is still true — what changed
/// is that this direction no longer needs an edge at all, and with it goes one
/// of the last `*mut task` to cross a C ABI boundary.
static OFFLOAD_FORWARD: OnceLock<fn(&ffi::task, c_int) -> bool> = OnceLock::new();

/// Install it. See [`OFFLOAD_FORWARD`].
pub fn set_offload_forward_hook(f: fn(&ffi::task, c_int) -> bool) {
    let _ = OFFLOAD_FORWARD.set(f);
}

/// Whether the hook has been installed — for the test in
/// `crates/kernel/offloadexec` that asserts registration installs it. With no
/// hook a signal is delivered to the emulated task rather than forwarded, which
/// is also what an unregistered binary gets, so no answer-checking test can
/// tell a missing install from an ordinary signal.
pub fn offload_forward_hook_installed() -> bool {
    OFFLOAD_FORWARD.get().is_some()
}

pub mod receive;

use guest_errno::c_int_::{EFAULT, EINVAL, EPERM, ESRCH};

fn current() -> *mut ffi::task {
    taskview::current()
}

/// Who a signal is for.
///
/// **Two ways of reaching a task's signal state, and a caller has one or the
/// other.** Another task's table is read under `pids_lock`, which is what
/// excludes the group-exit valve taking it; the calling task's own is read
/// through `taskview::with_current_queue`, which needs no lock because the
/// thread holds its own reference. Until 2026-09-30 both went through one
/// `sig_state(*mut task)` whose contract was the lock -- and `signal_self`,
/// the `SIGPIPE` hook and the fault paths called it for their own task
/// holding nothing, which is the lockless read of that field the accessor
/// exists to replace.
#[derive(Clone, Copy)]
pub enum Target<'a> {
    /// The calling task, holding no lock.
    Me,
    /// A task found under `pids_lock` -- which may be the caller itself, if
    /// that is how it was found.
    Task(kernel_pids::Task<'a>),
}

/// Make `task` leave the interpreter at its next gadget boundary.
///
/// Safe on any live task, including one running on another thread: `cpu` is
/// reached as a place rather than borrowed, and the poke is one atomic store
/// to the flag `poked_ptr` names, which the task's own thread polls.
///
/// A task that never went through `task_create_` -- `blank_task`'s value --
/// has no flag yet, and poking it does nothing.
pub fn poke(task: &ffi::task) {
    let cpu = task.cpu.get();
    // SAFETY: `poked_ptr` is written once, before the task is published, and
    // then points into the task itself, which `task` keeps live.
    unsafe {
        if !(*cpu).poked_ptr.is_null() {
            asbestos_dispatch::cpu_poke(cpu);
        }
    }
}

impl Target<'_> {
    /// The task, for the operations that still take a pointer. Null only for
    /// [`Target::Me`] on a thread with no task.
    fn raw(self) -> *mut ffi::task {
        match self {
            Target::Me => current(),
            Target::Task(t) => t.raw(),
        }
    }

    /// Run `f` over the task; `None` for [`Target::Me`] on a thread with no
    /// task.
    fn with_task<R>(self, f: impl FnOnce(&ffi::task) -> R) -> Option<R> {
        match self {
            Target::Me => taskview::with_current_task(f),
            Target::Task(t) => Some(f(t.task())),
        }
    }

    /// Run `f` over the task's signal table and queue; `None` for a task
    /// whose table the group-exit valve has taken.
    fn with_queue<R>(self, f: impl FnOnce(Queue<'_>) -> R) -> Option<R> {
        match self {
            Target::Me => taskview::with_current_queue(f),
            Target::Task(t) => t.signal_queue().map(f),
        }
    }

    /// Whether it has exited or is exiting, so a signal means nothing.
    fn gone(self) -> bool {
        match self {
            Target::Me => taskview::current_is_gone(),
            Target::Task(t) => t.is_zombie() || t.is_exiting(),
        }
    }

    fn traced(self) -> bool {
        match self {
            Target::Me => taskview::with_current_ptrace(|p| p.is_traced()).unwrap_or(false),
            Target::Task(t) => t.ptrace().is_some_and(|p| p.is_traced()),
        }
    }

    /// Make it leave the JIT at the next gadget boundary instead of waiting
    /// for `INT_TIMER`, which is up to 1024 blocks away.
    fn poke(self) {
        self.with_task(poke);
    }

    /// Wake it for a signal just recorded. Runs **without** sighand's lock;
    /// see the module comment. The calling thread is awake already.
    fn wake(self) {
        let Target::Task(t) = self else { return };
        if t.raw() == current() {
            return;
        }
        // Interrupts a host call that only a signal can end.
        t.kill_host_thread(libc::SIGUSR1);
        // `task_wake_waiting` takes the task's own lock for the condition it
        // signals.
        taskcalls::task_wake_waiting(t.task());
    }

    /// Run `f` over the task's thread group; `None` for one with no group.
    fn with_group<R>(self, f: impl FnOnce(&ffi::tgroup) -> R) -> Option<R> {
        match self {
            Target::Me => taskview::with_current_group(f),
            Target::Task(t) => t.group().map(|g| f(g.tgroup())),
        }
    }

    /// What a sender knows about it that its queue does not.
    fn recipient(self, sig: c_int) -> Recipient {
        let (stopped, init) = self.with_group(|g| (g.stop.is_stopped(), g.unkillable())).unwrap_or_default();
        // A sender that is no guest task -- the embedder, or a host thread of
        // this kernel's own such as the timer service -- stands where the
        // kernel or an ancestor namespace does: Linux's `force`, which lets
        // `SIGKILL` and `SIGSTOP` through to init and nothing else.
        let force = current().is_null();
        Recipient { traced: self.traced(), unkillable: init && !(force && !blockable(sig)), stopped }
    }

    /// A fatal signal for it was sent: its group exits with that status, if
    /// it is not already exiting. Answers whether this started it.
    fn start_exit(self, sig: c_int) -> bool {
        self.with_group(|g| g.exit.signalled(sig as u32)) == Some(true)
    }
}

/// `SIGKILL` to every thread of `g` but `spare`, and the group out of a stop
/// without telling anyone it continued: Linux's `zap_other_threads`, and the
/// loop that ends `complete_signal`. Answers how many threads the group has.
/// Under the `pids_lock` `g` borrows.
pub fn kill_threads(g: kernel_pids::Group<'_>, spare: *mut ffi::task) -> i32 {
    let mut n = 0;
    for t in g.threads() {
        n += 1;
        if t.raw() != spare {
            deliver_signal(Target::Task(t), ffi::SIGKILL_ as c_int, SigInfo::default());
        }
    }
    g.stop().release();
    n
}

/// A signal sent to `to` has started its group's exit: every thread is to
/// be killed and woken now, as Linux's `complete_signal` does, so that the
/// group goes even if the thread the signal was for never runs again.
///
/// The calling thread's own group is the exception, because reaching its
/// threads needs `pids_lock` and the callers that name [`Target::Me`] hold
/// locks of their own. The caller is running and leaves at its next check;
/// the first thread to leave ends the others (`crates/kernel/groupexit`).
fn end_group(to: Target<'_>) {
    match to {
        Target::Me => deliver_signal(Target::Me, ffi::SIGKILL_ as c_int, SigInfo::default()),
        Target::Task(t) => {
            if let Some(g) = t.group() {
                kill_threads(g, std::ptr::null_mut());
            }
        }
    }
}

/// Linux's `force_sig_info_to_task` on init: a fault the calling thread's own
/// instruction raised, with nothing to handle it, ends even init -- resuming
/// it would fault again for ever. The synchronous signals only; a `SIGPIPE`
/// to itself is an ordinary signal, which init discards.
fn forced_on_me(sig: c_int) {
    if !matches!(sig, 4 | 5 | 7 | 8 | 11 | 31) {
        return;
    }
    let unhandled = taskview::with_current_queue(|q| q.lock().table().handler(sig) == kernel_sigdisp::SIG_DFL);
    if unhandled == Some(true) {
        taskview::with_current_group(|g| g.set_unkillable(false));
    }
}

/// `SIGKILL` and `SIGSTOP` cannot be blocked, ignored or handled.
fn blockable(sig: c_int) -> bool {
    sig != ffi::SIGKILL_ as c_int && sig != ffi::SIGSTOP_ as c_int
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

/// The emulator's own faults and the exit path: a `SIGSEGV` for an address the
/// guest cannot reach, a `SIGKILL` for a group on its way out. The disposition
/// is not consulted, because these are not a process's to decline.
pub fn deliver_signal(to: Target<'_>, sig: c_int, info: SigInfo) {
    if to.raw().is_null() {
        return;
    }
    if matches!(to, Target::Me) {
        forced_on_me(sig);
    }
    let arrival = to
        .with_queue(|queue| queue.deliver(sig, info, blockable(sig)))
        .unwrap_or_default();
    if arrival.queued {
        signalfdcalls::signalfd_notify(sig);
    }
    if arrival.wake {
        to.wake();
    }
    to.poke();
}

/// The signal a child's parent gets when the child exits, which `clone(2)` lets
/// the child choose.
///
/// The legacy call takes it from `flags & CSIGNAL`, which is eight bits wide
/// while there are 64 signals, so a guest can ask for 100 — and then nothing
/// between the clone and the exit looks at it. Linux keeps the number rather
/// than refusing the clone (`wait(2)` can still tell such a child apart,
/// through `__WCLONE`) and declines to *send* it: `do_notify_parent` ends with
/// `if (valid_signal(sig) && sig)`. There was no such guard at any of the three
/// places that send it, so `send_signal` reached `sig_mask`, whose assert
/// aborted the emulator. One `clone3` from an unprivileged guest was enough.
///
/// Sent to the parent's **process**, as Linux's `do_notify_parent` does: any
/// of its threads may take it (`sigshared_probe`).
pub fn send_exit_signal(parent: kernel_pids::Task<'_>, sig: c_int, info: SigInfo) {
    if sig <= 0 || sig > ffi::MAX_SIG as c_int {
        return;
    }
    send_process_signal(parent, sig, info);
}

/// A signal sent to one **thread** -- `tgkill`, a fault, `SIGPIPE` -- which
/// the target's disposition may discard. A signal for the process is
/// [`send_process_signal`].
///
/// Not exported since 2026-09-09. `crates/kernel/ptrace` was the last thing to
/// reach it by symbol, and it takes a hook instead; `tools/dead-exports.py`
/// reported this the moment that changed. An export no C can reach is an
/// optimisation barrier on whatever path it sits on, and this one sits on every
/// signal.
pub fn send_signal(to: Target<'_>, sig: c_int, info: SigInfo) {
    if !about_to_queue(to, sig) {
        return;
    }

    if matches!(to, Target::Me) {
        forced_on_me(sig);
    }

    // Whether the disposition discards it, whether it is recorded, whether
    // it ends the process, and whether the thread has to be woken: one
    // acquisition, in crates/kernel/sighand. The rule the order encodes is
    // that a *blocked* signal is never discarded for being ignored -- and
    // neither is any signal to a traced task, whose tracer gets to see it
    // first.
    let recipient = to.recipient(sig);
    let arrival = to
        .with_queue(|queue| queue.send(sig, info, blockable(sig), recipient, || to.start_exit(sig)))
        .unwrap_or_default();
    if arrival.queued {
        to.poke();
        // Linux's signalfd_notify: a signal that becomes pending makes every
        // signalfd watching it readable, which means waking that description's
        // pollers. Waking the *thread* is not enough -- an epoll set is woken
        // by a description telling its watchers, and a thread blocked in
        // epoll_wait is not re-polling anything. See the note in
        // crates/kernel/signalfdcalls. Outside the sighand lock, which
        // sighand_send has already released.
        signalfdcalls::signalfd_notify(sig);
    }
    if arrival.ends_group {
        end_group(to);
    } else if arrival.wake {
        to.wake();
    }
    after_queueing(to, sig);
}

/// What every signal a process sends goes through before it is queued:
/// answers false when there is nothing to queue -- signal 0, a task that is
/// gone, or one running an offloaded host binary, which took it.
fn about_to_queue(to: Target<'_>, sig: c_int) -> bool {
    // The one thing `crates/kernel/ptrace` needs from this crate, installed
    // here rather than at boot because every route to a *stopped* tracee runs
    // through a signal first: an attach sends SIGSTOP, a `PTRACE_TRACEME` child
    // stops at its execve's SIGTRAP, and a syscall-stop needs a
    // `PTRACE_SYSCALL` on a tracee that is already stopped. So a `PTRACE_KILL`
    // cannot be reached before this has run.
    //
    // Before the early returns below, so that "any call arms it" is the whole
    // rule and there is no argument about which signals count. After the first
    // it is an acquire load that fails, on a path that already takes a mutex.
    kernel_ptrace::set_kill_hook(|task| {
        send_signal(Target::Task(task), ffi::SIGKILL_ as c_int, SigInfo::default());
    });

    // Signal zero is for testing whether a process exists.
    if sig == 0 {
        return false;
    }
    let task = to.raw();
    if task.is_null() || to.gone() {
        return false;
    }
    // Linux's `prepare_signal`: a process that is dying takes nothing more.
    // Its status was settled by whatever started the exit.
    if to.with_group(|g| g.exit.pending().is_some()) == Some(true) {
        return false;
    }
    trace_fatal_signal(task, sig);

    // Native offload: forward the signal to the host process running natively.
    // A hook, because the edge only runs one way otherwise; see
    // [`OFFLOAD_FORWARD`].
    if let Some(forward) = OFFLOAD_FORWARD.get()
        && to.with_task(|t| forward(t, sig)) == Some(true)
    {
        return false;
    }
    true
}

/// What a `SIGCONT` or a `SIGKILL` does to the group's stop, once it is
/// queued.
fn after_queueing(to: Target<'_>, sig: c_int) {
    if sig == ffi::SIGCONT_ as c_int || sig == ffi::SIGKILL_ as c_int {
        // Only a group that was actually stopped has been continued, and a
        // SIGKILL is not a continue whatever the group was doing. The object
        // decides both; see crates/kernel/groupstop.
        //
        // The parent is told by the *continued thread* as it leaves the stop,
        // not here: this is called with pids_lock already held from several
        // places -- do_exit's pdeath loop among them -- and finding the
        // parent needs that lock.
        to.with_group(|g| {
            if sig == ffi::SIGCONT_ as c_int {
                g.stop.resume();
            } else {
                g.stop.release();
            }
        });
    }
}

/// The `IUL_EXEC_TRACE` line for a signal that usually ends a process. Where a
/// V8 or Go crash gets correlated with the guest pc that produced it.
fn trace_fatal_signal(task: *mut ffi::task, sig: c_int) {
    let fatal = [
        ffi::SIGTRAP_,
        ffi::SIGABRT_,
        ffi::SIGILL_,
        ffi::SIGSEGV_,
        ffi::SIGBUS_,
    ];
    if !fatal.contains(&(sig as u32)) || !util_iulenv::env().exec_trace {
        return;
    }
    unsafe {
        let cpu = (*task).cpu.get().cast_const();
        let regs = (*cpu).regs;
        eprintln!(
            "SIGNAL_TRACE: sig={sig} pc={:#x} pid={} sp={:#x} lr={:#x} fault={:#x}",
            (*cpu).pc,
            (*task).pid(),
            (*cpu).sp,
            regs[30],
            (*cpu).segfault_addr
        );
    }
}

// `signal_dequeue` was here until 2026-09-30: a `pub unsafe fn` that took a
// signal off a task's queue **without the sighand lock** that every writer of
// the queue holds. It had no caller -- signalfd dequeues through its own
// guarded loop -- so the race was never reachable; `pub` is what kept
// `dead_code` from saying so.

// ---------------------------------------------------------------------------
// The calling thread signalling itself
// ---------------------------------------------------------------------------

/// Has the caller ignored or blocked this signal?
///
/// Linux's `is_ignored()`, and the terminal's background rules consult it
/// *before* asking whether the process group is orphaned — so a group that
/// ignores `SIGTTOU` is allowed to proceed even when it is orphaned. Split out
/// of what was `try_self_signal` because the answer decides the operation as well as
/// the signal, and because it is the cheap half: finding out whether a group is
/// orphaned needs `pids_lock`, and a caller that ignores the signal never has
/// to.
///
pub fn signal_is_ignored_by_current(sig: c_int) -> bool {
    let task = current();
    if task.is_null() {
        return true;
    }
    // The **calling** task's, so it comes from `current_sighand()` rather than
    // from a `pids_lock` read: this runs on the task's own thread with no lock, and
    // the field the latter reads has a cross-thread writer in the group-exit
    // valve. See `crates/kernel/taskview`'s accessor for the whole of it.
    taskview::with_current_queue(|queue| queue.is_ignored_or_blocked(sig)).unwrap_or(true)
}

/// `SIGPIPE` to the calling thread, for `crates/fs/pipecalls`: a write to a
/// pipe with no readers raises it as well as answering `EPIPE`.
///
/// Queued rather than delivered, so a **blocked** `SIGPIPE` stays pending —
/// which is what every program that handles `EPIPE` relies on.
///
pub fn signal_self(sig: c_int) {
    send_signal(Target::Me, sig, SigInfo::default());
}

/// `sigsuspend`'s mask, saved and replaced for the duration of one call.
///
pub fn sigmask_set_temp(mask: u64) {
    let task = current();
    if task.is_null() {
        return;
    }
    // `current_sighand()`, not a `pids_lock` read: this is the calling task, on
    // its own thread with no lock, and that read is of the field the group-exit
    // valve writes from another -- `signal_is_ignored_by_current` above says
    // why. It read the field until 2026-09-30, and with no null test.
    taskview::with_current_queue(|queue| queue.set_mask_temporarily(mask));
}

/// The end of a call that set a temporary mask: `epoll_pwait`, `ppoll`,
/// `pselect6`. One that is returning `EINTR` leaves the saved mask for the
/// delivery path, which runs the handler under the temporary mask and then
/// puts the old one back; any other answer puts it back first, so a signal
/// only the temporary mask let in is not delivered. That is Linux's
/// `restore_saved_sigmask_unless(ret == -EINTR)`, and until 2026-11-11 every
/// answer was the first case: a zero-timeout `epoll_pwait` with a signal
/// pending answered 0 and ran the handler (`epoll2_probe`).
pub fn sigmask_restore_temp<T>(result: &Result<T, guest_errno::Errno>) {
    if matches!(result, Err(e) if *e == guest_errno::Errno::EINTR) {
        return;
    }
    if current().is_null() {
        return;
    }
    taskview::with_current_queue(|queue| queue.restore_temporary_mask());
}

#[path = "routing.rs"]
mod routing;
pub use routing::{
    pgrp_is_orphaned, retarget_on_exit, send_group_signal, send_group_signal_locked, send_process_signal,
    signal_kill_task_for_rs,
};

#[path = "sigset.rs"]
mod sigset;
pub use sigset::{sigset_size_valid, user_get_sigset};

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_sighand as _;
    use kernel_sigqueue as _;

    #[test]
    fn only_two_signals_cannot_be_blocked() {
        // Linux's rule, and the one thing every caller of `blockable` is
        // deciding. Adding a third silently makes it undeliverable to a
        // sigwait.
        for sig in 1..=64 {
            let expected = sig != ffi::SIGKILL_ as c_int && sig != ffi::SIGSTOP_ as c_int;
            assert_eq!(blockable(sig), expected, "signal {sig}");
        }
    }

    #[test]
    fn a_sigset_is_exactly_eight_bytes() {
        // This accepted any multiple of 8 from 8 up, so a guest passing 16 was
        // told its mask had been set when only the first word was read.
        assert!(sigset_size_valid(8));
        assert!(!sigset_size_valid(0));
        assert!(!sigset_size_valid(4));
        assert!(!sigset_size_valid(16));
        assert!(!sigset_size_valid(128));
    }

    /// Delivering a signal arms `PTRACE_KILL`, and nothing else can catch it if
    /// it stops.
    ///
    /// A `PTRACE_KILL` with no hook installed is a **silent no-op**: the arm
    /// clears `stopped` and notifies, so the tracee resumes and the tracer sees
    /// a successful call, with no SIGKILL. That is not distinguishable by any
    /// unit test in `crates/kernel/ptrace`, which has no signal layer to
    /// deliver through.
    ///
    /// Signal zero, which returns before anything is queued — the install is
    /// deliberately the first statement, so that "any call arms it" is the
    /// whole rule.
    #[test]
    fn delivering_a_signal_arms_ptrace_kill() {
        // `Me` on a thread with no task: nothing past the arming runs.
        send_signal(Target::Me, 0, SigInfo::default());
        assert!(kernel_ptrace::kill_hook_installed());
    }
}
