//! Ptrace stop coordination used by signal reception.

use super::*;

// ---------------------------------------------------------------------------
// ptrace
// ---------------------------------------------------------------------------

/// Asked by the stop loop after every wake, with the ptrace lock held. A
/// `SIGKILL` does not end that wait -- the tracee is parked on the tracer, not
/// on its signal queue -- so this is what gets it out.
///
/// It takes sighand's lock, which is the order this file establishes:
/// [`signal_delivery_stop`] releases sighand's before taking ptrace's, and takes
/// it back after. `crates/kernel/ptrace`'s module comment records the same
/// thing from the other side, because `tools/lock-order.py` reads only C.
fn sigkill_is_pending() -> bool {
    taskview::with_current_queue(|queue| {
        let guard = queue.lock();
        (guard.queue().pending() | guard.shared().mask()) & mask_of(ffi::SIGKILL_ as c_int) != 0
    })
    .unwrap_or(false)
}

/// A syscall boundary, for a tracee the tracer told to stop at them.
///
/// This is what `strace` and `gdb`'s `catch syscall` are made of: the tracee
/// stops before the syscall runs and again after, and the tracer reads the
/// registers at each — the number and the arguments on the way in, the answer
/// on the way out. The two are indistinguishable to the tracer except by
/// counting, which is why the pairing is kept in `crates/kernel/ptrace` and
/// reset by anything that is not a boundary.
///
/// It is the same three steps as [`signal_delivery_stop`] with no sighand lock
/// in the way: record the stop, tell the tracer under `pids_lock`, park. A
/// `SIGKILL` gets the tracee out, as it does there, and turns into a group
/// exit rather than a return.
///
/// # Safety
/// Called on a guest thread at a syscall boundary, holding no lock: a
/// `SIGKILL` in the stop exits the thread without unwinding.
pub unsafe fn ptrace_syscall_boundary() {
    taskview::with_current_ptrace(syscall_stop);
}

fn syscall_stop(p: &ffi::ptrace_state) {
    // Not traced any more: no stop. The dispatcher asks `stops_at_syscalls`
    // once, at the entry, and takes the exit stop on that answer -- deliberately,
    // so a `PTRACE_CONT` from the entry does not strand the tracee at an exit
    // the tracer did not ask for. But that reasoning is about *which* stops a
    // tracer wants; a tracee whose tracer **exited** in the entry stop has no
    // tracer to want any, and stopping it again is the hang the detach was
    // written to fix, one stop further along. `ptrace_orphan_probe`'s
    // syscall-stop case was still "no" with the detach in place, for this.
    if !p.is_traced() {
        return;
    }
    p.enter_syscall_stop();
    notify_tracer_of_stop(p.stop_signal());
    if p.wait_while_stopped(sigkill_is_pending) {
        strace!("{} received a SIGKILL in syscall stop", taskview::current_pid());
        crate::do_exit_group(ffi::SIGKILL_ as c_int);
    }
    // `PTRACE_SYSCALL`'s `data` at a syscall stop is a signal the tracer
    // wants sent: Linux's `ptrace_report_syscall` does `send_sig(exit_code,
    // current, 1)` once the stop ends, so it is taken at the next return to
    // the guest like any other -- after the syscall, and through a
    // signal-delivery-stop for this tracee. It was consumed and dropped until
    // 2026-11-13, on the reasoning that injecting would run a handler between
    // the halves of a syscall; queueing is what Linux does, and the handler
    // runs after the exit stop (`ptrace_probe`'s "a signal passed at a
    // syscall stop").
    let sig = p.take_resume_signal();
    if sig != 0 {
        crate::send_signal(Target::Me, sig, SigInfo { sig, ..kernel_info() });
    }
}

/// A `PTRACE_EVENT_*` stop: the tracee parks where the event happened and the
/// tracer reads `SIGTRAP | (event << 8)` out of `wait`. Answers whether it
/// stopped, which is false when the tracer did not ask for that event.
///
/// **Where** it is called is the whole of what makes it right, and getting it
/// wrong is silent. `PTRACE_EVENT_EXEC` was a `SIGTRAP` queued at the end of
/// `execve` at first, which meant the tracee did not stop until it was back in
/// userspace -- *after* `execve`'s syscall-exit stop, where Linux puts the
/// event *before* it. strace noticed and said so: `Stray PTRACE_EVENT_EXEC
/// from pid 6, trying to recover...`, because it checks that an exec event
/// arrives while it believes the tracee is still inside a syscall. An event is
/// a stop taken at a point in the kernel, not a signal that finds its way to
/// one.
///
/// These stops are not on the way *to* userspace, and that is what makes their
/// abandon rule different from the two stops above: a `SIGKILL` here leaves the
/// stop and carries on, where the others call `do_exit_group`. The exit stop is
/// already inside `do_exit`, so calling it again would be the recursion; the
/// exec stop is on a path whose caller has to unwind. Both then die on the way
/// out, which is where they were going.
///
/// A tracer that never continues its tracee hangs it. That is Linux's
/// behaviour and the same hazard `ptrace_syscall_boundary` has, and `SIGKILL`
/// is the way out of all three.
///
/// On the calling thread, at the point in the kernel the event names. Safe:
/// unlike the other two stops a `SIGKILL` here does not exit the thread, so
/// nothing a caller holds is skipped. A caller holding a lock the tracer needs
/// hangs, which is a deadlock and not a soundness question.
pub fn ptrace_exec_event_stop() -> bool {
    // Linux's message is the pid the task had before the exec, which is its
    // own unless a non-leader thread exec'd; this kernel's exec keeps the pid.
    let pid = taskview::current_pid() as u64;
    ptrace_event_stop(ffi::PTRACE_EVENT_EXEC_ as c_int, ffi::PTRACE_O_TRACEEXEC_, pid)
}

/// `PTRACE_EVENT_EXIT`, from `do_exit` and before it releases anything. The
/// message is the exit status, as `wait` would report it.
pub fn ptrace_exit_event_stop(status: c_int) -> bool {
    ptrace_event_stop(ffi::PTRACE_EVENT_EXIT_ as c_int, ffi::PTRACE_O_TRACEEXIT_, status as u32 as u64)
}

/// Which event a new task is, by Linux's `kernel_clone`: a vfork, then
/// anything whose exit signal is not `SIGCHLD` (a thread's is 0), then a fork.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ForkEvent {
    Fork,
    Vfork,
    Clone,
}

impl ForkEvent {
    pub fn of(vfork: bool, exit_signal: c_int) -> ForkEvent {
        if vfork {
            ForkEvent::Vfork
        } else if exit_signal != ffi::SIGCHLD_ as c_int {
            ForkEvent::Clone
        } else {
            ForkEvent::Fork
        }
    }

    /// The option that asks for it, and its `PTRACE_EVENT_*`.
    fn option_and_event(self) -> (u32, c_int) {
        match self {
            ForkEvent::Fork => (0x2, 1),
            ForkEvent::Vfork => (0x4, 2),
            ForkEvent::Clone => (0x8, 3),
        }
    }

    /// Whether a tracee with `options` takes this event: the question a new
    /// task's auto-attach asks before it is let run.
    pub fn wanted(self, options: u32) -> bool {
        options & self.option_and_event().0 != 0
    }
}

/// The fork event stop, in the parent, once the new task `pid` has been let
/// run. The new task was attached already (`crates/kernel/forkcalls`).
pub fn ptrace_fork_event_stop(event: ForkEvent, pid: c_int) -> bool {
    let (option, ev) = event.option_and_event();
    ptrace_event_stop(ev, option, pid as u64)
}

/// `PTRACE_EVENT_VFORK_DONE`, in a vfork parent once its child has exec'd or
/// exited.
pub fn ptrace_vfork_done_stop(pid: c_int) -> bool {
    ptrace_event_stop(5, 0x20, pid as u64)
}

/// The stops above, which is where the option each event belongs to is
/// written down -- so a caller names the event it is at and no bit crosses a
/// crate boundary.
fn ptrace_event_stop(event: c_int, option: u32, msg: u64) -> bool {
    taskview::with_current_ptrace(|p| {
        if !(p.is_traced() && p.arm_event(event, option, msg)) {
            return false;
        }
        p.enter_stop(ffi::SIGTRAP_ as c_int, &event_info(event));
        notify_tracer_of_stop(p.stop_signal());
        p.leave_syscall_pairing();
        if p.wait_while_stopped(sigkill_is_pending) {
            strace!("{} received a SIGKILL in an event stop", taskview::current_pid());
        }
        // An event stop carries no signal to deliver, for the reason
        // `ptrace_syscall_boundary` gives: `PTRACE_CONT`'s `data` is one the
        // tracer wants injected, and injecting it here would run a handler at
        // a point the guest cannot take one. Consumed so it does not leak
        // into the next stop.
        let _ = p.take_resume_signal();
        true
    })
    .unwrap_or(false)
}

/// The `siginfo_` of an event stop: Linux's `ptrace_do_notify`, which says
/// `SIGTRAP`, `si_code` the reported status (`SIGTRAP | event << 8`) and the
/// stopping task as the sender. It was all zeroes until 2026-11-13, read as
/// "no sender" from a comment rather than measured; `ptrace_attach_probe`'s
/// GETSIGINFO after `PTRACE_INTERRUPT` reads `signo 5 code 0x8005`.
fn event_info(event: c_int) -> SigInfo {
    let mut info = SigInfo {
        sig: ffi::SIGTRAP_ as c_int,
        code: ffi::SIGTRAP_ as c_int | (event << 8),
        ..SigInfo::default()
    };
    info.__bindgen_anon_1.kill.pid = taskview::current_pid();
    info.__bindgen_anon_1.kill.uid = taskview::with_current_creds(|c| c.uid()).unwrap_or(0);
    info
}

/// `PTRACE_EVENT_STOP`, the event Linux reports for a trap with no other
/// event behind it.
const PTRACE_EVENT_STOP: c_int = 128;

/// Linux's `do_jobctl_trap` for a seized tracee: a `PTRACE_INTERRUPT`, or
/// the first stop of a task a seized one forked, taken on the way back to
/// the guest. Answers whether it stopped.
pub(super) fn trap_stop() -> bool {
    taskview::with_current_ptrace(|p| {
        if !p.take_trap() {
            return false;
        }
        p.enter_stop(ffi::SIGTRAP_ as c_int | (PTRACE_EVENT_STOP << 8), &event_info(PTRACE_EVENT_STOP));
        notify_tracer_of_stop(p.stop_signal());
        p.leave_syscall_pairing();
        if p.wait_while_stopped(sigkill_is_pending) {
            strace!("{} received a SIGKILL in a trap stop", taskview::current_pid());
            crate::do_exit_group(ffi::SIGKILL_ as c_int);
        }
        // Linux's `do_jobctl_trap` ignores what `ptrace_stop` returns, so a
        // `PTRACE_CONT` signal after a trap is dropped, as after an event
        // stop.
        let _ = p.take_resume_signal();
        true
    })
    .unwrap_or(false)
}

/// Tell the tracer that this task has stopped: Linux's
/// `do_notify_parent_cldstop(tsk, true, CLD_TRAPPED)`, to `tsk->parent`,
/// which is the tracer. It went to the real parent until 2026-11-13, which
/// was the tracer for as long as `PTRACE_TRACEME` was the only way in.
fn notify_tracer_of_stop(sig: c_int) {
    notify_of_stop(ffi::CLD_TRAPPED_ as c_int, sig, true);
}

/// Park a traced thread on its tracer, with the signal that stopped it.
///
/// Gives sighand's lock up for the wait and takes it back after: the tracer
/// reads the tracee's state under the ptrace lock, and the tracee must not hold
/// sighand's across a wait the tracer ends.
///
/// `allowed` is the set this delivery took `sig` under, which is what the
/// signal the tracer passes back is judged blocked against.
///
/// # Safety
/// Called on the guest thread `task` is.
pub(super) unsafe fn signal_delivery_stop<'a>(
    task: *mut ffi::task,
    queue: kernel_sighand::Queue<'a>,
    guard: QueueGuard<'a>,
    sig: c_int,
    info: &SigInfo,
    allowed: u64,
) -> QueueGuard<'a> {
    // SAFETY: the caller's contract -- this is `task`'s own thread. `None` is
    // a task on its way out, for which each step below is what the adapters
    // it replaced made it: nothing.
    let p = unsafe { taskview::ptrace_of(task) };
    if let Some(p) = p {
        p.enter_stop(sig, info);
    }
    // The tracer is told after sighand's lock is dropped, under pids_lock:
    // that is what protects a task from being reaped between the lookup and
    // the use, and the order everywhere else is pids_lock then sighand's. This
    // used to read the parent *before* dropping the guard, without the lock,
    // under a TODO saying it could not take it -- it can, two lines later.
    // `ptrace_enter_stop` has already recorded the stop, so the tracer finds
    // it whether it looks before or after the signal.
    drop(guard);
    notify_tracer_of_stop(sig);
    // Not a syscall boundary, so the next PTRACE_SYSCALL reports an entry
    // rather than continuing a pairing this interrupted.
    if let Some(p) = p {
        p.leave_syscall_pairing();
    }
    if p.is_some_and(|p| p.wait_while_stopped(sigkill_is_pending)) {
        strace!("{} received a SIGKILL in signal delivery stop", taskview::current_pid());
        crate::do_exit_group(ffi::SIGKILL_ as c_int);
    }
    let guard = queue.lock();

    // What the tracer decided. `PTRACE_CONT` with a signal delivers that
    // signal to the tracee as it resumes -- the one it stopped for, passed
    // through, which is what strace does with every signal it sees, or a
    // different one -- and with 0 suppresses it. Until 2026-09-04 nothing
    // read the tracer's answer and the stopped-for signal was always dropped.
    // The delivery goes through `receive_signal` like any other, so the
    // disposition, the frame and the mask are the ordinary ones; the siginfo
    // is the original when the signal is the same and a kernel-sent one when
    // the tracer substituted another.
    let resume = p.map_or(0, |p| p.take_resume_signal());
    if resume == 0 {
        return guard;
    }
    let delivered = if resume == sig {
        *info
    } else {
        SigInfo {
            sig: resume,
            ..kernel_info()
        }
    };
    // Linux's `ptrace_signal`, after the stop: "If the (new) signal is now
    // blocked, requeue it." A tracee is very often parked with the signal
    // blocked -- musl's `raise` blocks every signal around its `tkill`, so
    // a child that raised `SIGSTOP` is stopped inside that window -- and
    // the requeued signal is delivered when the mask lets it, which for a
    // tracee means through another signal-delivery-stop. The first version
    // of this delivered regardless and the tracee died of a signal Linux
    // stops it for; `ptrace_probe`'s "CONT with data=SIGTERM" measured it.
    //
    // Blocked by the mask *this delivery* runs under, which is Linux's
    // `current->blocked` at that point: inside `sigsuspend` it is the
    // temporary mask, which `deliver_pending` has already swapped back out
    // of the queue to put it in the handler's frame. Judged by the queue's
    // mask, a `SIGCHLD` a shell's `wait` was suspended for was requeued
    // instead of handled, the restarted `sigsuspend` took it again, and
    // `strace -f sh -c '... & wait'` printed that `SIGCHLD` for ever.
    let mut guard = guard;
    let blocked = allowed & mask_of(resume) == 0;
    if blocked {
        let blockable = resume != ffi::SIGKILL_ as c_int && resume != ffi::SIGSTOP_ as c_int;
        guard.queue_mut().arrive(resume, delivered, blockable);
        return guard;
    }
    unsafe { receive_signal(task, guard, &delivered) }
}
