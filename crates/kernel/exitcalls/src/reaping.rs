//! Zombie reaping, parent notification, and child reparenting.

use std::sync::atomic::Ordering;
use super::*;

/// What the parent will be told about how long this took.
///
/// The add and the read-back are one operation: what this thread contributed
/// and what the group has now are the pair the parent is credited with.
///
/// On the thread that is exiting.
pub(super) fn record_own_times(status: c_int) -> (grouprusage::Timeval, grouprusage::Timeval) {
    taskview::with_current_task(|t| t.exit_code.store(status as u32, Ordering::Relaxed));
    let rusage = hostrusage::rusage_get_thread();
    // The calling task's group, through the accessor that tests it for null,
    // where this dereferenced `(*task).group` without one. A task with no
    // group has nothing to add to and reports nothing.
    taskview::with_current_group(|g| {
        let total = g.times.add_own(rusage.utime, rusage.stime);
        (total.utime(), total.stime())
    })
    .unwrap_or_default()
}

/// `clock_t_` from a guest `timeval`. `kernel/time.h`'s `clock_from_timeval`,
/// which is `static inline`.
pub(super) fn clock_from_timeval(tv: grouprusage::Timeval) -> u64 {
    // 100 Hz, which is what this kernel reports through AT_CLKTCK.
    const HZ: u64 = 100;
    (tv.sec as u64) * HZ + (tv.usec as u64) / (1_000_000 / HZ)
}

/// Take this task out of the process tree and tell whoever is waiting.
///
/// Answers the group leader and whether nobody is coming to reap it.
///
/// Called on the exiting thread, with `pids_lock` held across this and the
/// destroy that follows -- see [`do_exit`].
pub(super) fn detach_and_notify(
    pids: &kernel_pids::PidsHeld,
    deferred: &super::Deferred,
    status: c_int,
    (utime, stime): (grouprusage::Timeval, grouprusage::Timeval),
) -> (*mut ffi::task, bool) {
    let me = kernel_pids::Task::current(pids).expect("the exiting thread has its task");
    let t = me.task();
    // `exiting` is already set: `claim_session_terminal` marks the task as
    // the first thing `do_exit` does under `pids_lock`.
    debug_assert!(t.exiting.get(), "do_exit marks the task before detaching it");
    // May already be NULL: another thread of the group can have released it
    // concurrently, after the safety valve's SIGUSR1.
    //
    // **A plain write, and every concurrent reader of this field takes
    // `pids_lock`**, which `do_exit` holds across this call. Checked
    // 2026-09-11 and re-checked 2026-09-12, against every reader of some
    // *other* task's `sighand`:
    //
    // - `signaldeliver`'s `thread_wants_signal` and `signal_thread` hold
    //   `pids_lock` -- `signal_thread`'s comment says every caller does, and
    //   the three cross-thread `deliver_signal` call sites are inside a
    //   `Pids::take()`.
    // - `reap_if_zombie` below reads `(*parent).sighand`, under `pids_lock`.
    // - The task's **own** thread reads its own reference, not this field,
    //   since 2026-09-12 -- `taskview`'s `current_sighand`. The thread
    //   executing this function is that thread, so there is nothing to be
    //   concurrent with even if it did.
    //
    // The valve was the one site where both halves failed together. It holds
    // `pids_lock` too, so what made it different was the lockless reader, and
    // that reader is gone.
    //
    // **The drop is a drop.** This used to be a `sighand_release` and a null
    // store, two statements that had to agree; releasing without clearing
    // leaves a dangling pointer a `/proc` reader can find, and clearing without
    // releasing leaks the whole group's table. Assigning `None` is both, and
    // the "release exactly once" across this, the valve and the cleanup handler
    // is `Drop`'s now.
    //
    // **Except the leader's**, which stays with its masks and pending sets
    // until `task_destroy`: Linux releases a group leader's only when it is
    // reaped, and `/proc/<pid>/status` of a zombie reads them -- a process
    // killed by a signal sent to it still shows that signal in `ShdPnd`
    // (`sigfatal_probe`). The `SIGKILL` that ended it is gone, as Linux's
    // `get_signal` takes it on the way out.
    // The exiting thread's own group, under the `pids_lock` the caller holds;
    // it dereferenced `(*task).group` with no null test.
    let leader = kernel_pids::Group::current(pids)
        .and_then(kernel_pids::Group::leader_task)
        .expect("a thread reaches detach_and_notify with its group and leader");
    // SAFETY, both: another thread reaches this queue only through the task's
    // `sighand`, under the `pids_lock` held here -- and a sender passes over a
    // task that is exiting.
    if leader.raw() == me.raw() {
        let kill = kernel_sigqueue::mask_of(ffi::SIGKILL_ as c_int);
        unsafe { (*t.signals.get()).retain(|info| kernel_sigqueue::mask_of(info.sig) != kill) };
    } else {
        t.sighand.set(None);
        unsafe { (*t.signals.get()).clear() };
    }

    reparent_children(pids, me);

    let mut auto_reap = false;
    let last_of_group = exit_tgroup(me, deferred);
    if last_of_group {
        // SEM_UNDO: what this process held is given back. The whole reason the
        // System V family is still used for locking is that a process which
        // dies holding a semaphore does not leave it held -- and no third
        // party can tell that case from a process that is merely slow. Here
        // rather than per thread because the undo list is per thread group,
        // which is what CLONE_SYSVSEM shares and every thread library sets.
        sysvsem::group_exiting(t.tgid.load(Ordering::Relaxed));
    }
    if last_of_group && !leader.is_zombie() {
        // Not already marked zombie by the do_exit_group force path.
        let mut parent = leader.parent();
        if parent.is_none() && t.pid() != 1 {
            // A non-init process with no parent: this happens during
            // reparenting, or if the parent exited first.
            parent = kernel_pids::Task::by_pid(pids, 1).filter(|t| !t.is_zombie());
            if let Some(init) = parent {
                proctree::set_parent(leader.raw(), init.raw());
            }
        }

        let Some(parent) = parent else {
            // init died, so the guest is over and this host process goes with
            // it. The hook runs first: halt_system() does not return, and its
            // `_exit(0)` is where the guest's status was being thrown away --
            // `iul -r <rootfs> /bin/false` answered 0, and so did every other
            // guest failure, which makes the CLI unusable from a script.
            //
            // An embedder's hook records and returns (ServerBox's writes the
            // session's exit code), so it still reaches halt_system; the CLI's
            // exits with the status and never gets there.
            run_exit_hook(leader.pid(), status);
            halt_system();
        };

        // A process that has exec'd tells its parent with SIGCHLD whatever
        // clone asked for: Linux's `exit_notify` resets a non-SIGCHLD exit
        // signal once the exec ids differ (`execthreads_probe`). The half of
        // that rule where the *parent* has exec'd since the fork is not here:
        // nothing records a parent's exec against its children.
        if leader.did_exec() {
            leader.task().exit_signal.store(ffi::SIGCHLD_ as c_int, Ordering::Relaxed);
        }

        // A child released without a wait credits its parent nothing, which
        // is what Linux does and reads as a loss: `wait_task_zombie` is the
        // only place that moves a child's times into `psig->cutime`, and an
        // auto-reaped child never reaches it -- `release_task` from
        // `exit_notify` does not.
        //
        // This crate did credit it, on the reasoning that "releasing the child
        // early is not a reason to lose them". A container run says otherwise:
        // a child that burned 1.7 s leaves RUSAGE_CHILDREN unchanged under
        // SIG_IGN, against +1.73 s for the same child reaped by `waitpid`.
        auto_reap = parent_will_never_wait(parent, leader);

        // `exit_notify`'s `kill_orphaned_pgrp(tsk->group_leader, NULL)`, after
        // the children have gone to their new parent and **before** the parent
        // is told: a parent woken by this exit can already see the signals.
        if let Some(own) = leader.group() {
            kill_orphaned_pgrp(pids, own, parent.group());
        }

        leader.mark_zombie();
        if let Some(g) = parent.group() {
            kernel_tgroup::tgroup_notify_child_exit(g);
        }
        // Straight to the registry, which is a leaf: the pidfd *syscalls*
        // depend on `fs-poll`, which ends a stuck wait through this crate, so
        // going through them would be a cycle.
        // The status a wait would report, which is what `PIDFD_INFO_EXIT`
        // reports once the zombie is reaped -- the same expression as
        // `crates/kernel/waitcalls`' `reap_if_zombie`.
        let pid = leader.pid();
        let wait_status = leader
            .group()
            .and_then(|g| g.exit_pending())
            .unwrap_or(leader.exit_code()) as i32;
        let matched = kernel_pidfd::notify_exit(pid, wait_status);
        // IUL_PIDFD_TRACE. It counts what was woken rather than saying an exit
        // happened, because the failure this diagnoses is a poller that was
        // *not* woken.
        if util_iulenv::env().pidfd_trace {
            eprintln!("[pidfd] notify_exit(pid={pid}): {matched} pidfds matched+woken");
        }
        notify_parent(parent, leader, me, utime, stime);
        run_exit_hook(leader.pid(), status);
    }
    (leader.raw(), auto_reap)
}

/// The children of a task that is leaving, moved to whoever takes them.
pub(super) fn reparent_children(pids: &kernel_pids::PidsHeld, me: kernel_pids::Task<'_>) {
    let new_parent = find_new_parent(pids, me);
    // Collected first, because reparenting takes each child off this list; the
    // walk was backwards by index for the same reason.
    let children: Vec<_> = me.children().collect();
    for child in children {
        // A tracer that leaves detaches its tracees, which is Linux's
        // `exit_ptrace`. Without it a tracee parked in a ptrace stop waits
        // for a continue that cannot come: `ptrace_orphan_probe` measured
        // two of its three cases hanging here where a real kernel resumed
        // all three. Here rather than in a loop of its own because every
        // tracee is a child -- PTRACE_TRACEME is the only way in -- so this
        // is the one walk that already visits them.
        if child.ptrace().is_some_and(|p| p.detach_on_tracer_exit()) {
            strace!("{} detached from its exiting tracer", child.pid());
        }
        // prctl(PR_SET_PDEATHSIG) asked to hear about this. Sent *before*
        // the reparenting, because it is about the parent that is going
        // away.
        let pdeath = child.attr().pdeath_signal();
        proctree::set_parent(child.raw(), new_parent);
        if pdeath != 0 {
            // To the process, as Linux's `group_send_sig_info(..., PIDTYPE_TGID)`.
            signaldeliver::send_process_signal(child, pdeath, ffi::siginfo_::default());
        }
        // `reparent_leader`'s `kill_orphaned_pgrp(p, father)`: this task may
        // have been what kept the child's group from being orphaned. Not when
        // a thread of the same process takes the child, which Linux skips
        // too: the process is still there.
        let same_process = child
            .parent()
            .and_then(|p| p.group())
            .zip(me.group())
            .is_some_and(|(a, b)| a.id() == b.id());
        if !same_process && let Some(group) = child.group() {
            kill_orphaned_pgrp(pids, group, me.group());
        }
    }
}

/// Linux's `kill_orphaned_pgrp`: `group`'s process group has just lost
/// `link`, a process in another group of the same session -- the exiting
/// process, or the parent of the exiting process -- which could have
/// continued it. If that leaves the group orphaned and something in it is
/// stopped, nobody is left who would ever send the `SIGCONT`, so the group
/// gets `SIGHUP` and `SIGCONT` now: POSIX's rule, and what lets a stopped job
/// whose shell died go away instead of staying stopped for ever.
///
/// Neither half existed until 2026-11-12 (`exitorder_probe`).
fn kill_orphaned_pgrp(pids: &kernel_pids::PidsHeld, group: kernel_pids::Group<'_>, link: Option<kernel_pids::Group<'_>>) {
    let Some(link) = link else {
        return;
    };
    let pgid = group.pgid();
    if link.pgid() == pgid || link.sid() != group.sid() {
        return;
    }
    if !signaldeliver::pgrp_is_orphaned(pids, pgid) || !pgrp_has_stopped(pids, pgid) {
        return;
    }
    for sig in [ffi::SIGHUP_, ffi::SIGCONT_] {
        let info = ffi::siginfo_ { sig: sig as c_int, code: ffi::SI_KERNEL_ as _, ..Default::default() };
        signaldeliver::send_group_signal_locked(pids, pgid as u32, sig as c_int, info);
    }
}

/// Linux's `has_stopped_jobs`: whether any process in the group is stopped.
fn pgrp_has_stopped(pids: &kernel_pids::PidsHeld, pgid: c_int) -> bool {
    (0..).map_while(|i| kernel_pids::pgroup_at(pids, pgid, i)).any(|g| g.stop().is_stopped())
}

/// Has the parent said it will never wait for this child?
///
/// POSIX: a parent that ignores `SIGCHLD`, or that asked for `SA_NOCLDWAIT`,
/// has said so, and its children are released as they exit rather than kept as
/// zombies for a wait that is not coming. Neither was implemented, so
/// `signal(SIGCHLD, SIG_IGN); fork();` — the ordinary way to write a forking
/// server that does not collect its children — left one task, one tgroup and
/// one pid behind per child, for the parent's lifetime.
///
/// `sighand` may be NULL: `do_exit` releases its own, and the safety valve in
/// `do_exit_group` nulls a stuck peer's without reparenting that peer's
/// children — so a child can reach this with a parent that has one no longer.
/// Asking a task on its way out what it thinks of `SIGCHLD` is not worth a
/// crash; it is not going to wait either way, and leaving the zombie is the
/// answer that was already correct before this branch existed.
///
/// Under the `pids_lock` both handles borrow.
pub(super) fn parent_will_never_wait(parent: kernel_pids::Task<'_>, leader: kernel_pids::Task<'_>) -> bool {
    if leader.exit_signal() != ffi::SIGCHLD_ as c_int {
        return false;
    }
    let Some(sh) = parent.sighand() else {
        return false;
    };
    let (handler, flags) = sh.handler_and_flags(ffi::SIGCHLD_ as c_int);
    handler == ffi::SIG_IGN_ as u64 || flags & ffi::SA_NOCLDWAIT_ != 0
}

/// The `SIGCHLD` a parent gets, under the `pids_lock` the handles borrow.
pub(super) fn notify_parent(
    parent: kernel_pids::Task<'_>,
    leader: kernel_pids::Task<'_>,
    task: kernel_pids::Task<'_>,
    utime: grouprusage::Timeval,
    stime: grouprusage::Timeval,
) {
    let mut info = ffi::siginfo_::default();
    // The pid is the *process's*, which is the leader's -- `task` is
    // whichever thread of the group happened to exit last, and telling a
    // parent a TID it never forked is not an answer to "which child".
    info.__bindgen_anon_1.child.pid = leader.pid();
    info.__bindgen_anon_1.child.uid = task.creds().uid();
    info.__bindgen_anon_1.child.status = task.exit_code() as i32;
    info.__bindgen_anon_1.child.utime = clock_from_timeval(utime) as i64;
    info.__bindgen_anon_1.child.stime = clock_from_timeval(stime) as i64;
    // Decoded, not the raw wait(2) word. A handler installed with
    // SA_SIGINFO reads si_code and si_status straight out of this, and it
    // used to get SI_KERNEL and 7936 for a child that exited 31. waitid was
    // taught this; the signal was not, and the two are the same question
    // asked from different sides.
    // A Rust call into `crates/kernel/sigqueue`, which owns `SigInfo`.
    // It was an `extern "C"` one into `crates/kernel/waitcalls` under a
    // `keep-c-abi` marker until 2026-09-09 -- reaping calls
    // `tgroup_release` out of *this* crate, so a Rust call that way is a
    // cycle. The decode is a pure function over the 128 bytes, so moving it
    // down to the type both callers share is what removed the edge rather
    // than routing around it.
    kernel_sigqueue::childinfo::decode_in_place(&mut info);
    // The decode says SIGCHLD, which is right for the signal it decodes.
    // clone(2) lets a child ask for a different one on exit, and that is
    // the signal being sent.
    info.sig = leader.exit_signal();
    signaldeliver::send_exit_signal(parent, leader.exit_signal(), info);
}
