//! Select a signal target and route process and group directed signals.

use super::*;

// ---------------------------------------------------------------------------
// Choosing which task, and which thread of it
// ---------------------------------------------------------------------------

/// Can this thread take a signal right now?
///
/// A reduced form of Linux's `wants_signal()`. The queue's `waiting` set is
/// `sigtimedwait`'s: a thread blocked in `sigwait` for a signal takes it even
/// though it is blocked, which is the whole point of `sigwait`.
///
/// Linux also passes over a thread that is not running and already has a
/// signal to act on; whether one is running is the host's to know, so that
/// half is not asked.
fn thread_wants_signal(task: kernel_pids::Task<'_>, sig: c_int) -> bool {
    if task.is_zombie() || task.is_exiting() {
        return false;
    }
    if task.sighand().is_none() {
        return false;
    }
    if !blockable(sig) {
        return true;
    }
    // SAFETY: the queue's `blocked` is read without sighand's lock for the
    // reason `signal_thread` gives.
    unsafe { (*task.task().signals.get()).wants(sig) }
}

/// Which thread of a process is told about a process-directed signal: Linux's
/// `complete_signal`. The task the sender named if it can take it, then any
/// other that can, and `None` when none can -- the signal then waits in the
/// shared set for a thread to unblock it, `sigwait` for it or read it from a
/// `signalfd`.
///
/// **Not the sender first.** This preferred the calling thread until
/// 2026-11-12, so a thread's `kill(getpid())` ran the handler on that thread
/// where Linux runs it on the leader (`sigshared_probe`); `raise` and `abort`
/// are `tgkill`, which names its thread.
///
/// `pids_lock` is held by every caller, which is what the thread list is locked
/// by. `blocked` is read without sighand's lock: a thread that blocks the
/// signal between this choice and the delivery leaves it in the shared set,
/// where a thread that unblocks it later finds it.
fn signal_thread<'a>(
    named: kernel_pids::Task<'a>,
    sig: c_int,
) -> Option<kernel_pids::Task<'a>> {
    if thread_wants_signal(named, sig) {
        return Some(named);
    }
    named
        .group()
        .into_iter()
        .flat_map(kernel_pids::Group::threads)
        .find(|&t| thread_wants_signal(t, sig))
}

/// Linux's `retarget_shared_pending`: the calling thread will not take the
/// process-directed signals in `which` -- it has blocked them, or it is
/// exiting -- so each goes to another thread of the process that can take it,
/// as [`signal_thread`] would have chosen had this one not been able to.
pub fn retarget_shared(mut which: u64) {
    let pids = kernel_pids::PidsGuard::take();
    let Some(me) = pids.me() else {
        return;
    };
    let Some(group) = me.group() else {
        return;
    };
    for t in group.threads() {
        if which == 0 {
            break;
        }
        if t.raw() == me.raw() || t.is_zombie() || t.is_exiting() {
            continue;
        }
        // Without sighand's lock, as `thread_wants_signal` reads it.
        // SAFETY: as there.
        let blocked = unsafe { (*t.task().signals.get()).blocked() };
        let takes = which & !blocked;
        if takes == 0 {
            continue;
        }
        which &= blocked;
        let to = Target::Task(t);
        let sig = takes.trailing_zeros() as c_int + 1;
        if to.with_queue(|queue| queue.choose(sig, true)) == Some(true) {
            to.wake();
        }
        to.poke();
    }
}

/// [`retarget_shared`] for a thread on its way out: what it could have taken
/// of its process's set is another thread's to take now.
pub fn retarget_on_exit() {
    let which = taskview::with_current_queue(|queue| {
        let guard = queue.lock();
        guard.shared().mask() & !guard.queue().blocked()
    })
    .unwrap_or(0);
    if which != 0 {
        retarget_shared(which);
    }
}

/// A process-directed signal: `kill(2)` and the group and session forms of
/// it, `sigqueue`, `pidfd_send_signal`, a timer, `SIGCHLD`, a terminal's.
///
/// It goes into the process's shared set, judged against the disposition and
/// mask of `named` -- the task the sender found, as Linux's `sig_ignored`
/// judges it -- and the thread [`signal_thread`] picks is woken to take it.
/// It used to be queued on that thread instead, so a signal every thread
/// blocked stayed on the leader for good when another thread unblocked it,
/// and `ShdPnd` was always zero.
///
/// `named` is a handle the registry answered under `pids_lock`, and its
/// lifetime is that hold: there is no pointer left that could have come from
/// anywhere else, and no separate proof of the lock to pass.
pub fn send_process_signal(
    named: kernel_pids::Task<'_>,
    sig: c_int,
    info: SigInfo,
) {
    // A leader that has exited ahead of its threads is still the process: the
    // signal is the process's, and it is judged by a thread that is there.
    let alive = |t: kernel_pids::Task<'_>| !t.is_zombie() && !t.is_exiting();
    let named = if alive(named) {
        named
    } else {
        match named.group().into_iter().flat_map(kernel_pids::Group::threads).find(|&t| alive(t)) {
            Some(t) => t,
            None => return,
        }
    };
    let to = Target::Task(named);
    if !about_to_queue(to, sig) {
        return;
    }
    let blockable = blockable(sig);
    let recipient = to.recipient(sig);
    let queued = to.with_queue(|queue| queue.send_shared(sig, info, blockable, recipient)) == Some(true);
    if queued {
        // Linux's `complete_signal`: the thread chosen decides whether the
        // signal is fatal to the whole process, and if it is the process goes
        // now, whatever that thread is doing -- parked, being ended by an
        // exec, or never scheduled again.
        if let Some(chosen) = signal_thread(named, sig) {
            let chosen = Target::Task(chosen);
            let arrival = chosen
                .with_queue(|queue| queue.chosen(sig, blockable, recipient, || chosen.start_exit(sig)))
                .unwrap_or_default();
            if arrival.ends_group {
                end_group(chosen);
            } else {
                if arrival.wake {
                    chosen.wake();
                }
                chosen.poke();
            }
        }
        // Every signalfd watching it is readable now, whichever thread reads.
        signalfdcalls::signalfd_notify(sig);
    }
    after_queueing(to, sig);
}

/// Is this process group orphaned?
///
/// POSIX: a process group is orphaned when no member has a parent in a
/// *different* process group of the *same* session. Such a parent is someone
/// who could still `SIGCONT` the group, which is the whole question.
///
/// It matters because stopping an orphaned group is a hang by construction:
/// `SIGTTIN` stops it and there is nobody left who would ever continue it,
/// which is why Linux's `tty_check_change` answers `EIO` instead of signalling.
/// There was no notion of an orphan here at all, so a background job whose
/// shell had gone stopped for good on its first read from the terminal.
///
/// The rule and its three exceptions are `crates/kernel/proctree`, where they
/// have a test each. What is here is the walk, which needs `pids_lock` and the
/// registry. An empty group is orphaned, which is what a `^C` aimed at a
/// foreground group that has already exited asks.
///
/// The `&PidsHeld` was a `/// # Safety: pids_lock is held` clause until
/// 2026-09-15 — see `crates/kernel/pids`' module comment.
pub fn pgrp_is_orphaned(pids: &kernel_pids::PidsHeld, pgid: c_int) -> bool {
    let mut i = 0;
    while let Some(tgroup) = kernel_pids::pgroup_at(pids, pgid, i) {
        i += 1;
        let Some(leader) = tgroup.leader_task() else {
            continue;
        };
        // A parent counts only while it is still in a group.
        let parent = leader.parent().and_then(|p| Some((p.pid(), p.group()?)));
        let m = proctree::Member {
            sid: tgroup.sid(),
            leader_alive: !leader.is_zombie() && !leader.is_exiting(),
            has_parent: parent.is_some(),
            parent_pid: parent.map_or(0, |(pid, _)| pid),
            parent_pgid: parent.map_or(0, |(_, g)| g.pgid()),
            parent_sid: parent.map_or(0, |(_, g)| g.sid()),
        };
        if proctree::member_keeps_group_alive(&m, pgid) {
            return false;
        }
    }
    true
}

/// Every process in a process group.
///
/// `pids_lock` is the **caller's**, which is what `_locked` means, and it stays
/// the caller's: this used to release it on the empty-group path. Two callers,
/// and both were broken by it — [`send_group_signal`] locks and releases either
/// side, so an empty group was a double release; and `crates/fs/tty` calls this
/// with `pids_lock` held for a whole terminal ioctl, so a `^C` whose foreground
/// process group had already exited — the ordinary state between a job
/// finishing and the shell reclaiming the terminal — released the lock
/// underneath the ioctl and the ioctl released it again on the way out.
///
/// The `&PidsHeld` was a `/// # Safety: pids_lock is held` clause until
/// 2026-09-15, and the `unsafe` stayed behind it for two weeks with no
/// section saying what else it asked: nothing, since the one pointer it reads
/// comes from the registry under the lock the argument proves.
pub fn send_group_signal_locked(
    pids: &kernel_pids::PidsHeld,
    pgid: u32,
    sig: c_int,
    info: SigInfo,
) -> c_int {
    if kernel_pids::pidreg_pgroup_len(pids, pgid as c_int) == 0 {
        return ESRCH;
    }
    let mut i = 0;
    while let Some(tgroup) = kernel_pids::pgroup_at(pids, pgid as c_int, i) {
        i += 1;
        if let Some(leader) = tgroup.leader_task() {
            send_process_signal(leader, sig, info);
        }
    }
    0
}

pub fn send_group_signal(pgid: u32, sig: c_int, info: SigInfo) -> c_int {
    let pids = kernel_pids::PidsGuard::take();
    // The `// SAFETY:` that stood here said "`PidsGuard` holds `pids_lock` for
    // the duration of the locked implementation, including every group member
    // lookup and delivery". That is what `pids.held()` passes now.
    send_group_signal_locked(pids.held(), pgid, sig, info)
}

/// Delivering to one task, for `crates/kernel/signalcalls`.
///
/// The split is **which tasks** against **how to deliver**: choosing them is
/// that crate — `kill(0)` means this group, `kill(-1)` means every other
/// leader, `kill(-n)` means group n — and that is where every defect in this
/// family was. Delivery is here because it reaches sighand, the target's queue
/// and the thread choice.
///
/// `given` is a `SigInfo` the caller supplied, or `None` for `kill`'s own.
///
/// `task`'s lifetime is a hold of `pids_lock`, and that is what matters here:
/// the credential read below is what
/// `docs/changelog/2026-09-15-a-permission-check-read-a-credential-set-mid-write.md`
/// is about -- it reads the *target's* whole `Creds` under that lock. It was
/// a `&PidsHeld` beside the handle until 2026-11-12, a second proof of the
/// same hold.
pub fn signal_kill_task_for_rs(
    task: kernel_pids::Task<'_>,
    sig: c_uint,
    thread_directed: bool,
    given: Option<SigInfo>,
) -> c_int {
    // Linux's kill_ok_by_cred, in crates/kernel/creds. It was five conditions
    // spelled the other way round, so a missing negation would have read as one
    // long expression rather than as a permission check.
    //
    // Two `&Creds` where this passed two `*const Creds` to a wrapper that
    // null-checked them and answered `false`. Neither can be null on this
    // path -- `me` is the calling guest task and `task` came from the registry
    // under the lock this function's contract names -- and the check could not
    // have caught a null `me` anyway, since what it was given was the address
    // of a *field* of one.
    let may = taskview::with_current_creds(|mine| mine.may_signal(task.creds())).unwrap_or(false);
    if !may {
        return EPERM;
    }
    let info = given.unwrap_or_else(|| {
        // SI_TKILL for tkill and tgkill, SI_USER for kill. Linux's do_tkill
        // sets one and kill_something_info the other, and a program that wants
        // to know whether a signal came from a *thread*-directed call reads
        // exactly this. It was SI_USER for both.
        //
        // si_pid is the sending **thread group's** id, not the sending
        // thread's: Linux's prepare_kill_siginfo uses task_tgid_vnr(current) on
        // both paths, and a multithreaded sender reported the sending thread's
        // tid.
        // `mut`: the union members below are bindgen's and cannot be named in
        // a struct literal.
        let mut info = ffi::siginfo_ {
            code: if thread_directed {
                ffi::SI_TKILL_ as c_int
            } else {
                ffi::SI_USER_ as c_int
            },
            ..Default::default()
        };
        // Writing a union member is safe; reading one is what is not.
        info.__bindgen_anon_1.kill.pid = taskview::current_tgid();
        info.__bindgen_anon_1.kill.uid = taskview::with_current_creds(|c| c.uid()).unwrap_or(0);
        info
    });
    if thread_directed {
        send_signal(Target::Task(task), sig as c_int, info);
    } else {
        send_process_signal(task, sig as c_int, info);
    }
    0
}

