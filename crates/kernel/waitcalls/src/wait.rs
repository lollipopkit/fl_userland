//! The wait loop: finding a child that has something to report, and reaping it.
//!
//! `sys_wait4` and `sys_waitid` in the parent module are the ABI on either side
//! of this — which `idtype` a pid means, the status decoding, the guest copies.
//! This is the part that walks the process tree.
//!
//! # `pids_lock` is held across the lookup *and* the use
//!
//! Tasks are not refcounted, so a task found through the tree can exit and be
//! freed the moment the lock is dropped. [`PidsGuard`] is a guard, and everything
//! below borrows from it. The wait itself releases and retakes the lock, which
//! is what [`task_wait_child_exit`] does through `wait_for`.
//!
//! # Whose children
//!
//! `wait()` with no pid is defined over the whole **thread group**, and a
//! process's children belong to the thread that forked them. The C walked
//! `current->children` once per thread in the group — the same list N times, and
//! never anyone else's — so a worker thread that forks and a main thread that
//! reaps got `ECHILD` for a child that was right there. That is every thread
//! pool spawning subprocesses and every `posix_spawn` off the main thread; it
//! only ever worked because a thread exiting reparents its children to another
//! thread of the group, so the defect was invisible whenever the forking thread
//! had already gone.
//!
//! `__WNOTHREAD` narrows it back to the caller's own children, and does so by
//! *skipping* the other threads rather than stopping after the first: the
//! group's thread list starts wherever insertion left it, so "the first" is not
//! reliably `current`.
//!
//! # The poll tick is a backstop, and it hides things
//!
//! The wait ends when something notifies `child_exit`, which every event a wait
//! can report does. The timeout on top of it replaced a comment saying it was
//! "to work around macOS condvar issues", which has not been tested either way.
//! It is worth knowing what a backstop costs: a continue was not notified at
//! all, in any revision, and the only symptom was that `waitpid(WCONTINUED)`
//! took a poll tick — 704 ms where a real kernel answers in microseconds, and
//! nothing here tests latency. `IUL_WAIT_POLL=0` removes it so that class of
//! defect is a hang instead, which is what the guest suite is run with as a
//! second pass.

use std::ffi::c_int;

use crate::{SIGINFO_SIZE, offset, set_i32};

pub use guest_errno::c_int_::{ECHILD, EINTR, EINVAL};

/// The wait options. They were `#define`s in `kernel/exit.c` and nowhere else.
pub mod opt {
    use std::ffi::c_int;
    pub const NOHANG: c_int = 1 << 0;
    pub const UNTRACED: c_int = 1 << 1;
    pub const EXITED: c_int = 1 << 2;
    pub const CONTINUED: c_int = 1 << 3;
    pub const NOWAIT: c_int = 1 << 24;
    /// The caller's own children rather than the thread group's.
    pub const NOTHREAD: c_int = 1 << 29;
    /// Both kinds of child, where without it the caller wants exactly one.
    pub const ALL: c_int = 1 << 30;
    pub const CLONE: c_int = 1 << 31;

    pub const KNOWN: c_int =
        NOHANG | UNTRACED | EXITED | CONTINUED | NOWAIT | NOTHREAD | ALL | CLONE;
    /// At least one of these has to be asked for; see [`super::do_wait`].
    pub const ANY_STATE: c_int = UNTRACED | EXITED | CONTINUED;
}
const P_ALL: c_int = 0;
const P_PID: c_int = 1;
const P_PGID: c_int = 2;

const SIGCHLD: i32 = 17;
const CLD_TRAPPED: i32 = 4;

/// `struct timeval_` is `crates/kernel/grouprusage`'s.
///
/// This file had its own -- the sixth `#[repr(C)] { sec: i64, usec: i64 }` in
/// the tree -- and handed it to the typed `GroupRusage` methods.
use grouprusage::Timeval;
use kernel_pids::{Group, PidsGuard, PidsHeld, Task};

/// `struct rusage_` is 144 bytes and only its two leading timevals are filled.
const RUSAGE_UTIME: usize = 0;
const RUSAGE_STIME: usize = 16;

/// `IUL_EXEC_TRACE`. A `static inline` over this field in `misc.h`, which
/// bindgen does not emit.
fn exec_trace() -> bool {
    util_iulenv::env().exec_trace
}

/// `IUL_WAIT_POLL`, in milliseconds. 0 means wait indefinitely.
fn wait_poll_ms() -> c_int {
    util_iulenv::env().wait_poll_ms
}

/* `now_ns` was defined here until 2026-09-15 — one of five private copies,
 * all asking `CLOCK_MONOTONIC` and answering `u64` nanoseconds. It is
 * `util_timeabi::monotonic_ns` now, which saturates where three of the five
 * multiplied plainly. */
use util_timeabi::monotonic_ns as now_ns;

/// What a wait found, written into the caller's `siginfo_` and `rusage_`.
struct Out<'a> {
    info: &'a mut [u8; SIGINFO_SIZE],
    rusage: Option<&'a mut [u8]>,
}

impl Out<'_> {
    fn set_child(&mut self, at: usize, v: i32) {
        set_i32(self.info, at, v);
    }
}

fn put_timeval(buf: &mut [u8], at: usize, v: Timeval) {
    buf[at..at + 8].copy_from_slice(&v.sec.to_le_bytes());
    buf[at + 8..at + 16].copy_from_slice(&v.usec.to_le_bytes());
}

/// Reaps `task` if it is a zombie, answering whether it was.
///
/// `WNOWAIT` looks without taking: the child is left so it can be waited for
/// again, and its times are **not** added to this process's children total.
///
/// `task` is a group leader (`reap_if_needed` asserts it), so a zombie one is
/// a group with no live threads -- a leader stays until its last thread has
/// gone -- which is the contract of the two calls that free it.
fn reap_if_zombie(
    pids: &PidsHeld,
    deferred: &exitcalls::Deferred,
    task: Task<'_>,
    out: &mut Out,
    options: c_int,
) -> bool {
    if !task.is_zombie() {
        return false;
    }
    let Some(group) = task.group() else {
        return false;
    };
    let exit_code = group.exit_pending().unwrap_or(task.exit_code()) as i32;
    out.set_child(offset::CHILD_STATUS, exit_code);

    let total = group.times().own();
    let (utime, stime) = (total.utime(), total.stime());
    if options & opt::NOWAIT == 0
        && let Some(mine) = Group::current(pids)
    {
        mine.times().add_children(utime, stime);
    }
    if let Some(r) = out.rusage.as_deref_mut() {
        put_timeval(r, RUSAGE_UTIME, utime);
        put_timeval(r, RUSAGE_STIME, stime);
    }
    // **`si_utime` and `si_stime` are not filled here**, and the belief that
    // they were -- "waitid has no rusage argument and reports these in the
    // siginfo instead" -- was wrong about Linux. `kernel_waitid` builds a
    // `waitid_info` of five fields (signo, errno, code, pid, uid, status) and
    // `copy_siginfo_to_user` writes that; a container run reads zero at offsets
    // 32 and 40 for a child that burned 1.7 seconds. The SIGCHLD *signal* is
    // the path that does carry them, and `notify_parent` still fills it.

    if options & opt::NOWAIT != 0 {
        return true;
    }

    if exec_trace() {
        let comm = task.comm();
        let msg = format!(
            "REAP[reaper={}]: pid={} exit={:#x} comm={comm}",
            taskview::current_pid(),
            task.pid(),
            exit_code as u32
        );
        logline::printk(&msg);
    }

    // SAFETY: a zombie leader, so its group has no live threads; see above.
    // `task` is not used after this.
    unsafe {
        exitcalls::tgroup_release(pids, task.raw(), deferred);
        taskcalls::task_destroy(pids, task.raw());
    }
    true
}

/// A group stop, if there is one to report.
///
/// One call, because the flag and the status are one answer: reading the flag,
/// dropping a lock and then taking the status lets a `SIGCONT` land in between,
/// so a waiter reports a stop for a child that has since been continued.
fn notify_if_stopped(group: Group<'_>, out: &mut Out, options: c_int) -> bool {
    let Some(status) = group.stop().read_stop(options & opt::NOWAIT != 0) else {
        return false;
    };
    out.set_child(offset::CHILD_STATUS, status as i32);
    true
}

/// A group that was stopped and has since been continued. Consumed by the wait
/// that reports it, as a stop is.
fn notify_if_continued(group: Group<'_>, out: &mut Out, options: c_int) -> bool {
    if !group.stop().take_continued(options & opt::NOWAIT != 0) {
        return false;
    }
    // Linux reports SIGCONT as the status and CLD_CONTINUED as the code; 0xffff
    // is the encoding the `waitid` path decodes below.
    out.set_child(offset::CHILD_STATUS, 0xffff);
    true
}

/// Whether this child has anything to report, and if so what.
fn reap_if_needed(
    pids: &PidsHeld,
    deferred: &exitcalls::Deferred,
    task: Task<'_>,
    mine: Group<'_>,
    out: &mut Out,
    options: c_int,
) -> bool {
    debug_assert!(task.leads_group());
    let Some(group) = task.group() else {
        return false;
    };
    // Traced by another process: its ptrace stops are the tracer's to
    // report, and so is its exit until the tracer has waited for it
    // (`exitcalls::ptrace_release_zombie`) -- Linux's `wait_consider_task`
    // for a real parent that is not the tracer. A group stop is still the
    // parent's to see.
    let traced_elsewhere = task.tracer().is_some_and(|t| !in_group(t, mine));
    if (options & opt::UNTRACED != 0 && notify_if_stopped(group, out, options))
        || (options & opt::CONTINUED != 0 && notify_if_continued(group, out, options))
        || (!traced_elsewhere && options & opt::EXITED != 0 && reap_if_zombie(pids, deferred, task, out, options))
    {
        out.set_child(offset::SIG, SIGCHLD);
        return true;
    }
    !traced_elsewhere && report_ptrace_stop(task, out, options)
}

/// A ptrace stop of `task`, for its tracer.
fn report_ptrace_stop(task: Task<'_>, out: &mut Out, options: c_int) -> bool {
    // `WUNTRACED` gates an *ordinary* group stop. A ptrace stop is reported to
    // the tracer whether or not it asked -- Linux's `wait_task_stopped`
    // consults the flag only when the waiter is not the tracer. Requiring the
    // flag made `waitpid(pid, &st, 0)` on a stopped tracee block for ever,
    // which is the call gdb and strace make.
    //
    // The read, the test and the take are one operation under the ptrace lock.
    // 0 means nothing to report.
    let nowait = options & opt::NOWAIT != 0;
    let Some(status) = task.ptrace().and_then(|p| p.take_stop_report(nowait)) else {
        return false;
    };
    out.set_child(offset::CHILD_STATUS, status as i32);
    // A ptrace stop and an ordinary group stop pack into the same status word,
    // and only this branch knows which one this is. `waitid` reports them
    // differently -- CLD_TRAPPED against CLD_STOPPED -- so say so here, while
    // the tracee is still around to ask. `wait4` ignores si_code.
    out.set_child(offset::CODE, CLD_TRAPPED);
    true
}

/// Whether `task` is a thread of `group`.
fn in_group(task: Task<'_>, group: Group<'_>) -> bool {
    task.group().is_some_and(|g| g.id() == group.id())
}

/// What a task this process traces and did not fork has to report: a ptrace
/// stop, or -- a leader whose whole group has exited -- its exit, after
/// which it is its real parent's (`exitcalls::ptrace_release_zombie`).
/// Linux's `wait_consider_task(ptrace = 1)`: no `__WCLONE` or `__WALL`
/// question is asked of a tracee, and a thread is one.
fn report_tracee(
    pids: &PidsHeld,
    deferred: &exitcalls::Deferred,
    task: Task<'_>,
    out: &mut Out,
    options: c_int,
) -> bool {
    if !task.is_zombie() {
        return report_ptrace_stop(task, out, options);
    }
    if options & opt::EXITED == 0 {
        return false;
    }
    let Some(group) = task.group() else {
        return false;
    };
    out.set_child(offset::CHILD_STATUS, group.exit_pending().unwrap_or(task.exit_code()) as i32);
    out.set_child(offset::SIG, SIGCHLD);
    if options & opt::NOWAIT == 0 {
        proctree::detach(task.raw());
        exitcalls::ptrace_release_zombie(pids, deferred, task);
    }
    true
}

/// A traced thread's exit that `tracer` holds (`proctree::push_report`), if
/// `want` accepts one. Taking it gives the tid back to the allocator.
fn report_thread_exit(
    pids: &PidsHeld,
    tracer: Task<'_>,
    want: impl Fn(&proctree::ExitReport) -> bool,
    out: &mut Out,
    options: c_int,
) -> bool {
    if options & opt::EXITED == 0 {
        return false;
    }
    let nowait = options & opt::NOWAIT != 0;
    let Some(report) = proctree::take_report(tracer.raw(), want, nowait) else {
        return false;
    };
    out.set_child(offset::CHILD_PID, report.tid);
    out.set_child(offset::CHILD_UID, report.uid as i32);
    out.set_child(offset::CHILD_STATUS, report.status as i32);
    out.set_child(offset::SIG, SIGCHLD);
    if !nowait {
        kernel_pids::set_task(pids, report.tid, std::ptr::null_mut());
    }
    true
}

/// Whether `child` is one this call is allowed to answer about. `mine` is the
/// waiting thread's group.
fn eligible(child: Task<'_>, mine: Group<'_>, idtype: c_int, id: c_int, options: c_int) -> bool {
    if !child.leads_group() {
        return false;
    }
    let Some(group) = child.group() else {
        return false;
    };
    if idtype == P_PGID {
        // id 0 is the caller's own process group, which is what `sys_wait4`
        // already maps its zero argument to.
        let want = if id == 0 { mine.pgid() } else { id };
        if group.pgid() != want {
            return false;
        }
    }
    // Linux's `eligible_child`: __WALL takes both kinds, and without it the
    // caller wants exactly one of them.
    if options & opt::ALL == 0 {
        let is_clone = child.exit_signal() != SIGCHLD;
        if is_clone != (options & opt::CLONE != 0) {
            return false;
        }
    }
    true
}

/// The wait. 0 with `info` filled, or a negative guest errno.
///
/// Safe since 2026-10-01: its contract was "called on a guest thread", and a
/// thread with no group answers `ECHILD` from the first lookup; the buffer
/// sizes it also stated are the parameter types.
pub fn do_wait(
    idtype: c_int,
    id: c_int,
    info: &mut [u8; SIGINFO_SIZE],
    rusage: Option<&mut [u8]>,
    options: c_int,
) -> c_int {
    if idtype != P_ALL && idtype != P_PID && idtype != P_PGID {
        return EINVAL;
    }
    if options & !opt::KNOWN != 0 {
        return EINVAL;
    }
    // Unknown bits were rejected and the absence of every known one was not, so
    // `waitid(P_PID, child, &si, 0)` fell into the blocking loop. `sys_wait4`
    // always adds WEXITED, so this only ever fires for `waitid`.
    if options & opt::ANY_STATE == 0 {
        return EINVAL;
    }

    // **Declared before the guard, so it is dropped after it** -- on every
    // path out of this function, including the several early returns below.
    // `exitcalls::Deferred` holds teardown that waits, and waiting under
    // `pids_lock` is the deadlock its own comment records; its `Drop` asserts
    // the order rather than trusting this comment.
    let deferred = exitcalls::Deferred::new();
    let pids = PidsGuard::take();
    let me = taskview::current();
    let mut out = Out { info, rusage };
    let mut got_signal = false;

    loop {
        // The caller's own group, which lives as long as the caller does.
        let Some(mine) = Group::current(pids.held()) else {
            return ECHILD;
        };
        if idtype != P_PID {
            let mut no_children = true;
            for parent in mine.threads() {
                if options & opt::NOTHREAD != 0 && parent.raw() != me {
                    continue;
                }
                for child in parent.children() {
                    if !eligible(child, mine, idtype, id, options) {
                        continue;
                    }
                    no_children = false;
                    // Read *before* reap_if_needed: reaping runs task_destroy,
                    // which memsets the task.
                    out.set_child(offset::CHILD_PID, child.pid());
                    out.set_child(offset::CHILD_UID, child.uid() as i32);
                    if reap_if_needed(pids.held(), &deferred, child, mine, &mut out, options) {
                        return 0;
                    }
                }
                // Linux's second walk, over `ptraced`. A tracee this process
                // forked was asked about above.
                let want_pgid = (idtype == P_PGID).then(|| if id == 0 { mine.pgid() } else { id });
                for tracee in parent.tracees() {
                    let is_child = tracee.parent().is_some_and(|p| in_group(p, mine));
                    if is_child && eligible(tracee, mine, idtype, id, options) {
                        continue;
                    }
                    if want_pgid.is_some_and(|pgid| tracee.group().is_none_or(|g| g.pgid() != pgid)) {
                        continue;
                    }
                    no_children = false;
                    out.set_child(offset::CHILD_PID, tracee.pid());
                    out.set_child(offset::CHILD_UID, tracee.uid() as i32);
                    if report_tracee(pids.held(), &deferred, tracee, &mut out, options) {
                        return 0;
                    }
                }
                if proctree::has_reports(parent.raw()) {
                    no_children = false;
                    let wanted = |r: &proctree::ExitReport| want_pgid.is_none_or(|pgid| r.pgid == pgid);
                    if report_thread_exit(pids.held(), parent, wanted, &mut out, options) {
                        return 0;
                    }
                }
            }
            if no_children {
                return ECHILD;
            }
        } else {
            // __WNOTHREAD narrows "a child of this process" to "a child of this
            // thread"; without it any thread of the group may name it. The
            // same for a tracer.
            let ours = |t: Task<'_>| if options & opt::NOTHREAD != 0 { t.raw() == me } else { in_group(t, mine) };
            let task = taskcalls::pid_get_task_zombie(pids.held(), id as u32);
            // SAFETY: found in the registry under `pids_lock`.
            let Some(task) = (unsafe { Task::from_raw(pids.held(), task) }) else {
                // A traced thread that has exited is a report, not a task;
                // there is nothing to wait *for* once it is not one either.
                for t in mine.threads().filter(|&t| ours(t)) {
                    if report_thread_exit(pids.held(), t, |r| r.tid == id, &mut out, options) {
                        return 0;
                    }
                }
                return ECHILD;
            };
            let parent_ours = task.parent().is_some_and(ours);
            if task.tracer().is_some_and(ours) && !(parent_ours && task.leads_group()) {
                // This process's tracee, thread or not, and not its child.
                out.set_child(offset::CHILD_PID, id);
                out.set_child(offset::CHILD_UID, task.uid() as i32);
                if report_tracee(pids.held(), &deferred, task, &mut out, options) {
                    return 0;
                }
            } else {
                if !parent_ours {
                    return ECHILD;
                }
                // SAFETY: a group's leader is live under `pids_lock`.
                let Some(leader) = task.group().and_then(|g| unsafe { Task::from_raw(pids.held(), g.leader()) }) else {
                    return ECHILD;
                };
                out.set_child(offset::CHILD_PID, id);
                out.set_child(offset::CHILD_UID, leader.uid() as i32);
                if reap_if_needed(pids.held(), &deferred, leader, mine, &mut out, options) {
                    return 0;
                }
            }
        }

        // `WNOHANG` leaves the info in an implementation-defined state. The pid
        // is set to 0 so `wait4` can pass that along, and the uid with it so a
        // "no child ready" result does not report the uid of a candidate that
        // was scanned.
        out.set_child(offset::CHILD_PID, 0);
        out.set_child(offset::CHILD_UID, 0);
        if options & opt::NOHANG != 0 {
            out.set_child(offset::SIG, SIGCHLD);
            return 0;
        }

        if got_signal {
            return EINTR;
        }

        // No matching child. Wait for one; see the module comment on the tick.
        taskview::set_blocking(true);
        // Only a real signal may set `got_signal`: treating _ETIMEDOUT as one
        // made every wait for a child that ran longer than the tick fail with
        // EINTR, which broke gcc (cc1 easily exceeds a second under emulation)
        // and every other fork-and-wait caller.
        let wait_err = task_wait_child_exit(pids.held(), mine, wait_poll_ms());
        taskview::set_blocking(false);
        if wait_err == EINTR {
            got_signal = true;
        }
        // `waitpid` is actively polling for a child; this is real work rather
        // than a stuck thread, and saying so is what keeps the poll_wait safety
        // valve from killing a parent waiting for a long-running child.
        mine.note_progress(now_ns());
    }
}

/// Park on this thread group's `child_exit` with `pids_lock` held, releasing it
/// while parked and taking it back before returning.
///
/// `kernel/task.c`'s until 2026-09-03, and what made it movable is that
/// `wait_for` is `crates/util/waitfor`'s: the timeout arithmetic is the only
/// content, and it was the one thing here nothing could test.
///
/// `poll_ms` of zero or less waits without a deadline. That is not a rounding
/// of "very soon": the caller passes `IUL_WAIT_POLL`, whose default is 1000 and
/// whose *0* means "never rescan" — a wait with nothing to recheck.
///
/// Safe since 2026-10-01: "`pids_lock` is held and `group` is live" is what
/// a `&PidsHeld` and a `Group` handle say.
pub fn task_wait_child_exit(pids: &kernel_pids::PidsHeld, group: Group<'_>, poll_ms: c_int) -> c_int {
    let timeout = libc::timespec {
        tv_sec: (poll_ms / 1000) as _,
        tv_nsec: ((poll_ms % 1000) as i64 * 1_000_000) as _,
    };
    let t = (poll_ms > 0).then_some(&timeout);
    waitfor::wait_for(&group.tgroup().child_exit, pids, t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_known_options_are_the_ones_that_are_handled() {
        // A bit outside this set is EINVAL, which is how a program tells "not
        // implemented" from "implemented and refused". The set was a list of
        // #defines in kernel/exit.c and nowhere else.
        assert_eq!(
            opt::KNOWN,
            0b1110_0001_0000_0000_0000_0000_0000_1111u32 as c_int
        );
        assert_eq!(opt::ANY_STATE, opt::UNTRACED | opt::EXITED | opt::CONTINUED);
        assert_eq!(opt::NOWAIT, 1 << 24);
    }

    #[test]
    fn a_timeval_is_two_eight_byte_words() {
        // `struct timeval_` is the guest's, not the host's: 64-bit on both
        // fields whatever the host does with suseconds_t.
        assert_eq!(size_of::<Timeval>(), 16);
        assert_eq!(std::mem::offset_of!(Timeval, usec), 8);
        // And the two the rusage carries are at its front, in this order.
        assert_eq!(RUSAGE_UTIME, 0);
        assert_eq!(RUSAGE_STIME, 16);
    }

    #[test]
    fn writing_a_timeval_is_little_endian_like_the_guest() {
        let mut buf = [0u8; 32];
        put_timeval(&mut buf, RUSAGE_STIME, Timeval { sec: 1, usec: 2 });
        assert_eq!(&buf[0..16], &[0u8; 16], "the utime slot is untouched");
        assert_eq!(buf[16], 1);
        assert_eq!(buf[24], 2);
    }
}
