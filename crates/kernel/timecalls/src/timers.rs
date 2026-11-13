//! Arming a timer, and delivering what it fires.
//!
//! The tables are elsewhere — the one interval timer a thread group can have is
//! `crates/kernel/itimer`, the POSIX timer table is
//! `crates/kernel/posixtimers`, and the deadline queue behind both is
//! `crates/util/timer`. What is here is the part that needs a **task**: which
//! process a `SIGALRM` goes to, and which thread a `SIGEV_THREAD_ID` timer
//! addresses.
//!
//! # Only `ITIMER_REAL` can be armed
//!
//! `ITIMER_VIRTUAL` and `ITIMER_PROF` count CPU time, and this kernel has no
//! running total to hang a deadline on: user and system time are sampled from
//! the host on demand, not accumulated. Firing them would mean polling the
//! host's rusage on a timer, whose resolution would be the poll interval.
//!
//! So they are `EINVAL` rather than a timer that never fires. A program that
//! asks for a profiling signal and never gets one waits for ever; one that is
//! refused falls back. `getitimer` still answers for them, because a program is
//! entitled to ask whether one is armed and the answer is "no".
//!
//! # The timer is made outside any lock
//!
//! `timer_new` takes the timer service's own lock, and holding the group's
//! across it would be two locks in an order nothing else establishes. So the
//! creation is a compare-exchange: a thread that loses frees the timer it made
//! and uses the winner's. One wasted `timer_new` in a race that happens at most
//! once per process.

use std::ffi::c_int;

use kernel_pids::{PidsGuard, TaskRef};
use kernel_posixtimers::{Notification, Timers};

use crate::ffi;

use guest_errno::c_int_::EINVAL;

/// `TIMER_NONE` in `util/timer.h`: `((timer_id_t) 0)`. A cast in a `#define`,
/// which bindgen does not emit as a value.
const TIMER_NONE: ffi::timer_id_t = 0;

/// The calling task's thread group, lent for `f`; `None` with no group.
fn group<R>(f: impl FnOnce(&ffi::tgroup) -> R) -> Option<R> {
    taskview::with_current_group(f)
}

/// A zeroed `siginfo_` with a `si_code` set. Everything a timer sends carries
/// `SI_TIMER`.
fn timer_info() -> ffi::siginfo_ {
    ffi::siginfo_ {
        code: ffi::SI_TIMER_,
        ..Default::default()
    }
}

/// What an `ITIMER_REAL` fires: a `SIGALRM` to the **process**.
///
/// # It used to be the thread that armed it, and that was two defects
///
/// The payload was `taskview::current()` as a `usize`, so the signal went to
/// whichever *thread* called `setitimer`. Linux's `it_real_fn` signals
/// `signal->leader_pid` — the process — and the difference is observable: a
/// thread that arms a timer and then exits leaves one that signals nobody here
/// and the process on Linux. `itimer_abi`'s `armed-by-a-thread-that-exits`
/// group is that case, and `differential.sh` reported it as a disagreement
/// before this changed.
///
/// It was also a dangling pointer, in the same window and for the same reason:
/// the arming thread's task is freed when that thread exits, and the expiry
/// dereferenced it.
///
/// # A `TaskRef`, resolved under the lock
///
/// Which is what `crates/kernel/posixtimers` already does — [`notify`] below —
/// and for the reason written there: a bare pid gets reused, and a timer whose
/// thread has gone would signal a stranger once the numbers wrap. That fix
/// landed for POSIX timers on 2026-09-04 and was never applied here.
///
/// The `TaskRef` names the group **leader**, so a `SIGALRM` reaches the process
/// for as long as the process exists, whichever thread armed it.
///
/// Resolving it takes `pids_lock` on the timer service thread, which is safe
/// only because the exit path stopped waiting for a timer under that lock —
/// see `crates/kernel/exitcalls`' `Deferred`. Doing this before that change
/// would have deadlocked the whole guest, which is not a guess:
/// `tests/guest/src/bin/timer_exit_race.rs` is the same cycle through
/// `posixtimers`.
struct Alarm {
    target: TaskRef,
}

impl util_timer::Expire for Alarm {
    fn expired(&self) {
        let pids = PidsGuard::take();
        let Some(leader) = pids.find_by_ref(self.target) else {
            // The process is gone, so there is nobody to signal. Linux's timer
            // goes with the process; this one is freed on the same teardown.
            return;
        };
        signaldeliver::send_process_signal(leader, ffi::SIGALRM_ as c_int, timer_info());
    }
}

/// Is `which` one of the three timers at all?
///
/// Separate from whether it can be armed: 3 is not a timer and never will be,
/// and answering it with a `FIXME` about something unimplemented was noise on
/// every call.
pub fn itimer_which_valid_for_rs(which: c_int) -> bool {
    which == ffi::ITIMER_REAL_ as c_int
        || which == ffi::ITIMER_VIRTUAL_ as c_int
        || which == ffi::ITIMER_PROF_ as c_int
}

/// `setitimer`'s state half. `old` is four `int64_t`: interval sec, interval
/// nsec, value sec, value nsec.
///
/// Four numbers each way rather than a struct, because the guest's `itimerval`
/// and the host's `timespec` pair are different shapes and only one of them is
/// this side's business — and their fields are in the **opposite order**.
pub fn itimer_set_for_rs(
    which: c_int,
    val_sec: i64,
    val_nsec: i64,
    int_sec: i64,
    int_nsec: i64,
    old: &mut [i64; 4],
) -> c_int {
    if !itimer_which_valid_for_rs(which) {
        return EINVAL;
    }
    if which != ffi::ITIMER_REAL_ as c_int {
        // See the module comment. The C printed a FIXME on the `debug` channel
        // here, which is off by default and said nothing the comment does not.
        return EINVAL;
    }

    let installed = group(|g| {
        let timer = &g.itimer;
        let id = timer.get();
        if id != TIMER_NONE {
            return Some(id);
        }
        // No `unsafe` left: reading the calling task was the only unsafe
        // operation in here, and `taskview::current()` is safe now.
        // **No `is_err` on this.** It carried one until 2026-09-14, and
        // `util_timer::timer_new` answers `svc.next_id + 1` under a mutex and
        // has no failure path at all — so the check was testing an encoding
        // its producer cannot produce, which is the shape `construct_task`'s
        // comment records about `fdtable_new`'s `is_null() || is_err()`. The
        // other two callers, `kernel/posixtimers` and `kernel/timerfdcalls`,
        // store the handle without asking.
        // `Alarm` is the timer's, dropped when the timer is freed. An earlier
        // attempt at this had the payload be an object `timecalls` leaked,
        // because `timer_free` is called from `crates/kernel/exitcalls` and
        // there was nowhere to release one; the timer owning its target is what
        // removes that question.
        // The leader, not the caller: see [`Alarm`].
        let target = leader_ref()?;
        let made = util_timer::timer_new(
            libc::CLOCK_REALTIME as c_int,
            std::sync::Arc::new(Alarm { target }),
        );
        let id = timer.install(made);
        if id != made {
            util_timer::timer_free(made);
        }
        Some(id)
    });
    let Some(Some(id)) = installed else {
        return EINVAL;
    };

    let spec = util_timer::Spec {
        interval: util_timer::Timespec {
            sec: int_sec as _,
            nsec: int_nsec as _,
        },
        value: util_timer::Timespec {
            sec: val_sec as _,
            nsec: val_nsec as _,
        },
    };
    let mut old_spec = util_timer::Spec::default();
    let err = util_timer::timer_set(id, spec, Some(&mut old_spec));
    if err < 0 {
        return err;
    }
    *old = [
        old_spec.interval.sec,
        old_spec.interval.nsec,
        old_spec.value.sec,
        old_spec.value.nsec,
    ];
    0
}

/// `getitimer`'s state half. No timer means none has been set, which reports as
/// all zeroes rather than as an error — a program is entitled to ask before it
/// sets one.
pub fn itimer_get_for_rs(which: c_int, out: &mut [i64; 4]) -> c_int {
    let mut spec = util_timer::Spec::default();
    let Some(id) = group(|g| g.itimer.get()) else {
        return EINVAL;
    };
    if which == ffi::ITIMER_REAL_ as c_int && id != TIMER_NONE {
        util_timer::timer_get(id, &mut spec);
    }
    *out = [
        spec.interval.sec,
        spec.interval.nsec,
        spec.value.sec,
        spec.value.nsec,
    ];
    0
}

// -------------------------------------------------------------- POSIX timers

/// This thread group's POSIX timer table, which is `crates/kernel/posixtimers`,
/// lent for `f`. `EINVAL` for a group with none.
///
/// It answered an `Option<&'static Timers>` until 2026-09-30. The table lives
/// as long as the group, which outlives the calling thread and not the
/// process; the closure says so.
pub(crate) fn with_posix_timers<R>(f: impl FnOnce(&Timers) -> R) -> Result<R, guest_errno::Errno> {
    taskview::with_current_group(|g| g.posix_timers.as_deref().map(f))
        .flatten()
        .ok_or(guest_errno::Errno::EINVAL)
}

/// Who a `SIGEV_SIGNAL` timer addresses: the process, through its group leader.
///
/// This used to be 0, and the callback looks the pid up — so every
/// `SIGEV_SIGNAL` timer, which is the default and what
/// `timer_create(clock, NULL, &id)` asks for, was created, armed, counted down,
/// and delivered nothing.
pub(crate) fn leader_ref() -> Option<TaskRef> {
    let pids = PidsGuard::take();
    let pid = pids.me()?.group()?.leader_pid();
    pids.refer(pid)
}

/// The thread a `SIGEV_THREAD_ID` timer addresses, or `None` for a pid that
/// is nobody's.
///
/// The lock is taken and released here. The version this replaces returned with
/// it **held** when the thread did not exist, so the next thing to want it —
/// fork, exit, wait, kill — waited for ever.
pub(crate) fn thread_ref(pid: c_int) -> Option<TaskRef> {
    PidsGuard::take().refer(pid)
}

/// Delivery: the one thing the table cannot do, because it needs a task.
///
/// The target is a [`TaskRef`] and is resolved under the registry's lock, so
/// a thread that has exited gets nothing -- and so does whichever task has
/// since been handed its number. This stored the bare pid until 2026-09-04,
/// under a TODO saying that pids get reused; a `SIGEV_THREAD_ID` timer whose
/// thread had gone signalled a stranger once the numbers wrapped. Linux's
/// `it_pid` is a `struct pid` for the same reason.
///
/// Two of them, because the target is either a thread or the process: a
/// `SIGEV_THREAD_ID` timer's signal waits on its thread, any other's in the
/// process's shared set (`sigshared_probe`), as Linux's `send_sigqueue`
/// takes a `PIDTYPE_PID` or a `PIDTYPE_TGID`.
pub(crate) fn notify_thread(n: &Notification) {
    let pids = PidsGuard::take();
    if let Some(thread) = pids.find_by_ref(n.target) {
        signaldeliver::send_signal(signaldeliver::Target::Task(thread), n.signal, notification_info(n));
    }
}

/// [`notify_thread`]'s other half: the target is the process's leader.
pub(crate) fn notify_process(n: &Notification) {
    let pids = PidsGuard::take();
    if let Some(leader) = pids.find_by_ref(n.target) {
        signaldeliver::send_process_signal(leader, n.signal, notification_info(n));
    }
}

fn notification_info(n: &Notification) -> ffi::siginfo_ {
    let mut info = timer_info();
    // The union member is chosen by the SI_TIMER code beside it.
    info.__bindgen_anon_1.timer.timer = n.timer_id;
    info.__bindgen_anon_1.timer.overrun = n.overrun;
    info.__bindgen_anon_1.timer.value.sv_ptr = n.sig_value;
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_timers_are_the_three_and_nothing_else() {
        // `which` of 3 is not a timer and never will be. An unknown one is
        // EINVAL, which is how a program tells "not implemented" from
        // "implemented and refused".
        assert!(itimer_which_valid_for_rs(ffi::ITIMER_REAL_ as c_int));
        assert!(itimer_which_valid_for_rs(ffi::ITIMER_VIRTUAL_ as c_int));
        assert!(itimer_which_valid_for_rs(ffi::ITIMER_PROF_ as c_int));
        assert!(!itimer_which_valid_for_rs(3));
        assert!(!itimer_which_valid_for_rs(-1));
        assert!(!itimer_which_valid_for_rs(i32::MAX));
    }

    // `a_timer_id_that_is_an_errno_is_recognised` was here until 2026-09-14.
    // Its comment said "timer_new answers ERR_PTR"; it does not, and never
    // did in Rust -- `util_timer::timer_new` hands back an id from a counter
    // and cannot fail. The test passed because it called the predicate
    // directly with an errno it had made itself, which is a test of the
    // predicate and not of the caller.
}
