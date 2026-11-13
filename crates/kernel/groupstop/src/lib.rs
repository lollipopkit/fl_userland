//! Whether a thread group is stopped, what it reports to `wait`, and whether
//! the continue that restarted it has been reported yet.
//!
//! Four fields of `struct tgroup` and a condition variable: `stopped`,
//! `continued`, `continue_pending`, `stopped_cond` — plus the stop status,
//! which was in `crates/kernel/groupexit` because it used to share a word with
//! the exit status. They are one object because **they are one answer**, and
//! the C had to say so in a comment on every reader:
//!
//! > The flag and the status are one answer: reading the flag, dropping the
//! > lock and then taking the status lets a SIGCONT land in between, so a
//! > waiter reports a stop for a child that has since been continued.
//!
//! It was true, and it was enforced by every caller remembering to take
//! `group->lock` around both. Here there is no way to reach one without the
//! other: every operation is a method that takes the lock for its own length.
//!
//! # Three things that are not obvious
//!
//! - **A continue is claimed, not read.** Every thread of a stopped group wakes
//!   from the same condition variable and exactly one of them may tell the
//!   parent. `wait_while_stopped` claims it as it leaves, under the lock that
//!   guards the flag.
//! - **A SIGCONT that overtakes the stop still counts.** The thread that took
//!   the stop signal always reaches the wait; if the group has already been
//!   continued by the time it gets there, the loop does not run and the event
//!   is still its to report. So the claim is outside the loop, not inside it.
//! - **`continued` and `continue_pending` are different things**, read by
//!   different sides. `continued` is consumed by the `wait` that reports it —
//!   the parent asking. `continue_pending` is the other direction: POSIX says a
//!   continued child generates `SIGCHLD` whether or not anyone is waiting, and
//!   a parent already blocked in `wait()` has to be woken rather than left to
//!   `do_wait`'s one-second poll. Neither happened.
//!
//! # Lock order
//!
//! This lock is **innermost** and takes nothing while held. `tools/lock-order.py`
//! reads only C and so cannot see it, which is why the ordering is written here:
//! it is taken under `pids_lock` (the reaping path), under `sighand`'s lock
//! (signal delivery), and under `tgroup->lock` (the group-exit kill loop), and
//! with none of them held (the wait at the end of a syscall). It takes none of
//! them, so there is no cycle in any of those orders.

use util_guestlock::GuestLock;

/// The one condition variable: a group that has been continued.
const CONT: u32 = 0;

#[derive(Debug, Default)]
struct State {
    stopped: bool,
    /// What a stopped group reports to `wait`. 0 means nothing to report —
    /// which is not the same as not being stopped, because an ordinary `wait`
    /// takes the status and leaves the group stopped.
    ///
    /// `SIGNAL_STOP` writes `sig << 8 | 0x7f`.
    stop_status: u32,
    /// A stop that has been continued and not yet reported to a `wait`.
    continued: bool,
    /// The same continue, not yet reported to the *parent* as `SIGCHLD`.
    continue_pending: bool,
    /// The signal that stopped the group, for the `SIGCHLD` the parent gets:
    /// its `si_status`. Kept apart from `stop_status`, which a `wait` consumes
    /// and which the notification may be sent after.
    stop_signal: u32,
}

/// What a thread learns from leaving a stop.
///
/// Two answers rather than one because two different things act on them: the
/// parent hears about the continue exactly once, and the *interrupted syscall*
/// restarts in every thread that was stopped. Returning only the claim, as this
/// used to, meant the restart could be applied to one thread of a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopWait {
    /// This thread was in a stop that has now ended, so whatever syscall the
    /// stop signal interrupted should be re-run rather than answer `EINTR`.
    pub was_stopped: bool,
    /// This thread is the one that tells the parent about the continue.
    pub report_continue: bool,
}

pub struct GroupStop {
    state: GuestLock<State>,
}

impl std::fmt::Debug for GroupStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupStop").finish_non_exhaustive()
    }
}

impl Default for GroupStop {
    fn default() -> GroupStop {
        GroupStop::new()
    }
}

impl GroupStop {
    pub fn new() -> GroupStop {
        GroupStop {
            state: GuestLock::new(State::default(), 1),
        }
    }

    /// A stop signal took effect: the group is stopped and reports `status`.
    pub fn stop(&self, status: u32) {
        let mut s = self.state.lock();
        s.stopped = true;
        s.stop_status = status;
        // `(sig << 8) | 0x7f`, which is how a wait reports a stop.
        s.stop_signal = status >> 8;
    }

    /// The signal that stopped the group, while it is stopped.
    ///
    /// Not consumed by anything: `read_stop` is the report a `wait` takes,
    /// and the parent's `SIGCHLD` may be built after a waiter has taken it.
    pub fn stop_signal(&self) -> Option<u32> {
        let s = self.state.lock();
        s.stopped.then_some(s.stop_signal)
    }

    /// A `SIGCONT` restarted the group, if it was stopped.
    ///
    /// Answers whether it was — only a group that was *actually* stopped has
    /// been continued, and a `SIGCONT` to a running one is not an event any
    /// waiter should see.
    pub fn resume(&self) -> bool {
        let was = {
            let mut s = self.state.lock();
            let was = s.stopped;
            if was {
                s.continued = true;
                s.continue_pending = true;
            }
            s.stopped = false;
            was
        };
        // Outside the lock: nothing here needs it and a waiter is about to take
        // it back.
        self.state.notify(CONT);
        was
    }

    /// Restarted without being continued: the group is exiting and every thread
    /// has to leave the stop, but nothing was continued and no waiter should
    /// hear otherwise.
    pub fn release(&self) {
        {
            let mut s = self.state.lock();
            s.stopped = false;
        }
        self.state.notify(CONT);
    }

    /// Sleeps while the group is stopped, then claims the right to report the
    /// continue.
    ///
    /// See the module comment for why the claim is outside the loop.
    pub fn wait_while_stopped(&self) -> StopWait {
        self.wait_while_stopped_noting(|_| {})
    }

    /// [`GroupStop::wait_while_stopped`], telling `note` `true` before the
    /// first sleep and `false` after the last, and nothing when it does not
    /// sleep: what `/proc/<pid>/syscall` reports of a stopped task is
    /// published there and costs nothing on the way past.
    pub fn wait_while_stopped_noting(&self, mut note: impl FnMut(bool)) -> StopWait {
        let mut slept = false;
        let mut s = self.state.lock();
        while s.stopped {
            if !slept {
                note(true);
            }
            slept = true;
            // A guest signal does not end this wait: being stopped is not
            // something the stopped process gets to be interrupted out of.
            // Only `SIGCONT` and `SIGKILL` end it, and both of them go through
            // `resume`/`release` above.
            s.wait_ignoring_signals(CONT, None);
        }
        if slept {
            note(false);
        }
        let report = s.continue_pending;
        s.continue_pending = false;
        // A thread that never slept was still in a stop if it is the one
        // claiming the continue: that is the SIGCONT which overtook the stop,
        // and its syscall was interrupted by the SIGSTOP just the same. In a
        // group where another thread claims it first, this one answers false
        // and its syscall keeps its EINTR -- the interleaving is narrow (the
        // whole window is between `stop` and this call) and the cost is one
        // spurious EINTR rather than a wrong restart.
        StopWait {
            was_stopped: slept || report,
            report_continue: report,
        }
    }

    /// What a stopped group reports to `wait`, or `None`.
    ///
    /// `nowait` is `WNOWAIT`: look without taking. Otherwise the status is
    /// consumed, because a stop is reported once — this used to be a read, a
    /// test and a write through an unlocked field, so two waiters could both
    /// report one stop.
    pub fn read_stop(&self, nowait: bool) -> Option<u32> {
        let mut s = self.state.lock();
        if !s.stopped {
            return None;
        }
        let status = s.stop_status;
        if status == 0 {
            return None;
        }
        if !nowait {
            s.stop_status = 0;
        }
        Some(status)
    }

    /// Whether the group has been continued since a `wait` last looked.
    ///
    /// Consumed by the `wait` that reports it, as a stop is, unless `nowait`.
    pub fn take_continued(&self, nowait: bool) -> bool {
        let mut s = self.state.lock();
        let continued = s.continued;
        if continued && !nowait {
            s.continued = false;
        }
        continued
    }

    /// For `/proc/<pid>/stat`'s state character, which is `T` for a stopped
    /// group.
    pub fn is_stopped(&self) -> bool {
        self.state.lock().stopped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_sighand as _;
    use kernel_sigqueue as _;

    fn stop() -> GroupStop {
        GroupStop::new()
    }

    /// A group that was never stopped reports nothing, whatever is asked.
    #[test]
    fn a_running_group_has_nothing_to_report() {
        let g = stop();
        assert!(!g.is_stopped());
        assert_eq!(g.read_stop(false), None);
        assert!(!g.take_continued(false));
        // And a SIGCONT to it is not an event: `resume` says so, and that is
        // what keeps a waiter from seeing a continue for a group that was
        // running all along.
        assert!(!g.resume());
        assert!(!g.take_continued(false));
    }

    /// The stop status is reported once and the group stays stopped.
    ///
    /// Two waiters could both report one stop when this was a read, a test and
    /// a write through an unlocked field.
    #[test]
    fn a_stop_is_reported_once_and_does_not_end_the_stop() {
        let g = stop();
        g.stop(19 << 8 | 0x7f);
        assert!(g.is_stopped());
        assert_eq!(g.read_stop(false), Some(19 << 8 | 0x7f));
        // Taken: the second waiter has nothing.
        assert_eq!(g.read_stop(false), None);
        // But the group is still stopped, which is a different question.
        assert!(g.is_stopped());
    }

    /// `WNOWAIT` looks without taking, so the next waiter still sees it.
    #[test]
    fn wnowait_leaves_the_status_where_it_was() {
        let g = stop();
        g.stop(0x137f);
        assert_eq!(g.read_stop(true), Some(0x137f));
        assert_eq!(g.read_stop(true), Some(0x137f));
        assert_eq!(g.read_stop(false), Some(0x137f));
        assert_eq!(g.read_stop(false), None);
    }

    /// A continue is two events with different consumers.
    #[test]
    fn a_continue_is_reported_to_the_waiter_and_to_the_parent_separately() {
        let g = stop();
        g.stop(0x137f);
        assert!(g.resume());
        assert!(!g.is_stopped());

        // The parent's SIGCHLD, claimed exactly once.
        assert!(
            g.wait_while_stopped().report_continue,
            "the first caller claims the report"
        );
        assert!(
            !g.wait_while_stopped().report_continue,
            "and the second gets nothing"
        );

        // The waiter's CLD_CONTINUED, consumed separately and still there.
        assert!(g.take_continued(false));
        assert!(!g.take_continued(false));
    }

    /// `WNOWAIT` on the continue, for the same reason as on the stop.
    #[test]
    fn wnowait_leaves_the_continue_where_it_was() {
        let g = stop();
        g.stop(0x137f);
        g.resume();
        assert!(g.take_continued(true));
        assert!(g.take_continued(true));
        assert!(g.take_continued(false));
        assert!(!g.take_continued(false));
    }

    /// A `SIGCONT` that arrives before the stopped thread reaches the wait.
    ///
    /// The loop does not run, and the event is still that thread's to report —
    /// which is why the claim is outside the loop and not inside it.
    #[test]
    fn a_continue_that_overtook_the_stop_is_still_reported() {
        let g = stop();
        g.stop(0x137f);
        g.resume();
        // Never sleeps: `stopped` is already false.
        let w = g.wait_while_stopped();
        assert!(w.report_continue);
        // And its syscall still restarts: the stop it was interrupted by
        // happened, whether or not this thread ever parked on it.
        assert!(w.was_stopped);
    }

    /// `/proc/<pid>/syscall`'s note is taken only by a thread that sleeps,
    /// once on the way in and once on the way out.
    #[test]
    fn the_note_is_for_a_thread_that_sleeps() {
        let g = stop();
        let mut notes = Vec::new();
        g.wait_while_stopped_noting(|n| notes.push(n));
        assert!(notes.is_empty(), "not stopped: nothing to note");
        g.stop(0x137f);
        let asleep = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|s| {
            let h = s.spawn(|| {
                let mut notes = Vec::new();
                g.wait_while_stopped_noting(|n| {
                    asleep.store(true, std::sync::atomic::Ordering::SeqCst);
                    notes.push(n);
                });
                notes
            });
            // Noted under the stop's lock, which the wait gives up and
            // `resume` takes: the resume cannot come before the sleep.
            while !asleep.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::yield_now();
            }
            g.resume();
            assert_eq!(h.join().unwrap(), [true, false]);
        });
    }

    /// The group-exit path restarts the threads without continuing the group.
    ///
    /// A thread leaving a stop because the process is being killed is not a
    /// continue, and a waiter must not be told it was one.
    #[test]
    fn a_release_is_not_a_continue() {
        let g = stop();
        g.stop(0x137f);
        g.release();
        assert!(!g.is_stopped());
        assert!(!g.take_continued(false), "nothing was continued");
        let w = g.wait_while_stopped();
        assert!(!w.report_continue, "and there is nothing to report");
        assert!(
            !w.was_stopped,
            "a release the thread never parked on is not a stop it left"
        );
        // And the status goes with the stop: a group that is not stopped has
        // nothing to say about one.
        assert_eq!(g.read_stop(false), None);
    }

    /// Stopping again after a continue starts over.
    #[test]
    fn a_second_stop_replaces_the_first() {
        let g = stop();
        g.stop(0x137f);
        g.resume();
        assert!(g.take_continued(false));
        g.stop(0x147f);
        assert!(g.is_stopped());
        assert_eq!(g.read_stop(false), Some(0x147f));
        // The continue from last time is gone, not carried forward.
        assert!(!g.take_continued(false));
    }
}
