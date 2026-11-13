//! Whether a thread group is exiting, with what status, and what a *stopped*
//! one reports to `wait`.
//!
//! # The flag and the status were two fields, and the flag was stored first
//!
//! `struct tgroup` had `bool doing_group_exit` and `dword_t group_exit_code`,
//! written under `group->lock`:
//!
//! ```c
//! if (!group->doing_group_exit) {
//!     group->doing_group_exit = true;
//!     group->group_exit_code = status;   // ← after the flag
//! }
//! ```
//!
//! and read in four places **with no lock at all** — the JIT quantum check in
//! `task_run_current`, the syscall return in `handle_interrupt`, the futex wait
//! and the poll wait:
//!
//! ```c
//! if (group->doing_group_exit)
//!     do_exit(group->group_exit_code);
//! ```
//!
//! Two plain stores in that order, and plain loads, are not ordered against
//! each other on aarch64. A reader could see the flag set and the *old* status
//! — so a thread killed by a group exit could exit with the wrong code, most
//! often 0. The field carried a `// TODO locking` and this is what it was
//! about.
//!
//! Both live in **one word** here. There is nothing to order, at any memory
//! ordering: a reader either sees the exit or it does not, and when it does the
//! status came with it.
//!
//! # And the status meant two things
//!
//! `group_exit_code` was also where a *stopped* group's status went —
//! `SIGNAL_STOP` wrote `sig << 8 | 0x7f` into it and `notify_if_stopped` read
//! it back and cleared it. One field, two questions, told apart by another
//! field.
//!
//! The stop status lived here for a while, separated from the exit status but
//! still apart from the flag that decides whether it means anything. It is
//! `crates/kernel/groupstop` now, with `stopped` itself: **the flag and the
//! status are one answer**, and keeping them in two objects meant every reader
//! had to take a lock around both and say so in a comment. Nothing here has
//! anything to do with a stop any more.
//!
//! # And an `execve` is the third state
//!
//! A thread that execs ends every other thread of its group (Linux's
//! `de_thread`) and the group goes on. While it waits for them the word says
//! so, with the exec'ing thread's tid: the others leave as they would for a
//! group exit, the exec'ing one does not, and a second `execve` or an
//! `exit_group` started meanwhile finds the group busy -- one compare-exchange
//! decides which of the three a group is doing, as `signal->group_exec_task`
//! and `SIGNAL_GROUP_EXIT` do between them.
//!
//! # A fatal signal starts the exit where it is sent
//!
//! Linux's `complete_signal` sets `SIGNAL_GROUP_EXIT` from the *sender*, with
//! the signal as the status ([`GroupExit::signalled`]), and an exec in
//! progress loses to it. Until 2026-11-13 the thread that took the signal
//! started the exit when it got to it, so a thread that `kill`ed its own
//! process went on to `exit_group(3)` and the parent saw 3, and a thread
//! already being ended by an exec that took the signal left alone while the
//! exec went on (`sigfatal_probe`).
//!
//! A sender is not a thread of the group, so it cannot be the one that waits
//! for the others. That is the third bit, *led*: the first thread of the group
//! to arrive in [`GroupExit::begin`] claims it. An exec that a signal
//! overtakes is already waiting for the others, so the signal claims it for
//! the exec'ing thread, which leaves with the signal's status once they have
//! gone.

#![deny(unsafe_op_in_unsafe_fn)]

use std::sync::atomic::{AtomicU64, Ordering};

/// Set in the high half when the group is exiting.
const EXITING: u64 = 1 << 32;
/// Set in the high half while a thread's `execve` ends the others; the low
/// half is that thread's tid.
const EXEC: u64 = 1 << 33;
/// Set with [`EXITING`] once a thread of the group is ending the others and
/// waiting for them; see the module comment.
const LED: u64 = 1 << 34;

/// The status a thread ended by another's `execve` leaves with: `SIGKILL`,
/// as `zap_other_threads` sends. Nobody is told it.
pub const KILLED_BY_EXEC: u32 = 9;

/// What [`GroupExit::begin`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Begin {
    /// This caller leads the exit: it ends the other threads, waits for
    /// them, and leaves with this status -- its own if it started the exit,
    /// the signal's if a sender did.
    Lead(u32),
    /// Another thread leads it; this is the status in force.
    Joined(u32),
    /// Another thread's `execve` is ending the group's other threads, this
    /// one among them: it leaves alone and the group goes on. Linux's
    /// `do_group_exit` with `group_exec_task` set.
    Exec,
}

/// A thread group's exit status.
#[derive(Debug, Default)]
#[repr(C)]
pub struct GroupExit {
    /// Bit 32 is "exiting", bit 33 "an exec is ending the other threads" and
    /// bit 34 "a thread leads the exit"; the low half is the status or the
    /// exec'ing tid. One word, so none of them can be seen apart -- see the
    /// module comment.
    exiting: AtomicU64,
}

impl GroupExit {
    pub fn new() -> GroupExit {
        GroupExit::default()
    }

    /// Move the word with `f`, which answers the new value or `Err` with what
    /// to answer instead; one compare-exchange loop for every transition.
    fn update<T>(&self, mut f: impl FnMut(u64) -> Result<(u64, T), T>) -> T {
        let mut seen = self.exiting.load(Ordering::Acquire);
        loop {
            let (want, answer) = match f(seen) {
                Ok(v) => v,
                Err(answer) => return answer,
            };
            match self.exiting.compare_exchange_weak(seen, want, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return answer,
                Err(now) => seen = now,
            }
        }
    }

    /// `exit_group`, or a thread that has to leave: start the group exiting
    /// with `status`, or find that it already is, or that an `execve` has the
    /// group.
    ///
    /// The second thread into `exit_group` adopts the first one's status,
    /// which is Linux's rule -- `SIGNAL_GROUP_EXIT` is set once and every
    /// thread leaves with it. The first thread here after a sender started
    /// the exit leads it.
    pub fn begin(&self, status: u32) -> Begin {
        self.update(|v| {
            if v == 0 {
                Ok((EXITING | LED | u64::from(status), Begin::Lead(status)))
            } else if v & EXITING == 0 {
                Err(Begin::Exec)
            } else if v & LED == 0 {
                Ok((v | LED, Begin::Lead(v as u32)))
            } else {
                Err(Begin::Joined(v as u32))
            }
        })
    }

    /// A signal fatal to the whole group was sent: Linux's `complete_signal`
    /// setting `SIGNAL_GROUP_EXIT`. The group exits with `status` unless it
    /// already is; answers whether this started it. An `execve` in progress
    /// loses, and its thread -- already waiting for the others -- leads.
    pub fn signalled(&self, status: u32) -> bool {
        self.update(|v| {
            if v & EXITING != 0 {
                Err(false)
            } else if v & EXEC != 0 {
                Ok((EXITING | LED | u64::from(status), true))
            } else {
                Ok((EXITING | u64::from(status), true))
            }
        })
    }

    /// Claim the group for `tid`'s `execve`. `Err` with the status to leave
    /// with when the group is already exiting or another thread's exec has
    /// it -- the caller is one of the threads being ended.
    pub fn begin_exec(&self, tid: i32) -> Result<(), u32> {
        let want = EXEC | u64::from(tid as u32);
        match self
            .exiting
            .compare_exchange(0, want, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(seen) if seen & EXITING != 0 => Err(seen as u32),
            Err(_) => Err(KILLED_BY_EXEC),
        }
    }

    /// The exec that [`Self::begin_exec`] claimed for `tid` is done with the
    /// other threads. `Err` with the status to leave with when a fatal signal
    /// overtook it ([`Self::signalled`]): the exec does not complete.
    pub fn end_exec(&self, tid: i32) -> Result<(), u32> {
        let held = EXEC | u64::from(tid as u32);
        match self.exiting.compare_exchange(held, 0, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(()),
            Err(seen) => {
                debug_assert!(seen & EXITING != 0, "end_exec by a thread that did not begin one: {seen:#x}");
                Err(seen as u32)
            }
        }
    }

    /// The status if the group is exiting. An exec in progress is not an
    /// exit: what a waiter or a pidfd reports is untouched by it.
    pub fn pending(&self) -> Option<u32> {
        let v = self.exiting.load(Ordering::Acquire);
        (v & EXITING != 0).then_some(v as u32)
    }

    /// Whether the thread `tid` has to leave, and with what status: the group
    /// is exiting, or another thread's `execve` is ending it.
    pub fn must_leave(&self, tid: i32) -> Option<u32> {
        let v = self.exiting.load(Ordering::Acquire);
        if v & EXITING != 0 {
            Some(v as u32)
        } else if v & EXEC != 0 && v as u32 != tid as u32 {
            Some(KILLED_BY_EXEC)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_fresh_group_is_not_exiting() {
        // `struct tgroup` is zeroed when it is made and tgroup_copy's
        // designated initialiser leaves this out on purpose, so a zeroed one
        // has to *be* "not exiting" rather than merely look like it.
        let g = GroupExit::default();
        assert_eq!(g.pending(), None);
    }

    #[test]
    fn the_first_caller_sets_the_status_and_the_rest_adopt_it() {
        let g = GroupExit::new();
        assert_eq!(g.begin(42), Begin::Lead(42));
        assert_eq!(
            g.begin(7),
            Begin::Joined(42),
            "the second adopts the first's status"
        );
        assert_eq!(g.pending(), Some(42));
    }

    #[test]
    fn a_status_of_zero_still_counts_as_exiting() {
        // The flag is a bit of its own, not "the status is non-zero" -- and
        // `exit_group(0)` is the ordinary case.
        let g = GroupExit::new();
        assert_eq!(g.begin(0), Begin::Lead(0));
        assert_eq!(
            g.pending(),
            Some(0),
            "exiting with status 0, not `not exiting`"
        );
        assert_eq!(g.begin(9), Begin::Joined(0));
    }

    #[test]
    fn the_whole_status_survives() {
        // do_exit_group is given `status << 8`, and a signal death is
        // `sig << 8 | 0x7f` -- neither fits in a byte.
        let g = GroupExit::new();
        g.begin(0xdead_beef);
        assert_eq!(g.pending(), Some(0xdead_beef));
    }

    #[test]
    fn the_flag_is_never_seen_without_the_status() {
        // The defect. Two plain fields with the flag stored first let a reader
        // see the exit and the *old* status; one word cannot.
        //
        // Probabilistic by nature -- it is a race -- so it runs the window many
        // times with readers spinning on it. Against two separate fields this
        // is what would catch a 0 where 0x1234 was asked for.
        for round in 0..200 {
            let g = Arc::new(GroupExit::new());
            let readers: Vec<_> = (0..4)
                .map(|_| {
                    let g = Arc::clone(&g);
                    std::thread::spawn(move || {
                        for _ in 0..2000 {
                            if let Some(s) = g.pending() {
                                assert_eq!(s, 0x1234, "saw the flag without the status");
                                return;
                            }
                            std::hint::spin_loop();
                        }
                    })
                })
                .collect();
            g.begin(0x1234);
            for r in readers {
                r.join().unwrap();
            }
            assert_eq!(g.pending(), Some(0x1234), "round {round}");
        }
    }

    #[test]
    fn only_one_caller_is_ever_first() {
        // is_group_leader decides who waits for the other threads, so two
        // threads both believing they are first is two waiters and no exiter.
        for _ in 0..200 {
            let g = Arc::new(GroupExit::new());
            let hands: Vec<_> = (0..8)
                .map(|i| {
                    let g = Arc::clone(&g);
                    std::thread::spawn(move || matches!(g.begin(100 + i), Begin::Lead(_)))
                })
                .collect();
            let firsts = hands
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|first| *first)
                .count();
            assert_eq!(firsts, 1);
        }
    }

    #[test]
    fn an_exec_ends_every_thread_but_its_own() {
        let g = GroupExit::new();
        assert_eq!(g.begin_exec(42), Ok(()));
        assert_eq!(g.must_leave(42), None, "the exec'ing thread stays");
        assert_eq!(g.must_leave(43), Some(KILLED_BY_EXEC));
        assert_eq!(g.pending(), None, "an exec is not an exit: wait and pidfd see nothing");
        g.end_exec(42).unwrap();
        assert_eq!(g.must_leave(43), None, "and the group goes on");
    }

    #[test]
    fn exit_group_during_an_exec_leaves_alone() {
        // Linux's do_group_exit with group_exec_task set: the caller exits
        // and starts nothing, so the exec is not killed.
        let g = GroupExit::new();
        g.begin_exec(42).unwrap();
        assert_eq!(g.begin(7 << 8), Begin::Exec);
        assert_eq!(g.must_leave(42), None);
    }

    #[test]
    fn an_exec_during_a_group_exit_or_another_exec_loses() {
        let g = GroupExit::new();
        g.begin(7 << 8);
        assert_eq!(g.begin_exec(42), Err(7 << 8), "it leaves with the exit's status");
        let g = GroupExit::new();
        g.begin_exec(42).unwrap();
        assert_eq!(g.begin_exec(43), Err(KILLED_BY_EXEC), "two execs: one wins");
    }

    #[test]
    fn only_one_of_many_execs_and_exits_wins() {
        for _ in 0..200 {
            let g = Arc::new(GroupExit::new());
            let hands: Vec<_> = (0..8)
                .map(|i| {
                    let g = Arc::clone(&g);
                    std::thread::spawn(move || if i % 2 == 0 { g.begin_exec(i).is_ok() } else { matches!(g.begin(i as u32), Begin::Lead(_)) })
                })
                .collect();
            let winners = hands.into_iter().map(|h| h.join().unwrap()).filter(|w| *w).count();
            assert_eq!(winners, 1);
        }
    }

    #[test]
    fn a_signal_starts_the_exit_and_the_first_thread_in_leads_it() {
        let g = GroupExit::new();
        assert!(g.signalled(15));
        assert_eq!(g.pending(), Some(15));
        assert_eq!(g.must_leave(7), Some(15));
        assert!(!g.signalled(10), "the first fatal signal is the status");
        assert_eq!(g.begin(3 << 8), Begin::Lead(15), "exit_group after it adopts the signal");
        assert_eq!(g.begin(0), Begin::Joined(15));
    }

    #[test]
    fn a_signal_after_exit_group_changes_nothing() {
        let g = GroupExit::new();
        assert_eq!(g.begin(3 << 8), Begin::Lead(3 << 8));
        assert!(!g.signalled(15));
        assert_eq!(g.pending(), Some(3 << 8));
    }

    #[test]
    fn a_signal_overtakes_an_exec() {
        // Linux's de_thread loses to SIGNAL_GROUP_EXIT: the exec'ing thread,
        // already waiting for the others, leaves with the signal's status.
        let g = GroupExit::new();
        g.begin_exec(42).unwrap();
        assert!(g.signalled(15));
        assert_eq!(g.must_leave(42), Some(15), "the exec'ing thread too");
        assert_eq!(g.begin(9), Begin::Joined(15), "the exec'ing thread leads; the others join");
        assert_eq!(g.end_exec(42), Err(15), "and the exec does not complete");
        assert_eq!(g.pending(), Some(15));
    }

    #[test]
    fn only_one_of_many_signals_and_exits_sets_the_status() {
        for _ in 0..200 {
            let g = Arc::new(GroupExit::new());
            let hands: Vec<_> = (0..8u32)
                .map(|i| {
                    let g = Arc::clone(&g);
                    std::thread::spawn(move || if i % 2 == 0 { g.signalled(i + 1) } else { matches!(g.begin(i + 1), Begin::Lead(s) if s == i + 1) })
                })
                .collect();
            let firsts = hands.into_iter().map(|h| h.join().unwrap()).filter(|w| *w).count();
            assert_eq!(firsts, 1);
        }
    }

    /// How large this got. It was pinned against a `static_assert` over an
    /// `unsigned char _opaque[N]` in `kernel/task.c`, because C had to reserve
    /// space for a struct it could not see — and **the two numbers were never
    /// compared**: the C asserted the blob's size and this asserted the type's,
    /// and for `group_exit` they were 16 and 8. `struct tgroup` embeds the type
    /// itself since 2026-09-05, so there is one number and nothing to disagree
    /// with it.
    #[test]
    fn the_size_and_alignment_are_recorded() {
        assert_eq!(std::mem::size_of::<GroupExit>(), 8);
        assert_eq!(std::mem::align_of::<GroupExit>(), 8);
    }
}
