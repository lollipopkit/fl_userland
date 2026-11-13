//! Re-executing a syscall that a signal interrupted.
//!
//! A syscall that returns `EINTR` is often not supposed to surface it at all.
//! Linux rewinds the program counter to the `svc` and restores the first
//! argument, so the syscall runs again — either when the handler returns, or
//! straight away if no handler ran.
//!
//! Load-bearing rather than a nicety: JSC's SIGPWR GC-safepoint handshake
//! registers `SA_RESTART` and otherwise livelocks, re-signalling a thread whose
//! futex keeps answering `EINTR`.
//!
//! # There are three answers, not two
//!
//! This used to be a boolean — "may this be re-run" — and a `switch` over three
//! syscall numbers in `handle_interrupt`. Linux has three codes, and the one in
//! the middle is the case the boolean could not express:
//!
//! | Linux | Restarted when a handler ran | Restarted when none did |
//! | --- | --- | --- |
//! | `ERESTARTSYS` | only if the handler asked (`SA_RESTART`) | yes |
//! | `ERESTARTNOHAND` | **never**, `SA_RESTART` or not | yes |
//! | `ERESTART_RESTARTBLOCK` | never | with an adjusted deadline |
//!
//! [`Restart::OnlyWithoutHandler`] is the middle row, and it is what `pause`,
//! `ppoll`, `pselect` and `rt_sigsuspend` are: they replace the signal mask for
//! the duration of the call, so re-running one after a handler would wait under
//! a mask the guest has since been told was restored.
//!
//! The bottom row is the one this kernel cannot do. Rewinding the pc restarts
//! the **full** duration rather than the remaining time, so `nanosleep` and
//! anything else carrying a deadline stays [`Restart::Never`] and surfaces the
//! `EINTR`, which is what a libc's own restart loop expects.
//!
//! # What that boolean cost
//!
//! A group stop restarted nothing at all: `^Z` then `fg` on a program blocked
//! in `pause()` made the `pause` **return**, because the wait ended with
//! `EINTR` and no handler ran, so nothing rewound. Measured against a real
//! kernel by `tests/guest/src/bin/wait_probe.rs`, which is where it was found.
//! And `futex` was armed with no regard for its timeout argument, so an
//! `SA_RESTART` handler arriving during `futex(FUTEX_WAIT, …, timeout)`
//! restarted the whole wait.
//!
//! # Why this is an object and not three fields
//!
//! The rewind is only correct when the machine is *still just past the `svc` of
//! the syscall that was interrupted*. `struct task` had:
//!
//! ```c
//! unsigned syscall_restart_num;
//! uint64_t syscall_restart_arg0;
//! uint64_t syscall_restart_pc;
//! bool syscall_restartable;
//! ```
//!
//! and twelve lines of comment explaining that checking the flag alone is
//! unsafe — a later interrupt that is not a syscall (`INT_TIMER` every quantum,
//! `INT_GPF` on a copy-on-write fault) runs the same signal delivery, and a new
//! `SA_RESTART` signal arriving then would rewind the pc into the middle of
//! ordinary code. The flag is sticky, so it survives from one interrupted
//! syscall to whatever runs next.
//!
//! Here there is no way to ask. [`SyscallRestart::take_rewind`] is given the pc
//! the machine is actually at and answers with the arguments *or nothing*; the
//! caller never sees the flag.
//!
//! `syscall_restart_num` is not here because nothing read it. It was stored on
//! every syscall — the decision it looks like it is for is made from the local
//! variable in `handle_interrupt`, one line away.

#![deny(unsafe_op_in_unsafe_fn)]

/// The syscall numbers, generated from `crates/kernel/syscalltable`.
pub mod nr {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/syscall_numbers.rs"));
}

/// The size of one `svc` instruction, which is what a rewind steps back over.
const SVC_LEN: u64 = 4;

/// What may be done about a syscall that answered `EINTR`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Restart {
    /// The `EINTR` reaches the guest whatever happens.
    ///
    /// Everything not classified, and every syscall carrying a deadline: a
    /// rewind would restart the full duration, so a `timeout N` wrapper's sleep
    /// would never end.
    #[default]
    Never = 0,
    /// Linux's `ERESTARTSYS`: restarted when the handler asked with
    /// `SA_RESTART`, and when no handler ran at all.
    IfHandlerAsks = 1,
    /// Linux's `ERESTARTNOHAND`: restarted **only** when no handler ran.
    OnlyWithoutHandler = 2,
    /// Linux's `ERESTARTNOINTR`: restarted whether a handler ran or not, and
    /// whatever it asked. `FUTEX_LOCK_PI` is the case: a PI mutex lock never
    /// answers `EINTR`, and its deadline is absolute, so the restart waits for
    /// exactly what is left.
    Always = 3,
    /// Linux's `ERESTART_RESTARTBLOCK`: a relative deadline. Restarted only
    /// when no handler ran, and then not from the top -- the number becomes
    /// `restart_syscall`, which runs the [`Block`] the syscall left, for the
    /// time that is left. Set by the syscall itself ([`SyscallRestart::set_block`]),
    /// never by [`classify`].
    Block = 4,
}

/// What `restart_syscall` runs: Linux's `restart_block`. `run` is the
/// interrupted syscall's own continuation, given back the `data` it left,
/// and answers as a syscall does.
#[derive(Clone, Copy, Debug)]
pub struct Block {
    pub run: fn(&[u64; 4]) -> i64,
    pub data: [u64; 4],
}

/// Where to resume a syscall that is to run again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rewind {
    pub pc: u64,
    pub arg0: u64,
    /// Run `restart_syscall` instead of the syscall itself: its number goes
    /// in `x8`.
    pub restart_syscall: bool,
}

/// Which class a syscall's `EINTR` is in, given the arguments it was called
/// with.
///
/// The arguments matter because a deadline is an argument: `ppoll` with no
/// timeout restarts and `ppoll` with one cannot, and they are the same number.
///
/// Deliberately **not** here: the socket calls. `recvfrom` and friends are
/// `ERESTARTSYS` on Linux only when the socket has no `SO_RCVTIMEO` — Linux
/// reads the socket to decide, and this sees the syscall arguments alone. A
/// timed `recv` restarted from the top would never time out. They are
/// [`Restart::Never`] here and `crates/fs/sock` answers the real question
/// with [`SyscallRestart::reclassify`], where it has the socket in hand.
pub fn classify(num: u64, args: &[u64; 6]) -> Restart {
    use nr::*;
    match num {
        // Slow-device I/O. Re-running reads or writes the same buffer again,
        // which is correct precisely because the interrupted call transferred
        // nothing -- a partial transfer returns the count, not `EINTR`.
        NR_READ | NR_WRITE | NR_READV | NR_WRITEV | NR_PREAD | NR_PWRITE | NR_PREADV
        | NR_PWRITEV | NR_PREADV2 | NR_PWRITEV2 => Restart::IfHandlerAsks,
        // Same argument, for the calls that move bytes between two descriptors.
        NR_SENDFILE64 | NR_SPLICE | NR_TEE | NR_COPY_FILE_RANGE => Restart::IfHandlerAsks,
        // Blocking waits with no deadline of their own.
        NR_WAIT4 | NR_WAITID | NR_FLOCK | NR_FCNTL | NR_IOCTL => Restart::IfHandlerAsks,
        // POSIX message queues: `wq_sleep` answers `ERESTARTSYS`, and the
        // deadline is an *absolute* `CLOCK_REALTIME` time, so running the call
        // again from the top waits for exactly what is left. `mqueue_probe`
        // measured both: an `SA_RESTART` handler during a 200 ms receive
        // returns `ETIMEDOUT` after 200 ms, not `EINTR` after 30.
        NR_MQ_TIMEDSEND | NR_MQ_TIMEDRECEIVE => Restart::IfHandlerAsks,
        // `futex(uaddr, op, val, timeout, …)`: the fourth argument is a guest
        // pointer to the deadline, and a null one means wait for ever.
        //
        // The PI lock and the requeue-PI wait are `ERESTARTNOINTR` on Linux and
        // carry absolute deadlines; the operation is the second argument, with
        // its two flag bits stripped.
        NR_FUTEX if matches!(args[1] as u32 & !(128 | 256), 6 | 11 | 13) => Restart::Always,
        NR_FUTEX => {
            if args[3] == 0 {
                Restart::IfHandlerAsks
            } else if args[1] as u32 & !(128 | 256) == 9 {
                // `FUTEX_WAIT_BITSET`'s deadline is absolute: from the top
                // waits until the same instant. Linux answers
                // `ERESTART_RESTARTBLOCK` for any timed wait, which is never
                // restarted after a handler, so this is the same answer.
                Restart::OnlyWithoutHandler
            } else {
                // A relative `FUTEX_WAIT` leaves a [`Block`].
                Restart::Never
            }
        }
        // `ppoll(fds, nfds, timeout, sigmask, sigsetsize)` and
        // `pselect(nfds, r, w, e, timeout, sigmask)`. Both replace the mask for
        // the duration, which is why they are the middle row rather than the
        // first.
        //
        // With a timeout too: Linux writes what is left of it back into the
        // caller's timespec (`poll_select_finish`) before answering
        // `ERESTARTNOHAND`, so the restart waits for the rest. This kernel
        // writes it back as well (`crates/kernel/pollcalls`); they were
        // `Never` until 2026-11-13, so `^Z`, `fg` ended a timed `poll` early
        // with `EINTR` (`stoprestart_probe`).
        NR_PPOLL | NR_PSELECT => Restart::OnlyWithoutHandler,
        // An absolute sleep runs again to the same instant: Linux's
        // `ERESTARTNOHAND` for `TIMER_ABSTIME`. A relative one leaves a
        // [`Block`].
        NR_CLOCK_NANOSLEEP if args[1] & 1 != 0 => Restart::OnlyWithoutHandler,
        NR_RT_SIGSUSPEND => Restart::OnlyWithoutHandler,
        // futex2's two waits take an **absolute** deadline, so re-running one
        // waits until the same instant rather than the full duration again --
        // and Linux answers `ERESTARTSYS` for both whatever the timeout.
        NR_FUTEX_WAIT | NR_FUTEX_WAITV => Restart::IfHandlerAsks,
        _ => Restart::Never,
    }
}

/// What an interrupted syscall needs to be run again.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct SyscallRestart {
    /// `cpu.pc` at syscall entry, which the `svc` gadget has already advanced
    /// to the instruction *after* the `svc`.
    pc: u64,
    /// The first argument. The return value overwrites `x0`, so restarting
    /// means putting it back.
    arg0: u64,
    /// What may be done about this syscall's `EINTR`, decided at entry from its
    /// number and arguments.
    class: Restart,
    /// Whether the syscall that `pc` describes did in fact answer `EINTR`.
    armed: bool,
    /// What `restart_syscall` runs, left by a syscall whose deadline is
    /// relative.
    block: Option<Block>,
}

impl SyscallRestart {
    /// A syscall is starting. Records what a restart would need, classifies it,
    /// and **disarms**: whatever was interrupted before, this is not it.
    pub fn entered(&mut self, pc: u64, num: u64, args: &[u64; 6]) {
        self.pc = pc;
        self.arg0 = args[0];
        self.class = classify(num, args);
        self.armed = false;
        // `restart_syscall` itself is what takes the block.
        if num != nr::NR_RESTART_SYSCALL {
            self.block = None;
        }
    }

    /// The syscall answering `EINTR` is to be continued by `block` if no
    /// handler runs: [`Restart::Block`].
    pub fn set_block(&mut self, block: Block) {
        self.block = Some(block);
        self.class = Restart::Block;
    }

    /// `restart_syscall`: the block the interrupted syscall left, once.
    pub fn take_block(&mut self) -> Option<Block> {
        self.block.take()
    }

    /// The syscall answered `EINTR`.
    pub fn interrupted(&mut self) {
        self.armed = true;
    }

    /// The syscall now running knows its own class better than its number
    /// does, and says so before it answers `EINTR`.
    ///
    /// That is the socket calls: Linux's `sock_intr_errno` restarts a wait on
    /// a socket with no timeout for that direction and refuses one that has
    /// a timeout, and the timeout is a property of the socket rather than an
    /// argument -- so [`classify`] cannot see it and answers [`Restart::Never`],
    /// and `crates/fs/sock` corrects it where it has the descriptor in hand.
    /// Until 2026-09-04 nothing did, and a `recv` interrupted under an
    /// `SA_RESTART` handler answered `EINTR` where Linux went on waiting.
    pub fn reclassify(&mut self, class: Restart) {
        self.class = class;
    }

    /// The pc to jump to and the first argument to restore, if a rewind is due
    /// **at this pc**.
    ///
    /// `at_pc` is where the machine actually is. A rewind is due only when that
    /// is still the instruction after the interrupted syscall's `svc`; anywhere
    /// else and the arming belongs to something that has already finished.
    ///
    /// `handler_ran` says whether a guest signal handler is being entered. The
    /// caller passes `true` only when that handler asked for a restart, so
    /// [`Restart::IfHandlerAsks`] needs no second test here; what the flag
    /// decides is [`Restart::OnlyWithoutHandler`], which refuses.
    ///
    /// Consumes the arming, because a rewind happens once.
    pub fn take_rewind(&mut self, at_pc: u64, handler_ran: bool) -> Option<Rewind> {
        if !self.armed || at_pc != self.pc {
            return None;
        }
        let due = match self.class {
            Restart::Never => false,
            Restart::IfHandlerAsks | Restart::Always => true,
            Restart::OnlyWithoutHandler | Restart::Block => !handler_ran,
        };
        if !due {
            return None;
        }
        self.armed = false;
        Some(Rewind {
            pc: self.pc - SVC_LEN,
            arg0: self.arg0,
            restart_syscall: self.class == Restart::Block,
        })
    }

    /// For diagnostics only. Deciding anything from this is the mistake the
    /// object exists to prevent.
    pub fn is_armed(&self) -> bool {
        self.armed
    }

    /// Whether a handler without `SA_RESTART` still restarts this syscall,
    /// which is [`Restart::Always`]. The signal path asks before it asks for
    /// the rewind, because it only asks at all for an `SA_RESTART` handler.
    pub fn restarts_regardless(&self) -> bool {
        self.class == Restart::Always
    }

    /// For diagnostics only.
    pub fn class(&self) -> Restart {
        self.class
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(pc: u64, arg0: u64) -> Option<Rewind> {
        Some(Rewind { pc, arg0, restart_syscall: false })
    }

    /// `entered` for a syscall whose arguments do not matter.
    fn enter(r: &mut SyscallRestart, pc: u64, num: u64, arg0: u64) {
        let mut args = [0u64; 6];
        args[0] = arg0;
        r.entered(pc, num, &args);
    }

    #[test]
    fn a_fresh_task_has_nothing_to_restart() {
        // `struct task` is zeroed when it is made and a child inherits its
        // parent's bytes, so a zeroed one has to *be* "nothing armed".
        let mut r = SyscallRestart::default();
        assert_eq!(r.take_rewind(0, false), None);
        assert_eq!(r.take_rewind(0x1000, true), None);
    }

    #[test]
    fn a_rewind_steps_back_over_the_svc_and_restores_the_argument() {
        let mut r = SyscallRestart::default();
        enter(&mut r, 0x1004, nr::NR_READ, 0xdead);
        r.interrupted();
        assert_eq!(r.take_rewind(0x1004, true), at(0x1000, 0xdead));
    }

    #[test]
    fn the_pc_has_to_still_be_the_interrupted_syscalls() {
        // The whole reason this is an object. The arming is sticky -- it
        // survives an EINTR whose handler had no SA_RESTART -- and a later
        // interrupt that is not a syscall runs the same delivery path. Rewinding
        // on the flag alone puts the pc four bytes back into ordinary code.
        let mut r = SyscallRestart::default();
        enter(&mut r, 0x1004, nr::NR_READ, 0xdead);
        r.interrupted();
        assert_eq!(r.take_rewind(0x2000, true), None, "somewhere else entirely");
        assert_eq!(
            r.take_rewind(0x1000, true),
            None,
            "even one instruction off"
        );
        assert_eq!(r.take_rewind(0x1008, true), None);
        // And it is still armed, because none of those consumed it: the real
        // signal for this syscall can still arrive.
        assert_eq!(r.take_rewind(0x1004, true), at(0x1000, 0xdead));
    }

    #[test]
    fn a_rewind_happens_once() {
        let mut r = SyscallRestart::default();
        enter(&mut r, 0x1004, nr::NR_READ, 7);
        r.interrupted();
        assert!(r.take_rewind(0x1004, true).is_some());
        assert_eq!(
            r.take_rewind(0x1004, true),
            None,
            "the second signal does not rewind again"
        );
    }

    #[test]
    fn entering_a_syscall_disarms_whatever_was_there() {
        // A new syscall is not the interrupted one, and its pc will usually
        // differ -- but not always: a loop calling the same syscall re-enters
        // at the same address. Arming has to be cleared rather than left to the
        // pc check.
        let mut r = SyscallRestart::default();
        enter(&mut r, 0x1004, nr::NR_READ, 1);
        r.interrupted();
        enter(&mut r, 0x1004, nr::NR_READ, 2);
        assert_eq!(
            r.take_rewind(0x1004, true),
            None,
            "the new call is not interrupted yet"
        );
        r.interrupted();
        assert_eq!(
            r.take_rewind(0x1004, true),
            at(0x1000, 2),
            "and it carries the new argument"
        );
    }

    #[test]
    fn a_syscall_with_a_deadline_never_restarts() {
        // nanosleep and friends: rewinding restarts the full duration rather
        // than the remaining time, so `timeout N` would never end.
        for num in [
            nr::NR_NANOSLEEP,
            nr::NR_CLOCK_NANOSLEEP,
            nr::NR_RT_SIGTIMEDWAIT,
        ] {
            let mut r = SyscallRestart::default();
            enter(&mut r, 0x1004, num, 1);
            r.interrupted();
            assert_eq!(
                r.take_rewind(0x1004, true),
                None,
                "syscall {num} with a handler"
            );
            assert_eq!(
                r.take_rewind(0x1004, false),
                None,
                "syscall {num} without one"
            );
        }
    }

    #[test]
    fn a_futex_restarts_only_without_a_timeout() {
        // The old code armed every futex. `futex(FUTEX_WAIT, …, timeout)`
        // interrupted by an SA_RESTART handler then waited the whole timeout
        // again from the top.
        let wait = [0x1000u64, 0, 0, 0, 0, 0];
        let mut r = SyscallRestart::default();
        r.entered(0x1004, nr::NR_FUTEX, &wait);
        r.interrupted();
        assert_eq!(r.take_rewind(0x1004, true), at(0x1000, 0x1000));

        let timed = [0x1000u64, 0, 0, 0x7fff_0000, 0, 0];
        let mut r = SyscallRestart::default();
        r.entered(0x1004, nr::NR_FUTEX, &timed);
        r.interrupted();
        assert_eq!(r.take_rewind(0x1004, true), None);
    }

    #[test]
    fn pause_restarts_without_a_handler_and_not_with_one() {
        // musl's `pause()` on aarch64 is `ppoll(NULL, 0, NULL, NULL)`: there is
        // no pause syscall in this table. Linux restarts it after a group stop
        // and answers EINTR to a handler, SA_RESTART or not, because the call
        // replaced the signal mask for its duration.
        let args = [0u64; 6];
        let mut r = SyscallRestart::default();
        r.entered(0x1004, nr::NR_PPOLL, &args);
        r.interrupted();
        assert_eq!(r.take_rewind(0x1004, true), None, "a handler ran");
        assert_eq!(
            r.take_rewind(0x1004, false),
            at(0x1000, 0),
            "the group was stopped and continued"
        );
    }

    /// A timed `ppoll` restarts when no handler ran, as Linux's does: the
    /// timespec holds what is left by then (`stoprestart_probe`).
    #[test]
    fn a_ppoll_with_a_timeout_restarts_only_without_a_handler() {
        let args = [0, 0, 0xbeef_0000, 0, 0, 0];
        let mut r = SyscallRestart::default();
        r.entered(0x1004, nr::NR_PPOLL, &args);
        r.interrupted();
        assert_eq!(r.take_rewind(0x1004, true), None, "a handler ran");
        assert_eq!(r.take_rewind(0x1004, false), at(0x1000, 0));
    }

    #[test]
    fn pselect_restarts_only_without_a_handler_timed_or_not() {
        for args in [[3, 0, 0, 0, 0, 0], [3, 0, 0, 0, 0xbeef_0000, 0]] {
            let mut r = SyscallRestart::default();
            r.entered(0x1004, nr::NR_PSELECT, &args);
            r.interrupted();
            assert_eq!(r.take_rewind(0x1004, true), None, "a handler ran");
            assert_eq!(r.take_rewind(0x1004, false), at(0x1000, 3));
        }
    }

    /// A relative sleep leaves a block: restarted without a handler as
    /// `restart_syscall`, which takes the block once; never after a handler.
    #[test]
    fn a_block_restarts_as_restart_syscall() {
        fn run(_: &[u64; 4]) -> i64 {
            0
        }
        let block = Block { run, data: [1, 2, 3, 4] };
        let mut r = SyscallRestart::default();
        r.entered(0x1004, nr::NR_NANOSLEEP, &[0; 6]);
        r.set_block(block);
        r.interrupted();
        assert_eq!(r.take_rewind(0x1004, true), None, "a handler ran");
        assert_eq!(r.take_rewind(0x1004, false), Some(Rewind { pc: 0x1000, arg0: 0, restart_syscall: true }));
        r.entered(0x1004, nr::NR_RESTART_SYSCALL, &[0; 6]);
        assert_eq!(r.take_block().map(|b| b.data), Some(block.data), "restart_syscall keeps it to take");
        assert!(r.take_block().is_none());
        r.set_block(block);
        r.entered(0x1004, nr::NR_GETPID, &[0; 6]);
        assert!(r.take_block().is_none(), "any other syscall drops it");
    }

    /// An absolute sleep and an absolute futex deadline run again from the
    /// top; a relative futex wait does not (it leaves a block).
    #[test]
    fn absolute_deadlines_restart_from_the_top() {
        assert_eq!(classify(nr::NR_CLOCK_NANOSLEEP, &[1, 1, 0, 0, 0, 0]), Restart::OnlyWithoutHandler);
        assert_eq!(classify(nr::NR_CLOCK_NANOSLEEP, &[1, 0, 0, 0, 0, 0]), Restart::Never);
        assert_eq!(classify(nr::NR_FUTEX, &[0, 9 | 128, 0, 0xbeef, 0, 0]), Restart::OnlyWithoutHandler);
        assert_eq!(classify(nr::NR_FUTEX, &[0, 128, 0, 0xbeef, 0, 0]), Restart::Never, "FUTEX_WAIT | PRIVATE");
    }

    #[test]
    fn a_pi_lock_restarts_whatever_the_handler_asked() {
        // FUTEX_LOCK_PI, LOCK_PI2 and WAIT_REQUEUE_PI, with and without the
        // private flag and with a deadline: Linux's ERESTARTNOINTR.
        for op in [6u64, 13, 11, 6 | 128, 13 | 128 | 256] {
            let args = [0x1000, op, 0, 0xbeef_0000, 0, 0];
            let mut r = SyscallRestart::default();
            r.entered(0x1004, nr::NR_FUTEX, &args);
            assert!(r.restarts_regardless(), "op {op:#x}");
            r.interrupted();
            assert_eq!(r.take_rewind(0x1004, true), at(0x1000, 0x1000), "op {op:#x}");
        }
        // FUTEX_WAIT is not one of them.
        let args = [0x1000, 128, 0, 0, 0, 0];
        let mut r = SyscallRestart::default();
        r.entered(0x1004, nr::NR_FUTEX, &args);
        assert!(!r.restarts_regardless());
    }

    #[test]
    fn the_futex2_waits_restart_when_asked_even_with_a_deadline() {
        // Their deadline is absolute, so the restart waits until the same
        // instant; Linux answers ERESTARTSYS for both.
        for n in [nr::NR_FUTEX_WAIT, nr::NR_FUTEX_WAITV] {
            let args = [0x1000, 0, 0, 0xbeef_0000, 0xbeef_0000, 1];
            let mut r = SyscallRestart::default();
            r.entered(0x1004, n, &args);
            r.interrupted();
            assert_eq!(r.take_rewind(0x1004, true), at(0x1000, 0x1000));
            assert!(!r.restarts_regardless());
        }
    }

    #[test]
    fn an_unclassified_syscall_surfaces_its_eintr() {
        // The default has to be Never: a syscall nobody has thought about
        // re-running is one that may not be safe to re-run.
        let mut r = SyscallRestart::default();
        enter(&mut r, 0x1004, nr::NR_GETPID, 0);
        r.interrupted();
        assert_eq!(r.take_rewind(0x1004, false), None);
    }

    #[test]
    fn an_argument_of_zero_is_still_an_argument() {
        // `read(0, ...)` is the commonest syscall there is, and a restart that
        // treated 0 as "nothing to restore" would hand the retry whatever the
        // return value left in x0.
        let mut r = SyscallRestart::default();
        enter(&mut r, 0x1004, nr::NR_READ, 0);
        r.interrupted();
        assert_eq!(r.take_rewind(0x1004, true), at(0x1000, 0));
    }

    #[test]
    fn the_generated_numbers_are_the_tables() {
        // If the parse in build.rs silently produced nothing useful, every
        // classification above would still compile and match nothing.
        assert_eq!(nr::NR_READ, 63);
        assert_eq!(nr::NR_WRITE, 64);
        assert_eq!(nr::NR_PPOLL, 73);
        assert_eq!(nr::NR_FUTEX, 98);
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
        // 24 until 2026-11-13, when it gained the restart block.
        assert_eq!(std::mem::size_of::<SyscallRestart>(), 64);
        assert_eq!(std::mem::align_of::<SyscallRestart>(), 8);
    }
}
