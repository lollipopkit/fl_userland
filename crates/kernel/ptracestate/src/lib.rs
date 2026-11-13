//! A task's tracing state: the flags, the stop, and the lock over them.
//!
//! Split out of `crates/kernel/ptrace` on 2026-09-11, and the split is the
//! whole reason this crate exists. `struct task` holds this object by pointer,
//! and a type `struct task` names has to be **below** `crates/kernel/taskview`
//! — but `kernel-ptrace` is the *syscall*, so its transitive closure is 65
//! crates and contains `taskview` itself: it needs `kernel-mmapcalls` to read a
//! tracee's memory for `PTRACE_PEEKDATA`, `kernel-proctree` and `kernel-pids`
//! to find the tracee, and `kernel-usercopy` to answer the tracer. Naming
//! `Ptrace` from `taskview` was therefore a cycle, and the field was an opaque
//! `ptrace_state` placeholder that all 29 of its readers cast back.
//!
//! The state itself needs two things: the guest ABI numbers and a lock. So this
//! is the same move `crates/kernel/rlimitstate` is the result of — the *state*
//! has few dependencies and the *syscall* has many — and it is the answer for
//! any remaining placeholder whose owning crate is a syscall family.
//!
//! `crates/kernel/ptrace` re-exports everything here, so a caller still writes
//! `kernel_ptrace::ptrace_is_traced`.
//!
//! # What is outside the lock, and why
//!
//! Two flags, and both have a reason that is about a hot path rather than about
//! convenience. See [`Ptrace::traced`] and [`Ptrace::at_syscalls`].
//!
//! # The lock order is `crates/kernel/ptrace`'s to state
//!
//! `pids_lock`, then this lock, then `sighand`'s — and the argument for each
//! half is about call sites this crate does not contain, so it is in that
//! crate's module comment. What is here is the object the middle term names.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_int;
use std::sync::atomic::{AtomicBool, Ordering};

use util_guestlock::{GuestGuard, GuestLock};

/// The shared Rust types and constants.
pub use iul_abi as ffi;

/// The one condition variable: the tracer has continued this tracee.
pub const CONT: u32 = 0;

/// What a ptrace stop is made of, under [`Ptrace`]'s lock.
///
/// The fields are `pub` because the syscall in `crates/kernel/ptrace` writes
/// four of them directly and reads a fifth, and the guard is what controls the
/// access: a caller cannot reach one of these without holding the lock, which
/// is the property that matters. Adding a setter per field would be eight
/// methods that each do one assignment.
#[derive(Default)]
pub struct State {
    /// What the tracer asked to have delivered when it continued the tracee:
    /// `PTRACE_CONT`'s and `PTRACE_DETACH`'s `data`, or 0 for "suppress the
    /// signal it stopped for". Read once by the tracee as it leaves the stop.
    /// It was not read at all until 2026-09-04, so every signal a tracer
    /// passed through -- which is every signal `strace` and `gdb` see -- was
    /// dropped on the floor.
    pub resume_signal: c_int,
    /// In signal-delivery-stop, waiting for the tracer.
    pub stopped: bool,
    /// The signal the stop is for, and 0 once a `wait` has reported it.
    pub signal: c_int,
    /// That signal's `siginfo_`, which `PTRACE_GETSIGINFO` hands to the tracer.
    pub info: ffi::siginfo_,
    /// `PTRACE_SETOPTIONS`' bits, of the ones this kernel honours.
    pub options: u32,
    /// Which half of a syscall the next stop is. Linux keeps this because
    /// entry and exit alternate and are otherwise indistinguishable to the
    /// tracer -- `strace` prints one line from the pair.
    pub in_syscall: bool,
    /// A `PTRACE_EVENT_*` the next `SIGTRAP` stop is, or 0 for none.
    ///
    /// An event stop is the ordinary stop with a different number reported, so
    /// this is armed by whatever generates the event and read once by
    /// `enter_stop`. Both happen on the **tracee's own thread** -- exec arms it
    /// and then stops -- so the field needs no more synchronisation than the
    /// lock it already sits under.
    pub pending_event: c_int,
}

/// A task's tracing state.
pub struct Ptrace {
    /// Set by `PTRACE_TRACEME`, cleared by `PTRACE_DETACH`. **Outside the
    /// lock**, and read lock-free: `send_signal` asks it for every signal to
    /// decide whether an ignored one is kept for the tracer, and
    /// `PTRACE_KILL` sends its `SIGKILL` *under* the lock -- so a read that
    /// took the lock was a self-deadlock, and the guest suite's `ptrace_regs`
    /// hung in exactly that call on 2026-09-04. A flag one thread sets and
    /// another reads needs no more than an atomic.
    traced: AtomicBool,
    /// Whether the tracer's last continue was `PTRACE_SYSCALL`, so the tracee
    /// stops again at the next syscall boundary.
    ///
    /// **Outside the lock, for the same reason `traced` is**: the dispatcher
    /// asks it twice per syscall, on the most-executed path in the tree, and
    /// taking a mutex there to read a boolean would be the whole cost of
    /// tracing paid by every process that is not traced. Written by the tracer
    /// under the lock and read by the tracee without it -- an atomic is the
    /// whole synchronisation that needs, because the tracee is stopped when
    /// the tracer writes it.
    at_syscalls: AtomicBool,
    state: GuestLock<State>,
}

impl Default for Ptrace {
    fn default() -> Ptrace {
        Ptrace::new()
    }
}

impl Ptrace {
    pub fn new() -> Ptrace {
        Ptrace {
            traced: AtomicBool::new(false),
            at_syscalls: AtomicBool::new(false),
            state: GuestLock::new(State::default(), 1),
        }
    }

    /// The stop state, locked.
    pub fn lock(&self) -> GuestGuard<'_, State> {
        self.state.lock()
    }

    /// `PTRACE_TRACEME`.
    pub fn set_traced(&self) {
        self.traced.store(true, Ordering::Release);
    }

    /// `PTRACE_DETACH`, and a tracer that exited.
    ///
    /// `Release`, paired with [`Ptrace::is_traced`]'s `Acquire`, so a tracee
    /// that sees the flag clear also sees whatever the tracer wrote before
    /// clearing it.
    pub fn set_detached(&self) {
        self.traced.store(false, Ordering::Release);
    }

    /// Whether signals to this task go through signal-delivery-stop.
    pub fn is_traced(&self) -> bool {
        self.traced.load(Ordering::Acquire)
    }

    /// Whether the tracee stops again at the next syscall boundary.
    ///
    /// Written while the tracee is stopped, so the `Relaxed` load the tracee
    /// makes without the lock cannot race a boundary it is at.
    pub fn set_stops_at_syscalls(&self, yes: bool) {
        self.at_syscalls.store(yes, Ordering::Relaxed);
    }

    /// Whether this task stops at every syscall boundary.
    ///
    /// `#[inline]` and two atomic loads, because `crates/kernel/syscalldispatch`
    /// asks it twice per syscall. A task nothing traces pays one load and a
    /// not-taken branch.
    #[inline]
    pub fn stops_at_syscalls(&self) -> bool {
        self.traced.load(Ordering::Relaxed) && self.at_syscalls.load(Ordering::Relaxed)
    }

    /// The stop a syscall boundary reports, and which half it is.
    ///
    /// `SIGTRAP`, or `SIGTRAP | 0x80` when the tracer asked for
    /// `PTRACE_O_TRACESYSGOOD` -- which is how a tracer tells a syscall-stop
    /// from a `SIGTRAP` the program raised itself, and is why every tracer
    /// sets that option first.
    pub fn enter_syscall_stop(&self) -> bool {
        let mut s = self.state.lock();
        let entering = !s.in_syscall;
        s.in_syscall = entering;
        let sig = if s.options & ffi::PTRACE_O_TRACESYSGOOD_ != 0 {
            ffi::SIGTRAP_ as c_int | 0x80
        } else {
            ffi::SIGTRAP_ as c_int
        };
        s.stopped = true;
        s.signal = sig;
        s.info = ffi::siginfo_::default();
        entering
    }

    /// A stop that is not a syscall boundary resets the half, so the next
    /// `PTRACE_SYSCALL` reports an entry. Linux's `in_syscall` is cleared the
    /// same way by anything that is not a syscall-stop.
    pub fn leave_syscall_pairing(&self) {
        self.state.lock().in_syscall = false;
    }

    /// Enter signal-delivery-stop, recording what stopped it.
    ///
    /// A `SIGTRAP` with an event armed is reported as `SIGTRAP | (event << 8)`
    /// instead, which is the whole of what a `PTRACE_O_TRACE*` option does:
    /// the stop is the same stop, and the tracer reads the event out of the
    /// second byte of the status. The arming is consumed here whether or not
    /// anything asks for the report, so an event cannot be left behind to
    /// re-label an unrelated `SIGTRAP` the program raises later.
    pub fn enter_stop(&self, sig: c_int, info: &ffi::siginfo_) {
        let mut s = self.state.lock();
        let event = core::mem::replace(&mut s.pending_event, 0);
        s.stopped = true;
        s.signal = if sig == ffi::SIGTRAP_ as c_int && event != 0 {
            sig | (event << 8)
        } else {
            sig
        };
        s.info = *info;
    }

    /// Arm a `PTRACE_EVENT_*` for the `SIGTRAP` stop that is about to happen,
    /// if the tracer asked for that event's option. The answer says whether it
    /// was armed, which is what tells a caller its stop is an event stop.
    pub fn arm_event(&self, event: c_int, option: u32) -> bool {
        let mut s = self.state.lock();
        let armed = s.options & option != 0;
        if armed {
            s.pending_event = event;
        }
        armed
    }

    /// Park until the tracer continues this tracee.
    ///
    /// `abandon` is asked after every wake, **with this lock held**, and a true
    /// answer leaves the loop without the tracer having continued anything —
    /// which is how a `SIGKILL` gets a tracee out of a stop, since a signal
    /// alone does not end this wait.
    pub fn wait_while_stopped(&self, mut abandon: impl FnMut() -> bool) -> bool {
        let mut s = self.state.lock();
        while s.stopped {
            s.wait_ignoring_signals(CONT, None);
            if abandon() {
                return true;
            }
        }
        false
    }

    /// The tracer has continued this tracee.
    pub fn resume(&self) {
        self.state.lock().stopped = false;
        self.state.notify(CONT);
    }

    /// What the tracer asked to have delivered as the stop ends, or 0.
    /// Consumed, so a later stop starts from nothing.
    pub fn take_resume_signal(&self) -> c_int {
        let mut s = self.state.lock();
        std::mem::take(&mut s.resume_signal)
    }

    /// The `wait(2)` status word a ptrace stop reports, or `None`.
    ///
    /// Reported to the tracer whether or not it passed `WUNTRACED`: Linux's
    /// `wait_task_stopped` consults that flag only when the waiter is not the
    /// tracer, and a traced task here is always traced by its parent. Requiring
    /// it made `waitpid(pid, &st, 0)` on a stopped tracee block for ever, which
    /// is the call gdb and strace make.
    ///
    /// The signal is consumed unless `nowait`, as an ordinary group stop's
    /// status is.
    pub fn take_stop_report(&self, nowait: bool) -> Option<u32> {
        let mut s = self.state.lock();
        if !s.stopped || s.signal == 0 {
            return None;
        }
        let status = ((s.signal as u32) << 8) | 0x7f;
        if !nowait {
            s.signal = 0;
        }
        Some(status)
    }
}

// ------------------------------------------------------- what used to be adapters
//
// `struct task` held a `*mut Ptrace`, and until 2026-09-30 this module was
// eleven `unsafe fn ptrace_*(p: *const Ptrace, ...)` that each tested it for
// null and called one method -- so every caller in five crates wrote an
// `unsafe` block to reach a method it could have called. The state is
// borrowed once now, with `taskview::ptrace_of`, whose `None` is a task that
// has none; what the adapters added beyond the null test is the two methods
// below. The field is an `Option<Box<Ptrace>>` since the same day, and
// `ptrace_state_new`, which answered `Box::into_raw`, went with it.

impl Ptrace {
    /// The signal the current stop is for, which the tracer's `SIGCHLD`
    /// carries as its `si_status`.
    pub fn stop_signal(&self) -> c_int {
        self.lock().signal
    }

    /// A tracer is leaving: let this tracee go.
    ///
    /// Linux's `exit_ptrace`, and without it a tracee parked in a ptrace stop waits
    /// for a continue that cannot come -- `tests/guest/src/bin/ptrace_orphan_probe.rs`
    /// measured two of its three cases hanging here where a real kernel resumes all
    /// three.
    ///
    /// It is a detach and not a kill: `PTRACE_O_EXITKILL` is the option that asks
    /// for the other behaviour, and this kernel does not honour it, so the tracee
    /// carries on as an ordinary process. The signal it stopped for is suppressed,
    /// which is what the resume path does with a resume signal of 0 -- the tracer
    /// that would have decided is gone.
    ///
    /// Answers whether anything was detached, for the caller's log.
    ///
    /// Called with `pids_lock` held, which is the documented order: `pids_lock`,
    /// then this lock.
    pub fn detach_on_tracer_exit(&self) -> bool {
        if !self.is_traced() {
            return false;
        }
        // Order: stop tracing first, then wake. A tracee that wakes while
        // `traced` is still set would take its *next* signal into another
        // stop, with no tracer to end it -- the same hang one level along.
        self.set_detached();
        self.set_stops_at_syscalls(false);
        // Any pending resume signal dies with the tracer that would have
        // chosen it.
        let _ = self.take_resume_signal();
        self.resume();
        true
    }
}
