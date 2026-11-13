//! Thread-group state layout.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};
use super::{ctty, group_exit, host_threads_state, posix_timers_state, proc_attr, task};
use iul_abi::{cond_t, group_rusage, group_stop, int_t, itimer, pid_t_};
use kernel_rlimitstate::Limits;
use std::sync::atomic::AtomicU64;

/// A thread group — a process, as a guest sees one.
///
/// **Not `Copy`**, which bindgen made it and which was never true: `exit` is a
/// `GroupExit`, whose one field is an `AtomicU64` holding the exiting flag and
/// the status in one word so that a reader cannot see them apart. Copying a
/// group would copy that atomic by value, which is exactly the thing the type
/// exists to prevent. C said nothing either way; the Rust type does.
///
/// **A `&tgroup` is sound while the group lives, since 2026-09-30.** Its
/// threads read `sid()`, `pgid()` and their limits with no lock, through a
/// shared reference to the whole struct, while other threads write it --
/// which is sound only if every byte another thread writes is behind an
/// atomic, a lock or a cell. `limits`, `attr` and `nice` were plain fields
/// written under `pids_lock` until that day; the lock orders the writers and
/// says nothing to a reader that does not take it. What is left plain is
/// written once, before any thread can reach the group (`leader`,
/// `fs_context`), or only at teardown, when no thread is left
/// (`posix_timers`).
#[repr(C)]
#[derive(Debug)]
pub struct tgroup {
    /// Which tasks are in this group lives in crates/kernel/proctree. It was a
    /// `struct list threads` here whose comment said "locked by pids_lock, by
    /// majority vote" -- accurate, and the reason it moved.
    ///
    /// Written before the group is registered, and by an `execve` from a
    /// thread that is not the leader, which becomes it (Linux's `de_thread`),
    /// under `pids_lock`. Every reader of another group's holds that lock.
    pub leader: AtomicPtr<task>,
    /// Written under `pids_lock` by `setpgid` and `setsid`, and **read
    /// without it** by `taskview::current_pgid`, which `sys_wait4`
    /// calls to map its `id == 0` argument before `do_wait` takes the guard.
    ///
    /// `pid_t_` with a `/// locked by pids_lock` comment until 2026-09-15 —
    /// true of every writer and of every reader but that one, which made the
    /// comment the whole of the protection. `AtomicI32` now, so the lock-free
    /// read is defined rather than merely aligned.
    ///
    /// Taking the guard in `current_pgid` instead is not available: it costs
    /// a global acquisition on every `wait4(0, …)` for one word, and the
    /// caller goes on to take the same non-reentrant lock a few frames later.
    pub sid: AtomicI32,
    /// See [`tgroup::sid`].
    pub pgid: AtomicI32,
    /// Which process group and session this is in lives in crates/kernel/pids
    /// now, keyed by the number rather than threaded through the pid entry --
    /// see kernel/pidreg.h for why. `pgid` and `sid` above are the cached copies
    /// and the groupcalls setters are their only writers.
    ///
    /// prctl state that belongs to the process rather than a thread, in
    /// crates/kernel/procattr and locked by pids_lock: `child_subreaper`, which
    /// makes this group the one an orphaned descendant reparents to instead of
    /// pid 1, and `dumpable`, which Linux keeps in mm->flags -- the same thing
    /// here, since every thread of a group shares an mm.
    ///
    /// `no_new_privs` was here and is per *thread* on Linux; it moved to
    /// struct task with the rest of the per-thread attributes.
    pub attr: proc_attr,
    /// The nice value, -20..19, locked by pids_lock. Nothing here schedules by
    /// it -- the host does the scheduling and is not told. It is kept because
    /// setpriority used to report success and change nothing, so a program that
    /// set its priority and read it back was contradicted by the next call.
    /// Remembering what the guest was told is the least this can do; per-thread
    /// nice, which Linux has, is not distinguished.
    ///
    /// Atomic since 2026-09-30, like `attr`: see `ProcAttr` for why a field
    /// written under `pids_lock` still cannot be a plain one here.
    pub nice: AtomicI32,
    /// `/proc/<pid>/oom_score_adj`, -1000..=1000, and the floor only a
    /// `CAP_SYS_RESOURCE` writer may go below. Per process and inherited by
    /// fork, as Linux's live in `signal_struct`. Nothing here acts on them;
    /// see `crates/fs/proc`'s `oom`.
    pub oom_score_adj: AtomicI32,
    pub oom_score_adj_min: AtomicI32,
    /// Whether this group is stopped, what it reports to `wait`, and whether
    /// the continue that restarted it has been reported yet -- in
    /// crates/kernel/groupstop, with its own lock and condition variable.
    ///
    /// It was four fields and a cond_t here (`stopped`, `continued`,
    /// `continue_pending`, `stopped_cond`) plus the stop status over in `exit`,
    /// and every reader carried a comment saying that the flag and the status
    /// are one answer and have to be read under one lock. They are one object
    /// now, so there is no way to reach either without the other.
    ///
    /// Held by value since 2026-09-30, with `ctty`, `itimer` and `times`. It
    /// drops with the struct, after `crates/kernel/exitcalls`' teardown has
    /// destroyed `child_exit` -- the order that teardown's comment asks for --
    /// and its lock's destructor still aborts on a waiter left parked in it.
    pub stop: group_stop,
    /// The controlling terminal this group holds a reference to, with the lock
    /// over it -- crates/kernel/ctty. It was `struct tty *tty` under `lock`
    /// below, and the retain and the store were two statements a caller had to
    /// remember to keep together.
    ///
    /// Held by value since 2026-09-30. It was a `Box::into_raw` that
    /// `tgroup_new` allocated, both teardown paths freed, and every reader
    /// dereferenced as `&*(*group).ctty` -- a second allocation and a null
    /// state for an object that is a lock and an `Option`, and that lives
    /// exactly as long as the group.
    pub ctty: ctty,
    /// The one interval timer this group can have armed -- crates/kernel/itimer,
    /// which holds the handle and nothing else. It was a `timer_id_t` here under
    /// `lock` below, and what that lock was doing was keeping the lazy creation
    /// from happening twice: setting and reading a timer is crates/util/timer's
    /// own to serialise, and it does.
    ///
    /// Held by value since 2026-09-30, like `ctty` and `times`: an `AtomicU64`
    /// that was a separate allocation, with a null state no reader could meet.
    pub itimer: itimer,
    /// The POSIX timers this group has, in crates/kernel/posixtimers, with
    /// their own lock: `lock` below is deliberately *not* held for any of it.
    ///
    /// `Some` for every live group. An `Option<Box>` rather than by value
    /// because `crates/kernel/exitcalls` takes it out under `pids_lock` and
    /// drops it after, since dropping one waits for an expiry that needs that
    /// lock. A `Box::into_raw` until 2026-09-30.
    pub posix_timers: Option<Box<posix_timers_state>>,
    /// The sixteen limits, `crates/kernel/rlimitstate`'s. Written under
    /// `pids_lock` and read without it by the group's own threads, so the table
    /// is atomic; it said "locked by `lock` below" for a month after that lock
    /// was deleted.
    pub limits: Limits,
    /// From <https://twitter.com/tblodt/status/957706819236904960>
    /// > there are two distinct ways for a p̶r̶o̶c̶e̶s̶s̶ thread group to exit:
    /// >
    /// > - each thread calls exit
    /// > wait will return the exit code for the group leader
    /// >
    /// > - any thread calls exit_group
    /// > the SIGNAL_GROUP_EXIT flag will be set and wait will return the status passed to exit_group
    ///
    /// Whether this group is exiting, with what status, and what a *stopped*
    /// one reports to wait -- in crates/kernel/groupexit.
    ///
    /// It was `bool doing_group_exit` and `dword_t group_exit_code` with a
    /// `// TODO locking` on them, written under `lock` below in that order and
    /// read in four places with no lock at all: the JIT quantum check, the
    /// syscall return, the futex wait and the poll wait. Two plain stores in
    /// that order are not ordered against two plain loads on aarch64, so a
    /// reader could see the flag set and the *old* status -- a thread killed by
    /// a group exit leaving with the wrong code. The flag and the status are one
    /// word now, so there is nothing left to order.
    ///
    /// The status also meant two things: SIGNAL_STOP wrote a stop status into
    /// the same field. Separate there.
    pub exit: group_exit,
    /// Once V8 prints a fatal-abort prefix to stderr (e.g. "abort: " or
    /// "# Fatal error"), suppress every subsequent stderr write from the
    /// group. The process is about to BRK anyway — further output is noise.
    /// Cleared on execve (new program state).
    /// V8 printed its abort banner: set by whichever thread wrote it, read by
    /// whichever thread then takes the fatal signal.
    ///
    /// A plain `bool` until 2026-09-15, written with no lock in
    /// `crates/kernel/v8mute` and `crates/kernel/execcalls` and read with no
    /// lock in `crates/kernel/signaldeliver`'s `terminate`. **Those are
    /// different threads of one group** — a V8 worker prints the banner and
    /// the thread that faults is the one that reports it — so the flag
    /// crossed between them on nothing at all.
    ///
    /// What it decides is which diagnostics a crash gets, not how the guest
    /// runs, which is why a lost write would never have been noticed.
    pub v8_aborting: AtomicBool,
    /// Linux's `SIGNAL_UNKILLABLE`: this is the first process, its
    /// namespace's init, and a signal it has not caught does nothing to it
    /// -- discarded when sent, skipped when taken. Every guest sender is in
    /// that namespace, so `SIGKILL` and `SIGSTOP` are no exception; only the
    /// embedder, which stands where an ancestor namespace would, gets those
    /// through. Cleared by a fault nothing handles, as Linux's
    /// `force_sig_info_to_task` clears it (`sigfatal_probe`).
    pub unkillable: AtomicBool,
    /// What this group's exited threads and reaped children consumed, with the
    /// lock over them -- crates/kernel/grouprusage. It was `rusage` and
    /// `children_rusage` under `lock` below, and the arithmetic that added to
    /// them carried between a seconds field and a microseconds field. The
    /// accumulators are one number each now, so there is nothing to carry.
    ///
    /// Held by value since 2026-09-30. It was a `Box::into_raw`, and the four
    /// readers each had an arm for the null no live group has.
    pub times: group_rusage,
    pub child_exit: cond_t,
    /// There was an `atomic_uint syscall_count` here, incremented on every
    /// syscall for deadlock detection and never loaded. `last_progress_ns`
    /// below is the value the detector actually reads.
    /// Timestamp of last real progress (non-blocking syscall completion).
    /// Updated atomically. Used by futex/poll safety valves to detect
    /// process-wide hangs where all threads are idle.
    pub last_progress_ns: AtomicU64,
    /// Opaque per-thread-group context for host integrations (e.g. fakefs
    /// path-translate hook). Inherited verbatim on fork via tgroup_copy().
    /// iul itself never interprets this value; host registers a meaning.
    pub fs_context: u64,
    /// How many host threads this group still has running -- which is not the
    /// same question as which tasks are in the thread list, because a task
    /// leaves that partway through do_exit and its pthread keeps unwinding
    /// afterwards. crates/kernel/hostthreads; refcounted, so a thread the
    /// group-exit valve gave up on can still report in after this is freed.
    pub hosts: std::sync::Arc<host_threads_state>,
    /// The signals sent to the process rather than to one of its threads --
    /// `kill`, `sigqueue`, a timer, `SIGCHLD`, a terminal's `^C` -- which any
    /// thread that does not block one may take: Linux's
    /// `signal->shared_pending`, `ShdPnd` in `/proc/<pid>/status`.
    ///
    /// Locked by the sighand lock of the group's threads, which all share one
    /// table (`CLONE_THREAD` requires `CLONE_SIGHAND`); reached only through
    /// `kernel_sighand::Queue`, which takes it. Until 2026-11-12 there was no
    /// such set: a process-directed signal was queued on whichever thread was
    /// chosen when it was sent, so one that every thread blocked stayed on the
    /// leader for good when another thread unblocked it (`sigshared_probe`).
    pub shared_signals: std::cell::UnsafeCell<kernel_sigqueue::Pending>,
    // for everything in this struct not locked by something else
    // `lock_t lock` was here, and it is gone. It was the lock everything
    // without one of its own ended up under, and everything has one now: the
    // thread list is crates/kernel/proctree, whose protocol is pids_lock; the
    // limits, the timers, the stop, the times, the terminal and the interval
    // timer are each a Rust object with its own; and the exit word is one
    // atomic.
    //
    // What settled it is that **every one of its eleven acquisitions held
    // pids_lock already**, and two threads holding one global lock cannot run
    // at once -- so the inner lock excluded nothing that the outer had not
    // excluded first.
}

impl tgroup {
    /// See [`tgroup::leader`].
    pub fn leader(&self) -> *mut task {
        self.leader.load(Ordering::Acquire)
    }

    /// See [`tgroup::sid`]. `Relaxed`: the two ids are independent words a
    /// guest reads one syscall at a time, and nothing is ordered against them.
    pub fn sid(&self) -> pid_t_ {
        self.sid.load(Ordering::Relaxed)
    }
    pub fn set_sid(&self, v: pid_t_) {
        self.sid.store(v, Ordering::Relaxed);
    }
    pub fn pgid(&self) -> pid_t_ {
        self.pgid.load(Ordering::Relaxed)
    }
    pub fn set_pgid(&self, v: pid_t_) {
        self.pgid.store(v, Ordering::Relaxed);
    }

    /// See [`tgroup::nice`].
    pub fn nice(&self) -> int_t {
        self.nice.load(Ordering::Relaxed)
    }
    pub fn set_nice(&self, v: int_t) {
        self.nice.store(v, Ordering::Relaxed);
    }

    /// See [`tgroup::oom_score_adj`].
    pub fn oom_score_adj(&self) -> int_t {
        self.oom_score_adj.load(Ordering::Relaxed)
    }
    pub fn oom_score_adj_min(&self) -> int_t {
        self.oom_score_adj_min.load(Ordering::Relaxed)
    }

    /// See [`tgroup::v8_aborting`]. `Relaxed`: it is a one-way flag whose
    /// readers want the value and order nothing against it.
    pub fn v8_aborting(&self) -> bool {
        self.v8_aborting.load(Ordering::Relaxed)
    }
    pub fn set_v8_aborting(&self, v: bool) {
        self.v8_aborting.store(v, Ordering::Relaxed);
    }

    /// See [`tgroup::unkillable`]. `Relaxed`: set before the first guest
    /// instruction, and cleared only on the way to the process's death.
    pub fn unkillable(&self) -> bool {
        self.unkillable.load(Ordering::Relaxed)
    }
    pub fn set_unkillable(&self, v: bool) {
        self.unkillable.store(v, Ordering::Relaxed);
    }
}
