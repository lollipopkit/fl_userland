//! Guest task state layout.

use std::sync::atomic::AtomicPtr;
use super::{creds, host_threads_state, ptrace_state, syscall_restart, task_cleanup, thread_attr};
use iul_abi::{cond_t, cpu_state, lock_t, pid_t_};
use fsinfo::FsInfo;
use kernel_sighand::SigHand;
use kernel_sigqueue::Signals;
use libc::{pid_t, pthread_t};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

// The host's `pid_t` and `pthread_t`, which `native_pid` and `thread` use. The
// guest's process identifiers use the distinct `pid_t_` alias above.

// ---------------------------------------------------------------------------
// The fields another thread reads or writes
// ---------------------------------------------------------------------------
//
// Each is its own type with `&self` methods, so `(*task).exiting.get()` borrows
// that one field. They were methods on `task` until 2026-10-02, and calling one
// formed a `&task` for the length of the call -- a shared reference to the
// whole struct while the task's own thread writes `cpu`, which is the
// unsoundness `crates/kernel/pids`' `Task` exists to avoid and then committed
// in its own `is_exiting`.

/// A one-way flag. `Relaxed`: its readers want the value and order nothing
/// against it. A reader that needs the flag *and* something the writer
/// published before it takes `pids_lock`, which every such reader already does.
#[derive(Debug, Default)]
pub struct Flag(AtomicBool);

/// [`task::thread`]: the host thread running a task, or none yet. Set once by
/// whoever starts it and read by other threads to signal it, so a word they
/// cannot see half of.
#[derive(Debug, Default)]
pub struct HostThread(std::sync::atomic::AtomicUsize);

impl HostThread {
    pub const fn none() -> HostThread {
        HostThread(std::sync::atomic::AtomicUsize::new(0))
    }
    /// The thread, or `None` before it has started.
    #[inline]
    pub fn get(&self) -> Option<pthread_t> {
        let t = self.0.load(Ordering::Acquire);
        (t != 0).then_some(t)
    }
    #[inline]
    pub fn set(&self, t: pthread_t) {
        self.0.store(t, Ordering::Release);
    }
}

impl Flag {
    pub const fn new(v: bool) -> Flag {
        Flag(AtomicBool::new(v))
    }
    #[inline]
    pub fn get(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
    #[inline]
    pub fn set(&self, v: bool) {
        self.0.store(v, Ordering::Relaxed);
    }
}

/// [`task::native_pid`]: the host pid a task is proxying for, as one word so
/// a reader cannot see half of a change. Zero is "none" in the word and `None`
/// at the interface.
#[derive(Debug, Default)]
pub struct ProxyPid(AtomicI32);

impl ProxyPid {
    #[inline]
    pub fn get(&self) -> Option<pid_t> {
        match self.0.load(Ordering::Relaxed) {
            0 => None,
            pid => Some(pid),
        }
    }
    #[inline]
    pub fn set(&self, pid: Option<pid_t>) {
        self.0.store(pid.unwrap_or(0), Ordering::Relaxed);
    }
}

/// [`task::native_offload_entry`]: the offload handler a task is inside.
///
/// `&'static` because the registry's entries are leaked and outlive every
/// task. `Relaxed`: the entry is immutable and already published when its
/// address is stored, so there is no other memory a reader needs with it.
#[derive(Debug, Default)]
pub struct OffloadSlot(AtomicPtr<offloadreg::Entry>);

impl OffloadSlot {
    #[inline]
    pub fn get(&self) -> Option<&'static offloadreg::Entry> {
        // SAFETY: null, or a leaked registry entry; only `set` writes it.
        unsafe { self.0.load(Ordering::Relaxed).as_ref() }
    }
    #[inline]
    pub fn set(&self, entry: Option<&'static offloadreg::Entry>) {
        self.0.store(
            entry.map_or(std::ptr::null_mut(), |e| std::ptr::from_ref(e).cast_mut()),
            Ordering::Relaxed,
        );
    }
}

/// A thread. One per guest thread, allocated by `crates/kernel/taskcalls` and
/// pointed at by the `current` thread-local, which is C's for the reason
/// CLAUDE.md measures.
///
/// The field comments came across from `kernel/task.h` with the fields: they
/// say what each one is locked by, and several record a defect that is
/// expensive to rediscover.
// **`#[repr(Rust)]` since 2026-09-09**, which is the default and so is spelled
// by the absence of a `repr(C)` above. Nothing depends on this layout: `iul.h`
// forward-declares `struct task;` and no C in this tree defines it, the
// gadgets index `struct cpu_state` and reach it as `(*task).cpu.get()`, and
// `cpu-offsets.h` is generated from `cpu_state` alone. Letting the compiler
// order the fields takes the struct from 1552 bytes to 1536.
//
// `#[repr(align(16))]` stays and is not decoration: `cpu_state` embeds
// `union arm64_vreg`, whose 128-bit lanes the SIMD gadgets address.
#[repr(align(16))]
// **Not `Copy` or `Clone`.** bindgen derives both on every struct and this one
// carried them across; the moment a field became an atomic they stopped meaning
// anything, because copying a `struct task` is not an operation this kernel has
// -- a task is created by `task_create_` and reached by pointer everywhere
// else. `task_cleanup` beside it lost them the same way when its four pointers
// became `AtomicPtr`.
pub struct task {
    pub cpu: std::cell::UnsafeCell<cpu_state>,
    /// The guest address space. **Two different things guard this field and
    /// neither replaces the other**, which is what one line saying "locked by
    /// general_lock" hid until 2026-09-11.
    ///
    /// - **`general_lock` keeps the object alive across a read.** A reader that
    ///   loads this and then clones the `Arc` must not observe a pointer whose
    ///   count has already reached zero, and `execve` and `do_exit` both
    ///   detach-then-release. The lock is what makes read-and-retain one step
    ///   against that; an atomic load cannot, because the release lands between
    ///   the two. `crates/fs/proc/src/pidmem.rs` names the reproduction:
    ///   `mm_release -> mem_destroy -> wrlock_destroy`, from a probe reading
    ///   `/proc/<pid>/statm` while other threads fork and exec. Five call sites
    ///   depend on it — four in `crates/fs/proc`, one in
    ///   `crates/kernel/procvmcalls`.
    /// - **The atomic slot keeps the word from being raced on.** The group-exit
    ///   valve nulls a *stuck sibling's* field from another thread
    ///   (`abandon_stuck_threads`), and readers run on the task's own
    ///   thread holding no lock at all: `current_mm`, `execcalls`' pre-swap
    ///   read and `forkcalls`' retain. Those cannot take `general_lock` — they are
    ///   ordinary syscall bodies — so a plain field here was a plain load
    ///   racing a plain store: UB by the language's rules, and unobserved only
    ///   because an aligned pointer store cannot tear on aarch64.
    ///
    /// That is the same argument `blocking` below and `task_cleanup`'s four
    /// pointers are converted under, and the point of making the *type* say so
    /// is that a plain access no longer compiles.
    ///
    /// An `ArcSlot` holding one count since 2026-10-16, as `files` is; the
    /// count was `struct mm`'s own `refcount`, kept by hand, and
    /// `ArcSlot::clone_arc` is the retain that needs `general_lock`.
    pub mm: util_arcslot::ArcSlot<iul_abi::mm>,
    // There was a `mem: *mut iul_abi::mem` here, "pointer to mm.mem, for
    // convenience". It was deleted on 2026-09-11: see `mem_of`, which is the
    // expression it cached, and the changelog beside it for the two ways the
    // two fields got out of step.
    pub thread: HostThread,
    // There was a `threadid: u64` here and **the whole repository named it
    // once** -- this declaration. Nothing wrote it and nothing read it, in any
    // revision of the Rust; it came across from `kernel/task.h` with the rest
    // of the fields on 2026-09-05 and was already dead there. Removed
    // 2026-09-12, found while naming every field of the struct for
    // `task_create_`'s `Box`.
    //
    // `tools/unread-fields.py` could not see it: it asks which fields are
    // *written and never read*, and a field that is never written either has
    // no write for it to start from.
    /// immutable
    pub group: AtomicPtr<super::tgroup>,
    /// The processors this thread may run on, from sched_setaffinity. A bit
    /// per processor, all set at first. Nothing here schedules by it -- the
    /// host does that and is not told -- but sched_setaffinity used to accept
    /// any mask and store nothing, so a program that pinned itself and read the
    /// mask back was told it had not. Locked by pids_lock.
    pub cpu_affinity: AtomicU64,
    /// prctl's per-thread attributes and personality, in crates/kernel/procattr:
    /// the thread name, the pdeath signal, no_new_privs, keepcaps and the
    /// personality. Locked by pids_lock -- which is a widening for `comm`, whose
    /// writers already took it and whose readers did not.
    ///
    /// `personality` and `no_new_privs` were on struct tgroup, and Linux keeps
    /// both on task_struct: one thread setting either reached its siblings.
    ///
    /// Behind a lock of its own since 2026-10-16. It was a plain field
    /// "locked by `pids_lock`", reached through a raw pointer at every writer
    /// and read on the task's own thread without the lock. The lock is the
    /// innermost one: nothing is taken while it is held.
    pub attr: locks::mutex::Mutex<thread_attr>,
    /// This task's count in its group's live-host-thread total, taken in
    /// copy_task under pids_lock -- so a task that exists is counted, with no
    /// window between being created and running. task_run_current moves it into
    /// the cleanup struct, which is what actually gives it back; task_destroy
    /// gives it back for a task that never ran.
    pub hosts: util_arcslot::ArcSlot<host_threads_state>,
    /// The thread id. Written once before publication, and once more by an
    /// `execve` from a thread that is not the leader, which takes the
    /// leader's number (Linux's `exchange_tids` in `de_thread`) under
    /// `pids_lock` once it is the only thread left. Atomic because the task's
    /// own thread reads it with no lock while others hold a `&task`.
    pub pid: AtomicI32,
    /// immutable
    pub tgid: AtomicI32,
    /// Who this task is: the real, effective and saved user and group ids, the
    /// ids a *filesystem* check is made against, the supplementary groups, and
    /// the user the RLIMIT_NPROC count was taken from. All of it in
    /// crates/kernel/creds, which owns the rules as well.
    ///
    /// One object rather than nine fields, because the fields have an invariant
    /// between them: `fsuid` and `fsgid` follow the effective ids on every
    /// change. That was three separate assignments here -- two setters and the
    /// execve transition -- and forgetting one leaves a process making file
    /// decisions with the id it had before its last setuid. There is no way to
    /// change an effective id now except through a call that carries the fs one
    /// along.
    ///
    /// Locked by `pids_lock`, and **since 2026-09-15 that is true of the
    /// writers too**.
    ///
    /// `nproc_uid` always was. The rest were written only by the task itself,
    /// with no lock, while `signaldeliver::signal_kill_task_for_rs` read the
    /// *whole set* under `pids_lock` to answer `creds_may_signal` — Linux's
    /// `kill_ok_by_cred`, which decides whether a `kill` is permitted.
    ///
    /// `Creds` is plain data: no atomic and no lock anywhere in
    /// `crates/kernel/creds`. So a process dropping privilege with
    /// `setresuid(1000, 1000, 1000)` presented `uid == 0` beside
    /// `suid == 1000` for the width of three stores, and a permission decision
    /// taken in that window matched neither the state before nor the state
    /// after. The ten writers take the lock now — see
    /// `crates/kernel/idcalls`'s `with_creds_locked`.
    ///
    /// An `UnsafeCell` since 2026-10-16, which is what the rule above is: the
    /// task's own thread reads it with no lock while it is the only writer, so
    /// a `&task` must not promise the bytes do not change.
    pub creds: std::cell::UnsafeCell<creds>,
    /// The thread name is `attr` above. It was `char comm[16]` here with
    /// __attribute__((nonstring)) -- which says it is not a C string and
    /// suppresses the truncation warning -- and that was not true of it: three
    /// printk("%s") sites and PR_GET_NAME read it as one, and two strncpy calls
    /// whose length was the whole array left it unterminated. A type that
    /// guarantees the sixteenth byte is zero cannot have that.
    /// for that one annoying setsid edge case
    /// This task has `execve`d. Written by its **own** thread with no lock —
    /// `crates/kernel/execcalls` and `crates/kernel/offloadexec` at the exec,
    /// `taskcalls` at creation — and read by **another** thread under
    /// `PidsGuard`: `setpgid`'s rule that a task which has exec'd may not be
    /// moved into another process group.
    ///
    /// A `bool` until 2026-09-15. The two sides never shared anything: the
    /// reader's lock is not one the writer takes, which is the same shape as
    /// `zombie` and `exiting` one commit earlier.
    pub did_exec: Flag,
    /// The descriptor table.
    ///
    /// **Two different claims, and only the first was ever true.**
    ///
    /// *Who may resurrect it.* `/proc/<pid>/fd` reads another task's table and
    /// retains it, and it must hold `pids_lock` across both — reading and then
    /// retaining without one is a resurrection. That
    /// rule stands and this atomic does not replace it.
    ///
    /// *Whether the word itself is raced on.* It is. `f_get` reads this field
    /// on **every descriptor syscall**, on the task's own thread, holding no
    /// lock, and the group-exit valve stores null into it from another thread.
    /// The valve's comment said this field was "excluded by `pids_lock`"; `f_get`
    /// is the counterexample. `AtomicPtr` since 2026-09-12, for exactly the
    /// reason `mm` became one on 2026-09-11.
    ///
    /// NULL for a task on its way out, which every reader has to expect. The
    /// table's *contents* are locked by the table's own mutex, which is a
    /// different thing and a different lock.
    ///
    /// *What the word is.* One `Arc<fdtable::Table>` count since 2026-09-12,
    /// where the table kept a `shares: AtomicUsize` of its own. **Not an
    /// `Option<Arc<Table>>`**, and the reason is the paragraph above: an owning
    /// field written under `pids_lock` puts a plain load back on the descriptor
    /// path, which is the defect this one was made atomic for. An
    /// [`util_arcslot::ArcSlot`] since 2026-10-16, where it was an `AtomicPtr`
    /// with `Arc::into_raw`/`from_raw` at every site that moved the count: the
    /// slot owns the count, and a task dropped with a table still in it gives
    /// the table back.
    pub files: util_arcslot::ArcSlot<iul_abi::fdtable>,
    // `syscall_refs` was here until 2026-10-16. It is a thread-local in
    // `crates/fs/fdobj` now: only this thread stored into it, and the valve's
    // hand-over put it in a cleanup this thread ran.
    /// The working directory, root and umask.
    ///
    /// Atomic for the same reason as `files`: `taskview::current_fs_info` reads
    /// it on every path syscall, on the task's own thread, holding no lock, and
    /// the valve stores null into it from another. The `pids_lock` rule about
    /// *resurrection* is as it was.
    ///
    /// An `ArcSlot` owning one count since 2026-10-16, as `files` is.
    pub fs: util_arcslot::ArcSlot<FsInfo>,
    /// The shared disposition table. What it *contains* is locked by
    /// `sighand->lock`, which is what this comment used to say and is a
    /// different thing from what the **field** is locked by.
    ///
    /// **An owning `Arc` since 2026-09-12**, where it was a `*mut SigHand`
    /// whose count `crates/kernel/sighand/src/abi.rs` maintained by hand with
    /// `Arc::into_raw`, `Arc::increment_strong_count` and `Arc::from_raw` at
    /// six sites. The object was always an `Arc`; what changed is that this
    /// field stops erasing one. Four hand-written obligations went with it —
    /// "release exactly once" across `detach_and_notify`, the valve and the
    /// cleanup handler; "`sighand_retain` at the `CLONE_SIGHAND` site pairs
    /// with a release somewhere"; "`hand_over` must not decrement"; and "the
    /// reader's use is safe because the object outlives the read".
    ///
    /// This field is written under `pids_lock`: at creation before the task is
    /// published, in `detach_and_notify` on the task's own thread, and in the
    /// group-exit valve's `abandon_stuck_threads` on *another* thread, which
    /// also takes this task's `general_lock`.
    ///
    /// **Nothing replaces a live thread's table after publication**, which is
    /// the property the thread-local cached reference in `current.rs` depends
    /// on and is the one thing here no type checks. `execve` mutates the object
    /// in place (`sighand_on_exec`) and `CLONE_SIGHAND` writes the *new* task's
    /// field; what can happen to a running thread's is that it is emptied. The
    /// grep is `rg -n '\(\*\w+\)\.sighand\s*=[^=]' --glob '*.rs' crates`, and
    /// a new writer in its output is a reason to re-read `set_current`.
    ///
    /// It was an `AtomicPtr` access on both sides between 2026-09-09 and
    /// 2026-09-12, because `signal_pending` loaded it from a parked thread
    /// holding no lock. That reader is gone: the running thread holds its own
    /// strong reference and reads *that*. So this field has no reader outside
    /// `pids_lock` any more and needs no atomic — which is the trade step 8 of
    /// `docs/object-model-arc.md` is, and is why the valve's hand-over is a
    /// plain move again.
    pub sighand: util_arcslot::ArcSlot<SigHand>,
    /// Which signals are blocked, which have arrived, and what arrived: the
    /// four masks and the queue, in crates/kernel/sigqueue. Locked by
    /// sighand->lock like the dispositions beside it.
    ///
    /// The real type since 2026-09-11, where it was an opaque `sigqueue_state`
    /// placeholder that every reader cast back. **Held by value since
    /// 2026-10-16**: it was a `*mut` to a `Box` that `task_create_` allocated
    /// and `task_destroy` freed -- the task's own lifetime, with an allocation,
    /// a free and a null check at every reader to say so. Reached through
    /// `&raw mut (*task).signals` where the lock is held, never through a
    /// reference to the task.
    /// An `UnsafeCell`: written under `sighand`'s lock while other threads hold
    /// a `&task`.
    pub signals: std::cell::UnsafeCell<Signals>,
    /// please don't signal this
    pub pause: cond_t,
    /// Set when this thread is in a blocking syscall (futex_wait, poll_wait,
    /// …). Used for deadlock detection: if every thread is blocking, it is a
    /// hang, and `crates/kernel/futexcalls`' stall diagnostic prints the state
    /// of each.
    ///
    /// **`AtomicBool`, for the same reason `task_cleanup`'s four pointers are
    /// `AtomicPtr`**: each thread writes its own, and the diagnostic reads
    /// *another* thread's while that thread is running. A plain `bool` there is
    /// a data race — harmless in practice on aarch64, where a byte load cannot
    /// tear, and UB by the language's rules either way. Making the type say so
    /// means a plain access does not compile. `Relaxed` on both sides: nothing
    /// is ordered against it, and a diagnostic that reads a value one
    /// instruction stale is a diagnostic that read a value one instruction
    /// stale.
    pub blocking: AtomicBool,
    /// There was an `int futex_pipe[2]` here: a pipe per thread that futex_wait
    /// parked on and futex_wake wrote a byte to. It is gone with the poll loop
    /// -- crates/kernel/futex parks on a condition variable, so a thread that
    /// has ever called futex no longer costs two file descriptors.
    /// There was a `uint64_t last_unblocked_ns` here, with a comment saying the
    /// deadlock detector used it to see how long the threads had been stuck.
    /// Nothing read it, in any revision: it was written at three sites, each
    /// time beside `group->last_progress_ns`, which is the value the detector
    /// actually reads. A per-*task* copy of a per-*group* answer.
    /// Uptime in hundredths of a second when this task was created, which is
    /// `/proc/<pid>/stat`'s field 22. `ps -o etime` and `top`'s process age are
    /// the uptime minus this; reporting zero, which this file did, dated every
    /// process to the boot and made them all as old as the machine. Written
    /// in task_create_, and by a non-leader `execve`, which takes the old
    /// leader's: the process is as old as it was (`execthreads_probe`).
    pub start_ticks: AtomicU64,
    /// Whether this task is traced, whether it is in signal-delivery-stop, and
    /// what stopped it -- with the lock and condition variable over them, in
    /// crates/kernel/ptrace. It was a seven-field sub-struct here and the only
    /// thing that read four of them was kernel/ptrace.c. `Some` for every task
    /// `task_create_` answered; `None` before that, and in a zeroed test task.
    ///
    /// A `Box::into_raw` until 2026-09-30, freed by hand in `task_destroy`.
    /// Not by value, because `Ptrace` holds a `GuestLock`, whose `Box` makes
    /// the zeroed `struct task` three tests build an invalid value.
    pub ptrace: Option<Box<ptrace_state>>,
    /// The seccomp mode and filter chain. Written by the task's own thread,
    /// and by another thread of its group only for `TSYNC`, under
    /// `pids_lock`; read lock-free on every syscall -- see
    /// `crates/kernel/seccomp` for why that read is sound.
    pub seccomp: kernel_seccomp::State,
    /// The namespaces this task is in. Replaced only by the task's own
    /// thread (`unshare`, `setns`), which also reads it through a cache
    /// (`with_current_nsproxy`); read by others (`/proc/<pid>/ns`, `setns`
    /// through a pidfd), which is why it is behind a lock.
    pub nsproxy: locks::mutex::Mutex<std::sync::Arc<kernel_nsproxy::NsProxy>>,
    /// Who this task's parent is and which tasks are its children live in
    /// crates/kernel/proctree, keyed by the task pointer and still locked by
    /// pids_lock. They were a `parent` pointer and two intrusive list links
    /// here. There is no header for it: every caller is Rust and calls the
    /// crate directly, so kernel/proctree.h went on 2026-09-05.
    ///
    pub clear_tid: AtomicU64,
    /// `set_robust_list`'s head. Written by the task's own thread; read by
    /// `get_robust_list` from any task that may ptrace this one, so not a
    /// thread_local, which it was from 2026-09 until 2026-11-13.
    pub robust_list: AtomicU64,
    /// `/proc/<pid>/io`'s counters; written by the task's own thread.
    pub io: kernel_observe::IoAccounting,
    /// The call `/proc/<pid>/syscall` reports; written by the task's own
    /// thread on every system call.
    pub syscall: kernel_observe::SyscallState,
    /// SA_RESTART support: on each syscall entry we snapshot the number and the
    /// first arg (x0/ebx), which the return value overwrites. If the syscall is
    /// interrupted (returns EINTR) and a signal with SA_RESTART is then
    /// delivered, receive_signals rewinds PC to the syscall instruction and
    /// restores the original first arg so the syscall re-executes — matching
    /// Linux. Without it, JSC's SIGPWR-based GC safepoint handshake (which
    /// registers SA_RESTART) livelocks on a futex that keeps returning EINTR.
    /// What an interrupted syscall needs to be run again, in
    /// crates/kernel/syscallrestart. It was four fields and twelve lines of
    /// comment saying why checking the flag alone is unsafe: the flag is sticky,
    /// and a later interrupt that is not a syscall runs the same delivery path,
    /// so a new SA_RESTART signal then would rewind the pc into ordinary code.
    /// The object is asked whether a rewind is due *at the pc the machine is at*
    /// and answers with the arguments or nothing; the flag is not reachable.
    ///
    /// `syscall_restart_num` was a fifth field. Nothing read it.
    /// Only this task's thread touches it, while others may hold a `&task`.
    pub restart: std::cell::UnsafeCell<syscall_restart>,
    /// locked by pids_lock
    pub exit_code: AtomicU32,
    /// Reaped-but-not-waited-for. Written once by `exitcalls`' reaping path,
    /// read by eleven places across `waitcalls`, `signaldeliver`, `fs/proc`,
    /// `taskcalls` and `taskview` -- some inside `PidsGuard` and some not.
    ///
    /// A plain `bool` under a shared `/// locked by pids_lock` comment until
    /// 2026-09-15, which was true of the writer and of only some readers. See
    /// [`task::exiting`], which is the same field one step worse.
    pub zombie: Flag,
    /// **This thread has been told to stop.** The whole point of the field is
    /// that *another* thread sets it: `exitcalls`' group-exit valve walks the
    /// group writing `exiting = true` on every member's task, and the member
    /// reads it in `syscalldispatch`'s syscall entry -- a hot path that cannot
    /// take a lock for one bool.
    ///
    /// So the writer and the reader are different threads and neither held
    /// anything. It was a `bool` until 2026-09-15; a field that exists to
    /// carry a signal between threads should always have been atomic.
    pub exiting: Flag,
    /// [T-ish-mm-leak-refcount-handoff] Set by the do_exit_group safety valve
    /// when it orphans a thread stuck in an uninterruptible host syscall: the
    /// valve can't mm_release() now (the thread may still hold the mm's own
    /// mem->lock inside user_write → UAF, see T-ish-mem-uaf-user-write), so it
    /// hands the release
    /// off to this thread's own pthread cleanup handler, which runs only after
    /// the thread has left the read_wrlock critical section. Prevents the mm
    /// (whole guest address space) from leaking forever when the thread never
    /// re-enters do_exit(). Cleared once released so it never double-frees.
    /// Where the safety valve hands the release over to, and where the thread's
    /// own pthread cleanup handler reads it from. See struct task_cleanup.
    ///
    /// **`AtomicPtr` since 2026-09-15.** The six fields *inside*
    /// `task_cleanup` were made atomic because the group-exit valve hands them
    /// over from another thread; the pointer to them was not, and it crosses
    /// the same boundary. `crates/kernel/taskcalls`' `task_run_current` writes
    /// it on the thread's own entry with **no lock**, and
    /// `crates/kernel/exitcalls`' valve reads it under that task's
    /// `general_lock` — no lock in common.
    ///
    /// The null the reader tests for is a real state, not only a
    /// memory-model artefact: a task joins its group before
    /// `task_run_current` runs, so the valve can legitimately arrive first.
    /// That was handled; what was not is that a non-atomic pointer written by
    /// one thread and read by another is undefined however the values fall.
    ///
    /// `Relaxed` on both sides: the record's own fields are atomics with
    /// their own hand-over, so nothing else has to become visible with the
    /// pointer.
    pub cleanup: AtomicPtr<task_cleanup>,
    /// Same handoff, for the descriptor table and the syscall-scoped references
    /// taken from it. Set by the do_exit_group safety valve when it orphans a
    /// thread stuck in a host syscall; acted on by that thread's own pthread
    /// cleanup handler, which runs only once the host thread has terminated.
    ///
    /// The vfork one-shot this task's parent is waiting on, or NULL. The task
    /// owns this reference and gives it back in vfork_notify, which is also
    /// where it is cleared -- crates/kernel/vforkhandoff.
    ///
    /// It used to be a pointer to a `struct vfork_info` on the *parent's stack
    /// frame*, with nothing but the wait loop's correctness keeping the frame
    /// alive under it. An Arc on each side has no such proof obligation.
    /// An `Option<Arc>` since 2026-09-30, where it was an `Arc::into_raw`
    /// handle released by hand. A clone that failed after taking one --
    /// `CLONE_PIDFD` with no descriptor to give -- destroyed the child without
    /// releasing it; the drop in `task_destroy` gives it back now.
    pub vfork: util_arcslot::ArcSlot<kernel_vforkhandoff::Handoff>,
    pub exit_signal: AtomicI32,
    /// `mm` and `vfork`, and nothing else. It reads like struct tgroup's lock did
    /// -- "everything not covered by some other lock" -- and it is not the same:
    /// that one was deleted because every acquisition already held pids_lock,
    /// and this one is taken by execve and by do_exit while they do *not*. It is
    /// the only thing stopping procfs, which takes both, from retaining an mm
    /// that a swap is about to free.
    ///
    /// `comm` was here and is in `attr` under pids_lock now -- it had two locks,
    /// general_lock at the two execve sites and pids_lock in prctl and /proc,
    /// which is to say it had none.
    pub general_lock: lock_t,
    /// Native offload, `posix_spawn` shape: the host pid this task is waiting
    /// for instead of running emulated code, or zero when it is not a proxy.
    ///
    /// **Two fields until 2026-09-15** — a `pid_t` and an `is_native_proxy:
    /// bool` — written by the task's own thread in
    /// `crates/kernel/offloadexec`'s spawn path and read by *another* thread
    /// in `native_offload_forward_signal`, which `signaldeliver` reaches
    /// through a hook when a signal is delivered to this task. Neither side
    /// held a lock.
    ///
    /// The pair had to agree, and the only read tested both:
    /// `is_native_proxy && native_pid > 0`. The writes were in a careful order
    /// — pid before flag on setup, flag before pid on teardown — which plain
    /// stores do not deliver: nothing stops the compiler or the CPU
    /// reordering them, and the reader has no acquire. A reader seeing the
    /// flag without the pid drops the signal; seeing a stale pid after
    /// teardown signals whatever host process now holds that number.
    ///
    /// One atomic word makes the disagreement unrepresentable, and
    /// [`ProxyPid::get`] presents it as `Option<pid_t>` so the zero
    /// is not a sentinel a caller has to know about. `Relaxed` is enough
    /// because the value **is** the whole handoff now: the host process
    /// already exists when the pid is stored, so there is no other memory for
    /// a reader to need alongside it.
    pub native_pid: ProxyPid,
    /// [T-ish-offload-signal-forward] Set while this task is executing an
    /// IN-PROCESS offload handler (native_offload_add_handler). Distinct from
    /// is_native_proxy, which covers only the posix_spawn shape: a handler runs
    /// on this very thread with no host pid, so a signal can't be forwarded with
    /// kill() — it has to go through the handler's abort callback instead.
    /// Opaque address into the static offload registry, which lives for the
    /// process lifetime, so it never dangles. Zero when not in a handler.
    /// The offload entry this thread is running, so a signal can reach its
    /// abort callback while the handler is in flight. Points into
    /// crates/kernel/offloadreg, whose entries are leaked and so outlive every
    /// task. NULL except during the call.
    /// **Written by this task's own thread** on entering and leaving the
    /// handler, and **read by another thread** in
    /// `native_offload_forward_signal` — the same function whose other shape
    /// reads [`task::native_pid`], converted one commit earlier and this one
    /// missed, because that sweep followed the `native_pid` grep rather than
    /// the function.
    ///
    /// A `*const` until 2026-09-15; `AtomicPtr` now, and
    /// [`OffloadSlot::get`] answers `Option<&'static Entry>` so the
    /// null is not a sentinel the reader tests by hand.
    pub native_offload_entry: OffloadSlot,
    /// What this task is blocked on, so a signal can wake it: the condition
    /// variable it is inside, under a lock of its own.
    ///
    /// There was a `lock_t *waiting_lock` beside it, set to the mutex the
    /// condition goes with -- and read nowhere, in any revision. The signal path
    /// says why: it deliberately does *not* take that mutex, because the target
    /// thread holds it inside pthread_cond_wait and spinning on it would stop
    /// the wait it is trying to end. A broadcast without the mutex costs at most
    /// a spurious wakeup, which every wait here re-checks for.
    ///
    /// A pointer and a `lock_t` beside it until 2026-10-16; the lock owns the
    /// field now, so it cannot be read without it.
    pub waiting_cond: locks::mutex::Mutex<Option<std::ptr::NonNull<cond_t>>>,
    /// Stacked Landlock domains restricting this task (`Arc<Vec<RulesetInner>>`
    /// owned by `kernel-misccalls`). Cloned across `fork`/`clone` and preserved
    /// across `execve`; dropped when the task is destroyed.
    pub landlock: locks::mutex::Mutex<Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>>,
}

impl task {
    /// See [`task::pid`].
    #[inline]
    pub fn pid(&self) -> pid_t_ {
        self.pid.load(Ordering::Relaxed)
    }

    /// See [`task::start_ticks`].
    #[inline]
    pub fn start_ticks(&self) -> u64 {
        self.start_ticks.load(Ordering::Relaxed)
    }

    /// See [`task::nsproxy`].
    pub fn nsproxy(&self) -> std::sync::Arc<kernel_nsproxy::NsProxy> {
        std::sync::Arc::clone(&locks::locked!(&self.nsproxy))
    }

    /// Replace this task's namespaces: on its own thread only, which is what
    /// keeps that thread's cache ([`crate::with_current_nsproxy`]) right. The
    /// old proxy is dropped after the lock is released.
    pub fn set_nsproxy(&self, ns: std::sync::Arc<kernel_nsproxy::NsProxy>) {
        debug_assert!(std::ptr::eq(self, crate::current()), "a task's namespaces are changed by its own thread");
        let old = std::mem::replace(&mut *locks::locked!(&self.nsproxy), std::sync::Arc::clone(&ns));
        crate::task_types::current::refresh_current_nsproxy(ns);
        drop(old);
    }

    /// Current stacked Landlock domains protecting this task, if any.
    pub fn landlock_domains(&self) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
        locks::locked!(&self.landlock).clone()
    }

    /// Replace this task's stacked Landlock domains, dropping the previous
    /// domain vector outside the lock.
    pub fn replace_landlock_domains(
        &self,
        next: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    ) {
        debug_assert!(std::ptr::eq(self, crate::current()), "a task's Landlock domain is changed by its own thread");
        let old = std::mem::replace(&mut *locks::locked!(&self.landlock), next);
        drop(old);
    }
}
