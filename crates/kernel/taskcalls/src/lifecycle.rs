//! Task creation, registration rollback, and destruction.

use std::sync::atomic::Ordering;
use kernel_pids::PidsHeld;
use std::sync::atomic::AtomicBool;
use super::*;

// ---------------------------------------------------------------------------
// Making a task
// ---------------------------------------------------------------------------

/// The number of tasks one user may have, `crates/kernel/pids`. The count is
/// taken where a task is created and given back where one is destroyed, and
/// this is its only caller.
use kernel_pids::{proccount_remove, proccount_try_add};

/// How many `struct task` allocations exist, for `/proc/iul/objects`.
///
/// **Not the same number as `task` in that file**, which counts
/// `crates/kernel/proctree`'s registry entries. This one includes the tasks
/// [`task_destroy`] has poisoned and not yet freed — up to [`DEFERRED_MAX`] of
/// them, and one at rest — so a healthy guest sits at "live tasks plus one"
/// rather than at "live tasks". A *leak* is the number climbing with the fork
/// count, which is what `tests/guest/src/bin/eventfd_leak.rs` asks.
static LIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many `struct task` allocations exist. See [`LIVE`].
pub fn task_live_count() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// The first process's task: **every field named**, and every zero a decision
/// somebody made rather than a side effect of `calloc`.
///
/// `libc::calloc` named fifteen of the thirty-four until 2026-09-12 and left
/// the rest zeroed. Writing them out is what makes the compiler ask about the
/// next field somebody adds, and it found one that had never been asked about:
/// `attr` is `ThreadAttr::default()` here, where zero is `timer_slack` 0
/// against 50 µs (and was the bounding set empty until that moved to the
/// credentials on 2026-11-13). Nothing was
/// wrong: `crates/kernel/boot`'s `construct_task` calls `ThreadAttr::init`
/// immediately after this for a second reason — `become_new_init_child` passes
/// a real parent, so the fork arm copies init's attributes and they have to be
/// reset either way — and that call stays. What changes is that the parentless
/// arm no longer *depends* on it.
///
/// Only the first process reaches this. Every other task is [`forked_task`],
/// which is the same literal with the parent's fields in it.
pub fn blank_task() -> ffi::task {
    ffi::task {
        // Registers, flags, and the pointer the gadgets reach the page table
        // through. `cpu_state::default()` names its own fields;
        // `task_create_` overwrites `excl_addr` and the poke flag after this.
        cpu: std::cell::UnsafeCell::new(ffi::cpu_state::default()),
        // The address space, installed by `construct_task`'s `task_set_mm`.
        mm: taskview::ArcSlot::empty(),
        // **Null means "no host thread has been created for this task"**, and
        // for the CLI's first process that stays true: `crates/tools/iul` runs
        // `task_run_current` on the process's own main thread rather than
        // calling `task_start`. An embedder that calls `task_start` gets the
        // pthread id there. Nothing reads the field except
        // `task_interrupt_host_call`, which passes it to `pthread_kill`.
        thread: ffi::HostThread::none(),
        // The thread group, built and installed by the caller.
        group: std::sync::atomic::AtomicPtr::new(std::ptr::null_mut()),
        // **0 is "has never asked", not "no processor"**, and it is deliberate:
        // `sched_getaffinity` answers every online processor for a zero, so a
        // task copied from another inherits its parent's mask rather than a
        // snapshot taken at creation. That is what Linux does; see
        // `crates/kernel/rescalls`' `sys_sched_getaffinity`.
        cpu_affinity: std::sync::atomic::AtomicU64::new(0),
        // See the note above: the zeroed value is not this one.
        attr: locks::mutex::Mutex::new(ffi::thread_attr::default()),
        // This task's count in its group's live-host-thread total, taken by the
        // caller once the group exists.
        hosts: taskview::ArcSlot::empty(),
        // Assigned by `task_create_` from the number it reserved.
        pid: std::sync::atomic::AtomicI32::new(0),
        // The caller's: `construct_task` sets it to `pid`, `copy_task` to the
        // group leader's. There is no task for which 0 is the answer.
        tgid: std::sync::atomic::AtomicI32::new(0),
        // Root, which is what the first process is: `Creds::default()` is
        // `init_cred`, uid 0 with full permitted, effective and bounding sets
        // and empty inheritable and ambient ones -- a root login's.
        creds: std::cell::UnsafeCell::new(ffi::creds::default()),
        did_exec: ffi::Flag::new(false),
        // The descriptor table and the working directory, `construct_task`'s.
        files: taskview::ArcSlot::empty(),
        fs: taskview::ArcSlot::empty(),
        // The disposition table, `construct_task`'s, and an empty signal
        // queue, which `task_create_` fills with what a child inherits.
        sighand: taskview::ArcSlot::empty(),
        signals: std::cell::UnsafeCell::new(kernel_sigqueue::Signals::default()),
        pause: ffi::cond_t::default(),
        blocking: std::sync::atomic::AtomicBool::new(false),
        // Overwritten by `task_create_` with the uptime; 0 would date the
        // process to the boot.
        start_ticks: std::sync::atomic::AtomicU64::new(0),
        // Made at the bottom of `task_create_`.
        ptrace: None,
        // No filter: the first process starts unconfined.
        seccomp: kernel_seccomp::State::new(),
        nsproxy: locks::mutex::Mutex::new(taskview::nsproxy::NsProxy::initial()),
        // `set_tid_address`'s futex word. 0 is "none", which is the state a
        // process starts in.
        clear_tid: std::sync::atomic::AtomicU64::new(0),
        robust_list: std::sync::atomic::AtomicU64::new(0),
        io: kernel_observe::IoAccounting::new_process(),
        syscall: kernel_observe::SyscallState::default(),
        // Nothing to restart: this task has not made a syscall yet.
        restart: std::cell::UnsafeCell::new(ffi::syscall_restart::default()),
        exit_code: std::sync::atomic::AtomicU32::new(0),
        zombie: ffi::Flag::new(false),
        exiting: ffi::Flag::new(false),
        // The pthread cleanup handoff, allocated by `task_run_current` on the
        // thread that runs this task.
        cleanup: AtomicPtr::new(std::ptr::null_mut()),
        // The `vfork` one-shot a parent waits on. The first process has no
        // parent; `copy_task` clears it for every other task.
        vfork: taskview::ArcSlot::empty(),
        // What the parent is told when this exits. The first process has no
        // parent to tell; `copy_task` sets a child's from `clone`'s flags.
        exit_signal: std::sync::atomic::AtomicI32::new(0),
        general_lock: ffi::lock_t::default(),
        // Native offload: no host process, no in-flight handler.
        native_pid: ffi::ProxyPid::default(),
        native_offload_entry: ffi::OffloadSlot::default(),
        // Not parked on anything yet.
        waiting_cond: locks::mutex::Mutex::new(None),
    }
}

/// A child's task: **every field named**, each either the parent's or fresh,
/// with the reason beside it.
///
/// It was `ptr::copy_nonoverlapping(parent, child, 1)` until 2026-09-30, then
/// a `ptr::write` over each of the four fields that own something (`sighand`,
/// `hosts`, `ptrace`, `vfork`), then a dozen assignments undoing what must not
/// be shared. That default was backwards: a field added to `struct task` was
/// silently the parent's, and one that owned something -- an `Arc`, a `Box`
/// -- was **two owners of one count** unless somebody remembered a line here.
/// `tools/fork-inherit.py`, removed with it, read this function looking for the ones nobody had,
/// and was a heuristic by its own account. A struct literal is not: a new
/// field does not compile until it is given a value here.
///
/// Three fields changed value in doing it, none observably. `thread` was the
/// parent's pthread id and is 0 (never started) until the child's own thread
/// sets it; nothing reads it before then. `native_pid` was the parent's and
/// is 0, as `native_offload_entry` already was: a task proxying a host
/// process is blocked waiting for it, not forking. `exit_code` was the
/// parent's, which is 0 for any task that can still fork.
///
/// # Safety
/// `parent` is live and `pids_lock` is held, which keeps its group and its
/// signal handle alive while they are read.
pub(super) unsafe fn forked_task(parent: &ffi::task) -> ffi::task {
    // SAFETY: the caller's contract. Each field is read through its own place,
    // never through a `&task`: when `become_new_init_child` is the caller the
    // parent is init, which may be running on another thread.
    unsafe {
        ffi::task {
            // The registers are the whole point of a fork; `task_create_`
            // copies them once the child has an address, and then clears the
            // exclusive monitor and points the poke flag at its own.
            cpu: std::cell::UnsafeCell::new(ffi::cpu_state::default()),
            // Shared or copied by `copy_task` according to `CLONE_VM`, and
            // replaced by `become_new_init_child`.
            mm: taskview::ArcSlot::new(parent.mm.clone_arc()),
            // Set by the child's own thread when it starts.
            thread: ffi::HostThread::none(),
            // Pointed at the old or the new group by `copy_task`.
            group: std::sync::atomic::AtomicPtr::new(parent.group.load(Ordering::Acquire)),
            cpu_affinity: std::sync::atomic::AtomicU64::new(parent.cpu_affinity.load(Ordering::Relaxed)),
            // Inherited, then `on_fork` below.
            attr: locks::mutex::Mutex::new(*locks::locked!(&parent.attr)),
            // This task's count in its group's host-thread total, taken by
            // `copy_task` once the group is known. The parent's `Arc` is the
            // parent's count.
            hosts: taskview::ArcSlot::empty(),
            // `task_create_`'s, from the number it reserved.
            pid: std::sync::atomic::AtomicI32::new(0),
            // `copy_task`'s: the child's own pid, or its group leader's.
            tgid: std::sync::atomic::AtomicI32::new(parent.tgid.load(Ordering::Relaxed)),
            // Inherited, and then `set_nproc_uid` below.
            creds: std::cell::UnsafeCell::new(*parent.creds.get()),
            did_exec: ffi::Flag::new(false),
            // Shared or copied by `copy_task` according to `CLONE_FILES` and
            // `CLONE_FS`, which is why the parent's pointers are here.
            // A counted share of the parent's, under the `pids_lock` the
            // caller holds; `copy_task` replaces it with a copy when the clone
            // does not share the table.
            files: taskview::ArcSlot::new(parent.files.clone_arc()),
            // As `files`: a counted share, replaced by a copy without `CLONE_FS`.
            fs: taskview::ArcSlot::new(parent.fs.clone_arc()),
            // **A counted share**, so `CLONE_SIGHAND` has nothing to do; a
            // fork without it assigns its own copy over this one, and that
            // drop is the release. Read under `pids_lock`, which every writer
            // of another task's `sighand` holds.
            sighand: taskview::ArcSlot::new(parent.sighand.clone_arc()),
            // Its own, made by `task_create_`, which then inherits the
            // parent's mask into it.
            signals: std::cell::UnsafeCell::new(kernel_sigqueue::Signals::default()),
            pause: ffi::cond_t::default(),
            blocking: AtomicBool::new(false),
            // `task_create_`'s: the uptime now, not the parent's age.
            start_ticks: std::sync::atomic::AtomicU64::new(0),
            // Its own, made by `task_create_`: a child sharing its parent's
            // would enter signal-delivery-stop whenever the parent was traced.
            ptrace: None,
            // The parent's mode and chain, which a child of either kind
            // inherits and keeps across `execve`. Read under the `pids_lock`
            // the caller holds, which is what `TSYNC` writes under.
            seccomp: parent.seccomp.for_child(),
            // A share of the parent's; `copy_task` gives the child new ones
            // for `clone`'s `CLONE_NEW*` flags.
            nsproxy: locks::mutex::Mutex::new(parent.nsproxy()),
            // `set_tid_address` is per thread; `copy_task` sets it for
            // `CLONE_CHILD_CLEARTID`.
            clear_tid: std::sync::atomic::AtomicU64::new(0),
            // Linux's `copy_process` clears it; the child's libc sets its own.
            robust_list: std::sync::atomic::AtomicU64::new(0),
            // Zero, in the parent's group; `copy_task` gives a new process
            // its own.
            io: parent.io.new_thread(),
            syscall: kernel_observe::SyscallState::default(),
            restart: std::cell::UnsafeCell::new(*parent.restart.get()),
            exit_code: std::sync::atomic::AtomicU32::new(0),
            zombie: ffi::Flag::new(false),
            // The parent's, so a thread forked while its group is being
            // taken down is already marked as going.
            exiting: ffi::Flag::new(parent.exiting.get()),
            // Set by the child's own thread when it starts. A copy would point
            // at the parent's, and the group-exit valve would write the
            // child's mm and descriptors into it.
            cleanup: AtomicPtr::new(std::ptr::null_mut()),
            // The parent's vfork handle is its parent's to give back; a vfork
            // child gets its own from `crates/kernel/forkcalls`.
            vfork: taskview::ArcSlot::empty(),
            // `copy_task`'s, from `clone`'s flags.
            exit_signal: std::sync::atomic::AtomicI32::new(parent.exit_signal.load(Ordering::Relaxed)),
            general_lock: ffi::lock_t::default(),
            native_pid: ffi::ProxyPid::default(),
            // A fork from inside a native offload handler would otherwise
            // leave the child believing it is in one, and signal forwarding
            // reads this to decide where a signal goes.
            native_offload_entry: ffi::OffloadSlot::default(),
            waiting_cond: locks::mutex::Mutex::new(None),
        }
    }
}

/// A task [`task_create_`] built and nothing else can reach: no pid maps to it
/// and no table holds it. Its fields are this owner's, so they are written
/// through [`NewTask::get_mut`] with no `unsafe`.
///
/// Its *address* may be stored while it is built -- a new group's `leader`,
/// the calling thread's `current` for the boot path's root open -- because
/// nothing reads through either until [`NewTask::publish`].
///
/// Dropping one destroys the task and gives its pid back, so a fork or a boot
/// that fails part-way has nothing to remember. The two paths called
/// `task_destroy` by hand from five places until 2026-10-17.
pub struct NewTask(std::ptr::NonNull<ffi::task>);

/// A published task that has not been started: reachable by pid, so only ever
/// shared, and still this owner's to start or to destroy.
pub struct Unstarted(std::ptr::NonNull<ffi::task>);

impl NewTask {
    /// The task's address, for what records it rather than reads it.
    pub fn as_ptr(&self) -> *mut ffi::task {
        self.0.as_ptr()
    }

    pub fn get_mut(&mut self) -> &mut ffi::task {
        // SAFETY: unpublished, so this owner is the only one that reaches it;
        // see the type comment for the addresses that are stored meanwhile.
        unsafe { self.0.as_mut() }
    }

    /// Make it reachable: its place in the process tree and its pid. `Err`
    /// gives it back with nothing recorded, and dropping it then destroys it.
    ///
    /// The caller holds `pids_lock` across this **and** whatever else it
    /// registers -- a thread group, its thread list -- so that nothing sees
    /// the task in one table and not another.
    pub fn publish(self, pids: &PidsHeld, parent: Option<kernel_pids::Task<'_>>) -> Result<Unstarted, NewTask> {
        let task = self.as_ptr();
        // Unconditionally, including the first process, which has no parent:
        // a task that is not in the tree has no children either as far as
        // anything can see, and /proc/iul/objects counted zero tasks while one
        // was running.
        if !proctree::add(task, parent.map_or(std::ptr::null_mut(), |p| p.raw())) {
            return Err(self);
        }
        if kernel_pids::set_task(pids, self.pid(), task) == 0 {
            proctree::remove(task);
            return Err(self);
        }
        let published = Unstarted(self.0);
        std::mem::forget(self);
        Ok(published)
    }
}

impl Unstarted {
    pub fn as_ptr(&self) -> *mut ffi::task {
        self.0.as_ptr()
    }

    /// As a registry handle, for the calls that take one.
    pub fn handle<'a>(&'a self, pids: &'a PidsHeld) -> kernel_pids::Task<'a> {
        // SAFETY: owned, so live for as long as `self` is borrowed.
        unsafe { kernel_pids::Task::from_raw(pids, self.as_ptr()) }.expect("an owned task is not null")
    }

    /// Run it on a host thread of its own, which owns it from then on.
    pub fn start(self) {
        let task = self.into_raw();
        // SAFETY: published and complete, and never started: that is this
        // type.
        unsafe { task_start(task) };
    }

    /// Give up ownership to a caller that runs the task itself -- the boot
    /// path binds it to the calling thread.
    pub fn into_raw(self) -> *mut ffi::task {
        let task = self.as_ptr();
        std::mem::forget(self);
        task
    }
}

impl std::ops::Deref for NewTask {
    type Target = ffi::task;
    fn deref(&self) -> &ffi::task {
        // SAFETY: owned and live; a `&task` is sound.
        unsafe { self.0.as_ref() }
    }
}

impl std::ops::Deref for Unstarted {
    type Target = ffi::task;
    fn deref(&self) -> &ffi::task {
        // SAFETY: as `NewTask`'s.
        unsafe { self.0.as_ref() }
    }
}

/// Takes `pids_lock`, so neither may be dropped with it held.
fn destroy_owned(task: std::ptr::NonNull<ffi::task>) {
    let pids = Pids::take();
    // SAFETY: an owner's task that never started, so nothing else holds it.
    unsafe { task_destroy(pids.held(), task.as_ptr()) };
}

impl Drop for NewTask {
    fn drop(&mut self) {
        destroy_owned(self.0);
    }
}

impl Drop for Unstarted {
    fn drop(&mut self) {
        destroy_owned(self.0);
    }
}

/// A new task, copied from `parent` — or built from nothing, for the first
/// process.
///
/// Every field is named, by [`blank_task`] or [`forked_task`]: see the second
/// for what the byte copy this used to be cost.
///
/// A new task: `_EAGAIN` when the user is at `RLIMIT_NPROC` or every pid
/// number is taken, `_ENOMEM` when the allocation failed.
///
/// It answered NULL for both and **spun for ever holding `pids_lock`** for the
/// second; then it answered an `ERR_PTR`, which told the two apart and was the
/// last object in this tree to carry that encoding outside the two functions
/// `iul.h` declares. Nothing in C names this, so it is a `Result`.
///
/// The trailing underscore is because there is a mach function by the same
/// name.
///
/// **Not published.** Its pid is reserved and nothing else can reach it: the
/// caller finishes it -- a fork's `copy_task`, the boot path's
/// `construct_task` -- and then calls [`NewTask::publish`]. Until 2026-09-30 this
/// function published it itself, and every field the caller then wrote was a
/// write to a task anyone could find by pid. A task that is never published
/// goes with [`task_destroy`], which gives the reservation back.
///
/// # Safety
/// `parent` is live, or null.
pub unsafe fn task_create_(parent: *mut ffi::task) -> Result<NewTask, Errno> {
    // SAFETY: the caller's contract.
    unsafe { task_create_at(parent, None) }
}

/// [`task_create_`], at the pid `want` names if it is `Some`: `clone3`'s
/// `set_tid`. `_EEXIST` when that number is in use.
///
/// # Safety
/// `parent` is live, or null.
pub unsafe fn task_create_at(parent: *mut ffi::task, want: Option<c_int>) -> Result<NewTask, Errno> {
    let pids = Pids::take();
    // SAFETY: the caller's contract -- live or null -- and `pids_lock` is held,
    // which keeps the parent and its group alive.
    let parent = unsafe { kernel_pids::Task::from_raw(pids.held(), parent) };

    // RLIMIT_NPROC, which was defined, given a default of 1024, and enforced
    // nowhere. Checked before a number is taken, so a refused fork leaves
    // nothing behind. A task with no parent is the first one, before there is
    // an rlimit to read or a `current` to read it from.
    //
    // The **parent's** limit and privilege, which for a guest's fork is
    // `current` and for an embedder's `become_new_init_child` is init. It read
    // `current` until 2026-09-29, which only worked for the embedder because
    // `task_start` left the last task it started bound to the calling thread;
    // once it stopped doing that, the first session crashed here.
    if let Some(parent) = parent {
        let limit = parent
            .group()
            .and_then(|g| g.limits().get(ffi::RLIMIT_NPROC_ as c_int as u32))
            .map_or(u64::MAX, |l| l.cur);
        let capped = limit.min(c_uint::MAX as u64) as c_uint;
        let creds = parent.creds();
        let uid = creds.uid();
        // `copy_process`: the root user, `CAP_SYS_RESOURCE` or
        // `CAP_SYS_ADMIN` goes past RLIMIT_NPROC. The first is a uid test on
        // Linux too -- `INIT_USER`, the user struct of uid 0.
        use taskview::caps::{CAP_SYS_ADMIN, CAP_SYS_RESOURCE};
        let exempt = uid == 0 || creds.capable(CAP_SYS_RESOURCE) || creds.capable(CAP_SYS_ADMIN);
        if !proccount_try_add(pids.held(), uid, capped, exempt) {
            return Err(Errno::EAGAIN);
        }
    }

    // One call, and it answers rather than searching for ever. The loop this
    // replaced walked the array from a static cursor and, at one point, had no
    // bound at all -- so a full table, which is 32768 unreaped zombies, stopped
    // the emulator dead with pids_lock held.
    let new_pid = match want {
        Some(pid) => match kernel_pids::pidreg_reserve(pids.held(), pid) {
            0 => pid,
            e => e,
        },
        None => kernel_pids::pidreg_alloc(pids.held(), ffi::MAX_PID as c_int),
    };
    if new_pid < 0 {
        if let Some(parent) = parent {
            proccount_remove(pids.held(), parent.creds().uid());
        }
        return Err(Errno::from_negative_or_eio(new_pid));
    }

    // Its own tracing state, and not the parent's -- a child sharing its
    // parent's would enter signal-delivery-stop whenever the parent was traced.
    // Not inherited at all, which is Linux's rule: a fork of a tracee is not
    // itself traced unless PTRACE_O_TRACEFORK asked, and nothing here honours
    // that option.
    let ptrace = ffi::ptrace_state::new();

    LIVE.fetch_add(1, Ordering::Relaxed);

    // Whoever the count was taken from, so task_destroy gives it back to the
    // same user even if this task changes its uid in between. Read before the
    // box below, because it reads the *parent*.
    let nproc_uid = parent.map_or(0, |p| p.creds().uid());
    let parent = parent.map(|p| p.task());

    let value = match parent {
        None => blank_task(),
        // SAFETY: `pids_lock` is held, which `forked_task` reads under.
        Some(p) => unsafe { forked_task(p) },
    };
    // **A `Box`, since 2026-10-01.** It was `std::alloc::alloc` with a null
    // test that answered `ENOMEM` and gave the pid and the per-user count
    // back -- for this allocation alone, while `blank_task`/`forked_task`
    // above and the address space, group and descriptor table around it
    // allocate the way every Rust allocation does, aborting.
    let mut t: Box<ffi::task> = Box::new(value);

    // **Owned, not borrowed**, for the field writes — which is what the long
    // note here used to be about. A `&mut` derived from a raw pointer that is
    // then handed to something else is invalidated under the aliasing rules
    // LTO acts on, which is the shape
    // `docs/changelog/2026-08-31-a-release-build-hung-closing-a-descriptor.md`
    // records; a `Box` cannot be in that position, because the raw pointer does
    // not exist again until `Box::into_raw`. And the three attribute calls are
    // `&mut self` methods now rather than raw-pointer shims, so the whole block
    // is safe code.
    //
    // Cleared, as on fork(2): the signal was a request about *this* thread's
    // parent, and the child's parent is someone else. Outside any `if` on
    // purpose -- a task with no parent has none either. 0 is always accepted.
    let _ = t.attr.get_mut().set_pdeath_signal(0);
    // The rest of what a fork does to the copy: the default timer slack becomes
    // the parent's current one.
    t.attr.get_mut().on_fork();
    t.creds.get_mut().set_nproc_uid(nproc_uid);
    *t.pid.get_mut() = new_pid;

    let cpu = t.cpu.get_mut();
    if let Some(parent) = parent {
        // Every register but the poke flag, which stays the child's own
        // `false`: a copied `true` seeds a permanent one-interrupt-per-block
        // storm in the child.
        // SAFETY: `t` is this function's; the parent is live under
        // `pids_lock`, and its registers are read through the cell.
        unsafe { ffi::copy_state(cpu, parent.cpu.get().cast_const()) };
    }

    // The exclusive monitor, invalidated after copying the parent's state:
    // a child must not inherit an LDXR reservation, because any context
    // switch or interrupt -- fork and clone among them -- invalidates one.
    cpu.excl_addr = u64::MAX;
    // The poke pointer must not be inherited either: it would alias the
    // *parent's* `_poked` byte. The address stays good across
    // `Box::into_raw`: a `Box` never moves what it points at.
    cpu.poked_ptr = &raw const cpu._poked;

    // Not the parent's age, and not 0, which would date the process to boot.
    *t.start_ticks.get_mut() = kernel_hoststats::get_uptime_ticks();

    // Its own signal state; what a child inherits of it is applied here.
    if let Some(parent) = parent {
        // SAFETY: the new queue is this task's and unpublished; the parent is
        // live under `pids_lock`.
        t.signals.get_mut().inherit(unsafe { &*parent.signals.get() });
    }
    t.ptrace = Some(Box::new(ptrace));
    install_parked_hook();

    // Not published: see this function's doc comment. `NewTask::publish` is the
    // one place a task becomes reachable, and nothing is written to it there
    // but the registries.
    drop(pids);
    Ok(NewTask(std::ptr::NonNull::from(Box::leak(t))))
}

// ---------------------------------------------------------------------------
// Giving one back
// ---------------------------------------------------------------------------

/// Task structs that have been destroyed and are waiting to be freed.
///
/// One round of delay: the next `task_destroy` frees what the previous one
/// left. A leaked or exiting pthread gets that long to finish touching a stale
/// `current` before `malloc` can hand the memory to somebody else.
pub(super) const DEFERRED_MAX: usize = 64;
static DEFERRED: Mutex<Vec<Poisoned>> = Mutex::new(Vec::new());

/// A destroyed task's allocation, zeroed and waiting to be given back.
///
/// **`MaybeUninit` and not `task`.** By the time one of these exists the
/// fields' destructors have run and the bytes have been overwritten with
/// zeros, so what is left is the allocation and nothing else — and dropping a
/// `Box<MaybeUninit<T>>` deallocates without running any glue, which is
/// exactly right and is now a property of the *type*. It was a `usize` and a
/// `libc::free` until 2026-09-12, which was correct only for as long as no
/// field of `struct task` had a destructor: poisoning a struct and then
/// dropping it as a `Box<task>` would destroy the field *before* its
/// destructor ran, which is a worse bug than the leak this conversion is
/// about.
struct Poisoned(
    // Never read, and `dead_code` is right to say so: the only operation left
    // on it is the deallocation its own drop glue performs, which is the whole
    // of what this type is for.
    #[allow(dead_code)] Box<std::mem::MaybeUninit<ffi::task>>,
);

// SAFETY: the allocation is only ever deallocated, under `pids_lock`, and its
// bytes are zero by the time it gets here -- there is nothing in it that
// belongs to the thread that put it on the list.
unsafe impl Send for Poisoned {}

/// Free everything the previous round deferred.
///
/// Called with `pids_lock` held, which [`task_destroy`] already requires.
fn flush_deferred() {
    let mut list = DEFERRED.lock().unwrap_or_else(|e| e.into_inner());
    let freed = list.len();
    // Each `Poisoned` deallocates as it goes; see the type.
    list.clear();
    LIVE.fetch_sub(freed, Ordering::Relaxed);
}

/// The `&PidsHeld` was a `/// # Safety: pids_lock is held` clause until
/// 2026-09-16 — see `crates/kernel/pids`' module comment.
///
/// # Safety
/// Nothing holds `task` any more.
pub unsafe fn task_destroy(pids: &PidsHeld, task: *mut ffi::task) {
    unsafe {
        // Given back where it was taken from. Linux drops the count in
        // release_task, which is here: when the parent reaps, not when the task
        // exits, so a guest that forks and never waits stays at its limit.
        proccount_remove(pids, (*taskview::creds_of(task)).nproc_uid());
        // Still set only if this task never reached the run loop -- a clone
        // that failed after copy_task, which sys_clone destroys. A task that
        // did run moved the handle into its cleanup struct, and its own pthread
        // gives it back from there.
        if let Some(hosts) = (*task).hosts.take() {
            hosts.finished();
        }
        // **Before the memset**, which would otherwise leak the whole thread
        // group's disposition table: zeroing an `Option<Arc<_>>` is a valid
        // `None` and drops nothing.
        //
        // Usually already `None` -- `detach_and_notify` drops it on the way out
        // and the group-exit valve hands it to the cleanup struct -- and the
        // paths where it is not are the ones that made the old `Partial` and
        // `Given` flags wrong: a task that failed part-way through
        // `construct_task` or `copy_task` still holds the reference
        // `task_create_` cloned from its parent. One statement covers all of
        // them, which is the release-exactly-once this file used to spread
        // across three crates.
        (*task).sighand.set(None);
        proctree::remove(task);
        kernel_pids::set_task(pids, (*task).pid(), std::ptr::null_mut());
        // The pid has no task any more: reaped, or a thread that exited. A
        // pidfd naming it reads POLLIN|POLLHUP from here on, which is what
        // Linux's pidfd_poll answers once `pid_task` finds nothing.
        kernel_pidfd::notify_gone((*task).pid());
    }

    // The previous round first: they have had time to quiesce.
    flush_deferred();

    unsafe {
        // The task's own locks and `pause` are destroyed with the fields below.
        // Every wait on them is on `current`'s own -- pause in sigsuspend,
        // pause, sigtimedwait and signalfd -- so the thread that could be
        // parked here is the one that has already left; the destroys trap if
        // that stops being true.
        //
        // The ptrace lock and its condition variable went with the state:
        // crates/kernel/ptrace owns both, and dropping the object destroys them.
        (*task).ptrace = None;
    }

    // Take the allocation back, **run the fields' destructors, and only then
    // poison**. That order is the whole reason this is three statements rather
    // than a `memset` and a `free`: the zeroing is what makes a stale `current`
    // crash on a NULL `group` instead of quietly corrupting whatever the
    // allocator hands out next, and it is also what would destroy a field
    // before its destructor could run. `libc::free` had no destructors to get
    // wrong; a `Box` does, and `drop_in_place` is where they go. Since 2026-10-16
    // it is also what destroys the task's two mutexes and its condition.
    //
    // SAFETY: `task` came from `task_create_`, `pids_lock` is held, and the
    // caller's contract is that nothing holds it any more.
    let mut poisoned: Box<std::mem::MaybeUninit<ffi::task>> =
        unsafe { Box::from_raw(task.cast()) };
    unsafe {
        std::ptr::drop_in_place(poisoned.as_mut_ptr());
        std::ptr::write_bytes(poisoned.as_mut_ptr(), 0, 1);
    }

    // The previous round is already gone; this one waits for the next. See the
    // module comment for what the delay buys.
    let mut list = DEFERRED.lock().unwrap_or_else(|e| e.into_inner());
    if list.len() < DEFERRED_MAX && list.try_reserve(1).is_ok() {
        list.push(Poisoned(poisoned));
    } else {
        // Rare, and only with 64 or more concurrent exits.
        drop(poisoned);
        LIVE.fetch_sub(1, Ordering::Relaxed);
    }
}
