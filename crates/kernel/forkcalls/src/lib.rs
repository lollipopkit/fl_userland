//! `clone`, `clone3`, `fork` and `vfork`: making a task out of another one.
//!
//! # What a child gets is a list of decisions, and the default matters
//!
//! `copy_task` starts from `task_create_`, whose child names every field --
//! `crates/kernel/taskcalls`' `forked_task` -- and then applies what the clone
//! flags decide. It used to copy the parent struct whole and undo what must not
//! be shared, and that default cost this tree twice: a field added to `struct
//! tgroup` was silently shared until somebody remembered to add a line, and on
//! 2026-08-23 two were found an hour apart -- one rlimit table for parent and
//! child, and one array of POSIX timer ids, which let a child's `timer_delete`
//! destroy a timer its parent still owned. `crates/kernel/tgroup` lists what a
//! new thread group inherits rather than undoing it here, for the same reason.
//!
//! # A thread is not a child
//!
//! `task_create_` links the new task under `current`, which is right for a fork
//! and wrong for a thread. Linux:
//!
//! ```text
//! if (clone_flags & (CLONE_PARENT|CLONE_THREAD))
//!     p->real_parent = current->real_parent;
//! else
//!     p->real_parent = current;
//! ```
//!
//! A process has one parent and every thread of it reports that parent, and
//! nobody waits for a thread. Getting it wrong hung any process whose second
//! thread exited the group: the thread was a child of its creator, so when the
//! creator exited the reparenting loop moved its children to "the first
//! surviving thread of my group" — that same thread — and the thread became its
//! own parent, so the ancestor walk in its own exit never terminated. That is
//! `exit()` from a worker thread, which Go, Node and any threaded C program do.
//!
//! # `vfork`'s handoff belongs to neither side alone
//!
//! The parent blocks until the child reaches `execve` or `exit`, and the object
//! it blocks on is `crates/kernel/vforkhandoff` — an `Arc` on each side. It used
//! to be a pointer to a struct on the *parent's stack frame*, with nothing but
//! the wait loop's correctness keeping that frame alive under the child.


use std::ffi::c_int;
use std::sync::RwLock;

use strace::strace;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

use guest_errno::Errno;
use guest_errno::i64_::{EFAULT, EINVAL, ENOMEM, EPERM};

/// Linux's `CLONE_*`, from `include/uapi/linux/sched.h`.
///
/// Written out rather than generated: there is no header in this tree that
/// defines them, so there is nothing to generate them from and nothing for
/// `tools/guessed-constants.py` to disagree with.
mod clone {
    pub const CSIGNAL: u64 = 0x0000_00ff;
    pub const VM: u64 = 0x0000_0100;
    pub const FS: u64 = 0x0000_0200;
    pub const FILES: u64 = 0x0000_0400;
    pub const SIGHAND: u64 = 0x0000_0800;
    pub const PIDFD: u64 = 0x0000_1000;
    pub const PTRACE: u64 = 0x0000_2000;
    pub const VFORK: u64 = 0x0000_4000;
    pub const PARENT: u64 = 0x0000_8000;
    pub const THREAD: u64 = 0x0001_0000;
    pub const NEWNS: u64 = 0x0002_0000;
    pub const SYSVSEM: u64 = 0x0004_0000;
    pub const SETTLS: u64 = 0x0008_0000;
    pub const PARENT_SETTID: u64 = 0x0010_0000;
    pub const CHILD_CLEARTID: u64 = 0x0020_0000;
    pub const DETACHED: u64 = 0x0040_0000;
    pub const UNTRACED: u64 = 0x0080_0000;
    pub const CHILD_SETTID: u64 = 0x0100_0000;
    pub const NEWCGROUP: u64 = 0x0200_0000;
    pub const NEWUTS: u64 = 0x0400_0000;
    pub const NEWIPC: u64 = 0x0800_0000;
    pub const NEWUSER: u64 = 0x1000_0000;
    pub const NEWPID: u64 = 0x2000_0000;
    pub const NEWNET: u64 = 0x4000_0000;
    pub const IO: u64 = 0x8000_0000;
    /// `clone3`-only, and above the 32 bits the legacy call has: the child
    /// starts with every signal at its default action. glibc's `posix_spawn`
    /// asks for it, so a guest linked against glibc reaches this.
    pub const CLEAR_SIGHAND: u64 = 0x1_0000_0000;
    /// `clone3`-only: start the child in the cgroup a descriptor names. There
    /// is no cgroup filesystem here, so every request is `EBADF`; see
    /// `sys_clone3`.
    pub const INTO_CGROUP: u64 = 0x2_0000_0000;

    /// What this kernel accepts. `CLONE_PTRACE` and `CLONE_UNTRACED` decide
    /// whether a traced parent's child is traced too (`auto_attach`);
    /// `CLONE_IO` shares an I/O context this kernel has no equivalent of, and
    /// does nothing here. Refusing the three with `EINVAL`, which this did, refused a program that
    /// runs everywhere else. Of the namespace flags only the kinds
    /// `crates/kernel/nsproxy` builds are here: a kernel built without a kind
    /// answers `EINVAL` to its flag.
    pub const IMPLEMENTED: u64 = VM
        | FILES
        | FS
        | SIGHAND
        | PIDFD
        | PTRACE
        | SYSVSEM
        | VFORK
        | THREAD
        | SETTLS
        | CHILD_SETTID
        | PARENT_SETTID
        | CHILD_CLEARTID
        | DETACHED
        | UNTRACED
        | IO
        | CLEAR_SIGHAND
        | NEWUTS;

    /// What `clone3` accepts: everything the legacy call has, minus the two
    /// ranges `clone3` took back for itself, plus `CLEAR_SIGHAND` -- and
    /// `PIDFD`, which it refused until 2026-09-30 though Linux has taken it
    /// here since 5.2, storing the descriptor in `args.pidfd`.
    /// `CLONE_INTO_CGROUP` is in the set and answered by `sys_clone3`.
    pub const CLONE3_OK: u64 = VM
        | FS
        | FILES
        | SIGHAND
        | PTRACE
        | VFORK
        | PARENT
        | THREAD
        | NEWNS
        | SYSVSEM
        | SETTLS
        | PARENT_SETTID
        | CHILD_CLEARTID
        | UNTRACED
        | CHILD_SETTID
        | NEWCGROUP
        | NEWUTS
        | NEWIPC
        | NEWUSER
        | NEWPID
        | NEWNET
        | IO
        | PIDFD
        | CLEAR_SIGHAND
        | INTO_CGROUP;
}

// ---------------------------------------------------------------------------
// The embedder's fork guard
// ---------------------------------------------------------------------------

/// The host layer's veto on a new process. `kernel/task.h` declares the type;
/// ServerBox installs one to bound how many processes a phone runs.
type ForkGuard = unsafe extern "C" fn() -> c_int;

static FORK_GUARD: RwLock<Option<ForkGuard>> = RwLock::new(None);

/// `None` removes the guard.
#[unsafe(no_mangle)]
pub extern "C" fn iul_set_fork_guard(guard: Option<ForkGuard>) {
    *FORK_GUARD.write().unwrap_or_else(|e| e.into_inner()) = guard;
}

/// Ask the guard, if there is one. A negative errno is returned to the guest
/// verbatim and no task is created.
fn fork_allowed() -> Result<(), i64> {
    let guard = *FORK_GUARD.read().unwrap_or_else(|e| e.into_inner());
    let Some(guard) = guard else {
        return Ok(());
    };
    match unsafe { guard() } {
        e if e < 0 => Err(e as i64),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Building the child
// ---------------------------------------------------------------------------

fn current() -> *mut ffi::task {
    taskview::current()
}

/// `pids_lock`, for a scope.
///
/// `crates/kernel/pids` owns the lock and the guard; this was a fourth private
/// copy of the same type until 2026-09-06, reaching the lock through the C ABI
/// -- which is why cargo never saw the dependency.
use kernel_pids::PidsGuard as Pids;

/// Shared by `clone` and `clone3`.
///
/// `flags` is 64 bits because `clone3` has flags above the 32 the legacy call
/// can express; everything below bit 32 means the same thing to both.
///
/// `pidfd` is where `CLONE_PIDFD` stores the descriptor: the legacy call's
/// `ptid`, which is why the two flags exclude each other there, or `clone3`'s
/// own `pidfd` field, where they do not.
///
/// `set_tid` is `clone3`'s: the pid the child is to have, already checked
/// against everything but whether it is free.
fn do_clone(
    flags: u64,
    stack: u64,
    ptid: u64,
    tls: u64,
    ctid: u64,
    pidfd: u64,
    set_tid: Option<c_int>,
) -> i64 {
    let unimplemented = flags & !clone::CSIGNAL & !clone::IMPLEMENTED;
    if unimplemented != 0 {
        strace!("unimplemented clone flags {unimplemented:#x}");
        return EINVAL;
    }
    // An exit signal past the last one is EINVAL, which `clone3` always
    // checked and the legacy call does since Linux 7.2 (measured on
    // 7.2.9 by `clone_probe`; 7.0.14 ran the child). The 0x40 "unused bit"
    // the probe sets is inside CSIGNAL, so it is this check too.
    if flags & clone::CSIGNAL > ffi::MAX_SIG as u64 {
        return EINVAL;
    }
    if flags & clone::SIGHAND != 0 && flags & clone::VM == 0 {
        return EINVAL;
    }
    if flags & clone::THREAD != 0 && flags & clone::SIGHAND == 0 {
        return EINVAL;
    }
    if flags & clone::PIDFD != 0 {
        // The legacy call stores the pidfd where CLONE_PARENT_SETTID stores
        // the tid, so the two exclude each other there -- and only there:
        // `clone3` has a field for each. CLONE_DETACHED is refused beside it
        // as Linux's copy_process does. A pidfd for a *thread* is 6.9's
        // PIDFD_THREAD one; it was EINVAL here, the pre-6.9 answer, until
        // the pidfd could name a thread.
        if (pidfd == ptid && flags & clone::PARENT_SETTID != 0) || flags & clone::DETACHED != 0 {
            return EINVAL;
        }
        // The store happens after the child exists and a failure unwinds it,
        // which is Linux's `bad_fork_put_pidfd`. Asking first is the same
        // answer without a child to unwind.
        if usercopy::GuestMem.write(pidfd, &(-1i32).to_le_bytes()) != 0 {
            return EFAULT;
        }
    }

    // Linux's `copy_namespaces`: a new namespace of any kind but a user one
    // needs `CAP_SYS_ADMIN`.
    if flags & taskview::nsproxy::Kind::BUILT != 0 && !taskview::capable(taskview::caps::CAP_SYS_ADMIN) {
        return EPERM;
    }

    // Let the host layer decide whether to allow this fork. Threads are exempt:
    // they share the parent's address space, so they do not add the per-process
    // memory cost the guard exists to bound, and denying them would break
    // pthread users.
    if flags & clone::THREAD == 0
        && let Err(e) = fork_allowed()
    {
        return e;
    }

    let mut task = match unsafe { taskcalls::task_create_at(current(), set_tid) } {
        Ok(task) => task,
        Err(e) => return e.as_i64(),
    };
    let mut given = match child::copy_task(&mut task, flags, stack, ptid, tls, ctid) {
        Ok(given) => given,
        Err(e) => {
            // This carried a FIXME -- "some other thread could get a pointer to the
            // task, and task_destroy does not free every part of one" -- and both
            // halves were re-read on 2026-09-06 and are no longer true.
            //
            // A pointer cannot outlive the lock: `crates/kernel/pids`' guard lends
            // a `Task<'_>` borrowed from itself, so every `.raw()` in the tree is
            // inside the guard's scope and the borrow checker says so. `task_destroy`
            // *requires* `pids_lock`, which `NewTask`'s drop takes -- and
            // since 2026-09-16 it requires it in the type.
            //
            // And what `copy_task` took, `Given::undo` gives back -- that structure
            // exists for this path; `task_destroy`'s own comments say which of the
            // rest it frees and why the pthread objects go before the memset.
            //
            // And the task is not published yet -- `child::publish` below is
            // where it becomes reachable, since 2026-09-30 -- so nothing else
            // has seen it. That closes what this comment used to record as
            // still true: a reader under `pids_lock` finding, by pid, a task
            // whose fields were still the parent's.
            return e;
        }
    };
    task.get_mut().cpu.get_mut().regs[0] = 0;

    // The parent's handle; the child gets its own.
    let mut vfork = None;
    if flags & clone::VFORK != 0 {
        let handoff = kernel_vforkhandoff::Handoff::new();
        task.vfork.set(Some(std::sync::Arc::clone(&handoff)));
        vfork = Some(handoff);
    }

    // The task may be destroyed by the time this returns, so save the pid.
    let pid = task.pid();

    // Complete: make it reachable. Everything above wrote a task nothing else
    // could find.
    let task = match child::publish(task, &mut given) {
        Ok(task) => task,
        Err(task) => {
            // SAFETY: what was given to this task, which has not started.
            unsafe { given.undo(&task) };
            return ENOMEM;
        }
    };

    // CLONE_PIDFD: a descriptor on the child, installed close-on-exec and
    // stored where the caller said, before the child runs -- so a caller that
    // reads it the moment clone returns finds it there. A descriptor that
    // cannot be made unwinds the child, as on Linux.
    if flags & clone::PIDFD != 0 {
        let fd = pidfdcalls::pidfd_open_for_clone(pid, flags & clone::THREAD != 0);
        if fd < 0 {
            // Both handles go: this function's with `vfork`, the child's with
            // the task. And what `copy_task` gave it -- its thread group, its
            // address space, its descriptor table and its path context --
            // which `task_destroy` does not release: until 2026-09-30 this
            // path left the group registered, naming the freed task as its
            // leader, and the other three allocated.
            // SAFETY: as above.
            unsafe { given.undo(&task) };
            return fd as i64;
        }
        // Checked writable above; a failure now is another thread unmapping
        // the word between, and Linux's put_user would lose the store the
        // same way.
        let _ = usercopy::GuestMem.write(pidfd, &fd.to_le_bytes());
    }

    // Linux's `ptrace_init_task` and `ptrace_event_pid`: a tracee whose
    // tracer asked for this event brings its new task with it, attached
    // before it runs, and stops at the event once the new task is running.
    let event = auto_attach(task.as_ptr(), flags);

    task.start();

    if let Some(event) = event {
        signaldeliver::receive::ptrace_fork_event_stop(event, pid);
    }

    if let Some(vfork) = vfork {
        // `task` is deliberately not named here, and neither is anything
        // reached through it: by this point the child may have exited, been
        // auto-reaped and freed its own struct. That is what the saved `pid` is
        // for; the handoff is reached through this function's own handle.
        vfork.wait();
        // Whether or not the vfork itself was an event: the option decides.
        signaldeliver::receive::ptrace_vfork_done_stop(pid);
    }

    pid as i64
}

/// Attach `child` to the calling thread's tracer if the tracer asked for the
/// event this clone is, or the caller passed `CLONE_PTRACE`, and answer the
/// event when the tracer asked for it. A seized tracee's
/// new task takes a `PTRACE_EVENT_STOP` trap first; an attached one's a
/// `SIGSTOP` -- what `ptrace_attach_probe` reads as the new task's first
/// report. It inherits the options either way, so its own children follow.
fn auto_attach(child: *mut ffi::task, flags: u64) -> Option<signaldeliver::receive::ForkEvent> {
    if flags & clone::UNTRACED != 0 {
        return None;
    }
    let pids = Pids::take();
    let me = pids.me()?;
    let mine = me.ptrace()?;
    if !mine.is_traced() {
        return None;
    }
    let tracer = me.tracer()?;
    // SAFETY: published under `pids_lock` and not started, so alive.
    let child = unsafe { kernel_pids::Task::from_raw(pids.held(), child) }?;
    let event = signaldeliver::receive::ForkEvent::of(flags & clone::VFORK != 0, child.exit_signal());
    let (seized, options) = mine.inherited();
    let wanted = event.wanted(options);
    if !wanted && flags & clone::PTRACE == 0 {
        return None;
    }
    let theirs = child.ptrace()?;
    if !proctree::attach(child.raw(), tracer.raw()) {
        return None;
    }
    theirs.attach(seized, options);
    if seized {
        theirs.request_trap();
    } else {
        signaldeliver::ptrace_signal(child, ffi::SIGSTOP_ as c_int);
    }
    wanted.then_some(event)
}

/// Called on a guest thread, from the syscall table.
pub fn sys_clone(
    flags: u32,
    stack: u64,
    ptid: u64,
    tls: u64,
    ctid: u64,
) -> Result<i64, Errno> {
    strace!("clone({flags:#x}, {stack:#x}, {ptid:#x}, {tls:#x}, {ctid:#x})");
    // The child's pid, or a negative errno. `do_clone` is shared with
    // `clone3`, which is the other spelling of the same call.
    Errno::split(do_clone(flags as u64, stack, ptid, tls, ctid, ptid, None))
}

mod child;
mod clone3;
mod share;
pub use clone3::sys_clone3;
pub use share::{sys_kcmp, sys_setns, sys_unshare};
