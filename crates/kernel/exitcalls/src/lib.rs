//! `exit`, `exit_group`, and everything a dying task gives back.
//!
//! # The order is the content
//!
//! Almost every line of this is "release X before Y", and almost every comment
//! records what happened when the order was the other way round. Three of them
//! are use-after-frees that were reproduced:
//!
//! - **`mm` is detached before it is released**, under `general_lock`, because
//!   that is the lock anything reading `task->mm` holds — `execve` to swap it,
//!   procfs to retain it. Released the other way round there is a window in
//!   which `task->mm` dangles and the task still looks alive, because `exiting`
//!   is not set until later, so `/proc/<pid>/statm` retains a freed `mm` and
//!   frees it a second time.
//! - **`files` and `fs` are taken out under `pids_lock`**, which is what
//!   `/proc/<pid>/fd` holds while it reads them. Same window, same shape;
//!   reproduced as a `SIGSEGV` at address zero inside `getdents64`.
//! - **They are released outside that lock**, because closing a descriptor runs
//!   a filesystem's `close`, which takes locks of its own and has no business
//!   doing so under the process table's.
//!
//! # `leader`, never `current`
//!
//! [`tgroup_release`] takes the leader. They are usually the same task, but a
//! thread that exits before its peers leaves on a different path, so a group
//! whose leader went first reaches the auto-reap on some other thread. Naming
//! `current` there frees the group and leaves the leader's task and pid behind
//! for ever — measured as a `pthread_exit`ing main thread staying waitable as a
//! zombie for the rest of the parent's life.
//!
//! # `pthread_exit` and Rust frames
//!
//! [`do_exit`] never returns; it ends in `pthread_exit`. On Darwin that
//! terminates the thread without unwinding the C stack, so the Rust frames
//! below it are simply abandoned — no destructor runs. **Nothing owning may be
//! alive at that call**, which is why every guard in this file is dropped
//! explicitly before it and why the values held across it are raw pointers.
//! The host here is always Darwin; glibc's `pthread_exit` does force an unwind,
//! and this would need `catch_unwind` there.


use std::sync::atomic::Ordering;
use std::ffi::{c_int, c_void};

use std::sync::OnceLock;

use strace::strace;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

mod dethread;
mod group;
mod reaping;
pub use dethread::de_thread;
pub use group::do_exit_group;
#[cfg(test)]
use reaping::clock_from_timeval;
use reaping::{detach_and_notify, record_own_times};
pub use reaping::ptrace_release_zombie;

fn current() -> *mut ffi::task {
    taskview::current()
}

/// `pids_lock`, for a scope.
///
/// `crates/kernel/pids` owns the lock and the guard; this was a fourth private
/// copy of the same type until 2026-09-06, reaching the lock through the C ABI
/// -- which is why cargo never saw the dependency.
use kernel_pids::{PidsGuard as Pids, PidsHeld};

/// The embedder's notification that a process has finished. `xX_main_Xx.h` sets
/// it in the CLI and ServerBox's boot code sets its own, which records the
/// session's exit code.
///
/// The hook is installed once at boot, before any guest runs. `OnceLock` keeps
/// the exit path's read synchronized with the embedder's installation instead
/// of exposing a writable global that could race with a dying task.
static EXIT_HOOK: OnceLock<extern "C" fn(c_int, c_int)> = OnceLock::new();

/// Install the embedder's process-exit notification.
///
/// **Exported, and one of the few that has to be.** `iul.h` declares it and an
/// embedder is the caller -- ServerBox's hook writes the session's exit code.
/// It replaced `extern void (*exit_hook)(struct task *, int)`, a `#[no_mangle]
/// static mut` whose writer could race the exit path's reader, and for one
/// commit the variable went without the header following: `iul.h` still named
/// a symbol nothing defined, so `tests/integration/sbm_api_test.c` -- the
/// embedder example, and the only thing that links `iul.h` from C -- stopped
/// linking, and `ninja` was red on a build whose cargo half was green.
///
/// The hook gets the process's pid rather than its `struct task`: a task
/// pointer asked the embedder to call back into `task_pid` while the task was
/// mid-exit, and that pid was the exiting *thread*'s, which is not the session's
/// when the leader exited first.
#[unsafe(no_mangle)]
pub extern "C" fn set_exit_hook(hook: extern "C" fn(pid: c_int, status: c_int)) {
    let _ = EXIT_HOOK.set(hook);
}

fn run_exit_hook(pid: c_int, status: c_int) {
    if let Some(hook) = EXIT_HOOK.get() {
        hook(pid, status);
    }
}

use logline::printk;

/// What [`restore_termios`] calls, or null.
///
/// **A hook, not a weak symbol.** `kernel/task.c` had a weak definition so an
/// embedder that does not link `crates/tools/iul` got a no-op, and the obvious
/// Rust translation — a `global_asm!` `.weak_definition` — builds and then
/// **fails a release link**: LTO puts the weak definition and the CLI's strong
/// one in one compilation unit, where the assembler sees a duplicate symbol
/// rather than the linker seeing a weak one to override. It was written that
/// way for one commit on 2026-09-06 and backed out.
///
/// A hook has no such edge: nothing is defined twice, an embedder that
/// installs nothing gets a call through a null check, and the CLI installs its
/// own at startup — which is the shape `CLAUDE.md` recommends for exactly this,
/// "a hook in the leaf crate, for a notification".
static TERMIOS_HOOK: OnceLock<extern "C" fn()> = OnceLock::new();

/// Install the terminal restore. `crates/tools/iul` calls this from `main`.
///
/// Installed at the point the terminal is saved rather than at boot: there is
/// then no ordering to get wrong, because nothing can be exiting yet.
pub fn set_restore_termios_hook(f: extern "C" fn()) {
    let _ = TERMIOS_HOOK.set(f);
}

/// Put the terminal back, if anything owns one.
fn restore_termios() {
    if let Some(f) = TERMIOS_HOOK.get() {
        f();
    }
}

// ---------------------------------------------------------------------------
// Giving a thread group back
// ---------------------------------------------------------------------------

/// Take this task out of its thread group; `true` if it was the last one.
///
/// Called with `pids_lock` held. A dead group's interval timer is disarmed
/// here: the group is unreachable by now — the only pointers to it come from
/// other threads' `current->group`, and there are none left, or from the pid
/// registry under this lock.
///
/// The group is *not* removed from its process group and session here. That
/// happens at reaping, because fish sets the pgid of an exited but not reaped
/// task (<https://github.com/Microsoft/WSL/issues/2786>).
fn exit_tgroup(task: kernel_pids::Task<'_>, deferred: &Deferred) -> bool {
    let Some(group) = task.group() else {
        return false;
    };
    let dead = proctree::group_remove(group.raw(), task.raw());
    if dead {
        // Taken out here, freed by `deferred` once `pids_lock` is released.
        // This used to call `timer_free` on the spot; see [`Deferred`].
        deferred.itimer(group.tgroup().itimer.take());
    }
    dead
}

/// Mark this thread as exiting, and if that leaves no live thread in a group
/// that leads its session, take the session's controlling terminal for
/// [`fs_tty::tty::session_leader_exited`].
///
/// That is Linux's `disassociate_ctty(1)`, which `do_exit` runs **before**
/// `exit_notify`: the foreground group has its `SIGHUP` before the parent can
/// be told of the exit, so a parent woken by `waitpid` already sees it
/// pending. Until 2026-11-12 the terminal was taken in [`exit_tgroup`] and
/// hung up after the parent had been notified (`exitorder_probe`).
///
/// The mark and the question are one hold of `pids_lock`, so that of two last
/// threads exiting at once exactly one finds the other already marked: the
/// part of Linux's `signal->live` count, decremented at the top of `do_exit`,
/// that this needs. After [`release_guest_memory`], as in Linux, where
/// `exit_mm` and `exit_files` come first.
fn claim_session_terminal() -> Option<fs_tty::tty::User> {
    let pids = Pids::take();
    let me = kernel_pids::Task::current(pids.held())?;
    me.task().exiting.set(true);
    let group = me.group()?;
    if group.sid() != group.leader_pid() || group.threads().any(|t| !t.is_exiting()) {
        return None;
    }
    group.tgroup().ctty.take()
}

/// Teardown that **waits**, collected under `pids_lock` and done without it.
///
/// `util_timer::timer_free` blocks until an expiry already in flight has
/// returned — that is what stops a timerfd firing after its descriptor is
/// closed, and it is the whole reason that function exists. A POSIX timer's
/// expiry resolves its target through the pid registry, so it takes
/// `pids_lock`.
///
/// Doing the free under `pids_lock` is therefore a two-thread cycle, and it was
/// one: the exiting thread held the lock and waited for the expiry, while the
/// timer service thread sat inside the expiry waiting for the lock. Since
/// `pids_lock` is kernel-wide, that stopped **every** guest thread, not just
/// the one exiting. `tests/guest/src/bin/timer_exit_race.rs` reproduces it and
/// `docs/changelog/2026-09-16-the-exit-path-waited-for-a-timer-under-the-lock-the-timer-needed.md`
/// has the two stacks.
///
/// The shape is `crates/kernel/posixtimers`' own: take the thing out under the
/// lock, release the lock, *then* wait. Its module comment calls that "the
/// whole discipline" — for the thread group's lock, which it had already been
/// caught by. Nothing applied it to `pids_lock`.
///
/// # Why a type and not two locals
///
/// So the rule has somewhere to live and something to check it. Dropping one
/// asserts that `pids_lock` is not held, which turns "somebody moved this
/// declaration" from a deadlock under load into an assertion, and `Cell` rather
/// than `&mut` so it can be handed down to `reap_if_zombie` as a shared
/// reference through two frames that have nothing else to say about it.
#[derive(Default)]
pub struct Deferred {
    /// The group's `ITIMER_REAL` handle, or `TIMER_NONE`.
    itimer: std::cell::Cell<u64>,
    /// The group's POSIX timer table.
    posix: std::cell::Cell<Option<Box<kernel_posixtimers::Timers>>>,
}

impl Deferred {
    pub fn new() -> Deferred {
        Deferred::default()
    }

    fn itimer(&self, armed: u64) {
        debug_assert_eq!(self.itimer.get(), 0, "two groups' timers in one Deferred");
        self.itimer.set(armed);
    }

    fn posix(&self, timers: Option<Box<kernel_posixtimers::Timers>>) {
        let previous = self.posix.replace(timers);
        debug_assert!(previous.is_none(), "two groups' timer tables in one Deferred");
    }
}

impl Drop for Deferred {
    fn drop(&mut self) {
        debug_assert!(
            !kernel_pids::held_by_this_thread(),
            "Deferred dropped under pids_lock, which is the deadlock it exists to avoid"
        );
        let armed = self.itimer.replace(0);
        if armed != 0 {
            util_timer::timer_free(armed);
        }
        // Taken out of a dead group under `pids_lock`; dropped here, without it.
        drop(self.posix.take());
    }
}

/// Everything a dead thread group owns, given back.
///
/// Called with `pids_lock` held, from the two places a group's last reference
/// goes away: the reaper in `crates/kernel/waitcalls`, and [`do_exit`]'s
/// auto-reap path for a child nobody will wait for.
///
/// It is one function because it was two copies of the same nine calls in the
/// same order, and a group acquires something new every few weeks. The copies
/// had already drifted: `stopped_cond` was created beside `child_exit` in every
/// one of the three places a tgroup is built, and fork's failure path destroyed
/// the pair, but neither exit path destroyed anything but `child_exit`. So did
/// `lock`, which nothing had ever destroyed.
///
/// # Safety
/// `leader` is the group's leader and the group has no live threads.
pub unsafe fn tgroup_release(pids: &PidsHeld, leader: *mut ffi::task, deferred: &Deferred) {
    let group = unsafe { taskview::group_of(leader) };
    unsafe {
        if let Some(g) = kernel_pids::Group::from_raw(pids, group) {
            groupcalls::group_leave_session(pids, g);
        }
        kernel_pids::remove(pids, taskview::ffi::TgroupId::of(&*group));
        // Handed to `deferred` rather than dropped here: `Timers`' destructor
        // waits for an expiry in flight, and this runs under `pids_lock`.
        // See [`Deferred`].
        deferred.posix((*group).posix_timers.take());
        proctree::group_forget(group);
        // Last: the condition variable and the stop guard the fields above,
        // so nothing may still be inside one of them by the time they go. Both
        // go with the struct, and each destroy is checked -- a waiter still
        // parked on one answers EBUSY, which aborts here rather than becoming a
        // crash somewhere else with no evidence left.
        // `crates/kernel/tgroup` allocated it and gives it back, because a
        // second `libc::free` here would be a second place to remember that
        // the struct is a `Box` -- and `free` runs no destructor.
        kernel_tgroup::tgroup_free_struct(group);
    }
}

/// Who this task's children belong to once it is gone.
///
/// A surviving thread of the same process first — a process's children stay
/// with the process. Otherwise up the tree to the nearest ancestor that asked
/// to be a **subreaper**, which is what a supervisor sets so it collects what
/// its children leave behind instead of losing them to init.
///
/// A subreaper that is itself exiting is no use. The walk ends at init, which
/// has no parent — and it really does end, because `proctree_set_parent`
/// refuses a move that would make a task its own ancestor. The comment here
/// used to claim a cycle was handled and nothing handled one: `copy_task` was
/// making a thread the child of its creator, so this loop reparented that
/// thread onto itself and the next exit spun here for ever.
fn find_new_parent(pids: &PidsHeld, task: kernel_pids::Task<'_>) -> *mut ffi::task {
    let sibling = task
        .group()
        .into_iter()
        .flat_map(kernel_pids::Group::threads)
        .find(|t| !t.is_exiting());
    if let Some(t) = sibling {
        return t.raw();
    }
    let mut ancestor = task.parent();
    while let Some(a) = ancestor {
        if a.group().is_some_and(kernel_pids::Group::child_subreaper) && !a.is_exiting() {
            return a.raw();
        }
        ancestor = a.parent();
    }
    taskcalls::pid_get_task(pids, 1)
}

// ---------------------------------------------------------------------------
// do_exit
// ---------------------------------------------------------------------------

/// This thread is finished. Never returns.
///
/// # Safety
/// Called on a guest thread, and this thread does not run again. Not from
/// inside `taskview::with_current_fdtable`: this gives the table's count back,
/// and that borrow's safety rests on nothing a closure can call doing so.
pub unsafe fn do_exit(status: c_int) -> ! {
    // This never returns to the syscall dispatcher, so the references f_get
    // took for the call that led here are released now instead -- while
    // `current` is still this task and no lock is held.
    fs_fdobj::syscall_refs_drain();

    if let Some(pid) = taskview::with_current_task(|t| t.pid()) {
        asbestos_diag::iul_dump_diagnostics_at_exit(pid == 1, false);
    }

    // If this thread was already marked as leaked by the safety valve, the
    // group leader has finished exiting and the group struct may be freed.
    // Don't touch any shared state -- just kill the host thread.
    if taskview::current_is_exiting() {
        taskview::clear_current();
        exit_this_thread();
    }

    // PTRACE_O_TRACEEXIT: the tracee stops here, with its memory, its
    // descriptors and its registers all still intact, and the tracer decides
    // when it may go. Before `release_guest_memory` for exactly that reason --
    // a tracer's whole use for this stop is reading what is about to be gone.
    signaldeliver::receive::ptrace_exit_event_stop(status);

    // Linux's `exit_signals`: a process-directed signal this thread could have
    // taken is another thread's now. One it was chosen for and did not get to
    // would otherwise wait until some other thread next looked.
    signaldeliver::retarget_on_exit();

    // Block SIGSEGV during exit, to prevent cosmetic crashes from host pthread
    // stack unwinding when many threads exit at once.
    if taskview::current_must_leave().is_some() {
        util_hostsig::block(&[libc::SIGSEGV, libc::SIGBUS]);
    }

    // Read now: the task is gone from `current` by the time PI waiters are
    // told, below.
    let tid = taskview::current_pid();
    release_guest_memory();

    // Without `pids_lock`: telling the session takes it, and hanging a
    // console up takes it again.
    if let Some(held) = claim_session_terminal() {
        fs_tty::tty::session_leader_exited(held);
    }

    // **Declared before the guard, so it is dropped after it.** Rust drops
    // locals in reverse declaration order, on every path out including an early
    // return, and what is in here waits -- see [`Deferred`], whose `Drop`
    // asserts this rather than trusting the order. Backed out on 2026-09-16 by
    // declaring it after the guard instead: the assertion fires on the first
    // guest process that is not init.
    let deferred = Deferred::new();

    // **One hold of pids_lock**, from here to the destroy. It has to be one:
    // between taking this task out of the tree and destroying it, a parent
    // reaping on another thread would otherwise free it, and the very next
    // thing this does is take that task's own general_lock. Splitting it in two
    // is a use-after-free that `tests/guest/src/bin/task_race.rs` reproduces in
    // seconds -- a trap inside `__lock`, from `vfork_notify`.
    {
        let pids = Pids::take();
        // This thread's time joins the group's total in the same hold of the
        // lock that takes it off the thread list, so `rusage_get_process`,
        // which sums the list and the total under the lock, sees it exactly
        // once. It was recorded before the lock until 2026-11-11, which left a
        // window where it was in both.
        let group_rusage = record_own_times(status);
        let (leader, auto_reap, keep_tid) =
            detach_and_notify(pids.held(), &deferred, status, group_rusage);

        // Under the lock, for the reason above.
        taskcalls::vfork_notify_current();

        // A PI futex this thread still held: the threads parked behind it are
        // told. **After** `detach_and_notify` marked the task exiting, because
        // that mark is how a thread about to park behind this one learns it is
        // gone, and **before** the destroy, which frees the tid for reuse --
        // told after, a new thread given the same tid would have its own lock
        // taken over. See `crates/kernel/futex`'s module comment on the owner
        // dying. `pids_lock` then the queue's is the order the stall dump uses.
        futexcalls::futex_exit_pi(tid);

        if auto_reap {
            // What the reaper does, done here because there is no reaper
            // coming. That function cannot be called: it reads `current` for
            // the rusage it credits to the waiter, and the task being released
            // is on this thread. The teardown itself is shared -- see
            // tgroup_release, which is also where the leader-not-current rule
            // is written down.
            //
            // Safe on this thread for the same reason the branch below is: the
            // group is dead, pids_lock is held, and nothing after this touches
            // the task before pthread_exit.
            unsafe {
                tgroup_release(pids.held(), leader, &deferred);
                if leader == current() {
                    taskview::clear_current();
                }
                taskcalls::task_destroy(pids.held(), leader);
            }
        }
        let self_task = current();
        if !self_task.is_null() && self_task != leader {
            unsafe {
                // Cleared before the destroy, to prevent a dangling access.
                taskview::clear_current();
                taskcalls::task_destroy(pids.held(), self_task);
            }
            // Its tracer holds its exit and can still name it: the number
            // stays out of the allocator until that `wait`.
            if keep_tid {
                kernel_pids::pidreg_reserve(pids.held(), tid);
            }
        }
    }

    // By hand: `exit_this_thread` runs no destructor (see the module
    // comment), so until 2026-11-12 nothing collected here was ever done --
    // a dead group's interval timer and POSIX timers were never freed on this
    // path.
    drop(deferred);
    exit_this_thread();
}

/// `pthread_exit`, with nothing of Rust's alive. See the module comment.
fn exit_this_thread() -> ! {
    unsafe { libc::pthread_exit(std::ptr::null_mut()) }
}

/// The address space, the descriptor table and the working directory, in the
/// order and under the locks the module comment gives.
///
/// Called on the thread that is exiting.
fn release_guest_memory() {
    // Both of these write to guest memory, so both have to happen before
    // the mm goes: after it there is none.
    //
    // The robust list first, as Linux's mm_release does. Without it a
    // thread that died holding a robust mutex left it locked for the life
    // of the process -- libc's own unwinding runs on the orderly path,
    // which is the one where nothing went wrong, so the kernel is the only
    // thing that can disown it.
    futexcalls::futex_exit_robust_list();

    let clear_tid = taskview::current_clear_tid();
    if clear_tid != 0 && usercopy::GuestMem.write(clear_tid, &0i32.to_le_bytes()) == 0 {
        futexcalls::futex_wake(clear_tid, 1);
    }

    // May already be NULL: the group-exit valve hands the pointer to this
    // thread's cleanup struct and clears task->mm as it does, under this
    // same general_lock, so exactly one of the two releases it.
    drop(taskcalls::take_current_mm());

    let dying = {
        // `pids_lock` is what stops `/proc/<pid>/fd` resurrecting either
        // between the read and the retain; the `swap` is what stops the
        // *word* being raced on by `f_get` and `current_fs_info`, which run
        // on this thread's own syscall path with no lock at all. Two
        // different properties, and this used to have only the first.
        let _pids = Pids::take();
        taskview::with_current_task(|t| (t.files.take(), t.fs.take()))
    };
    drop(dying);
}

// ---------------------------------------------------------------------------
// Halting
// ---------------------------------------------------------------------------

/// init has gone, so the guest is over. Never returns.
///
/// Three passes over every process: `SIGTERM`, then `SIGKILL`, then a host
/// `SIGTERM` to the thread itself. The first two go through the guest's own
/// signal machinery and need the thread to run; the third does not.
fn halt_system() -> ! {
    let mut max_iterations = 10; // Ten seconds.
    for state in 0..3 {
        let mut tasks_found = 0;
        for pid in 2..ffi::MAX_PID {
            // Held across the lookup *and* the use. `PidsGuard`'s own contract
            // is that a task found through the registry can exit and be freed
            // the moment the lock is dropped, and until 2026-09-16 this loop
            // held it for neither -- so the shutdown sweep could signal a task
            // another thread had just destroyed. Per iteration rather than
            // around the loop, because the loop sleeps a second between passes.
            let pids = Pids::take();
            let Some(task) = pids.find_live(pid as i32) else {
                continue;
            };
            tasks_found += 1;
            let to = signaldeliver::Target::Task(task);
            match state {
                0 => signaldeliver::deliver_signal(to, ffi::SIGTERM_ as c_int, ffi::siginfo_::default()),
                1 => signaldeliver::deliver_signal(to, ffi::SIGKILL_ as c_int, ffi::siginfo_::default()),
                _ => task.kill_host_thread(libc::SIGTERM),
            }
        }
        if tasks_found == 0 {
            break;
        }
        if state != 2 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            max_iterations -= 1;
            if max_iterations <= 0 {
                printk(&format!(
                    "halt_system: timeout after 10 seconds, {tasks_found} tasks remaining"
                ));
                break;
            }
        }
    }

    // Unmount every filesystem. A mount still in use stays, and so does
    // everything after it: this runs on the way out of the process, so give
    // up rather than refusing to halt.
    if let Err(point) = fs_mount::umount_all() {
        printk(&format!(
            "halt_system: {} is busy, leaving it mounted",
            point.to_string_lossy()
        ));
    }

    // The host terminal, and the last of the diagnostics. `_exit` runs no
    // atexit handler, so this is where it has to happen.
    unsafe {
        restore_termios();
        asbestos_diag::iul_dump_diagnostics_at_exit(true, false);
        // Force exit the whole host process: orphaned guest threads, stuck in
        // JIT loops after the do_exit_group force cleanup, would otherwise keep
        // it alive indefinitely. _exit is safe here -- init dying means this is
        // shutting down completely.
        libc::_exit(0)
    }
}

// ---------------------------------------------------------------------------
// The syscalls
// ---------------------------------------------------------------------------

/// Never returns, which is why the answer's type does not matter: `do_exit`
/// ends in `pthread_exit`. The `u32` is what the table's shim needs, not
/// something a guest can read.
pub fn sys_exit(status: u32) -> u32 {
    strace!("exit({status})");
    // Shifted into the wait(2) word's high byte: what a parent reads back is
    // `status << 8`, and the low byte is how the process died.
    // SAFETY: on a guest thread, from the syscall table; this thread does not
    // run again.
    unsafe { do_exit((status as c_int) << 8) }
}

/// As [`sys_exit`].
pub fn sys_exit_group(status: u32) -> u32 {
    strace!("exit_group({status})");
    // SAFETY: as `sys_exit`.
    unsafe { do_exit_group((status as c_int) << 8) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exit_status_lands_in_the_high_byte_of_the_wait_word() {
        // wait(2) packs the status into bits 8..15 and how the process died
        // into 0..7. Forgetting the shift makes `exit(1)` look like death by
        // signal 1.
        let word = |status: u32| (status as c_int) << 8;
        assert_eq!(word(0), 0);
        assert_eq!(word(1), 0x100);
        assert_eq!(word(31), 0x1f00);
        assert_eq!(word(255), 0xff00);
    }

    #[test]
    fn a_status_above_a_byte_keeps_only_what_wait_can_report() {
        // Linux truncates: exit(256) is reported as 0. The shift is where that
        // happens here, and a caller reading `word >> 8 & 0xff` sees it.
        let word = |status: u32| (status as c_int) << 8;
        assert_eq!((word(256) >> 8) & 0xff, 0);
        assert_eq!((word(257) >> 8) & 0xff, 1);
    }

    #[test]
    fn a_timeval_becomes_ticks_at_a_hundred_hertz() {
        // AT_CLKTCK says 100, and si_utime is in ticks. Dividing by the wrong
        // number reports a child's CPU time off by a factor the parent has no
        // way to notice.
        let tv = |sec: i64, usec: i64| grouprusage::Timeval { sec, usec };
        assert_eq!(clock_from_timeval(tv(0, 0)), 0);
        assert_eq!(clock_from_timeval(tv(1, 0)), 100);
        assert_eq!(clock_from_timeval(tv(0, 10_000)), 1);
        assert_eq!(clock_from_timeval(tv(0, 9_999)), 0, "under one tick");
        assert_eq!(clock_from_timeval(tv(2, 500_000)), 250);
    }
}
