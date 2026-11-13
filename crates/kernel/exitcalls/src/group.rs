//! Group exit coordination and cleanup for `exit_group`.

use super::*;
use std::ffi::c_uint;

// ---------------------------------------------------------------------------
// do_exit_group
// ---------------------------------------------------------------------------

/// Every thread of this process is finished. Never returns.
///
/// Also how a thread leaves that finds it has to (`current_must_leave`): a
/// fatal signal started the exit from outside the group, and the first of
/// its threads here leads it.
///
/// # Safety
/// As [`do_exit`].
pub unsafe fn do_exit_group(status: c_int) -> ! {
    let task = current();
    // No task and no group are the same question -- the dereferences below
    // assumed neither, and a caller has both: this is `exit_group`, or a
    // fatal signal on a guest thread.
    assert!(!task.is_null(), "exit_group on a thread with no task");
    asbestos_diag::iul_dump_diagnostics_at_exit(taskview::current_pid() == 1, true);
    // A leaked thread that woke up after the group already exited: bail
    // silently.
    if taskview::current_is_exiting() {
        taskview::clear_current();
        exit_this_thread();
    }

    let status = taskview::with_current_group(|group| {
        // One word, so the status cannot be seen without the flag -- and one
        // compare-exchange, so exactly one thread ever leads.
        match group.exit.begin(status as u32) {
            // Another thread's execve is ending this one: it leaves alone,
            // and the group goes on with the new program.
            kernel_groupexit::Begin::Exec => status,
            // Whoever leads has killed the others or is about to.
            kernel_groupexit::Begin::Joined(s) => s as c_int,
            // This thread started the exit, or is the first of its group
            // here after a fatal signal started it from outside. Only the
            // leader waits for the others; the rest leave immediately, which
            // is what stops them waiting on each other.
            kernel_groupexit::Begin::Lead(s) => {
                let thread_count = {
                    let pids = Pids::take();
                    kill_others(kernel_pids::Group::from_ref(pids.held(), group), false)
                };
                if thread_count > 1 {
                    wait_for_peers(group, thread_count);
                }
                s as c_int
            }
        }
    })
    .expect("exit_group on a task with no group");

    unsafe { do_exit(status) }
}

/// `SIGKILL` to every thread of `g`, the caller too unless `spare_self`, and
/// the group out of a stop: `signaldeliver::kill_threads`. Answers how many
/// threads the group has. Under the `pids_lock` `g` borrows.
pub(crate) fn kill_others(g: kernel_pids::Group<'_>, spare_self: bool) -> i32 {
    signaldeliver::kill_threads(g, if spare_self { current() } else { std::ptr::null_mut() })
}

/// Wait for the other host threads to finish, and give up on the ones that do
/// not.
///
/// They are DETACHED, so this cannot be a join; it is a condition variable in
/// `crates/kernel/hostthreads`, notified by each thread's own pthread cleanup
/// handler as its last act.
///
/// What that replaced was two waits in a row: a 10 ms poll of the group's
/// *thread list*, and then an unconditional 50 ms sleep to "give extra time for
/// pthread cleanup". Neither is the event. A thread leaves the thread list
/// partway through `do_exit` and keeps unwinding afterwards, which is why the
/// poll needed the sleep behind it — and a fixed sleep is longer than the event
/// usually takes, which is not the same as being long enough. Measured, fork to
/// `waitpid` returning, for a process with one extra thread: 69 ms before,
/// 0.2 ms after. A real arm64 kernel does it in 78 µs.
///
/// Called on the thread that started the group exit.
pub(crate) fn wait_for_peers(group: &ffi::tgroup, thread_count: i32) {
    // The timeout is unchanged and so is everything past it: a thread stuck in
    // an uninterruptible host syscall never reports in, and the force-kill path
    // below is what that is for.
    let max_wait_ms = (500 + thread_count * 10).min(5000) as c_uint;
    let hosts = &group.hosts;
    let quiet = hosts.wait_for(1, std::time::Duration::from_millis(max_wait_ms.into()));

    if quiet {
        unsafe {
            // Release the thread-specific malloc caches the threads that have
            // just finished were holding. Only on the path where they really
            // did finish -- on the other one they are still running and still
            // using theirs. This used to sit behind a 50 ms sleep whose job was
            // to make it true that the threads were done; waiting for the event
            // says so.
            malloc_zone_pressure_relief(std::ptr::null_mut(), 0);
        }
        return;
    }

    let remaining = hosts.live() as i32 - 1;
    if util_iulenv::env().exec_trace {
        printk(&format!(
            "SAFETY-VALVE[exit]: pid={} do_exit_group waited {max_wait_ms}ms, \
             {remaining} threads still stuck -> force kill",
            taskview::current_pid()
        ));
    }

    // Signal the stuck threads with SIGUSR1, repeatedly. Not pthread_cancel: it
    // can corrupt malloc state if the thread is cancelled inside malloc or
    // free.
    for _ in 0..3 {
        let mut still_alive = 0;
        {
            let pids = Pids::take();
            for t in kernel_pids::Group::from_ref(pids.held(), group).threads() {
                if t.raw() != current() && !t.is_exiting() {
                    still_alive += 1;
                    signaldeliver::poke(t.task());
                    t.kill_host_thread(libc::SIGUSR1);
                }
            }
        }
        if still_alive == 0 {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let leaked = abandon_stuck_threads(group);
    if leaked > 0 && util_iulenv::env().exec_trace {
        printk(&format!(
            "SAFETY-VALVE[exit]: pid={} leaked {leaked} stuck host threads",
            taskview::current_pid()
        ));
    }
}

/// Give up on the threads that never reported in.
///
/// If they are truly stuck in uninterruptible host syscalls, the leak is
/// preferable to risking heap corruption. They are marked exiting and taken off
/// the thread list, so `exit_tgroup` sees the group as dead and the parent is
/// notified.
///
/// **What each stuck thread still owns is handed to its own pthread cleanup
/// handler rather than released here**, and the reason is the same for all
/// four:
///
/// - The `mm`: the thread is by definition still inside a host syscall — say
///   `read` blocked on a pipe, in `user_write` — and may still hold `mem->lock`
///   and be about to dereference the `mem` inside it. Freeing it now is a
///   use-after-free, `EXC_BAD_ACCESS` at 0x38, which is `offsetof(struct mem,
///   lock)`. Deferring both avoids that *and*, unlike the old "accept the leak"
///   path, actually reclaims the address space once the host thread terminates.
/// - The syscall's descriptor references: a syscall holds its `struct fd`
///   through a reference `f_get` took. Releasing that here drops the last one,
///   which runs `fd->ops->close` — closing the *host* descriptor the thread is
///   blocked on, and freeing the struct the syscall reads when it returns.
///   Closing a descriptor another thread is blocked in is also how its number
///   gets reused underneath that thread.
///
/// The cost is that a pipe whose only other end is held by such a thread does
/// not see EOF until the thread dies. That is a wait; the alternative was a
/// use-after-free.
///
/// If a thread instead unblocks and re-enters `do_exit`, that releases them and
/// finds NULL here, so nothing is released twice.
///
/// Called on the thread that started the group exit.
fn abandon_stuck_threads(group: &ffi::tgroup) -> i32 {
    let pids = Pids::take();
    let mut leaked = 0;
    // Collected first: the loop takes threads off the list it would walk.
    let g = kernel_pids::Group::from_ref(pids.held(), group);
    let threads: Vec<_> = g.threads().collect();
    for t in threads {
        let task = t.task();
        if t.raw() == current() || task.exiting.get() {
            continue;
        }
        task.exiting.set(true);
        // SAFETY: the other writer of these slots is the task's own `do_exit`,
        // under general_lock (`mm`) or pids_lock (the rest); this holds both.
        // The cleanup struct outlives the task.
        unsafe {
            // general_lock, because do_exit detaches task->mm under it and this
            // hands the same pointer over -- `exiting` is set late in do_exit,
            // so a thread that is already in there can still be seen here.
            // Taken under pids_lock, which is the order the procfs snapshot
            // uses.
            let _held = taskcalls::GeneralGuard::of(task);
            proctree::group_remove(g.raw(), t.raw());
            // Handed to the thread's own cleanup struct rather than flagged on
            // the task: the handler must not read the task, which task_destroy
            // can free while it runs.
            let cleanup = task.cleanup.load(Ordering::Relaxed);
            if let Some(cleanup) = cleanup.as_ref() {
                // `mm` is the second of the six to go through the atomic
                // hand-over, since 2026-09-11, and for the same reason
                // `sighand` was the first: it has readers on the task's own
                // thread that hold no lock. `taskview::current_mm` is one, and
                // it is what `brk`, `mmap` and `mprotect` reach the address
                // space through.
                //
                // **This comment used to say the three below were "excluded by
                // `pids_lock` instead", and that was wrong about all three.**
                // Each has a reader on the task's own thread holding no lock,
                // and the counterexample took one grep each: `f_get` reads
                // `files` on every descriptor syscall, `syscall_ref_hold` reads
                // and writes `syscall_refs` in the same function, and
                // `taskview::current_fs_info` reads `fs` on every path syscall.
                // All of them are `ArcSlot`s now, and `move_to` is the
                // hand-over.
                //
                // **This was two stores**, because `task.mem` cached
                // `&raw mut (*mm).mem` beside it and had to be nulled in step.
                // That field is gone and this is the whole of it: `mem_of`
                // derives the address space from `mm`, so a null `mm` *is* a
                // null address space and there is nothing left to keep in
                // step. What `run_loop` and `task_mem` read as "the valve gave
                // up on me" is this store.
                task.mm.move_to(&cleanup.mm);
                task.files.move_to(&cleanup.files);
                task.fs.move_to(&cleanup.fs);
                // The fifth, since 2026-09-09. It was *released* here, with a
                // comment saying "the disposition table is not something a
                // blocked syscall dereferences" — which is false: a thread
                // parked in `crates/util/waitfor` reads `task->sighand` on
                // waking, to decide whether a signal ended its wait, and a
                // thread parked in `wait_for` is exactly the population this
                // loop is about.
                //
                // It was safe anyway, by an argument about call order: this
                // runs before the exiting thread's own `detach_and_notify`, so
                // that thread still held a reference. `move_to` **transfers**
                // the reference rather than dropping it, so the object is alive
                // for a reader that captured the pointer before the store —
                // which is a property of these three lines instead of a fact
                // about when another function runs. That is the whole reason
                // for the change; nothing observable moves.
                //
                // **And it is a plain move again**, since 2026-09-12, where it
                // was an `AtomicPtr` on the task side between 2026-09-09 and
                // then. The atomic was there because
                // `taskview::signal_pending` loaded that word from the parked
                // thread's own stack holding **neither** `pids_lock` nor that
                // thread's `general_lock` -- `wait_for` is called with
                // arbitrary locks held, so it can take neither. That reader is
                // gone: a thread holds its own strong reference to its
                // disposition table for as long as it runs and reads *that*,
                // which is step 8 of `docs/object-model-arc.md`.
                //
                // So `sighand` is now in the same position as `files`, `fs` and
                // `syscall_refs`: every cross-thread reader takes `pids_lock`
                // -- `/proc/<pid>/fd` is the one with a changelog entry --
                // and this loop holds it.
                //
                // What the `Arc` settles that no ordering did: the four
                // hand-written obligations this comment used to carry. The
                // transfer cannot decrement, because it moves a value; the
                // reference is released exactly once, because a `Drop` does it;
                // and the `sighand_retain` at the `CLONE_SIGHAND` site has a
                // pair by construction.
                task.sighand.move_to(&cleanup.sighand);
            }
        }
        leaked += 1;
    }
    leaked
}

unsafe extern "C" {
    fn malloc_zone_pressure_relief(zone: *mut c_void, goal: usize) -> usize;
}
