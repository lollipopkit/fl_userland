//! `execve` in a process with more than one thread: Linux's `de_thread`.
//!
//! The exec'ing thread ends every other thread of its group, as a group exit
//! would, and waits until they are gone. If it is not the leader it then takes
//! the leader's place: its tid becomes the process's pid, the old leader is
//! released without its parent hearing of it, and the process keeps its start
//! time. Until 2026-11-13 none of this happened: the other threads went on
//! running the old program in the new address space's group, and the pid
//! still named the old leader (`execthreads_probe`).
//!
//! The ending is `do_exit_group`'s: the same `SIGKILL` to each thread, the
//! same wait for their host threads, the same valve for one that does not
//! report in. What differs is the group's exit word, which says *exec by this
//! tid* rather than *exiting* (`crates/kernel/groupexit`): every reader that
//! lets a thread go -- the run loop, the syscall return, a host wait -- asks
//! `must_leave` with its own tid, so the exec'ing thread is the one that
//! stays, and a waiter or a pidfd sees no exit at all.
//!
//! A fatal signal sent while the exec waits ends the whole group, the exec'ing
//! thread included, as Linux's `complete_signal` and `de_thread` agree: the
//! sender turns the word into an exit (`GroupExit::signalled`), and this
//! thread, done waiting, finds the exec overtaken and leaves with the
//! signal's status instead of taking the leader's place. Until 2026-11-13 the
//! signal was acted on by whichever thread took it, one of those already
//! being ended, which left alone while the exec went on (`sigfatal_probe`).

use super::*;
use super::group::{kill_others, wait_for_peers};
use std::sync::atomic::Ordering;

/// End the calling thread's peers and make it its group's leader.
///
/// Answers the tid the caller had, which is what its PI futexes are recorded
/// under; it is the process's pid from here on. `Err` with a status when the
/// group is already exiting or another thread's `execve` has it: the caller is
/// one of the threads being ended, and leaves with that status.
///
/// On the exec'ing thread, holding no lock, before anything of the old image
/// is released.
pub fn de_thread() -> Result<c_int, c_int> {
    let me = current();
    let my_tid = taskview::current_pid();
    taskview::with_current_group(|group| {
        let threads = {
            let pids = Pids::take();
            let g = kernel_pids::Group::from_ref(pids.held(), group);
            // The ordinary exec: one thread, the leader. A leader that left
            // with `pthread_exit` is not in the list and still has to be
            // replaced, so this asks who leads rather than only how many.
            if g.thread_count() == 1 && g.leader() == me {
                return Ok(my_tid);
            }
            group.exit.begin_exec(my_tid).map_err(|status| status as c_int)?;
            kill_others(g, true)
        };

        // The host threads, not the thread list: a thread leaves the list
        // partway through `do_exit` and keeps running after it, and the old
        // leader's task is freed below. A leader that exited before this
        // exec is counted until its own cleanup has run.
        if group.hosts.live() > 1 {
            wait_for_peers(group, threads.max(2));
        }
        // What the valve gave up on is still running, so its task cannot be
        // freed; see `take_over`.
        let abandoned = group.hosts.live() > 1;

        let pids = Pids::take();
        let g = kernel_pids::Group::from_ref(pids.held(), group);
        debug_assert!(
            g.threads().all(|t| t.raw() == me),
            "every other thread has left the group"
        );
        // Under `pids_lock`, which a sender to another process holds, and no
        // other thread is left to send from: a fatal signal either overtook
        // the exec before this or finds a process of one thread after it.
        group.exit.end_exec(my_tid).map_err(|status| status as c_int)?;
        if g.leader() != me {
            // SAFETY: the group's leader, live under the lock; it has exited.
            let leader = unsafe { kernel_pids::Task::from_raw(pids.held(), g.leader()) }
                .expect("a group has a leader");
            take_over(pids.held(), g, leader, abandoned);
        }
        Ok(my_tid)
    })
    .expect("execve on a task with no group")
}

/// The calling thread becomes `leader`, which has exited: Linux's
/// `exchange_tids` and the rest of `de_thread`'s non-leader half. Under
/// `pids_lock`, with no other thread left in the group.
fn take_over(pids: &PidsHeld, g: kernel_pids::Group<'_>, leader: kernel_pids::Task<'_>, abandoned: bool) {
    let me = kernel_pids::Task::current(pids).expect("execve runs in a task");
    let (tgid, old_tid) = (leader.pid(), me.pid());

    // Its children came to this thread when it exited (`reparent_children`
    // takes a live sibling first), unless the valve gave up on it, which
    // reparents nothing.
    let children: Vec<_> = leader.children().collect();
    for child in children {
        proctree::set_parent(child.raw(), me.raw());
    }
    // A thread is already its process's parent's child; this keeps it so if
    // the two ever differ.
    proctree::set_parent(me.raw(), proctree::parent(leader.raw()));

    // The numbers swap, each keeping its generation: a pidfd for the process
    // names this task now, and one for this thread's old tid names the old
    // leader, which goes next.
    let swapped = kernel_pids::exchange(pids, tgid, old_tid);
    debug_assert!(swapped, "both numbers hold a task");
    me.task().pid.store(tgid, Ordering::Relaxed);
    leader.task().pid.store(old_tid, Ordering::Relaxed);
    g.tgroup().leader.store(me.raw(), Ordering::Release);
    // "When we take on its identity by switching to its PID, we also take its
    // birthdate" -- Linux's comment; `/proc/<pid>/stat` field 22 is the
    // process's, measured.
    me.task().start_ticks.store(leader.start_ticks(), Ordering::Relaxed);
    me.task().exit_signal.store(ffi::SIGCHLD_ as c_int, Ordering::Relaxed);

    if abandoned {
        // Its host thread may be one the valve gave up on, still inside a
        // host call and still holding the task as `current`. Out of every
        // table, and the struct left to it, as the valve leaves the others.
        proctree::remove(leader.raw());
        kernel_pids::set_task(pids, old_tid, std::ptr::null_mut());
        kernel_pidfd::notify_gone(old_tid);
    } else {
        // Released without a word to the parent: the process did not exit.
        // SAFETY: the old leader has exited and its host thread has finished;
        // nothing holds it.
        unsafe { taskcalls::task_destroy(pids, leader.raw()) };
    }
}
