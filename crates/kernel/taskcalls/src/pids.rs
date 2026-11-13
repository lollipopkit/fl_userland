//! Task and process id registry traversal.

use std::sync::atomic::Ordering;
use kernel_pids::PidsHeld;
use super::*;

/// The next live pid strictly greater than `after`, or 0 when there is none.
/// Every task, threads included: what `/proc/loadavg` and `/proc/stat` count.
/// The `/proc` listing itself is [`task_next_listed_pid`].
///
/// procfs walks pids. The C did that by taking `pids_lock`, stepping one pid,
/// and dropping it again — once per directory entry, and once per empty slot
/// in between, of which there are up to `MAX_PID`. One hold covers the whole
/// scan.
pub fn task_next_live_pid(after: c_int) -> c_int {
    let pids = Pids::take();
    let mut pid = after;
    loop {
        pid += 1;
        if pid > ffi::MAX_PID as c_int {
            return 0;
        }
        if live_task(pids.held(), pid).is_some() {
            return pid;
        }
    }
}

/// The next pid `/proc` lists, strictly greater than `after`, or 0.
///
/// What `/proc` lists is **processes**: every thread-group leader, a zombie
/// included -- `ps` shows a `<defunct>` process and an unreaped child is one.
/// Not threads, which have a pid of their own and are reachable by naming
/// it, as they are on Linux, but are listed under their process's `task`.
/// Until 2026-09-04 `/proc` was the walk above, so every thread of a
/// process was listed as a process of its own and no zombie was listed at
/// all.
pub fn task_next_listed_pid(after: c_int) -> c_int {
    let pids = Pids::take();
    let mut pid = after;
    loop {
        pid += 1;
        if pid > ffi::MAX_PID as c_int {
            return 0;
        }
        if kernel_pids::Task::by_pid(pids.held(), pid).is_some_and(|t| t.leads_group()) {
            return pid;
        }
    }
}

/// The task registered for `pid`, or null — and **null for a zombie**, which is
/// what `pid_get_task` means and what every caller but the reaper wants.
fn live_task(pids: &PidsHeld, pid: c_int) -> Option<kernel_pids::Task<'_>> {
    kernel_pids::Task::by_pid(pids, pid).filter(|t| !t.is_zombie())
}

/// The `&PidsHeld` was a `/// # Safety: pids_lock is held by the caller`
/// clause until 2026-09-16 — see `crates/kernel/pids`' module comment. What it
/// buys the *caller* is nothing, and what it buys the reader is that a caller
/// which does not hold the lock cannot be written: the answer is a raw pointer
/// the lock is what keeps alive, so the two have to be in scope together.
pub fn pid_get_task(pids: &PidsHeld, id: u32) -> *mut ffi::task {
    live_task(pids, id as c_int).map_or(std::ptr::null_mut(), |t| t.raw())
}

/// A zombie counts. `waitid(P_PIDFD)` and `/proc/<pid>` of an unreaped child
/// both need one. As [`pid_get_task`] otherwise.
pub fn pid_get_task_zombie(pids: &PidsHeld, id: u32) -> *mut ffi::task {
    kernel_pids::pidreg_task(pids, id as c_int)
}

/// `set_tid_address(2)` — where to write a zero and which futex to wake when
/// this thread dies.
///
/// Linux answers `task_pid_vnr(current)`, which is the caller's **thread** id.
/// The C returned `sys_getpid()`, the thread *group* id, and the two are the
/// same number for a main thread — so nothing noticed. Every threading runtime
/// calls this, and one that believed the answer had every thread claiming to
/// be the process.
///
/// The word itself is cleared and the futex woken in `crates/kernel/exitcalls`.
pub fn sys_set_tid_address(tid: u64) -> c_int {
    taskview::with_current_task(|t| {
        t.clear_tid.store(tid, Ordering::Relaxed);
        t.pid() as c_int
    })
    .expect("set_tid_address runs on a task")
}
