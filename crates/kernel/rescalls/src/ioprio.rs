//! `ioprio_get` and `ioprio_set`.
//!
//! Nothing here schedules I/O — what backs a guest file is a host file and the
//! host decides the order — so a priority is remembered and reported, like the
//! `prctl` attributes it shares `crates/kernel/procattr` with. The rules are
//! that crate's and were measured against a real arm64 kernel; what is here is
//! finding the tasks a request names.
//!
//! Both calls used to answer 0 for every argument, including a `which` that is
//! not one of the three, a pid that does not exist, and a class the kernel has
//! no name for. A program probing for real-time I/O priority was told it had it.

use std::ffi::c_int;

use strace::strace;

use guest_errno::Errno;
use crate::ffi;

const WHO_PROCESS: c_int = 1;
const WHO_PGRP: c_int = 2;
#[allow(dead_code)]
const WHO_USER: c_int = 3;

/// `pids_lock`, held for a scope. `crates/kernel/pids` owns it.
use kernel_pids::PidsGuard as Pids;
use kernel_pids::{Group, Task};

/// The task a `WHO_PROCESS` request names, lent under the guard.
fn task_of(pids: &Pids, who: c_int) -> Option<Task<'_>> {
    match who {
        0 => pids.me(),
        1.. => pids.find_live(who),
        _ => None,
    }
}

/// Every task a `WHO_PGRP` or `WHO_USER` request names.
///
/// The count is what tells "none of them" — which is `ESRCH` — from "all of them
/// said no". **`pids_lock` is held**, which is why neither arm calls
/// `task_next_live_pid`: that one takes the lock itself, and calling it here
/// deadlocked the emulator on the first `ioprio_get`.
///
/// Handles rather than addresses in a `Vec<usize>`, which is what this
/// collected until 2026-09-30 and each caller cast back to a task.
fn tasks_named(pids: &Pids, which: c_int, who: c_int) -> Vec<Task<'_>> {
    let me = pids.me();
    if which == WHO_PGRP {
        // The registry has this one exactly: the thread groups in a process
        // group, and proctree has each one's threads.
        let pgid = if who != 0 {
            who
        } else {
            me.and_then(|t| t.group()).map_or(0, Group::pgid)
        };
        let groups = kernel_pids::pidreg_pgroup_len(pids.held(), pgid);
        return (0..groups)
            .filter_map(|i| kernel_pids::pgroup_at(pids.held(), pgid, i))
            .flat_map(Group::threads)
            .collect();
    }

    // A *user* is not a list anything keeps, so this one scans. It is bounded by
    // MAX_PID and runs under pids_lock, which is the emulator's hottest lock --
    // acceptable only because nothing calls ioprio by user: `ionice` uses -p and
    // -g. If something ever does, the fix is an index, not a longer hold.
    let uid = if who != 0 {
        who as u32
    } else {
        me.map_or(0, |t| t.uid())
    };
    (1..=ffi::MAX_PID as c_int)
        .filter_map(|pid| pids.find_live(pid))
        .filter(|t| t.uid() == uid)
        .collect()
}

pub fn sys_ioprio_get(which: c_int, who: c_int) -> Result<c_int, Errno> {
    strace!("ioprio_get({which}, {who})");
    // Before the lookup: an unknown `which` is EINVAL whatever `who` is.
    if !kernel_procattr::ioprio_which_valid(which) {
        return Err(Errno::EINVAL);
    }
    let pids = Pids::take();
    if which == WHO_PROCESS {
        return task_of(&pids, who).map(|t| t.attr().ioprio()).ok_or(Errno::ESRCH);
    }
    // The best over the set, where a task that has never set one counts as
    // best-effort at the middle level rather than as zero. That is why the same
    // question about one task answers 0 and about its group answers the default
    // -- see procattr::ioprio_best.
    let tasks = tasks_named(&pids, which, who);
    if tasks.is_empty() {
        return Err(Errno::ESRCH);
    }
    Ok(tasks
        .iter()
        .map(|t| t.attr().ioprio())
        .fold(kernel_procattr::IOPRIO_BEST_DEFAULT, kernel_procattr::ioprio_best))
}

pub fn sys_ioprio_set(which: c_int, who: c_int, ioprio: c_int) -> Result<(), Errno> {
    strace!("ioprio_set({which}, {who}, {ioprio:#x})");
    // `ioprio_check_cap`: the real-time class is CAP_SYS_NICE's or
    // CAP_SYS_ADMIN's. A container's root does not have the second, so it is
    // one of the things differential.sh cannot arbitrate without the first --
    // see tests/guest/src/bin/misc_abi.rs.
    let privileged = taskview::capable(taskview::caps::CAP_SYS_NICE) || taskview::capable(taskview::caps::CAP_SYS_ADMIN);
    // Before `which`, and before `who` is resolved: Linux calls
    // ioprio_check_cap at the top of the syscall, so a malformed priority aimed
    // at a pid that does not exist is EINVAL rather than ESRCH.
    kernel_procattr::ioprio_check(ioprio as u32, privileged)
        .map_err(Errno::from_negative_or_eio)?;
    if !kernel_procattr::ioprio_which_valid(which) {
        return Err(Errno::EINVAL);
    }

    let pids = Pids::take();
    let tasks = if which == WHO_PROCESS {
        task_of(&pids, who).into_iter().collect()
    } else {
        tasks_named(&pids, which, who)
    };
    if tasks.is_empty() {
        return Err(Errno::ESRCH);
    }
    // The value was judged once, above, before any task was found -- so this
    // cannot fail, and the first error is recorded rather than acted on. Kept
    // as a check because "cannot fail" is a claim about the caller.
    let mut err = 0;
    for task in tasks {
        // `set_task_ioprio`, which stops at the first task it may not change.
        if !taskview::with_current_creds(|mine| mine.may_set_ioprio(task.creds())).unwrap_or(false) {
            return Err(Errno::EPERM);
        }
        let r = task.with_attr_mut(|a| a.set_ioprio(ioprio as u32, privileged));
        if let Err(e) = r
            && err == 0
        {
            err = e;
        }
    }
    applied(err)
}

/// What the loop above recorded. See `apply`: the value was judged once before
/// any task was found, so this is 0 on every path a caller can produce.
fn applied(err: c_int) -> Result<(), Errno> {
    if err == 0 {
        Ok(())
    } else {
        Err(Errno::from_negative_or_eio(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_whos_are_linuxs_numbers() {
        // IOPRIO_WHO_PROCESS, _PGRP and _USER from linux/ioprio.h. An unknown
        // one is EINVAL, which is how a program tells "not implemented" from
        // "implemented and refused".
        assert_eq!(WHO_PROCESS, 1);
        assert_eq!(WHO_PGRP, 2);
        assert_eq!(WHO_USER, 3);
    }

    /// The scan's bound. It is the pid space, and it runs under `pids_lock`.
    #[test]
    fn the_user_scan_is_bounded_by_the_pid_space() {
        const {
            assert!(ffi::MAX_PID > 0);
        }
    }
}
