//! Signal target selection for `kill(2)`, `tgkill(2)`, and `tkill(2)`.

use kernel_pids::PidsGuard;
use signaldeliver::signal_kill_task_for_rs;
use strace::strace;

use super::*;

// ---------------------------------------------------------------------------
// kill and its four spellings
// ---------------------------------------------------------------------------
//
// The split against `kernel/signal.c` is **which tasks** against **how to
// deliver**. Choosing them is here, and that is where every defect in this
// family was: `kill(0, sig)` re-encoded as `kill(-pgid, sig)` and becoming a
// broadcast, and the empty-group path unlocking `pids_lock` a second time.
// Delivery stays in C because it reaches sighand, the target's queue and the
// thread choice.

/// Queue a signal on one task — `crates/kernel/signaldeliver`, called as Rust.
///
/// It was a hand-written `extern "C"` declaration until 2026-09-09, because the
/// two crates were mutually dependent: delivery held the six `sys_*` entry
/// points for the syscalls this crate implements. Those are here now (see the
/// block below), so the cycle is gone and this is an ordinary call.
///
/// Worth keeping the note that declaration carried: its parameter said
/// `*mut c_void` where the definition said `*mut ffi::task`, so the two halves
/// of the interface disagreed and nothing could have said so. **Nothing checks
/// a C ABI declaration against its definition** — `tools/extern-signatures.py`
/// counts parameters and would not have caught this one.
/// `MAX_SIG` from `kernel/signal.h`.
pub(super) const MAX_SIG: c_uint = 64;
/// `MAX_PID` from `kernel/task.h`.
const MAX_PID: c_int = 1 << 15;

pub(super) use guest_errno::Errno;

/// What `signal_kill_task_for_rs` and the rest of the signal layer answer: 0,
/// or a negative guest errno.
pub(super) fn done(err: c_int) -> Result<(), Errno> {
    if err < 0 {
        Err(Errno::from_negative_or_eio(err))
    } else {
        Ok(())
    }
}

/// Every process in a process group.
///
/// `ESRCH` for a group with no members, and otherwise the *best* answer any of
/// them gave: killing a group fails only when no process could be signalled.
///
/// The lock is held throughout and is **not** released here. It was, on this
/// path only, and `do_kill` released it again — so `kill(-99999, 0)` from any
/// guest process was a double unlock of the global process-table lock. A
/// pthread mutex does not check ownership, so the second release handed the
/// lock away from whichever thread had since acquired it, leaving two of them
/// inside the process table at once.
pub(super) fn kill_group(
    guard: &PidsGuard,
    pgid: c_int,
    sig: c_uint,
    given: Option<SigInfo>,
) -> Result<(), Errno> {
    let groups = guard.pgroup(pgid);
    if groups.is_empty() {
        return Err(Errno::ESRCH);
    }
    // `EPERM` is the "nothing better yet" marker as well as an answer, which is
    // what makes "the best any of them gave" one comparison.
    let mut answer = Err(Errno::EPERM);
    for g in groups {
        // SAFETY: the guard is `pids_lock`, which is what keeps every
        // group the registry answered alive for the length of this loop.
        let g = g.as_ptr();
        // SAFETY: as above -- the group is live, and so is its leader if it
        // has one.
        let Some(leader) = (unsafe { kernel_pids::Task::from_raw(guard.held(), (*g).leader()) }) else {
            continue;
        };
        let one = done(signal_kill_task_for_rs(leader, sig, false, given));
        if answer == Err(Errno::EPERM) {
            answer = one;
        }
    }
    answer
}

/// `kill(-1, sig)`: every process this one may signal, except itself.
fn kill_everything(guard: &PidsGuard, sig: c_uint) -> Result<(), Errno> {
    let me = taskview::current();
    let mut answer = Err(Errno::EPERM);
    for pid in 2..MAX_PID {
        let Some(task) = guard.find_live(pid) else {
            continue;
        };
        if task.raw() == me || !task.is_leader() {
            continue;
        }
        let one = done(signal_kill_task_for_rs(task, sig, false, None));
        if answer == Err(Errno::EPERM) {
            answer = one;
        }
    }
    answer
}

/// The four spellings, and the one place that decides what a pid means.
pub(super) fn do_kill(
    pid: c_int,
    sig: c_uint,
    tgid: c_int,
    thread_directed: bool,
    given: Option<SigInfo>,
) -> Result<(), Errno> {
    strace!("kill({pid}, {sig})");
    if sig > MAX_SIG {
        return Err(Errno::EINVAL);
    }
    let guard = PidsGuard::take();

    // `kill(0, sig)` is this process's own group, and it must not be re-encoded
    // as `kill(-pgid, sig)` on the way there.
    //
    // It was, and -1 is not a process group -- it is *every* process. A guest
    // whose process group is 1, which the first process's is, turned
    // `kill(0, SIGTERM)` into a broadcast; what saved it was that
    // kill_everything skips the caller and then answers EPERM when it found
    // nothing else, so the call failed instead of killing the machine. A second
    // process in that group would have been killed by a call that means "signal
    // my own group".
    //
    // Linux does not do the round trip: `pid ? find_vpid(-pid) :
    // task_pgrp(current)`.
    if pid == 0 {
        return kill_group(&guard, taskview::current_pgid(), sig, None);
    }
    if pid == -1 {
        return kill_everything(&guard, sig);
    }
    if pid < 0 {
        return kill_group(&guard, -pid, sig, None);
    }

    let Some(task) = guard.find_live(pid) else {
        return Err(Errno::ESRCH);
    };
    // If tgid is nonzero, it must be correct.
    if tgid != 0 && task.tgid() != tgid {
        return Err(Errno::ESRCH);
    }
    done(signal_kill_task_for_rs(task, sig, thread_directed, given))
}

pub fn sys_kill(pid: c_int, sig: c_uint) -> Result<(), Errno> {
    do_kill(pid, sig, 0, false, None)
}

// tgkill and tkill name a thread, so the choice `signal_thread` makes for
// kill() must not happen here: the signal goes to the thread asked for even
// when that thread has it blocked, and sits pending there.

pub fn sys_tgkill(tgid: c_int, tid: c_int, sig: c_uint) -> Result<(), Errno> {
    if tid <= 0 || tgid <= 0 {
        return Err(Errno::EINVAL);
    }
    do_kill(tid, sig, tgid, true, None)
}

pub fn sys_tkill(tid: c_int, sig: c_uint) -> Result<(), Errno> {
    if tid <= 0 {
        return Err(Errno::EINVAL);
    }
    do_kill(tid, sig, 0, true, None)
}

/// `restart_syscall` (128).
///
/// Not something userspace calls on purpose: the kernel puts it in place of an
/// interrupted syscall that is to be resumed, and the signal return runs it.
/// Nothing here sets up a restart, so it is always the "no restart was pending"
/// case — which Linux spells `do_no_restart_syscall`, and which returns
/// `EINTR`. It was a stub, so it answered `ENOSYS`, and a caller that reached it
/// by any route saw a different error from the one that would have come out of
/// the syscall it replaced.
pub fn sys_restart_syscall() -> Result<(), Errno> {
    strace!("restart_syscall()");
    Err(Errno::EINTR)
}
