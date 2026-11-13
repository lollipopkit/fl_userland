//! Ending an embedder's session: the two things a host app does to a guest
//! process it started and is now closing.
//!
//! ServerBox did both by reaching into the engine -- `pid_get_task`, then
//! `send_group_signal(task->group->pgid, ...)` and `tty_disown(task->group)` --
//! which stopped being possible when `struct task` became opaque Rust. The
//! embedder example, `tests/integration/sbm_api_test.c`, skipped session close
//! entirely, which is why nothing noticed the interface did not have it.
//! Measured on 2026-09-29 by compiling ServerBox's `sbm_iul.c` against `iul.h`.
//!
//! Both take a pid rather than a task: the embedder remembers the pid of the
//! session it started, and a pointer it kept would dangle once that task is
//! reaped. The lookup and the use are one hold of `pids_lock`.

use std::ffi::c_int;

use guest_errno::c_int_::ESRCH;
use kernel_pids::PidsGuard;

/// Send `sig` to the process group of the process `pid`, as the kernel would
/// -- `si_code` `SI_KERNEL`, no sender. `0`, or `_ESRCH` for a pid that names
/// no live process.
///
/// A session is a process group: `sh` and whatever it is running in the
/// foreground. `SIGHUP` is what closing a terminal sends, and what a shell
/// takes as its terminal going away; `SIGKILL` is for a session that never
/// started.
#[unsafe(no_mangle)]
pub extern "C" fn iul_kill_process_group(pid: c_int, sig: c_int) -> c_int {
    let pids = PidsGuard::take();
    let Some(group) = pids.find_live(pid).and_then(|t| t.group()) else {
        return ESRCH;
    };
    let pgid = group.pgid();
    signaldeliver::send_group_signal_locked(pids.held(), pgid as u32, sig, signaldeliver::receive::kernel_info())
}

/// Make the session of the process `pid` give up its controlling terminal
/// now, rather than when its leader is reaped. `0`, or `_ESRCH`.
///
/// The group holds a reference to the terminal for as long as it is a
/// session leader, and it is given back on the way out of the session -- at
/// reaping. An embedder's sessions are children of an init that never waits,
/// so nothing reaps them, and the pty stayed allocated for the life of the
/// app: `/dev/pts` could never be unmounted and the system it belonged to
/// could never be detached. ServerBox found that on a device. This is the
/// same step reaping takes, `group_leave_session`, taken when the embedder
/// closes the terminal instead.
#[unsafe(no_mangle)]
pub extern "C" fn iul_leave_terminal(pid: c_int) -> c_int {
    let pids = PidsGuard::take();
    let Some(task) = pids.find(pid) else {
        return ESRCH;
    };
    if let Some(group) = task.group() {
        groupcalls::group_leave_session(pids.held(), group);
    }
    0
}
