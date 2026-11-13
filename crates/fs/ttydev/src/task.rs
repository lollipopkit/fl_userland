//! Process-side operations supplied to the terminal subsystem.

use super::*;

/// Where the two `PidsHeld` tokens meet.
///
/// `fs-tty` cannot name `kernel_pids::PidsHeld` and `kernel-pids` cannot name
/// `fs_tty::ops::PidsHeld` — the dependency edge between those two crates runs
/// one way only, and an edge back would be a cargo cycle. This crate is the
/// only one that sits on both sides: it implements the `TaskOps` that
/// `fs/tty`'s `with_pids_lock` calls to take the lock, and it calls
/// `kernel-pids` with it held.
///
/// So this is the whole of the `unsafe` the two-token design costs: one
/// function, converting a proof into the same proof.
fn held(_pids: &fs_tty::ops::PidsHeld) -> &kernel_pids::PidsHeld {
    // SAFETY: the only way to hold a `fs_tty::ops::PidsHeld` is to be inside
    // `fs_tty::ops::with_pids_lock`, which acquires `pids_lock` through
    // `TaskOps::pids_lock` below -- and releases it in a `Drop` after the
    // closure returns, so it is still held for as long as the borrow lives.
    unsafe { kernel_pids::PidsHeld::assume() }
}

// ------------------------------------------------------------- the task side

fn caller_pgid() -> c_int {
    group(ffi::tgroup::pgid)
}

fn caller_sid() -> c_int {
    group(ffi::tgroup::sid)
}

fn caller_pid() -> c_int {
    taskview::current_pid()
}

fn caller_is_session_leader() -> bool {
    group(ffi::tgroup::sid) == taskview::current_pid()
}

fn caller_has_tty() -> bool {
    group(|g| g.ctty.has())
}

fn is_controlling(tty: fs_tty::ops::TtyId) -> bool {
    group(|g| g.ctty.is(tty))
}

/// `CAP_SYS_ADMIN`, which `TIOCSCTTY` asks before stealing a terminal.
fn sys_admin() -> bool {
    taskview::capable(taskview::caps::CAP_SYS_ADMIN)
}

fn pgrp_is_orphaned(pids: &fs_tty::ops::PidsHeld, pgid: c_int) -> bool {
    signaldeliver::pgrp_is_orphaned(held(pids), pgid)
}

fn signal_is_ignored(sig: c_int) -> bool {
    signaldeliver::signal_is_ignored_by_current(sig)
}

/// `SIGINFO_NIL`: a zeroed `struct siginfo_`, which is what every signal sent
/// from here carries.
fn nil_info() -> ffi::siginfo_ {
    // `Default`, not `mem::zeroed`: bindgen derives it for this type and
    // it is the same all-zero value without the contract.
    ffi::siginfo_::default()
}

fn send_group_signal_locked(pids: &fs_tty::ops::PidsHeld, pgid: c_int, sig: c_int) {
    signaldeliver::send_group_signal_locked(held(pids), pgid as c_uint, sig, nil_info());
}

fn send_group_signal(pgid: c_int, sig: c_int) {
    signaldeliver::send_group_signal(pgid as c_uint, sig, nil_info());
}

/// Every member of a process group is in the same session — `setpgid` refuses to
/// move a group across one — so the first is as good as any.
fn pgrp_session(pids: &fs_tty::ops::PidsHeld, pgid: c_int) -> Option<c_int> {
    kernel_pids::pgroup_at(held(pids), pgid, 0).map(kernel_pids::Group::sid)
}

/// See the module comment on the two locks.
fn set_controlling(_pids: &fs_tty::ops::PidsHeld, tty: &Arc<Tty>) {
    // The claim takes the terminal's lock, so it is made after the group has
    // answered and outside `ctty`'s -- see `crates/kernel/ctty`.
    if let Some((sid, pgid)) = group(|g| g.ctty.set_if_none(tty).then(|| (g.sid(), g.pgid()))) {
        fs_tty::tty::claim(tty, sid, pgid);
    }
}

/// Take the terminal away from the session that has it.
fn steal_controlling(pids: &fs_tty::ops::PidsHeld, sid: c_int, tty: fs_tty::ops::TtyId) {
    let mut i = 0;
    while let Some(tgroup) = kernel_pids::session_at(held(pids), sid, i) {
        i += 1;
        tgroup.ctty().clear_if(tty);
    }
}

/// A hangup signals the session's leader, and `SIGCONT` after `SIGHUP` so a
/// stopped shell gets to see it.
///
/// The leader only: Linux's `tty_signal_session_leader` skips every process
/// that is not one, and the shell is what passes the news on to its jobs.
/// This signalled every process in the session until 2026-11-12, so a
/// foreground job got a `SIGHUP` -- and a `SIGCONT` -- that Linux never sends
/// it (`ttyhup_probe`).
fn hangup_session(pids: &fs_tty::ops::PidsHeld, sid: c_int) {
    let mut i = 0;
    while let Some(tgroup) = kernel_pids::session_at(held(pids), sid, i) {
        i += 1;
        if tgroup.leader_pid() != sid {
            continue;
        }
        let Some(leader) = tgroup.leader_task() else {
            continue;
        };
        signaldeliver::send_process_signal(leader, ffi::SIGHUP_ as c_int, nil_info());
        signaldeliver::send_process_signal(leader, ffi::SIGCONT_ as c_int, nil_info());
    }
}


/// The process layer, as a terminal sees it.
///
/// A unit struct implementing `fs_tty::ops::TaskOps`. The small helper
/// functions below keep the process-side operations together while the trait
/// provides the checked interface consumed by `fs-tty`.
pub(super) struct TaskOps;

// SAFETY: nothing here holds a terminal pointer past the call it is given in,
// and `pids_lock`/`pids_unlock` are the real lock.
impl fs_tty::ops::TaskOps for TaskOps {
    fn pgid(&self) -> c_int {
        caller_pgid()
    }
    fn sid(&self) -> c_int {
        caller_sid()
    }
    fn pid(&self) -> c_int {
        caller_pid()
    }
    fn is_session_leader(&self) -> bool {
        caller_is_session_leader()
    }
    fn has_tty(&self) -> bool {
        caller_has_tty()
    }
    fn sys_admin(&self) -> bool {
        sys_admin()
    }
    fn orphaned(&self, pids: &fs_tty::ops::PidsHeld, pgid: c_int) -> bool {
        pgrp_is_orphaned(pids, pgid)
    }
    fn ignores(&self, sig: c_int) -> bool {
        signal_is_ignored(sig)
    }
    fn signal_group_locked(&self, pids: &fs_tty::ops::PidsHeld, pgid: c_int, sig: c_int) {
        send_group_signal_locked(pids, pgid, sig);
    }
    fn signal_group(&self, pgid: c_int, sig: c_int) {
        send_group_signal(pgid, sig);
    }
    fn session_of(&self, pids: &fs_tty::ops::PidsHeld, pgid: c_int) -> Option<c_int> {
        pgrp_session(pids, pgid)
    }
    fn hangup(&self, pids: &fs_tty::ops::PidsHeld, sid: c_int) {
        hangup_session(pids, sid);
    }
    fn caller_ids(&self) -> (u32, u32) {
        taskview::current_fsids()
    }

    fn is_controlling(&self, tty: fs_tty::ops::TtyId) -> bool {
        is_controlling(tty)
    }
    fn set_controlling(&self, pids: &fs_tty::ops::PidsHeld, tty: &Arc<Tty>) {
        set_controlling(pids, tty);
    }
    fn steal_controlling(&self, pids: &fs_tty::ops::PidsHeld, sid: c_int, tty: fs_tty::ops::TtyId) {
        steal_controlling(pids, sid, tty);
    }

    fn locked(&self, f: &mut dyn FnMut()) {
        let _pids = kernel_pids::PidsGuard::take();
        f();
    }
}

/// There is no test for this, and the reason is the trait.
///
/// An operation added to `fs_tty::ops::TaskOps` is a compile error here, so
/// there is nothing a test could catch. It was a struct literal naming
/// eighteen fields until 2026-09-09 and had the same property for the same
/// reason — a `#[test]` asserting one of them was `Some` stood in for saying
/// so. `tty_fd_ops` below is *not* that shape: it starts zeroed and assigns,
/// which is why that one has a test.
pub(super) static TASK_OPS: TaskOps = TaskOps;
