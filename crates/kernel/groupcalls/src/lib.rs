//! Which process group and which session a process is in: `setpgid`,
//! `getpgid`, `setsid` and `getsid`.
//!
//! These are the four calls a shell uses to build a job. The state they read
//! and write is the pid registry — `crates/kernel/pids` — and a thread group's
//! two cached numbers; what is here is the rules, which is where every defect in
//! this family was.
//!
//! # The rule that was neither an errno nor a refusal
//!
//! `setpgid` used to record a process *joining* a group under its **own**
//! number rather than the group's, so `kill(-pgid, ...)` reached only the member
//! that created the group. A `^C` to a two-process pipeline stopped one of them,
//! and nothing anywhere reported it. There is one writer of the number now —
//! [`set_pgid`] — and it moves the registry entry and the cached field together,
//! which is what makes them unable to name different things.
//!
//! # Its five rules, in Linux's order
//!
//! Checked in the order `sys_setpgid` checks them, because which error a caller
//! sees depends on it:
//!
//! 1. a negative `pgid` is `EINVAL`, before anything is looked up;
//! 2. a pid that names nothing is `ESRCH` — **including a zombie**, which still
//!    has a number and is still a process to `setpgid`;
//! 3. a tid that is not a thread-group leader is `EINVAL`, not `ESRCH`;
//! 4. for another process: it must be a child of *this thread group* (not of
//!    the calling thread — a shell whose job control and whose spawning are on
//!    different threads must still be able to place what it started), in the
//!    same session (`EPERM`), and must not have `exec`ed yet (`EACCES`);
//! 5. a session leader cannot leave its group, not even for one of its own
//!    (`EPERM`), and the group joined must exist and be in the caller's session.


use std::ffi::c_int;

use kernel_pids::{PidsGuard, PidsHeld};
use guest_errno::Errno;
use strace::strace;

type Pid = c_int;
// `Task` and `Group` were raw-pointer aliases here until 2026-09-30. Every
// task and group this crate touches is a `kernel_pids` handle now, which
// carries the proof that `pids_lock` is held.

/* `tty_ptr(identity: usize) -> *const Tty` was here until 2026-09-16: the
 * integer-to-pointer half of a handle `crates/kernel/ctty` stored as a
 * `usize`. It is a `TtyId` -- `Identity<Tty>` -- and hands back its own
 * address, so there is nothing to undo. */

// `struct task` and `struct tgroup` are named through `taskview::ffi` in the
// two aliases above. This crate had its own `build.rs` running bindgen for
// them until 2026-09-08, with a comment arguing that "an allowlist per crate
// is what keeps each ffi module to the names its own code uses" — which was an
// argument for generating a *third* copy of two structs that are hand-written
// Rust in one place. The `task_self` it also declared was dead: there is a
// Rust `task_self` below and nothing called the C one.

// `task_pid_of`, `task_group_of` and `task_did_exec` were here until
// 2026-09-30: three `unsafe fn` over a raw task pointer whose contract was
// "`pids_lock` is held". `kernel_pids::Task` is that contract as a type, and
// every caller had one or could.

/// The registry entries. `pids_lock` is held for every one of them.
///
/// A hand-written `extern "C"` block until 2026-09-06, which is the same C ABI
/// call as an `ffi::` one and was invisible to `tools/rust-c-abi.py` for the
/// same length of time.
use kernel_pids::{Group as GroupRef, pgroup_at, pidreg_session_len, session_at};

mod policy;
pub use policy::Setpgid;
pub(crate) use policy::setpgid_check;

pub fn sys_setpgid(mut id: Pid, mut pgid: Pid) -> Result<(), Errno> {
    strace!("setpgid({id}, {pgid})");
    let pids = PidsGuard::take();
    let Some(me) = pids.me() else {
        return Err(Errno::ESRCH);
    };
    if id == 0 {
        id = me.pid();
    }
    if pgid == 0 {
        pgid = id;
    }
    // Checked before anything is looked up, as Linux does. A negative number
    // reached the registry as an unsigned one, became enormous, found nothing,
    // and came back EPERM.
    if pgid < 0 {
        return Err(Errno::EINVAL);
    }

    // A zombie still has a number and is still a process to setpgid, which
    // finds it and then refuses for one of the reasons below.
    let Some(task) = pids.find(id) else {
        return Err(Errno::ESRCH);
    };
    // A task on its way out has left its group; it is past being moved.
    let (Some(group), Some(caller_group)) = (task.group(), GroupRef::current(pids.held())) else {
        return Err(Errno::ESRCH);
    };
    let target = if id != pgid {
        pgroup_at(pids.held(), pgid, 0).map(GroupRef::sid)
    } else {
        None
    };

    let state = Setpgid {
        id,
        pgid,
        is_caller: task.raw() == me.raw(),
        is_leader: task.is_leader(),
        sid: group.sid(),
        caller_sid: caller_group.sid(),
        leader_pid: group.leader_pid(),
        parent_is_callers_group: task
            .parent()
            .and_then(|p| p.group())
            .is_some_and(|g| g.id() == caller_group.id()),
        did_exec: task.did_exec(),
        target_group_sid: target,
    };
    setpgid_check(&state)?;

    if group.pgid() != pgid {
        group.set_pgid(pgid);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// getpgid and getsid
// ---------------------------------------------------------------------------

/// Both read one number off a thread group, and both take the same shape: `0`
/// is the caller, anything else has to be found.
///
/// `getsid` took **no** argument at all — the number the guest passed in `x0`
/// was ignored and every caller got its own session. Right for `getsid(0)`,
/// which is what almost everything passes, and silently wrong for the rest,
/// which is why nothing noticed.
fn group_number(pid: Pid, of: impl FnOnce(GroupRef) -> Pid) -> Result<Pid, Errno> {
    let pids = PidsGuard::take();
    let group = if pid == 0 {
        GroupRef::current(pids.held())
    } else {
        pids.find_live(pid).and_then(|t| t.group())
    };
    group.map(of).ok_or(Errno::ESRCH)
}

pub fn sys_getpgid(pid: Pid) -> Result<Pid, Errno> {
    strace!("getpgid({pid})");
    group_number(pid, |g| g.pgid())
}

pub fn sys_getsid(pid: Pid) -> Result<Pid, Errno> {
    strace!("getsid({pid})");
    group_number(pid, |g| g.sid())
}

// ---------------------------------------------------------------------------
// setsid
// ---------------------------------------------------------------------------

/// Leave the session's controlling terminal behind.
///
/// `pids_lock` is held. The reference is **taken before either call**: the
/// disown takes the terminal's own lock and the release may take it too, and
/// asking the process layer about a terminal takes this group's — see the
/// lock-order note in `crates/kernel/ctty`.
///
/// The `&PidsHeld` was a `/// # Safety: pids_lock is held` clause until
/// 2026-09-16 — see `crates/kernel/pids`' module comment. It took a raw task
/// and read its group until 2026-09-30; the group handle is the whole of what
/// it needed and says the lock is held on its own.
pub fn group_leave_session(pids: &PidsHeld, group: GroupRef<'_>) {
    let Some(held) = group.ctty().take() else {
        return;
    };
    let sid = group.sid();
    // Everyone but this group: the caller is on its way out of the session and
    // is about to be moved, so counting itself would keep every terminal's
    // session alive for ever.
    //
    // The session's leader may already have been reaped -- an orphaned
    // background job is exactly that -- and then there is nothing left that
    // could be found through it, which is what this count is asking.
    let mut others = pidreg_session_len(pids, sid);
    // Two identities compared. It was `identity == group` against a
    // `*mut tgroup` until 2026-09-15.
    if session_at(pids, sid, 0).map(GroupRef::id) == Some(group.id()) && others == 1 {
        others = 0;
    }
    if others == 0 {
        fs_tty::tty::disown(held.tty());
    }
    // The group's reference, given back after the disown and outside ctty's
    // lock, since the release takes the terminal table's.
    drop(held);
}

/// Make `group` the leader of a new session. It took a raw task, took
/// `pids_lock` itself and read the task's group, until 2026-09-30.
pub fn group_setsid(pids: &PidsHeld, group: GroupRef<'_>) -> Result<Pid, Errno> {
    let new_sid = group.leader_pid();
    // Already a session leader, or already a process-group leader: either way
    // there is a group that would be split in two.
    if group.pgid() == new_sid || group.sid() == new_sid {
        return Err(Errno::EPERM);
    }
    group_leave_session(pids, group);
    // Both under `new_sid`, the thread *group leader's* pid. A non-leader
    // calling setsid used to file both under its own tid, and nothing but a
    // signal to the group could tell.
    group.set_sid(new_sid);
    group.set_pgid(new_sid);
    Ok(new_sid)
}

pub fn sys_setsid() -> Result<Pid, Errno> {
    strace!("setsid()");
    let pids = PidsGuard::take();
    let group = GroupRef::current(pids.held()).ok_or(Errno::ESRCH)?;
    group_setsid(pids.held(), group)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A process placing itself in a group it creates: the ordinary case, and
    /// the one every other test is a deviation from.
    fn ok() -> Setpgid {
        Setpgid {
            id: 100,
            pgid: 100,
            is_caller: true,
            is_leader: true,
            sid: 1,
            caller_sid: 1,
            leader_pid: 100,
            parent_is_callers_group: true,
            did_exec: false,
            target_group_sid: None,
        }
    }

    #[test]
    fn the_ordinary_case_is_allowed() {
        // sid 1 and leader_pid 100: not a session leader, creating its own
        // group.
        assert_eq!(setpgid_check(&ok()), Ok(()));
    }

    /// A tid that is not a thread-group leader is `EINVAL` and not the `ESRCH`
    /// a failed lookup would give. The difference matters to a caller deciding
    /// whether the process exists.
    #[test]
    fn a_thread_is_not_a_process() {
        let s = Setpgid {
            is_leader: false,
            ..ok()
        };
        assert_eq!(setpgid_check(&s), Err(Errno::EINVAL));
    }

    /// A session leader cannot leave its group. Its session number *is* its
    /// leader's pid, which is the test.
    #[test]
    fn a_session_leader_cannot_leave_its_group() {
        let s = Setpgid {
            sid: 100,
            caller_sid: 100,
            ..ok()
        };
        assert_eq!(setpgid_check(&s), Err(Errno::EPERM));
    }

    /// Placing another process: it must be a child of the caller's *thread
    /// group*, in the same session, and not yet `exec`ed — and each failure has
    /// its own errno, in that order.
    #[test]
    fn placing_another_process_has_three_rules_in_order() {
        let other = Setpgid {
            is_caller: false,
            ..ok()
        };

        let orphan = Setpgid {
            parent_is_callers_group: false,
            ..other
        };
        assert_eq!(setpgid_check(&orphan), Err(Errno::ESRCH));

        let elsewhere = Setpgid { sid: 2, ..other };
        assert_eq!(setpgid_check(&elsewhere), Err(Errno::EPERM));

        let exec = Setpgid {
            did_exec: true,
            ..other
        };
        assert_eq!(setpgid_check(&exec), Err(Errno::EACCES));

        // The order: a child that is *both* in another session and has exec'd
        // reports the session, because that is the check Linux makes first.
        let both = Setpgid {
            sid: 2,
            did_exec: true,
            ..other
        };
        assert_eq!(setpgid_check(&both), Err(Errno::EPERM));

        // And a child that satisfies all three is placed.
        assert_eq!(setpgid_check(&other), Ok(()));
    }

    /// Joining a group is not the same as creating one: the group has to exist
    /// and be in the caller's session.
    #[test]
    fn joining_a_group_needs_the_group_to_be_there() {
        let joining = Setpgid {
            pgid: 200,
            target_group_sid: None,
            ..ok()
        };
        assert_eq!(setpgid_check(&joining), Err(Errno::EPERM), "no such group");

        let elsewhere = Setpgid {
            target_group_sid: Some(2),
            ..joining
        };
        assert_eq!(
            setpgid_check(&elsewhere),
            Err(Errno::EPERM),
            "a group in another session"
        );

        let here = Setpgid {
            target_group_sid: Some(1),
            ..joining
        };
        assert_eq!(setpgid_check(&here), Ok(()));
    }

    /// Creating a group does not consult the target, because there is none
    /// yet. A check that asked would refuse every `setpgid(pid, pid)`, which
    /// is how a shell starts a job.
    #[test]
    fn creating_a_group_does_not_look_for_it() {
        let creating = Setpgid {
            target_group_sid: None,
            ..ok()
        };
        assert_eq!(creating.id, creating.pgid);
        assert_eq!(setpgid_check(&creating), Ok(()));
    }
}
