//! Scalar `setpgid` policy, independent of the process registry.

use guest_errno::Errno;

use super::Pid;

// ---------------------------------------------------------------------------
// setpgid
// ---------------------------------------------------------------------------

/// What `setpgid` needs to know about the process it names and about the
/// caller, so that the rules can be decided without a task pointer.
#[derive(Clone, Copy, Debug)]
pub struct Setpgid {
    /// The process named, after `0` has been resolved to the caller.
    pub id: Pid,
    pub pgid: Pid,
    /// Is it the calling thread?
    pub is_caller: bool,
    pub is_leader: bool,
    /// Its session, and the caller's.
    pub sid: Pid,
    pub caller_sid: Pid,
    /// Its thread group's leader pid, for the session-leader rule.
    pub leader_pid: Pid,
    /// Only meaningful when `!is_caller`.
    pub parent_is_callers_group: bool,
    pub did_exec: bool,
    /// Whether the group being joined exists, and its session. `None` when
    /// `id == pgid`, where the group is being *created*.
    pub target_group_sid: Option<Pid>,
}

/// `Ok(())` to go ahead, or the guest errno.
///
/// Every check is here rather than beside the lookups, so the order can be
/// stated once and tested without a process table.
pub(crate) fn setpgid_check(s: &Setpgid) -> Result<(), Errno> {
    if !s.is_leader {
        // setpgid names a *process*, so a tid that is not a thread-group
        // leader is EINVAL -- not the ESRCH that looking a number up and
        // finding nothing would give.
        return Err(Errno::EINVAL);
    }
    if !s.is_caller {
        // A child of any thread of this process, not just of the calling
        // thread: a shell whose job control and whose spawning are on
        // different threads must still be able to place what it started.
        if !s.parent_is_callers_group {
            return Err(Errno::ESRCH);
        }
        // A child that has left for a session of its own is no longer ours.
        if s.sid != s.caller_sid {
            return Err(Errno::EPERM);
        }
        // And one that has already exec'd is no longer the program we started.
        // This is how a shell may place a child between fork and exec and not
        // after: the window is the child's to use.
        if s.did_exec {
            return Err(Errno::EACCES);
        }
    }
    // A session leader cannot leave its group, not even for one of its own.
    if s.sid == s.leader_pid {
        return Err(Errno::EPERM);
    }
    if s.id != s.pgid {
        // The group has to exist and be in the caller's session.
        match s.target_group_sid {
            None => return Err(Errno::EPERM),
            Some(sid) if sid != s.caller_sid => return Err(Errno::EPERM),
            Some(_) => {}
        }
    }
    Ok(())
}
