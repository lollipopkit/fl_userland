//! Job-control state and transition policy.

use std::ffi::c_int;

use super::{EINVAL, ENOTTY, EPERM, ESRCH, O_NOCTTY};

/// The guest's pid type. 0 means "none" for both fields, which is what the C
/// used and what `TIOCGPGRP` reports as "no foreground group".
pub type Pid = c_int;

/// One terminal's job-control state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JobControl {
    /// The session that owns this terminal, or 0.
    session: Pid,
    /// The foreground process group, or 0.
    fg_group: Pid,
}

/// Which signal the operation would raise if it is refused. The two are not
/// symmetric, which is the point of naming them: a caller that ignores
/// `SIGTTIN` gets `EIO`, and one that ignores `SIGTTOU` is allowed to proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig {
    /// A read.
    Ttin,
    /// A write, or a change to the terminal's settings.
    Ttou,
}

/// What a process trying to use a terminal from the background should get.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Carry on. Either this is the foreground group, or the terminal is not
    /// this process's controlling one — which Linux allows freely.
    Allow,
    /// Stop the caller with this signal.
    Stop,
    /// `EIO`. An orphaned process group has nobody left who could continue it,
    /// so stopping it would be a hang rather than a suspension; Linux answers
    /// `EIO` without signalling. This kernel had no notion of an orphan at all,
    /// so a background job whose shell had exited stopped for good.
    Eio,
}

impl JobControl {
    pub fn new() -> JobControl {
        JobControl::default()
    }

    pub fn session(&self) -> Pid {
        self.session
    }

    pub fn fg_group(&self) -> Pid {
        self.fg_group
    }

    /// Is this terminal free for a session leader to claim?
    pub fn unowned(&self) -> bool {
        self.session == 0
    }

    /// The session leader has gone and nothing is left in the session.
    ///
    /// Only the session is cleared. The foreground group goes with the next
    /// claim, and leaving it means `TIOCGPGRP` keeps answering the same number
    /// until then — which is what the C did and what a caller reading a
    /// terminal nobody owns has no better answer for.
    pub fn disown(&mut self) {
        self.session = 0;
    }

    /// Linux's hangup and session-leader exit, which clear both the session
    /// and the foreground group: nothing owns the terminal afterwards, and
    /// the next claim starts from nothing.
    pub fn detach(&mut self) {
        self.session = 0;
        self.fg_group = 0;
    }

    /// Claimed as a controlling terminal by a session.
    pub fn claim(&mut self, sid: Pid, pgid: Pid) {
        self.session = sid;
        self.fg_group = pgid;
    }

    /// Whether an open should try to claim this terminal.
    ///
    /// `is_pty_master` is refused whatever the flags say. Linux's `tty_open`
    /// spells it out:
    ///
    /// ```c
    /// noctty = (filp->f_flags & O_NOCTTY) || ... ||
    ///          (tty->driver->type == TTY_DRIVER_TYPE_PTY &&
    ///           tty->driver->subtype == PTY_TYPE_MASTER);
    /// ```
    ///
    /// The master is the side a terminal emulator holds; the process group
    /// being controlled is on the slave, and there is nothing on the master
    /// side to control.
    pub fn open_claims(open_flags: c_int, is_pty_master: bool) -> bool {
        open_flags & O_NOCTTY == 0 && !is_pty_master
    }

    /// `TIOCGPGRP`.
    ///
    /// Asked of a terminal that is not the caller's controlling one, or of one
    /// with no foreground group, it is `ENOTTY` rather than a number the caller
    /// would then act on.
    pub fn get_pgrp(&self, is_current: bool) -> Result<Pid, c_int> {
        if !is_current || self.fg_group == 0 {
            return Err(ENOTTY);
        }
        Ok(self.fg_group)
    }

    /// `TIOCSPGRP`'s first two checks, which need nothing looked up.
    ///
    /// Split from [`set_pgrp`] because the order matters and is not the order
    /// the checks read in. Linux rejects a negative number *before* deciding
    /// whether the terminal is the caller's, so a negative pgid on someone
    /// else's terminal is `EINVAL`, not `ENOTTY`. A caller does the lookup for
    /// [`set_pgrp`] only if this returns `Ok`.
    pub fn set_pgrp_check(
        &self,
        want: Pid,
        is_current: bool,
        caller_sid: Pid,
    ) -> Result<(), c_int> {
        if want < 0 {
            return Err(EINVAL);
        }
        if !is_current || caller_sid != self.session {
            return Err(ENOTTY);
        }
        Ok(())
    }

    /// `TIOCSPGRP`'s remaining checks, and the store.
    ///
    /// `group_sid` is the session the wanted process group belongs to, or
    /// `None` if no such group exists — the one fact the caller has to look up.
    ///
    /// A refusal changes nothing. That is not obvious from the C this replaces,
    /// which stored the number and had no refusals to change anything after.
    pub fn set_pgrp(
        &mut self,
        want: Pid,
        is_current: bool,
        caller_sid: Pid,
        group_sid: Option<Pid>,
    ) -> Result<(), c_int> {
        self.set_pgrp_check(want, is_current, caller_sid)?;
        let Some(group_sid) = group_sid else {
            return Err(ESRCH);
        };
        if group_sid != caller_sid {
            return Err(EPERM);
        }
        self.fg_group = want;
        Ok(())
    }

    /// `TIOCSCTTY`: whether this terminal may be claimed, and how.
    ///
    /// `Ok(true)` means it must be stolen from the session that has it first;
    /// `Ok(false)` means it is free. `force` is the ioctl's argument and only
    /// means anything with `CAP_SYS_ADMIN`.
    pub fn set_ctty(
        &self,
        caller_is_session_leader: bool,
        caller_sid: Pid,
        caller_already_has_a_tty: bool,
        force: bool,
        sys_admin: bool,
    ) -> Result<Option<bool>, c_int> {
        // Already ours: nothing to do, and not an error.
        if caller_is_session_leader && caller_sid == self.session {
            return Ok(None);
        }
        if caller_already_has_a_tty {
            return Err(EPERM);
        }
        if self.session != 0 {
            if force && sys_admin {
                return Ok(Some(true));
            }
            return Err(EPERM);
        }
        Ok(Some(false))
    }

    /// Whether [`access`](Self::access) needs to know about orphans.
    ///
    /// The two cheap conditions decide it on their own — the terminal is not
    /// ours, or we *are* the foreground group — and they decide it for every
    /// read an interactive program makes. Asking this first is what lets the
    /// caller keep a kernel-wide lock off the common path: finding the caller's
    /// process group and asking whether it is orphaned both need `pids_lock`,
    /// which every fork, exit, wait and kill also takes.
    ///
    /// Measured: a 64-byte round trip through a pty cost 2.4 µs idle and 11.0 µs
    /// with three threads doing nothing but `getpgid`/`getsid`/`getppid`.
    pub fn access_needs_orphan(&self, is_current: bool, caller_pgid: Pid) -> bool {
        is_current && self.fg_group != 0 && caller_pgid != self.fg_group
    }

    /// A read, write or settings change from a group that may not be the
    /// foreground one.
    ///
    /// `is_current` is whether this terminal is the caller's controlling one —
    /// using a terminal that is not is allowed freely, which is surprising and
    /// is what Linux does.
    ///
    /// `ignored` is whether the caller has ignored *or blocked* the signal. The
    /// order of the last two checks is Linux's and is not the order they read
    /// in: `is_ignored` is consulted **before** the group is asked whether it is
    /// orphaned. So an orphaned group that ignores `SIGTTOU` is allowed to
    /// proceed, where asking about the orphan first would refuse it.
    ///
    /// It is also the cheaper question, so a caller that ignores the signal
    /// never needs the orphan answer at all — and finding that out is what
    /// costs a kernel-wide lock.
    pub fn access(
        &self,
        is_current: bool,
        caller_pgid: Pid,
        sig: Sig,
        ignored: bool,
        orphaned: bool,
    ) -> Access {
        if !self.access_needs_orphan(is_current, caller_pgid) {
            return Access::Allow;
        }
        if ignored {
            // Taken at its word for a write; a read cannot be, because there
            // would be nothing to return and the caller would spin.
            return match sig {
                Sig::Ttin => Access::Eio,
                Sig::Ttou => Access::Allow,
            };
        }
        if orphaned {
            return Access::Eio;
        }
        Access::Stop
    }

    /// Who a hangup signals: the session, if one owns this terminal.
    pub fn hangup_target(&self) -> Option<Pid> {
        (self.session != 0).then_some(self.session)
    }
}
