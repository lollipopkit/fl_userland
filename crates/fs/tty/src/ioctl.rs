//! The terminal's ioctls.
//!
//! `pids_lock` is taken for every one of them rather than for the ones that
//! turn out to need it. Three do — `TIOCSCTTY` and `TIOCSPGRP` read a session,
//! `TIOCSWINSZ` signals a process group — and each used to carry its own
//! `unlock; lock(pids); lock` dance under a comment that read "locking is
//! ***hard**". The third did not, and took the terminal's lock and then
//! `pids_lock`, which is the opposite of the order a session teardown takes
//! them in: two threads, one in `TIOCSWINSZ` and one in `task_leave_session`,
//! deadlock.
//!
//! Taking it here makes the order one-directional for the whole file and
//! deletes both dances. It costs a global acquisition on `TCGETS`, which is on
//! no hot path — reads and writes do not come through here.

use crate::ops::{Pid, PidsHeld, TtyId, task};
use crate::pty;
use crate::tty::{self, Kind, Tty};
use ldisc::{Termios, Termios2};
use std::ffi::c_int;
use std::sync::Arc;

pub const TCGETS: c_int = 0x5401;
pub const TCSETS: c_int = 0x5402;
pub const TCSETSW: c_int = 0x5403;
pub const TCSETSF: c_int = 0x5404;
/// The `termios2` forms, which is what a **modern glibc actually calls**:
/// `tcgetattr`, `tcsetattr` and therefore `isatty` use these where the kernel
/// has them, and fall back to the four above only on `ENOTTY`... except that
/// glibc does not fall back — it reports the error. So these being missing made
/// `isatty()` false for every terminal on Ubuntu, and sshd refused every
/// interactive session because `openpty` then failed `ttyname`.
///
/// The numbers are `_IOR('T', 0x2A, struct termios2)` and its three siblings,
/// so the size is in them: `0x2c` is 44. They do not fit an `i32`, which is
/// what `cmd` is by the time a driver sees it.
pub const TCGETS2: c_int = 0x802c_542au32 as c_int;
pub const TCSETS2: c_int = 0x402c_542bu32 as c_int;
pub const TCSETSW2: c_int = 0x402c_542cu32 as c_int;
pub const TCSETSF2: c_int = 0x402c_542du32 as c_int;
pub const TCFLSH: c_int = 0x540b;
pub const TIOCSCTTY: c_int = 0x540e;
pub const TIOCGPGRP: c_int = 0x540f;
pub const TIOCSPGRP: c_int = 0x5410;
/// The session that owns the terminal. Missing until 2026-11-11, so `tcgetsid`
/// and `ps`'s session column answered `ENOTTY` for every terminal.
pub const TIOCGSID: c_int = 0x5429;
pub const TIOCGWINSZ: c_int = 0x5413;
pub const TIOCSWINSZ: c_int = 0x5414;
pub const FIONREAD: c_int = 0x541b;
/// Bytes still in the output queue. There is no output buffer here — a write
/// reaches the other end or the host immediately — so the answer is always
/// zero, which is what a caller waiting for the queue to drain needs to see.
pub const TIOCOUTQ: c_int = 0x5411;
/// Drain the output and, with a non-zero argument, send a break. Nothing here
/// has an output queue to drain and a pseudoterminal has no line to break, so
/// both are a no-op — but `ENOTTY` is not: `tcdrain` and `tcsendbreak` are
/// built on this, and a shell restoring a terminal calls the first.
pub const TCSBRK: c_int = 0x5409;
pub const TCSBRKP: c_int = 0x5425;
/// Exclusive mode: further opens of this terminal answer `EBUSY`.
pub const TIOCEXCL: c_int = 0x540c;
pub const TIOCNXCL: c_int = 0x540d;

pub const TCIFLUSH: usize = 0;
pub const TCOFLUSH: usize = 1;
pub const TCIOFLUSH: usize = 2;

/// How many bytes the argument points at, 0 when it is a value, or -1 when the
/// command is not one of ours.
pub(crate) fn arg_size(cmd: c_int) -> isize {
    match cmd {
        TCGETS | TCSETS | TCSETSF | TCSETSW => size_of::<Termios>() as isize,
        TCGETS2 | TCSETS2 | TCSETSF2 | TCSETSW2 => size_of::<Termios2>() as isize,
        TIOCGWINSZ | TIOCSWINSZ => size_of::<tty::Winsize>() as isize,
        TIOCGPGRP | TIOCSPGRP | TIOCGSID | FIONREAD => 4,
        pty::TIOCSPTLCK | pty::TIOCGPTN | pty::TIOCPKT | pty::TIOCGPKT => 4,
        TIOCOUTQ => 4,
        TCFLSH | TIOCSCTTY | TCSBRK | TCSBRKP | TIOCEXCL | TIOCNXCL => 0,
        _ => -1,
    }
}

/// Which ioctls a background process group may not issue.
///
/// Linux calls `tty_check_change` for these and not for the rest: changing the
/// terminal's settings, flushing its buffers, or moving the foreground group
/// are all things a background process doing them to the terminal the
/// foreground one is using would break. `TIOCSWINSZ` is deliberately not among
/// them — Linux lets a background process resize, because a terminal emulator
/// on the other end of a pty is not in the foreground group and has to be able
/// to report a resize.
///
/// It applies whether or not `TOSTOP` is set. `TOSTOP` governs *writes*.
fn needs_foreground(cmd: c_int) -> bool {
    matches!(
        cmd,
        TCSETS
            | TCSETSW
            | TCSETSF
            | TCSETS2
            | TCSETSW2
            | TCSETSF2
            | TCFLSH
            | TIOCSPGRP
            | pty::TIOCSPTLCK
    )
}

/// The argument, as whichever shape the command names.
pub enum Arg<'a> {
    /// `TCFLSH`, `TIOCSCTTY`: the value itself.
    Value(usize),
    Word(&'a mut u32),
    Termios(&'a mut Termios),
    Termios2(&'a mut Termios2),
    Winsize(&'a mut tty::Winsize),
}

pub fn ioctl(open: &tty::Open, cmd: c_int, arg: Arg<'_>) -> c_int {
    let tty_ = open.tty();
    crate::ops::with_pids_lock(|pids| {
        if open.hung_up() {
            // A description that has hung up has no foreground group to
            // report, which is what TIOCSPGRP is asking about; everything else
            // is EIO.
            return if cmd == TIOCSPGRP {
                tty::ENOTTY
            } else {
                tty::EIO
            };
        }
        if needs_foreground(cmd) {
            let err = check_change(pids, tty_);
            if err < 0 {
                return err;
            }
        }
        dispatch(pids, tty_, cmd, arg)
    })
}

/// The always-on half of the background rule: changing a terminal's settings
/// from the background raises `SIGTTOU` whether or not `TOSTOP` is set.
///
/// Two things about its shape are surprising and are Linux's:
/// a process that has *ignored* `SIGTTOU` is allowed to proceed, and an
/// orphaned group gets `EIO` rather than being stopped — stopping it would be
/// a hang, because there is nobody left who could send `SIGCONT`.
///
/// `pids_lock` is held.
fn check_change(pids: &PidsHeld, tty_: &Arc<Tty>) -> c_int {
    let settings = tty_.settings_side();
    let pgid = task().pgid();
    let orphaned = task().orphaned(pids, pgid);
    let is_current = crate::tty::is_controlling_terminal(&settings);
    let ignored = task().ignores(tty::SIGTTOU);
    let action = {
        let state = settings.lock();
        state
            .jobctl
            .access(is_current, pgid, jobctl::Sig::Ttou, ignored, orphaned)
    };
    match action {
        jobctl::Access::Allow => 0,
        jobctl::Access::Eio => tty::EIO,
        jobctl::Access::Stop => {
            // The whole process group, as Linux's kill_pgrp does.
            task().signal_group_locked(pids, pgid, tty::SIGTTOU);
            tty::EINTR
        }
    }
}

fn dispatch(pids: &PidsHeld, tty_: &Arc<Tty>, cmd: c_int, arg: Arg<'_>) -> c_int {
    match (cmd, arg) {
        (TCFLSH, Arg::Value(what)) => match what {
            // Only input flushing is currently useful: there is no output
            // buffer to drop.
            TCIFLUSH | TCIOFLUSH => {
                let settings = tty_.settings_side();
                settings.lock().ldisc.buffer.clear();
                settings.notify_consumed();
                0
            }
            TCOFLUSH => 0,
            _ => tty::EINVAL,
        },
        (TIOCSCTTY, Arg::Value(force)) => set_ctty(pids, tty_, force != 0),
        (TIOCGPGRP, Arg::Word(out)) => match get_pgrp(tty_) {
            Ok(pgid) => {
                *out = pgid as u32;
                0
            }
            Err(e) => e,
        },
        (TIOCSPGRP, Arg::Word(want)) => set_pgrp(pids, tty_, *want as i32),
        (TIOCGSID, Arg::Word(out)) => match get_sid(tty_) {
            Ok(sid) => {
                *out = sid as u32;
                0
            }
            Err(e) => e,
        },
        (FIONREAD, Arg::Word(out)) => {
            *out = tty_.settings_side().lock().ldisc.buffer.len() as u32;
            0
        }
        (TIOCOUTQ, Arg::Word(out)) => {
            // Always zero: a write here reaches the other end or the host
            // before it returns, so nothing is ever queued behind it.
            *out = 0;
            0
        }
        // Nothing to drain and no line to break. Answering rather than
        // refusing is the point: tcdrain() and tcsendbreak() are built on
        // these, and a shell restoring a terminal calls the first.
        (TCSBRK | TCSBRKP, Arg::Value(_)) => 0,
        (TIOCEXCL, Arg::Value(_)) => {
            tty_.settings_side().lock().exclusive = true;
            0
        }
        (TIOCNXCL, Arg::Value(_)) => {
            tty_.settings_side().lock().exclusive = false;
            0
        }
        // These operate on the *slave* side of a pair even when the master was
        // named: `tcsetattr` on either end changes the same line discipline.
        (TCGETS, Arg::Termios(out)) => {
            *out = tty_.settings_side().lock().termios;
            0
        }
        (TCSETSF, Arg::Termios(new)) => {
            let settings = tty_.settings_side();
            {
                let mut state = settings.lock();
                state.ldisc.buffer.clear();
                state.termios = *new;
            }
            settings.notify_consumed();
            0
        }
        // TCSETSW drains the output first; there is no output buffer here.
        (TCSETS | TCSETSW, Arg::Termios(new)) => {
            tty_.settings_side().lock().termios = *new;
            0
        }
        // The `termios2` forms answer from the same stored settings plus the
        // two speeds beside them, so `TCGETS` and `TCGETS2` cannot disagree.
        (TCGETS2, Arg::Termios2(out)) => {
            let settings = tty_.settings_side();
            let state = settings.lock();
            *out = Termios2::of(&state.termios, state.ispeed, state.ospeed);
            0
        }
        (TCSETSF2, Arg::Termios2(new)) => {
            let settings = tty_.settings_side();
            {
                let mut state = settings.lock();
                state.ldisc.buffer.clear();
                state.set_termios2(new);
            }
            settings.notify_consumed();
            0
        }
        (TCSETS2 | TCSETSW2, Arg::Termios2(new)) => {
            tty_.settings_side().lock().set_termios2(new);
            0
        }
        (TIOCGWINSZ, Arg::Winsize(out)) => {
            *out = tty_.settings_side().lock().winsize;
            0
        }
        (TIOCSWINSZ, Arg::Winsize(new)) => {
            set_winsize_locked(pids, tty_, *new);
            0
        }
        // The master's own four, which reach through to the slave.
        (pty::TIOCSPTLCK | pty::TIOCGPTN | pty::TIOCPKT | pty::TIOCGPKT, Arg::Word(word)) => {
            if tty_.kind != Kind::PtyMaster {
                return tty::ENOTTY;
            }
            pty::master_ioctl(tty_, cmd, word)
        }
        _ => tty::ENOTTY,
    }
}

/// `pids_lock` is already held, so this is not [`crate::tty::set_winsize`].
fn set_winsize_locked(pids: &PidsHeld, tty_: &Arc<Tty>, winsize: tty::Winsize) {
    let settings = tty_.settings_side();
    let fg = {
        let mut state = settings.lock();
        state.winsize = winsize;
        state.jobctl.fg_group()
    };
    if fg != 0 {
        task().signal_group_locked(pids, fg, tty::SIGWINCH);
    }
}

/// A master asking reads the slave's number without the ownership check: the
/// master is not anyone's controlling terminal, so the check would refuse every
/// one of them.
fn get_pgrp(tty_: &Arc<Tty>) -> Result<Pid, c_int> {
    let settings = tty_.settings_side();
    // Before the lock: see the note on `is_controlling_terminal`. A master is
    // nobody's controlling terminal, so it does not have to ask at all.
    let is_current = tty_.kind != Kind::PtyMaster && crate::tty::is_controlling_terminal(&settings);
    let state = settings.lock();
    if tty_.kind == Kind::PtyMaster {
        return Ok(state.jobctl.fg_group());
    }
    state.jobctl.get_pgrp(is_current)
}

/// `tiocgsid`: on a slave, only for the caller's controlling terminal; on a
/// master, the slave's session whoever asks. `ENOTTY` for a terminal no session
/// owns.
fn get_sid(tty_: &Arc<Tty>) -> Result<Pid, c_int> {
    let settings = tty_.settings_side();
    if tty_.kind != Kind::PtyMaster && !crate::tty::is_controlling_terminal(&settings) {
        return Err(tty::ENOTTY);
    }
    match settings.lock().jobctl.session() {
        0 => Err(tty::ENOTTY),
        sid => Ok(sid),
    }
}

/// What this number is for: the next `^C` goes to it, and a read from a process
/// group that is not it stops that group. Storing whatever arrived pointed the
/// terminal at groups in other sessions and at numbers that were not process
/// groups at all, and said nothing.
fn set_pgrp(pids: &PidsHeld, tty_: &Arc<Tty>, want: Pid) -> c_int {
    let settings = tty_.settings_side();
    let sid = task().sid();
    let is_current = crate::tty::is_controlling_terminal(&settings);
    // Two steps, because the order is the ABI and the middle of it needs a
    // lookup only the process layer can do: the argument and ownership checks
    // first, then whether that group exists and what session it is in, then
    // the store.
    if let Err(e) = settings.lock().jobctl.set_pgrp_check(want, is_current, sid) {
        return e;
    }
    let group_sid = task().session_of(pids, want);
    match settings
        .lock()
        .jobctl
        .set_pgrp(want, is_current, sid, group_sid)
    {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `TIOCSCTTY`: make this the caller's controlling terminal.
fn set_ctty(pids: &PidsHeld, tty_: &Arc<Tty>, force: bool) -> c_int {
    let settings = tty_.settings_side();
    let what = {
        let state = settings.lock();
        state.jobctl.set_ctty(
            task().is_session_leader(),
            task().sid(),
            task().has_tty(),
            force,
            task().sys_admin(),
        )
    };
    let steal = match what {
        Err(e) => return e,
        // Already ours.
        Ok(None) => return 0,
        Ok(Some(steal)) => steal,
    };
    if steal {
        // Every group in the session that has it loses it. The session names a
        // pid and a session leader can be reaped, so this is the process
        // layer's to do rather than something to look up here.
        let sid = settings.lock().jobctl.session();
        task().steal_controlling(pids, sid, TtyId::of(&settings));
    }
    task().set_controlling(pids, &settings);
    0
}
