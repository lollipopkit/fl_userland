//! `TIOCSPGRP`: which process group a terminal sends its signals to.
//!
//! The number is what a later `^C` is delivered to, and what a read from a
//! background group is compared against. Storing whatever the caller passed
//! meant a terminal could be pointed at a group in another session — or at a
//! number that is not a process group at all — and nothing said so.
//!
//! Linux checks three things after establishing that the caller's controlling
//! terminal is this one: the number is not negative, it names a process group
//! that exists, and that group is in the caller's session. `EINVAL`, `ESRCH`,
//! `EPERM`, in that order.
//!
//! Everything here runs in a forked child, because `setsid` fails for a process
//! group leader and a program started from a shell is one. The parent stays in
//! the original session, which is what gives the `EPERM` case a real process
//! group in a *different* session to point at — the check cannot be made with
//! an invented number, because that one is `ESRCH` first.

use guest_tests::{Harness, check};
use std::ffi::CString;

const TIOCSPGRP: u64 = 0x5410;
const TIOCGPGRP: u64 = 0x540F;
const TIOCSCTTY: u64 = 0x540E;

fn ioctl_pgrp(fd: i32, cmd: u64, v: &mut i32) -> i64 {
    unsafe { libc::syscall(libc::SYS_ioctl, fd, cmd, v as *mut i32) }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A pty pair whose slave this process can make its controlling terminal.
fn open_pty() -> Option<(i32, i32)> {
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master < 0 {
        return None;
    }
    if unsafe { libc::grantpt(master) } != 0 || unsafe { libc::unlockpt(master) } != 0 {
        unsafe { libc::close(master) };
        return None;
    }
    let mut name = [0u8; 128];
    if unsafe { libc::ptsname_r(master, name.as_mut_ptr().cast(), name.len()) } != 0 {
        unsafe { libc::close(master) };
        return None;
    }
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let path = CString::new(&name[..end]).ok()?;
    let slave = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if slave < 0 {
        unsafe { libc::close(master) };
        return None;
    }
    Some((master, slave))
}

fn child(parent_pgid: i32) -> i32 {
    let mut h = Harness::new();

    // Closing the last descriptor for a session leader's controlling terminal
    // hangs it up, and a hangup signals the foreground process group -- which
    // is this one. The default action is to die, so the summary never printed
    // and the sweep read that as "the two ran a different number of checks".
    // Ignored here because this is not a test about hangup.
    unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };

    h.group("setup");
    let sid = unsafe { libc::setsid() };
    check!(h, sid > 0, "a session of our own: sid={sid} errno={}", errno());
    let Some((master, slave)) = open_pty() else {
        check!(h, false, "a pty pair");
        return h.finish();
    };
    check!(h, true, "a pty pair");
    let r = unsafe { libc::syscall(libc::SYS_ioctl, slave, TIOCSCTTY, 0) };
    check!(h, r == 0, "it is our controlling terminal: r={r} errno={}", errno());

    let my_pgid = unsafe { libc::getpgrp() };
    check!(h, my_pgid > 0, "our process group: {my_pgid}");
    check!(h, my_pgid != parent_pgid,
        "which is not the parent's: {my_pgid} vs {parent_pgid}");

    h.group("a-group-of-our-own-is-accepted");
    let mut v = my_pgid;
    let r = ioctl_pgrp(slave, TIOCSPGRP, &mut v);
    check!(h, r == 0, "TIOCSPGRP with our own group: r={r} errno={}", errno());
    let mut back = 0;
    let r = ioctl_pgrp(slave, TIOCGPGRP, &mut back);
    check!(h, r == 0, "TIOCGPGRP: r={r} errno={}", errno());
    check!(h, back == my_pgid, "reads back what was set: {back} vs {my_pgid}");

    h.group("negative-is-EINVAL");
    // Checked before the number is looked up, so it does not matter that no
    // process group could have it.
    for bad in [-1i32, -2, i32::MIN] {
        let mut v = bad;
        let r = ioctl_pgrp(slave, TIOCSPGRP, &mut v);
        let e = errno();
        check!(h, r == -1 && e == libc::EINVAL, "TIOCSPGRP({bad}): r={r} errno={e}");
    }

    h.group("a-group-that-does-not-exist-is-ESRCH");
    // 0 is not negative and is not a process group either. A large number is
    // the same case reached the other way.
    for bad in [0i32, 30000, 32000] {
        let mut v = bad;
        let r = ioctl_pgrp(slave, TIOCSPGRP, &mut v);
        let e = errno();
        check!(h, r == -1 && e == libc::ESRCH, "TIOCSPGRP({bad}): r={r} errno={e}");
    }

    h.group("a-group-in-another-session-is-EPERM");
    // The parent: a real process group, still running, in the session this
    // child left. Nothing about it is wrong except that it is not ours.
    let mut v = parent_pgid;
    let r = ioctl_pgrp(slave, TIOCSPGRP, &mut v);
    let e = errno();
    check!(h, r == -1 && e == libc::EPERM,
        "TIOCSPGRP({parent_pgid}): r={r} errno={e}");

    h.group("a-refusal-changes-nothing");
    // Every refusal above must have left the terminal pointing where it was.
    // A kernel that stored the number and then failed would have moved the
    // target of the next ^C.
    let mut back = 0;
    let r = ioctl_pgrp(slave, TIOCGPGRP, &mut back);
    check!(h, r == 0, "TIOCGPGRP after the refusals: r={r}");
    check!(h, back == my_pgid, "still our group: {back} vs {my_pgid}");

    h.group("a-foreground-group-that-has-since-exited");
    // The ordinary state between a job finishing and the shell reclaiming the
    // terminal: the terminal still names the job's process group and the group
    // has no members left. Anything that signals the foreground group then --
    // a `^C`, or the SIGWINCH a resize sends -- reaches an empty group.
    //
    // send_group_signal_locked released pids_lock on that path. It is called
    // with pids_lock held for the whole ioctl, so the lock went away
    // underneath the ioctl and the ioctl released it again on the way out. A
    // pthread mutex does not refuse a release by a thread that does not hold
    // it; the second one hands the lock to whichever thread had since taken
    // it. Only a LOCK_DEBUG build turns that into a visible abort, so what is
    // checked here is that the calls behave -- the deterministic proof is
    // running this under one.
    {
        let gone = unsafe { libc::fork() };
        if gone == 0 {
            unsafe {
                libc::setpgid(0, 0);
                libc::_exit(0);
            }
        }
        let mut status = 0;
        unsafe { libc::waitpid(gone, &mut status, 0) };
        // Reaped, so the group is empty -- but the terminal is still pointed
        // at it, because nothing has moved it.
        let mut v = gone;
        let r = ioctl_pgrp(slave, TIOCSPGRP, &mut v);
        // Setting it may legitimately be ESRCH now that the group is gone;
        // what matters is the case where it was set *before* the exit, which
        // is what the loop below arranges.
        let _ = r;

        let live = unsafe { libc::fork() };
        if live == 0 {
            unsafe {
                libc::setpgid(0, 0);
                libc::pause();
                libc::_exit(0);
            }
        }
        unsafe { libc::setpgid(live, live) };
        let mut v = live;
        let r = ioctl_pgrp(slave, TIOCSPGRP, &mut v);
        check!(h, r == 0, "point the terminal at a live child's group: r={r} errno={}", errno());
        unsafe { libc::kill(live, libc::SIGKILL) };
        let mut status = 0;
        unsafe { libc::waitpid(live, &mut status, 0) };

        let mut back = 0;
        ioctl_pgrp(slave, TIOCGPGRP, &mut back);
        check!(h, back == live, "the terminal still names it: {back} vs {live}");

        // A resize signals the foreground group. It is empty.
        #[repr(C)]
        struct Winsize { row: u16, col: u16, xpixel: u16, ypixel: u16 }
        let ws = Winsize { row: 40, col: 100, xpixel: 0, ypixel: 0 };
        const TIOCSWINSZ: u64 = 0x5414;
        let r = unsafe { libc::syscall(libc::SYS_ioctl, master, TIOCSWINSZ, &raw const ws) };
        check!(h, r == 0, "TIOCSWINSZ with an empty foreground group: r={r} errno={}", errno());

        // And the terminal still works afterwards, which it would not if the
        // process table's lock had been handed away underneath it.
        let mut back = 0;
        let r = ioctl_pgrp(slave, TIOCGPGRP, &mut back);
        check!(h, r == 0 && back == live, "and the terminal still answers: r={r} back={back}");

        // Put it back, so the checks after this one see what they expect.
        let mut v = my_pgid;
        ioctl_pgrp(slave, TIOCSPGRP, &mut v);
    }

    h.group("not-our-controlling-terminal");
    // A second pty, never made anyone's controlling terminal. A well-formed
    // request on it is ENOTTY in both directions -- but a malformed one is
    // refused for being malformed first, which is what the negative case
    // below pins down.
    if let Some((m2, s2)) = open_pty() {
        let mut v = my_pgid;
        let r = ioctl_pgrp(s2, TIOCSPGRP, &mut v);
        let e = errno();
        check!(h, r == -1 && e == libc::ENOTTY, "TIOCSPGRP on another pty: r={r} errno={e}");
        // EINVAL, not ENOTTY: Linux checks the number before it checks whose
        // controlling terminal this is. Written the other way round first, and
        // the sweep said so -- the emulator agreed with the guess and the
        // kernel did not.
        let mut v = -1;
        let r = ioctl_pgrp(s2, TIOCSPGRP, &mut v);
        let e = errno();
        check!(h, r == -1 && e == libc::EINVAL,
            "and a negative number there is EINVAL, checked first: r={r} errno={e}");
        let mut out = 0;
        let r = ioctl_pgrp(s2, TIOCGPGRP, &mut out);
        let e = errno();
        check!(h, r == -1 && e == libc::ENOTTY, "TIOCGPGRP on it: r={r} errno={e}");
        unsafe { libc::close(s2) };
        unsafe { libc::close(m2) };
    } else {
        // Deliberately the same number of checks either way: the sweep
        // compares how many ran on each side.
        for _ in 0..3 {
            check!(h, false, "a second pty pair");
        }
    }

    unsafe { libc::close(slave) };
    unsafe { libc::close(master) };
    h.finish()
}

fn main() {
    let parent_pgid = unsafe { libc::getpgrp() };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        std::process::exit(child(parent_pgid));
    }
    if pid < 0 {
        eprintln!("  FAIL  [fork] could not fork: errno={}", errno());
        std::process::exit(1);
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    // The child printed everything. Exiting with its status and nothing else
    // keeps the check count the child's.
    std::process::exit(if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 1 });
}
