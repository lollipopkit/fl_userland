//! Job control: what a background process gets from its controlling terminal.
//!
//! Linux's `tty_check_change`, for a read by a process group that is not the
//! foreground one:
//!
//! ```c
//! if (is_ignored(SIGTTIN) || is_current_pgrp_orphaned())
//!     return -EIO;
//! kill_pgrp(task_pgrp(current), SIGTTIN, 1);
//! ```
//!
//! Two things this tree did differently.
//!
//! The **orphan** clause was missing entirely. A process group is orphaned when
//! no member has a parent that is in a different group of the same session —
//! which is what happens the moment the shell that started a background job
//! exits. Stopping such a group is a hang by construction: `SIGTTIN` stops it,
//! and there is nobody left who would ever send `SIGCONT`. POSIX has the rule
//! precisely so that the read fails instead.
//!
//! And the signal went to the calling **process** rather than its process
//! **group**, so only one member of a multi-process background job stopped.

use guest_tests::{Harness, check, cpath};

/// A pty pair, with the slave opened.
fn open_pty() -> Option<(i32, i32, String)> {
    unsafe {
        // O_NOCTTY on both ends *here*. This process is a session leader with
        // no controlling terminal, so an open without the flag claims one --
        // and then the "shell" forked below cannot take the same terminal,
        // TIOCSCTTY answers EPERM, and the background read this test is about
        // is not a background read at all. The shell's own open, further down,
        // deliberately omits the flag: taking the terminal is its job.
        //
        // It used to work without this because a pty *master* could be claimed,
        // so the parent's first open took the master and left the slave free.
        // Linux never lets a master be a controlling terminal.
        let master = libc::open(cpath("/dev/ptmx").as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 {
            return None;
        }
        libc::grantpt(master);
        libc::unlockpt(master);
        let name = libc::ptsname(master);
        if name.is_null() {
            return None;
        }
        let path = std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned();
        let slave = libc::open(cpath(&path).as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        if slave < 0 {
            return None;
        }
        Some((master, slave, path))
    }
}

fn main() {
    let mut h = Harness::new();
    h.group("orphaned-pgrp");

    let Some((master, slave, path)) = open_pty() else {
        check!(h, false, "opening a pty");
        std::process::exit(h.finish());
    };

    // The shape: this process forks a session leader, which keeps the
    // terminal and stays; the leader forks a "shell", the shell forks a "job"
    // into a new process group -- not the foreground one -- and exits. The
    // job's group is then orphaned: its only member's parent is outside the
    // session. The leader staying matters: when a session leader exits, the
    // session loses its terminal (Linux's `disassociate_ctty`), and a read of
    // a terminal that is not the caller's controlling one is no background
    // read at all. This test had the leader leave until 2026-11-12, and
    // passed only because that loss was not implemented (`ttyhup_probe`; a
    // real kernel failed it the same way once it was).
    let mut pipefd = [0i32; 2];
    unsafe { libc::pipe(pipefd.as_mut_ptr()) };

    let shell = unsafe { libc::fork() };
    if shell == 0 {
        unsafe {
            libc::close(pipefd[0]);
            // A session of our own, with the pty as the controlling terminal.
            libc::setsid();
            let s = libc::open(cpath(&path).as_ptr(), libc::O_RDWR);
            libc::ioctl(s, libc::TIOCSCTTY as _, 0);

            let middle = libc::fork();
            if middle == 0 {
                let job = libc::fork();
                if job == 0 {
                    // A process group of our own, which is *not* made the
                    // foreground one, and then a read from the terminal.
                    libc::setpgid(0, 0);
                    let mut buf = [0u8; 8];
                    // Wait for the shell to be gone, so the group is orphaned.
                    libc::sleep(1);
                    *libc::__errno_location() = 0;
                    let n = libc::read(s, buf.as_mut_ptr().cast(), buf.len());
                    let e = *libc::__errno_location();
                    // Report through the pipe: n and errno.
                    let msg = [n as i32, e];
                    libc::write(pipefd[1], msg.as_ptr().cast(), 8);
                    libc::_exit(0);
                }
                // The shell keeps the job in the background and leaves.
                libc::_exit(0);
            }
            let mut st = 0;
            libc::waitpid(middle, &mut st, 0);
            // The leader holds the terminal until the job has answered.
            libc::sleep(3);
            libc::_exit(0);
        }
    }
    unsafe { libc::close(pipefd[1]) };

    let mut st = 0;

    // The job must report EIO rather than stopping. If it stopped, nothing
    // arrives and the read below blocks — so the check is bounded by making the
    // pipe non-blocking after a grace period.
    std::thread::sleep(std::time::Duration::from_millis(2500));
    unsafe { libc::fcntl(pipefd[0], libc::F_SETFL, libc::O_NONBLOCK) };
    let mut msg = [0i32; 2];
    let got = unsafe { libc::read(pipefd[0], msg.as_mut_ptr().cast(), 8) };

    check!(
        h,
        got == 8,
        "the orphaned background job answered rather than stopping (read {got})"
    );
    if got == 8 {
        check!(
            h,
            msg[0] == -1 && msg[1] == libc::EIO,
            "and answered EIO: n={} errno={}",
            msg[0],
            msg[1]
        );
    }

    h.group("steal-a-dead-session");
    // A terminal whose session leader has exited can still be taken by a new
    // session leader.
    //
    // This started as an attempt to reach the unguarded `pid_get(tty->session)`
    // in `tiocsctty`'s force branch, which is the same shape as the NULL
    // dereference fixed in `task_leave_session`. It does not reach it: when the
    // leader is reaped, `task_leave_session` now clears `tty->session`, so the
    // force branch is not entered at all and the steal is the ordinary path.
    //
    // The check is therefore what it can honestly be — that the steal works —
    // and not "did not crash", which would pass without executing anything.
    let (master2, _slave2, path2) = match open_pty() {
        Some(t) => t,
        None => {
            check!(h, false, "opening a second pty");
            std::process::exit(h.finish());
        }
    };

    let leader = unsafe { libc::fork() };
    if leader == 0 {
        unsafe {
            libc::setsid();
            let s = libc::open(cpath(&path2).as_ptr(), libc::O_RDWR);
            libc::ioctl(s, libc::TIOCSCTTY as _, 0);
            // A member of this session that outlives its leader.
            if libc::fork() == 0 {
                libc::sleep(4);
                libc::_exit(0);
            }
            libc::_exit(0);
        }
    }
    let mut st2 = 0;
    unsafe { libc::waitpid(leader, &mut st2, 0) };
    std::thread::sleep(std::time::Duration::from_millis(300));

    // Now steal it, as root, from a session of our own.
    let thief = unsafe { libc::fork() };
    if thief == 0 {
        unsafe {
            libc::setsid();
            let s = libc::open(cpath(&path2).as_ptr(), libc::O_RDWR);
            let r = libc::ioctl(s, libc::TIOCSCTTY as _, 1);
            libc::_exit(if r == 0 { 0 } else { 2 });
        }
    }
    let mut st3 = 0;
    unsafe { libc::waitpid(thief, &mut st3, 0) };
    check!(
        h,
        libc::WIFEXITED(st3) && libc::WEXITSTATUS(st3) == 0,
        "a new session leader can take a terminal whose leader has exited: status {}",
        libc::WEXITSTATUS(st3)
    );

    unsafe {
        libc::close(master);
        libc::close(slave);
        libc::close(master2);
        libc::close(pipefd[0]);
        libc::waitpid(shell, &mut st, 0);
        // Whatever is left of the jobs.
        while libc::waitpid(-1, &mut st, libc::WNOHANG) > 0 {}
    }
    std::process::exit(h.finish());
}
