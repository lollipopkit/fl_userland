//! What an exiting process has sent by the time its parent's `waitpid`
//! returns: the session leader's `SIGHUP` to its terminal's foreground group
//! (`disassociate_ctty`), and `SIGHUP` plus `SIGCONT` to a process group the
//! exit leaves orphaned with a stopped member (`kill_orphaned_pgrp`). Linux's
//! `do_exit` sends all of them before `exit_notify` tells the parent.
//!
//! Until 2026-11-12 the session leader's `SIGHUP` went out after the parent
//! had been woken, and the orphaned-group signals not at all, so a stopped
//! job whose shell died stayed stopped for ever. The receivers block
//! `SIGHUP`, so it stays pending where `/proc/<pid>/status` shows it, and the
//! parent reads that the moment its wait returns: no sleep decides anything.
//! `exitorder_probe` is the same four cases as a report.

use guest_tests::{Harness, check};

fn status_field(pid: i32, key: &str) -> String {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    s.lines()
        .find_map(|l| l.strip_prefix(key))
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|| "absent".into())
}

/// Whether `SIGHUP` is pending for `pid` (either set: this kernel has no
/// `ShdPnd` of its own), and whether it is stopped.
fn observe(pid: i32) -> (bool, bool) {
    let hup = 1u64 << (libc::SIGHUP - 1);
    let bit = |key: &str| u64::from_str_radix(&status_field(pid, key), 16).is_ok_and(|m| m & hup != 0);
    (bit("SigPnd:") || bit("ShdPnd:"), status_field(pid, "State:").starts_with('T'))
}

fn block_hup() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGHUP);
        libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
}

fn pipe() -> (i32, i32) {
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    (fds[0], fds[1])
}

fn send_pid(fd: i32, pid: i32) {
    unsafe { libc::write(fd, (&raw const pid).cast(), 4) };
}

fn recv_pid(fd: i32) -> i32 {
    let mut pid = 0i32;
    let n = unsafe { libc::read(fd, (&raw mut pid).cast(), 4) };
    if n == 4 { pid } else { -1 }
}

/// A receiver: blocks `SIGHUP`, reports its pid on `ready`, optionally stops
/// itself, and waits to be killed.
fn receiver(ready: i32, stop: bool) -> ! {
    block_hup();
    send_pid(ready, unsafe { libc::getpid() });
    if stop {
        unsafe { libc::raise(libc::SIGSTOP) };
    }
    loop {
        unsafe { libc::pause() };
    }
}

/// Runs `scenario` in a forked child, which answers the receiver's state on
/// a pipe, and reaps what it leaves to this process (init, here and in the
/// container both).
fn case(scenario: fn() -> (bool, bool)) -> (bool, bool) {
    let (r, w) = pipe();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (pending, stopped) = scenario();
        let word = i32::from(pending) | i32::from(stopped) << 1;
        send_pid(w, word);
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(w) };
    let word = recv_pid(r);
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    while unsafe { libc::waitpid(-1, &mut st, 0) } > 0 {}
    (word & 1 != 0, word & 2 != 0)
}

/// Waits for `x` and looks at `receiver` the moment the wait returns.
fn after_wait(x: i32, receiver: i32) -> (bool, bool) {
    let mut st = 0;
    unsafe { libc::waitpid(x, &mut st, 0) };
    let seen = observe(receiver);
    unsafe { libc::kill(receiver, libc::SIGKILL) };
    seen
}

/// The foreground member watches the leader itself, through a pidfd, and
/// asks its own pending set the moment the pidfd says the leader has exited.
///
/// That is the earliest anything can know of the exit -- this kernel marks
/// the pidfd in the same hold of its lock as it wakes the parent -- and it
/// needs no lock the exiting thread will want next, so a kernel that sends the
/// `SIGHUP` after the notification is caught between the two. Waiting in the
/// parent instead was not: a woken waiter's reaction is slower than the
/// exiting thread's next few microseconds, and the check passed against that
/// order eight runs in eight. This one catches it about one run in five,
/// hence `main`'s repetition. On a correct kernel the signal is pending
/// before the pidfd can be readable, so the answer does not depend on timing.
fn session_leader() -> (bool, bool) {
    let (r, w) = pipe();
    let (answer_r, answer_w) = pipe();
    let leader = unsafe { libc::fork() };
    if leader == 0 {
        unsafe {
            libc::setsid();
            let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            libc::grantpt(m);
            libc::unlockpt(m);
            let s = libc::open(libc::ptsname(m), libc::O_RDWR | libc::O_NOCTTY);
            libc::ioctl(s, libc::TIOCSCTTY as _, 0);
            let (lr, lw) = pipe();
            if libc::fork() == 0 {
                block_hup();
                let pidfd = libc::syscall(libc::SYS_pidfd_open, libc::getppid(), 0) as i32;
                send_pid(lw, libc::getpid());
                let mut p = libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 };
                while pidfd >= 0 && libc::poll(&mut p, 1, 0) == 0 {}
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigpending(&mut set);
                send_pid(answer_w, libc::sigismember(&set, libc::SIGHUP));
                loop {
                    libc::pause();
                }
            }
            send_pid(w, recv_pid(lr));
            libc::_exit(0);
        }
    }
    let member = recv_pid(r);
    let seen_by_member = recv_pid(answer_r) == 1;
    let (seen_by_parent, _) = after_wait(leader, member);
    (seen_by_member && seen_by_parent, false)
}

/// `child_setpgid`: the stopped child makes its own group, so the exiting
/// process was the link that kept it; otherwise the exiting process makes
/// one and its own exit is what orphans it.
fn orphaning(child_setpgid: bool, exiter_setpgid: bool) -> (bool, bool) {
    unsafe { libc::setsid() };
    let (r, w) = pipe();
    let x = unsafe { libc::fork() };
    if x == 0 {
        unsafe {
            if exiter_setpgid {
                libc::setpgid(0, 0);
            }
            let c = libc::fork();
            if c == 0 {
                if child_setpgid {
                    libc::setpgid(0, 0);
                }
                receiver(w, true);
            }
            let mut st = 0;
            libc::waitpid(c, &mut st, libc::WUNTRACED);
            libc::_exit(0);
        }
    }
    let child = recv_pid(r);
    after_wait(x, child)
}

fn main() {
    let mut h = Harness::new();

    h.group("session-leader");
    // Repeated because a kernel with the old order is caught only when the
    // member's poll lands in the window, about one run in five here; on a
    // correct kernel every run passes, so the count changes nothing there.
    let runs = 32;
    let late = (0..runs).filter(|_| !case(session_leader).0).count();
    check!(
        h,
        late == 0,
        "the foreground member's SIGHUP is pending once the leader's exit is visible, to its pidfd and to its parent's wait: missing in {late} of {runs}"
    );

    h.group("orphaned-group");
    let (pending, stopped) = case(|| orphaning(false, true));
    check!(h, pending && !stopped, "its exit orphans its own group: SIGHUP {pending}, still stopped {stopped}");
    let (pending, stopped) = case(|| orphaning(true, false));
    check!(h, pending && !stopped, "its exit orphans its child's group: SIGHUP {pending}, still stopped {stopped}");
    let (pending, stopped) = case(|| orphaning(false, false));
    check!(h, !pending && stopped, "a group it does not orphan is left alone: SIGHUP {pending}, still stopped {stopped}");

    std::process::exit(h.finish());
}
