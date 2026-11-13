//! What a process that exits has already sent by the time its parent's
//! `waitpid` returns.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container and diffed by `tests/integration/probe_diff.sh`.
//!
//! Linux's `do_exit` runs `disassociate_ctty` (the session leader's
//! `SIGHUP` to its terminal's foreground group) and then `exit_notify`, which
//! sends `SIGHUP` and `SIGCONT` to a process group the exit leaves orphaned
//! with a stopped member -- for the exiting process's own group, and for each
//! child's -- before it notifies the parent. So a parent woken by the exit
//! can already see those signals. Each receiver blocks `SIGHUP`, so it stays
//! pending and `/proc/<pid>/status` shows whether it was sent; `SIGCONT` shows
//! as the receiver no longer being stopped. No sleep decides an outcome.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<56} -> {value}");
    let _ = std::io::stdout().flush();
}

fn status_field(pid: i32, key: &str) -> String {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    s.lines()
        .find_map(|l| l.strip_prefix(key))
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|| "absent".into())
}

/// Whether `SIGHUP` is pending for `pid`, and whether it is stopped. The two
/// pending sets are read as one: this kernel queues a process-directed signal
/// on a thread and has no `ShdPnd` of its own (`crates/fs/proc`'s `pid.rs`).
/// Running and sleeping are one answer, because which one a continued process
/// is in at that instant is the scheduler's.
fn report(prefix: &str, pid: i32) {
    let hup = 1u64 << (libc::SIGHUP - 1);
    let bit = |key: &str| u64::from_str_radix(&status_field(pid, key), 16).is_ok_and(|m| m & hup != 0);
    let pending = bit("SigPnd:") || bit("ShdPnd:");
    line(&format!("{prefix}: SIGHUP pending"), pending);
    let stopped = status_field(pid, "State:").starts_with('T');
    line(&format!("{prefix}: stopped"), stopped);
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

/// Runs `f` in a forked child, then reaps everything left for this process,
/// which is init in both places: the receivers are reparented here.
fn section(f: impl FnOnce()) {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    while unsafe { libc::waitpid(-1, &mut st, 0) } > 0 {}
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

/// The session leader exits holding a pty as its controlling terminal; the
/// receiver is in the foreground group and holds the master, so nothing but
/// the leader's exit hangs the session up.
fn session_leader() {
    println!("########## a session leader exits ##########");
    section(|| {
        let (r, w) = pipe();
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
                    receiver(lw, false);
                }
                let member = recv_pid(lr);
                send_pid(w, member);
                libc::_exit(0);
            }
        }
        let member = recv_pid(r);
        let mut st = 0;
        unsafe { libc::waitpid(leader, &mut st, 0) };
        report("the foreground member, when the wait returns", member);
        unsafe { libc::kill(member, libc::SIGKILL) };
    });
}

/// The exiting process was the only member of its process group with a
/// parent elsewhere in the session; its stopped child is left in a group
/// nobody can continue.
fn own_group_orphaned() {
    println!("########## its exit orphans its own group ##########");
    section(|| {
        unsafe { libc::setsid() };
        let (r, w) = pipe();
        let x = unsafe { libc::fork() };
        if x == 0 {
            unsafe {
                libc::setpgid(0, 0);
                let c = libc::fork();
                if c == 0 {
                    receiver(w, true);
                }
                let mut st = 0;
                libc::waitpid(c, &mut st, libc::WUNTRACED);
                libc::_exit(0);
            }
        }
        let child = recv_pid(r);
        let mut st = 0;
        unsafe { libc::waitpid(x, &mut st, 0) };
        report("the stopped child, when the wait returns", child);
        unsafe { libc::kill(child, libc::SIGKILL) };
    });
}

/// The exiting process is the parent that kept its child's group, in another
/// group of the same session, from being orphaned.
fn childs_group_orphaned() {
    println!("########## its exit orphans its child's group ##########");
    section(|| {
        unsafe { libc::setsid() };
        let (r, w) = pipe();
        let x = unsafe { libc::fork() };
        if x == 0 {
            unsafe {
                let c = libc::fork();
                if c == 0 {
                    libc::setpgid(0, 0);
                    receiver(w, true);
                }
                let mut st = 0;
                libc::waitpid(c, &mut st, libc::WUNTRACED);
                libc::_exit(0);
            }
        }
        let child = recv_pid(r);
        let mut st = 0;
        unsafe { libc::waitpid(x, &mut st, 0) };
        report("the stopped child, when the wait returns", child);
        unsafe { libc::kill(child, libc::SIGKILL) };
    });
}

/// The control: the exiting process and its stopped child share a group, so
/// its exit changes nothing about whether that group is orphaned.
fn not_orphaned() {
    println!("########## a group that is not orphaned ##########");
    section(|| {
        unsafe { libc::setsid() };
        let (r, w) = pipe();
        let x = unsafe { libc::fork() };
        if x == 0 {
            unsafe {
                let c = libc::fork();
                if c == 0 {
                    receiver(w, true);
                }
                let mut st = 0;
                libc::waitpid(c, &mut st, libc::WUNTRACED);
                libc::_exit(0);
            }
        }
        let child = recv_pid(r);
        let mut st = 0;
        unsafe { libc::waitpid(x, &mut st, 0) };
        report("a stopped child in the session leader's group", child);
        unsafe { libc::kill(child, libc::SIGKILL) };
    });
}

fn main() {
    session_leader();
    own_group_orphaned();
    childs_group_orphaned();
    not_orphaned();
}
