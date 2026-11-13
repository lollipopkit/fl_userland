//! The state letter `/proc/<pid>/stat` and `status` report for a process that
//! is blocked.
//!
//! A process asleep in a system call is `S`, and one on a CPU is `R`. This
//! kernel answered `R` for every live, unstopped task until 2026-10-18, so
//! `ps` showed a shell waiting for its child, a `sleep` and a reader of an
//! empty pipe all running.
//!
//! Each child blocks a different way, because the kernel parks a thread
//! through more than one path: a host `nanosleep`, a `wait_for` on a
//! condition (pipes, `pause`), and `wait4`.

use guest_tests::{Harness, check};
use std::time::{Duration, Instant};

/// The letter after the last `)` of `/proc/<pid>/stat`.
fn stat_state(pid: i32) -> Option<char> {
    let line = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    line[line.rfind(')')? + 1..].trim_start().chars().next()
}

/// The letter of the `State:` line of `/proc/<pid>/status`.
fn status_state(pid: i32) -> Option<char> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = text.lines().find(|l| l.starts_with("State:"))?;
    line["State:".len()..].trim_start().chars().next()
}

/// Fork a child that runs `body` and never returns from it.
fn spawn(body: fn()) -> i32 {
    // SAFETY: the child calls only `body` and `_exit`.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        body();
        // SAFETY: ends the child.
        unsafe { libc::_exit(0) };
    }
    pid
}

/// Poll until `want` is reported, for up to two seconds: a child that has
/// just been forked may not have reached its blocking call yet.
fn settles_to(pid: i32, want: char) -> (Option<char>, Option<char>) {
    let start = Instant::now();
    loop {
        let got = (stat_state(pid), status_state(pid));
        if got == (Some(want), Some(want)) || start.elapsed() > Duration::from_secs(2) {
            return got;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn reap(pid: i32) {
    // SAFETY: plain syscalls on our own child.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
}

/// The read end of a pipe nothing writes, for the reader child.
static READ_END: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

fn main() {
    let mut h = Harness::new();

    h.group("asleep-in-nanosleep-is-S");
    let pid = spawn(|| std::thread::sleep(Duration::from_secs(30)));
    let got = settles_to(pid, 'S');
    check!(h, got == (Some('S'), Some('S')), "stat and status: {got:?}");
    reap(pid);

    h.group("blocked-reading-an-empty-pipe-is-S");
    let mut fds = [-1; 2];
    // SAFETY: fills `fds`.
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    READ_END.store(fds[0], std::sync::atomic::Ordering::Relaxed);
    let pid = spawn(|| {
        let mut b = [0u8; 1];
        // SAFETY: the read end, which nothing writes.
        let fd = READ_END.load(std::sync::atomic::Ordering::Relaxed);
        unsafe { libc::read(fd, b.as_mut_ptr().cast(), 1) };
    });
    let got = settles_to(pid, 'S');
    check!(h, got == (Some('S'), Some('S')), "stat and status: {got:?}");
    reap(pid);

    h.group("in-pause-is-S");
    let pid = spawn(|| {
        // SAFETY: waits for a signal.
        unsafe { libc::pause() };
    });
    let got = settles_to(pid, 'S');
    check!(h, got == (Some('S'), Some('S')), "stat and status: {got:?}");
    reap(pid);

    h.group("waiting-for-a-child-is-S");
    let pid = spawn(|| {
        // Short: it outlives the parent `reap` kills.
        let child = spawn(|| std::thread::sleep(Duration::from_secs(3)));
        // SAFETY: waits for its own child.
        unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) };
    });
    let got = settles_to(pid, 'S');
    check!(h, got == (Some('S'), Some('S')), "stat and status: {got:?}");
    reap(pid);

    h.group("spinning-is-R");
    let pid = spawn(|| {
        let mut x = 0u64;
        loop {
            x = std::hint::black_box(x.wrapping_add(1));
        }
    });
    let got = settles_to(pid, 'R');
    check!(h, got == (Some('R'), Some('R')), "stat and status: {got:?}");
    reap(pid);

    h.group("this-process-reading-its-own-state-is-R");
    let me = std::process::id() as i32;
    let got = (stat_state(me), status_state(me));
    check!(h, got == (Some('R'), Some('R')), "stat and status: {got:?}");

    std::process::exit(h.finish());
}
