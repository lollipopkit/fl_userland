//! What each signal does to a process that has not asked for anything.
//!
//! The default action is a table, and a table is where one wrong entry is
//! silent: a signal whose default is *terminate* but which the kernel ignores
//! kills nothing and reports nothing, and every program that relies on it —
//! `SIGIO` to a process that never registered a handler, say — just carries on.
//!
//! This asks the kernel rather than the header. For each signal it forks a
//! child that installs nothing, sends the signal, and reports which of the four
//! things happened: nothing, terminated, stopped, or continued.
//!
//! The interesting rows, and Linux's answers:
//!
//! - `SIGCHLD`, `SIGURG`, `SIGWINCH`, `SIGCONT` are ignored. That is
//!   `SIG_KERNEL_IGNORE_MASK`, and it is exactly four.
//! - `SIGSTOP`, `SIGTSTP`, `SIGTTIN`, `SIGTTOU` stop.
//! - everything else terminates, **including `SIGIO`**.

use guest_tests::{Harness, check};
use std::time::{Duration, Instant};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum What {
    /// Still running: the signal was ignored.
    Nothing,
    /// Terminated by this signal.
    Killed(i32),
    /// Stopped.
    Stopped,
    /// Could not tell -- the child never started, or the probe failed.
    Unknown,
}

/// Sends `sig` to a freshly forked child with default dispositions and reports
/// what became of it.
fn what_happens(sig: i32) -> What {
    let mut ready = [0i32; 2];
    if unsafe { libc::pipe(ready.as_mut_ptr()) } != 0 {
        return What::Unknown;
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(ready[0]) };
        // A process group of its own, whose parent is in a different group of
        // the same session. Without it the group is orphaned, and Linux's
        // get_signal discards the job-control stop signals in an orphaned
        // group -- "the job control signals do nothing in an orphaned pgrp,
        // but SIGSTOP always works". Three rows read "ignored" for that reason
        // alone.
        unsafe { libc::setpgid(0, 0) };
        // Nothing installed, nothing blocked: the kernel's own answer.
        //
        // Resetting every disposition matters more than it looks. A Rust
        // program starts with SIGPIPE ignored by its own runtime, and the
        // child inherits that -- so SIGPIPE read as "ignored by default" when
        // it is nothing of the kind. SIGKILL and SIGSTOP are skipped because
        // *installing* anything for them is EINVAL, including SIG_DFL.
        let mut dfl: libc::sigaction = unsafe { std::mem::zeroed() };
        dfl.sa_sigaction = libc::SIG_DFL;
        unsafe { libc::sigemptyset(&mut dfl.sa_mask) };
        for s in 1..=64 {
            if s == libc::SIGKILL || s == libc::SIGSTOP {
                continue;
            }
            unsafe { libc::sigaction(s, &dfl, std::ptr::null_mut()) };
        }
        let mut empty: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(&mut empty) };
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) };
        unsafe { libc::write(ready[1], b"x".as_ptr().cast(), 1) };
        unsafe { libc::close(ready[1]) };
        loop {
            unsafe { libc::pause() };
        }
    }
    unsafe { libc::close(ready[1]) };
    if pid < 0 {
        unsafe { libc::close(ready[0]) };
        return What::Unknown;
    }
    // Wait for it to be in pause() with a clean mask, so "nothing happened"
    // cannot be "it had not started yet".
    let mut b = [0u8; 1];
    let started = unsafe { libc::read(ready[0], b.as_mut_ptr().cast(), 1) } == 1;
    unsafe { libc::close(ready[0]) };
    if !started {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        return What::Unknown;
    }

    unsafe { libc::kill(pid, sig) };

    // Three seconds, not four hundred milliseconds.
    //
    // Only the "nothing happened" outcome pays the whole deadline -- every
    // other one breaks out as soon as waitpid reports -- so the cost is a few
    // seconds across the handful of rows that expect a signal to be ignored.
    //
    // The short one misreported under load: `SIGSYS terminates: Nothing` once,
    // inside the full guest suite, and never in six runs on its own. A
    // deadline that decides "the signal was ignored" is really deciding "I did
    // not see it die yet", and 400 ms of that is a machine's spare capacity
    // rather than a statement about signals.
    let mut result = What::Nothing;
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(3000) {
        let mut st = 0;
        let w = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG | libc::WUNTRACED) };
        if w == pid {
            result = if libc::WIFSIGNALED(st) {
                What::Killed(libc::WTERMSIG(st))
            } else if libc::WIFSTOPPED(st) {
                What::Stopped
            } else {
                // Exited of its own accord, which pause() does not do.
                What::Unknown
            };
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    // "Nothing happened" has to mean the child is still there. If it is gone
    // and this loop did not see it, the answer is Unknown -- which fails
    // loudly -- rather than a quiet "the signal was ignored".
    if result == What::Nothing && unsafe { libc::kill(pid, 0) } != 0 {
        result = What::Unknown;
    }

    // Clean up whatever state it is in.
    unsafe { libc::kill(pid, libc::SIGCONT) };
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let mut st = 0;
    loop {
        let w = unsafe { libc::waitpid(pid, &mut st, libc::WUNTRACED) };
        if w != pid || !libc::WIFSTOPPED(st) {
            break;
        }
        unsafe { libc::kill(pid, libc::SIGCONT) };
    }
    result
}

fn name(sig: i32) -> &'static str {
    match sig {
        1 => "SIGHUP", 2 => "SIGINT", 3 => "SIGQUIT", 4 => "SIGILL",
        5 => "SIGTRAP", 6 => "SIGABRT", 7 => "SIGBUS", 8 => "SIGFPE",
        9 => "SIGKILL", 10 => "SIGUSR1", 11 => "SIGSEGV", 12 => "SIGUSR2",
        13 => "SIGPIPE", 14 => "SIGALRM", 15 => "SIGTERM", 16 => "SIGSTKFLT",
        17 => "SIGCHLD", 18 => "SIGCONT", 19 => "SIGSTOP", 20 => "SIGTSTP",
        21 => "SIGTTIN", 22 => "SIGTTOU", 23 => "SIGURG", 24 => "SIGXCPU",
        25 => "SIGXFSZ", 26 => "SIGVTALRM", 27 => "SIGPROF", 28 => "SIGWINCH",
        29 => "SIGIO", 30 => "SIGPWR", 31 => "SIGSYS",
        35 => "the first usable RT signal", 64 => "SIGRTMAX",
        _ => "?",
    }
}

fn main() {
    let mut h = Harness::new();

    h.group("ignored-by-default");
    // SIG_KERNEL_IGNORE_MASK, and it is exactly these four.
    for sig in [libc::SIGCHLD, libc::SIGURG, libc::SIGWINCH, libc::SIGCONT] {
        let got = what_happens(sig);
        check!(h, got == What::Nothing, "{} is ignored: {got:?}", name(sig));
    }

    h.group("stopped-by-default");
    for sig in [libc::SIGSTOP, libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
        let got = what_happens(sig);
        check!(h, got == What::Stopped, "{} stops: {got:?}", name(sig));
    }

    h.group("terminating-by-default");
    // Everything else. SIGIO is the row worth naming: its default is terminate,
    // and a kernel that puts it in the ignore set kills nothing and says
    // nothing.
    for sig in [
        libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGKILL,
        libc::SIGUSR1, libc::SIGUSR2, libc::SIGPIPE, libc::SIGALRM,
        libc::SIGTERM, libc::SIGXCPU, libc::SIGXFSZ, libc::SIGVTALRM,
        libc::SIGPROF, libc::SIGIO, libc::SIGPWR, libc::SIGSYS,
        libc::SIGSTKFLT,
        // 35, not 34: musl reserves 32, 33 and 34 for its own use and its
        // sigaction() wrapper refuses them outright, so the reset loop above
        // cannot clear whatever it has installed there. 34 read as "ignored by
        // default" for that reason and nothing to do with the kernel.
        35, 64,
    ] {
        let got = what_happens(sig);
        check!(h, got == What::Killed(sig), "{} terminates: {got:?}", name(sig));
    }

    h.group("a-handler-beats-the-default");
    // The control. Every row above is about the *absence* of a disposition, and
    // a kernel that terminated on everything would satisfy most of them.
    let mut ready = [0i32; 2];
    check!(h, unsafe { libc::pipe(ready.as_mut_ptr()) } == 0, "a pipe");
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(ready[0]) };
        extern "C" fn on_io(_: i32) {}
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = on_io as *const () as usize;
        unsafe { libc::sigemptyset(&mut act.sa_mask) };
        unsafe { libc::sigaction(libc::SIGIO, &act, std::ptr::null_mut()) };
        unsafe { libc::write(ready[1], b"x".as_ptr().cast(), 1) };
        unsafe { libc::close(ready[1]) };
        loop {
            unsafe { libc::pause() };
        }
    }
    unsafe { libc::close(ready[1]) };
    let mut b = [0u8; 1];
    let started = unsafe { libc::read(ready[0], b.as_mut_ptr().cast(), 1) } == 1;
    unsafe { libc::close(ready[0]) };
    check!(h, pid > 0 && started, "a child with a SIGIO handler: pid={pid}");
    if pid > 0 && started {
        unsafe { libc::kill(pid, libc::SIGIO) };
        std::thread::sleep(Duration::from_millis(200));
        let mut st = 0;
        let w = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG | libc::WUNTRACED) };
        check!(h, w == 0, "SIGIO with a handler does not terminate it: w={w} status={st:#x}");
        unsafe { libc::kill(pid, libc::SIGKILL) };
        unsafe { libc::waitpid(pid, &mut st, 0) };
    } else {
        check!(h, false, "a child with a SIGIO handler");
    }

    h.group("nothing-is-left-behind");
    let mut st = 0;
    let w = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
    let e = errno();
    check!(h, w <= 0, "every child is gone: w={w} status={st:#x} errno={e}");

    std::process::exit(h.finish());
}
