//! What a parent's `SIGCHLD` handler is told, for each thing a child can do.
//!
//! **A report, not a check**, diffed against an arm64 container by
//! `tests/integration/probe_diff.sh`.
//!
//! `waitid` and the `SIGCHLD` a parent receives are the same question asked
//! from two sides, and `wait_probe` covers only the first. A handler installed
//! with `SA_SIGINFO` reads `si_code`, `si_pid`, `si_uid` and `si_status`
//! straight out of the signal — a supervisor that keeps children by pid, a
//! runtime that decides between "reap" and "ignore" on `si_code` — and Linux
//! fills them for every one of the five notifications
//! (`do_notify_parent` for an exit, `do_notify_parent_cldstop` for a stop,
//! a ptrace stop and a continue). Which of those this kernel fills, and with
//! what, is what this prints.
//!
//! `si_utime` and `si_stime` are printed as "small" rather than as values: a
//! child that does nothing has used a few ticks at most on either kernel, and
//! the exact number is noise.

use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, Ordering};

const PTRACE_TRACEME: i64 = 0;
const PTRACE_DETACH: i64 = 17;

static SEEN: AtomicU32 = AtomicU32::new(0);
static CODE: AtomicI32 = AtomicI32::new(0);
static PID: AtomicI32 = AtomicI32::new(0);
static UID: AtomicI32 = AtomicI32::new(-1);
static STATUS: AtomicI32 = AtomicI32::new(0);
static UTIME: AtomicI64 = AtomicI64::new(-1);
static STIME: AtomicI64 = AtomicI64::new(-1);

/// The aarch64 `siginfo_t`: `si_signo` at 0, `si_code` at 8, and the
/// `_sigchld` member at 16 — `pid`, `uid`, `status`, four bytes of padding,
/// `utime`, `stime`.
extern "C" fn on_chld(_sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    let raw = info as *const u8;
    let i32_at = |off: usize| unsafe { (raw.add(off) as *const i32).read_unaligned() };
    let i64_at = |off: usize| unsafe { (raw.add(off) as *const i64).read_unaligned() };
    CODE.store(i32_at(8), Ordering::SeqCst);
    PID.store(i32_at(16), Ordering::SeqCst);
    UID.store(i32_at(20), Ordering::SeqCst);
    STATUS.store(i32_at(24), Ordering::SeqCst);
    UTIME.store(i64_at(32), Ordering::SeqCst);
    STIME.store(i64_at(40), Ordering::SeqCst);
    SEEN.fetch_add(1, Ordering::SeqCst);
}

fn install() {
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = on_chld as *const () as usize;
    act.sa_flags = libc::SA_SIGINFO;
    unsafe {
        libc::sigemptyset(&mut act.sa_mask);
        libc::sigaction(libc::SIGCHLD, &act, std::ptr::null_mut());
    }
}

fn code_name(c: i32) -> String {
    match c {
        1 => "CLD_EXITED".into(),
        2 => "CLD_KILLED".into(),
        3 => "CLD_DUMPED".into(),
        4 => "CLD_TRAPPED".into(),
        5 => "CLD_STOPPED".into(),
        6 => "CLD_CONTINUED".into(),
        0 => "SI_USER".into(),
        128 => "SI_KERNEL".into(),
        n => format!("code {n}"),
    }
}

/// Wait for the handler to have run `n` times, or give up after three seconds.
fn wait_seen(n: u32) -> bool {
    for _ in 0..3000 {
        if SEEN.load(Ordering::SeqCst) >= n {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    false
}

fn report(what: &str, child: i32, uid: u32) {
    let seen = wait_seen(1);
    println!("## {what}");
    println!("  handler ran                                        -> {}", seen as i32);
    println!(
        "  si_code                                            -> {}",
        code_name(CODE.load(Ordering::SeqCst))
    );
    println!(
        "  si_pid is the child                                -> {}",
        (PID.load(Ordering::SeqCst) == child) as i32
    );
    println!(
        "  si_uid is ours                                     -> {}",
        (UID.load(Ordering::SeqCst) as u32 == uid) as i32
    );
    println!(
        "  si_status                                          -> {}",
        STATUS.load(Ordering::SeqCst)
    );
    let small = |v: i64| (0..100).contains(&v) as i32;
    println!(
        "  si_utime small                                     -> {}",
        small(UTIME.load(Ordering::SeqCst))
    );
    println!(
        "  si_stime small                                     -> {}",
        small(STIME.load(Ordering::SeqCst))
    );
}

fn reset() {
    SEEN.store(0, Ordering::SeqCst);
    CODE.store(-1, Ordering::SeqCst);
    PID.store(0, Ordering::SeqCst);
    UID.store(-1, Ordering::SeqCst);
    STATUS.store(-1, Ordering::SeqCst);
    UTIME.store(-1, Ordering::SeqCst);
    STIME.store(-1, Ordering::SeqCst);
}

fn reap(child: i32) {
    let mut status = 0;
    unsafe { libc::waitpid(child, &mut status, libc::__WALL) };
}

fn main() {
    install();
    let uid = unsafe { libc::getuid() };

    // An exit.
    reset();
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::_exit(31) };
    }
    report("a child that exits 31", child, uid);
    reap(child);

    // A kill.
    reset();
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::raise(libc::SIGTERM);
            libc::_exit(1);
        }
    }
    report("a child killed by SIGTERM", child, uid);
    reap(child);

    // A stop, then a continue, then a kill: three notifications from one
    // child, each on its own. The child *sleeps* after the stop rather than
    // exiting: a child that exits the instant it is continued races its own
    // continue notification with its exit notification, and SIGCHLD is a
    // standard signal, so whichever is queued second is coalesced into the
    // first -- on any kernel. The first version of this probe did that and
    // printed the exit's siginfo under the continue's heading.
    reset();
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::raise(libc::SIGSTOP);
            libc::sleep(30);
            libc::_exit(0);
        }
    }
    report("a child that stops with SIGSTOP", child, uid);
    reset();
    unsafe { libc::kill(child, libc::SIGCONT) };
    report("and is continued", child, uid);
    reset();
    unsafe { libc::kill(child, libc::SIGKILL) };
    report("and is then killed", child, uid);
    reap(child);

    // A ptrace stop: the child traces itself and raises SIGSTOP, so the
    // parent -- which is its tracer -- gets the trap notification.
    reset();
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::syscall(libc::SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);
            libc::raise(libc::SIGSTOP);
            libc::_exit(0);
        }
    }
    report("a traced child that stops", child, uid);
    reset();
    unsafe { libc::syscall(libc::SYS_ptrace, PTRACE_DETACH, child, 0, 0) };
    // Detaching resumes it; it exits.
    report("and exits once detached", child, uid);
    reap(child);
}
