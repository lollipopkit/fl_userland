//! The process's shared pending set and a thread's own, as a real arm64
//! kernel keeps them (`sigshared_probe`).
//!
//! A process-directed signal -- `kill`, `sigqueue`, `pidfd_send_signal`, a
//! timer, `SIGCHLD`, a terminal's `^C` -- waits in the shared set (`ShdPnd`)
//! for any thread that does not block it; a thread-directed one -- `tgkill`,
//! `rt_tgsigqueueinfo`, `SIGEV_THREAD_ID`, `SIGPIPE` -- waits on that thread
//! (`SigPnd`). Until 2026-11-12 there was no shared set: a process-directed
//! signal was queued on whichever thread was chosen when it was sent, so one
//! every thread blocked stayed on the leader when another thread unblocked
//! it, `sigwaitinfo` and `signalfd` in another thread never saw it, and
//! `ShdPnd` was always zero.
//!
//! Every case runs in a fresh child process; a child reports through its
//! exit status, one bit per check, so nothing is printed from a thread.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

const USR1: i32 = libc::SIGUSR1;
const USR2: i32 = libc::SIGUSR2;
const WINCH: i32 = libc::SIGWINCH;

fn bit(sig: i32) -> u64 {
    1u64 << (sig - 1)
}

fn gettid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

fn pid() -> i32 {
    unsafe { libc::getpid() }
}

fn sigset(sigs: &[i32]) -> libc::sigset_t {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    for &s in sigs {
        unsafe { libc::sigaddset(&mut set, s) };
    }
    set
}

fn block(sigs: &[i32]) {
    let set = sigset(sigs);
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
}

fn unblock(sigs: &[i32]) {
    let set = sigset(sigs);
    unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
}

fn pending() -> u64 {
    let mut set = sigset(&[]);
    unsafe { libc::sigpending(&mut set) };
    (1..=64).filter(|&s| unsafe { libc::sigismember(&set, s) } == 1).fold(0, |m, s| m | bit(s))
}

/// `SigPnd` and `ShdPnd` of a status file.
fn status(path: &str) -> (u64, u64) {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    let get = |k: &str| s.lines().find_map(|l| l.strip_prefix(k)).and_then(|v| u64::from_str_radix(v.trim(), 16).ok());
    (get("SigPnd:").unwrap_or(u64::MAX), get("ShdPnd:").unwrap_or(u64::MAX))
}

fn proc_status() -> (u64, u64) {
    status(&format!("/proc/{}/status", pid()))
}

fn task_status(tid: i32) -> (u64, u64) {
    status(&format!("/proc/{}/task/{tid}/status", pid()))
}

/// How long any wait here may take: a signal that never arrives is a failed
/// check, not a hung test.
const BOUND: libc::timespec = libc::timespec { tv_sec: 3, tv_nsec: 0 };

static HANDLED_BY: AtomicI64 = AtomicI64::new(0);

extern "C" fn record(_sig: i32) {
    HANDLED_BY.store(gettid() as i64, Ordering::SeqCst);
}

fn handle(sig: i32, handler: usize) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn tgkill(tid: i32, sig: i32) {
    unsafe { libc::syscall(libc::SYS_tgkill, pid(), tid, sig) };
}

fn settle() {
    std::thread::sleep(Duration::from_millis(50));
}

type Job = Box<dyn FnOnce() -> u64 + Send>;

/// A second thread that runs what it is sent.
struct Worker {
    tid: i32,
    jobs: mpsc::Sender<Job>,
    answers: mpsc::Receiver<u64>,
    handle: std::thread::JoinHandle<()>,
}

impl Worker {
    fn spawn() -> Worker {
        let (jt, jr) = mpsc::channel::<Job>();
        let (at, ar) = mpsc::channel::<u64>();
        let handle = std::thread::spawn(move || {
            at.send(gettid() as u64).unwrap();
            for job in jr {
                at.send(job()).unwrap();
            }
        });
        let tid = ar.recv().unwrap() as i32;
        Worker { tid, jobs: jt, answers: ar, handle }
    }

    fn run(&self, f: impl FnOnce() -> u64 + Send + 'static) -> u64 {
        self.jobs.send(Box::new(f)).unwrap();
        self.answers.recv_timeout(Duration::from_secs(5)).unwrap_or(u64::MAX)
    }

    fn finish(self) {
        drop(self.jobs);
        let _ = self.handle.join();
    }
}

/// Runs `f` in a child; each `bool` it answers is one check.
fn child(h: &mut Harness, names: &[&str], f: fn() -> Vec<bool>) {
    let p = unsafe { libc::fork() };
    if p == 0 {
        let got = f();
        let mut status = 0;
        for (i, ok) in got.iter().enumerate() {
            if !ok {
                status |= 1 << i;
            }
        }
        if got.len() != names.len() {
            status = 0xff;
        }
        unsafe { libc::_exit(status) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(p, &mut st, 0) };
    let code = if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 0xff };
    for (i, name) in names.iter().enumerate() {
        check!(h, code != 0xff && code & (1 << i) == 0, "{name} (child status {code:#x})");
    }
}

fn both_sets() -> Vec<bool> {
    let main = gettid();
    block(&[USR1, USR2, WINCH]);
    let w = Worker::spawn();
    unsafe { libc::kill(pid(), USR1) };
    tgkill(main, USR2);
    tgkill(w.tid, WINCH);
    settle();
    let other = w.tid;
    let mut out = vec![
        proc_status() == (bit(USR2), bit(USR1)),
        task_status(other) == (bit(WINCH), bit(USR1)),
        pending() == bit(USR1) | bit(USR2),
        w.run(pending) == bit(USR1) | bit(WINCH),
    ];
    handle(USR1, record as *const () as usize);
    w.run(|| {
        unblock(&[USR1]);
        0
    });
    out.push(HANDLED_BY.load(Ordering::SeqCst) == other as i64);
    out.push(proc_status() == (bit(USR2), 0));
    w.finish();
    out
}

fn taken_elsewhere() -> Vec<bool> {
    let main = gettid();
    block(&[USR1]);
    let w = Worker::spawn();
    unsafe { libc::kill(pid(), USR1) };
    let waited = w.run(|| {
        let set = sigset(&[USR1]);
        unsafe { libc::sigtimedwait(&set, std::ptr::null_mut(), &BOUND) as u64 }
    });
    let mut out = vec![waited == USR1 as u64, proc_status() == (0, 0)];
    // Already waiting when it arrives.
    let (tx, rx) = mpsc::channel();
    let t = std::thread::spawn(move || {
        let set = sigset(&[USR1]);
        tx.send(unsafe { libc::sigtimedwait(&set, std::ptr::null_mut(), &BOUND) }).unwrap();
    });
    std::thread::sleep(Duration::from_millis(100));
    unsafe { libc::kill(pid(), USR1) };
    out.push(rx.recv_timeout(Duration::from_secs(5)) == Ok(USR1));
    let _ = t.join();
    // A signalfd in the other thread reads the process's and not the main
    // thread's own.
    let fd = w.run(|| unsafe { libc::signalfd(-1, &sigset(&[USR1]), libc::SFD_NONBLOCK) } as u64) as i32;
    let read = move || {
        let mut b = [0u8; 128];
        let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), 128) };
        if n == 128 { u64::from(u32::from_ne_bytes([b[0], b[1], b[2], b[3]])) } else { 0 }
    };
    unsafe { libc::kill(pid(), USR1) };
    out.push(w.run(read) == USR1 as u64);
    tgkill(main, USR1);
    out.push(w.run(read) == 0);
    out.push(read() == USR1 as u64);
    w.finish();
    out
}

fn kill_from_a_thread() -> Vec<bool> {
    let main = gettid();
    handle(USR1, record as *const () as usize);
    let w = Worker::spawn();
    w.jobs
        .send(Box::new(|| {
            unsafe { libc::kill(libc::getpid(), USR1) };
            std::thread::sleep(Duration::from_millis(100));
            0
        }))
        .unwrap();
    let _ = w.answers.recv_timeout(Duration::from_secs(5));
    let mut out = vec![HANDLED_BY.load(Ordering::SeqCst) == main as i64];
    HANDLED_BY.store(0, Ordering::SeqCst);
    let other = w.tid;
    w.run(|| {
        unsafe { libc::raise(USR1) };
        0
    });
    out.push(HANDLED_BY.load(Ordering::SeqCst) == other as i64);
    w.finish();
    out
}

fn exec_report() -> ! {
    let ok = proc_status() == (bit(USR2), bit(USR1)) && pending() == bit(USR1) | bit(USR2);
    std::process::exit(if ok { 0 } else { 1 });
}

fn exec_keeps() -> Vec<bool> {
    block(&[USR1, USR2]);
    let me = guest_tests::cpath("/proc/self/exe");
    let a0 = guest_tests::cpath("signal_shared");
    let a1 = guest_tests::cpath("exec-report");
    let argv = [a0.as_ptr(), a1.as_ptr(), std::ptr::null()];
    // Forked first, so the exec is of a process with one thread: an exec from
    // a thread that is not the leader is not what this checks.
    let p = unsafe { libc::fork() };
    if p == 0 {
        unsafe {
            libc::kill(libc::getpid(), USR1);
            libc::syscall(libc::SYS_tgkill, libc::getpid(), gettid(), USR2);
            libc::execv(me.as_ptr(), argv.as_ptr());
            libc::_exit(2);
        }
    }
    let mut st = 0;
    unsafe { libc::waitpid(p, &mut st, 0) };
    vec![libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0]
}

fn fork_clears() -> Vec<bool> {
    block(&[USR1, USR2]);
    unsafe { libc::kill(pid(), USR1) };
    tgkill(gettid(), USR2);
    let p = unsafe { libc::fork() };
    if p == 0 {
        let ok = proc_status() == (0, 0) && pending() == 0;
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(p, &mut st, 0) };
    vec![libc::WEXITSTATUS(st) == 0, pending() == bit(USR1) | bit(USR2)]
}

fn thread_exit() -> Vec<bool> {
    block(&[USR1, WINCH]);
    let w = Worker::spawn();
    tgkill(w.tid, WINCH);
    unsafe { libc::kill(pid(), USR1) };
    settle();
    w.finish();
    vec![proc_status() == (0, bit(USR1)), pending() == bit(USR1)]
}

fn ignoring_discards() -> Vec<bool> {
    block(&[USR1, USR2]);
    let w = Worker::spawn();
    unsafe { libc::kill(pid(), USR1) };
    tgkill(gettid(), USR1);
    tgkill(w.tid, USR2);
    unsafe { libc::kill(pid(), USR2) };
    settle();
    let mut out = vec![proc_status() == (bit(USR1), bit(USR1) | bit(USR2))];
    handle(USR1, libc::SIG_IGN);
    out.push(proc_status() == (0, bit(USR2)));
    handle(USR2, libc::SIG_IGN);
    out.push(w.run(pending) == 0);
    w.finish();
    out
}

fn senders() -> Vec<bool> {
    let main = gettid();
    let rt = libc::SIGRTMIN() + 1;
    block(&[libc::SIGALRM, USR1, USR2, libc::SIGCHLD, libc::SIGPIPE, rt]);
    let w = Worker::spawn();
    let mut out = Vec::new();
    // ITIMER_REAL.
    let it = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: 0, tv_usec: 10_000 },
    };
    unsafe { libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()) };
    std::thread::sleep(Duration::from_millis(100));
    out.push(proc_status() == (0, bit(libc::SIGALRM)));
    // A POSIX timer for the process, and one for a thread.
    let arm = |notify: i32, sig: i32, tid: i32| unsafe {
        let mut sev: libc::sigevent = std::mem::zeroed();
        sev.sigev_notify = notify;
        sev.sigev_signo = sig;
        sev.sigev_notify_thread_id = tid;
        let mut t: libc::timer_t = std::ptr::null_mut();
        libc::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut t);
        let ts = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: 0, tv_nsec: 10_000_000 },
        };
        libc::timer_settime(t, 0, &ts, std::ptr::null_mut());
        std::thread::sleep(Duration::from_millis(100));
    };
    arm(libc::SIGEV_SIGNAL, USR1, 0);
    out.push(proc_status().1 & bit(USR1) != 0);
    // SIGEV_THREAD_ID, which the libc crate does not name for musl.
    arm(4, USR2, w.tid);
    out.push(task_status(w.tid).0 == bit(USR2) && task_status(main).0 == 0);
    // SIGCHLD.
    let p = unsafe { libc::fork() };
    if p == 0 {
        unsafe { libc::_exit(0) };
    }
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    unsafe { libc::waitid(libc::P_PID, p as u32, &mut info, libc::WEXITED | libc::WNOWAIT) };
    settle();
    out.push(proc_status().1 & bit(libc::SIGCHLD) != 0);
    unsafe { libc::waitpid(p, std::ptr::null_mut(), 0) };
    // SIGPIPE is the writing thread's.
    w.run(|| unsafe {
        let mut fds = [0i32; 2];
        libc::pipe(fds.as_mut_ptr());
        libc::close(fds[0]);
        libc::write(fds[1], b"x".as_ptr().cast(), 1);
        libc::close(fds[1]);
        0
    });
    let (own, shared) = task_status(w.tid);
    out.push(own & bit(libc::SIGPIPE) != 0 && shared & bit(libc::SIGPIPE) == 0);
    // sigqueue and pidfd_send_signal address the process, rt_tgsigqueueinfo a
    // thread.
    for v in [1usize, 2] {
        unsafe { libc::sigqueue(pid(), rt, libc::sigval { sival_ptr: v as *mut libc::c_void }) };
    }
    let values = w.run(move || {
        let set = sigset(&[rt]);
        let mut digits = 0;
        for _ in 0..2 {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            unsafe { libc::sigtimedwait(&set, &mut info, &BOUND) };
            digits = digits * 10 + unsafe { info.si_value().sival_ptr } as u64;
        }
        digits
    });
    out.push(values == 12);
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid(), 0) } as i32;
    unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd, rt, std::ptr::null::<u8>(), 0) };
    out.push(proc_status().1 & bit(rt) != 0);
    w.finish();
    out
}

fn terminal() -> Vec<bool> {
    unsafe {
        libc::setsid();
        block(&[libc::SIGINT]);
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        libc::grantpt(m);
        libc::unlockpt(m);
        let s = libc::open(libc::ptsname(m), libc::O_RDWR);
        libc::ioctl(s, libc::TIOCSCTTY, 0);
        libc::write(m, b"\x03".as_ptr().cast(), 1);
    }
    settle();
    vec![proc_status() == (0, bit(libc::SIGINT))]
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("exec-report") {
        exec_report();
    }
    let mut h = Harness::new();
    h.group("two-sets");
    child(
        &mut h,
        &[
            "kill is the process's and tgkill the thread's",
            "a thread's status shows its own and the process's",
            "sigpending in the main thread is the union",
            "and in the other thread its own union",
            "the thread that unblocks a signal every thread blocked takes it",
            "and it leaves the shared set",
        ],
        both_sets,
    );
    h.group("taken-by-another-thread");
    child(
        &mut h,
        &[
            "sigwaitinfo in another thread takes a pending kill",
            "and the shared set is empty after",
            "a thread already in sigwaitinfo takes a kill",
            "a signalfd read in another thread takes a kill",
            "but not the main thread's own signal",
            "which the main thread reads from the same descriptor",
        ],
        taken_elsewhere,
    );
    h.group("which-thread");
    child(
        &mut h,
        &["a thread's kill(getpid()) runs on the main thread", "a thread's raise() runs on that thread"],
        kill_from_a_thread,
    );
    h.group("exec-fork-exit");
    child(&mut h, &["execve keeps both sets"], exec_keeps);
    child(&mut h, &["a forked child has neither", "and the parent keeps both"], fork_clears);
    child(
        &mut h,
        &["a thread's own pending signal goes with it, the process's stays", "and sigpending agrees"],
        thread_exit,
    );
    h.group("ignore-discards");
    child(
        &mut h,
        &[
            "before: the main thread's own and the process's",
            "SIG_IGN empties a signal out of both",
            "and out of every other thread's own",
        ],
        ignoring_discards,
    );
    h.group("senders");
    child(
        &mut h,
        &[
            "ITIMER_REAL is the process's",
            "a SIGEV_SIGNAL timer is the process's",
            "a SIGEV_THREAD_ID timer is its thread's",
            "SIGCHLD is the process's",
            "SIGPIPE is the writing thread's",
            "sigqueue is the process's, in order, to any thread",
            "pidfd_send_signal is the process's",
        ],
        senders,
    );
    child(&mut h, &["a terminal's ^C is the process's"], terminal);
    std::process::exit(h.finish());
}
