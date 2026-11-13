//! Where a signal waits: the process's shared pending set or one thread's.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container and diffed by `tests/integration/probe_diff.sh`.
//!
//! Linux keeps two sets. A process-directed signal -- `kill`, `sigqueue`,
//! `pidfd_send_signal`, a timer, `SIGCHLD`, a terminal's `^C` -- waits in
//! the process's (`ShdPnd`) and any thread that does not block it may take
//! it; a thread-directed one -- `tgkill`, `tkill`, `rt_tgsigqueueinfo`,
//! `SIGEV_THREAD_ID` -- waits in that thread's (`SigPnd`). `sigpending` is
//! the union. Every case runs in a fresh child process.

use std::ffi::CString;
use std::io::Write;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<60} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn gettid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

fn pid() -> i32 {
    unsafe { libc::getpid() }
}

fn set_of(mask: u64) -> String {
    let v: Vec<String> = (1..=64).filter(|s| mask & (1u64 << (s - 1)) != 0).map(|s| s.to_string()).collect();
    format!("{{{}}}", v.join(","))
}

fn sigset(sigs: &[i32]) -> libc::sigset_t {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    for &s in sigs {
        unsafe { libc::sigaddset(&mut set, s) };
    }
    set
}

fn mask(how: i32, sigs: &[i32]) {
    let set = sigset(sigs);
    unsafe { libc::pthread_sigmask(how, &set, std::ptr::null_mut()) };
}

fn pending() -> String {
    let mut set = sigset(&[]);
    unsafe { libc::sigpending(&mut set) };
    let m: u64 = (1..=64).filter(|&s| unsafe { libc::sigismember(&set, s) } == 1).fold(0, |m, s| m | 1u64 << (s - 1));
    set_of(m)
}

/// `SigPnd` and `ShdPnd` of a status file.
fn status(path: &str) -> String {
    let Ok(s) = std::fs::read_to_string(path) else {
        return format!("errno {}", errno());
    };
    let get = |k: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix(k))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
            .map_or("?".into(), set_of)
    };
    format!("SigPnd {} ShdPnd {}", get("SigPnd:"), get("ShdPnd:"))
}

/// Fields 31 to 34 of `stat`: pending, blocked, ignored, caught. A signal
/// above 31 is blocked and one ignored, to show how wide the fields are.
fn stat_signals() -> String {
    let rt = libc::SIGRTMIN() + 2;
    mask(libc::SIG_BLOCK, &[rt]);
    handle(rt + 1, libc::SIG_IGN);
    let s = std::fs::read_to_string(format!("/proc/{}/stat", pid())).unwrap_or_default();
    let rest = s.rsplit_once(") ").map_or("", |(_, r)| r);
    let f: Vec<&str> = rest.split_whitespace().collect();
    (31..=34).map(|n| f.get(n - 3).copied().unwrap_or("-")).collect::<Vec<_>>().join(" ")
}

fn proc_status() -> String {
    status(&format!("/proc/{}/status", pid()))
}

fn task_status(tid: i32) -> String {
    status(&format!("/proc/{}/task/{tid}/status", pid()))
}

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

fn who(main: i32, worker: i32) -> &'static str {
    match HANDLED_BY.load(Ordering::SeqCst) as i32 {
        0 => "nobody",
        t if t == main => "the main thread",
        t if t == worker => "the other thread",
        _ => "some other thread",
    }
}

fn tgkill(tid: i32, sig: i32) -> i64 {
    unsafe { libc::syscall(libc::SYS_tgkill, pid(), tid, sig) }
}

fn settle() {
    std::thread::sleep(Duration::from_millis(50));
}

type Job = Box<dyn FnOnce() -> String + Send>;

/// A second thread that runs what it is sent and answers a line.
struct Worker {
    tid: i32,
    jobs: mpsc::Sender<Job>,
    answers: mpsc::Receiver<String>,
    handle: std::thread::JoinHandle<()>,
}

impl Worker {
    fn spawn() -> Worker {
        let (jt, jr) = mpsc::channel::<Job>();
        let (at, ar) = mpsc::channel::<String>();
        let handle = std::thread::spawn(move || {
            at.send(gettid().to_string()).unwrap();
            for job in jr {
                at.send(job()).unwrap();
            }
        });
        let tid = ar.recv().unwrap().parse().unwrap();
        Worker { tid, jobs: jt, answers: ar, handle }
    }

    fn run(&self, f: impl FnOnce() -> String + Send + 'static) -> String {
        self.jobs.send(Box::new(f)).unwrap();
        self.answers.recv_timeout(Duration::from_secs(3)).unwrap_or_else(|_| "no answer".into())
    }

    fn finish(self) {
        drop(self.jobs);
        let _ = self.handle.join();
    }
}

fn child(title: &str, f: impl FnOnce()) {
    println!("########## {title} ##########");
    let _ = std::io::stdout().flush();
    let p = unsafe { libc::fork() };
    if p == 0 {
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(p, &mut st, 0) };
}

const USR1: i32 = libc::SIGUSR1;
const USR2: i32 = libc::SIGUSR2;
const WINCH: i32 = libc::SIGWINCH;

fn both_sets() {
    let main = gettid();
    mask(libc::SIG_BLOCK, &[USR1, USR2, WINCH]);
    let w = Worker::spawn();
    unsafe { libc::kill(pid(), USR1) };
    tgkill(main, USR2);
    tgkill(w.tid, WINCH);
    settle();
    line("/proc/<pid>/status", proc_status());
    line("/proc/<pid>/task/<main>/status", task_status(main));
    line("/proc/<pid>/task/<other>/status", task_status(w.tid));
    line("sigpending in the main thread", pending());
    line("sigpending in the other thread", w.run(pending));
    line("/proc/<pid>/stat signal fields 31-34", stat_signals());
    handle(USR1, record as *const () as usize);
    line(
        "the other thread unblocks SIGUSR1",
        w.run(|| {
            mask(libc::SIG_UNBLOCK, &[USR1]);
            "done".into()
        }),
    );
    line("  it ran on", who(main, w.tid));
    line("  /proc/<pid>/status after", proc_status());
    line("  sigpending in the main thread after", pending());
    w.finish();
}

fn sigwait_elsewhere() {
    mask(libc::SIG_BLOCK, &[USR1]);
    let w = Worker::spawn();
    unsafe { libc::kill(pid(), USR1) };
    let r = w.run(|| {
        let set = sigset(&[USR1]);
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let s = unsafe { libc::sigwaitinfo(&set, &mut info) };
        let from_us = unsafe { info.si_pid() } == unsafe { libc::getpid() };
        format!("signal {s}, code {}, from this process {from_us}", info.si_code)
    });
    line("kill, then sigwaitinfo in the other thread", r);
    line("  /proc/<pid>/status after", proc_status());
    // And the other order: the thread is already waiting.
    let (tx, rx) = mpsc::channel();
    let t = std::thread::spawn(move || {
        let set = sigset(&[USR1]);
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let s = unsafe { libc::sigwaitinfo(&set, &mut info) };
        tx.send(s).unwrap();
    });
    std::thread::sleep(Duration::from_millis(100));
    unsafe { libc::kill(pid(), USR1) };
    let got = rx.recv_timeout(Duration::from_secs(3)).map_or("no answer".into(), |s| format!("signal {s}"));
    line("sigwaitinfo in a thread, then kill", got);
    let _ = t.join();
    // A thread-directed signal is not another thread's to take.
    let main = gettid();
    tgkill(main, USR1);
    let r = w.run(|| {
        let set = sigset(&[USR1]);
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let s = unsafe { libc::sigtimedwait(&set, std::ptr::null_mut(), &ts) };
        if s < 0 { if errno() == libc::EAGAIN { "EAGAIN".into() } else { format!("errno {}", errno()) } } else { format!("signal {s}") }
    });
    line("tgkill(main), sigtimedwait(0) in the other thread", r);
    line("  sigpending in the main thread", pending());
    w.finish();
}

fn signalfd_elsewhere() {
    let main = gettid();
    mask(libc::SIG_BLOCK, &[USR1]);
    let w = Worker::spawn();
    let fd = w.run(|| {
        let set = sigset(&[USR1]);
        unsafe { libc::signalfd(-1, &set, libc::SFD_NONBLOCK) }.to_string()
    });
    let fd: i32 = fd.parse().unwrap_or(-1);
    let read = move || {
        let mut b = [0u8; 128];
        let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), 128) };
        if n < 0 {
            if errno() == libc::EAGAIN { "EAGAIN".to_string() } else { format!("errno {}", errno()) }
        } else {
            format!("signal {}", u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
        }
    };
    unsafe { libc::kill(pid(), USR1) };
    line("kill, then a signalfd read in the other thread", w.run(read));
    tgkill(main, USR1);
    line("tgkill(main), then a signalfd read in the other thread", w.run(read));
    line("  the main thread reads the same descriptor", read());
    w.finish();
}

fn kill_from_a_thread() {
    let main = gettid();
    handle(USR1, record as *const () as usize);
    let w = Worker::spawn();
    HANDLED_BY.store(0, Ordering::SeqCst);
    // The main thread is waiting in `recv`, a futex, with nothing blocked.
    w.jobs
        .send(Box::new(|| {
            unsafe { libc::kill(libc::getpid(), USR1) };
            std::thread::sleep(Duration::from_millis(100));
            String::new()
        }))
        .unwrap();
    let _ = w.answers.recv_timeout(Duration::from_secs(3));
    line("the other thread calls kill(getpid()), nobody blocks it", who(main, w.tid));
    HANDLED_BY.store(0, Ordering::SeqCst);
    let _ = w.run(|| {
        unsafe { libc::raise(USR1) };
        String::new()
    });
    line("the other thread calls raise()", who(main, w.tid));
    w.finish();
}

fn exec_report(label: &str) {
    line(&format!("  {label}: /proc/<pid>/status"), proc_status());
    line(&format!("  {label}: sigpending"), pending());
}

fn exec_self(label: &str) {
    let me = CString::new("/proc/self/exe").unwrap();
    let a0 = CString::new("sigshared_probe").unwrap();
    let a1 = CString::new("exec-report").unwrap();
    let a2 = CString::new(label).unwrap();
    let argv = [a0.as_ptr(), a1.as_ptr(), a2.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    let _ = std::io::stdout().flush();
    unsafe { libc::execve(me.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    line(label, format!("execve: errno {}", errno()));
}

fn exec_keeps() {
    mask(libc::SIG_BLOCK, &[USR1, USR2]);
    unsafe { libc::kill(pid(), USR1) };
    tgkill(gettid(), USR2);
    line("before exec: /proc/<pid>/status", proc_status());
    exec_self("after exec");
}

fn exec_from_a_thread() {
    mask(libc::SIG_BLOCK, &[USR1, USR2, WINCH]);
    let main = gettid();
    let w = Worker::spawn();
    unsafe { libc::kill(pid(), USR1) };
    tgkill(main, USR2);
    tgkill(w.tid, WINCH);
    line("before exec: /proc/<pid>/status", proc_status());
    let _ = w.jobs.send(Box::new(|| {
        exec_self("after exec from a thread");
        String::new()
    }));
    std::thread::sleep(Duration::from_secs(3));
}

fn fork_clears() {
    mask(libc::SIG_BLOCK, &[USR1, USR2]);
    unsafe { libc::kill(pid(), USR1) };
    tgkill(gettid(), USR2);
    let p = unsafe { libc::fork() };
    if p == 0 {
        line("the forked child: /proc/<pid>/status", proc_status());
        line("the forked child: sigpending", pending());
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(p, std::ptr::null_mut(), 0) };
    line("the parent after the fork: sigpending", pending());
}

fn thread_exit_drops_its_own() {
    mask(libc::SIG_BLOCK, &[USR1, WINCH]);
    let w = Worker::spawn();
    tgkill(w.tid, WINCH);
    unsafe { libc::kill(pid(), USR1) };
    settle();
    line("before the thread exits: /proc/<pid>/status", proc_status());
    w.finish();
    line("after it exits: /proc/<pid>/status", proc_status());
    line("after it exits: sigpending", pending());
}

fn ignoring_discards() {
    mask(libc::SIG_BLOCK, &[USR1, USR2]);
    let w = Worker::spawn();
    unsafe { libc::kill(pid(), USR1) };
    tgkill(gettid(), USR1);
    tgkill(w.tid, USR2);
    unsafe { libc::kill(pid(), USR2) };
    settle();
    line("before: /proc/<pid>/status", proc_status());
    handle(USR1, libc::SIG_IGN);
    line("SIG_IGN for SIGUSR1: /proc/<pid>/status", proc_status());
    line("  sigpending", pending());
    handle(USR2, libc::SIG_IGN);
    line("SIG_IGN for SIGUSR2: the other thread's sigpending", w.run(pending));
    line("  /proc/<pid>/task/<other>/status", task_status(w.tid));
    w.finish();
}

fn timers() {
    let main = gettid();
    mask(libc::SIG_BLOCK, &[libc::SIGALRM, USR1, USR2]);
    let w = Worker::spawn();
    let it = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: 0, tv_usec: 10_000 },
    };
    unsafe { libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()) };
    std::thread::sleep(Duration::from_millis(100));
    line("ITIMER_REAL fired: /proc/<pid>/status", proc_status());
    let arm = |notify: i32, sig: i32, tid: i32| unsafe {
        let mut sev: libc::sigevent = std::mem::zeroed();
        sev.sigev_notify = notify;
        sev.sigev_signo = sig;
        sev.sigev_notify_thread_id = tid;
        let mut t: libc::timer_t = std::ptr::null_mut();
        if libc::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut t) != 0 {
            return format!("timer_create errno {}", errno());
        }
        let ts = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: 0, tv_nsec: 10_000_000 },
        };
        libc::timer_settime(t, 0, &ts, std::ptr::null_mut());
        std::thread::sleep(Duration::from_millis(100));
        "ok".to_string()
    };
    let r = arm(libc::SIGEV_SIGNAL, USR1, 0);
    line("SIGEV_SIGNAL timer fired", r);
    line("  /proc/<pid>/status", proc_status());
    // SIGEV_THREAD_ID, which the libc crate does not name for musl.
    let r = arm(4, USR2, w.tid);
    line("SIGEV_THREAD_ID timer at the other thread fired", r);
    line("  /proc/<pid>/task/<main>/status", task_status(main));
    line("  /proc/<pid>/task/<other>/status", task_status(w.tid));
    w.finish();
}

fn sigchld_and_sigpipe() {
    mask(libc::SIG_BLOCK, &[libc::SIGCHLD, libc::SIGPIPE]);
    let w = Worker::spawn();
    let p = unsafe { libc::fork() };
    if p == 0 {
        unsafe { libc::_exit(0) };
    }
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    unsafe { libc::waitid(libc::P_PID, p as u32, &mut info, libc::WEXITED | libc::WNOWAIT) };
    settle();
    line("a child exited: /proc/<pid>/status", proc_status());
    unsafe { libc::waitpid(p, std::ptr::null_mut(), 0) };
    let r = w.run(|| {
        let mut fds = [0i32; 2];
        unsafe {
            libc::pipe(fds.as_mut_ptr());
            libc::close(fds[0]);
            let n = libc::write(fds[1], b"x".as_ptr().cast(), 1);
            let e = errno();
            libc::close(fds[1]);
            format!("write {n}, errno {e}")
        }
    });
    line("the other thread writes to a pipe with no reader", r);
    line("  /proc/<pid>/status", proc_status());
    line("  /proc/<pid>/task/<other>/status", task_status(w.tid));
    w.finish();
}

fn terminal() {
    unsafe {
        libc::setsid();
        mask(libc::SIG_BLOCK, &[libc::SIGINT]);
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if m < 0 || libc::grantpt(m) != 0 || libc::unlockpt(m) != 0 {
            line("a pty", format!("errno {}", errno()));
            return;
        }
        let name = libc::ptsname(m);
        let s = libc::open(name, libc::O_RDWR);
        let ctty = libc::ioctl(s, libc::TIOCSCTTY, 0);
        line("the slave is the controlling terminal", if ctty == 0 { "yes".to_string() } else { format!("errno {}", errno()) });
        libc::write(m, b"\x03".as_ptr().cast(), 1);
        settle();
        line("^C on the terminal: /proc/<pid>/status", proc_status());
    }
}

fn queued_values() {
    let rt = libc::SIGRTMIN() + 1;
    mask(libc::SIG_BLOCK, &[rt, USR1, USR2]);
    let w = Worker::spawn();
    for v in [1, 2] {
        let val = libc::sigval { sival_ptr: v as *mut libc::c_void };
        unsafe { libc::sigqueue(pid(), rt, val) };
    }
    line("two sigqueue(pid) of SIGRTMIN+1: /proc/<pid>/status", proc_status());
    let r = w.run(move || {
        let set = sigset(&[rt]);
        let mut out = Vec::new();
        for _ in 0..2 {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            unsafe { libc::sigwaitinfo(&set, &mut info) };
            out.push(format!("{}", unsafe { info.si_value().sival_ptr } as usize));
        }
        out.join(", ")
    });
    line("  the other thread takes them, values", r);
    // The raw calls, one of each direction.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    info.si_signo = USR1;
    info.si_code = -1; // SI_QUEUE
    let r = unsafe { libc::syscall(libc::SYS_rt_sigqueueinfo, pid(), USR1, &info) };
    line("rt_sigqueueinfo(pid, SIGUSR1)", r);
    let mut info2: libc::siginfo_t = unsafe { std::mem::zeroed() };
    info2.si_signo = USR2;
    info2.si_code = -1;
    let r = unsafe { libc::syscall(libc::SYS_rt_tgsigqueueinfo, pid(), w.tid, USR2, &info2) };
    line("rt_tgsigqueueinfo(pid, other, SIGUSR2)", r);
    line("  /proc/<pid>/status", proc_status());
    line("  /proc/<pid>/task/<other>/status", task_status(w.tid));
    w.finish();
}

fn pidfd() {
    mask(libc::SIG_BLOCK, &[USR1]);
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid(), 0) } as i32;
    let r = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, fd, USR1, std::ptr::null::<u8>(), 0) };
    line("pidfd_send_signal(self, SIGUSR1)", r);
    line("  /proc/<pid>/status", proc_status());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("exec-report") {
        exec_report(args.get(2).map_or("?", String::as_str));
        return;
    }
    child("one of each, every thread blocking them", both_sets);
    child("sigwaitinfo in another thread", sigwait_elsewhere);
    child("signalfd in another thread", signalfd_elsewhere);
    child("kill from a thread", kill_from_a_thread);
    child("execve", exec_keeps);
    child("execve from a thread that is not the leader", exec_from_a_thread);
    child("fork", fork_clears);
    child("a thread exits with a signal of its own pending", thread_exit_drops_its_own);
    child("SIG_IGN discards what is pending", ignoring_discards);
    child("timers", timers);
    child("SIGCHLD and SIGPIPE", sigchld_and_sigpipe);
    child("a terminal", terminal);
    child("queued values", queued_values);
    child("pidfd", pidfd);
}
