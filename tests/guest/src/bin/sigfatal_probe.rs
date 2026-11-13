//! When a fatal signal ends a process: at send time or at delivery.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container and diffed by `tests/integration/probe_diff.sh`.
//!
//! Linux decides at send time (`complete_signal`): a signal whose disposition
//! is the default, whose default terminates without a core, and which the
//! chosen thread does not block, starts the group exit there and then, with
//! the signal as the status, and every thread gets `SIGKILL`. So a thread
//! that sends one to its own process does not return from `kill`, a second
//! fatal signal or an `exit_group` that follows does not change the status,
//! and an `execve` in progress does not complete. Every case but the last
//! group runs in a fresh child; the last group is about this program as pid 1
//! (`SIGNAL_UNKILLABLE`), which it is here and in the container.

use std::ffi::{CString, c_int};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

const TERM: c_int = libc::SIGTERM;
const KILL: c_int = libc::SIGKILL;
const USR1: c_int = libc::SIGUSR1;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<64} -> {value}");
    let _ = std::io::stdout().flush();
}

fn getpid() -> i32 {
    unsafe { libc::getpid() }
}

fn gettid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

fn tgkill(pid: i32, tid: i32, sig: c_int) {
    unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, sig) };
}

fn exit_group(code: c_int) -> ! {
    unsafe { libc::syscall(libc::SYS_exit_group, code) };
    unreachable!()
}

fn mask(how: c_int, sigs: &[c_int]) {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    for &s in sigs {
        unsafe { libc::sigaddset(&mut set, s) };
    }
    unsafe { libc::pthread_sigmask(how, &set, std::ptr::null_mut()) };
}

fn set_of(m: u64) -> String {
    let v: Vec<String> = (1..=64).filter(|s| m & (1u64 << (s - 1)) != 0).map(|s| s.to_string()).collect();
    format!("{{{}}}", v.join(","))
}

fn status_field(pid: i32, key: &str) -> String {
    match std::fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(s) => s.lines().find_map(|l| l.strip_prefix(key)).map_or("?".into(), |v| v.trim().to_string()),
        Err(e) => format!("errno {}", e.raw_os_error().unwrap_or(0)),
    }
}

fn status_set(pid: i32, key: &str) -> String {
    let v = status_field(pid, key);
    u64::from_str_radix(&v, 16).map_or(v, set_of)
}

fn state(pid: i32) -> String {
    status_field(pid, "State:").chars().next().map_or("?".into(), |c| c.to_string())
}

fn pipe() -> (c_int, c_int) {
    let mut fds = [0; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    (fds[0], fds[1])
}

fn put(fd: c_int, v: i32) {
    unsafe { libc::write(fd, (&raw const v).cast(), 4) };
}

fn get(fd: c_int) -> i32 {
    let mut v = 0i32;
    let n = unsafe { libc::read(fd, (&raw mut v).cast(), 4) };
    if n == 4 { v } else { -1 }
}

fn describe(st: c_int) -> String {
    if libc::WIFEXITED(st) {
        format!("exited {}", libc::WEXITSTATUS(st))
    } else if libc::WIFSIGNALED(st) {
        format!("killed by {}", libc::WTERMSIG(st))
    } else if libc::WIFSTOPPED(st) {
        format!("stopped by {}", libc::WSTOPSIG(st))
    } else {
        format!("status {st:#x}")
    }
}

/// Wait for `pid` up to `limit`; a child that outlives it is killed and
/// reported as hung.
fn reap(pid: i32, limit: Duration) -> String {
    let t0 = Instant::now();
    loop {
        let mut st = 0;
        let r = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
        if r == pid {
            return describe(st);
        }
        if r < 0 {
            return format!("waitpid errno {}", std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        if t0.elapsed() > limit {
            unsafe { libc::kill(pid, KILL) };
            unsafe { libc::waitpid(pid, &mut st, 0) };
            return "hung".into();
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn fork(f: impl FnOnce()) -> i32 {
    let _ = std::io::stdout().flush();
    let p = unsafe { libc::fork() };
    if p == 0 {
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    p
}

/// A thread that parks for ever in `futex_wait` and reports its tid.
fn park_thread() -> i32 {
    static WORD: AtomicI32 = AtomicI32::new(0);
    let (r, w) = pipe();
    std::thread::spawn(move || {
        put(w, gettid());
        loop {
            unsafe { libc::syscall(libc::SYS_futex, WORD.as_ptr(), libc::FUTEX_WAIT, 0, std::ptr::null::<libc::timespec>()) };
        }
    });
    get(r)
}

fn park() -> ! {
    loop {
        unsafe { libc::pause() };
    }
}

fn settle() {
    std::thread::sleep(Duration::from_millis(100));
}

// ---------------------------------------------------------------------------
// The status the parent sees
// ---------------------------------------------------------------------------

fn status_cases() {
    println!("########## status ##########");
    let p = fork(|| {
        park_thread();
        std::thread::spawn(|| {
            unsafe { libc::kill(getpid(), TERM) };
            exit_group(3);
        });
        park();
    });
    line("a thread kill()s its process with SIGTERM, then exit_group(3)", reap(p, Duration::from_secs(5)));

    let p = fork(|| {
        let leader = gettid();
        std::thread::spawn(move || {
            tgkill(getpid(), leader, TERM);
            exit_group(3);
        });
        park();
    });
    line("a thread tgkill()s the parked leader with SIGTERM, then exit_group(3)", reap(p, Duration::from_secs(5)));

    let p = fork(|| {
        park_thread();
        std::thread::spawn(|| {
            unsafe { libc::kill(getpid(), TERM) };
            unsafe { libc::kill(getpid(), USR1) };
            exit_group(3);
        });
        park();
    });
    line("SIGTERM then SIGUSR1 to its own process from a thread", reap(p, Duration::from_secs(5)));

    let p = fork(|| {
        mask(libc::SIG_BLOCK, &[TERM]);
        let (r, w) = pipe();
        std::thread::spawn(move || {
            mask(libc::SIG_UNBLOCK, &[TERM]);
            put(w, 0);
            park();
        });
        get(r);
        unsafe { libc::kill(getpid(), TERM) };
        exit_group(3);
    });
    line("the leader blocks SIGTERM, kill()s itself, then exit_group(3)", reap(p, Duration::from_secs(5)));

    let p = fork(|| {
        mask(libc::SIG_BLOCK, &[TERM]);
        park_thread();
        unsafe { libc::kill(getpid(), TERM) };
        settle();
        exit_group(3);
    });
    line("every thread blocks SIGTERM, it is sent, then exit_group(3)", reap(p, Duration::from_secs(5)));

    let p = fork(|| {
        mask(libc::SIG_BLOCK, &[TERM]);
        park_thread();
        unsafe { libc::kill(getpid(), TERM) };
        settle();
        mask(libc::SIG_UNBLOCK, &[TERM]);
        exit_group(3);
    });
    line("every thread blocks SIGTERM, it is sent, then one unblocks it", reap(p, Duration::from_secs(5)));

    let p = fork(|| {
        park_thread();
        std::thread::spawn(|| {
            unsafe { libc::kill(getpid(), KILL) };
            exit_group(3);
        });
        park();
    });
    line("a thread kill()s its process with SIGKILL, then exit_group(3)", reap(p, Duration::from_secs(5)));

    let p = fork(|| {
        park_thread();
        std::thread::spawn(|| {
            unsafe { libc::raise(libc::SIGPIPE) };
            exit_group(3);
        });
        park();
    });
    line("a thread raise()s SIGPIPE, then exit_group(3)", reap(p, Duration::from_secs(5)));

    let p = fork(|| {
        park_thread();
        std::thread::spawn(|| {
            unsafe { libc::kill(getpid(), libc::SIGQUIT) };
            settle();
            exit_group(3);
        });
        park();
    });
    // A core-dumping signal still goes through delivery on Linux.
    line("a thread kill()s its process with SIGQUIT, then exit_group(3)", reap(p, Duration::from_secs(5)));

    let p = fork(|| {
        let (r, w) = pipe();
        std::thread::spawn(move || {
            put(w, 0);
            exit_group(3);
        });
        get(r);
        unsafe { libc::kill(getpid(), TERM) };
        park();
    });
    line("exit_group(3) in one thread, SIGTERM to itself from the leader", {
        let s = reap(p, Duration::from_secs(5));
        if s == "exited 3" || s == "killed by 15" { "exited 3 or killed by 15".to_string() } else { s }
    });
}

// ---------------------------------------------------------------------------
// Where the threads are when it arrives
// ---------------------------------------------------------------------------

/// A child whose leader and one other thread both block in `wait`, killed
/// with `sig` by the parent once both are there.
fn blocked_case(what: &str, sig: c_int, wait: fn()) {
    let (r, w) = pipe();
    let p = fork(move || {
        std::thread::spawn(move || {
            put(w, 0);
            wait();
        });
        wait();
    });
    get(r);
    settle();
    unsafe { libc::kill(p, sig) };
    line(&format!("{what}, sent {sig}"), reap(p, Duration::from_secs(5)));
}

fn in_futex() {
    static WORD: AtomicI32 = AtomicI32::new(0);
    loop {
        unsafe { libc::syscall(libc::SYS_futex, WORD.as_ptr(), libc::FUTEX_WAIT, 0, std::ptr::null::<libc::timespec>()) };
    }
}

fn in_pipe_read() {
    // The write end stays open, so the read never sees EOF.
    let (r, _w) = pipe();
    let mut b = [0u8; 1];
    loop {
        unsafe { libc::read(r, b.as_mut_ptr().cast(), 1) };
    }
}

fn in_nanosleep() {
    loop {
        let ts = libc::timespec { tv_sec: 100, tv_nsec: 0 };
        unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
    }
}

fn in_epoll_wait() {
    let ep = unsafe { libc::epoll_create1(0) };
    let mut ev = [libc::epoll_event { events: 0, u64: 0 }];
    loop {
        unsafe { libc::epoll_wait(ep, ev.as_mut_ptr(), 1, -1) };
    }
}

fn in_spin() {
    let mut x = 0u64;
    loop {
        x = std::hint::black_box(x.wrapping_add(1));
    }
}

fn blocked_cases() {
    println!("########## where the threads are ##########");
    blocked_case("both threads in futex_wait", TERM, in_futex);
    blocked_case("both threads in futex_wait", KILL, in_futex);
    blocked_case("both threads in read on an empty pipe", TERM, in_pipe_read);
    blocked_case("both threads in nanosleep", TERM, in_nanosleep);
    blocked_case("both threads in epoll_wait", TERM, in_epoll_wait);
    blocked_case("both threads spinning", TERM, in_spin);

    // The leader blocks the signal and the other thread does not: it is
    // chosen, and the group goes.
    let (r, w) = pipe();
    let p = fork(move || {
        mask(libc::SIG_BLOCK, &[TERM]);
        std::thread::spawn(move || {
            mask(libc::SIG_UNBLOCK, &[TERM]);
            put(w, 0);
            in_futex();
        });
        in_spin();
    });
    get(r);
    settle();
    unsafe { libc::kill(p, TERM) };
    line("the spinning leader blocks SIGTERM, a parked thread does not", reap(p, Duration::from_secs(5)));
}

// ---------------------------------------------------------------------------
// Stopped groups
// ---------------------------------------------------------------------------

fn wait_stopped(p: i32) -> String {
    let mut st = 0;
    let r = unsafe { libc::waitpid(p, &mut st, libc::WUNTRACED) };
    if r == p { describe(st) } else { "waitpid failed".into() }
}

fn stopped_cases() {
    println!("########## stopped groups ##########");
    let p = fork(|| {
        park_thread();
        park();
    });
    settle();
    unsafe { libc::kill(p, libc::SIGSTOP) };
    line("a two-thread child, SIGSTOP", wait_stopped(p));
    unsafe { libc::kill(p, KILL) };
    line("  then SIGKILL", reap(p, Duration::from_secs(5)));

    let p = fork(|| {
        park_thread();
        park();
    });
    settle();
    unsafe { libc::kill(p, libc::SIGSTOP) };
    line("a two-thread child, SIGSTOP", wait_stopped(p));
    unsafe { libc::kill(p, TERM) };
    settle();
    line("  then SIGTERM: its state", state(p));
    line("  ShdPnd while stopped", status_set(p, "ShdPnd:"));
    unsafe { libc::kill(p, libc::SIGCONT) };
    line("  then SIGCONT", reap(p, Duration::from_secs(5)));

    let p = fork(|| {
        park_thread();
        park();
    });
    settle();
    unsafe { libc::kill(p, TERM) };
    unsafe { libc::kill(p, libc::SIGSTOP) };
    line("SIGTERM then SIGSTOP at once", reap(p, Duration::from_secs(5)));
}

// ---------------------------------------------------------------------------
// execve against a fatal signal
// ---------------------------------------------------------------------------

/// The program the exec runs: it touches nothing about signals and waits.
/// The alarm turns a survivor into a `SIGALRM` death rather than a hang.
fn sleeper() -> ! {
    unsafe { libc::alarm(3) };
    park();
}

fn exec_round(me: &CString, sig: c_int, spin: bool) -> String {
    let (r, w) = pipe();
    let me = me.clone();
    let p = fork(move || {
        for _ in 0..3 {
            if spin {
                std::thread::spawn(in_spin);
            } else {
                park_thread();
            }
        }
        std::thread::spawn(move || {
            let arg = CString::new("sleeper").unwrap();
            let argv = [me.as_ptr(), arg.as_ptr(), std::ptr::null()];
            put(w, 0);
            unsafe { libc::execv(me.as_ptr(), argv.as_ptr()) };
        });
        park();
    });
    get(r);
    unsafe { libc::kill(p, sig) };
    reap(p, Duration::from_secs(6))
}

fn exec_cases(me: &CString) {
    println!("########## execve ##########");
    for (sig, spin) in [(TERM, false), (TERM, true), (KILL, false), (KILL, true)] {
        let mut outcomes: Vec<(String, u32)> = Vec::new();
        for _ in 0..40 {
            let o = exec_round(me, sig, spin);
            match outcomes.iter_mut().find(|(k, _)| *k == o) {
                Some((_, n)) => *n += 1,
                None => outcomes.push((o, 1)),
            }
        }
        outcomes.sort();
        let s: Vec<String> = outcomes.iter().map(|(k, n)| format!("{k} x{n}")).collect();
        let who = if spin { "spinning" } else { "parked" };
        line(&format!("a thread execs, three {who}, {sig} sent as it starts, 40 rounds"), s.join(", "));
    }
}

// ---------------------------------------------------------------------------
// What is left: a zombie's sets, a pidfd, the parent-death signal
// ---------------------------------------------------------------------------

fn aftermath_cases() {
    println!("########## after ##########");
    let p = fork(|| {
        park_thread();
        park();
    });
    settle();
    unsafe { libc::kill(p, TERM) };
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    unsafe { libc::waitid(libc::P_PID, p as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
    line("a zombie killed by SIGTERM: State", state(p));
    line("  SigPnd", status_set(p, "SigPnd:"));
    line("  ShdPnd", status_set(p, "ShdPnd:"));
    line("  Threads", status_field(p, "Threads:"));
    line("  reaped", reap(p, Duration::from_secs(5)));

    let p = fork(|| {
        park_thread();
        park();
    });
    settle();
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, p, 0) } as c_int;
    let mut pfd = libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 };
    let before = unsafe { libc::poll(&mut pfd, 1, 0) };
    line("a pidfd before SIGTERM: poll", before);
    unsafe { libc::kill(p, TERM) };
    pfd.revents = 0;
    let after = unsafe { libc::poll(&mut pfd, 1, 3000) };
    line("  after it, within 3 s: poll", format!("{after} revents {:#x}", pfd.revents));
    line("  reaped", reap(p, Duration::from_secs(5)));
    unsafe { libc::close(pidfd) };

    let (r, w) = pipe();
    let p = fork(move || {
        let c = fork(move || {
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, USR1 as libc::c_ulong) };
            put(w, getpid());
            park();
        });
        let _ = c;
        park_thread();
        park();
    });
    let c = get(r);
    settle();
    unsafe { libc::kill(p, TERM) };
    line("a parent with PR_SET_PDEATHSIG(SIGUSR1) child, SIGTERM", reap(p, Duration::from_secs(5)));
    line("  the child, reparented here", reap(c, Duration::from_secs(5)));
}

// ---------------------------------------------------------------------------
// pid 1
// ---------------------------------------------------------------------------

static CAUGHT: AtomicBool = AtomicBool::new(false);

extern "C" fn caught(_: c_int) {
    CAUGHT.store(true, Ordering::SeqCst);
}

fn handle(sig: c_int, handler: libc::sighandler_t) {
    unsafe { libc::signal(sig, handler) };
}

fn init_cases() {
    println!("########## pid 1 ##########");
    if getpid() != 1 {
        line("this program is not pid 1", getpid());
        return;
    }
    unsafe { libc::kill(1, TERM) };
    settle();
    line("kill(1, SIGTERM) from itself, SIG_DFL", "survived");
    line("  ShdPnd", status_set(1, "ShdPnd:"));
    tgkill(1, 1, USR1);
    settle();
    line("tgkill(1, 1, SIGUSR1) from itself, SIG_DFL", "survived");

    // A thread that does not block it, gone again before the cases below.
    let free = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(300));
    });
    settle();
    let tids = threads_of_1();
    if let Some(&t) = tids.iter().find(|&&t| t != 1) {
        tgkill(1, t, TERM);
    }
    let _ = free.join();
    line("tgkill of another thread of pid 1, SIGTERM, SIG_DFL", "survived");

    mask(libc::SIG_BLOCK, &[TERM]);
    park_thread();
    unsafe { libc::kill(1, TERM) };
    line("SIGTERM while every thread blocks it: ShdPnd", status_set(1, "ShdPnd:"));
    mask(libc::SIG_UNBLOCK, &[TERM]);
    settle();
    line("  then the leader unblocks it", "survived");
    line("  ShdPnd after", status_set(1, "ShdPnd:"));

    handle(TERM, caught as *const () as libc::sighandler_t);
    unsafe { libc::kill(1, TERM) };
    settle();
    line("kill(1, SIGTERM) with a handler: it ran", CAUGHT.load(Ordering::SeqCst));
    handle(TERM, libc::SIG_DFL);

    let c = fork(|| {
        unsafe { libc::kill(1, KILL) };
    });
    let _ = reap(c, Duration::from_secs(5));
    settle();
    line("a child sends SIGKILL to 1", "survived");

    let c = fork(|| {
        unsafe { libc::kill(1, TERM) };
    });
    let _ = reap(c, Duration::from_secs(5));
    settle();
    line("a child sends SIGTERM to 1", "survived");

    let (r, w) = pipe();
    let c = fork(move || {
        unsafe { libc::kill(1, libc::SIGSTOP) };
        std::thread::sleep(Duration::from_millis(100));
        let s = state(1);
        put(w, s.bytes().next().unwrap_or(b'?') as i32);
        unsafe { libc::kill(1, libc::SIGCONT) };
    });
    let s = get(r);
    let _ = reap(c, Duration::from_secs(5));
    line("a child sends SIGSTOP to 1: State the child sees", (s as u8) as char);

    let (r, w) = pipe();
    let c = fork(move || {
        unsafe { libc::kill(1, libc::SIGTSTP) };
        std::thread::sleep(Duration::from_millis(100));
        let s = state(1);
        put(w, s.bytes().next().unwrap_or(b'?') as i32);
        unsafe { libc::kill(1, libc::SIGCONT) };
    });
    let s = get(r);
    let _ = reap(c, Duration::from_secs(5));
    line("a child sends SIGTSTP to 1: State the child sees", (s as u8) as char);

    // Last, because Linux ends pid 1 here: the signal is not ignored at
    // generation (the leader blocks it), and the thread chosen for it does
    // not, so `complete_signal` starts the group exit.
    mask(libc::SIG_BLOCK, &[TERM]);
    let (r, w) = pipe();
    std::thread::spawn(move || {
        mask(libc::SIG_UNBLOCK, &[TERM]);
        put(w, 0);
        in_futex();
    });
    get(r);
    line("the leader blocks SIGTERM, another thread does not: kill(1)", "sending");
    unsafe { libc::kill(1, TERM) };
    settle();
    line("  pid 1", "survived");
}

fn threads_of_1() -> Vec<i32> {
    std::fs::read_dir("/proc/1/task")
        .map(|d| d.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect())
        .unwrap_or_default()
}

/// A fatal signal sent to one *thread* of a process blocked in a syscall:
/// `tgkill`, which is also how a tracer's `PTRACE_O_EXITKILL` and
/// `PTRACE_KILL` arrive. The thread has to be woken out of the wait.
fn thread_directed_cases() {
    for (name, sig) in [("SIGKILL", KILL), ("SIGTERM, SIG_DFL", TERM)] {
        let (r, w) = pipe();
        let p = fork(|| {
            let _ = get(r);
            unsafe { libc::_exit(1) };
        });
        std::thread::sleep(Duration::from_millis(50));
        tgkill(p, p, sig);
        unsafe { libc::close(w) };
        line(&format!("tgkill {name} to a child blocked in read"), reap(p, Duration::from_secs(5)));
        unsafe { libc::close(r) };
    }
    // A non-leader thread blocked in read: the whole process goes.
    for (name, sig) in [("SIGKILL", KILL), ("SIGTERM, SIG_DFL", TERM)] {
        let (r, w) = pipe();
        let (tr, tw) = pipe();
        let p = fork(|| {
            let t = std::thread::spawn(move || {
                put(tw, gettid());
                let _ = get(r);
            });
            let _ = t.join();
            unsafe { libc::_exit(1) };
        });
        let tid = get(tr);
        std::thread::sleep(Duration::from_millis(50));
        tgkill(p, tid, sig);
        unsafe { libc::close(w) };
        line(&format!("tgkill {name} to a thread blocked in read"), reap(p, Duration::from_secs(5)));
        unsafe { libc::close(r) };
        unsafe { libc::close(tr) };
        unsafe { libc::close(tw) };
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("sleeper") {
        sleeper();
    }
    let me = CString::new(args[0].clone()).unwrap();
    status_cases();
    blocked_cases();
    thread_directed_cases();
    stopped_cases();
    exec_cases(&me);
    aftermath_cases();
    init_cases();
}
