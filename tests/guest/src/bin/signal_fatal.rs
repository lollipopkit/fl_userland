//! A fatal signal ends the whole process when it is sent, as Linux's
//! `complete_signal` decides: the status is the signal whatever the process
//! does next, and an `execve` in progress does not complete.
//!
//! Until 2026-11-13 the decision was the delivering thread's, so a thread
//! that `kill`ed its own process went on to `exit_group(3)` and the parent saw
//! 3, and a thread already being ended by another's `execve` that took the
//! signal left alone while the exec carried on. `sigfatal_probe` is the
//! report; every expectation here is what a real arm64 kernel answered there.
//!
//! `--stress N` runs N rounds of the exec race: one thread execs while the
//! leader spins in system calls and the parent sends `SIGTERM` at a jittered
//! moment around the exec. Every round must die of `SIGTERM`; a round in
//! which the signal was lost is a `SIGALRM` from the new program, and a hang
//! is a failure, not a wait.

use guest_tests::{Harness, check};
use std::ffi::{CString, c_int};
use std::sync::atomic::AtomicI32;
use std::time::{Duration, Instant};

const TERM: c_int = libc::SIGTERM;
const KILL: c_int = libc::SIGKILL;

fn getpid() -> i32 {
    unsafe { libc::getpid() }
}

fn gettid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
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

fn pipe() -> (c_int, c_int) {
    let mut fds = [0; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    (fds[0], fds[1])
}

fn put(fd: c_int) {
    unsafe { libc::write(fd, [0u8].as_ptr().cast(), 1) };
}

fn get(fd: c_int) {
    let mut b = [0u8; 1];
    unsafe { libc::read(fd, b.as_mut_ptr().cast(), 1) };
}

/// The wait status, or `None` when the child outlived `limit` (it is then
/// killed and reaped).
fn reap(pid: i32, limit: Duration) -> Option<c_int> {
    let t0 = Instant::now();
    loop {
        let mut st = 0;
        if unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) } == pid {
            return Some(st);
        }
        if t0.elapsed() > limit {
            describe_threads(pid);
            unsafe { libc::kill(pid, KILL) };
            let t1 = Instant::now();
            while unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) } != pid {
                if t1.elapsed() > limit {
                    println!("  pid {pid} outlived SIGKILL");
                    describe_threads(pid);
                    std::process::exit(1);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            return None;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// What each thread of a child that outlived its limit is doing.
fn describe_threads(pid: i32) {
    let tids: Vec<String> = std::fs::read_dir(format!("/proc/{pid}/task"))
        .map(|d| d.filter_map(|e| Some(e.ok()?.file_name().to_string_lossy().into_owned())).collect())
        .unwrap_or_default();
    for tid in tids {
        let read = |f: &str| std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/{f}")).unwrap_or_default();
        let state = read("status").lines().find(|l| l.starts_with("State:")).unwrap_or("").to_string();
        println!("  pid {pid} tid {tid}: {state}, syscall {}", read("syscall").trim());
    }
}

fn killed_by(st: Option<c_int>) -> Option<c_int> {
    st.filter(|&s| libc::WIFSIGNALED(s)).map(|s| libc::WTERMSIG(s))
}

fn show(st: Option<c_int>) -> String {
    match st {
        None => "a hang".into(),
        Some(s) if libc::WIFSIGNALED(s) => format!("signal {}", libc::WTERMSIG(s)),
        Some(s) if libc::WIFEXITED(s) => format!("exit {}", libc::WEXITSTATUS(s)),
        Some(s) => format!("status {s:#x}"),
    }
}

fn fork(f: impl FnOnce()) -> i32 {
    let p = unsafe { libc::fork() };
    if p == 0 {
        f();
        unsafe { libc::_exit(0) };
    }
    p
}

fn park() -> ! {
    static WORD: AtomicI32 = AtomicI32::new(0);
    loop {
        unsafe { libc::syscall(libc::SYS_futex, WORD.as_ptr(), libc::FUTEX_WAIT, 0, std::ptr::null::<libc::timespec>()) };
    }
}

fn park_thread() {
    let (r, w) = pipe();
    std::thread::spawn(move || {
        put(w);
        park();
    });
    get(r);
}

const LIMIT: Duration = Duration::from_secs(10);

fn status(h: &mut Harness) {
    h.group("status");
    // The sender does not return from kill(): the exit status is the signal.
    let p = fork(|| {
        park_thread();
        std::thread::spawn(|| {
            unsafe { libc::kill(getpid(), TERM) };
            exit_group(3);
        });
        park();
    });
    let st = reap(p, LIMIT);
    check!(h, killed_by(st) == Some(TERM), "kill(getpid(), SIGTERM) from a thread, then exit_group(3): {}", show(st));

    let p = fork(|| {
        park_thread();
        std::thread::spawn(|| {
            unsafe { libc::kill(getpid(), KILL) };
            exit_group(3);
        });
        park();
    });
    let st = reap(p, LIMIT);
    check!(h, killed_by(st) == Some(KILL), "kill(getpid(), SIGKILL) from a thread, then exit_group(3): {}", show(st));

    // Thread-directed: tgkill decides at send time too.
    let p = fork(|| {
        let leader = gettid();
        std::thread::spawn(move || {
            unsafe { libc::syscall(libc::SYS_tgkill, getpid(), leader, TERM) };
            exit_group(3);
        });
        park();
    });
    let st = reap(p, LIMIT);
    check!(h, killed_by(st) == Some(TERM), "tgkill of the parked leader, then exit_group(3): {}", show(st));

    // The sender blocks it; the thread chosen does not.
    let p = fork(|| {
        mask(libc::SIG_BLOCK, &[TERM]);
        let (r, w) = pipe();
        std::thread::spawn(move || {
            mask(libc::SIG_UNBLOCK, &[TERM]);
            put(w);
            park();
        });
        get(r);
        unsafe { libc::kill(getpid(), TERM) };
        exit_group(3);
    });
    let st = reap(p, LIMIT);
    check!(h, killed_by(st) == Some(TERM), "the leader blocks SIGTERM, kills itself, exit_group(3): {}", show(st));

    // The first fatal signal is the status.
    let p = fork(|| {
        park_thread();
        std::thread::spawn(|| {
            unsafe { libc::kill(getpid(), TERM) };
            unsafe { libc::kill(getpid(), libc::SIGUSR1) };
            exit_group(3);
        });
        park();
    });
    let st = reap(p, LIMIT);
    check!(h, killed_by(st) == Some(TERM), "SIGTERM then SIGUSR1: {}", show(st));

    // Nobody can take it: nothing is decided, and exit_group's status stands.
    let p = fork(|| {
        mask(libc::SIG_BLOCK, &[TERM]);
        park_thread();
        unsafe { libc::kill(getpid(), TERM) };
        std::thread::sleep(Duration::from_millis(50));
        exit_group(3);
    });
    let st = reap(p, LIMIT);
    check!(h, st.is_some_and(|s| libc::WIFEXITED(s) && libc::WEXITSTATUS(s) == 3), "every thread blocks SIGTERM: {}", show(st));

    // A core-dumping signal is still delivery's to act on, and acts. Set to
    // the default first: a shell's `&` starts this with SIGQUIT ignored.
    let p = fork(|| {
        unsafe { libc::signal(libc::SIGQUIT, libc::SIG_DFL) };
        park_thread();
        unsafe { libc::kill(getpid(), libc::SIGQUIT) };
        std::thread::sleep(Duration::from_millis(50));
        exit_group(3);
    });
    let st = reap(p, LIMIT);
    check!(h, killed_by(st) == Some(libc::SIGQUIT), "SIGQUIT: {}", show(st));
}

fn stopped(h: &mut Harness) {
    h.group("stopped");
    // SIGTERM to a stopped group waits for SIGCONT: no thread can take it.
    let p = fork(|| {
        park_thread();
        park();
    });
    std::thread::sleep(Duration::from_millis(50));
    unsafe { libc::kill(p, libc::SIGSTOP) };
    let mut st = 0;
    unsafe { libc::waitpid(p, &mut st, libc::WUNTRACED) };
    check!(h, libc::WIFSTOPPED(st), "stopped first: {st:#x}");
    unsafe { libc::kill(p, TERM) };
    std::thread::sleep(Duration::from_millis(100));
    let r = unsafe { libc::waitpid(p, &mut st, libc::WNOHANG) };
    check!(h, r == 0, "SIGTERM does not end a stopped group (waitpid {r}, status {st:#x})");
    unsafe { libc::kill(p, libc::SIGCONT) };
    let st = reap(p, LIMIT);
    check!(h, killed_by(st) == Some(TERM), "SIGCONT lets it die of SIGTERM: {}", show(st));

    let p = fork(|| {
        park_thread();
        park();
    });
    std::thread::sleep(Duration::from_millis(50));
    unsafe { libc::kill(p, libc::SIGSTOP) };
    let mut st = 0;
    unsafe { libc::waitpid(p, &mut st, libc::WUNTRACED) };
    unsafe { libc::kill(p, KILL) };
    let st = reap(p, LIMIT);
    check!(h, killed_by(st) == Some(KILL), "SIGKILL ends a stopped group: {}", show(st));
}

/// pid 1 ignores a default-action signal sent from its own namespace, which
/// every sender here is in: Linux's `SIGNAL_UNKILLABLE`.
fn init(h: &mut Harness) {
    h.group("pid 1");
    if getpid() != 1 {
        println!("  (not pid 1: skipped)");
        return;
    }
    unsafe { libc::kill(1, TERM) };
    std::thread::sleep(Duration::from_millis(50));
    check!(h, true, "kill(1, SIGTERM) from itself: survived");
    let c = fork(|| {
        unsafe { libc::kill(1, KILL) };
    });
    let _ = reap(c, LIMIT);
    std::thread::sleep(Duration::from_millis(50));
    check!(h, true, "SIGKILL to 1 from a child: survived");
}

/// The new program. It leaves SIGTERM at the default, so the only way it
/// survives is that the signal was lost; the alarm tells that round apart
/// from a hang.
fn sleeper() -> ! {
    unsafe { libc::alarm(2) };
    park();
}

fn spin_us(us: u64) {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_micros(us) {
        std::hint::spin_loop();
    }
}

fn exec_race(h: &mut Harness, me: &CString, rounds: u32) {
    h.group("execve against SIGTERM");
    let mut lost = 0;
    let mut seed = 0x9e37_79b9_7f4a_7c15u64 ^ u64::from(getpid() as u32);
    for round in 0..rounds {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        // Mostly within 60 us of the byte, which is where the exec claims
        // the group here; the rest spread over the whole exec.
        let jitter = if round % 4 == 0 { seed % 3000 } else { seed % 60 };
        let (r, w) = pipe();
        let me = me.clone();
        let p = fork(move || {
            park_thread();
            std::thread::spawn(move || {
                let arg = CString::new("sleeper").unwrap();
                let argv = [me.as_ptr(), arg.as_ptr(), std::ptr::null()];
                put(w);
                unsafe { libc::execv(me.as_ptr(), argv.as_ptr()) };
            });
            loop {
                unsafe { libc::getppid() };
            }
        });
        unsafe { libc::close(w) };
        let mut pfd = libc::pollfd { fd: r, events: libc::POLLIN, revents: 0 };
        if unsafe { libc::poll(&mut pfd, 1, LIMIT.as_millis() as c_int) } != 1 {
            println!("  round {round}: the child never got as far as the exec");
            describe_threads(p);
            check!(h, false, "round {round}: the child stuck before the exec");
            unsafe { libc::kill(p, KILL) };
            let _ = reap(p, LIMIT);
            break;
        }
        get(r);
        unsafe { libc::close(r) };
        spin_us(jitter);
        unsafe { libc::kill(p, TERM) };
        let st = reap(p, LIMIT);
        if round % 1000 == 999 {
            println!("  {} rounds", round + 1);
        }
        if killed_by(st) != Some(TERM) {
            lost += 1;
            if lost <= 5 {
                println!("  round {round} (jitter {jitter} us): {}", show(st));
            }
        }
    }
    check!(h, lost == 0, "{lost} of {rounds} rounds did not die of SIGTERM");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("sleeper") {
        sleeper();
    }
    let me = CString::new(args[0].clone()).unwrap();
    let mut h = Harness::new();
    let stress = args.iter().position(|a| a == "--stress").and_then(|i| args.get(i + 1)?.parse().ok());
    match stress {
        Some(n) => exec_race(&mut h, &me, n),
        None => {
            status(&mut h);
            stopped(&mut h);
            exec_race(&mut h, &me, 20);
            init(&mut h);
        }
    }
    std::process::exit(h.finish());
}
