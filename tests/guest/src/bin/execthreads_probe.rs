//! `execve` in a process with more than one thread: Linux's `de_thread`.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container and diffed by `tests/integration/probe_diff.sh`.
//!
//! Every case runs in a fresh child, which is the process that execs. The new
//! program is this binary again with `report <case> key=value...`, and prints
//! what it finds against the values the old program passed it. Numbers that
//! differ between runs (pids, ticks) are printed as relations.

use std::ffi::{CString, c_int, c_long, c_void};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

const USR1: c_int = libc::SIGUSR1;
const USR2: c_int = libc::SIGUSR2;
const WINCH: c_int = libc::SIGWINCH;

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

fn getpid() -> i32 {
    unsafe { libc::getpid() }
}

fn tgkill(tid: i32, sig: c_int) {
    unsafe { libc::syscall(libc::SYS_tgkill, getpid(), tid, sig) };
}

fn set_of(mask: u64) -> String {
    let v: Vec<String> = (1..=64).filter(|s| mask & (1u64 << (s - 1)) != 0).map(|s| s.to_string()).collect();
    format!("{{{}}}", v.join(","))
}

fn mask(how: c_int, sigs: &[c_int]) {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    for &s in sigs {
        unsafe { libc::sigaddset(&mut set, s) };
    }
    unsafe { libc::pthread_sigmask(how, &set, std::ptr::null_mut()) };
}

fn status_field(path: &str, key: &str) -> String {
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .map_or("?".into(), |v| v.trim().to_string()),
        Err(e) => format!("errno {}", e.raw_os_error().unwrap_or(0)),
    }
}

fn status_set(key: &str) -> String {
    let v = status_field("/proc/self/status", key);
    u64::from_str_radix(&v, 16).map_or(v, set_of)
}

/// Field 22 of a `stat` file: the start time in ticks.
fn start_time(path: &str) -> u64 {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    let after = s.rfind(')').map_or("", |i| &s[i + 2..]);
    after.split_whitespace().nth(19).and_then(|v| v.parse().ok()).unwrap_or(0)
}

fn task_entries() -> Vec<i32> {
    let mut v: Vec<i32> = std::fs::read_dir("/proc/self/task")
        .map(|d| d.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn rel<T: PartialEq>(a: T, b: T) -> &'static str {
    if a == b { "same" } else { "differs" }
}

// ---------------------------------------------------------------------------
// The program the exec runs
// ---------------------------------------------------------------------------

fn kv(args: &[String], k: &str) -> Option<i64> {
    args.iter().find_map(|a| a.strip_prefix(k)?.strip_prefix('=')?.parse().ok())
}

fn report(case: &str, args: &[String]) {
    let p = |what: &str, v: &dyn std::fmt::Display| line(&format!("  {case}: {what}"), v);
    let pid = getpid();
    if let Some(before) = kv(args, "pid") {
        p("getpid is the pid before the exec", &rel(pid as i64, before));
    }
    p("gettid is getpid", &rel(gettid(), pid));
    let tasks = task_entries();
    p("/proc/self/task", &if tasks == [pid] { "only <pid>".to_string() } else { format!("{} entries", tasks.len()) });
    p("Threads: in status", &status_field("/proc/self/status", "Threads:"));
    p("Tgid: is Pid:", &rel(status_field("/proc/self/status", "Tgid:"), status_field("/proc/self/status", "Pid:")));
    if let Some(old) = kv(args, "oldtid") {
        let r = std::fs::metadata(format!("/proc/{old}")).map_or_else(|e| format!("errno {}", e.raw_os_error().unwrap_or(0)), |_| "exists".into());
        p("/proc/<the exec'ing thread's old tid>", &r);
    }
    if let Some(v) = kv(args, "ppid") {
        p("getppid", &rel(unsafe { libc::getppid() } as i64, v));
    }
    if let Some(v) = kv(args, "pgid") {
        p("getpgid", &rel(unsafe { libc::getpgid(0) } as i64, v));
    }
    if let Some(v) = kv(args, "sid") {
        p("getsid", &rel(unsafe { libc::getsid(0) } as i64, v));
    }
    if let (Some(lead), Some(own)) = (kv(args, "start"), kv(args, "tstart")) {
        let now = start_time("/proc/self/stat") as i64;
        let what = if now == lead && now != own {
            "the old leader's"
        } else if now == own && now != lead {
            "the exec'ing thread's"
        } else if now == lead {
            "the old leader's (both equal)"
        } else {
            "neither"
        };
        p("start time in /proc/self/stat", &what);
    } else if let Some(lead) = kv(args, "start") {
        p("start time in /proc/self/stat", &rel(start_time("/proc/self/stat") as i64, lead));
    }
    if args.iter().any(|a| a == "signals") {
        p("SigBlk", &status_set("SigBlk:"));
        p("SigPnd", &status_set("SigPnd:"));
        p("ShdPnd", &status_set("ShdPnd:"));
    }
    if let Some(fd) = kv(args, "fd_keep") {
        let r = unsafe { libc::fcntl(fd as c_int, libc::F_GETFD) };
        p("a descriptor without O_CLOEXEC", &if r < 0 { format!("errno {}", errno()) } else { "open".into() });
    }
    if let Some(fd) = kv(args, "fd_cloexec") {
        let r = unsafe { libc::fcntl(fd as c_int, libc::F_GETFD) };
        p("a descriptor with O_CLOEXEC", &if r < 0 { format!("errno {}", errno()) } else { "open".into() });
    }
    if let Some(id) = kv(args, "timer") {
        let mut its: libc::itimerspec = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::syscall(libc::SYS_timer_gettime, id as c_long, &mut its) };
        p("timer_gettime of a POSIX timer made before", &if r < 0 { format!("errno {}", errno()) } else { "0".into() });
    }
    if args.iter().any(|a| a == "itimer") {
        let mut it: libc::itimerval = unsafe { std::mem::zeroed() };
        unsafe { libc::getitimer(libc::ITIMER_REAL, &mut it) };
        p("ITIMER_REAL", &if it.it_value.tv_sec > 0 { "still armed" } else { "disarmed" });
        let zero: libc::itimerval = unsafe { std::mem::zeroed() };
        unsafe { libc::setitimer(libc::ITIMER_REAL, &zero, std::ptr::null_mut()) };
    }
    if args.iter().any(|a| a == "prctl") {
        let mut v: c_int = 0;
        unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut v as *mut c_int) };
        p("PR_GET_CHILD_SUBREAPER", &v);
        let mut s: c_int = 0;
        unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut s as *mut c_int) };
        p("PR_GET_PDEATHSIG", &s);
    }
    if let (Some(go), Some(back)) = (kv(args, "go"), kv(args, "back")) {
        unsafe { libc::write(go as c_int, b"x".as_ptr().cast(), 1) };
        p("the CLONE_VM process still runs", &if wait_byte(back as c_int, 3000) { "answered" } else { "no answer" });
        let mut st = 0;
        let r = unsafe { libc::waitpid(-1, &mut st, libc::__WALL) };
        p("  and is reaped by the new program", &if r > 0 { describe(st) } else { format!("errno {}", errno()) });
    }
    if let Some(fd) = kv(args, "pdeath") {
        // The child the old leader forked: did it hear its parent thread die,
        // and who is its parent now?
        let mut buf = [0u8; 64];
        let n = read_timeout(fd as c_int, &mut buf, 8000);
        p("the old leader's child says", &String::from_utf8_lossy(&buf[..n]).trim().to_string());
        let mut st = 0;
        unsafe { libc::waitpid(-1, &mut st, libc::__WALL) };
    }
    if let Some(fd) = kv(args, "hold") {
        // Say this program has printed what it prints, and stay until the
        // parent has looked at the pidfd.
        if let Some(ready) = kv(args, "ready") {
            unsafe { libc::write(ready as c_int, b"x".as_ptr().cast(), 1) };
        }
        let mut b = [0u8; 1];
        unsafe { libc::read(fd as c_int, b.as_mut_ptr().cast(), 1) };
    }
    if args.iter().any(|a| a == "ran") {
        p("the new program ran", &"yes");
    }
}

fn wait_byte(fd: c_int, ms: c_int) -> bool {
    let mut b = [0u8; 1];
    read_timeout(fd, &mut b, ms) == 1
}

fn read_timeout(fd: c_int, buf: &mut [u8], ms: c_int) -> usize {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    if unsafe { libc::poll(&mut pfd, 1, ms) } != 1 {
        return 0;
    }
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    n.max(0) as usize
}

// ---------------------------------------------------------------------------
// The old program
// ---------------------------------------------------------------------------

fn exec_argv(case: &str, extra: &[String]) -> (Vec<CString>, Vec<*const libc::c_char>) {
    let mut owned = vec![
        CString::new("execthreads_probe").unwrap(),
        CString::new("report").unwrap(),
        CString::new(case).unwrap(),
    ];
    owned.extend(extra.iter().map(|s| CString::new(s.as_str()).unwrap()));
    let mut ptrs: Vec<*const libc::c_char> = owned.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    (owned, ptrs)
}

/// Exec this binary as the report; answers the errno if it came back.
fn exec_report(case: &str, extra: &[String]) -> i32 {
    exec_path("/proc/self/exe", case, extra)
}

fn exec_path(path: &str, case: &str, extra: &[String]) -> i32 {
    let me = CString::new(path).unwrap();
    let (_owned, argv) = exec_argv(case, extra);
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    let _ = std::io::stdout().flush();
    unsafe { libc::execve(me.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    errno()
}

fn describe(st: c_int) -> String {
    if libc::WIFEXITED(st) {
        format!("exited {}", libc::WEXITSTATUS(st))
    } else if libc::WIFSIGNALED(st) {
        format!("killed by {}", libc::WTERMSIG(st))
    } else {
        format!("status {st:#x}")
    }
}

/// Every wait event for the child's pid, until there are none.
fn reap_all(child: i32) -> String {
    let mut out = Vec::new();
    loop {
        let mut st = 0;
        let r = unsafe { libc::waitpid(child, &mut st, libc::__WALL) };
        if r < 0 {
            out.push(format!("then errno {}", errno()));
            break;
        }
        let who = if r == child { "the child" } else { "another pid" };
        out.push(format!("{who} {}", describe(st)));
    }
    out.join(", ")
}

/// Run `f` in a fresh child with its output collected, and answer the
/// collected output and the wait events.
fn in_child(f: impl FnOnce()) -> (String, String, i32) {
    let mut fds = [0; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let _ = std::io::stdout().flush();
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::close(fds[0]);
            libc::dup2(fds[1], 1);
            libc::close(fds[1]);
            // A case that hangs is a finding, not a stuck run.
            libc::alarm(20);
        }
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(fds[1]) };
    let waits = reap_all(child);
    let mut out = String::new();
    unsafe { libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK) };
    let mut f = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fds[0]) };
    let _ = f.read_to_string(&mut out);
    (out, waits, child)
}

fn case(name: &str, f: impl FnOnce()) {
    line(name, "");
    let (out, waits, _) = in_child(f);
    print!("{out}");
    line(&format!("  {name}: the parent's wait events"), waits);
}

/// Threads parked in the calls the exec has to end, and one spinning.
fn park_threads() {
    let mut p = [0; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let r = p[0];
    std::thread::spawn(move || {
        let mut b = [0u8; 1];
        unsafe { libc::read(r, b.as_mut_ptr().cast(), 1) };
    });
    std::thread::spawn(|| std::thread::sleep(Duration::from_secs(60)));
    std::thread::spawn(|| {
        static WORD: u32 = 0;
        unsafe {
            libc::syscall(libc::SYS_futex, &WORD as *const u32, libc::FUTEX_WAIT, 0, std::ptr::null::<libc::timespec>())
        };
    });
    std::thread::spawn(|| unsafe {
        let ep = libc::epoll_create1(0);
        let mut ev: libc::epoll_event = std::mem::zeroed();
        libc::epoll_wait(ep, &mut ev, 1, -1);
    });
    std::thread::spawn(|| unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut a: libc::sockaddr_in = std::mem::zeroed();
        a.sin_family = libc::AF_INET as _;
        a.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
        libc::bind(s, (&a as *const libc::sockaddr_in).cast(), std::mem::size_of_val(&a) as _);
        libc::listen(s, 1);
        libc::accept(s, std::ptr::null_mut(), std::ptr::null_mut());
    });
    std::thread::spawn(|| {
        static SPIN: AtomicU64 = AtomicU64::new(0);
        loop {
            SPIN.fetch_add(1, Ordering::Relaxed);
        }
    });
    std::thread::sleep(Duration::from_millis(200));
}

fn leader_execs() {
    case("the leader execs while six threads are parked or spinning", || {
        park_threads();
        let pid = getpid();
        let start = start_time("/proc/self/stat");
        exec_report("leader", &[format!("pid={pid}"), format!("start={start}"), "ran".into()]);
    });
}

fn other_execs() {
    case("a thread that is not the leader execs", || {
        park_threads();
        let pid = getpid();
        let (ppid, pgid, sid) = unsafe { (libc::getppid(), libc::getpgid(0), libc::getsid(0)) };
        let start = start_time("/proc/self/stat");
        let t = std::thread::spawn(move || {
            let tid = gettid();
            let tstart = start_time(&format!("/proc/self/task/{tid}/stat"));
            exec_report(
                "other",
                &[
                    format!("pid={pid}"),
                    format!("oldtid={tid}"),
                    format!("ppid={ppid}"),
                    format!("pgid={pgid}"),
                    format!("sid={sid}"),
                    format!("start={start}"),
                    format!("tstart={tstart}"),
                    "ran".into(),
                ],
            );
        });
        // The leader is parked in a join, which is a futex wait.
        let _ = t.join();
    });
}

fn what_survives() {
    case("what a thread's exec keeps", || {
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) };
        mask(libc::SIG_BLOCK, &[USR1, WINCH]);
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, USR1 as libc::c_ulong) };
        unsafe { libc::kill(getpid(), USR1) };
        tgkill(gettid(), WINCH);
        let keep = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        let cloexec = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        let mut sev: libc::sigevent = unsafe { std::mem::zeroed() };
        sev.sigev_notify = libc::SIGEV_NONE;
        let mut id: c_int = -1;
        unsafe { libc::syscall(libc::SYS_timer_create, libc::CLOCK_MONOTONIC, &mut sev, &mut id) };
        let its = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: 100, tv_nsec: 0 },
        };
        unsafe { libc::syscall(libc::SYS_timer_settime, id as c_long, 0, &its, std::ptr::null_mut::<libc::itimerspec>()) };
        let it = libc::itimerval {
            it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
            it_value: libc::timeval { tv_sec: 100, tv_usec: 0 },
        };
        unsafe { libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()) };
        let t = std::thread::spawn(move || {
            mask(libc::SIG_SETMASK, &[USR1, USR2]);
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, USR2 as libc::c_ulong) };
            tgkill(gettid(), USR2);
            exec_report(
                "keeps",
                &[
                    "signals".into(),
                    format!("fd_keep={keep}"),
                    format!("fd_cloexec={cloexec}"),
                    format!("timer={id}"),
                    "itimer".into(),
                    "prctl".into(),
                ],
            );
        });
        let _ = t.join();
    });
}

static GOT: AtomicU64 = AtomicU64::new(0);

extern "C" fn note(sig: c_int) {
    GOT.fetch_or(1 << sig, Ordering::SeqCst);
}

fn exit_signal() {
    for (name, threaded) in [
        ("a clone child with exit signal SIGUSR1: a thread execs", true),
        ("a clone child with exit signal SIGUSR1: the leader execs", false),
    ] {
        line(name, "");
        let (out, waits, _) = in_child(move || {
            unsafe {
                libc::signal(libc::SIGCHLD, note as *const () as libc::sighandler_t);
                libc::signal(USR1, note as *const () as libc::sighandler_t);
            }
            let child = unsafe { libc::syscall(libc::SYS_clone, USR1 as c_long, 0, 0, 0, 0) } as i32;
            if child == 0 {
                if threaded {
                    let t = std::thread::spawn(|| {
                        exec_report("exitsig", &[]);
                    });
                    let _ = t.join();
                } else {
                    exec_report("exitsig", &[]);
                }
                unsafe { libc::_exit(99) };
            }
            let mut st = 0;
            let r = unsafe { libc::waitpid(child, &mut st, libc::__WALL) };
            std::thread::sleep(Duration::from_millis(100));
            let got = GOT.load(Ordering::SeqCst);
            let names: Vec<&str> = [(libc::SIGCHLD, "SIGCHLD"), (USR1, "SIGUSR1")]
                .iter()
                .filter(|(s, _)| got & (1 << s) != 0)
                .map(|&(_, n)| n)
                .collect();
            line("  exitsig: waitpid(__WALL)", if r == child { describe(st) } else { format!("errno {}", errno()) });
            line("  exitsig: the signal the parent got", format!("{names:?}"));
        });
        print!("{out}");
        line("  exitsig: the outer wait events", waits);
    }
}

fn two_exec() {
    line("two threads exec at once", "");
    let (out, waits, _) = in_child(|| {
        let b = Arc::new(Barrier::new(2));
        let mut hs = Vec::new();
        for _ in 0..2 {
            let b = Arc::clone(&b);
            hs.push(std::thread::spawn(move || {
                b.wait();
                exec_report("two", &["ran".into()]);
            }));
        }
        for h in hs {
            let _ = h.join();
        }
    });
    let ran = out.lines().filter(|l| l.contains("the new program ran")).count();
    line("  two: programs that ran", ran);
    line("  two: the parent's wait events", waits);
}

fn exit_group_races_exec() {
    line("one thread calls exit_group(7) while another execs", "");
    let mut verdicts = std::collections::BTreeSet::new();
    for _ in 0..20 {
        let (out, waits, _) = in_child(|| {
            let b = Arc::new(Barrier::new(2));
            let b2 = Arc::clone(&b);
            std::thread::spawn(move || {
                b2.wait();
                exec_report("race", &["ran".into()]);
            });
            b.wait();
            unsafe { libc::syscall(libc::SYS_exit_group, 7) };
        });
        let ran = out.contains("the new program ran");
        let v = match (ran, waits.as_str()) {
            (true, "the child exited 0, then errno 10") => "the exec won",
            (false, "the child exited 7, then errno 10") => "exit_group won",
            _ => "inconsistent",
        };
        verdicts.insert(if v == "inconsistent" { format!("inconsistent: ran={ran} {waits}") } else { v.to_string() });
    }
    // Which one wins is a race; only a mixture of the two is wrong.
    let bad: Vec<_> = verdicts.iter().filter(|v| v.starts_with("inconsistent")).collect();
    line("  race: 20 rounds", if bad.is_empty() { "each round one or the other".to_string() } else { format!("{bad:?}") });
}

fn failed_exec() {
    case("a thread's exec fails before the point of no return", || {
        let mut ping = [0; 2];
        let mut pong = [0; 2];
        unsafe {
            libc::pipe(ping.as_mut_ptr());
            libc::pipe(pong.as_mut_ptr());
        }
        let (r, w) = (ping[0], pong[1]);
        std::thread::spawn(move || {
            let mut b = [0u8; 1];
            loop {
                if unsafe { libc::read(r, b.as_mut_ptr().cast(), 1) } != 1 {
                    return;
                }
                unsafe { libc::write(w, b.as_ptr().cast(), 1) };
            }
        });
        std::thread::spawn(|| std::thread::sleep(Duration::from_secs(60)));
        std::thread::sleep(Duration::from_millis(100));
        let dir = format!("/tmp/execthreads_probe.{}", getpid());
        let _ = std::fs::create_dir(&dir);
        let noexec = format!("{dir}/noexec");
        let garbage = format!("{dir}/garbage");
        std::fs::write(&noexec, b"#!/bin/sh\n").unwrap();
        std::fs::write(&garbage, b"this is not a program\n").unwrap();
        unsafe {
            libc::chmod(CString::new(noexec.as_str()).unwrap().as_ptr(), 0o644);
            libc::chmod(CString::new(garbage.as_str()).unwrap().as_ptr(), 0o755);
        }
        for (what, path) in [("a path that does not exist", format!("{dir}/none")), ("a file with no execute bit", noexec), ("a file that is no format", garbage)] {
            let t = std::thread::spawn(move || exec_path(&path, "fail", &[]));
            let e = t.join().unwrap();
            let n = task_entries().len();
            unsafe { libc::write(ping[1], b"x".as_ptr().cast(), 1) };
            let alive = wait_byte(pong[0], 2000);
            line(
                &format!("  fail: {what}"),
                format!("errno {e}, {n} threads after, a parked one {}", if alive { "answers" } else { "is gone" }),
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    });
}

/// `struct robust_list_head` and one lock entry, by hand, so the probe owns
/// the lists musl would otherwise manage.
#[repr(C)]
struct RobustHead {
    next: *mut c_void,
    futex_offset: c_long,
    pending: *mut c_void,
}

fn robust_and_clear_tid() {
    line("a killed thread's robust list and clear_child_tid", "");
    // Shared with the parent, which reads it after the child's exec.
    let page = unsafe {
        libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1, 0)
    } as *mut u8;
    let word = |off: usize| unsafe { &*(page.add(off) as *const std::sync::atomic::AtomicU32) };
    let (_, waits, _) = in_child(move || {
        let page = page as usize;
        let register = move |entry_off: usize, lock_off: usize, ctid_off: usize| {
            let page = page as *mut u8;
            let tid = gettid() as u32;
            unsafe {
                let entry = page.add(entry_off) as *mut *mut c_void;
                let head = Box::leak(Box::new(RobustHead {
                    next: entry.cast(),
                    futex_offset: (lock_off - entry_off) as c_long,
                    pending: std::ptr::null_mut(),
                }));
                *entry = (head as *mut RobustHead).cast();
                (*(page.add(lock_off) as *const std::sync::atomic::AtomicU32)).store(tid, Ordering::SeqCst);
                (*(page.add(ctid_off) as *const std::sync::atomic::AtomicU32)).store(tid, Ordering::SeqCst);
                // The tid itself, for the parent to compare the words with.
                (*(page.add(ctid_off + 4) as *const std::sync::atomic::AtomicU32)).store(tid, Ordering::SeqCst);
                libc::syscall(libc::SYS_set_robust_list, head as *mut RobustHead, std::mem::size_of::<RobustHead>());
                libc::syscall(libc::SYS_set_tid_address, page.add(ctid_off));
            }
        };
        // The leader's, at 0..; the exec'ing thread's, at 256...
        register(0, 64, 128);
        let t = std::thread::spawn(move || {
            register(256, 320, 384);
            exec_report("robust", &[]);
        });
        let _ = t.join();
    });
    // Against the tid the thread had, which the parent cannot know otherwise.
    let what = |v: u32, tid: u32| match v {
        0 => "0".to_string(),
        v if v == tid => "its tid, unchanged".to_string(),
        0x4000_0000 => "FUTEX_OWNER_DIED, the tid cleared".to_string(),
        v if v == tid | 0x4000_0000 => "FUTEX_OWNER_DIED, the tid kept".to_string(),
        v => format!("{v:#x}"),
    };
    let (lead, own) = (word(132).load(Ordering::SeqCst), word(388).load(Ordering::SeqCst));
    line("  robust: the killed leader's robust lock", what(word(64).load(Ordering::SeqCst), lead));
    line("  robust: the killed leader's clear_child_tid word", what(word(128).load(Ordering::SeqCst), lead));
    line("  robust: the exec'ing thread's robust lock", what(word(320).load(Ordering::SeqCst), own));
    line("  robust: the exec'ing thread's clear_child_tid word", what(word(384).load(Ordering::SeqCst), own));
    line("  robust: the parent's wait events", waits);
}

/// A thread made with the raw `clone`, which runs this on its own stack.
extern "C" fn raw_exec(arg: *mut c_void) -> c_int {
    let argv = arg as *const *const libc::c_char;
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    let e = unsafe { libc::syscall(libc::SYS_execve, *argv, argv, envp.as_ptr()) };
    let msg = [b'e', b'x', b'e', b'c', b' ', b'0' + (-e / 10) as u8, b'0' + (-e % 10) as u8, b'\n'];
    unsafe { libc::syscall(libc::SYS_write, 1, msg.as_ptr(), msg.len()) };
    unsafe { libc::syscall(libc::SYS_exit, 1) };
    0
}

const RAW_THREAD: c_int = libc::CLONE_VM | libc::CLONE_FS | libc::CLONE_FILES | libc::CLONE_SIGHAND | libc::CLONE_THREAD | libc::CLONE_SYSVSEM;

/// `clone(2)` onto a stack of its own, running `f(arg)` and then `exit`.
///
/// musl's `clone()` refuses `CLONE_THREAD` (1.2.5), and a thread made
/// without `pthread_create` is the point: it touches no libc state.
///
/// # Safety
/// `stack` is the top of a mapping `f` may use; `f` uses no TLS.
unsafe fn raw_clone(flags: c_int, stack: *mut c_void, f: extern "C" fn(*mut c_void) -> c_int, arg: *mut c_void) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "stp x11, x12, [x10, #-16]!",
            "mov x1, x10",
            "mov x8, #220",
            "svc #0",
            "cbnz x0, 2f",
            "ldp x9, x0, [sp], #16",
            "blr x9",
            "mov x8, #93",
            "svc #0",
            "2:",
            inout("x10") stack => _,
            in("x11") f,
            in("x12") arg,
            inout("x0") flags as i64 => ret,
            out("x1") _,
            in("x2") 0u64,
            in("x3") 0u64,
            in("x4") 0u64,
            out("x8") _,
            out("x9") _,
            clobber_abi("C"),
        );
    }
    ret
}

fn stack() -> *mut c_void {
    let size = 256 * 1024;
    let s = unsafe {
        libc::mmap(std::ptr::null_mut(), size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    } as *mut u8;
    unsafe { s.add(size).cast() }
}

fn vfork_released() {
    case("vfork, then a thread of the child execs", || {
        let path = CString::new("/proc/self/exe").unwrap();
        let (_owned, mut argv) = exec_argv("vfork", &["ran".into()]);
        argv[0] = path.as_ptr();
        let sp = stack();
        #[allow(deprecated)]
        let child = unsafe { libc::vfork() };
        if child == 0 {
            unsafe {
                if raw_clone(RAW_THREAD, sp, raw_exec, argv.as_ptr() as *mut c_void) < 0 {
                    libc::syscall(libc::SYS_exit_group, *libc::__errno_location());
                }
                libc::syscall(libc::SYS_ppoll, std::ptr::null::<libc::pollfd>(), 0, std::ptr::null::<libc::timespec>(), std::ptr::null::<libc::sigset_t>());
                libc::syscall(libc::SYS_exit_group, 98);
            }
        }
        // Printed after the wait, so the report's lines come first whichever
        // order the two would otherwise race in.
        let mut st = 0;
        unsafe { libc::waitpid(child, &mut st, 0) };
        line("  vfork: the parent was released", "yes");
        line("  vfork: the child", describe(st));
    });
}

extern "C" fn clone_vm_sibling(arg: *mut c_void) -> c_int {
    let fds = arg as *const c_int;
    let mut b = [0u8; 1];
    unsafe {
        if libc::syscall(libc::SYS_read, *fds, b.as_mut_ptr(), 1) == 1 {
            libc::syscall(libc::SYS_write, *fds.add(1), b.as_ptr(), 1);
        }
        libc::syscall(libc::SYS_exit, 5);
    }
    0
}

fn clone_vm_untouched() {
    case("a CLONE_VM process sharing the old address space", || {
        let mut go = [0; 2];
        let mut back = [0; 2];
        unsafe {
            libc::pipe(go.as_mut_ptr());
            libc::pipe(back.as_mut_ptr());
        }
        let fds = Box::leak(Box::new([go[0], back[1]]));
        unsafe { raw_clone(libc::CLONE_VM | libc::SIGCHLD, stack(), clone_vm_sibling, fds.as_mut_ptr().cast()) };
        let t = std::thread::spawn(move || {
            exec_report("clonevm", &[format!("go={}", go[1]), format!("back={}", back[0])]);
        });
        let _ = t.join();
    });
}

fn files_unshared() {
    case("a files table shared by CLONE_FILES with another process", || {
        let mut ask = [0; 2];
        unsafe { libc::pipe(ask.as_mut_ptr()) };
        let sibling = unsafe { libc::syscall(libc::SYS_clone, (libc::CLONE_FILES | libc::SIGCHLD) as c_long, 0, 0, 0, 0) } as i32;
        if sibling == 0 {
            // After the other process has execed and opened something, ask
            // whether that descriptor is in the table this one still has.
            let mut b = [0u8; 16];
            let n = read_timeout(ask[0], &mut b, 5000);
            let fd: c_int = String::from_utf8_lossy(&b[..n]).trim().parse().unwrap_or(-1);
            let r = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            line("  files: the sibling sees the new program's new descriptor", if r < 0 { format!("no, errno {}", errno()) } else { "yes".into() });
            unsafe { libc::_exit(0) };
        }
        let t = std::thread::spawn(move || {
            exec_report("files", &[format!("ask={}", ask[1])]);
        });
        let _ = t.join();
    });
}

fn pdeath_of_leaders_child() {
    case("the old leader's child, with PR_SET_PDEATHSIG", || {
        let mut tell = [0; 2];
        let mut ready = [0; 2];
        unsafe {
            libc::pipe(tell.as_mut_ptr());
            libc::pipe(ready.as_mut_ptr());
        }
        let child = unsafe { libc::fork() };
        if child == 0 {
            unsafe {
                libc::signal(USR1, note as *const () as libc::sighandler_t);
                libc::prctl(libc::PR_SET_PDEATHSIG, USR1 as libc::c_ulong);
                libc::write(ready[1], b"x".as_ptr().cast(), 1);
            }
            let parent = unsafe { libc::getppid() };
            for _ in 0..500 {
                if GOT.load(Ordering::SeqCst) & (1 << USR1) != 0 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let got = GOT.load(Ordering::SeqCst) & (1 << USR1) != 0;
            let ppid = unsafe { libc::getppid() };
            let msg = format!("{}, getppid {}", if got { "got SIGUSR1" } else { "no signal" }, rel(ppid, parent));
            unsafe { libc::write(tell[1], msg.as_ptr().cast(), msg.len()) };
            unsafe { libc::_exit(0) };
        }
        // Not before the child has asked for the signal.
        wait_byte(ready[0], 5000);
        let t = std::thread::spawn(move || {
            exec_report("pdeath", &[format!("pdeath={}", tell[0])]);
        });
        let _ = t.join();
    });
}

fn pidfd_kept() {
    line("a pidfd taken before a thread execs", "");
    let mut hold = [0; 2];
    unsafe { libc::pipe(hold.as_mut_ptr()) };
    let mut ready = [0; 2];
    unsafe { libc::pipe(ready.as_mut_ptr()) };
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::alarm(20) };
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            exec_report("pidfd", &[format!("hold={}", hold[0]), format!("ready={}", ready[1])]);
        });
        let _ = t.join();
        unsafe { libc::_exit(97) };
    }
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) } as c_int;
    // Until the new program has printed its lines and is waiting: what is
    // asked of the pidfd is about a process that has exec'd.
    wait_byte(ready[0], 10_000);
    let r = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd, 0, std::ptr::null::<libc::siginfo_t>(), 0) };
    line("  pidfd: pidfd_send_signal(0) after the exec", if r == 0 { "0".to_string() } else { format!("errno {}", errno()) });
    let mut pfd = libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 };
    let n = unsafe { libc::poll(&mut pfd, 1, 0) };
    line("  pidfd: readable while the new program runs", if n == 1 { "yes" } else { "no" });
    unsafe { libc::write(hold[1], b"x".as_ptr().cast(), 1) };
    let n = unsafe { libc::poll(&mut pfd, 1, 5000) };
    line("  pidfd: readable once it exits", if n == 1 { "yes" } else { "no" });
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::waitid(libc::P_PIDFD, pidfd as libc::id_t, &mut info, libc::WEXITED) };
    let status = unsafe { info.si_status() };
    line("  pidfd: waitid(P_PIDFD)", if r == 0 { format!("si_pid {} si_status {status}", rel(unsafe { info.si_pid() }, child)) } else { format!("errno {}", errno()) });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("report") {
        let case = args.get(2).cloned().unwrap_or_default();
        report(&case, &args[3..]);
        if let Some(fd) = kv(&args[3..], "ask") {
            // The files case: open something, and tell the sibling its number.
            // Above anything either table had open, so the number names
            // only this descriptor.
            let fd2 = unsafe { libc::fcntl(libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY), libc::F_DUPFD, 200) };
            let msg = format!("{fd2}\n");
            unsafe { libc::write(fd as c_int, msg.as_ptr().cast(), msg.len()) };
            let mut st = 0;
            unsafe { libc::waitpid(-1, &mut st, libc::__WALL) };
        }
        return;
    }
    let cases: [(&str, fn()); 13] = [
        ("leader", leader_execs),
        ("other", other_execs),
        ("keeps", what_survives),
        ("exitsig", exit_signal),
        ("two", two_exec),
        ("race", exit_group_races_exec),
        ("fail", failed_exec),
        ("robust", robust_and_clear_tid),
        ("vfork", vfork_released),
        ("clonevm", clone_vm_untouched),
        ("files", files_unshared),
        ("pdeath", pdeath_of_leaders_child),
        ("pidfd", pidfd_kept),
    ];
    // `only <name>` runs one case, for looking at it alone.
    let only = (args.get(1).map(String::as_str) == Some("only")).then(|| args.get(2).cloned().unwrap_or_default());
    for (name, f) in cases {
        if only.as_deref().is_none_or(|o| o == name) {
            f();
        }
    }
}
