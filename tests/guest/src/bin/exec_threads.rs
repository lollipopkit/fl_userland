//! `execve` from a process with more than one thread ends the others and,
//! from a thread that is not the leader, moves the pid to the exec'ing
//! thread: Linux's `de_thread`. The expected values are a real arm64
//! kernel's, from `execthreads_probe`.
//!
//!   exec_threads                 the checks
//!   exec_threads --stress <n>    n rounds of an exec ending threads parked in
//!                                read, futex, nanosleep, epoll_wait and accept
//!                                and one spinning, alternating leader and not
//!
//! Every case runs in a child with an alarm, so an exec that never finishes
//! ending its threads fails the case instead of hanging the suite.

use std::collections::HashMap;
use std::ffi::{CString, c_int, c_long, c_void};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use guest_tests::{Harness, check};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn gettid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

fn getpid() -> i32 {
    unsafe { libc::getpid() }
}

fn status_field(key: &str) -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim().to_string()))
        .unwrap_or_default()
}

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

fn mask(how: c_int, sigs: &[c_int]) {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    for &s in sigs {
        unsafe { libc::sigaddset(&mut set, s) };
    }
    unsafe { libc::pthread_sigmask(how, &set, std::ptr::null_mut()) };
}

// ---------------------------------------------------------------------------
// The new program: what it finds, as key=value lines
// ---------------------------------------------------------------------------

fn report(args: &[String]) {
    let pid = getpid();
    let mut out = vec![
        format!("pid={pid}"),
        format!("tid={}", gettid()),
        format!("tasks={:?}", task_entries()),
        format!("threads={}", status_field("Threads:")),
        format!("ppid={}", unsafe { libc::getppid() }),
        format!("pgid={}", unsafe { libc::getpgid(0) }),
        format!("sid={}", unsafe { libc::getsid(0) }),
        format!("start={}", start_time("/proc/self/stat")),
        format!("sigblk={}", status_field("SigBlk:")),
        format!("sigpnd={}", status_field("SigPnd:")),
        format!("shdpnd={}", status_field("ShdPnd:")),
    ];
    for a in args {
        if let Some(t) = a.strip_prefix("oldtid=") {
            out.push(format!("oldtid_exists={}", std::path::Path::new(&format!("/proc/{t}")).exists()));
        }
        if let Some(fd) = a.strip_prefix("fd=") {
            let fd: c_int = fd.parse().unwrap();
            out.push(format!("fd{fd}_open={}", unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0));
        }
        if let Some(id) = a.strip_prefix("timer=") {
            let mut its: libc::itimerspec = unsafe { std::mem::zeroed() };
            let r = unsafe { libc::syscall(libc::SYS_timer_gettime, id.parse::<c_long>().unwrap(), &mut its) };
            out.push(format!("timer_errno={}", if r < 0 { errno() } else { 0 }));
        }
        if a == "itimer" {
            let mut it: libc::itimerval = unsafe { std::mem::zeroed() };
            unsafe { libc::getitimer(libc::ITIMER_REAL, &mut it) };
            out.push(format!("itimer_armed={}", it.it_value.tv_sec > 0));
            let zero: libc::itimerval = unsafe { std::mem::zeroed() };
            unsafe { libc::setitimer(libc::ITIMER_REAL, &zero, std::ptr::null_mut()) };
        }
        if a == "prctl" {
            let (mut sub, mut pd): (c_int, c_int) = (0, 0);
            unsafe {
                libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut sub as *mut c_int);
                libc::prctl(libc::PR_GET_PDEATHSIG, &mut pd as *mut c_int);
            }
            out.push(format!("subreaper={sub}"));
            out.push(format!("pdeathsig={pd}"));
        }
        if let Some(fd) = a.strip_prefix("relay=") {
            // Whatever the old leader's child wrote, passed on.
            let mut buf = [0u8; 64];
            let n = read_timeout(fd.parse().unwrap(), &mut buf, 8000);
            out.push(format!("relay={}", String::from_utf8_lossy(&buf[..n]).trim()));
            let mut st = 0;
            unsafe { libc::waitpid(-1, &mut st, libc::__WALL) };
        }
        if let Some(fd) = a.strip_prefix("go=") {
            unsafe { libc::write(fd.parse().unwrap(), b"x".as_ptr().cast(), 1) };
        }
        if let Some(fd) = a.strip_prefix("back=") {
            let mut b = [0u8; 1];
            let answered = read_timeout(fd.parse().unwrap(), &mut b, 3000) == 1;
            out.push(format!("sibling={}", if answered { "answered" } else { "silent" }));
            let mut st = 0;
            unsafe { libc::waitpid(-1, &mut st, libc::__WALL) };
            out.push(format!("sibling_status={}", if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 }));
        }
        if let Some(fd) = a.strip_prefix("ask=") {
            // A descriptor above anything either table had, for the CLONE_FILES
            // sibling to look for.
            let n = unsafe { libc::fcntl(libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY), libc::F_DUPFD, 200) };
            let msg = format!("{n}\n");
            unsafe { libc::write(fd.parse().unwrap(), msg.as_ptr().cast(), msg.len()) };
            let mut st = 0;
            unsafe { libc::waitpid(-1, &mut st, libc::__WALL) };
            out.push(format!("sibling_status={}", if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 }));
        }
    }
    let mut stdout = std::io::stdout();
    let _ = writeln!(stdout, "{}", out.join("\n"));
    let _ = stdout.flush();
}

fn read_timeout(fd: c_int, buf: &mut [u8], ms: c_int) -> usize {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    if unsafe { libc::poll(&mut pfd, 1, ms) } != 1 {
        return 0;
    }
    unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) }.max(0) as usize
}

fn exec_report(extra: &[String]) -> i32 {
    exec_path("/proc/self/exe", extra)
}

fn exec_path(path: &str, extra: &[String]) -> i32 {
    let me = CString::new(path).unwrap();
    let mut owned = vec![CString::new("exec_threads").unwrap(), CString::new("--report").unwrap()];
    owned.extend(extra.iter().map(|s| CString::new(s.as_str()).unwrap()));
    let mut argv: Vec<*const libc::c_char> = owned.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    let _ = std::io::stdout().flush();
    unsafe { libc::execve(me.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    errno()
}

// ---------------------------------------------------------------------------
// The old program
// ---------------------------------------------------------------------------

/// What a case's child printed, its pid, and the wait events for that pid.
struct Ran {
    facts: HashMap<String, String>,
    out: String,
    pid: i32,
    waits: Vec<String>,
}

impl Ran {
    fn get(&self, k: &str) -> &str {
        self.facts.get(k).map_or("", String::as_str)
    }
    fn num(&self, k: &str) -> i64 {
        self.get(k).parse().unwrap_or(-1)
    }
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

/// Run `f` in a child whose stdout is collected; the child's own lines and
/// the new program's both land there.
fn in_child(f: impl FnOnce()) -> Ran {
    let mut fds = [0; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let _ = std::io::stdout().flush();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(fds[0]);
            libc::dup2(fds[1], 1);
            libc::close(fds[1]);
            libc::alarm(20);
        }
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(fds[1]) };
    let mut waits = Vec::new();
    loop {
        let mut st = 0;
        if unsafe { libc::waitpid(pid, &mut st, libc::__WALL) } < 0 {
            break;
        }
        waits.push(describe(st));
    }
    let mut out = String::new();
    unsafe { libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK) };
    let mut file = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fds[0]) };
    let _ = file.read_to_string(&mut out);
    let facts = out.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
    Ran { facts, out, pid, waits }
}

/// Threads parked in the calls an exec has to end, and one spinning.
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
        unsafe { libc::syscall(libc::SYS_futex, &WORD as *const u32, libc::FUTEX_WAIT, 0, std::ptr::null::<libc::timespec>()) };
    });
    std::thread::spawn(|| unsafe {
        let ep = libc::epoll_create1(0);
        let mut ev: libc::epoll_event = std::mem::zeroed();
        libc::epoll_wait(ep, &mut ev, 1, -1);
    });
    std::thread::spawn(|| unsafe {
        let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let mut a: libc::sockaddr_un = std::mem::zeroed();
        a.sun_family = libc::AF_UNIX as _;
        // Abstract, so nothing is left in the filesystem.
        let name = format!("exec_threads.{}.{}", getpid(), gettid());
        for (i, b) in name.bytes().enumerate() {
            a.sun_path[i + 1] = b as libc::c_char;
        }
        let len = (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()) as libc::socklen_t;
        libc::bind(s, (&a as *const libc::sockaddr_un).cast(), len);
        libc::listen(s, 1);
        libc::accept(s, std::ptr::null_mut(), std::ptr::null_mut());
    });
    std::thread::spawn(|| {
        static SPIN: AtomicU64 = AtomicU64::new(0);
        loop {
            SPIN.fetch_add(1, Ordering::Relaxed);
        }
    });
}

fn one_thread_left(h: &mut Harness, r: &Ran, what: &str) {
    check!(h, r.num("pid") == r.pid as i64, "{what}: the pid is the one the parent forked ({} vs {})", r.get("pid"), r.pid);
    check!(h, r.get("tid") == r.get("pid"), "{what}: gettid is getpid ({} vs {})", r.get("tid"), r.get("pid"));
    check!(h, r.get("tasks") == format!("[{}]", r.pid), "{what}: /proc/self/task is the pid alone: {}", r.get("tasks"));
    check!(h, r.get("threads") == "1", "{what}: Threads: {}", r.get("threads"));
    check!(h, r.waits == ["exited 0"], "{what}: the parent sees one exit for the pid: {:?}", r.waits);
}

fn leader_execs(h: &mut Harness) {
    h.group("leader execs");
    let r = in_child(|| {
        park_threads();
        std::thread::sleep(Duration::from_millis(200));
        exec_report(&[]);
    });
    one_thread_left(h, &r, "leader");
}

fn other_execs(h: &mut Harness) {
    h.group("a thread execs");
    let r = in_child(|| {
        park_threads();
        let (ppid, pgid, sid) = unsafe { (libc::getppid(), libc::getpgid(0), libc::getsid(0)) };
        let start = start_time("/proc/self/stat");
        // Late enough that the thread's own start time differs from the
        // process's.
        std::thread::sleep(Duration::from_millis(200));
        let t = std::thread::spawn(move || {
            println!("before_ppid={ppid}\nbefore_pgid={pgid}\nbefore_sid={sid}\nbefore_start={start}");
            let tid = gettid();
            println!("thread_start={}", start_time(&format!("/proc/self/task/{tid}/stat")));
            exec_report(&[format!("oldtid={tid}")]);
        });
        let _ = t.join();
    });
    one_thread_left(h, &r, "non-leader");
    check!(h, r.get("oldtid_exists") == "false", "/proc/<old tid> is gone: {}", r.get("oldtid_exists"));
    for k in ["ppid", "pgid", "sid"] {
        check!(h, r.get(k) == r.get(&format!("before_{k}")), "{k} kept: {} vs {}", r.get(k), r.get(&format!("before_{k}")));
    }
    check!(
        h,
        r.get("start") == r.get("before_start") && r.get("start") != r.get("thread_start"),
        "the start time is the old leader's: {} (leader {}, thread {})",
        r.get("start"),
        r.get("before_start"),
        r.get("thread_start")
    );
}

fn what_survives(h: &mut Harness) {
    h.group("what survives");
    let r = in_child(|| {
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) };
        mask(libc::SIG_BLOCK, &[libc::SIGUSR1, libc::SIGWINCH]);
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGUSR1 as libc::c_ulong) };
        unsafe { libc::kill(getpid(), libc::SIGUSR1) };
        unsafe { libc::syscall(libc::SYS_tgkill, getpid(), gettid(), libc::SIGWINCH) };
        let keep = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        let cloexec = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        let mut sev: libc::sigevent = unsafe { std::mem::zeroed() };
        sev.sigev_notify = libc::SIGEV_NONE;
        let mut id: c_int = -1;
        unsafe { libc::syscall(libc::SYS_timer_create, libc::CLOCK_MONOTONIC, &mut sev, &mut id) };
        let it = libc::itimerval {
            it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
            it_value: libc::timeval { tv_sec: 100, tv_usec: 0 },
        };
        unsafe { libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()) };
        let t = std::thread::spawn(move || {
            mask(libc::SIG_SETMASK, &[libc::SIGUSR1, libc::SIGUSR2]);
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGUSR2 as libc::c_ulong) };
            unsafe { libc::syscall(libc::SYS_tgkill, getpid(), gettid(), libc::SIGUSR2) };
            exec_report(&[format!("fd={keep}"), format!("fd={cloexec}"), format!("timer={id}"), "itimer".into(), "prctl".into()]);
        });
        let _ = t.join();
    });
    one_thread_left(h, &r, "keeps");
    // SIGUSR1 is 10 and SIGUSR2 12: the exec'ing thread's mask and its own
    // pending signal, the process's pending one, and not the leader's.
    check!(h, r.get("sigblk") == "0000000000000a00", "the exec'ing thread's mask: {}", r.get("sigblk"));
    check!(h, r.get("sigpnd") == "0000000000000800", "its own pending signal, not the leader's: {}", r.get("sigpnd"));
    check!(h, r.get("shdpnd") == "0000000000000200", "the process's pending signal: {}", r.get("shdpnd"));
    // The report prints the two in the order they were passed.
    let opens: Vec<_> = r.out.lines().filter(|l| l.starts_with("fd") && l.contains("_open=")).collect();
    check!(h, opens.len() == 2 && opens[0].ends_with("=true") && opens[1].ends_with("=false"), "O_CLOEXEC closed, the other kept: {opens:?}");
    check!(h, r.get("timer_errno") == "22", "a POSIX timer is gone: errno {}", r.get("timer_errno"));
    check!(h, r.get("itimer_armed") == "true", "ITIMER_REAL survives");
    check!(h, r.get("subreaper") == "1", "PR_SET_CHILD_SUBREAPER survives: {}", r.get("subreaper"));
    check!(h, r.get("pdeathsig") == "12", "the exec'ing thread's own PR_SET_PDEATHSIG: {}", r.get("pdeathsig"));
}

static GOT: AtomicU64 = AtomicU64::new(0);

extern "C" fn note(sig: c_int) {
    GOT.fetch_or(1 << sig, Ordering::SeqCst);
}

fn exit_signal(h: &mut Harness) {
    h.group("exit signal");
    for threaded in [true, false] {
        let r = in_child(move || {
            unsafe {
                libc::signal(libc::SIGCHLD, note as *const () as libc::sighandler_t);
                libc::signal(libc::SIGUSR1, note as *const () as libc::sighandler_t);
            }
            let child = unsafe { libc::syscall(libc::SYS_clone, libc::SIGUSR1 as c_long, 0, 0, 0, 0) } as i32;
            if child == 0 {
                if threaded {
                    let _ = std::thread::spawn(|| exec_report(&[])).join();
                } else {
                    exec_report(&[]);
                }
                unsafe { libc::_exit(99) };
            }
            let mut st = 0;
            unsafe { libc::waitpid(child, &mut st, libc::__WALL) };
            std::thread::sleep(Duration::from_millis(100));
            println!("got={:#x}\nchild_status={}", GOT.load(Ordering::SeqCst), describe(st));
        });
        let want = format!("{:#x}", 1u64 << libc::SIGCHLD);
        check!(h, r.get("got") == want, "clone(SIGUSR1) then exec (from a thread: {threaded}): the parent gets SIGCHLD: {}", r.get("got"));
        check!(h, r.get("child_status") == "exited 0", "and the new program ran: {}", r.get("child_status"));
    }
}

fn two_exec(h: &mut Harness) {
    h.group("two execs at once");
    for round in 0..10 {
        let r = in_child(|| {
            let b = Arc::new(Barrier::new(2));
            let hs: Vec<_> = (0..2)
                .map(|_| {
                    let b = Arc::clone(&b);
                    std::thread::spawn(move || {
                        b.wait();
                        exec_report(&[]);
                    })
                })
                .collect();
            for t in hs {
                let _ = t.join();
            }
        });
        let ran = r.out.lines().filter(|l| l.starts_with("pid=")).count();
        check!(h, ran == 1, "round {round}: one of the two ran, {ran} did");
        check!(h, r.waits == ["exited 0"], "round {round}: one exit: {:?}", r.waits);
    }
}

fn exit_group_races_exec(h: &mut Harness) {
    h.group("exit_group against exec");
    for round in 0..20 {
        let r = in_child(|| {
            let b = Arc::new(Barrier::new(2));
            let b2 = Arc::clone(&b);
            std::thread::spawn(move || {
                b2.wait();
                exec_report(&[]);
            });
            b.wait();
            unsafe { libc::syscall(libc::SYS_exit_group, 7) };
        });
        let ran = r.out.contains("pid=");
        let ok = (ran && r.waits == ["exited 0"]) || (!ran && r.waits == ["exited 7"]);
        check!(h, ok, "round {round}: one or the other, not a mixture: ran={ran} {:?}", r.waits);
    }
}

fn failed_exec(h: &mut Harness) {
    h.group("a failed exec leaves the threads");
    let r = in_child(|| {
        let mut ping = [0; 2];
        let mut pong = [0; 2];
        unsafe {
            libc::pipe(ping.as_mut_ptr());
            libc::pipe(pong.as_mut_ptr());
        }
        let (rd, wr) = (ping[0], pong[1]);
        std::thread::spawn(move || {
            let mut b = [0u8; 1];
            while unsafe { libc::read(rd, b.as_mut_ptr().cast(), 1) } == 1 {
                unsafe { libc::write(wr, b.as_ptr().cast(), 1) };
            }
        });
        std::thread::sleep(Duration::from_millis(100));
        let dir = format!("/tmp/exec_threads.{}", getpid());
        let _ = std::fs::create_dir(&dir);
        let noexec = format!("{dir}/noexec");
        let garbage = format!("{dir}/garbage");
        std::fs::write(&noexec, b"#!/bin/sh\n").unwrap();
        std::fs::write(&garbage, b"not a program\n").unwrap();
        unsafe {
            libc::chmod(CString::new(noexec.as_str()).unwrap().as_ptr(), 0o644);
            libc::chmod(CString::new(garbage.as_str()).unwrap().as_ptr(), 0o755);
        }
        for (name, path) in [("enoent", format!("{dir}/none")), ("eacces", noexec), ("enoexec", garbage)] {
            let e = std::thread::spawn(move || exec_path(&path, &[])).join().unwrap();
            unsafe { libc::write(ping[1], b"x".as_ptr().cast(), 1) };
            let mut b = [0u8; 1];
            let alive = read_timeout(pong[0], &mut b, 2000) == 1;
            println!("{name}={e},{},{alive}", task_entries().len());
        }
        let _ = std::fs::remove_dir_all(&dir);
    });
    for (k, e) in [("enoent", 2), ("eacces", 13), ("enoexec", 8)] {
        check!(h, r.get(k) == format!("{e},2,true"), "{k}: errno, threads after, the parked one answers: {}", r.get(k));
    }
    check!(h, r.waits == ["exited 0"], "and the process exits on its own: {:?}", r.waits);
}

#[repr(C)]
struct RobustHead {
    next: *mut c_void,
    futex_offset: c_long,
    pending: *mut c_void,
}

fn robust_list(h: &mut Harness) {
    h.group("a killed thread's robust list");
    let page = unsafe {
        libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1, 0)
    } as usize;
    let word = |off: usize| unsafe { &*((page + off) as *const std::sync::atomic::AtomicU32) };
    let register = move |base: usize| {
        let tid = gettid() as u32;
        unsafe {
            let entry = (page + base) as *mut *mut c_void;
            let head = Box::leak(Box::new(RobustHead { next: entry.cast(), futex_offset: 64, pending: std::ptr::null_mut() }));
            *entry = (head as *mut RobustHead).cast();
            (*((page + base + 64) as *const std::sync::atomic::AtomicU32)).store(tid, Ordering::SeqCst);
            (*((page + base + 128) as *const std::sync::atomic::AtomicU32)).store(tid, Ordering::SeqCst);
            (*((page + base + 132) as *const std::sync::atomic::AtomicU32)).store(tid, Ordering::SeqCst);
            libc::syscall(libc::SYS_set_robust_list, head as *mut RobustHead, std::mem::size_of::<RobustHead>());
            libc::syscall(libc::SYS_set_tid_address, page + base + 128);
        }
    };
    let r = in_child(move || {
        register(0);
        let _ = std::thread::spawn(move || {
            register(256);
            exec_report(&[]);
        })
        .join();
    });
    check!(h, r.waits == ["exited 0"], "the exec ran: {:?}", r.waits);
    check!(h, word(64).load(Ordering::SeqCst) == 0x4000_0000, "the killed leader's lock: FUTEX_OWNER_DIED, tid cleared: {:#x}", word(64).load(Ordering::SeqCst));
    check!(h, word(128).load(Ordering::SeqCst) == 0, "the killed leader's clear_child_tid word is 0");
    let own = word(388).load(Ordering::SeqCst);
    // Linux walks the exec'ing thread's list with the pid it has taken, so a
    // lock holding its old tid is not its own any more and is left alone.
    check!(h, word(320).load(Ordering::SeqCst) == own, "the exec'ing thread's lock is left: {:#x}", word(320).load(Ordering::SeqCst));
    check!(h, word(384).load(Ordering::SeqCst) == own, "and its clear_child_tid word too");
}

/// `clone(2)` onto a stack of its own, running `f(arg)` and then `exit`;
/// musl's `clone()` refuses `CLONE_THREAD`.
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

extern "C" fn raw_exec(arg: *mut c_void) -> c_int {
    let argv = arg as *const *const libc::c_char;
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    unsafe { libc::syscall(libc::SYS_execve, *argv, argv, envp.as_ptr()) };
    unsafe { libc::syscall(libc::SYS_exit, 1) };
    0
}

const RAW_THREAD: c_int = libc::CLONE_VM | libc::CLONE_FS | libc::CLONE_FILES | libc::CLONE_SIGHAND | libc::CLONE_THREAD | libc::CLONE_SYSVSEM;

fn vfork_released(h: &mut Harness) {
    h.group("vfork");
    let r = in_child(|| {
        let path = CString::new("/proc/self/exe").unwrap();
        let a1 = CString::new("--report").unwrap();
        let argv = [path.as_ptr(), a1.as_ptr(), std::ptr::null()];
        let sp = stack();
        #[allow(deprecated)]
        let child = unsafe { libc::vfork() };
        if child == 0 {
            unsafe {
                if raw_clone(RAW_THREAD, sp, raw_exec, argv.as_ptr() as *mut c_void) < 0 {
                    libc::syscall(libc::SYS_exit_group, 96);
                }
                libc::syscall(libc::SYS_ppoll, std::ptr::null::<libc::pollfd>(), 0, std::ptr::null::<libc::timespec>(), std::ptr::null::<libc::sigset_t>());
                libc::syscall(libc::SYS_exit_group, 98);
            }
        }
        let mut st = 0;
        unsafe { libc::waitpid(child, &mut st, 0) };
        println!("vfork_child={}", describe(st));
    });
    check!(h, r.get("vfork_child") == "exited 0", "the vfork parent was released and the child ran: {}", r.get("vfork_child"));
    check!(h, r.get("threads") == "1", "one thread in the child: {}", r.get("threads"));
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

fn clone_vm_untouched(h: &mut Harness) {
    h.group("a CLONE_VM process");
    let r = in_child(|| {
        let mut go = [0; 2];
        let mut back = [0; 2];
        unsafe {
            libc::pipe(go.as_mut_ptr());
            libc::pipe(back.as_mut_ptr());
        }
        let fds = Box::leak(Box::new([go[0], back[1]]));
        unsafe { raw_clone(libc::CLONE_VM | libc::SIGCHLD, stack(), clone_vm_sibling, fds.as_mut_ptr().cast()) };
        let _ = std::thread::spawn(move || exec_report(&[format!("go={}", go[1]), format!("back={}", back[0])])).join();
    });
    check!(h, r.get("threads") == "1", "the exec ran: {:?}", r.waits);
    check!(h, r.get("sibling") == "answered", "the process sharing the old space still runs: {}", r.get("sibling"));
    check!(h, r.get("sibling_status") == "5", "and is reaped by the new program: {}", r.get("sibling_status"));
}

fn files_unshared(h: &mut Harness) {
    h.group("CLONE_FILES with another process");
    let r = in_child(|| {
        let mut ask = [0; 2];
        unsafe { libc::pipe(ask.as_mut_ptr()) };
        let sibling = unsafe { libc::syscall(libc::SYS_clone, (libc::CLONE_FILES | libc::SIGCHLD) as c_long, 0, 0, 0, 0) } as i32;
        if sibling == 0 {
            let mut b = [0u8; 16];
            let n = read_timeout(ask[0], &mut b, 5000);
            let fd: c_int = String::from_utf8_lossy(&b[..n]).trim().parse().unwrap_or(-1);
            let seen = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
            unsafe { libc::_exit(if seen { 1 } else { 0 }) };
        }
        let _ = std::thread::spawn(move || exec_report(&[format!("ask={}", ask[1])])).join();
    });
    check!(h, r.get("sibling_status") == "0", "the sibling does not see the new program's descriptor: {}", r.get("sibling_status"));
}

fn pdeath_of_leaders_child(h: &mut Harness) {
    h.group("PR_SET_PDEATHSIG");
    let r = in_child(|| {
        let mut tell = [0; 2];
        let mut ready = [0; 2];
        unsafe {
            libc::pipe(tell.as_mut_ptr());
            libc::pipe(ready.as_mut_ptr());
        }
        if unsafe { libc::fork() } == 0 {
            unsafe {
                libc::signal(libc::SIGUSR1, note as *const () as libc::sighandler_t);
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGUSR1 as libc::c_ulong);
                libc::write(ready[1], b"x".as_ptr().cast(), 1);
            }
            let parent = unsafe { libc::getppid() };
            let deadline = Instant::now() + Duration::from_secs(5);
            while GOT.load(Ordering::SeqCst) & (1 << libc::SIGUSR1) == 0 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let got = GOT.load(Ordering::SeqCst) & (1 << libc::SIGUSR1) != 0;
            let msg = format!("{got},{}", unsafe { libc::getppid() } == parent);
            unsafe { libc::write(tell[1], msg.as_ptr().cast(), msg.len()) };
            unsafe { libc::_exit(0) };
        }
        // Not before the child has asked for the signal: under load, 100 ms
        // after the fork was not always enough, and the exec then ended a
        // leader whose child had not asked yet.
        let mut b = [0u8; 1];
        read_timeout(ready[0], &mut b, 5000);
        let _ = std::thread::spawn(move || exec_report(&[format!("relay={}", tell[0])])).join();
    });
    check!(h, r.get("relay") == "true,true", "the old leader's child got its PDEATHSIG, and its parent is the same pid: {}", r.get("relay"));
}

fn pidfd_kept(h: &mut Harness) {
    h.group("pidfd");
    let mut hold = [0; 2];
    let mut started = [0; 2];
    unsafe {
        libc::pipe(hold.as_mut_ptr());
        libc::pipe(started.as_mut_ptr());
    }
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::alarm(20);
            libc::dup2(libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY), 1);
        }
        let _ = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            // The report says it has started, then blocks on `relay=` until
            // the parent writes.
            exec_report(&[format!("go={}", started[1]), format!("relay={}", hold[0])]);
        })
        .join();
        unsafe { libc::_exit(97) };
    }
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) } as c_int;
    check!(h, pidfd >= 0, "pidfd_open: errno {}", errno());
    let mut b = [0u8; 1];
    check!(h, read_timeout(started[0], &mut b, 10_000) == 1, "the new program has started");
    let r = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd, 0, std::ptr::null::<libc::siginfo_t>(), 0) };
    check!(h, r == 0, "pidfd_send_signal after the exec: errno {}", errno());
    let mut pfd = libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 };
    check!(h, unsafe { libc::poll(&mut pfd, 1, 0) } == 0, "not readable while the new program runs");
    unsafe { libc::write(hold[1], b"x".as_ptr().cast(), 1) };
    check!(h, unsafe { libc::poll(&mut pfd, 1, 5000) } == 1, "readable once it exits");
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::waitid(libc::P_PIDFD, pidfd as libc::id_t, &mut info, libc::WEXITED) };
    check!(h, r == 0 && unsafe { info.si_pid() } == child && unsafe { info.si_status() } == 0, "waitid(P_PIDFD) reaps it: {r} errno {}", errno());
}

// ---------------------------------------------------------------------------
// The stress
// ---------------------------------------------------------------------------

fn stress(rounds: u32) -> i32 {
    let started = Instant::now();
    let mut bad = 0;
    for round in 0..rounds {
        let from_leader = round % 2 == 0;
        let r = in_child(move || {
            park_threads();
            // Long enough for some threads to park, short enough that others
            // are still starting when the exec arrives.
            std::thread::sleep(Duration::from_millis((round % 5) as u64 * 5));
            if from_leader {
                exec_report(&[]);
            } else {
                let _ = std::thread::spawn(|| exec_report(&[])).join();
            }
        });
        let ok = r.waits == ["exited 0"] && r.get("threads") == "1" && r.num("pid") == r.pid as i64 && r.get("tid") == r.get("pid");
        if !ok {
            bad += 1;
            println!("  FAIL  round {round} (from the leader: {from_leader}): {:?} {:?}", r.waits, r.out.lines().take(4).collect::<Vec<_>>());
        }
    }
    let ms = started.elapsed().as_millis();
    println!("  stress: {rounds} rounds, {bad} failed, {ms} ms, {} ms per round", ms / u128::from(rounds.max(1)));
    i32::from(bad != 0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--report") => {
            report(&args[2..]);
            return;
        }
        Some("--stress") => {
            let n = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(200);
            std::process::exit(stress(n));
        }
        _ => {}
    }
    let mut h = Harness::new();
    leader_execs(&mut h);
    other_execs(&mut h);
    what_survives(&mut h);
    exit_signal(&mut h);
    two_exec(&mut h);
    exit_group_races_exec(&mut h);
    failed_exec(&mut h);
    robust_list(&mut h);
    vfork_released(&mut h);
    clone_vm_untouched(&mut h);
    files_unshared(&mut h);
    pdeath_of_leaders_child(&mut h);
    pidfd_kept(&mut h);
    std::process::exit(h.finish());
}
