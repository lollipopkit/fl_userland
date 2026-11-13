//! What `epoll_pwait2`, the epoll busy-poll ioctls and `EPOLLEXCLUSIVE`'s
//! wake-one rule answer.
//!
//! One line per case, nothing asserted: `probe_diff.sh` compares the lines
//! against a real kernel. Every wait is bounded, so a case that should time out
//! costs its timeout and no more.
//!
//! # Timing lines
//!
//! Elapsed times are printed as lower bounds only. An upper bound for a
//! sub-millisecond timeout is not a property of the kernel: the OrbStack
//! kernel these are compared against has ~3 ms timer granularity, and takes
//! 2.5-3.5 ms for a 300 us `epoll_pwait2` and for a 300 us `nanosleep` alike
//! (measured 2026-11-11). `epoll_pwait2_abi` checks the upper bound relative
//! to `nanosleep` instead.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

unsafe fn sys(n: i64, a: i64, b: i64, c: i64, d: i64, e: i64, f: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a => ret,
            in("x1") b, in("x2") c, in("x3") d, in("x4") e, in("x5") f,
            options(nostack)
        );
    }
    ret
}

fn errname(e: i32) -> String {
    let n = match e {
        1 => "EPERM", 4 => "EINTR", 9 => "EBADF", 11 => "EAGAIN", 12 => "ENOMEM",
        14 => "EFAULT", 22 => "EINVAL", 25 => "ENOTTY", 38 => "ENOSYS",
        95 => "EOPNOTSUPP",
        _ => return format!("errno {e}"),
    };
    n.into()
}

fn r(v: i64) -> String {
    if v < 0 && v > -4096 { format!("-{}", errname(-v as i32)) } else { v.to_string() }
}

fn say(what: &str, v: i64) {
    println!("  {what:<58} {}", r(v));
    let _ = std::io::stdout().flush();
}

fn show(what: &str, v: impl std::fmt::Display) {
    println!("  {what:<58} {v}");
    let _ = std::io::stdout().flush();
}

const NR_EVENTFD2: i64 = 19;
const NR_EPOLL_CREATE1: i64 = 20;
const NR_EPOLL_CTL: i64 = 21;
const NR_EPOLL_PWAIT: i64 = 22;
const NR_IOCTL: i64 = 29;
const NR_PIPE2: i64 = 59;
const NR_WRITE: i64 = 64;
const NR_EPOLL_PWAIT2: i64 = 441;

const EPOLLIN: u32 = 0x001;
const EPOLLEXCLUSIVE: u32 = 1 << 28;
const EPOLLET: u32 = 1 << 31;
const EPOLL_CTL_ADD: i64 = 1;

const EPIOCSPARAMS: i64 = 0x4008_8a01;
const EPIOCGPARAMS: i64 = 0x8008_8a02;
/// `_IOW(0x8A, 0x01, u32)`: the right number with the wrong size.
const EPIOCSPARAMS_SIZE4: i64 = 0x4004_8a01;
const FIONBIO: i64 = 0x5421;

const SIGUSR1: i32 = 10;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Event {
    events: u32,
    _pad: u32,
    data: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Ts {
    sec: i64,
    nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq)]
struct Params {
    usecs: u32,
    budget: u16,
    prefer: u8,
    pad: u8,
}

fn epoll() -> i64 {
    unsafe { sys(NR_EPOLL_CREATE1, 0, 0, 0, 0, 0, 0) }
}

fn ctl(ep: i64, fd: i64, events: u32) -> i64 {
    let ev = Event { events, _pad: 0, data: fd as u64 };
    unsafe { sys(NR_EPOLL_CTL, ep, EPOLL_CTL_ADD, fd, &ev as *const _ as i64, 0, 0) }
}

fn eventfd() -> i64 {
    unsafe { sys(NR_EVENTFD2, 0, 0, 0, 0, 0, 0) }
}

fn pipe() -> (i64, i64) {
    let mut fds = [0i32; 2];
    unsafe { sys(NR_PIPE2, fds.as_mut_ptr() as i64, 0, 0, 0, 0, 0) };
    (fds[0] as i64, fds[1] as i64)
}

fn poke(fd: i64) -> i64 {
    let one = 1u64;
    unsafe { sys(NR_WRITE, fd, &one as *const _ as i64, 8, 0, 0, 0) }
}

fn close(fd: i64) {
    unsafe { libc::close(fd as i32) };
}

/// `epoll_pwait2` with every argument spelled out.
fn pwait2(ep: i64, events: i64, max: i64, timeout: i64, mask: i64, size: i64) -> i64 {
    unsafe { sys(NR_EPOLL_PWAIT2, ep, events, max, timeout, mask, size) }
}

fn pwait2_ts(ep: i64, ts: Option<Ts>) -> i64 {
    let mut out = [Event::default(); 4];
    let ts = ts.map(|t| Box::new(t));
    let p = ts.as_ref().map_or(0, |t| &**t as *const Ts as i64);
    pwait2(ep, out.as_mut_ptr() as i64, 4, p, 0, 8)
}

fn ioctl(fd: i64, cmd: i64, arg: i64) -> i64 {
    unsafe { sys(NR_IOCTL, fd, cmd, arg, 0, 0, 0) }
}

fn get_params(ep: i64) -> String {
    let mut p = Params { usecs: 0xdead, budget: 0xbeef, prefer: 0xaa, pad: 0xbb };
    let ret = ioctl(ep, EPIOCGPARAMS, &mut p as *mut _ as i64);
    if ret < 0 {
        return r(ret);
    }
    format!(
        "{} usecs {} budget {} prefer {} pad {}",
        ret, p.usecs, p.budget, p.prefer, p.pad
    )
}

fn set_params(ep: i64, p: Params) -> i64 {
    ioctl(ep, EPIOCSPARAMS, &p as *const _ as i64)
}

fn arguments() {
    println!("## epoll_pwait2 arguments");
    let ep = epoll();
    let idle = epoll();
    let efd = eventfd();
    poke(efd);
    ctl(ep, efd, EPOLLIN);
    let (rd, wr) = pipe();

    say("NULL timeout, one ready", pwait2_ts(ep, None));
    say("zero timeout, nothing ready", pwait2_ts(idle, Some(Ts { sec: 0, nsec: 0 })));
    say("zero timeout, one ready", pwait2_ts(ep, Some(Ts { sec: 0, nsec: 0 })));
    say("tv_nsec = 1_000_000_000", pwait2_ts(ep, Some(Ts { sec: 0, nsec: 1_000_000_000 })));
    say("tv_nsec = -1", pwait2_ts(ep, Some(Ts { sec: 0, nsec: -1 })));
    say("tv_sec = -1", pwait2_ts(ep, Some(Ts { sec: -1, nsec: 0 })));
    say("tv_sec = LLONG_MAX, one ready", pwait2_ts(ep, Some(Ts { sec: i64::MAX, nsec: 0 })));
    say("tv_sec = LLONG_MAX, nsec 999999999, one ready",
        pwait2_ts(ep, Some(Ts { sec: i64::MAX, nsec: 999_999_999 })));

    let mut out = [Event::default(); 4];
    let o = out.as_mut_ptr() as i64;
    let zero = Ts::default();
    let z = &zero as *const Ts as i64;
    say("an unreadable timeout", pwait2(ep, o, 4, 8, 0, 8));
    say("maxevents 0", pwait2(ep, o, 0, z, 0, 8));
    say("maxevents -1", pwait2(ep, o, -1, z, 0, 8));
    say("maxevents INT_MAX/16 + 1", pwait2(ep, o, (i32::MAX / 16 + 1) as i64, z, 0, 8));
    say("a closed epfd", pwait2(999, o, 4, z, 0, 8));
    say("a pipe as epfd", pwait2(rd, o, 4, z, 0, 8));
    say("events NULL, one ready", pwait2(ep, 0, 4, z, 0, 8));
    say("events past the address space", pwait2(ep, -4096, 4, z, 0, 8));

    let mask = 0u64;
    let m = &mask as *const u64 as i64;
    say("a mask with sigsetsize 4", pwait2(idle, o, 4, z, m, 4));
    say("a mask with sigsetsize 16", pwait2(idle, o, 4, z, m, 16));
    say("a mask with sigsetsize 1<<32 | 8", pwait2(idle, o, 4, z, m, (1 << 32) | 8));
    say("epoll_pwait, a mask with sigsetsize 1<<32 | 8",
        unsafe { sys(NR_EPOLL_PWAIT, idle, o, 4, 0, m, (1 << 32) | 8) });
    say("NULL mask with sigsetsize 4", pwait2(idle, o, 4, z, 0, 4));
    say("an unreadable mask", pwait2(idle, o, 4, z, 8, 8));

    println!("## epoll_pwait2, which argument is checked first");
    let bad_ns = Ts { sec: 0, nsec: -1 };
    let b = &bad_ns as *const Ts as i64;
    say("closed epfd, timeout tv_nsec -1", pwait2(999, o, 4, b, 0, 8));
    say("closed epfd, unreadable timeout", pwait2(999, o, 4, 8, 0, 8));
    say("closed epfd, sigsetsize 4", pwait2(999, o, 4, z, m, 4));
    say("closed epfd, maxevents 0", pwait2(999, o, 0, z, 0, 8));
    say("closed epfd, events past the address space", pwait2(999, -4096, 4, z, 0, 8));
    say("maxevents 0, timeout tv_nsec -1", pwait2(ep, o, 0, b, 0, 8));
    say("maxevents 0, sigsetsize 4", pwait2(ep, o, 0, z, m, 4));
    say("unreadable mask, timeout tv_nsec -1", pwait2(ep, o, 4, b, 8, 8));
    say("a pipe as epfd, sigsetsize 4", pwait2(rd, o, 4, z, m, 4));

    // `epoll_pwait2`'s timeout is `const`: nothing is written back.
    let mut ts = Ts { sec: 0, nsec: 10_000_000 };
    let ret = pwait2(idle, o, 4, &mut ts as *mut Ts as i64, 0, 8);
    say("10 ms on an idle set", ret);
    show("  the timeout after", format!("{}s {}ns", ts.sec, ts.nsec));

    close(rd);
    close(wr);
    close(efd);
    close(ep);
    close(idle);
}

fn timing() {
    println!("## epoll_pwait2 timeouts");
    let idle = epoll();
    let elapsed = |ts: Ts| {
        let t = Instant::now();
        let ret = pwait2_ts(idle, Some(ts));
        (ret, t.elapsed())
    };
    // The best of five, so that one preemption moves nothing.
    let best = |ts: Ts| {
        let mut best = Duration::MAX;
        let mut ret = 0;
        for _ in 0..5 {
            let (rv, d) = elapsed(ts);
            ret = rv;
            best = best.min(d);
        }
        (ret, best)
    };
    let (ret, d) = best(Ts { sec: 0, nsec: 300_000 });
    say("300 us", ret);
    show("  took at least 300 us", d >= Duration::from_micros(300));
    say("1 ns", best(Ts { sec: 0, nsec: 1 }).0);
    let (ret, d) = elapsed(Ts { sec: 0, nsec: 20_000_000 });
    say("20 ms", ret);
    show("  took at least 20 ms", d >= Duration::from_millis(20));
    show("  took under 200 ms", d < Duration::from_millis(200));

    // epoll_pwait's milliseconds are unchanged by the above.
    let mut out = [Event::default(); 4];
    let t = Instant::now();
    let ret = unsafe { sys(NR_EPOLL_PWAIT, idle, out.as_mut_ptr() as i64, 4, 1, 0, 8) };
    let d = t.elapsed();
    say("epoll_pwait 1 ms", ret);
    show("  took at least 1 ms", d >= Duration::from_millis(1));

    // NULL blocks until an event, from another thread.
    let ep = epoll();
    let efd = eventfd();
    ctl(ep, efd, EPOLLIN);
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        poke(efd);
    });
    let t = Instant::now();
    let ret = pwait2_ts(ep, None);
    let d = t.elapsed();
    writer.join().unwrap();
    say("NULL timeout, written after 30 ms", ret);
    show("  took at least 30 ms", d >= Duration::from_millis(30));
    close(efd);
    close(ep);
    close(idle);
}

static HANDLED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_usr1(_: i32) {
    HANDLED.store(true, Ordering::SeqCst);
}

fn sigmask_now() -> u64 {
    let mut old = 0u64;
    unsafe { sys(135, 0, 0, &mut old as *mut u64 as i64, 8, 0, 0) };
    old
}

fn signals() {
    println!("## epoll_pwait2 and a signal");
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_usr1 as *const () as usize;
        libc::sigaction(SIGUSR1, &sa, std::ptr::null_mut());
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, SIGUSR1);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    let idle = epoll();
    let pid = unsafe { libc::getpid() };
    let tid = unsafe { libc::gettid() };
    let kill_later = move || {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, SIGUSR1) };
        })
    };

    // Unblocked only for the wait.
    HANDLED.store(false, Ordering::SeqCst);
    let open = 0u64;
    let k = kill_later();
    let ts = Ts { sec: 2, nsec: 0 };
    let mut out = [Event::default(); 4];
    let ret = pwait2(idle, out.as_mut_ptr() as i64, 4, &ts as *const Ts as i64,
        &open as *const u64 as i64, 8);
    k.join().unwrap();
    say("unblocked by the temporary mask", ret);
    show("  the handler ran", HANDLED.load(Ordering::SeqCst));
    show("  SIGUSR1 blocked again after", sigmask_now() & (1 << (SIGUSR1 - 1)) != 0);

    // Still blocked by the temporary mask.
    HANDLED.store(false, Ordering::SeqCst);
    let closed = 1u64 << (SIGUSR1 - 1);
    let k = kill_later();
    let ts = Ts { sec: 0, nsec: 100_000_000 };
    let ret = pwait2(idle, out.as_mut_ptr() as i64, 4, &ts as *const Ts as i64,
        &closed as *const u64 as i64, 8);
    k.join().unwrap();
    say("blocked by the temporary mask, 100 ms", ret);
    show("  the handler ran", HANDLED.load(Ordering::SeqCst));
    // Take it, so nothing is left for the next case.
    let open = 0u64;
    let ts = Ts { sec: 0, nsec: 0 };
    let ret = pwait2(idle, out.as_mut_ptr() as i64, 4, &ts as *const Ts as i64,
        &open as *const u64 as i64, 8);
    say("  then a zero wait with it unblocked", ret);
    show("  the handler ran", HANDLED.load(Ordering::SeqCst));
    close(idle);
}

fn params() {
    println!("## EPIOCSPARAMS and EPIOCGPARAMS");
    let ep = epoll();
    show("GPARAMS on a new set", get_params(ep));
    say("SPARAMS {100, 8, 1, 0}", set_params(ep, Params { usecs: 100, budget: 8, prefer: 1, pad: 0 }));
    show("  GPARAMS after", get_params(ep));
    say("SPARAMS pad 1", set_params(ep, Params { usecs: 5, budget: 5, prefer: 0, pad: 1 }));
    say("SPARAMS prefer 2", set_params(ep, Params { usecs: 5, budget: 5, prefer: 2, pad: 0 }));
    say("SPARAMS usecs 0x80000000", set_params(ep, Params { usecs: 0x8000_0000, budget: 5, prefer: 0, pad: 0 }));
    show("  GPARAMS after three refusals", get_params(ep));
    say("SPARAMS usecs 0x7fffffff", set_params(ep, Params { usecs: 0x7fff_ffff, budget: 5, prefer: 0, pad: 0 }));
    show("  GPARAMS after", get_params(ep));
    say("SPARAMS budget 64", set_params(ep, Params { usecs: 0, budget: 64, prefer: 0, pad: 0 }));
    show("  GPARAMS after", get_params(ep));
    say("SPARAMS pad 1 and budget 65", set_params(ep, Params { usecs: 0, budget: 65, prefer: 0, pad: 1 }));
    say("SPARAMS prefer 2 and budget 65", set_params(ep, Params { usecs: 0, budget: 65, prefer: 2, pad: 0 }));
    say("SPARAMS NULL", ioctl(ep, EPIOCSPARAMS, 0));
    say("GPARAMS NULL", ioctl(ep, EPIOCGPARAMS, 0));
    let p = Params::default();
    say("SPARAMS with a 4-byte size", ioctl(ep, EPIOCSPARAMS_SIZE4, &p as *const _ as i64));
    let (rd, wr) = pipe();
    say("SPARAMS on a pipe", ioctl(rd, EPIOCSPARAMS, &p as *const _ as i64));
    let efd = eventfd();
    let mut q = Params::default();
    say("GPARAMS on an eventfd", ioctl(efd, EPIOCGPARAMS, &mut q as *mut _ as i64));
    let on = 1i32;
    say("FIONBIO on a set", ioctl(ep, FIONBIO, &on as *const _ as i64));
    say("ioctl 0x8a03 on a set", ioctl(ep, 0x8a03, 0));
    let mut termios = [0u8; 64];
    say("TCGETS on a set", ioctl(ep, 0x5401, termios.as_mut_ptr() as i64));
    let mut n = 0i32;
    say("FIONREAD on a set", ioctl(ep, 0x541b, &mut n as *mut i32 as i64));
    close(efd);
    close(rd);
    close(wr);
    close(ep);
}

/// How many of `n` threads, each waiting on its own set, see one write.
fn woken(n: usize, events: u32, use_pipe: bool) -> usize {
    let (target, writer, extra) = if use_pipe {
        let (rd, wr) = pipe();
        (rd, wr, Some(wr))
    } else {
        let e = eventfd();
        (e, e, None)
    };
    let ready = std::sync::Arc::new(AtomicU32::new(0));
    let threads: Vec<_> = (0..n)
        .map(|_| {
            let ep = epoll();
            ctl(ep, target, events);
            let ready = ready.clone();
            std::thread::spawn(move || {
                let mut out = [Event::default(); 1];
                ready.fetch_add(1, Ordering::SeqCst);
                let got = unsafe { sys(NR_EPOLL_PWAIT, ep, out.as_mut_ptr() as i64, 1, 300, 0, 8) };
                close(ep);
                got == 1
            })
        })
        .collect();
    while ready.load(Ordering::SeqCst) < n as u32 {
        std::thread::yield_now();
    }
    // Long enough that every thread is parked, not merely started.
    std::thread::sleep(Duration::from_millis(50));
    if use_pipe {
        unsafe { sys(NR_WRITE, writer, b"x".as_ptr() as i64, 1, 0, 0, 0) };
    } else {
        poke(writer);
    }
    let count = threads.into_iter().map(|t| t.join().unwrap()).filter(|&b| b).count();
    close(target);
    if let Some(w) = extra {
        close(w);
    }
    count
}

/// How many of `n` threads waiting on **one** set see one edge.
fn woken_one_set(n: usize) -> usize {
    let ep = epoll();
    let efd = eventfd();
    ctl(ep, efd, EPOLLIN | EPOLLET);
    let ready = std::sync::Arc::new(AtomicU32::new(0));
    let threads: Vec<_> = (0..n)
        .map(|_| {
            let ready = ready.clone();
            std::thread::spawn(move || {
                let mut out = [Event::default(); 1];
                ready.fetch_add(1, Ordering::SeqCst);
                unsafe { sys(NR_EPOLL_PWAIT, ep, out.as_mut_ptr() as i64, 1, 300, 0, 8) == 1 }
            })
        })
        .collect();
    while ready.load(Ordering::SeqCst) < n as u32 {
        std::thread::yield_now();
    }
    std::thread::sleep(Duration::from_millis(50));
    poke(efd);
    let count = threads.into_iter().map(|t| t.join().unwrap()).filter(|&b| b).count();
    close(efd);
    close(ep);
    count
}

fn exclusive() {
    println!("## EPOLLEXCLUSIVE: four threads, four sets, one write");
    for (name, ev, p) in [
        ("eventfd, EPOLLEXCLUSIVE", EPOLLIN | EPOLLEXCLUSIVE, false),
        ("eventfd, EPOLLEXCLUSIVE|EPOLLET", EPOLLIN | EPOLLEXCLUSIVE | EPOLLET, false),
        ("pipe, EPOLLEXCLUSIVE", EPOLLIN | EPOLLEXCLUSIVE, true),
        ("eventfd, not exclusive", EPOLLIN, false),
        ("pipe, not exclusive", EPOLLIN, true),
    ] {
        let n = woken(4, ev, p);
        show(&format!("{name}: at least one woke"), n >= 1);
        show(&format!("{name}: exactly one woke"), n == 1);
        show(&format!("{name}: all four woke"), n == 4);
    }
    println!("## four threads on one set, EPOLLET, one write");
    let n = woken_one_set(4);
    show("at least one woke", n >= 1);
    show("all four woke", n == 4);
}

fn main() {
    arguments();
    timing();
    signals();
    params();
    exclusive();
}
