//! `epoll_pwait2`, and the wait rules it shares with `epoll_pwait`.
//!
//! `epoll2_probe` prints the answers; this asserts the ones that must hold on
//! any kernel, so `differential.sh` can run it against a real one.
//!
//! # The sub-millisecond check is relative
//!
//! A 300 us timeout cannot be asserted to return within some fixed bound: the
//! OrbStack kernel this is compared against has ~3 ms timer granularity and
//! takes 2.5-3.5 ms for a 300 us `epoll_pwait2` and for a 300 us `nanosleep`
//! alike. What is asserted is that `epoll_pwait2` honours a short timeout as
//! well as `nanosleep` does on the same machine -- which a timeout carried in
//! milliseconds fails by the better part of a millisecond wherever `nanosleep`
//! is precise.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use guest_tests::{Harness, check, check_fails};

const NR_EPOLL_PWAIT2: libc::c_long = 441;
const EPIOCSPARAMS: libc::c_ulong = 0x4008_8a01;
const EPIOCGPARAMS: libc::c_ulong = 0x8008_8a02;
const SIGUSR1: i32 = libc::SIGUSR1;

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Debug)]
struct Params {
    usecs: u32,
    budget: u16,
    prefer: u8,
    pad: u8,
}

fn pwait2(ep: i32, max: i32, ts: Option<&libc::timespec>, mask: Option<&u64>) -> i64 {
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
    let t = ts.map_or(std::ptr::null(), |t| t as *const libc::timespec);
    let m = mask.map_or(std::ptr::null(), |m| m as *const u64);
    unsafe { libc::syscall(NR_EPOLL_PWAIT2, ep, out.as_mut_ptr(), max, t, m, 8usize) }
}

fn ts(sec: i64, nsec: i64) -> libc::timespec {
    libc::timespec { tv_sec: sec, tv_nsec: nsec }
}

fn eventfd() -> i32 {
    unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) }
}

fn poke(fd: i32) {
    let one = 1u64;
    unsafe { libc::write(fd, &one as *const u64 as *const libc::c_void, 8) };
}

fn watch(ep: i32, fd: i32) {
    let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: fd as u64 };
    unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) };
}

/// The shortest of five runs of `f`, so one preemption decides nothing.
fn best(f: impl Fn()) -> Duration {
    (0..5)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .min()
        .unwrap()
}

static HANDLED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_usr1(_: i32) {
    HANDLED.store(true, Ordering::SeqCst);
}

fn usr1_pending() -> bool {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigpending(&mut set);
        libc::sigismember(&set, SIGUSR1) == 1
    }
}

fn usr1_blocked() -> bool {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut set);
        libc::sigismember(&set, SIGUSR1) == 1
    }
}

fn main() {
    let mut h = Harness::new();
    let ep = unsafe { libc::epoll_create1(0) };
    let idle = unsafe { libc::epoll_create1(0) };
    let efd = eventfd();
    watch(ep, efd);

    h.group("timeouts");
    let t = Instant::now();
    let r = pwait2(idle, 4, Some(&ts(0, 0)), None);
    check!(h, r == 0 && t.elapsed() < Duration::from_millis(50),
        "a zero timeout returns at once: r={r} after {:?}", t.elapsed());
    poke(efd);
    check!(h, pwait2(ep, 4, Some(&ts(0, 0)), None) == 1, "a zero timeout reports what is ready");
    check!(h, pwait2(ep, 4, None, None) == 1, "a NULL timeout reports what is ready");
    check!(h, pwait2(ep, 4, Some(&ts(i64::MAX, 999_999_999)), None) == 1,
        "the largest timeout is a timeout, not an overflow");
    let mut n = 0u64;
    unsafe { libc::read(efd, &mut n as *mut u64 as *mut libc::c_void, 8) };

    let t = Instant::now();
    let r = pwait2(idle, 4, Some(&ts(0, 20_000_000)), None);
    let d = t.elapsed();
    check!(h, r == 0 && d >= Duration::from_millis(20), "20 ms waits 20 ms: r={r} after {d:?}");

    let waited = best(|| {
        pwait2(idle, 4, Some(&ts(0, 300_000)), None);
    });
    let slept = best(|| std::thread::sleep(Duration::from_micros(300)));
    check!(h, waited >= Duration::from_micros(300), "300 us is not cut short: {waited:?}");
    check!(h, waited <= slept + Duration::from_micros(500),
        "300 us is honoured as nanosleep honours it: epoll_pwait2 {waited:?}, nanosleep {slept:?}");

    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        poke(efd);
    });
    let t = Instant::now();
    let r = pwait2(ep, 4, None, None);
    let d = t.elapsed();
    writer.join().unwrap();
    check!(h, r == 1 && d >= Duration::from_millis(25),
        "a NULL timeout blocks until the event: r={r} after {d:?}");
    unsafe { libc::read(efd, &mut n as *mut u64 as *mut libc::c_void, 8) };

    let before = ts(0, 5_000_000);
    let mut after = before;
    unsafe {
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
        libc::syscall(NR_EPOLL_PWAIT2, idle, out.as_mut_ptr(), 1, &mut after as *mut libc::timespec,
            std::ptr::null::<u64>(), 8usize);
    }
    let after = unsafe { std::ptr::read_volatile(&after) };
    check!(h, (after.tv_sec, after.tv_nsec) == (before.tv_sec, before.tv_nsec),
        "the timeout is not written back: {}s {}ns", after.tv_sec, after.tv_nsec);

    h.group("refused");
    check_fails!(h, pwait2(idle, 4, Some(&ts(0, 1_000_000_000)), None), libc::EINVAL, "tv_nsec of a second");
    check_fails!(h, pwait2(idle, 4, Some(&ts(0, -1)), None), libc::EINVAL, "a negative tv_nsec");
    check_fails!(h, pwait2(idle, 4, Some(&ts(-1, 0)), None), libc::EINVAL, "a negative tv_sec");
    check_fails!(h, unsafe {
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
        libc::syscall(NR_EPOLL_PWAIT2, idle, out.as_mut_ptr(), 1, 8usize, 0usize, 8usize)
    }, libc::EFAULT, "an unreadable timeout");
    check_fails!(h, pwait2(-1, 4, Some(&ts(0, -1)), None), libc::EINVAL,
        "the timeout is checked before the descriptor");
    check_fails!(h, pwait2(idle, 0, Some(&ts(0, 0)), None), libc::EINVAL, "maxevents 0");
    check_fails!(h, pwait2(-1, 4, Some(&ts(0, 0)), None), libc::EBADF, "a closed epfd");
    check_fails!(h, pwait2(efd, 4, Some(&ts(0, 0)), None), libc::EINVAL, "an eventfd as epfd");
    check_fails!(h, unsafe {
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
        let mask = 0u64;
        libc::syscall(NR_EPOLL_PWAIT2, idle, out.as_mut_ptr(), 1, &ts(0, 0) as *const libc::timespec,
            &mask as *const u64, 4usize)
    }, libc::EINVAL, "a mask with sigsetsize 4");

    h.group("signals");
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_usr1 as *const () as usize;
        libc::sigaction(SIGUSR1, &sa, std::ptr::null_mut());
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, SIGUSR1);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    let (pid, tid) = unsafe { (libc::getpid(), libc::gettid()) };
    let open = 0u64;
    let k = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, SIGUSR1) };
    });
    HANDLED.store(false, Ordering::SeqCst);
    libc_clear_errno();
    let r = pwait2(idle, 4, Some(&ts(5, 0)), Some(&open));
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    k.join().unwrap();
    check!(h, r == -1 && e == libc::EINTR, "a signal the temporary mask admits is EINTR: r={r} errno={e}");
    check!(h, HANDLED.load(Ordering::SeqCst), "and its handler ran");
    check!(h, usr1_blocked(), "and the old mask is back");

    // A zero timeout answers 0 even with a signal pending that the temporary
    // mask admits -- the deadline is looked at before the signal -- and the
    // old mask comes back with the signal still pending, undelivered.
    unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, SIGUSR1) };
    HANDLED.store(false, Ordering::SeqCst);
    let r = pwait2(idle, 4, Some(&ts(0, 0)), Some(&open));
    check!(h, r == 0, "epoll_pwait2, zero timeout, a signal pending: r={r}");
    check!(h, !HANDLED.load(Ordering::SeqCst) && usr1_pending(),
        "the signal stays pending: handled={} pending={}", HANDLED.load(Ordering::SeqCst), usr1_pending());
    let r = unsafe {
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
        libc::syscall(libc::SYS_epoll_pwait, idle, out.as_mut_ptr(), 1, 0, &open as *const u64, 8usize)
    };
    check!(h, r == 0 && !HANDLED.load(Ordering::SeqCst),
        "epoll_pwait, zero timeout, a signal pending: r={r} handled={}", HANDLED.load(Ordering::SeqCst));
    // Taken by a wait that lets it in, so nothing is left behind.
    let r = pwait2(idle, 4, Some(&ts(1, 0)), Some(&open));
    check!(h, r == -1 && HANDLED.load(Ordering::SeqCst), "a timed wait then takes it: r={r}");

    h.group("busy-poll parameters");
    let get = |fd: i32| {
        let mut p = Params { usecs: 1, budget: 1, prefer: 1, pad: 1 };
        let r = unsafe { libc::ioctl(fd, EPIOCGPARAMS as _, &mut p) };
        (r, p)
    };
    let set = |fd: i32, p: Params| unsafe { libc::ioctl(fd, EPIOCSPARAMS as _, &p) };
    check!(h, get(ep) == (0, Params::default()), "a new set reports zeroes: {:?}", get(ep));
    let p = Params { usecs: 250, budget: 16, prefer: 1, pad: 0 };
    check!(h, set(ep, p) == 0, "parameters are stored");
    check!(h, get(ep) == (0, p), "and read back: {:?}", get(ep));
    check_fails!(h, set(ep, Params { pad: 1, ..p }), libc::EINVAL, "a pad byte");
    check_fails!(h, set(ep, Params { prefer: 2, ..p }), libc::EINVAL, "prefer 2");
    check_fails!(h, set(ep, Params { usecs: 1 << 31, ..p }), libc::EINVAL, "usecs past S32_MAX");
    check!(h, get(ep) == (0, p), "a refused set changes nothing: {:?}", get(ep));
    check_fails!(h, unsafe { libc::ioctl(ep, 0x5401 as _, [0u8; 64].as_mut_ptr()) }, libc::EINVAL,
        "another ioctl on a set is EINVAL, not ENOTTY");
    check_fails!(h, unsafe { libc::ioctl(efd, EPIOCGPARAMS as _, &mut Params::default()) }, libc::ENOTTY,
        "the parameters on an eventfd");

    std::process::exit(h.finish());
}

fn libc_clear_errno() {
    guest_tests::sys::clear_errno();
}
