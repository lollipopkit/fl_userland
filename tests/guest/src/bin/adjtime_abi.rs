//! `adjtimex` and `clock_adjtime`, the setting calls' argument order, and the
//! clock ids each clock syscall takes.
//!
//! `clock2_probe` prints the answers; this asserts what must hold on any
//! kernel. The NTP state itself is the machine's, so it is checked for
//! consistency rather than for values.
//!
//! # Seccomp
//!
//! Needs `--security-opt seccomp=unconfined` in a container (`differential.sh`'s
//! `seccomp_off`): docker's default profile answers `EPERM` to every
//! `clock_settime` and `settimeofday` without `CAP_SYS_TIME`, before the kernel
//! validates the arguments whose order is checked here.
//!
//! # Nothing here can move a clock
//!
//! Every setting call is refused for a caller without `CAP_SYS_TIME`, and is a
//! no-op for one with it: a frequency set to the value just read, a
//! single-shot offset of zero, a time set to the time just read.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use guest_tests::{Harness, check, check_fails};

const NR_CLOCK_ADJTIME: libc::c_long = 266;
const NR_ADJTIMEX: libc::c_long = 171;

const STA_UNSYNC: i32 = 0x0040;
const TIME_ERROR: i64 = 5;

/// The aarch64 `struct timex`, as offsets into 208 bytes.
struct Timex([u8; 208]);

impl Timex {
    fn new(modes: u32) -> Timex {
        let mut t = Timex([0u8; 208]);
        t.0[164..].fill(0x5a);
        t.0[..4].copy_from_slice(&modes.to_le_bytes());
        t
    }
    fn long(&self, at: usize) -> i64 {
        i64::from_le_bytes(self.0[at..at + 8].try_into().unwrap())
    }
    fn int(&self, at: usize) -> i32 {
        i32::from_le_bytes(self.0[at..at + 4].try_into().unwrap())
    }
    fn set_long(&mut self, at: usize, v: i64) {
        self.0[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
}

fn adjtimex(t: &mut Timex) -> i64 {
    unsafe { libc::syscall(NR_ADJTIMEX, t.0.as_mut_ptr()) }
}

fn clock_adjtime(clock: i32, t: &mut Timex) -> i64 {
    unsafe { libc::syscall(NR_CLOCK_ADJTIME, clock, t.0.as_mut_ptr()) }
}

fn now(clock: i32) -> libc::timespec {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::syscall(libc::SYS_clock_gettime, clock, &mut ts) };
    ts
}

fn ns(t: &libc::timespec) -> i128 {
    t.tv_sec as i128 * 1_000_000_000 + t.tv_nsec as i128
}

fn nanosleep(clock: i32, flags: i32, sec: i64, nsec: i64) -> i64 {
    let req = libc::timespec { tv_sec: sec, tv_nsec: nsec };
    unsafe {
        libc::syscall(libc::SYS_clock_nanosleep, clock, flags, &req, std::ptr::null_mut::<libc::timespec>())
    }
}

/// A raw `clock_nanosleep` answers the errno as its value, not through errno.
fn sleep_errno(clock: i32, flags: i32, sec: i64, nsec: i64) -> i32 {
    let r = nanosleep(clock, flags, sec, nsec);
    if r < 0 { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) } else { 0 }
}

fn cpu_ns(who: i32) -> i128 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(who, &mut ru) };
    let tv = |t: libc::timeval| t.tv_sec as i128 * 1_000_000_000 + t.tv_usec as i128 * 1000;
    tv(ru.ru_utime) + tv(ru.ru_stime)
}

extern "C" fn on_alarm(_: i32) {}

fn main() {
    let mut h = Harness::new();

    h.group("reading");
    let mut t = Timex::new(0);
    let r = adjtimex(&mut t);
    let status = t.int(40);
    check!(h, (0..=TIME_ERROR).contains(&r), "adjtimex(0) answers a clock state: {r}");
    check!(h, (r == TIME_ERROR) == (status & STA_UNSYNC != 0),
        "TIME_ERROR exactly when STA_UNSYNC is set: r={r} status={status:#x}");
    check!(h, t.int(0) == 0, "modes is left alone");
    check!(h, t.long(16).abs() <= 500 << 16, "freq within the tolerance: {}", t.long(16));
    check!(h, t.long(24) >= 0 && t.long(32) >= 0, "maxerror and esterror are not negative");
    check!(h, t.long(64) == 32_768_000, "tolerance is MAXFREQ_SCALED: {}", t.long(64));
    check!(h, t.long(88) == 10_000, "tick is USER_HZ's: {}", t.long(88));
    let real = now(libc::CLOCK_REALTIME);
    check!(h, (t.long(72) - real.tv_sec).abs() <= 1 && (0..1_000_000).contains(&t.long(80)),
        "time is the realtime clock in microseconds: {}s {}us", t.long(72), t.long(80));
    check!(h, t.0[164..].iter().all(|&b| b == 0x5a), "the padding is left alone");
    let tai = t.int(160) as i64;

    let mut c = Timex::new(0);
    let rc = clock_adjtime(libc::CLOCK_REALTIME, &mut c);
    check!(h, (0..=TIME_ERROR).contains(&rc) && c.long(88) == 10_000,
        "clock_adjtime(CLOCK_REALTIME) is adjtimex: {rc}");
    let mut s = Timex::new(0xa001);
    s.set_long(8, 12345);
    let rs = adjtimex(&mut s);
    check!(h, (0..=TIME_ERROR).contains(&rs) && s.int(0) == 0xa001 && s.long(8) != 12345,
        "ADJ_OFFSET_SS_READ reads the pending offset: r={rs} offset={}", s.long(8));
    check_fails!(h, unsafe { libc::syscall(NR_ADJTIMEX, 0usize) }, libc::EFAULT, "adjtimex(NULL)");
    check_fails!(h, unsafe { libc::syscall(NR_CLOCK_ADJTIME, 99, 0usize) }, libc::EFAULT,
        "the buffer is read before the clock is looked at");
    check_fails!(h, clock_adjtime(libc::CLOCK_MONOTONIC, &mut Timex::new(0)), libc::EOPNOTSUPP,
        "CLOCK_MONOTONIC cannot be adjusted");
    check_fails!(h, clock_adjtime(libc::CLOCK_TAI, &mut Timex::new(0)), libc::EOPNOTSUPP,
        "CLOCK_TAI cannot be adjusted");
    check_fails!(h, clock_adjtime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut Timex::new(0)), libc::EOPNOTSUPP,
        "a CPU clock cannot be adjusted");
    check_fails!(h, clock_adjtime(99, &mut Timex::new(0)), libc::EINVAL, "clock 99");
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    check_fails!(h, clock_adjtime(((!null) << 3) | 3, &mut Timex::new(0)), libc::EINVAL,
        "a dynamic clock on a descriptor that is not one");

    h.group("setting is refused");
    let freq = t.long(16);
    let before = now(libc::CLOCK_REALTIME);
    for (what, modes) in [
        ("ADJ_FREQUENCY, unchanged", 0x0002u32),
        ("ADJ_TICK 10000", 0x4000),
        ("ADJ_OFFSET_SINGLESHOT 0", 0x8001),
        ("ADJ_SETOFFSET {0, 0}", 0x0100),
        ("an unallocated bit", 1 << 30),
    ] {
        let mut a = Timex::new(modes);
        a.set_long(16, freq);
        a.set_long(88, 10_000);
        check_fails!(h, adjtimex(&mut a), libc::EPERM, "adjtimex({what})");
        let mut a = Timex::new(modes);
        a.set_long(16, freq);
        a.set_long(88, 10_000);
        check_fails!(h, clock_adjtime(libc::CLOCK_REALTIME, &mut a), libc::EPERM, "clock_adjtime({what})");
    }
    check_fails!(h, adjtimex(&mut Timex::new(0x8000)), libc::EINVAL,
        "ADJ_ADJTIME without SINGLESHOT, before the permission");

    let set = |clock: i32, sec: i64, nsec: i64| {
        let ts = libc::timespec { tv_sec: sec, tv_nsec: nsec };
        unsafe { libc::syscall(libc::SYS_clock_settime, clock, &ts) }
    };
    let n = now(libc::CLOCK_REALTIME);
    check_fails!(h, set(libc::CLOCK_REALTIME, n.tv_sec, n.tv_nsec), libc::EPERM,
        "clock_settime(CLOCK_REALTIME, now)");
    check_fails!(h, set(libc::CLOCK_REALTIME, n.tv_sec, -1), libc::EINVAL, "clock_settime, nsec -1");
    check_fails!(h, set(libc::CLOCK_REALTIME, i64::MAX, 0), libc::EINVAL, "clock_settime, sec LLONG_MAX");
    check_fails!(h, unsafe { libc::syscall(libc::SYS_clock_settime, 0, 0usize) }, libc::EFAULT,
        "clock_settime(CLOCK_REALTIME, NULL)");
    check_fails!(h, set(libc::CLOCK_MONOTONIC, 1, 0), libc::EINVAL, "clock_settime(CLOCK_MONOTONIC)");
    check_fails!(h, unsafe { libc::syscall(libc::SYS_clock_settime, 1, 0usize) }, libc::EINVAL,
        "the clock is checked before the time is read");
    check_fails!(h, set(libc::CLOCK_PROCESS_CPUTIME_ID, 0, 0), libc::EINVAL,
        "clock_settime(CLOCK_PROCESS_CPUTIME_ID)");
    let stod = |tv: Option<[i64; 2]>, tz: usize| unsafe {
        libc::syscall(libc::SYS_settimeofday, tv.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()), tz)
    };
    // A request that sets nothing is a success with CAP_SYS_TIME, which the
    // guest's root has and a container's root does not (`caps_probe`), so
    // the capability goes first: the refusal is the rule being asked.
    guest_tests::caps::without(&[25]);
    check_fails!(h, stod(None, 0), libc::EPERM, "settimeofday(NULL, NULL) without CAP_SYS_TIME");
    check_fails!(h, stod(Some([n.tv_sec, 1_000_000]), 0), libc::EINVAL, "settimeofday, usec 1e6");
    check_fails!(h, stod(Some([-1, 0]), 0), libc::EINVAL, "settimeofday, sec -1");
    check_fails!(h, stod(None, 8), libc::EFAULT, "settimeofday, unreadable tz");
    let after = now(libc::CLOCK_REALTIME);
    check!(h, (ns(&after) - ns(&before)).abs() < 5_000_000_000, "and the clock did not move");

    h.group("clock ids");
    let tai_now = now(libc::CLOCK_TAI);
    let real = now(libc::CLOCK_REALTIME);
    check!(h, ((ns(&tai_now) - ns(&real)) / 1_000_000_000 - tai as i128).abs() <= 1,
        "CLOCK_TAI is the realtime clock plus adjtimex's tai ({tai})");
    check!(h, sleep_errno(libc::CLOCK_TAI, 0, 0, 1_000_000) == 0, "CLOCK_TAI can be slept on");
    check!(h, sleep_errno(libc::CLOCK_MONOTONIC_RAW, 0, 0, 1000) == libc::EOPNOTSUPP,
        "CLOCK_MONOTONIC_RAW cannot be slept on");
    check!(h, sleep_errno(libc::CLOCK_REALTIME_COARSE, 0, 0, 1000) == libc::EOPNOTSUPP,
        "CLOCK_REALTIME_COARSE cannot be slept on");
    check!(h, sleep_errno(libc::CLOCK_THREAD_CPUTIME_ID, 1, 0, 0) == libc::EOPNOTSUPP,
        "CLOCK_THREAD_CPUTIME_ID cannot be slept on");
    check!(h, sleep_errno(99, 0, 0, 1000) == libc::EINVAL, "clock 99 is not a clock");
    check!(h, sleep_errno(libc::CLOCK_MONOTONIC_RAW, 0, 0, -1) == libc::EOPNOTSUPP,
        "the clock is checked before the request");
    check!(h, sleep_errno(libc::CLOCK_PROCESS_CPUTIME_ID, 1, 0, 0) == 0,
        "an absolute CPU-time deadline already past returns at once");
    let pid = unsafe { libc::getpid() };
    check!(h, sleep_errno(((!pid) << 3) | 2, 1, 0, 0) == 0, "and on the process's encoded clock");
    check!(h, sleep_errno(((!0) << 3) | 6, 1, 0, 0) == libc::EINVAL,
        "a thread's encoded clock cannot be slept on");
    let mut cpu = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let r = unsafe { libc::syscall(libc::SYS_clock_gettime, ((!pid) << 3) | 2, &mut cpu) };
    check!(h, r == 0, "the process's encoded SCHED clock reads");
    let r = unsafe { libc::syscall(libc::SYS_clock_gettime, ((!0) << 3) | 6, &mut cpu) };
    check!(h, r == 0, "the calling thread's encoded SCHED clock reads");
    let mut res = libc::timespec { tv_sec: 9, tv_nsec: 9 };
    let r = unsafe { libc::syscall(libc::SYS_clock_getres, ((!0) << 3) | 2, &mut res) };
    check!(h, r == 0 && res.tv_sec == 0 && res.tv_nsec == 1, "SCHED reports a nanosecond");
    let r = unsafe { libc::syscall(libc::SYS_clock_gettime, ((!99_999) << 3) | 2, &mut cpu) };
    check!(h, r == -1, "a pid that does not exist has no CPU clock");

    for clock in [libc::CLOCK_MONOTONIC_RAW, libc::CLOCK_MONOTONIC_COARSE] {
        let mut sev: libc::sigevent = unsafe { std::mem::zeroed() };
        sev.sigev_notify = libc::SIGEV_NONE;
        let mut id: usize = 0;
        check_fails!(h, unsafe { libc::syscall(libc::SYS_timer_create, clock, &mut sev, &mut id) },
            libc::EOPNOTSUPP, "timer_create({clock})");
    }
    let mut sev: libc::sigevent = unsafe { std::mem::zeroed() };
    sev.sigev_notify = libc::SIGEV_SIGNAL;
    sev.sigev_signo = 0;
    let mut id: usize = 0;
    check_fails!(h, unsafe { libc::syscall(libc::SYS_timer_create, libc::CLOCK_MONOTONIC, &mut sev, &mut id) },
        libc::EINVAL, "timer_create with signal 0");

    h.group("process CPU time counts every thread");
    // A sibling spins; the main thread does not run. The process clock
    // advances with the sibling, and a relative sleep on it returns.
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::channel();
    let spin = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            tx.send(unsafe { libc::gettid() }).unwrap();
            let start = Instant::now();
            let mut x = 0u64;
            while !stop.load(Ordering::Relaxed) && start.elapsed() < Duration::from_secs(5) {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                std::hint::black_box(x);
            }
        })
    };
    std::thread::sleep(Duration::from_millis(100));
    let main_only = cpu_ns(libc::RUSAGE_THREAD);
    let process = cpu_ns(libc::RUSAGE_SELF);
    check!(h, process - main_only >= 50_000_000,
        "getrusage(RUSAGE_SELF) includes a running sibling: process {process} main {main_only}");
    // The sibling's own clock, as `pthread_getcpuclockid` names it.
    let spin_tid = rx.recv().unwrap();
    let mut theirs = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let r = unsafe { libc::syscall(libc::SYS_clock_gettime, ((!spin_tid) << 3) | 6, &mut theirs) };
    check!(h, r == 0 && ns(&theirs) >= 50_000_000,
        "another thread's SCHED clock reads its time: r={r} {}", ns(&theirs));
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::_exit(0) };
    }
    let mut c = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let r = unsafe { libc::syscall(libc::SYS_clock_gettime, ((!child) << 3) | 6, &mut c) };
    check!(h, r == -1, "a thread of another process has no thread clock for us");
    unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) };
    // A watchdog, so a process clock that does not advance fails the check
    // with EINTR instead of hanging the suite.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_alarm as *const () as usize;
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
        libc::alarm(4);
    }
    let before = now(libc::CLOCK_PROCESS_CPUTIME_ID);
    let t = Instant::now();
    let r = sleep_errno(libc::CLOCK_PROCESS_CPUTIME_ID, 0, 0, 30_000_000);
    let wall = t.elapsed();
    unsafe { libc::alarm(0) };
    let after = now(libc::CLOCK_PROCESS_CPUTIME_ID);
    stop.store(true, Ordering::Relaxed);
    spin.join().unwrap();
    check!(h, r == 0 && wall < Duration::from_secs(4),
        "a 30 ms sleep on the process clock returns: errno {r} after {wall:?}");
    check!(h, ns(&after) - ns(&before) >= 30_000_000,
        "after the process clock moved 30 ms: {}", ns(&after) - ns(&before));

    std::process::exit(h.finish());
}
