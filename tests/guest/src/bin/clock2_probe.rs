//! What `adjtimex` and `clock_adjtime` report and refuse, which clock ids each
//! clock syscall takes, and the setting calls' argument order.
//!
//! One line per case, nothing asserted: `probe_diff.sh` compares the lines
//! against a real kernel.
//!
//! # Nothing here can move a clock
//!
//! Every setting call is either refused before it could act or is a no-op if
//! it were obeyed: a frequency set to the value just read, a tick of 10000, a
//! single-shot offset of zero, a time set to the time just read. A container
//! has no `CAP_SYS_TIME`, so on Linux they are all refused anyway; the no-op
//! values are there so that a container that did have it would change nothing.
//!
//! # The container's seccomp profile
//!
//! Docker's default profile answers `EPERM` for every `clock_settime` and
//! `settimeofday` without `CAP_SYS_TIME`, before the kernel validates
//! anything. Those lines are recorded from `--security-opt seccomp=unconfined`
//! by hand and tagged in `probe_diff.sh`'s `known_ok`.
//!
//! # Machine state
//!
//! The NTP fields `adjtimex` reports (`freq`, `maxerror`, `status`, the return
//! value) are the state of the machine's clock discipline, not rules of the
//! kernel. They are printed as properties a guest can rely on rather than as
//! numbers.

use std::io::Write;

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
        1 => "EPERM", 3 => "ESRCH", 4 => "EINTR", 9 => "EBADF", 11 => "EAGAIN",
        12 => "ENOMEM", 14 => "EFAULT", 22 => "EINVAL", 25 => "ENOTTY",
        38 => "ENOSYS", 95 => "EOPNOTSUPP",
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

const NR_IOCTL: i64 = 29;
const NR_PSELECT6: i64 = 72;
const NR_PPOLL: i64 = 73;
const NR_READ: i64 = 63;
const NR_TIMERFD_CREATE: i64 = 85;
const NR_TIMERFD_SETTIME: i64 = 86;
const NR_TIMER_CREATE: i64 = 107;
const NR_TIMER_DELETE: i64 = 111;
const NR_CLOCK_SETTIME: i64 = 112;
const NR_CLOCK_GETTIME: i64 = 113;
const NR_CLOCK_GETRES: i64 = 114;
const NR_CLOCK_NANOSLEEP: i64 = 115;
const NR_SETTIMEOFDAY: i64 = 170;
const NR_ADJTIMEX: i64 = 171;
const NR_GETPID: i64 = 172;
const NR_GETTID: i64 = 178;
const NR_CLOCK_ADJTIME: i64 = 266;

const REALTIME: i64 = 0;
const MONOTONIC: i64 = 1;

const ADJ_OFFSET: u32 = 0x0001;
const ADJ_FREQUENCY: u32 = 0x0002;
const ADJ_MAXERROR: u32 = 0x0004;
const ADJ_STATUS: u32 = 0x0010;
const ADJ_TAI: u32 = 0x0080;
const ADJ_SETOFFSET: u32 = 0x0100;
const ADJ_MICRO: u32 = 0x1000;
const ADJ_NANO: u32 = 0x2000;
const ADJ_TICK: u32 = 0x4000;
const ADJ_OFFSET_SINGLESHOT: u32 = 0x8001;
const ADJ_OFFSET_SS_READ: u32 = 0xa001;

const STA_UNSYNC: i64 = 0x0040;

/// The aarch64 `struct timex`, 208 bytes, as offsets.
struct Timex([u8; 208]);

impl Timex {
    fn new(modes: u32) -> Timex {
        // The padding is filled with a pattern so a kernel that writes it
        // back unchanged can be told from one that clears it.
        let mut t = Timex([0u8; 208]);
        t.0[164..].fill(0x5a);
        t.0[0..4].copy_from_slice(&modes.to_le_bytes());
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
    fn ptr(&mut self) -> i64 {
        self.0.as_mut_ptr() as i64
    }
}

fn adjtimex(t: &mut Timex) -> i64 {
    unsafe { sys(NR_ADJTIMEX, t.ptr(), 0, 0, 0, 0, 0) }
}

fn clock_adjtime(clock: i64, t: &mut Timex) -> i64 {
    unsafe { sys(NR_CLOCK_ADJTIME, clock, t.ptr(), 0, 0, 0, 0) }
}

fn now(clock: i64) -> (i64, i64) {
    let mut ts = [0i64; 2];
    unsafe { sys(NR_CLOCK_GETTIME, clock, ts.as_mut_ptr() as i64, 0, 0, 0, 0) };
    (ts[0], ts[1])
}

/// The fields of a read-only reply.
fn report(name: &str, ret: i64, t: &Timex) {
    if ret < 0 {
        say(name, ret);
        return;
    }
    show(name, "a clock state");
    let status = t.long(40) as i32 as i64;
    show("  the return is TIME_ERROR exactly when STA_UNSYNC is set",
        (ret == 5) == (status & STA_UNSYNC != 0));
    show("  the return is TIME_OK or TIME_ERROR", ret == 0 || ret == 5);
    show("  modes", format!("{:#x}", t.int(0)));
    show("  offset", t.long(8));
    show("  freq within +-500 ppm", t.long(16).abs() <= 500 << 16);
    show("  maxerror within 0..=16 s", (0..=16_000_000).contains(&t.long(24)));
    show("  esterror within 0..=16 s", (0..=16_000_000).contains(&t.long(32)));
    show("  status bits outside the NTP set",
        format!("{:#x}", status & !0xffff));
    show("  status STA_NANO", status & 0x2000 != 0);
    show("  constant within 0..=10", (0..=10).contains(&t.long(48)));
    show("  precision", t.long(56));
    show("  tolerance", t.long(64));
    let (sec, nsec) = now(REALTIME);
    let usec = t.long(80);
    show("  time within a second of CLOCK_REALTIME", (t.long(72) - sec).abs() <= 1);
    show("  time.tv_usec below a million", (0..1_000_000).contains(&usec));
    let _ = nsec;
    show("  tick", t.long(88));
    show("  ppsfreq", t.long(96));
    show("  jitter", t.long(104));
    show("  shift", t.int(112));
    show("  stabil", t.long(120));
    show("  jitcnt", t.long(128));
    show("  calcnt", t.long(136));
    show("  errcnt", t.long(144));
    show("  stbcnt", t.long(152));
    show("  tai", t.int(160));
    show("  the padding is left alone", t.0[164..].iter().all(|&b| b == 0x5a));
}

fn read_only() {
    println!("## adjtimex and clock_adjtime, reading");
    let mut t = Timex::new(0);
    let ret = adjtimex(&mut t);
    report("adjtimex(modes 0)", ret, &t);
    let mut t = Timex::new(0);
    let ret = clock_adjtime(REALTIME, &mut t);
    report("clock_adjtime(CLOCK_REALTIME, modes 0)", ret, &t);

    let mut t = Timex::new(ADJ_OFFSET_SS_READ);
    t.set_long(8, 12345);
    let ret = adjtimex(&mut t);
    show("adjtimex(ADJ_OFFSET_SS_READ)", if ret >= 0 { "a clock state".into() } else { r(ret) });
    show("  modes after", format!("{:#x}", t.int(0)));
    show("  offset after (12345 before)", t.long(8));
    let mut t = Timex::new(ADJ_OFFSET_SS_READ | ADJ_FREQUENCY);
    t.set_long(16, 1 << 20);
    let ret = adjtimex(&mut t);
    show("adjtimex(ADJ_OFFSET_SS_READ | ADJ_FREQUENCY)", if ret >= 0 { "a clock state".into() } else { r(ret) });
    show("  freq after (1<<20 before) within +-500 ppm", t.long(16).abs() <= 500 << 16);

    say("adjtimex(NULL)", unsafe { sys(NR_ADJTIMEX, 0, 0, 0, 0, 0, 0) });
    say("adjtimex(unmapped)", unsafe { sys(NR_ADJTIMEX, 8, 0, 0, 0, 0, 0) });
    say("clock_adjtime(CLOCK_REALTIME, NULL)", unsafe { sys(NR_CLOCK_ADJTIME, 0, 0, 0, 0, 0, 0) });
    say("clock_adjtime(99, NULL)", unsafe { sys(NR_CLOCK_ADJTIME, 99, 0, 0, 0, 0, 0) });
    say("clock_adjtime(CLOCK_MONOTONIC, NULL)", unsafe { sys(NR_CLOCK_ADJTIME, 1, 0, 0, 0, 0, 0) });
}

/// The clock ids, by name, including the encoded CPU and dynamic clocks.
fn clock_ids() -> Vec<(String, i64)> {
    let pid = unsafe { sys(NR_GETPID, 0, 0, 0, 0, 0, 0) };
    let tid = unsafe { sys(NR_GETTID, 0, 0, 0, 0, 0, 0) };
    let cpu = |pid: i64, kind: i64| ((!pid) << 3) | kind;
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) } as i64;
    let mut ids: Vec<(String, i64)> = [
        "REALTIME", "MONOTONIC", "PROCESS_CPUTIME_ID", "THREAD_CPUTIME_ID", "MONOTONIC_RAW",
        "REALTIME_COARSE", "MONOTONIC_COARSE", "BOOTTIME", "REALTIME_ALARM", "BOOTTIME_ALARM",
        "SGI_CYCLE (10)", "TAI",
    ]
    .iter()
    .enumerate()
    .map(|(i, n)| (n.to_string(), i as i64))
    .collect();
    ids.extend([
        ("12".to_string(), 12),
        ("AUX0 (16)".to_string(), 16),
        ("AUX7 (23)".to_string(), 23),
        ("24".to_string(), 24),
        ("-1".to_string(), -1),
        ("own process, PROF".to_string(), cpu(pid, 0)),
        ("own process, VIRT".to_string(), cpu(pid, 1)),
        ("own process, SCHED".to_string(), cpu(pid, 2)),
        ("pid 0, SCHED".to_string(), cpu(0, 2)),
        ("own thread, PROF".to_string(), cpu(tid, 4)),
        ("own thread, SCHED".to_string(), cpu(tid, 6)),
        ("tid 0, SCHED".to_string(), cpu(0, 6)),
        ("own process, kind 3 and per-thread (7)".to_string(), cpu(pid, 7)),
        ("a pid that does not exist, SCHED".to_string(), cpu(99_999, 2)),
        ("dynamic clock on /dev/null".to_string(), cpu(null, 3)),
        ("dynamic clock on a closed fd".to_string(), cpu(999, 3)),
    ]);
    ids
}

fn per_clock() {
    let ids = clock_ids();
    println!("## clock_gettime and clock_getres");
    for (name, id) in &ids {
        let mut ts = [0i64; 2];
        let g = unsafe { sys(NR_CLOCK_GETTIME, *id, ts.as_mut_ptr() as i64, 0, 0, 0, 0) };
        let mut res = [-1i64; 2];
        let s = unsafe { sys(NR_CLOCK_GETRES, *id, res.as_mut_ptr() as i64, 0, 0, 0, 0) };
        let res = if s == 0 { format!("{}s {}ns", res[0], res[1]) } else { r(s) };
        show(name, format!("gettime {} getres {res}", if g == 0 { "ok".into() } else { r(g) }));
    }
    println!("## clock_adjtime by clock");
    for (name, id) in &ids {
        let mut t = Timex::new(0);
        let ret = clock_adjtime(*id, &mut t);
        show(name, if ret >= 0 { "a state".to_string() } else { r(ret) });
    }
    println!("## clock_nanosleep by clock, absolute 0");
    for (name, id) in &ids {
        // Absolute and in the past, so nothing waits: a relative sleep on a
        // CPU clock would wait for CPU time this thread is not using.
        let zero = [0i64; 2];
        let abs = unsafe { sys(NR_CLOCK_NANOSLEEP, *id, 1, zero.as_ptr() as i64, 0, 0, 0) };
        show(name, format!("absolute 0 {}", r(abs)));
    }
    println!("## clock_nanosleep, relative 1 ms on the wall clocks");
    for (name, id) in ids.iter().filter(|(_, id)| [0, 1, 4, 5, 6, 7, 8, 9, 11].contains(id)) {
        let ms = [0i64, 1_000_000];
        let rel = unsafe { sys(NR_CLOCK_NANOSLEEP, *id, 0, ms.as_ptr() as i64, 0, 0, 0) };
        say(name, rel);
    }
    println!("## timer_create by clock, SIGEV_NONE");
    for (name, id) in &ids {
        let mut sev = [0u8; 64];
        sev[12..16].copy_from_slice(&1i32.to_le_bytes()); // SIGEV_NONE
        let mut timer = 0i32;
        let ret = unsafe {
            sys(NR_TIMER_CREATE, *id, sev.as_ptr() as i64, &mut timer as *mut i32 as i64, 0, 0, 0)
        };
        if ret == 0 {
            unsafe { sys(NR_TIMER_DELETE, timer as i64, 0, 0, 0, 0, 0) };
        }
        say(name, ret);
    }
    println!("## timerfd_create by clock");
    for (name, id) in &ids {
        let ret = unsafe { sys(NR_TIMERFD_CREATE, *id, 0, 0, 0, 0, 0) };
        if ret >= 0 {
            unsafe { libc::close(ret as i32) };
        }
        show(name, if ret >= 0 { "a descriptor".into() } else { r(ret) });
    }
}

fn sigev_thread_id() {
    println!("## timer_create(SIGEV_THREAD_ID)");
    let tid = unsafe { sys(NR_GETTID, 0, 0, 0, 0, 0, 0) } as i32;
    let other = std::thread::spawn(|| unsafe { sys(NR_GETTID, 0, 0, 0, 0, 0, 0) } as i32);
    let gone = other.join().unwrap();
    let parked = std::sync::Arc::new(std::sync::Barrier::new(2));
    let p2 = parked.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let live = std::thread::spawn(move || {
        tx.send(unsafe { sys(NR_GETTID, 0, 0, 0, 0, 0, 0) } as i32).unwrap();
        p2.wait();
    });
    let live_tid = rx.recv().unwrap();
    for (name, target, signo) in [
        ("own tid, SIGUSR1", tid, 10i32),
        ("another live thread", live_tid, 10),
        ("a thread that has exited", gone, 10),
        ("tid 0", 0, 10),
        ("own tid, signal 0", tid, 0),
        ("own tid, signal 65", tid, 65),
    ] {
        let mut sev = [0u8; 64];
        sev[8..12].copy_from_slice(&signo.to_le_bytes());
        sev[12..16].copy_from_slice(&4i32.to_le_bytes()); // SIGEV_THREAD_ID
        sev[16..20].copy_from_slice(&target.to_le_bytes());
        let mut timer = 0i32;
        let ret = unsafe {
            sys(NR_TIMER_CREATE, MONOTONIC, sev.as_ptr() as i64, &mut timer as *mut i32 as i64, 0, 0, 0)
        };
        if ret == 0 {
            unsafe { sys(NR_TIMER_DELETE, timer as i64, 0, 0, 0, 0, 0) };
        }
        say(name, ret);
    }
    for (name, method, signo) in [
        ("SIGEV_SIGNAL, signal 0", 0i32, 0i32),
        ("SIGEV_SIGNAL, SIGUSR1", 0, 10),
        ("SIGEV_THREAD (2), SIGUSR1", 2, 10),
        ("SIGEV_THREAD (2), signal 0", 2, 0),
        ("SIGEV_NONE, signal 99", 1, 99),
        ("method 3", 3, 10),
    ] {
        let mut sev = [0u8; 64];
        sev[8..12].copy_from_slice(&signo.to_le_bytes());
        sev[12..16].copy_from_slice(&method.to_le_bytes());
        let mut timer = 0i32;
        let ret = unsafe {
            sys(NR_TIMER_CREATE, MONOTONIC, sev.as_ptr() as i64, &mut timer as *mut i32 as i64, 0, 0, 0)
        };
        if ret == 0 {
            unsafe { sys(NR_TIMER_DELETE, timer as i64, 0, 0, 0, 0, 0) };
        }
        say(name, ret);
    }
    // Another thread's CPU clock, which Linux answers.
    let cpu = |pid: i64, kind: i64| ((!pid) << 3) | kind;
    let mut ts = [0i64; 2];
    let g = unsafe { sys(NR_CLOCK_GETTIME, cpu(live_tid as i64, 6), ts.as_mut_ptr() as i64, 0, 0, 0, 0) };
    say("clock_gettime(another live thread, SCHED)", g);
    parked.wait();
    live.join().unwrap();
}

fn setting() {
    println!("## setting, without CAP_SYS_TIME");
    let mut read = Timex::new(0);
    adjtimex(&mut read);
    let freq = read.long(16);
    let cases: Vec<(&str, u32, Box<dyn Fn(&mut Timex)>)> = vec![
        ("ADJ_FREQUENCY, the current value", ADJ_FREQUENCY, Box::new(move |t| t.set_long(16, freq))),
        ("ADJ_FREQUENCY, past LLONG_MAX/PPM_SCALE", ADJ_FREQUENCY, Box::new(|t| t.set_long(16, i64::MAX))),
        ("ADJ_TICK 10000", ADJ_TICK, Box::new(|t| t.set_long(88, 10000))),
        ("ADJ_TICK 1", ADJ_TICK, Box::new(|t| t.set_long(88, 1))),
        ("ADJ_OFFSET_SINGLESHOT 0", ADJ_OFFSET_SINGLESHOT, Box::new(|_| {})),
        ("ADJ_ADJTIME (0x8000) alone", 0x8000, Box::new(|_| {})),
        ("ADJ_SETOFFSET {0, 0}", ADJ_SETOFFSET, Box::new(|_| {})),
        ("ADJ_SETOFFSET usec -1", ADJ_SETOFFSET, Box::new(|t| t.set_long(80, -1))),
        ("ADJ_OFFSET 0", ADJ_OFFSET, Box::new(|_| {})),
        ("ADJ_MAXERROR", ADJ_MAXERROR, Box::new(|t| t.set_long(24, 16_000_000))),
        ("ADJ_STATUS STA_UNSYNC", ADJ_STATUS, Box::new(|t| t.set_long(40, STA_UNSYNC))),
        ("ADJ_TAI 0", ADJ_TAI, Box::new(|_| {})),
        ("ADJ_MICRO", ADJ_MICRO, Box::new(|_| {})),
        ("ADJ_NANO", ADJ_NANO, Box::new(|_| {})),
        ("an unallocated bit (0x40000000)", 0x4000_0000, Box::new(|_| {})),
    ];
    for (name, modes, fill) in &cases {
        let mut t = Timex::new(*modes);
        fill(&mut t);
        let a = adjtimex(&mut t);
        let mut t = Timex::new(*modes);
        fill(&mut t);
        let c = clock_adjtime(REALTIME, &mut t);
        let mut t = Timex::new(*modes);
        fill(&mut t);
        let m = clock_adjtime(MONOTONIC, &mut t);
        show(name, format!("adjtimex {} REALTIME {} MONOTONIC {}", r(a), r(c), r(m)));
    }
    say("adjtimex(ADJ_FREQUENCY) into NULL", unsafe { sys(NR_ADJTIMEX, 0, 0, 0, 0, 0, 0) });

    println!("## clock_settime and settimeofday, without CAP_SYS_TIME");
    let (s, n) = now(REALTIME);
    let set = |clock: i64, sec: i64, nsec: i64| {
        let ts = [sec, nsec];
        unsafe { sys(NR_CLOCK_SETTIME, clock, ts.as_ptr() as i64, 0, 0, 0, 0) }
    };
    say("clock_settime(REALTIME, now)", set(REALTIME, s, n));
    say("clock_settime(REALTIME, nsec -1)", set(REALTIME, s, -1));
    say("clock_settime(REALTIME, nsec 1e9)", set(REALTIME, s, 1_000_000_000));
    say("clock_settime(REALTIME, sec -1)", set(REALTIME, -1, 0));
    say("clock_settime(REALTIME, sec LLONG_MAX)", set(REALTIME, i64::MAX, 0));
    say("clock_settime(REALTIME, NULL)", unsafe { sys(NR_CLOCK_SETTIME, 0, 0, 0, 0, 0, 0) });
    let (ms, mn) = now(MONOTONIC);
    say("clock_settime(MONOTONIC, now)", set(MONOTONIC, ms, mn));
    say("clock_settime(MONOTONIC, NULL)", unsafe { sys(NR_CLOCK_SETTIME, 1, 0, 0, 0, 0, 0) });
    say("clock_settime(PROCESS_CPUTIME_ID, 0)", set(2, 0, 0));
    say("clock_settime(BOOTTIME, now)", set(7, ms, mn));
    let (ts, tn) = now(11);
    say("clock_settime(TAI, now)", set(11, ts, tn));
    say("clock_settime(99, now)", set(99, s, n));
    say("clock_settime(99, NULL)", unsafe { sys(NR_CLOCK_SETTIME, 99, 0, 0, 0, 0, 0) });

    let stod = |tv: Option<[i64; 2]>, tz: Option<[i32; 2]>| {
        let tvp = tv.as_ref().map_or(0, |v| v.as_ptr() as i64);
        let tzp = tz.as_ref().map_or(0, |v| v.as_ptr() as i64);
        unsafe { sys(NR_SETTIMEOFDAY, tvp, tzp, 0, 0, 0, 0) }
    };
    let (s, n) = now(REALTIME);
    say("settimeofday(NULL, NULL)", stod(None, None));
    say("settimeofday(now, NULL)", stod(Some([s, n / 1000]), None));
    say("settimeofday(usec 1e6, NULL)", stod(Some([s, 1_000_000]), None));
    say("settimeofday(usec -1, NULL)", stod(Some([s, -1]), None));
    say("settimeofday(sec -1, NULL)", stod(Some([-1, 0]), None));
    say("settimeofday(NULL, tz {0, 0})", stod(None, Some([0, 0])));
    say("settimeofday(NULL, tz minuteswest 1000)", stod(None, Some([1000, 0])));
    say("settimeofday(unmapped, NULL)", unsafe { sys(NR_SETTIMEOFDAY, 8, 0, 0, 0, 0, 0) });
    say("settimeofday(NULL, unmapped)", unsafe { sys(NR_SETTIMEOFDAY, 0, 8, 0, 0, 0, 0) });
}

fn timerfd_ticks() {
    println!("## TFD_IOC_SET_TICKS");
    const SET_TICKS: i64 = 0x4008_5400;
    let fd = unsafe { sys(NR_TIMERFD_CREATE, MONOTONIC, libc::O_NONBLOCK as i64, 0, 0, 0, 0) };
    let ticks = |v: u64| unsafe { sys(NR_IOCTL, fd, SET_TICKS, &v as *const u64 as i64, 0, 0, 0) };
    say("ticks 5", ticks(5));
    let mut n = 0u64;
    let got = unsafe { sys(NR_READ, fd, &mut n as *mut u64 as i64, 8, 0, 0, 0) };
    show("  read", format!("{} count {n}", r(got)));
    say("ticks 0", ticks(0));
    say("ticks NULL", unsafe { sys(NR_IOCTL, fd, SET_TICKS, 0, 0, 0, 0) });
    let spec = [0i64, 0, 100, 0];
    unsafe { sys(NR_TIMERFD_SETTIME, fd, 0, spec.as_ptr() as i64, 0, 0, 0) };
    say("ticks 3 on an armed timer", ticks(3));
    let got = unsafe { sys(NR_READ, fd, &mut n as *mut u64 as i64, 8, 0, 0, 0) };
    show("  read", format!("{} count {n}", r(got)));
    let p = unsafe { libc::eventfd(0, 0) } as i64;
    let v = 1u64;
    say("ticks on an eventfd", unsafe { sys(NR_IOCTL, p, SET_TICKS, &v as *const u64 as i64, 0, 0, 0) });
    unsafe {
        libc::close(p as i32);
        libc::close(fd as i32);
    }
}

fn poll_writeback() {
    println!("## ppoll and pselect6, the timeout written back");
    let mut ts = [0i64, 10_000_000];
    let ret = unsafe { sys(NR_PPOLL, 0, 0, ts.as_mut_ptr() as i64, 0, 8, 0) };
    say("ppoll(0 fds, 10 ms)", ret);
    show("  the timeout after", format!("{}s {}ns", ts[0], ts[1]));
    let mut ts = [5i64, 0];
    let mut fds = [libc::pollfd { fd: 0, events: libc::POLLOUT, revents: 0 }];
    let out = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY) };
    fds[0].fd = out;
    let ret = unsafe { sys(NR_PPOLL, fds.as_mut_ptr() as i64, 1, ts.as_mut_ptr() as i64, 0, 8, 0) };
    say("ppoll(a ready fd, 5 s)", ret);
    show("  the timeout after is below 5 s and above 4 s", ts[0] == 4 && ts[1] > 0);
    let mut ts = [0i64, 10_000_000];
    let ret = unsafe { sys(NR_PSELECT6, 0, 0, 0, 0, ts.as_mut_ptr() as i64, 0) };
    say("pselect6(0, 10 ms)", ret);
    show("  the timeout after", format!("{}s {}ns", ts[0], ts[1]));
    let mask = 0u64;
    let mut ts = [0i64, 0];
    let ret = unsafe {
        sys(NR_PPOLL, 0, 0, ts.as_mut_ptr() as i64, &mask as *const u64 as i64, (1 << 32) | 8, 0)
    };
    say("ppoll, a mask with sigsetsize 1<<32 | 8", ret);
    unsafe { libc::close(out) };
}

fn main() {
    read_only();
    per_clock();
    sigev_thread_id();
    setting();
    timerfd_ticks();
    poll_writeback();
}
