//! What the timers answer: `timerfd`, `setitimer`, and the POSIX timer family.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! # Why this exists
//!
//! Every sleep, every timeout and every `alarm` in every guest is one of these,
//! and nothing compared them against a real kernel: `deadline_probe` asks about
//! one arithmetic rule and `timerfd`'s own crate has unit tests for its flag
//! validation, which is the implementation agreeing with itself. What a program
//! branches on is the errno for an argument it got wrong and the value a
//! `gettime` reads back, and neither had ever been measured.
//!
//! # Nothing here prints a duration
//!
//! The two sides are diffed as text, so a line carrying a nanosecond count
//! would differ on every run. Every answer is *classified*: `armed`, `disarmed`,
//! `at or below what was asked`, `counted 1`. A case that needs an interval to
//! elapse sleeps for several times its length, so the classification is the
//! same on a fast machine and a slow one.

use std::ffi::c_int;
use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<52} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EINVAL => "EINVAL",
        libc::EPERM => "EPERM",
        libc::EBADF => "EBADF",
        libc::EFAULT => "EFAULT",
        libc::EAGAIN => "EAGAIN",
        libc::ENOSYS => "ENOSYS",
        libc::EINTR => "EINTR",
        libc::ESRCH => "ESRCH",
        libc::ENODEV => "ENODEV",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::ERANGE => "ERANGE",
        libc::EOVERFLOW => "EOVERFLOW",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn r(v: i64) -> String {
    if v < 0 { named(errno()) } else { v.to_string() }
}

const TFD_NONBLOCK: c_int = 0o4000;
const TFD_CLOEXEC: c_int = 0o2000000;
const TFD_TIMER_ABSTIME: c_int = 1;
const TFD_TIMER_CANCEL_ON_SET: c_int = 2;

fn ts(sec: i64, nsec: i64) -> libc::timespec {
    libc::timespec { tv_sec: sec, tv_nsec: nsec }
}

fn spec(value: (i64, i64), interval: (i64, i64)) -> libc::itimerspec {
    libc::itimerspec {
        it_value: ts(value.0, value.1),
        it_interval: ts(interval.0, interval.1),
    }
}

fn zero_spec() -> libc::itimerspec {
    spec((0, 0), (0, 0))
}

/// How an `itimerspec` reads back, without printing a duration.
fn describe(it: &libc::itimerspec, asked: (i64, i64)) -> String {
    let armed = it.it_value.tv_sec != 0 || it.it_value.tv_nsec != 0;
    let interval = it.it_interval.tv_sec != 0 || it.it_interval.tv_nsec != 0;
    if !armed {
        return if interval { "disarmed, interval kept".into() } else { "disarmed".into() };
    }
    let want = asked.0 as i128 * 1_000_000_000 + asked.1 as i128;
    let have = it.it_value.tv_sec as i128 * 1_000_000_000 + it.it_value.tv_nsec as i128;
    let bound = if have <= want { "at or below what was asked" } else { "above what was asked" };
    if interval { format!("armed, {bound}, interval kept") } else { format!("armed, {bound}") }
}

fn main() {
    timerfd_creation();
    timerfd_arming();
    timerfd_reading();
    itimer();
    posix_timers();
    sleeping();
}

/// `timerfd_create`'s clocks and flags.
fn timerfd_creation() {
    println!("## timerfd_create");
    for (name, clock) in [
        ("CLOCK_REALTIME", libc::CLOCK_REALTIME),
        ("CLOCK_MONOTONIC", libc::CLOCK_MONOTONIC),
        ("CLOCK_BOOTTIME", libc::CLOCK_BOOTTIME),
        ("CLOCK_PROCESS_CPUTIME_ID", libc::CLOCK_PROCESS_CPUTIME_ID),
        ("CLOCK_THREAD_CPUTIME_ID", libc::CLOCK_THREAD_CPUTIME_ID),
    ] {
        let fd = unsafe { libc::timerfd_create(clock, 0) };
        line(&format!("  {name}"), if fd >= 0 { "a descriptor".into() } else { named(errno()) });
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
    let bad = unsafe { libc::timerfd_create(99, 0) };
    line("  clock 99", if bad >= 0 { "a descriptor".into() } else { named(errno()) });
    if bad >= 0 {
        unsafe { libc::close(bad) };
    }
    let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC) };
    line("  TFD_NONBLOCK|TFD_CLOEXEC", if fd >= 0 { "a descriptor".into() } else { named(errno()) });
    if fd >= 0 {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        line("    FD_CLOEXEC set", (flags & libc::FD_CLOEXEC != 0).to_string());
        unsafe { libc::close(fd) };
    }
    let bad = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0x40) };
    line("  a flag that means nothing", if bad >= 0 { "a descriptor".into() } else { named(errno()) });
    if bad >= 0 {
        unsafe { libc::close(bad) };
    }
}

/// `timerfd_settime` and `timerfd_gettime`.
fn timerfd_arming() {
    println!("## timerfd_settime");
    let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, TFD_NONBLOCK) };
    let mut old = zero_spec();
    let mut now = zero_spec();

    // An unarmed timer reads back as all zeroes.
    let rc = unsafe { libc::timerfd_gettime(fd, &mut now) };
    line("  gettime before any arm", format!("{} {}", r(rc as i64), describe(&now, (0, 0))));

    // A one-shot, then what gettime says about it.
    let rc = unsafe { libc::timerfd_settime(fd, 0, &spec((10, 0), (0, 0)), &mut old) };
    line("  settime(10s, no interval)", format!("{} old {}", r(rc as i64), describe(&old, (0, 0))));
    let rc = unsafe { libc::timerfd_gettime(fd, &mut now) };
    line("    gettime after", format!("{} {}", r(rc as i64), describe(&now, (10, 0))));

    // Re-arming answers the *old* value, which is what a caller saving and
    // restoring a timeout reads.
    let rc = unsafe { libc::timerfd_settime(fd, 0, &spec((20, 0), (5, 0)), &mut old) };
    line("  settime(20s, interval 5s)", format!("{} old {}", r(rc as i64), describe(&old, (10, 0))));
    let rc = unsafe { libc::timerfd_gettime(fd, &mut now) };
    line("    gettime after", format!("{} {}", r(rc as i64), describe(&now, (20, 0))));

    // Disarming keeps the interval field in what it reports back, and a
    // gettime then says disarmed.
    let rc = unsafe { libc::timerfd_settime(fd, 0, &zero_spec(), &mut old) };
    line("  settime(0), disarming", format!("{} old {}", r(rc as i64), describe(&old, (20, 0))));
    let rc = unsafe { libc::timerfd_gettime(fd, &mut now) };
    line("    gettime after", format!("{} {}", r(rc as i64), describe(&now, (0, 0))));

    // An interval with no value is a timer that never starts.
    let rc = unsafe { libc::timerfd_settime(fd, 0, &spec((0, 0), (1, 0)), std::ptr::null_mut()) };
    line("  settime(value 0, interval 1s)", r(rc as i64));
    let rc = unsafe { libc::timerfd_gettime(fd, &mut now) };
    line("    gettime after", format!("{} {}", r(rc as i64), describe(&now, (0, 0))));

    println!("## timerfd_settime, refused");
    for (what, s) in [
        ("nsec = 1_000_000_000", spec((0, 1_000_000_000), (0, 0))),
        ("nsec negative", spec((0, -1), (0, 0))),
        ("sec negative", spec((-1, 0), (0, 0))),
        ("interval nsec out of range", spec((1, 0), (0, 2_000_000_000))),
    ] {
        let rc = unsafe { libc::timerfd_settime(fd, 0, &s, std::ptr::null_mut()) };
        line(&format!("  {what}"), r(rc as i64));
    }
    let rc = unsafe { libc::timerfd_settime(fd, 0x40, &spec((1, 0), (0, 0)), std::ptr::null_mut()) };
    line("  a flag that means nothing", r(rc as i64));
    let rc = unsafe { libc::timerfd_settime(fd, 0, std::ptr::null(), std::ptr::null_mut()) };
    line("  a null new value", r(rc as i64));
    let rc = unsafe { libc::timerfd_gettime(fd, std::ptr::null_mut()) };
    line("  gettime into null", r(rc as i64));

    // The absolute form, with a deadline that has already passed: it fires at
    // once rather than being refused.
    let mut t = ts(0, 0);
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    let past = spec((t.tv_sec - 10, t.tv_nsec), (0, 0));
    let rc = unsafe { libc::timerfd_settime(fd, TFD_TIMER_ABSTIME, &past, std::ptr::null_mut()) };
    line("  ABSTIME with a deadline in the past", r(rc as i64));
    let mut count: u64 = 0;
    let n = unsafe { libc::read(fd, (&raw mut count).cast(), 8) };
    line("    reads", format!("{} count {count}", r(n as i64)));

    // The same with an interval: every whole interval since the deadline is an
    // expiration too, counted by the time `settime` returns. 10.5 s late on a
    // 1 s interval is eleven. This read raced the host timer until 2026-09-29
    // -- the expiry was counted asynchronously -- so it answered 1, or EAGAIN.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    let (sec, nsec) = if t.tv_nsec >= 500_000_000 {
        (t.tv_sec - 10, t.tv_nsec - 500_000_000)
    } else {
        (t.tv_sec - 11, t.tv_nsec + 500_000_000)
    };
    let past = spec((sec, nsec), (1, 0));
    let rc = unsafe { libc::timerfd_settime(fd, TFD_TIMER_ABSTIME, &past, std::ptr::null_mut()) };
    line("  ABSTIME 10.5s in the past, interval 1s", r(rc as i64));
    let mut count: u64 = 0;
    let n = unsafe { libc::read(fd, (&raw mut count).cast(), 8) };
    line("    reads", format!("{} count {count}", r(n as i64)));
    unsafe { libc::timerfd_settime(fd, 0, &zero_spec(), std::ptr::null_mut()) };

    // Zero disarms with the absolute flag too. It was subtracted from now and
    // armed a timer due at once, so the read below answered a count.
    unsafe { libc::timerfd_settime(fd, 0, &spec((10, 0), (0, 0)), std::ptr::null_mut()) };
    let rc = unsafe { libc::timerfd_settime(fd, TFD_TIMER_ABSTIME, &zero_spec(), std::ptr::null_mut()) };
    line("  ABSTIME with a zero value", r(rc as i64));
    let rc = unsafe { libc::timerfd_gettime(fd, &mut now) };
    line("    gettime after", format!("{} {}", r(rc as i64), describe(&now, (0, 0))));
    let mut count: u64 = 0;
    let n = unsafe { libc::read(fd, (&raw mut count).cast(), 8) };
    line("    reads", format!("{} count {count}", r(n as i64)));

    // A descriptor that is not a timerfd.
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let rc = unsafe { libc::timerfd_settime(p[0], 0, &spec((1, 0), (0, 0)), std::ptr::null_mut()) };
    line("  settime on a pipe", r(rc as i64));
    let rc = unsafe { libc::timerfd_gettime(p[0], &mut now) };
    line("  gettime on a pipe", r(rc as i64));
    let rc = unsafe { libc::timerfd_settime(-1, 0, &spec((1, 0), (0, 0)), std::ptr::null_mut()) };
    line("  settime on -1", r(rc as i64));
    unsafe {
        libc::close(p[0]);
        libc::close(p[1]);
        libc::close(fd);
    }
}

/// What a read takes out of a timerfd.
fn timerfd_reading() {
    println!("## reading a timerfd");
    let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, TFD_NONBLOCK) };

    // Nothing has expired.
    let mut count: u64 = 0;
    let n = unsafe { libc::read(fd, (&raw mut count).cast(), 8) };
    line("  read of an unarmed timer", r(n as i64));

    // A short buffer is refused whatever the state.
    let mut small = [0u8; 4];
    let n = unsafe { libc::read(fd, small.as_mut_ptr().cast(), 4) };
    line("  a four-byte read", r(n as i64));

    // One expiry.
    unsafe { libc::timerfd_settime(fd, 0, &spec((0, 50_000_000), (0, 0)), std::ptr::null_mut()) };
    unsafe { libc::usleep(200_000) };
    let n = unsafe { libc::read(fd, (&raw mut count).cast(), 8) };
    line("  after one expiry", format!("{} count {count}", r(n as i64)));
    let n = unsafe { libc::read(fd, (&raw mut count).cast(), 8) };
    line("  and again, having taken it", r(n as i64));

    // An interval that has run several times: the count is how many, and a
    // read takes them all. 50 ms every 50 ms for 350 ms is at least three.
    unsafe {
        libc::timerfd_settime(fd, 0, &spec((0, 50_000_000), (0, 50_000_000)), std::ptr::null_mut());
        libc::usleep(350_000);
    }
    let n = unsafe { libc::read(fd, (&raw mut count).cast(), 8) };
    line("  after an interval ran a few times", format!("{} counted at least 3 {}", r(n as i64), count >= 3));
    // Disarmed *before* the second read, because the interval is 50 ms and the
    // two reads are not guaranteed to be closer together than that on a slow
    // machine -- which would make this case answer "another expiry" on one side
    // and "nothing" on the other for a reason that is not a difference. What is
    // being asked is whether the first read took every accumulated expiry.
    unsafe { libc::timerfd_settime(fd, 0, &zero_spec(), std::ptr::null_mut()) };
    let n = unsafe { libc::read(fd, (&raw mut count).cast(), 8) };
    line("  and again, disarmed first", r(n as i64));

    // Disarming clears what has accumulated.
    unsafe {
        libc::timerfd_settime(fd, 0, &spec((0, 10_000_000), (0, 10_000_000)), std::ptr::null_mut());
        libc::usleep(100_000);
        libc::timerfd_settime(fd, 0, &zero_spec(), std::ptr::null_mut());
    }
    let n = unsafe { libc::read(fd, (&raw mut count).cast(), 8) };
    line("  read after disarming", r(n as i64));

    // CANCEL_ON_SET on a monotonic timer, which cannot be cancelled by a
    // clock change: Linux refuses the combination.
    let rc = unsafe {
        libc::timerfd_settime(
            fd,
            TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET,
            &spec((0, 0), (0, 0)),
            std::ptr::null_mut(),
        )
    };
    line("  CANCEL_ON_SET on a monotonic timer", r(rc as i64));
    unsafe { libc::close(fd) };
}

/// `setitimer` and `getitimer`.
fn itimer() {
    println!("## setitimer");
    let mut old: libc::itimerval = unsafe { std::mem::zeroed() };
    let mut now: libc::itimerval = unsafe { std::mem::zeroed() };
    let val = |sec: i64, usec: i64, isec: i64, iusec: i64| libc::itimerval {
        it_value: libc::timeval { tv_sec: sec, tv_usec: usec },
        it_interval: libc::timeval { tv_sec: isec, tv_usec: iusec },
    };
    let describe_val = |it: &libc::itimerval, asked: i64| -> String {
        let armed = it.it_value.tv_sec != 0 || it.it_value.tv_usec != 0;
        if !armed {
            return "disarmed".into();
        }
        let have = it.it_value.tv_sec as i128 * 1_000_000 + it.it_value.tv_usec as i128;
        if have <= asked as i128 { "armed, at or below what was asked".into() } else { "armed, above".into() }
    };

    for (name, which) in [
        ("ITIMER_REAL", libc::ITIMER_REAL),
        ("ITIMER_VIRTUAL", libc::ITIMER_VIRTUAL),
        ("ITIMER_PROF", libc::ITIMER_PROF),
    ] {
        let rc = unsafe { libc::setitimer(which, &val(10, 0, 0, 0), &mut old) };
        line(&format!("  {name} armed for 10s"), r(rc as i64));
        // The follow-ups name the timer too: they are three different subjects
        // and a shared label cannot be allowlisted for one of them.
        let rc = unsafe { libc::getitimer(which, &mut now) };
        line(&format!("  {name} getitimer after"), format!("{} {}", r(rc as i64), describe_val(&now, 10_000_000)));
        let rc = unsafe { libc::setitimer(which, &val(0, 0, 0, 0), &mut old) };
        line(&format!("  {name} disarming answers the old"), format!("{} {}", r(rc as i64), describe_val(&old, 10_000_000)));
    }

    // The argument rules.
    let rc = unsafe { libc::setitimer(9, &val(1, 0, 0, 0), std::ptr::null_mut()) };
    line("  which = 9", r(rc as i64));
    let rc = unsafe { libc::getitimer(9, &mut now) };
    line("  getitimer(9)", r(rc as i64));
    let rc = unsafe { libc::setitimer(libc::ITIMER_REAL, &val(0, 1_000_000, 0, 0), std::ptr::null_mut()) };
    line("  usec = 1_000_000", r(rc as i64));
    let rc = unsafe { libc::setitimer(libc::ITIMER_REAL, &val(0, -1, 0, 0), std::ptr::null_mut()) };
    line("  usec negative", r(rc as i64));
    let rc = unsafe { libc::setitimer(libc::ITIMER_REAL, std::ptr::null(), std::ptr::null_mut()) };
    line("  a null new value, which means disarm", r(rc as i64));
    let rc = unsafe { libc::getitimer(libc::ITIMER_REAL, std::ptr::null_mut()) };
    line("  getitimer into null", r(rc as i64));

    // alarm() is setitimer(ITIMER_REAL) with a coarser interface, and the two
    // are the same timer: an alarm replaces what setitimer armed.
    unsafe { libc::setitimer(libc::ITIMER_REAL, &val(30, 0, 0, 0), std::ptr::null_mut()) };
    let left = unsafe { libc::alarm(60) };
    line("  alarm(60) after setitimer(30s) answers", format!("{}", left <= 30 && left >= 28));
    let left = unsafe { libc::alarm(0) };
    line("  alarm(0) cancels and answers", format!("{}", left <= 60 && left >= 58));
    let rc = unsafe { libc::getitimer(libc::ITIMER_REAL, &mut now) };
    line("    getitimer after alarm(0)", format!("{} {}", r(rc as i64), describe_val(&now, 0)));
}

/// The POSIX timer family: `timer_create` and its four companions.
fn posix_timers() {
    println!("## POSIX timers");
    let mut id: libc::timer_t = std::ptr::null_mut();
    let mut ev: libc::sigevent = unsafe { std::mem::zeroed() };
    ev.sigev_notify = libc::SIGEV_NONE;
    let rc = unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &mut ev, &mut id) };
    line("  timer_create(SIGEV_NONE)", r(rc as i64));
    if rc == 0 {
        let mut now = zero_spec();
        let rc = unsafe { libc::timer_gettime(id, &mut now) };
        line("    gettime before arming", format!("{} {}", r(rc as i64), describe(&now, (0, 0))));
        let rc = unsafe { libc::timer_settime(id, 0, &spec((10, 0), (0, 0)), std::ptr::null_mut()) };
        line("    settime(10s)", r(rc as i64));
        let rc = unsafe { libc::timer_gettime(id, &mut now) };
        line("    gettime after", format!("{} {}", r(rc as i64), describe(&now, (10, 0))));
        let rc = unsafe { libc::timer_getoverrun(id) };
        line("    getoverrun on a timer that has not fired", r(rc as i64));
        let rc = unsafe { libc::timer_delete(id) };
        line("    timer_delete", r(rc as i64));
        let rc = unsafe { libc::timer_gettime(id, &mut now) };
        line("    gettime after deleting", r(rc as i64));
        let rc = unsafe { libc::timer_delete(id) };
        line("    deleting twice", r(rc as i64));
    }

    // A signal-notifying timer, which is what a program actually uses.
    let mut ev: libc::sigevent = unsafe { std::mem::zeroed() };
    ev.sigev_notify = libc::SIGEV_SIGNAL;
    ev.sigev_signo = libc::SIGUSR1;
    let mut id2: libc::timer_t = std::ptr::null_mut();
    let rc = unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &mut ev, &mut id2) };
    line("  timer_create(SIGEV_SIGNAL, SIGUSR1)", r(rc as i64));
    if rc == 0 {
        // Blocked, so the expiry is observable as a pending signal rather than
        // as a handler this probe would have to synchronise with.
        let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR1);
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        }
        unsafe { libc::timer_settime(id2, 0, &spec((0, 50_000_000), (0, 0)), std::ptr::null_mut()) };
        unsafe { libc::usleep(250_000) };
        let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigpending(&mut pending) };
        line("    SIGUSR1 pending after it fired", (unsafe { libc::sigismember(&pending, libc::SIGUSR1) } == 1).to_string());
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let t = ts(0, 0);
        let got = unsafe { libc::sigtimedwait(&set, &mut info, &t) };
        line("    sigtimedwait takes it", r(got as i64));
        if got == libc::SIGUSR1 {
            // SI_TIMER is -2; what a program reads to tell a timer's signal
            // from a kill.
            line("      si_code is SI_TIMER", (info.si_code == -2).to_string());
        }
        unsafe {
            libc::timer_delete(id2);
            libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        }
    }

    // The refusals.
    let mut id3: libc::timer_t = std::ptr::null_mut();
    let mut bad: libc::sigevent = unsafe { std::mem::zeroed() };
    bad.sigev_notify = 99;
    let rc = unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &mut bad, &mut id3) };
    line("  timer_create with sigev_notify 99", r(rc as i64));
    let mut sig: libc::sigevent = unsafe { std::mem::zeroed() };
    sig.sigev_notify = libc::SIGEV_SIGNAL;
    sig.sigev_signo = 99;
    let rc = unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &mut sig, &mut id3) };
    line("  timer_create with signal 99", r(rc as i64));
    let rc = unsafe { libc::timer_create(99, std::ptr::null_mut(), &mut id3) };
    line("  timer_create with clock 99", r(rc as i64));
}

/// `nanosleep` and `clock_nanosleep`, whose argument rules are the same shape.
fn sleeping() {
    println!("## sleeping");
    let mut rem = ts(0, 0);
    let rc = unsafe { libc::nanosleep(&ts(0, 1_000_000_000), &mut rem) };
    line("  nanosleep(nsec = 1_000_000_000)", r(rc as i64));
    let rc = unsafe { libc::nanosleep(&ts(-1, 0), &mut rem) };
    line("  nanosleep(sec = -1)", r(rc as i64));
    let rc = unsafe { libc::nanosleep(&ts(0, 0), &mut rem) };
    line("  nanosleep(0)", r(rc as i64));

    let rc = unsafe {
        libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &ts(0, 1_000_000), std::ptr::null_mut())
    };
    line("  clock_nanosleep(1ms)", r(rc as i64));
    // clock_nanosleep answers a positive errno rather than setting errno.
    let rc = unsafe {
        libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &ts(0, -1), std::ptr::null_mut())
    };
    line("  clock_nanosleep(nsec = -1)", if rc == 0 { "0".into() } else { named(rc) });
    let rc = unsafe {
        libc::clock_nanosleep(99, 0, &ts(0, 1000), std::ptr::null_mut())
    };
    line("  clock_nanosleep(clock 99)", if rc == 0 { "0".into() } else { named(rc) });
    // An absolute deadline already past returns at once, not an error.
    let mut t = ts(0, 0);
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    let rc = unsafe {
        libc::clock_nanosleep(
            libc::CLOCK_MONOTONIC,
            libc::TIMER_ABSTIME,
            &ts(t.tv_sec - 5, t.tv_nsec),
            std::ptr::null_mut(),
        )
    };
    line("  clock_nanosleep(ABSTIME, already past)", if rc == 0 { "0".into() } else { named(rc) });
    // CLOCK_THREAD_CPUTIME_ID is not a clock you may sleep on.
    let rc = unsafe {
        libc::clock_nanosleep(libc::CLOCK_THREAD_CPUTIME_ID, 0, &ts(0, 1000), std::ptr::null_mut())
    };
    line("  clock_nanosleep(CLOCK_THREAD_CPUTIME_ID)", if rc == 0 { "0".into() } else { named(rc) });
}
