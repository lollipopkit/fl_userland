//! Sleeping and timers.
//!
//! `kernel/time.c` is 629 lines with nothing covering it: no test in the tree
//! calls `nanosleep`, `setitimer` or `timer_create`. Every program that waits
//! for anything goes through one of them.
//!
//! The checks are about the parts a program can be broken by rather than the
//! precise durations, which nothing can promise: that a sleep does not return
//! *early*, that an interrupted one reports how much is left, that an absolute
//! deadline in the past returns at once rather than sleeping for its value,
//! and that a timer that fires reports what remains.

use std::sync::atomic::{AtomicU32, Ordering};

use guest_tests::{Harness, check, check_fails, sys};

static ALARMS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_alarm(_: libc::c_int) {
    ALARMS.fetch_add(1, Ordering::Relaxed);
}

fn ts(sec: i64, nsec: i64) -> libc::timespec {
    libc::timespec { tv_sec: sec, tv_nsec: nsec }
}

fn now(clock: libc::clockid_t) -> libc::timespec {
    let mut t = ts(0, 0);
    unsafe { libc::clock_gettime(clock, &mut t) };
    t
}

fn elapsed_ms(a: &libc::timespec, b: &libc::timespec) -> i64 {
    (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1_000_000
}

fn install(sig: libc::c_int, handler: extern "C" fn(libc::c_int)) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn t_clocks(h: &mut Harness) {
    h.group("clocks");
    for (id, name) in [
        (libc::CLOCK_REALTIME, "CLOCK_REALTIME"),
        (libc::CLOCK_MONOTONIC, "CLOCK_MONOTONIC"),
        (libc::CLOCK_BOOTTIME, "CLOCK_BOOTTIME"),
        (libc::CLOCK_PROCESS_CPUTIME_ID, "CLOCK_PROCESS_CPUTIME_ID"),
        (libc::CLOCK_THREAD_CPUTIME_ID, "CLOCK_THREAD_CPUTIME_ID"),
    ] {
        let mut t = ts(-1, -1);
        let r = unsafe { libc::clock_gettime(id, &mut t) };
        check!(
            h,
            r == 0 && t.tv_sec >= 0 && (0..1_000_000_000).contains(&t.tv_nsec),
            "{name}: r={r} {}s {}ns",
            t.tv_sec,
            t.tv_nsec
        );
        let mut res = ts(-1, -1);
        let r = unsafe { libc::clock_getres(id, &mut res) };
        check!(
            h,
            r == 0 && (res.tv_sec > 0 || res.tv_nsec > 0),
            "{name} resolution: r={r} {}ns",
            res.tv_nsec
        );
    }

    // MONOTONIC does not go backwards.
    let a = now(libc::CLOCK_MONOTONIC);
    let b = now(libc::CLOCK_MONOTONIC);
    check!(
        h,
        elapsed_ms(&a, &b) >= 0,
        "CLOCK_MONOTONIC does not go backwards"
    );

    check_fails!(
        h,
        {
            let mut t = ts(0, 0);
            unsafe { libc::clock_gettime(99, &mut t) }
        } as i64,
        libc::EINVAL,
        "an unknown clock"
    );
}

fn t_nanosleep(h: &mut Harness) {
    h.group("nanosleep");

    // A sleep must not return early. Late is the platform's business.
    let a = now(libc::CLOCK_MONOTONIC);
    let r = unsafe { libc::nanosleep(&ts(0, 80_000_000), std::ptr::null_mut()) };
    let b = now(libc::CLOCK_MONOTONIC);
    check!(h, r == 0, "nanosleep returned {r}");
    check!(
        h,
        elapsed_ms(&a, &b) >= 75,
        "80ms is not returned from early: {}ms",
        elapsed_ms(&a, &b)
    );

    // Out-of-range nanoseconds.
    check_fails!(
        h,
        unsafe { libc::nanosleep(&ts(0, 1_000_000_000), std::ptr::null_mut()) } as i64,
        libc::EINVAL,
        "tv_nsec of a full second"
    );
    check_fails!(
        h,
        unsafe { libc::nanosleep(&ts(0, -1), std::ptr::null_mut()) } as i64,
        libc::EINVAL,
        "a negative tv_nsec"
    );
    check_fails!(
        h,
        unsafe { libc::nanosleep(&ts(-1, 0), std::ptr::null_mut()) } as i64,
        libc::EINVAL,
        "a negative tv_sec"
    );

    // A zero sleep is legal and returns at once.
    let a = now(libc::CLOCK_MONOTONIC);
    let r = unsafe { libc::nanosleep(&ts(0, 0), std::ptr::null_mut()) };
    check!(
        h,
        r == 0 && elapsed_ms(&a, &now(libc::CLOCK_MONOTONIC)) < 50,
        "a zero sleep returns at once: r={r}"
    );
}

/// An interrupted sleep says how much of it is left, which is what a caller
/// needs to finish it.
fn t_interrupted_sleep(h: &mut Harness) {
    h.group("interrupted");
    install(libc::SIGALRM, on_alarm);
    ALARMS.store(0, Ordering::Relaxed);

    let mut remaining = ts(-1, -1);
    unsafe { libc::alarm(1) };
    let a = now(libc::CLOCK_MONOTONIC);
    let r = unsafe { libc::nanosleep(&ts(5, 0), &mut remaining) };
    let waited = elapsed_ms(&a, &now(libc::CLOCK_MONOTONIC));
    unsafe { libc::alarm(0) };

    check!(
        h,
        r == -1 && sys::errno() == libc::EINTR,
        "a sleep cut short by a signal is EINTR: r={r} errno={}",
        sys::errno()
    );
    check!(h, ALARMS.load(Ordering::Relaxed) == 1, "the handler ran once");
    check!(
        h,
        (500..2500).contains(&waited),
        "and it returned when the signal arrived, not at the end: {waited}ms"
    );
    let left_ms = remaining.tv_sec * 1000 + remaining.tv_nsec / 1_000_000;
    check!(
        h,
        (0..1_000_000_000).contains(&remaining.tv_nsec) && remaining.tv_sec >= 0,
        "the remaining time is a valid timespec: {}s {}ns",
        remaining.tv_sec,
        remaining.tv_nsec
    );
    check!(
        h,
        (2500..5000).contains(&left_ms),
        "and is about what is left of five seconds: {left_ms}ms"
    );
}

/// An absolute deadline is a deadline, not a duration. One in the past is not
/// a five-second sleep.
fn t_absolute_deadline(h: &mut Harness) {
    h.group("abstime");

    let mut past = now(libc::CLOCK_MONOTONIC);
    past.tv_sec -= 5;
    let a = now(libc::CLOCK_MONOTONIC);
    let r = unsafe {
        libc::clock_nanosleep(libc::CLOCK_MONOTONIC, libc::TIMER_ABSTIME, &past, std::ptr::null_mut())
    };
    let waited = elapsed_ms(&a, &now(libc::CLOCK_MONOTONIC));
    check!(h, r == 0, "a deadline in the past returns 0, got {r}");
    check!(
        h,
        waited < 100,
        "and returns at once rather than sleeping: {waited}ms"
    );

    // A deadline 80ms out.
    let mut target = now(libc::CLOCK_MONOTONIC);
    target.tv_nsec += 80_000_000;
    if target.tv_nsec >= 1_000_000_000 {
        target.tv_sec += 1;
        target.tv_nsec -= 1_000_000_000;
    }
    let a = now(libc::CLOCK_MONOTONIC);
    let r = unsafe {
        libc::clock_nanosleep(libc::CLOCK_MONOTONIC, libc::TIMER_ABSTIME, &target, std::ptr::null_mut())
    };
    let waited = elapsed_ms(&a, &now(libc::CLOCK_MONOTONIC));
    check!(h, r == 0, "sleeping to a deadline returned {r}");
    check!(h, waited >= 70, "and waited for it: {waited}ms");

    // The relative form of the same call.
    let a = now(libc::CLOCK_MONOTONIC);
    let r = unsafe {
        libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &ts(0, 60_000_000), std::ptr::null_mut())
    };
    check!(
        h,
        r == 0 && elapsed_ms(&a, &now(libc::CLOCK_MONOTONIC)) >= 55,
        "the relative form sleeps too: r={r}"
    );

    // clock_nanosleep reports its error as a return value, not through errno.
    let r = unsafe {
        libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &ts(0, 1_000_000_000), std::ptr::null_mut())
    };
    check!(
        h,
        r == libc::EINVAL,
        "clock_nanosleep returns the errno rather than setting it: {r}"
    );
}

fn t_alarm_and_itimer(h: &mut Harness) {
    h.group("itimer");
    install(libc::SIGALRM, on_alarm);
    ALARMS.store(0, Ordering::Relaxed);

    // alarm() answers how much was left of the previous one.
    unsafe { libc::alarm(0) };
    let prev = unsafe { libc::alarm(10) };
    check!(h, prev == 0, "alarm with nothing armed reports 0, got {prev}");
    let prev = unsafe { libc::alarm(20) };
    check!(
        h,
        (9..=10).contains(&prev),
        "and then reports what was left of the last: {prev}"
    );
    let prev = unsafe { libc::alarm(0) };
    check!(h, (19..=20).contains(&prev), "cancelling reports the same: {prev}");

    // getitimer sees what setitimer armed, and counts down.
    let want = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: 5, tv_usec: 0 },
    };
    let r = unsafe { libc::setitimer(libc::ITIMER_REAL, &want, std::ptr::null_mut()) };
    check!(h, r == 0, "setitimer returned {r}");
    let mut got: libc::itimerval = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::getitimer(libc::ITIMER_REAL, &mut got) };
    check!(
        h,
        r == 0 && got.it_value.tv_sec <= 5 && got.it_value.tv_sec >= 3,
        "getitimer reports the time left: r={r} {}s",
        got.it_value.tv_sec
    );

    // Disarming, and the old value coming back.
    let off: libc::itimerval = unsafe { std::mem::zeroed() };
    let mut old: libc::itimerval = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::setitimer(libc::ITIMER_REAL, &off, &mut old) };
    check!(
        h,
        r == 0 && old.it_value.tv_sec >= 3,
        "disarming reports what was left: r={r} {}s",
        old.it_value.tv_sec
    );
    let mut got: libc::itimerval = unsafe { std::mem::zeroed() };
    unsafe { libc::getitimer(libc::ITIMER_REAL, &mut got) };
    check!(
        h,
        got.it_value.tv_sec == 0 && got.it_value.tv_usec == 0,
        "and it is disarmed: {}s {}us",
        got.it_value.tv_sec,
        got.it_value.tv_usec
    );

    // A short one that actually fires.
    ALARMS.store(0, Ordering::Relaxed);
    let want = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: 0, tv_usec: 60_000 },
    };
    unsafe { libc::setitimer(libc::ITIMER_REAL, &want, std::ptr::null_mut()) };
    let mut waited = 0;
    while ALARMS.load(Ordering::Relaxed) == 0 && waited < 2000 {
        unsafe { libc::usleep(20_000) };
        waited += 20;
    }
    check!(
        h,
        ALARMS.load(Ordering::Relaxed) == 1,
        "a 60ms ITIMER_REAL fires once within {waited}ms"
    );
    unsafe { libc::setitimer(libc::ITIMER_REAL, &off, std::ptr::null_mut()) };
}

/// POSIX timers: created, armed, fired, and asked what is left.
fn t_posix_timer(h: &mut Harness) {
    h.group("timer_create");
    install(libc::SIGUSR1, on_alarm);
    ALARMS.store(0, Ordering::Relaxed);

    let mut sev: libc::sigevent = unsafe { std::mem::zeroed() };
    sev.sigev_notify = libc::SIGEV_SIGNAL;
    sev.sigev_signo = libc::SIGUSR1;
    let mut id: libc::timer_t = std::ptr::null_mut();
    let r = unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut id) };
    if r != 0 {
        check!(h, false, "timer_create returned {r} errno {}", sys::errno());
        return;
    }
    check!(h, true, "timer_create");

    let spec = libc::itimerspec {
        it_interval: ts(0, 0),
        it_value: ts(3, 0),
    };
    let r = unsafe { libc::timer_settime(id, 0, &spec, std::ptr::null_mut()) };
    check!(h, r == 0, "timer_settime returned {r}");

    let mut cur: libc::itimerspec = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::timer_gettime(id, &mut cur) };
    check!(
        h,
        r == 0 && cur.it_value.tv_sec <= 3 && (cur.it_value.tv_sec > 0 || cur.it_value.tv_nsec > 0),
        "timer_gettime reports the time left: r={r} {}s {}ns",
        cur.it_value.tv_sec,
        cur.it_value.tv_nsec
    );

    // Re-arm short and let it fire.
    let spec = libc::itimerspec {
        it_interval: ts(0, 0),
        it_value: ts(0, 60_000_000),
    };
    unsafe { libc::timer_settime(id, 0, &spec, std::ptr::null_mut()) };
    let mut waited = 0;
    while ALARMS.load(Ordering::Relaxed) == 0 && waited < 2000 {
        unsafe { libc::usleep(20_000) };
        waited += 20;
    }
    check!(
        h,
        ALARMS.load(Ordering::Relaxed) >= 1,
        "the timer fires its signal within {waited}ms"
    );

    let r = unsafe { libc::timer_getoverrun(id) };
    check!(h, r >= 0, "timer_getoverrun returned {r}");
    let r = unsafe { libc::timer_delete(id) };
    check!(h, r == 0, "timer_delete returned {r}");

    unsafe { libc::signal(libc::SIGUSR1, libc::SIG_DFL) };
}

fn main() {
    let mut h = Harness::new();
    t_clocks(&mut h);
    t_nanosleep(&mut h);
    t_interrupted_sleep(&mut h);
    t_absolute_deadline(&mut h);
    t_alarm_and_itimer(&mut h);
    t_posix_timer(&mut h);
    std::process::exit(h.finish());
}
