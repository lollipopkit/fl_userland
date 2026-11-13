//! `nanosleep`, `clock_nanosleep` and `setitimer`: what the guest is promised.

use guest_tests::{Harness, check};

fn ms_since(t0: std::time::Instant) -> u128 {
    t0.elapsed().as_millis()
}

fn main() {
    let mut h = Harness::new();

    h.group("nanosleep-actually-sleeps");
    // A sleep is a lower bound. `nanosleep` had a fast path that called
    // sched_yield() and returned 0 for anything up to a millisecond, so a
    // program polling every 1ms was spinning instead.
    const N: u32 = 200;
    let req = libc::timespec { tv_sec: 0, tv_nsec: 1_000_000 };
    let t0 = std::time::Instant::now();
    for _ in 0..N {
        let mut rem = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::nanosleep(&req, &mut rem) };
    }
    let took = ms_since(t0);
    check!(h, took >= 150,
        "{N} sleeps of 1ms took at least 150ms: {took}ms");

    // And a sleep just over the old threshold, which never took the fast path,
    // as the control: if this one is also short the measurement is broken
    // rather than the fast path being the cause.
    let req2 = libc::timespec { tv_sec: 0, tv_nsec: 2_000_000 };
    let t1 = std::time::Instant::now();
    for _ in 0..100 {
        let mut rem = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::nanosleep(&req2, &mut rem) };
    }
    let took2 = ms_since(t1);
    check!(h, took2 >= 150, "control: 100 sleeps of 2ms took at least 150ms: {took2}ms");

    h.group("nanosleep-rejects-nonsense");
    for (sec, nsec) in [(0i64, 1_000_000_000i64), (0, -1), (-1, 0), (0, i64::MAX)] {
        let req = libc::timespec { tv_sec: sec as _, tv_nsec: nsec as _ };
        let mut rem = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let r = unsafe { libc::nanosleep(&req, &mut rem) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        check!(h, r == -1 && e == libc::EINVAL,
            "nanosleep({sec}, {nsec}) is EINVAL: r={r} errno={e}");
    }

    h.group("clock-nanosleep");
    for (sec, nsec) in [(0i64, 1_000_000_000i64), (0, -1), (-1, 0)] {
        let req = libc::timespec { tv_sec: sec as _, tv_nsec: nsec as _ };
        let r = unsafe {
            libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &req, std::ptr::null_mut())
        };
        // clock_nanosleep reports through the return value, not errno.
        check!(h, r == libc::EINVAL,
            "clock_nanosleep({sec}, {nsec}) is EINVAL: r={r}");
    }
    // And a real one sleeps.
    let req = libc::timespec { tv_sec: 0, tv_nsec: 20_000_000 };
    let t2 = std::time::Instant::now();
    let r = unsafe { libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &req, std::ptr::null_mut()) };
    let took3 = ms_since(t2);
    check!(h, r == 0 && took3 >= 15, "clock_nanosleep(20ms) slept: r={r} took={took3}ms");

    h.group("setitimer-validates");
    // Linux: tv_usec outside [0, 1000000) is EINVAL, for either field.
    let cases: [(i64, i64, i64, i64); 4] = [
        (0, 2_000_000, 0, 0),
        (0, -1, 0, 0),
        (0, 0, 0, 2_000_000),
        (0, 0, 0, -1),
    ];
    for (vs, vu, is, iu) in cases {
        let it = libc::itimerval {
            it_value: libc::timeval { tv_sec: vs as _, tv_usec: vu as _ },
            it_interval: libc::timeval { tv_sec: is as _, tv_usec: iu as _ },
        };
        let r = unsafe { libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        check!(h, r == -1 && e == libc::EINVAL,
            "setitimer(value {vs}s {vu}us, interval {is}s {iu}us) is EINVAL: r={r} errno={e}");
    }
    // The control: a legal one is still accepted, so the check above is not
    // "setitimer always fails".
    let ok = libc::itimerval {
        it_value: libc::timeval { tv_sec: 0, tv_usec: 999_999 },
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
    };
    let r = unsafe { libc::setitimer(libc::ITIMER_REAL, &ok, std::ptr::null_mut()) };
    check!(h, r == 0, "control: a legal setitimer is still accepted: r={r}");
    let off = libc::itimerval {
        it_value: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
    };
    unsafe { libc::setitimer(libc::ITIMER_REAL, &off, std::ptr::null_mut()) };

    h.group("itimer-remaining");
    // aarch64 Linux has no `alarm` syscall -- musl builds alarm() on setitimer
    // and does its own rounding -- so what this exercises is sys_setitimer's
    // old_value path, which is where the remaining time is converted back from
    // nanoseconds to a timeval.
    //
    // Said because the first version of this group called alarm() and asserted
    // a rounding rule. It passed against the kernel with that rule and against
    // the kernel without it, because the rule under test was musl's. The
    // sys_alarm it was aimed at is unreachable from this guest and has been
    // removed.
    unsafe { libc::signal(libc::SIGALRM, libc::SIG_IGN) };
    let ten = libc::itimerval {
        it_value: libc::timeval { tv_sec: 10, tv_usec: 0 },
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
    };
    let r = unsafe { libc::setitimer(libc::ITIMER_REAL, &ten, std::ptr::null_mut()) };
    check!(h, r == 0, "arming a 10s ITIMER_REAL: r={r}");

    std::thread::sleep(std::time::Duration::from_millis(700));
    let off = libc::itimerval {
        it_value: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
    };
    let mut old: libc::itimerval = unsafe { std::mem::zeroed() };
    unsafe { libc::setitimer(libc::ITIMER_REAL, &off, &mut old) };
    let left_us = old.it_value.tv_sec as i64 * 1_000_000 + old.it_value.tv_usec as i64;
    check!(h, (8_900_000..=9_500_000).contains(&left_us),
        "the remaining time comes back as ~9.3s: {}s {}us ({left_us}us)",
        old.it_value.tv_sec, old.it_value.tv_usec);
    // tv_usec is a microsecond field. If the nanosecond-to-microsecond divide
    // went missing it would hold ~3e8 and the range above would catch it, but
    // say it directly too.
    check!(h, (0..1_000_000).contains(&(old.it_value.tv_usec as i64)),
        "and tv_usec is microseconds, in range: {}", old.it_value.tv_usec);
    check!(h, old.it_interval.tv_sec == 0 && old.it_interval.tv_usec == 0,
        "a one-shot timer reports no interval: {}s {}us",
        old.it_interval.tv_sec, old.it_interval.tv_usec);

    // Cancelled means cancelled: getitimer reports zeroes, not the old value.
    let mut now: libc::itimerval = unsafe { std::mem::zeroed() };
    unsafe { libc::getitimer(libc::ITIMER_REAL, &mut now) };
    check!(h, now.it_value.tv_sec == 0 && now.it_value.tv_usec == 0,
        "a cancelled timer reads back as zero: {}s {}us",
        now.it_value.tv_sec, now.it_value.tv_usec);
    unsafe { libc::signal(libc::SIGALRM, libc::SIG_DFL) };

    std::process::exit(h.finish());
}
