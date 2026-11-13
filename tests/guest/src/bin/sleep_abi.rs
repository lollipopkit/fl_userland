//! `nanosleep` and `clock_nanosleep` at the syscall boundary.
//!
//! Through `syscall(2)` rather than libc, because libc validates the flags and
//! the clock itself for some of these and never reaches the kernel.
//!
//! What this pins:
//!
//! - **An absolute sleep ends at the deadline**, not a fixed duration after the
//!   clock was read. The C worked out `deadline - now` once and slept for that
//!   long, so anything that delayed the thread in between came out of the far
//!   end.
//! - **A flag that is not `TIMER_ABSTIME` is ignored, not refused.** Written
//!   the other way round first, from memory, and a real arm64 kernel said no:
//!   `SYSCALL_DEFINE4(clock_nanosleep, ...)` tests `flags & TIMER_ABSTIME` and
//!   never `flags & ~TIMER_ABSTIME`, so an unknown bit makes a *relative*
//!   sleep that succeeds.
//!
//! Compared against a real kernel by `differential.sh`.

use guest_tests::{Harness, check};

const TIMER_ABSTIME: i64 = 1;
const CLOCK_REALTIME: i64 = 0;
const CLOCK_MONOTONIC: i64 = 1;

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

fn clock_nanosleep(clock: i64, flags: i64, req: *const Timespec, rem: *mut Timespec) -> i64 {
    unsafe { libc::syscall(libc::SYS_clock_nanosleep, clock, flags, req, rem) }
}

fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> i64 {
    unsafe { libc::syscall(libc::SYS_nanosleep, req, rem) }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn now(clock: i64) -> Timespec {
    let mut ts = Timespec::default();
    unsafe { libc::syscall(libc::SYS_clock_gettime, clock, &mut ts) };
    ts
}

fn ns_between(a: Timespec, b: Timespec) -> i64 {
    (b.sec - a.sec) * 1_000_000_000 + (b.nsec - a.nsec)
}

fn main() {
    let mut h = Harness::new();

    h.group("an-unknown-flag-is-ignored-not-refused");
    let req = Timespec { sec: 0, nsec: 1_000_000 };
    // Bit 0 clear, so each of these is a *relative* one-millisecond sleep.
    for odd in [2i64, 4, 0x8000_0000] {
        check!(
            h,
            clock_nanosleep(CLOCK_MONOTONIC, odd, &req, std::ptr::null_mut()) == 0,
            "flags {odd:#x} is a relative sleep: {}",
            errno()
        );
    }
    // Bit 0 set, so this one is absolute -- and a deadline of a millisecond
    // after the epoch has long passed.
    let past = Timespec { sec: 1, nsec: 0 };
    check!(
        h,
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME | 2, &past, std::ptr::null_mut()) == 0,
        "and TIMER_ABSTIME with rubbish beside it is still absolute"
    );

    h.group("a-clock-that-is-not-a-clock-is-einval");
    // 8..11 are the alarm clocks, which a real kernel has and answers EPERM for
    // without CAP_WAKE_ALARM -- a different answer, and not one to assert
    // against here.
    for bad in [100i64, 0x7fff_ffff] {
        check!(
            h,
            clock_nanosleep(bad, 0, &req, std::ptr::null_mut()) == -1 && errno() == libc::EINVAL,
            "clock {bad}: errno {}",
            errno()
        );
    }

    h.group("a-denormalised-timespec-is-einval");
    for bad in [
        Timespec { sec: 0, nsec: -1 },
        Timespec { sec: -1, nsec: 0 },
        Timespec { sec: 0, nsec: 1_000_000_000 },
        Timespec { sec: 0, nsec: 2_000_000_000 },
    ] {
        check!(
            h,
            clock_nanosleep(CLOCK_MONOTONIC, 0, &bad, std::ptr::null_mut()) == -1
                && errno() == libc::EINVAL,
            "{bad:?}: errno {}",
            errno()
        );
        check!(
            h,
            nanosleep(&bad, std::ptr::null_mut()) == -1 && errno() == libc::EINVAL,
            "nanosleep {bad:?}: errno {}",
            errno()
        );
    }

    h.group("a-relative-sleep-is-a-lower-bound");
    // 50 ms, which is long enough to measure and short enough not to matter.
    let want_ns = 50_000_000i64;
    let before = now(CLOCK_MONOTONIC);
    let r = nanosleep(
        &Timespec { sec: 0, nsec: want_ns },
        std::ptr::null_mut(),
    );
    let slept = ns_between(before, now(CLOCK_MONOTONIC));
    check!(h, r == 0, "nanosleep returned {r}");
    check!(
        h,
        slept >= want_ns,
        "slept {slept} ns, which is less than the {want_ns} asked for"
    );
    // Generous: this is an emulator, and the assertion is about the floor.
    check!(h, slept < want_ns * 8, "and not absurdly more: {slept} ns");

    h.group("an-absolute-deadline-ends-at-the-deadline");
    let start = now(CLOCK_MONOTONIC);
    let mut deadline = start;
    deadline.nsec += want_ns;
    if deadline.nsec >= 1_000_000_000 {
        deadline.sec += 1;
        deadline.nsec -= 1_000_000_000;
    }
    let r = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, std::ptr::null_mut());
    let after = now(CLOCK_MONOTONIC);
    check!(h, r == 0, "clock_nanosleep(TIMER_ABSTIME) returned {r}");
    check!(
        h,
        ns_between(deadline, after) >= 0,
        "woke {} ns before the deadline",
        -ns_between(deadline, after)
    );
    check!(
        h,
        ns_between(start, after) < want_ns * 8,
        "and not absurdly after it: {} ns", ns_between(start, after)
    );

    h.group("an-absolute-deadline-in-the-past-returns-at-once");
    let past = Timespec { sec: 1, nsec: 0 };
    let before = now(CLOCK_MONOTONIC);
    let r = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &past, std::ptr::null_mut());
    let took = ns_between(before, now(CLOCK_MONOTONIC));
    check!(h, r == 0, "returned {r}");
    check!(h, took < 20_000_000, "and promptly: {took} ns");

    h.group("realtime-and-monotonic-are-both-clocks");
    let mut ts = now(CLOCK_REALTIME);
    ts.nsec += 1_000_000;
    if ts.nsec >= 1_000_000_000 {
        ts.sec += 1;
        ts.nsec -= 1_000_000_000;
    }
    check!(
        h,
        clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, std::ptr::null_mut()) == 0,
        "CLOCK_REALTIME absolute"
    );
    check!(
        h,
        clock_nanosleep(CLOCK_REALTIME, 0, &req, std::ptr::null_mut()) == 0,
        "CLOCK_REALTIME relative"
    );

    h.group("times-returns-the-uptime");
    // Linux answers with the uptime in clock ticks, not zero. Measuring elapsed
    // time by subtracting two times() results is what the call is for and what
    // its man page shows; a kernel that answers 0 measures nothing.
    let t0 = unsafe { libc::syscall(libc::SYS_times, std::ptr::null_mut::<u8>()) };
    check!(h, t0 > 0, "times(NULL) is a tick count, not {t0}");
    // 100 ticks a second, so 50 ms is 5 of them -- and the assertion is only
    // that it moves, because an emulator's idea of "a tick later" is its own.
    nanosleep(&Timespec { sec: 0, nsec: 50_000_000 }, std::ptr::null_mut());
    let t1 = unsafe { libc::syscall(libc::SYS_times, std::ptr::null_mut::<u8>()) };
    check!(h, t1 > t0, "and it advances: {t0} then {t1}");

    h.group("a-zero-sleep-is-not-an-error");
    let zero = Timespec { sec: 0, nsec: 0 };
    check!(h, nanosleep(&zero, std::ptr::null_mut()) == 0, "nanosleep(0)");
    check!(
        h,
        clock_nanosleep(CLOCK_MONOTONIC, 0, &zero, std::ptr::null_mut()) == 0,
        "clock_nanosleep(0)"
    );

    std::process::exit(h.finish());
}
