//! The clocks: which ones exist, what they answer, and who may set one.
//!
//! Eight clock ids, two of which are not host clocks at all —
//! `CLOCK_PROCESS_CPUTIME_ID` and `CLOCK_THREAD_CPUTIME_ID` are answered from
//! this task's own accounting, and are the two most recently found returning
//! `EINVAL` because nothing mapped them.
//!
//! # What a container cannot answer
//!
//! `clock_settime` is mostly outside this test, and the reason is worth
//! recording. Docker's default seccomp profile **filters the syscall** unless
//! `CAP_SYS_TIME` is present, and answers `EPERM` for every argument — an
//! unknown clock, a clock with no setter, a malformed time. A comparison run
//! there reports what the filter does rather than what Linux does.
//!
//! The first version of this file asserted Linux's documented ordering
//! (`EINVAL` for an unknown clock and for a malformed time, *before* the
//! permission check) and the container said `EPERM` to all nine. Adding
//! `CAP_SYS_TIME` would answer it and would also let a mistake here move a
//! machine's wall clock, so the checks are gone instead of weakened.
//!
//! What is left is the part both sides really do agree on: an ordinary user may
//! not set the clock, and nothing here ever sets one.

use guest_tests::{Harness, check};

const REALTIME: i32 = 0;
const MONOTONIC: i32 = 1;
const PROCESS_CPUTIME: i32 = 2;
const THREAD_CPUTIME: i32 = 3;
const MONOTONIC_RAW: i32 = 4;
const REALTIME_COARSE: i32 = 5;
const MONOTONIC_COARSE: i32 = 6;
const BOOTTIME: i32 = 7;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn gettime(clock: i32) -> (i32, libc::timespec, i32) {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let r = unsafe { libc::clock_gettime(clock, &mut ts) };
    (r, ts, errno())
}

fn nanos(ts: &libc::timespec) -> i128 {
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

fn name(clock: i32) -> &'static str {
    match clock {
        0 => "CLOCK_REALTIME",
        1 => "CLOCK_MONOTONIC",
        2 => "CLOCK_PROCESS_CPUTIME_ID",
        3 => "CLOCK_THREAD_CPUTIME_ID",
        4 => "CLOCK_MONOTONIC_RAW",
        5 => "CLOCK_REALTIME_COARSE",
        6 => "CLOCK_MONOTONIC_COARSE",
        7 => "CLOCK_BOOTTIME",
        _ => "?",
    }
}

fn main() {
    let mut h = Harness::new();

    // In a child, because privilege is dropped at the bottom.
    let outer = unsafe { libc::fork() };
    if outer != 0 {
        let mut st = 0;
        unsafe { libc::waitpid(outer, &mut st, 0) };
        std::process::exit(if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 1 });
    }

    h.group("every-clock-answers");
    let all = [REALTIME, MONOTONIC, PROCESS_CPUTIME, THREAD_CPUTIME,
               MONOTONIC_RAW, REALTIME_COARSE, MONOTONIC_COARSE, BOOTTIME];
    for c in all {
        let (r, ts, e) = gettime(c);
        check!(h, r == 0, "clock_gettime({}) : r={r} errno={e}", name(c));
        check!(h, ts.tv_nsec >= 0 && ts.tv_nsec < 1_000_000_000,
            "and its nanoseconds are a nanosecond count: {}", ts.tv_nsec);
        let mut res = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let r = unsafe { libc::clock_getres(c, &mut res) };
        check!(h, r == 0, "clock_getres({}) : r={r} errno={}", name(c), errno());
        check!(h, nanos(&res) > 0, "with a resolution: {}ns", nanos(&res));
    }

    h.group("the-monotonic-clocks-do-not-go-backwards");
    for c in [MONOTONIC, MONOTONIC_RAW, MONOTONIC_COARSE, BOOTTIME] {
        let (_, a, _) = gettime(c);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let (_, b, _) = gettime(c);
        check!(h, nanos(&b) >= nanos(&a), "{} advances: {} -> {}", name(c), nanos(&a), nanos(&b));
    }

    h.group("the-cpu-clocks-measure-cpu");
    // Burning cycles has to move them, and a process's total cannot be less
    // than one of its threads'.
    let (_, before_thread, _) = gettime(THREAD_CPUTIME);
    let (_, before_proc, _) = gettime(PROCESS_CPUTIME);
    let mut acc = 0u64;
    let spin = std::time::Instant::now();
    while spin.elapsed() < std::time::Duration::from_millis(120) {
        for i in 0..2000u64 {
            acc = acc.wrapping_mul(6364136223846793005).wrapping_add(i);
        }
    }
    std::hint::black_box(acc);
    let (_, after_thread, _) = gettime(THREAD_CPUTIME);
    let (_, after_proc, _) = gettime(PROCESS_CPUTIME);
    check!(h, nanos(&after_thread) > nanos(&before_thread),
        "CLOCK_THREAD_CPUTIME_ID advances while spinning: {} -> {}",
        nanos(&before_thread), nanos(&after_thread));
    check!(h, nanos(&after_proc) > nanos(&before_proc),
        "and CLOCK_PROCESS_CPUTIME_ID: {} -> {}", nanos(&before_proc), nanos(&after_proc));
    check!(h, nanos(&after_proc) >= nanos(&after_thread),
        "the process has used at least what this thread has: {} vs {}",
        nanos(&after_proc), nanos(&after_thread));

    h.group("a-clock-that-does-not-exist");
    for bad in [99i32, 1000] {
        let (r, _, e) = gettime(bad);
        check!(h, r == -1 && e == libc::EINVAL, "clock_gettime({bad}) is EINVAL: r={r} errno={e}");
        let mut res = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let r = unsafe { libc::clock_getres(bad, &mut res) };
        let e = errno();
        check!(h, r == -1 && e == libc::EINVAL, "clock_getres({bad}) is EINVAL: r={r} errno={e}");
    }

    h.group("setting-a-clock-is-refused");
    // Everything this can say about clock_settime, and no more.
    //
    // A container cannot answer for the rest. Docker's default seccomp profile
    // filters `clock_settime` outright unless CAP_SYS_TIME is present, and
    // answers EPERM for *every* argument -- an unknown clock, a clock with no
    // setter, a malformed time. So a container run tells us what the filter
    // does, not what Linux does, and the checks that used to be here were
    // measuring Docker.
    //
    // Running the container with CAP_SYS_TIME would answer it and would also
    // let a mistake in this file move a machine's wall clock. Not worth it.
    //
    // What is left is the one thing that is true of both: an ordinary user may
    // not set the clock. Privilege is dropped first so that a well-formed
    // request is refused rather than obeyed.
    check!(h, unsafe { libc::setuid(1000) } == 0,
        "dropping to an ordinary user: errno={}", errno());
    let (_, now, _) = gettime(REALTIME);
    let r = unsafe { libc::clock_settime(REALTIME, &now) };
    let e = errno();
    check!(h, r == -1 && e == libc::EPERM,
        "clock_settime(CLOCK_REALTIME) without the right is EPERM: r={r} errno={e}");
    let (_, still, _) = gettime(REALTIME);
    check!(h, (nanos(&still) - nanos(&now)).abs() < 5_000_000_000,
        "and the clock did not move: {} -> {}", nanos(&now), nanos(&still));

    std::process::exit(h.finish());
}
