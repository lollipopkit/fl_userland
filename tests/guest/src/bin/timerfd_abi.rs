//! `timerfd`: which clocks, which flags, and what a read returns.
//!
//! A timerfd is a descriptor whose readability *is* the timer, so every
//! argument to it is checked by the kernel and nothing else. `timerfd_create`
//! here validated neither its flags nor its clock: any bit pattern was
//! accepted, and so was every clock id `clockid_to_real` could map — including
//! the two CPU-time clocks, which Linux refuses because a timer cannot be armed
//! against a clock that only advances while the process runs.
//!
//! A wrong answer is silent in both directions. An accepted flag does nothing,
//! so a program that asked for `TFD_NONBLOCK` and got a blocking descriptor
//! hangs on the first read instead of being told at create time. An accepted
//! clock produces a timer that never fires.
//!
//! The expiration count is the other half: a read gives the number of times the
//! timer fired since the last read, and zeroes it. A kernel that returns 1 for
//! a timer that fired five times loses four ticks, and a periodic timer's
//! consumer drifts without ever seeing an error.

use guest_tests::{Harness, check};
use std::time::Duration;

const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;
const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
const CLOCK_BOOTTIME: i32 = 7;

const TFD_NONBLOCK: i32 = 0o4000;
const TFD_CLOEXEC: i32 = 0o2000000;
const TFD_TIMER_ABSTIME: i32 = 1;
const TFD_TIMER_CANCEL_ON_SET: i32 = 2;

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct Itimerspec {
    interval_sec: i64,
    interval_nsec: i64,
    value_sec: i64,
    value_nsec: i64,
}

impl Itimerspec {
    fn after(ms: i64) -> Self {
        Itimerspec { interval_sec: 0, interval_nsec: 0,
                     value_sec: ms / 1000, value_nsec: (ms % 1000) * 1_000_000 }
    }
    fn every(ms: i64) -> Self {
        Itimerspec { interval_sec: ms / 1000, interval_nsec: (ms % 1000) * 1_000_000,
                     value_sec: ms / 1000, value_nsec: (ms % 1000) * 1_000_000 }
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn create(clock: i32, flags: i32) -> (i32, i32) {
    let r = unsafe { libc::syscall(libc::SYS_timerfd_create, clock, flags) } as i32;
    (r, errno())
}

fn settime(fd: i32, flags: i32, spec: &Itimerspec) -> (i32, i32) {
    let r = unsafe {
        libc::syscall(libc::SYS_timerfd_settime, fd, flags, spec as *const Itimerspec,
                      std::ptr::null_mut::<Itimerspec>())
    } as i32;
    (r, errno())
}

fn settime_old(fd: i32, flags: i32, spec: &Itimerspec) -> (i32, Itimerspec) {
    let mut old = Itimerspec::default();
    let r = unsafe {
        libc::syscall(libc::SYS_timerfd_settime, fd, flags, spec as *const Itimerspec,
                      &raw mut old)
    } as i32;
    (r, old)
}

fn gettime(fd: i32) -> (i32, Itimerspec) {
    let mut out = Itimerspec::default();
    let r = unsafe { libc::syscall(libc::SYS_timerfd_gettime, fd, &raw mut out) } as i32;
    (r, out)
}

/// Reads the expiration count, or the errno as a negative.
fn read_count(fd: i32) -> i64 {
    let mut n: u64 = 0;
    let r = unsafe { libc::read(fd, (&raw mut n).cast(), 8) };
    if r == 8 { n as i64 } else { -(errno() as i64) }
}

fn main() {
    let mut h = Harness::new();

    h.group("the-clocks-a-timerfd-may-use");
    for c in [CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME] {
        let (fd, e) = create(c, 0);
        check!(h, fd >= 0, "timerfd_create(clock {c}): fd={fd} errno={e}");
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
    // The CPU-time clocks are refused. A timer against a clock that advances
    // only while the process is scheduled is not something a descriptor can
    // wait on, and this kernel accepted both once they were mapped for
    // clock_gettime -- producing a timerfd that never became readable.
    for c in [CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID] {
        let (fd, e) = create(c, 0);
        check!(h, fd == -1 && e == libc::EINVAL,
            "timerfd_create(cpu clock {c}) is EINVAL: fd={fd} errno={e}");
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
    // The coarse and raw variants are readable through clock_gettime and are
    // not arming clocks. So is every id past the end of the table.
    for c in [4, 5, 6, 99, -1, 0x7fff_ffff] {
        let (fd, e) = create(c, 0);
        check!(h, fd == -1 && e == libc::EINVAL,
            "timerfd_create(clock {c}) is EINVAL: fd={fd} errno={e}");
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
    // The two alarm clocks wake a suspended machine, which this cannot do.
    // Linux takes them and wants CAP_WAKE_ALARM, so a container without that
    // capability refuses them too -- with EPERM there and EINVAL here. Both are
    // a refusal and the errno differs for a reason neither side can fix, so
    // what is checked is that the descriptor is refused.
    for c in [8, 9] {
        let (fd, e) = create(c, 0);
        check!(h, fd == -1, "timerfd_create(alarm clock {c}) is refused: fd={fd} errno={e}");
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }

    h.group("the-flags-timerfd_create-takes");
    // The two that exist, and that they do something. A flag that is accepted
    // and ignored is worse than one that is refused: the caller believes it.
    let (fd, e) = create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    check!(h, fd >= 0, "TFD_CLOEXEC: fd={fd} errno={e}");
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    check!(h, fl & libc::FD_CLOEXEC != 0, "and it is set: {fl:#x}");
    unsafe { libc::close(fd) };
    let (fd, e) = create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    check!(h, fd >= 0, "TFD_NONBLOCK: fd={fd} errno={e}");
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    check!(h, fl & libc::O_NONBLOCK != 0, "and it is set: {fl:#x}");
    // Which is observable as behaviour, not just as a flag word: an unarmed
    // timerfd read must be EAGAIN rather than a wait for ever.
    check!(h, read_count(fd) == -(libc::EAGAIN as i64),
        "so a read of an unarmed timer is EAGAIN: {}", read_count(fd));
    unsafe { libc::close(fd) };
    let (fd, e) = create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    check!(h, fd >= 0, "both together: fd={fd} errno={e}");
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
    // And everything else is refused.
    for flags in [1, 2, 4, 0o10000, 0x8000_0000u32 as i32, TFD_CLOEXEC | 1] {
        let (fd, e) = create(CLOCK_MONOTONIC, flags);
        check!(h, fd == -1 && e == libc::EINVAL,
            "timerfd_create(flags {flags:#x}) is EINVAL: fd={fd} errno={e}");
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }

    h.group("the-flags-timerfd_settime-takes");
    let (fd, _) = create(CLOCK_MONOTONIC, 0);
    check!(h, fd >= 0, "a timerfd: fd={fd}");
    let spec = Itimerspec::after(3600_000);
    for flags in [0, TFD_TIMER_ABSTIME, TFD_TIMER_CANCEL_ON_SET,
                  TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET] {
        // Absolute needs an absolute time, so use a relative one only when the
        // flag is not set; either way what is being checked is the flag word.
        let s = if flags & TFD_TIMER_ABSTIME != 0 {
            let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            unsafe { libc::clock_gettime(CLOCK_MONOTONIC, &mut now) };
            Itimerspec { interval_sec: 0, interval_nsec: 0,
                         value_sec: now.tv_sec as i64 + 3600, value_nsec: 0 }
        } else {
            spec
        };
        let (r, e) = settime(fd, flags, &s);
        check!(h, r == 0, "timerfd_settime(flags {flags:#x}): r={r} errno={e}");
    }
    for flags in [4, 8, 0x8000_0000u32 as i32] {
        let (r, e) = settime(fd, flags, &spec);
        check!(h, r == -1 && e == libc::EINVAL,
            "timerfd_settime(flags {flags:#x}) is EINVAL: r={r} errno={e}");
    }

    h.group("a-malformed-time");
    // The interval is checked even when the value is zero, which is the
    // disarming case -- it is what every re-arm after the first uses.
    let bad = [
        Itimerspec { interval_sec: 0, interval_nsec: 0, value_sec: 0, value_nsec: -1 },
        Itimerspec { interval_sec: 0, interval_nsec: 0, value_sec: 0, value_nsec: 1_000_000_000 },
        Itimerspec { interval_sec: 0, interval_nsec: -1, value_sec: 0, value_nsec: 0 },
        Itimerspec { interval_sec: 0, interval_nsec: 1_000_000_000, value_sec: 1, value_nsec: 0 },
        Itimerspec { interval_sec: -1, interval_nsec: 0, value_sec: 1, value_nsec: 0 },
        Itimerspec { interval_sec: 0, interval_nsec: 0, value_sec: -1, value_nsec: 0 },
    ];
    for s in bad {
        let (r, e) = settime(fd, 0, &s);
        check!(h, r == -1 && e == libc::EINVAL, "{s:?} is EINVAL: r={r} errno={e}");
    }
    // A bad address, before and after any of that.
    let r = unsafe {
        libc::syscall(libc::SYS_timerfd_settime, fd, 0, 1usize,
                      std::ptr::null_mut::<Itimerspec>())
    };
    check!(h, r == -1 && errno() == libc::EFAULT, "an unmapped new_value is EFAULT: r={r}");
    let r = unsafe { libc::syscall(libc::SYS_timerfd_gettime, fd, 1usize) };
    check!(h, r == -1 && errno() == libc::EFAULT, "and an unmapped curr_value: r={r}");

    h.group("disarming-and-reading-back");
    let zero = Itimerspec::default();
    let (r, _) = settime(fd, 0, &zero);
    check!(h, r == 0, "disarming: r={r} errno={}", errno());
    let (r, got) = gettime(fd);
    check!(h, r == 0, "timerfd_gettime: r={r} errno={}", errno());
    check!(h, got.value_sec == 0 && got.value_nsec == 0,
        "a disarmed timer reads back as zero: {got:?}");
    // Arming reports the previous setting, which is how a caller saves and
    // restores one.
    let (r, old) = settime_old(fd, 0, &Itimerspec::after(3600_000));
    check!(h, r == 0, "arming: r={r}");
    check!(h, old.value_sec == 0 && old.value_nsec == 0,
        "the old value of a disarmed timer is zero: {old:?}");
    let (r, old) = settime_old(fd, 0, &zero);
    check!(h, r == 0, "disarming again: r={r}");
    check!(h, old.value_sec > 3500, "and reports what was there: {old:?}");
    unsafe { libc::close(fd) };

    h.group("a-timer-that-fires");
    let (fd, _) = create(CLOCK_MONOTONIC, 0);
    check!(h, fd >= 0, "a timerfd: fd={fd}");
    let (r, _) = settime(fd, 0, &Itimerspec::after(60));
    check!(h, r == 0, "armed for 60ms: r={r}");
    let started = std::time::Instant::now();
    let n = read_count(fd);
    let waited = started.elapsed();
    check!(h, n == 1, "the read gives one expiration: {n}");
    check!(h, waited >= Duration::from_millis(40),
        "and it waited for it: {}ms", waited.as_millis());
    check!(h, waited < Duration::from_secs(3), "not for ever: {}ms", waited.as_millis());
    // A one-shot timer does not re-arm, so it reads back as zero and a
    // non-blocking read finds nothing.
    let (_, got) = gettime(fd);
    check!(h, got.value_sec == 0 && got.value_nsec == 0,
        "a one-shot timer is disarmed after it fires: {got:?}");
    unsafe { libc::close(fd) };

    h.group("a-periodic-timer-counts-what-it-missed");
    // The expiration count is a count, not a flag. A consumer that sleeps
    // through four ticks has to be told four, or it drifts silently.
    let (fd, _) = create(CLOCK_MONOTONIC, 0);
    let (r, _) = settime(fd, 0, &Itimerspec::every(30));
    check!(h, r == 0, "a 30ms interval: r={r}");
    std::thread::sleep(Duration::from_millis(230));
    let n = read_count(fd);
    check!(h, n >= 3, "the read reports several expirations: {n}");
    check!(h, n <= 20, "and not an implausible number: {n}");
    // And the count is cleared by the read.
    unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
    let after = read_count(fd);
    check!(h, after == -(libc::EAGAIN as i64) || after >= 1,
        "reading again gives EAGAIN or the next tick: {after}");
    unsafe { libc::close(fd) };

    h.group("an-absolute-time-in-the-past-fires-at-once");
    let (fd, _) = create(CLOCK_MONOTONIC, 0);
    let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(CLOCK_MONOTONIC, &mut now) };
    let past = Itimerspec { interval_sec: 0, interval_nsec: 0,
                            value_sec: now.tv_sec as i64 - 10, value_nsec: 0 };
    let (r, e) = settime(fd, TFD_TIMER_ABSTIME, &past);
    check!(h, r == 0, "arming for ten seconds ago: r={r} errno={e}");
    let started = std::time::Instant::now();
    let n = read_count(fd);
    check!(h, n >= 1, "it has already expired: {n}");
    check!(h, started.elapsed() < Duration::from_secs(2),
        "and the read did not wait: {}ms", started.elapsed().as_millis());
    unsafe { libc::close(fd) };

    h.group("a-read-that-is-too-short");
    let (fd, _) = create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    let (r, _) = settime(fd, 0, &Itimerspec::after(10));
    check!(h, r == 0, "armed: r={r}");
    std::thread::sleep(Duration::from_millis(80));
    let mut small = [0u8; 4];
    let r = unsafe { libc::read(fd, small.as_mut_ptr().cast(), 4) };
    let e = errno();
    check!(h, r == -1 && e == libc::EINVAL, "a four-byte read is EINVAL: r={r} errno={e}");
    // And the expiration it refused to give is still there.
    let n = read_count(fd);
    check!(h, n == 1, "the expiration was not consumed: {n}");
    unsafe { libc::close(fd) };

    h.group("poll-sees-it");
    let (fd, _) = create(CLOCK_MONOTONIC, 0);
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let r = unsafe { libc::poll(&mut pfd, 1, 0) };
    check!(h, r == 0, "an unarmed timerfd is not readable: r={r} revents={:#x}", pfd.revents);
    let (r, _) = settime(fd, 0, &Itimerspec::after(50));
    check!(h, r == 0, "armed: r={r}");
    pfd.revents = 0;
    let r = unsafe { libc::poll(&mut pfd, 1, 3000) };
    check!(h, r == 1 && pfd.revents & libc::POLLIN != 0,
        "and poll wakes when it fires: r={r} revents={:#x}", pfd.revents);
    check!(h, read_count(fd) == 1, "with an expiration to read");
    unsafe { libc::close(fd) };

    h.group("the-calls-refuse-a-descriptor-that-is-not-one");
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let (r, e) = settime(p[0], 0, &Itimerspec::after(10));
    check!(h, r == -1 && e == libc::EINVAL, "timerfd_settime on a pipe is EINVAL: r={r} errno={e}");
    let (r, _) = gettime(p[0]);
    check!(h, r == -1 && errno() == libc::EINVAL, "and timerfd_gettime: r={r}");
    unsafe { libc::close(p[0]) };
    unsafe { libc::close(p[1]) };
    let (r, e) = settime(4096, 0, &Itimerspec::after(10));
    check!(h, r == -1 && e == libc::EBADF, "a closed descriptor is EBADF: r={r} errno={e}");

    std::process::exit(h.finish());
}
