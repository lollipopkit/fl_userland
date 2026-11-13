//! What `eventfd2` and the three `timerfd` calls do with their arguments.
//!
//! # Why this exists
//!
//! An event loop is built from four descriptor types: `epoll`, `signalfd`,
//! `eventfd` and `timerfd`. The first two have probes and found three defects
//! and two between them; these two had none. libuv, tokio, glib and systemd all
//! use both, and both are **fixed-size wire formats with flag rules** — the
//! combination this tree keeps finding defects in.
//!
//! `timerfd` has more rules than anything else of its size: two clocks, two
//! flags at create and two more at arm, a deadline that is absolute or relative
//! depending on one bit, an `itimerspec` whose two halves this kernel and the
//! host order **oppositely**, and a read that answers eight bytes of expiry
//! count or blocks.
//!
//! # Timing is not what is being asked
//!
//! Whether a 50 ms timer fires in 50 ms is `time_semantics`'. What is here is
//! what the calls *answer*: which flags are refused, what a read of the wrong
//! size does, what an unarmed timer reports, and what `gettime` says about a
//! timer that has already expired. Every case either returns at once or is
//! bounded by a short arm, so the probe cannot hang.

use std::io::Write;

unsafe fn sys(n: i64, a: i64, b: i64, c: i64, d: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a => ret,
            in("x1") b, in("x2") c, in("x3") d,
            options(nostack)
        );
    }
    ret
}

const NR_EVENTFD2: i64 = 19;
const NR_TIMERFD_CREATE: i64 = 85;
const NR_TIMERFD_SETTIME: i64 = 86;
const NR_TIMERFD_GETTIME: i64 = 87;
const NR_READ: i64 = 63;
const NR_WRITE: i64 = 64;
const NR_CLOSE: i64 = 57;

fn errname(e: i32) -> String {
    let n = match e {
        1 => "EPERM", 4 => "EINTR", 9 => "EBADF", 11 => "EAGAIN", 12 => "ENOMEM",
        14 => "EFAULT", 22 => "EINVAL", 24 => "EMFILE", 25 => "ENOTTY",
        29 => "ESPIPE", 32 => "EPIPE", 38 => "ENOSYS", 75 => "EOVERFLOW",
        95 => "EOPNOTSUPP",
        _ => return format!("errno {e}"),
    };
    n.into()
}

fn r(v: i64) -> String {
    if v < 0 && v > -4096 {
        format!("-{}", errname(-v as i32))
    } else {
        v.to_string()
    }
}

/// A descriptor's *number* is not comparable — the two sides have different
/// things open — so a success is reported as `ok`.
fn fd(v: i64) -> String {
    if v < 0 { r(v) } else { "ok".into() }
}

fn say(what: &str, s: String) {
    println!("  {what:<52} {s}");
    let _ = std::io::stdout().flush();
}

const CLOCK_REALTIME: i64 = 0;
const CLOCK_MONOTONIC: i64 = 1;
const CLOCK_BOOTTIME: i64 = 7;
const CLOCK_REALTIME_ALARM: i64 = 8;
const CLOCK_BOOTTIME_ALARM: i64 = 9;

const TFD_NONBLOCK: i64 = 0o4000; // O_NONBLOCK
const TFD_CLOEXEC: i64 = 0o2000000; // O_CLOEXEC
const TFD_TIMER_ABSTIME: i64 = 1;
const TFD_TIMER_CANCEL_ON_SET: i64 = 2;

const EFD_SEMAPHORE: i64 = 1;

fn main() {
    println!("## eventfd2 and timerfd");

    println!("## eventfd2 flags");
    for (flags, name) in [
        (0i64, "0"),
        (EFD_SEMAPHORE, "EFD_SEMAPHORE"),
        (TFD_NONBLOCK, "EFD_NONBLOCK"),
        (TFD_CLOEXEC, "EFD_CLOEXEC"),
        (EFD_SEMAPHORE | TFD_NONBLOCK | TFD_CLOEXEC, "all three"),
        (1 << 4, "an unallocated bit"),
        (-1, "every bit"),
    ] {
        let f = unsafe { sys(NR_EVENTFD2, 0, flags, 0, 0) };
        say(&format!("eventfd2(0, {name})"), fd(f));
        if f >= 0 {
            unsafe { sys(NR_CLOSE, f, 0, 0, 0) };
        }
    }

    println!("## eventfd reads and writes");
    let ev = unsafe { sys(NR_EVENTFD2, 3, TFD_NONBLOCK, 0, 0) };
    let mut buf = [0u8; 16];
    let b = buf.as_mut_ptr() as i64;
    say("read 8 bytes of a counter of 3", r(unsafe { sys(NR_READ, ev, b, 8, 0) }));
    say("  the value it gave", format!("{}", u64::from_ne_bytes(buf[..8].try_into().unwrap())));
    say("read again, now empty and non-blocking", r(unsafe { sys(NR_READ, ev, b, 8, 0) }));
    say("read 4 bytes", r(unsafe { sys(NR_READ, ev, b, 4, 0) }));
    say("read 16 bytes", r(unsafe { sys(NR_READ, ev, b, 16, 0) }));
    say("read 0 bytes", r(unsafe { sys(NR_READ, ev, b, 0, 0) }));
    say("read into an unmapped buffer", r(unsafe { sys(NR_READ, ev, 0x10, 8, 0) }));

    let one = 1u64.to_ne_bytes();
    let onep = one.as_ptr() as i64;
    say("write 8 bytes of 1", r(unsafe { sys(NR_WRITE, ev, onep, 8, 0) }));
    say("write 4 bytes", r(unsafe { sys(NR_WRITE, ev, onep, 4, 0) }));
    say("write 16 bytes", r(unsafe { sys(NR_WRITE, ev, onep, 16, 0) }));
    // 7, 8 and 9 pin the shape of the rule: a read takes "at least eight" and a
    // write takes "exactly eight", which is not a symmetry anybody would guess.
    say("write 7 bytes", r(unsafe { sys(NR_WRITE, ev, onep, 7, 0) }));
    say("write 9 bytes", r(unsafe { sys(NR_WRITE, ev, onep, 9, 0) }));
    say("read 9 bytes", r(unsafe { sys(NR_READ, ev, b, 9, 0) }));
    // `ULLONG_MAX` is the one value a write may not carry: it is the counter's
    // "overflowed" sentinel.
    let max = u64::MAX.to_ne_bytes();
    say("write ULLONG_MAX", r(unsafe { sys(NR_WRITE, ev, max.as_ptr() as i64, 8, 0) }));
    // And the value one below it saturates the counter, so the *next* write of
    // 1 has nowhere to go -- EAGAIN on a non-blocking descriptor.
    let near = (u64::MAX - 1).to_ne_bytes();
    say("write ULLONG_MAX - 1", r(unsafe { sys(NR_WRITE, ev, near.as_ptr() as i64, 8, 0) }));
    say("write 1 into a full counter", r(unsafe { sys(NR_WRITE, ev, onep, 8, 0) }));
    say("read the full counter", r(unsafe { sys(NR_READ, ev, b, 8, 0) }));
    say("  the value it gave", format!("{}", u64::from_ne_bytes(buf[..8].try_into().unwrap())));
    unsafe { sys(NR_CLOSE, ev, 0, 0, 0) };

    println!("## eventfd semaphore mode");
    let sem = unsafe { sys(NR_EVENTFD2, 3, EFD_SEMAPHORE | TFD_NONBLOCK, 0, 0) };
    for i in 1..=4 {
        let n = unsafe { sys(NR_READ, sem, b, 8, 0) };
        say(
            &format!("semaphore read {i}"),
            if n < 0 { r(n) } else { format!("{}", u64::from_ne_bytes(buf[..8].try_into().unwrap())) },
        );
    }
    unsafe { sys(NR_CLOSE, sem, 0, 0, 0) };

    println!("## timerfd_create");
    for (clock, name) in [
        (CLOCK_REALTIME, "CLOCK_REALTIME"),
        (CLOCK_MONOTONIC, "CLOCK_MONOTONIC"),
        (CLOCK_BOOTTIME, "CLOCK_BOOTTIME"),
        (CLOCK_REALTIME_ALARM, "CLOCK_REALTIME_ALARM"),
        (CLOCK_BOOTTIME_ALARM, "CLOCK_BOOTTIME_ALARM"),
        (2, "CLOCK_PROCESS_CPUTIME_ID"),
        (3, "CLOCK_THREAD_CPUTIME_ID"),
        (99, "an unallocated clock"),
        (-1, "clock -1"),
    ] {
        let f = unsafe { sys(NR_TIMERFD_CREATE, clock, 0, 0, 0) };
        say(&format!("timerfd_create({name})"), fd(f));
        if f >= 0 {
            unsafe { sys(NR_CLOSE, f, 0, 0, 0) };
        }
    }
    for (flags, name) in [
        (TFD_NONBLOCK, "TFD_NONBLOCK"),
        (TFD_CLOEXEC, "TFD_CLOEXEC"),
        (1, "bit 0, which is neither"),
        (-1, "every bit"),
    ] {
        let f = unsafe { sys(NR_TIMERFD_CREATE, CLOCK_MONOTONIC, flags, 0, 0) };
        say(&format!("timerfd_create(MONOTONIC, {name})"), fd(f));
        if f >= 0 {
            unsafe { sys(NR_CLOSE, f, 0, 0, 0) };
        }
    }

    println!("## timerfd_settime");
    let tf = unsafe { sys(NR_TIMERFD_CREATE, CLOCK_MONOTONIC, TFD_NONBLOCK, 0, 0) };
    // `struct itimerspec` is { interval, value } -- the interval **first**,
    // which is the opposite of the host's `timer_spec`. A kernel that has them
    // the wrong way round arms a one-shot as an interval timer and vice versa,
    // and `gettime` below is what shows it.
    let spec = |int_sec: i64, int_nsec: i64, val_sec: i64, val_nsec: i64| {
        [int_sec, int_nsec, val_sec, val_nsec]
    };
    let disarm = spec(0, 0, 0, 0);
    say("settime, all zero (disarm)", r(unsafe {
        sys(NR_TIMERFD_SETTIME, tf, 0, disarm.as_ptr() as i64, 0)
    }));
    say("settime, NULL new_value", r(unsafe {
        sys(NR_TIMERFD_SETTIME, tf, 0, 0, 0)
    }));
    say("settime, unreadable new_value", r(unsafe {
        sys(NR_TIMERFD_SETTIME, tf, 0, 0x10, 0)
    }));
    for (s, name) in [
        (spec(0, 0, 0, -1), "value tv_nsec = -1"),
        (spec(0, 0, 0, 1_000_000_000), "value tv_nsec = 1e9"),
        (spec(0, 0, -1, 0), "value tv_sec = -1"),
        (spec(0, -1, 1, 0), "interval tv_nsec = -1"),
        (spec(0, 1_000_000_000, 1, 0), "interval tv_nsec = 1e9"),
        (spec(-1, 0, 1, 0), "interval tv_sec = -1"),
    ] {
        say(&format!("settime, {name}"), r(unsafe {
            sys(NR_TIMERFD_SETTIME, tf, 0, s.as_ptr() as i64, 0)
        }));
    }
    for (flags, name) in [
        (TFD_TIMER_ABSTIME, "TFD_TIMER_ABSTIME"),
        (TFD_TIMER_CANCEL_ON_SET, "TFD_TIMER_CANCEL_ON_SET"),
        (TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, "both"),
        (4, "bit 2, which is neither"),
        (-1, "every bit"),
    ] {
        let s = spec(0, 0, 1, 0);
        say(&format!("settime({name})"), r(unsafe {
            sys(NR_TIMERFD_SETTIME, tf, flags, s.as_ptr() as i64, 0)
        }));
    }
    // An absolute deadline in 1970 on a monotonic timer has already passed, so
    // it fires at once rather than being refused.
    let past = spec(0, 0, 1, 0);
    say("settime(ABSTIME, deadline in the past)", r(unsafe {
        sys(NR_TIMERFD_SETTIME, tf, TFD_TIMER_ABSTIME, past.as_ptr() as i64, 0)
    }));

    println!("## timerfd_gettime");
    // Armed as a one-shot far in the future, so what `gettime` reports is
    // stable: an interval of zero and a value that has not arrived.
    let far = spec(0, 0, 10_000, 0);
    unsafe { sys(NR_TIMERFD_SETTIME, tf, 0, far.as_ptr() as i64, 0) };
    let mut got = [0i64; 4];
    let g = unsafe { sys(NR_TIMERFD_GETTIME, tf, got.as_mut_ptr() as i64, 0, 0) };
    say("gettime of a one-shot", r(g));
    say("  interval is zero", format!("{}", got[0] == 0 && got[1] == 0));
    say("  value is in the future", format!("{}", got[2] > 0 || got[3] > 0));
    // And with an interval, which is the half that would be swapped.
    let both = spec(5, 0, 10_000, 0);
    unsafe { sys(NR_TIMERFD_SETTIME, tf, 0, both.as_ptr() as i64, 0) };
    let g = unsafe { sys(NR_TIMERFD_GETTIME, tf, got.as_mut_ptr() as i64, 0, 0) };
    say("gettime of an interval timer", r(g));
    say("  interval seconds", format!("{}", got[0]));
    say("  value is in the future", format!("{}", got[2] > 0 || got[3] > 0));
    say("gettime, NULL destination", r(unsafe {
        sys(NR_TIMERFD_GETTIME, tf, 0, 0, 0)
    }));
    say("gettime, unmapped destination", r(unsafe {
        sys(NR_TIMERFD_GETTIME, tf, 0x10, 0, 0)
    }));

    println!("## timerfd reads");
    unsafe { sys(NR_TIMERFD_SETTIME, tf, 0, disarm.as_ptr() as i64, 0) };
    say("read a disarmed timer, non-blocking", r(unsafe { sys(NR_READ, tf, b, 8, 0) }));
    say("read 4 bytes", r(unsafe { sys(NR_READ, tf, b, 4, 0) }));
    say("write to a timerfd", r(unsafe { sys(NR_WRITE, tf, onep, 8, 0) }));
    // Does arming again clear an expiry that has already happened? A one-shot
    // in the past fires at once; the next settime is what an event loop does
    // when it reschedules, and a stale count read after it is a spurious wakeup.
    let now_ish = spec(0, 0, 0, 1);
    unsafe { sys(NR_TIMERFD_SETTIME, tf, 0, now_ish.as_ptr() as i64, 0) };
    unsafe { libc::usleep(20_000) };
    say("read after a one-shot fired", r(unsafe { sys(NR_READ, tf, b, 8, 0) }));
    say("  the count it gave", format!("{}", u64::from_ne_bytes(buf[..8].try_into().unwrap())));
    unsafe { sys(NR_TIMERFD_SETTIME, tf, 0, now_ish.as_ptr() as i64, 0) };
    unsafe { libc::usleep(20_000) };
    unsafe { sys(NR_TIMERFD_SETTIME, tf, 0, far.as_ptr() as i64, 0) };
    say("read after re-arming far away", r(unsafe { sys(NR_READ, tf, b, 8, 0) }));
    unsafe { sys(NR_TIMERFD_SETTIME, tf, 0, now_ish.as_ptr() as i64, 0) };
    unsafe { libc::usleep(20_000) };
    unsafe { sys(NR_TIMERFD_SETTIME, tf, 0, disarm.as_ptr() as i64, 0) };
    say("read after disarming", r(unsafe { sys(NR_READ, tf, b, 8, 0) }));

    println!("## the wrong descriptor");
    let ev2 = unsafe { sys(NR_EVENTFD2, 0, 0, 0, 0) };
    say("timerfd_settime on an eventfd", r(unsafe {
        sys(NR_TIMERFD_SETTIME, ev2, 0, disarm.as_ptr() as i64, 0)
    }));
    say("timerfd_gettime on an eventfd", r(unsafe {
        sys(NR_TIMERFD_GETTIME, ev2, got.as_mut_ptr() as i64, 0, 0)
    }));
    say("timerfd_settime on a closed descriptor", r(unsafe {
        sys(NR_TIMERFD_SETTIME, 9999, 0, disarm.as_ptr() as i64, 0)
    }));
    say("timerfd_gettime on a closed descriptor", r(unsafe {
        sys(NR_TIMERFD_GETTIME, 9999, got.as_mut_ptr() as i64, 0, 0)
    }));
    unsafe {
        sys(NR_CLOSE, ev2, 0, 0, 0);
        sys(NR_CLOSE, tf, 0, 0, 0);
    }
}
