//! `FUTEX_WAIT_BITSET`'s absolute timeout, and which clock it is measured on.
//!
//! Linux measures it against **CLOCK_MONOTONIC** unless `FUTEX_CLOCK_REALTIME`
//! (256) is set in `op`, in which case CLOCK_REALTIME. `sys_futex` converted it
//! using CLOCK_REALTIME either way, and `FUTEX_CMD_MASK_` masks the flag off
//! without anything ever reading it.
//!
//! Subtracting an epoch time (~1.7e9) from a monotonic one (~9e5) is a large
//! negative, which the conversion clamps to zero — so the wait returned
//! `ETIMEDOUT` immediately instead of waiting.
//!
//! Not reachable through musl, which computes its own relative timeout in
//! userspace and only ever issues `FUTEX_WAIT`. glibc uses `FUTEX_WAIT_BITSET`,
//! so this is a Ubuntu/Rocky guest's `pthread_cond_timedwait` on a monotonic
//! condvar returning instantly and the caller spinning. Probed with the raw
//! syscall so the result does not depend on which libc is in the rootfs.

use guest_tests::{Harness, check};
use std::time::Instant;

const FUTEX_WAIT_BITSET: i64 = 9;
const FUTEX_CMP_REQUEUE: i64 = 4;
const FUTEX_PRIVATE_FLAG: i64 = 128;
const FUTEX_CLOCK_REALTIME: i64 = 256;
const FUTEX_BITSET_MATCH_ANY: i64 = -1i32 as u32 as i64;

fn now(clock: libc::clockid_t) -> libc::timespec {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts
}

/// Add `ms` to a timespec, normalising in *both* directions.
///
/// Only the carry was handled before, so `plus_ms(now, -5000)` left tv_nsec at
/// about -5e9 -- a timespec no kernel accepts. Linux answered EINVAL and the
/// check that expected ETIMEDOUT failed there, which is how the missing
/// validation on this side was found: it took the same nonsense and waited.
fn plus_ms(mut ts: libc::timespec, ms: i64) -> libc::timespec {
    ts.tv_nsec += ms * 1_000_000;
    while ts.tv_nsec >= 1_000_000_000 {
        ts.tv_nsec -= 1_000_000_000;
        ts.tv_sec += 1;
    }
    while ts.tv_nsec < 0 {
        ts.tv_nsec += 1_000_000_000;
        ts.tv_sec -= 1;
    }
    ts
}

/// Waits on a futex whose value will never change, so the only way out is the
/// timeout. Returns how long it actually blocked and the errno.
fn wait_until(deadline: libc::timespec, extra_flags: i64) -> (u128, i32) {
    let word: u32 = 0;
    let start = Instant::now();
    let r = unsafe {
        libc::syscall(
            libc::SYS_futex,
            &word as *const u32,
            FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG | extra_flags,
            0i64, // the value it currently holds, so the wait is entered
            &deadline as *const libc::timespec,
            std::ptr::null::<u8>(),
            FUTEX_BITSET_MATCH_ANY,
        )
    };
    let e = if r < 0 { std::io::Error::last_os_error().raw_os_error().unwrap_or(0) } else { 0 };
    (start.elapsed().as_millis(), e)
}

fn main() {
    let mut h = Harness::new();

    // The default clock. A deadline 300 ms out on CLOCK_MONOTONIC must block
    // for about 300 ms; reading it as a realtime deadline makes it long past.
    h.group("futex-monotonic");
    let (waited, e) = wait_until(plus_ms(now(libc::CLOCK_MONOTONIC), 300), 0);
    check!(h, e == libc::ETIMEDOUT, "the wait ends in ETIMEDOUT, got errno {e}");
    check!(
        h,
        waited >= 250,
        "a 300 ms monotonic deadline waits ~300 ms, waited {waited} ms"
    );
    check!(h, waited < 2000, "and does not overshoot: {waited} ms");

    // With FUTEX_CLOCK_REALTIME the deadline is a realtime one, and must be
    // read as such. This is the control: it passed before the fix as well, so
    // the fix has to keep it working rather than swap which one is broken.
    h.group("futex-realtime");
    let (waited, e) = wait_until(plus_ms(now(libc::CLOCK_REALTIME), 300), FUTEX_CLOCK_REALTIME);
    check!(h, e == libc::ETIMEDOUT, "the wait ends in ETIMEDOUT, got errno {e}");
    check!(
        h,
        waited >= 250,
        "a 300 ms realtime deadline waits ~300 ms, waited {waited} ms"
    );
    check!(h, waited < 2000, "and does not overshoot: {waited} ms");

    // A deadline already in the past must not wait at all, on either clock —
    // otherwise the checks above are satisfied by something that always waits.
    h.group("futex-past");
    let (waited, e) = wait_until(plus_ms(now(libc::CLOCK_MONOTONIC), -5000), 0);
    check!(h, e == libc::ETIMEDOUT, "a past deadline is ETIMEDOUT, got errno {e}");
    check!(h, waited < 100, "and returns at once, waited {waited} ms");

    // A timespec no kernel accepts must be refused rather than interpreted.
    // This waited: nothing checked the field, and in the absolute case the
    // subtraction that follows turned the nonsense into a zero timeout, so the
    // call answered ETIMEDOUT -- which a caller reads as "your deadline
    // passed" rather than "your deadline was not a time".
    h.group("futex-invalid");
    let bad = |sec: i64, nsec: i64| libc::timespec { tv_sec: sec as _, tv_nsec: nsec as _ };
    for (sec, nsec, what) in [
        (0i64, -1i64, "a negative nanosecond field"),
        (0, 1_000_000_000, "a nanosecond field of a full second"),
        (-1, 0, "a negative second field"),
    ] {
        let (_, e) = wait_until(bad(sec, nsec), 0);
        check!(h, e == libc::EINVAL, "{what} is EINVAL, got errno {e}");
    }

    // The fourth argument again, in its *other* meaning. For the two requeue
    // operations it is a count rather than a deadline, and `do_futex` narrows
    // it to `u32` before `futex_requeue` reads it as an `int`:
    //
    //     if (nr_wake < 0 || nr_requeue < 0)
    //             return -EINVAL;
    //
    // So 0x8000_0000 is a refusal, not a request to move two billion waiters.
    // This kernel counted in u32 throughout and answered 0, which a caller
    // reads as "no waiter matched" and will not retry.
    h.group("futex-requeue-counts");
    let requeue = |val: i64, val2: i64, expect: i64| -> i32 {
        let (a, b) = (0u32, 0u32);
        let r = unsafe {
            libc::syscall(
                libc::SYS_futex,
                &a as *const u32,
                FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG,
                val,
                val2,
                &b as *const u32,
                expect,
            )
        };
        if r < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    };
    check!(h, requeue(0, 1, 0) == 0, "an ordinary requeue of one is fine");
    let e = requeue(0, 0x8000_0000, 0);
    check!(h, e == libc::EINVAL, "a requeue count of 0x8000_0000 is EINVAL, got errno {e}");
    let e = requeue(0x8000_0000, 1, 0);
    check!(h, e == libc::EINVAL, "and so is a wake count of 0x8000_0000, got errno {e}");
    // The top half of the register is dropped first, so these two are the same
    // request and must answer alike.
    let e = requeue(0, 0x1_8000_0000, 0);
    check!(h, e == libc::EINVAL, "0x1_8000_0000 is the same count, got errno {e}");
    // And the count is judged before the value comparison: this is EINVAL
    // rather than the EAGAIN a mismatched value would otherwise give.
    let e = requeue(0, 0x8000_0000, 1);
    check!(h, e == libc::EINVAL, "the count is judged before the value, got errno {e}");

    std::process::exit(h.finish());
}
