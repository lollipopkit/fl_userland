//! A guest timeout as the [`Instant`] the queue waits until.
//!
//! The queue takes a deadline rather than a duration (see
//! `crates/kernel/futex`'s `park`), so every form a guest can write -- relative
//! for `FUTEX_WAIT`, absolute on `CLOCK_MONOTONIC` or `CLOCK_REALTIME` for the
//! rest -- is turned into one here, once, at syscall entry.
//!
//! An absolute time on `CLOCK_REALTIME` is converted against the clock's value
//! *now*, so a host clock step during the wait moves the deadline with it. That
//! is a difference from Linux, which re-arms on a clock set; this kernel cannot
//! set the host clock, so the step is never the guest's own.

use std::time::{Duration, Instant};

use guest_errno::Errno;
use usercopy::GuestMem;
use util_timeabi as timeabi;

use crate::rules::relative_to;

/// `now + d`, or `None` -- wait for ever -- when that is past what an
/// `Instant` can hold. `timespec_valid` puts no upper bound on `tv_sec`, so a
/// wait of `LLONG_MAX` seconds is a request a real kernel accepts.
pub(crate) fn after(d: Duration) -> Option<Instant> {
    Instant::now().checked_add(d)
}

/// The guest `struct __kernel_timespec` at `addr`: `EFAULT` if unreadable,
/// `EINVAL` if not normalised. Linux's `get_timespec64` + `timespec64_valid`.
pub(crate) fn read(addr: u64) -> Result<(i64, i64), Errno> {
    let mut raw = [0u8; 16];
    if GuestMem.read(addr, &mut raw) != 0 {
        return Err(Errno::EFAULT);
    }
    let sec = i64::from_le_bytes(raw[..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(raw[8..].try_into().unwrap());
    // Linux's futex_wait does get_timespec64 then timespec64_valid, and answers
    // EINVAL for a tv_nsec outside [0, 1e9) or a negative tv_sec. This did not,
    // so a caller that handed over an unnormalised timespec -- the shape an
    // arithmetic slip on a deadline produces -- got a wait rather than the
    // error naming its mistake.
    if !timeabi::timespec_valid(sec, nsec) {
        return Err(Errno::EINVAL);
    }
    Ok((sec, nsec))
}

/// A relative timeout, from now.
pub(crate) fn relative((sec, nsec): (i64, i64)) -> Option<Instant> {
    // Saturating: see `timeabi::timespec_to_nsec`.
    after(Duration::from_nanos(timeabi::timespec_to_nsec(sec, nsec).max(0) as u64))
}

/// An absolute time on `clock`, which is `CLOCK_MONOTONIC` or
/// `CLOCK_REALTIME`.
///
/// `FUTEX_WAIT_BITSET` measured this against `CLOCK_REALTIME` whatever the flag
/// said until 2026-09-03, which made every monotonic deadline already past.
pub(crate) fn absolute((sec, nsec): (i64, i64), clock: libc::clockid_t) -> Option<Instant> {
    // Both clocks exist everywhere this builds; a failure would read as the
    // epoch, which makes any absolute deadline already past.
    let (now_sec, now_nsec) = timeabi::host_clock(clock).unwrap_or((0, 0));
    relative({
        let t = relative_to(sec, nsec, now_sec, now_nsec);
        (t.tv_sec, t.tv_nsec)
    })
}
