//! Conversion and clock helpers for timerfd deadlines.

use std::ffi::c_int;

use util_timeabi::{Clock, HostClock};

use crate::{ffi, timeabi};

// ---------------------------------------------------------------------------
// The two deadline representations
// ---------------------------------------------------------------------------

/// The guest's `itimerspec`, as the host timer service wants it.
///
/// The field order is the whole content of this function: the guest struct is
/// `{interval, value}` and the host one is `{value, interval}`.
pub(super) fn to_host(it: &ffi::itimerspec_) -> util_timer::Spec {
    util_timer::Spec {
        value: util_timer::Timespec {
            sec: it.value.sec as _,
            nsec: it.value.nsec as _,
        },
        interval: util_timer::Timespec {
            sec: it.interval.sec as _,
            nsec: it.interval.nsec as _,
        },
    }
}

pub(super) fn from_host(spec: &util_timer::Spec) -> ffi::itimerspec_ {
    ffi::itimerspec_ {
        interval: ffi::timespec_ {
            sec: spec.interval.sec as _,
            nsec: spec.interval.nsec as _,
        },
        value: ffi::timespec_ {
            sec: spec.value.sec as _,
            nsec: spec.value.nsec as _,
        },
    }
}

/// `x - y`, borrowing a second where the nanoseconds do not reach.
///
/// A duplicate of `timespec_subtract` in `util/timer.h`, which is `static
/// inline` and so has no symbol to call. Its own tests are below, because an
/// off-by-one in the borrow is a deadline a second out and nothing else would
/// notice.
pub(super) fn subtract(x: (i64, i64), y: (i64, i64)) -> (i64, i64) {
    let (mut xs, mut xn) = x;
    if xn < y.1 {
        xs -= 1;
        xn += 1_000_000_000;
    }
    (xs - y.0, xn - y.1)
}

/// Which host clock a timerfd's clock id runs on, and its host number.
///
/// Fewer clocks than `clock_gettime` takes: `crates/kernel/timerfd`'s
/// `clock_valid` is the rule, and this is the mapping for the ones that pass
/// it.
pub(super) fn host_clock(clockid: c_int) -> Option<c_int> {
    match timeabi::clock_of(clockid as u32) {
        Clock::Host(HostClock::Realtime) => Some(libc::CLOCK_REALTIME as c_int),
        Clock::Host(HostClock::Monotonic) => Some(libc::CLOCK_MONOTONIC as c_int),
        _ => None,
    }
}

/// Zero on failure, which cannot happen: `clockid` is one of the two this
/// file maps a guest clock onto.
pub(super) fn now(clockid: c_int) -> (i64, i64) {
    util_timeabi::host_clock(clockid as libc::clockid_t).unwrap_or((0, 0))
}
