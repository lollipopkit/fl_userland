//! What counts as a valid time, and the arithmetic on one.
//!
//! `kernel/time.c` keeps the timers, the locks and the host calls. What is here
//! is the part that is a decision about values: whether a guest's `timespec` or
//! `timeval` is one Linux would accept, and the conversions that can
//! overflow.
//!
//! The reason to separate it is that a time is a **two-field number with a
//! carry**, and every defect in this area has been in the relationship between
//! the fields rather than in either one: a `tv_usec` of two million accepted as
//! two seconds, a `tv_usec * 1000` that overflowed on the way to nanoseconds, a
//! remainder rounded to nearest where Linux rounds up. None of those are
//! reachable from a syscall test without a timer running; all of them are one
//! line here.

pub const NSEC_PER_SEC: i64 = 1_000_000_000;
pub const USEC_PER_SEC: i64 = 1_000_000;
pub const NSEC_PER_USEC: i64 = 1_000;

pub use guest_errno::c_int_::EINVAL;

#[path = "clock.rs"]
pub mod clock;
pub use clock::{Clock, CpuWhich, HostClock, Ops, clock_of, is_dynamic, ops};

#[path = "arithmetic.rs"]
mod arithmetic;
pub use arithmetic::*;

// ------------------------------------------------------------- C binding

/* `timeabi_absolute_deadline` was here, for `util/sync.c`'s `wait_for`. That is
 * `crates/util/waitfor` as of 2026-09-03 and calls `absolute_deadline` above as
 * ordinary Rust, so the export had no C caller -- and `util/sync.c` was still
 * declaring it, which is what kept `tools/dead-exports.py` from saying so. */

pub fn timeabi_timespec_valid(sec: i64, nsec: i64) -> i32 {
    timespec_valid(sec, nsec) as i32
}

#[cfg(test)]
/// User plus system as nanoseconds, or -1 on overflow.
pub(crate) fn timeabi_cpu_time_nsec(
    utime_sec: i64,
    utime_usec: i64,
    stime_sec: i64,
    stime_usec: i64,
) -> i64 {
    cpu_time_nsec(utime_sec, utime_usec, stime_sec, stime_usec).unwrap_or(-1)
}

#[cfg(test)]
pub(crate) fn timeabi_clock_kind(id: u32) -> i32 {
    match clock_of(id) {
        Clock::Host(HostClock::Realtime) => 0,
        Clock::Host(HostClock::Monotonic) => 1,
        Clock::Cpu { per_thread: false, .. } => 2,
        Clock::Cpu { per_thread: true, .. } => 3,
        Clock::Invalid => -1,
    }
}

#[cfg(test)]
/// Nanoseconds left until an absolute deadline, or 0 if it has passed.
///
/// Called on every pass of the sleep loop, so that a delay between reading the
/// clock and sleeping comes out of the sleep rather than off the end of it.
pub(crate) fn timeabi_remaining_until(
    deadline_sec: i64,
    deadline_nsec: i64,
    now_sec: i64,
    now_nsec: i64,
) -> i64 {
    remaining_until(deadline_sec, deadline_nsec, now_sec, now_nsec).unwrap_or(0)
}

#[cfg(test)]
mod tests;
