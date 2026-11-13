//! Tests for guest time validation, clock mapping, and conversions.

use super::*;
use crate::arithmetic::timeval_valid;

// ------------------------------------------------------------ the clocks

// ---------------------------------------------------------- clock ticks

#[test]
fn a_timeval_becomes_hundredths() {
    assert_eq!(timeval_to_ticks(1, 0), 100);
    assert_eq!(timeval_to_ticks(0, 10_000), 1, "one tick is 10ms");
    assert_eq!(timeval_to_ticks(0, 9_999), 0, "and part of one is none");
    assert_eq!(timeval_to_ticks(2, 500_000), 250);
}

#[test]
fn ticks_truncate_rather_than_round() {
    // Reporting more CPU time than was spent is the worse direction: a
    // shell doing job accounting would show a process using more than the
    // wall clock it ran for.
    assert_eq!(timeval_to_ticks(0, 19_999), 1);
    assert_eq!(timeval_to_ticks(0, 999_999), 99);
}

#[test]
fn an_absurd_timeval_saturates() {
    assert!(timeval_to_ticks(i64::MAX, 0) > 0);
}

#[test]
fn a_host_timespec_cannot_wrap() {
    assert_eq!(host_timespec_to_ns(1, 2), 1_000_000_002);
    assert_eq!(host_timespec_to_ns(i64::MAX, i64::MAX), u64::MAX);
    assert_eq!(host_timespec_to_ns(-1, 2), 2);
}

// ------------------------------------------------------------- cpu time

#[test]
fn cpu_time_is_user_plus_system() {
    // The defect: only utime was counted, so a syscall-heavy program
    // reported a fraction of what it had spent.
    assert_eq!(cpu_time_nsec(1, 0, 2, 0), Some(3 * NSEC_PER_SEC));
    assert_eq!(cpu_time_nsec(0, 500_000, 0, 500_000), Some(NSEC_PER_SEC));
    assert_eq!(cpu_time_nsec(0, 0, 0, 0), Some(0));
}

#[test]
fn the_microsecond_halves_carry() {
    // 1.5s user + 1.5s system is 3s, not 2s and 1e6 microseconds left over.
    let ns = cpu_time_nsec(1, 500_000, 1, 500_000).unwrap();
    assert_eq!(ns, 3 * NSEC_PER_SEC);
    assert_eq!(nsec_to_timespec(ns), (3, 0));
}

#[test]
fn an_impossible_rusage_does_not_wrap() {
    assert_eq!(cpu_time_nsec(i64::MAX, 0, 1, 0), None);
    assert_eq!(cpu_time_nsec(i64::MAX / 2, 0, i64::MAX / 2, 0), None);
    assert_eq!(timeabi_cpu_time_nsec(i64::MAX, 0, 1, 0), -1);
}

#[test]
fn nanoseconds_split_into_a_timespec() {
    assert_eq!(nsec_to_timespec(0), (0, 0));
    assert_eq!(nsec_to_timespec(1), (0, 1));
    assert_eq!(nsec_to_timespec(NSEC_PER_SEC), (1, 0));
    assert_eq!(nsec_to_timespec(NSEC_PER_SEC + 7), (1, 7));
}

#[test]
fn the_coarse_clocks_are_their_precise_ones() {
    // A guest asking for a cheap clock gets an accurate one, which is a
    // promise in the right direction.
    assert_eq!(clock_of(clock::REALTIME_COARSE), clock_of(clock::REALTIME));
    assert_eq!(
        clock_of(clock::MONOTONIC_COARSE),
        clock_of(clock::MONOTONIC)
    );
}

#[test]
fn raw_and_boottime_are_monotonic() {
    // Neither is exactly monotonic -- one is without NTP slew, the other
    // counts suspended time -- and a host that offers neither is better
    // answered with the nearest thing than with EINVAL.
    assert_eq!(clock_of(clock::MONOTONIC_RAW), clock_of(clock::MONOTONIC));
    assert_eq!(clock_of(clock::BOOTTIME), clock_of(clock::MONOTONIC));
}

#[test]
fn the_cpu_time_clocks_are_not_host_clocks() {
    assert_eq!(
        clock_of(clock::PROCESS_CPUTIME_ID),
        Clock::Cpu { pid: 0, per_thread: false, which: CpuWhich::Sched }
    );
    assert_eq!(
        clock_of(clock::THREAD_CPUTIME_ID),
        Clock::Cpu { pid: 0, per_thread: true, which: CpuWhich::Sched }
    );
}

/// `(~pid << 3) | which`, with bit 2 for a thread: what glibc's
/// `clock_getcpuclockid` and `pthread_getcpuclockid` hand out.
#[test]
fn an_encoded_cpu_clock_names_its_task_and_kind() {
    let enc = |pid: i32, k: i32| (((!pid) << 3) | k) as u32;
    assert_eq!(clock_of(enc(42, 2)), Clock::Cpu { pid: 42, per_thread: false, which: CpuWhich::Sched });
    assert_eq!(clock_of(enc(42, 0)), Clock::Cpu { pid: 42, per_thread: false, which: CpuWhich::Prof });
    assert_eq!(clock_of(enc(7, 5)), Clock::Cpu { pid: 7, per_thread: true, which: CpuWhich::Virt });
    assert_eq!(clock_of(enc(0, 6)), Clock::Cpu { pid: 0, per_thread: true, which: CpuWhich::Sched });
    // Kind 3 is the dynamic clock and kind 7 is no kind at all.
    assert_eq!(clock_of(enc(5, 3)), Clock::Invalid);
    assert!(is_dynamic(enc(5, 3)));
    assert_eq!(clock_of(enc(5, 7)), Clock::Invalid);
    assert_eq!(clock_of(u32::MAX), Clock::Invalid, "-1 is pid 0, kind 7");
}

/// The rows measured against 7.2 by `clock2_probe`.
#[test]
fn which_clocks_sleep_arm_timers_and_adjust() {
    let o = |id: u32| ops(id).expect("a clock");
    assert_eq!(o(clock::REALTIME), Ops { set: true, adjust: true, sleep: true, timer: true, alarm: false });
    for id in [clock::MONOTONIC, clock::BOOTTIME, clock::TAI, clock::PROCESS_CPUTIME_ID] {
        assert_eq!(o(id), Ops { sleep: true, timer: true, ..Ops::default() }, "id {id}");
    }
    assert_eq!(o(clock::THREAD_CPUTIME_ID), Ops { timer: true, ..Ops::default() });
    for id in [clock::MONOTONIC_RAW, clock::REALTIME_COARSE, clock::MONOTONIC_COARSE] {
        assert_eq!(o(id), Ops::default(), "id {id}");
    }
    assert!(o(clock::REALTIME_ALARM).alarm && o(clock::BOOTTIME_ALARM).sleep);
    for id in [10u32, 12, 16, 23, 24, 99] {
        assert_eq!(ops(id), None, "id {id}");
    }
    assert!(!o(u32::MAX).adjust && o(u32::MAX).sleep, "an encoded CPU clock");
    assert!(o(((!5i32 << 3) | 3) as u32).adjust, "a dynamic clock");
}

#[test]
fn anything_else_is_not_a_clock() {
    for id in [10u32, 12, 16, 100, u32::MAX] {
        assert_eq!(clock_of(id), Clock::Invalid, "id {id}");
    }
    assert_eq!(timeabi_clock_kind(u32::MAX), -1);
}

#[test]
fn tai_reads_the_realtime_clock_and_the_alarm_clocks_their_namesakes() {
    assert_eq!(clock_of(clock::TAI), clock_of(clock::REALTIME));
    assert_eq!(clock_of(clock::REALTIME_ALARM), clock_of(clock::REALTIME));
    assert_eq!(clock_of(clock::BOOTTIME_ALARM), clock_of(clock::BOOTTIME));
}

// ------------------------------------------------------- nanosleep flags

/// Measured against a real arm64 kernel, not read off a man page: a
/// rejection of the unknown bits was written here first and five checks in
/// `sleep_abi` failed on Linux and passed here, which is the wrong way
/// round.
#[test]
fn only_the_bottom_bit_is_looked_at() {
    assert!(!nanosleep_is_absolute(0));
    assert!(nanosleep_is_absolute(TIMER_ABSTIME));
    // Unknown bits are ignored rather than refused, so this is a relative
    // sleep and not an error.
    assert!(!nanosleep_is_absolute(2));
    assert!(!nanosleep_is_absolute(4));
    assert!(nanosleep_is_absolute(3), "abstime is set, whatever else is");
    assert!(nanosleep_is_absolute(u32::MAX));
}

// ----------------------------------------------------- absolute deadlines

#[test]
fn a_deadline_in_the_future_has_time_left() {
    assert_eq!(remaining_until(10, 0, 9, 0), Some(NSEC_PER_SEC));
    assert_eq!(remaining_until(10, 500, 10, 0), Some(500));
}

#[test]
fn a_deadline_that_has_passed_is_none() {
    assert_eq!(remaining_until(9, 0, 10, 0), None);
    assert_eq!(
        remaining_until(10, 0, 10, 0),
        None,
        "exactly now has passed"
    );
    assert_eq!(remaining_until(10, 0, 10, 1), None);
}

/// A guest may name any deadline it likes, and the answer to "how long until
/// i64::MAX seconds from now" must not be a negative number.
#[test]
fn an_unreachable_deadline_saturates() {
    let left = remaining_until(i64::MAX, 0, 0, 0);
    assert_eq!(left, Some(i64::MAX));
    assert!(left.unwrap() > 0);
}

#[test]
fn a_deadline_before_the_epoch_is_past() {
    assert_eq!(remaining_until(i64::MIN, 0, 0, 0), None);
}

#[test]
fn the_deadline_abi_reports_zero_for_past() {
    assert_eq!(timeabi_remaining_until(10, 0, 9, 0), NSEC_PER_SEC);
    assert_eq!(timeabi_remaining_until(9, 0, 10, 0), 0);
}

/// Both halves, and the interval unconditionally -- including when the
/// value is zero, which is how a timer is disarmed.
#[test]
fn an_itimerspec_is_checked_on_both_halves() {
    assert!(itimerspec_valid(0, 0, 0, 0), "disarming is valid");
    assert!(itimerspec_valid(1, 500, 2, 600));
    assert!(!itimerspec_valid(0, -1, 0, 0), "a bad value");
    assert!(
        !itimerspec_valid(0, 0, 0, -1),
        "a bad interval with a zero value"
    );
    assert!(!itimerspec_valid(0, 0, -1, 0));
    assert!(!itimerspec_valid(0, NSEC_PER_SEC, 0, 0));
    assert!(!itimerspec_valid(0, 0, 0, NSEC_PER_SEC));
}

/// A timeout must never expire early, so the remainder rounds *up*. Half
/// a millisecond is one, not zero -- zero is a spin.
#[test]
fn a_sub_millisecond_timeout_is_not_zero() {
    assert_eq!(timespec_to_poll_ms(0, 500_000), Some(1));
    assert_eq!(timespec_to_poll_ms(0, 1), Some(1));
    assert_eq!(timespec_to_poll_ms(0, 999_999), Some(1));
}

/// Zero is the one case that is genuinely zero: "poll and return".
#[test]
fn zero_stays_zero() {
    assert_eq!(timespec_to_poll_ms(0, 0), Some(0));
}

#[test]
fn whole_milliseconds_are_exact() {
    assert_eq!(timespec_to_poll_ms(0, NSEC_PER_MSEC), Some(1));
    assert_eq!(timespec_to_poll_ms(0, 20 * NSEC_PER_MSEC), Some(20));
    assert_eq!(timespec_to_poll_ms(1, 0), Some(1_000));
    assert_eq!(timespec_to_poll_ms(2, 500 * NSEC_PER_MSEC), Some(2_500));
}

/// A timespec that is not a time gets no answer at all. The C computed
/// `sec * 1000 + nsec / 1000000` on unchecked input, so {-1, 0} came out
/// as -1000 -- and a negative timeout means "wait for ever" to poll.
#[test]
fn an_invalid_timespec_has_no_millisecond_count() {
    assert_eq!(timespec_to_poll_ms(-1, 0), None);
    assert_eq!(timespec_to_poll_ms(0, -1), None);
    assert_eq!(timespec_to_poll_ms(0, NSEC_PER_SEC), None);
    assert_eq!(timespec_to_poll_ms(i64::MIN, 0), None);
}

/// The boundary the C got wrong: a sum of exactly a billion nanoseconds is
/// one second, not a denormalised zero seconds. `pthread_cond_timedwait`
/// answers EINVAL for the latter, which reads as a spurious wake.
#[test]
fn a_whole_second_of_nanoseconds_carries() {
    assert_eq!(absolute_deadline(5, 400_000_000, 0, 600_000_000), (6, 0));
    assert_ne!(
        absolute_deadline(5, 400_000_000, 0, 600_000_000).1,
        NSEC_PER_SEC,
        "a denormalised tv_nsec is what pthread_cond_timedwait refuses"
    );
}

#[test]
fn a_sum_below_a_second_does_not_carry() {
    assert_eq!(
        absolute_deadline(5, 400_000_000, 2, 599_999_999),
        (7, 999_999_999)
    );
    assert_eq!(absolute_deadline(0, 0, 0, 0), (0, 0));
}

/// Above a second as well as at it. One carry is enough for two normalised
/// inputs, and the arithmetic does not depend on that being true.
#[test]
fn a_sum_above_a_second_carries_once() {
    assert_eq!(
        absolute_deadline(1, 999_999_999, 1, 999_999_999),
        (3, 999_999_998)
    );
}

/// A deadline past the end of time is one that never arrives.
#[test]
fn the_far_future_saturates_rather_than_wrapping() {
    let (sec, nsec) = absolute_deadline(i64::MAX, 999_999_999, 10, 999_999_999);
    assert_eq!(sec, i64::MAX);
    assert!((0..NSEC_PER_SEC).contains(&nsec));
}

/// Longer than poll can express is clamped rather than wrapped. Wrapping
/// a large second count produces a negative int, which is the hang again.
///
/// **An overflowing multiply is that case too**, and this asserted `None`
/// for it until 2026-09-03 — matching a `checked_mul(...)?` that made
/// `ppoll(tv_sec = LLONG_MAX)` answer `EINVAL`. `timespec_valid` is
/// Linux's rule and puts no upper bound on `tv_sec`, because Linux
/// saturates; `poll_probe` is what found it.
#[test]
fn a_huge_timeout_is_clamped_not_wrapped() {
    assert_eq!(
        timespec_to_poll_ms(i64::MAX, 0),
        Some(i32::MAX),
        "an overflow is 'longer than can be expressed', not an error"
    );
    let far = timespec_to_poll_ms(1 << 40, 0).unwrap();
    assert_eq!(far, i32::MAX);
    assert!(far > 0, "a clamped timeout must not come out negative");
}

#[test]
fn the_boundary_of_a_valid_timespec() {
    assert!(timespec_valid(0, 0));
    assert!(timespec_valid(0, NSEC_PER_SEC - 1));
    assert!(timespec_valid(i64::MAX, 0));
    assert!(!timespec_valid(0, NSEC_PER_SEC));
    assert!(!timespec_valid(0, -1));
    assert!(!timespec_valid(-1, 0));
    assert!(!timespec_valid(0, i64::MAX));
    assert!(!timespec_valid(i64::MIN, 0));
}

/// A negative nanosecond field is invalid, not small. Read as small, a
/// request Linux refuses is answered with success -- which is the shape of
/// the defect the fast path in nanosleep had.
#[test]
fn a_negative_nanosecond_count_is_never_a_short_sleep() {
    for nsec in [-1i64, -999, -NSEC_PER_SEC, i64::MIN + 1] {
        assert!(!timespec_valid(0, nsec), "{nsec}");
    }
}

#[test]
fn an_itimerval_is_only_valid_if_both_halves_are() {
    assert!(itimerval_valid(0, 0, 0, 0));
    assert!(itimerval_valid(1, 999_999, 1, 999_999));
    // The value alone being fine is not enough.
    assert!(!itimerval_valid(0, 0, 0, USEC_PER_SEC));
    assert!(!itimerval_valid(0, 0, 0, -1));
    // Nor the interval alone.
    assert!(!itimerval_valid(0, USEC_PER_SEC, 0, 0));
    assert!(!itimerval_valid(0, -1, 0, 0));
    assert!(!itimerval_valid(-1, 0, 0, 0));
}

/// Anything that passes validation converts without overflowing -- so the
/// order (validate, then convert) is safe, and the checked conversion is
/// there for the case where someone gets that order wrong.
#[test]
fn a_valid_timeval_always_converts() {
    for sec in [0i64, 1, 1000, i64::MAX / 2] {
        for usec in [0i64, 1, 999_999] {
            assert!(timeval_valid(sec, usec));
            assert!(usec_to_nsec(usec).is_some(), "{usec}");
        }
    }
}

#[test]
fn the_conversion_refuses_rather_than_wrapping() {
    assert_eq!(usec_to_nsec(1_000), Some(1_000_000));
    assert_eq!(usec_to_nsec(0), Some(0));
    assert_eq!(usec_to_nsec(i64::MAX), None);
    assert_eq!(usec_to_nsec(i64::MIN), None);
    // Just inside and just outside.
    assert!(usec_to_nsec(i64::MAX / 1000).is_some());
    assert!(usec_to_nsec(i64::MAX / 1000 + 1).is_none());
}

/// The monotonic clock answers, advances, and goes through the saturating
/// conversion rather than a plain multiply.
///
/// The third assertion is the one that is about *this* function rather than
/// about the host: five crates had their own `now_ns` and three multiplied
/// plainly, which is an overflow check in a debug build. There is no way to
/// hand `monotonic_ns` a bad `timespec` from a test — it asks the host — so
/// what is asserted here is that it is monotonic and non-zero, and
/// `a_host_timespec_cannot_wrap` above covers the
/// arithmetic it delegates to.
#[test]
fn the_monotonic_clock_advances() {
    let a = monotonic_ns();
    assert_ne!(a, 0, "the host has a monotonic clock");
    let b = monotonic_ns();
    assert!(b >= a, "monotonic: {b} came after {a}");
    // A second reading some work later is still sane rather than wrapped.
    let c = monotonic_ns();
    assert!(c >= b && c - a < 60 * 1_000_000_000, "no wrap, no jump");
}
