//! Time validation, deadline arithmetic, and timeout conversions.

use crate::{NSEC_PER_SEC, NSEC_PER_USEC, USEC_PER_SEC};

/// Convert a non-negative host `timespec` to nanoseconds without wrapping.
///
/// Host monotonic clocks are non-negative, and a value past the range of a
/// `u64` represents a deadline that cannot arrive in this process's lifetime.
/// Keep that meaning instead of allowing debug overflow checks to abort the
/// caller.
pub fn host_timespec_to_ns(sec: i64, nsec: i64) -> u64 {
    (sec.max(0) as u64)
        .saturating_mul(NSEC_PER_SEC as u64)
        .saturating_add(nsec.max(0) as u64)
}

/// The host monotonic clock, in nanoseconds.
///
/// **One definition.** Five crates had a private `now_ns` of their own on
/// 2026-09-15 — `kernel/waitcalls`, `kernel/tgroup`, `fs/poll`,
/// `kernel/epollcalls` and `fs/sock` — all asking `CLOCK_MONOTONIC` and all
/// answering `u64` nanoseconds, and only one of the five used
/// [`host_timespec_to_ns`]. Three did the arithmetic as
///
/// ```ignore
/// ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
/// ```
///
/// which is a plain multiply: in a debug build that is an overflow check, and
/// the doc on `host_timespec_to_ns` says avoiding exactly that is what it is
/// for. They are deadline arithmetic for `poll`, `epoll_wait`, `wait4` and
/// socket batching, so the answer feeds a timeout rather than a display.
///
/// **`crates/fs/fakechange` deliberately does not use this** and says so on
/// its own function: it wants the clock that does not run while the device is
/// asleep, which on Apple is `CLOCK_UPTIME_RAW` rather than
/// `CLOCK_MONOTONIC`. That is a different question, not a second answer to
/// this one.
pub fn monotonic_ns() -> u64 {
    // A failure reads as zero, which is "no time has passed" -- the
    // conservative direction for a deadline. `CLOCK_MONOTONIC` exists
    // everywhere this builds, so it does not happen.
    let (sec, nsec) = host_clock(libc::CLOCK_MONOTONIC).unwrap_or((0, 0));
    host_timespec_to_ns(sec, nsec)
}

/// A host clock's reading as `(seconds, nanoseconds)`, or the host `errno` for
/// an id the host does not have.
///
/// **The one `clock_gettime` in the tree.** There were eleven, each with its
/// own `timespec` -- three of them `mem::zeroed` -- and its own `unsafe`, and
/// eight of them discarded the return value, so a failure read as the epoch
/// with nothing to say it was chosen. A caller that still reads a failure as
/// zero now writes `unwrap_or((0, 0))` where it can be seen. The obligation is
/// discharged here and has no caller's half: the pointer is to a local, and
/// any `id` may be passed, since an unknown one is `EINVAL` rather than
/// undefined.
pub fn host_clock(id: libc::clockid_t) -> Result<(i64, i64), i32> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a local `timespec`, writable for the call.
    if unsafe { libc::clock_gettime(id, &mut ts) } != 0 {
        return Err(last_errno());
    }
    Ok((ts.tv_sec, ts.tv_nsec))
}

/// [`host_clock`]'s resolution, with the same contract.
pub fn host_clock_res(id: libc::clockid_t) -> Result<(i64, i64), i32> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: as above.
    if unsafe { libc::clock_getres(id, &mut ts) } != 0 {
        return Err(last_errno());
    }
    Ok((ts.tv_sec, ts.tv_nsec))
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL)
}

/// `clock_nanosleep`'s only flag.
pub const TIMER_ABSTIME: u32 = 1;

/// Whether `clock_nanosleep`'s `flags` asks for an absolute deadline.
///
/// **Linux does not validate the other bits**, and this is written down because
/// it looks as though it should. `SYSCALL_DEFINE4(clock_nanosleep, ...)` tests
/// `flags & TIMER_ABSTIME` and never `flags & ~TIMER_ABSTIME`, so
/// `clock_nanosleep(CLOCK_MONOTONIC, 2, ...)` is a *relative* sleep that
/// succeeds.
///
/// A rejection was written here and a real arm64 kernel disagreed — five checks
/// in `tests/guest/src/bin/sleep_abi.rs` said so before the change reached
/// anything. `docs/changelog/2026-08-29-clock-nanosleep-slept-against-a-stopwatch.md`
/// records it, because the rule reads like one that ought to exist.
pub fn nanosleep_is_absolute(flags: u32) -> bool {
    flags & TIMER_ABSTIME != 0
}

/// How much of an absolute deadline is left, in nanoseconds. `None` when it has
/// passed.
///
/// Recomputed on every pass of the sleep loop rather than converted to a
/// duration once, which is the defect this replaces: the C worked out
/// `deadline - now` and then slept for that long, so anything that delayed the
/// thread between the two — a page fault, another thread, the host scheduler —
/// came out of the far end of the sleep and the deadline was missed by that
/// much. Linux sleeps against the clock, not against a stopwatch.
///
/// Saturating rather than wrapping: a guest may name a deadline of `i64::MAX`
/// seconds, and the answer to "how long until then" is "longer than you can
/// express", not a negative number.
pub fn remaining_until(
    deadline_sec: i64,
    deadline_nsec: i64,
    now_sec: i64,
    now_nsec: i64,
) -> Option<i64> {
    let deadline = deadline_sec
        .saturating_mul(NSEC_PER_SEC)
        .saturating_add(deadline_nsec);
    let now = now_sec
        .saturating_mul(NSEC_PER_SEC)
        .saturating_add(now_nsec);
    let left = deadline.saturating_sub(now);
    (left > 0).then_some(left)
}

/// `now + relative`, as a **normalised** `timespec`.
///
/// `pthread_cond_timedwait` takes an absolute deadline on Linux and a relative
/// one on Apple, so `util/sync.c` builds this on the Linux side only. It got
/// the normalisation wrong for one value: the carry was `if (tv_nsec >
/// 1000000000)`, so a sum of **exactly** a billion was left denormalised.
/// POSIX requires `tv_nsec` in `[0, 999999999]` and `pthread_cond_timedwait`
/// answers `EINVAL` for anything else — which is neither 0 nor `ETIMEDOUT`, so
/// the wait reported a spurious wake and the caller's loop spun until the
/// deadline instead of sleeping to it. A caller asking for a whole number of
/// seconds hits it whenever the clock's nanosecond field happens to be zero.
///
/// Both `nsec` arguments are expected below a billion, which is what a
/// `clock_gettime` and a normalised relative timeout give, so one carry is
/// enough. It is a `divmod` anyway, because "one carry is enough" is exactly
/// the reasoning that was wrong.
///
/// Saturating on the seconds: a deadline past the end of time is one that never
/// arrives, which is what a caller asking for it meant.
pub fn absolute_deadline(now_sec: i64, now_nsec: i64, rel_sec: i64, rel_nsec: i64) -> (i64, i64) {
    let nsec = now_nsec.saturating_add(rel_nsec);
    let carry = nsec.div_euclid(NSEC_PER_SEC);
    let sec = now_sec.saturating_add(rel_sec).saturating_add(carry);
    (sec, nsec.rem_euclid(NSEC_PER_SEC))
}

/// A `rusage`'s user and system halves as one nanosecond count, which is what
/// the CPU-time clocks report.
///
/// **Both halves**, which is the defect this replaces: `CLOCK_THREAD_CPUTIME_ID`
/// reported only `utime`, so a syscall-heavy program looked idle. CPU time is
/// user plus system in every description of it there is.
///
/// `None` on overflow rather than a wrapped number. Not reachable from a real
/// `rusage` — it would take 292 years of CPU — but the multiplication is the
/// kind that is checked or is undefined, and the C's was neither.
pub fn cpu_time_nsec(
    utime_sec: i64,
    utime_usec: i64,
    stime_sec: i64,
    stime_usec: i64,
) -> Option<i64> {
    let secs = utime_sec.checked_add(stime_sec)?;
    let usecs = utime_usec.checked_add(stime_usec)?;
    secs.checked_mul(NSEC_PER_SEC)?
        .checked_add(usecs.checked_mul(NSEC_PER_USEC)?)
}

/// Nanoseconds as a `timespec`'s two fields.
pub fn nsec_to_timespec(nsec: i64) -> (i64, i64) {
    (nsec / NSEC_PER_SEC, nsec % NSEC_PER_SEC)
}

/// What `clock_getres` reports for a CPU-time clock.
///
/// Linux says a nanosecond. Both used to be `EINVAL` here, because the clock
/// table did not know them — so a program that asks the resolution before using
/// one was told the clock does not exist.
pub const CPUTIME_RESOLUTION_NSEC: i64 = 1;

/// What `clock_getres` reports for the tick-sampled CPU clocks, `PROF` and
/// `VIRT`: `NSEC_PER_SEC / HZ`, with the reference kernel's `HZ` of 1000.
pub const CPUTIME_TICK_NSEC: i64 = 1_000_000;

/// The clock ticks a second, which is `sysconf(_SC_CLK_TCK)` and is 100 on
/// every Linux this emulator targets.
pub const CLOCK_TICKS_PER_SEC: i64 = 100;

/// A `timeval` as clock ticks, which is what `times(2)` and `wait4`'s rusage
/// report.
///
/// Truncating rather than rounding, which is what Linux does: a tick is a
/// hundredth of a second and reporting more time than was spent is worse than
/// reporting less.
pub fn timeval_to_ticks(sec: i64, usec: i64) -> i64 {
    sec.saturating_mul(CLOCK_TICKS_PER_SEC)
        .saturating_add(usec / (USEC_PER_SEC / CLOCK_TICKS_PER_SEC))
}

/// Is this a `struct timespec` a sleep may be asked for?
///
/// Linux's `timespec64_valid`: a non-negative second count and a nanosecond
/// field in `[0, 1e9)`. A negative `tv_nsec` is not "slightly less" — it is
/// invalid, and reading it as a small number is how a request Linux refuses
/// gets answered with success.
pub fn timespec_valid(sec: i64, nsec: i64) -> bool {
    sec >= 0 && (0..NSEC_PER_SEC).contains(&nsec)
}

/// What the wall clock may be set to: a valid time, and below
/// `TIME_SETTOD_SEC_MAX` -- `KTIME_SEC_MAX` less thirty years of uptime, so
/// that the monotonic clock cannot overflow `ktime_t` later.
/// `clock_settime(CLOCK_REALTIME, {LLONG_MAX, 0})` is `EINVAL` for this.
pub fn timespec_valid_settod(sec: i64, nsec: i64) -> bool {
    const KTIME_SEC_MAX: i64 = i64::MAX / NSEC_PER_SEC;
    const TIME_UPTIME_SEC_MAX: i64 = 30 * 365 * 24 * 3600;
    timespec_valid(sec, nsec) && sec < KTIME_SEC_MAX - TIME_UPTIME_SEC_MAX
}

/// The same rule at microsecond scale, for `setitimer` and friends.
pub(crate) fn timeval_valid(sec: i64, usec: i64) -> bool {
    sec >= 0 && (0..USEC_PER_SEC).contains(&usec)
}

/// Both halves of an `itimerspec`, for `timerfd_settime` and `timer_settime`.
///
/// The interval is checked as well as the value, and unconditionally — Linux's
/// `timerfd_settime` refuses a bad interval even when the value is zero, which
/// is the disarming case. That is not pedantry: the interval is what every
/// re-arm after the first one uses, so an unchecked one is a timer that fires
/// at a rate nobody asked for, for as long as the program runs. An interval of
/// `{-1, 0}` accepted here armed a timer that expired continuously.
pub fn itimerspec_valid(
    value_sec: i64,
    value_nsec: i64,
    interval_sec: i64,
    interval_nsec: i64,
) -> bool {
    timespec_valid(value_sec, value_nsec) && timespec_valid(interval_sec, interval_nsec)
}

/// Both halves of an `itimerval`. Linux checks the interval as well as the
/// value: an interval out of range is refused even when the value is fine,
/// because the interval is what every re-arm after the first one uses.
pub fn itimerval_valid(
    value_sec: i64,
    value_usec: i64,
    interval_sec: i64,
    interval_usec: i64,
) -> bool {
    timeval_valid(value_sec, value_usec) && timeval_valid(interval_sec, interval_usec)
}

/// Microseconds to nanoseconds, refusing rather than wrapping.
///
/// `usec * 1000` on a 64-bit microsecond field overflows above about 9.2e15,
/// and the result of a signed overflow is not a number the caller can check —
/// it is undefined behaviour in the C this replaces. A validated `timeval`
/// cannot reach it, which is exactly why the conversion must not be the thing
/// relied on to notice.
pub fn usec_to_nsec(usec: i64) -> Option<i64> {
    usec.checked_mul(NSEC_PER_USEC)
}

pub const NSEC_PER_MSEC: i64 = 1_000_000;

/// A validated `timespec` as a nanosecond count, **saturating**.
///
/// Every wait in this kernel needs this and five of them wrote it out:
/// `sec * 1_000_000_000 + nsec`, on a value the guest chose. `timespec_valid`
/// is Linux's rule and puts **no upper bound on `tv_sec`** — Linux saturates —
/// so `LLONG_MAX` is a request a real kernel accepts, and the multiply
/// overflows.
///
/// What that costs depends on the build, and both answers are bad. With
/// overflow checks on it is a panic inside an `extern "C"` function, which
/// cannot unwind, so the **whole emulator aborts** — one syscall, one argument,
/// from any guest. With them off it wraps, and a wait meant to last for ever
/// returns at whatever time the wrapped number names.
///
/// `tools/lock-order.py`'s sibling problem: it was fixed in
/// `timespec_to_poll_ms` on 2026-09-03 after `poll_probe` found it in `ppoll`,
/// and the same line was still written out by hand in `rt_sigtimedwait`,
/// `futex`, `recvmmsg` and `clock_nanosleep`. Saturating rather than checked
/// for the reason stated there: `i64::MAX` nanoseconds is 292 years, which is
/// indistinguishable from waiting until something happens, so an overflow is
/// that case and not an error.
///
/// The caller validates first; this does not, because the callers answer
/// different errnos for an invalid one.
pub fn timespec_to_nsec(sec: i64, nsec: i64) -> i64 {
    sec.saturating_mul(NSEC_PER_SEC).saturating_add(nsec)
}

/// A validated `timespec` as a millisecond count for `poll`, **rounded up**.
///
/// `ppoll` takes nanoseconds and `poll` takes milliseconds, so something has
/// to give. What must not give is the direction: a timeout that expires
/// *early* wakes a caller that asked to be left alone, and a sub-millisecond
/// one truncated to zero turns a wait into a spin. `ppoll(fds, n, {0, 500000})`
/// -- half a millisecond, which every event loop asks for -- became `poll(fds,
/// n, 0)`.
///
/// Returns `None` for a `timespec` that is not a time, which the caller
/// answers `EINVAL`. That mattered more than the rounding: the conversion was
/// `sec * 1000 + nsec / 1000000` on unchecked input, so `{-1, 0}` came out as
/// `-1000`, and a negative timeout means *wait for ever* to `poll`. A guest
/// asking for a negative timeout got a hang.
///
/// Clamped to `i32::MAX` milliseconds -- about 24 days -- because that is what
/// `poll` can express. Anything longer is indistinguishable from waiting until
/// something happens.
pub fn timespec_to_poll_ms(sec: i64, nsec: i64) -> Option<i32> {
    if !timespec_valid(sec, nsec) {
        return None;
    }
    // Saturating, not checked. The clamp below is already the statement that
    // anything past `i32::MAX` milliseconds is indistinguishable from waiting
    // until something happens -- so an overflow is that case, not an error.
    //
    // `checked_mul(...)?` made it an error, and `timespec_valid` puts no upper
    // bound on `tv_sec`: `ppoll` with `tv_sec = LLONG_MAX` is a valid request
    // that Linux accepts and saturates, and this answered `EINVAL`. An event
    // loop that computes an absolute deadline and overflows therefore spins
    // instead of waiting.
    let ms = sec
        .saturating_mul(1_000)
        .saturating_add((nsec + NSEC_PER_MSEC - 1) / NSEC_PER_MSEC);
    Some(ms.min(i32::MAX as i64) as i32)
}
