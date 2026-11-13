//! Two rules the wait loop applies, without the loop.
//!
//! `fs/poll.c` holds the loop itself — it reads `current` for pending signals,
//! group exit and the idle valve, and that is task policy. What is here is the
//! arithmetic and the decision, which are pure and were both wrong.

/// A nanosecond clock reading. Monotonic; the loop uses `CLOCK_MONOTONIC`.
pub type Nanos = u64;

/// How long the next pass may block, in milliseconds.
///
/// Each pass waits at most a second so that signals and group exit stay
/// responsive, and the guest's own timeout is a **deadline fixed once**. The C
/// deducted a flat second per *timed-out* pass, which left every other way of
/// going round the loop free: a wakeup that turned out not to be for us
/// restarted the whole second, so a stream of unrelated wakeups held a timed
/// wait open indefinitely.
///
/// `None` means the deadline has arrived and the wait is over with nothing
/// ready — which is a `poll()` returning 0, not an error.
pub fn slice_ms(deadline: Option<Nanos>, now: Nanos) -> Option<i32> {
    const SECOND_MS: i32 = 1000;
    let Some(deadline) = deadline else {
        return Some(SECOND_MS);
    };
    if now >= deadline {
        return None;
    }
    let remaining = deadline - now;
    if remaining >= 1_000_000_000 {
        return Some(SECOND_MS);
    }
    // Rounded **up**: a remaining time under half a millisecond would round
    // down to zero, and a zero slice is a spin rather than a wait.
    Some(remaining.div_ceil(1_000_000) as i32)
}

/// What the idle-exit valve is asked about a thread group.
#[derive(Clone, Copy, Debug)]
pub struct Idle {
    /// `IUL_IDLE_EXIT`, in seconds. Zero or less is off, which is the default.
    pub limit_secs: i64,
    /// How long since this group last made progress.
    pub idle_secs: i64,
    /// pid 1 legitimately idles; killing it halts the system.
    pub is_init: bool,
    /// An interactive shell idles waiting for a key.
    pub has_ctty: bool,
    /// A process waiting on a child it started is not idle, whatever it is
    /// blocked in.
    pub has_live_children: bool,
}

/// Whether to end the whole thread group.
///
/// This valve was written for "V8/libuv exit cleanup hangs" and killed **any**
/// process idle in `poll()` for its limit — every daemon waiting for a
/// connection — and it exits the group with status **0**, so a supervisor sees
/// success. It is off by default now and this is what it does when it is on;
/// see `docs/changelog/` and the note in `fs/poll.c`.
///
/// Narrowing it to what it is for would need a reproducer of that hang, and
/// there is not one here.
pub fn should_give_up(i: &Idle) -> bool {
    if i.limit_secs <= 0 {
        return false;
    }
    if i.is_init || i.has_ctty {
        return false;
    }
    if i.idle_secs < i.limit_secs {
        return false;
    }
    !i.has_live_children
}

/// How many whole seconds have passed, for [`Idle::idle_secs`].
///
/// Saturating rather than wrapping: `now` is behind `last` only if the clock
/// went backwards, and a huge idle time would then trip the valve on a process
/// that had just made progress.
pub(crate) fn idle_secs(last: Nanos, now: Nanos) -> i64 {
    (now.saturating_sub(last) / 1_000_000_000) as i64
}

// ---------------------------------------------------------------------------
// The C boundary
// ---------------------------------------------------------------------------

/// [`slice_ms`], with `-1` for "the deadline has arrived".
///
/// The two arguments rather than an `Option` because the loop in `fs/poll.c`
/// has a `bool timed` beside its deadline.
pub fn poll_slice_ms(timed: bool, deadline_ns: u64, now_ns: u64) -> i32 {
    slice_ms(timed.then_some(deadline_ns), now_ns).unwrap_or(-1)
}

/// [`should_give_up`].
pub fn poll_should_give_up(
    limit_secs: i64,
    idle_secs: i64,
    is_init: bool,
    has_ctty: bool,
    has_live_children: bool,
) -> bool {
    should_give_up(&Idle {
        limit_secs,
        idle_secs,
        is_init,
        has_ctty,
        has_live_children,
    })
}

/// [`idle_secs`].
pub fn poll_idle_secs(last_ns: u64, now_ns: u64) -> i64 {
    idle_secs(last_ns, now_ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: Nanos = 1_000_000_000;

    /// An untimed wait always takes the full second, whatever the clock says.
    #[test]
    fn an_untimed_wait_is_a_second_a_pass() {
        assert_eq!(slice_ms(None, 0), Some(1000));
        assert_eq!(slice_ms(None, 999 * SEC), Some(1000));
    }

    /// A deadline further off than a second is still a second: the cap is what
    /// keeps signals and group exit responsive.
    #[test]
    fn a_distant_deadline_is_capped_at_a_second() {
        assert_eq!(slice_ms(Some(10 * SEC), 0), Some(1000));
        assert_eq!(slice_ms(Some(2 * SEC), SEC), Some(1000));
    }

    /// A nearer one is what is left, rounded up. Rounding down would give a
    /// zero slice for anything under half a millisecond, and a zero slice is a
    /// spin.
    #[test]
    fn a_near_deadline_is_what_is_left_rounded_up() {
        assert_eq!(slice_ms(Some(SEC / 2), 0), Some(500));
        assert_eq!(slice_ms(Some(1_500_000), 0), Some(2), "1.5ms rounds to 2");
        assert_eq!(
            slice_ms(Some(1), 0),
            Some(1),
            "a nanosecond is still a wait"
        );
        assert_eq!(slice_ms(Some(SEC - 1), 0), Some(1000));
    }

    /// The deadline arriving ends the wait, and a deadline already past ends it
    /// immediately rather than waiting a second first.
    #[test]
    fn an_arrived_deadline_ends_the_wait() {
        assert_eq!(slice_ms(Some(SEC), SEC), None);
        assert_eq!(slice_ms(Some(SEC), 2 * SEC), None);
        assert_eq!(slice_ms(Some(0), 0), None);
    }

    /// The deadline is fixed, so going round the loop for a reason that was not
    /// the timeout does not extend it. The C deducted a second per *timed-out*
    /// pass, so a stream of unrelated wakeups held a timed wait open for ever;
    /// here the same deadline with a later `now` is simply less time.
    #[test]
    fn an_unrelated_wakeup_does_not_extend_a_timed_wait() {
        let deadline = Some(SEC);
        let mut previous = slice_ms(deadline, 0).expect("not yet");
        for now in [SEC / 4, SEC / 2, 3 * SEC / 4] {
            let slice = slice_ms(deadline, now).expect("not yet");
            assert!(slice < previous, "{slice} is not less than {previous}");
            previous = slice;
        }
        assert_eq!(slice_ms(deadline, SEC), None);
    }

    /// Off by default, and off is the answer whatever else is true.
    #[test]
    fn the_valve_is_off_unless_it_is_switched_on() {
        let idle = Idle {
            limit_secs: 0,
            idle_secs: 1_000_000,
            is_init: false,
            has_ctty: false,
            has_live_children: false,
        };
        assert!(!should_give_up(&idle));
        assert!(!should_give_up(&Idle {
            limit_secs: -1,
            ..idle
        }));
    }

    /// The three exemptions, each on its own.
    #[test]
    fn init_a_terminal_and_a_live_child_are_each_enough() {
        let tripping = Idle {
            limit_secs: 60,
            idle_secs: 61,
            is_init: false,
            has_ctty: false,
            has_live_children: false,
        };
        assert!(should_give_up(&tripping), "the case the valve is for");

        assert!(!should_give_up(&Idle {
            is_init: true,
            ..tripping
        }));
        assert!(!should_give_up(&Idle {
            has_ctty: true,
            ..tripping
        }));
        assert!(!should_give_up(&Idle {
            has_live_children: true,
            ..tripping
        }));
    }

    /// The boundary. `idle == limit` trips, because the limit is "this long or
    /// longer" — and one second short does not.
    #[test]
    fn the_limit_is_inclusive() {
        let at = Idle {
            limit_secs: 60,
            idle_secs: 60,
            is_init: false,
            has_ctty: false,
            has_live_children: false,
        };
        assert!(should_give_up(&at));
        assert!(!should_give_up(&Idle {
            idle_secs: 59,
            ..at
        }));
    }

    /// A clock that went backwards must not read as an enormous idle time and
    /// kill a process that had just made progress.
    #[test]
    fn a_backwards_clock_is_no_idle_time() {
        assert_eq!(idle_secs(0, 5 * SEC), 5);
        assert_eq!(idle_secs(5 * SEC, 5 * SEC), 0);
        assert_eq!(idle_secs(10 * SEC, 5 * SEC), 0, "now behind last");
        assert_eq!(idle_secs(0, SEC - 1), 0, "not a whole second yet");
    }
}
