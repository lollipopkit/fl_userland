//! `timerfd`: a descriptor whose readability is a timer.
//!
//! The state is one number — how many times the timer has fired since the last
//! read — and the arming itself belongs to `crates/util/timer`, which already
//! owns the deadline queue. What this crate adds is the counter and the two
//! sets of rules that were not being applied at all.
//!
//! # The flags nobody checked
//!
//! `timerfd_create` validated neither its flags nor its clock. Any bit pattern
//! was accepted, so a program that asked for `TFD_NONBLOCK` on a kernel that
//! did not have it would be told yes and then hang on the first read. Asked
//! against a real arm64 Linux, six of six garbage flag words are `EINVAL`; this
//! kernel returned a descriptor for all six.
//!
//! `timerfd_settime` had the opposite defect: it rejected
//! `TFD_TIMER_CANCEL_ON_SET`, which Linux accepts.
//!
//! # `TFD_TIMER_CANCEL_ON_SET`
//!
//! Accepted and then not acted on, which needs saying rather than hiding. The
//! flag asks for reads to answer `ECANCELED` after a *discontinuous change to
//! `CLOCK_REALTIME`* — and this kernel's realtime clock is the host's, which a
//! guest cannot set: `clock_settime` is `EPERM` for an ordinary user and there
//! is no path by which a guest moves the host's wall clock. So the event the
//! flag reports cannot occur here, and a timer armed with it behaves exactly as
//! Linux's would on a machine whose clock never jumps.
//!
//! That is not the same as ignoring a flag. `TFD_NONBLOCK` ignored would be a
//! lie about behaviour the caller can observe; this one is a report about an
//! event that has no source.
//!
//! # The clocks
//!
//! Fewer than `clock_gettime` takes. A timer cannot be armed against a clock
//! that only advances while the process is scheduled, so the two CPU-time
//! clocks are `EINVAL` here even though they are readable elsewhere — which is
//! a trap this kernel walked into, because mapping them for `clock_gettime`
//! silently made them acceptable to `timerfd_create` as well.

use pollset::Watchers;
use std::ffi::c_int;
use std::sync::Arc;
use util_guestlock::{GuestLock, Woke};

pub use guest_errno::isize_::{EAGAIN, EINTR, EINVAL};
pub const POLL_READ: i32 = 1;
pub const O_CLOEXEC: u32 = 0o2000000;
pub const O_NONBLOCK: u32 = 0o4000;

/// The one condition this object has: it fired.
const FIRED: u32 = 0;

/// `TFD_TIMER_ABSTIME`: the value is a point on the clock, not a duration.
pub const TFD_TIMER_ABSTIME: u32 = 1;
/// `TFD_TIMER_CANCEL_ON_SET`: see the module comment. Accepted; unreachable
/// here.
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 2;

/// The clock ids a `timerfd` may name, as the guest spells them.
pub const CLOCK_REALTIME: c_int = 0;
pub const CLOCK_MONOTONIC: c_int = 1;
pub const CLOCK_BOOTTIME: c_int = 7;
/// `CLOCK_REALTIME_ALARM` and `CLOCK_BOOTTIME_ALARM`. Linux takes them and
/// requires `CAP_WAKE_ALARM`; there is no wakeup-from-suspend here, so they are
/// refused rather than silently treated as their non-alarm namesakes — a timer
/// that quietly does not wake the machine is the failure the flag exists to
/// prevent.
pub const CLOCK_REALTIME_ALARM: c_int = 8;
pub const CLOCK_BOOTTIME_ALARM: c_int = 9;

/// Everything a timerfd is: how many times it has fired since the last read.
#[derive(Debug, Default)]
pub struct TimerFd {
    pub expirations: u64,
}

/// A timerfd, its lock, and the description's reverse edge.
///
/// The lock is its own rather than the descriptor's. It used to be reached
/// through a five-entry vtable that C bound into a mutable global at startup —
/// C owning the lock and Rust reaching into the state with raw pointers, with
/// nothing checking that the two matched. An expiration count is nobody else's
/// business.
pub struct Descriptor {
    count: GuestLock<TimerFd>,
    watchers: Arc<Watchers>,
}

impl Descriptor {
    /// Create timer state holding its own reference to the description's
    /// reverse edge. The edge remains alive until this state is dropped.
    /// An `Arc` since 2026-09-16, and the second owner is the timer: the host
    /// timer's target *is* this state, so the service thread holds a reference
    /// of its own for the length of an expiry. That is shared ownership in the
    /// sense the word is meant — two holders with independent lifetimes — and
    /// not a borrow checker workaround. What it replaces is the descriptor's
    /// address as a `usize` in the timer's payload, with the "free waits for a
    /// callback in flight" rule as the only thing between an expiry and a
    /// use-after-free.
    pub fn new(watchers: Arc<Watchers>) -> Arc<Self> {
        let count = GuestLock::new(TimerFd::new(), 1);
        LIVE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Arc::new(Self { count, watchers })
    }

    fn wake_pollers(&self, events: u32) {
        self.watchers.notify(events);
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    }
}

impl TimerFd {
    pub fn new() -> TimerFd {
        TimerFd { expirations: 0 }
    }

    /// The timer fired. Saturating rather than wrapping: a count that wrapped
    /// to zero would make a readable descriptor unreadable, which is a hang
    /// rather than a wrong number.
    pub fn fire(&mut self) {
        self.fire_n(1);
    }

    /// `n` expirations at once: an absolute deadline already in the past
    /// counts every interval that has gone by since it, which can be many.
    pub fn fire_n(&mut self, n: u64) {
        self.expirations = self.expirations.saturating_add(n);
    }

    /// Arming again throws away expiries that have already happened.
    ///
    /// This is `timerfd_settime`'s, and it is what makes rescheduling a timer
    /// safe: an event loop that arms a timer, misses the fire, and arms it
    /// again for a later deadline must not then be handed the old expiry the
    /// moment it reads. Nothing reset the count, so it was — measured by
    /// `tests/guest/src/bin/evfd_probe.rs`, where a read after re-arming is
    /// `EAGAIN` on a real kernel and answered a stale count of 1 here.
    ///
    /// It applies to disarming too, which is the same call with a zero value.
    pub fn rearm(&mut self) {
        self.expirations = 0;
    }

    /// `TFD_IOC_SET_TICKS`: the count becomes `n`, whatever it was.
    pub fn set_ticks(&mut self, n: u64) {
        self.expirations = n;
    }

    /// What a read would take, or `None` if it would block.
    pub fn try_read(&mut self) -> Option<u64> {
        if self.expirations == 0 {
            return None;
        }
        Some(core::mem::replace(&mut self.expirations, 0))
    }

    /// Which poll events a reader would see right now. Never writable: there
    /// is nothing to write to a timerfd.
    pub fn poll_types(&self) -> i32 {
        if self.expirations != 0 { POLL_READ } else { 0 }
    }
}

/// An absolute deadline `late_ns` in the past, on a timer with this interval:
/// how many expirations that already is, and how long until the next one --
/// 0 for a timer with no interval, which then has nothing left to do.
///
/// Linux's answer, from `hrtimer_forward`: the deadline itself is one, every
/// whole interval since is another, and the next fire is the next interval
/// boundary after now -- a whole interval away when now is on one.
///
/// **Counted here, at `settime`, and not left to the host timer.** An already
/// expired deadline was armed as a zero-or-negative delay and counted when the
/// timer thread next woke, so a nonblocking read straight after `settime` could
/// run first and answer `EAGAIN`, where Linux answers the count: `timer_probe`
/// saw it under load. A deadline of exactly now was worse, and armed nothing
/// at all, because a zero value is how a timer is *disarmed*.
pub fn overdue(late_ns: u128, interval_ns: u128) -> (u64, u128) {
    if interval_ns == 0 {
        return (1, 0);
    }
    let whole = late_ns / interval_ns;
    let count = u64::try_from(whole.saturating_add(1)).unwrap_or(u64::MAX);
    (count, interval_ns - late_ns % interval_ns)
}

/// Are these `timerfd_create` flags ones this implements?
pub fn create_flags_valid(flags: u32) -> bool {
    flags & !(O_CLOEXEC | O_NONBLOCK) == 0
}

/// Are these `timerfd_settime` flags ones Linux defines?
pub fn settime_flags_valid(flags: u32) -> bool {
    flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) == 0
}

/// May a timerfd be armed against this clock?
pub fn clock_valid(clockid: c_int) -> bool {
    matches!(clockid, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME)
}

// ---------------------------------------------------------------------------
// The interface
// ---------------------------------------------------------------------------
//
// Rust, not `extern "C"`. It was a C ABI until 2026-08-31, because the
// descriptor and its three syscalls were C; they are
// crates/kernel/timerfdcalls now, and an export no C can reach is what
// `tools/dead-exports.py` is for. `timerfd_live_count` is the exception:
// fs/proc/iul.c reads it for the leak check.

/// How many timerfd states exist, for the leak check. The C had nothing to
/// free -- the counter was a field in a union -- so moving the state
/// introduced a way to leak that did not exist before.
pub static LIVE: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);

/// The host timer's target is the descriptor state itself.
///
/// Which is the whole of what the `(fn(usize), usize)` pair was expressing, and
/// the callback it replaces had a null check the other two consumers' did not —
/// an untyped payload leaves that decision to each caller. There is no null
/// here to check.
impl util_timer::Expire for Descriptor {
    fn expired(&self) {
        self.fire();
    }
}

impl Descriptor {
    /// Discard expirations from the timer that was armed before this call.
    pub fn rearm(&self) {
        self.count.lock().rearm();
    }

    /// Record one expiration and notify readers and pollers.
    pub fn fire(&self) {
        self.fire_n(1);
    }

    /// Record `n` expirations and notify readers and pollers.
    pub fn fire_n(&self, n: u64) {
        {
            let mut count = self.count.lock();
            count.fire_n(n);
            count.owner().notify(FIRED);
        }
        self.wake_pollers(POLL_READ as u32);
    }

    /// Replace the expiration count and notify readers and pollers.
    pub fn set_ticks(&self, n: u64) {
        {
            let mut count = self.count.lock();
            count.set_ticks(n);
            count.owner().notify(FIRED);
        }
        self.wake_pollers(POLL_READ as u32);
    }

    /// Read the expiration count, waiting when required.
    pub fn read_count(&self, nonblock: i32, out: &mut u64) -> isize {
        let mut count = self.count.lock();
        loop {
            if let Some(value) = count.try_read() {
                *out = value;
                return 8;
            }
            if nonblock != 0 {
                return EAGAIN;
            }
            if count.wait(FIRED, None) == Woke::Interrupted {
                return EINTR;
            }
        }
    }

    /// Return the readiness bits currently reported by the timer.
    pub fn poll_types(&self) -> i32 {
        self.count.lock().poll_types()
    }

    /// The expirations a read would take now, without taking them.
    pub fn ticks(&self) -> u64 {
        self.count.lock().expirations
    }
}

pub fn timerfd_live_count() -> i64 {
    LIVE.load(core::sync::atomic::Ordering::Relaxed)
}

/// Everything a timerfd descriptor owns.
///
/// `state`'s rules — the saturating count, the blocking read, the poll answer —
/// are [`Descriptor`]'s. What is added is the two things that only make sense
/// next to a descriptor: which host timer drives it, and which clock that timer
/// runs on.
///
/// **Here since 2026-09-29**, from `crates/kernel/timerfdcalls`. It was the
/// syscall crate's, which put `kernel-taskview` in its owner's closure and kept
/// `struct fd`'s `state.timerfd` an opaque placeholder with a cast at each of
/// three readers. Nothing in it needs the syscall layer.
pub struct Instance {
    /// Shared with the host timer, which holds the other reference: the
    /// timer's target *is* this state. It was a `Box` and the timer carried
    /// `&mut *this as *mut TimerFd as usize`, so an expiry reconstructed a
    /// `*mut TimerFd` -- this type, in that crate -- and tested it for null.
    pub state: Arc<Descriptor>,
    /// The host timer, or [`TIMER_NONE`].
    pub timer: u64,
    /// The **host** clock id, as `timer_new` was given it. An absolute deadline
    /// is made relative against this one.
    pub clockid: c_int,
    /// The guest's clock id, as `timerfd_create` was given it, for
    /// `/proc/<pid>/fdinfo`.
    pub guest_clockid: c_int,
    /// The flags of the last `timerfd_settime` that armed or disarmed it
    /// (`TFD_TIMER_ABSTIME`, `TFD_TIMER_CANCEL_ON_SET`), for the same file.
    pub settime_flags: core::sync::atomic::AtomicU32,
}

/// 0 is never a real timer, so it is the "none yet" value.
pub const TIMER_NONE: u64 = 0;

impl Drop for Instance {
    fn drop(&mut self) {
        // The timer first. Its callback runs on the timer thread and touches
        // the state, so freeing the state while a firing is in flight would be
        // a use-after-free; `timer_free` waits for a callback already running.
        if self.timer != TIMER_NONE {
            util_timer::timer_free(self.timer);
        }
    }
}

#[cfg(test)]
mod blocking_tests;

#[cfg(test)]
mod tests {
    use super::*;

    const S: u128 = 1_000_000_000;

    /// A deadline in the past with no interval is one expiration, and then
    /// nothing is left armed.
    #[test]
    fn an_overdue_one_shot_is_one_expiration_and_done() {
        assert_eq!(overdue(10 * S, 0), (1, 0));
        assert_eq!(overdue(0, 0), (1, 0), "a deadline of exactly now has expired");
    }

    /// With an interval, every whole interval since the deadline is another,
    /// and the next fire is at the next boundary.
    #[test]
    fn an_overdue_interval_counts_what_went_by() {
        // 10.5 s late on a 1 s interval: the deadline, and ten more.
        assert_eq!(overdue(10 * S + S / 2, S), (11, S / 2));
        // Exactly on a boundary: that boundary is counted and the next is a
        // whole interval away.
        assert_eq!(overdue(3 * S, S), (4, S));
        // Less than one interval late.
        assert_eq!(overdue(S / 4, S), (1, 3 * S / 4));
    }

    /// A count too large for the read is the largest one, not a wrapped one.
    #[test]
    fn an_overdue_count_saturates() {
        assert_eq!(overdue(u128::MAX, 1).0, u64::MAX);
    }

    /// Arming again throws away what has already expired.
    ///
    /// This is what makes rescheduling safe, and nothing did it: an event loop
    /// that armed a timer, missed the fire and armed it again for a later
    /// deadline was handed the old expiry the moment it read, and acted on a
    /// deadline it had replaced. `tests/guest/src/bin/evfd_probe.rs` measures
    /// it against a real kernel, where the read after a re-arm is `EAGAIN`.
    #[test]
    fn arming_again_discards_an_expiry_that_already_happened() {
        let mut t = TimerFd::new();
        t.fire();
        t.fire();
        t.rearm();
        assert_eq!(t.try_read(), None, "the two expiries went with the re-arm");
        assert_eq!(t.poll_types(), 0, "and it is not readable any more");
        // A fire after the re-arm is the new timer's and is kept.
        t.fire();
        assert_eq!(t.try_read(), Some(1));
    }

    #[test]
    fn a_read_takes_the_whole_count_and_clears_it() {
        let mut t = TimerFd::new();
        assert_eq!(t.try_read(), None, "an unarmed timer has nothing to give");
        t.fire();
        t.fire();
        t.fire();
        assert_eq!(
            t.try_read(),
            Some(3),
            "a read reports every expiry since the last one"
        );
        assert_eq!(t.try_read(), None, "and leaves nothing behind");
    }

    /// A count that wrapped to zero would make a readable descriptor
    /// unreadable, which is a hang rather than a wrong number.
    #[test]
    fn the_count_saturates_rather_than_wrapping() {
        let mut t = TimerFd {
            expirations: u64::MAX,
        };
        t.fire();
        assert_eq!(t.expirations, u64::MAX);
        assert_eq!(t.try_read(), Some(u64::MAX));
    }

    #[test]
    fn poll_is_readable_only_with_an_expiry_and_never_writable() {
        let mut t = TimerFd::new();
        assert_eq!(t.poll_types(), 0);
        t.fire();
        assert_eq!(t.poll_types(), POLL_READ);
        t.try_read();
        assert_eq!(t.poll_types(), 0);
    }

    /// The two that exist and nothing else. This kernel accepted every one of
    /// the rejected cases below and returned a working descriptor, so a
    /// program that asked for a flag this does not have was told yes.
    #[test]
    fn create_takes_cloexec_and_nonblock_only() {
        assert!(create_flags_valid(0));
        assert!(create_flags_valid(O_CLOEXEC));
        assert!(create_flags_valid(O_NONBLOCK));
        assert!(create_flags_valid(O_CLOEXEC | O_NONBLOCK));
        assert!(
            !create_flags_valid(1),
            "TFD_TIMER_ABSTIME is a settime flag"
        );
        assert!(!create_flags_valid(2));
        assert!(!create_flags_valid(4));
        assert!(!create_flags_valid(0o10000));
        assert!(!create_flags_valid(0x8000_0000));
        assert!(
            !create_flags_valid(O_CLOEXEC | 1),
            "one good bit does not excuse a bad one"
        );
    }

    /// Both of Linux's, including the one this kernel refused.
    #[test]
    fn settime_takes_abstime_and_cancel_on_set() {
        assert!(settime_flags_valid(0));
        assert!(settime_flags_valid(TFD_TIMER_ABSTIME));
        assert!(settime_flags_valid(TFD_TIMER_CANCEL_ON_SET));
        assert!(settime_flags_valid(
            TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET
        ));
        assert!(!settime_flags_valid(4));
        assert!(!settime_flags_valid(8));
        assert!(!settime_flags_valid(0x8000_0000));
    }

    /// The CPU-time clocks are the trap: they are readable through
    /// `clock_gettime`, and mapping them there silently made them acceptable
    /// here, producing a timerfd that could never become readable.
    #[test]
    fn the_clocks_are_fewer_than_clock_gettime_takes() {
        assert!(clock_valid(CLOCK_REALTIME));
        assert!(clock_valid(CLOCK_MONOTONIC));
        assert!(clock_valid(CLOCK_BOOTTIME));
        assert!(!clock_valid(2), "CLOCK_PROCESS_CPUTIME_ID");
        assert!(!clock_valid(3), "CLOCK_THREAD_CPUTIME_ID");
        assert!(!clock_valid(4), "CLOCK_MONOTONIC_RAW");
        assert!(!clock_valid(5), "CLOCK_REALTIME_COARSE");
        assert!(!clock_valid(6), "CLOCK_MONOTONIC_COARSE");
        assert!(
            !clock_valid(CLOCK_REALTIME_ALARM),
            "no wakeup from suspend here"
        );
        assert!(!clock_valid(CLOCK_BOOTTIME_ALARM));
        assert!(!clock_valid(99));
        assert!(!clock_valid(-1));
    }
}
