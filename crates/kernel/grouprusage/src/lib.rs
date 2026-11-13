//! What a thread group's exited threads and reaped children consumed.
//!
//! Two `struct rusage_` fields of `struct tgroup` — `rusage` and
//! `children_rusage` — with the lock that guards them and the arithmetic that
//! adds to them.
//!
//! # Microseconds, not seconds and microseconds
//!
//! The guest's `struct timeval` is a pair, and every defect this arithmetic has
//! had was a carry between the halves. The C carried once, so a `src` that was
//! not normalised — `usec` at or above a million, which nothing guaranteed it
//! was not — left `dst` denormalised too, and a guest libc doing arithmetic on
//! that is wrong by whole seconds. It was fixed by carrying in a loop.
//!
//! Stored as one number there is nothing to carry. A pair goes in, a pair comes
//! out, and the pair that comes out is normalised whatever went in — which is
//! not a rule anyone has to remember, because it is the only thing the
//! representation can do.
//!
//! # The lock
//!
//! Its own, where this was `tgroup->lock`. Nothing else is read with it: the
//! two accumulators are independent of the rest of the group, and the C took
//! the group lock around them only because that lock is where everything
//! without a lock of its own ended up. It is innermost and takes nothing.

use std::sync::Mutex;

/// The guest's `struct timeval`: seconds and microseconds, both signed.
///
/// Declared here rather than generated because it is two words and
/// `kernel/time.h` asserts nothing about it that a `#[repr(C)]` pair of `i64`
/// does not say. `crates/kernel/hostrusage` re-exports this one; it had an
/// identical copy until 2026-09-05, and the two met through a C ABI call that
/// converted without checking.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeval {
    pub sec: i64,
    pub usec: i64,
}

plain::plain!(Timeval { sec, usec });

impl Timeval {
    /// Whatever the pair says, as one number. A `usec` above a million is not
    /// refused: it is what the pair means.
    pub fn to_micros(self) -> i64 {
        self.sec.saturating_mul(1_000_000).saturating_add(self.usec)
    }

    /// Normalised: `usec` in `[0, 1_000_000)` for a positive total, and the
    /// borrow taken out of `sec` for a negative one.
    pub fn from_micros(us: i64) -> Timeval {
        let mut sec = us / 1_000_000;
        let mut usec = us % 1_000_000;
        if usec < 0 {
            usec += 1_000_000;
            sec -= 1;
        }
        Timeval { sec, usec }
    }
}

/// One accumulator: user time and system time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Times {
    pub utime_us: i64,
    pub stime_us: i64,
}

impl Times {
    pub fn add(&mut self, utime: Timeval, stime: Timeval) {
        self.utime_us = self.utime_us.saturating_add(utime.to_micros());
        self.stime_us = self.stime_us.saturating_add(stime.to_micros());
    }

    pub fn utime(self) -> Timeval {
        Timeval::from_micros(self.utime_us)
    }

    pub fn stime(self) -> Timeval {
        Timeval::from_micros(self.stime_us)
    }
}

#[derive(Debug, Default)]
struct State {
    /// This group's threads that have already exited.
    own: Times,
    /// The children this group has reaped, and the ones it released without
    /// waiting for — a parent asked for those times the moment it calls
    /// `getrusage(RUSAGE_CHILDREN)`, and releasing a child early is not a
    /// reason to lose them.
    children: Times,
}

#[derive(Debug, Default)]
pub struct GroupRusage {
    state: Mutex<State>,
}

impl GroupRusage {
    pub fn new() -> GroupRusage {
        GroupRusage::default()
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Adds an exited thread's times and answers the group's new total.
    ///
    /// One call, because the C did the add and then read the field back for the
    /// parent — two operations under one lock, which is what this is.
    pub fn add_own(&self, utime: Timeval, stime: Timeval) -> Times {
        self.with(|s| {
            s.own.add(utime, stime);
            s.own
        })
    }

    pub fn own(&self) -> Times {
        self.with(|s| s.own)
    }

    pub fn add_children(&self, utime: Timeval, stime: Timeval) {
        self.with(|s| s.children.add(utime, stime));
    }

    pub fn children(&self) -> Times {
        self.with(|s| s.children)
    }

    /// What this group's **exited threads** consumed, and what its **reaped
    /// children** did, read under one acquisition.
    ///
    /// `times_of(Option<&GroupRusage>)` until 2026-09-30, a free function
    /// whose `None` was the null a group's `times` field no longer has. Both
    /// halves were functions in `kernel/task.c` until 2026-09-03.
    pub fn both(&self) -> (Times, Times) {
        self.with(|s| (s.own, s.children))
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    fn tv(sec: i64, usec: i64) -> Timeval {
        Timeval { sec, usec }
    }

    /// A pair that is not normalised still means what it says, and what comes
    /// back always is.
    ///
    /// This is the defect the C carried once for: `{1, 1_500_000}` is one and a
    /// half seconds, and adding it to `{0, 0}` used to leave `{1, 1_500_000}`
    /// rather than `{2, 500_000}`.
    #[test]
    fn a_denormalised_input_comes_back_normalised() {
        assert_eq!(tv(1, 1_500_000).to_micros(), 2_500_000);
        assert_eq!(Timeval::from_micros(2_500_000), tv(2, 500_000));
        let mut t = Times::default();
        t.add(tv(1, 1_500_000), tv(0, 0));
        assert_eq!(t.utime(), tv(2, 500_000));
        // And several times over, which is what "carry as many times as it
        // takes" was written for.
        let mut t = Times::default();
        t.add(tv(0, 9_999_999), tv(0, 0));
        assert_eq!(t.utime(), tv(9, 999_999));
    }

    /// Every microsecond count round-trips, and `usec` never leaves its range.
    #[test]
    fn every_total_normalises_into_range() {
        for us in [0i64, 1, 999_999, 1_000_000, 1_000_001, 123_456_789] {
            let t = Timeval::from_micros(us);
            assert!((0..1_000_000).contains(&t.usec), "{us} -> {t:?}");
            assert_eq!(t.to_micros(), us);
        }
    }

    /// A negative total borrows rather than leaving a negative `usec`.
    ///
    /// Nothing here should produce one — times only accumulate — but a guest
    /// can hand a negative pair to something that adds it, and `-1 % 1_000_000`
    /// is `-1` in Rust as it is in C.
    #[test]
    fn a_negative_total_borrows_from_the_seconds() {
        assert_eq!(Timeval::from_micros(-1), tv(-1, 999_999));
        assert_eq!(Timeval::from_micros(-1).to_micros(), -1);
        assert_eq!(Timeval::from_micros(-1_000_000), tv(-1, 0));
        assert_eq!(Timeval::from_micros(-1_500_000), tv(-2, 500_000));
        assert_eq!(Timeval::from_micros(-1_500_000).to_micros(), -1_500_000);
    }

    /// The two accumulators are independent: a reaped child does not move the
    /// group's own total and vice versa.
    #[test]
    fn a_groups_own_time_and_its_childrens_are_different_answers() {
        let g = GroupRusage::new();
        g.add_own(tv(1, 0), tv(2, 0));
        g.add_children(tv(10, 0), tv(20, 0));
        assert_eq!(g.own().utime(), tv(1, 0));
        assert_eq!(g.own().stime(), tv(2, 0));
        assert_eq!(g.children().utime(), tv(10, 0));
        assert_eq!(g.children().stime(), tv(20, 0));
    }

    /// `add_own` answers the new total, which is what the exiting thread hands
    /// to its parent — the C read the field back after the add, under the same
    /// lock, and this is that pair of operations.
    #[test]
    fn adding_answers_the_new_total() {
        let g = GroupRusage::new();
        assert_eq!(g.add_own(tv(1, 500_000), tv(0, 0)).utime(), tv(1, 500_000));
        let t = g.add_own(tv(0, 600_000), tv(0, 0));
        assert_eq!(
            t.utime(),
            tv(2, 100_000),
            "and the carry is across calls too"
        );
        assert_eq!(g.own(), t);
    }

    /// Nothing overflows into nonsense: a guest cannot make this wrap by
    /// handing over a large pair.
    #[test]
    fn an_enormous_pair_saturates_rather_than_wrapping() {
        let mut t = Times::default();
        t.add(tv(i64::MAX, i64::MAX), tv(0, 0));
        assert_eq!(t.utime_us, i64::MAX);
        t.add(tv(i64::MAX, 0), tv(0, 0));
        assert_eq!(t.utime_us, i64::MAX, "and stays there");
    }
}
