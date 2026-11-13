//! The one interval timer a thread group can have armed.
//!
//! `struct tgroup`'s `itimer` — a handle into `crates/util/timer`, created the
//! first time `setitimer(ITIMER_REAL)` is called and freed when the group
//! goes.
//!
//! # No lock, and that is not a shortcut
//!
//! The C held `tgroup->lock` around the whole of `itimer_set`, and what that
//! lock was doing was two things: keeping the lazy creation from happening
//! twice, and serialising `timer_set` against `timer_get`. The second is
//! `crates/util/timer`'s own job and it does it — the timer service has a lock
//! over its table. So all that is left is the creation, which is a
//! compare-exchange.
//!
//! A thread that loses the exchange frees the timer it made and uses the
//! winner's, which is one wasted `timer_new` in a race that happens at most
//! once per process. Without the exchange the loser's timer is *installed* and
//! the winner's is leaked — still armed, still firing, and read by nobody, so
//! the group gets a `SIGALRM` it did not ask for.
//!
//! That race is not reachable from `tests/guest/src/bin/itimer_abi.rs`, which
//! passes either way: `install` is only called when the group has no timer, and
//! one thread never races itself. `exactly_one_of_many_racing_installs_wins`
//! below is what covers it, and it fails against a plain store. The alternative — a lock held across `timer_new`, which
//! takes the timer service's — is a lock order for the sake of a case that
//! resolves itself.
//!
//! # Only `ITIMER_REAL` exists
//!
//! `ITIMER_VIRTUAL` and `ITIMER_PROF` count CPU time, and this kernel has no
//! running total to hang a deadline on: user and system time are sampled from
//! the host on demand, not accumulated. They are `EINVAL` rather than a timer
//! that never fires — a program that asks for a profiling signal and never
//! gets one waits for ever, and one that is refused falls back. `getitimer`
//! answers for them, because a program is entitled to ask whether one is armed
//! and the answer is "no". That rule is `crates/kernel/timecalls`'; what is
//! here is the handle.

use std::sync::atomic::{AtomicU64, Ordering};

/// `TIMER_NONE` from `util/timer.h`: no timer.
const NONE: u64 = 0;

#[derive(Debug, Default)]
pub struct Itimer {
    id: AtomicU64,
}

impl Itimer {
    pub fn new() -> Itimer {
        Itimer::default()
    }

    /// The timer this group has, or `TIMER_NONE`.
    pub fn get(&self) -> u64 {
        self.id.load(Ordering::Acquire)
    }

    /// Stores `made` if the group has no timer, and answers whichever is now
    /// the group's.
    ///
    /// A caller that gets back something other than what it made lost the
    /// race and frees its own. `TIMER_NONE` in is a caller that made nothing,
    /// and answers whatever is there.
    pub fn install(&self, made: u64) -> u64 {
        if made == NONE {
            return self.get();
        }
        match self
            .id
            .compare_exchange(NONE, made, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => made,
            Err(existing) => existing,
        }
    }

    /// Removes the timer and answers it, for the caller to free. `TIMER_NONE`
    /// when there was none.
    pub fn take(&self) -> u64 {
        self.id.swap(NONE, Ordering::AcqRel)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_fresh_group_has_no_timer() {
        let t = Itimer::new();
        assert_eq!(t.get(), NONE);
        assert_eq!(t.take(), NONE, "and taking none answers none");
        // A caller that made nothing gets back what is there, which is nothing.
        assert_eq!(t.install(NONE), NONE);
    }

    #[test]
    fn the_first_timer_installed_is_the_groups() {
        let t = Itimer::new();
        assert_eq!(t.install(7), 7);
        assert_eq!(t.get(), 7);
        // The second caller is told about the first's, which is its cue to free
        // the one it made.
        assert_eq!(t.install(9), 7);
        assert_eq!(t.get(), 7);
        // And a caller with nothing to install still reads it.
        assert_eq!(t.install(NONE), 7);
    }

    #[test]
    fn taking_it_leaves_room_for_another() {
        let t = Itimer::new();
        t.install(7);
        assert_eq!(t.take(), 7);
        assert_eq!(t.get(), NONE);
        assert_eq!(t.install(9), 9, "and the next one wins");
    }

    /// Exactly one winner, however many threads arrive at once. Every loser is
    /// told the winner's id, which is what it frees its own against.
    #[test]
    fn exactly_one_of_many_racing_installs_wins() {
        for _ in 0..64 {
            let t = Arc::new(Itimer::new());
            let hands: Vec<_> = (1..=8u64)
                .map(|n| {
                    let t = Arc::clone(&t);
                    std::thread::spawn(move || t.install(n))
                })
                .collect();
            let answers: Vec<u64> = hands.into_iter().map(|h| h.join().unwrap()).collect();
            let winner = t.get();
            assert!((1..=8).contains(&winner));
            assert!(
                answers.iter().all(|&a| a == winner),
                "every caller was told the same timer: {answers:?} against {winner}"
            );
        }
    }
}
