//! The transient poll set — everything `poll()`, `ppoll()`, `select()` and
//! `pselect()` need for one wait, and the reverse edge from an open file
//! description back to the threads waiting on it.
//!
//! `fs/poll.c` used to own three things at once: a set of registrations, an
//! intrusive list linking each registration into its descriptor, and the host
//! wait. The list is what made it hard. A registration node was reachable from
//! the descriptor and from the set, freed by whichever tore down first, and the
//! loser of that race retried under `sched_yield` while holding neither lock.
//!
//! Here the set owns a strong reference to every member and to one [`Waiter`],
//! and each description holds one [`Watchers`] list of everything waiting on
//! it — transient sets and durable watchers such as epoll alike. Nothing is
//! reachable from two owners, so nothing races: a set that goes away removes
//! its own entries, and a description that goes away drops its list. The set
//! itself never leaves the thread that made the syscall and therefore holds no
//! lock at all — where the C took the set's lock on every pass of the wait and
//! again on every wakeup, for every registration.
//!
//! What stays in C is what needs `struct fd`: a member's readiness, its host
//! descriptor and whether it is a socket are the callbacks in [`Ops`]. This
//! crate never dereferences a member pointer.

mod set;
pub mod wait;
mod waiter;

pub use set::{Members, PollSet};
pub use waiter::{Waiter, WakeSet, Watcher, Watchers};

use std::panic::{AssertUnwindSafe, catch_unwind};

/// Publish a readiness transition to everything watching this description.
///
/// Takes no descriptor lock. The one rule a caller must keep is that a watcher
/// may ask the description for its current readiness, so this must not be
/// called while holding a lock the description's own poll operation takes —
/// see `poll_wakeup` in `fs/poll.h`.
pub fn poll_watchers_notify(watchers: &Watchers, events: u32) {
    catch_unwind(AssertUnwindSafe(|| watchers.notify(events))).unwrap_or(())
}

/// The description is closing: every durable watcher loses what it holds
/// naming it.
///
/// Both take a reference since 2026-09-30, when a description started
/// holding its list as an `Arc` rather than an `Arc::into_raw` pointer that a
/// `poll_watchers_new` here made and `fd_finalize` took back by hand.
pub fn poll_watchers_closed(watchers: &Watchers) {
    catch_unwind(AssertUnwindSafe(|| watchers.closed())).unwrap_or(())
}

// The `pollset_*` free functions were here until 2026-09-09: eleven
// `pub unsafe fn` over a `*mut PollSet`, each checking for null and some
// wrapping the body in `catch_unwind`. They existed because `fs/poll.c` called
// them, and that file is gone -- `crates/fs/poll` is the only caller and holds
// the set as a value. What they were doing is what `Box`, `Drop` and a method
// do, so [`PollSet`] is the API and the wrapper is not.
