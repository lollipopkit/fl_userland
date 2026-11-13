//! `eventfd`: a counter you can wait on.
//!
//! The first stateful object moved to Rust. The crate allocates and owns the
//! state, keeps its reverse watcher edge through an `Arc`, and exposes typed
//! methods to the descriptor callbacks.
//!
//! # What is still C, and why
//!
//! One allocation. `wait_for` is the emulator's interruptible condition wait:
//! it returns `EINTR` when a guest signal arrives, and nothing in `std` does
//! that — a guest asleep on a Rust condvar could not be killed. So the mutex
//! and its condition variable are C's, through [`GuestLock`], and the state
//! they protect is this crate's, reachable only through the guard.
//!
//! The lock remains a small C-backed primitive because `wait_for` must be
//! interruptible by guest signals. The counter and its watcher edge are Rust
//! state, and raw pointer conversion is limited to the FFI boundary.
//!
//! # The counter
//!
//! A read empties it; a write adds to it. Both block while they cannot proceed
//! — a read on zero, a write that would overflow — unless the descriptor is
//! non-blocking, when they answer `EAGAIN`. `EFD_SEMAPHORE` makes a read take
//! one instead of all of it.

use pollset::Watchers;
use std::sync::Arc;
use util_guestlock::{GuestLock, Woke};

pub use guest_errno::isize_::{EAGAIN, EINTR, EINVAL};
pub const POLL_READ: i32 = 1;
pub const POLL_WRITE: i32 = 4;
pub const O_CLOEXEC: u32 = 0o2000000;
pub const O_NONBLOCK: u32 = 0o4000;

/// The one condition this object has: the counter changed.
const CHANGED: u32 = 0;

/// An eventfd, its lock, and the description's reverse edge.
///
/// The reverse edge is owned through an `Arc`, so the state cannot outlive the
/// watcher list it notifies.
pub struct Descriptor {
    counter: GuestLock<EventFd>,
    watchers: Arc<Watchers>,
    id: Id,
}

impl Descriptor {
    /// Allocate an eventfd state and retain its reverse edge.
    pub fn new(initval: u64, semaphore: bool, watchers: Arc<Watchers>) -> Box<Self> {
        let counter = GuestLock::new(EventFd::new(initval, semaphore), 1);
        LIVE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Box::new(Self { counter, watchers, id: Id::new() })
    }

    /// The three lines `/proc/<pid>/fdinfo` adds for an eventfd, in
    /// `eventfd_show_fdinfo`'s layout: the count as `%16llx`, padded with
    /// spaces, the id and whether it is a semaphore.
    pub fn fdinfo(&self) -> String {
        let (count, semaphore) = {
            let counter = self.counter.lock();
            (counter.val, counter.semaphore)
        };
        format!(
            "eventfd-count: {count:16x}\neventfd-id: {}\neventfd-semaphore: {}\n",
            self.id.0,
            u8::from(semaphore)
        )
    }

    fn wake_pollers(&self, events: u32) {
        self.watchers.notify(events);
    }

    /// Read the counter, waiting until a value is available when required.
    pub fn read(&self, nonblock: bool) -> Result<u64, isize> {
        let taken = {
            let mut counter = self.counter.lock();
            loop {
                if let Some(value) = counter.try_read() {
                    counter.owner().notify(CHANGED);
                    break Ok(value);
                }
                if nonblock {
                    break Err(EAGAIN);
                }
                if counter.wait(CHANGED, None) == Woke::Interrupted {
                    break Err(EINTR);
                }
            }
        };
        if taken.is_ok() {
            self.wake_pollers(POLL_WRITE as u32);
        }
        taken
    }

    /// Add to the counter, waiting for room when required.
    pub fn write(&self, nonblock: bool, increment: u64) -> Result<(), isize> {
        if increment == u64::MAX {
            return Err(EINVAL);
        }
        let done = {
            let mut counter = self.counter.lock();
            loop {
                if counter.try_write(increment).is_some() {
                    counter.owner().notify(CHANGED);
                    break Ok(());
                }
                if nonblock {
                    break Err(EAGAIN);
                }
                if counter.wait(CHANGED, None) == Woke::Interrupted {
                    break Err(EINTR);
                }
            }
        };
        if done.is_ok() {
            self.wake_pollers(POLL_READ as u32);
        }
        done
    }

    /// Return the readiness bits currently reported by the counter.
    pub fn poll_types(&self) -> i32 {
        self.counter.lock().poll_types()
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// An eventfd's `eventfd-id`: the lowest number no live eventfd has, which is
/// what Linux's `ida_alloc` hands out. CRIU and `lsof` tell two eventfds apart
/// by it. Released when the eventfd goes.
struct Id(u32);

static IDS: std::sync::Mutex<std::collections::BTreeSet<u32>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

impl Id {
    fn new() -> Id {
        let mut used = IDS.lock().unwrap_or_else(|e| e.into_inner());
        let id = lowest_free(&used);
        used.insert(id);
        Id(id)
    }
}

/// The first gap: the set is ordered, so the n-th entry is n until it is not.
fn lowest_free(used: &std::collections::BTreeSet<u32>) -> u32 {
    used.iter()
        .zip(0u32..)
        .find(|&(&u, n)| u != n)
        .map_or(used.len() as u32, |(_, n)| n)
}

impl Drop for Id {
    fn drop(&mut self) {
        IDS.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.0);
    }
}

/// `EFD_SEMAPHORE`. Not an open flag: it must not reach `f_install`, which
/// would read bit 0 as `O_WRONLY`.
pub const EFD_SEMAPHORE: u32 = 1;

/// Everything an eventfd is.
#[derive(Debug)]
pub struct EventFd {
    pub val: u64,
    pub semaphore: bool,
}

impl EventFd {
    pub fn new(initval: u64, semaphore: bool) -> EventFd {
        EventFd {
            val: initval,
            semaphore,
        }
    }

    /// What a read would take, or `None` if it would block.
    ///
    /// Split out from the blocking loop so the decision — which is all of the
    /// eventfd semantics — is a pure function with tests, and the loop around
    /// it is the only thing that needs a lock.
    pub fn try_read(&mut self) -> Option<u64> {
        if self.val == 0 {
            return None;
        }
        Some(if self.semaphore {
            self.val -= 1;
            1
        } else {
            core::mem::replace(&mut self.val, 0)
        })
    }

    /// Add to the counter, or `None` if it would overflow and must wait.
    ///
    /// The counter's ceiling is `u64::MAX - 1`: `u64::MAX` is reserved, so a
    /// write that would reach it blocks rather than saturating.
    pub fn try_write(&mut self, increment: u64) -> Option<()> {
        if increment == u64::MAX {
            return None;
        }
        let sum = self.val.checked_add(increment)?;
        // `==`, not `>=`: `sum` is a `u64`, so the two are the same test and
        // only one of them says what the doc comment above says --
        // `u64::MAX` is the reserved value, not a bound to stay under.
        if sum == u64::MAX {
            return None;
        }
        self.val = sum;
        Some(())
    }

    /// Which poll events a reader would see right now.
    pub fn poll_types(&self) -> i32 {
        let mut types = 0;
        if self.val > 0 {
            types |= POLL_READ;
        }
        if self.val < u64::MAX - 1 {
            types |= POLL_WRITE;
        }
        types
    }
}

/// Are these `eventfd2` flags ones this implements?
pub fn flags_valid(flags: u32) -> bool {
    flags & !(EFD_SEMAPHORE | O_CLOEXEC | O_NONBLOCK) == 0
}

// ---------------------------------------------------------------------------
// Allocation accounting
// ---------------------------------------------------------------------------

/// How many eventfd states exist. Only for the leak check below; a counter
/// that is never read would be dead weight, and one that is read only by a
/// test would prove nothing about the build that ships.
pub static LIVE: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);

/// How many are allocated right now.
///
/// The old counter was two fields in a C union, while the Rust descriptor is a
/// heap allocation. This makes the close path checkable from a guest instead
/// of by reading `fd_close` and believing it.
pub fn eventfd_live_count() -> i64 {
    LIVE.load(core::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
mod blocking_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// Lowest free first, so a released id is handed out again. On a set
    /// rather than the global, which the other tests' eventfds share.
    #[test]
    fn an_eventfd_id_is_the_lowest_free_one() {
        let set = |v: &[u32]| v.iter().copied().collect::<std::collections::BTreeSet<u32>>();
        assert_eq!(lowest_free(&set(&[])), 0);
        assert_eq!(lowest_free(&set(&[0, 1, 2])), 3);
        assert_eq!(lowest_free(&set(&[0, 2, 3])), 1);
        assert_eq!(lowest_free(&set(&[1, 2])), 0);
    }

    #[test]
    fn fdinfo_is_linuxs_layout() {
        let watchers = Arc::new(Watchers::default());
        let d = Descriptor::new(0x1234_5678_9abc, true, watchers);
        let text = d.fdinfo();
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("eventfd-count:     123456789abc"));
        assert!(lines.next().unwrap().starts_with("eventfd-id: "));
        assert_eq!(lines.next(), Some("eventfd-semaphore: 1"));
    }

    /// A plain read takes the whole counter and leaves nothing.
    #[test]
    fn a_read_empties_the_counter() {
        let mut ev = EventFd::new(7, false);
        assert_eq!(ev.try_read(), Some(7));
        assert_eq!(ev.val, 0);
        assert_eq!(ev.try_read(), None, "and there is nothing left to take");
    }

    /// In semaphore mode it takes one, which is the whole difference between
    /// an event flag and a counting semaphore.
    #[test]
    fn a_semaphore_read_takes_one() {
        let mut ev = EventFd::new(3, true);
        assert_eq!(ev.try_read(), Some(1));
        assert_eq!(ev.val, 2);
        assert_eq!(ev.try_read(), Some(1));
        assert_eq!(ev.try_read(), Some(1));
        assert_eq!(ev.try_read(), None);
    }

    #[test]
    fn a_write_adds() {
        let mut ev = EventFd::new(0, false);
        assert_eq!(ev.try_write(5), Some(()));
        assert_eq!(ev.try_write(6), Some(()));
        assert_eq!(ev.val, 11);
    }

    /// The ceiling is `u64::MAX - 1`. A write that would reach `u64::MAX`
    /// blocks; it does not saturate, because saturating would report a count
    /// the guest never wrote.
    #[test]
    fn a_write_that_would_reach_the_ceiling_waits() {
        let mut ev = EventFd::new(u64::MAX - 1, false);
        assert_eq!(ev.try_write(1), None);
        assert_eq!(ev.val, u64::MAX - 1, "and the counter is untouched");
        assert_eq!(ev.try_write(0), Some(()), "adding nothing always fits");
    }

    /// The addition must not wrap on the way to deciding. `val + increment` in
    /// 64-bit arithmetic overflows here and comes out small, which reads as
    /// "plenty of room".
    #[test]
    fn an_overflowing_write_does_not_wrap_into_acceptance() {
        let mut ev = EventFd::new(u64::MAX - 10, false);
        assert_eq!(ev.try_write(100), None);
        assert_eq!(ev.val, u64::MAX - 10);
        // And one that exactly fits is taken.
        assert_eq!(ev.try_write(9), Some(()));
        assert_eq!(ev.val, u64::MAX - 1);
    }

    /// `u64::MAX` is not a value the counter may be given at all.
    #[test]
    fn the_reserved_value_is_never_written() {
        let mut ev = EventFd::new(0, false);
        assert_eq!(ev.try_write(u64::MAX), None);
        assert_eq!(ev.val, 0);
    }

    #[test]
    fn poll_reports_readable_when_there_is_something() {
        assert_eq!(EventFd::new(0, false).poll_types(), POLL_WRITE);
        assert_eq!(EventFd::new(1, false).poll_types(), POLL_READ | POLL_WRITE);
        assert_eq!(EventFd::new(u64::MAX - 1, false).poll_types(), POLL_READ);
    }

    #[test]
    fn the_flags_are_the_three_this_implements() {
        assert!(flags_valid(0));
        assert!(flags_valid(EFD_SEMAPHORE));
        assert!(flags_valid(O_CLOEXEC | O_NONBLOCK));
        assert!(flags_valid(EFD_SEMAPHORE | O_CLOEXEC | O_NONBLOCK));
        assert!(!flags_valid(0x40), "an undefined flag");
        assert!(!flags_valid(2), "O_WRONLY is not an eventfd flag");
    }
}
