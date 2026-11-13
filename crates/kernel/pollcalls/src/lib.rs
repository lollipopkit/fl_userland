//! Waiting on a set of descriptors: `select`, `pselect`, `poll` and `ppoll`.
//!
//! The set itself is `fs/poll.c` — building one, registering with the host, and
//! the wait loop, whose task policy (pending signals, group exit, the idle-exit
//! valve) is what keeps it there. What is here is everything on either side:
//! the two guest representations of "which descriptors and which events", the
//! bounds on them, and the merge that registers a description once.
//!
//! # The bound on `nfds` is not pedantry
//!
//! Both calls size arrays from a number the guest chose. `select`'s three sets
//! were stack arrays with nothing between `nfds` and the bit count, so
//! `select(1000000000, ...)` asked for 125 MB of stack three times over; and
//! `poll`'s two were stack VLAs, so `ppoll(fds, 100000000, ...)` asked for 800
//! MB and took the emulator down along with every other guest process in it.
//!
//! Linux bounds both by `RLIMIT_NOFILE` — `select` clamps and `poll` refuses —
//! because a bit past the last descriptor a process may open can never be set,
//! and a poll naming more descriptors than it may have open cannot be answered.
//! Both allocate on the heap even so: a descriptor limit is allowed to be
//! large, and a limit-sized array is not something to put on a stack either.


use std::ffi::{c_int, c_uint};

use strace::strace;
use usercopy::GuestMem;
use util_timeabi as timeabi;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

use guest_errno::Errno;
use guest_errno::i64_::{EBADF, EFAULT, EINVAL};

// Through the enum, not the macros: three of these names belong to
// `<signal.h>` as well, and bindgen keeps the definition it saw first. See
// this crate's `build.rs`.
const POLL_READ: c_int = fs_poll::bits::READ as c_int;
const POLL_PRI: c_int = fs_poll::bits::PRI as c_int;
const POLL_WRITE: c_int = fs_poll::bits::WRITE as c_int;
const POLL_ERR: c_int = fs_poll::bits::ERR as c_int;
const POLL_HUP: c_int = fs_poll::bits::HUP as c_int;
const POLL_NVAL: c_int = fs_poll::bits::NVAL as c_int;
/// Not used by anything here, and that is the assertion: it is the one bit a
/// caller has to ask for, so it is absent from `POLL_ALWAYS_LISTENING`.
#[allow(dead_code)]
const POLL_RDHUP: c_int = fs_poll::bits::RDHUP as c_int;
const RLIMIT_NOFILE: c_int = ffi::RLIMIT_NOFILE_ as c_int;

/// What each of `select`'s three sets asks about.
///
/// A read set wants a hang-up and an error too — a descriptor whose peer has
/// gone is *readable* as far as `select` is concerned, and a caller that does
/// not treat it so spins.
const SELECT_READ: c_int = POLL_READ | POLL_HUP | POLL_ERR;
const SELECT_WRITE: c_int = POLL_WRITE | POLL_ERR;
const SELECT_EX: c_int = POLL_PRI;

/// The time left of a `ppoll` or `pselect6` timeout, written back.
///
/// Linux's `poll_select_finish` does this for both at syscall level, on every
/// return -- success, timeout and `EINTR` alike -- and libc's `select`
/// relies on it. A zero timeout has nothing to write and a null one is not
/// there; a destination that cannot be written is ignored, as Linux ignores
/// it, because the call's own answer is the one that matters. This wrote
/// nothing until 2026-11-11 (`clock2_probe`).
struct Remaining {
    addr: u64,
    deadline_ns: u64,
}

impl Remaining {
    fn start(addr: u64, sec: i64, nsec: i64) -> Option<Remaining> {
        if addr == 0 || (sec == 0 && nsec == 0) {
            return None;
        }
        let ns = u64::try_from(timeabi::timespec_to_nsec(sec, nsec)).unwrap_or(u64::MAX);
        Some(Remaining { addr, deadline_ns: timeabi::monotonic_ns().saturating_add(ns) })
    }

    fn finish(self) {
        let left = self.deadline_ns.saturating_sub(timeabi::monotonic_ns());
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&((left / 1_000_000_000) as i64).to_le_bytes());
        b[8..].copy_from_slice(&((left % 1_000_000_000) as i64).to_le_bytes());
        let _ = GuestMem.write(self.addr, &b);
    }
}

#[path = "poll.rs"]
mod poll;
#[path = "select.rs"]
mod select;
#[cfg(test)]
pub(crate) use poll::POLL_ALWAYS_LISTENING;
pub use poll::sys_ppoll;
pub use select::sys_pselect;
#[cfg(test)]
pub(crate) use select::{bit_set, bit_test, bits_size};

#[cfg(test)]
mod tests {
    use super::*;

    /// Every poll bit is a distinct bit, which is what catches the constants
    /// coming from the wrong header.
    ///
    /// `POLL_ERR`, `POLL_PRI` and `POLL_HUP` are `<signal.h>` names too -- 4, 5
    /// and 6, the `si_code`s a `SIGIO` carries -- and the first version of this
    /// crate got those instead of `fs/poll.h`'s. Nothing about the arithmetic
    /// complained: `POLL_ERR` came out as 4, which is `POLL_WRITE`, so a
    /// `poll()` waiting to read an eventfd was satisfied by the eventfd merely
    /// being writable and returned at once with `revents = POLLOUT`.
    ///
    /// Asserting the values would restate them and defeat the point of
    /// generating them. Asserting the *shape* does not: 3, 5 and 6 are not
    /// powers of two, and 4 is already taken.
    #[test]
    fn every_poll_bit_is_a_distinct_bit() {
        let bits = [
            ("READ", POLL_READ),
            ("PRI", POLL_PRI),
            ("WRITE", POLL_WRITE),
            ("ERR", POLL_ERR),
            ("HUP", POLL_HUP),
            ("NVAL", POLL_NVAL),
            ("RDHUP", POLL_RDHUP),
        ];
        let mut seen = 0;
        for (name, bit) in bits {
            assert!(
                bit > 0 && bit.count_ones() == 1,
                "{name} = {bit} is not one bit"
            );
            assert_eq!(seen & bit, 0, "{name} = {bit} collides with an earlier bit");
            seen |= bit;
        }
    }

    /// The bit arithmetic `select`'s three sets are built from.
    #[test]
    fn a_set_holds_one_bit_per_descriptor() {
        assert_eq!(bits_size(0), 0);
        assert_eq!(bits_size(1), 1);
        assert_eq!(bits_size(8), 1);
        assert_eq!(bits_size(9), 2);
        let mut set = vec![0u8; bits_size(64)];
        bit_set(0, &mut set);
        bit_set(63, &mut set);
        assert!(bit_test(0, &set) && bit_test(63, &set));
        assert!(!bit_test(1, &set) && !bit_test(62, &set));
        // Out of range reads false and writes nothing, rather than running off
        // the end -- the clamp to RLIMIT_NOFILE can leave a caller's index
        // beyond the set this allocated.
        assert!(!bit_test(64, &set));
        bit_set(64, &mut set);
        assert_eq!(set.len(), 8);
    }

    /// A read set asks about hang-up and error too: a descriptor whose peer has
    /// gone is readable as far as `select` is concerned, and a caller that does
    /// not treat it so spins.
    #[test]
    fn the_select_masks_include_what_a_caller_must_not_miss() {
        assert_ne!(SELECT_READ & POLL_HUP, 0);
        assert_ne!(SELECT_READ & POLL_ERR, 0);
        assert_ne!(SELECT_WRITE & POLL_ERR, 0);
        assert_eq!(SELECT_EX, POLL_PRI);
        // And they are disjoint enough that the callback can tell them apart.
        assert_ne!(SELECT_READ & POLL_READ, 0);
        assert_eq!(SELECT_WRITE & POLL_READ, 0);
    }

    /// `POLL_RDHUP` is not in the always-listening set, and that is the point:
    /// a program that does not know about half-closes must not start seeing a
    /// bit it will not recognise.
    #[test]
    fn rdhup_is_only_reported_to_a_caller_that_asked() {
        assert_eq!(POLL_ALWAYS_LISTENING & POLL_RDHUP, 0);
        assert_ne!(POLL_ALWAYS_LISTENING & POLL_NVAL, 0);
        assert_ne!(POLL_ALWAYS_LISTENING & POLL_HUP, 0);
        assert_ne!(POLL_ALWAYS_LISTENING & POLL_ERR, 0);
    }
}
