//! Which message a `msgrcv` takes, and what the argument limits are.
//!
//! The selector is the only part of this family that is not obvious, and all
//! three of its cases were **measured** against an arm64 kernel by
//! `tests/guest/src/bin/sysvmsg_probe.rs` rather than read off `msgrcv(2)`:
//!
//! - `msgtyp > 0` is that exact type, and with `MSG_EXCEPT` it is every type
//!   *but* that one.
//! - `msgtyp < 0` is **not** "any but this". It is the message with the
//!   **lowest** type that is at most `|msgtyp|`, which is the priority queue
//!   this family exists to be. A queue holding types 2, 3 and 9 answers
//!   `msgtyp -4` with the type 2 message, and `msgtyp -1` with `ENOMSG`.
//! - `msgtyp == 0` is the first message, and `MSG_EXCEPT` means nothing with
//!   it -- there is no type to except.

/// `MSGMAX`: the largest message. Measured from `/proc/sys/kernel/msgmax`.
pub const MSGMAX: usize = 8192;
/// `MSGMNB`: the default bytes a queue holds, and its `msg_qbytes`.
pub const MSGMNB: usize = 16384;
/// `MSGMNI`: queues in the system.
pub const MSGMNI: usize = 32000;

pub const MSG_NOERROR: i32 = 0o10000;
pub const MSG_EXCEPT: i32 = 0o20000;

use sysvipc::Errno;

/// `msgsnd`'s two refusals, which are both `EINVAL` and are different
/// mistakes: a type at or below zero is reserved (it is what `msgrcv`'s
/// selector means by "no type"), and a message longer than `MSGMAX` would not
/// fit in any queue.
pub(crate) fn check_send(mtype: i64, size: usize) -> Result<(), Errno> {
    if mtype <= 0 || size > MSGMAX {
        Err(Errno::EINVAL)
    } else {
        Ok(())
    }
}

/// `msgrcv`'s size, which is a `size_t` from the guest and may be enormous.
/// Linux refuses anything that does not fit in an `ssize_t`.
pub(crate) fn check_recv_size(size: u64) -> Result<usize, Errno> {
    if size > i64::MAX as u64 {
        Err(Errno::EINVAL)
    } else {
        Ok(size as usize)
    }
}

/// Which message in `types` a `msgrcv` would take, by index.
///
/// A pure function over the types alone, so the three cases are something a
/// unit test can state without a queue.
pub fn select(types: &[i64], msgtyp: i64, except: bool) -> Option<usize> {
    if msgtyp == 0 {
        return (!types.is_empty()).then_some(0);
    }
    if msgtyp > 0 {
        return types
            .iter()
            .position(|t| if except { *t != msgtyp } else { *t == msgtyp });
    }
    // The lowest type at most |msgtyp|, and among equals the first -- which is
    // what makes the queue a priority queue rather than a filter.
    let bound = msgtyp.unsigned_abs() as i64;
    types
        .iter()
        .enumerate()
        .filter(|(_, t)| **t <= bound)
        .min_by_key(|(i, t)| (**t, *i))
        .map(|(i, _)| i)
}

/// Whether a message of `size` fits in a queue that holds `cbytes` in `qnum`
/// messages with a limit of `qbytes`.
///
/// **Two conditions, not one.** Linux refuses when the bytes would not fit
/// *or* when the count would exceed `qbytes` — the second is what stops an
/// unbounded number of zero-length messages, which the first alone permits.
pub fn fits(size: usize, cbytes: usize, qnum: usize, qbytes: usize) -> bool {
    size + cbytes <= qbytes && qnum < qbytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_negative_msgtyp_is_a_priority_queue_and_not_a_filter() {
        // Measured: a queue of 2, 3, 9 answers -4 with the type 2 message.
        let q = [2i64, 3, 9];
        assert_eq!(select(&q, -4, false), Some(0));
        assert_eq!(
            select(&q, -9, false),
            Some(0),
            "still the lowest, not the last"
        );
        assert_eq!(select(&q, -1, false), None, "nothing at or below 1");
        // Out of order in the queue: the *lowest type* wins, not the earliest.
        let q = [9i64, 3, 2];
        assert_eq!(select(&q, -9, false), Some(2));
        // And among equal types the earliest, which is what keeps a queue of
        // one type first-in-first-out.
        let q = [5i64, 3, 3, 9];
        assert_eq!(select(&q, -5, false), Some(1));
    }

    #[test]
    fn a_positive_msgtyp_is_exact_and_msg_except_inverts_it() {
        let q = [2i64, 3, 9];
        assert_eq!(select(&q, 3, false), Some(1));
        assert_eq!(select(&q, 7, false), None);
        assert_eq!(select(&q, 3, true), Some(0), "the first that is not a 3");
        assert_eq!(select(&q, 2, true), Some(1));
        // A queue of nothing else is ENOMSG rather than the message itself.
        assert_eq!(select(&[3i64], 3, true), None);
    }

    #[test]
    fn msgtyp_zero_is_the_first_message_and_ignores_msg_except() {
        let q = [7i64, 1];
        assert_eq!(select(&q, 0, false), Some(0));
        assert_eq!(select(&q, 0, true), Some(0), "there is no type to except");
        assert_eq!(select(&[], 0, false), None);
    }

    #[test]
    fn a_type_at_or_below_zero_cannot_be_sent() {
        // It is what the selector means by "no type", so a queue holding one
        // could not be searched.
        assert_eq!(check_send(0, 1), Err(Errno::EINVAL));
        assert_eq!(check_send(-1, 1), Err(Errno::EINVAL));
        assert_eq!(check_send(1, 0), Ok(()), "an empty message is fine");
        assert_eq!(check_send(1, MSGMAX), Ok(()));
        assert_eq!(check_send(1, MSGMAX + 1), Err(Errno::EINVAL));
    }

    #[test]
    fn a_queue_is_bounded_by_bytes_and_by_count() {
        // The count is what stops an unbounded number of zero-length messages,
        // which the byte limit alone permits.
        assert!(fits(100, 0, 0, MSGMNB));
        assert!(fits(MSGMNB, 0, 0, MSGMNB));
        assert!(!fits(MSGMNB + 1, 0, 0, MSGMNB));
        assert!(!fits(1, MSGMNB, 0, MSGMNB));
        assert!(fits(0, 0, MSGMNB - 1, MSGMNB));
        assert!(
            !fits(0, 0, MSGMNB, MSGMNB),
            "the count, with no bytes at all"
        );
    }

    #[test]
    fn a_receive_size_that_does_not_fit_in_an_ssize_t_is_refused() {
        assert_eq!(check_recv_size(0), Ok(0));
        assert_eq!(check_recv_size(i64::MAX as u64), Ok(i64::MAX as usize));
        assert_eq!(check_recv_size(i64::MAX as u64 + 1), Err(Errno::EINVAL));
        assert_eq!(check_recv_size(u64::MAX), Err(Errno::EINVAL));
    }
}
