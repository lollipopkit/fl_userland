//! What the arguments mean, decided without touching any memory.
//!
//! Everything here is a pure function over numbers, so the awkward cases — a
//! zero-length element, two lists of different total length, a length that is
//! negative when read as `ssize_t` — are things a unit test can write. The
//! syscall above is then the copying and nothing else.
//!
//! The rules are **measured**, not read off the man page:
//! `tests/guest/src/bin/procvm_probe.rs` against an arm64 container. The page
//! does not say that `pid` 0 is `ESRCH` rather than "myself", that a list of
//! 1024 elements is accepted and 1025 refused, or that a remote element which
//! is good followed by one that is not answers the partial count rather than
//! `EFAULT`.

/// `UIO_MAXIOV`. A list of exactly this many is accepted; one more is
/// `EINVAL`, on either side.
pub const IOV_MAX: u64 = 1024;

/// `SSIZE_MAX`. An element longer than this is negative as an `ssize_t`, which
/// is the form Linux's `iovec_from_user` checks and refuses.
pub const SSIZE_MAX: u64 = i64::MAX as u64;

/// Linux's `MAX_RW_COUNT`: `INT_MAX` rounded down to a page. A transfer is
/// truncated to it rather than refused.
pub const MAX_RW_COUNT: u64 = 0x7fff_f000;

pub use guest_errno::Errno;

/// One `struct iovec` as the guest wrote it. 16 bytes on a 64-bit guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Iov {
    pub base: u64,
    pub len: u64,
}
plain::plain!(Iov { base, len });

/// A count of iovecs, refused before anything is read.
///
/// The order matters and is Linux's: the count is checked against `IOV_MAX`
/// *before* the array is read, so a caller passing 2000 elements at an
/// unreadable address gets `EINVAL` and not `EFAULT`.
pub(crate) fn check_count(n: u64) -> Result<usize, Errno> {
    if n > IOV_MAX {
        Err(Errno::EINVAL)
    } else {
        Ok(n as usize)
    }
}

/// `flags` is reserved and must be zero.
pub fn check_flags(flags: u64) -> Result<(), Errno> {
    if flags == 0 { Ok(()) } else { Err(Errno::EINVAL) }
}

/// Which task the call is about. Linux's `process_vm_rw` calls
/// `find_get_task_by_vpid`, which has no "0 means me" case — unlike `prlimit`,
/// where 0 *is* the caller. Measured: `pid` 0 and -1 are both `ESRCH`.
pub(crate) fn check_pid(pid: i32) -> Result<i32, Errno> {
    if pid <= 0 { Err(Errno::ESRCH) } else { Ok(pid) }
}

/// Refuse a list before any of it is transferred.
///
/// Linux imports *both* vectors before it moves a byte, so one bad length
/// anywhere is `EINVAL` with nothing copied -- not a partial transfer up to the
/// bad element. That is the opposite of what a bad *address* does, which is the
/// distinction [`pairs`]'s caller has to keep.
pub(crate) fn check_lengths(iovs: &[Iov]) -> Result<(), Errno> {
    if iovs.iter().any(|i| i.len > SSIZE_MAX) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// One contiguous piece of a transfer: `len` bytes from `from` to `to`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Piece {
    pub local: u64,
    pub remote: u64,
    pub len: u64,
}

/// Walk the two lists together, cutting each at the other's boundaries.
///
/// The transfer is `min(local total, remote total)` bytes, gathered: two remote
/// elements can fill one local buffer and one remote element can be scattered
/// across two local ones. Zero-length elements are skipped rather than yielded,
/// so a caller never has to think about a zero-byte copy.
///
/// Truncated at `MAX_RW_COUNT`, which is what Linux does instead of refusing a
/// list whose total does not fit in an `int`.
pub fn pairs(local: &[Iov], remote: &[Iov]) -> Vec<Piece> {
    let mut out = Vec::new();
    let (mut li, mut ri) = (0usize, 0usize);
    let (mut loff, mut roff) = (0u64, 0u64);
    let mut done = 0u64;

    while li < local.len() && ri < remote.len() && done < MAX_RW_COUNT {
        let lrem = local[li].len - loff;
        let rrem = remote[ri].len - roff;
        if lrem == 0 {
            li += 1;
            loff = 0;
            continue;
        }
        if rrem == 0 {
            ri += 1;
            roff = 0;
            continue;
        }
        let n = lrem.min(rrem).min(MAX_RW_COUNT - done);
        out.push(Piece {
            local: local[li].base.wrapping_add(loff),
            remote: remote[ri].base.wrapping_add(roff),
            len: n,
        });
        loff += n;
        roff += n;
        done += n;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iov(base: u64, len: u64) -> Iov {
        Iov { base, len }
    }

    #[test]
    fn a_count_of_exactly_uio_maxiov_is_accepted() {
        // 1024 is accepted and 1025 is not, which the man page does not say and
        // the probe measured.
        assert_eq!(check_count(0), Ok(0));
        assert_eq!(check_count(1024), Ok(1024));
        assert_eq!(check_count(1025), Err(Errno::EINVAL));
        assert_eq!(check_count(u64::MAX), Err(Errno::EINVAL));
    }

    #[test]
    fn a_length_that_is_negative_as_ssize_t_is_refused() {
        assert_eq!(check_lengths(&[iov(0x1000, SSIZE_MAX)]), Ok(()));
        assert_eq!(check_lengths(&[iov(0x1000, SSIZE_MAX + 1)]), Err(Errno::EINVAL));
        assert_eq!(check_lengths(&[iov(0x1000, u64::MAX)]), Err(Errno::EINVAL));
        // And the whole list is looked at, not just the first: a bad element
        // behind a good one refuses the call rather than transferring the good
        // one, which is the difference from a bad address.
        assert_eq!(
            check_lengths(&[iov(0x1000, 8), iov(0x2000, u64::MAX)]),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn pid_zero_is_not_the_caller_here() {
        // Unlike prlimit, where 0 means "me". Measured: ESRCH.
        assert_eq!(check_pid(0), Err(Errno::ESRCH));
        assert_eq!(check_pid(-1), Err(Errno::ESRCH));
        assert_eq!(check_pid(1), Ok(1));
    }

    #[test]
    fn the_transfer_is_the_shorter_of_the_two_totals() {
        let one = pairs(&[iov(0x1000, 4)], &[iov(0x9000, 25)]);
        assert_eq!(
            one,
            vec![Piece {
                local: 0x1000,
                remote: 0x9000,
                len: 4
            }]
        );

        let other = pairs(&[iov(0x1000, 64)], &[iov(0x9000, 25)]);
        assert_eq!(
            other,
            vec![Piece {
                local: 0x1000,
                remote: 0x9000,
                len: 25
            }]
        );
    }

    #[test]
    fn two_remote_pieces_fill_one_local_buffer() {
        // The gather the probe measured: 4 bytes from one place and 4 from
        // another land next to each other in the caller's buffer.
        let got = pairs(&[iov(0x1000, 8)], &[iov(0x9000, 4), iov(0x9010, 4)]);
        assert_eq!(
            got,
            vec![
                Piece {
                    local: 0x1000,
                    remote: 0x9000,
                    len: 4
                },
                Piece {
                    local: 0x1004,
                    remote: 0x9010,
                    len: 4
                },
            ]
        );
    }

    #[test]
    fn one_remote_piece_scatters_across_two_local_ones() {
        let got = pairs(&[iov(0x1000, 3), iov(0x2000, 5)], &[iov(0x9000, 8)]);
        assert_eq!(
            got,
            vec![
                Piece {
                    local: 0x1000,
                    remote: 0x9000,
                    len: 3
                },
                Piece {
                    local: 0x2000,
                    remote: 0x9003,
                    len: 5
                },
            ]
        );
    }

    #[test]
    fn a_zero_length_element_yields_nothing_rather_than_a_zero_byte_copy() {
        assert!(pairs(&[iov(0x1000, 0)], &[iov(0x9000, 0)]).is_empty());
        assert!(pairs(&[], &[]).is_empty());
        assert!(pairs(&[iov(0x1000, 8)], &[]).is_empty());
        // And a zero in the middle is stepped over, not stopped at.
        let got = pairs(
            &[iov(0x1000, 8)],
            &[iov(0x9000, 4), iov(0x9500, 0), iov(0x9010, 4)],
        );
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[1],
            Piece {
                local: 0x1004,
                remote: 0x9010,
                len: 4
            }
        );
    }

    #[test]
    fn the_total_is_truncated_at_max_rw_count() {
        // Rather than refused: two elements of 1 GiB each is 2 GiB, which does
        // not fit in the `int` Linux counts with.
        let gib = 1u64 << 30;
        let got = pairs(&[iov(0x1000, 4 * gib)], &[iov(0x9000, 4 * gib)]);
        let total: u64 = got.iter().map(|p| p.len).sum();
        assert_eq!(total, MAX_RW_COUNT);
    }

    #[test]
    fn flags_are_reserved() {
        assert_eq!(check_flags(0), Ok(()));
        assert_eq!(check_flags(1), Err(Errno::EINVAL));
    }
}
