//! The argument rules, decided without touching a semaphore.
//!
//! Every one is **measured** against an arm64 kernel by
//! `tests/guest/src/bin/sysvsem_probe.rs`, and four are not in `semop(2)` or
//! `semget(2)`:
//!
//! - `nsems` of 0 is `EINVAL` on a create and *fine* on a lookup.
//! - A `sem_num` past the end of the set is `EFBIG` from `semop` and `EINVAL`
//!   from `semctl` — the same mistake, two errnos, and a caller that maps one
//!   of them reports the wrong thing for the other call.
//! - `SETVAL` outside `0..=SEMVMX` is `ERANGE`, not `EINVAL`.
//! - A batch with one bad operation applies **none** of them.

/// `SEMMSL`: semaphores per set. Measured from `/proc/sys/kernel/sem`.
pub const SEMMSL: i32 = 32000;
/// `SEMOPM`: operations per `semop`.
pub const SEMOPM: usize = 500;
/// `SEMVMX`: the largest value a semaphore may hold.
pub const SEMVMX: i32 = 32767;
/// `SEMMNI`: sets in the system.
pub const SEMMNI: usize = 32000;

use sysvipc::Errno;

/// `semget`'s `nsems`, which means different things on a create and a lookup.
///
/// On a create it is how many to make, and zero is refused. On a lookup it is
/// "at least this many", and zero asks for nothing in particular -- so a
/// lookup naming *more* than the set has is `EINVAL` and one naming fewer is
/// the id.
pub(crate) fn check_nsems_create(nsems: i32) -> Result<usize, Errno> {
    if nsems <= 0 || nsems > SEMMSL {
        Err(Errno::EINVAL)
    } else {
        Ok(nsems as usize)
    }
}

pub(crate) fn check_nsems_lookup(nsems: i32, have: usize) -> Result<(), Errno> {
    if nsems < 0 || nsems as usize > have {
        Err(Errno::EINVAL)
    } else {
        Ok(())
    }
}

/// `semop`'s operation count.
pub(crate) fn check_nsops(n: u64) -> Result<usize, Errno> {
    if n == 0 {
        Err(Errno::EINVAL)
    } else if n as usize > SEMOPM {
        Err(Errno::E2BIG)
    } else {
        Ok(n as usize)
    }
}

/// A `sem_num` an operation names. `EFBIG`, which is `semop`'s answer and not
/// `semctl`'s.
pub(crate) fn check_sem_num_op(num: u16, nsems: usize) -> Result<usize, Errno> {
    if num as usize >= nsems {
        Err(Errno::EFBIG)
    } else {
        Ok(num as usize)
    }
}

/// A `sem_num` a `semctl` names. `EINVAL`, and a negative one too -- which is
/// why this takes a signed number where the one above takes the unsigned field
/// of a `struct sembuf`.
pub(crate) fn check_sem_num_ctl(num: i32, nsems: usize) -> Result<usize, Errno> {
    if num < 0 || num as usize >= nsems {
        Err(Errno::EINVAL)
    } else {
        Ok(num as usize)
    }
}

/// `SETVAL`'s and `SETALL`'s range.
pub fn check_value(v: i64) -> Result<u16, Errno> {
    if !(0..=SEMVMX as i64).contains(&v) {
        Err(Errno::ERANGE)
    } else {
        Ok(v as u16)
    }
}

/// One operation, as `struct sembuf` carries it. Six bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Op {
    pub num: u16,
    pub op: i16,
    pub flags: i16,
}

pub const SEMBUF_LEN: usize = 6;
pub const SEM_UNDO: i16 = 0x1000;
pub const IPC_NOWAIT_OP: i16 = 0o4000;

/// A `struct sembuf` array out of a guest's bytes.
pub(crate) fn decode_ops(buf: &[u8]) -> Vec<Op> {
    buf.as_chunks::<SEMBUF_LEN>()
        .0
        .iter()
        .map(|c| Op {
            num: u16::from_le_bytes([c[0], c[1]]),
            op: i16::from_le_bytes([c[2], c[3]]),
            flags: i16::from_le_bytes([c[4], c[5]]),
        })
        .collect()
}

/// Whether a set of values satisfies a batch, and what it would become.
///
/// `None` means the batch would block: some operation cannot be applied yet.
/// **All or nothing** -- Linux's `perform_atomic_semop` unwinds what it did on
/// the first operation it cannot do, so a batch never leaves half its effect
/// behind. That is what makes `semop` a way to take two locks at once without
/// deadlocking.
///
/// An overflow past `SEMVMX` is `ERANGE`, which is not a block: waiting would
/// not help.
pub fn apply(values: &[u16], ops: &[Op]) -> Result<Option<Vec<u16>>, Errno> {
    let mut next: Vec<u16> = values.to_vec();
    for o in ops {
        let i = check_sem_num_op(o.num, values.len())?;
        let cur = next[i] as i32;
        if o.op == 0 {
            if cur != 0 {
                return Ok(None);
            }
        } else {
            let want = cur + o.op as i32;
            if want < 0 {
                return Ok(None);
            }
            if want > SEMVMX {
                return Err(Errno::ERANGE);
            }
            next[i] = want as u16;
        }
    }
    Ok(Some(next))
}

/// Whether a batch changes anything, which decides whether it needs write
/// permission and whether other waiters have to be woken.
pub(crate) fn alters(ops: &[Op]) -> bool {
    ops.iter().any(|o| o.op != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(num: u16, o: i16) -> Op {
        Op {
            num,
            op: o,
            flags: 0,
        }
    }

    #[test]
    fn nsems_means_two_different_things() {
        // Zero is refused on a create and is the ordinary way to look one up.
        assert_eq!(check_nsems_create(0), Err(Errno::EINVAL));
        assert_eq!(check_nsems_create(-1), Err(Errno::EINVAL));
        assert_eq!(check_nsems_create(1), Ok(1));
        assert_eq!(check_nsems_create(SEMMSL), Ok(SEMMSL as usize));
        assert_eq!(check_nsems_create(SEMMSL + 1), Err(Errno::EINVAL));
        assert_eq!(check_nsems_create(100_000), Err(Errno::EINVAL));

        assert_eq!(check_nsems_lookup(0, 2), Ok(()));
        assert_eq!(check_nsems_lookup(1, 2), Ok(()));
        assert_eq!(check_nsems_lookup(2, 2), Ok(()));
        assert_eq!(check_nsems_lookup(3, 2), Err(Errno::EINVAL), "more than it has");
    }

    #[test]
    fn one_mistake_has_two_errnos_depending_on_the_call() {
        // A sem_num past the end: EFBIG from semop, EINVAL from semctl. A
        // caller that maps one of them reports the wrong thing for the other.
        assert_eq!(check_sem_num_op(3, 3), Err(Errno::EFBIG));
        assert_eq!(check_sem_num_op(2, 3), Ok(2));
        assert_eq!(check_sem_num_ctl(3, 3), Err(Errno::EINVAL));
        assert_eq!(check_sem_num_ctl(-1, 3), Err(Errno::EINVAL));
        assert_eq!(check_sem_num_ctl(2, 3), Ok(2));
    }

    #[test]
    fn a_value_outside_the_range_is_erange_and_not_einval() {
        assert_eq!(check_value(0), Ok(0));
        assert_eq!(check_value(SEMVMX as i64), Ok(SEMVMX as u16));
        assert_eq!(check_value(-1), Err(Errno::ERANGE));
        assert_eq!(check_value(32768), Err(Errno::ERANGE));
    }

    #[test]
    fn a_batch_applies_all_of_itself_or_none() {
        // The property that makes semop a way to take two locks at once: the
        // second cannot succeed while the first waits.
        let v = [1u16, 0];
        assert_eq!(apply(&v, &[op(0, -1), op(1, -1)]).unwrap(), None);
        // Neither is applied, which a caller cannot see from the answer alone
        // -- the values are the input's, untouched.
        assert_eq!(apply(&v, &[op(0, -1)]).unwrap(), Some(vec![0, 0]));
        assert_eq!(apply(&v, &[op(0, -1), op(1, 1)]).unwrap(), Some(vec![0, 1]));
    }

    #[test]
    fn waiting_for_zero_is_not_a_change() {
        assert_eq!(apply(&[0u16], &[op(0, 0)]).unwrap(), Some(vec![0]));
        assert_eq!(apply(&[1u16], &[op(0, 0)]).unwrap(), None);
        assert!(
            !alters(&[op(0, 0)]),
            "a wait-for-zero needs only read permission"
        );
        assert!(alters(&[op(0, 0), op(0, 1)]));
    }

    #[test]
    fn an_overflow_is_an_error_rather_than_a_wait() {
        // Waiting would not help: nothing another process does makes room.
        assert_eq!(apply(&[SEMVMX as u16], &[op(0, 1)]), Err(Errno::ERANGE));
        assert_eq!(apply(&[0u16], &[op(0, 32767)]).unwrap(), Some(vec![32767]));
        // And a bad sem_num inside a batch is checked before anything is kept.
        assert_eq!(apply(&[0u16], &[op(0, 1), op(9, 1)]), Err(Errno::EFBIG));
    }

    #[test]
    fn a_sembuf_is_six_bytes_read_as_three_fields() {
        // Wrong here and every operation names the wrong semaphore. `sem_op`
        // is *signed*: a release of -1 read as 65535 is not a release.
        assert_eq!(SEMBUF_LEN, 6);
        let bytes = [1u8, 0, 0xff, 0xff, 0x00, 0x10];
        let ops = decode_ops(&bytes);
        assert_eq!(
            ops,
            vec![Op {
                num: 1,
                op: -1,
                flags: SEM_UNDO
            }]
        );
        // A trailing partial struct is dropped rather than read past.
        assert_eq!(decode_ops(&[1, 0, 0]).len(), 0);
        assert_eq!(decode_ops(&[1, 0, 1, 0, 0, 0, 9]).len(), 1);
    }

    #[test]
    fn the_operation_count_has_two_limits_with_two_errnos() {
        assert_eq!(check_nsops(0), Err(Errno::EINVAL));
        assert_eq!(check_nsops(1), Ok(1));
        assert_eq!(check_nsops(SEMOPM as u64), Ok(SEMOPM));
        assert_eq!(check_nsops(SEMOPM as u64 + 1), Err(Errno::E2BIG));
        assert_eq!(check_nsops(u64::MAX), Err(Errno::E2BIG));
    }
}
