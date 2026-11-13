//! The futex2 syscalls: `futex_waitv` (449), `futex_wake` (454), `futex_wait`
//! (455) and `futex_requeue` (456).
//!
//! Each operation gets its own number and its own argument list, and the word
//! size and sharing are flags (`FUTEX2_SIZE_*`, `FUTEX2_PRIVATE`) rather than
//! bits of an operation word. Underneath they are the same queue as `futex(2)`,
//! so a `futex_wait` is woken by a `FUTEX_WAKE` and the other way round.
//!
//! # What Linux accepts, measured
//!
//! Every rule here is a line of `tests/guest/src/bin/futex2_probe.rs` run on a
//! real arm64 kernel, not the man page:
//!
//! - only `FUTEX2_SIZE_U32`; U8, U16 and U64 are `EINVAL`, and so is any bit
//!   outside `FUTEX2_VALID_MASK`;
//! - a value or mask wider than the word is `EINVAL`, a mask of 0 too;
//! - a timeout is **absolute**, on `CLOCK_MONOTONIC` or `CLOCK_REALTIME` and
//!   nothing else -- but the clock is only looked at when there is a timeout;
//! - `FUTEX2_NUMA` makes the futex two words, the value and a node: aligned to
//!   eight, a node of `-1` is filled in (with 0, the only node here), any other
//!   node past the last is `EINVAL`, and the node word is read even for a
//!   private wake, so an unmapped one is `EFAULT`. `FUTEX2_MPOL` only chooses
//!   how `-1` is filled in, and one node makes every policy the same;
//! - `futex_waitv` and `futex_requeue` refuse `FUTEX2_NUMA` in an entry, and a
//!   null vector is `EINVAL` rather than `EFAULT`;
//! - `futex_requeue` compares the first entry's value only, and refuses to move
//!   waiters between a private and a shared futex.
//!
//! # Restarting
//!
//! Both waits are absolute, so re-running one after a signal handler is
//! correct, and Linux answers `ERESTARTSYS` for them whatever the timeout.
//! `crates/kernel/syscallrestart` classifies them so.

use std::ffi::c_int;
use std::time::Instant;

use guest_errno::Errno;
use kernel_futex::Word;
use strace::strace;
use usercopy::GuestMem;

use crate::guestmem::CurrentSpace;
use crate::{counted, deadline, futex_wait, wake_count};

const FUTEX2_SIZE_MASK: u32 = 0x03;
const FUTEX2_SIZE_U32: u32 = 0x02;
const FUTEX2_NUMA: u32 = 0x04;
const FUTEX2_MPOL: u32 = 0x08;
const FUTEX2_PRIVATE: u32 = 128;
/// Linux's `FUTEX2_VALID_MASK`.
const FUTEX2_VALID_MASK: u32 = FUTEX2_SIZE_MASK | FUTEX2_NUMA | FUTEX2_MPOL | FUTEX2_PRIVATE;

/// `FUTEX_WAITV_MAX`.
const WAITV_MAX: u32 = 128;
/// `FUTEX_NO_NODE`.
const NO_NODE: u32 = u32::MAX;
/// How many NUMA nodes this kernel reports: one.
const NR_NODES: u32 = 1;

/// A decoded `flags` word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Flags {
    private: bool,
    numa: bool,
}

/// `futex2_to_flags` + `futex_flags_valid`: `EINVAL` for an unknown bit or a
/// size other than 32 bits.
fn parse_flags(flags: u32) -> Result<Flags, Errno> {
    if flags & !FUTEX2_VALID_MASK != 0 || flags & FUTEX2_SIZE_MASK != FUTEX2_SIZE_U32 {
        return Err(Errno::EINVAL);
    }
    Ok(Flags {
        private: flags & FUTEX2_PRIVATE != 0,
        numa: flags & FUTEX2_NUMA != 0,
    })
}

/// `futex_validate_input`: a value or mask must fit the word.
fn fits(v: u64) -> Result<u32, Errno> {
    u32::try_from(v).map_err(|_| Errno::EINVAL)
}

/// The futex at `addr` with `flags`, checked the way `get_futex_key` checks it
/// for a NUMA futex: aligned to its whole size, and the node word read --
/// and, when it is `-1`, written with the node this kernel has.
fn word(addr: u64, f: Flags) -> Result<Word, Errno> {
    let align = if f.numa { 8 } else { 4 };
    if !addr.is_multiple_of(align) {
        return Err(Errno::EINVAL);
    }
    if f.numa {
        let naddr = addr + 4;
        let mut raw = [0u8; 4];
        if GuestMem.read(naddr, &mut raw) != 0 {
            return Err(Errno::EFAULT);
        }
        match u32::from_le_bytes(raw) {
            NO_NODE => {
                if GuestMem.write(naddr, &0u32.to_le_bytes()) != 0 {
                    return Err(Errno::EFAULT);
                }
            }
            node if node >= NR_NODES => return Err(Errno::EINVAL),
            _ => {}
        }
    }
    Ok(Word { addr, private: f.private })
}

/// `futex2_setup_timeout`: an absolute time on one of two clocks.
fn timeout(addr: u64, clockid: c_int) -> Result<Option<Instant>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let clock = match clockid {
        0 => libc::CLOCK_REALTIME,
        1 => libc::CLOCK_MONOTONIC,
        _ => return Err(Errno::EINVAL),
    };
    Ok(deadline::absolute(deadline::read(addr)?, clock))
}

/// A guest `struct futex_waitv`: `{ u64 val; u64 uaddr; u32 flags; u32
/// __reserved; }`, 24 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WaitvEntry {
    val: u64,
    uaddr: u64,
    flags: u32,
    reserved: u32,
}

const WAITV_SIZE: usize = 24;

impl WaitvEntry {
    fn decode(raw: &[u8; WAITV_SIZE]) -> WaitvEntry {
        WaitvEntry {
            val: u64::from_le_bytes(raw[0..8].try_into().unwrap()),
            uaddr: u64::from_le_bytes(raw[8..16].try_into().unwrap()),
            flags: u32::from_le_bytes(raw[16..20].try_into().unwrap()),
            reserved: u32::from_le_bytes(raw[20..24].try_into().unwrap()),
        }
    }
}

/// `futex_parse_waitv`: `n` entries at `addr`, each decoded and checked.
fn parse_waitv(addr: u64, n: usize) -> Result<Vec<(Word, u32)>, Errno> {
    let mut raw = Vec::new();
    raw.try_reserve_exact(n * WAITV_SIZE).map_err(|_| Errno::ENOMEM)?;
    raw.resize(n * WAITV_SIZE, 0);
    if GuestMem.read(addr, &mut raw) != 0 {
        return Err(Errno::EFAULT);
    }
    let mut out = Vec::with_capacity(n);
    for chunk in raw.as_chunks::<WAITV_SIZE>().0 {
        let e = WaitvEntry::decode(chunk);
        if e.reserved != 0 {
            return Err(Errno::EINVAL);
        }
        let f = parse_flags(e.flags)?;
        if f.numa {
            return Err(Errno::EINVAL);
        }
        let val = fits(e.val)?;
        out.push((word(e.uaddr, f)?, val));
    }
    Ok(out)
}

/// `futex_wake(uaddr, mask, nr, flags)`: how many were woken.
pub fn sys_futex_wake(uaddr: u64, mask: u64, nr: c_int, flags: u32) -> Result<i64, Errno> {
    strace!("futex_wake({uaddr:#x}, {mask:#x}, {nr}, {flags:#x})");
    let f = parse_flags(flags)?;
    let mask = fits(mask)?;
    if mask == 0 {
        return Err(Errno::EINVAL);
    }
    let w = word(uaddr, f)?;
    // Not quite `futex(2)`'s count: `futex2_probe` with three parked
    // measured 0 waking none and -1 waking one on a 7.2 kernel, where
    // `FUTEX_WAKE` wakes one for both. A count of 0 returns before the
    // queue is looked at; a negative one goes through `wake_count`.
    if nr == 0 {
        return Ok(0);
    }
    Errno::split(counted(kernel_futex::wake(&CurrentSpace::new(), w, wake_count(nr), mask)))
}

/// `futex_wait(uaddr, val, mask, flags, timeout, clockid)`: 0 when woken.
pub fn sys_futex_wait(
    uaddr: u64,
    val: u64,
    mask: u64,
    flags: u32,
    timeout_addr: u64,
    clockid: c_int,
) -> Result<i64, Errno> {
    strace!("futex_wait({uaddr:#x}, {val}, {mask:#x}, {flags:#x}, {timeout_addr:#x}, {clockid})");
    let f = parse_flags(flags)?;
    let (val, mask) = (fits(val)?, fits(mask)?);
    let deadline = timeout(timeout_addr, clockid)?;
    if mask == 0 {
        return Err(Errno::EINVAL);
    }
    let w = word(uaddr, f)?;
    Errno::split(futex_wait(w, val, mask, deadline))
}

/// `futex_waitv(waiters, nr_futexes, flags, timeout, clockid)`: the index of
/// the futex that was woken.
pub fn sys_futex_waitv(
    waiters: u64,
    nr: u32,
    flags: u32,
    timeout_addr: u64,
    clockid: c_int,
) -> Result<i64, Errno> {
    strace!("futex_waitv({waiters:#x}, {nr}, {flags:#x}, {timeout_addr:#x}, {clockid})");
    if flags != 0 || nr == 0 || nr > WAITV_MAX || waiters == 0 {
        return Err(Errno::EINVAL);
    }
    let deadline = timeout(timeout_addr, clockid)?;
    let words = parse_waitv(waiters, nr as usize)?;
    taskview::set_blocking(true);
    let r = kernel_futex::waitv(&CurrentSpace::new(), &words, deadline);
    taskview::set_blocking(false);
    match r {
        Ok(i) => Ok(i as i64),
        Err(e) => Err(Errno::from_negative_or_eio(e)),
    }
}

/// `futex_requeue(waiters[2], flags, nr_wake, nr_requeue)`: woken plus moved.
pub fn sys_futex_requeue(waiters: u64, flags: u32, nr_wake: c_int, nr_requeue: c_int) -> Result<i64, Errno> {
    strace!("futex_requeue({waiters:#x}, {flags:#x}, {nr_wake}, {nr_requeue})");
    if flags != 0 || waiters == 0 {
        return Err(Errno::EINVAL);
    }
    let w = parse_waitv(waiters, 2)?;
    let ((from, cmpval), (to, _)) = (w[0], w[1]);
    if nr_wake < 0 || nr_requeue < 0 || from.private != to.private {
        return Err(Errno::EINVAL);
    }
    Errno::split(counted(kernel_futex::requeue(
        &CurrentSpace::new(),
        from,
        to,
        nr_wake as u32,
        nr_requeue as u32,
        Some(cmpval),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_32_bit_size_and_the_known_bits_parse() {
        assert_eq!(parse_flags(FUTEX2_SIZE_U32), Ok(Flags { private: false, numa: false }));
        assert_eq!(
            parse_flags(FUTEX2_SIZE_U32 | FUTEX2_PRIVATE | FUTEX2_NUMA | FUTEX2_MPOL),
            Ok(Flags { private: true, numa: true })
        );
        for size in [0, 1, 3] {
            assert_eq!(parse_flags(size | FUTEX2_PRIVATE), Err(Errno::EINVAL), "size {size}");
        }
        assert_eq!(parse_flags(FUTEX2_SIZE_U32 | 0x10), Err(Errno::EINVAL));
        assert_eq!(parse_flags(FUTEX2_SIZE_U32 | 1 << 31), Err(Errno::EINVAL));
    }

    #[test]
    fn a_value_wider_than_the_word_is_refused() {
        assert_eq!(fits(0xffff_ffff), Ok(0xffff_ffff));
        assert_eq!(fits(1 << 32), Err(Errno::EINVAL));
        assert_eq!(fits(u64::MAX), Err(Errno::EINVAL));
    }

    #[test]
    fn a_waitv_entry_is_val_uaddr_flags_reserved() {
        let mut raw = [0u8; WAITV_SIZE];
        raw[0..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        raw[8..16].copy_from_slice(&0xdead_beef_0000u64.to_le_bytes());
        raw[16..20].copy_from_slice(&0x82u32.to_le_bytes());
        raw[20..24].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            WaitvEntry::decode(&raw),
            WaitvEntry { val: 0x1122_3344_5566_7788, uaddr: 0xdead_beef_0000, flags: 0x82, reserved: 7 }
        );
    }
}
