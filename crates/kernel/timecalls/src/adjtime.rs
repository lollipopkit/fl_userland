//! `adjtimex` and `clock_adjtime`: the NTP clock discipline's state, read.
//!
//! # What is reported
//!
//! The host's. This kernel's clocks are the host's clocks, and the host
//! disciplines them (`timed` on macOS and iOS), so the honest answer to "is
//! the clock synchronised, and how far off might it be" is the host's own
//! `ntp_adjtime(2)` -- which is public API on both and takes no privilege to
//! read. A container on Linux sees its host kernel's state in the same way.
//! Where the host will not say, the answer is a freshly booted Linux's:
//! unsynchronised, a maximum error of `NTP_PHASE_LIMIT`, `TIME_ERROR`.
//!
//! The fields that are this kernel's own and not the discipline's are
//! Linux's constants: `tick` is `USER_HZ`'s 10000 us, `tolerance` is
//! `MAXFREQ_SCALED`, `precision` is a microsecond, and `tai` is 0 because
//! nothing here sets it (so `CLOCK_TAI` reads the realtime clock).
//!
//! # Nothing is ever set
//!
//! A guest may not discipline the host's clock. Every mode that would write
//! is answered as for a process without `CAP_SYS_TIME`, in Linux's order
//! (`timekeeping_validate_timex`): a single-shot `adjtime` without its
//! single-shot bit is `EINVAL` before the permission, and everything else
//! that writes is `EPERM`. Measured against 7.2 by
//! `tests/guest/src/bin/clock2_probe.rs` on 2026-11-11, mode by mode.
//!
//! # The wire format
//!
//! The aarch64 `struct __kernel_timex`, 208 bytes, decoded from and encoded
//! into a byte array at the offsets below. Linux copies the whole struct in,
//! edits it, and copies the whole struct out, so the padding and every field
//! it does not fill come back as the caller left them -- and an unreadable
//! buffer is `EFAULT` before anything else is looked at.

use std::ffi::c_uint;

use guest_errno::Errno;
use usercopy::GuestMem;
use util_timeabi as timeabi;

/// `sizeof(struct __kernel_timex)` on a 64-bit kernel.
pub(crate) const TIMEX_SIZE: usize = 208;

/// Field offsets. `long`s are eight bytes; each `int` but `tai` is followed by
/// four bytes of padding; eleven `int`s of padding close the struct.
mod at {
    pub const MODES: usize = 0;
    pub const OFFSET: usize = 8;
    pub const FREQ: usize = 16;
    pub const MAXERROR: usize = 24;
    pub const ESTERROR: usize = 32;
    pub const STATUS: usize = 40;
    pub const CONSTANT: usize = 48;
    pub const PRECISION: usize = 56;
    pub const TOLERANCE: usize = 64;
    pub const TIME_SEC: usize = 72;
    pub const TIME_USEC: usize = 80;
    pub const TICK: usize = 88;
    pub const PPSFREQ: usize = 96;
    pub const JITTER: usize = 104;
    pub const SHIFT: usize = 112;
    pub const STABIL: usize = 120;
    pub const JITCNT: usize = 128;
    pub const CALCNT: usize = 136;
    pub const ERRCNT: usize = 144;
    pub const STBCNT: usize = 152;
    pub const TAI: usize = 160;
    pub const PADDING: usize = 164;
}
const _: () = assert!(at::PADDING + 11 * 4 == TIMEX_SIZE);

const ADJ_OFFSET_SINGLESHOT: u32 = 0x0001;
const ADJ_SETOFFSET: u32 = 0x0100;
const ADJ_OFFSET_READONLY: u32 = 0x2000;
const ADJ_ADJTIME: u32 = 0x8000;

const STA_UNSYNC: i32 = 0x0040;
const STA_NANO: i32 = 0x2000;

const TIME_ERROR: i64 = 5;

/// `NTP_PHASE_LIMIT`: the maximum error a clock nothing has synchronised is
/// reported with, in microseconds.
const NTP_PHASE_LIMIT: i64 = 16_000_000;
/// `MAXFREQ_SCALED`: 500 ppm, in the 16.16 fixed point `freq` uses.
const MAXFREQ_SCALED: i64 = 500 << 16;
/// `USER_HZ` is 100, so a tick is 10000 us.
const TICK_USEC: i64 = 10_000;

/// Whether `modes` only reads, or the errno a caller without `CAP_SYS_TIME`
/// is told: Linux's `timekeeping_validate_timex` up to its first capability
/// test, which is as far as such a caller gets.
fn read_only(modes: u32) -> Result<(), Errno> {
    if modes & ADJ_ADJTIME != 0 {
        // The old `adjtime(2)` interface: single-shot or nothing, and only
        // the read-only variant (`ADJ_OFFSET_SS_READ`) is unprivileged.
        if modes & ADJ_OFFSET_SINGLESHOT == 0 {
            return Err(Errno::EINVAL);
        }
        if modes & ADJ_OFFSET_READONLY == 0 {
            return Err(Errno::EPERM);
        }
    } else if modes != 0 {
        return Err(Errno::EPERM);
    }
    if modes & ADJ_SETOFFSET != 0 {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// The discipline's state, in Linux's units: microseconds, with `STA_NANO`
/// clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    /// `TIME_OK` to `TIME_ERROR`, what the call returns.
    state: i64,
    offset: i64,
    freq: i64,
    maxerror: i64,
    esterror: i64,
    status: i32,
    constant: i64,
    ppsfreq: i64,
    jitter: i64,
    shift: i32,
    stabil: i64,
    jitcnt: i64,
    calcnt: i64,
    errcnt: i64,
    stbcnt: i64,
}

impl State {
    /// A Linux kernel that has just booted and that nothing has synchronised.
    const UNSYNCHRONISED: State = State {
        state: TIME_ERROR,
        offset: 0,
        freq: 0,
        maxerror: NTP_PHASE_LIMIT,
        esterror: NTP_PHASE_LIMIT,
        status: STA_UNSYNC,
        constant: 2,
        ppsfreq: 0,
        jitter: 0,
        shift: 0,
        stabil: 0,
        jitcnt: 0,
        calcnt: 0,
        errcnt: 0,
        stbcnt: 0,
    };

    /// The host's, converted: nanosecond fields to microseconds when the host
    /// keeps nanoseconds, and `TIME_ERROR` whenever the host says it is not
    /// synchronised, which is Linux's rule for the return value.
    fn from_host(ret: i32, t: &libc::timex) -> State {
        let nano = t.status & STA_NANO != 0;
        let usec = |v: libc::c_long| if nano { v / 1000 } else { v };
        let status = t.status & !STA_NANO;
        State {
            state: if status & STA_UNSYNC != 0 { TIME_ERROR } else { i64::from(ret) },
            offset: usec(t.offset),
            freq: t.freq,
            maxerror: t.maxerror,
            esterror: t.esterror,
            status,
            constant: t.constant,
            ppsfreq: t.ppsfreq,
            jitter: usec(t.jitter),
            shift: t.shift,
            stabil: t.stabil,
            jitcnt: t.jitcnt,
            calcnt: t.calcnt,
            errcnt: t.errcnt,
            stbcnt: t.stbcnt,
        }
    }
}

/// The host's discipline state, or an unsynchronised clock's if the host will
/// not say.
fn host_state() -> State {
    // SAFETY: an all-zero `timex` is a valid one, and modes 0 only reads.
    let mut t: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: `t` is a live, writable `timex`.
    let ret = unsafe { libc::ntp_adjtime(&mut t) };
    if !(0..=TIME_ERROR as i32).contains(&ret) {
        return State::UNSYNCHRONISED;
    }
    State::from_host(ret, &t)
}

/// Fill a read-only reply into `raw`, answering the state.
///
/// `modes` is left as the caller set it. For `ADJ_OFFSET_SS_READ` the offset
/// is the single-shot `adjtime` offset still to apply, which is zero because
/// nothing here starts one.
fn fill(raw: &mut [u8; TIMEX_SIZE], modes: u32, s: State, now: (i64, i64)) -> i64 {
    let mut long = |o: usize, v: i64| raw[o..o + 8].copy_from_slice(&v.to_le_bytes());
    long(at::OFFSET, if modes & ADJ_ADJTIME != 0 { 0 } else { s.offset });
    long(at::FREQ, s.freq);
    long(at::MAXERROR, s.maxerror);
    long(at::ESTERROR, s.esterror);
    long(at::CONSTANT, s.constant);
    long(at::PRECISION, 1);
    long(at::TOLERANCE, MAXFREQ_SCALED);
    long(at::TIME_SEC, now.0);
    long(at::TIME_USEC, now.1 / timeabi::NSEC_PER_USEC);
    long(at::TICK, TICK_USEC);
    long(at::PPSFREQ, s.ppsfreq);
    long(at::JITTER, s.jitter);
    long(at::STABIL, s.stabil);
    long(at::JITCNT, s.jitcnt);
    long(at::CALCNT, s.calcnt);
    long(at::ERRCNT, s.errcnt);
    long(at::STBCNT, s.stbcnt);
    let mut int = |o: usize, v: i32| raw[o..o + 4].copy_from_slice(&v.to_le_bytes());
    int(at::STATUS, s.status);
    int(at::SHIFT, s.shift);
    int(at::TAI, 0);
    s.state
}

/// `clock_adjtime(clock, buf)`, and `adjtimex(buf)` with `CLOCK_REALTIME`.
pub(crate) fn clock_adjtime(clock: c_uint, buf: u64) -> Result<i64, Errno> {
    let mut raw = [0u8; TIMEX_SIZE];
    if GuestMem.read(buf, &mut raw) != 0 {
        return Err(Errno::EFAULT);
    }
    let Some(ops) = timeabi::ops(clock) else {
        return Err(Errno::EINVAL);
    };
    if !ops.adjust {
        return Err(Errno::EOPNOTSUPP);
    }
    // A dynamic clock's descriptor is never a `/dev/ptp*` here.
    if timeabi::is_dynamic(clock) {
        return Err(Errno::EINVAL);
    }
    let modes = u32::from_le_bytes(raw[at::MODES..at::MODES + 4].try_into().unwrap());
    read_only(modes)?;
    let now = super::host_now(libc::CLOCK_REALTIME)?;
    let state = fill(&mut raw, modes, host_state(), now);
    if GuestMem.write(buf, &raw) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rows `clock2_probe` measured, for a caller without `CAP_SYS_TIME`.
    #[test]
    fn only_the_two_read_only_modes_are_allowed() {
        assert_eq!(read_only(0), Ok(()));
        assert_eq!(read_only(0xa001), Ok(()), "ADJ_OFFSET_SS_READ");
        assert_eq!(read_only(0xa001 | 0x0002), Ok(()), "and ADJ_FREQUENCY, which it ignores");
        assert_eq!(read_only(0x8000), Err(Errno::EINVAL), "ADJ_ADJTIME without SINGLESHOT");
        assert_eq!(read_only(0x8001), Err(Errno::EPERM), "ADJ_OFFSET_SINGLESHOT");
        assert_eq!(read_only(0xa101), Err(Errno::EPERM), "SS_READ with ADJ_SETOFFSET");
        for modes in [0x0001, 0x0002, 0x0004, 0x0010, 0x0080, 0x0100, 0x1000, 0x2000, 0x4000, 1 << 30] {
            assert_eq!(read_only(modes), Err(Errno::EPERM), "modes {modes:#x}");
        }
    }

    /// Every field lands at its offset, and the padding and `modes` are left
    /// as the caller had them.
    #[test]
    fn a_reply_fills_the_fields_and_leaves_the_rest() {
        let mut raw = [0x5au8; TIMEX_SIZE];
        raw[..4].copy_from_slice(&0u32.to_le_bytes());
        let s = State { offset: 7, maxerror: 9, status: STA_UNSYNC, ..State::UNSYNCHRONISED };
        assert_eq!(fill(&mut raw, 0, s, (1_700_000_000, 123_456_789)), TIME_ERROR);
        let long = |o: usize| i64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
        let int = |o: usize| i32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
        assert_eq!(int(at::MODES), 0);
        assert_eq!(long(at::OFFSET), 7);
        assert_eq!(long(at::MAXERROR), 9);
        assert_eq!(int(at::STATUS), STA_UNSYNC);
        assert_eq!(long(at::TOLERANCE), 32_768_000);
        assert_eq!((long(at::TIME_SEC), long(at::TIME_USEC)), (1_700_000_000, 123_456));
        assert_eq!(long(at::TICK), 10_000);
        assert_eq!(int(at::TAI), 0);
        assert!(raw[at::PADDING..].iter().all(|&b| b == 0x5a));
        // The padding after `status` is the caller's too.
        assert_eq!(&raw[at::STATUS + 4..at::CONSTANT], &[0x5a; 4]);
    }

    /// `ADJ_OFFSET_SS_READ` answers the single-shot offset still to apply,
    /// and none is ever started here.
    #[test]
    fn a_single_shot_read_answers_no_pending_offset() {
        let mut raw = [0u8; TIMEX_SIZE];
        let s = State { offset: 5, ..State::UNSYNCHRONISED };
        fill(&mut raw, 0xa001, s, (0, 0));
        assert_eq!(i64::from_le_bytes(raw[at::OFFSET..at::OFFSET + 8].try_into().unwrap()), 0);
    }

    /// A host keeping nanoseconds is reported in microseconds, and an
    /// unsynchronised host is `TIME_ERROR` whatever it returned.
    #[test]
    fn the_host_state_is_converted_to_linuxs_units() {
        // SAFETY: an all-zero `timex` is a valid one.
        let mut t: libc::timex = unsafe { std::mem::zeroed() };
        t.status = STA_NANO | 0x0001;
        t.offset = 12_345;
        let s = State::from_host(0, &t);
        assert_eq!((s.state, s.offset, s.status), (0, 12, 0x0001));
        t.status |= STA_UNSYNC;
        assert_eq!(State::from_host(0, &t).state, TIME_ERROR);
    }

    /// The host answers on this machine, with a state in range.
    #[test]
    fn the_host_answers() {
        let s = host_state();
        assert!((0..=TIME_ERROR).contains(&s.state), "{s:?}");
        assert_eq!(s.status & STA_NANO, 0);
    }
}
