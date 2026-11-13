//! The 128-byte `siginfo_` a wait or an exit fills, and what its status word
//! means.
//!
//! Here rather than in `crates/kernel/waitcalls` since 2026-09-09, which is
//! the crate that *drove* it — and `crates/kernel/exitcalls` reached it through
//! the C ABI under a `keep-c-abi` marker, because a Rust call the other way is
//! a cycle: reaping calls `tgroup_release` out of `exitcalls`. The marker's own
//! TODO said the answer, and this is it. The decode is a pure function over
//! 128 bytes and belongs with the type, so both callers reach it downward and
//! the edge is gone.

use std::ffi::c_int;

use crate::SigInfo;

const CLD_EXITED: c_int = 1;
const CLD_KILLED: c_int = 2;
const CLD_DUMPED: c_int = 3;
const CLD_TRAPPED: c_int = 4;
const CLD_STOPPED: c_int = 5;
const CLD_CONTINUED: c_int = 6;
const SIGCHLD: c_int = 17;
const SIGCONT: c_int = 18;

/// The guest's `struct siginfo_`: 128 bytes.
///
/// The offsets are `kernel/signal.h`'s and are written down rather than
/// mirrored as a struct, for the reason `crates/fs/cmsg` and
/// `crates/kernel/sigframe` exist — every defect either of those ever had was
/// an offset, and a struct definition cannot be asked to justify one.
pub mod offset {
    pub const SIG: usize = 0;
    #[allow(dead_code)]
    pub const SIG_ERRNO: usize = 4;
    pub const CODE: usize = 8;

    /// **The union starts at 16, not 12.** Three 4-byte ints come first, which
    /// ends at 12 — but the union contains `sqword_t utime` and `stime`, so it
    /// is 8-aligned and the compiler pads to 16.
    ///
    /// The first version of this file wrote 12, and every one of
    /// nineteen checks failed: the decode read a
    /// status word that was really `si_uid` and wrote its answer over the pid.
    /// That test exists because reaching this through `sys_waitid` would need a
    /// real child per encoding, and it is what caught this in one run.
    pub const CHILD_PID: usize = 16;
    /// Filled by the wait loop, not read here — named so the layout is complete
    /// and `CHILD_STATUS` is checkable against it.
    #[allow(dead_code)]
    pub const CHILD_UID: usize = 20;
    pub const CHILD_STATUS: usize = 24;
    /// Not read here either. `kernel/signal.h` states these sit at 32 and 40,
    /// which is what [`super::tests::the_child_offsets_agree_with_the_header`]
    /// checks the three above against: `status` ends at 28 and `utime` is
    /// 8-aligned, so 32 is the only place it can be.
    #[allow(dead_code)]
    pub const CHILD_UTIME: usize = 32;
    #[allow(dead_code)]
    pub const CHILD_STIME: usize = 40;
}

/// 128 bytes, as the guest's libc sizes its buffers.
pub const SIGINFO_SIZE: usize = 128;

pub fn get_i32(buf: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
}

pub fn set_i32(buf: &mut [u8], at: usize, v: i32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// The raw `wait(2)` status word as the `(si_code, si_status)` pair `waitid(2)`
/// is specified to return.
///
/// The encodings come from the places that write `child.status`:
///
/// | writer | word |
/// | --- | --- |
/// | `sys_exit`/`sys_exit_group` | `status << 8`, so the low byte is 0 |
/// | a fatal signal | the low byte is the signal |
/// | a group stop | `sig << 8 \| 0x7f` |
/// | a ptrace stop | `signal << 8 \| 0x7f` |
///
/// A ptrace stop packs identically to a group stop and cannot be told apart
/// from the word alone, so `do_wait` marks it `CLD_TRAPPED` as it reads it and
/// this leaves that alone; anything else with that shape is a group stop.
///
/// Nothing here sets the `0x80` core-dump bit today, so `CLD_DUMPED` is
/// unreachable in practice; it is handled anyway so this stays correct if core
/// dumps are ever implemented.
pub fn decode_status(status: u32, code_in: i32) -> (i32, i32) {
    if status & 0xff == 0x7f {
        // Stopped: WIFSTOPPED, signal in the high byte.
        let code = if code_in == CLD_TRAPPED {
            CLD_TRAPPED
        } else {
            CLD_STOPPED
        };
        (code, ((status >> 8) & 0xff) as i32)
    } else if status == 0xffff {
        // Continued: WIFCONTINUED. Nothing produces this yet -- SIGCONT does
        // not set the group exit code -- but decode it so the case is not
        // silently misreported as an exit if WCONTINUED support lands.
        (CLD_CONTINUED, SIGCONT)
    } else if status & 0x7f != 0 {
        // Terminated by a signal: WIFSIGNALED, signal in the low seven bits.
        let code = if status & 0x80 != 0 {
            CLD_DUMPED
        } else {
            CLD_KILLED
        };
        (code, (status & 0x7f) as i32)
    } else {
        // A normal exit: WIFEXITED, exit code in the high byte.
        (CLD_EXITED, ((status >> 8) & 0xff) as i32)
    }
}

/// The same, in place, for `sys_waitid`, which drives it
/// directly.
///
/// Reaching it through `sys_waitid` would mean a real child in a real process
/// for each of the six encodings, and two of them — continued and dumped —
/// cannot be produced at all.
///
/// Decode a live `SigInfo` in place.
pub fn decode_in_place(info: &mut SigInfo) {
    let buf = crate::as_bytes_mut(info);
    let status = get_i32(buf, offset::CHILD_STATUS) as u32;
    let (code, decoded) = decode_status(status, get_i32(buf, offset::CODE));
    set_i32(buf, offset::SIG, SIGCHLD);
    set_i32(buf, offset::CODE, code);
    set_i32(buf, offset::CHILD_STATUS, decoded);
}
