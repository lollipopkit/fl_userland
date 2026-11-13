//! `siginfo_t` decoding and `signalfd_siginfo` encoding.

// siginfo_t, as the guest's kernel/signal.h lays it out
// ---------------------------------------------------------------------------

/// The guest's `siginfo_t`. Its libc sizes buffers by this.
pub const SIGINFO_BYTES: usize = 128;

pub(crate) const SI_SIGNO: usize = 0;
pub(crate) const SI_ERRNO: usize = 4;
pub(crate) const SI_CODE: usize = 8;
/// The union is 8-aligned because `si_utime` is, so it starts at 16 rather
/// than at 12 where the three leading `int`s end. That gap is the reason
/// `si_utime` is at 32 and not at 28, which it was once written as.
pub(crate) const SI_UNION: usize = 16;

pub(crate) const KILL_PID: usize = SI_UNION;
pub(crate) const KILL_UID: usize = SI_UNION + 4;

pub(crate) const CHLD_PID: usize = SI_UNION;
pub(crate) const CHLD_UID: usize = SI_UNION + 4;
pub(crate) const CHLD_STATUS: usize = SI_UNION + 8;
pub(crate) const CHLD_UTIME: usize = SI_UNION + 16;
pub(crate) const CHLD_STIME: usize = SI_UNION + 24;

pub(crate) const FAULT_ADDR: usize = SI_UNION;

pub(crate) const TIMER_ID: usize = SI_UNION;
pub(crate) const TIMER_OVERRUN: usize = SI_UNION + 4;
pub(crate) const TIMER_VALUE: usize = SI_UNION + 8;

// ---------------------------------------------------------------------------
// signalfd_siginfo, as include/uapi/linux/signalfd.h lays it out
// ---------------------------------------------------------------------------

/// The record a read yields. Readers index it by position.
pub const RECORD_BYTES: usize = 128;

pub(crate) const SSI_SIGNO: usize = 0;
pub(crate) const SSI_ERRNO: usize = 4;
pub(crate) const SSI_CODE: usize = 8;
pub(crate) const SSI_PID: usize = 12;
pub(crate) const SSI_UID: usize = 16;
pub(crate) const SSI_FD: usize = 20;
pub(crate) const SSI_TID: usize = 24;
pub(crate) const SSI_BAND: usize = 28;
pub(crate) const SSI_OVERRUN: usize = 32;
pub(crate) const SSI_TRAPNO: usize = 36;
pub(crate) const SSI_STATUS: usize = 40;
pub(crate) const SSI_INT: usize = 44;
pub(crate) const SSI_PTR: usize = 48;
pub(crate) const SSI_UTIME: usize = 56;
pub(crate) const SSI_STIME: usize = 64;
pub(crate) const SSI_ADDR: usize = 72;
pub(crate) const SSI_ADDR_LSB: usize = 80;

// Signal numbers and si_codes this rule turns on.
pub(crate) const SIGILL: i32 = 4;
pub(crate) const SIGTRAP: i32 = 5;
pub(crate) const SIGBUS: i32 = 7;
pub(crate) const SIGFPE: i32 = 8;
pub(crate) const SIGSEGV: i32 = 11;
pub(crate) const SIGCHLD: i32 = 17;
pub(crate) const SI_TIMER: i32 = -2;

pub(crate) const SIGKILL: u32 = 9;
pub(crate) const SIGSTOP: u32 = 19;

/// The record, before it is bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Record {
    pub signo: u32,
    pub errno: i32,
    pub code: i32,
    pub pid: u32,
    pub uid: u32,
    pub tid: u32,
    pub overrun: u32,
    pub status: i32,
    pub int_: i32,
    pub ptr: u64,
    pub utime: u64,
    pub stime: u64,
    pub addr: u64,
}

pub(crate) fn i32_at(b: &[u8], at: usize) -> i32 {
    i32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
pub(crate) fn u32_at(b: &[u8], at: usize) -> u32 {
    i32_at(b, at) as u32
}
pub(crate) fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

/// Read a `siginfo_t` and say what a `signalfd` reports for it.
///
/// The whole of the rule, in one place. `si_code` is what decides, and its
/// sign matters: a *positive* code means the kernel raised the signal and the
/// union describes the event, while a negative one means somebody sent it and
/// the union describes the sender. A fault with `si_code <= 0` is a `kill(2)`
/// of `SIGSEGV`, not a segfault, and reporting an address for it would be
/// reporting the sender's pid as a memory address.
pub fn describe(info: &[u8]) -> Record {
    assert!(info.len() >= SIGINFO_BYTES, "siginfo is 128 bytes");
    let signo = i32_at(info, SI_SIGNO);
    let code = i32_at(info, SI_CODE);
    let mut r = Record {
        signo: signo as u32,
        errno: i32_at(info, SI_ERRNO),
        code,
        ..Record::default()
    };

    if signo == SIGCHLD {
        r.pid = u32_at(info, CHLD_PID);
        r.uid = u32_at(info, CHLD_UID);
        r.status = i32_at(info, CHLD_STATUS);
        r.utime = u64_at(info, CHLD_UTIME);
        r.stime = u64_at(info, CHLD_STIME);
        return r;
    }

    if matches!(signo, SIGILL | SIGFPE | SIGSEGV | SIGBUS | SIGTRAP) && code > 0 {
        r.addr = u64_at(info, FAULT_ADDR);
        return r;
    }

    if code == SI_TIMER {
        r.tid = u32_at(info, TIMER_ID);
        r.overrun = u32_at(info, TIMER_OVERRUN);
        r.ptr = u64_at(info, TIMER_VALUE);
        r.int_ = i32_at(info, TIMER_VALUE);
        return r;
    }

    // Everything else that reaches a signalfd was sent by somebody: kill,
    // tkill, sigqueue, or the kernel on their behalf.
    r.pid = u32_at(info, KILL_PID);
    r.uid = u32_at(info, KILL_UID);
    r
}

/// Lay the record out as the 128 bytes a reader indexes.
pub fn encode(out: &mut [u8], r: &Record) {
    assert!(out.len() >= RECORD_BYTES, "record buffer too small");
    // All of it, not only the fields in use: the tail is `__pad`, and a reader
    // that finds its own bytes there reads them as fields.
    out[..RECORD_BYTES].fill(0);
    let put32 = |out: &mut [u8], at: usize, v: u32| {
        out[at..at + 4].copy_from_slice(&v.to_le_bytes());
    };
    let put64 = |out: &mut [u8], at: usize, v: u64| {
        out[at..at + 8].copy_from_slice(&v.to_le_bytes());
    };
    put32(out, SSI_SIGNO, r.signo);
    put32(out, SSI_ERRNO, r.errno as u32);
    put32(out, SSI_CODE, r.code as u32);
    put32(out, SSI_PID, r.pid);
    put32(out, SSI_UID, r.uid);
    put32(out, SSI_FD, 0);
    put32(out, SSI_TID, r.tid);
    put32(out, SSI_BAND, 0);
    put32(out, SSI_OVERRUN, r.overrun);
    put32(out, SSI_TRAPNO, 0);
    put32(out, SSI_STATUS, r.status as u32);
    put32(out, SSI_INT, r.int_ as u32);
    put64(out, SSI_PTR, r.ptr);
    put64(out, SSI_UTIME, r.utime);
    put64(out, SSI_STIME, r.stime);
    put64(out, SSI_ADDR, r.addr);
    put32(out, SSI_ADDR_LSB, 0);
}

/// The signals a `signalfd` may report.
///
/// `SIGKILL` and `SIGSTOP` are removed silently, as Linux removes them:
/// consuming either through a descriptor would let a process survive a signal
/// it is not allowed to survive. Silently, not with an error, because a caller
/// that asks for "everything" with a full mask is not making a mistake.
pub fn usable_mask(mask: u64) -> u64 {
    mask & !(1u64 << (SIGKILL - 1)) & !(1u64 << (SIGSTOP - 1))
}

/// `SFD_CLOEXEC | SFD_NONBLOCK`, which are `O_CLOEXEC | O_NONBLOCK`.
pub fn flags_valid(flags: u32) -> bool {
    flags & !(0o2000000 | 0o4000) == 0
}
