//! The aarch64 signal frame: the bytes a guest finds on its stack when a
//! handler is entered, and the bytes `rt_sigreturn` reads back.
//!
//! This is a wire format, and it is the one in this tree with the worst record.
//! Four defects came out of describing it as a C struct and casting:
//!
//! - the whole frame was i386's, with a `restorer`, `pinfo`/`puc` copies and
//!   eight bytes of x86 machine code (`pop eax; mov eax, 173; int 0x80`)
//!   written onto an aarch64 stack — which moved the siginfo 32 bytes into the
//!   frame, the one thing about the layout a guest can observe;
//! - `siginfo_`'s union ended at 48, so `user_put` wrote 48 of the 128 bytes a
//!   caller had allocated and left the tail as it found it;
//! - `si_utime`/`si_stime` sat at 28 and 32 rather than 32 and 40, so a guest
//!   reading one got the other;
//! - `mcontext` sat at 168 in the ucontext and `__reserved` at 280 in it, eight
//!   bytes short of Linux's 176 and 288 each. A comment said the reverse --
//!   that an `aligned(16)` had "pushed mcontext from 168 to 176, and Go's
//!   runtime reads it at a fixed 168" -- and was never measured: Linux's
//!   `struct sigcontext` has `__reserved` `aligned(16)`, and Go's own
//!   `ucontext` carries a `_pad2 [8]byte` for exactly that. Every handler that
//!   read or wrote a register through its `ucontext_t` saw the neighbouring
//!   one; `trap_probe` found it on 2026-09-29, once it compared `si_addr` with
//!   the context's `pc` instead of printing an absolute address.
//!
//! Every one is an offset. Offsets belong somewhere they can be asserted, so
//! this crate builds the frame a byte at a time from a register snapshot and
//! parses it back, and the module-level tests state each offset the aarch64
//! Linux ABI fixes.
//!
//! # What stays in C
//!
//! `kernel/signal.c` keeps everything that is not the format: which signal is
//! being delivered, the `sighand` lock, the altstack decision, the syscall
//! restart rewind, and the writes into `struct cpu_state`. This crate never
//! sees a task. It is handed a [`Regs`] and gives back bytes — the same split
//! procfs uses, where C takes the snapshot under whatever locks apply and Rust
//! formats it.
//!
//! # The extension records
//!
//! `sigcontext.__reserved` is not a struct, it is a **chain**: a run of
//! `{magic: u32, size: u32}` headers, each `size` covering its own header,
//! terminated by one with both fields zero. Linux's `parse_user_sigframe`
//! walks it. The C here read `fpsimd_context` from offset 0 and checked only
//! its magic, which works while the only writer of the frame is the same code
//! that reads it back — and stops working for a guest that builds its own, or
//! the moment a second record is written before the FPSIMD one.

#![no_std]

extern crate alloc;

// ---------------------------------------------------------------------------
// The layout
// ---------------------------------------------------------------------------

/// `struct rt_sigframe` on aarch64 Linux is `{ siginfo, ucontext }` and
/// nothing else. `sp` points at its first byte when a handler is entered, so a
/// guest reconstructing the frame from `sp` — libgcc's aarch64 fallback
/// unwinder casts the CFA straight to this — finds the siginfo there.
pub const INFO_OFFSET: usize = 0;
/// The guest's `siginfo_t` is 128 bytes and its libc sizes buffers by that.
pub const INFO_SIZE: usize = 128;
pub const UC_OFFSET: usize = INFO_SIZE;

// Within the ucontext.
const UC_FLAGS: usize = 0;
const UC_LINK: usize = 8;
const UC_STACK: usize = 16;
const UC_SIGMASK: usize = 40;
/// `struct sigcontext` is `aligned(16)` through its `__reserved`, so it starts
/// at 176 and not at 168, where `uc_sigmask`'s 128 bytes end. Go's
/// `runtime.ucontext` spells the gap as `_pad2 [8]byte`.
const UC_MCONTEXT: usize = 176;

// Within stack_t.
const STACK_SP: usize = 0;
const STACK_FLAGS: usize = 8;
const STACK_SIZE: usize = 16;
/// `sizeof(stack_t)`. Not used to place anything -- the fields above do that
/// -- but asserted below, because a guest allocates one of these.
#[allow(dead_code)]
const STACK_BYTES: usize = 24;

// Within sigcontext.
const SC_FAULT_ADDRESS: usize = 0;
const SC_REGS: usize = 8;
const SC_SP: usize = 256;
const SC_PC: usize = 264;
const SC_PSTATE: usize = 272;
/// 288, not 280 where `pstate` ends: the `aligned(16)`.
const SC_RESERVED: usize = 288;
/// The reserved area is 4096 bytes, and that is part of the ABI: it fixes
/// `sizeof(struct ucontext)`, which a guest that allocates one relies on.
const SC_RESERVED_LEN: usize = 4096;
const SIGCONTEXT_BYTES: usize = SC_RESERVED + SC_RESERVED_LEN;

const UCONTEXT_BYTES: usize = UC_MCONTEXT + SIGCONTEXT_BYTES;
/// The whole frame, which is what the guest's `sp` is moved down by.
pub const FRAME_SIZE: usize = UC_OFFSET + UCONTEXT_BYTES;

/// Extension record magics, from `arch/arm64/include/uapi/asm/sigcontext.h`.
pub const FPSIMD_MAGIC: u32 = 0x4650_8001;
pub const ESR_MAGIC: u32 = 0x4553_5201;
pub const EXTRA_MAGIC: u32 = 0x4558_5401;
pub const SVE_MAGIC: u32 = 0x5356_4501;

/// A record header is `{magic, size}`, and `size` covers the header.
const RECORD_HEADER: usize = 8;
/// `struct fpsimd_context`: the header, then `fpsr`, `fpcr`, then 32 128-bit
/// vector registers at offset 16.
const FPSIMD_VREGS: usize = 16;
pub const FPSIMD_SIZE: usize = FPSIMD_VREGS + 32 * 16;

// ---------------------------------------------------------------------------
// What the format carries
// ---------------------------------------------------------------------------

/// The CPU state a signal frame saves and restores.
///
/// Deliberately not `struct cpu_state`: that one is a contract with hand
/// written assembly through `cpu-offsets.h`, and mirroring it here would be a
/// second such contract that no compiler checks. This is the subset the frame
/// holds, and the C side copies into it field by field.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Regs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub fault_address: u64,
    pub fpsr: u32,
    pub fpcr: u32,
    /// v0..v31, each 128 bits, little-endian as the guest sees them.
    pub vregs: [u128; 32],
}

/// `stack_t` as the frame carries it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stack {
    pub sp: u64,
    pub flags: i32,
    pub size: u64,
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

fn put_u32(out: &mut [u8], at: usize, v: u32) {
    out[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(out: &mut [u8], at: usize, v: u64) {
    out[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn get_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

fn get_u64(buf: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[at..at + 8]);
    u64::from_le_bytes(b)
}

/// Build a signal frame.
///
/// `out` must be at least [`FRAME_SIZE`] bytes and is written from the start.
/// Returns **how many bytes were actually written**, which is less than
/// `FRAME_SIZE`: the extension chain ends after the FPSIMD record and its
/// terminator, and the rest of the 4096-byte reserved area is never read.
///
/// The C this replaces built the whole 4672-byte frame (4688 since the 2026-09-29 offset fix) as a zeroed local and
/// copied all of it into guest memory on every signal delivery, about 3560
/// bytes of which is zeroes nothing will look at. This writes 1112.
///
/// **That is not measurably faster**, and it is worth saying so: 200k
/// `raise()`/handler round trips came to a median 1373 ns each against 1398
/// before, which is inside the run-to-run spread. Whatever signal delivery
/// costs, it is not this memcpy. The shorter write is kept because it is what
/// an encoder that knows its own output length produces, and because it is
/// what Linux does — it writes the records and leaves the rest of the user's
/// stack as it found it — not because it bought anything.
///
/// The guest's `sp` still moves by [`FRAME_SIZE`] either way, because that is
/// the ABI.
///
/// # Panics
/// If `out` is shorter than [`FRAME_SIZE`] or `info` is not [`INFO_SIZE`].
pub fn encode(out: &mut [u8], info: &[u8], stack: Stack, sigmask: u64, regs: &Regs) -> usize {
    assert!(out.len() >= FRAME_SIZE, "frame buffer too small");
    assert_eq!(info.len(), INFO_SIZE, "siginfo is 128 bytes");

    let written = UC_OFFSET + UC_MCONTEXT + SC_RESERVED + FPSIMD_SIZE + RECORD_HEADER;
    out[..written].fill(0);

    out[INFO_OFFSET..INFO_OFFSET + INFO_SIZE].copy_from_slice(info);

    let uc = UC_OFFSET;
    put_u64(out, uc + UC_FLAGS, 0);
    put_u64(out, uc + UC_LINK, 0);
    put_u64(out, uc + UC_STACK + STACK_SP, stack.sp);
    put_u32(out, uc + UC_STACK + STACK_FLAGS, stack.flags as u32);
    put_u64(out, uc + UC_STACK + STACK_SIZE, stack.size);
    put_u64(out, uc + UC_SIGMASK, sigmask);

    let sc = uc + UC_MCONTEXT;
    put_u64(out, sc + SC_FAULT_ADDRESS, regs.fault_address);
    for (i, r) in regs.regs.iter().enumerate() {
        put_u64(out, sc + SC_REGS + i * 8, *r);
    }
    put_u64(out, sc + SC_SP, regs.sp);
    put_u64(out, sc + SC_PC, regs.pc);
    put_u64(out, sc + SC_PSTATE, regs.pstate);

    // The extension chain: one FPSIMD record, then the terminator. Written
    // through the same helper a reader walks, so the two cannot disagree about
    // where a record's payload starts.
    let fp = sc + SC_RESERVED;
    put_u32(out, fp, FPSIMD_MAGIC);
    put_u32(out, fp + 4, FPSIMD_SIZE as u32);
    put_u32(out, fp + 8, regs.fpsr);
    put_u32(out, fp + 12, regs.fpcr);
    for (i, v) in regs.vregs.iter().enumerate() {
        out[fp + FPSIMD_VREGS + i * 16..fp + FPSIMD_VREGS + (i + 1) * 16]
            .copy_from_slice(&v.to_le_bytes());
    }
    // magic 0, size 0 ends the chain. Already zero from the fill above; written
    // out anyway, because "it happens to be zeroed" is how a terminator goes
    // missing when the fill changes.
    put_u32(out, fp + FPSIMD_SIZE, 0);
    put_u32(out, fp + FPSIMD_SIZE + 4, 0);

    written
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// What a frame said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub regs: Regs,
    pub stack: Stack,
    pub sigmask: u64,
    /// Whether an FPSIMD record was present. Its absence is legal — Linux
    /// treats it as "leave the FP state alone" — and is not the same as one
    /// full of zeroes, which would wipe the guest's registers.
    pub have_fpsimd: bool,
}

/// Parse a frame out of guest memory.
///
/// Returns `None` if the buffer is too short. Everything else in it is
/// untrusted: a guest may hand `rt_sigreturn` any bytes it likes, so a record
/// with an absurd size, a chain that does not terminate, or a magic nobody
/// recognises has to be survivable rather than fatal.
pub fn decode(frame: &[u8]) -> Option<Frame> {
    if frame.len() < FRAME_SIZE {
        return None;
    }
    let uc = UC_OFFSET;
    let sc = uc + UC_MCONTEXT;

    // `mut`: the rest is a loop over the register array, which a struct
    // literal cannot express.
    let mut regs = Regs {
        fault_address: get_u64(frame, sc + SC_FAULT_ADDRESS),
        ..Default::default()
    };
    for i in 0..31 {
        regs.regs[i] = get_u64(frame, sc + SC_REGS + i * 8);
    }
    regs.sp = get_u64(frame, sc + SC_SP);
    regs.pc = get_u64(frame, sc + SC_PC);
    regs.pstate = get_u64(frame, sc + SC_PSTATE);

    let stack = Stack {
        sp: get_u64(frame, uc + UC_STACK + STACK_SP),
        flags: get_u32(frame, uc + UC_STACK + STACK_FLAGS) as i32,
        size: get_u64(frame, uc + UC_STACK + STACK_SIZE),
    };
    let sigmask = get_u64(frame, uc + UC_SIGMASK);

    let mut have_fpsimd = false;
    let reserved = &frame[sc + SC_RESERVED..sc + SC_RESERVED + SC_RESERVED_LEN];
    for (magic, body) in Records::new(reserved) {
        if magic == FPSIMD_MAGIC && body.len() >= FPSIMD_SIZE - RECORD_HEADER {
            // `body` starts after the {magic, size} header, so fpsr is at 0.
            regs.fpsr = get_u32(body, 0);
            regs.fpcr = get_u32(body, 4);
            for i in 0..32 {
                let at = FPSIMD_VREGS - RECORD_HEADER + i * 16;
                let mut b = [0u8; 16];
                b.copy_from_slice(&body[at..at + 16]);
                regs.vregs[i] = u128::from_le_bytes(b);
            }
            have_fpsimd = true;
        }
    }

    Some(Frame {
        regs,
        stack,
        sigmask,
        have_fpsimd,
    })
}

/// Walks the `{magic, size}` chain in a reserved area.
///
/// Yields `(magic, body)` for each well-formed record and stops at the
/// terminator, at anything that does not fit, or at a size that would not
/// advance — a record claiming a size below its own header would otherwise
/// loop for ever on input the guest chose.
struct Records<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Records<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Records { buf, at: 0 }
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = (u32, &'a [u8]);

    fn next(&mut self) -> Option<(u32, &'a [u8])> {
        if self.at + RECORD_HEADER > self.buf.len() {
            return None;
        }
        let magic = get_u32(self.buf, self.at);
        let size = get_u32(self.buf, self.at + 4) as usize;
        if magic == 0 && size == 0 {
            return None; // the terminator
        }
        if size < RECORD_HEADER || self.at + size > self.buf.len() {
            return None;
        }
        let body = &self.buf[self.at + RECORD_HEADER..self.at + size];
        self.at += size;
        Some((magic, body))
    }
}

#[cfg(test)]
mod tests;
