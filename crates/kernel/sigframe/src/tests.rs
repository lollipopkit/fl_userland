//! Tests for signal frame offsets, round-trips, and hostile records.

use super::*;
use alloc::vec;

/// The aarch64 Linux ABI, stated rather than derived.
///
/// Every number here was a bug at some point, and three of them were bugs
/// that a struct definition made invisible. `sizeof` cannot be asked to
/// justify itself; this can.
#[test]
fn the_offsets_are_the_ones_linux_fixes() {
    assert_eq!(
        INFO_OFFSET, 0,
        "the siginfo is first, and libgcc's unwinder finds it there"
    );
    assert_eq!(INFO_SIZE, 128, "the guest's siginfo_t is 128 bytes");
    assert_eq!(UC_OFFSET, 128, "the ucontext follows it");
    assert_eq!(UC_STACK, 16);
    assert_eq!(UC_SIGMASK, 40);
    assert_eq!(
        UC_MCONTEXT, 176,
        "sigcontext is aligned(16): libc's ucontext_t and Go's runtime.ucontext both put it at 176"
    );
    assert_eq!(STACK_BYTES, 24, "guest stack_t is 24 bytes");
    assert_eq!(STACK_SIZE, 16, "stack_t's size is at 16");
    assert_eq!(SC_REGS, 8, "sigcontext's regs follow fault_address");
    assert_eq!(SC_PC, 264);
    assert_eq!(SC_PSTATE, 272);
    assert_eq!(SC_RESERVED, 288, "__reserved is aligned(16)");
    assert_eq!(SIGCONTEXT_BYTES, 4384, "guest sigcontext is 4384 bytes");
    assert_eq!(FPSIMD_SIZE, 528, "guest fpsimd_context is 528 bytes");
    assert_eq!(FRAME_SIZE, 128 + 176 + 4384);
    assert!(FRAME_SIZE.is_multiple_of(16), "the frame keeps sp 16-aligned");
}

fn sample() -> Regs {
    let mut r = Regs::default();
    for (i, reg) in r.regs.iter_mut().enumerate() {
        *reg = 0x1000 + i as u64;
    }
    r.sp = 0xffff_0000;
    r.pc = 0xdead_beef;
    r.pstate = 0x6000_0000;
    r.fault_address = 0xbad_add4;
    r.fpsr = 0x1234;
    r.fpcr = 0x5678;
    for (i, vreg) in r.vregs.iter_mut().enumerate() {
        *vreg = (i as u128) << 96 | 0xabcd;
    }
    r
}

/// `struct sigframe_regs` in `kernel/sigframe.h` mirrors [`Regs`], and the
/// C asserts these same three numbers. Either side changing alone is then
/// a build failure rather than a frame the other half reads at the wrong
/// offsets -- which is the class of defect this crate exists to remove.
#[test]
fn the_c_mirror_of_regs_cannot_drift() {
    assert_eq!(core::mem::size_of::<Regs>(), 800);
    assert_eq!(core::mem::offset_of!(Regs, fpsr), 280);
    assert_eq!(core::mem::offset_of!(Regs, vregs), 288);
}

#[test]
fn a_frame_round_trips() {
    let regs = sample();
    let stack = Stack {
        sp: 0x7000,
        flags: 1,
        size: 0x4000,
    };
    let info = [0xABu8; INFO_SIZE];
    let mut buf = vec![0u8; FRAME_SIZE];
    encode(&mut buf, &info, stack, 0xdead_0000_beef_0000, &regs);

    let got = decode(&buf).expect("decode");
    assert_eq!(got.regs, regs);
    assert_eq!(got.stack, stack);
    assert_eq!(got.sigmask, 0xdead_0000_beef_0000);
    assert!(got.have_fpsimd);
}

/// The siginfo goes in whole. It used to be written 48 bytes at a time
/// because the union it lived in ended there, so a caller that had filled
/// its 128-byte buffer with a pattern read most of the pattern back.
#[test]
fn the_whole_siginfo_lands_in_the_frame() {
    let info: [u8; INFO_SIZE] = core::array::from_fn(|i| i as u8);
    let mut buf = vec![0u8; FRAME_SIZE];
    encode(&mut buf, &info, Stack::default(), 0, &Regs::default());
    assert_eq!(&buf[..INFO_SIZE], &info[..]);
}

/// Only the prefix that carries something is written; the tail of the
/// reserved area is not touched. The frame is still FRAME_SIZE, because
/// that is what `sp` moves by.
#[test]
fn the_write_stops_after_the_terminator() {
    let mut buf = vec![0x5Au8; FRAME_SIZE];
    let n = encode(
        &mut buf,
        &[0u8; INFO_SIZE],
        Stack::default(),
        0,
        &Regs::default(),
    );
    assert!(n < FRAME_SIZE, "the whole frame need not be written: {n}");
    assert_eq!(n, 128 + 176 + 288 + 528 + 8);
    assert!(
        buf[n..].iter().all(|&b| b == 0x5A),
        "the tail was written to"
    );
    // And what was written still parses, which is the only thing the
    // shorter write may not break.
    assert!(decode(&buf).is_some());
}

/// FPSIMD need not be the first record. The C read it from offset 0 and
/// checked its magic, so a frame with anything ahead of it — Linux writes
/// an `esr_context` for a fault — lost the guest's floating-point state.
#[test]
fn fpsimd_is_found_after_another_record() {
    let regs = sample();
    let mut buf = vec![0u8; FRAME_SIZE];
    encode(&mut buf, &[0u8; INFO_SIZE], Stack::default(), 0, &regs);

    // Rebuild the chain as {esr, fpsimd, terminator}.
    let res = UC_OFFSET + UC_MCONTEXT + SC_RESERVED;
    let fpsimd: alloc::vec::Vec<u8> = buf[res..res + FPSIMD_SIZE].to_vec();
    const ESR_SIZE: usize = 16;
    put_u32(&mut buf, res, ESR_MAGIC);
    put_u32(&mut buf, res + 4, ESR_SIZE as u32);
    put_u64(&mut buf, res + 8, 0x9600_0000);
    buf[res + ESR_SIZE..res + ESR_SIZE + FPSIMD_SIZE].copy_from_slice(&fpsimd);
    put_u32(&mut buf, res + ESR_SIZE + FPSIMD_SIZE, 0);
    put_u32(&mut buf, res + ESR_SIZE + FPSIMD_SIZE + 4, 0);

    let got = decode(&buf).expect("decode");
    assert!(
        got.have_fpsimd,
        "fpsimd was not found behind the esr record"
    );
    assert_eq!(got.regs.vregs, regs.vregs);
    assert_eq!(got.regs.fpcr, regs.fpcr);
}

/// No FPSIMD record at all is legal, and is not the same as one full of
/// zeroes: Linux leaves the FP state alone. The caller is told which.
#[test]
fn a_frame_without_fpsimd_says_so() {
    let mut buf = vec![0u8; FRAME_SIZE];
    encode(&mut buf, &[0u8; INFO_SIZE], Stack::default(), 0, &sample());
    let res = UC_OFFSET + UC_MCONTEXT + SC_RESERVED;
    put_u32(&mut buf, res, 0);
    put_u32(&mut buf, res + 4, 0);
    let got = decode(&buf).expect("decode");
    assert!(!got.have_fpsimd);
    assert_eq!(
        got.regs.vregs, [0u128; 32],
        "and nothing was read into them"
    );
}

/// `rt_sigreturn` reads whatever the guest left on its stack, so the chain
/// is untrusted input. None of these may hang or read out of bounds.
#[test]
fn a_hostile_chain_terminates() {
    let base = {
        let mut b = vec![0u8; FRAME_SIZE];
        encode(
            &mut b,
            &[0u8; INFO_SIZE],
            Stack::default(),
            0,
            &Regs::default(),
        );
        b
    };
    let res = UC_OFFSET + UC_MCONTEXT + SC_RESERVED;

    // A size of zero with a non-zero magic would not advance the cursor.
    let mut buf = base.clone();
    put_u32(&mut buf, res, FPSIMD_MAGIC);
    put_u32(&mut buf, res + 4, 0);
    assert!(decode(&buf).is_some());

    // A size below the header is the same trap by another route.
    let mut buf = base.clone();
    put_u32(&mut buf, res, ESR_MAGIC);
    put_u32(&mut buf, res + 4, 4);
    assert!(decode(&buf).is_some());

    // A size past the end of the reserved area.
    let mut buf = base.clone();
    put_u32(&mut buf, res, FPSIMD_MAGIC);
    put_u32(&mut buf, res + 4, 0xFFFF_FFFF);
    assert!(decode(&buf).is_some());

    // An FPSIMD record that claims to be well-formed but is too short to
    // hold the registers must not be read as though it were.
    let mut buf = base.clone();
    put_u32(&mut buf, res, FPSIMD_MAGIC);
    put_u32(&mut buf, res + 4, 16);
    let got = decode(&buf).expect("decode");
    assert!(!got.have_fpsimd);

    // A chain with no terminator at all: records that tile the whole area.
    let mut buf = base.clone();
    let mut at = res;
    while at + 16 <= res + SC_RESERVED_LEN {
        put_u32(&mut buf, at, ESR_MAGIC);
        put_u32(&mut buf, at + 4, 16);
        at += 16;
    }
    assert!(decode(&buf).is_some());
}

/// A frame shorter than the ABI's is refused rather than read past.
#[test]
fn a_short_frame_is_refused() {
    assert!(decode(&[]).is_none());
    assert!(decode(&vec![0u8; FRAME_SIZE - 1]).is_none());
}
