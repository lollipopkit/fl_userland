//! One guest instruction: read it, classify it, and hand it to its class.
//!
//! # What is not here
//!
//! Two peepholes that fused CPython's inlined `Py_INCREF`/`Py_DECREF` were in
//! the C, both behind `#define DISABLE_..._FUSION 1` with a comment saying the
//! gadgets they emit "are still a work in progress and are NOT yet committed".
//! They were not: `gadget_incref` and `gadget_decref` are in no `.S` in this
//! tree, so the code could not have linked, and no build ever compiled a line
//! of it. Deleted rather than moved, the way `cpu_single_step` was.

use crate::classify::{Class, classify};
use crate::{BLOCK_ENDS, DECODED, ffi};
use std::ffi::c_int;

/// Compile one instruction into the block.
///
/// Answers 1 to keep going and 0 to end the block, which is what `gen_step`'s
/// caller in `asbestos/asbestos.c` treats as `continue` and `stop`.
///
/// # Safety
/// `tlb` is this thread's.
/// Not `#[unsafe(no_mangle)]` since 2026-09-06, for the reason
/// `tools/dead-exports.py` now reports: no C source or assembly names it,
/// no `ffi::` reaches it, and no header the embedder example compiles
/// against declares it. An export nobody can reach is an optimisation
/// barrier, and this one is on the block-compile path.
pub unsafe fn gen_step(b: &mut crate::Builder, tlb: *mut ffi::tlb) -> c_int {
    let mut g = b.decoder();
    // SAFETY: the caller's contract.
    unsafe { g.begin(tlb) };

    let Some(insn) = g.peek() else {
        // The instruction is not readable, which is a block that ran off the
        // end of a mapping. The guest gets the fault at that address.
        g.interrupt(ffi::INT_GPF as c_int);
        return BLOCK_ENDS;
    };
    g.consume(1);
    g.set_last_insn(insn);

    // Two SVE instructions, modelled as the 128-bit vectors this emulator has.
    // They are here rather than in the SIMD class because `arm64_classify_insn`
    // puts the SVE encoding space in `INSN_UNKNOWN`, so a class decoder would
    // never see them.
    let rd = (insn & 0x1f) as u64;
    let rm = ((insn >> 16) & 0x1f) as u64;
    if insn & 0xffe0_fc00 == 0x04a0_3000 {
        let rn = ((insn >> 5) & 0x1f) as u64;
        g.slow_call(asbestos_crypto::slow::slow_sve_eor, rd | (rn << 8) | (rm << 16));
        return DECODED;
    }
    if insn & 0xffe0_fc00 == 0x04e0_3400 || insn & 0xffe0_fc00 == 0x04a0_3400 {
        // Destructive: the destination is also the first source. The rotate is
        // encoded as a distance from the top of the element rather than as
        // itself, and a distance of zero means a whole 32 rather than none.
        let zm = ((insn >> 5) & 0x1f) as u64;
        let low = match (32 - rm) & 0x1f {
            0 => 32,
            n => n,
        };
        let imm = low + if (insn >> 22) & 1 != 0 { 0 } else { 32 };
        g.slow_call(asbestos_crypto::slow::slow_xar, rd | (rd << 8) | (zm << 16) | (imm << 24));
        return DECODED;
    }

    // The extensions beyond ARMv8.0, before the class decoders: an encoding
    // here is one they either refuse or do not know, and taking it first keeps
    // that whole set in one module.
    if let Some(r) = crate::features::decode(&mut g, insn) {
        return r;
    }

    match classify(insn) {
        Class::DpImm => crate::dpimm::decode(&mut g, insn),
        Class::Branch | Class::Exception | Class::System => crate::branch::decode(&mut g, insn),
        Class::LdSt => crate::ldst::decode(&mut g, insn),
        Class::DpReg => crate::dpreg::decode(&mut g, insn),
        Class::SimdFp => crate::simd::decode(&mut g, insn),
        Class::Unknown => g.undefined(),
    }
}
