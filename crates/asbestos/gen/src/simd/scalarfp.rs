//! Scalar floating-point: the conversions to and from general registers, the
//! compares, and the one-, two- and three-source arithmetic.
//!
//! These share the `0 0 0 11110 ftype ...` space with a general register on one
//! side, which is what separates them from everything else in the class.
//!
//! # `ftype` is a two-bit field with three meanings
//!
//! 0 is single, 1 is double, 3 is half — an extension this kernel does not
//! implement — and 2 is unallocated *except* in the two `FMOV`s that move the
//! high half of a 128-bit register, where it means exactly that. So the check
//! is per instruction, not once at the top, and writing it once at the top is
//! how the high-half `FMOV`s would stop being decoded.

use crate::gadgets::*;
use crate::{DECODED, Gadget, Gen};
use std::ffi::c_int;

/// Conversion between a general register and a floating-point one, by
/// `(rmode, opcode)`.
static CONVERT: &[(u32, u32, Gadget)] = &[
    (0, 0, gadget_fcvtns_scalar),
    (0, 1, gadget_fcvtnu_scalar),
    (0, 2, gadget_scvtf_scalar),
    (0, 3, gadget_ucvtf_scalar),
    (0, 4, gadget_fcvtas_scalar),
    (0, 5, gadget_fcvtau_scalar),
    (0, 6, gadget_fmov_fp_to_gpr),
    (0, 7, gadget_fmov_gpr_to_fp),
    (1, 0, gadget_fcvtps_scalar),
    (1, 1, gadget_fcvtpu_scalar),
    (2, 0, gadget_fcvtms_scalar),
    (2, 1, gadget_fcvtmu_scalar),
    (3, 0, gadget_fcvtzs_scalar),
    (3, 1, gadget_fcvtzu_scalar),
];

/// The two-source arithmetic, by opcode.
static BINARY: &[Gadget] = &[
    gadget_fmul_scalar,
    gadget_fdiv_scalar,
    gadget_fadd_scalar,
    gadget_fsub_scalar,
    gadget_fmax_scalar,
    gadget_fmin_scalar,
    gadget_fmaxnm_scalar,
    gadget_fminnm_scalar,
    gadget_fnmul_scalar,
];

/// The three-source arithmetic, by `o1:o0`. All four multiply and add; they
/// differ in which of the two results is negated.
static TERNARY: [Gadget; 4] = [
    gadget_fmadd_scalar,
    gadget_fmsub_scalar,
    gadget_fnmadd_scalar,
    gadget_fnmsub_scalar,
];

pub fn decode(g: &mut Gen, insn: u32) -> Option<c_int> {
    let rd = (insn & 0x1f) as u64;
    let rn = ((insn >> 5) & 0x1f) as u64;
    let rm = ((insn >> 16) & 0x1f) as u64;
    let ftype = (insn >> 22) & 3;

    // Conversion, and the four `FMOV`s that cross between register files.
    if insn & 0x7f20_fc00 == 0x1e20_0000 {
        let sf = ((insn >> 31) & 1) as u64;
        let rmode = (insn >> 19) & 3;
        let opcode = (insn >> 16) & 7;

        // The two that move the *top* half of a vector register. `ftype = 2`
        // is what says "128-bit", and it is the only place that value is
        // allocated at all.
        let high_half = ftype == 2 && sf == 1 && rmode == 1;
        let gadget: Option<Gadget> = match (high_half, opcode) {
            (true, 6) => Some(gadget_fmov_fp_to_gpr_hi),
            (true, 7) => Some(gadget_fmov_gpr_to_fp_hi),
            (true, _) => None,
            // `ftype = 2` is allocated **only** for those two, and the comment
            // above said so while the table below was reached anyway: it
            // matches on `(rmode, opcode)` and never looks at the type, so
            // twenty encodings decoded as an `SCVTF` or an `FCVTZS` of a
            // precision that does not exist. `decode_probe` swept the group and
            // a real kernel refuses every one.
            (false, _) if ftype == 2 => None,
            // Half precision to or from a general register -- the conversions
            // and `FMOV Wd, Hn` -- is FEAT_FP16, which is not advertised, and
            // none of these gadgets has a half case: `FCVTPU Wd, Hn` ran as a
            // conversion of a double and `FMOV Wd, Hn` moved 64 bits.
            (false, _) if ftype == 3 => None,
            // The two plain `FMOV`s move a whole register between the files, so
            // the two registers have to be the same size: `FMOV Wd, Sn` and
            // `FMOV Xd, Dn`, not one of each. `sf` is the general register's
            // width and `ftype` is the vector one, and the table below matches
            // on neither — so `FMOV Wd, Dn` decoded and moved a double into a
            // 32-bit register.
            (false, 6 | 7) if rmode == 0 && sf as u32 != ftype => None,
            _ => CONVERT
                .iter()
                .find(|(r, o, _)| *r == rmode && *o == opcode)
                .map(|(_, _, gadget)| *gadget),
        };
        if let Some(gadget) = gadget {
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | ((ftype as u64) << 16) | (sf << 18));
            return Some(DECODED);
        }
    }

    // The fixed-point forms of the same four conversions: the value is scaled
    // by 2^fbits on the way through, so an integer register holds a fraction.
    if insn & 0x7f20_0000 == 0x1e00_0000 && ftype <= 1 {
        let sf = ((insn >> 31) & 1) as u64;
        let rmode = (insn >> 19) & 3;
        let opcode = (insn >> 16) & 7;
        // The encoding carries `scale`, and what the gadget wants is how many
        // fraction bits that leaves — always out of 64, whatever `sf` says,
        // because the gadget works in 64 bits and narrows afterwards.
        let fbits = 64 - ((insn >> 10) & 0x3f) as u64;
        // A W register has at most 32 fraction bits, so `scale` (64 - fbits)
        // is 32 or more: bit 15 of the instruction must be set when `sf` is
        // clear. The rest was read as a scale of 1 to 31 and ran.
        if sf == 0 && (insn >> 15) & 1 == 0 {
            return Some(g.undefined());
        }
        let gadget: Option<Gadget> = match (rmode, opcode) {
            (3, 0) => Some(gadget_fcvtzs_fixpt_gpr),
            (3, 1) => Some(gadget_fcvtzu_fixpt_gpr),
            (0, 2) => Some(gadget_scvtf_fixpt_gpr),
            (0, 3) => Some(gadget_ucvtf_fixpt_gpr),
            _ => None,
        };
        if let Some(gadget) = gadget {
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | ((ftype as u64) << 16) | (sf << 18) | (fbits << 20));
            return Some(DECODED);
        }
    }

    // FCMP, FCMPE, and their forms that compare against zero.
    if insn & 0xff20_fc00 == 0x1e20_2000 {
        if ftype > 1 {
            return Some(g.undefined());
        }
        // `opcode2` is five bits and only its top two carry anything — bit 4 is
        // the signalling form and bit 3 the compare against zero. The low three
        // **must be zero**, and were not read at all, so 56 encodings decoded as
        // whichever `FCMP` those two bits named. The same shape as the `op2`
        // that made half of conditional select run.
        if insn & 0x7 != 0 {
            return Some(g.undefined());
        }
        // Bit 4 is the `E`, and it is the whole difference between `FCMP` and
        // `FCMPE`: the signalling form raises Invalid for a *quiet* NaN where
        // the other does not. It was not decoded at all until 2026-09-02, so
        // both ran as `FCMP` and `fetestexcept(FE_INVALID)` after a `<` on a
        // NaN — which is what a C relational operator compiles to — reported
        // nothing. See `tests/guest/src/bin/fp_probe.rs`.
        let e = ((insn >> 4) & 1) as u64;
        // Bit 3 says the second operand is the constant zero rather than a
        // register, which is why the two forms pack different words.
        if insn & 0x8 != 0 {
            g.gadget(gadget_fcmp_zero_scalar);
            g.emit(rn | ((ftype as u64) << 16) | (e << 20));
        } else {
            g.gadget(gadget_fcmp_scalar);
            g.emit(rn | (rm << 8) | ((ftype as u64) << 16) | (e << 20));
        }
        return Some(DECODED);
    }

    // FCCMP/FCCMPE: compare if the condition holds, and otherwise set the flags
    // to a constant the instruction carries.
    if insn & 0xff20_0c00 == 0x1e20_0400 {
        if ftype > 1 {
            return Some(g.undefined());
        }
        let cond = ((insn >> 12) & 0xf) as u64;
        let nzcv = (insn & 0xf) as u64;
        // Bit 4 is the `E` of `FCCMPE`, as in `FCMPE`: the signalling form
        // raises Invalid for a quiet NaN. It was dropped, so both ran as
        // `FCCMP`.
        let e = ((insn >> 4) & 1) as u64;
        g.gadget(gadget_fccmp_scalar);
        g.emit(rn | (rm << 8) | ((ftype as u64) << 16) | (cond << 20) | (nzcv << 24) | (e << 28));
        return Some(DECODED);
    }

    // FCSEL.
    if insn & 0xff20_0c00 == 0x1e20_0c00 {
        if ftype > 1 {
            return Some(g.undefined());
        }
        let cond = ((insn >> 12) & 0xf) as u64;
        g.gadget(gadget_fcsel_scalar);
        g.emit(rd | (rn << 8) | (rm << 16) | ((ftype as u64) << 24));
        g.emit(cond);
        return Some(DECODED);
    }

    // One-source arithmetic — `FMOV`, `FABS`, `FNEG`, `FSQRT`, the `FRINT`s
    // and the conversions between precisions. There is one gadget for all
    // sixteen: it re-runs the guest's own instruction on the host with the
    // emulated registers as operands, so the rounding and the exceptions are
    // the hardware's rather than something written down here.
    if insn & 0xff20_7c00 == 0x1e20_4000 {
        let opcode = (insn >> 15) & 0x3f;
        // Opcodes 4 to 7 are `FCVT` and the low two bits name the *destination*
        // precision: 0 single, 1 double, 3 half, and 2 nothing. A conversion to
        // the precision it already is names no instruction either, so `FCVT S,
        // S` is not one — nor is opcode 13, which is a hole in the rounding
        // family. Five encodings ran as whatever the shared gadget made of the
        // number.
        let unallocated =
            matches!(opcode, 4..=7 if opcode & 3 == 2 || opcode & 3 == ftype) || opcode == 13;
        // A half-precision *source* (`ftype = 3`) is FEAT_FP16 for every
        // operation but the two conversions out of it, which are baseline: the
        // decoder refused those, and `fcvt s0, h1` raised SIGILL.
        let readable = ftype <= 1 || (ftype == 3 && matches!(opcode, 4 | 5));
        if readable && opcode <= 15 && !unallocated {
            g.gadget(gadget_fp_dp1);
            g.emit(rd | (rn << 8) | ((ftype as u64) << 16) | ((opcode as u64) << 20));
            return Some(DECODED);
        }
    }

    // Two-source arithmetic.
    if insn & 0xff20_0000 == 0x1e20_0000 && (insn >> 10) & 3 == 2 {
        if ftype > 1 {
            return Some(g.undefined());
        }
        let opcode = ((insn >> 12) & 0xf) as usize;
        if let Some(&gadget) = BINARY.get(opcode) {
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | (rm << 16) | ((ftype as u64) << 24));
            return Some(DECODED);
        }
    }

    // Three-source: multiply two and add the third, with two independent
    // negations. `M` and `S` — bits 31 and 29 — must be clear; they name
    // instruction sets this does not have.
    if insn & 0x5f00_0000 == 0x1f00_0000 {
        if insn & 0x8000_0000 != 0 || insn & 0x2000_0000 != 0 || ftype > 1 {
            return Some(g.undefined());
        }
        let op = (((insn >> 21) & 1) << 1) | ((insn >> 15) & 1);
        let ra = ((insn >> 10) & 0x1f) as u64;
        g.gadget(TERNARY[op as usize]);
        g.emit(rd | (rn << 8) | (rm << 16) | (ra << 24));
        g.emit(ftype as u64);
        return Some(DECODED);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Decoder;

    /// No `(rmode, opcode)` appears twice — a duplicate would be one rounding
    /// mode silently answering for another, which produces a right-looking
    /// number that is one ulp out about half the time.
    #[test]
    fn the_conversion_table_has_no_duplicate_pairs() {
        let mut seen: Vec<(u32, u32)> = CONVERT.iter().map(|(r, o, _)| (*r, *o)).collect();
        let n = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), n);
    }

    /// `ftype = 2` is unallocated everywhere except the two high-half `FMOV`s,
    /// and those need `rmode = 1` and a 64-bit register as well. A check
    /// written once at the top of the function would refuse them.
    #[test]
    fn the_high_half_moves_are_the_only_use_of_ftype_two() {
        // `fmov x0, v1.d[1]`.
        let insn = 0x9eae_0000u32 | (1 << 5);
        assert_eq!((insn >> 22) & 3, 2, "ftype");
        assert_eq!((insn >> 31) & 1, 1, "sf");
        assert_eq!((insn >> 19) & 3, 1, "rmode");
        assert_eq!((insn >> 16) & 7, 6, "opcode");
        assert_eq!(
            insn & 0x7f20_fc00,
            0x1e20_0000,
            "it is in the conversion group"
        );
    }

    /// The three-source group is the one that has to check `M` and `S`: they
    /// are two bits that are not part of any field this decodes, so an encoding
    /// with either set is a different instruction set rather than a variant.
    #[test]
    fn the_ternary_group_refuses_m_and_s() {
        let fmadd = 0x1f00_0000u32;
        assert_eq!(fmadd & 0x5f00_0000, 0x1f00_0000);
        // With M set, the same mask still matches — which is why it is a check
        // in the body and not part of the mask.
        assert_eq!((fmadd | 0x8000_0000) & 0x5f00_0000, 0x1f00_0000);
        assert_eq!((fmadd | 0x2000_0000) & 0x5f00_0000, 0x1f00_0000);
    }

    /// The four ternary forms are `o1:o0`, and the two bits are eight apart in
    /// the instruction — one at 21 and one at 15 — so assembling the index in
    /// the wrong order swaps `FMSUB` with `FNMADD`.
    #[test]
    fn the_ternary_index_is_o1_then_o0() {
        let build = |o1: u32, o0: u32| 0x1f00_0000u32 | (o1 << 21) | (o0 << 15);
        let index = |insn: u32| (((insn >> 21) & 1) << 1) | ((insn >> 15) & 1);
        assert_eq!(index(build(0, 0)), 0);
        assert_eq!(index(build(0, 1)), 1);
        assert_eq!(index(build(1, 0)), 2);
        assert_eq!(index(build(1, 1)), 3);
        assert_eq!(
            TERNARY[2] as *const () as usize,
            gadget_fnmadd_scalar as *const () as usize
        );
    }

    /// This group answers `None` for an encoding that is not its own, and the
    /// dispatcher above it falls through to the undefined interrupt. A test
    /// wants the two together.
    fn decode_or_undefined(g: &mut Gen, insn: u32) -> c_int {
        match decode(g, insn) {
            Some(r) => r,
            None => g.undefined(),
        }
    }

    /// `ftype = 10` names a 128-bit operand and is allocated **only** for the
    /// two `FMOV`s that move a vector register's top half. The comment above the
    /// decoder said so while the table below it was reached anyway — it matches
    /// on `(rmode, opcode)` and never looked at the type — so twenty encodings
    /// decoded as a conversion of a precision that does not exist.
    #[test]
    fn ftype_two_is_only_the_high_half_moves() {
        let mut d = Decoder::new();
        let cvt = |sf: u32, ftype: u32, rmode: u32, opcode: u32| {
            0x1e20_0000 | (sf << 31) | (ftype << 22) | (rmode << 19) | (opcode << 16)
        };
        assert!(
            d.decodes(decode_or_undefined, cvt(1, 2, 1, 6)),
            "FMOV Xd, Vn.D[1]"
        );
        assert!(
            d.decodes(decode_or_undefined, cvt(1, 2, 1, 7)),
            "FMOV Vd.D[1], Xn"
        );
        for rmode in 0..4u32 {
            for opcode in 0..8u32 {
                if rmode == 1 && (opcode == 6 || opcode == 7) {
                    continue;
                }
                assert!(
                    !d.decodes(decode_or_undefined, cvt(1, 2, rmode, opcode)),
                    "ftype 2 rmode {rmode} opcode {opcode}"
                );
                assert!(!d.decodes(decode_or_undefined, cvt(0, 2, rmode, opcode)));
            }
        }
        // And with a 32-bit general register they do not exist either.
        assert!(!d.decodes(decode_or_undefined, cvt(0, 2, 1, 6)));
    }

    /// The plain `FMOV` moves a whole register between the files, so the two
    /// have to be the same size: `FMOV Wd, Sn` and `FMOV Xd, Dn`, not one of
    /// each. Neither `sf` nor `ftype` was looked at, so `FMOV Wd, Dn` decoded.
    #[test]
    fn a_register_to_register_fmov_moves_between_equal_widths() {
        let mut d = Decoder::new();
        let fmov = |sf: u32, ftype: u32, opcode: u32| {
            0x1e20_0000 | (sf << 31) | (ftype << 22) | (opcode << 16)
        };
        for opcode in [6u32, 7] {
            assert!(
                d.decodes(decode_or_undefined, fmov(0, 0, opcode)),
                "W and S"
            );
            assert!(
                d.decodes(decode_or_undefined, fmov(1, 1, opcode)),
                "X and D"
            );
            assert!(
                !d.decodes(decode_or_undefined, fmov(0, 1, opcode)),
                "W and D"
            );
            assert!(
                !d.decodes(decode_or_undefined, fmov(1, 0, opcode)),
                "X and S"
            );
            // The half-precision forms are FEAT_FP16, which is not advertised:
            // the gadgets have no half case (`FMOV Wd, Hn` moved 64 bits, where
            // a real CPU zero-extends 16), so they are undefined.
            assert!(
                !d.decodes(decode_or_undefined, fmov(0, 3, opcode)),
                "W and H"
            );
            assert!(
                !d.decodes(decode_or_undefined, fmov(1, 3, opcode)),
                "X and H"
            );
        }
    }

    /// `opcode2` is five bits and only its top two carry anything: bit 4 is the
    /// signalling form and bit 3 the compare against zero. The low three must be
    /// zero, and were not read — so 56 encodings decoded as whichever `FCMP`
    /// those two bits named.
    #[test]
    fn the_low_bits_of_a_compares_opcode2_must_be_zero() {
        let mut d = Decoder::new();
        let cmp = |ftype: u32, opcode2: u32| 0x1e20_2000 | (ftype << 22) | opcode2;
        for ftype in 0..2u32 {
            for opcode2 in 0..32u32 {
                assert_eq!(
                    d.decodes(decode_or_undefined, cmp(ftype, opcode2)),
                    opcode2 & 7 == 0,
                    "ftype {ftype} opcode2 {opcode2}"
                );
            }
        }
    }

    /// Opcodes 4 to 7 of the one-source group are `FCVT` and their low two bits
    /// name the *destination* precision. Converting to the precision the operand
    /// already is names no instruction, nor does destination `10`, nor does
    /// opcode 13.
    #[test]
    fn a_precision_conversion_changes_the_precision() {
        let mut d = Decoder::new();
        let dp1 = |ftype: u32, opcode: u32| 0x1e20_4000 | (ftype << 22) | (opcode << 15);
        assert!(!d.decodes(decode_or_undefined, dp1(0, 4)), "FCVT S to S");
        assert!(!d.decodes(decode_or_undefined, dp1(1, 5)), "FCVT D to D");
        assert!(d.decodes(decode_or_undefined, dp1(0, 5)), "FCVT S to D");
        assert!(d.decodes(decode_or_undefined, dp1(1, 4)), "FCVT D to S");
        assert!(
            !d.decodes(decode_or_undefined, dp1(0, 6)),
            "destination 10 is nothing"
        );
        for ftype in 0..2u32 {
            assert!(!d.decodes(decode_or_undefined, dp1(ftype, 13)), "opcode 13");
            // The rounding family around the hole still decodes.
            for opcode in [8u32, 9, 10, 11, 12, 14, 15] {
                assert!(
                    d.decodes(decode_or_undefined, dp1(ftype, opcode)),
                    "op {opcode}"
                );
            }
        }
    }
}
