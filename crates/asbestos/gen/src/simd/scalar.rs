//! The scalar SIMD forms: one element of a vector register, operated on alone.
//!
//! These are not the scalar floating-point instructions — those are
//! [`super::scalarfp`], and they have a general register on one side. These
//! have a vector register on both, and the operation is the vector one applied
//! to lane zero. The integer ones are 64-bit only, because a narrower scalar
//! integer operation is what the general registers are for.

use super::shift::{Amount, width_and_shift};
use crate::gadgets::*;
use crate::{DECODED, Gadget, Gen};
use std::ffi::c_int;

/// The scalar three-same forms that exist at **every** element width, by
/// `(U, opcode)`.
///
/// None of these was decoded until 2026-09-03. A compiler does not emit a
/// scalar SIMD form from ordinary C — they come from NEON intrinsics, which is
/// what ffmpeg, libvpx and OpenSSL are written in — so nothing in this tree's
/// rootfs used one and no test reached them. `decode_probe` found them by
/// sweeping the encoding space.
static SIZED: &[(u32, u32, Gadget)] = &[
    (0, 0x01, gadget_sqadd_scalar),
    (1, 0x01, gadget_uqadd_scalar),
    (0, 0x05, gadget_sqsub_scalar),
    (1, 0x05, gadget_uqsub_scalar),
    (0, 0x09, gadget_sqshl_scalar),
    (1, 0x09, gadget_uqshl_scalar),
    (0, 0x0b, gadget_sqrshl_scalar),
    (1, 0x0b, gadget_uqrshl_scalar),
];

/// The two that exist for halfwords and words only: a doubling multiply of two
/// 32-bit values needs 64 bits and the destination has 32.
static HALF_WORD: &[(u32, u32, Gadget)] = &[
    (0, 0x16, gadget_sqdmulh_scalar),
    (1, 0x16, gadget_sqrdmulh_scalar),
];

/// The floating-point three-same forms. `size`'s low bit is the precision and
/// its **high bit selects the instruction**, which is why the key is a triple
/// and not a pair — `FCMGE` and `FCMGT` are the same `(U, opcode)`.
static FP_THREE_SAME: &[(u32, u32, u32, Gadget)] = &[
    (0, 0, 0x1b, gadget_fmulx_scalar3),
    (0, 0, 0x1c, gadget_fcmeq_scalar3),
    (1, 0, 0x1c, gadget_fcmge_scalar3),
    (1, 1, 0x1c, gadget_fcmgt_scalar3),
    (1, 0, 0x1d, gadget_facge_scalar3),
    (1, 1, 0x1d, gadget_facgt_scalar3),
    (0, 0, 0x1f, gadget_frecps_scalar3),
    (0, 1, 0x1f, gadget_frsqrts_scalar3),
];

/// The 64-bit integer three-register operations, by `(U, opcode)`.
static THREE_SAME: &[(u32, u32, Gadget)] = &[
    (0, 0x0a, gadget_srshl_scalar),
    (1, 0x0a, gadget_urshl_scalar),
    (0, 0x11, gadget_cmtst_scalar),
    (0, 0x06, gadget_cmgt_scalar_i64),
    (1, 0x06, gadget_cmhi_scalar_i64),
    (0, 0x07, gadget_cmge_scalar_i64),
    (1, 0x07, gadget_cmhs_scalar_i64),
    (0, 0x08, gadget_sshl_scalar_i64),
    (1, 0x08, gadget_ushl_scalar_i64),
    (0, 0x10, gadget_add_scalar_i64),
    (1, 0x10, gadget_sub_scalar_i64),
    (1, 0x11, gadget_cmeq_scalar_i64),
];

/// The pairwise reductions: two lanes of one register down to one value. The
/// mask drops the precision bit, so each entry covers single and double.
static PAIRWISE: &[(u32, Gadget)] = &[
    (0x7e30_d800, gadget_faddp_scalar),
    (0x7e30_f800, gadget_fmaxp_scalar),
    (0x7eb0_f800, gadget_fminp_scalar),
    (0x7e30_c800, gadget_fmaxnmp_scalar),
    (0x7eb0_c800, gadget_fminnmp_scalar),
];

/// The scalar two-register misc forms that exist at every element width, by
/// `(U, opcode)`. `SUQADD` and `USQADD` accumulate into the destination, which
/// is why their gadget reads it.
static UNARY_SIZED: &[(u32, u32, Gadget)] = &[
    (0, 0x03, gadget_suqadd_scalar1),
    (1, 0x03, gadget_usqadd_scalar1),
    (0, 0x07, gadget_sqabs_scalar1),
    (1, 0x07, gadget_sqneg_scalar1),
];

/// The saturating narrows, whose source element is twice the destination's — so
/// `size` names the destination and 64-bit is not a width it can have.
static UNARY_NARROW: &[(u32, u32, Gadget)] = &[
    (1, 0x12, gadget_sqxtun_scalar1),
    (0, 0x14, gadget_sqxtn_scalar1),
    (1, 0x14, gadget_uqxtn_scalar1),
];

/// The floating-point unary forms, by `(U, a, opcode)` where `a` is bit 23 —
/// the same shape as the three-same table above and for the same reason.
static FP_UNARY: &[(u32, u32, u32, Gadget)] = &[
    (0, 0, 0x1a, gadget_fcvtns_scalar1),
    (1, 0, 0x1a, gadget_fcvtnu_scalar1),
    (0, 1, 0x1a, gadget_fcvtps_scalar1),
    (1, 1, 0x1a, gadget_fcvtpu_scalar1),
    (0, 0, 0x1b, gadget_fcvtms_scalar1),
    (1, 0, 0x1b, gadget_fcvtmu_scalar1),
    (0, 0, 0x1c, gadget_fcvtas_scalar1),
    (1, 0, 0x1c, gadget_fcvtau_scalar1),
    (0, 1, 0x1d, gadget_frecpe_scalar1),
    (1, 1, 0x1d, gadget_frsqrte_scalar1),
    (0, 1, 0x1f, gadget_frecpx_scalar1),
];

/// Compare one 64-bit element against zero, and the two unary operations
/// beside them, by `(U, opcode)`.
static AGAINST_ZERO: &[(u32, u32, Gadget)] = &[
    (0, 0x08, gadget_cmgt_scalar_zero),
    (1, 0x08, gadget_cmge_scalar_zero),
    (0, 0x09, gadget_cmeq_scalar_zero),
    (1, 0x09, gadget_cmle_scalar_zero),
    (0, 0x0a, gadget_cmlt_scalar_zero),
    (0, 0x0b, gadget_abs_scalar),
    (1, 0x0b, gadget_neg_scalar),
];

/// The floating-point compares against zero, likewise.
static FP_AGAINST_ZERO: &[(u32, u32, Gadget)] = &[
    (0, 0x0c, gadget_fcmgt_scalar_zero),
    (1, 0x0c, gadget_fcmge_scalar_zero),
    (0, 0x0d, gadget_fcmeq_scalar_zero),
    (1, 0x0d, gadget_fcmle_scalar_zero),
    (0, 0x0e, gadget_fcmlt_scalar_zero),
];

/// The saturating left shifts, which exist at every width — so they are not in
/// [`SHIFTS`], whose entries are all doubleword-only.
static SHIFTS_SIZED: &[(u32, u32, Gadget, Amount)] = &[
    (1, 0x0c, gadget_sqshlu_imm_scalar, Amount::Left),
    (0, 0x0e, gadget_sqshl_imm_scalar, Amount::Left),
    (1, 0x0e, gadget_uqshl_imm_scalar, Amount::Left),
];

/// The saturating narrowing right shifts, whose destination is half the source
/// and which therefore have three widths rather than four.
static SHIFTS_NARROW: &[(u32, u32, Gadget)] = &[
    (1, 0x10, gadget_sqshrun_imm_scalar),
    (1, 0x11, gadget_sqrshrun_imm_scalar),
    (0, 0x12, gadget_sqshrn_imm_scalar),
    (1, 0x12, gadget_uqshrn_imm_scalar),
    (0, 0x13, gadget_sqrshrn_imm_scalar),
    (1, 0x13, gadget_uqrshrn_imm_scalar),
];

/// The shifts by an immediate, by `(U, opcode)`, with the rule for reading the
/// amount — the same three rules as the vector shifts in [`super::shift`].
/// **`immh` must name a doubleword** for everything but the two conversions:
/// a scalar shift operates on one 64-bit element and the narrower encodings do
/// not exist. This was unchecked until 2026-09-03, so `sshr b0, b0, #1` — which
/// is not an instruction — was accepted and shifted the register as bytes.
/// Found by `tests/guest/src/bin/decode_probe.rs` as an encoding this ran and a
/// real kernel refused.
static SHIFTS: &[(u32, u32, Gadget, Amount)] = &[
    (0, 0x0a, gadget_shl_imm_scalar, Amount::Left),
    // The rounding right shifts and the two that accumulate, all 64-bit only.
    (0, 0x04, gadget_srshr_imm_scalar, Amount::Right),
    (1, 0x04, gadget_urshr_imm_scalar, Amount::Right),
    (0, 0x06, gadget_srsra_imm_scalar, Amount::Right),
    (1, 0x06, gadget_ursra_imm_scalar, Amount::Right),
    // Shift and *insert*, which have no register form and are done with
    // general-purpose registers.
    (1, 0x08, gadget_sri_imm_scalar, Amount::Right),
    (1, 0x0a, gadget_sli_imm_scalar, Amount::Left),
    (0, 0x00, gadget_sshr_imm_scalar, Amount::Right),
    (1, 0x00, gadget_ushr_imm_scalar, Amount::Right),
    (0, 0x02, gadget_ssra_imm_scalar, Amount::Right),
    (1, 0x02, gadget_usra_imm_scalar, Amount::Right),
    // The fixed-point conversions, whose "shift" is how many fraction bits the
    // integer has. It is read exactly like a right shift, which is what makes
    // them belong in this table rather than beside the other conversions.
    (0, 0x1c, gadget_scvtf_fixpt_scalar, Amount::FixedPoint),
    (1, 0x1c, gadget_ucvtf_fixpt_scalar, Amount::FixedPoint),
    (0, 0x1f, gadget_fcvtzs_fixpt_scalar, Amount::FixedPoint),
    (1, 0x1f, gadget_fcvtzu_fixpt_scalar, Amount::FixedPoint),
];

pub fn decode(g: &mut Gen, insn: u32) -> Option<c_int> {
    let rd = (insn & 0x1f) as u64;
    let rn = ((insn >> 5) & 0x1f) as u64;
    let rm = ((insn >> 16) & 0x1f) as u64;
    let u = (insn >> 29) & 1;

    // Three registers of *different* widths: the scalar saturating doubling
    // multiply-long, `SQDMULL Dd, Sn, Sm` and `SQDMULL Sd, Hn, Hm` and the two
    // that accumulate. Only these three exist in the scalar class. They had no
    // decoding, so an allocated, advertised instruction raised SIGILL while the
    // by-element and vector forms worked. The by-element gadget is the same
    // operation with the second operand taken from lane 0 of `Vm`.
    if insn & 0xdf20_0c00 == 0x5e20_0000 {
        let size = (insn >> 22) & 3;
        let gadget = match (u, (insn >> 12) & 0xf) {
            (0, 0x9) => gadget_sqdmlal_scelem,
            (0, 0xb) => gadget_sqdmlsl_scelem,
            (0, 0xd) => gadget_sqdmull_scelem,
            _ => return Some(g.undefined()),
        };
        // `size` is the *source* width: halfwords into words or words into
        // doublewords.
        if size != 1 && size != 2 {
            return Some(g.undefined());
        }
        g.gadget(gadget);
        g.emit(rd | (rn << 8) | (rm << 16) | ((size as u64) << 24));
        return Some(DECODED);
    }

    // Three registers, same width.
    if insn & 0xdf20_0400 == 0x5e20_0400 {
        let sz = (insn >> 22) & 3;
        let opcode = (insn >> 11) & 0x1f;

        // The ones with an arrangement at every width. The gadget is told the
        // size and picks it; an arrangement the architecture does not have
        // would not assemble, which is what makes a missing width a build
        // failure rather than a wrong answer.
        if let Some(&(_, _, gadget)) = SIZED.iter().find(|(tu, top, _)| *tu == u && *top == opcode)
        {
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | (rm << 16) | ((sz as u64) << 24));
            return Some(DECODED);
        }
        if let Some(&(_, _, gadget)) = HALF_WORD
            .iter()
            .find(|(tu, top, _)| *tu == u && *top == opcode)
        {
            if sz != 1 && sz != 2 {
                return Some(g.undefined());
            }
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | (rm << 16) | ((sz as u64) << 24));
            return Some(DECODED);
        }
        // The floating-point forms, where bit 23 has already chosen which
        // instruction and only the precision is left for the gadget.
        if opcode >= 0x18 {
            let a = (sz >> 1) & 1;
            if let Some(&(_, _, _, gadget)) = FP_THREE_SAME
                .iter()
                .find(|(tu, ta, top, _)| *tu == u && *ta == a && *top == opcode)
            {
                g.gadget(gadget);
                g.emit(rd | (rn << 8) | (rm << 16) | (((sz & 1) as u64) << 24));
                return Some(DECODED);
            }
        }

        // The integer forms below are 64-bit and nothing else.
        if sz == 3
            && let Some(&(_, _, gadget)) = THREE_SAME
                .iter()
                .find(|(tu, top, _)| *tu == u && *top == opcode)
        {
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | (rm << 16));
            return Some(DECODED);
        }
        // `FABD`: the one floating-point instruction in this group, where bit
        // 23 says so and bit 22 is the precision.
        if u == 1 && sz & 2 != 0 && opcode == 0x1a {
            g.gadget(gadget_fabd_scalar);
            g.emit(rd | (rn << 8) | (rm << 16) | (((sz & 1) as u64) << 24));
            return Some(DECODED);
        }
    }

    // The floating-point pairwise reductions.
    if let Some(&(_, gadget)) = PAIRWISE.iter().find(|(v, _)| *v == insn & 0xffbf_fc00) {
        let sz = ((insn >> 22) & 1) as u64;
        g.gadget(gadget);
        g.emit(rd | (rn << 8) | (sz << 16));
        return Some(DECODED);
    }

    // `ADDP Dd, Vn.2D`, the integer one, which has no precision bit and so is
    // an exact encoding.
    if insn & 0xffff_fc00 == 0x5ef1_b800 {
        g.gadget(gadget_addp_scalar);
        g.emit(rd | (rn << 8));
        return Some(DECODED);
    }

    // The scalar two-register misc group, which the three tables above cover
    // between them. `size` is bits 23:22 and means a width for the first two
    // and a precision-plus-selector for the third.
    if insn & 0xdf3e_0c00 == 0x5e20_0800 {
        let size = (insn >> 22) & 3;
        let opcode = (insn >> 12) & 0x1f;
        if let Some(&(_, _, gadget)) = UNARY_SIZED
            .iter()
            .find(|(tu, top, _)| *tu == u && *top == opcode)
        {
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | ((size as u64) << 16));
            return Some(DECODED);
        }
        if let Some(&(_, _, gadget)) = UNARY_NARROW
            .iter()
            .find(|(tu, top, _)| *tu == u && *top == opcode)
        {
            if size == 3 {
                return Some(g.undefined());
            }
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | ((size as u64) << 16));
            return Some(DECODED);
        }
        // `FCVTXN` narrows a double to a single, so `sz` clear names nothing.
        if u == 1 && opcode == 0x16 {
            if size != 1 {
                return Some(g.undefined());
            }
            g.gadget(gadget_fcvtxn_scalar1);
            g.emit(rd | (rn << 8));
            return Some(DECODED);
        }
        let a = (size >> 1) & 1;
        if let Some(&(_, _, _, gadget)) = FP_UNARY
            .iter()
            .find(|(tu, ta, top, _)| *tu == u && *ta == a && *top == opcode)
        {
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | (((size & 1) as u64) << 16));
            return Some(DECODED);
        }
    }

    // Compare a 64-bit element against zero, and `ABS`/`NEG`.
    if insn & 0xdffe_0c00 == 0x5ee0_0800 {
        let opcode = (insn >> 12) & 0x1f;
        if let Some(&(_, _, gadget)) = AGAINST_ZERO
            .iter()
            .find(|(tu, top, _)| *tu == u && *top == opcode)
        {
            g.gadget(gadget);
            g.emit(rd | (rn << 8));
            return Some(DECODED);
        }
    }

    // The floating-point compares against zero.
    if insn & 0xdfbe_0c00 == 0x5ea0_0800 {
        let opcode = (insn >> 12) & 0x1f;
        let sz = ((insn >> 22) & 1) as u64;
        if let Some(&(_, _, gadget)) = FP_AGAINST_ZERO
            .iter()
            .find(|(tu, top, _)| *tu == u && *top == opcode)
        {
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | (sz << 16));
            return Some(DECODED);
        }
    }

    // Convert between a floating-point value and an integer, both in vector
    // registers. Two encodings, one per direction; `U` is the signedness.
    let sz = ((insn >> 22) & 1) as u64;
    let convert: Option<Gadget> = match insn & 0xdfbf_fc00 {
        0x5ea1_b800 => Some(if u != 0 {
            gadget_fcvtzu_simd_scalar
        } else {
            gadget_fcvtzs_simd_scalar
        }),
        0x5e21_d800 => Some(if u != 0 {
            gadget_ucvtf_simd_scalar
        } else {
            gadget_scvtf_simd_scalar
        }),
        _ => None,
    };
    if let Some(gadget) = convert {
        g.gadget(gadget);
        g.emit(rd | (rn << 8) | (sz << 16));
        return Some(DECODED);
    }

    // Shift one element by an immediate, and the fixed-point conversions that
    // share the encoding.
    if insn & 0xdf80_0400 == 0x5f00_0400 {
        let immh = (insn >> 19) & 0xf;
        let immb = (insn >> 16) & 0x7;
        let opcode = (insn >> 11) & 0x1f;
        // The ones with an arrangement at every width, and the narrowing ones
        // whose destination is half their source. Both before the
        // doubleword-only table below, which is what [`SHIFTS`] holds.
        if let Some(&(_, _, gadget, how)) = SHIFTS_SIZED
            .iter()
            .find(|(tu, top, _, _)| *tu == u && *top == opcode)
        {
            let Some((esize, shift)) = width_and_shift(immh, immb, how) else {
                return Some(g.undefined());
            };
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | ((shift as u64) << 16) | ((esize as u64) << 24));
            return Some(DECODED);
        }
        if let Some(&(_, _, gadget)) = SHIFTS_NARROW
            .iter()
            .find(|(tu, top, _)| *tu == u && *top == opcode)
        {
            let Some((esize, shift)) = width_and_shift(immh, immb, Amount::Narrowing) else {
                return Some(g.undefined());
            };
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | ((shift as u64) << 16) | ((esize as u64) << 24));
            return Some(DECODED);
        }

        let Some(&(_, _, gadget, how)) = SHIFTS
            .iter()
            .find(|(tu, top, _, _)| *tu == u && *top == opcode)
        else {
            return Some(g.undefined());
        };
        // A scalar shift is one 64-bit element and nothing narrower; the two
        // fixed-point conversions have their own rule, which `width_and_shift`
        // applies.
        if how != Amount::FixedPoint && immh & 0x8 == 0 {
            return Some(g.undefined());
        }
        let Some((esize, shift)) = width_and_shift(immh, immb, how) else {
            return Some(g.undefined());
        };
        g.gadget(gadget);
        g.emit(rd | (rn << 8) | ((shift as u64) << 16) | ((esize as u64) << 24));
        return Some(DECODED);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// None of the five tables repeats a key.
    #[test]
    fn no_table_repeats_a_key() {
        let pairs: [Vec<(u32, u32)>; 4] = [
            THREE_SAME.iter().map(|(u, op, _)| (*u, *op)).collect(),
            AGAINST_ZERO.iter().map(|(u, op, _)| (*u, *op)).collect(),
            FP_AGAINST_ZERO.iter().map(|(u, op, _)| (*u, *op)).collect(),
            SHIFTS.iter().map(|(u, op, _, _)| (*u, *op)).collect(),
        ];
        for table in pairs {
            let n = table.len();
            let mut sorted = table;
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), n);
        }
        let mut values: Vec<u32> = PAIRWISE.iter().map(|(v, _)| *v).collect();
        let n = values.len();
        values.sort_unstable();
        values.dedup();
        assert_eq!(values.len(), n);
        for (v, _) in PAIRWISE {
            assert_eq!(v & 0xffbf_fc00, *v, "{v:#010x}");
        }
    }

    /// The fixed-point conversions read `immh:immb` as a right shift, and what
    /// comes out is a count of fraction bits. `#1` is one fraction bit, which
    /// is a right shift of one — the two really are the same arithmetic, which
    /// is why they are in the shift table.
    #[test]
    fn a_fixed_point_scale_is_a_right_shift() {
        // 64-bit, `#1`: immh:immb = 127.
        assert_eq!(width_and_shift(0b1111, 0b111, Amount::Right), Some((3, 1)));
        // 64-bit, `#64`: immh:immb = 64.
        assert_eq!(width_and_shift(0b1000, 0b000, Amount::Right), Some((3, 64)));
    }
}
