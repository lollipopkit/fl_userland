//! Two registers in, one out — or one register reduced to a scalar.
//!
//! `0 Q U 01110 size 1x000 opcode 10 Rn Rd` covers the unary vector operations
//! and, with bit 20 set, the across-lane reductions. The C was thirty separate
//! `if`s over the same mask, each re-extracting the same five fields and each
//! carrying its own spelling of the width rule; there are three tables here and
//! the widths are [`Widths`], shared with the three-same class.
//!
//! # Two arms of the C were unreachable and one of them mattered
//!
//! `CMEQ #0` was decoded twice: once with no width check and once, three
//! hundred lines later, with the correct one. The first won, so
//! `cmeq v0.1d, v1.1d, #0` — an encoding that names a vector with one 64-bit
//! lane, which does not exist — was accepted. `RBIT` was decoded twice the same
//! way, the second time under a mask that had erased `size`, so the unallocated
//! `size` values were decoded as `RBIT` as well. Both are one entry here, with
//! the rule.

use super::Widths;
use crate::gadgets::*;
use crate::{DECODED, Gadget, Gen};
use std::ffi::c_int;

/// Everything whose operand word is `rd | rn<<8 | size<<16 | Q<<24`, by the
/// encoding it masks to under `0xbf3f_fc00` — which keeps `Q`, `U`, `size` and
/// the opcode, and drops only the two register numbers.
static UNARY: &[(u32, Gadget, Widths)] = &[
    // Pairwise add long, and the two that accumulate into the destination.
    (0x0e20_2800, gadget_saddlp_vec, Widths::NoD),
    (0x2e20_2800, gadget_uaddlp_vec, Widths::NoD),
    (0x0e20_6800, gadget_sadalp_vec, Widths::NoD),
    (0x2e20_6800, gadget_uadalp_vec, Widths::NoD),
    // Saturating narrow. `XTN` is the non-saturating one and is decoded with
    // the three-different group, because that is where its siblings are.
    (0x2e21_2800, gadget_sqxtun_vec, Widths::NoD),
    (0x0e21_4800, gadget_sqxtn_vec, Widths::NoD),
    (0x2e21_4800, gadget_uqxtn_vec, Widths::NoD),
    // Compare against zero.
    (0x0e20_8800, gadget_cmgt_zero_vec, Widths::NoScalarD),
    (0x2e20_8800, gadget_cmge_zero_vec, Widths::NoScalarD),
    (0x0e20_9800, gadget_cmeq_zero_vec, Widths::NoScalarD),
    (0x2e20_9800, gadget_cmle_zero_vec, Widths::NoScalarD),
    (0x0e20_a800, gadget_cmlt_zero_vec, Widths::NoScalarD),
    // Absolute value and negation, plain and saturating.
    (0x0e20_b800, gadget_abs_vec, Widths::NoScalarD),
    (0x2e20_b800, gadget_neg_vec, Widths::NoScalarD),
    (0x0e20_7800, gadget_sqabs_vec, Widths::NoScalarD),
    (0x2e20_7800, gadget_sqneg_vec, Widths::NoScalarD),
    // The two that add a signed vector to an unsigned one, saturating, in
    // place. None of these four was decoded until 2026-09-02.
    (0x0e20_3800, gadget_suqadd_vec, Widths::NoScalarD),
    (0x2e20_3800, gadget_usqadd_vec, Widths::NoScalarD),
    // Count leading sign bits and leading zeroes.
    (0x0e20_4800, gadget_cls_vec, Widths::NoD),
    (0x2e20_4800, gadget_clz_vec, Widths::NoD),
    // Byte reversal within each element. `REV64` reverses within 64 bits, so
    // its source elements can be up to 32; `REV32` within 32, so up to 16.
    (0x0e20_0800, gadget_rev64_vec, Widths::NoD),
    (0x2e20_0800, gadget_rev32_vec, Widths::ByteOrHalf),
    // Across lanes: one vector in, one scalar out.
    (0x0e31_b800, gadget_addv_vec, Widths::Reduction),
    (0x0e30_3800, gadget_saddlv_vec, Widths::Reduction),
    (0x2e30_3800, gadget_uaddlv_vec, Widths::Reduction),
    (0x0e30_a800, gadget_smaxv_vec, Widths::Reduction),
    (0x2e30_a800, gadget_umaxv_vec, Widths::Reduction),
    (0x0e31_a800, gadget_sminv_vec, Widths::Reduction),
    (0x2e31_a800, gadget_uminv_vec, Widths::Reduction),
];

/// The floating-point unary operations, by the encoding they mask to under
/// `0xbfbf_fc00` — which drops `Q` and the *precision* bit as well as the
/// registers, because one gadget serves both precisions and is told which.
///
/// Bit 23 stays: it is the top half of `size` and it selects between unrelated
/// operations, so a table that dropped it would decode `FRINTN` as `FRINTP`.
static FLOAT_UNARY: &[(u32, Gadget)] = &[
    // Integer to floating-point.
    (0x0e21_d800, gadget_scvtf_int_vec),
    (0x2e21_d800, gadget_ucvtf_int_vec),
    // Floating-point to integer, one entry per rounding mode: toward zero,
    // to nearest even, toward -inf, toward +inf, and ties away from zero.
    (0x0ea1_b800, gadget_fcvtzs_int_vec),
    (0x2ea1_b800, gadget_fcvtzu_int_vec),
    (0x0e21_a800, gadget_fcvtns_int_vec),
    (0x2e21_a800, gadget_fcvtnu_int_vec),
    (0x0e21_b800, gadget_fcvtms_int_vec),
    (0x2e21_b800, gadget_fcvtmu_int_vec),
    (0x0ea1_a800, gadget_fcvtps_int_vec),
    (0x2ea1_a800, gadget_fcvtpu_int_vec),
    (0x0e21_c800, gadget_fcvtas_int_vec),
    (0x2e21_c800, gadget_fcvtau_int_vec),
    // Round to an integral floating-point value, seven rounding modes.
    (0x0e21_8800, gadget_frintn_vec_vec),
    (0x2e21_8800, gadget_frinta_vec_vec),
    (0x0ea1_8800, gadget_frintp_vec_vec),
    (0x0e21_9800, gadget_frintm_vec_vec),
    (0x2e21_9800, gadget_frintx_vec_vec),
    (0x0ea1_9800, gadget_frintz_vec_vec),
    (0x2ea1_9800, gadget_frinti_vec_vec),
    // The unary arithmetic.
    (0x0ea0_f800, gadget_fabs_vec_vec),
    (0x2ea0_f800, gadget_fneg_vec_vec),
    (0x2ea1_f800, gadget_fsqrt_vec_vec),
    (0x0ea1_d800, gadget_frecpe_vec_vec),
    (0x2ea1_d800, gadget_frsqrte_vec_vec),
    // Compare against zero.
    (0x0ea0_d800, gadget_fcmeq_zero_vec),
    (0x2ea0_c800, gadget_fcmge_zero_vec),
    (0x0ea0_c800, gadget_fcmgt_zero_vec),
    (0x2ea0_d800, gadget_fcmle_zero_vec),
    (0x0ea0_e800, gadget_fcmlt_zero_vec),
];

pub fn decode(g: &mut Gen, insn: u32) -> Option<c_int> {
    let q = ((insn >> 30) & 1) as u64;
    let size = (insn >> 22) & 0x3;
    let sz = (insn >> 22) & 1;
    let rn = ((insn >> 5) & 0x1f) as u64;
    let rd = (insn & 0x1f) as u64;
    let sized = |g: &mut Gen, gadget: Gadget, width: u64| -> c_int {
        g.gadget(gadget);
        g.emit(rd | (rn << 8) | (width << 16) | (q << 24));
        DECODED
    };

    if let Some(&(_, gadget, widths)) = UNARY.iter().find(|(v, _, _)| *v == insn & 0xbf3f_fc00) {
        if !widths.allows(size, q as u32) {
            return Some(g.undefined());
        }
        return Some(sized(g, gadget, size as u64));
    }

    // Narrow and widen between two floating-point precisions.
    //
    // Before the general table because that one refuses double precision with
    // `Q` clear, and these are the operations for which that is the *normal*
    // form: `FCVTN Vd.2s, Vn.2d` narrows two doubles into the low half.
    if let mask @ (0x0e21_6800 | 0x0e21_7800 | 0x2e21_6800) = insn & 0xbfbf_fc00 {
        let gadget = match mask {
            0x0e21_6800 => gadget_fcvtn_vec,
            0x0e21_7800 => gadget_fcvtl_vec,
            // `FCVTXN` rounds a double to a single with the odd-rounding rule
            // that makes a later narrowing exact. There is nothing narrower
            // than a single to round to, so `sz` clear is unallocated.
            _ if sz == 0 => return Some(g.undefined()),
            _ => gadget_fcvtxn_vec,
        };
        return Some(sized(g, gadget, sz as u64));
    }

    if let Some(&(_, gadget)) = FLOAT_UNARY.iter().find(|(v, _)| *v == insn & 0xbfbf_fc00) {
        // Double precision means two lanes, which needs the whole register.
        if sz == 1 && q == 0 {
            return Some(g.undefined());
        }
        return Some(sized(g, gadget, sz as u64));
    }

    // SHLL/SHLL2: shift each element left by its own width, into an element
    // twice as wide. The amount is not encoded — it *is* the width — which is
    // what separates this from `USHLL #n` and is why the gadget is chosen per
    // width rather than told one.
    if insn & 0xbf3f_fc00 == 0x2e21_3800 {
        let gadget = match (size, q) {
            (3, _) => return Some(g.undefined()),
            (2, 0) => gadget_shll_vec_s_to_d,
            (2, _) => gadget_shll2_vec_s_to_d,
            (1, 0) => gadget_shll_vec_h_to_s,
            (1, _) => gadget_shll2_vec_h_to_s,
            (_, 0) => gadget_shll_vec_b_to_h,
            (_, _) => gadget_shll2_vec_b_to_h,
        };
        g.gadget(gadget);
        g.emit(rd | (rn << 8));
        return Some(DECODED);
    }

    // `URECPE` and `URSQRTE`: unsigned integer reciprocal and
    // reciprocal-square-root estimates. Undecoded until 2026-09-03, and found by
    // sweeping the encoding space rather than by anybody naming them --
    // `tests/guest/src/bin/decode_probe.rs`. Baseline ASIMD, so a guest reaches
    // one without asking `AT_HWCAP` anything.
    //
    // **Not in `UNARY`**, whose mask drops `size`: these are `size = 10` and
    // `FCVTAS` is the same opcode at `size = 00`, so an entry there would have
    // captured every `FCVTAS` in the tree. They have no width operand either --
    // 32-bit elements are the only form there is.
    let word_estimate: Option<Gadget> = match insn & 0xbfff_fc00 {
        0x0ea1_c800 => Some(gadget_urecpe_vec),
        0x2ea1_c800 => Some(gadget_ursqrte_vec),
        _ => None,
    };
    if let Some(gadget) = word_estimate {
        g.gadget(gadget);
        g.emit(rd | (rn << 8) | (q << 24));
        return Some(DECODED);
    }

    // `REV16` reverses byte pairs, so its elements are bytes and nothing else:
    // `size` is part of the encoding rather than an operand.
    if insn & 0xbfff_fc00 == 0x0e20_1800 {
        g.gadget(gadget_rev16_vec);
        g.emit(rd | (rn << 8) | (q << 24));
        return Some(DECODED);
    }

    // `NOT`, `RBIT` and `CNT` all work a byte at a time, so their operand word
    // has no width in it. `size` tells the three apart — it was masked away
    // until 2026-09-02, and every vector `rbit` in every revision ran as `not`
    // while `RBIT`'s own arm could never be reached.
    let bytewise: Option<Gadget> = match insn & 0xbfff_fc00 {
        0x2e20_5800 => Some(gadget_not_vec),
        0x2e60_5800 => Some(gadget_rbit_vec),
        0x0e20_5800 => Some(gadget_cnt_vec),
        _ => None,
    };
    if let Some(gadget) = bytewise {
        g.gadget(gadget);
        g.emit(rd | (rn << 8) | (q << 16));
        return Some(DECODED);
    }

    // The floating-point reductions, which exist for `.4s` alone — so `Q` and
    // the precision are both fixed and the encoding is an exact value.
    let across: Option<Gadget> = match insn & 0xffff_fc00 {
        0x6e30_f800 => Some(gadget_fmaxv_vec),
        0x6eb0_f800 => Some(gadget_fminv_vec),
        0x6e30_c800 => Some(gadget_fmaxnmv_vec),
        0x6eb0_c800 => Some(gadget_fminnmv_vec),
        _ => None,
    };
    if let Some(gadget) = across {
        g.gadget(gadget);
        g.emit(rd | (rn << 8));
        return Some(DECODED);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every table entry has to be a value its own mask can produce. A typo in
    /// one of the register fields is invisible otherwise: the entry simply
    /// never matches, and the instruction becomes an illegal one.
    #[test]
    fn every_entry_survives_its_own_mask() {
        for (v, _, _) in UNARY {
            assert_eq!(v & 0xbf3f_fc00, *v, "{v:#010x}");
        }
        for (v, _) in FLOAT_UNARY {
            assert_eq!(v & 0xbfbf_fc00, *v, "{v:#010x}");
        }
    }

    /// And no two entries collide, in either table.
    #[test]
    fn no_two_entries_share_an_encoding() {
        let mut ints: Vec<u32> = UNARY.iter().map(|(v, _, _)| *v).collect();
        let n = ints.len();
        ints.sort_unstable();
        ints.dedup();
        assert_eq!(ints.len(), n);

        let mut floats: Vec<u32> = FLOAT_UNARY.iter().map(|(v, _)| *v).collect();
        let n = floats.len();
        floats.sort_unstable();
        floats.dedup();
        assert_eq!(floats.len(), n);
    }

    /// The two tables are read under different masks, and the second is looser
    /// — it drops the precision bit. An entry of the first that collides with
    /// one of the second *after* that bit goes would be decoded twice, and
    /// which answer wins would depend on the order the two searches run in.
    #[test]
    fn the_two_tables_do_not_overlap_under_the_looser_mask() {
        for (int_v, _, _) in UNARY {
            for (float_v, _) in FLOAT_UNARY {
                assert_ne!(int_v & 0xbfbf_fc00, *float_v, "{int_v:#010x}");
            }
        }
    }

    /// `NOT` and `RBIT` differ in `size` and nothing else. This is the check
    /// that the mask keeps it — the defect it records is one hex digit.
    #[test]
    fn not_and_rbit_differ_only_in_size() {
        let not = 0x2e20_5800u32;
        let rbit = 0x2e60_5800u32;
        assert_eq!(not ^ rbit, 1 << 22, "one bit of `size` apart");
        // Under the mask the C used, which cleared bits 23:22, they are the
        // same instruction.
        assert_eq!(not & 0xbf3f_fc00, rbit & 0xbf3f_fc00);
        // Under this one they are not.
        assert_ne!(not & 0xbfff_fc00, rbit & 0xbfff_fc00);
    }

    /// `REV64` and `REV32` have different width rules and they are the reason
    /// `Widths::ByteOrHalf` exists: reversing bytes inside a 32-bit element
    /// needs the elements to be smaller than that.
    #[test]
    fn the_two_reversals_bound_their_sources_differently() {
        assert!(Widths::NoD.allows(2, 0), "rev64 v0.2s");
        assert!(
            !Widths::ByteOrHalf.allows(2, 0),
            "there is no rev32 of words"
        );
        assert!(Widths::ByteOrHalf.allows(1, 0), "rev32 v0.4h");
        assert!(Widths::ByteOrHalf.allows(0, 0), "rev32 v0.8b");
    }
}
