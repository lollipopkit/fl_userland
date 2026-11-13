//! `0 Q U 01110 size 1 Rm opcode 1 Rn Rd` — two vectors in, one out, every
//! lane the same width.
//!
//! Sixty-odd instructions in one encoding, chosen by `U` and a five-bit
//! opcode. The C was a chain of sixty `else if`s testing both; the interesting
//! content is not the pairing but **which widths each one has**, and that was
//! spread over the chain as a repeated `if (size == 3) { undefined }` with no
//! two spellings quite alike.
//!
//! # The widths are the rule
//!
//! There are five answers and they are [`Widths`]:
//!
//! - most integer operations have all four, but a 64-bit element needs a
//!   128-bit register to have two of: the encoding with `Q` clear (`.1D`) names
//!   a vector that does not exist, for every operation in this class. `Widths::All`
//!   used to say otherwise for two dozen of them, and each such encoding ran;
//! - the ones that would need a 64-bit multiply or comparison per lane have no
//!   `D` form at all;
//! - the saturating doubling multiplies are `H` and `S` only;
//! - `PMUL` is bytes only.
//!
//! Getting one of these wrong is not a wrong answer but a *missing* one: the
//! guest takes an illegal instruction on an encoding that is allocated.
//!
//! # Above `0x18` it is floating-point, and `size` is not a size
//!
//! For those, bit 22 is the precision and bit 23 selects between two unrelated
//! operations — `FADD` and `FSUB` are one opcode apart in that bit, not in the
//! opcode. The C wrote the pairing out as a comment table; here it is the
//! table.

use super::Widths;
use crate::gadgets::*;
use crate::{DECODED, Gadget, Gen};
use std::ffi::c_int;

/// The integer half, by `(U, opcode)`.
static INTEGER: &[(u32, u32, Gadget, Widths)] = &[
    // The halving adds have no 64-bit form: halving a pair of 64-bit values
    // needs 65 bits, which is what makes them B/H/S only. Both were `All` until
    // `decode_probe` swept the space and found the CPU refusing what this
    // accepted -- the signed and unsigned twins of the *pairwise* max and min
    // below disagreed the same way.
    (0, 0x00, gadget_shadd_vec, Widths::NoD),
    (1, 0x00, gadget_uhadd_vec, Widths::NoD),
    (0, 0x01, gadget_sqadd_vec, Widths::NoScalarD),
    (1, 0x01, gadget_uqadd_vec, Widths::NoScalarD),
    (0, 0x02, gadget_srhadd_vec, Widths::NoD),
    (1, 0x02, gadget_urhadd_vec, Widths::NoD),
    (0, 0x04, gadget_shsub_vec, Widths::NoD),
    (1, 0x04, gadget_uhsub_vec, Widths::NoD),
    (0, 0x05, gadget_sqsub_vec, Widths::NoScalarD),
    (1, 0x05, gadget_uqsub_vec, Widths::NoScalarD),
    (0, 0x06, gadget_cmgt_reg_vec, Widths::NoScalarD),
    (1, 0x06, gadget_cmhi_vec, Widths::NoScalarD),
    (0, 0x07, gadget_cmge_reg_vec, Widths::NoScalarD),
    (1, 0x07, gadget_cmhs_vec, Widths::NoScalarD),
    (0, 0x08, gadget_sshl_vec, Widths::NoScalarD),
    (1, 0x08, gadget_ushl_vec, Widths::NoScalarD),
    (0, 0x09, gadget_sqshl_vec, Widths::NoScalarD),
    (1, 0x09, gadget_uqshl_vec, Widths::NoScalarD),
    (0, 0x0a, gadget_srshl_vec, Widths::NoScalarD),
    (1, 0x0a, gadget_urshl_vec, Widths::NoScalarD),
    (0, 0x0b, gadget_sqrshl_vec, Widths::NoScalarD),
    (1, 0x0b, gadget_uqrshl_vec, Widths::NoScalarD),
    (0, 0x0c, gadget_smax_vec, Widths::NoD),
    (1, 0x0c, gadget_umax_vec, Widths::NoD),
    (0, 0x0d, gadget_smin_vec, Widths::NoD),
    (1, 0x0d, gadget_umin_vec, Widths::NoD),
    (0, 0x0e, gadget_sabd_vec, Widths::NoD),
    (1, 0x0e, gadget_uabd_vec, Widths::NoD),
    (0, 0x0f, gadget_saba_vec, Widths::NoD),
    (1, 0x0f, gadget_uaba_vec, Widths::NoD),
    (0, 0x10, gadget_add_vec, Widths::NoScalarD),
    (1, 0x10, gadget_sub_vec, Widths::NoScalarD),
    (0, 0x11, gadget_cmtst_vec, Widths::NoScalarD),
    (1, 0x11, gadget_cmeq_vec, Widths::NoScalarD),
    (0, 0x12, gadget_mla_vec, Widths::NoD),
    (1, 0x12, gadget_mls_vec, Widths::NoD),
    (0, 0x13, gadget_mul_vec, Widths::NoD),
    (1, 0x13, gadget_pmul_vec, Widths::ByteOnly),
    (0, 0x14, gadget_smaxp_vec, Widths::NoD),
    (1, 0x14, gadget_umaxp_vec, Widths::NoD),
    (0, 0x15, gadget_sminp_vec, Widths::NoD),
    (1, 0x15, gadget_uminp_vec, Widths::NoD),
    (0, 0x16, gadget_sqdmulh_vec, Widths::HalfWord),
    (1, 0x16, gadget_sqrdmulh_vec, Widths::HalfWord),
    (0, 0x17, gadget_addp_vec, Widths::NoScalarD),
];

/// Opcode `0x03` is eight bitwise operations, and `size` picks which — it is
/// not a width at all there, because every one of them works a bit at a time.
static LOGIC: [Gadget; 8] = [
    gadget_and_vec,
    gadget_bic_vec,
    gadget_orr_vec,
    gadget_orn_vec,
    gadget_eor_vec,
    gadget_bsl_vec,
    gadget_bit_vec,
    gadget_bif_vec,
];

/// The floating-point half, by `(U, a, opcode)` where `a` is bit 23.
///
/// The gaps are real: `0x1d` has no `U = 0` form and `0x1f` has no
/// `U = 1, a = 1`, so an encoding that lands in one is unallocated rather than
/// something this does not implement.
static FLOAT: &[(u32, u32, u32, Gadget)] = &[
    (0, 0, 0x18, gadget_fp_fmaxnm_vec),
    (0, 1, 0x18, gadget_fp_fminnm_vec),
    // The pairwise forms, which had no entry until 2026-09-03: `0x18` was
    // written as a `U = 0` opcode only, and `FMAXP`/`FMINP` at `0x1e` were
    // taken for the whole family. They are the NaN-quiet pairwise max and min,
    // which is what a horizontal reduction over data that may contain one
    // wants, and they are baseline ASIMD -- a compiler emits them without
    // asking `AT_HWCAP` anything.
    (1, 0, 0x18, gadget_fp_fmaxnmp_vec),
    (1, 1, 0x18, gadget_fp_fminnmp_vec),
    (0, 0, 0x19, gadget_fp_fmla_vec),
    (0, 1, 0x19, gadget_fp_fmls_vec),
    (0, 0, 0x1a, gadget_fp_fadd_vec),
    (0, 1, 0x1a, gadget_fp_fsub_vec),
    (1, 0, 0x1a, gadget_fp_faddp_vec),
    (1, 1, 0x1a, gadget_fp_fabd_vec),
    (0, 0, 0x1b, gadget_fp_fmulx_vec),
    (1, 0, 0x1b, gadget_fp_fmul_vec),
    (0, 0, 0x1c, gadget_fp_fcmeq_vec),
    (1, 0, 0x1c, gadget_fp_fcmge_vec),
    (1, 1, 0x1c, gadget_fp_fcmgt_vec),
    (1, 0, 0x1d, gadget_fp_facge_vec),
    (1, 1, 0x1d, gadget_fp_facgt_vec),
    (0, 0, 0x1e, gadget_fp_fmax_vec),
    (0, 1, 0x1e, gadget_fp_fmin_vec),
    (1, 0, 0x1e, gadget_fp_fmaxp_vec),
    (1, 1, 0x1e, gadget_fp_fminp_vec),
    (0, 0, 0x1f, gadget_fp_frecps_vec),
    (0, 1, 0x1f, gadget_fp_frsqrts_vec),
    (1, 0, 0x1f, gadget_fp_fdiv_vec),
];

pub fn decode(g: &mut Gen, insn: u32) -> Option<c_int> {
    if insn & 0x9f20_0400 != 0x0e20_0400 {
        return None;
    }
    let q = (insn >> 30) & 1;
    let u = (insn >> 29) & 1;
    let size = (insn >> 22) & 0x3;
    let rm = ((insn >> 16) & 0x1f) as u64;
    let opcode = (insn >> 11) & 0x1f;
    let rn = ((insn >> 5) & 0x1f) as u64;
    let rd = (insn & 0x1f) as u64;

    // The bitwise group, where `size` is a selector.
    if opcode == 0x03 {
        let gadget = LOGIC[(u * 4 + size) as usize];
        g.gadget(gadget);
        g.emit(rd | (rn << 8) | (rm << 16) | ((size as u64) << 24) | ((q as u64) << 26));
        return Some(DECODED);
    }

    if let Some(&(_, _, gadget, widths)) = INTEGER
        .iter()
        .find(|(tu, top, _, _)| *tu == u && *top == opcode)
    {
        if !widths.allows(size, q) {
            return Some(g.undefined());
        }
        g.gadget(gadget);
        g.emit(rd | (rn << 8) | (rm << 16) | ((size as u64) << 24) | ((q as u64) << 26));
        return Some(DECODED);
    }

    if opcode >= 0x18 {
        // `size` is two independent bits here: the low one is the precision
        // the gadget needs, the high one chooses the operation.
        let sz = size & 1;
        let a = (size >> 1) & 1;
        if let Some(&(_, _, _, gadget)) = FLOAT
            .iter()
            .find(|(tu, ta, top, _)| *tu == u && *ta == a && *top == opcode)
        {
            // `sz:Q == 10` is unallocated: a double-precision lane needs the
            // whole 128-bit register (there is no `.1D` vector).
            if sz == 1 && q == 0 {
                return Some(g.undefined());
            }
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | (rm << 16) | ((sz as u64) << 24) | ((q as u64) << 26));
            return Some(DECODED);
        }
    }

    // Every opcode in this encoding is accounted for above, so what is left is
    // unallocated. Falling through to the arms after this one would let an
    // encoding that means nothing be decoded as something else.
    Some(g.undefined())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No `(U, opcode)` appears twice: the table is searched in order, so a
    /// duplicate would be one instruction silently decoded as another.
    #[test]
    fn the_integer_table_has_no_duplicate_pairs() {
        let mut seen: Vec<(u32, u32)> = INTEGER.iter().map(|(u, op, _, _)| (*u, *op)).collect();
        let n = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), n);
        // And opcode 3 is *not* in it: it is the bitwise group, handled before
        // the search, and an entry here would shadow four instructions.
        assert!(!INTEGER.iter().any(|(_, op, _, _)| *op == 0x03));
    }

    /// The floating-point table likewise, on the triple that selects it.
    #[test]
    fn the_float_table_has_no_duplicate_triples() {
        let mut seen: Vec<(u32, u32, u32)> =
            FLOAT.iter().map(|(u, a, op, _)| (*u, *a, *op)).collect();
        let n = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), n);
        // All of them are in the range that reaches the search.
        assert!(FLOAT.iter().all(|(_, _, op, _)| *op >= 0x18));
    }

    /// The five width rules, at the boundary each one is about. `ADD` and
    /// `MUL` differ here and the difference is the point: `add v0.2d` is a real
    /// instruction and `mul v0.2d` is not.
    #[test]
    fn the_width_rules_differ_where_it_matters() {
        // 64-bit elements, two of them.
        assert!(Widths::NoScalarD.allows(3, 1), "add v0.2d");
        assert!(!Widths::NoScalarD.allows(3, 0), "there is no 1d vector");
        assert!(!Widths::NoD.allows(3, 1), "mul has no 64-bit form at all");
        assert!(Widths::NoD.allows(2, 0), "mul v0.2s");
        // The doubling multiplies are the narrow pair.
        assert!(!Widths::HalfWord.allows(0, 1));
        assert!(Widths::HalfWord.allows(1, 1));
        assert!(Widths::HalfWord.allows(2, 1));
        assert!(!Widths::HalfWord.allows(3, 1));
        // PMUL is polynomial arithmetic over GF(2)[x] on bytes.
        assert!(Widths::ByteOnly.allows(0, 1));
        assert!(!Widths::ByteOnly.allows(1, 1));
    }

    /// The eight bitwise operations, in the order `U:size` gives them. `BSL`
    /// and `BIT` are one step apart and do different things with the
    /// destination, so the order is not a detail.
    #[test]
    fn the_logic_group_is_indexed_by_u_and_size() {
        let name_of = |i: usize| LOGIC[i] as usize;
        assert_eq!(
            name_of(0),
            gadget_and_vec as *const () as usize,
            "U=0 size=0"
        );
        assert_eq!(
            name_of(3),
            gadget_orn_vec as *const () as usize,
            "U=0 size=3"
        );
        assert_eq!(
            name_of(4),
            gadget_eor_vec as *const () as usize,
            "U=1 size=0"
        );
        assert_eq!(
            name_of(5),
            gadget_bsl_vec as *const () as usize,
            "U=1 size=1"
        );
        assert_eq!(
            name_of(7),
            gadget_bif_vec as *const () as usize,
            "U=1 size=3"
        );
    }
}
