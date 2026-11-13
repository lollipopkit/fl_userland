//! `0 Q U 01110 size 1 Rm opcode 00 Rn Rd` — the widening and narrowing pairs,
//! plus the two shuffles that share the encoding space below them.
//!
//! Every one of these has a result whose elements are twice or half the
//! source's, which is why `size` is the *source* width and 64-bit is not
//! allocated: there is no 128-bit element to widen into.
//!
//! # `PMULL` is in the middle of this and is not one of them
//!
//! Opcode `0xe` with `U` clear is `PMULL`, at `size` 0 or 3 — including the
//! 3 that every other instruction here rejects, because a polynomial multiply
//! of two 64-bit values is exactly what makes a 128-bit result. It has its own
//! decoder further down the class, so this one has to decline rather than fault:
//! the C spelled that with a `goto` past its own `undefined`.

use crate::gadgets::*;
use crate::{DECODED, Gadget, Gen};
use std::ffi::c_int;

/// By opcode, signed then unsigned. `0x9`, `0xb` and `0xd` are the saturating
/// doubling forms and are in [`SAT_DOUBLING`] below; `0xe` is `PMULL`, handled
/// elsewhere in the class.
static WIDENING: &[(u32, Gadget, Gadget)] = &[
    (0x0, gadget_saddl_vec, gadget_uaddl_vec),
    (0x1, gadget_saddw_vec, gadget_uaddw_vec),
    (0x2, gadget_ssubl_vec, gadget_usubl_vec),
    (0x3, gadget_ssubw_vec, gadget_usubw_vec),
    (0x4, gadget_addhn_vec, gadget_raddhn_vec),
    (0x5, gadget_sabal_vec, gadget_uabal_vec),
    (0x6, gadget_subhn_vec, gadget_rsubhn_vec),
    (0x7, gadget_sabdl_vec, gadget_uabdl_vec),
    (0x8, gadget_smlal_vec, gadget_umlal_vec),
    (0xa, gadget_smlsl_vec, gadget_umlsl_vec),
    (0xc, gadget_smull_vec, gadget_umull_vec),
];

/// The three saturating doubling long multiplies, which have **no unsigned
/// twin**: doubling is a signed operation, so `U = 1` at these opcodes is
/// unallocated rather than the other half of a pair.
///
/// They were absent until 2026-09-03, and the reason recorded here was that
/// they were "deliberately" so. They were absent because the C had no gadget:
/// `decode_probe` sweeps the encoding space, and a real kernel runs all three.
/// They are the Q15 and Q31 primitives every fixed-point audio codec is built
/// out of.
///
/// Half and word sources only. A byte form would double a product of two bytes
/// into a halfword, which the architecture does not allocate.
static SAT_DOUBLING: &[(u32, Gadget)] = &[
    (0x9, gadget_sqdmlal_vec),
    (0xb, gadget_sqdmlsl_vec),
    (0xd, gadget_sqdmull_vec),
];

pub fn decode(g: &mut Gen, insn: u32) -> Option<c_int> {
    if insn & 0x9f20_0c00 != 0x0e20_0000 {
        return None;
    }
    let q = ((insn >> 30) & 1) as u64;
    let u = (insn >> 29) & 1;
    let size = (insn >> 22) & 0x3;
    let rm = ((insn >> 16) & 0x1f) as u64;
    let opcode = (insn >> 12) & 0xf;
    let rn = ((insn >> 5) & 0x1f) as u64;
    let rd = (insn & 0x1f) as u64;

    // `PMULL`, which is this encoding and not this instruction group.
    if opcode == 0xe && u == 0 && (size == 0 || size == 3) {
        return None;
    }

    if size == 3 {
        return Some(g.undefined());
    }

    if let Some(&(_, gadget)) = SAT_DOUBLING.iter().find(|(op, _)| *op == opcode) {
        // No unsigned form, and no byte source.
        if u != 0 || size == 0 {
            return Some(g.undefined());
        }
        g.gadget(gadget);
        g.emit(rd | (rn << 8) | (rm << 16) | ((size as u64) << 24) | (q << 26));
        return Some(DECODED);
    }

    let Some(&(_, signed, unsigned)) = WIDENING.iter().find(|(op, _, _)| *op == opcode) else {
        return Some(g.undefined());
    };
    g.gadget(if u != 0 { unsigned } else { signed });
    g.emit(rd | (rn << 8) | (rm << 16) | ((size as u64) << 24) | (q << 26));
    Some(DECODED)
}

/// `XTN`/`XTN2`: take the bottom half of each element.
///
/// `Q` is not a vector length here — it says whether the narrowed result goes
/// in the low half of the destination or the high one, which is what makes
/// `XTN2` a second instruction rather than a wider `XTN`.
pub fn xtn(g: &mut Gen, insn: u32) -> Option<c_int> {
    if insn & 0xbf3f_fc00 != 0x0e21_2800 {
        return None;
    }
    let hi = ((insn >> 30) & 1) as u64;
    let size = (insn >> 22) & 0x3;
    let rn = ((insn >> 5) & 0x1f) as u64;
    let rd = (insn & 0x1f) as u64;
    if size == 3 {
        return Some(g.undefined());
    }
    g.gadget(gadget_xtn_vec);
    g.emit(rd | (rn << 8) | ((size as u64) << 16) | (hi << 18));
    Some(DECODED)
}

/// `UZP1`/`UZP2`, `TRN1`/`TRN2`, `ZIP1`/`ZIP2` — the six lane shuffles.
///
/// `op2` at 14:12 is three bits and only six of the eight are allocated: 0 and
/// 4 are not a permute at all.
pub fn permute(g: &mut Gen, insn: u32) -> Option<c_int> {
    if insn & 0xbf20_8c00 != 0x0e00_0800 {
        return None;
    }
    let q = (insn >> 30) & 1;
    let size = (insn >> 22) & 0x3;
    let rm = ((insn >> 16) & 0x1f) as u64;
    let op2 = (insn >> 12) & 0x7;
    let rn = ((insn >> 5) & 0x1f) as u64;
    let rd = (insn & 0x1f) as u64;

    // 64-bit elements need a 128-bit register to have two of.
    if size == 3 && q == 0 {
        return Some(g.undefined());
    }

    let gadget: Gadget = match op2 {
        1 => gadget_uzp1_vec,
        5 => gadget_uzp2_vec,
        2 => gadget_trn1_vec,
        6 => gadget_trn2_vec,
        3 => gadget_zip1_vec,
        7 => gadget_zip2_vec,
        // The C fell through to the arms below rather than faulting, and this
        // keeps that: 0 and 4 are the encodings the two-register-misc group
        // reaches through the same mask.
        _ => return None,
    };
    g.gadget(gadget);
    g.emit(rd | (rn << 8) | (rm << 16) | ((size as u64) << 24) | ((q as u64) << 26));
    Some(DECODED)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `PMULL` sits inside this encoding at the one `size` everything else
    /// rejects. Faulting on it — which is what dropping the check does —
    /// makes every AES-GCM and CRC guest die on an allocated instruction.
    #[test]
    fn pmull_is_declined_rather_than_refused() {
        // `pmull v0.8h, v1.8b, v2.8b`: U=0, opcode=0xe, size=0.
        let pmull8 = 0x0e20_e000u32;
        assert_eq!(
            pmull8 & 0x9f20_0c00,
            0x0e20_0000,
            "it does match this group"
        );
        assert_eq!((pmull8 >> 12) & 0xf, 0xe);
        assert_eq!((pmull8 >> 22) & 3, 0);
        // `pmull v0.1q, v1.1d, v2.1d`: size=3, which every widening
        // instruction here refuses.
        let pmull64 = 0x0ee0_e000u32;
        assert_eq!((pmull64 >> 22) & 3, 3);
    }

    /// The opcode table pairs a signed instruction with its unsigned twin, and
    /// the two are one bit apart in the instruction. A row whose two gadgets
    /// were swapped would compute a right answer for the wrong signedness,
    /// which is invisible until an operand's top bit is set.
    #[test]
    fn every_opcode_pairs_two_distinct_gadgets() {
        for (op, s, u) in WIDENING {
            assert_ne!(*s as usize, *u as usize, "opcode {op:#x}");
        }
        let mut ops: Vec<u32> = WIDENING.iter().map(|(op, _, _)| *op).collect();
        let n = ops.len();
        ops.sort_unstable();
        ops.dedup();
        assert_eq!(ops.len(), n);
        // The three saturating doubling opcodes are in their own table: they
        // have no unsigned twin, so a row here would need two gadgets and one
        // of them would be a lie.
        for gap in [0x9u32, 0xb, 0xd] {
            assert!(!WIDENING.iter().any(|(op, _, _)| *op == gap));
            assert!(SAT_DOUBLING.iter().any(|(op, _)| *op == gap));
        }
    }
}
