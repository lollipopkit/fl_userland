//! Multiply by one lane of a second vector, broadcast.
//!
//! The interesting part is not the operations but **where the lane index is**.
//! Three bits called `H`, `L` and `M` are scattered across the instruction, and
//! how many of them are the index depends on the element width — because the
//! ones that are not are the top bit of `Rm`.
//!
//! | width | index | second operand |
//! | --- | --- | --- |
//! | 16-bit | `H:L:M` | `Rm`, four bits: only `v0`–`v15` |
//! | 32-bit | `H:L` | `M:Rm` |
//! | 64-bit | `H` | `M:Rm` |
//!
//! Reading `M` as part of the register at 16-bit width names a register the
//! instruction cannot reach, and reading it as part of the index at 32-bit
//! width indexes a lane that does not exist. Both are silent.

use crate::gadgets::*;
use crate::{DECODED, Gadget, Gen};
use std::ffi::c_int;

/// Which widths an indexed operation has.
#[derive(Clone, Copy, PartialEq)]
enum For {
    /// 16- and 32-bit sources, widening to 32 and 64.
    Widening,
    /// 16- and 32-bit, same width out.
    HalfWord,
    /// Single and double precision.
    Float,
}

impl For {
    fn allows(self, size: u32) -> bool {
        match self {
            For::Widening | For::HalfWord => size == 1 || size == 2,
            For::Float => size >= 2,
        }
    }
}

/// The vector forms, by `(U, opcode)`.
static VECTOR: &[(u32, u32, Gadget, For)] = &[
    (0, 0x8, gadget_mul_elem_vec, For::HalfWord),
    (1, 0x0, gadget_mla_elem_vec, For::HalfWord),
    (1, 0x4, gadget_mls_elem_vec, For::HalfWord),
    (0, 0xa, gadget_smull_elem_vec, For::Widening),
    (1, 0xa, gadget_umull_elem_vec, For::Widening),
    (0, 0x2, gadget_smlal_elem_vec, For::Widening),
    (1, 0x2, gadget_umlal_elem_vec, For::Widening),
    (0, 0x6, gadget_smlsl_elem_vec, For::Widening),
    (1, 0x6, gadget_umlsl_elem_vec, For::Widening),
    (0, 0x9, gadget_fmul_elem_vec, For::Float),
    // `FMULX` is `FMUL` with the rule that infinity times zero is two rather
    // than a NaN, which is what a reciprocal step needs. The *scalar* form was
    // decoded and the vector one was not -- found by sweeping the encoding
    // space rather than by anybody noticing the asymmetry.
    (1, 0x9, gadget_fmulx_elem_vec, For::Float),
    (0, 0x1, gadget_fmla_elem_vec, For::Float),
    (0, 0x5, gadget_fmls_elem_vec, For::Float),
    (0, 0xc, gadget_sqdmulh_elem_vec, For::HalfWord),
    (0, 0xd, gadget_sqrdmulh_elem_vec, For::HalfWord),
    (0, 0xb, gadget_sqdmull_elem_vec, For::Widening),
    (0, 0x3, gadget_sqdmlal_elem_vec, For::Widening),
    (0, 0x7, gadget_sqdmlsl_elem_vec, For::Widening),
];

/// The scalar floating-point forms, whose sources are single or double
/// precision and nothing else.
static SCALAR: &[(u32, u32, Gadget)] = &[
    (0, 0x9, gadget_fmul_elem_scalar),
    (0, 0x1, gadget_fmla_elem_scalar),
    (0, 0x5, gadget_fmls_elem_scalar),
    (1, 0x9, gadget_fmulx_elem_scalar),
];

/// The scalar *integer* forms: the saturating doubling multiplies, whose
/// sources are halfwords or words. Undecoded until 2026-09-03.
///
/// `long` says the destination is twice the source, which is what separates
/// `SQDMULL` from `SQDMULH` — the first widens and the second keeps the high
/// half.
static SCALAR_INT: &[(u32, u32, Gadget)] = &[
    (0, 0xc, gadget_sqdmulh_scelem),
    (0, 0xd, gadget_sqrdmulh_scelem),
    (0, 0xb, gadget_sqdmull_scelem),
    (0, 0x3, gadget_sqdmlal_scelem),
    (0, 0x7, gadget_sqdmlsl_scelem),
];

/// Pull the second operand and the lane index apart, per width.
///
/// `None` for a width this encoding does not name.
fn operand_and_index(insn: u32, size: u32) -> Option<(u32, u32)> {
    let l = (insn >> 21) & 1;
    let m = (insn >> 20) & 1;
    let rm4 = (insn >> 16) & 0xf;
    let h = (insn >> 11) & 1;
    match size {
        1 => Some((rm4, (h << 2) | (l << 1) | m)),
        2 => Some(((m << 4) | rm4, (h << 1) | l)),
        // `sz:L == 11` is unallocated: a double has one bit of index (`H`), so
        // `L` is not free. It was ignored, and the encoding ran.
        3 if l == 0 => Some(((m << 4) | rm4, h)),
        _ => None,
    }
}

/// `01 op 11111 size L M Rm opcode H 0 Rn Rd` — the scalar forms, whose
/// sources are single or double precision and nothing else.
pub fn scalar(g: &mut Gen, insn: u32) -> Option<c_int> {
    // `U` is bit 29 and must be **free**: the mask was `0xff00_0400`, which
    // checks it, so every `U = 1` entry in [`SCALAR`] was unreachable and
    // `FMULX` by element answered `SIGILL` for the scalar form while the table
    // had a gadget for it. `simd_probe` found it the moment a case named one.
    if insn & 0xdf00_0400 != 0x5f00_0000 {
        return None;
    }
    let u = (insn >> 29) & 1;
    let size = (insn >> 22) & 3;
    let opcode = (insn >> 12) & 0xf;
    let rn = ((insn >> 5) & 0x1f) as u64;
    let rd = (insn & 0x1f) as u64;

    // The integer forms first: their sources are halfwords and words, so the
    // width rule is the other one and `size >= 2` below would refuse the
    // halfword form outright.
    if let Some(&(_, _, gadget)) = SCALAR_INT
        .iter()
        .find(|(tu, top, _)| *tu == u && *top == opcode)
    {
        let Some((rm, index)) = operand_and_index(insn, size).filter(|_| size == 1 || size == 2)
        else {
            return Some(g.undefined());
        };
        g.gadget(gadget);
        g.emit(
            rd | (rn << 8) | ((rm as u64) << 16) | ((index as u64) << 21) | ((size as u64) << 24),
        );
        return Some(DECODED);
    }

    // 16-bit is FP16, which this does not implement, and 0 is unallocated.
    let Some((rm, index)) = operand_and_index(insn, size).filter(|_| size >= 2) else {
        return Some(g.undefined());
    };

    let found = SCALAR
        .iter()
        .find(|(tu, top, _)| *tu == u && *top == opcode);
    let &(_, _, gadget) = found?;
    g.gadget(gadget);
    g.emit(rd | (rn << 8) | ((rm as u64) << 16) | ((index as u64) << 21) | ((size as u64) << 24));
    Some(DECODED)
}

/// `0 Q U 01111 size L M Rm opcode H 0 Rn Rd` — the vector forms.
pub fn vector(g: &mut Gen, insn: u32) -> Option<c_int> {
    if insn & 0x9f00_0400 != 0x0f00_0000 {
        return None;
    }
    let q = ((insn >> 30) & 1) as u64;
    let u = (insn >> 29) & 1;
    let size = (insn >> 22) & 3;
    let opcode = (insn >> 12) & 0xf;
    let rn = ((insn >> 5) & 0x1f) as u64;
    let rd = (insn & 0x1f) as u64;

    let Some((rm, index)) = operand_and_index(insn, size) else {
        return Some(g.undefined());
    };

    let found = VECTOR
        .iter()
        .find(|(tu, top, _, _)| *tu == u && *top == opcode);
    // An opcode with no entry falls through to the arms below rather than
    // faulting: this encoding space is shared, and the C said so.
    let &(_, _, gadget, widths) = found?;
    if !widths.allows(size) {
        return Some(g.undefined());
    }
    // A double-precision element in a 64-bit vector (`FMUL Vd.1D, ...`) does
    // not exist: `sz:Q == 10` is unallocated.
    if widths == For::Float && size == 3 && q == 0 {
        return Some(g.undefined());
    }
    g.gadget(gadget);
    g.emit(
        rd | (rn << 8)
            | ((rm as u64) << 16)
            | ((index as u64) << 21)
            | ((size as u64) << 24)
            | (q << 26),
    );
    Some(DECODED)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three bits of index, at each width. This is the table from the
    /// module comment, as an assertion.
    #[test]
    fn the_index_and_the_register_share_three_bits() {
        // H=1, L=1, M=1, Rm4=0b0101.
        let insn = (1u32 << 21) | (1 << 20) | (0b0101 << 16) | (1 << 11);
        // 16-bit: every one of the three is index, and the register is four
        // bits — `v5`, not `v21`.
        assert_eq!(operand_and_index(insn, 1), Some((0b00101, 0b111)));
        // 32-bit: `M` joins the register.
        assert_eq!(operand_and_index(insn, 2), Some((0b10101, 0b11)));
        // 64-bit: only `H` is left, and `L` must be clear (`sz:L == 11` is
        // unallocated).
        assert_eq!(operand_and_index(insn, 3), None);
        assert_eq!(
            operand_and_index(insn & !(1 << 21), 3),
            Some((0b10101, 0b1))
        );
        // Byte elements cannot be indexed: there is nowhere to put three bits
        // of index and sixteen lanes.
        assert_eq!(operand_and_index(insn, 0), None);
    }

    /// Reading `M` the wrong way round at 16-bit width is the failure this is
    /// shaped to prevent: it names `v21` where the instruction means `v5`, and
    /// indexes lane 3 where it means lane 7.
    #[test]
    fn misreading_m_changes_both_operands() {
        let insn = (1u32 << 21) | (1 << 20) | (0b0101 << 16) | (1 << 11);
        let (rm16, idx16) = operand_and_index(insn, 1).unwrap();
        let (rm32, idx32) = operand_and_index(insn, 2).unwrap();
        assert_ne!(rm16, rm32);
        assert_ne!(idx16, idx32);
    }

    /// Neither table repeats a `(U, opcode)`.
    #[test]
    fn the_tables_have_no_duplicate_pairs() {
        for pairs in [
            VECTOR
                .iter()
                .map(|(u, op, _, _)| (*u, *op))
                .collect::<Vec<_>>(),
            SCALAR
                .iter()
                .map(|(u, op, _)| (*u, *op))
                .collect::<Vec<_>>(),
            SCALAR_INT
                .iter()
                .map(|(u, op, _)| (*u, *op))
                .collect::<Vec<_>>(),
        ] {
            let n = pairs.len();
            let mut sorted = pairs;
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), n);
        }
    }
}
