//! Peepholes: two or three guest instructions compiled into one gadget.
//!
//! Each of these ends the block, because the second instruction is a branch —
//! so a fusion is not just fewer gadgets but one fewer dispatch through the
//! interpreter's loop, which is where the saving is.
//!
//! # The shape they all share
//!
//! A fused branch emits **four** words: the gadget, its operands, the target
//! and the fallthrough. The last two are addresses with bit 63 set, which is
//! how the dispatch loop tells an unchained slot from a code pointer — the
//! block cache overwrites them with real pointers when it chains, and
//! `Gen::set_jump_slots` records where they are so it can find them.
//!
//! Getting the slot indices wrong patches the wrong word, which is a jump into
//! the middle of an operand, so they are recorded by the one helper that
//! emitted them rather than by the caller counting.

use crate::gadgets;
use crate::{BLOCK_ENDS, Gadget, Gen, decode};

/// The `B.cond` encoding, and the condition it carries.
///
/// `None` unless the word really is one: the top byte is fixed and bit 4 must
/// be clear, which is what separates `B.cond` from `BC.cond`.
pub fn bcond(insn: u32) -> Option<u32> {
    if insn & 0xff00_0010 != 0x5400_0000 {
        return None;
    }
    let cond = insn & 0xf;
    // `AL` and `NV` are not worth fusing: the branch is unconditional and the
    // tables are fourteen long, so this is also what keeps the index in range.
    (cond < 14).then_some(cond)
}

/// Emit a fused conditional branch: the gadget, its operands, and the two
/// destinations, then end the block.
///
/// `at` is where the `B.cond` was, because its offset is relative to itself
/// and the caller has already consumed it.
fn branch(g: &mut Gen, gadget: Gadget, operands: &[u64], at: u64, br: u32) -> i32 {
    let target = at.wrapping_add(decode::branch_imm19(br) as u64);
    g.gadget(gadget);
    for &w in operands {
        g.emit(w);
    }
    // Bit 63 marks an address the loop must still resolve; a chained slot
    // holds a code pointer instead.
    g.emit(target | (1 << 63));
    g.emit(g.ip() | (1 << 63));
    g.set_jump_slots();
    BLOCK_ENDS
}

/// `CMP`/`SUBS` with an immediate, followed by `B.cond`.
///
/// `None` if the next instruction is not a `B.cond`, in which case the caller
/// emits the unfused form. `Some(BLOCK_ENDS)` when it fused.
pub(crate) fn subs_imm_bcond(g: &mut Gen, sf: u32, rd: u32, rn: u32, imm12: u32) -> Option<i32> {
    let next = g.peek()?;
    let cond = bcond(next)? as usize;
    let at = g.ip();
    g.consume(1);

    Some(if rd == 31 {
        // `CMP`: flags only, so the destination is not an operand.
        let gadget = if sf != 0 {
            gadgets::FUSED_CMP_BCOND[cond]
        } else {
            gadgets::FUSED_CMP32_BCOND[cond]
        };
        branch(g, gadget, &[rn as u64 | ((imm12 as u64) << 8)], at, next)
    } else {
        let gadget = if sf != 0 {
            gadgets::FUSED_SUBS_BCOND[cond]
        } else {
            gadgets::FUSED_SUBS32_BCOND[cond]
        };
        branch(
            g,
            gadget,
            &[rd as u64 | ((rn as u64) << 8) | ((imm12 as u64) << 16)],
            at,
            next,
        )
    })
}

/// `CMP`/`SUBS` of two registers, followed by `B.cond`.
///
/// The register form of [`subs_imm_bcond`], and 64-bit only: the C had no
/// 32-bit table for it, and the caller only reaches this when `sf` is set.
pub(crate) fn subs_reg_bcond(g: &mut Gen, rd: u32, rn: u32, rm: u32) -> Option<i32> {
    let next = g.peek()?;
    let cond = bcond(next)? as usize;
    let at = g.ip();
    g.consume(1);

    Some(if rd == 31 {
        branch(
            g,
            gadgets::FUSED_CMP_REG_BCOND[cond],
            &[rn as u64 | ((rm as u64) << 8)],
            at,
            next,
        )
    } else {
        branch(
            g,
            gadgets::FUSED_SUBS_REG_BCOND[cond],
            &[rd as u64 | ((rn as u64) << 8) | ((rm as u64) << 16)],
            at,
            next,
        )
    })
}

/// `AND Wd, Wn, #mask` then `CMP Wd, #imm12` then `B.cond`, three guest
/// instructions in one gadget.
///
/// The commonest triple there is: the C measured it at about 4.5% of all
/// dispatches under CPython, which is `if (Py_TYPE(o)->tp_flags & FLAG)`.
///
/// Every condition of the shape has to hold or the caller falls back:
/// 32-bit, a real destination and source, the follow-up must be `CMP Wd, #imm`
/// with no shift comparing *that* register, and the condition must be one the
/// table has — `mi`, `pl`, `vs` and `vc` are not, because they read N and V,
/// which the fused gadget computes from the masked value rather than from the
/// subtraction.
pub(crate) fn and_cmp32_bcond(g: &mut Gen, rd: u32, rn: u32, mask: u64) -> Option<i32> {
    let cmp = g.peek()?;
    // `CMP Wn, #imm12` is `SUBS WZR, Wn, #imm12`: sf=0, op=1, S=1.
    if cmp & 0xff80_0000 != 0x7100_0000 {
        return None;
    }
    let cmp_sh = (cmp >> 22) & 1;
    let cmp_rd = cmp & 0x1f;
    let cmp_rn = (cmp >> 5) & 0x1f;
    let cmp_imm = (cmp >> 10) & 0xfff;
    // It has to compare the register the AND just wrote, and discard its own
    // result — anything else is a different program.
    if cmp_sh != 0 || cmp_rd != 31 || cmp_rn != rd {
        return None;
    }

    let br_at = g.ip() + 4;
    let br = g.peek_at(br_at)?;
    let cond = bcond(br)? as usize;
    let gadget = gadgets::FUSED_AND_CMP32_BCOND[cond]?;

    g.consume(2);
    Some(branch(
        g,
        gadget,
        &[
            rd as u64 | ((rn as u64) << 5) | ((cmp_imm as u64) << 10),
            mask & 0xffff_ffff,
        ],
        br_at,
        br,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `B.cond` test, which is what stops a fusion firing on something
    /// that merely looks like one.
    #[test]
    fn only_a_real_conditional_branch_fuses() {
        // B.eq +0
        assert_eq!(bcond(0x5400_0000), Some(0));
        // B.le
        assert_eq!(bcond(0x5400_000d), Some(13));
        // B.al and B.nv are refused: nothing to gain, and it is what keeps the
        // condition inside a fourteen-entry table.
        assert_eq!(bcond(0x5400_000e), None);
        assert_eq!(bcond(0x5400_000f), None);
        // Bit 4 set is `BC.cond`, a different instruction.
        assert_eq!(bcond(0x5400_0010), None);
        // An unconditional `b`.
        assert_eq!(bcond(0x1400_0000), None);
        // A `cbz`, which is also a branch and is not this one.
        assert_eq!(bcond(0x3400_0000), None);
    }

    /// The `CMP` half of the three-instruction peephole, checked without a
    /// block: the shape is what decides whether it fires.
    #[test]
    fn the_and_cmp_peephole_needs_the_exact_shape() {
        // `cmp w3, #7` is `subs wzr, w3, #7`.
        let cmp = |rn: u32, imm: u32, sh: u32, rd: u32| {
            0x7100_0000 | (sh << 22) | (imm << 10) | (rn << 5) | rd
        };
        let is_cmp_of = |insn: u32, of: u32| {
            insn & 0xff80_0000 == 0x7100_0000
                && (insn >> 22) & 1 == 0
                && insn & 0x1f == 31
                && (insn >> 5) & 0x1f == of
        };
        assert!(is_cmp_of(cmp(3, 7, 0, 31), 3));
        assert!(
            !is_cmp_of(cmp(3, 7, 1, 31), 3),
            "a shifted immediate is not this form"
        );
        assert!(
            !is_cmp_of(cmp(3, 7, 0, 4), 3),
            "a SUBS with a destination is not a CMP"
        );
        assert!(
            !is_cmp_of(cmp(4, 7, 0, 31), 3),
            "it must compare the register AND wrote"
        );
        // The 64-bit CMP is a different opcode and must not match.
        assert!(!is_cmp_of(0xf100_0000 | (7 << 10) | (3 << 5) | 31, 3));
    }

    /// The four conditions the three-way fusion refuses, and why. A table with
    /// them filled in would give a different answer from the unfused path for
    /// any masked value whose top bit is set.
    #[test]
    fn the_three_way_fusion_refuses_the_signed_conditions() {
        for cond in [4usize, 5, 6, 7] {
            assert!(
                gadgets::FUSED_AND_CMP32_BCOND[cond].is_none(),
                "cond {cond}"
            );
        }
        for cond in [0usize, 1, 2, 3, 8, 9, 10, 11, 12, 13] {
            assert!(
                gadgets::FUSED_AND_CMP32_BCOND[cond].is_some(),
                "cond {cond}"
            );
        }
    }
}
