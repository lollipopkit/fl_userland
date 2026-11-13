//! The SIMD shifts by an immediate, which are one encoding and one table.
//!
//! Twenty instructions share a single form — `0 Q U 011110 immh immb opcode 1
//! Rn Rd` — and differ only in `U`, the opcode, and how the shift *amount* is
//! read out of `immh:immb`. In C this was twenty near-identical blocks of
//! twenty lines; here it is a table of twenty entries and three rules.
//!
//! # `immh` is the element width and the amount at once
//!
//! `immh:immb` is seven bits that encode both, and which is which depends on
//! the highest set bit of `immh`: `1xxx` is a 64-bit element, `01xx` a 32-bit
//! one, `001x` a 16-bit one and `0001` an 8-bit one. Then
//!
//! - a **left** shift is `immh:immb - 8·width`, counting up from the bottom of
//!   the element;
//! - a **right** shift is `16·width - immh:immb`, counting down from the top;
//! - a **narrowing** right shift is the same, but the source element is twice
//!   the destination's, so `immh`'s top bit is not a width — a 64-bit source
//!   would narrow to 32 and there is no 128-bit element to shift.
//!
//! # `immh == 0` is not a shift at all
//!
//! It is `MOVI`/`MVNI`, a different instruction in the same encoding space.
//! Every arm here has to check it and fall through, and the C said so in a
//! comment on each of the twenty; here it is one condition in one place.

use crate::gadgets::*;
use crate::{DECODED, Gadget, Gen};
use asbestos_crypto::slow;
use emu_tlb::access::SlowFn;
use std::ffi::c_int;

/// What runs a shift.
#[derive(Clone, Copy)]
enum Run {
    Asm(Gadget),
    /// Rust, through `slow_call`.
    Rust(SlowFn),
    /// The gadget for 8- and 16-bit elements, which it does inline with a
    /// jump table over the amount, and Rust for the wider ones.
    Split(Gadget, SlowFn),
}
use Run::{Asm, Rust, Split};

/// How to read the shift amount out of `immh:immb`.
#[derive(Clone, Copy, PartialEq)]
pub enum Amount {
    /// Counting up from the bottom of the element: `SHL`, `SLI`.
    Left,
    /// Counting down from the top: every right shift and insert.
    Right,
    /// A right shift whose source is twice the destination's width, so the
    /// widest element `immh` can name is 32 bits.
    Narrowing,
    /// The fixed-point conversions, whose immediate is a *scale* read like a
    /// right shift but which exist for 32- and 64-bit elements only: `immh`
    /// of `0001` is unallocated and `001x` is FEAT_FP16, which this kernel
    /// does not advertise. Accepting either ran the 32-bit path over narrower
    /// data.
    FixedPoint,
}

/// The element width, as a log2 of the byte count, and the shift amount.
///
/// `None` for an `immh` this rule cannot read: zero, which is `MOVI`/`MVNI`
/// rather than a shift, and — for a narrowing shift — anything with the top
/// bit set, because the source would be 128 bits wide.
///
/// The C had no second case: it computed `64 - immh:immb` in `uint32_t`, so
/// `shrn v0.2s, v1.2d, #3` with `immh = 1100` produced a shift of about four
/// billion and the gadget was handed it. Nothing rejected the encoding and
/// nothing could have noticed.
pub(crate) fn width_and_shift(immh: u32, immb: u32, how: Amount) -> Option<(u32, u32)> {
    if immh == 0 {
        return None;
    }
    if how == Amount::FixedPoint && immh & 0xc == 0 {
        return None;
    }
    let immhb = (immh << 3) | immb;
    let esize = if how == Amount::Narrowing {
        // The source is one width up, so `immh`'s top bit is not allocated.
        if immh & 0x8 != 0 {
            return None;
        } else if immh & 0x4 != 0 {
            2
        } else if immh & 0x2 != 0 {
            1
        } else {
            0
        }
    } else if immh & 0x8 != 0 {
        3
    } else if immh & 0x4 != 0 {
        2
    } else if immh & 0x2 != 0 {
        1
    } else {
        0
    };
    let bits = 8u32 << esize;
    let shift = match how {
        Amount::Left => immhb - bits,
        _ => 2 * bits - immhb,
    };
    Some((esize, shift))
}

/// Every shift-by-immediate, by the value its encoding masks to.
///
/// The mask is `0xbf80fc00` for all of them: bit 31, `U`, the six fixed bits,
/// the five opcode bits and bit 10.
static SHIFTS: &[(u32, Run, Amount)] = &[
    (0x0f00_5400, Split(gadget_shl_imm_vec, slow::slow_shl), Amount::Left),
    (0x2f00_5400, Rust(slow::slow_sli), Amount::Left),
    (0x2f00_0400, Rust(slow::slow_ushr), Amount::Right),
    (0x0f00_0400, Rust(slow::slow_sshr), Amount::Right),
    (0x2f00_1400, Rust(slow::slow_usra), Amount::Right),
    (0x0f00_1400, Rust(slow::slow_ssra), Amount::Right),
    (0x0f00_2400, Asm(gadget_srshr_imm_vec), Amount::Right),
    (0x2f00_2400, Asm(gadget_urshr_imm_vec), Amount::Right),
    (0x0f00_3400, Asm(gadget_srsra_imm_vec), Amount::Right),
    (0x2f00_3400, Asm(gadget_ursra_imm_vec), Amount::Right),
    (0x2f00_4400, Rust(slow::slow_sri), Amount::Right),
    // The saturating left shifts, undecoded until 2026-09-03 and all three
    // baseline ASIMD. `SQSHLU` is the odd one: it shifts a *signed* value and
    // saturates into the *unsigned* range, which is why it has a `U` of 1 and
    // an opcode of its own rather than being `SQSHL`'s twin.
    (0x0f00_7400, Asm(gadget_sqshl_imm_vec), Amount::Left),
    (0x2f00_7400, Asm(gadget_uqshl_imm_vec), Amount::Left),
    (0x2f00_6400, Asm(gadget_sqshlu_imm_vec), Amount::Left),
    // The fixed-point conversions, whose immediate is a *scale* rather than a
    // shift and which are read exactly like a right shift -- the count of
    // fraction bits and the distance from the top of the element are the same
    // number. Undecoded until 2026-09-03; the scalar forms were not.
    (0x0f00_e400, Asm(gadget_scvtf_fixpt_vec), Amount::FixedPoint),
    (0x2f00_e400, Asm(gadget_ucvtf_fixpt_vec), Amount::FixedPoint),
    (0x0f00_fc00, Asm(gadget_fcvtzs_fixpt_vec), Amount::FixedPoint),
    (0x2f00_fc00, Asm(gadget_fcvtzu_fixpt_vec), Amount::FixedPoint),
    // The narrowing ones, whose source element is twice the destination's.
    (0x0f00_8400, Asm(gadget_shrn_vec), Amount::Narrowing),
    (0x0f00_8c00, Asm(gadget_rshrn_vec), Amount::Narrowing),
    (0x2f00_9c00, Asm(gadget_uqrshrn_vec), Amount::Narrowing),
    (0x0f00_9c00, Asm(gadget_sqrshrn_vec), Amount::Narrowing),
    (0x2f00_9400, Asm(gadget_uqshrn_vec), Amount::Narrowing),
    (0x0f00_9400, Asm(gadget_sqshrn_vec), Amount::Narrowing),
    (0x2f00_8400, Asm(gadget_sqshrun_vec), Amount::Narrowing),
    (0x2f00_8c00, Asm(gadget_sqrshrun_vec), Amount::Narrowing),
];

/// Try the shift table. `None` means this is not one — including the
/// `immh == 0` case, which the caller must let fall through to `MOVI`.
pub fn decode(g: &mut Gen, insn: u32) -> Option<c_int> {
    let masked = insn & 0xbf80_fc00;
    let &(_, run, how) = SHIFTS.iter().find(|(v, _, _)| *v == masked)?;
    let immh = (insn >> 19) & 0xf;
    let immb = (insn >> 16) & 0x7;
    // `immh == 0` is a different instruction in the same encoding, so the
    // caller has to get a chance at it; anything else this rule cannot read is
    // an encoding that means nothing.
    if immh == 0 {
        return None;
    }
    let Some((esize, shift)) = width_and_shift(immh, immb, how) else {
        return Some(g.undefined());
    };

    let q = (insn >> 30) & 1;
    // `immh = 1xxx` with `Q` clear is `.1D`, a vector that does not exist: it
    // is unallocated for every shift in the table, and ran as the 2D form on
    // the low half.
    if esize == 3 && q == 0 {
        return Some(g.undefined());
    }
    let rd = insn & 0x1f;
    let rn = (insn >> 5) & 0x1f;
    let arg = rd as u64 | ((rn as u64) << 8) | ((shift as u64) << 16) | ((esize as u64) << 24) | ((q as u64) << 28);
    match run {
        Asm(gadget) => g.gadget(gadget),
        Split(gadget, _) if esize < 2 => g.gadget(gadget),
        Rust(f) | Split(_, f) => {
            g.slow_call(f, arg);
            return Some(DECODED);
        }
    }
    g.emit(arg);
    Some(DECODED)
}

/// `SSHLL`/`USHLL` and their upper-half forms: shift left into an element
/// twice as wide.
///
/// A separate table because the *gadget* depends on the width, not just the
/// packed operand — there are twelve of them, one per (signed, half, width).
pub fn lengthening(g: &mut Gen, insn: u32) -> Option<c_int> {
    // **Bit 28 is what separates the vector shift group from the scalar one**,
    // and this mask did not check it until 2026-09-03 — so every scalar shift
    // encoding whose opcode is `0x14` was decoded as a vector `SSHLL`. The
    // vector form is `0 Q U 011110` and the scalar `01 U 111110`; bits 31:30
    // cannot tell them apart, because `SSHLL2` has bit 30 set too.
    //
    // One hex digit, and the same shape as the `RBIT` mask that had erased
    // `size`. `tests/guest/src/bin/decode_probe.rs` is what found it: the
    // encoding ran here and a real kernel refused it.
    if insn & 0x9f80_fc00 != 0x0f00_a400 {
        return None;
    }
    let q = (insn >> 30) & 1;
    let u = (insn >> 29) & 1;
    let immh = (insn >> 19) & 0xf;
    let immb = (insn >> 16) & 0x7;
    let immhb = ((immh << 3) | immb) as i64;
    let rd = insn & 0x1f;
    let rn = (insn >> 5) & 0x1f;

    // The source width, from the highest set bit of `immh`. There is no
    // 64-bit source: it would lengthen to 128, which is a whole register, so
    // the top bit is unallocated rather than a width.
    if immh & 0x8 != 0 {
        return Some(g.undefined());
    }
    let (shift, gadget) = if immh & 0x4 != 0 {
        (
            immhb - 32,
            match (q, u) {
                (0, 0) => gadget_sshll_vec_s_to_d,
                (0, _) => gadget_ushll_vec_s_to_d,
                (_, 0) => gadget_sshll2_vec_s_to_d,
                _ => gadget_ushll2_vec_s_to_d,
            },
        )
    } else if immh & 0x2 != 0 {
        (
            immhb - 16,
            match (q, u) {
                (0, 0) => gadget_sshll_vec_h_to_s,
                (0, _) => gadget_ushll_vec_h_to_s,
                (_, 0) => gadget_sshll2_vec_h_to_s,
                _ => gadget_ushll2_vec_h_to_s,
            },
        )
    } else if immh & 0x1 != 0 {
        (
            immhb - 8,
            match (q, u) {
                (0, 0) => gadget_sshll_vec_b_to_h,
                (0, _) => gadget_ushll_vec_b_to_h,
                (_, 0) => gadget_sshll2_vec_b_to_h,
                _ => gadget_ushll2_vec_b_to_h,
            },
        )
    } else {
        // `immh == 0` again: `MOVI`, not a shift.
        return None;
    };

    g.gadget(gadget);
    g.emit(rd as u64 | ((rn as u64) << 8) | ((shift as u64) << 16));
    Some(DECODED)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three rules, at every width. A left shift counts up from the bottom
    /// of the element and a right one down from the top, and confusing them
    /// gives a shift of `2·width − n` where `n` belongs.
    #[test]
    fn a_left_shift_counts_up_and_a_right_one_counts_down() {
        // `shl v0.16b, v1.16b, #3`: immh = 0001, immb = 011, so immhb = 11.
        assert_eq!(width_and_shift(0b0001, 0b011, Amount::Left), Some((0, 3)));
        // `ushr v0.16b, v1.16b, #3`: immhb = 13, and 16 − 13 = 3.
        assert_eq!(width_and_shift(0b0001, 0b101, Amount::Right), Some((0, 3)));
        // The same amount at each width.
        assert_eq!(
            width_and_shift(0b0010, 0b011, Amount::Left),
            Some((1, 3)),
            "halfword"
        );
        assert_eq!(
            width_and_shift(0b0100, 0b011, Amount::Left),
            Some((2, 3)),
            "word"
        );
        assert_eq!(
            width_and_shift(0b1000, 0b011, Amount::Left),
            Some((3, 3)),
            "doubleword"
        );
        // A 64-bit right shift of 3 is `immh:immb == 125`, which is as close to
        // the top of the field as the left form's 3 is to the bottom.
        assert_eq!(width_and_shift(0b1111, 0b101, Amount::Right), Some((3, 3)));
    }

    /// The extremes, which are what a shift of zero and of one less than the
    /// width encode as. A left shift of zero is `immhb == width`, and a right
    /// shift by the full width is `immhb == width` too — the same number
    /// meaning opposite things, which is why the rule cannot be shared.
    #[test]
    fn the_boundaries_of_each_rule() {
        // `shl #0` on bytes.
        assert_eq!(width_and_shift(0b0001, 0b000, Amount::Left), Some((0, 0)));
        // `shl #7`, the largest a byte can take.
        assert_eq!(width_and_shift(0b0001, 0b111, Amount::Left), Some((0, 7)));
        // `ushr #8`, the largest right shift of a byte.
        assert_eq!(width_and_shift(0b0001, 0b000, Amount::Right), Some((0, 8)));
        // `ushr #1`, the smallest.
        assert_eq!(width_and_shift(0b0001, 0b111, Amount::Right), Some((0, 1)));
    }

    /// A narrowing shift's source is twice its destination, so `immh`'s top
    /// bit is unallocated — reading it as a width would name a 64-bit
    /// destination narrowed from something that does not exist.
    #[test]
    fn a_narrowing_shift_has_no_64_bit_width() {
        assert_eq!(
            width_and_shift(0b0100, 0b011, Amount::Narrowing),
            Some((2, 29))
        );
        // With the top bit set there is no width to name, and the C's answer
        // was `64 - 99` in unsigned arithmetic.
        assert_eq!(width_and_shift(0b1100, 0b011, Amount::Narrowing), None);
        // The plain right rule reads the same field as a 64-bit element, which
        // is what makes this a rule and not a range check.
        assert_eq!(width_and_shift(0b1100, 0b011, Amount::Right), Some((3, 29)));
    }

    /// `immh == 0` is `MOVI`/`MVNI`, not a shift, and every arm has to fall
    /// through rather than compute a negative amount.
    #[test]
    fn immh_zero_is_a_different_instruction() {
        assert_eq!(width_and_shift(0, 0, Amount::Left), None);
        assert_eq!(width_and_shift(0, 7, Amount::Right), None);
        assert_eq!(width_and_shift(0, 3, Amount::Narrowing), None);
        assert_eq!(width_and_shift(0, 3, Amount::FixedPoint), None);
    }

    /// The fixed-point conversions have no 8- or 16-bit form: `immh = 0001` is
    /// unallocated and `001x` is FEAT_FP16, which this kernel does not
    /// advertise. Accepting either would run the 32-bit path over narrower
    /// data, which is a wrong answer rather than a refusal — and is what the
    /// first version of these entries did, caught by `decode_probe` reporting
    /// an encoding this ran and a real kernel refused.
    #[test]
    fn a_fixed_point_conversion_is_words_or_doublewords() {
        assert_eq!(
            width_and_shift(0b0001, 0b011, Amount::FixedPoint),
            None,
            "8-bit"
        );
        assert_eq!(
            width_and_shift(0b0010, 0b011, Amount::FixedPoint),
            None,
            "16-bit"
        );
        assert_eq!(
            width_and_shift(0b0011, 0b011, Amount::FixedPoint),
            None,
            "16-bit"
        );
        assert_eq!(
            width_and_shift(0b0100, 0b011, Amount::FixedPoint),
            Some((2, 29))
        );
        assert_eq!(
            width_and_shift(0b1000, 0b011, Amount::FixedPoint),
            Some((3, 61))
        );
        // The plain right rule accepts all four widths, which is why this is a
        // separate `Amount` and not a range check at the call site.
        assert!(width_and_shift(0b0001, 0b011, Amount::Right).is_some());
    }

    /// Every entry masks to a distinct value: two on one would be one
    /// instruction decoded as another, silently, since the table is searched
    /// in order.
    #[test]
    fn the_table_has_no_duplicate_encodings() {
        let mut seen: Vec<u32> = SHIFTS.iter().map(|(v, _, _)| *v).collect();
        let n = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), n);
        // And every one is a value the mask can actually produce.
        for (v, _, _) in SHIFTS {
            assert_eq!(v & 0xbf80_fc00, *v, "{v:#010x} has bits the mask drops");
        }
    }
}
