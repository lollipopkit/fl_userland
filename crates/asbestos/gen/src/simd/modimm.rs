//! `MOVI`, `MVNI`, `ORR`/`BIC` with an immediate, and the vector `FMOV`.
//!
//! One encoding — `0 Q op 0111100000 abc cmode 01 defgh Rd` — and five
//! instructions, told apart by `cmode` and `op`. Eight scattered bits make one
//! byte, and `cmode` says how to spread that byte over sixty-four.
//!
//! # `cmode` is three things at once
//!
//! Its low bit selects `ORR`/`BIC` over `MOVI`/`MVNI` for the values that have
//! both, `0xc` and `0xd` are a different expansion (the "move shifted, ones
//! below" forms), and `0xe`/`0xf` leave the family entirely — `0xf` is `FMOV`,
//! and `0xe` with `op` set is the one that makes a 64-bit element out of eight
//! bits by expanding each to a byte. Every one of those is a separate rule and
//! they are separate here.

use crate::gadgets::*;
use crate::{DECODED, Gen};
use std::ffi::c_int;

/// Spread `imm8` over 64 bits the way `cmode` says.
///
/// `None` for the values that are not this family — the caller has already
/// handled `0xc`, `0xd`, `0xe`-with-`op` and `0xf`, so what is left unhandled
/// is unallocated.
fn pattern(cmode: u32, imm8: u8) -> Option<u64> {
    let imm8 = imm8 as u64;
    match cmode {
        // 32-bit elements, shifted left by 0, 8, 16 or 24.
        0x0 | 0x2 | 0x4 | 0x6 => {
            let elem = imm8 << ((cmode >> 1) * 8);
            Some(elem | (elem << 32))
        }
        // 16-bit elements, shifted left by 0 or 8.
        0x8 | 0xa => {
            let elem = imm8 << (((cmode >> 1) & 1) * 8);
            Some(elem | (elem << 16) | (elem << 32) | (elem << 48))
        }
        // 8-bit elements: the byte in every lane.
        0xe => Some(imm8 * 0x0101_0101_0101_0101),
        _ => None,
    }
}

pub fn decode(g: &mut Gen, insn: u32) -> Option<c_int> {
    if insn & 0x9ff8_0c00 != 0x0f00_0400 {
        return None;
    }
    let q = (insn >> 30) & 1;
    let op = (insn >> 29) & 1;
    let cmode = (insn >> 12) & 0xf;
    let rd = (insn & 0x1f) as u64;

    // `abc` at 18:16 and `defgh` at 9:5 are one byte split by the encoding.
    let imm8 = ((((insn >> 16) & 7) << 5) | ((insn >> 5) & 0x1f)) as u8;

    // MOVI Dd, #imm / MOVI Vd.2D, #imm: each *bit* of the byte becomes a whole
    // byte of the element, so the only values it can make are the ones whose
    // every byte is 0x00 or 0xff. It is what a compiler emits for a lane mask.
    if cmode == 0xe && op == 1 {
        let mut elem = 0u64;
        for i in 0..8 {
            if imm8 & (1 << i) != 0 {
                elem |= 0xffu64 << (i * 8);
            }
        }
        return Some(set(g, rd, elem, if q != 0 { elem } else { 0 }));
    }

    // FMOV Vd.<T>, #imm — the same eight bits as the scalar `FMOV`, expanded
    // as a floating-point constant here at compile time rather than by a
    // gadget at run time.
    if cmode == 0xf {
        let (single, double) = super::vfp_expand(imm8);
        if op == 0 {
            let elem = ((single as u64) << 32) | single as u64;
            return Some(set(g, rd, elem, if q != 0 { elem } else { 0 }));
        }
        // The double form is 2D only: there is no 1D vector to put it in.
        if q == 0 {
            return Some(g.undefined());
        }
        return Some(set(g, rd, double, double));
    }

    // ORR and BIC take the odd `cmode` values of the ones that have a 32- or
    // 16-bit expansion, so the pattern is the one an even `cmode` would give.
    // `0xd` is odd and is *not* one of them — it is `MOVI ... MSL #16`.
    let is_orr_bic = cmode & 1 != 0 && cmode != 0xd;

    let pat = match cmode {
        // MOVI/MVNI with a "move shifted, ones below" expansion: the byte moves
        // up and the vacated bits are set rather than cleared.
        0xc => {
            let elem = (imm8 as u64) << 8 | 0xff;
            elem | (elem << 32)
        }
        0xd => {
            let elem = (imm8 as u64) << 16 | 0xffff;
            elem | (elem << 32)
        }
        _ => pattern(if is_orr_bic { cmode - 1 } else { cmode }, imm8)?,
    };

    let lo = pat;
    let hi = if q != 0 { pat } else { 0 };

    Some(if is_orr_bic {
        g.gadget(if op != 0 {
            gadget_bic_imm_vec
        } else {
            gadget_orr_imm_vec
        });
        g.emit(rd | ((q as u64) << 8));
        g.emit(lo);
        g.emit(hi);
        DECODED
    } else if op != 0 {
        // MVNI is MOVI of the complement, worked out here so that there is one
        // gadget rather than two.
        set(g, rd, !lo, if q != 0 { !hi } else { 0 })
    } else {
        set(g, rd, lo, hi)
    })
}

/// Write a 128-bit constant into a vector register.
fn set(g: &mut Gen, rd: u64, lo: u64, hi: u64) -> c_int {
    g.gadget(gadget_set_vec_imm);
    g.emit(rd);
    g.emit(lo);
    g.emit(hi);
    DECODED
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three expansions that make a repeating pattern, at the widths they
    /// repeat over. Getting the width wrong gives a value that is right in the
    /// bottom lane and wrong in every other one, which is what makes it worth a
    /// test rather than a read.
    #[test]
    fn a_cmode_says_how_wide_the_element_is() {
        // `movi v0.4s, #0x12`: 32-bit elements, no shift.
        assert_eq!(pattern(0x0, 0x12), Some(0x0000_0012_0000_0012));
        // `movi v0.4s, #0x12, lsl #16`.
        assert_eq!(pattern(0x4, 0x12), Some(0x0012_0000_0012_0000));
        // `movi v0.8h, #0x12`: 16-bit elements.
        assert_eq!(pattern(0x8, 0x12), Some(0x0012_0012_0012_0012));
        // `movi v0.8h, #0x12, lsl #8`.
        assert_eq!(pattern(0xa, 0x12), Some(0x1200_1200_1200_1200));
        // `movi v0.16b, #0x12`.
        assert_eq!(pattern(0xe, 0x12), Some(0x1212_1212_1212_1212));
        // The odd values belong to ORR/BIC and are reached by subtracting one,
        // so asking directly is a question about an unallocated encoding.
        assert_eq!(pattern(0x1, 0x12), None);
    }

    /// `cmode = 0xe` means two different instructions depending on `op`, and
    /// they are not variants of each other: one puts the byte in every lane,
    /// the other expands each *bit* to a byte.
    #[test]
    fn the_bit_expansion_only_makes_lane_masks() {
        // `movi d0, #0xff` -- every bit set, so every byte.
        let mut expanded = 0u64;
        for i in 0..8 {
            if (1 << i) != 0 {
                expanded |= 0xffu64 << (i * 8);
            }
        }
        assert_eq!(expanded, u64::MAX);
        // `movi d0, #0b1010_1010` -- alternating bytes.
        let mut alt = 0u64;
        for i in 0..8 {
            if 0xaau8 & (1 << i) != 0 {
                alt |= 0xffu64 << (i * 8);
            }
        }
        assert_eq!(alt, 0xff00_ff00_ff00_ff00);
        // Where `op = 0` at the same `cmode` puts the byte in every lane.
        assert_eq!(pattern(0xe, 0xaa), Some(0xaaaa_aaaa_aaaa_aaaa));
    }

    /// The two shifted-with-ones forms, which are the only ones that set bits
    /// the immediate does not name. They are what a compiler emits for a mask
    /// ending in ones, and reading them as a plain shift loses those bits.
    #[test]
    fn the_msl_forms_fill_below_with_ones() {
        let elem8 = (0x12u64 << 8) | 0xff;
        assert_eq!(elem8, 0x12ff);
        let elem16 = (0x12u64 << 16) | 0xffff;
        assert_eq!(elem16, 0x12_ffff);
    }
}
