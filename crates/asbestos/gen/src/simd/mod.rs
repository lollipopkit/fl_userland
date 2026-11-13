//! SIMD and floating-point: the largest class, and the one with the least
//! structure.
//!
//! `gen_simd_fp` was 2911 lines and 101 return points, and its shape was one
//! `if ((insn & mask) == value)` per instruction — about a hundred masks, each
//! re-extracting the same five or six fields, with the width rules spelled
//! differently at each site. It is nine modules of tables here.
//!
//! # The order is the interface
//!
//! A chain of `if`s has an order, and in this class that order *matters*:
//! several encodings are matched by more than one mask, and which arm gets
//! there first is what decides the answer. [`decode`] is that order, written
//! out, with a note at each point where it is load-bearing. The four places
//! that are not simply "the C did it this way" are:
//!
//! - the shifts before [`modimm`], because `immh == 0` is `MOVI` in the same
//!   encoding space;
//! - [`three_diff`] before [`crypto`], because `PMULL` is inside the widening
//!   group's mask and has to be declined rather than refused;
//! - [`misc`]'s narrowing conversions before its general table, which refuses
//!   the `Q = 0` form they need;
//! - [`lane`]'s `MOV Xd, Vn.D[1]` before its general `UMOV`, which is the same
//!   instruction with a slower gadget.
//!
//! Everything else is disjoint, and the tests in each module are what say so:
//! every table asserts that no two of its entries mask to one value.
//!
//! # Two arms of the C were unreachable
//!
//! `CMEQ #0` and `RBIT` were each decoded twice, and in both cases the first
//! arm was the wrong one — it accepted encodings the second would have
//! refused. Deduplicating them is most of why this is shorter.

use crate::Gen;
use std::ffi::c_int;

pub mod crypto;
pub mod indexed;
pub mod lane;
pub mod misc;
pub mod modimm;
pub mod scalar;
pub mod scalarfp;
pub mod shift;
pub mod three_diff;
pub mod three_same;
pub mod vecldst;

/// Which element widths an operation is defined for.
///
/// Shared by [`three_same`] and [`misc`] because the same five rules recur:
/// the C wrote each of them out about thirty times, in four spellings.
#[derive(Clone, Copy, PartialEq)]
pub enum Widths {
    /// No 64-bit element — the operation would need a 64-bit multiply or
    /// comparison per lane.
    NoD,
    /// 64-bit elements, but only two of them: `2D` and not `1D`. A different
    /// rule from [`Widths::NoD`], and confusing the two is what turns
    /// `add v0.2d, v1.2d, v2.2d` into an illegal instruction.
    NoScalarD,
    /// The across-lanes reductions (`ADDV`, `SMAXV`, ...): no 64-bit element,
    /// and a word needs the whole register (`.2S` is unallocated, since one
    /// pair of words is what `ADDP` is for).
    Reduction,
    /// The saturating doubling multiplies: `H` and `S`.
    HalfWord,
    /// Sources narrower than a word, for an operation that works within one:
    /// `REV32`.
    ByteOrHalf,
    /// `PMUL`, which is polynomial arithmetic on bytes.
    ByteOnly,
}

impl Widths {
    pub fn allows(self, size: u32, q: u32) -> bool {
        match self {
            Widths::NoD => size != 3,
            Widths::NoScalarD => !(size == 3 && q == 0),
            Widths::Reduction => size != 3 && !(size == 2 && q == 0),
            Widths::HalfWord => size == 1 || size == 2,
            Widths::ByteOrHalf => size < 2,
            Widths::ByteOnly => size == 0,
        }
    }
}

/// The element width and the lane index, out of the five-bit `imm5` field.
///
/// The lowest set bit says the width and everything above it is the index, so
/// `xxxx1` is a byte with a four-bit index and `x1000` a doubleword with one
/// bit. `None` when the field is zero, which names no width at all — five
/// instructions read this field and every one of them has to handle that.
pub(crate) fn imm5_lane(imm5: u32) -> Option<(u32, u32)> {
    let esize = if imm5 & 1 != 0 {
        0
    } else if imm5 & 2 != 0 {
        1
    } else if imm5 & 4 != 0 {
        2
    } else if imm5 & 8 != 0 {
        3
    } else {
        return None;
    };
    Some((esize, imm5 >> (esize + 1)))
}

/// Expand an eight-bit floating-point immediate into single and double
/// precision, as `VFPExpandImm` defines it.
///
/// The C had two of these — one that built the bits and one that computed
/// `(16 + frac) / 2^(7 - exp)` in host `double` and reinterpreted the result,
/// after inverting bit 6 of the field to make the exponent read as a small
/// unsigned number. They agree, because both are the same eight bits spread
/// the same way; there is one here, and it is the bit construction, because
/// that is the one whose correctness can be read off the encoding.
///
/// `sign` is bit 7, `exp` is bit 6 repeated to fill the exponent and then
/// *inverted in its top bit*, and the low four bits are the top of the
/// fraction. That is what makes the representable set ±[0.125, 31].
pub(crate) fn vfp_expand(imm8: u8) -> (u32, u64) {
    let sign = ((imm8 >> 7) & 1) as u64;
    let b = ((imm8 >> 6) & 1) as u64;
    let cdefgh = (imm8 & 0x3f) as u64;
    let top2 = (cdefgh >> 4) & 3;
    let frac = cdefgh & 0xf;

    let exp32 = ((1 - b) << 7) | (if b != 0 { 0x1f } else { 0 } << 2) | top2;
    let single = ((sign << 31) | (exp32 << 23) | (frac << 19)) as u32;

    let exp64 = ((1 - b) << 10) | (if b != 0 { 0xff } else { 0 } << 2) | top2;
    let double = (sign << 63) | (exp64 << 52) | (frac << 48);

    (single, double)
}

/// Decode one SIMD or floating-point instruction.
///
/// The arms run in the order the C's did, and where that order is what makes
/// an answer right there is a comment saying so.
pub fn decode(g: &mut Gen, insn: u32) -> c_int {
    // The scalar `FMOV`s and `INS` from a general register.
    if let Some(r) = lane::moves(g, insn) {
        return r;
    }
    // Shifts by an immediate, before `MOVI`: they share an encoding and
    // `immh == 0` is what tells them apart, so every arm here declines rather
    // than faults when it sees one.
    if let Some(r) = shift::decode(g, insn) {
        return r;
    }
    if let Some(r) = shift::lengthening(g, insn) {
        return r;
    }
    // `DUP`, `INS` between vectors, `UMOV` and `SMOV`.
    if let Some(r) = lane::dup_ins_umov(g, insn) {
        return r;
    }
    // The three quadword accesses whose encodings land in this class.
    if let Some(r) = vecldst::decode(g, insn) {
        return r;
    }
    if let Some(r) = modimm::decode(g, insn) {
        return r;
    }
    if let Some(r) = three_same::decode(g, insn) {
        return r;
    }
    // Before `crypto`, which is where `PMULL` is: it lives inside this mask
    // and this declines it.
    if let Some(r) = three_diff::decode(g, insn) {
        return r;
    }
    if let Some(r) = three_diff::xtn(g, insn) {
        return r;
    }
    if let Some(r) = three_diff::permute(g, insn) {
        return r;
    }
    if let Some(r) = misc::decode(g, insn) {
        return r;
    }
    if let Some(r) = scalarfp::decode(g, insn) {
        return r;
    }
    if let Some(r) = crypto::decode(g, insn) {
        return r;
    }
    if let Some(r) = indexed::scalar(g, insn) {
        return r;
    }
    if let Some(r) = indexed::vector(g, insn) {
        return r;
    }
    if let Some(r) = scalar::decode(g, insn) {
        return r;
    }
    g.undefined()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two constants every guest uses. `1.0` is the one an assembler
    /// writes as `fmov d0, #1.0`, and its encoded byte is `0x70`.
    #[test]
    fn the_floating_point_immediates_are_the_ones_the_hardware_makes() {
        let (single, double) = vfp_expand(0x70);
        assert_eq!(single, 1.0f32.to_bits());
        assert_eq!(double, 1.0f64.to_bits());
        // `-1.0` is the same byte with the sign bit.
        let (single, double) = vfp_expand(0xf0);
        assert_eq!(single, (-1.0f32).to_bits());
        assert_eq!(double, (-1.0f64).to_bits());
        // `2.0`: exp one higher.
        let (single, double) = vfp_expand(0x00);
        assert_eq!(single, 2.0f32.to_bits());
        assert_eq!(double, 2.0f64.to_bits());
        // The two ends of the range this encoding can name.
        assert_eq!(vfp_expand(0x40).1, 0.125f64.to_bits(), "the smallest");
        assert_eq!(vfp_expand(0x3f).1, 31.0f64.to_bits(), "the largest");
    }

    /// The value the C computed in floating point, over the whole domain. Both
    /// spellings have to agree for every one of the 256 bytes, or a constant a
    /// compiler folded into an `FMOV` comes out different from the one it
    /// meant.
    #[test]
    fn the_bit_construction_agrees_with_the_arithmetic() {
        for raw in 0u16..256 {
            let raw = raw as u8;
            // What `arm64_fpimm_to_bits` did: invert bit 6, then read a sign,
            // a three-bit exponent and a four-bit fraction out of the result.
            let flipped = raw ^ 0x40;
            let sign = (flipped >> 7) & 1;
            let exp = ((flipped >> 4) & 7) as i32;
            let frac = (flipped & 0xf) as f64;
            let mut value = (16.0 + frac) / f64::from(1u32 << (7 - exp));
            if sign != 0 {
                value = -value;
            }
            let (single, double) = vfp_expand(raw);
            assert_eq!(double, value.to_bits(), "imm8 {raw:#04x}");
            assert_eq!(single, (value as f32).to_bits(), "imm8 {raw:#04x}");
        }
    }

    /// Encodings a real arm64 kernel answers SIGILL for and this decoder used to
    /// run (`insn_diff` against a real kernel found each), and their allocated
    /// neighbours, which must still decode. Two hundred words were of these
    /// shapes in every hundred thousand random ones.
    #[test]
    fn unallocated_simd_encodings_are_undefined() {
        use crate::harness::Decoder;
        let mut d = Decoder::new();
        for (name, insn) in [
            ("addp .1d", 0x0eef_be1cu32),
            ("fmaxnm three-same .1d", 0x0e7c_c666),
            ("shift immh=1xxx, Q=0", 0x2f66_e54b),
            ("fmla by element .1d", 0x0fd7_530a),
            ("fmul by element, sz:L = 11", 0x2fd5_9a78),
            ("dup .1d, element", 0x0e08_0420),
            ("dup .1d, general", 0x0e08_0c00),
            ("sha1c with bit 15", 0x5e0e_80b1),
            ("aesd with size 3", 0x4ee8_592d),
            ("umov Xd from a byte", 0x4e07_3cc4),
            ("umaxv .2s", 0x2eb0_a832),
            ("fcvtzs Wd, Dn, #33", 0x1e58_3963),
        ] {
            assert!(!d.decodes(decode, insn), "{name} ({insn:#010x}) is unallocated");
        }
        for (name, insn) in [
            ("addp .2d", 0x4eef_be1cu32),
            ("fmaxnm .2d", 0x4e7c_c666),
            ("shl .2d", 0x4f4f_5400),
            ("dup .2d", 0x4e08_0420),
            ("dup .2d, general", 0x4e08_0c00),
            ("aesd", 0x4e28_5820),
            ("umov Xd from a doubleword", 0x4e08_3c00),
            ("umaxv .4s", 0x6eb0_a820),
            ("fcvtzs Wd, Dn, #33 (scale 31 is not allowed, 47 is)", 0x1e58_bc00),
        ] {
            assert!(d.decodes(decode, insn), "{name} ({insn:#010x}) is allocated");
        }
    }

    /// The width rules, at the one boundary where two of them differ. This is
    /// the same assertion `three_same` makes, kept here because the enum lives
    /// here and the next person to add a variant will read this file.
    #[test]
    fn no_scalar_d_is_not_no_d() {
        assert!(Widths::NoScalarD.allows(3, 1));
        assert!(!Widths::NoD.allows(3, 1));
        assert!(!Widths::NoScalarD.allows(3, 0));
    }
}
