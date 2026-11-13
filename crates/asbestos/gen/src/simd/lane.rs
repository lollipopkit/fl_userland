//! Moving one lane: `DUP`, `INS`, `UMOV`, `SMOV` and the scalar `FMOV`s.
//!
//! What these share is `imm5`, a five-bit field that names an element width
//! and a lane index at once — and which the C decoded **five separate times**,
//! twenty lines each, once per instruction that reads one. It is
//! [`super::imm5_lane`] here.

use super::imm5_lane;
use crate::gadgets::*;
use crate::{DECODED, Gadget, Gen};
use std::ffi::c_int;

/// The scalar `FMOV`s and the four `INS Vd.<T>[i], Rn` widths.
///
/// First in the class because the C had them first, and the order of these
/// tests is what decides which instruction an ambiguous encoding is: `INS`
/// from a general register and `UMOV` to one differ in one opcode bit.
pub fn moves(g: &mut Gen, insn: u32) -> Option<c_int> {
    let rd = (insn & 0x1f) as u64;
    let rn = ((insn >> 5) & 0x1f) as u64;
    let is_double = insn & 0x0040_0000 != 0;

    // FMOV (scalar, immediate).
    //
    // The C decoded this **twice**, and neither mask was right. The first
    // checked bits 14 and 13, which are the bottom two bits of `imm8`, so it
    // matched only the immediates whose fraction is a multiple of four; the
    // second, three hundred lines later, checked the fixed bits correctly but
    // not `ftype`, so a half-precision `FMOV` — which this does not implement —
    // was decoded as a single. Between them every value was decoded, by one of
    // two paths, into one of two gadgets.
    //
    // The fixed part is bits 12:5, which are `100 00000`; `ftype` at 23:22 is
    // the precision and 2 and 3 are not ones this kernel has.
    //
    // One gadget rather than the two the C had. `set_vec_imm` writes the whole
    // 128 bits, which is what an `FMOV` to a scalar does — the upper lanes are
    // zeroed — so the old `gadget_fmov_fp_imm` body is no longer needed.
    if insn & 0xff20_1fe0 == 0x1e20_1000 {
        let ftype = (insn >> 22) & 3;
        if ftype > 1 {
            return Some(g.undefined());
        }
        let imm8 = ((insn >> 13) & 0xff) as u8;
        let (single, double) = super::vfp_expand(imm8);
        g.gadget(gadget_set_vec_imm);
        g.emit(rd);
        g.emit(if is_double { double } else { single as u64 });
        g.emit(0);
        return Some(DECODED);
    }

    // FMOV (scalar, register): one FP register to another.
    if insn & 0xffbf_fc00 == 0x1e20_4000 {
        g.gadget(gadget_fmov_fp_to_fp);
        g.emit(rd | (rn << 8) | ((is_double as u64) << 16));
        return Some(DECODED);
    }

    // INS Vd.<T>[index], Rn — a general register into one lane.
    //
    // The C had this four times, one per width, each with its own mask and its
    // own way of pulling the index out of `imm5`; two of the four masks were
    // written to check a different set of bits from the other two. They are one
    // arm and one width table here.
    if insn & 0xffe0_fc00 == 0x4e00_1c00 {
        // `imm5 == 0` names no width. The C's four arms each simply failed to
        // match, so it falls through to whatever comes next rather than
        // faulting -- which is the same answer for a different reason.
        let (esize, index) = imm5_lane((insn >> 16) & 0x1f)?;
        let gadget: Gadget = match esize {
            0 => gadget_ins_gpr_to_vec_b,
            1 => gadget_ins_gpr_to_vec_h,
            2 => gadget_ins_gpr_to_vec_s,
            _ => gadget_ins_gpr_to_vec_d,
        };
        g.gadget(gadget);
        g.emit(rd | (rn << 8) | ((index as u64) << 16));
        return Some(DECODED);
    }

    None
}

/// `DUP`, `INS` between vectors, and the two ways to read a lane into a general
/// register.
pub(crate) fn dup_ins_umov(g: &mut Gen, insn: u32) -> Option<c_int> {
    let rd = (insn & 0x1f) as u64;
    let rn = ((insn >> 5) & 0x1f) as u64;
    let q = ((insn >> 30) & 1) as u64;
    let imm5 = (insn >> 16) & 0x1f;

    // DUP Vd.<T>, Vn.<T>[index] — one lane to every lane.
    if insn & 0xbfe0_fc00 == 0x0e00_0400 {
        let Some((esize, index)) = imm5_lane(imm5) else {
            return Some(g.undefined());
        };
        // `.1D` is not an arrangement: a doubleword lane needs `Q` set.
        if esize == 3 && q == 0 {
            return Some(g.undefined());
        }
        g.gadget(gadget_dup_elem_vec);
        g.emit(rd | (rn << 8) | ((esize as u64) << 16) | ((index as u64) << 20) | (q << 24));
        return Some(DECODED);
    }

    // DUP Vd, Vn.<T>[index] — the scalar form, which writes one element.
    if insn & 0xffe0_fc00 == 0x5e00_0400 {
        let Some((esize, index)) = imm5_lane(imm5) else {
            return Some(g.undefined());
        };
        g.gadget(gadget_dup_elem_scalar);
        g.emit(rd | (rn << 8) | ((esize as u64) << 16) | ((index as u64) << 20));
        return Some(DECODED);
    }

    // INS Vd.<T>[dst], Vn.<T>[src] — lane to lane, so there are two indices:
    // `imm5` gives the width and the destination, `imm4` the source at that
    // width.
    if insn & 0xffe0_8400 == 0x6e00_0400 {
        let Some((esize, dst)) = imm5_lane(imm5) else {
            return Some(g.undefined());
        };
        let src = ((insn >> 11) & 0xf) >> esize;
        g.gadget(gadget_ins_elem_vec);
        g.emit(
            rd | (rn << 8) | ((esize as u64) << 16) | ((dst as u64) << 20) | ((src as u64) << 24),
        );
        return Some(DECODED);
    }

    // DUP Vd.<T>, Rn — a general register to every lane. Only the width is
    // read out of `imm5`; there is no index to name.
    if insn & 0xbfe0_fc00 == 0x0e00_0c00 {
        let Some((esize, _)) = imm5_lane(imm5) else {
            return Some(g.undefined());
        };
        if esize == 3 && q == 0 {
            return Some(g.undefined());
        }
        g.gadget(gadget_dup_gpr_to_vec);
        g.emit(rd | (rn << 8) | ((esize as u64) << 16) | (q << 24));
        return Some(DECODED);
    }

    // MOV Xd, Vn.D[0]. This is `UMOV` below with one set of operands, and it
    // is here first because it has a gadget that does not have to work out a
    // width at run time — it is what a compiler emits to get a double into a
    // general register, so it is worth the special case.
    //
    // The mask was `0xffe0_fc00` until 2026-09-06, which clears bits 20:16 —
    // `imm5`, the field that says D[0] — while the pattern sets them. So
    // `insn & mask` could never equal it and this arm was **dead**: every
    // `MOV Xd, Vn.D[0]` fell through to the general `UMOV` below, which
    // decodes it correctly and works the width out at run time. Not a wrong
    // answer, a fast path nobody took. `clippy::bad_bit_mask` is what said so,
    // and it is deny-by-default — nothing here had run clippy.
    if insn & 0xffff_fc00 == 0x4e08_3c00 {
        g.gadget(gadget_mov_v_to_gpr);
        g.emit(rd | (rn << 8));
        return Some(DECODED);
    }

    // UMOV and SMOV: read one lane into a general register, zero-extending or
    // sign-extending it.
    //
    // SMOV was decoded by nothing until 2026-09-02 — it is what a compiler
    // emits to read a *signed* lane out of a vector, and a guest reaching one
    // died on an illegal instruction. `tests/guest/src/bin/simd_probe.rs` found
    // it.
    //
    // The opcode is bits 14:11: 0111 for UMOV and 0101 for SMOV, with bit 10
    // set below them. Reading the field at 15:12 gets it one bit out and
    // answers "unsigned" for both, which is how the first version of this
    // decoded SMOV and then did not sign-extend.
    if insn & 0xbfe0_fc00 == 0x0e00_3c00 || insn & 0xbfe0_fc00 == 0x0e00_2c00 {
        let sign_extend = (insn >> 11) & 0xf == 0x5;
        let Some((esize, index)) = imm5_lane(imm5) else {
            return Some(g.undefined());
        };
        // The lane must exist: a 128-bit register holds `16 >> esize` of them.
        if index >= 16 >> esize {
            return Some(g.undefined());
        }
        // SMOV to a W register may not name a word element and SMOV to an X
        // may not name a doubleword: the sign extension would have nothing to
        // do, and the encoding is unallocated rather than a no-op.
        if sign_extend && esize >= if q != 0 { 3 } else { 2 } {
            return Some(g.undefined());
        }
        // `UMOV` to an X register reads a doubleword and to a W register
        // anything narrower; the other pairings (`UMOV Xd, Vn.B[i]`) are
        // unallocated, and ran as a zero-extending move.
        if !sign_extend && (esize == 3) != (q != 0) {
            return Some(g.undefined());
        }
        g.gadget(gadget_umov_vec_to_gpr);
        g.emit(
            rd | (rn << 8)
                | ((esize as u64) << 16)
                | ((index as u64) << 20)
                | ((sign_extend as u64) << 24)
                | (q << 25),
        );
        return Some(DECODED);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The width and the index come out of one field, and which bits are the
    /// index depends on which bit of the field is the lowest set one.
    #[test]
    fn imm5_names_a_width_and_a_lane() {
        // `v0.b[13]`: imm5 = 13<<1 | 1 = 0b11011.
        assert_eq!(imm5_lane(0b11011), Some((0, 13)));
        // `v0.h[5]`: imm5 = 5<<2 | 0b10.
        assert_eq!(imm5_lane(0b10110), Some((1, 5)));
        // `v0.s[3]`: imm5 = 3<<3 | 0b100.
        assert_eq!(imm5_lane(0b11100), Some((2, 3)));
        // `v0.d[1]`: imm5 = 1<<4 | 0b1000.
        assert_eq!(imm5_lane(0b11000), Some((3, 1)));
        // Zero names nothing, and every arm has to handle that rather than
        // shift by a width it has not got.
        assert_eq!(imm5_lane(0), None);
    }

    /// `SMOV` and `UMOV` differ in one opcode bit, and the field they differ in
    /// is at 14:11 — one bit below where it reads as a size.
    #[test]
    fn smov_and_umov_are_told_apart_at_the_right_offset() {
        // `umov w0, v1.b[3]`: imm5 = 0b00111.
        let umov = 0x0e00_3c00 | (0b00111 << 16) | (1 << 5);
        // `smov w0, v1.b[3]`.
        let smov = 0x0e00_2c00 | (0b00111 << 16) | (1 << 5);
        assert_eq!((umov >> 11) & 0xf, 0x7);
        assert_eq!((smov >> 11) & 0xf, 0x5);
        // Read at 15:12 -- the way the first version did -- neither answers 5,
        // so the test for SMOV is never true and both decode as UMOV: the
        // right gadget, told the wrong thing about the sign.
        assert_ne!((umov >> 12) & 0xf, 0x5);
        assert_ne!((smov >> 12) & 0xf, 0x5);
    }
}
