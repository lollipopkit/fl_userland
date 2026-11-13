//! Three quadword accesses that reach this class instead of the load/store one.
//!
//! `arm64_classify_insn` sends most of `LDR Q`/`STR Q` to `INSN_LD_ST`, which
//! is `crates/asbestos/gen/src/ldst.rs`. These three arrive here because their
//! encodings sit in the SIMD space, and they stay where the C had them: a
//! decoder that answers for an encoding twice is a decoder whose two answers
//! can disagree.

use crate::gadgets::*;
use crate::{DECODED, Gen};
use std::ffi::c_int;

pub fn decode(g: &mut Gen, insn: u32) -> Option<c_int> {
    let rt = (insn & 0x1f) as u64;
    let rn = ((insn >> 5) & 0x1f) as u64;

    // STR Qt, [Xn, #imm12] — the offset is scaled by the access size, so a
    // quadword's is sixteen bytes per unit.
    if insn & 0xffc0_0000 == 0x3d80_0000 {
        let offset = (((insn >> 10) & 0xfff) as u64) * 16;
        g.gadget(gadget_calc_addr_imm);
        g.emit(rn | (offset << 8));
        g.gadget(gadget_str_q);
        g.emit(rt);
        return Some(DECODED);
    }

    // STUR Qt, [Xn, #imm9] — unscaled and signed.
    if insn & 0xffe0_0c00 == 0x3c80_0000 {
        let imm9 = crate::decode::sign_extend(((insn >> 12) & 0x1ff) as u64, 9);
        g.gadget(gadget_calc_addr_imm);
        g.emit(rn | ((imm9 as u64) << 8));
        g.gadget(gadget_str_q);
        g.emit(rt);
        return Some(DECODED);
    }

    // STP Qt, Qt2, [Xn, #imm7] — scaled by sixteen, like the single store.
    if insn & 0xffc0_0000 == 0xad00_0000 {
        let rt2 = ((insn >> 10) & 0x1f) as u64;
        let imm7 = crate::decode::sign_extend(((insn >> 15) & 0x7f) as u64, 7);
        let offset = imm7.wrapping_mul(16) as u64;
        g.gadget(gadget_calc_addr_imm);
        g.emit(rn | (offset << 8));
        g.gadget(gadget_stp_q);
        g.emit(rt | (rt2 << 8));
        return Some(DECODED);
    }

    None
}
