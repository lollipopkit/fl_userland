//! The instructions beyond ARMv8.0 that a guest may use once it is told the CPU
//! has them.
//!
//! # Why a module of its own, and why it is asked first
//!
//! Each of these is an encoding one of the class decoders either refuses or does
//! not know, and `step.rs` offers every instruction here before them. A feature
//! is the whole set of its encodings, and the rule for advertising one
//! (`asbestos_features::caps`) is that **all** of them execute, so keeping them
//! in one place is what makes that checkable.
//!
//! The gadgets are `asbestos/guest-arm64/gadgets-aarch64/features.S`, assembled
//! with `.arch armv8-a+crypto`: the host is an iPhone from the iOS 13 floor and
//! has none of these features natively. The ones done in software are
//! `slow_call`s into `asbestos_features::slow`.

use crate::gadgets::gadgets;
use crate::ldst::{load_gadget, store_gadget};
use crate::{DECODED, Gen};
use std::ffi::c_int;

gadgets! {
    gadget_dit_mrs,
    gadget_dit_msr,
    gadget_dit_set,
    gadget_fcadd_d,
    gadget_fcadd_s,
    gadget_fcmla_d,
    gadget_fcmla_elem_s,
    gadget_fcmla_s,
    gadget_flagm_axflag,
    gadget_flagm_cfinv,
    gadget_flagm_rmif,
    gadget_flagm_setf,
    gadget_flagm_xaflag,
    gadget_mrs_const,
    gadget_msr_fpcr_fz16,
    gadget_rdm_h,
    gadget_sb,
    gadget_rdm_s,
    gadget_smmla,
    gadget_sudot_elem,
    gadget_ummla,
    gadget_usdot_elem,
    gadget_usdot_vec,
    gadget_usmmla,
    gadget_sdot_elem,
    gadget_sdot_vec,
    gadget_udot_elem,
    gadget_udot_vec,
}

/// Decode one instruction of a feature, or `None` if it is not one.
pub(crate) fn decode(g: &mut Gen, insn: u32) -> Option<c_int> {
    match (insn >> 25) & 0xf {
        0b0100 | 0b0110 | 0b1100 | 0b1110 => lrcpc(g, insn),
        0b0111 | 0b1111 => simd_fp(g, insn),
        0b0101 | 0b1101 => flagm_reg(g, insn),
        0b1010 | 0b1011 => system(g, insn),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// LRCPC and LRCPC2
// ---------------------------------------------------------------------------

/// `LDAPR`, `LDAPUR*` and `STLUR*`.
///
/// The host has none of them, so each is the plain access and a barrier, which
/// is what `LDAR` and `STLR` are here too (`atomics.rs` explains why a release
/// carries a trailing barrier as well; an RCpc load stays at one): guest threads are host threads, and
/// `dmb ish` after a load (before a store) is at least as strong as the
/// acquire (release) the instruction asks for. RCpc is the *weaker* of the two
/// orderings, so the stronger one is a correct implementation.
///
/// A fault goes through the same load and store gadgets as any other access, so
/// `fault_code_pc` is recorded by the shared exit.
fn lrcpc(g: &mut Gen, insn: u32) -> Option<c_int> {
    let size = insn >> 30;
    let rn = (insn >> 5) & 0x1f;
    let rt = insn & 0x1f;

    // LDAPR Wt/Xt, [Xn]: `size 111000 1 0 1 11111 1 100 00 Rn Rt`.
    if insn & 0x3fff_fc00 == 0x38bf_c000 {
        let load = load_gadget(size, false, false)?;
        g.addr_imm(rn, 0);
        g.gadget(load);
        g.barrier();
        g.store_reg(rt);
        return Some(DECODED);
    }

    // LDAPUR/STLUR: `size 011001 opc 0 imm9 00 Rn Rt`.
    if insn & 0x3f20_0c00 == 0x1900_0000 {
        let opc = (insn >> 22) & 3;
        let offset = ((insn as i64 >> 12) & 0x1ff) << 55 >> 55;
        // Which (size, opc) are allocated: the sign-extending loads exist for
        // bytes and halfwords to either width and for a word to 64 only, and a
        // doubleword has just the store and the load.
        if size == 3 && opc > 1 || size == 2 && opc == 3 {
            return None;
        }
        if opc == 0 {
            // STLUR: release, so the barrier comes first.
            let store = store_gadget(size)?;
            g.load_reg(rt);
            g.addr_imm(rn, offset);
            g.barrier();
            g.gadget(store);
            g.barrier(); // a release is also ordered before a later LDAR
        } else {
            // LDAPUR, then the sign-extending forms to 64 and to 32 bits.
            let load = load_gadget(size, opc >= 2, opc == 2)?;
            g.addr_imm(rn, offset);
            g.gadget(load);
            g.barrier();
            g.store_reg(rt);
        }
        return Some(DECODED);
    }
    None
}

// ---------------------------------------------------------------------------
// SIMD and floating point
// ---------------------------------------------------------------------------

fn simd_fp(g: &mut Gen, insn: u32) -> Option<c_int> {
    // FJCVTZS Wd, Dn (FEAT_JSCVT): `0 0 0 11110 01 1 11 110 000000 Rn Rd`.
    if insn & 0xffff_fc00 == 0x1e7e_0000 {
        g.slow_call(asbestos_features::slow::slow_fjcvtzs, insn as u64);
        return Some(DECODED);
    }
    // SDOT and UDOT (FEAT_DotProd), vector: `0 Q U 01110 10 0 Rm 100101 Rn Rd`,
    // and by element: `0 Q U 01111 10 L M Rm 1110 H 0 Rn Rd`. U picks unsigned.
    if insn & 0x9fe0_fc00 == 0x0e80_9400 {
        g.gadget(if insn >> 29 & 1 != 0 { gadget_udot_vec } else { gadget_sdot_vec });
        g.emit(insn as u64);
        return Some(DECODED);
    }
    if insn & 0x9fc0_f400 == 0x0f80_e000 {
        g.gadget(if insn >> 29 & 1 != 0 { gadget_udot_elem } else { gadget_sdot_elem });
        g.emit(insn as u64);
        return Some(DECODED);
    }
    // Half-precision arithmetic (FEAT_FP16), before FCMA's `size = 01` refusal.
    match asbestos_features::fp16::decode(insn) {
        asbestos_features::fp16::Decoded::Mine(_) => {
            g.slow_call(asbestos_features::slow::slow_fp16, insn as u64);
            return Some(DECODED);
        }
        asbestos_features::fp16::Decoded::Undefined => return Some(g.undefined()),
        asbestos_features::fp16::Decoded::NotMine => {}
    }
    // BF16: BFDOT, BFMMLA, BFMLALB/T, BFCVT, BFCVTN(2).
    if let Some(word) = asbestos_features::bf16::pack(insn) {
        g.slow_call(asbestos_features::slow::slow_bf16, word);
        return Some(DECODED);
    }
    if let Some(r) = i8mm(g, insn) {
        return Some(r);
    }
    if let Some(r) = fcma(g, insn) {
        return Some(r);
    }
    if let Some(r) = frintts(g, insn) {
        return Some(r);
    }
    rdm(g, insn)
}

/// FRINT32Z/X and FRINT64Z/X (FEAT_FRINTTS), scalar single and double
/// (`0 0 0 11110 0 sz 1 0100 op(2) 10000 Rn Rd`) and vector
/// (`0 Q U 01110 0 sz 1 00001 1111 x 10 Rn Rd`: U picks X, bit 12 picks 64).
///
/// The mode word is `crates/asbestos/features::frint::frintts`'s:
/// bits 1:0 the operation, bit 2 double, bit 3 a 128-bit vector, bit 4 scalar.
fn frintts(g: &mut Gen, insn: u32) -> Option<c_int> {
    let mode = if insn & 0xffbe_7c00 == 0x1e28_4000 {
        let op = (insn >> 15) & 3;
        let double = (insn >> 22) & 1;
        op | double << 2 | 16
    } else if insn & 0x9fbf_ec00 == 0x0e21_e800 {
        let op = (insn >> 29) & 1 | ((insn >> 12) & 1) << 1;
        let double = (insn >> 22) & 1;
        let q = (insn >> 30) & 1;
        // `.1d` is reserved.
        if double == 1 && q == 0 {
            return Some(g.undefined());
        }
        op | double << 2 | q << 3
    } else {
        return None;
    };
    g.slow_call(asbestos_features::slow::slow_frintts, insn as u64 | (mode as u64) << 32);
    Some(DECODED)
}

/// I8MM (FEAT_I8MM): `USDOT` vector (`0 Q 0 01110 10 0 Rm 100111 Rn Rd`) and by
/// element (`0 Q 0 01111 10 L M Rm 1111 H 0 Rn Rd`), `SUDOT` by element (the
/// same with `size` 00), and `SMMLA`/`UMMLA`/`USMMLA`
/// (`0 1 U 01110 10 0 Rm 1010 x 1 Rn Rd`, `x` set for the mixed-sign one).
fn i8mm(g: &mut Gen, insn: u32) -> Option<c_int> {
    let gadget = if insn & 0xbfe0_fc00 == 0x0e80_9c00 {
        gadget_usdot_vec
    } else if insn & 0xbfc0_f400 == 0x0f80_f000 {
        gadget_usdot_elem
    } else if insn & 0xbfc0_f400 == 0x0f00_f000 {
        gadget_sudot_elem
    } else if insn & 0xffe0_fc00 == 0x4e80_a400 {
        gadget_smmla
    } else if insn & 0xffe0_fc00 == 0x6e80_a400 {
        gadget_ummla
    } else if insn & 0xffe0_fc00 == 0x4e80_ac00 {
        gadget_usmmla
    } else {
        return None;
    };
    g.gadget(gadget);
    g.emit(insn as u64);
    Some(DECODED)
}

/// FCMLA and FCADD (FEAT_FCMA), single and double precision.
///
/// FCMLA vector `0 Q 1 01110 size 0 Rm 1 1 0 rot(2) 1 Rn Rd` (rotation at
/// 12:11), FCADD `... 1 1 1 rot 0 1 ...` (rotation at 12) and FCMLA by element
/// `0 Q 1 01111 size L M Rm 0 rot(2) 1 H 0 Rn Rd` (rotation at 14:13).
///
/// The half-precision forms (`size` 01) need FP16 arithmetic, which is not
/// implemented, so they are undefined here; `fcma` is architecturally allowed
/// without `fphp`.
fn fcma(g: &mut Gen, insn: u32) -> Option<c_int> {
    let size = (insn >> 22) & 3;
    let q = (insn >> 30) & 1;
    let l = (insn >> 21) & 1;
    let (single, double, elem) = if insn & 0xbf20_e400 == 0x2e00_c400 {
        (gadget_fcmla_s as unsafe extern "C" fn(), gadget_fcmla_d as unsafe extern "C" fn(), false)
    } else if insn & 0xbf20_ec00 == 0x2e00_e400 {
        (gadget_fcadd_s as unsafe extern "C" fn(), gadget_fcadd_d as unsafe extern "C" fn(), false)
    } else if insn & 0xbf00_9400 == 0x2f00_1000 {
        (gadget_fcmla_elem_s as unsafe extern "C" fn(), gadget_fcmla_elem_s as unsafe extern "C" fn(), true)
    } else {
        return None;
    };
    let gadget = match (size, elem) {
        (2, false) => single,
        // A 64-bit register holds half a complex double, so `.1d` is reserved.
        (3, false) if q == 1 => double,
        // Only one pair of singles is selectable by H, and only in a 128-bit
        // register: L must be 0 and Q 1.
        (2, true) if l == 0 && q == 1 => single,
        _ => return Some(g.undefined()),
    };
    g.gadget(gadget);
    g.emit(insn as u64);
    Some(DECODED)
}

/// SQRDMLAH and SQRDMLSH (FEAT_RDM). All four forms are U=1 and 16- or 32-bit
/// elements; the other sizes are unallocated.
///
/// vector `0 Q 1 01110 size 0 Rm 1000 s 1 Rn Rd`, scalar the same with
/// `01 1 11110`, by element `0 Q 1 01111 size L M Rm 1 1 s 1 1 H 0 Rn Rd` and
/// scalar by element `01 1 11111`; `s` is the subtract bit.
fn rdm(g: &mut Gen, insn: u32) -> Option<c_int> {
    let size = (insn >> 22) & 3;
    // (mode bits: 1 subtract, 2 by element, 4 scalar)
    let mode = if insn & 0xbf20_f400 == 0x2e00_8400 {
        // The subtract bit is the low bit of the opcode, at 11.
        (insn >> 11) & 1
    } else if insn & 0xff20_f400 == 0x7e00_8400 {
        4 | (insn >> 11) & 1
    } else if insn & 0xbf00_d400 == 0x2f00_d000 {
        // By element: opcode 1101 add, 1111 subtract; bit 11 is H there, so
        // the subtract bit is 13.
        2 | (insn >> 13) & 1
    } else if insn & 0xff00_d400 == 0x7f00_d000 {
        6 | (insn >> 13) & 1
    } else {
        return None;
    };
    if size != 1 && size != 2 {
        return Some(g.undefined());
    }
    g.gadget(if size == 1 { gadget_rdm_h } else { gadget_rdm_s });
    g.emit(insn as u64 | (mode as u64) << 32);
    Some(DECODED)
}

// ---------------------------------------------------------------------------
// FlagM and FlagM2
// ---------------------------------------------------------------------------

/// The system-class encodings: `CFINV`, `XAFLAG` and `AXFLAG` (`MSR
/// (immediate)` with `op1` 0, `CRm` 0 and `Rt` 31, told apart by `op2`), the DIT
/// moves, and the persistent-memory cache operations.
fn system(g: &mut Gen, insn: u32) -> Option<c_int> {
    let rt = (insn & 0x1f) as u64;
    let gadget = match insn {
        0xd500_401f => gadget_flagm_cfinv,
        0xd500_403f => gadget_flagm_xaflag,
        0xd500_405f => gadget_flagm_axflag,
        // SB (FEAT_SB): `system.rs` makes it a memory barrier for the guests
        // that run without the feature; here it is the speculation barrier.
        0xd503_30ff => gadget_sb,
        _ => {
            // MSR FPCR, Xt, keeping FZ16 (see the gadget).
            if insn & 0xffff_ffe0 == 0xd51b_4400 {
                g.gadget(gadget_msr_fpcr_fz16);
                g.emit(rt);
                return Some(DECODED);
            }
            // MSR DIT, #imm (`CRm` 0 or 1).
            if insn & 0xffff_feff == 0xd503_405f {
                g.gadget(gadget_dit_set);
                g.emit(((insn >> 8) & 1) as u64);
                return Some(DECODED);
            }
            // MSR DIT, Xt and MRS Xt, DIT: S3_3_C4_C2_5.
            if insn & 0xffff_ffe0 == 0xd51b_42a0 {
                g.gadget(gadget_dit_msr);
                g.emit(rt);
                return Some(DECODED);
            }
            if insn & 0xffff_ffe0 == 0xd53b_42a0 {
                g.gadget(gadget_dit_mrs);
                g.emit(rt);
                return Some(DECODED);
            }
            // DC CVAP and DC CVADP (FEAT_DPB, FEAT_DPB2): clean to the point
            // of persistence. Host memory is coherent and nothing here is
            // persistent, so they are what DC CVAC and DC CVAU already are in
            // `system.rs`: a no-op, whichever register they name.
            if insn & 0xffff_fee0 == 0xd50b_7c20 {
                return Some(DECODED);
            }
            return None;
        }
    };
    g.gadget(gadget);
    Some(DECODED)
}

/// `SETF8`/`SETF16` (`0 0 1 11010000 000000 0 sz 0 0 10 Rn 0 1101`) and `RMIF`
/// (`1 0 1 11010000 imm6 00001 Rn 0 mask`).
fn flagm_reg(g: &mut Gen, insn: u32) -> Option<c_int> {
    let rn = ((insn >> 5) & 0x1f) as u64;
    if insn & 0xffff_bc1f == 0x3a00_080d {
        g.gadget(gadget_flagm_setf);
        g.emit(rn | (((insn >> 14) & 1) as u64) << 8);
        return Some(DECODED);
    }
    if insn & 0xffe0_7c10 == 0xba00_0400 {
        let shift = ((insn >> 15) & 0x3f) as u64;
        let mask = (insn & 0xf) as u64;
        g.gadget(gadget_flagm_rmif);
        g.emit(rn | shift << 8 | mask << 16);
        return Some(DECODED);
    }
    None
}
