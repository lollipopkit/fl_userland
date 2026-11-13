//! Addressed integer load/store instruction decoders.

use super::*;

// ---------------------------------------------------------------------------
// The addressed loads and stores
// ---------------------------------------------------------------------------

/// `LDR` from a pc-relative address, which is how a large constant is loaded.
/// The address is known when the block is compiled, so the gadget takes it.
pub(super) fn literal(g: &mut Gen, insn: u32) -> c_int {
    let opc = (insn >> 30) & 0x3;
    let v = (insn >> 26) & 1;
    let rt = insn & 0x1f;

    // `PRFM (literal)`. A hint with no effect here, like the other two prefetch
    // forms -- and unlike them it was refused, so a program that prefetched
    // through a literal pool took `SIGILL`. Answered before the address is
    // computed, because nothing would read it.
    if v == 0 && opc == 3 {
        return DECODED;
    }

    let target = g.orig_ip().wrapping_add(decode::branch_imm19(insn) as u64);

    g.gadget(gadget_calc_addr_pc_rel);
    g.emit(target);

    if v != 0 {
        let gadget = match opc {
            0 => gadget_ldr_simd_s,
            1 => gadget_ldr_simd_d,
            2 => gadget_ldr_simd_q,
            _ => return g.undefined(),
        };
        g.gadget(gadget);
        g.emit(rt as u64);
        return DECODED;
    }

    let gadget = match opc {
        0 => gadget_load32,
        1 => gadget_load64,
        2 => gadget_load32_sx,
        _ => unreachable!("opc 3 answered above"),
    };
    g.gadget(gadget);
    g.store_reg(rt);
    DECODED
}

/// The scaled unsigned-immediate form, which is the commonest way a field is
/// read out of a structure.
pub(super) fn unsigned_imm(g: &mut Gen, insn: u32) -> c_int {
    let size = (insn >> 30) & 0x3;
    let v = (insn >> 26) & 1;
    let opc = (insn >> 22) & 0x3;
    let imm12 = (insn >> 10) & 0xfff;
    let rn = (insn >> 5) & 0x1f;
    let rt = insn & 0x1f;

    if !register_form_allocated(size, v, opc, true) {
        return g.undefined();
    }

    if v != 0 {
        // A 128-bit access is `size == 0` with the high `opc` bit, which is
        // the one place the size field does not give the width.
        let q = size == 0 && opc & 2 != 0;
        let scale = if q { 4 } else { size };
        let bytes = if q { 16 } else { 1 << size };
        g.addr_imm(rn, ((imm12 as u64) << scale) as i64);
        let Some(gadget) = simd_gadget(bytes, opc & 1 == 1) else {
            return g.undefined();
        };
        g.gadget(gadget);
        g.emit(rt as u64);
        return DECODED;
    }

    // `PRFM`, a prefetch hint. It has no effect here and must not fault.
    if size == 3 && opc == 2 {
        return DECODED;
    }

    let offset = (imm12 as u64) << size;
    let is_load = opc & 1 == 1 || opc & 2 == 2;
    let sign_extend = opc & 2 != 0;

    // A sign-extending byte or halfword load has no fused gadget: it is rare
    // enough that the three-gadget path is not worth twelve more of them.
    if is_load && sign_extend && size < 2 {
        g.addr_imm(rn, offset as i64);
        let Some(gadget) = load_gadget(size, true, opc == 2) else {
            return g.undefined();
        };
        g.gadget(gadget);
        g.store_reg(rt);
        return DECODED;
    }

    let param = rt as u64 | ((rn as u64) << 8) | (offset << 16);
    // Neither register is 31, so the gadget can skip the `SP` and `XZR`
    // checks; `sp_fast` is the same for a base that *is* `SP`, which every
    // access to a local is.
    let fast = rn != 31 && rt != 31;
    let sp_fast = rn == 31 && rt != 31;

    let gadget = if is_load {
        match size {
            0 => {
                if fast {
                    gadget_load8_imm_fast
                } else {
                    gadget_load8_imm
                }
            }
            1 => {
                if fast {
                    gadget_load16_imm_fast
                } else {
                    gadget_load16_imm
                }
            }
            2 => {
                if sign_extend {
                    gadget_load32_sx_imm
                } else if fast {
                    gadget_load32_imm_fast
                } else if sp_fast {
                    gadget_load32_sp_imm
                } else {
                    gadget_load32_imm
                }
            }
            3 => {
                if fast {
                    gadget_load64_imm_fast
                } else if sp_fast {
                    gadget_load64_sp_imm
                } else {
                    gadget_load64_imm
                }
            }
            _ => return g.undefined(),
        }
    } else {
        match size {
            0 => {
                if fast {
                    gadget_store8_imm_fast
                } else {
                    gadget_store8_imm
                }
            }
            1 => {
                if fast {
                    gadget_store16_imm_fast
                } else {
                    gadget_store16_imm
                }
            }
            2 => {
                if fast {
                    gadget_store32_imm_fast
                } else if sp_fast {
                    gadget_store32_sp_imm
                } else {
                    gadget_store32_imm
                }
            }
            3 => {
                if fast {
                    gadget_store64_imm_fast
                } else if sp_fast {
                    gadget_store64_sp_imm
                } else {
                    gadget_store64_imm
                }
            }
            _ => return g.undefined(),
        }
    };
    g.gadget(gadget);
    g.emit(param);
    DECODED
}

/// The register-offset form: `[Xn, Xm, extend #shift]`, which is how an array
/// is indexed.
pub(super) fn reg_offset(g: &mut Gen, insn: u32) -> c_int {
    let size = (insn >> 30) & 0x3;
    let v = (insn >> 26) & 1;
    let opc = (insn >> 22) & 0x3;
    let rm = (insn >> 16) & 0x1f;
    let option = (insn >> 13) & 0x7;
    let s = (insn >> 12) & 1;
    let rn = (insn >> 5) & 0x1f;
    let rt = insn & 0x1f;

    // Four of the eight `option` values name an extend that exists: `010`
    // (UXTW), `011` (LSL), `110` (SXTW) and `111` (SXTX) -- which is to say
    // bit 1 must be set. The other four were decoded and handed to
    // `calc_addr_reg`, which extended by whatever the number meant to it: 128
    // encodings, every one `SIGILL` on a real kernel.
    if option & 2 == 0 {
        return g.undefined();
    }
    if !register_form_allocated(size, v, opc, true) {
        return g.undefined();
    }

    if v != 0 {
        let q = size == 0 && opc & 2 != 0;
        let bytes = if q { 16 } else { 1 << size };
        let shift = if s != 0 { if q { 4 } else { size } } else { 0 };
        g.addr_reg(rn, rm, option, shift);
        let Some(gadget) = simd_gadget(bytes, opc & 1 != 0) else {
            return g.undefined();
        };
        g.gadget(gadget);
        g.emit(rt as u64);
        return DECODED;
    }

    if size == 3 && opc == 2 {
        return DECODED; // PRFM
    }

    let shift = if s != 0 { size } else { 0 };
    let is_load = opc == 1 || opc == 2 || opc == 3;
    let sign_extend = opc >= 2;
    let to64 = opc == 2;

    // The fused gadgets only handle `option == 3`, which is `LSL`/`UXTX` —
    // that is, no extension at all. Anything narrower needs the generic
    // address computation.
    let fused = option == 3 && !(is_load && sign_extend && size < 2);

    if fused {
        let param = rt as u64 | ((rn as u64) << 8) | ((rm as u64) << 16) | ((shift as u64) << 24);
        let plain_load = is_load && !sign_extend && rn != 31 && rm != 31 && rt != 31;
        if plain_load && size == 3 {
            g.gadget(gadget_load64_reg_fast);
            g.emit(param);
            return DECODED;
        }
        if plain_load && size == 2 {
            g.gadget(gadget_load32_reg_fast);
            g.emit(param);
            return DECODED;
        }
        let gadget = if is_load {
            match size {
                0 => gadget_load8_reg,
                1 => gadget_load16_reg,
                2 => {
                    if sign_extend {
                        gadget_load32_sx_reg
                    } else {
                        gadget_load32_reg
                    }
                }
                3 => gadget_load64_reg,
                _ => return g.undefined(),
            }
        } else {
            match size {
                0 => gadget_store8_reg,
                1 => gadget_store16_reg,
                2 => gadget_store32_reg,
                3 => gadget_store64_reg,
                _ => return g.undefined(),
            }
        };
        g.gadget(gadget);
        g.emit(param);
        return DECODED;
    }

    g.addr_reg(rn, rm, option, shift);
    if is_load {
        let Some(gadget) = load_gadget(size, sign_extend, to64) else {
            return g.undefined();
        };
        g.gadget(gadget);
        g.store_reg(rt);
    } else {
        g.load_reg(rt);
        let Some(gadget) = store_gadget(size) else {
            return g.undefined();
        };
        g.gadget(gadget);
    }
    DECODED
}

/// `LDUR`/`STUR` and the pre- and post-indexed forms, which share an encoding
/// separated by two bits at 11:10.
pub(super) fn unscaled_or_indexed(g: &mut Gen, insn: u32) -> c_int {
    let size = (insn >> 30) & 0x3;
    let v = (insn >> 26) & 1;
    let opc = (insn >> 22) & 0x3;
    // The 9-bit offset is **signed**, and it is why every shift of it below
    // goes through `as u64`: shifting a negative left is undefined in C, and
    // this decoder runs for every instruction translated.
    let imm9 = decode::sign_extend(((insn >> 12) & 0x1ff) as u64, 9);
    let mode = (insn >> 10) & 0x3; // 0 unscaled, 1 post, 2 unprivileged, 3 pre
    let rn = (insn >> 5) & 0x1f;
    let rt = insn & 0x1f;

    // Only the unscaled form has a prefetch: `PRFUM`. There is no post-indexed,
    // pre-indexed or unprivileged one.
    if !register_form_allocated(size, v, opc, mode == 0) {
        return g.undefined();
    }

    if v != 0 {
        let q = size == 0 && opc & 2 != 0;
        let bytes = if q { 16 } else { 1u32 << size };
        match mode {
            0 | 3 => g.addr_imm(rn, imm9),
            1 => g.addr_base(rn),
            _ => return g.undefined(),
        }
        let Some(gadget) = simd_gadget(bytes, opc & 1 != 0) else {
            return g.undefined();
        };
        g.gadget(gadget);
        g.emit(rt as u64);
        if mode == 1 || mode == 3 {
            // `update_base` rather than `writeback_addr`, so the whole 64-bit
            // register is written rather than the computed address's width.
            g.gadget(gadget_update_base);
            g.emit(rn as u64 | ((imm9 as u64) << 8));
        }
        return DECODED;
    }

    if size == 3 && opc == 2 {
        return DECODED; // PRFUM
    }

    // `LDTR`/`STTR`, the unprivileged forms. On a real kernel they read and
    // write through the EL0 translation regime while running at EL1, which is
    // what `mode == 2` is *for*; this used to refuse them with a comment saying
    // they "need a second translation regime".
    //
    // A guest here has one regime and nothing else — every access it makes is
    // already the unprivileged one — so these are `LDUR`/`STUR` exactly.
    // Thirteen encodings answered `SIGILL`, and a compiler emits them: they are
    // what `__builtin_...` uaccess helpers and hand-written copy loops use.
    let is_pre = mode == 3;
    let is_unscaled = mode == 0 || mode == 2;
    let is_load = opc == 1 || opc == 2 || opc == 3;
    let narrow_sx = opc >= 2 && size < 2;

    // `LDUR`/`STUR` with no writeback and no register 31: one gadget for the
    // address, the access and the register write.
    if is_unscaled && rn != 31 && rt != 31 && !narrow_sx {
        let param = rt as u64 | ((rn as u64) << 8) | (((imm9 as u64) & 0xffff_ffff_ffff) << 16);
        let gadget = if is_load {
            // A sign-extending word load has no fused form.
            if opc == 2 && size == 2 {
                None
            } else {
                Some(match size {
                    0 => gadget_load8_imm_signed_fast,
                    1 => gadget_load16_imm_signed_fast,
                    2 => gadget_load32_imm_signed_fast,
                    _ => gadget_load64_imm_signed_fast,
                })
            }
        } else {
            Some(match size {
                0 => gadget_store8_imm_signed_fast,
                1 => gadget_store16_imm_signed_fast,
                2 => gadget_store32_imm_signed_fast,
                _ => gadget_store64_imm_signed_fast,
            })
        };
        if let Some(gadget) = gadget {
            g.gadget(gadget);
            g.emit(param);
            return DECODED;
        }
    }

    // The indexed fast paths, which collapse four gadgets into one.
    if !is_unscaled && rn != 31 && (size == 2 || size == 3) {
        let param = rt as u64 | ((rn as u64) << 8) | (((imm9 as i32) as u32 as u64) << 16);
        let gadget = if is_load {
            // A post-indexed load into its own base register is CONSTRAINED
            // UNPREDICTABLE — the writeback and the loaded value both want the
            // register — so it takes the generic chain rather than a guess.
            if rt != 31 && rn != rt && opc & 2 == 0 {
                Some(match (size == 3, is_pre) {
                    (true, true) => gadget_ldr64_imm_preidx_fast,
                    (true, false) => gadget_ldr64_imm_postidx_fast,
                    (false, true) => gadget_ldr32_imm_preidx_fast,
                    (false, false) => gadget_ldr32_imm_postidx_fast,
                })
            } else {
                None
            }
        } else if rt != 31 {
            Some(match (size == 3, is_pre) {
                (true, true) => gadget_str64_imm_preidx_fast,
                (true, false) => gadget_str64_imm_postidx_fast,
                (false, true) => gadget_str32_imm_preidx_fast,
                (false, false) => gadget_str32_imm_postidx_fast,
            })
        } else {
            // `STR XZR` is the store-zero idiom, and common enough for four
            // gadgets of its own.
            Some(match (size == 3, is_pre) {
                (true, true) => gadget_str64_xzr_imm_preidx_fast,
                (true, false) => gadget_str64_xzr_imm_postidx_fast,
                (false, true) => gadget_str32_xzr_imm_preidx_fast,
                (false, false) => gadget_str32_xzr_imm_postidx_fast,
            })
        };
        if let Some(gadget) = gadget {
            g.gadget(gadget);
            g.emit(param);
            return DECODED;
        }
    }

    if is_pre || is_unscaled {
        g.addr_imm(rn, imm9);
    } else {
        g.addr_base(rn);
    }

    if is_load {
        let Some(gadget) = load_gadget(size, opc >= 2, opc == 2) else {
            return g.undefined();
        };
        g.gadget(gadget);
        g.store_reg(rt);
    } else {
        g.load_reg(rt);
        let Some(gadget) = store_gadget(size) else {
            return g.undefined();
        };
        g.gadget(gadget);
    }

    if !is_unscaled {
        if is_pre {
            g.gadget(gadget_writeback_addr);
            g.emit(rn as u64);
        } else {
            g.gadget(gadget_update_base);
            g.emit(rn as u64 | ((imm9 as u64) << 8));
        }
    }
    DECODED
}

/// `LDP`/`STP`, including the two idioms every function prologue and epilogue
/// is made of.
pub(super) fn pair(g: &mut Gen, insn: u32) -> c_int {
    let opc = (insn >> 30) & 0x3;
    let v = (insn >> 26) & 1;
    let mode = (insn >> 23) & 0x7; // 1 post, 2 signed offset, 3 pre, 0 non-temporal
    let l = (insn >> 22) & 1;
    let imm7 = decode::sign_extend(((insn >> 15) & 0x7f) as u64, 7);
    let rt2 = (insn >> 10) & 0x1f;
    let rn = (insn >> 5) & 0x1f;
    let rt = insn & 0x1f;

    let is_pre = mode == 3;
    let is_post = mode == 1;
    // Mode 0 is `LDNP`/`STNP`, whose non-temporal hint is advisory: the
    // addressing is the signed-offset one.
    let is_offset = mode == 2 || mode == 0;
    if !is_pre && !is_post && !is_offset {
        return g.undefined();
    }

    // Which `opc` values exist for an integer pair. `01` is `LDPSW` and
    // `STGP`, neither of which has a non-temporal form, and `11` is nothing at
    // all -- ten encodings that were decoded as their neighbours. The SIMD
    // side already refuses `11` in its own match.
    if v == 0 && (opc == 3 || (opc == 1 && mode == 0)) {
        return g.undefined();
    }

    if v != 0 {
        let bytes: i64 = match opc {
            0 => 4,
            1 => 8,
            2 => 16,
            _ => return g.undefined(),
        };
        let offset = imm7 * bytes;
        if is_post {
            g.addr_base(rn);
        } else {
            g.addr_imm(rn, offset);
        }
        let gadget = match (opc, l != 0) {
            (0, true) => gadget_ldp_simd_s,
            (1, true) => gadget_ldp_simd_d,
            (2, true) => gadget_ldp_simd_q,
            (0, false) => gadget_stp_simd_s,
            (1, false) => gadget_stp_simd_d,
            (2, false) => gadget_stp_simd_q,
            _ => return g.undefined(),
        };
        g.gadget(gadget);
        g.emit(rt as u64 | ((rt2 as u64) << 8));
        if is_post {
            g.gadget(gadget_update_base);
            g.emit(rn as u64 | ((offset as u64) << 8));
        } else if is_pre {
            g.gadget(gadget_writeback_addr);
            g.emit(rn as u64);
        }
        return DECODED;
    }

    let is64 = opc == 2;
    let offset = imm7 * if is64 { 8 } else { 4 };

    if is_offset {
        let param = rt as u64
            | ((rt2 as u64) << 8)
            | ((rn as u64) << 16)
            | (((offset as i16) as u16 as u64) << 24);
        let fast = rn != 31 && rt != 31 && rt2 != 31;
        let gadget = match (l != 0, fast, is64) {
            (true, true, true) => gadget_ldp64_imm_fast,
            (true, true, false) => gadget_ldp32_imm_fast,
            (true, false, true) => gadget_ldp64_imm,
            (true, false, false) => gadget_ldp32_imm,
            (false, true, true) => gadget_stp64_imm_fast,
            (false, true, false) => gadget_stp32_imm_fast,
            (false, false, true) => gadget_stp64_imm,
            (false, false, false) => gadget_stp32_imm,
        };
        g.gadget(gadget);
        g.emit(param);
        return DECODED;
    }

    // `STP X29, X30, [SP, #-N]!` and `LDP X29, X30, [SP], #N`: the prologue
    // and the epilogue, in nearly every function of every guest binary. The
    // generic three-gadget path here was the largest single hot pair measured
    // on Python workloads.
    if is64 && rn == 31 {
        let param = rt as u64 | ((rt2 as u64) << 8) | (((offset as i32) as u32 as u64) << 16);
        let gadget = match (l != 0, is_pre) {
            (true, true) => gadget_ldp64_imm_preidx_sp,
            (true, false) => gadget_ldp64_imm_postidx_sp,
            (false, true) => gadget_stp64_imm_preidx_sp,
            (false, false) => gadget_stp64_imm_postidx_sp,
        };
        g.gadget(gadget);
        g.emit(param);
        return DECODED;
    }

    // The same for a general base — but only when the destinations and the
    // base are different registers. A post-indexed `LDP` into its own base has
    // the writeback overriding a loaded value, and the generic chain is what
    // gets that order right.
    if is64 && rn != 31 && rt != 31 && rt2 != 31 && rn != rt && rn != rt2 {
        let param = rt as u64
            | ((rt2 as u64) << 8)
            | ((rn as u64) << 16)
            | (((offset as i16) as u16 as u64) << 24);
        let gadget = match (l != 0, is_pre) {
            (true, true) => gadget_ldp64_imm_preidx_fast,
            (true, false) => gadget_ldp64_imm_postidx_fast,
            (false, true) => gadget_stp64_imm_preidx_fast,
            (false, false) => gadget_stp64_imm_postidx_fast,
        };
        g.gadget(gadget);
        g.emit(param);
        return DECODED;
    }

    if is_post {
        g.addr_base(rn);
    } else {
        g.addr_imm(rn, offset);
    }
    g.gadget(match (l != 0, is64) {
        (true, true) => gadget_ldp64,
        (true, false) => gadget_ldp32,
        (false, true) => gadget_stp64,
        (false, false) => gadget_stp32,
    });
    g.emit(rt as u64 | ((rt2 as u64) << 8));
    if is_post {
        g.gadget(gadget_update_base);
        g.emit(rn as u64 | ((offset as u64) << 8));
    } else {
        g.gadget(gadget_writeback_addr);
        g.emit(rn as u64);
    }
    DECODED
}
