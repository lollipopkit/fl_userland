//! SIMD structure and single-lane load/store instruction decoders.

use super::*;

// ---------------------------------------------------------------------------
// The SIMD structure loads
// ---------------------------------------------------------------------------

/// How many registers an `LD1`–`LD4` opcode names, and whether it interleaves.
///
/// The two are separate encodings of the same idea: `LD1` with four registers
/// loads them back to back, and `LD4` with four *deinterleaves* one array of
/// four-element structures into them.
pub(super) fn struct_regs(opcode: u32) -> Option<(u32, bool)> {
    Some(match opcode {
        0x7 => (1, false),
        0xa => (2, false),
        0x6 => (3, false),
        0x2 => (4, false),
        0x8 => (2, true),
        0x4 => (3, true),
        0x0 => (4, true),
        _ => return None,
    })
}

/// `LD1`–`LD4` and `ST1`–`ST4` over whole registers, with and without a
/// post-index.
pub(super) fn simd_structs(g: &mut Gen, insn: u32, post: bool) -> c_int {
    let q = (insn >> 30) & 1;
    let l = (insn >> 22) & 1;
    let rm = (insn >> 16) & 0x1f;
    let opcode = (insn >> 12) & 0xf;
    let size = (insn >> 10) & 3;
    let rn = (insn >> 5) & 0x1f;
    let rt = insn & 0x1f;

    let Some((regs, interleaved)) = struct_regs(opcode) else {
        return g.undefined();
    };
    // A de-interleaving form with 64-bit elements in 64-bit vectors has one
    // element per register, and there is nothing to de-interleave: `size:Q` of
    // `110` is unallocated for `LD2`/`LD3`/`LD4` and their stores. The
    // *non*-interleaving `LD1` forms beside them do allow it, which is why the
    // rule is on `interleaved` and not on the opcode.
    if interleaved && size == 3 && q == 0 {
        return g.undefined();
    }
    let per_reg = if q != 0 { 16 } else { 8 };

    g.addr_imm(rn, 0);

    if interleaved {
        let f: emu_tlb::access::SlowFn = if l != 0 {
            emu_tlb::access::slow_simd_load_interleaved
        } else {
            emu_tlb::access::slow_simd_store_interleaved
        };
        g.slow_call(f, rt as u64 | ((regs as u64) << 8) | ((size as u64) << 16) | ((q as u64) << 24));
    } else {
        for i in 0..regs {
            // The register numbers wrap at 32: `ld1 {v31.16b, v0.16b}` is a
            // legal pair.
            let vt = (rt + i) & 0x1f;
            g.gadget(match (l != 0, q != 0) {
                (true, true) => gadget_ldr_simd_q,
                (true, false) => gadget_ldr_simd_d,
                (false, true) => gadget_str_simd_q,
                (false, false) => gadget_str_simd_d,
            });
            g.emit(vt as u64);
            if i + 1 < regs {
                g.addr_advance(per_reg);
            }
        }
    }

    if post {
        writeback(g, rn, rm, per_reg * regs as u64);
    }
    DECODED
}

/// The post-index of a structure access: `Xm` when it names one, and the total
/// number of bytes moved when it is `XZR`.
fn writeback(g: &mut Gen, rn: u32, rm: u32, bytes: u64) {
    if rm == 31 {
        g.gadget(gadget_update_base);
        g.emit(rn as u64 | (bytes << 8));
    } else {
        g.gadget(gadget_update_base_reg);
        g.emit(rn as u64 | ((rm as u64) << 8));
    }
}

/// `LD1`–`LD4` of a single lane, and the replicating `LDnR` forms.
pub(super) fn simd_single(g: &mut Gen, insn: u32, post: bool) -> c_int {
    let q = (insn >> 30) & 1;
    let l = (insn >> 22) & 1;
    let r = (insn >> 21) & 1;
    let rm = (insn >> 16) & 0x1f;
    let opcode = (insn >> 13) & 0x7;
    let s = (insn >> 12) & 1;
    let size = (insn >> 10) & 0x3;
    let rn = (insn >> 5) & 0x1f;
    let rt = insn & 0x1f;

    // `LDnR`: load one element and copy it to every lane, which is how a
    // scalar is broadcast before a vector operation.
    if (opcode == 6 || opcode == 7) && s == 0 && l == 1 {
        let (regs, gadget): (u64, Gadget) = match (opcode, r) {
            (6, 0) => (1, gadget_ld1r_vec),
            (6, _) => (2, gadget_ld2r_vec),
            (7, 0) => (3, gadget_ld3r_vec),
            _ => (4, gadget_ld4r_vec),
        };
        g.addr_imm(rn, 0);
        g.gadget(gadget);
        g.emit(rt as u64 | ((size as u64) << 8) | ((q as u64) << 16));
        if post {
            writeback(g, rn, rm, (1u64 << size) * regs);
        }
        return DECODED;
    }

    // How many registers, from `R` and the low bit of the opcode.
    let (regs, base_opcode) = if opcode & 1 != 0 {
        (if r != 0 { 4 } else { 3 }, opcode - 1)
    } else {
        (if r != 0 { 2 } else { 1 }, opcode)
    };

    // Which lane, and how wide it is. The lane number is assembled from `Q`,
    // `S` and `size` differently at every width, because the number of lanes
    // differs — sixteen bytes, eight halfwords, four words, two doublewords.
    //
    // The halfword row is `Q:S:size<1>`, and it was `size & 1`: **the low bit of
    // every 16-bit lane number was always zero**, so `ld1 {v0.h}[1]` loaded into
    // lane 0 and so did lanes 3, 5 and 7. The two bits are not
    // interchangeable — `size<0>` is required to be zero and carries no lane at
    // all, which is the same fact from the other side and is the refusal below.
    // Found by reading, after `decode_probe` reported the *encodings* this
    // accepted and a real kernel does not.
    let (elem, lane) = match (base_opcode, size) {
        (0, _) => (1u32, (q << 3) | (s << 2) | size),
        // `size<0>` names no lane and must be zero.
        (2, _) if size & 1 != 0 => return g.undefined(),
        (2, _) => (2, (q << 2) | (s << 1) | (size >> 1)),
        (4, 0) => (4, (q << 1) | s),
        // The doubleword row has two lanes, so `Q` is the whole index and `S`
        // must be zero.
        (4, 1) if s != 0 => return g.undefined(),
        (4, 1) => (8, q),
        _ => return g.undefined(),
    };
    let lane_offset = lane * elem;

    g.addr_imm(rn, 0);
    for i in 0..regs {
        if i > 0 {
            g.gadget(gadget_addr_add_imm);
            g.emit(elem as u64);
        }
        let vr = (rt + i) % 32;
        g.gadget(match (l != 0, elem) {
            (true, 1) => gadget_ld1_single_b,
            (true, 2) => gadget_ld1_single_h,
            (true, 4) => gadget_ld1_single_s,
            (true, _) => gadget_ld1_single_d,
            (false, 1) => gadget_st1_single_b,
            (false, 2) => gadget_st1_single_h,
            (false, 4) => gadget_st1_single_s,
            (false, _) => gadget_st1_single_d,
        });
        g.emit(vr as u64 | ((lane_offset as u64) << 8));
    }

    if post {
        writeback(g, rn, rm, (elem * regs) as u64);
    }
    DECODED
}
