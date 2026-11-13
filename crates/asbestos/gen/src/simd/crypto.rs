//! Table lookup, `EXT`, and the cryptographic extensions.
//!
//! Grouped together because they share nothing with the rest of the class:
//! each is a fixed encoding with register numbers in it and no `size` field to
//! decide anything, so what they need is a table of exact patterns.
//!
//! # What is implemented, and why that decides `AT_HWCAP`
//!
//! AES, PMULL, SHA-1, SHA-256, SHA-512, SM3, SM4 and the four SHA-3
//! instructions are all here. Every crypto library branches on `AT_HWCAP`
//! before using any of them, so an extension that is decoded and *not*
//! advertised is one that never runs — which is how four of these went
//! untested for as long as they existed. See `crates/kernel/initstack`.

use crate::gadgets::*;
use crate::{DECODED, Gadget, Gen};
use asbestos_crypto::slow;
use emu_tlb::access::SlowFn;
use std::ffi::c_int;

/// Two vector registers in, one out, and nothing else in the encoding: the
/// mask is exact and the operand word is `rd | rn<<8 | rm<<16`.
static THREE_REG: &[(u32, u32, Gadget)] = &[
    // SHA-512, SM3 and RAX1 share the `011` group, so each needs the full
    // mask — the three SHA-512 instructions differ from `RAX1` only in bits
    // 11:10.
    (0xffe0_fc00, 0xce60_8000, gadget_sha512h),
    (0xffe0_fc00, 0xce60_8400, gadget_sha512h2),
    (0xffe0_fc00, 0xce60_8800, gadget_sha512su1),
];

/// The same shapes, run in Rust through `slow_call` (see
/// `asbestos_crypto::slow`): `RAX1`, `SM3PARTW1` and the one-register `SM4E`,
/// whose operand words are the gadgets' unchanged.
static THREE_REG_SLOW: &[(u32, u32, SlowFn)] = &[
    (0xffe0_fc00, 0xce60_8c00, slow::slow_rax1),
    (0xffe0_fc00, 0xce60_c000, slow::slow_sm3partw1),
    (0xffff_fc00, 0xcec0_8400, slow::slow_sm4e),
];

/// One register in, one out.
static TWO_REG: &[(u32, Gadget)] = &[(0xcec0_8000, gadget_sha512su0)];

/// The SHA-1 and SHA-256 three-register instructions, by the opcode at 13:12.
/// Bit 14 separates the two families.
static SHA1: [Option<Gadget>; 4] = [
    Some(gadget_sha1c),
    Some(gadget_sha1p),
    Some(gadget_sha1m),
    Some(gadget_sha1su0),
];
static SHA256: [Option<Gadget>; 4] = [
    Some(gadget_sha256h),
    Some(gadget_sha256h2),
    Some(gadget_sha256su1),
    None,
];

pub fn decode(g: &mut Gen, insn: u32) -> Option<c_int> {
    let rd = (insn & 0x1f) as u64;
    let rn = ((insn >> 5) & 0x1f) as u64;
    let rm = ((insn >> 16) & 0x1f) as u64;
    let q = ((insn >> 30) & 1) as u64;

    // TBL/TBX: use one to four consecutive registers as a table of bytes and
    // index it with a vector. `TBX` leaves the destination alone where an
    // index is out of range; `TBL` writes zero.
    if insn & 0xbfe0_8c00 == 0x0e00_0000 {
        let op = (insn >> 12) & 1;
        let len = ((insn >> 13) & 3) as u64;
        let f: SlowFn = if op != 0 { slow::slow_tbx } else { slow::slow_tbl };
        g.slow_call(f, rd | (rn << 8) | (rm << 16) | (len << 24) | (q << 28));
        return Some(DECODED);
    }

    // EXT: a window of bytes spanning the join between two registers.
    if insn & 0xbfe0_8400 == 0x2e00_0000 {
        let imm4 = ((insn >> 11) & 0xf) as u64;
        // A 64-bit EXT has eight bytes to start from: imm4 >= 8 is UNDEFINED.
        // The gadget indexes an eight-entry jump table with this field, so an
        // encoding let through jumped past the table (imm4 = 11 lands on a
        // `br` to itself and hangs the host thread, beyond any signal).
        if q == 0 && imm4 >= 8 {
            return Some(g.undefined());
        }
        g.gadget(gadget_ext_vec);
        g.emit(rd | (rn << 8) | (rm << 16) | (imm4 << 24) | (q << 28));
        return Some(DECODED);
    }

    // AES: one round of the cipher, split into the two halves a round is made
    // of so that a chain of them pipelines.
    // `size` (23:22) is fixed at 00: the mask left it free, so `4ee8592d` (size
    // 11) ran as AESD.
    if insn & 0xffff_0c00 == 0x4e28_0800 {
        let gadget: Gadget = match (insn >> 12) & 0xf {
            4 => gadget_aese,
            5 => gadget_aesd,
            6 => gadget_aesmc,
            7 => gadget_aesimc,
            _ => return None,
        };
        g.gadget(gadget);
        g.emit(rd | (rn << 8));
        return Some(DECODED);
    }

    // SHA-1 and SHA-256, two registers.
    if insn & 0xffff_cc00 == 0x5e28_0800 {
        let gadget: Gadget = match (insn >> 12) & 3 {
            0 => gadget_sha1h,
            1 => gadget_sha1su1,
            2 => gadget_sha256su0,
            _ => return None,
        };
        g.gadget(gadget);
        g.emit(rd | (rn << 8));
        return Some(DECODED);
    }

    // SHA-1 and SHA-256, three registers. Bit 14 is which family.
    for (value, table) in [(0x5e00_0000u32, &SHA1), (0x5e00_4000u32, &SHA256)] {
        // Bit 15 is fixed at zero as well: leaving it out ran `5e0e80b1` (bits
        // 15:12 = 1000), which no SHA instruction has, as SHA-1 choose.
        if insn & 0xffe0_cc00 == value {
            let gadget = table[((insn >> 12) & 3) as usize]?;
            g.gadget(gadget);
            g.emit(rd | (rn << 8) | (rm << 16));
            return Some(DECODED);
        }
    }

    if let Some(&(_, gadget)) = TWO_REG.iter().find(|(v, _)| *v == insn & 0xffff_fc00) {
        g.gadget(gadget);
        g.emit(rd | (rn << 8));
        return Some(DECODED);
    }

    if let Some(&(_, _, gadget)) = THREE_REG.iter().find(|(mask, v, _)| *v == insn & *mask) {
        g.gadget(gadget);
        g.emit(rd | (rn << 8) | (rm << 16));
        return Some(DECODED);
    }

    if let Some(&(_, _, f)) = THREE_REG_SLOW.iter().find(|(mask, v, _)| *v == insn & *mask) {
        g.slow_call(f, rd | (rn << 8) | (rm << 16));
        return Some(DECODED);
    }

    // XAR: exclusive-or two vectors and rotate the result, which is the whole
    // of a Keccak round's final step.
    //
    // Nothing decoded it until 2026-09-02, though the helper and the gadget
    // were both here — only the *SVE* encoding was, which is a different
    // instruction that happens to share the mnemonic. Every Keccak
    // implementation on aarch64 uses this one, so a guest computing SHA-3 died
    // on an illegal instruction. `tests/guest/src/bin/crypto_probe.rs` is what
    // found it.
    if insn & 0xffe0_0000 == 0xce80_0000 {
        let imm = ((insn >> 10) & 0x3f) as u64;
        g.slow_call(slow::slow_xar, rd | (rn << 8) | (rm << 16) | (imm << 24));
        return Some(DECODED);
    }

    // EOR3 and BCAX, the two four-register SHA-3 instructions. They are one
    // bit of the group field apart and both were needed before a Keccak round
    // would run at all.
    let four_reg: [(u32, SlowFn); 2] = [(0xce00_0000, slow::slow_eor3), (0xce20_0000, slow::slow_bcax)];
    for (value, f) in four_reg {
        if insn & 0xffe0_8000 == value {
            let ra = ((insn >> 10) & 0x1f) as u64;
            g.slow_call(f, rd | (rn << 8) | (rm << 16) | (ra << 24));
            return Some(DECODED);
        }
    }

    // PMULL/PMULL2: polynomial multiply, which is a carry-less multiply and is
    // what GHASH and CRC are built out of. `size` is 0 or 3 and the gadget is
    // told which — the 64-bit form makes a 128-bit result, which is why it is
    // the one encoding in the widening group that allows `size = 3`.
    if insn & 0xbf20_fc00 == 0x0e20_e000 {
        let size = ((insn >> 22) & 3) as u64;
        g.slow_call(slow::slow_pmull, rd | (rn << 8) | (rm << 16) | (q << 24) | (size << 26));
        return Some(DECODED);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Decoder;

    /// `EXT Vd.8B, Vn.8B, Vm.8B, #imm4` with imm4 >= 8 is unallocated. It was
    /// decoded, and its gadget spun forever in a jump table (`0x2e125a66`,
    /// imm4 = 11). This cannot be a guest test: the guest never returns.
    #[test]
    fn a_64_bit_ext_needs_an_index_below_eight() {
        let mut d = Decoder::new();
        let ext = |q: u32, imm4: u32| 0x2e00_0000 | (q << 30) | (imm4 << 11) | (2 << 16) | (3 << 5);
        for imm4 in 0..8 {
            assert!(d.decodes(crate::simd::decode, ext(0, imm4)), "ext .8b #{imm4}");
        }
        for imm4 in 8..16 {
            assert!(!d.decodes(crate::simd::decode, ext(0, imm4)), "ext .8b #{imm4}");
        }
        assert!(d.decodes(crate::simd::decode, ext(1, 15)), "ext .16b #15");
        assert!(!d.decodes(crate::simd::decode, 0x2e12_5a66), "the reported word");
    }

    /// Every exact-match entry has to survive its own mask.
    #[test]
    fn every_entry_survives_its_own_mask() {
        for (mask, v) in THREE_REG.iter().map(|(m, v, _)| (m, v)).chain(THREE_REG_SLOW.iter().map(|(m, v, _)| (m, v))) {
            assert_eq!(v & mask, *v, "{v:#010x}");
        }
        for (v, _) in TWO_REG {
            assert_eq!(v & 0xffff_fc00, *v, "{v:#010x}");
        }
    }

    /// `RAX1` shares its eleven top bits with the three SHA-512 instructions,
    /// which is why it cannot be matched on those alone. This is the check
    /// that the four are distinguishable at all.
    #[test]
    fn rax1_and_the_sha512_group_need_the_low_bits() {
        // Across both tables: RAX1 and SM3PARTW1 run through `slow_call`, and
        // the decoder tries the gadget table first.
        let group: Vec<u32> = THREE_REG
            .iter()
            .map(|(_, v, _)| *v)
            .chain(THREE_REG_SLOW.iter().map(|(_, v, _)| *v))
            .filter(|v| v & 0xffe0_0000 == 0xce60_0000)
            .collect();
        assert_eq!(group.len(), 5, "four SHA-512/RAX1 and SM3PARTW1");
        // Under the eleven-bit mask they are one value.
        for v in &group {
            assert_eq!(v & 0xffe0_0000, 0xce60_0000);
        }
        // Under the full one they are five.
        let mut full: Vec<u32> = group.iter().map(|v| v & 0xffe0_fc00).collect();
        full.sort_unstable();
        full.dedup();
        assert_eq!(full.len(), 5);
    }

    /// `EOR3` and `BCAX` are matched on the top eleven bits *and* bit 15,
    /// because `Ra` sits at 14:10 and would otherwise be part of the compare.
    #[test]
    fn the_four_register_forms_leave_room_for_ra() {
        let eor3 = 0xce00_0000u32 | (0x1f << 10);
        assert_eq!(eor3 & 0xffe0_8000, 0xce00_0000);
        let bcax = 0xce20_0000u32 | (0x1f << 10);
        assert_eq!(bcax & 0xffe0_8000, 0xce20_0000);
        // And they are not each other.
        assert_ne!(eor3 & 0xffe0_8000, bcax & 0xffe0_8000);
    }
}
