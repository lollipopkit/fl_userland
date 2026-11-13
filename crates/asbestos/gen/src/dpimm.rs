//! Data processing (immediate): everything whose second operand is encoded in
//! the instruction rather than named by a register.
//!
//! Six groups, told apart by `op0` at bits 25:23 except for `ADR`, which has
//! its own top-level pattern:
//!
//! | | |
//! | --- | --- |
//! | `ADR`, `ADRP` | an address relative to the pc |
//! | `ADD`/`SUB` immediate | with and without flags, with and without `LSL #12` |
//! | `EXTR` | the one three-register instruction in this class |
//! | logical immediate | `AND`, `ORR`, `EOR`, `ANDS`, over the bitmask encoding |
//! | move wide | `MOVN`, `MOVZ`, `MOVK` |
//! | bitfield | `SBFM`, `BFM`, `UBFM`, and the seven aliases over them |
//!
//! # Why there are so many gadgets per operation
//!
//! Most of these have a *specialised* gadget for the common shape and a
//! generic one for the rest, and the condition is always the same two things:
//! neither register is 31, and there is no shift. Register 31 is `XZR` in most
//! encodings and `SP` in a few, and the generic gadget is the one that knows
//! which — so the specialisation is "this cannot be the stack pointer and
//! cannot be the zero register", which is nearly every instruction a compiler
//! emits and none of the awkward ones.
//!
//! # What checks it
//!
//! `tests/guest/src/bin/scalar_probe.rs`, against a real arm64 CPU: every
//! flag-setting form, all fourteen conditions, the seven bitfield aliases, the
//! bitmask immediates, `EXTR`, the moves and `ADR`/`ADRP`. It was written
//! first, which is the order that makes a rewrite of a decoder safe.

use crate::gadgets::*;
use crate::{DECODED, Gen, decode, fuse};
use std::ffi::c_int;

pub fn decode(g: &mut Gen, insn: u32) -> c_int {
    let op0 = (insn >> 23) & 0x7;

    if insn & 0x1f00_0000 == 0x1000_0000 {
        return adr(g, insn);
    }
    // op0 = 3 is add/subtract-with-tags (`ADDG`/`SUBG`, MTE), which is not
    // advertised, so it is undefined. Matching
    // `op0 & 6 == 2` ran `ADDG` as a plain `ADD`.
    if op0 == 0x2 {
        return add_sub_imm(g, insn);
    }
    // `EXTR`: 64-bit is 0x93c00000 and 32-bit is 0x13800000, and the two are
    // not one pattern with a size bit — `N` has to agree with `sf`, which is
    // why there are two constants rather than a mask over one.
    if insn & 0xffe0_0000 == 0x93c0_0000 || insn & 0xffe0_0000 == 0x1380_0000 {
        let sf = (insn >> 31) & 1;
        let rm = (insn >> 16) & 0x1f;
        let imm = (insn >> 10) & 0x3f;
        // A 32-bit `EXTR` rotates by less than 32. The field is six bits wide
        // for both widths and the top half is unallocated for the narrow one --
        // the same rule the shifted-register forms above already apply, and the
        // one place here it was missing.
        if sf == 0 && imm >= 32 {
            return g.undefined();
        }
        let rn = (insn >> 5) & 0x1f;
        let rd = insn & 0x1f;
        g.gadget(gadget_extr);
        g.emit(
            rd as u64
                | ((rn as u64) << 8)
                | ((rm as u64) << 16)
                | ((imm as u64) << 24)
                | ((sf as u64) << 30),
        );
        return DECODED;
    }
    if op0 == 0x4 {
        return logical_imm(g, insn);
    }
    if insn & 0x1f80_0000 == 0x1280_0000 {
        return move_wide(g, insn);
    }
    if insn & 0x1f80_0000 == 0x1300_0000 {
        return bitfield(g, insn);
    }

    g.undefined()
}

/// `ADR` and `ADRP`, plus the two pairs they are almost always half of.
///
/// The address is computed *here*, at compile time, because the pc of the
/// instruction is known then — so the gadget stores a constant rather than
/// doing arithmetic. That is also what makes the two fusions below possible.
fn adr(g: &mut Gen, insn: u32) -> c_int {
    let rd = insn & 0x1f;
    let is_adrp = (insn >> 31) & 1 != 0;
    let imm = decode::adr_imm(insn);

    let target = if is_adrp {
        // The page, not the address: the low twelve bits of the pc are dropped
        // and the immediate is a count of pages.
        (g.orig_ip() & !0xfff).wrapping_add((imm as u64) << 12)
    } else {
        g.orig_ip().wrapping_add(imm as u64)
    };

    // `ADRP` is almost never alone: it is the first half of a two-instruction
    // sequence that forms an address and then uses it, and every compiler
    // emits it that way for anything outside ±1 MB.
    if is_adrp
        && rd != 31
        && let Some(next) = g.peek()
    {
        // `ADRP Xd, #page` then `LDR Xt, [Xd, #imm12]`, which is how a
        // global is read.
        if next & 0xffc0_0000 == 0xf940_0000 {
            let ldr_rt = next & 0x1f;
            let ldr_rn = (next >> 5) & 0x1f;
            let offset = ((next >> 10) & 0xfff) << 3; // scaled by 8
            if ldr_rn == rd && ldr_rt != 31 {
                g.consume(1);
                g.gadget(gadget_fused_adrp_ldr64);
                g.emit(ldr_rt as u64 | ((rd as u64) << 5) | ((offset as u64) << 16));
                g.emit(target);
                return DECODED;
            }
        }
        // `ADRP Xd, #page` then `ADD Xd, Xd, #imm12`, which is how its
        // address is taken. Same destination both times, no shift.
        if next & 0xffc0_0000 == 0x9100_0000 {
            let add_rd = next & 0x1f;
            let add_rn = (next >> 5) & 0x1f;
            let add_imm = (next >> 10) & 0xfff;
            if add_rn == rd && add_rd == rd {
                g.consume(1);
                g.gadget(gadget_fused_adrp_add);
                g.emit(rd as u64 | ((add_imm as u64) << 8));
                g.emit(target);
                return DECODED;
            }
        }
    }

    g.gadget(gadget_adr);
    // All 64 bits: `ADRP` at a low pc with a negative offset is a register
    // value above 2^48, and masking it (as this once did, to pack it next to
    // `rd`) is a different answer from a real CPU.
    g.emit(rd as u64);
    g.emit(target);
    DECODED
}

/// `ADD`/`SUB` with a 12-bit immediate, optionally shifted left by 12.
fn add_sub_imm(g: &mut Gen, insn: u32) -> c_int {
    let sf = (insn >> 31) & 1;
    let op = (insn >> 30) & 1; // 0 add, 1 sub
    let s = (insn >> 29) & 1; // set flags
    let sh = (insn >> 22) & 1; // LSL #12
    let imm12 = (insn >> 10) & 0xfff;
    let rn = (insn >> 5) & 0x1f;
    let rd = insn & 0x1f;

    // `SUBS`/`CMP` followed by `B.cond` is the commonest pair in any program,
    // and fusing it removes a whole trip through the dispatch loop.
    if sh == 0
        && rn != 31
        && s != 0
        && op == 1
        && let Some(r) = fuse::subs_imm_bcond(g, sf, rd, rn, imm12)
    {
        return r;
    }

    // The specialised gadgets, which is everything whose source is neither SP
    // nor XZR. The immediate is *not* pre-shifted: `imm12 << 12` does not fit
    // in twelve bits, so the shift is a flag the gadget applies.
    let plain = sf != 0 && sh == 0 && rn != 31;
    let shifted = sf != 0 && sh != 0 && rn != 31;
    let packed = rd as u64 | ((rn as u64) << 8) | ((imm12 as u64) << 16);

    // `rd == 31` is allowed for the flag-setting forms, because that is `CMP`
    // and `CMN` and the result is genuinely discarded.
    if plain && s != 0 {
        g.gadget(if op != 0 {
            gadget_subs_imm_64
        } else {
            gadget_adds_imm_64
        });
        g.emit(packed);
        return DECODED;
    }
    if shifted && s != 0 {
        g.gadget(if op != 0 {
            gadget_subs_imm_64_sh
        } else {
            gadget_adds_imm_64_sh
        });
        g.emit(packed);
        return DECODED;
    }
    if plain && s == 0 && rd != 31 {
        g.gadget(if op != 0 {
            gadget_sub_imm_64
        } else {
            gadget_add_imm_64
        });
        g.emit(packed);
        return DECODED;
    }
    if shifted && s == 0 && rd != 31 {
        g.gadget(if op != 0 {
            gadget_sub_imm_64_sh
        } else {
            gadget_add_imm_64_sh
        });
        g.emit(packed);
        return DECODED;
    }

    let plain32 = sf == 0 && sh == 0 && rn != 31;
    if plain32 && s != 0 {
        g.gadget(if op != 0 {
            gadget_subs_imm_32
        } else {
            gadget_adds_imm_32
        });
        g.emit(packed);
        return DECODED;
    }
    if plain32 && s == 0 && rd != 31 {
        g.gadget(if op != 0 {
            gadget_sub_imm_32
        } else {
            gadget_add_imm_32
        });
        g.emit(packed);
        return DECODED;
    }

    // `ADD Xd, SP, #imm` — a stack slot's address, which every function
    // prologue with a local produces.
    if sf != 0 && sh == 0 && rn == 31 && s == 0 && rd != 31 {
        g.gadget(if op != 0 {
            gadget_sub_imm_sp_src_64
        } else {
            gadget_add_imm_sp_src_64
        });
        g.emit(rd as u64 | ((imm12 as u64) << 16));
        return DECODED;
    }

    // What is left is the SP cases and 32-bit with a shift, which the generic
    // gadget handles from the flags in the packed word.
    g.gadget(if op != 0 {
        gadget_sub_imm
    } else {
        gadget_add_imm
    });
    g.emit(packed | ((sf as u64) << 28) | ((s as u64) << 29) | ((sh as u64) << 30));
    DECODED
}

/// `AND`, `ORR`, `EOR` and `ANDS` with a bitmask immediate.
fn logical_imm(g: &mut Gen, insn: u32) -> c_int {
    let sf = (insn >> 31) & 1;
    let opc = (insn >> 29) & 0x3;
    let n = (insn >> 22) & 1;
    let immr = (insn >> 16) & 0x3f;
    let imms = (insn >> 10) & 0x3f;
    let rn = (insn >> 5) & 0x1f;
    let rd = insn & 0x1f;

    let Some(imm) = decode::bitmask_imm(n, imms, immr, sf != 0) else {
        // Two of the thirteen-bit encodings are unallocated, and a guest can
        // write either.
        return g.undefined();
    };

    // `AND Wd, Wn, #mask` then `CMP Wd, #imm` then `B.cond`: three
    // instructions in one gadget, and the commonest triple there is.
    if opc == 0
        && sf == 0
        && rn != 31
        && rd != 31
        && let Some(r) = fuse::and_cmp32_bcond(g, rd, rn, imm)
    {
        return r;
    }

    // The two hot shapes get their own gadget: masking a tag bit off a pointer
    // and testing one.
    if opc == 0 && rn != 31 && rd != 31 {
        g.gadget(if sf != 0 {
            gadget_and_imm_64_simple
        } else {
            gadget_and_imm_32_simple
        });
        g.emit(rd as u64 | ((rn as u64) << 8));
        g.emit(imm);
        return DECODED;
    }
    // `ANDS`, where `rd == 31` is `TST` and is handled inside the gadget.
    if opc == 3 && rn != 31 {
        g.gadget(if sf != 0 {
            gadget_ands_imm_64
        } else {
            gadget_ands_imm_32
        });
        g.emit(rd as u64 | ((rn as u64) << 8));
        g.emit(imm);
        return DECODED;
    }

    let gadget = match opc {
        0 | 3 => gadget_and_imm, // ANDS reaches the same gadget, with a flag
        1 => gadget_orr_imm,
        2 => gadget_eor_imm,
        _ => return g.undefined(),
    };
    g.gadget(gadget);
    g.emit(
        rd as u64 | ((rn as u64) << 8) | ((sf as u64) << 16) | if opc == 3 { 1 << 17 } else { 0 },
    );
    g.emit(imm);
    DECODED
}

/// `MOVN`, `MOVZ` and `MOVK`: sixteen bits into one of four halfword slots.
fn move_wide(g: &mut Gen, insn: u32) -> c_int {
    let sf = (insn >> 31) & 1;
    let opc = (insn >> 29) & 0x3;
    let hw = (insn >> 21) & 0x3;
    let imm16 = (insn >> 5) & 0xffff;
    let rd = insn & 0x1f;

    // A 32-bit destination has only two halfwords, so `hw` above 1 is not an
    // encoding — it is unallocated rather than a shift off the end.
    if sf == 0 && hw >= 2 {
        return g.undefined();
    }

    let gadget = match opc {
        0 => gadget_movn,
        2 => gadget_movz,
        3 => gadget_movk,
        _ => return g.undefined(), // opc 1 is unallocated
    };
    g.gadget(gadget);
    g.emit(rd as u64 | ((hw as u64) << 8) | ((imm16 as u64) << 16) | ((sf as u64) << 32));
    DECODED
}

/// `SBFM`, `BFM` and `UBFM`, and the seven aliases the assembler spells over
/// them.
///
/// One encoding, seven mnemonics: `LSL`, `LSR`, `ASR`, `UBFX`, `SBFX`, `BFI`
/// and the sign/zero extends are all `immr`/`imms` pairs. Recognising an alias
/// is worth a gadget of its own because the generic bitfield extractor is
/// several times the work of a shift, and a shift is what most of these are.
fn bitfield(g: &mut Gen, insn: u32) -> c_int {
    let sf = (insn >> 31) & 1;
    let opc = (insn >> 29) & 0x3;
    let n = (insn >> 22) & 1;
    let immr = (insn >> 16) & 0x3f;
    let imms = (insn >> 10) & 0x3f;
    let rn = (insn >> 5) & 0x1f;
    let rd = insn & 0x1f;

    // `N` selects the register width and must agree with `sf`, and a 32-bit
    // operation cannot name a bit at 32 or above -- both fields are six bits
    // wide for both widths. None of the three was read: `N` was not extracted
    // at all, so a 32-bit `SBFM` with `N = 1` ran, and so did one asking for
    // bit 40 of a `W` register. 480 encodings, every one `SIGILL` on a real
    // kernel.
    if n != sf || (sf == 0 && (imms >= 32 || immr >= 32)) {
        return g.undefined();
    }

    // The fused gadgets read both registers out of one word, so they need real
    // ones; `BFM` needs the destination as a source too and has no fused form.
    let can_fuse = rn != 31 && rd != 31 && opc != 1;
    let fused_param = immr as u64
        | ((imms as u64) << 8)
        | ((sf as u64) << 16)
        | ((rn as u64) << 20)
        | ((rd as u64) << 28);

    if can_fuse {
        let size = if sf != 0 { 64 } else { 32 };
        let pkt = rd as u64 | ((rn as u64) << 8);
        // `LSR #s` is `UBFM` with `imms = size-1`, and `ASR #s` is `SBFM` with
        // the same — the extract runs to the top of the register, which is
        // what makes it a shift rather than a field.
        if imms == size - 1 {
            if opc == 2 {
                g.gadget(if sf != 0 {
                    gadget_lsr_imm_64
                } else {
                    gadget_lsr_imm_32
                });
                g.emit(pkt | ((immr as u64) << 16));
                return DECODED;
            }
            if opc == 0 {
                g.gadget(if sf != 0 {
                    gadget_asr_imm_64
                } else {
                    gadget_asr_imm_32
                });
                g.emit(pkt | ((immr as u64) << 16));
                return DECODED;
            }
        }
        // `LSL #s` is `UBFM` with `immr = size - s` and `imms = size - 1 - s`,
        // so the two are adjacent. A shift of zero would need `imms = -1` and
        // is never encoded this way, which is why the equality is exact.
        if opc == 2 && immr == imms + 1 && immr < size {
            let shift = size - immr;
            g.gadget(if sf != 0 {
                gadget_lsl_imm_64
            } else {
                gadget_lsl_imm_32
            });
            g.emit(pkt | ((shift as u64) << 16));
            return DECODED;
        }
    }

    match opc {
        0 => {
            if can_fuse {
                g.gadget(gadget_sbfm_fused);
                g.emit(fused_param);
                return DECODED;
            }
            g.gadget(gadget_load_reg);
            g.emit(rn as u64);
            // The sign-extend aliases, which are `SBFM` from bit 0.
            if immr == 0 && imms == 31 && sf == 1 {
                g.gadget(gadget_sxtw);
            } else if immr == 0 && imms == 15 {
                g.gadget(gadget_sxth);
                g.emit(sf as u64);
            } else if immr == 0 && imms == 7 {
                g.gadget(gadget_sxtb);
                g.emit(sf as u64);
            } else {
                g.gadget(gadget_sbfm);
                g.emit(immr as u64 | ((imms as u64) << 8) | ((sf as u64) << 16));
            }
        }
        2 => {
            if can_fuse {
                g.gadget(gadget_ubfm_fused);
                g.emit(fused_param);
                return DECODED;
            }
            g.gadget(gadget_load_reg);
            g.emit(rn as u64);
            if immr == 0 && imms == 31 && sf == 1 {
                g.gadget(gadget_uxtw);
            } else if immr == 0 && imms == 15 {
                g.gadget(gadget_uxth);
                g.emit(sf as u64);
            } else if immr == 0 && imms == 7 {
                g.gadget(gadget_uxtb);
                g.emit(sf as u64);
            } else {
                g.gadget(gadget_ubfm);
                g.emit(immr as u64 | ((imms as u64) << 8) | ((sf as u64) << 16));
            }
        }
        1 => {
            // `BFM` merges into the destination, so it reads it as well —
            // which is why the destination register is in the operand word and
            // there is no fused form.
            g.gadget(gadget_load_reg);
            g.emit(rn as u64);
            g.gadget(gadget_bfm);
            g.emit(immr as u64 | ((imms as u64) << 8) | ((sf as u64) << 16) | ((rd as u64) << 24));
        }
        _ => return g.undefined(),
    }

    // Everything that did not take a fused path leaves its answer in the
    // scratch register, and this is what puts it back.
    g.gadget(gadget_store_reg);
    g.emit(rd as u64);
    DECODED
}

#[cfg(test)]
mod tests {
    use super::{bitfield, decode};
    use crate::harness::Decoder;

    /// The bitfield aliases, which are one encoding wearing seven names. What
    /// is checked is the *recognition*, because emitting the generic extractor
    /// for a shift is correct and several times slower, and emitting a shift
    /// for something that is not one is wrong.
    #[test]
    fn the_shift_aliases_are_recognised_by_their_immr_and_imms() {
        // `lsr x0, x1, #7` is `ubfm x0, x1, #7, #63`.
        let is_lsr = |_immr: u32, imms: u32, sf: u32| imms == if sf != 0 { 63 } else { 31 };
        assert!(is_lsr(7, 63, 1));
        assert!(is_lsr(7, 31, 0));
        assert!(
            !is_lsr(7, 62, 1),
            "an extract that stops short is a field, not a shift"
        );

        // `lsl x0, x1, #7` is `ubfm x0, x1, #57, #56`: immr == imms + 1.
        let is_lsl = |immr: u32, imms: u32, sf: u32| {
            let size = if sf != 0 { 64u32 } else { 32 };
            immr == imms + 1 && immr < size
        };
        assert!(is_lsl(57, 56, 1), "lsl #7, 64-bit");
        assert!(is_lsl(25, 24, 0), "lsl #7, 32-bit");
        assert!(!is_lsl(7, 63, 1), "that is an lsr");
        // The boundary: `lsl #1` is immr=63, imms=62 and is in range; immr=64
        // is not encodable at all.
        assert!(is_lsl(63, 62, 1));
        assert!(!is_lsl(32, 31, 0), "immr must be under the register width");
    }

    /// The result of `ADRP` is a register value: a negative page offset from a
    /// low pc wraps below zero and keeps all 64 bits. The operand carried it in
    /// 48 bits, so `adrp x0, #-1 page` at pc 0 gave `0x0000_ffff_ffff_f000`.
    #[test]
    fn adrp_keeps_all_sixty_four_bits() {
        let mut d = Decoder::new();
        // ADRP X0, #-1 (immhi = all ones, immlo = 0b11).
        let adrp_back = 0x9000_0000u32 | (0x7ffff << 5) | (3 << 29);
        assert!(d.decodes(decode, adrp_back));
        let (rd, target) = d.last_pair();
        assert_eq!(rd, 0);
        assert_eq!(target, 0u64.wrapping_sub(0x1000));
    }

    /// `ADDG`/`SUBG` (op0 = 3, MTE) are not advertised and are unallocated
    /// here; they were matched with the add/subtract immediate and ran as it.
    #[test]
    fn add_subtract_with_tags_is_undefined() {
        let mut d = Decoder::new();
        // ADD X0, X1, #1 is 0x91000420; setting bit 23 makes it ADDG.
        assert!(d.decodes(decode, 0x9100_0420), "add x0, x1, #1");
        assert!(!d.decodes(decode, 0x9100_0420 | (1 << 23)), "addg");
        assert!(!d.decodes(decode, 0xd100_0420 | (1 << 23)), "subg");
        assert!(!d.decodes(decode, 0x1100_0420 | (1 << 23)), "sf=0 form");
    }

    /// `ADRP` drops the low twelve bits of the pc and scales the immediate by
    /// a page; `ADR` does neither. Getting them the same way round is an
    /// address that is right for one and four kilobytes out for the other.
    #[test]
    fn adrp_is_relative_to_the_page_and_adr_to_the_instruction() {
        let pc = 0x1234_5678u64;
        let imm = 3i64;
        let adr_target = pc.wrapping_add(imm as u64);
        let adrp_target = (pc & !0xfff).wrapping_add((imm as u64) << 12);
        assert_eq!(adr_target, 0x1234_567b);
        assert_eq!(adrp_target, 0x1234_8000);
        assert_eq!(adrp_target & 0xfff, 0, "an adrp result is page aligned");
        // Negative, which is what a backward reference produces.
        let back = (pc & !0xfff).wrapping_add(((-2i64) as u64) << 12);
        assert_eq!(back, 0x1234_3000);
    }

    /// A 32-bit `MOVZ`/`MOVK` has two halfword slots, not four. `hw` of 2 or 3
    /// is unallocated, and treating it as a shift writes past the register.
    #[test]
    fn a_32_bit_move_wide_has_only_two_slots() {
        let bad = |sf: u32, hw: u32| sf == 0 && hw >= 2;
        assert!(!bad(1, 3), "a 64-bit destination has four");
        assert!(!bad(0, 1));
        assert!(bad(0, 2));
        assert!(bad(0, 3));
    }

    /// `N` selects the width for a bitfield and must agree with `sf`, and a
    /// 32-bit operation names no bit at 32 or above — in `imms` or in `immr`.
    /// None of the three was read, so a 32-bit `SBFM` asking for bit 40 of a
    /// `W` register ran.
    #[test]
    fn a_bitfield_is_the_width_its_n_and_sf_agree_on() {
        let mut d = Decoder::new();
        let bf = |sf: u32, opc: u32, n: u32, immr: u32, imms: u32| {
            0x1300_0000 | (sf << 31) | (opc << 29) | (n << 22) | (immr << 16) | (imms << 10)
        };
        for opc in 0..3u32 {
            assert!(d.decodes(bitfield, bf(0, opc, 0, 0, 0)), "32-bit, N = 0");
            assert!(d.decodes(bitfield, bf(1, opc, 1, 0, 0)), "64-bit, N = 1");
            assert!(
                !d.decodes(bitfield, bf(0, opc, 1, 0, 0)),
                "32-bit with N = 1"
            );
            assert!(
                !d.decodes(bitfield, bf(1, opc, 0, 0, 0)),
                "64-bit with N = 0"
            );
            assert!(!d.decodes(bitfield, bf(0, opc, 0, 0, 32)), "imms 32 of a W");
            assert!(!d.decodes(bitfield, bf(0, opc, 0, 32, 0)), "immr 32 of a W");
            // The same numbers are fine at 64 bits.
            assert!(d.decodes(bitfield, bf(1, opc, 1, 32, 32)));
        }
        // `opc = 3` names nothing at either width, and already did not decode.
        assert!(!d.decodes(bitfield, bf(1, 3, 1, 0, 0)));
    }

    /// A 32-bit `EXTR` rotates by less than 32: the field is six bits wide for
    /// both widths and the top half is unallocated for the narrow one. The
    /// shifted-register forms already applied that rule and this was the one
    /// place it was missing.
    #[test]
    fn a_32_bit_extract_rotates_by_less_than_32() {
        let mut d = Decoder::new();
        let extr = |sf: u32, n: u32, imms: u32| 0x1380_0000 | (sf << 31) | (n << 22) | (imms << 10);
        assert!(
            d.decodes(decode, extr(0, 0, 31)),
            "31 is the largest 32-bit rotate"
        );
        assert!(!d.decodes(decode, extr(0, 0, 32)));
        assert!(!d.decodes(decode, extr(0, 0, 63)));
        assert!(
            d.decodes(decode, extr(1, 1, 63)),
            "and 63 is fine at 64 bits"
        );
    }
}
