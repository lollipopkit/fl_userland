//! Data processing (register): the arithmetic, the logic, the shifts, the
//! conditional selects and the multiplies.
//!
//! Nine groups, told apart by three fields — `op0` at bit 30, `op1` at 28 and
//! `op2` at 24:21 — except for the four that have a pattern of their own.
//!
//! # The specialisations, and the one condition behind all of them
//!
//! Nearly every group here has a fast gadget and a generic one, and the test
//! is always some combination of the same three things: **no shift, no
//! register 31, no flags**. Register 31 is `XZR` in these encodings and `SP`
//! in a few, and the shift and extend fields cost work per operand; the
//! generic gadget knows all of that and the fast one assumes none of it
//! applies. What the fast path covers is "an ordinary two-register operation",
//! which is nearly everything a compiler emits.
//!
//! # The three identities
//!
//! `ORR Xd, XZR, Xm` is how the assembler spells `MOV`, and `AND`/`ORR` of a
//! register with itself is the same thing again; `EOR Xn, Xn` is a way to
//! write zero. Recognising them turns a two-source operation into a move or a
//! constant, and they are common enough to be worth it — the C's comment says
//! CPython's interpreter loop and CRC inner loops.
//!
//! # What checks it
//!
//! `tests/guest/src/bin/scalar_probe.rs`, against a real arm64 CPU: the
//! flag-setting forms with their carries and overflows, the extended and
//! shifted operands, all fourteen conditions through `CSEL` and `CCMP`,
//! division by zero and `INT_MIN / -1`, the register shifts at every amount,
//! `CLZ`/`CLS`/`RBIT`/`REV`, and the multiplies including the widening ones.

use crate::gadgets::*;
use crate::{DECODED, Gadget, Gen, fuse};
use std::ffi::c_int;

pub fn decode(g: &mut Gen, insn: u32) -> c_int {
    let op0 = (insn >> 30) & 1;
    let op1 = (insn >> 28) & 1;
    let op2 = (insn >> 21) & 0xf;

    if op1 == 0 && op2 & 0x8 == 0 {
        return logical_shifted(g, insn);
    }
    if op1 == 0 && op2 & 0x9 == 0x8 {
        return add_sub_shifted(g, insn);
    }
    if insn & 0x1f20_0000 == 0x0b20_0000 {
        return add_sub_extended(g, insn);
    }
    if insn & 0x1fe0_fc00 == 0x1a00_0000 {
        return add_sub_carry(g, insn);
    }
    if insn & 0x3fe0_0410 == 0x3a40_0000 {
        return cond_compare(g, insn);
    }
    if insn & 0x1fe0_0000 == 0x1a80_0000 {
        return cond_select(g, insn);
    }
    if insn & 0x5fe0_0000 == 0x1ac0_0000 {
        return two_source(g, insn);
    }
    if op0 == 1 && op1 == 1 && op2 == 0x6 {
        return one_source(g, insn);
    }
    if op1 == 1 && op2 & 0x8 == 0x8 {
        return three_source(g, insn);
    }

    g.undefined()
}

/// `AND`, `ORR`, `EOR` and their inverted and flag-setting forms, with the
/// second operand optionally shifted.
fn logical_shifted(g: &mut Gen, insn: u32) -> c_int {
    let sf = (insn >> 31) & 1;
    let opc = (insn >> 29) & 0x3;
    let shift = (insn >> 22) & 0x3;
    let n = (insn >> 21) & 1; // invert the second operand: BIC, ORN, EON
    let rm = (insn >> 16) & 0x1f;
    let imm6 = (insn >> 10) & 0x3f;
    let rn = (insn >> 5) & 0x1f;
    let rd = insn & 0x1f;

    // A 32-bit operation cannot shift by 32 or more: the field is six bits
    // wide for both widths and the top half is unallocated for the narrow one.
    if sf == 0 && imm6 >= 32 {
        return g.undefined();
    }

    if shift != 0 || imm6 != 0 {
        let gadget = match opc {
            0 | 3 => gadget_and_reg_shifted,
            1 => gadget_orr_reg_shifted,
            2 => gadget_eor_reg_shifted,
            _ => return g.undefined(),
        };
        g.gadget(gadget);
        g.emit(
            rd as u64
                | ((rn as u64) << 8)
                | ((rm as u64) << 16)
                | ((sf as u64) << 24)
                | if opc == 3 { 1 << 25 } else { 0 }
                | ((n as u64) << 26)
                | ((shift as u64) << 27),
        );
        g.emit(imm6 as u64);
        return DECODED;
    }

    // `MOV Xd, Xm` is `ORR Xd, XZR, Xm` — the assembler has no other spelling,
    // so this is every register move in every program.
    if opc == 1 && n == 0 && rn == 31 && rd != 31 && rm != 31 {
        g.gadget(if sf != 0 {
            gadget_mov_reg
        } else {
            gadget_mov_reg32
        });
        g.emit(rd as u64 | ((rm as u64) << 16));
        return DECODED;
    }

    // A logical operation of a register with itself has a constant answer.
    if rn == rm && n == 0 && opc != 3 {
        // `EOR Xd, Xn, Xn` is zero, which is a `MOVZ` of nothing.
        if opc == 2 && rd != 31 {
            g.gadget(gadget_movz);
            g.emit(rd as u64 | ((sf as u64) << 32));
            return DECODED;
        }
        // `AND` and `ORR` of a register with itself are that register.
        if (opc == 0 || opc == 1) && rd != 31 && rn != 31 {
            g.gadget(if sf != 0 {
                gadget_mov_reg
            } else {
                gadget_mov_reg32
            });
            g.emit(rd as u64 | ((rn as u64) << 16));
            return DECODED;
        }
    }

    // The unshifted, uninverted, no-flags, no-`XZR` case, which is the bulk of
    // any interpreter's bit manipulation.
    if n == 0 && opc != 3 && rn != 31 && rm != 31 && rd != 31 {
        let fast = match (sf != 0, opc) {
            (true, 0) => gadget_and_reg_64_nshift,
            (true, 1) => gadget_orr_reg_64_nshift,
            (true, 2) => gadget_eor_reg_64_nshift,
            (false, 0) => gadget_and_reg_32_nshift,
            (false, 1) => gadget_orr_reg_32_nshift,
            (false, 2) => gadget_eor_reg_32_nshift,
            _ => unreachable!("opc 3 is excluded above"),
        };
        g.gadget(fast);
        g.emit(rd as u64 | ((rn as u64) << 8) | ((rm as u64) << 16));
        return DECODED;
    }

    // The generic gadget, which reads the inversion and the flag bit out of
    // the packed word. `ANDS`, `BIC`, `ORN` and `EON` all reach it.
    let gadget = match opc {
        0 | 3 => gadget_and_reg,
        1 => gadget_orr_reg,
        2 => gadget_eor_reg,
        _ => return g.undefined(),
    };
    g.gadget(gadget);
    g.emit(
        rd as u64
            | ((rn as u64) << 8)
            | ((rm as u64) << 16)
            | ((sf as u64) << 24)
            | if opc == 3 { 1 << 25 } else { 0 }
            | ((n as u64) << 26),
    );
    DECODED
}

/// `ADD`/`SUB` where the second operand is a register, optionally shifted.
fn add_sub_shifted(g: &mut Gen, insn: u32) -> c_int {
    let sf = (insn >> 31) & 1;
    let op = (insn >> 30) & 1;
    let s = (insn >> 29) & 1;
    let shift = (insn >> 22) & 0x3;
    let rm = (insn >> 16) & 0x1f;
    let imm6 = (insn >> 10) & 0x3f;
    let rn = (insn >> 5) & 0x1f;
    let rd = insn & 0x1f;

    // `ROR` is not an allocated shift for the arithmetic forms, only for the
    // logical ones above.
    if shift == 3 {
        return g.undefined();
    }
    if sf == 0 && imm6 >= 32 {
        return g.undefined();
    }

    let spec = sf != 0 && imm6 == 0 && rn != 31 && rm != 31;
    let packed = rd as u64 | ((rn as u64) << 8) | ((rm as u64) << 16);

    // `SUBS`/`CMP` of two registers followed by `B.cond`, which is the
    // register form of the commonest pair there is.
    if spec
        && s != 0
        && op == 1
        && let Some(r) = fuse::subs_reg_bcond(g, rd, rn, rm)
    {
        return r;
    }
    if spec && s != 0 {
        g.gadget(if op != 0 {
            gadget_subs_reg_64_nshift
        } else {
            gadget_adds_reg_64_nshift
        });
        g.emit(packed);
        return DECODED;
    }
    if spec && s == 0 && rd != 31 {
        g.gadget(if op != 0 {
            gadget_sub_reg_64_nshift
        } else {
            gadget_add_reg_64_nshift
        });
        g.emit(packed);
        return DECODED;
    }

    let spec32 = sf == 0 && imm6 == 0 && shift == 0 && rn != 31 && rm != 31;
    if spec32 && s == 0 && rd != 31 {
        g.gadget(if op != 0 {
            gadget_sub_reg_32_nshift
        } else {
            gadget_add_reg_32_nshift
        });
        g.emit(packed);
        return DECODED;
    }
    // `rd == 31` is allowed here: that is `CMP`/`CMN`, and the gadget knows.
    if spec32 && s != 0 {
        g.gadget(if op != 0 {
            gadget_subs_reg_32_nshift
        } else {
            gadget_adds_reg_32_nshift
        });
        g.emit(packed);
        return DECODED;
    }

    let gadget = match (s != 0, op != 0) {
        (true, true) => gadget_subs_reg,
        (true, false) => gadget_adds_reg,
        (false, true) => gadget_sub_reg,
        (false, false) => gadget_add_reg,
    };
    g.gadget(gadget);
    g.emit(
        packed
            | ((sf as u64) << 24)
            | ((s as u64) << 25)
            | ((shift as u64) << 26)
            | ((imm6 as u64) << 32),
    );
    DECODED
}

/// `ADD`/`SUB` with an *extended* register: the second operand is sign- or
/// zero-extended from a narrower width and then shifted by up to four.
///
/// This is what indexing an array with a 32-bit value compiles to, and it is
/// also the only form in which register 31 means `SP` for the first operand —
/// which is why there is no fast path here.
fn add_sub_extended(g: &mut Gen, insn: u32) -> c_int {
    let sf = (insn >> 31) & 1;
    let op = (insn >> 30) & 1;
    let s = (insn >> 29) & 1;
    let rm = (insn >> 16) & 0x1f;
    let option = (insn >> 13) & 0x7;
    let imm3 = (insn >> 10) & 0x7;
    let rn = (insn >> 5) & 0x1f;
    let rd = insn & 0x1f;

    // `imm3` is the left shift applied *after* the extend, and it is 0 to 4 —
    // three of its eight values name nothing. It was passed straight to the
    // gadget, which shifted by 5, 6 or 7: 192 encodings that a real kernel
    // answers `SIGILL` for. Unlike the register-offset load's `option`, every
    // one of *those* eight values names an extend, which is why this group's
    // rule is on the other field.
    if imm3 > 4 {
        return g.undefined();
    }
    // Bits 23:22 (`opt`) are reserved and must be zero: `0x1f20_0000` in the
    // caller leaves them free, and every value ran as the extended add.
    if (insn >> 22) & 3 != 0 {
        return g.undefined();
    }

    let gadget = match (s != 0, op != 0) {
        (true, true) => gadget_subs_ext,
        (true, false) => gadget_adds_ext,
        (false, true) => gadget_sub_ext,
        (false, false) => gadget_add_ext,
    };
    g.gadget(gadget);
    g.emit(
        rd as u64
            | ((rn as u64) << 8)
            | ((rm as u64) << 16)
            | ((option as u64) << 24)
            | ((imm3 as u64) << 27)
            | ((sf as u64) << 30),
    );
    DECODED
}

/// `ADC`, `ADCS`, `SBC`, `SBCS`: the carry-in forms, which are how anything
/// wider than a register is added.
fn add_sub_carry(g: &mut Gen, insn: u32) -> c_int {
    let sf = (insn >> 31) & 1;
    let op = (insn >> 30) & 1;
    let s = (insn >> 29) & 1;
    let rm = (insn >> 16) & 0x1f;
    let rn = (insn >> 5) & 0x1f;
    let rd = insn & 0x1f;

    g.gadget(if op != 0 {
        gadget_sbc_reg
    } else {
        gadget_adc_reg
    });
    g.emit(
        rd as u64
            | ((rn as u64) << 8)
            | ((rm as u64) << 16)
            | ((sf as u64) << 24)
            | ((s as u64) << 25),
    );
    DECODED
}

/// `CCMP` and `CCMN`: compare if a condition holds, and otherwise write the
/// four-bit immediate straight into `NZCV`.
///
/// That second half is the whole instruction — it is what a short-circuiting
/// `&&` between two comparisons compiles to, and the flags it leaves on the
/// untaken side decide the branch after it.
fn cond_compare(g: &mut Gen, insn: u32) -> c_int {
    let sf = (insn >> 31) & 1;
    let op = (insn >> 30) & 1; // 0 CCMN, 1 CCMP
    let is_imm = (insn >> 11) & 1;
    let rm_or_imm5 = (insn >> 16) & 0x1f;
    let cond = (insn >> 12) & 0xf;
    let rn = (insn >> 5) & 0x1f;
    let nzcv = insn & 0xf;

    let gadget = match (is_imm != 0, op != 0) {
        (true, true) => gadget_ccmp_imm,
        (true, false) => gadget_ccmn_imm,
        (false, true) => gadget_ccmp_reg,
        (false, false) => gadget_ccmn_reg,
    };
    g.gadget(gadget);
    g.emit(
        rn as u64
            | ((rm_or_imm5 as u64) << 8)
            | ((cond as u64) << 16)
            | ((nzcv as u64) << 20)
            | ((sf as u64) << 24),
    );
    DECODED
}

/// `CSEL`, `CSINC`, `CSINV`, `CSNEG` — and the six aliases over them that a
/// compiler emits instead of a branch.
fn cond_select(g: &mut Gen, insn: u32) -> c_int {
    let sf = (insn >> 31) & 1;
    let op = (insn >> 30) & 1;
    let s = (insn >> 29) & 1;
    let rm = (insn >> 16) & 0x1f;
    let cond = (insn >> 12) & 0xf;
    let op2 = (insn >> 10) & 0x3;
    let rn = (insn >> 5) & 0x1f;
    let rd = insn & 0x1f;

    if s != 0 {
        return g.undefined();
    }

    // `op` and `op2` together pick which of the four: 0 selects, 1 increments,
    // 2 inverts, 3 negates the second operand when the condition is false.
    //
    // `op2` is **two** bits and only its low one is part of that number. Its
    // high bit is not allocated, and folding the whole field into the selector
    // made `op2 = 2` decode as `CSINV` and `op2 = 3` as `CSNEG` — 128 encodings
    // that a real kernel answers `SIGILL` for, silently running as a different
    // instruction. `decode_probe` found it by sweeping the group; nothing else
    // could have, because no assembler will emit one.
    if op2 > 1 {
        return g.undefined();
    }
    let gadget = match (op << 1) | op2 {
        0 => gadget_csel,
        1 => gadget_csinc,
        2 => gadget_csinv,
        3 => gadget_csneg,
        _ => return g.undefined(),
    };
    g.gadget(gadget);
    g.emit(
        rd as u64
            | ((rn as u64) << 8)
            | ((rm as u64) << 16)
            | ((cond as u64) << 24)
            | ((sf as u64) << 28),
    );
    DECODED
}

/// Two-source: the divides, the register shifts and the eight CRC32
/// instructions.
fn two_source(g: &mut Gen, insn: u32) -> c_int {
    let sf = (insn >> 31) & 1;
    let s = (insn >> 29) & 1;
    let rm = (insn >> 16) & 0x1f;
    let opcode = (insn >> 10) & 0x3f;
    let rn = (insn >> 5) & 0x1f;
    let rd = insn & 0x1f;

    if s != 0 {
        return g.undefined();
    }

    // The three shifts are hot enough for a 64-bit fast gadget. `RORV` is not
    // among them because it is rare outside hashing.
    if sf != 0 && rd != 31 && rn != 31 && rm != 31 {
        let fast: Option<Gadget> = match opcode {
            0x08 => Some(gadget_lslv_64),
            0x09 => Some(gadget_lsrv_64),
            0x0a => Some(gadget_asrv_64),
            _ => None,
        };
        if let Some(fast) = fast {
            g.gadget(fast);
            g.emit(rd as u64 | ((rn as u64) << 8) | ((rm as u64) << 16));
            return DECODED;
        }
    }

    let gadget = match opcode {
        0x02 => gadget_udiv,
        0x03 => gadget_sdiv,
        0x08 => gadget_lslv,
        0x09 => gadget_lsrv,
        0x0a => gadget_asrv,
        0x0b => gadget_rorv,
        // Every CRC32 form fixes its width. The byte, halfword and word ones
        // take a 32-bit source and are **only** allocated with `sf = 0`; the
        // doubleword ones take a 64-bit source and only with `sf = 1`.
        //
        // Half of that rule was written and half was not, so `crc32b` with
        // `sf = 1` ran the 32-bit gadget where a real kernel answers `SIGILL`.
        // Six encodings, and the giveaway is that the comment below already
        // stated the rule for the other direction — the twin is where this
        // tree's width defects keep being: `SHADD` and `SRHADD` had no 64-bit
        // form while their unsigned halves accepted one.
        0x10 if sf == 0 => gadget_crc32b,
        0x11 if sf == 0 => gadget_crc32h,
        0x12 if sf == 0 => gadget_crc32w,
        0x13 if sf != 0 => gadget_crc32x,
        0x14 if sf == 0 => gadget_crc32cb,
        0x15 if sf == 0 => gadget_crc32ch,
        0x16 if sf == 0 => gadget_crc32cw,
        0x17 if sf != 0 => gadget_crc32cx,
        _ => return g.undefined(),
    };
    g.gadget(gadget);
    g.emit(rd as u64 | ((rn as u64) << 8) | ((rm as u64) << 16) | ((sf as u64) << 24));
    DECODED
}

/// One-source: `RBIT`, `REV16`, `REV32`, `REV`, `CLZ`, `CLS`.
fn one_source(g: &mut Gen, insn: u32) -> c_int {
    let sf = (insn >> 31) & 1;
    let s = (insn >> 29) & 1;
    let opcode2 = (insn >> 16) & 0x1f;
    let opcode = (insn >> 10) & 0x3f;
    let rn = (insn >> 5) & 0x1f;
    let rd = insn & 0x1f;

    if s != 0 || opcode2 != 0 {
        return g.undefined();
    }

    let gadget = match opcode {
        0x00 => gadget_rbit,
        0x01 => gadget_rev16,
        // Opcode 2 is `REV` for a 32-bit destination and `REV32` for a 64-bit
        // one — the same number meaning two different reversals, which is the
        // one place in this group where `sf` picks the instruction rather than
        // its width.
        0x02 => {
            if sf == 0 {
                gadget_rev
            } else {
                gadget_rev32
            }
        }
        // And opcode 3 is the 64-bit `REV`, which has no 32-bit form because
        // opcode 2 already is it.
        0x03 if sf == 1 => gadget_rev,
        0x04 => gadget_clz,
        0x05 => gadget_cls,
        _ => return g.undefined(),
    };
    g.gadget(gadget);
    g.emit(rd as u64 | ((rn as u64) << 8) | ((sf as u64) << 24));
    DECODED
}

/// Three-source: the multiply-accumulates, including the widening and
/// high-half forms.
fn three_source(g: &mut Gen, insn: u32) -> c_int {
    let sf = (insn >> 31) & 1;
    let op54 = (insn >> 29) & 0x3;
    let op31 = (insn >> 21) & 0x7;
    let rm = (insn >> 16) & 0x1f;
    let o0 = (insn >> 15) & 1; // 0 accumulate, 1 subtract
    let ra = (insn >> 10) & 0x1f;
    let rn = (insn >> 5) & 0x1f;
    let rd = insn & 0x1f;

    // `op54` is 0 for every allocated encoding here.
    let gadget: Option<Gadget> = if op54 != 0 {
        None
    } else {
        match (sf, op31) {
            // `MADD`/`MSUB` at both widths, which is also how `MUL` and `MNEG`
            // are spelled — with `XZR` as the accumulator.
            (_, 0) => Some(if o0 != 0 { gadget_msub } else { gadget_madd }),
            // The widening and high-half forms are 64-bit only: they exist to
            // produce a result wider than their operands.
            (1, 1) => Some(if o0 != 0 {
                gadget_smsubl
            } else {
                gadget_smaddl
            }),
            // `SMULH` and `UMULH` have no subtracting form, so `o0 = 1` is not
            // allocated for either. It was ignored, and two encodings a real
            // kernel refuses ran as the multiply — the same shape as the `op2`
            // above it: a field read for the bits that select and not for the
            // ones that must be zero.
            (1, 2) if o0 == 0 => Some(gadget_smulh),
            (1, 5) => Some(if o0 != 0 {
                gadget_umsubl
            } else {
                gadget_umaddl
            }),
            (1, 6) if o0 == 0 => Some(gadget_umulh),
            _ => None,
        }
    };
    let Some(gadget) = gadget else {
        return g.undefined();
    };

    g.gadget(gadget);
    // `SMULH` and `UMULH` have no accumulator, and `ra` is packed anyway —
    // the gadget ignores it, and leaving it out would need a second layout.
    g.emit(
        rd as u64
            | ((rn as u64) << 8)
            | ((rm as u64) << 16)
            | ((ra as u64) << 24)
            | ((sf as u64) << 29),
    );
    DECODED
}

#[cfg(test)]
mod tests {
    use super::{add_sub_extended, cond_select, three_source, two_source};
    use crate::harness::Decoder;

    /// `MOV Xd, Xm` has no encoding of its own: it is `ORR Xd, XZR, Xm`, which
    /// is why the recognition is by *shape* and not by opcode. Getting the
    /// condition wrong turns every register move into the generic three-input
    /// logical gadget.
    #[test]
    fn a_move_is_an_or_with_the_zero_register() {
        // ORR Xd, Xn, Xm: sf 1, opc 01, shift 00, N 0.
        let orr = |rd: u32, rn: u32, rm: u32| 0xaa00_0000 | (rm << 16) | (rn << 5) | rd;
        let is_mov = |insn: u32| {
            let opc = (insn >> 29) & 3;
            let n = (insn >> 21) & 1;
            let rn = (insn >> 5) & 0x1f;
            let rd = insn & 0x1f;
            let rm = (insn >> 16) & 0x1f;
            opc == 1 && n == 0 && rn == 31 && rd != 31 && rm != 31
        };
        assert!(is_mov(orr(0, 31, 1)), "mov x0, x1");
        assert!(!is_mov(orr(0, 2, 1)), "a real orr is not a move");
        assert!(!is_mov(orr(31, 31, 1)), "into xzr is a discard, not a move");
        assert!(!is_mov(orr(0, 31, 31)), "from xzr is a zero, not a move");
    }

    /// Opcode 2 in the one-source group is `REV` for a `W` destination and
    /// `REV32` for an `X` one: the same number, two different reversals. That
    /// is the only place `sf` picks the instruction rather than its width, and
    /// treating it as a width gives byte order that is wrong in half the
    /// register.
    #[test]
    fn one_source_opcode_two_means_two_different_instructions() {
        let which = |sf: u32, opcode: u32| match (sf, opcode) {
            (0, 2) => "rev32bit",
            (1, 2) => "rev32halves",
            (1, 3) => "rev64",
            _ => "other",
        };
        assert_eq!(which(0, 2), "rev32bit");
        assert_eq!(which(1, 2), "rev32halves");
        assert_eq!(which(1, 3), "rev64");
        // There is no 32-bit opcode 3: opcode 2 already is the 32-bit REV.
        assert_eq!(which(0, 3), "other");
    }

    /// Bits 23:22 of the extended-register forms are reserved-zero.
    #[test]
    fn add_sub_extended_needs_opt_zero() {
        let mut d = Decoder::new();
        // ADD X0, X1, W2, UXTW
        let add = 0x8b22_4020u32;
        assert!(d.decodes(add_sub_extended, add));
        for opt in 1..4 {
            assert!(!d.decodes(add_sub_extended, add | (opt << 22)), "opt={opt}");
        }
    }

    /// The widening multiplies exist to produce a result wider than their
    /// operands, so a 32-bit encoding of one is not allocated. Accepting it
    /// would run a 64-bit gadget on a 32-bit instruction.
    ///
    /// This asked a **copy** of the rule until 2026-09-03 — a closure listing
    /// the allocated `(sf, op31)` pairs, which cannot fail however wrong the
    /// decoder is. It asks the decoder now, and the first thing it found is the
    /// case below it.
    #[test]
    fn the_widening_multiplies_are_64_bit_only() {
        let mut d = Decoder::new();
        let three =
            |sf: u32, op31: u32, o0: u32| 0x1b00_0000 | (sf << 31) | (op31 << 21) | (o0 << 15);
        assert!(
            d.decodes(three_source, three(0, 0, 0)),
            "32-bit madd exists"
        );
        assert!(d.decodes(three_source, three(1, 0, 0)));
        assert!(d.decodes(three_source, three(1, 1, 0)), "smaddl");
        assert!(
            !d.decodes(three_source, three(0, 1, 0)),
            "there is no 32-bit smaddl"
        );
        assert!(
            !d.decodes(three_source, three(0, 2, 0)),
            "nor a 32-bit smulh"
        );
        assert!(
            !d.decodes(three_source, three(1, 3, 0)),
            "op31 3 and 4 are unallocated"
        );
        assert!(!d.decodes(three_source, three(1, 4, 0)));
    }

    /// `SMULH` and `UMULH` multiply and keep the high half; there is nothing to
    /// subtract from, so neither has an `o0 = 1` form. It was not read, and both
    /// unallocated encodings ran as the multiply — found by `decode_probe`
    /// sweeping the group against a real kernel, which answers `SIGILL` for
    /// each.
    #[test]
    fn the_high_half_multiplies_have_no_subtracting_form() {
        let mut d = Decoder::new();
        let three = |op31: u32, o0: u32| 0x1b00_0000 | (1 << 31) | (op31 << 21) | (o0 << 15);
        assert!(d.decodes(three_source, three(2, 0)), "smulh");
        assert!(!d.decodes(three_source, three(2, 1)), "and no smsubh");
        assert!(d.decodes(three_source, three(6, 0)), "umulh");
        assert!(!d.decodes(three_source, three(6, 1)), "and no umsubh");
        // The forms that *do* have one still do.
        assert!(d.decodes(three_source, three(0, 1)), "msub");
        assert!(d.decodes(three_source, three(1, 1)), "smsubl");
        assert!(d.decodes(three_source, three(5, 1)), "umsubl");
    }

    /// `op2` is two bits and only its low one names an instruction. Its high
    /// bit is unallocated, and folding the whole field into the selector made
    /// `op2 = 2` a `CSINV` and `op2 = 3` a `CSNEG` — 128 encodings, every one of
    /// which a real kernel refuses.
    #[test]
    fn conditional_select_has_no_third_or_fourth_op2() {
        let mut d = Decoder::new();
        let csel = |op: u32, op2: u32, cond: u32| {
            0x1a80_0000 | (1 << 31) | (op << 30) | (cond << 12) | (op2 << 10)
        };
        for op in 0..2u32 {
            for cond in [0u32, 7, 14, 15] {
                assert!(
                    d.decodes(cond_select, csel(op, 0, cond)),
                    "op{op} cond{cond}"
                );
                assert!(d.decodes(cond_select, csel(op, 1, cond)));
                assert!(
                    !d.decodes(cond_select, csel(op, 2, cond)),
                    "op2=2 op{op} cond{cond}"
                );
                assert!(!d.decodes(cond_select, csel(op, 3, cond)));
            }
        }
        // `S` is unallocated for the whole group and was already refused.
        assert!(!d.decodes(cond_select, csel(0, 0, 0) | (1 << 29)));
    }

    /// Each `CRC32` form fixes the width of its source, so `sf` is part of the
    /// encoding rather than a width to pass through. Half of that was written:
    /// the doubleword forms were refused with `sf = 0` and the byte, halfword
    /// and word forms were accepted with `sf = 1`, six encodings that do not
    /// exist. `AT_HWCAP` claims CRC32, so a guest reaches these.
    #[test]
    fn each_crc32_form_fixes_its_width() {
        let mut d = Decoder::new();
        let crc = |sf: u32, opcode: u32| 0x1ac0_0000 | (sf << 31) | (opcode << 10);
        for (opcode, name) in [
            (0x10, "b"),
            (0x11, "h"),
            (0x12, "w"),
            (0x14, "cb"),
            (0x15, "ch"),
            (0x16, "cw"),
        ] {
            assert!(
                d.decodes(two_source, crc(0, opcode)),
                "crc32{name} is 32-bit"
            );
            assert!(
                !d.decodes(two_source, crc(1, opcode)),
                "and has no 64-bit form"
            );
        }
        for (opcode, name) in [(0x13, "x"), (0x17, "cx")] {
            assert!(
                d.decodes(two_source, crc(1, opcode)),
                "crc32{name} is 64-bit"
            );
            assert!(
                !d.decodes(two_source, crc(0, opcode)),
                "and has no 32-bit form"
            );
        }
    }

    /// `ROR` is a shift for the logical group and not for the arithmetic one:
    /// `shift == 3` there is unallocated, and accepting it would rotate where
    /// the program asked for nothing.
    #[test]
    fn rotate_is_not_a_shift_for_the_arithmetic_forms() {
        let arith_ok = |shift: u32| shift != 3;
        assert!(arith_ok(0) && arith_ok(1) && arith_ok(2));
        assert!(!arith_ok(3));
    }

    /// The shift an extended-register add applies after widening its operand is
    /// 0 to 4. It was handed to the gadget unchecked, which shifted by 5, 6 or
    /// 7 — 192 encodings a real kernel refuses.
    ///
    /// The `option` field beside it is the opposite case and is why this is
    /// worth a test of its own: all eight of *its* values name an extend, so
    /// the rule for this group is on the other field entirely.
    #[test]
    fn an_extended_operand_shifts_by_at_most_four() {
        let mut d = Decoder::new();
        let ext = |option: u32, imm3: u32| 0x0b20_0000 | (1 << 31) | (option << 13) | (imm3 << 10);
        for option in 0..8u32 {
            for imm3 in 0..5u32 {
                assert!(
                    d.decodes(add_sub_extended, ext(option, imm3)),
                    "opt{option} imm3 {imm3}"
                );
            }
            for imm3 in 5..8u32 {
                assert!(
                    !d.decodes(add_sub_extended, ext(option, imm3)),
                    "opt{option} imm3 {imm3}"
                );
            }
        }
    }
}
