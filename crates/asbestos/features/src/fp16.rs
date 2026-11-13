//! Half-precision floating point (FEAT_FP16): the scalar and AdvSIMD
//! instructions that do arithmetic on `half`.
//!
//! # Why software
//!
//! The host CPU (an A9 at the iOS 13 floor) has half-precision *conversions* and
//! nothing else, and doing half arithmetic in single precision and converting
//! back is correct for the operations that round once but not for a fused
//! multiply-add, and it leaves the exception flags, `FPCR.FZ16` and the NaN rules
//! to be reconstructed around it. Every instruction is instead computed here on
//! the bit patterns with `softfloat`/`fpops`, which have the Arm rules spelled
//! out, and checked against a real kernel over every FPCR mode
//! (`tests/guest/src/bin/insn_features.rs`).
//!
//! # Structure
//!
//! [`decode`] turns an encoding into an [`Inst`] and says whether the encoding
//! is half precision at all; [`execute`] runs one on the register file. The
//! gadget passes the whole instruction word, so the decoder in
//! `crates/asbestos/gen` only has to ask [`decode`].

use crate::fpops::*;
use crate::softfloat::*;

/// How many lanes an instruction covers, and whether it writes a vector or a
/// scalar (which zeroes the rest of the register).
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Shape {
    Scalar,
    V4,
    V8,
}

impl Shape {
    fn lanes(self) -> usize {
        match self {
            Shape::Scalar => 1,
            Shape::V4 => 4,
            Shape::V8 => 8,
        }
    }
}

/// A lane-wise binary operation.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Bin {
    Add,
    Sub,
    Mul,
    Nmul,
    Div,
    Max,
    Min,
    MaxNm,
    MinNm,
    MulX,
    Abd,
    RecipStep,
    RsqrtStep,
    CmpEq,
    CmpGe,
    CmpGt,
    Acge,
    Acgt,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Cmp {
    Eq,
    Ge,
    Gt,
    Le,
    Lt,
}

/// A lane-wise unary operation.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Un {
    Abs,
    Neg,
    Sqrt,
    /// Round to integral: the rounding (`None`: FPCR.RMode) and whether Inexact
    /// is raised.
    Rint(Option<Round>, bool),
    RecipEst,
    RsqrtEst,
    RecipX,
    /// Convert to a 16-bit integer with a rounding; unsigned.
    ToInt(Round, bool),
    FromInt(bool),
    /// Compare with zero.
    CmpZero(Cmp),
}

/// The reductions and pairwise operations.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Red {
    Add,
    Max,
    Min,
    MaxNm,
    MinNm,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Op {
    Bin(Bin),
    Un(Un),
    /// `FMLA`/`FMLS`: `Vd += Vn * Vm` fused; `true` negates `Vn` (`FMLS`).
    Mla(bool),
    /// Pairwise over the concatenation of Vn and Vm.
    Pair(Red),
    /// Pairwise of one register into a scalar (`FADDP h0, v1.2h`).
    PairScalar(Red),
    /// Across the lanes into a scalar.
    Across(Red),
    /// The scalar three-source forms: whether `Ha` and `Hn` are negated.
    Fma3(bool, bool),
    Fmov,
    FmovImm,
    /// `FMOV Wd/Xd, Hn`, and `FMOV Hd, Wn/Xn`.
    FmovToGp,
    FmovFromGp,
    Fcmp { signal: bool, zero: bool },
    Fccmp { signal: bool },
    Fcsel,
    /// Half to a general register, with a rounding and signedness.
    ToGp(Round, bool),
    /// A general register integer to half.
    FromGp(bool),
    /// The SIMD fixed-point conversions (fraction bits in `imm`).
    FixedToFp(bool),
    FpToFixed(bool),
    Fcmla,
    Fcadd,
}

/// A decoded instruction.
#[derive(Clone, Copy, Debug)]
pub struct Inst {
    pub op: Op,
    pub shape: Shape,
    pub rd: usize,
    pub rn: usize,
    pub rm: usize,
    pub ra: usize,
    /// The by-element index, fraction bits, condition, rotation or immediate:
    /// per operation.
    pub imm: u32,
    /// A by-element form: `Vm` supplies one lane, `imm` says which.
    pub elem: bool,
    /// A 64-bit general register operand.
    pub wide: bool,
    /// The instruction has fraction bits in `imm` (the fixed-point forms of the
    /// general-register conversions).
    pub fixed: bool,
    pub insn: u32,
}

fn mk(op: Op, shape: Shape, insn: u32) -> Inst {
    Inst {
        op,
        shape,
        rd: (insn & 0x1f) as usize,
        rn: ((insn >> 5) & 0x1f) as usize,
        rm: ((insn >> 16) & 0x1f) as usize,
        ra: ((insn >> 10) & 0x1f) as usize,
        imm: 0,
        elem: false,
        wide: false,
        fixed: false,
        insn,
    }
}

/// What [`decode`] says about an encoding.
#[derive(Debug)]
pub enum Decoded {
    /// Not a half-precision encoding: some other decoder's.
    NotMine,
    /// In the half-precision space and not allocated.
    Undefined,
    Mine(Inst),
}

use Decoded::*;

/// Decode an encoding, or say it is not half precision.
pub fn decode(insn: u32) -> Decoded {
    // The scalar floating-point classes: `M S 0 11110 type ...` with the general
    // register conversions carrying `sf` in bit 31. Type 11 is half.
    if insn & 0x7f00_0000 == 0x1e00_0000 {
        if (insn >> 22) & 3 != 3 {
            return NotMine;
        }
        return scalar_fp(insn);
    }
    if insn & 0xff00_0000 == 0x1f00_0000 {
        if (insn >> 22) & 3 != 3 {
            return NotMine;
        }
        // FMADD, FMSUB, FNMADD, FNMSUB: o1 negates Ha, and o1 ^ o0 negates Hn.
        let (o1, o0) = ((insn >> 21) & 1 != 0, (insn >> 15) & 1 != 0);
        return Mine(mk(Op::Fma3(o1, o1 != o0), Shape::Scalar, insn));
    }
    simd(insn)
}

fn scalar_fp(insn: u32) -> Decoded {
    let sf = insn >> 31 != 0;
    let s = Shape::Scalar;
    if insn & 0x0020_0000 == 0 {
        // Fixed point: `sf 0 0 11110 type 0 rmode(2) opcode(3) scale(6) Rn Rd`.
        let (rmode, opcode) = ((insn >> 19) & 3, (insn >> 16) & 7);
        let scale = (insn >> 10) & 0x3f;
        if !sf && scale & 0x20 == 0 {
            return Undefined;
        }
        let op = match (rmode, opcode) {
            (0, 2) => Op::FromGp(false),
            (0, 3) => Op::FromGp(true),
            (3, 0) => Op::ToGp(Round::Zero, false),
            (3, 1) => Op::ToGp(Round::Zero, true),
            _ => return Undefined,
        };
        let mut i = mk(op, s, insn);
        i.wide = sf;
        i.fixed = true;
        i.imm = 64 - scale;
        return Mine(i);
    }
    if (insn >> 10) & 0x3f == 0 {
        // Float <-> integer: `sf 0 0 11110 type 1 rmode(2) opcode(3) 000000 Rn Rd`.
        let (rmode, opcode) = ((insn >> 19) & 3, (insn >> 16) & 7);
        let op = match (rmode, opcode) {
            (0, 0) => Op::ToGp(Round::Nearest, false),
            (0, 1) => Op::ToGp(Round::Nearest, true),
            (0, 2) => Op::FromGp(false),
            (0, 3) => Op::FromGp(true),
            (0, 4) => Op::ToGp(Round::TieAway, false),
            (0, 5) => Op::ToGp(Round::TieAway, true),
            (0, 6) => Op::FmovToGp,
            (0, 7) => Op::FmovFromGp,
            (1, 0) => Op::ToGp(Round::PlusInf, false),
            (1, 1) => Op::ToGp(Round::PlusInf, true),
            (2, 0) => Op::ToGp(Round::MinusInf, false),
            (2, 1) => Op::ToGp(Round::MinusInf, true),
            (3, 0) => Op::ToGp(Round::Zero, false),
            (3, 1) => Op::ToGp(Round::Zero, true),
            _ => return Undefined,
        };
        let mut i = mk(op, s, insn);
        i.wide = sf;
        return Mine(i);
    }
    if sf {
        return Undefined;
    }
    // The remaining classes have sf = 0 and bit 21 set.
    match (insn >> 10) & 3 {
        0 if (insn >> 12) & 1 == 1 => {
            // FMOV immediate: `... 1 imm8 100 imm5 Rd`, imm5 zero.
            if (insn >> 5) & 0x1f != 0 || (insn >> 10) & 7 != 0b100 {
                return Undefined;
            }
            let mut i = mk(Op::FmovImm, s, insn);
            i.imm = (insn >> 13) & 0xff;
            Mine(i)
        }
        0 if (insn >> 13) & 1 == 1 => {
            // Compare: `... Rm op(2) 1000 Rn opcode2(5)`, op 00.
            if (insn >> 14) & 3 != 0 || insn & 7 != 0 || (insn >> 10) & 0xf != 0b1000 {
                return Undefined;
            }
            let zero = (insn >> 3) & 1 != 0;
            if zero && (insn >> 16) & 0x1f != 0 {
                return Undefined;
            }
            Mine(mk(Op::Fcmp { signal: (insn >> 4) & 1 != 0, zero }, s, insn))
        }
        0 if (insn >> 14) & 1 == 1 => {
            // One source: `... 1 opcode(6) 10000 Rn Rd`.
            if (insn >> 10) & 0x1f != 0b10000 {
                return Undefined;
            }
            let op = match (insn >> 15) & 0x3f {
                0b000000 => Op::Fmov,
                0b000001 => Op::Un(Un::Abs),
                0b000010 => Op::Un(Un::Neg),
                0b000011 => Op::Un(Un::Sqrt),
                0b001000 => Op::Un(Un::Rint(Some(Round::Nearest), false)),
                0b001001 => Op::Un(Un::Rint(Some(Round::PlusInf), false)),
                0b001010 => Op::Un(Un::Rint(Some(Round::MinusInf), false)),
                0b001011 => Op::Un(Un::Rint(Some(Round::Zero), false)),
                0b001100 => Op::Un(Un::Rint(Some(Round::TieAway), false)),
                0b001110 => Op::Un(Un::Rint(None, true)),
                0b001111 => Op::Un(Un::Rint(None, false)),
                // FCVT half to single and double are the baseline conversions.
                0b000100 | 0b000101 => return NotMine,
                _ => return Undefined,
            };
            Mine(mk(op, s, insn))
        }
        0 => Undefined,
        2 => {
            // Two source: opcode 15:12.
            let op = match (insn >> 12) & 0xf {
                0 => Bin::Mul,
                1 => Bin::Div,
                2 => Bin::Add,
                3 => Bin::Sub,
                4 => Bin::Max,
                5 => Bin::Min,
                6 => Bin::MaxNm,
                7 => Bin::MinNm,
                8 => Bin::Nmul,
                _ => return Undefined,
            };
            Mine(mk(Op::Bin(op), s, insn))
        }
        3 => {
            let mut i = mk(Op::Fcsel, s, insn);
            i.imm = (insn >> 12) & 0xf;
            Mine(i)
        }
        _ => {
            // Conditional compare: `... Rm cond 01 Rn op nzcv`.
            let mut i = mk(Op::Fccmp { signal: (insn >> 4) & 1 != 0 }, s, insn);
            i.imm = (insn >> 12) & 0xf;
            Mine(i)
        }
    }
}

fn shape_q(insn: u32) -> Shape {
    if insn >> 30 & 1 != 0 { Shape::V8 } else { Shape::V4 }
}

/// The AdvSIMD half-precision spaces.
fn simd(insn: u32) -> Decoded {
    let (u, a) = ((insn >> 29) & 1, (insn >> 23) & 1);
    // Three same, vector and scalar: `0 Q U 01110 a 10 Rm 00 opcode(3) 1 Rn Rd`.
    let three_v = insn & 0x9f60_c400 == 0x0e40_0400;
    let three_s = insn & 0xdf60_c400 == 0x5e40_0400;
    if three_v || three_s {
        let opcode = (insn >> 11) & 7;
        let shape = if three_s { Shape::Scalar } else { shape_q(insn) };
        // Only the scalar forms whose vector form has a scalar twin exist.
        let op = match (u, a, opcode) {
            (0, 0, 0) => Op::Bin(Bin::MaxNm),
            (0, 0, 1) => Op::Mla(false),
            (0, 0, 2) => Op::Bin(Bin::Add),
            (0, 0, 3) => Op::Bin(Bin::MulX),
            (0, 0, 4) => Op::Bin(Bin::CmpEq),
            (0, 0, 6) => Op::Bin(Bin::Max),
            (0, 0, 7) => Op::Bin(Bin::RecipStep),
            (0, 1, 0) => Op::Bin(Bin::MinNm),
            (0, 1, 1) => Op::Mla(true),
            (0, 1, 2) => Op::Bin(Bin::Sub),
            (0, 1, 6) => Op::Bin(Bin::Min),
            (0, 1, 7) => Op::Bin(Bin::RsqrtStep),
            (1, 0, 0) => Op::Pair(Red::MaxNm),
            (1, 0, 2) => Op::Pair(Red::Add),
            (1, 0, 3) => Op::Bin(Bin::Mul),
            (1, 0, 4) => Op::Bin(Bin::CmpGe),
            (1, 0, 5) => Op::Bin(Bin::Acge),
            (1, 0, 6) => Op::Pair(Red::Max),
            (1, 0, 7) => Op::Bin(Bin::Div),
            (1, 1, 0) => Op::Pair(Red::MinNm),
            (1, 1, 2) => Op::Bin(Bin::Abd),
            (1, 1, 4) => Op::Bin(Bin::CmpGt),
            (1, 1, 5) => Op::Bin(Bin::Acgt),
            (1, 1, 6) => Op::Pair(Red::Min),
            _ => return Undefined,
        };
        if three_s {
            let ok = matches!(
                op,
                Op::Bin(Bin::MulX | Bin::CmpEq | Bin::RecipStep | Bin::RsqrtStep | Bin::CmpGe | Bin::Acge | Bin::Abd | Bin::CmpGt | Bin::Acgt)
            );
            if !ok {
                return Undefined;
            }
        }
        return Mine(mk(op, shape, insn));
    }
    // Two-register miscellaneous: `0 Q U 01110 a 111100 opcode(5) 10 Rn Rd`.
    let misc_v = insn & 0x9f7e_0c00 == 0x0e78_0800;
    let misc_s = insn & 0xdf7e_0c00 == 0x5e78_0800;
    if misc_v || misc_s {
        let opcode = (insn >> 12) & 0x1f;
        let shape = if misc_s { Shape::Scalar } else { shape_q(insn) };
        let r = Some;
        let op = match (u, a, opcode) {
            (0, 0, 0b11000) => Un::Rint(r(Round::Nearest), false),
            (0, 0, 0b11001) => Un::Rint(r(Round::MinusInf), false),
            (0, 0, 0b11010) => Un::ToInt(Round::Nearest, false),
            (0, 0, 0b11011) => Un::ToInt(Round::MinusInf, false),
            (0, 0, 0b11100) => Un::ToInt(Round::TieAway, false),
            (0, 0, 0b11101) => Un::FromInt(false),
            (0, 1, 0b01100) => Un::CmpZero(Cmp::Gt),
            (0, 1, 0b01101) => Un::CmpZero(Cmp::Eq),
            (0, 1, 0b01110) => Un::CmpZero(Cmp::Lt),
            (0, 1, 0b01111) => Un::Abs,
            (0, 1, 0b11000) => Un::Rint(r(Round::PlusInf), false),
            (0, 1, 0b11001) => Un::Rint(r(Round::Zero), false),
            (0, 1, 0b11010) => Un::ToInt(Round::PlusInf, false),
            (0, 1, 0b11011) => Un::ToInt(Round::Zero, false),
            (0, 1, 0b11101) => Un::RecipEst,
            (0, 1, 0b11111) => Un::RecipX,
            (1, 0, 0b11000) => Un::Rint(r(Round::TieAway), false),
            (1, 0, 0b11001) => Un::Rint(None, true),
            (1, 0, 0b11010) => Un::ToInt(Round::Nearest, true),
            (1, 0, 0b11011) => Un::ToInt(Round::MinusInf, true),
            (1, 0, 0b11100) => Un::ToInt(Round::TieAway, true),
            (1, 0, 0b11101) => Un::FromInt(true),
            (1, 1, 0b01100) => Un::CmpZero(Cmp::Ge),
            (1, 1, 0b01101) => Un::CmpZero(Cmp::Le),
            (1, 1, 0b01111) => Un::Neg,
            (1, 1, 0b11001) => Un::Rint(None, false),
            (1, 1, 0b11010) => Un::ToInt(Round::PlusInf, true),
            (1, 1, 0b11011) => Un::ToInt(Round::Zero, true),
            (1, 1, 0b11101) => Un::RsqrtEst,
            (1, 1, 0b11111) => Un::Sqrt,
            _ => return Undefined,
        };
        // The scalar forms have no rounding, abs, neg or sqrt, and FRECPX has
        // no vector form.
        let scalar_ok = matches!(op, Un::ToInt(..) | Un::FromInt(_) | Un::CmpZero(_) | Un::RecipEst | Un::RecipX | Un::RsqrtEst);
        if misc_s && !scalar_ok || misc_v && matches!(op, Un::RecipX) {
            return Undefined;
        }
        return Mine(mk(Op::Un(op), shape, insn));
    }
    // Across lanes: `0 Q U 01110 a 11 0000 opcode(5) 10 Rn Rd`.
    if insn & 0x9f7e_0c00 == 0x0e30_0800 {
        let red = match (u, a, (insn >> 12) & 0x1f) {
            (0, 0, 0b01100) => Red::MaxNm,
            (0, 1, 0b01100) => Red::MinNm,
            (0, 0, 0b01111) => Red::Max,
            (0, 1, 0b01111) => Red::Min,
            _ => return NotMine,
        };
        return Mine(mk(Op::Across(red), shape_q(insn), insn));
    }
    // Scalar pairwise: `01 U 11110 a 11 0000 opcode(5) 10 Rn Rd`.
    if insn & 0xdf7e_0c00 == 0x5e30_0800 {
        let red = match (u, a, (insn >> 12) & 0x1f) {
            // U is 0 for all five in half precision; the single and double
            // forms, which have U = 1, are the baseline decoders'.
            (0, 0, 0b01101) => Red::Add,
            (0, 0, 0b01100) => Red::MaxNm,
            (0, 1, 0b01100) => Red::MinNm,
            (0, 0, 0b01111) => Red::Max,
            (0, 1, 0b01111) => Red::Min,
            _ => return NotMine,
        };
        return Mine(mk(Op::PairScalar(red), Shape::Scalar, insn));
    }
    // By element: `0 Q U 01111 00 L M Rm opcode(4) H 0 Rn Rd` (size 00 is half).
    let elem_v = insn & 0x9fc0_0400 == 0x0f00_0000;
    let elem_s = insn & 0xdfc0_0400 == 0x5f00_0000;
    if elem_v || elem_s {
        let op = match (u, (insn >> 12) & 0xf) {
            (0, 0b0001) => Op::Mla(false),
            (0, 0b0101) => Op::Mla(true),
            (0, 0b1001) => Op::Bin(Bin::Mul),
            (1, 0b1001) => Op::Bin(Bin::MulX),
            _ => return NotMine,
        };
        let mut i = mk(op, if elem_s { Shape::Scalar } else { shape_q(insn) }, insn);
        i.elem = true;
        // Rm is four bits here, and the index is H:L:M.
        i.rm = ((insn >> 16) & 0xf) as usize;
        i.imm = ((insn >> 11) & 1) << 2 | ((insn >> 21) & 1) << 1 | ((insn >> 20) & 1);
        return Mine(i);
    }
    // Shift by immediate: the fixed-point conversions at immh = 001x.
    let sh_v = insn & 0x9f80_0400 == 0x0f00_0400;
    let sh_s = insn & 0xdf80_0400 == 0x5f00_0400;
    if (sh_v || sh_s) && (insn >> 20) & 7 == 1 {
        let opcode = (insn >> 11) & 0x1f;
        let op = match (u, opcode) {
            (0, 0b11100) => Op::FixedToFp(false),
            (1, 0b11100) => Op::FixedToFp(true),
            (0, 0b11111) => Op::FpToFixed(false),
            (1, 0b11111) => Op::FpToFixed(true),
            _ => return NotMine,
        };
        let mut i = mk(op, if sh_s { Shape::Scalar } else { shape_q(insn) }, insn);
        i.imm = 32 - ((insn >> 16) & 0x7f);
        return Mine(i);
    }
    // FMOV (vector, immediate), half: `0 Q 0 0111100000 abc 1111 11 defgh Rd`.
    if insn & 0xbff8_fc00 == 0x0f00_fc00 {
        let mut i = mk(Op::FmovImm, shape_q(insn), insn);
        i.imm = ((insn >> 16) & 7) << 5 | ((insn >> 5) & 0x1f);
        return Mine(i);
    }
    // FCMLA and FCADD, half: the `size = 01` forms of the FCMA encodings.
    let size = (insn >> 22) & 3;
    if size == 1 {
        if insn & 0xbf20_e400 == 0x2e00_c400 {
            let mut i = mk(Op::Fcmla, shape_q(insn), insn);
            i.imm = (insn >> 11) & 3;
            return Mine(i);
        }
        if insn & 0xbf20_ec00 == 0x2e00_e400 {
            let mut i = mk(Op::Fcadd, shape_q(insn), insn);
            i.imm = (insn >> 12) & 1;
            return Mine(i);
        }
        if insn & 0xbf00_9400 == 0x2f00_1000 {
            // The 64-bit form has two complex numbers, so H (the high bit of the
            // index) must be 0.
            if (insn >> 30) & 1 == 0 && (insn >> 11) & 1 == 1 {
                return Undefined;
            }
            let mut i = mk(Op::Fcmla, shape_q(insn), insn);
            i.elem = true;
            i.imm = (insn >> 13) & 3;
            // The pair index is H:L.
            i.rm = ((insn >> 16) & 0x1f) as usize;
            i.wide = false;
            return Mine(i);
        }
    }
    NotMine
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// The registers an instruction reads and writes.
pub struct Regs<'a> {
    pub fp: &'a mut [[u64; 2]; 32],
    /// x0-x30; register 31 is not here (it is XZR to these instructions).
    pub x: &'a mut [u64; 31],
    /// The condition flags in bits 31:28.
    pub nzcv: &'a mut u32,
}

fn lane(q: [u64; 2], i: usize) -> u16 {
    (q[i / 4] >> (16 * (i % 4))) as u16
}

fn pack(lanes: &[u16; 8], n: usize) -> [u64; 2] {
    let mut o = [0u64; 2];
    for (i, &l) in lanes.iter().enumerate().take(n) {
        o[i / 4] |= (l as u64) << (16 * (i % 4));
    }
    o
}

fn env_of(fpcr: u64) -> Env {
    let fz = fpcr & (1 << 19) != 0;
    Env { fz, fz_out: fz, dn: fpcr & (1 << 25) != 0, idc: false }
}

const H: Fmt = HALF;

fn cmp_mask(b: bool) -> u16 {
    if b { 0xffff } else { 0 }
}

fn bin(op: Bin, a: u16, b: u16, env: Env, rm: Round, flags: &mut u8) -> u16 {
    let (x, y) = (a as u64, b as u64);
    (match op {
        Bin::Add => fpadd(x, y, H, env, rm, flags),
        Bin::Sub => fpsub(x, y, H, env, rm, flags),
        Bin::Mul => fpmul(x, y, H, env, rm, flags),
        Bin::Nmul => neg(fpmul(x, y, H, env, rm, flags), H),
        Bin::Div => fpdiv(x, y, H, env, rm, flags),
        Bin::Max => fpmaxmin(x, y, true, false, H, env, flags),
        Bin::Min => fpmaxmin(x, y, false, false, H, env, flags),
        Bin::MaxNm => fpmaxmin(x, y, true, true, H, env, flags),
        Bin::MinNm => fpmaxmin(x, y, false, true, H, env, flags),
        Bin::MulX => fpmulx(x, y, H, env, rm, flags),
        Bin::Abd => abs(fpsub(x, y, H, env, rm, flags), H),
        Bin::RecipStep => fprecps(x, y, H, env, rm, flags),
        Bin::RsqrtStep => fprsqrts(x, y, H, env, rm, flags),
        Bin::CmpEq => cmp_mask(fpcompare_bool(x, y, 0, H, env, flags)) as u64,
        Bin::CmpGe => cmp_mask(fpcompare_bool(x, y, 1, H, env, flags)) as u64,
        Bin::CmpGt => cmp_mask(fpcompare_bool(x, y, 2, H, env, flags)) as u64,
        Bin::Acge => cmp_mask(fpcompare_bool(abs(x, H), abs(y, H), 1, H, env, flags)) as u64,
        Bin::Acgt => cmp_mask(fpcompare_bool(abs(x, H), abs(y, H), 2, H, env, flags)) as u64,
    }) as u16
}

fn un(op: Un, a: u16, env: Env, rm: Round, flags: &mut u8) -> u16 {
    let x = a as u64;
    (match op {
        Un::Abs => abs(x, H),
        Un::Neg => neg(x, H),
        Un::Sqrt => fpsqrt(x, H, env, rm, flags),
        Un::Rint(mode, exact) => fprint(x, mode.unwrap_or(rm), exact, H, env, flags),
        Un::RecipEst => fprecpe(x, H, env, rm, flags),
        Un::RsqrtEst => fprsqrte(x, H, env, flags),
        Un::RecipX => fprecpx(x, H, env, flags),
        Un::ToInt(mode, unsigned) => fp_to_int(x, 0, unsigned, 16, mode, H, env, flags),
        Un::FromInt(unsigned) => int_to_fp(x, !unsigned, 16, 0, H, env, rm, flags),
        Un::CmpZero(c) => {
            let zero = 0u64;
            cmp_mask(match c {
                Cmp::Eq => fpcompare_bool(x, zero, 0, H, env, flags),
                Cmp::Ge => fpcompare_bool(x, zero, 1, H, env, flags),
                Cmp::Gt => fpcompare_bool(x, zero, 2, H, env, flags),
                Cmp::Le => fpcompare_bool(zero, x, 1, H, env, flags),
                Cmp::Lt => fpcompare_bool(zero, x, 2, H, env, flags),
            }) as u64
        }
    }) as u16
}

fn reduce(red: Red, v: &[u16], env: Env, rm: Round, flags: &mut u8) -> u16 {
    if v.len() == 1 {
        return v[0];
    }
    let (lo, hi) = v.split_at(v.len() / 2);
    let (lo, hi) = (reduce(red, lo, env, rm, flags), reduce(red, hi, env, rm, flags));
    let (x, y) = (lo as u64, hi as u64);
    (match red {
        Red::Add => fpadd(x, y, H, env, rm, flags),
        Red::Max => fpmaxmin(x, y, true, false, H, env, flags),
        Red::Min => fpmaxmin(x, y, false, false, H, env, flags),
        Red::MaxNm => fpmaxmin(x, y, true, true, H, env, flags),
        Red::MinNm => fpmaxmin(x, y, false, true, H, env, flags),
    }) as u16
}

/// `FCMP`-style flags to the NZCV register.
fn set_nzcv(r: &mut Regs, flags: u32) {
    *r.nzcv = flags << 28;
}

/// The condition `cond` against the flags in `nzcv` (bits 31:28).
fn cond_holds(cond: u32, nzcv: u32) -> bool {
    let (n, z, c, v) = (nzcv >> 31 & 1 != 0, nzcv >> 30 & 1 != 0, nzcv >> 29 & 1 != 0, nzcv >> 28 & 1 != 0);
    let base = match cond >> 1 {
        0 => z,
        1 => c,
        2 => n,
        3 => v,
        4 => c && !z,
        5 => n == v,
        6 => n == v && !z,
        _ => true,
    };
    if cond & 1 != 0 && cond != 0b1111 { !base } else { base }
}

fn vfp_expand_half(imm8: u32) -> u16 {
    let (sign, b, cd, efgh) = ((imm8 >> 7) & 1, (imm8 >> 6) & 1, (imm8 >> 4) & 3, imm8 & 0xf);
    ((sign << 15) | ((b ^ 1) << 14) | ((if b == 1 { 3 } else { 0 }) << 12) | (cd << 10) | (efgh << 6)) as u16
}

/// Run one instruction. Returns the FPSR flags to set.
pub fn execute(i: &Inst, r: &mut Regs, fpcr: u64) -> u8 {
    let mut flags = 0u8;
    let env = env_of(fpcr);
    let rm = Round::from_rmode(fpcr >> 22);
    let n = i.shape.lanes();
    let vn = r.fp[i.rn];
    let vm = r.fp[i.rm];
    let vd = r.fp[i.rd];
    // Vm as lanes: a broadcast lane for the by-element forms.
    let m_lane = |k: usize| -> u16 { if i.elem { lane(vm, i.imm as usize) } else { lane(vm, k) } };
    let mut out = [0u16; 8];
    let mut result: Option<[u64; 2]> = None;
    match i.op {
        Op::Bin(b) => {
            for (k, o) in out.iter_mut().enumerate().take(n) {
                *o = bin(b, lane(vn, k), m_lane(k), env, rm, &mut flags);
            }
        }
        Op::Un(u) => {
            for (k, o) in out.iter_mut().enumerate().take(n) {
                *o = un(u, lane(vn, k), env, rm, &mut flags);
            }
        }
        Op::Mla(neg_n) => {
            for (k, o) in out.iter_mut().enumerate().take(n) {
                let a = lane(vn, k) as u64;
                let a = if neg_n { neg(a, H) } else { a };
                *o = fpmuladd(lane(vd, k) as u64, a, m_lane(k) as u64, H, env, rm, &mut flags) as u16;
            }
        }
        Op::Pair(red) => {
            let mut all = [0u16; 16];
            for k in 0..n {
                all[k] = lane(vn, k);
                all[n + k] = lane(vm, k);
            }
            for (k, o) in out.iter_mut().enumerate().take(n) {
                *o = reduce(red, &all[2 * k..2 * k + 2], env, rm, &mut flags);
            }
        }
        Op::PairScalar(red) => {
            out[0] = reduce(red, &[lane(vn, 0), lane(vn, 1)], env, rm, &mut flags);
        }
        Op::Across(red) => {
            let v: Vec<u16> = (0..n).map(|k| lane(vn, k)).collect();
            out[0] = reduce(red, &v, env, rm, &mut flags);
            // The result is a scalar: the rest of the register is zero.
            r.fp[i.rd] = pack(&out, 1);
            return flags;
        }
        Op::Fma3(neg_a, neg_n) => {
            let a = lane(r.fp[i.ra], 0) as u64;
            let a = if neg_a { neg(a, H) } else { a };
            let x = lane(vn, 0) as u64;
            let x = if neg_n { neg(x, H) } else { x };
            out[0] = fpmuladd(a, x, lane(vm, 0) as u64, H, env, rm, &mut flags) as u16;
        }
        Op::Fmov => out[0] = lane(vn, 0),
        Op::FmovImm => {
            let v = vfp_expand_half(i.imm);
            for o in out.iter_mut().take(if i.shape == Shape::Scalar { 1 } else { n }) {
                *o = v;
            }
        }
        Op::FmovToGp => {
            let v = lane(vn, 0) as u64;
            write_x(r, i.rd, v);
            return 0;
        }
        Op::FmovFromGp => {
            out[0] = read_x(r, i.rn) as u16;
        }
        Op::Fcmp { signal, zero } => {
            let b = if zero { 0 } else { lane(vm, 0) as u64 };
            let f = fpcompare(lane(vn, 0) as u64, b, signal, H, env, &mut flags);
            set_nzcv(r, f);
            return flags;
        }
        Op::Fccmp { signal } => {
            if cond_holds(i.imm, *r.nzcv) {
                let f = fpcompare(lane(vn, 0) as u64, lane(vm, 0) as u64, signal, H, env, &mut flags);
                set_nzcv(r, f);
            } else {
                set_nzcv(r, i.insn & 0xf);
            }
            return flags;
        }
        Op::Fcsel => {
            out[0] = if cond_holds(i.imm, *r.nzcv) { lane(vn, 0) } else { lane(vm, 0) };
        }
        Op::ToGp(mode, unsigned) => {
            let width = if i.wide { 64 } else { 32 };
            let fbits = if i.fixed { i.imm } else { 0 };
            let v = fp_to_int(lane(vn, 0) as u64, fbits, unsigned, width, mode, H, env, &mut flags);
            write_x(r, i.rd, v);
            return flags;
        }
        Op::FromGp(unsigned) => {
            let width = if i.wide { 64 } else { 32 };
            let fbits = if i.fixed { i.imm } else { 0 };
            out[0] = int_to_fp(read_x(r, i.rn), !unsigned, width, fbits, H, env, rm, &mut flags) as u16;
        }
        Op::FixedToFp(unsigned) => {
            for (k, o) in out.iter_mut().enumerate().take(n) {
                *o = int_to_fp(lane(vn, k) as u64, !unsigned, 16, i.imm, H, env, rm, &mut flags) as u16;
            }
        }
        Op::FpToFixed(unsigned) => {
            for (k, o) in out.iter_mut().enumerate().take(n) {
                *o = fp_to_int(lane(vn, k) as u64, i.imm, unsigned, 16, Round::Zero, H, env, &mut flags) as u16;
            }
        }
        Op::Fcmla => {
            // Pairs (re, im): the multiplicand is Vn's re or im duplicated, the
            // multiplier Vm (negated and swapped by rotation), fused into Vd.
            let rot = i.imm;
            let pairs = n / 2;
            for p in 0..pairs {
                let (nre, nim) = (lane(vn, 2 * p) as u64, lane(vn, 2 * p + 1) as u64);
                let mp = if i.elem { i.imm_pair() } else { p };
                let (mre, mim) = if i.elem { (lane(vm, 2 * mp) as u64, lane(vm, 2 * mp + 1) as u64) } else { (lane(vm, 2 * p) as u64, lane(vm, 2 * p + 1) as u64) };
                let (dre, dim) = (lane(vd, 2 * p) as u64, lane(vd, 2 * p + 1) as u64);
                let (n1, m1, m2) = match rot {
                    0 => (nre, mre, mim),
                    1 => (nim, neg(mim, H), mre),
                    2 => (nre, neg(mre, H), neg(mim, H)),
                    _ => (nim, mim, neg(mre, H)),
                };
                out[2 * p] = fpmuladd(dre, n1, m1, H, env, rm, &mut flags) as u16;
                out[2 * p + 1] = fpmuladd(dim, n1, m2, H, env, rm, &mut flags) as u16;
            }
        }
        Op::Fcadd => {
            let pairs = n / 2;
            for p in 0..pairs {
                let (nre, nim) = (lane(vn, 2 * p) as u64, lane(vn, 2 * p + 1) as u64);
                let (mre, mim) = (lane(vm, 2 * p) as u64, lane(vm, 2 * p + 1) as u64);
                let (a, b) = if i.imm == 0 { (neg(mim, H), mre) } else { (mim, neg(mre, H)) };
                out[2 * p] = fpadd(nre, a, H, env, rm, &mut flags) as u16;
                out[2 * p + 1] = fpadd(nim, b, H, env, rm, &mut flags) as u16;
            }
        }
    }
    let _ = &mut result;
    r.fp[i.rd] = result.unwrap_or_else(|| pack(&out, n));
    flags
}

impl Inst {
    /// The complex-pair index of a by-element `FCMLA`: H:L.
    fn imm_pair(&self) -> usize {
        (((self.insn >> 11) & 1) << 1 | ((self.insn >> 21) & 1)) as usize
    }
}

fn read_x(r: &Regs, n: usize) -> u64 {
    if n == 31 { 0 } else { r.x[n] }
}

fn write_x(r: &mut Regs, n: usize, v: u64) {
    if n != 31 {
        r.x[n] = v;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op_of(insn: u32) -> Op {
        match decode(insn) {
            Mine(i) => i.op,
            other => panic!("{insn:08x} decoded as {other:?}"),
        }
    }

    /// One encoding of each family, from the assembler, decodes as itself.
    #[test]
    fn each_family_decodes() {
        assert_eq!(op_of(0x0f03_fe00), Op::FmovImm, "fmov v0.4h, #1.0");
        assert_eq!(op_of(0x1eee_1000), Op::FmovImm, "fmov h0, #1.0");
        assert_eq!(op_of(0x1ee6_0020), Op::FmovToGp, "fmov w0, h1");
        assert_eq!(op_of(0x9ee7_0020), Op::FmovFromGp, "fmov h0, x1");
        assert_eq!(op_of(0x1ee2_0020), Op::FromGp(false), "scvtf h0, w1");
        assert_eq!(op_of(0x1ee4_0020), Op::ToGp(Round::TieAway, false), "fcvtas w0, h1");
        assert_eq!(op_of(0x1fc2_0c20), Op::Fma3(false, false), "fmadd h0, h1, h2, h3");
        assert_eq!(op_of(0x1ee1_2000), Op::Fcmp { signal: false, zero: false }, "fcmp h0, h1");
        assert_eq!(op_of(0x1ee0_2008), Op::Fcmp { signal: false, zero: true }, "fcmp h0, #0.0");
        assert_eq!(op_of(0x1ee1_2010), Op::Fcmp { signal: true, zero: false }, "fcmpe h0, h1");
        assert_eq!(op_of(0x1ee2_1c20), Op::Fcsel, "fcsel h0, h1, h2, ne");
        assert_eq!(op_of(0x5e42_1c20), Op::Bin(Bin::MulX), "fmulx h0, h1, h2");
        assert_eq!(op_of(0x5ef9_d820), Op::Un(Un::RecipEst), "frecpe h0, h1");
        assert_eq!(op_of(0x5ef9_f820), Op::Un(Un::RecipX), "frecpx h0, h1");
        assert_eq!(op_of(0x5e30_d820), Op::PairScalar(Red::Add), "faddp h0, v1.2h");
        assert_eq!(op_of(0x4e30_f820), Op::Across(Red::Max), "fmaxv h0, v1.8h");
        assert_eq!(op_of(0x4f32_1020), Op::Mla(false), "fmla v0.8h, v1.8h, v2.h[3]");
        assert_eq!(op_of(0x5f32_9820), Op::Bin(Bin::Mul), "fmul h0, h1, v2.h[7]");
        assert_eq!(op_of(0x4f1d_e420), Op::FixedToFp(false), "scvtf v0.8h, v1.8h, #3");
        assert_eq!(op_of(0x5f1d_fc20), Op::FpToFixed(false), "fcvtzs h0, h1, #3");
        assert_eq!(op_of(0x6e42_3c20), Op::Bin(Bin::Div), "fdiv v0.8h, v1.8h, v2.8h");
        assert_eq!(op_of(0x7ec2_1420), Op::Bin(Bin::Abd), "fabd h0, h1, h2");
    }

    /// Neighbours that are not half precision are left to the other decoders.
    #[test]
    fn other_encodings_are_not_claimed() {
        assert!(matches!(decode(0x1e20_4020), NotMine), "fmov s0, s1");
        assert!(matches!(decode(0x1e62_2820), NotMine), "fadd d0, d1, d2");
        assert!(matches!(decode(0x0e20_1c00), NotMine), "and v0.8b");
        // FCVT half <-> single: the baseline conversions.
        assert!(matches!(decode(0x1ee2_4020), NotMine), "fcvt s0, h1");
    }

    fn run(insn: u32, setup: impl FnOnce(&mut [[u64; 2]; 32]), fpcr: u64) -> ([[u64; 2]; 32], u8) {
        let Mine(i) = decode(insn) else { panic!("{insn:08x}") };
        let mut fp = [[0u64; 2]; 32];
        setup(&mut fp);
        let (mut x, mut nzcv) = ([0u64; 31], 0u32);
        let flags = execute(&i, &mut Regs { fp: &mut fp, x: &mut x, nzcv: &mut nzcv }, fpcr);
        (fp, flags)
    }

    /// Measured on a real kernel: `frsqrte v0.4h, v1.4h` of the subnormals 0..3.
    #[test]
    fn the_reciprocal_square_root_estimate_of_subnormals() {
        let (fp, _) = run(0x2ef9_d820, |fp| fp[1] = [0x0003_0002_0001_0000, 0], 0);
        assert_eq!(fp[0][0], 0x689c_69a4_6bfc_7c00);
    }

    /// Measured: `fcvtzs h1, h23, #4` of 0x3f79 (1.868...) truncates
    /// 29.9 to 29, inexact.
    #[test]
    fn fixed_point_conversion_truncates() {
        let (fp, flags) = run(0x5f1c_fee1, |fp| fp[23] = [0x3f79, 0], 0);
        assert_eq!(fp[1][0], 0x1d);
        assert_eq!(flags, IXC);
    }

    #[test]
    fn a_scalar_write_zeroes_the_rest_of_the_register() {
        let (fp, _) = run(
            0x1ee0_4020,
            |fp| {
                fp[0] = [u64::MAX, u64::MAX];
                fp[1] = [0x3c00, 0x1234];
            },
            0,
        );
        assert_eq!(fp[0], [0x3c00, 0]);
    }

    /// FZ16 flushes a subnormal operand without raising Input Denormal.
    #[test]
    fn fz16_flushes_silently() {
        // fadd h0, h1, h2 with h1 subnormal and h2 = 1.0: the flushed operand
        // adds nothing, and no flag is raised.
        let (fp, flags) = run(
            0x1ee2_2820,
            |fp| {
                fp[1] = [0x0001, 0];
                fp[2] = [0x3c00, 0];
            },
            1 << 19,
        );
        assert_eq!(fp[0][0], 0x3c00);
        assert_eq!(flags, 0);
    }
}
