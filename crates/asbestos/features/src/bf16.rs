//! BF16 (FEAT_BF16): `BFDOT`, `BFMMLA`, `BFMLALB`/`BFMLALT` and the
//! `BFCVT*` conversions.
//!
//! # The standard behaviours
//!
//! `BFDOT` and `BFMMLA` with `FPCR.EBF` clear do not follow FPCR at all. Measured
//! on a real arm64 kernel over 68,224 cases in every FPCR rounding mode, FZ and DN
//! combination, with subnormal, infinite, NaN and overflowing operands:
//!
//! - subnormal inputs are read as zero and subnormal results are zero, and
//!   neither raises a flag;
//! - a NaN in, or made by, the operation is the default NaN, quiet, no flag;
//! - the products are exact and the two sums (products with each other, then the
//!   accumulator) are single-precision **round-to-odd**, which overflows to
//!   infinity;
//! - the FPSR cumulative flags are never set.
//!
//! That is the Arm pseudocode's `BFAdd`/`BFMul` with a fixed environment, and it
//! is what a non-EBF16 implementation has to produce, which is why it is the one
//! modelled (ID_AA64ISAR1_EL1.BF16 = 1).

use crate::softfloat::*;

/// The fixed environment of `BFDOT` and `BFMMLA`.
const STD: Env = Env { fz: true, fz_out: true, dn: true, idc: true };

/// A bfloat16 as the single it widens to.
fn widen(x: u16) -> u64 {
    (x as u64) << 16
}

/// `BFMul`: two bfloat16 values multiplied exactly into a single.
fn bfmul(a: u16, b: u16) -> u32 {
    fpmul(widen(a), widen(b), SINGLE, STD, Round::Nearest, &mut 0) as u32
}

/// `BFAdd`: single-precision addition rounded to odd.
fn bfadd(a: u32, b: u32) -> u32 {
    fpadd(a as u64, b as u64, SINGLE, STD, Round::Odd, &mut 0) as u32
}

/// `BFDotAdd`: `acc + a0*b0 + a1*b1`.
pub fn bfdot(acc: u32, a: [u16; 2], b: [u16; 2]) -> u32 {
    bfadd(acc, bfadd(bfmul(a[0], b[0]), bfmul(a[1], b[1])))
}

// ---------------------------------------------------------------------------
// The instructions
// ---------------------------------------------------------------------------

/// The BF16 instructions, told apart by encoding.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Op {
    /// `BFDOT Vd.{2S,4S}, Vn.{4H,8H}, Vm.{4H,8H}`
    Dot,
    /// `BFDOT Vd, Vn, Vm.2H[index]`
    DotElem,
    /// `BFMMLA Vd.4S, Vn.8H, Vm.8H`
    Mmla,
    /// `BFMLALB`/`BFMLALT` Vd.4S, Vn.8H, Vm.8H
    MlalB,
    MlalT,
    /// The same by element, `Vm.H[index]`.
    MlalBElem,
    MlalTElem,
    /// `BFCVT Hd, Sn`
    Cvt,
    /// `BFCVTN Vd.4H, Vn.4S` and `BFCVTN2 Vd.8H, Vn.4S`
    Cvtn,
    Cvtn2,
}

pub(crate) const OPS: [Op; 10] = [
    Op::Dot, Op::DotElem, Op::Mmla, Op::MlalB, Op::MlalT, Op::MlalBElem, Op::MlalTElem, Op::Cvt, Op::Cvtn, Op::Cvtn2,
];

impl Op {
    /// Which instruction an encoding is, or `None`.
    pub fn decode(insn: u32) -> Option<Op> {
        Some(if insn & 0xbfe0_fc00 == 0x2e40_fc00 {
            Op::Dot
        } else if insn & 0xbfc0_f400 == 0x0f40_f000 {
            Op::DotElem
        } else if insn & 0xffe0_fc00 == 0x6e40_ec00 {
            Op::Mmla
        } else if insn & 0xbfe0_fc00 == 0x2ec0_fc00 {
            if insn >> 30 & 1 == 0 { Op::MlalB } else { Op::MlalT }
        } else if insn & 0xbfc0_f400 == 0x0fc0_f000 {
            if insn >> 30 & 1 == 0 { Op::MlalBElem } else { Op::MlalTElem }
        } else if insn & 0xffff_fc00 == 0x1e63_4000 {
            Op::Cvt
        } else if insn & 0xbfff_fc00 == 0x0ea1_6800 {
            if insn >> 30 & 1 == 0 { Op::Cvtn } else { Op::Cvtn2 }
        } else {
            return None;
        })
    }

    fn code(self) -> u64 {
        OPS.iter().position(|&o| o == self).unwrap() as u64
    }
}

fn lanes16(q: [u64; 2]) -> [u16; 8] {
    std::array::from_fn(|i| (q[i / 4] >> (16 * (i % 4))) as u16)
}
fn lanes32(q: [u64; 2]) -> [u32; 4] {
    std::array::from_fn(|i| (q[i / 2] >> (32 * (i % 2))) as u32)
}
fn from32(l: [u32; 4]) -> [u64; 2] {
    [l[0] as u64 | (l[1] as u64) << 32, l[2] as u64 | (l[3] as u64) << 32]
}

/// Run one instruction on the register file. Returns the FPSR flags to set.
pub fn execute(op: Op, insn: u32, fp: &mut [[u64; 2]; 32], fpcr: u64) -> u8 {
    let rd = (insn & 0x1f) as usize;
    let rn = ((insn >> 5) & 0x1f) as usize;
    let rm = ((insn >> 16) & 0x1f) as usize;
    let q = insn >> 30 & 1 != 0;
    let (l, h, m) = (insn >> 21 & 1, insn >> 11 & 1, insn >> 20 & 1);
    let (n, acc) = (lanes16(fp[rn]), lanes32(fp[rd]));
    let mut flags = 0;
    let env = Env::from_fpcr(fpcr);
    let rounding = Round::from_rmode(fpcr >> 22);
    let out: [u64; 2] = match op {
        Op::Dot | Op::DotElem => {
            let m16 = if op == Op::Dot {
                lanes16(fp[rm])
            } else {
                // The element is a pair of bfloat16 (32 bits), index H:L, and
                // Rm is five bits.
                let idx = (h << 1 | l) as usize;
                let pair = [lanes16(fp[rm])[2 * idx], lanes16(fp[rm])[2 * idx + 1]];
                [pair[0], pair[1], pair[0], pair[1], pair[0], pair[1], pair[0], pair[1]]
            };
            let lanes = if q { 4 } else { 2 };
            let mut o = [0u32; 4];
            for i in 0..lanes {
                o[i] = bfdot(acc[i], [n[2 * i], n[2 * i + 1]], [m16[2 * i], m16[2 * i + 1]]);
            }
            from32(o)
        }
        Op::Mmla => {
            let m16 = lanes16(fp[rm]);
            let mut o = [0u32; 4];
            for i in 0..2 {
                for j in 0..2 {
                    let (a, b) = (&n[4 * i..4 * i + 4], &m16[4 * j..4 * j + 4]);
                    let t = bfdot(acc[2 * i + j], [a[0], a[1]], [b[0], b[1]]);
                    o[2 * i + j] = bfdot(t, [a[2], a[3]], [b[2], b[3]]);
                }
            }
            from32(o)
        }
        Op::MlalB | Op::MlalT | Op::MlalBElem | Op::MlalTElem => {
            let top = matches!(op, Op::MlalT | Op::MlalTElem) as usize;
            let elem = matches!(op, Op::MlalBElem | Op::MlalTElem);
            // By element Rm is four bits and the index is H:L:M.
            let (m16, rm) = if elem { (lanes16(fp[rm & 0xf]), rm & 0xf) } else { (lanes16(fp[rm]), rm) };
            let _ = rm;
            let idx = (h << 2 | l << 1 | m) as usize;
            let mut o = [0u32; 4];
            for i in 0..4 {
                let b = if elem { m16[idx] } else { m16[2 * i + top] };
                o[i] = fpmuladd(acc[i] as u64, widen(n[2 * i + top]), widen(b), SINGLE, env, rounding, &mut flags) as u32;
            }
            from32(o)
        }
        Op::Cvt => {
            let x = lanes32(fp[rn])[0];
            [f32_to_bf16(x, env, rounding, &mut flags) as u64, 0]
        }
        Op::Cvtn | Op::Cvtn2 => {
            let x = lanes32(fp[rn]);
            let mut half = 0u64;
            for (i, v) in x.iter().enumerate() {
                half |= (f32_to_bf16(*v, env, rounding, &mut flags) as u64) << (16 * i);
            }
            if op == Op::Cvtn { [half, 0] } else { [fp[rd][0], half] }
        }
    };
    fp[rd] = out;
    flags
}

/// The word the decoder emits for `insn`, or `None` if it is not a BF16 one.
pub fn pack(insn: u32) -> Option<u64> {
    Some(insn as u64 | Op::decode(insn)?.code() << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bf(x: f32) -> u16 {
        (x.to_bits() >> 16) as u16
    }

    #[test]
    fn a_dot_product_is_exact_for_small_values() {
        // 1*2 + 3*4 + 5 = 19
        let r = bfdot(5.0f32.to_bits(), [bf(1.0), bf(3.0)], [bf(2.0), bf(4.0)]);
        assert_eq!(f32::from_bits(r), 19.0);
    }

    /// A row of measurements from a real kernel: acc, a0, a1, b0, b1, result.
    #[test]
    fn round_to_odd_matches_the_hardware() {
        let rows: [(u32, u16, u16, u16, u16, u32); 4] = [
            (0x40585f6c, 0x3fcf, 0xc369, 0xbce7, 0x3fb5, 0xc3a31219),
            (0x4576956b, 0xbd7a, 0x42bf, 0x3df6, 0xc20d, 0x4410bd30),
            (0xc4033204, 0x3d98, 0x428f, 0x41fd, 0x42ee, 0x45f99085),
            (0x3a79b4ad, 0xbe4c, 0xbc3d, 0x4293, 0x3e75, 0xc16a4f69),
        ];
        for (acc, a0, a1, b0, b1, want) in rows {
            assert_eq!(bfdot(acc, [a0, a1], [b0, b1]), want, "{acc:08x}");
        }
    }

    #[test]
    fn denormals_nans_and_overflow() {
        let one = bf(1.0);
        // A denormal operand is a zero: 0x0001 * 1.0 + 0 = 0, no denormal out.
        assert_eq!(bfdot(0, [0x0001, 0], [one, one]), 0);
        // Any NaN is the default NaN.
        assert_eq!(bfdot(0x7f80_0001, [0, 0], [0, 0]), 0x7fc0_0000);
        // Overflow is infinity, in both signs.
        assert_eq!(bfdot(0x7f7f_ffff, [0x7f7f, 0], [one, one]), 0x7f80_0000);
        assert_eq!(bfdot(0xff7f_ffff, [0xff7f, 0], [one, one]), 0xff80_0000);
    }

    #[test]
    fn every_op_decodes_from_its_encoding_and_back() {
        for (insn, want) in [
            (0x2e42_fc20u32, Op::Dot),
            (0x4f62_f020, Op::DotElem),
            (0x6e42_ec20, Op::Mmla),
            (0x2ec2_fc20, Op::MlalB),
            (0x6ec2_fc20, Op::MlalT),
            (0x0ff2_f020, Op::MlalBElem),
            (0x4ff2_f020, Op::MlalTElem),
            (0x1e63_4020, Op::Cvt),
            (0x0ea1_6820, Op::Cvtn),
            (0x4ea1_6820, Op::Cvtn2),
        ] {
            assert_eq!(Op::decode(insn), Some(want), "{insn:08x}");
            assert_eq!(OPS[Op::decode(insn).unwrap().code() as usize], want);
        }
        // Neighbours that are other instructions.
        assert_eq!(Op::decode(0x2e82_9420), None, "sdot");
        assert_eq!(Op::decode(0x2f82_d020), None, "sqrdmlah by element");
    }

    #[test]
    fn a_conversion_rounds_to_nearest_even_by_default() {
        let mut fp = [[0u64; 2]; 32];
        fp[1] = [0x3f80_8000 | (0x3f80_8001u64 << 32), 0];
        let flags = execute(Op::Cvtn, 0x0ea1_6820, &mut fp, 0);
        // 1.00390625 is halfway: ties to even -> 1.0; the next up is above half.
        assert_eq!(fp[0][0] & 0xffff, 0x3f80);
        assert_eq!((fp[0][0] >> 16) & 0xffff, 0x3f81);
        assert_eq!(flags, IXC);
    }
}
