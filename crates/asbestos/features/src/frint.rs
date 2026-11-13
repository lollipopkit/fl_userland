//! `FRINT32Z`, `FRINT32X`, `FRINT64Z` and `FRINT64X` (FEAT_FRINTTS): round a
//! floating-point value to an integral value that fits a 32- or 64-bit signed
//! integer, and answer the most negative such integer (as a float) when it does
//! not fit. C's `nearbyint`/`rint` with a range check built in, which is why
//! they exist: converting through `int` no longer has undefined behaviour.
//!
//! `Z` rounds toward zero and `X` uses the FPCR rounding mode; **both** raise
//! Inexact when they round (the first version raised it for `X` only, and the
//! differential against a real kernel showed `Z` sets IXC too). Written as integer arithmetic on the bit pattern: the host
//! FPU's rounding mode is the guest's FPCR, and it has no such instruction.
//!
//! The rules, each checked against a real arm64 kernel by
//! `tests/guest/src/bin/insn_features.rs`:
//!
//! - NaN, infinity and a result outside the signed range give Invalid Operation
//!   and the most negative integer (-2^31 or -2^63) as a float of the operand's
//!   width. A NaN does not propagate.
//! - Zero keeps its sign, and so does a result that rounds to zero.
//! - With FPCR.FZ a subnormal operand is a zero and raises Input Denormal.
//! - Inexact is raised when the result is in range and was rounded.

use crate::jscvt::{IDC, IOC, IXC};

/// Which of the four instructions.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Op {
    R32Z,
    R32X,
    R64Z,
    R64X,
}

impl Op {
    pub fn from_bits(bits: u64) -> Op {
        match bits & 3 {
            0 => Op::R32Z,
            1 => Op::R32X,
            2 => Op::R64Z,
            _ => Op::R64X,
        }
    }
    fn intsize(self) -> u32 {
        match self {
            Op::R32Z | Op::R32X => 32,
            _ => 64,
        }
    }
    /// `X` variants use the FPCR rounding mode; `Z` rounds toward zero.
    fn uses_fpcr_mode(self) -> bool {
        matches!(self, Op::R32X | Op::R64X)
    }
}

/// FPCR.RMode values.
const RN: u32 = 0;
const RP: u32 = 1;
const RM: u32 = 2;

/// (exponent bits, fraction bits) of the two element types.
#[derive(Clone, Copy)]
pub struct Format {
    ebits: u32,
    mbits: u32,
}
pub const SINGLE: Format = Format { ebits: 8, mbits: 23 };
pub const DOUBLE: Format = Format { ebits: 11, mbits: 52 };

/// One element. Returns the result bits and the FPSR flags to set.
pub fn round_int_n(bits: u64, fmt: Format, op: Op, fpcr: u64) -> (u64, u8) {
    let width = 1 + fmt.ebits + fmt.mbits;
    let sign = bits >> (width - 1) & 1;
    let exp = (bits >> fmt.mbits) & ((1 << fmt.ebits) - 1);
    let frac = bits & ((1 << fmt.mbits) - 1);
    let bias = (1i64 << (fmt.ebits - 1)) - 1;
    let zero = sign << (width - 1);
    let n = op.intsize();

    // The most negative integer as a float, which is the answer to anything
    // that does not fit: -2^(n-1) has exponent n-1 and a zero fraction.
    let most_neg = (1u64 << (width - 1)) | (((n as i64 - 1 + bias) as u64) << fmt.mbits);

    if exp == (1 << fmt.ebits) - 1 {
        return (most_neg, IOC);
    }
    let fz = fpcr & (1 << 24) != 0;
    // value = mant * 2^e2
    let (mant, e2) = if exp == 0 {
        if frac == 0 {
            return (zero, 0);
        }
        if fz {
            return (zero, IDC);
        }
        (frac, 1 - bias - fmt.mbits as i64)
    } else {
        ((1u64 << fmt.mbits) | frac, exp as i64 - bias - fmt.mbits as i64)
    };

    let rmode = if op.uses_fpcr_mode() { ((fpcr >> 22) & 3) as u32 } else { 3 };
    // The truncated magnitude, and whether something was dropped, and whether
    // the dropped part rounds it up.
    let (mag, inexact, up) = if e2 >= 0 {
        // Integral already. Anything at or beyond 2^64 is out of range; the
        // shift is bounded so it cannot overflow the u128.
        if e2 >= 64 {
            return (most_neg, IOC);
        }
        ((mant as u128) << e2, false, false)
    } else {
        let shift = (-e2) as u32;
        if shift >= 120 {
            // Below 2^-67 of a unit: nothing survives but the fact that it is
            // not zero, and it is below half.
            (0u128, true, round_up(rmode, sign != 0, 0, false, false, true))
        } else {
            let m = mant as u128;
            let int = m >> shift;
            let rem = m & ((1u128 << shift) - 1);
            let half = 1u128 << (shift - 1);
            (
                int,
                rem != 0,
                round_up(rmode, sign != 0, int, rem > half, rem == half, rem != 0),
            )
        }
    };
    let mag = mag + up as u128;
    // The signed range: [-2^(n-1), 2^(n-1) - 1].
    let limit = 1u128 << (n - 1);
    if if sign != 0 { mag > limit } else { mag >= limit } {
        return (most_neg, IOC);
    }
    let flags = if inexact { IXC } else { 0 };
    if mag == 0 {
        return (zero, flags);
    }
    // mag is at most 2^63 and was a float's integral part, so it is exactly
    // representable: rebuild the float from it.
    let p = 127 - mag.leading_zeros(); // position of the leading one
    let frac = if p <= fmt.mbits { (mag << (fmt.mbits - p)) as u64 } else { (mag >> (p - fmt.mbits)) as u64 };
    let out = zero | (((p as i64 + bias) as u64) << fmt.mbits) | (frac & ((1 << fmt.mbits) - 1));
    (out, flags)
}

/// Whether rounding increases the magnitude.
fn round_up(rmode: u32, negative: bool, int: u128, over_half: bool, half: bool, nonzero: bool) -> bool {
    match rmode {
        RN => over_half || (half && int & 1 == 1),
        // Toward +inf: a positive value with a remainder goes up in magnitude,
        // a negative one goes toward zero.
        RP => nonzero && !negative,
        RM => nonzero && negative,
        _ => false,
    }
}

/// The whole register. `mode`: bits 1:0 the [`Op`], bit 2 double precision,
/// bit 3 a 128-bit vector, bit 4 scalar (one element, the rest of `Vd`
/// zeroed). Returns the result and the FPSR flags to set.
pub fn frintts(src: [u64; 2], fpcr: u64, mode: u64) -> ([u64; 2], u8) {
    let op = Op::from_bits(mode);
    let double = mode & 4 != 0;
    let (fmt, lanes, esize) = if double { (DOUBLE, 2, 64) } else { (SINGLE, 4, 32) };
    let lanes = if mode & 16 != 0 {
        1
    } else if mode & 8 != 0 {
        lanes
    } else {
        lanes / 2
    };
    let mut out = [0u64; 2];
    let mut flags = 0;
    for i in 0..lanes {
        let at = i * esize;
        let (word, shift) = (at / 64, at % 64);
        let lane = (src[word] >> shift) & if esize == 64 { u64::MAX } else { 0xffff_ffff };
        let (r, f) = round_int_n(lane, fmt, op, fpcr);
        out[word] |= r << shift;
        flags |= f;
    }
    (out, flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(bits: u32, op: Op, fpcr: u64) -> (u32, u8) {
        let (r, f) = round_int_n(bits as u64, SINGLE, op, fpcr);
        (r as u32, f)
    }
    fn d(bits: u64, op: Op, fpcr: u64) -> (u64, u8) {
        round_int_n(bits, DOUBLE, op, fpcr)
    }

    #[test]
    fn toward_zero_and_in_range() {
        assert_eq!(s(1.5f32.to_bits(), Op::R32Z, 0), (1.0f32.to_bits(), IXC));
        assert_eq!(s((-1.5f32).to_bits(), Op::R32Z, 0), ((-1.0f32).to_bits(), IXC));
        assert_eq!(s(0.5f32.to_bits(), Op::R32Z, 0), (0, IXC));
        assert_eq!(s((-0.5f32).to_bits(), Op::R32Z, 0), (0x8000_0000, IXC), "keeps the sign of zero");
        assert_eq!(s(1.0f32.to_bits(), Op::R32Z, 0), (1.0f32.to_bits(), 0), "exact");
    }

    #[test]
    fn x_uses_the_rounding_mode() {
        assert_eq!(s(2.5f32.to_bits(), Op::R32X, 0), (2.0f32.to_bits(), IXC), "ties to even");
        assert_eq!(s(3.5f32.to_bits(), Op::R32X, 0), (4.0f32.to_bits(), IXC));
        assert_eq!(s(2.5f32.to_bits(), Op::R32X, 1 << 22), (3.0f32.to_bits(), IXC), "toward +inf");
        assert_eq!(s(2.5f32.to_bits(), Op::R32X, 2 << 22), (2.0f32.to_bits(), IXC), "toward -inf");
        assert_eq!(s((-2.5f32).to_bits(), Op::R32X, 2 << 22), ((-3.0f32).to_bits(), IXC));
        assert_eq!(s(2.0f32.to_bits(), Op::R32X, 0), (2.0f32.to_bits(), 0), "exact");
    }

    #[test]
    fn out_of_range_is_the_most_negative_integer() {
        let neg32 = (-2147483648.0f32).to_bits();
        assert_eq!(s((2147483648.0f32).to_bits(), Op::R32Z, 0), (neg32, IOC));
        assert_eq!(s(neg32, Op::R32Z, 0), (neg32, 0), "-2^31 fits");
        assert_eq!(s(f32::NAN.to_bits(), Op::R32Z, 0), (neg32, IOC), "a NaN does not propagate");
        assert_eq!(s(f32::INFINITY.to_bits(), Op::R64Z, 0), ((-9223372036854775808.0f32).to_bits(), IOC));
        assert_eq!(d((2147483648.0f64).to_bits(), Op::R32Z, 0), ((-2147483648.0f64).to_bits(), IOC));
        assert_eq!(d((2147483647.0f64).to_bits(), Op::R32Z, 0), ((2147483647.0f64).to_bits(), 0));
        assert_eq!(d((9223372036854775808.0f64).to_bits(), Op::R64Z, 0), ((-9223372036854775808.0f64).to_bits(), IOC));
        assert_eq!(d((-9223372036854775808.0f64).to_bits(), Op::R64Z, 0), ((-9223372036854775808.0f64).to_bits(), 0));
        // Rounding up out of range: 2^31 - 0.5 rounds to 2^31 to nearest.
        assert_eq!(d((2147483647.5f64).to_bits(), Op::R32X, 0), ((-2147483648.0f64).to_bits(), IOC));
    }

    #[test]
    fn a_subnormal_is_a_zero_under_fz() {
        assert_eq!(s(1, Op::R32Z, 1 << 24), (0, IDC));
        assert_eq!(s(0x8000_0001, Op::R32Z, 1 << 24), (0x8000_0000, IDC));
        assert_eq!(s(1, Op::R32Z, 0), (0, IXC));
        assert_eq!(s(1, Op::R32X, 0), (0, IXC));
        assert_eq!(s(0x8000_0001, Op::R32X, 2 << 22), ((-1.0f32).to_bits(), IXC), "toward -inf");
    }

    #[test]
    fn a_vector_is_lane_by_lane() {
        let src = [
            (1.5f32.to_bits() as u64) | ((-2.5f32).to_bits() as u64) << 32,
            (f32::NAN.to_bits() as u64) | (7.0f32.to_bits() as u64) << 32,
        ];
        let (out, flags) = frintts(src, 0, 8);
        assert_eq!(out[0] as u32, 1.0f32.to_bits());
        assert_eq!((out[0] >> 32) as u32, (-2.0f32).to_bits());
        assert_eq!(out[1] as u32, (-2147483648.0f32).to_bits());
        assert_eq!((out[1] >> 32) as u32, 7.0f32.to_bits());
        assert_eq!(flags, IOC | IXC, "1.5 and -2.5 were rounded, the NaN is invalid");
        // The 64-bit vector leaves the top half zero.
        let (out, _) = frintts(src, 0, 0);
        assert_eq!(out[1], 0);
    }
}
