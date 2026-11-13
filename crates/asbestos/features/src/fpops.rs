//! The floating-point operations beyond add, multiply and fused multiply-add,
//! on any [`Fmt`]: divide, square root, the four `FMAX`/`FMIN` families,
//! `FMULX`, the reciprocal and reciprocal-square-root estimates and steps,
//! round to integral, conversion to and from integers and comparison.
//!
//! Written from the Arm pseudocode for the half-precision instructions
//! (`fp16.rs`), and general over the format so that a test can check them
//! against the host's single and double precision. Everything is integer
//! arithmetic on bit patterns; see `softfloat` for why.

use crate::softfloat::*;
use std::cmp::Ordering;

/// The condition flags a comparison sets, as NZCV in bits 3:0.
pub const NZCV_UNORDERED: u32 = 0b0011;
pub const NZCV_EQUAL: u32 = 0b0110;
pub const NZCV_LESS: u32 = 0b1000;
pub const NZCV_GREATER: u32 = 0b0010;

fn sign_of(v: Val) -> bool {
    match v {
        Val::Zero(s) | Val::Inf(s) | Val::Num { neg: s, .. } => s,
        Val::Nan(..) => false,
    }
}

fn sign_bit(fmt: Fmt) -> u64 {
    1 << (fmt.ebits + fmt.mbits)
}

/// `FPNeg` on the bits: the sign flips, a NaN's included.
pub fn neg(a: u64, fmt: Fmt) -> u64 {
    a ^ sign_bit(fmt)
}

/// `FPAbs`: the sign clears, a NaN's included.
pub fn abs(a: u64, fmt: Fmt) -> u64 {
    a & !sign_bit(fmt)
}

fn bias(fmt: Fmt) -> i32 {
    (1 << (fmt.ebits - 1)) - 1
}

/// +-2^`e` as bits (`e` in the normal range).
pub fn pow2(e: i32, fmt: Fmt, negative: bool) -> u64 {
    (((e + bias(fmt)) as u64) << fmt.mbits) | if negative { sign_bit(fmt) } else { 0 }
}

/// `FPDiv`.
pub fn fpdiv(a: u64, b: u64, fmt: Fmt, env: Env, rounding: Round, flags: &mut u8) -> u64 {
    let (x, y) = (unpack(a, fmt, env, flags), unpack(b, fmt, env, flags));
    if let Some(n) = process_nans(&[x, y], fmt, env, flags) {
        return n;
    }
    let neg = sign_of(x) != sign_of(y);
    match (x, y) {
        (Val::Inf(_), Val::Inf(_)) | (Val::Zero(_), Val::Zero(_)) => {
            *flags |= IOC;
            fmt.default_nan()
        }
        (Val::Inf(_), _) => fmt.infinity(neg),
        (_, Val::Zero(_)) => {
            *flags |= DZC;
            fmt.infinity(neg)
        }
        (_, Val::Inf(_)) | (Val::Zero(_), _) => fmt.zero(neg),
        (Val::Num { mant: m1, exp: e1, .. }, Val::Num { mant: m2, exp: e2, .. }) => {
            // 64 quotient bits are plenty (the format keeps at most 53), and the
            // remainder becomes a sticky bit below them.
            let num = (m1 as u128) << 64;
            let q = num / m2 as u128;
            let sticky = !num.is_multiple_of(m2 as u128);
            round(neg, (q << 1) | sticky as u128, e1 - e2 - 65, fmt, rounding, env, flags)
        }
        _ => fmt.default_nan(),
    }
}

/// Integer square root, and whether it was inexact.
fn isqrt(n: u128) -> (u128, bool) {
    let (mut lo, mut hi) = (0u128, 1u128 << 64);
    while lo + 1 < hi {
        let mid = (lo + hi) / 2;
        if mid * mid <= n {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    (lo, lo * lo != n)
}

/// `FPSqrt`.
pub fn fpsqrt(a: u64, fmt: Fmt, env: Env, rounding: Round, flags: &mut u8) -> u64 {
    let x = unpack(a, fmt, env, flags);
    if let Some(n) = process_nans(&[x], fmt, env, flags) {
        return n;
    }
    match x {
        Val::Zero(s) => fmt.zero(s),
        Val::Inf(false) => fmt.infinity(false),
        Val::Inf(true) | Val::Num { neg: true, .. } => {
            *flags |= IOC;
            fmt.default_nan()
        }
        Val::Num { mant, exp, .. } => {
            // sqrt(m * 2^e) with e even, and m widened by 2k bits so the root
            // keeps about 63.
            let (mut m, mut e) = (mant as u128, exp);
            if e & 1 != 0 {
                m <<= 1;
                e -= 1;
            }
            let bits = 128 - m.leading_zeros() as i32;
            let k = (126 - bits) / 2;
            let (s, inexact) = isqrt(m << (2 * k));
            round(false, (s << 1) | inexact as u128, e / 2 - k - 1, fmt, rounding, env, flags)
        }
        Val::Nan(..) => fmt.default_nan(),
    }
}

/// The order of two non-NaN operands by value (zeros equal).
fn cmp_vals(x: Val, y: Val) -> Ordering {
    // Rank: -inf < negative numbers < zero < positive numbers < +inf.
    let key = |v: Val| -> (i32, i32, u64) {
        match v {
            Val::Inf(true) => (-3, 0, 0),
            Val::Inf(false) => (3, 0, 0),
            Val::Zero(_) => (0, 0, 0),
            Val::Num { neg: true, mant, exp } => (-1, -(top_exp(mant, exp)), u64::MAX - norm(mant)),
            Val::Num { neg: false, mant, exp } => (1, top_exp(mant, exp), norm(mant)),
            Val::Nan(..) => (0, 0, 0),
        }
    };
    key(x).cmp(&key(y))
}

/// The exponent of the leading one of `mant * 2^exp`.
fn top_exp(mant: u64, exp: i32) -> i32 {
    63 - mant.leading_zeros() as i32 + exp
}
/// `mant` left-aligned, so mantissas compare across exponents.
fn norm(mant: u64) -> u64 {
    mant << mant.leading_zeros()
}

/// The pattern for an unpacked operand, exact (no flags: it was already
/// representable).
fn repack(v: Val, fmt: Fmt) -> u64 {
    match v {
        Val::Zero(s) => fmt.zero(s),
        Val::Inf(s) => fmt.infinity(s),
        Val::Num { neg, mant, exp } => round(neg, mant as u128, exp, fmt, Round::Nearest, Env { fz: false, fz_out: false, dn: false, idc: true }, &mut 0),
        Val::Nan(b, _) => b,
    }
}

/// `FPMax`/`FPMin`, and with `numeric` `FPMaxNum`/`FPMinNum`, which treat a
/// single quiet NaN as missing.
pub fn fpmaxmin(a: u64, b: u64, is_max: bool, numeric: bool, fmt: Fmt, env: Env, flags: &mut u8) -> u64 {
    let (mut x, mut y) = (unpack(a, fmt, env, flags), unpack(b, fmt, env, flags));
    if numeric {
        let (xq, yq) = (matches!(x, Val::Nan(_, false)), matches!(y, Val::Nan(_, false)));
        // A lone quiet NaN becomes the identity of the operation.
        if xq && !yq {
            x = Val::Inf(is_max);
        } else if !xq && yq {
            y = Val::Inf(is_max);
        }
    }
    if let Some(n) = process_nans(&[x, y], fmt, env, flags) {
        return n;
    }
    // Zeros of opposite sign: +0 is larger than -0 for these.
    if let (Val::Zero(s1), Val::Zero(s2)) = (x, y) {
        return fmt.zero(if is_max { s1 && s2 } else { s1 || s2 });
    }
    let pick_x = match cmp_vals(x, y) {
        Ordering::Greater => is_max,
        Ordering::Less => !is_max,
        Ordering::Equal => true,
    };
    repack(if pick_x { x } else { y }, fmt)
}

/// `FPMulX`: `FMUL` except that infinity times zero is 2.0.
pub fn fpmulx(a: u64, b: u64, fmt: Fmt, env: Env, rounding: Round, flags: &mut u8) -> u64 {
    let (x, y) = (unpack(a, fmt, env, &mut 0), unpack(b, fmt, env, &mut 0));
    if matches!((x, y), (Val::Inf(_), Val::Zero(_)) | (Val::Zero(_), Val::Inf(_))) {
        // The operands were flushed (and IDC raised) by the unpack above only
        // for the check; raise it for real.
        let _ = unpack(a, fmt, env, flags);
        let _ = unpack(b, fmt, env, flags);
        return pow2(1, fmt, sign_of(x) != sign_of(y));
    }
    fpmul(a, b, fmt, env, rounding, flags)
}

/// `FRECPS`: `2 - a*b` fused.
pub fn fprecps(a: u64, b: u64, fmt: Fmt, env: Env, rounding: Round, flags: &mut u8) -> u64 {
    let a = neg(a, fmt);
    let (x, y) = (unpack(a, fmt, env, &mut 0), unpack(b, fmt, env, &mut 0));
    if let (Val::Inf(_), Val::Zero(_)) | (Val::Zero(_), Val::Inf(_)) = (x, y) {
        let _ = unpack(a, fmt, env, flags);
        let _ = unpack(b, fmt, env, flags);
        return pow2(1, fmt, false);
    }
    fpmuladd(pow2(1, fmt, false), a, b, fmt, env, rounding, flags)
}

/// `FRSQRTS`: `(3 - a*b) / 2` fused, rounded once.
pub fn fprsqrts(a: u64, b: u64, fmt: Fmt, env: Env, rounding: Round, flags: &mut u8) -> u64 {
    let a = neg(a, fmt);
    let (x, y) = (unpack(a, fmt, env, &mut 0), unpack(b, fmt, env, &mut 0));
    if let (Val::Inf(_), Val::Zero(_)) | (Val::Zero(_), Val::Inf(_)) = (x, y) {
        let _ = unpack(a, fmt, env, flags);
        let _ = unpack(b, fmt, env, flags);
        // 1.5
        return pow2(0, fmt, false) | (1 << (fmt.mbits - 1));
    }
    // 3.0 is 1.5 * 2
    let three = pow2(1, fmt, false) | (1 << (fmt.mbits - 1));
    fpmuladd_scaled(three, a, b, -1, fmt, env, rounding, flags)
}

/// `RecipEstimate`: the 8-bit reciprocal estimate of a 9-bit fraction in
/// [256, 511].
fn recip_estimate(a: u32) -> u32 {
    let a = a * 2 + 1;
    let b = (1u32 << 19) / a;
    b.div_ceil(2)
}

/// `RecipSqrtEstimate`: for a fraction in [128, 511].
fn recip_sqrt_estimate(a: u32) -> u32 {
    // In units of 1/512 for 0.25..0.5 and of 1/256 (rounded up to odd) for
    // 0.5..1.0.
    let a = if a < 256 { a * 2 + 1 } else { ((a >> 1) << 1).wrapping_add(1) * 2 } as u64;
    let mut b = 512u64;
    while a * (b + 1) * (b + 1) < 1 << 28 {
        b += 1;
    }
    b.div_ceil(2) as u32
}

/// Whether to flush a result that is too large to invert: FZ (FZ16 for half).
fn fpcr_overflow(rounding: Round, negative: bool, fmt: Fmt, flags: &mut u8) -> u64 {
    *flags |= OFC | IXC;
    let to_inf = match rounding {
        Round::PlusInf => !negative,
        Round::MinusInf => negative,
        Round::Zero => false,
        _ => true,
    };
    if to_inf { fmt.infinity(negative) } else { fmt.max_finite(negative) }
}

/// `FPRecipEstimate` (`FRECPE`).
pub fn fprecpe(a: u64, fmt: Fmt, env: Env, rounding: Round, flags: &mut u8) -> u64 {
    let x = unpack(a, fmt, env, flags);
    if let Some(n) = process_nans(&[x], fmt, env, flags) {
        return n;
    }
    let mbits = fmt.mbits as i32;
    let ebits = fmt.ebits as i32;
    match x {
        Val::Inf(s) => fmt.zero(s),
        Val::Zero(s) => {
            *flags |= DZC;
            fmt.infinity(s)
        }
        Val::Num { neg: s, mant, exp } => {
            let top = top_exp(mant, exp);
            let emin = 1 - bias(fmt);
            // |value| < 2^-(2^(E-1) ... ): the reciprocal would overflow.
            if top < -(bias(fmt) + 1) {
                return fpcr_overflow(rounding, s, fmt, flags);
            }
            // Flushed result: |value| >= 2^(2^(E-1) - 2) when flushing.
            if env.fz_out && top >= (1 << (ebits - 1)) - 2 {
                *flags |= UFC;
                return fmt.zero(s);
            }
            // The fraction as a mantissa-width field, and the exponent field.
            let (mut frac, mut e) = if (a >> fmt.mbits) & ((1 << fmt.ebits) - 1) == 0 {
                (a & ((1 << fmt.mbits) - 1), 0i32)
            } else {
                (a & ((1 << fmt.mbits) - 1), ((a >> fmt.mbits) & ((1 << fmt.ebits) - 1)) as i32)
            };
            let _ = emin;
            // Left-align into 52 bits, as the pseudocode does.
            frac <<= 52 - mbits;
            if e == 0 {
                if frac >> 51 & 1 == 0 {
                    e = -1;
                    frac = (frac & ((1 << 50) - 1)) << 2;
                } else {
                    frac = (frac & ((1 << 51) - 1)) << 1;
                }
            }
            let scaled = (1u32 << 8) | ((frac >> 44) & 0xff) as u32;
            let mut result_exp = (2 * bias(fmt) - 1) - e;
            let estimate = recip_estimate(scaled);
            let mut fraction: u64 = ((estimate & 0xff) as u64) << 44;
            if result_exp == 0 {
                fraction = (1 << 51) | (fraction >> 1);
            } else if result_exp == -1 {
                fraction = (1 << 50) | (fraction >> 2);
                result_exp = 0;
            }
            let sign = if s { sign_bit(fmt) } else { 0 };
            sign | ((result_exp as u64 & ((1 << ebits) - 1)) << mbits) | (fraction >> (52 - mbits))
        }
        Val::Nan(..) => fmt.default_nan(),
    }
}

/// `FPRSqrtEstimate` (`FRSQRTE`).
pub fn fprsqrte(a: u64, fmt: Fmt, env: Env, flags: &mut u8) -> u64 {
    let x = unpack(a, fmt, env, flags);
    if let Some(n) = process_nans(&[x], fmt, env, flags) {
        return n;
    }
    let mbits = fmt.mbits as i32;
    let ebits = fmt.ebits as i32;
    match x {
        Val::Zero(s) => {
            *flags |= DZC;
            fmt.infinity(s)
        }
        Val::Inf(false) => fmt.zero(false),
        Val::Inf(true) | Val::Num { neg: true, .. } => {
            *flags |= IOC;
            fmt.default_nan()
        }
        Val::Num { .. } => {
            let mut e = ((a >> fmt.mbits) & ((1 << fmt.ebits) - 1)) as i32;
            let mut frac = (a & ((1 << fmt.mbits) - 1)) << (52 - mbits);
            if e == 0 {
                while frac >> 51 & 1 == 0 {
                    frac = (frac & ((1 << 51) - 1)) << 1;
                    e -= 1;
                }
                frac = (frac & ((1 << 51) - 1)) << 1;
            }
            let scaled = if e & 1 == 0 { (1u32 << 8) | ((frac >> 44) & 0xff) as u32 } else { (1u32 << 7) | ((frac >> 45) & 0x7f) as u32 };
            let result_exp = (3 * bias(fmt) - 1 - e).div_euclid(2);
            let estimate = recip_sqrt_estimate(scaled);
            let fraction = ((estimate & 0xff) as u64) << 44;
            ((result_exp as u64 & ((1 << ebits) - 1)) << mbits) | (fraction >> (52 - mbits))
        }
        Val::Nan(..) => fmt.default_nan(),
    }
}

/// `FPRecipX` (`FRECPX`): the sign, the inverted exponent and a zero fraction.
pub fn fprecpx(a: u64, fmt: Fmt, env: Env, flags: &mut u8) -> u64 {
    let x = unpack(a, fmt, env, flags);
    if let Some(n) = process_nans(&[x], fmt, env, flags) {
        return n;
    }
    let exp_mask = (1u64 << fmt.ebits) - 1;
    let exp = (a >> fmt.mbits) & exp_mask;
    let result_exp = if exp == 0 { exp_mask - 1 } else { !exp & exp_mask };
    (a & sign_bit(fmt)) | (result_exp << fmt.mbits)
}

/// The `FPRoundInt` family: round to an integral value in the same format.
/// `exact` raises Inexact when the value changes.
pub fn fprint(a: u64, rounding: Round, exact: bool, fmt: Fmt, env: Env, flags: &mut u8) -> u64 {
    let x = unpack(a, fmt, env, flags);
    if let Some(n) = process_nans(&[x], fmt, env, flags) {
        return n;
    }
    match x {
        Val::Zero(_) | Val::Inf(_) => repack(x, fmt),
        Val::Num { neg, mant, exp } => {
            let (int, inexact) = round_to_int(neg, mant, exp, rounding);
            if exact && inexact {
                *flags |= IXC;
            }
            if int == 0 {
                fmt.zero(neg)
            } else {
                // The integer is at most the operand's magnitude rounded up, so
                // it is representable.
                round(neg, int, 0, fmt, Round::Nearest, Env { fz: false, fz_out: false, dn: false, idc: true }, &mut 0)
            }
        }
        Val::Nan(..) => fmt.default_nan(),
    }
}

/// `mant * 2^exp` rounded to an integer magnitude by `rounding` (which sees the
/// sign), and whether it was inexact.
fn round_to_int(neg: bool, mant: u64, exp: i32, rounding: Round) -> (u128, bool) {
    if exp >= 0 {
        return ((mant as u128) << exp.min(64), false);
    }
    let shift = (-exp) as u32;
    if shift >= 126 {
        let up = match rounding {
            Round::PlusInf => !neg,
            Round::MinusInf => neg,
            _ => false,
        };
        return (up as u128, true);
    }
    let m = mant as u128;
    let int = m >> shift;
    let rem = m & ((1u128 << shift) - 1);
    let half = 1u128 << (shift - 1);
    let inexact = rem != 0;
    let up = match rounding {
        Round::Nearest => rem > half || (rem == half && int & 1 == 1),
        Round::TieAway => rem >= half,
        Round::PlusInf => inexact && !neg,
        Round::MinusInf => inexact && neg,
        Round::Zero | Round::Odd => false,
    };
    (int + up as u128, inexact)
}

/// `FPToFixed`: convert to a `width`-bit integer with `fbits` fraction bits,
/// saturating. Returns the two's complement result in the low bits and sets
/// Invalid Operation on NaN and overflow, Inexact when rounded.
#[allow(clippy::too_many_arguments)]
pub fn fp_to_int(a: u64, fbits: u32, unsigned: bool, width: u32, rounding: Round, fmt: Fmt, env: Env, flags: &mut u8) -> u64 {
    let x = unpack(a, fmt, env, flags);
    let (lo, hi): (i128, i128) = if unsigned { (0, (1i128 << width) - 1) } else { (-(1i128 << (width - 1)), (1i128 << (width - 1)) - 1) };
    let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
    let (value, overflow, inexact) = match x {
        Val::Nan(_, snan) => {
            let _ = snan;
            (0i128, true, false)
        }
        Val::Zero(_) => (0, false, false),
        Val::Inf(s) => (if s { lo } else { hi }, true, false),
        Val::Num { neg, mant, exp } => {
            let (int, inexact) = round_to_int(neg, mant, exp + fbits as i32, rounding);
            let v = if int > (1u128 << 100) { i128::MAX / 2 } else { int as i128 };
            let v = if neg { -v } else { v };
            if v > hi {
                (hi, true, inexact)
            } else if v < lo {
                (lo, true, inexact)
            } else {
                (v, false, inexact)
            }
        }
    };
    if overflow {
        *flags |= IOC;
    } else if inexact {
        *flags |= IXC;
    }
    (value as i64 as u64) & mask
}

/// `FixedToFP`: an integer (`value`, signed or unsigned as `signed` says, in
/// `width` bits) with `fbits` fraction bits to `fmt`.
#[allow(clippy::too_many_arguments)]
pub fn int_to_fp(raw: u64, signed: bool, width: u32, fbits: u32, fmt: Fmt, env: Env, rounding: Round, flags: &mut u8) -> u64 {
    let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
    let raw = raw & mask;
    let (neg, mag) = if signed && raw >> (width - 1) & 1 == 1 { (true, (!raw).wrapping_add(1) & mask) } else { (false, raw) };
    if mag == 0 {
        return fmt.zero(false);
    }
    round(neg, mag as u128, -(fbits as i32), fmt, rounding, env, flags)
}

/// `FPCompare`: the flags for `FCMP`/`FCCMP`. `signal` is the `E` forms, which
/// raise Invalid Operation for a quiet NaN too.
pub fn fpcompare(a: u64, b: u64, signal: bool, fmt: Fmt, env: Env, flags: &mut u8) -> u32 {
    let (x, y) = (unpack(a, fmt, env, flags), unpack(b, fmt, env, flags));
    let (xn, yn) = (matches!(x, Val::Nan(..)), matches!(y, Val::Nan(..)));
    if xn || yn {
        if signal || matches!(x, Val::Nan(_, true)) || matches!(y, Val::Nan(_, true)) {
            *flags |= IOC;
        }
        return NZCV_UNORDERED;
    }
    match cmp_vals(x, y) {
        Ordering::Equal => NZCV_EQUAL,
        Ordering::Less => NZCV_LESS,
        Ordering::Greater => NZCV_GREATER,
    }
}

/// `FPCompareEQ`, `FPCompareGE` and `FPCompareGT`: `what` 0, 1, 2. A NaN makes
/// them false; EQ raises Invalid Operation only for a signaling one, GE and GT
/// for any.
pub fn fpcompare_bool(a: u64, b: u64, what: u32, fmt: Fmt, env: Env, flags: &mut u8) -> bool {
    let (x, y) = (unpack(a, fmt, env, flags), unpack(b, fmt, env, flags));
    let nan = matches!(x, Val::Nan(..)) || matches!(y, Val::Nan(..));
    if nan {
        if what != 0 || matches!(x, Val::Nan(_, true)) || matches!(y, Val::Nan(_, true)) {
            *flags |= IOC;
        }
        return false;
    }
    let o = cmp_vals(x, y);
    match what {
        0 => o == Ordering::Equal,
        1 => o != Ordering::Less,
        _ => o == Ordering::Greater,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENV: Env = Env { fz: false, fz_out: false, dn: false, idc: true };

    fn s(x: f32) -> u64 {
        x.to_bits() as u64
    }
    fn f(bits: u64) -> f32 {
        f32::from_bits(bits as u32)
    }

    #[test]
    fn division_and_square_root_match_the_host_in_single() {
        for &(a, b) in &[(1.0f32, 3.0), (10.0, 4.0), (-7.5, 2.5), (1e30, 1e-10), (3.0, 7.0), (1.0, 0.0), (0.0, 0.0), (1e-40, 3.0)] {
            let mut fl = 0;
            let got = fpdiv(s(a), s(b), SINGLE, ENV, Round::Nearest, &mut fl);
            let want = a / b;
            assert!(got as u32 == want.to_bits() || (f(got).is_nan() && want.is_nan()), "{a} / {b}: {} vs {want}", f(got));
        }
        for &a in &[2.0f32, 9.0, 0.5, 1e-40, 1e30, 3.0, 0.0] {
            let mut fl = 0;
            let got = fpsqrt(s(a), SINGLE, ENV, Round::Nearest, &mut fl);
            assert_eq!(got as u32, a.sqrt().to_bits(), "sqrt {a}");
        }
        let mut fl = 0;
        let got = fpsqrt(s(-1.0), SINGLE, ENV, Round::Nearest, &mut fl);
        assert_eq!((got as u32, fl), (0x7fc0_0000, IOC));
    }

    #[test]
    fn divide_by_zero_flags() {
        let mut fl = 0;
        assert_eq!(f(fpdiv(s(1.0), s(0.0), SINGLE, ENV, Round::Nearest, &mut fl)), f32::INFINITY);
        assert_eq!(fl, DZC);
    }

    #[test]
    fn max_and_min_treat_zeros_and_nans() {
        let mut fl = 0;
        // FMAX of +0 and -0 is +0; FMIN is -0.
        assert_eq!(fpmaxmin(s(0.0), s(-0.0), true, false, SINGLE, ENV, &mut fl), s(0.0));
        assert_eq!(fpmaxmin(s(0.0), s(-0.0), false, false, SINGLE, ENV, &mut fl), s(-0.0));
        // FMAXNM ignores a lone quiet NaN; FMAX returns it.
        let qnan = 0x7fc0_0000u64;
        assert_eq!(fpmaxmin(qnan, s(1.0), true, true, SINGLE, ENV, &mut fl), s(1.0));
        assert_eq!(fpmaxmin(qnan, s(1.0), true, false, SINGLE, ENV, &mut fl), qnan);
        assert_eq!(fl, 0);
        // A signaling NaN is invalid in both.
        assert_eq!(fpmaxmin(0x7f80_0001, s(1.0), true, true, SINGLE, ENV, &mut fl), 0x7fc0_0001);
        assert_eq!(fl, IOC);
        assert_eq!(fpmaxmin(s(-3.0), s(2.0), true, false, SINGLE, ENV, &mut 0), s(2.0));
        assert_eq!(fpmaxmin(s(-3.0), s(-2.0), false, false, SINGLE, ENV, &mut 0), s(-3.0));
    }

    #[test]
    fn integer_conversion_saturates_and_flags() {
        let mut fl = 0;
        // 1.5 to nearest even is 2, inexact.
        assert_eq!(fp_to_int(s(1.5), 0, false, 32, Round::Nearest, SINGLE, ENV, &mut fl), 2);
        assert_eq!(fl, IXC);
        fl = 0;
        // Out of range saturates and is invalid.
        assert_eq!(fp_to_int(s(3e9), 0, false, 32, Round::Zero, SINGLE, ENV, &mut fl), 0x7fff_ffff);
        assert_eq!(fl, IOC);
        fl = 0;
        assert_eq!(fp_to_int(s(3e9), 0, true, 32, Round::Zero, SINGLE, ENV, &mut fl), 3_000_000_000);
        assert_eq!(fl, 0);
        assert_eq!(fp_to_int(s(-1.0), 0, true, 32, Round::Zero, SINGLE, ENV, &mut fl), 0);
        assert_eq!(fl, IOC);
        fl = 0;
        assert_eq!(fp_to_int(f32::NAN.to_bits() as u64, 0, false, 32, Round::Zero, SINGLE, ENV, &mut fl), 0);
        assert_eq!(fl, IOC);
        // Fixed point: 1.5 with 2 fraction bits is 6.
        fl = 0;
        assert_eq!(fp_to_int(s(1.5), 2, false, 32, Round::Zero, SINGLE, ENV, &mut fl), 6);
        assert_eq!(fl, 0);
    }

    #[test]
    fn integers_convert_back() {
        let mut fl = 0;
        assert_eq!(int_to_fp(0xffff_fffd, true, 32, 0, SINGLE, ENV, Round::Nearest, &mut fl), s(-3.0));
        assert_eq!(int_to_fp(7, false, 32, 1, SINGLE, ENV, Round::Nearest, &mut fl), s(3.5));
        assert_eq!(fl, 0);
        // 2^24 + 1 is inexact in single.
        assert_eq!(int_to_fp(16777217, false, 32, 0, SINGLE, ENV, Round::Nearest, &mut fl), s(16777216.0));
        assert_eq!(fl, IXC);
    }

    #[test]
    fn rounding_to_integral() {
        let mut fl = 0;
        assert_eq!(f(fprint(s(2.5), Round::Nearest, true, SINGLE, ENV, &mut fl)), 2.0);
        assert_eq!(fl, IXC);
        assert_eq!(f(fprint(s(2.5), Round::TieAway, false, SINGLE, ENV, &mut 0)), 3.0);
        assert_eq!(f(fprint(s(-2.5), Round::MinusInf, false, SINGLE, ENV, &mut 0)), -3.0);
        assert_eq!(fprint(s(-0.25), Round::Nearest, false, SINGLE, ENV, &mut 0), s(-0.0));
        assert_eq!(f(fprint(s(1e10), Round::Zero, true, SINGLE, ENV, &mut fl)), 1e10);
    }

    #[test]
    fn comparison_flags() {
        let mut fl = 0;
        assert_eq!(fpcompare(s(1.0), s(2.0), false, SINGLE, ENV, &mut fl), NZCV_LESS);
        assert_eq!(fpcompare(s(2.0), s(2.0), false, SINGLE, ENV, &mut fl), NZCV_EQUAL);
        assert_eq!(fpcompare(s(0.0), s(-0.0), false, SINGLE, ENV, &mut fl), NZCV_EQUAL);
        assert_eq!(fpcompare(s(3.0), s(2.0), false, SINGLE, ENV, &mut fl), NZCV_GREATER);
        assert_eq!(fl, 0);
        assert_eq!(fpcompare(0x7fc0_0000, s(2.0), false, SINGLE, ENV, &mut fl), NZCV_UNORDERED);
        assert_eq!(fl, 0, "a quiet NaN is quiet for FCMP");
        assert_eq!(fpcompare(0x7fc0_0000, s(2.0), true, SINGLE, ENV, &mut fl), NZCV_UNORDERED);
        assert_eq!(fl, IOC, "and invalid for FCMPE");
    }
}
