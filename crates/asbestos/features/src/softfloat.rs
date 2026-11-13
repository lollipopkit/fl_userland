//! IEEE binary floating-point on bit patterns, with the Arm rules that the
//! extensions here need and the host FPU cannot give: round-to-odd, half
//! precision, and exception flags and flush-to-zero spelled out rather than
//! inherited from whatever FPCR the guest last wrote.
//!
//! Every function is integer arithmetic. The host's FPCR is the *guest's* while
//! guest code runs, so a `+` on an `f32` here would round the way the guest last
//! asked it to.

/// FPSR cumulative exception flags.
pub const IOC: u8 = 1 << 0;
pub const DZC: u8 = 1 << 1;
pub const OFC: u8 = 1 << 2;
pub const UFC: u8 = 1 << 3;
pub const IXC: u8 = 1 << 4;
pub const IDC: u8 = 1 << 7;

/// A binary format: exponent and fraction widths.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Fmt {
    pub ebits: u32,
    pub mbits: u32,
}

pub const HALF: Fmt = Fmt { ebits: 5, mbits: 10 };
pub const BFLOAT: Fmt = Fmt { ebits: 8, mbits: 7 };
pub const SINGLE: Fmt = Fmt { ebits: 8, mbits: 23 };
pub const DOUBLE: Fmt = Fmt { ebits: 11, mbits: 52 };

impl Fmt {
    fn bias(self) -> i32 {
        (1 << (self.ebits - 1)) - 1
    }
    fn emax_field(self) -> u64 {
        (1 << self.ebits) - 1
    }
    fn sign_bit(self) -> u64 {
        1 << (self.ebits + self.mbits)
    }
    pub fn quiet_bit(self) -> u64 {
        1 << (self.mbits - 1)
    }
    pub fn infinity(self, neg: bool) -> u64 {
        (self.emax_field() << self.mbits) | if neg { self.sign_bit() } else { 0 }
    }
    pub fn zero(self, neg: bool) -> u64 {
        if neg { self.sign_bit() } else { 0 }
    }
    pub fn max_finite(self, neg: bool) -> u64 {
        ((self.emax_field() - 1) << self.mbits) | ((1 << self.mbits) - 1) | if neg { self.sign_bit() } else { 0 }
    }
    pub fn default_nan(self) -> u64 {
        (self.emax_field() << self.mbits) | self.quiet_bit()
    }
}

/// How an operation treats denormals and NaNs.
#[derive(Clone, Copy, Debug)]
pub struct Env {
    /// Flush denormal operands to zero (raising Input Denormal).
    pub fz: bool,
    /// Flush results that would be denormal to zero (raising Underflow).
    pub fz_out: bool,
    /// Every NaN result is the default NaN.
    pub dn: bool,
    /// A flushed denormal operand raises Input Denormal. Half precision under
    /// FPCR.FZ16 does not (measured on a real kernel).
    pub idc: bool,
}

impl Env {
    /// FPCR's own: FZ flushes operands and results alike.
    pub fn from_fpcr(fpcr: u64) -> Env {
        let fz = fpcr & (1 << 24) != 0;
        Env { fz, fz_out: fz, dn: fpcr & (1 << 25) != 0, idc: true }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Round {
    Nearest,
    /// Ties away from zero (`FRINTA`, `FCVTA*`).
    TieAway,
    PlusInf,
    MinusInf,
    Zero,
    /// Round to odd: an inexact result takes the neighbour with an odd last bit.
    Odd,
}

impl Round {
    /// FPCR.RMode.
    pub fn from_rmode(rmode: u64) -> Round {
        match rmode & 3 {
            0 => Round::Nearest,
            1 => Round::PlusInf,
            2 => Round::MinusInf,
            _ => Round::Zero,
        }
    }
}

/// An unpacked operand: `Num` is `mant * 2^exp` with the sign apart.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Val {
    Zero(bool),
    Inf(bool),
    /// A NaN, as its bits, and whether it was signaling.
    Nan(u64, bool),
    Num { neg: bool, mant: u64, exp: i32 },
}

/// Unpack. With `fz` a denormal is a zero and raises Input Denormal.
pub fn unpack(bits: u64, fmt: Fmt, env: Env, flags: &mut u8) -> Val {
    let neg = bits & fmt.sign_bit() != 0;
    let e = (bits >> fmt.mbits) & fmt.emax_field();
    let f = bits & ((1 << fmt.mbits) - 1);
    if e == fmt.emax_field() {
        if f == 0 {
            Val::Inf(neg)
        } else {
            Val::Nan(bits, f & fmt.quiet_bit() == 0)
        }
    } else if e == 0 {
        if f == 0 {
            Val::Zero(neg)
        } else if env.fz {
            if env.idc {
                *flags |= IDC;
            }
            Val::Zero(neg)
        } else {
            Val::Num { neg, mant: f, exp: 1 - fmt.bias() - fmt.mbits as i32 }
        }
    } else {
        Val::Num { neg, mant: f | (1 << fmt.mbits), exp: e as i32 - fmt.bias() - fmt.mbits as i32 }
    }
}

/// `FPProcessNaNs`: a signaling NaN first, then a quiet one, quieted (IOC for a
/// signaling one), or the default NaN under DN. `None` if no operand is a NaN.
pub fn process_nans(ops: &[Val], fmt: Fmt, env: Env, flags: &mut u8) -> Option<u64> {
    let snan = ops.iter().find_map(|v| match v {
        Val::Nan(b, true) => Some(*b),
        _ => None,
    });
    let qnan = ops.iter().find_map(|v| match v {
        Val::Nan(b, false) => Some(*b),
        _ => None,
    });
    let pick = snan.or(qnan)?;
    if snan.is_some() {
        *flags |= IOC;
    }
    Some(if env.dn { fmt.default_nan() } else { pick | fmt.quiet_bit() })
}

/// `FPRound`: round `neg * mant * 2^exp` (an exact value) to `fmt`.
///
/// `mant` may be wider than the format. Flags follow the Arm pseudocode:
/// Overflow and Inexact for a result too large, Underflow when a tiny result is
/// inexact, and with FZ a tiny result is flushed to zero and raises Underflow.
/// Overflow gives infinity or the largest finite value according to the rounding
/// mode; round to odd gives the largest finite.
pub fn round(neg: bool, mant: u128, exp: i32, fmt: Fmt, rounding: Round, env: Env, flags: &mut u8) -> u64 {
    if mant == 0 {
        return fmt.zero(neg);
    }
    let sign = if neg { fmt.sign_bit() } else { 0 };
    let top = 127 - mant.leading_zeros() as i32; // position of the leading one
    let e = top + exp; // unbiased exponent of the leading one
    let emin = 1 - fmt.bias();
    let tiny = e < emin;
    if tiny && env.fz_out {
        *flags |= UFC;
        return sign;
    }
    // Bits to drop to keep `mbits + 1` significant bits, or fewer for a denormal.
    let mut drop = top - fmt.mbits as i32;
    if tiny {
        drop += emin - e;
    }
    let (mut q, inexact);
    let mut up = false;
    if drop <= 0 {
        q = mant << (-drop) as u32;
        inexact = false;
    } else if drop > 127 {
        // Everything is below the rounding position: nothing survives but that
        // the value is not zero, and it is below half.
        q = 0;
        inexact = true;
        up = match rounding {
            Round::PlusInf => !neg,
            Round::MinusInf => neg,
            _ => false,
        };
    } else {
        q = mant >> drop;
        let rem = mant & ((1u128 << drop) - 1);
        let half = 1u128 << (drop - 1);
        inexact = rem != 0;
        up = match rounding {
            Round::Nearest => rem > half || (rem == half && q & 1 == 1),
            Round::TieAway => rem >= half,
            Round::PlusInf => inexact && !neg,
            Round::MinusInf => inexact && neg,
            Round::Zero | Round::Odd => false,
        };
    }
    if up {
        q += 1;
    }
    if rounding == Round::Odd && inexact {
        q |= 1;
    }
    if inexact {
        *flags |= IXC;
        if tiny {
            *flags |= UFC;
        }
    }
    // `q` is the significand at the rounded position; a carry may have made it
    // one bit wider, and a denormal that rounded up may have become normal.
    let mut exp_field = if tiny { 0i64 } else { (e + fmt.bias()) as i64 };
    if tiny {
        if q >> fmt.mbits != 0 {
            exp_field = 1;
        }
    } else if q >> (fmt.mbits + 1) != 0 {
        q >>= 1;
        exp_field += 1;
    }
    if exp_field >= fmt.emax_field() as i64 {
        *flags |= OFC | IXC;
        let to_inf = match rounding {
            // Round to odd overflows to infinity here, as measured on a real
            // arm64 kernel (a largest-finite result was wrong in every case).
            Round::Nearest | Round::TieAway | Round::Odd => true,
            Round::PlusInf => !neg,
            Round::MinusInf => neg,
            Round::Zero => false,
        };
        return if to_inf { fmt.infinity(neg) } else { fmt.max_finite(neg) };
    }
    sign | ((exp_field as u64) << fmt.mbits) | (q as u64 & ((1 << fmt.mbits) - 1))
}

/// `FPAdd`.
pub fn fpadd(a: u64, b: u64, fmt: Fmt, env: Env, rounding: Round, flags: &mut u8) -> u64 {
    let (x, y) = (unpack(a, fmt, env, flags), unpack(b, fmt, env, flags));
    if let Some(n) = process_nans(&[x, y], fmt, env, flags) {
        return n;
    }
    match (x, y) {
        (Val::Inf(s1), Val::Inf(s2)) => {
            if s1 == s2 {
                fmt.infinity(s1)
            } else {
                *flags |= IOC;
                fmt.default_nan()
            }
        }
        (Val::Inf(s), _) | (_, Val::Inf(s)) => fmt.infinity(s),
        (Val::Zero(s1), Val::Zero(s2)) => fmt.zero(if rounding == Round::MinusInf { s1 || s2 } else { s1 && s2 }),
        (Val::Zero(_), Val::Num { neg, mant, exp }) | (Val::Num { neg, mant, exp }, Val::Zero(_)) => {
            round(neg, mant as u128, exp, fmt, rounding, env, flags)
        }
        (Val::Num { neg: n1, mant: m1, exp: e1 }, Val::Num { neg: n2, mant: m2, exp: e2 }) => {
            add_nums(n1, m1, e1, n2, m2, e2, fmt, env, rounding, flags)
        }
        _ => fmt.default_nan(),
    }
}

/// `FPSub`: an add of the negated second operand, except that a NaN second
/// operand is returned as it was (`FPSub` unpacks before it negates).
pub fn fpsub(a: u64, b: u64, fmt: Fmt, env: Env, rounding: Round, flags: &mut u8) -> u64 {
    let (x, y) = (unpack(a, fmt, env, &mut 0), unpack(b, fmt, env, &mut 0));
    if matches!(x, Val::Nan(..)) || matches!(y, Val::Nan(..)) {
        return fpadd(a, b, fmt, env, rounding, flags);
    }
    fpadd(a, b ^ fmt.sign_bit(), fmt, env, rounding, flags)
}

#[allow(clippy::too_many_arguments)]
fn add_nums(n1: bool, m1: u64, e1: i32, n2: bool, m2: u64, e2: i32, fmt: Fmt, env: Env, r: Round, flags: &mut u8) -> u64 {
    // Align to the smaller exponent. Beyond 60 bits of separation the smaller
    // operand cannot change any bit the result keeps, only whether it is
    // inexact and which way it rounds, so it is replaced by a sticky unit far
    // below the larger one's last bit.
    let (big, small) = if e1 >= e2 { ((n1, m1, e1), (n2, m2, e2)) } else { ((n2, m2, e2), (n1, m1, e1)) };
    let spread = big.2 - small.2;
    let (sm, se) = if spread > 60 { (1u64, big.2 - 64) } else { (small.1, small.2) };
    let e = se.min(big.2);
    let vb = (big.1 as i128) << (big.2 - e) as u32;
    let vs = (sm as i128) << (se - e) as u32;
    let sum = (if big.0 { -vb } else { vb }) + (if small.0 { -vs } else { vs });
    if sum == 0 {
        return fmt.zero(r == Round::MinusInf);
    }
    round(sum < 0, sum.unsigned_abs(), e, fmt, r, env, flags)
}

/// `FPMulAdd`: `acc + a * b` rounded once.
pub fn fpmuladd(acc: u64, a: u64, b: u64, fmt: Fmt, env: Env, rounding: Round, flags: &mut u8) -> u64 {
    fpmuladd_scaled(acc, a, b, 0, fmt, env, rounding, flags)
}

/// `FPMulAdd` with the exact sum multiplied by `2^scale` before it is rounded:
/// `FRSQRTS` is `(3 + a*b) / 2` rounded once.
#[allow(clippy::too_many_arguments)]
pub fn fpmuladd_scaled(acc: u64, a: u64, b: u64, scale: i32, fmt: Fmt, env: Env, rounding: Round, flags: &mut u8) -> u64 {
    let (va, x, y) = (unpack(acc, fmt, env, flags), unpack(a, fmt, env, flags), unpack(b, fmt, env, flags));
    // A signaling NaN in any operand, then a quiet one, addend first (measured:
    // an accumulator that is a signaling NaN wins over one in a multiplicand).
    let nan = process_nans(&[va, x, y], fmt, env, flags);
    let inf_times_zero = matches!((x, y), (Val::Inf(_), Val::Zero(_)) | (Val::Zero(_), Val::Inf(_)));
    if matches!(va, Val::Nan(_, false)) && inf_times_zero {
        *flags |= IOC;
        return fmt.default_nan();
    }
    if let Some(n) = nan {
        return n;
    }
    let sign_p = |x: Val, y: Val| -> bool {
        let s = |v: Val| match v {
            Val::Zero(s) | Val::Inf(s) | Val::Num { neg: s, .. } => s,
            Val::Nan(..) => false,
        };
        s(x) != s(y)
    };
    let inf_p = matches!(x, Val::Inf(_)) || matches!(y, Val::Inf(_));
    let zero_p = matches!(x, Val::Zero(_)) || matches!(y, Val::Zero(_));
    let neg_p = sign_p(x, y);
    if inf_times_zero || matches!(va, Val::Inf(s) if inf_p && s != neg_p) {
        *flags |= IOC;
        return fmt.default_nan();
    }
    if let Val::Inf(s) = va {
        return fmt.infinity(s);
    }
    if inf_p {
        return fmt.infinity(neg_p);
    }
    if let (Val::Zero(sa), true) = (va, zero_p)
        && sa == neg_p
    {
        return fmt.zero(sa);
    }
    // The exact value: acc + a*b.
    let (pm, pe): (u128, i32) = match (x, y) {
        (Val::Num { mant: m1, exp: e1, .. }, Val::Num { mant: m2, exp: e2, .. }) => (m1 as u128 * m2 as u128, e1 + e2),
        _ => (0, 0),
    };
    let (am, ae, an): (u128, i32, bool) = match va {
        Val::Num { neg, mant, exp } => (mant as u128, exp, neg),
        _ => (0, 0, false),
    };
    let sum_neg;
    let (mant, exp);
    if pm == 0 && am == 0 {
        return fmt.zero(rounding == Round::MinusInf);
    } else if pm == 0 {
        (mant, exp, sum_neg) = (am, ae, an);
    } else if am == 0 {
        (mant, exp, sum_neg) = (pm, pe, neg_p);
    } else {
        // Align. The product is at most 2*(mbits+1) bits wide and the addend
        // mbits+1; a spread beyond 120 bits leaves the smaller one as sticky.
        let e = pe.min(ae);
        let (sp, sa) = ((pe - e) as u32, (ae - e) as u32);
        if sp > 60 || sa > 60 {
            let ((bm, be, bn), (_, _, sn)) = if pe >= ae { ((pm, pe, neg_p), (am, ae, an)) } else { ((am, ae, an), (pm, pe, neg_p)) };
            let big = (bm as i128) << 64;
            let small: i128 = 1;
            let sum = (if bn { -big } else { big }) + (if sn { -small } else { small });
            return round(sum < 0, sum.unsigned_abs(), be - 64 + scale, fmt, rounding, env, flags);
        }
        let vp = (pm as i128) << sp;
        let va_ = (am as i128) << sa;
        let sum = (if neg_p { -vp } else { vp }) + (if an { -va_ } else { va_ });
        if sum == 0 {
            return fmt.zero(rounding == Round::MinusInf);
        }
        (mant, exp, sum_neg) = (sum.unsigned_abs(), e, sum < 0);
    }
    round(sum_neg, mant, exp + scale, fmt, rounding, env, flags)
}

/// `FPMul`.
pub fn fpmul(a: u64, b: u64, fmt: Fmt, env: Env, rounding: Round, flags: &mut u8) -> u64 {
    let (x, y) = (unpack(a, fmt, env, flags), unpack(b, fmt, env, flags));
    if let Some(n) = process_nans(&[x, y], fmt, env, flags) {
        return n;
    }
    match (x, y) {
        (Val::Inf(_), Val::Zero(_)) | (Val::Zero(_), Val::Inf(_)) => {
            *flags |= IOC;
            fmt.default_nan()
        }
        (Val::Inf(s1), Val::Inf(s2)) | (Val::Inf(s1), Val::Num { neg: s2, .. }) | (Val::Num { neg: s1, .. }, Val::Inf(s2)) => {
            fmt.infinity(s1 != s2)
        }
        (Val::Zero(s1), Val::Zero(s2)) | (Val::Zero(s1), Val::Num { neg: s2, .. }) | (Val::Num { neg: s1, .. }, Val::Zero(s2)) => {
            fmt.zero(s1 != s2)
        }
        (Val::Num { neg: n1, mant: m1, exp: e1 }, Val::Num { neg: n2, mant: m2, exp: e2 }) => {
            round(n1 != n2, m1 as u128 * m2 as u128, e1 + e2, fmt, rounding, env, flags)
        }
        _ => fmt.default_nan(),
    }
}

/// `FPConvert` from single to bfloat16 (`BFCVT`): rounds by the given mode and
/// treats NaNs, denormals and flags as `env` says.
pub fn f32_to_bf16(x: u32, env: Env, rounding: Round, flags: &mut u8) -> u16 {
    match unpack(x as u64, SINGLE, env, flags) {
        Val::Nan(bits, signaling) => {
            if signaling {
                *flags |= IOC;
            }
            if env.dn { BFLOAT.default_nan() as u16 } else { ((bits >> 16) as u16) | BFLOAT.quiet_bit() as u16 }
        }
        Val::Inf(s) => BFLOAT.infinity(s) as u16,
        Val::Zero(s) => BFLOAT.zero(s) as u16,
        Val::Num { neg, mant, exp } => round(neg, mant as u128, exp, BFLOAT, rounding, env, flags) as u16,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENV: Env = Env { fz: false, fz_out: false, dn: false, idc: true };

    fn add32(a: f32, b: f32, r: Round) -> (f32, u8) {
        let mut fl = 0;
        let out = fpadd(a.to_bits() as u64, b.to_bits() as u64, SINGLE, ENV, r, &mut fl);
        (f32::from_bits(out as u32), fl)
    }

    #[test]
    fn nearest_matches_the_host() {
        for (a, b) in [(1.0f32, 2.0), (0.1, 0.2), (1e30, 1e30), (-3.5, 3.5), (1.0, 1e-10), (16777216.0, 1.0)] {
            let (got, _) = add32(a, b, Round::Nearest);
            assert_eq!(got.to_bits(), (a + b).to_bits(), "{a} + {b}");
        }
    }

    #[test]
    fn round_to_odd_sets_the_last_bit_when_inexact() {
        // 2^24 + 1 is not a single: round-to-odd truncates and sets the last bit.
        let (got, fl) = add32(16777216.0, 1.0, Round::Odd);
        assert_eq!(fl, IXC);
        assert_eq!(got.to_bits() & 1, 1);
        // An exact sum is left alone.
        let (got, fl) = add32(16777216.0, 2.0, Round::Odd);
        assert_eq!((got, fl), (16777218.0, 0));
    }

    #[test]
    fn overflow_and_flags() {
        let (got, fl) = add32(f32::MAX, f32::MAX, Round::Nearest);
        assert_eq!((got, fl), (f32::INFINITY, OFC | IXC));
        // Round to odd overflows to infinity too.
        let (got, fl) = add32(f32::MAX, f32::MAX, Round::Odd);
        assert_eq!((got, fl), (f32::INFINITY, OFC | IXC));
        let (got, fl) = add32(f32::INFINITY, f32::NEG_INFINITY, Round::Nearest);
        assert_eq!((got.to_bits(), fl), (0x7fc0_0000, IOC));
    }

    #[test]
    fn a_zero_sum_takes_its_sign_from_the_rounding_mode() {
        assert_eq!(add32(1.0, -1.0, Round::Nearest).0.to_bits(), 0);
        assert_eq!(add32(1.0, -1.0, Round::MinusInf).0.to_bits(), 0x8000_0000);
        assert_eq!(add32(-0.0, -0.0, Round::Nearest).0.to_bits(), 0x8000_0000);
    }

    #[test]
    fn denormals_and_flush_to_zero() {
        let tiny = f32::from_bits(1);
        let (got, fl) = add32(tiny, tiny, Round::Nearest);
        assert_eq!((got.to_bits(), fl), (2, 0));
        let mut fl = 0;
        let fz = Env { fz: true, fz_out: true, dn: false, idc: true };
        let out = fpadd(1, 1, SINGLE, fz, Round::Nearest, &mut fl);
        assert_eq!((out, fl), (0, IDC));
    }

    #[test]
    fn half_precision_rounds_like_half() {
        let mut fl = 0;
        // 1.0 + 2^-11 is halfway between 1.0 and 1.0 + 2^-10 -> ties to even (1.0)
        let out = fpadd(0x3c00, 0x1000, HALF, ENV, Round::Nearest, &mut fl);
        assert_eq!((out, fl), (0x3c00, IXC));
        let out = fpmul(0x7bff, 0x7bff, HALF, ENV, Round::Nearest, &mut fl);
        assert_eq!(out, 0x7c00);
    }
}
