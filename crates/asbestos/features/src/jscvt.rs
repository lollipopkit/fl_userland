//! `FJCVTZS Wd, Dn`: the JavaScript double-to-int32 conversion (FEAT_JSCVT).
//!
//! ECMAScript `ToInt32` truncates toward zero and keeps the low 32 bits, so
//! 2^32 + 5 is 5 and -1.5 is -1. The instruction does that in one step and
//! reports in Z whether the conversion was exact, which is how JavaScriptCore
//! and V8 decide whether they may keep an integer representation.
//!
//! It is written as integer arithmetic on the bit pattern. The host FPU is not
//! consulted: its rounding mode and flush-to-zero setting are the *guest's*
//! FPCR, and the answer here depends on neither, except that FZ turns a
//! subnormal input into zero and raises IDC.
//!
//! Every value in the tests was measured on a real arm64 kernel
//! (`tests/guest/src/bin/insn_features.rs` is the differential).

/// Cumulative exception flags in FPSR.
pub const IOC: u8 = 1 << 0;
pub const IXC: u8 = 1 << 4;
pub const IDC: u8 = 1 << 7;

/// FPCR.FZ.
const FZ: u64 = 1 << 24;

/// What `FJCVTZS` produces.
#[derive(Debug, PartialEq, Eq)]
pub struct Conversion {
    pub result: u32,
    /// The Z flag; N, C and V are always clear.
    pub z: bool,
    /// The FPSR flags to set, ORed into what is there.
    pub flags: u8,
}

pub fn fjcvtzs(op: u64, fpcr: u64) -> Conversion {
    let negative = op >> 63 != 0;
    let exp = (op >> 52) & 0x7ff;
    let frac = op & ((1 << 52) - 1);
    let out = |result: u32, z: bool, flags: u8| Conversion { result, z, flags };

    // A NaN or an infinity has no integer value: zero, and Invalid Operation.
    if exp == 0x7ff {
        return out(0, false, IOC);
    }
    if exp == 0 {
        if frac == 0 {
            // +0 converts exactly; -0 does not, because ToInt32 cannot say it.
            return out(0, !negative, 0);
        }
        // A subnormal is a nonzero magnitude below one: truncation gives 0 and
        // is inexact; with FZ it is flushed to zero instead and only the
        // input-denormal flag is raised.
        return if fpcr & FZ != 0 { out(0, false, IDC) } else { out(0, false, IXC) };
    }

    // 1.frac * 2^e as a 53-bit integer and a shift.
    let e = exp as i32 - 1023;
    let mant = (1u64 << 52) | frac;
    // The truncated magnitude (modulo 2^64), whether all of it is known, and
    // whether anything was dropped.
    let (magnitude, complete, inexact) = if e < 0 {
        (0u64, true, true)
    } else if e <= 52 {
        let shift = 52 - e;
        (mant >> shift, true, mant & ((1u64 << shift) - 1) != 0)
    } else {
        // Every bit of the fraction is above the binary point and only the low
        // 32 of the result matter; a shift of 64 or more leaves them zero.
        let shift = e - 52;
        (if shift >= 64 { 0 } else { mant << shift }, false, false)
    };
    let result = (if negative { magnitude.wrapping_neg() } else { magnitude }) as u32;
    // In range when the truncated value is a signed 32-bit integer.
    let in_range = complete
        && if negative { magnitude <= 1 << 31 } else { magnitude < 1 << 31 };
    if !in_range {
        return out(result, false, IOC);
    }
    if inexact {
        return out(result, false, IXC);
    }
    out(result, true, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(op: u64, fpcr: u64) -> (u32, bool, u8) {
        let c = fjcvtzs(op, fpcr);
        (c.result, c.z, c.flags)
    }

    /// Each row is a measurement from a real kernel.
    #[test]
    fn matches_the_hardware() {
        assert_eq!(c(0, 0), (0, true, 0), "+0 is exact");
        assert_eq!(c(0x8000_0000_0000_0000, 0), (0, false, 0), "-0 is not");
        assert_eq!(c(0x3ff0_0000_0000_0000, 0), (1, true, 0));
        assert_eq!(c(0x3ff8_0000_0000_0000, 0), (1, false, IXC), "1.5");
        assert_eq!(c(0xbff8_0000_0000_0000, 0), (0xffff_ffff, false, IXC), "-1.5");
        assert_eq!(c(0x3fe0_0000_0000_0000, 0), (0, false, IXC), "0.5");
        assert_eq!(c(1, 0), (0, false, IXC), "the smallest subnormal");
        assert_eq!(c(1, FZ), (0, false, IDC), "flushed: only the input flag");
        assert_eq!(c(0x000f_ffff_ffff_ffff, FZ), (0, false, IDC));
        for special in [
            0x7ff0_0000_0000_0000u64,
            0xfff0_0000_0000_0000,
            0x7ff8_0000_0000_0000,
            0x7ff0_0000_0000_0001,
        ] {
            assert_eq!(c(special, 0), (0, false, IOC));
        }
        assert_eq!(c(0x41df_ffff_ffc0_0000, 0), (0x7fff_ffff, true, 0), "2^31-1");
        assert_eq!(c(0x41e0_0000_0000_0000, 0), (0x8000_0000, false, IOC), "2^31 wraps");
        assert_eq!(c(0xc1e0_0000_0000_0000, 0), (0x8000_0000, true, 0), "-2^31 fits");
        assert_eq!(c(0xc1e0_0000_0020_0000, 0), (0x7fff_ffff, false, IOC), "-2^31-1");
        assert_eq!(c(0x41f0_0000_0000_0000, 0), (0, false, IOC), "2^32");
        assert_eq!(c(0x41ef_ffff_ffe0_0000, 0), (0xffff_ffff, false, IOC), "2^32-1");
        assert_eq!(c(0x4330_0000_0000_0000, 0), (0, false, IOC), "2^52");
        assert_eq!(c(0x43e0_0000_0000_0000, 0), (0, false, IOC), "2^63");
        assert_eq!(c(0x7fef_ffff_ffff_ffff, 0), (0, false, IOC), "the largest finite");
        assert_eq!(c(0x4160_0000_0000_0001, 0), (0x80_0000, false, IXC));
    }

    #[test]
    fn the_low_word_of_a_large_value_is_kept() {
        // 2^32 + 5 as a double.
        let v = (4294967301.0f64).to_bits();
        assert_eq!(c(v, 0), (5, false, IOC));
    }
}
