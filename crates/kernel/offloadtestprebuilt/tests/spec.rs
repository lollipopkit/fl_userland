//! What a generated spec_fn is written against.
//!
//! In `tests/` rather than a `#[cfg(test)] mod`, for the reason
//! `tests/register.rs` gives: the `--lib` test target cannot link, because the
//! registration constructor keeps every spec_fn alive and through them the
//! gadgets.

// The gadget symbols and `iul_printk`.
use iul as _;

use offloadtestprebuilt::spec::*;

/// The two that C's operators get wrong for AArch64, and the one Rust
/// panics on.
#[test]
fn the_arithmetic_is_the_guests() {
    assert_eq!(add(u64::MAX, 1), 0, "wraps rather than panicking");
    assert_eq!(sub(0, 1), u64::MAX);
    assert_eq!(udiv(1, 0), 0, "AArch64 answers zero, not a trap");
    assert_eq!(sdiv(-8i64 as u64, 0), 0);
    assert_eq!(sdiv(-8i64 as u64, 2), -4i64 as u64);
    assert_eq!(
        sar(-8i64 as u64, 1),
        -4i64 as u64,
        "arithmetic, not logical"
    );
    assert_eq!(shr(-8i64 as u64, 1), 0x7fff_ffff_ffff_fffc);
    // A shift amount of the register width **masks to zero** rather than
    // producing zero: `LSL Xd, Xn, Xm` uses `Xm mod 64`. Rust's `<<` panics
    // here and C's is undefined, which is why these are functions.
    assert_eq!(shl(1, 64), 1);
    assert_eq!(shr(2, 64), 2);
    assert_eq!(sar(-2i64 as u64, 64), -2i64 as u64);
    assert_eq!(ror(1, 64), 1);
    assert_eq!(sx(8, 0xff), u64::MAX);
    assert_eq!(zx(8, 0xffff), 0xff);
    assert_eq!(w32(0x1_0000_0001), 1);
    assert_eq!(umulh(u64::MAX, 2), 1);
    assert_eq!(smulh(-1i64 as u64, 2), u64::MAX);
    assert_eq!(rev16(0x0102_0304_0506_0708), 0x0201_0403_0605_0807);
    assert_eq!(
        clz(32, 0xffff_ffff_0000_0001),
        31,
        "the w form ignores the top half"
    );
}

/// Every condition, against the pair a `cmp` would have set.
#[test]
fn the_conditions_read_the_pair() {
    let mut f = Flags::default();
    f.cmp(1, 1);
    assert!(f.eq() && !f.ne() && f.hs() && f.ls() && f.ge() && f.le());
    f.cmp(2, 1);
    assert!(f.ne() && f.hi() && f.gt() && !f.lo() && !f.lt());
    // Signed and unsigned disagree here, which is the whole reason both
    // sets exist.
    f.cmp(-1i64 as u64, 1);
    assert!(f.hi(), "unsigned: all-ones is the largest");
    assert!(f.lt(), "signed: it is -1");
}

#[test]
fn an_unordered_fcmp_is_neither_greater_nor_equal() {
    let mut f = Flags::default();
    f.fcmp(f64::NAN, 1.0);
    assert!(!f.gt() && !f.ge() && !f.eq());
    f.fcmp(2.0, 1.0);
    assert!(f.gt() && f.ge() && !f.eq());
    f.fcmp(1.0, 1.0);
    assert!(f.eq() && f.ge() && f.le());
}
