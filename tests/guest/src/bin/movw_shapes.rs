//! Constant materialisation: `MOVZ`, `MOVK`, `MOVN`, in every shape.
//!
//! Written with inline assembly rather than by letting the compiler choose, so
//! that the exact instruction sequences are the ones under test — including the
//! ones a compiler would never emit, like a `MOVK` whose `hw` repeats a field
//! the `MOVZ` already wrote.
//!
//! It was written as the safety net for fusing a `MOVZ` with the `MOVK` chain
//! after it into one gadget. That fusion was built, measured, and **backed out**
//! — it fired on 1% of translated `MOVZ` and bought nothing outside the noise.
//!
//! The test stays, because constant materialisation had no coverage of its own
//! and the shapes below are worth pinning whatever the generator does with
//! them.
//!
//! It found an error before any of that: the expected value for
//! `skipped_field` was written for `lsl #48` and the instruction says
//! `lsl #32`. The emulator was right and the test was wrong, which is the
//! usual way round.

use guest_tests::{Harness, check};
use std::arch::asm;

macro_rules! movz_only {
    ($name:ident, $hw:literal, $imm:literal) => {
        fn $name() -> u64 {
            let out: u64;
            unsafe {
                asm!(concat!("movz {o}, #", $imm, ", lsl #", $hw), o = out(reg) out);
            }
            out
        }
    };
}

movz_only!(z0, 0, 0x1234);
movz_only!(z16, 16, 0x1234);
movz_only!(z32, 32, 0x1234);
movz_only!(z48, 48, 0x1234);

/// A full 64-bit constant: movz plus three movk, the longest chain there is.
fn full64() -> u64 {
    let out: u64;
    unsafe {
        asm!(
            "movz {o}, #0xccd, lsl #0",
            "movk {o}, #0xed55, lsl #16",
            "movk {o}, #0x51af, lsl #32",
            "movk {o}, #0xff00, lsl #48",
            o = out(reg) out
        );
    }
    out
}

/// Two 32-bit halves, which is what a 32-bit constant costs.
fn half32() -> u32 {
    let out: u32;
    unsafe {
        asm!(
            "movz {o:w}, #0x89ab, lsl #0",
            "movk {o:w}, #0x4567, lsl #16",
            o = out(reg) out
        );
    }
    out
}

/// A `MOVK` that rewrites the field the `MOVZ` just wrote. Legal, and a fusion
/// that ORs instead of replacing gets it wrong.
fn overwrite_same_field() -> u64 {
    let out: u64;
    unsafe {
        asm!(
            "movz {o}, #0xffff, lsl #0",
            "movk {o}, #0x0001, lsl #0",
            o = out(reg) out
        );
    }
    out
}

/// `MOVK` chain that skips a field, so bits 16..32 stay zero.
fn skipped_field() -> u64 {
    let out: u64;
    unsafe {
        asm!(
            "movz {o}, #0xaaaa, lsl #0",
            "movk {o}, #0xbbbb, lsl #32",
            o = out(reg) out
        );
    }
    out
}

/// A 32-bit `MOVZ` must zero the top half of the 64-bit register.
fn w_zero_extends() -> u64 {
    let out: u64;
    unsafe {
        asm!(
            "movz {o}, #0xffff, lsl #48",   // dirty the top half first
            "movz {o:w}, #0x1111, lsl #0",  // 32-bit write must clear it
            o = out(reg) out
        );
    }
    out
}

/// `MOVN` is not fused, and must keep working beside the ones that are.
fn movn_then_movk() -> u64 {
    let out: u64;
    unsafe {
        asm!(
            "movn {o}, #0x0000, lsl #0",    // all ones
            "movk {o}, #0x1234, lsl #16",
            o = out(reg) out
        );
    }
    out
}

/// A `MOVZ`/`MOVK` pair separated by an unrelated instruction: not a chain, and
/// a fusion that looks past the intervening instruction would corrupt it.
fn interrupted_chain() -> u64 {
    let out: u64;
    let other: u64;
    unsafe {
        asm!(
            "movz {o}, #0x1111, lsl #0",
            "movz {t}, #0x9999, lsl #0",
            "movk {o}, #0x2222, lsl #16",
            o = out(reg) out,
            t = out(reg) other,
        );
    }
    // `other` must be untouched by the movk that follows it.
    assert_eq!(other, 0x9999, "the intervening instruction was clobbered");
    out
}

fn main() {
    let mut h = Harness::new();
    h.group("movw");

    check!(h, z0() == 0x1234, "movz lsl 0: {:#x}", z0());
    check!(h, z16() == 0x1234_0000, "movz lsl 16: {:#x}", z16());
    check!(h, z32() == 0x1234_0000_0000, "movz lsl 32: {:#x}", z32());
    check!(h, z48() == 0x1234_0000_0000_0000, "movz lsl 48: {:#x}", z48());

    check!(h, full64() == 0xff00_51af_ed55_0ccd,
           "movz + three movk: {:#x}", full64());
    check!(h, half32() == 0x4567_89ab, "32-bit movz + movk: {:#x}", half32());
    check!(h, overwrite_same_field() == 0x0001,
           "movk replacing the field movz wrote: {:#x}", overwrite_same_field());
    check!(h, skipped_field() == 0x0000_bbbb_0000_aaaa,
           "movk chain that skips a field: {:#x}", skipped_field());
    check!(h, w_zero_extends() == 0x1111,
           "a 32-bit movz zeroes the top half: {:#x}", w_zero_extends());
    check!(h, movn_then_movk() == 0xffff_ffff_1234_ffff,
           "movn then movk: {:#x}", movn_then_movk());
    check!(h, interrupted_chain() == 0x2222_1111,
           "a chain with an instruction in the middle: {:#x}", interrupted_chain());

    std::process::exit(h.finish());
}
