//! #22 — the AdvSIMD lane narrow and widen conversions had no gadget.
//!
//! `FCVTN`/`FCVTN2`, `FCVTL`/`FCVTL2` and `FCVTXN`/`FCVTXN2` are mandatory
//! ARMv8.0-A Advanced SIMD and this emulator advertises `asimd`, so a guest
//! executing one was killed outright. numpy's `float64`↔`float32` `.astype()`
//! hits them.
//!
//! Every expected value here was taken from running the same helpers **natively
//! on an Apple Silicon host**, so this checks the emulated result bit for bit
//! against real hardware rather than against a re-derivation of the spec.
//!
//! `tests/regress/regress_asimd_fcvt.c` + `.S` until 2026-09-09, where they
//! needed an aarch64 cross-compiler that is usually not installed.
//!
//! # Why the instructions are in `global_asm!`
//!
//! Each helper is a whole function, so nothing can be scheduled between the
//! load, the instruction under test and the store. `asm!` inside a function
//! does not give that: the compiler is free to insert code around it, and a
//! spilled vector register would be converted by the *host* rather than by the
//! gadget. It was a separate `.S` file for the same reason;
//! `global_asm!` is that, assembled by LLVM through rustc rather than by a
//! cross-assembler nobody has installed.

use std::arch::global_asm;

use guest_tests::{check, Harness};

global_asm!(
    r#"
.text
.global do_fcvtn
.align 4
do_fcvtn:                  // 2xdouble -> 2xfloat, low half; x0=in x1=out
    ldr q0, [x0]
    movi v1.4s, #0
    fcvtn v1.2s, v0.2d
    str q1, [x1]
    ret

.global do_fcvtn2
.align 4
do_fcvtn2:                 // narrow into the high half; x2 seeds the low half
    ldr q0, [x0]
    ldr q1, [x2]
    fcvtn2 v1.4s, v0.2d
    str q1, [x1]
    ret

.global do_fcvtl
.align 4
do_fcvtl:                  // 2xfloat -> 2xdouble
    ldr q0, [x0]
    movi v1.4s, #0
    fcvtl v1.2d, v0.2s
    str q1, [x1]
    ret

.global do_fcvtl2
.align 4
do_fcvtl2:                 // widen the HIGH two floats
    ldr q0, [x0]
    movi v1.4s, #0
    fcvtl2 v1.2d, v0.4s
    str q1, [x1]
    ret

.global do_fcvtxn
.align 4
do_fcvtxn:                 // narrow with round-to-odd
    ldr q0, [x0]
    movi v1.4s, #0
    fcvtxn v1.2s, v0.2d
    str q1, [x1]
    ret

.global do_fcvtxn2
.align 4
do_fcvtxn2:
    ldr q0, [x0]
    ldr q1, [x2]
    fcvtxn2 v1.4s, v0.2d
    str q1, [x1]
    ret

.global do_fcvtn_h
.align 4
do_fcvtn_h:                // 4xsingle -> 4xhalf (the sz=0 form)
    ldr q0, [x0]
    movi v1.4s, #0
    fcvtn v1.4h, v0.4s
    str q1, [x1]
    ret

.global do_fcvtl_h
.align 4
do_fcvtl_h:                // 4xhalf -> 4xsingle (the sz=0 form)
    ldr q0, [x0]
    movi v1.4s, #0
    fcvtl v1.4s, v0.4h
    str q1, [x1]
    ret
"#
);

unsafe extern "C" {
    fn do_fcvtn(input: *const u64, out: *mut u64);
    fn do_fcvtn2(input: *const u64, out: *mut u64, seed: *const u64);
    fn do_fcvtl(input: *const u64, out: *mut u64);
    fn do_fcvtl2(input: *const u64, out: *mut u64);
    fn do_fcvtxn(input: *const u64, out: *mut u64);
    fn do_fcvtxn2(input: *const u64, out: *mut u64, seed: *const u64);
    fn do_fcvtn_h(input: *const u64, out: *mut u64);
    fn do_fcvtl_h(input: *const u64, out: *mut u64);
}

/// Sixteen bytes, aligned, which is what a `ldr q` and a `str q` want.
#[repr(C, align(16))]
struct V([u64; 2]);

fn eq(h: &mut Harness, name: &str, got: &V, want: [u64; 2]) {
    check!(
        h,
        got.0 == want,
        "{name}: {:016x} {:016x}, wanted {:016x} {:016x}",
        got.0[0],
        got.0[1],
        want[0],
        want[1]
    );
}

fn main() {
    let mut h = Harness::new();
    h.group("fcvt");

    let d2 = V([0x3FF8_0000_0000_0000, 0xC002_0000_0000_0000]); // 1.5, -2.25
    let s2 = V([0xC098_0000_4060_0000, 0]); // 3.5f, -4.75f
    let s4 = V([0xC098_0000_4060_0000, 0x4110_0000_4100_0000]); // +8.0f, 9.0f high
    let seed = V([0x4100_0000_4110_0000, 0]); // 9.0f, 8.0f

    let mut o = V([0, 0]);
    // SAFETY: every helper reads sixteen aligned bytes at `x0` (and `x2`) and
    // writes sixteen at `x1`. `V` is exactly that.
    unsafe {
        do_fcvtn(d2.0.as_ptr(), o.0.as_mut_ptr());
        eq(&mut h, "FCVTN", &o, [0xC010_0000_3FC0_0000, 0]);

        o = V([0, 0]);
        do_fcvtn2(d2.0.as_ptr(), o.0.as_mut_ptr(), seed.0.as_ptr());
        eq(&mut h, "FCVTN2", &o, [seed.0[0], 0xC010_0000_3FC0_0000]);

        o = V([0, 0]);
        do_fcvtl(s2.0.as_ptr(), o.0.as_mut_ptr());
        eq(&mut h, "FCVTL", &o, [0x400C_0000_0000_0000, 0xC013_0000_0000_0000]); // 3.5, -4.75

        o = V([0, 0]);
        do_fcvtl2(s4.0.as_ptr(), o.0.as_mut_ptr());
        eq(&mut h, "FCVTL2", &o, [0x4020_0000_0000_0000, 0x4022_0000_0000_0000]); // 8.0, 9.0

        o = V([0, 0]);
        do_fcvtxn(d2.0.as_ptr(), o.0.as_mut_ptr());
        eq(&mut h, "FCVTXN", &o, [0xC010_0000_3FC0_0000, 0]);

        o = V([0, 0]);
        do_fcvtxn2(d2.0.as_ptr(), o.0.as_mut_ptr(), seed.0.as_ptr());
        eq(&mut h, "FCVTXN2", &o, [seed.0[0], 0xC010_0000_3FC0_0000]);
    }

    h.group("fcvt-sz0");
    // The single<->half forms. 3.5 -> 0x4300, -4.75 -> 0xC4C0, 8.0 -> 0x4800,
    // 9.0 -> 0x4880.
    let f4 = V([0xC098_0000_4060_0000, 0x4110_0000_4100_0000]);
    let packed = 0x4880_4800_C4C0_4300u64;
    // SAFETY: as above.
    unsafe {
        o = V([0, 0]);
        do_fcvtn_h(f4.0.as_ptr(), o.0.as_mut_ptr());
        eq(&mut h, "FCVTN.4h", &o, [packed, 0]);

        let h4 = V([packed, 0]);
        o = V([0, 0]);
        do_fcvtl_h(h4.0.as_ptr(), o.0.as_mut_ptr());
        eq(&mut h, "FCVTL.4s", &o, [0xC098_0000_4060_0000, 0x4110_0000_4100_0000]);
    }

    h.group("round-to-odd");
    // A double just above 1.0 that is not representable in single. Round-to-odd
    // must give the odd-mantissa neighbour 0x3F800001, where FCVTN's
    // round-to-nearest-even gives exactly 1.0.
    let tiny = V([0x3FF0_0000_0000_0001, 0x3FF0_0000_0000_0001]);
    // SAFETY: as above.
    unsafe {
        o = V([0, 0]);
        do_fcvtxn(tiny.0.as_ptr(), o.0.as_mut_ptr());
        let lo = o.0[0] as u32;
        check!(h, lo == 0x3F80_0001, "FCVTXN rounds to odd: {lo:#010x}");

        o = V([0, 0]);
        do_fcvtn(tiny.0.as_ptr(), o.0.as_mut_ptr());
        let lo = o.0[0] as u32;
        check!(h, lo == 0x3F80_0000, "FCVTN rounds to nearest even: {lo:#010x}");
    }

    std::process::exit(h.finish());
}
