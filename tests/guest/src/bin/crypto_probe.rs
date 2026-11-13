//! Every AArch64 cryptographic and SIMD-permute instruction the interpreter
//! implements in software, printed rather than asserted.
//!
//! # Why this is a probe
//!
//! `asbestos/guest-arm64/crypto_helpers.c` is 1295 lines implementing forty of
//! these instructions, called from the gadgets in `crypto.S` by name.
//! **Nothing tested any of them.** They are reachable only from assembly, so
//! all forty sit in `tools/dead-exports.py`'s allowlist, and no test in the
//! tree named AES, SHA or SM3 before this file.
//!
//! That is the worst shape a defect can have here. A wrong AES round does not
//! crash: it produces the wrong ciphertext, and a guest that encrypts
//! something writes the wrong bytes to disk or the network and carries on. A
//! wrong SHA round gives a wrong digest, which a package manager reports as a
//! corrupt download. Neither is visible from inside the emulator.
//!
//! # The ground truth is the hardware, and the first attempt got that wrong
//!
//! This began as `crypto_abi.rs`, asserting against FIPS-197 and FIPS-180-4
//! vectors written down from memory. Four of its thirty checks failed **on a
//! real arm64 kernel** — the constants were the AES state serialised the other
//! way round, row-major where a `q` register holds it column-major. The
//! emulator was never even reached.
//!
//! So the vectors went and the comparison stayed. This is a static
//! `aarch64-unknown-linux-musl` binary on an Apple Silicon machine, so
//! `tests/integration/probe_diff.sh` runs the *same binary* in an arm64
//! container, where every instruction below is executed by the CPU. Any
//! difference between the two sides is the interpreter getting an instruction
//! wrong, and there is nothing for a mis-transcribed constant to be wrong
//! about.
//!
//! # What it prints
//!
//! One line per instruction per input, plus a few *relations* that have to
//! hold whatever the byte order is — `aesd` undoing `aese`, `aesimc` undoing
//! `aesmc`, and `aese(x, k)` equalling `aese(x ^ k, 0)`. Those last are worth
//! printing because they name which of a pair is broken: a version with
//! `aesmc` and `aesimc` swapped passes any test that uses them together.
//!
//! Inputs are chosen so a lane differs from its neighbours and at least one is
//! negative, which is what tells `usra` from `ssra` and `tbl` from `tbx`.

#![allow(clippy::missing_safety_doc)]


use std::arch::asm;

/// A 128-bit vector, as sixteen bytes in memory order.
type V = [u8; 16];

/// `aese vd.16b, vn.16b` — AddRoundKey, SubBytes, ShiftRows.
///
/// Note the order: ARM's `AESE` xors *first*, so `aese(d, k)` is
/// `ShiftRows(SubBytes(d ^ k))`. Getting that backwards is one of the two
/// mistakes a software implementation makes.
#[target_feature(enable = "aes,sha2,sha3,neon")]
unsafe fn aese(d: V, k: V) -> V {
    let mut out = d;
    unsafe {
        asm!(
            "ldr q0, [{d}]",
            "ldr q1, [{k}]",
            "aese v0.16b, v1.16b",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            k = in(reg) &k,
            out("q0") _, out("q1") _,
        );
    }
    out
}

/// `aesd vd.16b, vn.16b` — the decrypt half: xor, InvShiftRows, InvSubBytes.
#[target_feature(enable = "aes,sha2,sha3,neon")]
unsafe fn aesd(d: V, k: V) -> V {
    let mut out = d;
    unsafe {
        asm!(
            "ldr q0, [{d}]",
            "ldr q1, [{k}]",
            "aesd v0.16b, v1.16b",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            k = in(reg) &k,
            out("q0") _, out("q1") _,
        );
    }
    out
}

/// `aesmc vd.16b, vn.16b` — MixColumns.
#[target_feature(enable = "aes,sha2,sha3,neon")]
unsafe fn aesmc(x: V) -> V {
    let mut out = x;
    unsafe {
        asm!(
            "ldr q0, [{x}]",
            "aesmc v0.16b, v0.16b",
            "str q0, [{x}]",
            x = in(reg) &mut out,
            out("q0") _,
        );
    }
    out
}

/// `aesimc vd.16b, vn.16b` — InvMixColumns.
#[target_feature(enable = "aes,sha2,sha3,neon")]
unsafe fn aesimc(x: V) -> V {
    let mut out = x;
    unsafe {
        asm!(
            "ldr q0, [{x}]",
            "aesimc v0.16b, v0.16b",
            "str q0, [{x}]",
            x = in(reg) &mut out,
            out("q0") _,
        );
    }
    out
}

/// One `.4s` three-operand instruction: `op vd.4s, vn.4s, vm.4s`.
macro_rules! v3_4s {
    ($name:ident, $op:literal) => {
        #[target_feature(enable = "aes,sha2,sha3,neon")]
        unsafe fn $name(d: [u32; 4], n: [u32; 4], m: [u32; 4]) -> [u32; 4] {
            let mut out = d;
            unsafe {
                asm!(
                    "ldr q0, [{d}]",
                    "ldr q1, [{n}]",
                    "ldr q2, [{m}]",
                    concat!($op, " v0.4s, v1.4s, v2.4s"),
                    "str q0, [{d}]",
                    d = in(reg) &mut out,
                    n = in(reg) &n,
                    m = in(reg) &m,
                    out("q0") _, out("q1") _, out("q2") _,
                );
            }
            out
        }
    };
}

/// `SHA256H <Qd>, <Qn>, <Vm>.4S`: the two state halves are whole 128-bit
/// registers and only the third operand is a lane list.
macro_rules! q3_4s {
    ($name:ident, $op:literal) => {
        #[target_feature(enable = "aes,sha2,sha3,neon")]
        unsafe fn $name(d: [u32; 4], n: [u32; 4], m: [u32; 4]) -> [u32; 4] {
            let mut out = d;
            unsafe {
                asm!(
                    "ldr q0, [{d}]",
                    "ldr q1, [{n}]",
                    "ldr q2, [{m}]",
                    concat!($op, " q0, q1, v2.4s"),
                    "str q0, [{d}]",
                    d = in(reg) &mut out,
                    n = in(reg) &n,
                    m = in(reg) &m,
                    out("q0") _, out("q1") _, out("q2") _,
                );
            }
            out
        }
    };
}

/// The same with a scalar `sn` in the second position, which is how the SHA-1
/// round instructions take the rotating `e` word.
macro_rules! v3_s_4s {
    ($name:ident, $op:literal) => {
        #[target_feature(enable = "aes,sha2,sha3,neon")]
        unsafe fn $name(d: [u32; 4], n: u32, m: [u32; 4]) -> [u32; 4] {
            let mut out = d;
            unsafe {
                asm!(
                    "ldr q0, [{d}]",
                    "fmov s1, {n:w}",
                    "ldr q2, [{m}]",
                    concat!($op, " q0, s1, v2.4s"),
                    "str q0, [{d}]",
                    d = in(reg) &mut out,
                    n = in(reg) n,
                    m = in(reg) &m,
                    out("q0") _, out("q1") _, out("q2") _,
                );
            }
            out
        }
    };
}

/// A two-operand `.4s`: `op vd.4s, vn.4s`.
macro_rules! v2_4s {
    ($name:ident, $op:literal) => {
        #[target_feature(enable = "aes,sha2,sha3,neon")]
        unsafe fn $name(d: [u32; 4], n: [u32; 4]) -> [u32; 4] {
            let mut out = d;
            unsafe {
                asm!(
                    "ldr q0, [{d}]",
                    "ldr q1, [{n}]",
                    concat!($op, " v0.4s, v1.4s"),
                    "str q0, [{d}]",
                    d = in(reg) &mut out,
                    n = in(reg) &n,
                    out("q0") _, out("q1") _,
                );
            }
            out
        }
    };
}

/// A three-operand `.16b`: `op vd.16b, vn.16b, vm.16b`.
macro_rules! v3_16b {
    ($name:ident, $op:literal) => {
        #[target_feature(enable = "aes,sha2,sha3,neon")]
        unsafe fn $name(n: V, m: V) -> V {
            let mut out = [0u8; 16];
            unsafe {
                asm!(
                    "ldr q1, [{n}]",
                    "ldr q2, [{m}]",
                    concat!($op, " v0.16b, v1.16b, v2.16b"),
                    "str q0, [{d}]",
                    d = in(reg) &mut out,
                    n = in(reg) &n,
                    m = in(reg) &m,
                    out("q0") _, out("q1") _, out("q2") _,
                );
            }
            out
        }
    };
}

q3_4s!(sha256h, "sha256h");
q3_4s!(sha256h2, "sha256h2");
v3_4s!(sha256su1, "sha256su1");
v2_4s!(sha256su0, "sha256su0");
v3_s_4s!(sha1c, "sha1c");
v3_s_4s!(sha1p, "sha1p");
v3_s_4s!(sha1m, "sha1m");
v3_4s!(sha1su0, "sha1su0");
v2_4s!(sha1su1, "sha1su1");

v3_16b!(zip1_16b, "zip1");
v3_16b!(zip2_16b, "zip2");
v3_16b!(uzp1_16b, "uzp1");
v3_16b!(uzp2_16b, "uzp2");
v3_16b!(trn1_16b, "trn1");
v3_16b!(trn2_16b, "trn2");

/// `sha1h sd, sn` — a plain rotate left by 30, which is the whole instruction.
#[target_feature(enable = "aes,sha2,sha3,neon")]
unsafe fn sha1h(x: u32) -> u32 {
    let out: u32;
    unsafe {
        asm!(
            "fmov s0, {x:w}",
            "sha1h s0, s0",
            "fmov {o:w}, s0",
            x = in(reg) x,
            o = out(reg) out,
            out("q0") _,
        );
    }
    out
}

/// `eor3 vd.16b, vn.16b, vm.16b, va.16b` — a three-way xor, SHA-3 extension.
/// Assembled as `.inst` because it needs `+sha3`, which the baseline target
/// this is built for does not enable.
#[target_feature(enable = "aes,sha2,sha3,neon")]
unsafe fn eor3(n: V, m: V, a: V) -> V {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "ldr q1, [{n}]",
            "ldr q2, [{m}]",
            "ldr q3, [{a}]",
            // EOR3 <Vd>.16B, <Vn>.16B, <Vm>.16B, <Va>.16B
            //   0xce00 0000 | Rm<<16 | Ra<<10 | Rn<<5 | Rd
            //   d=0, n=1, m=2, a=3
            ".inst 0xce020c20",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            m = in(reg) &m,
            a = in(reg) &a,
            out("q0") _, out("q1") _, out("q2") _, out("q3") _,
        );
    }
    out
}

/// `pmull vd.1q, vn.1d, vm.1d` — carry-less multiply of the low halves.
#[target_feature(enable = "aes,sha2,sha3,neon")]
unsafe fn pmull(n: u64, m: u64) -> V {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "fmov d1, {n}",
            "fmov d2, {m}",
            "pmull v0.1q, v1.1d, v2.1d",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) n,
            m = in(reg) m,
            out("q0") _, out("q1") _, out("q2") _,
        );
    }
    out
}

/// `tbl vd.16b, {vn.16b}, vm.16b` — a byte gather; an index past 15 gives 0.
#[target_feature(enable = "aes,sha2,sha3,neon")]
unsafe fn tbl1(table: V, idx: V) -> V {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "ldr q1, [{t}]",
            "ldr q2, [{i}]",
            "tbl v0.16b, {{v1.16b}}, v2.16b",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            t = in(reg) &table,
            i = in(reg) &idx,
            out("q0") _, out("q1") _, out("q2") _,
        );
    }
    out
}

/// `tbx vd.16b, {vn.16b}, vm.16b` — the same, but an index past 15 **leaves
/// the destination byte alone**. That difference from `tbl` is the whole
/// instruction and is exactly the sort of thing a software version drops.
#[target_feature(enable = "aes,sha2,sha3,neon")]
unsafe fn tbx1(dst: V, table: V, idx: V) -> V {
    let mut out = dst;
    unsafe {
        asm!(
            "ldr q0, [{d}]",
            "ldr q1, [{t}]",
            "ldr q2, [{i}]",
            "tbx v0.16b, {{v1.16b}}, v2.16b",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            t = in(reg) &table,
            i = in(reg) &idx,
            out("q0") _, out("q1") _, out("q2") _,
        );
    }
    out
}

/// `sri vd.2d, vn.2d, #shift` — shift right and insert, keeping the
/// destination's high bits.
#[target_feature(enable = "aes,sha2,sha3,neon")]
unsafe fn sri_2d_32(dst: [u64; 2], n: [u64; 2]) -> [u64; 2] {
    let mut out = dst;
    unsafe {
        asm!(
            "ldr q0, [{d}]",
            "ldr q1, [{n}]",
            "sri v0.2d, v1.2d, #32",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            out("q0") _, out("q1") _,
        );
    }
    out
}

/// `sli vd.2d, vn.2d, #shift` — shift left and insert, keeping the low bits.
#[target_feature(enable = "aes,sha2,sha3,neon")]
unsafe fn sli_2d_32(dst: [u64; 2], n: [u64; 2]) -> [u64; 2] {
    let mut out = dst;
    unsafe {
        asm!(
            "ldr q0, [{d}]",
            "ldr q1, [{n}]",
            "sli v0.2d, v1.2d, #32",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            out("q0") _, out("q1") _,
        );
    }
    out
}

/// `usra vd.2d, vn.2d, #shift` — unsigned shift right and *accumulate*.
#[target_feature(enable = "aes,sha2,sha3,neon")]
unsafe fn usra_2d_8(dst: [u64; 2], n: [u64; 2]) -> [u64; 2] {
    let mut out = dst;
    unsafe {
        asm!(
            "ldr q0, [{d}]",
            "ldr q1, [{n}]",
            "usra v0.2d, v1.2d, #8",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            out("q0") _, out("q1") _,
        );
    }
    out
}

/// `ssra vd.2d, vn.2d, #shift` — the signed form, so the shift is arithmetic.
#[target_feature(enable = "aes,sha2,sha3,neon")]
unsafe fn ssra_2d_8(dst: [u64; 2], n: [u64; 2]) -> [u64; 2] {
    let mut out = dst;
    unsafe {
        asm!(
            "ldr q0, [{d}]",
            "ldr q1, [{n}]",
            "ssra v0.2d, v1.2d, #8",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            out("q0") _, out("q1") _,
        );
    }
    out
}

/// A three-operand `.2d`: `op vd.2d, vn.2d, vm.2d`, for the SHA-512 pair.
/// `+sha3` is what LLVM calls the extension these live in.
macro_rules! v3_2d {
    ($name:ident, $op:literal) => {
        #[target_feature(enable = "aes,sha2,sha3,sm4,neon")]
        unsafe fn $name(d: [u64; 2], n: [u64; 2], m: [u64; 2]) -> [u64; 2] {
            let mut out = d;
            unsafe {
                asm!(
                    "ldr q0, [{d}]",
                    "ldr q1, [{n}]",
                    "ldr q2, [{m}]",
                    concat!($op, " v0.2d, v1.2d, v2.2d"),
                    "str q0, [{d}]",
                    d = in(reg) &mut out,
                    n = in(reg) &n,
                    m = in(reg) &m,
                    out("q0") _, out("q1") _, out("q2") _,
                );
            }
            out
        }
    };
}

/// `SHA512H <Qd>, <Qn>, <Vm>.2D` — two whole registers and a lane list, the
/// same shape as `sha256h`.
macro_rules! q3_2d {
    ($name:ident, $op:literal) => {
        #[target_feature(enable = "aes,sha2,sha3,sm4,neon")]
        unsafe fn $name(d: [u64; 2], n: [u64; 2], m: [u64; 2]) -> [u64; 2] {
            let mut out = d;
            unsafe {
                asm!(
                    "ldr q0, [{d}]",
                    "ldr q1, [{n}]",
                    "ldr q2, [{m}]",
                    concat!($op, " q0, q1, v2.2d"),
                    "str q0, [{d}]",
                    d = in(reg) &mut out,
                    n = in(reg) &n,
                    m = in(reg) &m,
                    out("q0") _, out("q1") _, out("q2") _,
                );
            }
            out
        }
    };
}

q3_2d!(sha512h, "sha512h");
q3_2d!(sha512h2, "sha512h2");
v3_2d!(sha512su1, "sha512su1");

/// `SHA512SU0 <Vd>.2D, <Vn>.2D`.
#[target_feature(enable = "aes,sha2,sha3,sm4,neon")]
unsafe fn sha512su0(d: [u64; 2], n: [u64; 2]) -> [u64; 2] {
    let mut out = d;
    unsafe {
        asm!(
            "ldr q0, [{d}]",
            "ldr q1, [{n}]",
            "sha512su0 v0.2d, v1.2d",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            out("q0") _, out("q1") _,
        );
    }
    out
}

/// `SM3PARTW1 <Vd>.4S, <Vn>.4S, <Vm>.4S` — the SM3 message expansion.
#[target_feature(enable = "aes,sha2,sha3,sm4,neon")]
unsafe fn sm3partw1(d: [u32; 4], n: [u32; 4], m: [u32; 4]) -> [u32; 4] {
    let mut out = d;
    unsafe {
        asm!(
            "ldr q0, [{d}]",
            "ldr q1, [{n}]",
            "ldr q2, [{m}]",
            "sm3partw1 v0.4s, v1.4s, v2.4s",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            m = in(reg) &m,
            out("q0") _, out("q1") _, out("q2") _,
        );
    }
    out
}

/// `SM4E <Vd>.4S, <Vn>.4S` — one SM4 round, in place.
#[target_feature(enable = "aes,sha2,sha3,sm4,neon")]
unsafe fn sm4e(d: [u32; 4], n: [u32; 4]) -> [u32; 4] {
    let mut out = d;
    unsafe {
        asm!(
            "ldr q0, [{d}]",
            "ldr q1, [{n}]",
            "sm4e v0.4s, v1.4s",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            out("q0") _, out("q1") _,
        );
    }
    out
}

/// `XAR <Vd>.2D, <Vn>.2D, <Vm>.2D, #imm6` — xor then rotate right, SHA-3.
#[target_feature(enable = "aes,sha2,sha3,sm4,neon")]
unsafe fn xar_17(n: [u64; 2], m: [u64; 2]) -> [u64; 2] {
    let mut out = [0u64; 2];
    unsafe {
        asm!(
            "ldr q1, [{n}]",
            "ldr q2, [{m}]",
            "xar v0.2d, v1.2d, v2.2d, #17",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            m = in(reg) &m,
            out("q0") _, out("q1") _, out("q2") _,
        );
    }
    out
}

/// The **scalar** accumulate forms, `usra d0, d1, #n`. `crypto_helpers.c` has
/// `usra_scalar_helper` and `ssra_scalar_helper` for these and no gadget calls
/// either one, which is the question this asks.
#[target_feature(enable = "aes,sha2,sha3,sm4,neon")]
unsafe fn usra_d_8(d: u64, n: u64) -> u64 {
    let out: u64;
    unsafe {
        asm!(
            "fmov d0, {d}",
            "fmov d1, {n}",
            "usra d0, d1, #8",
            "fmov {o}, d0",
            d = in(reg) d,
            n = in(reg) n,
            o = out(reg) out,
            out("q0") _, out("q1") _,
        );
    }
    out
}

#[target_feature(enable = "aes,sha2,sha3,sm4,neon")]
unsafe fn ssra_d_8(d: u64, n: u64) -> u64 {
    let out: u64;
    unsafe {
        asm!(
            "fmov d0, {d}",
            "fmov d1, {n}",
            "ssra d0, d1, #8",
            "fmov {o}, d0",
            d = in(reg) d,
            n = in(reg) n,
            o = out(reg) out,
            out("q0") _, out("q1") _,
        );
    }
    out
}

/// The plain immediate shifts, which have helpers of their own.
#[target_feature(enable = "aes,sha2,sha3,sm4,neon")]
unsafe fn shl_16b_3(n: V) -> V {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "ldr q1, [{n}]",
            "shl v0.16b, v1.16b, #3",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            out("q0") _, out("q1") _,
        );
    }
    out
}

#[target_feature(enable = "aes,sha2,sha3,sm4,neon")]
unsafe fn ushr_16b_3(n: V) -> V {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "ldr q1, [{n}]",
            "ushr v0.16b, v1.16b, #3",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            out("q0") _, out("q1") _,
        );
    }
    out
}

#[target_feature(enable = "aes,sha2,sha3,sm4,neon")]
unsafe fn sshr_16b_3(n: V) -> V {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "ldr q1, [{n}]",
            "sshr v0.16b, v1.16b, #3",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            out("q0") _, out("q1") _,
        );
    }
    out
}

/// `BCAX <Vd>.16B, <Vn>.16B, <Vm>.16B, <Va>.16B` — `Vn EOR (Vm AND NOT Va)`,
/// the SHA-3 bit-clear-and-xor. `.inst` because the assembler wants `+sha3`
/// spelled on the instruction and this is assembled at baseline.
#[target_feature(enable = "aes,sha2,sha3,sm4,neon")]
unsafe fn bcax(n: V, m: V, a: V) -> V {
    let mut out = [0u8; 16];
    unsafe {
        asm!(
            "ldr q1, [{n}]",
            "ldr q2, [{m}]",
            "ldr q3, [{a}]",
            // BCAX: 0xce20 0000 | Rm<<16 | Ra<<10 | Rn<<5 | Rd; d=0,n=1,m=2,a=3
            ".inst 0xce220c20",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            m = in(reg) &m,
            a = in(reg) &a,
            out("q0") _, out("q1") _, out("q2") _, out("q3") _,
        );
    }
    out
}

/// `RAX1 <Vd>.2D, <Vn>.2D, <Vm>.2D` — `Vn EOR ROL(Vm, 1)`, the other SHA-3
/// instruction a Keccak round emits.
#[target_feature(enable = "aes,sha2,sha3,sm4,neon")]
unsafe fn rax1(n: [u64; 2], m: [u64; 2]) -> [u64; 2] {
    let mut out = [0u64; 2];
    unsafe {
        asm!(
            "ldr q1, [{n}]",
            "ldr q2, [{m}]",
            // RAX1: 0xce60 8c00 | Rm<<16 | Rn<<5 | Rd; d=0, n=1, m=2
            ".inst 0xce628c20",
            "str q0, [{d}]",
            d = in(reg) &mut out,
            n = in(reg) &n,
            m = in(reg) &m,
            out("q0") _, out("q1") _, out("q2") _,
        );
    }
    out
}

/// The CRC32 instructions, which are a HWCAP bit of their own. Both
/// polynomials, since `crc32` and `crc32c` are different instructions and a
/// table-driven fallback picks one by name.
#[target_feature(enable = "crc,neon")]
unsafe fn crc32_all(acc: u32, x: u64) -> [u32; 8] {
    let (mut b, mut hh, mut w, mut d): (u32, u32, u32, u32);
    let (mut cb, mut ch, mut cw, mut cd): (u32, u32, u32, u32);
    unsafe {
        asm!(
            "crc32b  {b:w},  {a:w}, {x:w}",
            "crc32h  {h:w},  {a:w}, {x:w}",
            "crc32w  {w:w},  {a:w}, {x:w}",
            "crc32x  {d:w},  {a:w}, {x}",
            "crc32cb {cb:w}, {a:w}, {x:w}",
            "crc32ch {ch:w}, {a:w}, {x:w}",
            "crc32cw {cw:w}, {a:w}, {x:w}",
            "crc32cx {cd:w}, {a:w}, {x}",
            a = in(reg) acc,
            x = in(reg) x,
            b = out(reg) b, h = out(reg) hh, w = out(reg) w, d = out(reg) d,
            cb = out(reg) cb, ch = out(reg) ch, cw = out(reg) cw, cd = out(reg) cd,
        );
    }
    [b, hh, w, d, cb, ch, cw, cd]
}

fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}

fn h32(v: &[u32]) -> String {
    v.iter().map(|w| format!("{w:08x}")).collect::<Vec<_>>().join(" ")
}

fn main() {
    // ---------------------------------------------------------------- AES
    let state: V = [
        0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48,
        0x08,
    ];
    let key: V = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    println!("########## aes ##########");
    let e0 = unsafe { aese(state, [0; 16]) };
    println!("  aese(s, 0)     = {}", hex(&e0));
    let ek = unsafe { aese(state, key) };
    println!("  aese(s, k)     = {}", hex(&ek));
    let d0 = unsafe { aesd(state, [0; 16]) };
    println!("  aesd(s, 0)     = {}", hex(&d0));
    let dk = unsafe { aesd(state, key) };
    println!("  aesd(s, k)     = {}", hex(&dk));
    let mc = unsafe { aesmc(state) };
    println!("  aesmc(s)       = {}", hex(&mc));
    let imc = unsafe { aesimc(state) };
    println!("  aesimc(s)      = {}", hex(&imc));

    // The relations. Each names one instruction of a pair when it breaks,
    // which a composition that cancels cannot.
    let xored: V = std::array::from_fn(|i| state[i] ^ key[i]);
    println!("  aese(x,k)==aese(x^k,0): {}", ek == unsafe { aese(xored, [0; 16]) });
    println!("  aesimc(aesmc(x))==x:    {}", unsafe { aesimc(mc) } == state);
    println!("  aesd(aese(x,0),0)==x:   {}", unsafe { aesd(e0, [0; 16]) } == state);

    // --------------------------------------------------------------- SHA-1
    println!("########## sha1 ##########");
    for x in [0x0000_0001u32, 0x8000_0000, 0x1234_5678, 0xffff_ffff] {
        // ROL 30, and the only instruction here simple enough to state.
        let got = unsafe { sha1h(x) };
        println!("  sha1h({x:08x})  = {got:08x}  rol30={}", got == x.rotate_left(30));
    }
    let abcd = [0x6745_2301u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let e = 0xc3d2_e1f0u32;
    let w = [0x6162_6380u32, 0x1111_2222, 0x8000_0000, 0x0000_0018];
    println!("  sha1c   = {}", h32(&unsafe { sha1c(abcd, e, w) }));
    println!("  sha1p   = {}", h32(&unsafe { sha1p(abcd, e, w) }));
    println!("  sha1m   = {}", h32(&unsafe { sha1m(abcd, e, w) }));
    println!("  sha1su0 = {}", h32(&unsafe { sha1su0(abcd, w, [1, 2, 3, 4]) }));
    println!("  sha1su1 = {}", h32(&unsafe { sha1su1(abcd, w) }));

    // ------------------------------------------------------------- SHA-256
    println!("########## sha256 ##########");
    println!("  sha256su0 = {}", h32(&unsafe { sha256su0([1, 2, 3, 4], [5, 6, 7, 8]) }));
    println!(
        "  sha256su1 = {}",
        h32(&unsafe { sha256su1([1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]) })
    );
    println!(
        "  sha256h   = {}",
        h32(&unsafe { sha256h(abcd, [5, 6, 7, 8], [9, 10, 11, 12]) })
    );
    println!(
        "  sha256h2  = {}",
        h32(&unsafe { sha256h2(abcd, [5, 6, 7, 8], [9, 10, 11, 12]) })
    );
    // A whole compression, which is what catches an error that the
    // instructions cancel between themselves.
    println!("  sha256(\"abc\") = {}", h32(&sha256_abc()));

    // ---------------------------------------------------------------- misc
    println!("########## eor3 and pmull ##########");
    let a: V = std::array::from_fn(|i| i as u8);
    let b: V = std::array::from_fn(|i| (i as u8).wrapping_mul(3));
    let c: V = std::array::from_fn(|i| 0xff ^ i as u8);
    let e3 = unsafe { eor3(a, b, c) };
    println!("  eor3       = {}", hex(&e3));
    println!("  eor3==a^b^c: {}", e3 == std::array::from_fn(|i| a[i] ^ b[i] ^ c[i]));
    println!("  pmull(x,1) = {}", hex(&unsafe { pmull(0x0123_4567_89ab_cdef, 1) }));
    println!("  pmull(b,b) = {}", hex(&unsafe { pmull(0b1011, 0b1011) }));
    println!("  pmull(f,f) = {}", hex(&unsafe { pmull(u64::MAX, u64::MAX) }));

    // ------------------------------------------------------------- permutes
    println!("########## permutes ##########");
    let lo: V = std::array::from_fn(|i| i as u8);
    let hi: V = std::array::from_fn(|i| 0x10 + i as u8);
    println!("  zip1 = {}", hex(&unsafe { zip1_16b(lo, hi) }));
    println!("  zip2 = {}", hex(&unsafe { zip2_16b(lo, hi) }));
    println!("  uzp1 = {}", hex(&unsafe { uzp1_16b(lo, hi) }));
    println!("  uzp2 = {}", hex(&unsafe { uzp2_16b(lo, hi) }));
    println!("  trn1 = {}", hex(&unsafe { trn1_16b(lo, hi) }));
    println!("  trn2 = {}", hex(&unsafe { trn2_16b(lo, hi) }));

    // `tbl` gives zero for an index past the end and `tbx` leaves the byte
    // alone. That one difference is the whole distinction between them, so
    // half the indices below are out of range.
    println!("########## table lookup ##########");
    let table: V = std::array::from_fn(|i| 0xa0 + i as u8);
    let idx: V = std::array::from_fn(|i| if i < 8 { (15 - i) as u8 } else { 200 });
    println!("  tbl = {}", hex(&unsafe { tbl1(table, idx) }));
    println!("  tbx = {}", hex(&unsafe { tbx1([0x5a; 16], table, idx) }));

    // ------------------------------------------- shift, insert and accumulate
    println!("########## shift insert and accumulate ##########");
    // The second lane is negative, which is the only thing that tells the
    // signed accumulate from the unsigned one.
    let d = [0xffff_ffff_ffff_ffffu64, 0x0000_0000_0000_0000];
    let n = [0x0123_4567_89ab_cdefu64, 0xfedc_ba98_7654_3210];
    let sri = unsafe { sri_2d_32(d, n) };
    let sli = unsafe { sli_2d_32(d, n) };
    let usra = unsafe { usra_2d_8(d, n) };
    let ssra = unsafe { ssra_2d_8(d, n) };
    println!("  sri  #32 = {:016x} {:016x}", sri[0], sri[1]);
    println!("  sli  #32 = {:016x} {:016x}", sli[0], sli[1]);
    println!("  usra  #8 = {:016x} {:016x}", usra[0], usra[1]);
    println!("  ssra  #8 = {:016x} {:016x}", ssra[0], ssra[1]);
    println!("  usra!=ssra on a negative lane: {}", usra != ssra);

    println!("########## what the cpu says it has ##########");
    // AT_HWCAP. A guest library picks its code path from these bits, so a
    // feature the interpreter implements but does not advertise is dead, and
    // one it advertises but does not implement is an illegal instruction.
    let cap = unsafe { libc::getauxval(16) };
    let has = |bit: u32| cap & (1u64 << bit) != 0;
    for (name, bit) in [
        ("aes", 3u32), ("sha1", 5), ("sha2", 6), ("sha3", 17),
        ("sm3", 18), ("sm4", 19), ("sha512", 21),
    ] {
        println!("  {name}: {}", has(bit));
    }

    println!("########## sha512 sm3 sm4 xar ##########");
    let d2 = [0x0123_4567_89ab_cdefu64, 0xfedc_ba98_7654_3210];
    let n2 = [0x1111_2222_3333_4444u64, 0x8000_0000_0000_0001];
    let m2 = [0xdead_beef_cafe_babeu64, 0x0000_0000_0000_002a];
    println!("  sha512h   = {:016x} {:016x}", unsafe { sha512h(d2, n2, m2) }[0], unsafe { sha512h(d2, n2, m2) }[1]);
    println!("  sha512h2  = {:016x} {:016x}", unsafe { sha512h2(d2, n2, m2) }[0], unsafe { sha512h2(d2, n2, m2) }[1]);
    println!("  sha512su0 = {:016x} {:016x}", unsafe { sha512su0(d2, n2) }[0], unsafe { sha512su0(d2, n2) }[1]);
    println!("  sha512su1 = {:016x} {:016x}", unsafe { sha512su1(d2, n2, m2) }[0], unsafe { sha512su1(d2, n2, m2) }[1]);
    // Gated on the bit, and the line is printed either way so the two sides
    // have the same shape. Apple Silicon implements neither FEAT_SM3 nor
    // FEAT_SM4, so running these unguarded takes SIGILL in the container and
    // loses every line after it.
    if has(18) {
        println!("  sm3partw1 = {}", h32(&unsafe { sm3partw1(abcd, [5, 6, 7, 8], [9, 10, 11, 12]) }));
    } else {
        println!("  sm3partw1 = no FEAT_SM3");
    }
    if has(19) {
        println!("  sm4e      = {}", h32(&unsafe { sm4e(abcd, [5, 6, 7, 8]) }));
    } else {
        println!("  sm4e      = no FEAT_SM4");
    }
    let x = unsafe { xar_17(n2, m2) };
    println!("  xar #17   = {:016x} {:016x}", x[0], x[1]);
    println!(
        "  xar==rotr(n^m,17): {}",
        x[0] == (n2[0] ^ m2[0]).rotate_right(17) && x[1] == (n2[1] ^ m2[1]).rotate_right(17)
    );

    println!("########## sha3 bcax and rax1 ##########");
    // These two are the rest of a Keccak round. Nothing decoded either until
    // 2026-09-02, which is why the SHA3 HWCAP bit cannot simply be turned on.
    let bx = unsafe { bcax(a, b, c) };
    println!("  bcax  = {}", hex(&bx));
    println!(
        "  bcax==n^(m&!a): {}",
        bx == std::array::from_fn(|i| a[i] ^ (b[i] & !c[i]))
    );
    let rx = unsafe { rax1(n2, m2) };
    println!("  rax1  = {:016x} {:016x}", rx[0], rx[1]);
    println!(
        "  rax1==n^rol(m,1): {}",
        rx[0] == n2[0] ^ m2[0].rotate_left(1) && rx[1] == n2[1] ^ m2[1].rotate_left(1)
    );

    println!("########## crc32 ##########");
    let crc = unsafe { crc32_all(0xffff_ffff, 0x0123_4567_89ab_cdef) };
    for (name, v) in ["crc32b", "crc32h", "crc32w", "crc32x", "crc32cb", "crc32ch", "crc32cw", "crc32cx"]
        .iter()
        .zip(crc)
    {
        println!("  {name} = {v:08x}");
    }

    println!("########## scalar and immediate shifts ##########");
    println!("  usra d,#8 = {:016x}", unsafe { usra_d_8(d[0], n[1]) });
    println!("  ssra d,#8 = {:016x}", unsafe { ssra_d_8(d[0], n[1]) });
    println!("  shl  .16b,#3 = {}", hex(&unsafe { shl_16b_3(hi) }));
    println!("  ushr .16b,#3 = {}", hex(&unsafe { ushr_16b_3(hi) }));
    println!("  sshr .16b,#3 = {}", hex(&unsafe { sshr_16b_3(hi) }));
}

/// SHA-256 of `"abc"`, one block, using only the four crypto instructions for
/// the compression. The published digest is what checks it.
fn sha256_abc() -> [u32; 8] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    // "abc" padded to one 512-bit block, as big-endian words.
    let mut w = [0u32; 64];
    w[0] = 0x6162_6380;
    w[15] = 24;

    // The schedule, with the two schedule instructions. They work four words
    // at a time: su0 takes w[i-16..i-12] and w[i-12..i-8], su1 takes that
    // partial result with w[i-8..i-4] and w[i-4..i].
    let mut i = 16;
    while i < 64 {
        let a: [u32; 4] = w[i - 16..i - 12].try_into().unwrap();
        let b: [u32; 4] = w[i - 12..i - 8].try_into().unwrap();
        let c: [u32; 4] = w[i - 8..i - 4].try_into().unwrap();
        let d: [u32; 4] = w[i - 4..i].try_into().unwrap();
        let partial = unsafe { sha256su0(a, b) };
        let full = unsafe { sha256su1(partial, c, d) };
        w[i..i + 4].copy_from_slice(&full);
        i += 4;
    }

    // The compression, four rounds at a time.
    let mut abcd = [0x6a09_e667u32, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a];
    let mut efgh = [0x510e_527fu32, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19];
    let (i0, e0) = (abcd, efgh);
    for r in (0..64).step_by(4) {
        let wk: [u32; 4] = std::array::from_fn(|j| w[r + j].wrapping_add(K[r + j]));
        let prev = abcd;
        abcd = unsafe { sha256h(abcd, efgh, wk) };
        efgh = unsafe { sha256h2(efgh, prev, wk) };
    }
    let mut out = [0u32; 8];
    for j in 0..4 {
        out[j] = i0[j].wrapping_add(abcd[j]);
        out[j + 4] = e0[j].wrapping_add(efgh[j]);
    }
    out
}
