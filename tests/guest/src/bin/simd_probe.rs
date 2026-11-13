//! The NEON instruction set, printed rather than asserted.
//!
//! # Why this exists
//!
//! `asbestos/guest-arm64/gen.c` is 6853 lines and most of it decodes SIMD and
//! floating-point. Every guest `memcpy`, `strlen`, `memchr`, JSON parse and
//! UTF-8 validation goes through it — musl and every compiler's autovectoriser
//! emit these constantly.
//!
//! **Nothing tested any of it.** Before this file there were 148 programs in
//! `tests/guest/src/bin` and not one named a vector instruction; the only SIMD
//! coverage in the tree was the crypto probe beside this, written the same day.
//! A guest that runs at all exercises a few dozen of these by accident, and an
//! instruction that is decoded *wrongly* rather than not at all produces
//! wrong bytes with nothing to notice — which is the same shape as the wrong
//! `sha1su1` in `docs/changelog/2026-09-02-the-emulator-hid-four-crypto-extensions-it-had.md`.
//!
//! # Ground truth
//!
//! The hardware. This is a static `aarch64-unknown-linux-musl` binary on an
//! Apple Silicon machine, so `tests/integration/probe_diff.sh` runs the same
//! binary in an arm64 container where the CPU executes every instruction
//! below. A difference between the two sides is the interpreter getting one
//! wrong, and there is no constant here for anyone to mis-transcribe.
//!
//! An instruction `gen.c` does not decode does not print a wrong answer: it
//! kills the process with `illegal instruction`, and the probe's output stops
//! there. That is the loudest possible failure and it is why the cases are
//! grouped smallest-first — the group heading is how far it got.
//!
//! # The inputs
//!
//! Three fixed vectors, chosen so that one run says as much as possible:
//!
//! - `A` spans the signed boundary — `0x7f`, `0x80`, `0xff`, `0x00` — so the
//!   signed and unsigned forms of everything disagree, and so saturating
//!   instructions actually saturate.
//! - `B` has `0x00`, `0xff`, `0x01`, `0x80` and two alternating patterns, so a
//!   shift or a select has something to move.
//! - `D` preloads the destination, because the accumulate, insert and
//!   bit-select forms read it. A version that ignored the destination would
//!   otherwise look right.
//!
//! Every lane differs from its neighbours, which is what catches a permute
//! that has two lanes the wrong way round.

use std::arch::asm;

/// Signed boundaries in every lane width.
static A: [u8; 16] = [
    0x00, 0x7f, 0x80, 0xff, 0x01, 0xfe, 0x40, 0xc0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
];
/// Small shifts, all-ones, all-zeroes and two alternating patterns.
static B: [u8; 16] = [
    0x01, 0x01, 0x01, 0x01, 0x7f, 0x7f, 0x80, 0x80, 0xff, 0x00, 0x55, 0xaa, 0x0f, 0xf0, 0x33, 0xcc,
];
/// What the destination holds before the instruction runs.
static D: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

/// Sixty-four bytes shared with a forked child, where it leaves its answer.
static mut SLOT: *mut u8 = std::ptr::null_mut();

/// Run `f` in a forked child and answer whether it finished.
///
/// # Why a fork per instruction
///
/// An instruction `gen.c` does not decode raises `SIGILL`, whose default
/// action ends the process — so the first gap hides every one after it, and
/// the first run of this probe reported one missing instruction out of the
/// eleven that were. A child per case turns each into one line, which is what
/// makes a single run a complete list.
///
/// It also keeps the rule `probe_diff.sh` needs: the same number of lines
/// whether a case works or not. A case that dies prints `SIGILL` and the two
/// sides still line up.
///
/// The child does nothing but the assembly, a `memcpy` into shared memory and
/// `_exit` — no allocation, no destructors, nothing that a `fork` child must
/// not touch.
fn isolated(f: impl FnOnce()) -> bool {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            f();
            libc::_exit(0);
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }
}

fn slot(n: usize) -> String {
    unsafe { std::slice::from_raw_parts(SLOT, n) }
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Run one instruction with `q0 = D`, `q1 = A`, `q2 = B` and print `q0`.
///
/// Everything below is this macro. `q0` is loaded from `D` rather than left
/// undefined so that the accumulate and insert forms have something to read
/// and a wrong answer is a wrong *value* rather than whatever was in the
/// register.
macro_rules! p {
    ($($op:literal),+ $(,)?) => {{
        let ok = isolated(|| unsafe {
            let mut out = D;
            asm!(
                "ldr q0, [{d}]",
                "ldr q1, [{a}]",
                "ldr q2, [{b}]",
                $($op,)+
                "str q0, [{d}]",
                d = in(reg) &mut out,
                a = in(reg) &A,
                b = in(reg) &B,
                out("q0") _, out("q1") _, out("q2") _, out("q3") _,
            );
            std::ptr::copy_nonoverlapping(out.as_ptr(), SLOT, 16);
        });
        // The instruction text is the label, so the output names exactly what
        // ran and a diff points at an encoding rather than a case number.
        println!(
            "  {:<34} {}",
            concat!($($op),+),
            if ok { slot(16) } else { "SIGILL".to_string() }
        );
    }};
}

/// The same for an instruction whose result lands in a general register.
macro_rules! g {
    ($($op:literal),+ $(,)?) => {{
        let ok = isolated(|| unsafe {
            let out: u64;
            asm!(
                "ldr q0, [{d}]",
                "ldr q1, [{a}]",
                "ldr q2, [{b}]",
                $($op,)+
                d = in(reg) &D,
                a = in(reg) &A,
                b = in(reg) &B,
                o = out(reg) out,
                out("q0") _, out("q1") _, out("q2") _,
            );
            std::ptr::copy_nonoverlapping(out.to_le_bytes().as_ptr(), SLOT, 8);
        });
        println!(
            "  {:<34} {}",
            concat!($($op),+),
            if ok { slot(8) } else { "SIGILL".to_string() }
        );
    }};
}

fn main() {
    // Shared with each child, so its answer survives its exit.
    unsafe {
        SLOT = libc::mmap(
            std::ptr::null_mut(),
            64,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
        .cast();
        assert!(SLOT as isize != -1, "no shared page");
    }

    println!("########## bitwise ##########");
    p!("and v0.16b, v1.16b, v2.16b");
    p!("orr v0.16b, v1.16b, v2.16b");
    p!("eor v0.16b, v1.16b, v2.16b");
    p!("bic v0.16b, v1.16b, v2.16b");
    p!("orn v0.16b, v1.16b, v2.16b");
    p!("not v0.16b, v1.16b");
    // The three bit-selects read the destination, which is why D is loaded.
    // BSL selects with the destination, BIT and BIF with the second source —
    // and mixing them up is invisible when the destination is all ones.
    p!("bsl v0.16b, v1.16b, v2.16b");
    p!("bit v0.16b, v1.16b, v2.16b");
    p!("bif v0.16b, v1.16b, v2.16b");
    p!("mvn v0.16b, v1.16b");

    println!("########## integer arithmetic ##########");
    for w in ["16b", "8h", "4s", "2d"] {
        match w {
            "16b" => {
                p!("add v0.16b, v1.16b, v2.16b");
                p!("sub v0.16b, v1.16b, v2.16b");
                p!("mul v0.16b, v1.16b, v2.16b");
                p!("neg v0.16b, v1.16b");
                p!("abs v0.16b, v1.16b");
            }
            "8h" => {
                p!("add v0.8h, v1.8h, v2.8h");
                p!("sub v0.8h, v1.8h, v2.8h");
                p!("mul v0.8h, v1.8h, v2.8h");
                p!("neg v0.8h, v1.8h");
                p!("abs v0.8h, v1.8h");
            }
            "4s" => {
                p!("add v0.4s, v1.4s, v2.4s");
                p!("sub v0.4s, v1.4s, v2.4s");
                p!("mul v0.4s, v1.4s, v2.4s");
                p!("neg v0.4s, v1.4s");
                p!("abs v0.4s, v1.4s");
            }
            _ => {
                p!("add v0.2d, v1.2d, v2.2d");
                p!("sub v0.2d, v1.2d, v2.2d");
                p!("neg v0.2d, v1.2d");
                p!("abs v0.2d, v1.2d");
            }
        }
    }
    // Multiply-accumulate reads the destination.
    p!("mla v0.4s, v1.4s, v2.4s");
    p!("mls v0.4s, v1.4s, v2.4s");

    println!("########## saturating ##########");
    // A spans the signed boundary, so these actually saturate. A version that
    // wrapped instead would agree with the plain add above and differ here.
    p!("sqadd v0.16b, v1.16b, v2.16b");
    p!("uqadd v0.16b, v1.16b, v2.16b");
    p!("sqsub v0.16b, v1.16b, v2.16b");
    p!("uqsub v0.16b, v1.16b, v2.16b");
    p!("sqadd v0.4s, v1.4s, v2.4s");
    p!("uqadd v0.4s, v1.4s, v2.4s");
    p!("sqneg v0.16b, v1.16b");
    p!("sqabs v0.16b, v1.16b");
    p!("suqadd v0.16b, v1.16b");
    p!("usqadd v0.16b, v1.16b");

    println!("########## min max and compare ##########");
    p!("smax v0.16b, v1.16b, v2.16b");
    p!("umax v0.16b, v1.16b, v2.16b");
    p!("smin v0.16b, v1.16b, v2.16b");
    p!("umin v0.16b, v1.16b, v2.16b");
    p!("smax v0.4s, v1.4s, v2.4s");
    p!("umin v0.4s, v1.4s, v2.4s");
    p!("sabd v0.16b, v1.16b, v2.16b");
    p!("uabd v0.16b, v1.16b, v2.16b");
    p!("saba v0.16b, v1.16b, v2.16b");
    p!("uaba v0.16b, v1.16b, v2.16b");
    p!("cmeq v0.16b, v1.16b, v2.16b");
    p!("cmge v0.16b, v1.16b, v2.16b");
    p!("cmgt v0.16b, v1.16b, v2.16b");
    p!("cmhi v0.16b, v1.16b, v2.16b");
    p!("cmhs v0.16b, v1.16b, v2.16b");
    p!("cmtst v0.16b, v1.16b, v2.16b");
    // Against zero, which is a different encoding and is what every `strlen`
    // and `memchr` in musl uses.
    p!("cmeq v0.16b, v1.16b, #0");
    p!("cmge v0.16b, v1.16b, #0");
    p!("cmgt v0.16b, v1.16b, #0");
    p!("cmle v0.16b, v1.16b, #0");
    p!("cmlt v0.16b, v1.16b, #0");

    println!("########## pairwise and reductions ##########");
    p!("addp v0.16b, v1.16b, v2.16b");
    p!("addp v0.4s, v1.4s, v2.4s");
    p!("saddlp v0.8h, v1.16b");
    p!("uaddlp v0.8h, v1.16b");
    p!("sadalp v0.8h, v1.16b");
    p!("uadalp v0.8h, v1.16b");
    p!("smaxp v0.16b, v1.16b, v2.16b");
    p!("uminp v0.16b, v1.16b, v2.16b");
    // The reductions write a scalar, so the rest of q0 must end up zero — a
    // version that left the old destination there would show it here.
    p!("addv b0, v1.16b");
    p!("addv s0, v1.4s");
    p!("smaxv b0, v1.16b");
    p!("uminv b0, v1.16b");
    p!("uaddlv h0, v1.16b");
    p!("saddlv h0, v1.16b");
    p!("addp d0, v1.2d");

    println!("########## widening and narrowing ##########");
    p!("uaddl v0.8h, v1.8b, v2.8b");
    p!("saddl v0.8h, v1.8b, v2.8b");
    p!("uaddl2 v0.8h, v1.16b, v2.16b");
    p!("usubl v0.8h, v1.8b, v2.8b");
    p!("uaddw v0.8h, v0.8h, v1.8b");
    p!("umull v0.8h, v1.8b, v2.8b");
    p!("smull v0.8h, v1.8b, v2.8b");
    p!("umlal v0.8h, v1.8b, v2.8b");
    p!("xtn v0.8b, v1.8h");
    p!("xtn2 v0.16b, v1.8h");
    p!("sqxtn v0.8b, v1.8h");
    p!("uqxtn v0.8b, v1.8h");
    p!("sqxtun v0.8b, v1.8h");
    p!("addhn v0.8b, v1.8h, v2.8h");
    p!("raddhn v0.8b, v1.8h, v2.8h");
    p!("ushll v0.8h, v1.8b, #3");
    p!("sshll v0.8h, v1.8b, #3");
    p!("ushll2 v0.8h, v1.16b, #0");
    p!("uxtl v0.8h, v1.8b");
    p!("sxtl v0.8h, v1.8b");

    println!("########## shifts ##########");
    p!("shl v0.16b, v1.16b, #3");
    p!("ushr v0.16b, v1.16b, #3");
    p!("sshr v0.16b, v1.16b, #3");
    p!("urshr v0.16b, v1.16b, #3");
    p!("srshr v0.16b, v1.16b, #3");
    p!("usra v0.16b, v1.16b, #3");
    p!("ssra v0.16b, v1.16b, #3");
    p!("ursra v0.16b, v1.16b, #3");
    p!("sri v0.16b, v1.16b, #3");
    p!("sli v0.16b, v1.16b, #3");
    p!("shl v0.8h, v1.8h, #5");
    p!("ushr v0.4s, v1.4s, #9");
    p!("sshr v0.2d, v1.2d, #17");
    p!("shrn v0.8b, v1.8h, #3");
    p!("rshrn v0.8b, v1.8h, #3");
    p!("sqshrn v0.8b, v1.8h, #3");
    p!("uqshrn v0.8b, v1.8h, #3");
    // Register shifts, where the amount is per lane and signed: a negative
    // amount shifts right. That sign is the thing a software version drops.
    p!("ushl v0.16b, v1.16b, v2.16b");
    p!("sshl v0.16b, v1.16b, v2.16b");
    p!("urshl v0.16b, v1.16b, v2.16b");
    p!("sqshl v0.16b, v1.16b, v2.16b");
    p!("uqshl v0.16b, v1.16b, v2.16b");
    p!("shl d0, d1, #7");
    p!("ushr d0, d1, #7");
    p!("sshr d0, d1, #7");

    println!("########## register shifts at boundary amounts ##########");
    // A register shift amount is a **signed** per-lane byte, and an amount at
    // or past the element width gives zero — it is not a shift modulo the
    // width, which is what an implementation built on the host's `lsr` gets by
    // default, since AArch64 register shifts use only the low six bits.
    //
    // `movi` overwrites the amount vector, so each of these is one exact
    // amount in every lane. 64 and -64 are the ones that catch the modulo:
    // both are 0 mod 64 and both must give zero.
    for amt in ["#8", "#63", "#64", "#65", "#127", "#0xc0", "#0xf8", "#0x80"] {
        match amt {
            "#8" => {
                p!("movi v2.16b, #8", "ushl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #8", "sshl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #8", "urshl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #8", "uqshl v0.16b, v1.16b, v2.16b");
            }
            "#63" => {
                p!("movi v2.16b, #63", "ushl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #63", "sshl v0.16b, v1.16b, v2.16b");
            }
            "#64" => {
                p!("movi v2.16b, #64", "ushl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #64", "sshl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #64", "ushl v0.2d, v1.2d, v2.2d");
                p!("movi v2.16b, #64", "sshl v0.2d, v1.2d, v2.2d");
            }
            "#65" => {
                p!("movi v2.16b, #65", "ushl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #65", "ushl v0.4s, v1.4s, v2.4s");
            }
            "#127" => {
                p!("movi v2.16b, #127", "ushl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #127", "sshl v0.8h, v1.8h, v2.8h");
            }
            // -64, which is 0 mod 64 in the other direction.
            "#0xc0" => {
                p!("movi v2.16b, #0xc0", "ushl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #0xc0", "sshl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #0xc0", "ushl v0.2d, v1.2d, v2.2d");
                p!("movi v2.16b, #0xc0", "sshl v0.2d, v1.2d, v2.2d");
            }
            // -8, exactly the element width.
            "#0xf8" => {
                p!("movi v2.16b, #0xf8", "ushl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #0xf8", "sshl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #0xf8", "urshl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #0xf8", "uqshl v0.16b, v1.16b, v2.16b");
            }
            // -128, the most negative amount there is.
            _ => {
                p!("movi v2.16b, #0x80", "ushl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #0x80", "sshl v0.16b, v1.16b, v2.16b");
                p!("movi v2.16b, #0x80", "ushl v0.4s, v1.4s, v2.4s");
                p!("movi v2.16b, #0x80", "sshl v0.2d, v1.2d, v2.2d");
            }
        }
    }

    // The lane number of a single-element load is assembled from three fields
    // and a different combination at every width: `Q:S:size` for a byte,
    // `Q:S:size<1>` for a halfword, `Q:S` for a word and `Q` for a doubleword.
    // The halfword row read `size<0>` instead of `size<1>` -- and `size<0>`
    // names no lane, it is required to be zero -- so the low bit of every
    // 16-bit lane number was zero and lanes 1, 3, 5 and 7 all landed in the
    // even lane below them. A *value* defect, which `decode_probe` cannot see:
    // it asks whether an encoding runs.
    println!("########## single-element loads, every lane ##########");
    p!("ld1 {{v0.b}}[0], [{a}]");
    p!("ld1 {{v0.b}}[5], [{a}]");
    p!("ld1 {{v0.b}}[15], [{a}]");
    p!("ld1 {{v0.h}}[0], [{a}]");
    p!("ld1 {{v0.h}}[1], [{a}]");
    p!("ld1 {{v0.h}}[2], [{a}]");
    p!("ld1 {{v0.h}}[3], [{a}]");
    p!("ld1 {{v0.h}}[4], [{a}]");
    p!("ld1 {{v0.h}}[5], [{a}]");
    p!("ld1 {{v0.h}}[6], [{a}]");
    p!("ld1 {{v0.h}}[7], [{a}]");
    p!("ld1 {{v0.s}}[0], [{a}]");
    p!("ld1 {{v0.s}}[1], [{a}]");
    p!("ld1 {{v0.s}}[2], [{a}]");
    p!("ld1 {{v0.s}}[3], [{a}]");
    p!("ld1 {{v0.d}}[0], [{a}]");
    p!("ld1 {{v0.d}}[1], [{a}]");
    // And the multi-register forms at the same widths, whose lane comes from
    // the same three fields.
    p!("ld2 {{v0.h, v1.h}}[3], [{a}]");
    p!("ld3 {{v0.h, v1.h, v2.h}}[5], [{a}]");
    p!("ld4 {{v0.h, v1.h, v2.h, v3.h}}[7], [{a}]");

    println!("########## counting and reversing ##########");
    p!("cnt v0.16b, v1.16b");
    p!("clz v0.16b, v1.16b");
    p!("cls v0.16b, v1.16b");
    p!("rbit v0.16b, v1.16b");
    p!("rev16 v0.16b, v1.16b");
    p!("rev32 v0.16b, v1.16b");
    p!("rev64 v0.16b, v1.16b");
    p!("rev32 v0.8h, v1.8h");
    p!("rev64 v0.4s, v1.4s");

    println!("########## permute and move ##########");
    p!("ext v0.16b, v1.16b, v2.16b, #5");
    p!("ext v0.16b, v1.16b, v2.16b, #0");
    p!("ext v0.16b, v1.16b, v2.16b, #15");
    p!("zip1 v0.16b, v1.16b, v2.16b");
    p!("zip2 v0.8h, v1.8h, v2.8h");
    p!("uzp1 v0.4s, v1.4s, v2.4s");
    p!("uzp2 v0.2d, v1.2d, v2.2d");
    p!("trn1 v0.8h, v1.8h, v2.8h");
    p!("trn2 v0.4s, v1.4s, v2.4s");
    p!("dup v0.16b, v1.b[5]");
    p!("dup v0.4s, v1.s[3]");
    p!("dup v0.2d, v1.d[1]");
    // From a general register, which is what a compiler emits to broadcast a
    // scalar into a loop.
    p!("mov x9, #0x5a", "dup v0.16b, w9");
    p!("mov x9, #0x1234", "dup v0.8h, w9");
    // INS reads the destination, so a version that rebuilt the register would
    // lose the other lanes.
    p!("ins v0.b[3], v1.b[7]");
    p!("ins v0.s[1], v1.s[2]");
    p!("mov x9, #0xab", "ins v0.b[9], w9");
    p!("mov v0.16b, v1.16b");
    // The scalar moves out, which land in a general register.
    g!("umov {o:w}, v1.b[2]", "and {o}, {o}, #0xff");
    g!("umov {o:w}, v1.s[3]");
    g!("smov {o}, v1.b[2]");
    g!("smov {o}, v1.h[1]");
    g!("smov {o}, v1.s[1]");
    // The W forms, which sign-extend to 32 bits and zero the top half —
    // a different answer from extending to 64, and the one a `Q` bit chooses.
    g!("smov {o:w}, v1.b[2]");
    g!("smov {o:w}, v1.h[1]");
    g!("umov {o:w}, v1.h[1]");
    g!("fmov {o}, d1");
    g!("fmov {o:w}, s1");
    g!("mov {o}, v1.d[1]");
    // `d[0]` and `d[1]` are one pair on purpose. `d[0]` is the only lane read
    // `crates/asbestos/gen`'s decoder gives a **special gadget** to -- one that
    // does not work the width out at run time, because it is what a compiler
    // emits to get a double into a general register -- and until 2026-09-06 the
    // mask guarding that arm cleared the `imm5` field the pattern set, so the
    // arm was dead and every one of these fell through to the general `UMOV`.
    // `d[1]` still does, so the two together say the fast path answers what the
    // general one did *and* that it has not started answering for the lane it
    // is not for.
    g!("mov {o}, v1.d[0]");

    println!("########## table lookup ##########");
    // One to four table registers, and indices that run off the end of each.
    // TBL zeroes those and TBX leaves the destination, which is the whole
    // difference between the two and is why D is loaded.
    p!("ldr q3, [{b}]", "tbl v0.16b, {{v1.16b}}, v3.16b");
    p!("ldr q3, [{b}]", "tbx v0.16b, {{v1.16b}}, v3.16b");
    p!("ldr q3, [{b}]", "tbl v0.16b, {{v1.16b, v2.16b}}, v3.16b");
    p!("ldr q3, [{b}]", "tbx v0.16b, {{v1.16b, v2.16b}}, v3.16b");
    p!("ldr q3, [{b}]", "tbl v0.8b, {{v1.16b}}, v3.8b");

    println!("########## floating point ##########");
    p!("scvtf v0.4s, v1.4s");
    p!("ucvtf v0.4s, v1.4s");
    p!("scvtf v0.2d, v1.2d");
    p!("fadd v0.4s, v1.4s, v2.4s");
    p!("fsub v0.4s, v1.4s, v2.4s");
    p!("fmul v0.4s, v1.4s, v2.4s");
    p!("fdiv v0.4s, v1.4s, v2.4s");
    p!("fabs v0.4s, v1.4s");
    p!("fneg v0.4s, v1.4s");
    p!("fsqrt v0.4s, v1.4s");
    p!("fmla v0.4s, v1.4s, v2.4s");
    p!("fmls v0.4s, v1.4s, v2.4s");
    p!("fmax v0.4s, v1.4s, v2.4s");
    p!("fmin v0.4s, v1.4s, v2.4s");
    // The NaN-propagating forms, which differ from FMAX/FMIN only when one
    // operand is NaN — and A reinterpreted as floats has some.
    p!("fmaxnm v0.4s, v1.4s, v2.4s");
    p!("fminnm v0.4s, v1.4s, v2.4s");
    p!("fabd v0.4s, v1.4s, v2.4s");
    p!("fcmeq v0.4s, v1.4s, v2.4s");
    p!("fcmge v0.4s, v1.4s, v2.4s");
    p!("fcmgt v0.4s, v1.4s, v2.4s");
    p!("fcmeq v0.4s, v1.4s, #0.0");
    p!("frecpe v0.4s, v1.4s");
    p!("frsqrte v0.4s, v1.4s");
    // The NaN-quiet pairwise max and min, and the two unsigned integer
    // estimates. All four were undecoded until 2026-09-03 and none of them is
    // an extension -- they are baseline ASIMD, which a compiler emits without
    // asking `AT_HWCAP` anything. Found by `decode_probe`, which sweeps the
    // encoding space rather than naming instructions somebody thought of; this
    // is where the *answers* are checked.
    p!("fmaxnmp v0.4s, v1.4s, v2.4s");
    p!("fminnmp v0.4s, v1.4s, v2.4s");
    p!("fmaxnmp v0.2d, v1.2d, v2.2d");
    p!("fminnmp v0.2d, v1.2d, v2.2d");
    p!("urecpe v0.4s, v1.4s");
    p!("ursqrte v0.4s, v1.4s");
    p!("urecpe v0.2s, v1.2s");
    p!("ursqrte v0.2s, v1.2s");
    // And the four width rules the sweep found too permissive: a halving add
    // and a pairwise max have no 64-bit form, and this accepted one.
    // The saturating shifts by an immediate, at every width -- the answers, not
    // just whether they decode. `SQSHLU` shifts a signed value and saturates
    // into the *unsigned* range, so a negative lane must come out zero, and A
    // has some.
    p!("sqshl v0.16b, v1.16b, #3");
    p!("sqshl v0.8h, v1.8h, #5");
    p!("sqshl v0.4s, v1.4s, #9");
    p!("sqshl v0.2d, v1.2d, #17");
    p!("uqshl v0.16b, v1.16b, #3");
    p!("uqshl v0.8h, v1.8h, #5");
    p!("uqshl v0.4s, v1.4s, #9");
    p!("uqshl v0.2d, v1.2d, #17");
    p!("sqshlu v0.16b, v1.16b, #3");
    p!("sqshlu v0.8h, v1.8h, #5");
    p!("sqshlu v0.4s, v1.4s, #9");
    p!("sqshlu v0.2d, v1.2d, #17");
    p!("sqshlu v0.2s, v1.2s, #0");
    // The vector fixed-point conversions, whose immediate is a scale rather
    // than a shift. Undecoded until 2026-09-03, while the scalar forms were
    // not -- which is what a swept encoding space finds and a hand-written case
    // list does not.
    p!("scvtf v0.4s, v1.4s, #7");
    p!("ucvtf v0.4s, v1.4s, #7");
    p!("scvtf v0.2s, v1.2s, #1");
    p!("scvtf v0.2d, v1.2d, #20");
    p!("ucvtf v0.2d, v1.2d, #20");
    p!("fcvtzs v0.4s, v1.4s, #3");
    p!("fcvtzu v0.4s, v1.4s, #3");
    p!("fcvtzs v0.2d, v1.2d, #11");
    // The saturating doubling long multiplies: the Q15 and Q31 primitives, and
    // the three whose absence was recorded as deliberate. Both halves and both
    // widths, because the `2` forms read the *upper* source lanes and getting
    // that backwards is a right answer computed from the wrong data.
    p!("sqdmull v0.4s, v1.4h, v2.4h");
    p!("sqdmull2 v0.4s, v1.8h, v2.8h");
    p!("sqdmull v0.2d, v1.2s, v2.2s");
    p!("sqdmull2 v0.2d, v1.4s, v2.4s");
    p!("sqdmlal v0.4s, v1.4h, v2.4h");
    p!("sqdmlal2 v0.4s, v1.8h, v2.8h");
    p!("sqdmlal v0.2d, v1.2s, v2.2s");
    p!("sqdmlsl v0.4s, v1.4h, v2.4h");
    p!("sqdmlsl2 v0.2d, v1.4s, v2.4s");
    // The scalar three-same forms: one element of a vector register operated on
    // alone. None was decoded until 2026-09-03. A scalar operation writes one
    // element and **zeroes the rest of the register**, which is why the whole
    // 16 bytes are printed rather than the element.
    p!("sqadd b0, b1, b2");
    p!("sqadd h0, h1, h2");
    p!("sqadd s0, s1, s2");
    p!("sqadd d0, d1, d2");
    p!("uqadd b0, b1, b2");
    p!("uqadd d0, d1, d2");
    p!("sqsub h0, h1, h2");
    p!("uqsub s0, s1, s2");
    p!("sqshl b0, b1, b2");
    p!("uqshl d0, d1, d2");
    p!("sqrshl s0, s1, s2");
    p!("uqrshl h0, h1, h2");
    p!("srshl d0, d1, d2");
    p!("urshl d0, d1, d2");
    p!("cmtst d0, d1, d2");
    p!("sqdmulh h0, h1, h2");
    p!("sqdmulh s0, s1, s2");
    p!("sqrdmulh h0, h1, h2");
    p!("fmulx s0, s1, s2");
    p!("fmulx d0, d1, d2");
    p!("fcmeq s0, s1, s2");
    p!("fcmge d0, d1, d2");
    p!("fcmgt s0, s1, s2");
    p!("facge s0, s1, s2");
    p!("facgt d0, d1, d2");
    p!("frecps s0, s1, s2");
    p!("frsqrts d0, d1, d2");
    // The scalar two-register misc forms. `suqadd` and `usqadd` accumulate
    // into the destination, which is why `q0` is loaded from `D` above and why
    // a wrong answer here is a wrong *value* rather than whatever was there.
    p!("suqadd b0, b1");
    p!("suqadd d0, d1");
    p!("usqadd s0, s1");
    p!("sqabs h0, h1");
    p!("sqabs d0, d1");
    p!("sqneg b0, b1");
    p!("sqxtn b0, h1");
    p!("sqxtn h0, s1");
    p!("sqxtn s0, d1");
    p!("uqxtn b0, h1");
    p!("sqxtun s0, d1");
    p!("fcvtxn s0, d1");
    p!("fcvtns s0, s1");
    p!("fcvtnu d0, d1");
    p!("fcvtms s0, s1");
    p!("fcvtmu d0, d1");
    p!("fcvtas s0, s1");
    p!("fcvtau d0, d1");
    p!("fcvtps s0, s1");
    p!("fcvtpu d0, d1");
    p!("frecpe s0, s1");
    p!("frsqrte d0, d1");
    p!("frecpx s0, s1");
    // The scalar shifts by an immediate. `sri` and `sli` insert rather than
    // shift, so the destination's surviving bits are half the answer -- which
    // is why `q0` is loaded from `D` and why a shift of the full width, where
    // nothing of the source survives, has its own case.
    p!("srshr d0, d1, #7");
    p!("urshr d0, d1, #63");
    p!("srsra d0, d1, #3");
    p!("ursra d0, d1, #64");
    p!("sri d0, d1, #1");
    p!("sri d0, d1, #64");
    p!("sli d0, d1, #0");
    p!("sli d0, d1, #63");
    p!("sqshl b0, b1, #3");
    p!("sqshl d0, d1, #40");
    p!("uqshl h0, h1, #5");
    p!("sqshlu s0, s1, #9");
    p!("sqshlu d0, d1, #0");
    p!("sqshrn b0, h1, #3");
    p!("sqshrn h0, s1, #9");
    p!("sqshrn s0, d1, #17");
    p!("uqshrn b0, h1, #3");
    p!("sqrshrn h0, s1, #9");
    p!("uqrshrn s0, d1, #17");
    p!("sqshrun b0, h1, #3");
    p!("sqrshrun s0, d1, #17");
    // `FMULX` by element, the last baseline instruction this group was missing:
    // the *scalar* form was decoded and the vector one was not.
    p!("fmulx v0.4s, v1.4s, v2.s[1]");
    p!("fmulx v0.2d, v1.2d, v2.d[1]");
    p!("fmulx s0, s1, v2.s[2]");
    // The scalar by-element saturating doubling multiplies, and a lane index
    // that is not zero -- the lane is fetched with a register offset, so an
    // index of 0 would pass whatever the arithmetic did.
    p!("sqdmulh h0, h1, v2.h[5]");
    p!("sqdmulh s0, s1, v2.s[3]");
    p!("sqrdmulh h0, h1, v2.h[2]");
    p!("sqdmull s0, h1, v2.h[7]");
    p!("sqdmull d0, s1, v2.s[1]");
    p!("sqdmlal s0, h1, v2.h[3]");
    p!("sqdmlsl d0, s1, v2.s[2]");
    p!("shadd v0.4s, v1.4s, v2.4s");
    p!("uhadd v0.4s, v1.4s, v2.4s");
    p!("srhadd v0.8h, v1.8h, v2.8h");
    p!("umaxp v0.4s, v1.4s, v2.4s");
    p!("uminp v0.4s, v1.4s, v2.4s");
    p!("frecps v0.4s, v1.4s, v2.4s");
    p!("frsqrts v0.4s, v1.4s, v2.4s");
    // The five rounding modes, which a `floor`/`ceil`/`round` compiles to.
    p!("frintn v0.4s, v1.4s");
    p!("frintp v0.4s, v1.4s");
    p!("frintm v0.4s, v1.4s");
    p!("frintz v0.4s, v1.4s");
    p!("frinta v0.4s, v1.4s");
    p!("fcvtzs v0.4s, v1.4s");
    p!("fcvtzu v0.4s, v1.4s");
    p!("fcvtns v0.4s, v1.4s");
    p!("fcvtms v0.4s, v1.4s");
    p!("fcvtps v0.4s, v1.4s");
    p!("fcvtas v0.4s, v1.4s");
    // Between widths, which is where a narrowing rounds.
    p!("fcvtl v0.2d, v1.2s");
    p!("fcvtn v0.2s, v1.2d");
    p!("fcvtxn v0.2s, v1.2d");
    p!("faddp v0.4s, v1.4s, v2.4s");
    p!("faddp s0, v1.2s");
    p!("fmaxv s0, v1.4s");
    p!("fminnmv s0, v1.4s");
    // Scalar, which is most of what a non-vectorised program runs.
    p!("fadd s0, s1, s2");
    p!("fmul d0, d1, d2");
    p!("fdiv d0, d1, d2");
    p!("fmadd s0, s1, s2, s0");
    p!("fnmsub d0, d1, d2, d0");
    p!("fcvt d0, s1");
    p!("fcvt s0, d1");
    // By-element multiplies, which is what a dot product or an FFT emits.
    p!("mul v0.4s, v1.4s, v2.s[2]");
    p!("mla v0.4s, v1.4s, v2.s[1]");
    p!("fmul v0.4s, v1.4s, v2.s[3]");
    p!("fmla v0.4s, v1.4s, v2.s[0]");
    p!("umull v0.4s, v1.4h, v2.h[3]");
    p!("sqdmulh v0.4s, v1.4s, v2.4s");
    p!("sqrdmulh v0.8h, v1.8h, v2.8h");

    println!("########## immediates ##########");
    // MOVI and MVNI have a shift and an "shift ones" variant, and the 64-bit
    // form expands each bit of the immediate to a whole byte.
    p!("movi v0.16b, #0x5a");
    p!("movi v0.4s, #0x12, lsl #8");
    p!("movi v0.4s, #0xff, msl #8");
    p!("movi d0, #0xff00ff00ff00ff00");
    p!("mvni v0.4s, #0x12, lsl #16");
    p!("movi v0.2d, #0xffffffffffffffff");
    p!("fmov v0.4s, #1.5");
    p!("fmov v0.2d, #-2.0");
    // The bitmask immediates, which read the destination.
    p!("orr v0.4s, #0x0f, lsl #8");
    p!("bic v0.4s, #0xf0, lsl #16");

    println!("########## loads and stores ##########");
    // The structured loads, which are how a program reads interleaved data and
    // which `gen.c` has to split into several registers. Written to a buffer
    // and read back so the *store* half is exercised too.
    let mut buf = [0u8; 64];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(1);
    }
    macro_rules! ldst {
        ($label:literal, $ld:literal, $st:literal) => {{
            let ok = isolated(|| unsafe {
                let mut out = [0u8; 64];
                asm!(
                    $ld,
                    $st,
                    src = in(reg) buf.as_ptr(),
                    dst = in(reg) out.as_mut_ptr(),
                    out("q0") _, out("q1") _, out("q2") _, out("q3") _,
                );
                std::ptr::copy_nonoverlapping(out.as_ptr(), SLOT, 64);
            });
            println!(
                "  {:<34} {}",
                $label,
                if ok { slot(64) } else { "SIGILL".to_string() }
            );
        }};
    }
    ldst!("ld1/st1 x1", "ld1 {{v0.16b}}, [{src}]", "st1 {{v0.16b}}, [{dst}]");
    ldst!(
        "ld1/st1 x4",
        "ld1 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{src}]",
        "st1 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{dst}]"
    );
    ldst!(
        "ld2/st2",
        "ld2 {{v0.16b, v1.16b}}, [{src}]",
        "st2 {{v0.16b, v1.16b}}, [{dst}]"
    );
    ldst!(
        "ld3/st3",
        "ld3 {{v0.16b, v1.16b, v2.16b}}, [{src}]",
        "st3 {{v0.16b, v1.16b, v2.16b}}, [{dst}]"
    );
    ldst!(
        "ld4/st4",
        "ld4 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{src}]",
        "st4 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{dst}]"
    );
    // The replicating and single-lane forms.
    ldst!("ld1r", "ld1r {{v0.16b}}, [{src}]", "st1 {{v0.16b}}, [{dst}]");
    ldst!("ld2r", "ld2r {{v0.8h, v1.8h}}, [{src}]", "st1 {{v0.16b, v1.16b}}, [{dst}]");
    ldst!(
        "ld1 single lane",
        "movi v0.16b, #0\nld1 {{v0.b}}[5], [{src}]",
        "st1 {{v0.16b}}, [{dst}]"
    );
    ldst!(
        "ld1 post-increment",
        "ld1 {{v0.16b}}, [{src}], #16\nld1 {{v1.16b}}, [{src}]",
        "st1 {{v0.16b, v1.16b}}, [{dst}]"
    );
    // The plain pair, which every function prologue spilling FP registers uses.
    ldst!(
        "ldp/stp q",
        "ldp q0, q1, [{src}]",
        "stp q0, q1, [{dst}]"
    );
    ldst!("ldr/str d", "ldr d0, [{src}]", "str d0, [{dst}]");
    ldst!("ldur/stur q unaligned", "ldur q0, [{src}, #3]", "stur q0, [{dst}, #1]");
}
