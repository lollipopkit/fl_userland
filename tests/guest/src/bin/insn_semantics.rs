//! Instruction results the random differential (`insn_diff`) found wrong,
//! each with the answer a real arm64 kernel gives.
//!
//! Every expected value here was taken from, or checked against, a real
//! kernel on Apple silicon (`docker run --platform linux/arm64`).

use guest_tests::insn::{State, run, setup, slot_addr};
use guest_tests::{Harness, check};

const FPSR_IOC: u64 = 1 << 0;
const FPSR_OFC: u64 = 1 << 2;
const FPSR_QC: u64 = 1 << 27;
const FPCR_AHP: u64 = 1 << 26;
const NZCV_Z: u64 = 1 << 30;
const NZCV_C: u64 = 1 << 29;

fn exec(insn: u32, f: impl FnOnce(&mut State)) -> (State, bool) {
    let mut st = State::zeroed();
    f(&mut st);
    unsafe { run(insn, &st) }
}

/// Run in a child, for an instruction whose wrong answer kills the process
/// (it writes SP, and the stub runs on SP). True if the child exits 0.
fn survives(insn: u32, f: impl FnOnce(&mut State), ok: impl FnOnce(&State, &State) -> bool) -> bool {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let mut st = State::zeroed();
        f(&mut st);
        let (after, ill) = unsafe { run(insn, &st) };
        unsafe { libc::_exit(if !ill && ok(&st, &after) { 0 } else { 1 }) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

#[derive(Clone, Copy)]
enum Kind { Sshr, Ushr, Ssra, Usra, Srshr, Srsra, Ursra, Sri }

/// One immediate right shift, lane by lane, in 128-bit arithmetic so that a
/// shift by the whole element width is just a shift.
fn model(kind: Kind, d: [u64; 2], n: [u64; 2], esize: u32, shift: u32, q: bool) -> [u64; 2] {
    let (d, n) = (d[0] as u128 | (d[1] as u128) << 64, n[0] as u128 | (n[1] as u128) << 64);
    let lanes = if q { 128 } else { 64 } / esize;
    let full = (1u128 << esize) - 1;
    let mut out = 0u128;
    for i in 0..lanes {
        let lane = |v: u128| (v >> (i * esize)) & full;
        let (dn, nn) = (lane(d), lane(n));
        let sn = ((nn << (128 - esize)) as i128) >> (128 - esize);
        let round = 1i128 << (shift - 1);
        let r = match kind {
            Kind::Sshr => (sn >> shift) as u128,
            Kind::Ushr => nn >> shift,
            Kind::Ssra => dn.wrapping_add((sn >> shift) as u128),
            Kind::Usra => dn.wrapping_add(nn >> shift),
            Kind::Srshr => ((sn + round) >> shift) as u128,
            Kind::Srsra => dn.wrapping_add(((sn + round) >> shift) as u128),
            Kind::Ursra => dn.wrapping_add((nn + round as u128) >> shift),
            Kind::Sri => {
                let keep = if shift >= esize { 0 } else { full >> shift };
                (dn & !keep) | ((nn >> shift) & keep)
            }
        } & full;
        out |= r << (i * esize);
    }
    [out as u64, (out >> 64) as u64]
}

fn main() {
    unsafe { setup() };
    let mut h = Harness::new();

    h.group("add-sub-shifted-register-rd31-is-zr");
    // In the shifted-register forms register 31 is WZR/XZR; only the immediate
    // and extended-register forms name SP. The gadget wrote the sum to SP.
    for (name, insn) in [("add wzr, w30, w27, asr #21", 0x0b9b_57dfu32), ("sub xzr, x24, x17, lsr #30", 0xcb51_7b1f)] {
        let ok = survives(insn, |s| {
            s.x[30] = 0x1234;
            s.x[27] = 0x4000_0000;
            s.x[24] = 0x10_0000;
            s.x[17] = 0xc000_0000;
        }, |b, a| a.x == b.x);
        check!(h, ok, "{name}: no register changes and SP is untouched");
    }

    h.group("ccmp-ccmn-nv-is-always");
    // Condition 0b1111 (NV) holds like AL: ConditionHolds is true for 111x.
    // The four conditional-compare gadgets took it as never.
    for (name, insn) in [
        ("ccmp w12, w3, #15, nv", 0x7a43_f18fu32),
        ("ccmn w12, w3, #15, nv", 0x3a43_f18f),
    ] {
        let (a, _) = exec(insn, |s| {
            s.x[12] = 5;
            s.x[3] = if name.starts_with("ccmn") { 0u32.wrapping_sub(5) as u64 } else { 5 };
        });
        check!(h, a.nzcv == NZCV_Z | NZCV_C, "{name}: compares, nzcv={:#x} (want Z|C)", a.nzcv);
    }
    for (name, insn) in [("ccmp x1, #3, #0, nv", 0xfa43_f820u32), ("ccmn x1, #3, #0, nv", 0xba43_f820)] {
        let (a, _) = exec(insn, |s| {
            s.x[1] = if name.starts_with("ccmn") { (-3i64) as u64 } else { 3 };
            s.nzcv = 0xf << 28;
        });
        check!(h, a.nzcv == NZCV_Z | NZCV_C, "{name}: compares, nzcv={:#x} (want Z|C)", a.nzcv);
    }

    h.group("adrp-is-64-bit");
    // adrp x25, #-2732306432 from 0x3000xxxx: the result wraps below zero,
    // and the architecture keeps all 64 bits. It was masked to 48.
    let (a, _) = exec(0xb0ae_9239, |_| {});
    let want = (slot_addr() & !0xfff).wrapping_add((-2_732_306_432i64) as u64);
    check!(h, a.x[25] == want, "adrp x25: {:#x} (want {want:#x})", a.x[25]);

    h.group("64-bit-shift-insert-accumulate-clears-the-top");
    // A 64-bit destination (Q=0, or a scalar D) zeroes bits 127:64. These
    // read-modify-write the whole register and kept them.
    for (name, insn, rd) in [
        ("sli v19.8b, v6.8b, #3", 0x2f0b_54d3u32, 19),
        ("sri v20.4h, v31.4h, #14", 0x2f12_47f4, 20),
        ("ssra v15.8b, v9.8b, #5", 0x0f0b_152f, 15),
        ("usra v1.2s, v22.2s, #10", 0x2f36_16c1, 1),
        ("ssra d7, d22, #20", 0x5f6c_16c7, 7),
        ("usra d9, d10, #14", 0x7f72_1549, 9),
    ] {
        let (a, _) = exec(insn, |s| {
            for q in &mut s.q {
                *q = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
            }
        });
        check!(h, a.q[rd][1] == 0, "{name}: top half {:#x} (want 0)", a.q[rd][1]);
    }

    h.group("ssra-by-the-element-width");
    // ssra v17.8h, v2.8h, #16: a shift by the full width leaves each lane's
    // sign, so negative lanes add -1. The gadget added nothing.
    let (a, _) = exec(0x4f10_1451, |s| {
        s.q[17] = [0x778d_b6bd_7b18_6e36, 0x7f7f_ffff_3f80_0000];
        s.q[2] = [0x94bb_e22e_310f_9a73, 0x000b_0040_00e9_003c];
    });
    check!(h, a.q[17] == [0x778c_b6bc_7b18_6e35, 0x7f7f_ffff_3f80_0000],
        "ssra .8h #16: {:016x}{:016x}", a.q[17][1], a.q[17][0]);

    h.group("sqshlu-sets-qc");
    // A negative lane saturates to zero, which is a saturation: FPSR.QC.
    let (a, _) = exec(0x6f20_66a9, |s| s.q[21] = [0x0096_00a2_0028_00e2, 0x6cad_fbaa_c902_2cff]);
    check!(h, a.fpsr & FPSR_QC != 0, "sqshlu v9.4s, v21.4s, #0: fpsr={:#x} (want QC)", a.fpsr);

    h.group("fixed-point-fcvtz");
    // To a W register the top 32 bits are zero; the gadget sign-extended.
    let (a, _) = exec(0x1e18_a3e9, |s| {
        s.q[31] = [0x153c_b18d_ca59_d9a2, 0];
        s.x[9] = 0xffff_ffff_0000_0000;
    });
    check!(h, a.x[9] == 0x8000_0000, "fcvtzs w9, s31, #24: {:#x} (want 0x80000000)", a.x[9]);
    // An invalid conversion raises IOC; it must not also raise OFC, which the
    // multiply-then-convert the gadget does sets.
    let (a, _) = exec(0x4f4b_fd62, |s| s.q[11] = [0x0094_0085_00b7_00e9, 0x7fc0_0000_bf80_0000]);
    check!(h, a.fpsr & FPSR_OFC == 0 && a.fpsr & FPSR_IOC != 0,
        "fcvtzs v2.2d, v11.2d, #53: fpsr={:#x} (want IOC, no OFC)", a.fpsr);

    h.group("fcvt-to-and-from-half");
    // Base ARMv8.0 FP, not FEAT_FP16. Half from single/double copied the
    // source bits; single/double from half raised SIGILL.
    let one_s = 0x3f80_0000u64;
    let one_d = 0x3ff0_0000_0000_0000u64;
    let one_h = 0x3c00u64;
    for (name, insn, src, want) in [
        ("fcvt h0, s1", 0x1e23_c020u32, one_s, one_h),
        ("fcvt h0, d1", 0x1e63_c020, one_d, one_h),
        ("fcvt s0, h1", 0x1ee2_4020, one_h, one_s),
        ("fcvt d0, h1", 0x1ee2_c020, one_h, one_d),
    ] {
        let (a, ill) = exec(insn, |s| s.q[1] = [src, 0]);
        check!(h, !ill && a.q[0] == [want, 0], "{name} of 1.0: ill={ill} {:#x} (want {want:#x})", a.q[0][0]);
    }
    // FPCR.AHP: the alternative format has no NaN; a NaN converts to 0 with IOC.
    let (a, _) = exec(0x1e23_c020, |s| {
        s.q[1] = [0x7fc0_0000, 0];
        s.fpcr = FPCR_AHP;
    });
    check!(h, a.q[0][0] == 0 && a.fpsr & FPSR_IOC != 0,
        "fcvt h0, s1 of NaN under AHP: {:#x} fpsr={:#x} (want 0, IOC)", a.q[0][0], a.fpsr);

    h.group("scalar-saturating-doubling-multiply-long");
    // AdvSIMD scalar three-different: SIGILL here, and FEAT_AdvSIMD is
    // advertised. The by-element and vector forms were implemented.
    for (name, insn, want) in [
        ("sqdmull d0, s1, s2", 0x5ea2_d020u32, 24u64),
        ("sqdmlal d0, s1, s2", 0x5ea2_9020, 34),
        ("sqdmlsl d0, s1, s2", 0x5ea2_b020, (-14i64) as u64),
    ] {
        let (a, ill) = exec(insn, |s| {
            s.q[0] = [10, 0];
            s.q[1] = [3, 0];
            s.q[2] = [4, 0];
        });
        check!(h, !ill && a.q[0] == [want, 0], "{name}: ill={ill} {:#x} (want {want:#x})", a.q[0][0]);
    }

    h.group("fccmpe-signals-for-a-quiet-nan");
    // FCCMPE raises Invalid for any NaN, FCCMP only for a signalling one. The
    // E bit was dropped, so both ran quietly. (NV holds like AL.)
    let (a, _) = exec(0x1e2f_f57d, |s| {
        s.q[11] = [0x7fc0_0000, 0];
        s.q[15] = [0x3f80_0000, 0];
    });
    check!(h, a.fpsr & FPSR_IOC != 0, "fccmpe s11, s15, nv of a quiet NaN: fpsr={:#x} (want IOC)", a.fpsr);
    let (a, _) = exec(0x1e2f_f56d, |s| {
        s.q[11] = [0x7fc0_0000, 0];
        s.q[15] = [0x3f80_0000, 0];
    });
    check!(h, a.fpsr & FPSR_IOC == 0, "fccmp s11, s15, nv of a quiet NaN: fpsr={:#x} (want none)", a.fpsr);

    h.group("fixed-point-scale-by-the-whole-width");
    // A 32-bit element has up to 32 fraction bits; `1 << 32` in a W register
    // is 1, not 2^32, so the scale was 1.
    let f1 = 0x3f80_0000u64;
    let (a, _) = exec(0x5f20_fc20, |s| s.q[1] = [f1, 0]); // fcvtzs s0, s1, #32
    check!(h, a.q[0] == [0x7fff_ffff, 0] && a.fpsr & FPSR_OFC == 0 && a.fpsr & FPSR_IOC != 0,
        "fcvtzs s0, s1, #32 of 1.0: {:#x} fpsr={:#x} (want 0x7fffffff, IOC only)", a.q[0][0], a.fpsr);
    let (a, _) = exec(0x4f20_fc20, |s| s.q[1] = [f1 | 0xbf80_0000 << 32, 0x3f00_0000 | 0x8000_0000 << 32]);
    // Lanes 1.0, -1.0, 0.5 and -0.0, each scaled by 2^32.
    check!(h, a.q[0] == [0x8000_0000_7fff_ffff, 0x0000_0000_7fff_ffff],
        "fcvtzs v0.4s, v1.4s, #32: {:016x}{:016x}", a.q[0][1], a.q[0][0]);
    let (a, _) = exec(0x5f20_e420, |s| s.q[1] = [0x8000_0000, 0]); // scvtf s0, s1, #32
    check!(h, a.q[0] == [0xbf00_0000, 0], "scvtf s0, s1, #32 of INT_MIN: {:#x} (want -0.5)", a.q[0][0]);
    let (a, _) = exec(0x6f20_e420, |s| s.q[1] = [0x8000_0000 | 0x4000_0000 << 32, 0]); // ucvtf v0.4s, v1.4s, #32
    check!(h, a.q[0] == [0x3f00_0000 | 0x3e80_0000 << 32, 0], "ucvtf v0.4s, v1.4s, #32: {:#x}", a.q[0][0]);
    // A double that overflows when scaled saturates and raises IOC only; the
    // scaling multiply's own overflow (OFC) and inexact (IXC) are not the
    // instruction's.
    let (a, _) = exec(0x9e58_0020, |s| s.q[1] = [0x7e37_e43c_8800_759c, 0]); // fcvtzs x0, d1, #64 of 1e300
    check!(h, a.x[0] == 0x7fff_ffff_ffff_ffff && a.fpsr == FPSR_IOC,
        "fcvtzs x0, d1, #64 of 1e300: {:#x} fpsr={:#x} (want INT64_MAX, IOC)", a.x[0], a.fpsr);
    let (a, _) = exec(0x1e19_8020, |s| s.q[1] = [0x3f00_0000, 0]); // fcvtzu w0, s1, #32 of 0.5
    check!(h, a.x[0] == 0x8000_0000, "fcvtzu w0, s1, #32 of 0.5: {:#x}", a.x[0]);
    // 64-bit integer to *single* with fbits: converted once, at single
    // precision. Through a double it rounds twice: 2^62 + 2^38 + 1 is above the
    // halfway point of a single, but the double conversion drops the 1 and the
    // single then sees an exact tie and rounds down.
    let x = (1u64 << 62) + (1 << 38) + 1;
    for (name, insn) in [("scvtf s0, x1, #1", 0x9e02_fc20u32), ("ucvtf s0, x1, #1", 0x9e03_fc20)] {
        let (a, _) = exec(insn, |s| s.x[1] = x);
        let want = ((1u64 << 62) + (1 << 39)) as f32 / 2.0;
        check!(h, a.q[0][0] == u64::from(want.to_bits()), "{name}: {:#x} (want {:#x})", a.q[0][0], want.to_bits());
    }

    h.group("right-shift-by-the-element-width");
    // A shift by the whole width (`SSRA Dd, Dn, #64`) shifts everything out:
    // zero, or the sign. lsr/asr take the amount modulo 64.
    let neg = 0x8000_0000_0000_0001u64;
    for (name, insn, want) in [
        ("ssra d0, d1, #64", 0x5f40_1420u32, 10u64.wrapping_sub(1)),
        ("usra d0, d1, #64", 0x7f40_1420, 10),
        ("sshr d0, d1, #64", 0x5f40_0420, u64::MAX),
        ("ushr d0, d1, #64", 0x7f40_0420, 0),
        ("srshr d0, d1, #64", 0x5f40_2420, 0),
        ("urshr d0, d1, #64", 0x7f40_2420, 1),
        ("sri d0, d1, #64", 0x7f40_4420, 10),
    ] {
        let (a, _) = exec(insn, |s| {
            s.q[0] = [10, 0xdead];
            s.q[1] = [neg, 0xbeef];
        });
        check!(h, a.q[0] == [want, 0], "{name}: {:#x}{:016x} (want {want:#x})", a.q[0][1], a.q[0][0]);
    }
    // The vector forms against a model of each lane. `esize` is in bits.
    for (name, insn, kind, esize, shift, q) in [
        ("ssra v0.2d, v1.2d, #64", 0x4f40_1420u32, Kind::Ssra, 64u32, 64u32, true),
        ("usra v0.2d, v1.2d, #64", 0x6f40_1420, Kind::Usra, 64, 64, true),
        ("sshr v0.2d, v1.2d, #64", 0x4f40_0420, Kind::Sshr, 64, 64, true),
        ("usra v0.4s, v1.4s, #32", 0x6f20_1420, Kind::Usra, 32, 32, true),
        ("ssra v0.8h, v1.8h, #16", 0x4f10_1420, Kind::Ssra, 16, 16, true),
        ("srshr v0.8h, v1.8h, #16", 0x4f10_2420, Kind::Srshr, 16, 16, true),
        ("ursra v0.4s, v1.4s, #32", 0x6f20_3420, Kind::Ursra, 32, 32, true),
        ("srsra v0.16b, v1.16b, #8", 0x4f08_3420, Kind::Srsra, 8, 8, true),
        ("sri v0.8h, v1.8h, #16", 0x6f10_4420, Kind::Sri, 16, 16, true),
        ("sri v0.8b, v1.8b, #8", 0x2f08_4420, Kind::Sri, 8, 8, false),
        ("ushr v0.16b, v1.16b, #8", 0x6f08_0420, Kind::Ushr, 8, 8, true),
        ("srsra v0.4h, v1.4h, #5", 0x0f1b_3420, Kind::Srsra, 16, 5, false),
        ("ursra v0.2s, v1.2s, #7", 0x2f39_3420, Kind::Ursra, 32, 7, false),
    ] {
        let d = [0x0123_4567_89ab_cdefu64, 0xfedc_ba98_7654_3210];
        let n = [0x8000_7fff_0001_ffffu64, 0x80ff_0080_ff01_7f80];
        let (a, _) = exec(insn, |s| {
            s.q[0] = d;
            s.q[1] = n;
        });
        let want = model(kind, d, n, esize, shift, q);
        check!(h, a.q[0] == want, "{name}: {:016x}{:016x} (want {:016x}{:016x})",
            a.q[0][1], a.q[0][0], want[1], want[0]);
    }

    h.group("sqshlu-scalar-and-vector-qc");
    // A negative element saturates to zero: QC. A positive one only when the
    // shifted value does not fit.
    for (name, insn, src, qc) in [
        ("sqshlu d3, d0, #38", 0x7f66_6403u32, 0x8000_0000_0000_0001u64, true),
        ("sqshlu s20, s19, #8", 0x7f28_6674, 0x8000_0001, true),
        ("sqshlu h28, h17, #9", 0x7f19_663c, 0x8001, true),
        ("sqshlu b1, b2, #3", 0x7f0b_6441, 0x81, true),
        ("sqshlu d3, d0, #38", 0x7f66_6403, 1, false),
        ("sqshlu s20, s19, #8", 0x7f28_6674, 1, false),
        ("sqshlu d3, d0, #38", 0x7f66_6403, 1 << 30, true),
    ] {
        let (a, _) = exec(insn, |s| {
            s.q[0] = [src, 0];
            s.q[19] = [src, 0];
            s.q[17] = [src, 0];
            s.q[2] = [src, 0];
        });
        check!(h, (a.fpsr & FPSR_QC != 0) == qc, "{name} of {src:#x}: fpsr={:#x} (QC wanted: {qc})", a.fpsr);
    }
    // Q=0 forms saturate only the lanes they have: the high half of the
    // source is not an operand.
    let (a, _) = exec(0x2f20_6462, |s| s.q[3] = [0x0000_0001_0000_0001, 0x8000_0000_8000_0000]);
    check!(h, a.fpsr & FPSR_QC == 0, "sqshlu v2.2s, v3.2s, #0 with a negative high half: fpsr={:#x} (want no QC)", a.fpsr);

    h.group("unallocated-encodings-are-undefined");
    // Accepted and run as something else. A program that probes for a feature
    // by catching SIGILL is told it exists.
    for (name, insn) in [
        // Add/subtract immediate with tags, sf=0: unallocated.
        ("dpimm op0=011, sf=0", 0x1192_04c6u32),
        // Add/subtract extended register with opt != 00: unallocated.
        ("adds extended, opt=10", 0x2ba2_cc6f),
        // `.1D` is not an arrangement, for any three-same, shift or lane op.
        ("addp v.1d (three-same, Q=0, size=3)", 0x0eef_be1c),
        ("fmaxnm v.1d (three-same FP, Q=0, sz=1)", 0x0e7c_c666),
        ("shift by immediate, immh=1xxx with Q=0", 0x2f66_e54b),
        ("fmla by element, sz=1 with Q=0", 0x0fd7_530a),
        ("fmul by element, sz=1 with L=1", 0x2fd5_9a78),
        ("dup v.1d", 0x0e08_0420),
        // SHA-1 with bit 15 set; AES with size != 0.
        ("sha1 three-register, bit 15", 0x5e0e_80b1),
        ("aesd, size=11", 0x4ee8_592d),
        // UMOV to an X register of a byte lane.
        ("umov x4, v6.b[3]", 0x4e07_3cc4),
        // Across-lanes over two words.
        ("umaxv, .2s", 0x2eb0_a832),
        // Fixed-point conversion to a W register with more than 32 fraction bits.
        ("fcvtzs w, d, #fbits>32", 0x1e58_3963),
    ] {
        let (_, ill) = exec(insn, |_| {});
        check!(h, ill, "{name} ({insn:#010x}) raises SIGILL");
    }

    std::process::exit(h.finish());
}
