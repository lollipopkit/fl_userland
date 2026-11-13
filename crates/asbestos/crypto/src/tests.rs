//! Every expected value here was **measured on an arm64 CPU**, not recited.
//!
//! `tests/guest/src/bin/crypto_probe.rs` computes each of these with the real
//! instruction; running it in an arm64 container on this machine prints the
//! answers, and they are transcribed here. That matters because the first
//! attempt at testing this used FIPS-197 constants written from memory, and
//! four of them were the AES state serialised the wrong way round — they
//! failed against the hardware before the emulator was ever reached.
//!
//! To regenerate:
//!
//! ```text
//! cd tests/guest && cargo build --release --target aarch64-unknown-linux-musl --bin crypto_probe
//! docker run --rm --platform linux/arm64 \
//!     -v "$PWD/target/aarch64-unknown-linux-musl/release:/t:ro" alpine /t/crypto_probe
//! ```

use super::*;

fn h(s: &str) -> [u8; 16] {
    let b: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    b.try_into().unwrap()
}

const ABCD: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

const N2: [u64; 2] = [0x1111_2222_3333_4444, 0x8000_0000_0000_0001];
const M2: [u64; 2] = [0xdead_beef_cafe_babe, 0x0000_0000_0000_002a];

fn ramp(f: impl Fn(usize) -> u8) -> [u8; 16] {
    std::array::from_fn(f)
}

#[test]
fn sha3_matches_the_hardware() {
    let a = ramp(|i| i as u8);
    let b = ramp(|i| (i as u8).wrapping_mul(3));
    let c = ramp(|i| 0xff ^ i as u8);
    assert_eq!(sha3::eor3(a, b, c), h("fffcf9f6f3f0edeae7e4e1dedbd8d5d2"));
    assert_eq!(sha3::bcax(a, b, c), h("00000002000004020000000a08080402"));
    assert_eq!(sha3::rax1(N2, M2), [0xac4a5ffda6ce3139, 0x8000000000000055]);
    assert_eq!(
        sha3::xar(N2, M2, 17),
        [0xff7d67de4e66fce6, 0x0015c00000000000]
    );
}

/// `XAR` rotates by `imm & 63`, and 0 must not be a 64-bit shift — which in
/// Rust would be a panic in debug and unspecified in release. The C guarded it
/// with an explicit `if (n == 0) return x` and `rotate_right` does the same
/// thing without one.
#[test]
fn xar_by_zero_is_a_plain_xor() {
    assert_eq!(sha3::xar(N2, M2, 0), [N2[0] ^ M2[0], N2[1] ^ M2[1]]);
    assert_eq!(
        sha3::xar(N2, M2, 64),
        [N2[0] ^ M2[0], N2[1] ^ M2[1]],
        "and 64 wraps to 0"
    );
}

#[test]
fn sm3_and_sm4_match_the_hardware() {
    // Measured on the emulator rather than the CPU: Apple Silicon implements
    // neither FEAT_SM3 nor FEAT_SM4, so `crypto_probe` prints "no FEAT_SM3"
    // there. These pin what the C did, so the port is checked even though the
    // behaviour itself is not.
    assert_eq!(
        sm::sm3partw1(ABCD, [5, 6, 7, 8], [9, 10, 11, 12]),
        [0xf4f1b0b5, 0x3df8387e, 0x8a0c4ec9, 0xdd5fbf35]
    );
    assert_eq!(
        sm::sm4e(ABCD, [5, 6, 7, 8]),
        [0x9cbacc4d, 0x420e6a7b, 0x0726ee59, 0x6feadc79]
    );
}

#[test]
fn pmull_matches_the_hardware() {
    assert_eq!(
        pmull::mul64(0x0123_4567_89ab_cdef, 1),
        0x0123_4567_89ab_cdef
    );
    // x^3+x+1 squared in GF(2)[x] is x^6+x^2+1: the bits spread out.
    assert_eq!(pmull::mul64(0b1011, 0b1011), 0b1000101);
    assert_eq!(
        pmull::mul64(u64::MAX, u64::MAX),
        0x5555_5555_5555_5555_5555_5555_5555_5555
    );
}

#[test]
fn the_shifts_match_the_hardware() {
    use simd::Shift::*;
    let d = [0xffff_ffff_ffff_ffffu64, 0];
    let n = [0x0123_4567_89ab_cdefu64, 0xfedc_ba98_7654_3210];
    let bytes = |v: [u64; 2]| -> [u8; 16] {
        let mut o = [0u8; 16];
        o[..8].copy_from_slice(&v[0].to_le_bytes());
        o[8..].copy_from_slice(&v[1].to_le_bytes());
        o
    };
    let words = |b: [u8; 16]| -> [u64; 2] {
        [
            u64::from_le_bytes(b[..8].try_into().unwrap()),
            u64::from_le_bytes(b[8..].try_into().unwrap()),
        ]
    };
    let (d8, n8) = (bytes(d), bytes(n));
    assert_eq!(
        words(simd::shift_imm(RightInsert, false, d8, n8, 32, 3, true)),
        [0xffffffff01234567, 0x00000000fedcba98]
    );
    assert_eq!(
        words(simd::shift_imm(LeftInsert, false, d8, n8, 32, 3, true)),
        [0x89abcdefffffffff, 0x7654321000000000]
    );
    assert_eq!(
        words(simd::shift_imm(RightAccumulate, false, d8, n8, 8, 3, true)),
        [0x000123456789abcc, 0x00fedcba98765432]
    );
    assert_eq!(
        words(simd::shift_imm(RightAccumulate, true, d8, n8, 8, 3, true)),
        [0x000123456789abcc, 0xfffedcba98765432]
    );

    // The `.16b` forms, which is where the signed and unsigned right shifts
    // are told apart: every lane of `hi` has its top bit clear except none, so
    // the two agree here and the probe says so too.
    let hi = ramp(|i| 0x10 + i as u8);
    assert_eq!(
        simd::shift_imm(Left, false, [0; 16], hi, 3, 0, true),
        h("80889098a0a8b0b8c0c8d0d8e0e8f0f8")
    );
    assert_eq!(
        simd::shift_imm(Right, false, [0; 16], hi, 3, 0, true),
        h("02020202020202020303030303030303")
    );
    assert_eq!(
        simd::shift_imm(Right, true, [0; 16], hi, 3, 0, true),
        h("02020202020202020303030303030303")
    );
}

/// The signed right shift has to sign-extend from the *element* width, not
/// from 64. A lane whose top bit is set is the only input that shows it, and
/// the `.16b` values above happen not to have one.
#[test]
fn a_signed_right_shift_extends_from_the_element_not_the_register() {
    use simd::Shift::*;
    let n = [0x80u8; 16]; // every byte is -128
    let unsigned = simd::shift_imm(Right, false, [0; 16], n, 3, 0, true);
    let signed = simd::shift_imm(Right, true, [0; 16], n, 3, 0, true);
    assert_eq!(unsigned, [0x10u8; 16], "0x80 >> 3 unsigned");
    assert_eq!(signed, [0xf0u8; 16], "-128 >> 3 is -16");
}

/// `SRI` keeps the destination's *top* `shift` bits and `SLI` its bottom ones.
/// Swapping the two masks is the mistake, and it is invisible when the
/// destination is all ones or all zeroes — which is what the hardware vector
/// above uses for one lane each.
#[test]
fn the_insert_shifts_keep_opposite_ends() {
    use simd::Shift::*;
    let d = [0xaau8; 16];
    let n = [0x0fu8; 16];
    // SRI #4: keep the top four bits of 0xaa (0xa0), insert 0x0f >> 4 = 0x00.
    assert_eq!(
        simd::shift_imm(RightInsert, false, d, n, 4, 0, true),
        [0xa0u8; 16]
    );
    // SLI #4: keep the bottom four of 0xaa (0x0a), insert 0x0f << 4 = 0xf0.
    assert_eq!(
        simd::shift_imm(LeftInsert, false, d, n, 4, 0, true),
        [0xfau8; 16]
    );
}

/// A 64-bit destination is written as a whole register, so the top eight bytes
/// are zero after *every* shift: plain, insert or accumulate. The insert and
/// accumulate forms read the destination but do not preserve its top half; the
/// C left it, and a real kernel zeroes it (`SLI Vd.8B`, `USRA Vd.2S`, `SSRA Dd`).
#[test]
fn the_half_register_forms_zero_the_top_half_for_every_shift() {
    use simd::Shift::*;
    let d = [0xffu8; 16];
    let n = [0x11u8; 16];
    for (op, signed) in [
        (Left, false),
        (Right, false),
        (RightAccumulate, false),
        (RightAccumulate, true),
        (RightInsert, false),
        (LeftInsert, false),
    ] {
        let r = simd::shift_imm(op, signed, d, n, 1, 0, false);
        assert_eq!(&r[8..], &[0u8; 8], "top half of {}", r[0]);
    }
    // And the low half is still computed from the whole destination.
    let inserted = simd::shift_imm(LeftInsert, false, d, n, 1, 0, false);
    assert_eq!(&inserted[..8], &[0x23u8 | 0x01; 8], "0x11 << 1 over 0xff's low bit");
}

/// A right shift by the whole element width is allowed and shifts every bit
/// out: the accumulate forms add zero (or the sign, -1, for a negative signed
/// lane) and `SRI` inserts nothing. `SSRA Vd.8H, Vn.8H, #16` accumulated the
/// lane itself, and at 64 bits the shift wrapped to zero.
#[test]
fn a_right_shift_by_the_element_width_shifts_everything_out() {
    use simd::Shift::*;
    let d = ramp(|i| i as u8);
    // Halfwords 0x8000 (negative) and 0x7fff (positive), alternating.
    let n: [u8; 16] = core::array::from_fn(|i| [0x00, 0x80, 0xff, 0x7f][i % 4]);
    let signed = simd::shift_imm(RightAccumulate, true, d, n, 16, 1, true);
    let unsigned = simd::shift_imm(RightAccumulate, false, d, n, 16, 1, true);
    assert_eq!(unsigned, d, "USRA #16 adds zero");
    for lane in 0..8 {
        let before = u16::from_le_bytes([d[lane * 2], d[lane * 2 + 1]]);
        let got = u16::from_le_bytes([signed[lane * 2], signed[lane * 2 + 1]]);
        let sign = if lane % 2 == 0 { 0xffff } else { 0 };
        assert_eq!(got, before.wrapping_add(sign), "SSRA #16, lane {lane}");
    }
    let neg64 = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 1, 0, 0, 0, 0, 0, 0, 0x40];
    let s64 = simd::shift_imm(Right, true, [0; 16], neg64, 64, 3, true);
    assert_eq!(&s64[..8], &[0xffu8; 8], "SSHR #64 of a negative doubleword");
    assert_eq!(&s64[8..], &[0u8; 8]);
    assert_eq!(simd::shift_imm(Right, false, [0; 16], neg64, 64, 3, true), [0u8; 16]);
    assert_eq!(simd::shift_imm(RightInsert, false, d, n, 64, 3, true), d, "SRI #64");
}

/// The `slow_call` entries do nothing but read, call and write back — which
/// is exactly what makes them worth one test rather than one each.
#[test]
fn the_c_entry_points_read_and_write_the_registers_they_name() {
    // `RAX1 V3, V1, V2` through the register file, as the `slow_call` gadget
    // reaches it.
    let mut cpu = emu_abi::cpu_state::default();
    cpu.fp[1].d = N2;
    cpu.fp[2].d = M2;
    unsafe { crate::slow::slow_rax1(&mut cpu, std::ptr::null_mut(), 0, 3 | (1 << 8) | (2 << 16)) };
    assert_eq!(cpu.fp[3].d, sha3::rax1(N2, M2));

    // The one that reads its destination as an input.
    // `USRA V4.16B, V5.16B, #2`.
    cpu.fp[4] = emu_abi::arm64_vreg::from_bytes([0x11; 16]);
    cpu.fp[5] = emu_abi::arm64_vreg::from_bytes([0x40; 16]);
    unsafe { crate::slow::slow_usra(&mut cpu, std::ptr::null_mut(), 0, 4 | (5 << 8) | (2 << 16) | (1 << 28)) };
    assert_eq!(cpu.fp[4].bytes(), [0x21u8; 16], "0x11 + (0x40 >> 2)");
    // A shift by the whole width: `USHR V6.2D, V5.2D, #64` needs the eight-bit
    // amount field, and gives zero.
    cpu.fp[6] = emu_abi::arm64_vreg::from_bytes([0xff; 16]);
    unsafe { crate::slow::slow_ushr(&mut cpu, std::ptr::null_mut(), 0, 6 | (5 << 8) | (64 << 16) | (3 << 24) | (1 << 28)) };
    assert_eq!(cpu.fp[6].bytes(), [0; 16], "USHR #64");
}

/// A register file whose byte `i` is `i`, as the table tests read it.
fn numbered_file() -> emu_abi::cpu_state {
    let mut cpu = emu_abi::cpu_state::default();
    for (r, v) in cpu.fp.iter_mut().enumerate() {
        *v = emu_abi::arm64_vreg::from_bytes(std::array::from_fn(|i| (r * 16 + i) as u8));
    }
    cpu
}

/// `TBL Vd, {Vn..}, Vm` and `TBX` as their operand words: `rd | rn << 8 |
/// rm << 16 | len << 24 | q << 28`.
fn lookup(cpu: &mut emu_abi::cpu_state, tbx: bool, rd: u64, rn: u64, rm: u64, len: u64) -> [u8; 16] {
    let arg = rd | (rn << 8) | (rm << 16) | (len << 24) | (1 << 28);
    let f = if tbx { crate::slow::slow_tbx } else { crate::slow::slow_tbl };
    unsafe { f(cpu, std::ptr::null_mut(), 0, arg) };
    cpu.fp[rd as usize].bytes()
}

/// `TBL` and `TBX` differ only in what an out-of-range index does, and both
/// wrap from `v31` to `v0`.
#[test]
fn the_table_lookups_differ_only_past_the_end() {
    // A one-register table at v2, and indices half in range and half not, in
    // v5; the destination v9 starts as 0x5a everywhere.
    let idx: [u8; 16] = std::array::from_fn(|i| if i < 8 { (15 - i) as u8 } else { 200 });
    for (tbx, rest, what) in [(false, 0, "tbl zeroes an index past the table"), (true, 0x5a, "tbx leaves it")] {
        let mut cpu = numbered_file();
        cpu.fp[5] = emu_abi::arm64_vreg::from_bytes(idx);
        cpu.fp[9] = emu_abi::arm64_vreg::from_bytes([0x5a; 16]);
        let want: [u8; 16] = std::array::from_fn(|i| if i < 8 { (32 + 15 - i) as u8 } else { rest });
        assert_eq!(lookup(&mut cpu, tbx, 9, 2, 5, 0), want, "{what}");
    }
}

/// A table starting at `v31` runs off the end of the register file and wraps
/// to `v0`. Nothing in the guest suite reaches this, and it was pointer
/// arithmetic against the file's base until the lookup took the file itself.
#[test]
fn a_table_at_the_end_of_the_register_file_wraps_to_v0() {
    let mut cpu = numbered_file();
    // Index 16 is the first byte of the *second* table register, which is v0.
    cpu.fp[5] = emu_abi::arm64_vreg::from_bytes([16; 16]);
    assert_eq!(lookup(&mut cpu, false, 9, 31, 5, 1), [0u8; 16], "v0's first byte, not one past the file");
}
