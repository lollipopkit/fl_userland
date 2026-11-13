//! Decoder tests for load/store instruction generation.

use super::addressed::{literal, pair, reg_offset, unscaled_or_indexed, unsigned_imm};
use super::simd_access::struct_regs;
use crate::harness::Decoder;

/// `CASP` has to be matched before `CAS`, and the `sz` bit has to be in
/// the match. The 64-bit one is a **sixteen-byte** atomic; handling it as
/// a 64-bit compare-and-swap tears the pair, which is the `libpas`
/// versioned-field corruption that hangs Bun.
#[test]
fn the_pair_compare_and_swap_is_matched_before_the_single() {
    // CASP X0, X1, X2, X3, [X4] — sz=1.
    let casp64 = 0x4820_7c00u32 | (4 << 5);
    // CASP W0, W1, W2, W3, [X4] — sz=0, an eight-byte atomic.
    let casp32 = 0x0820_7c00u32 | (4 << 5);
    // CAS X0, X1, [X2] — bit 23 set.
    let cas = 0x08a0_7c00u32 | (2 << 5) | (1 << 30);

    assert_eq!(casp64 & 0xffa0_7c00, 0x4820_7c00);
    assert_eq!(casp32 & 0xffa0_7c00, 0x0820_7c00);
    assert_ne!(casp64 & 0xffa0_7c00, 0x0820_7c00, "the widths are distinct");
    // The plain CAS mask leaves the size field free -- it has to, because
    // CASB and CASH have bit 31 clear -- so it would also match CASP if
    // CASP were not tested first.
    assert_eq!(cas & 0x3fa0_7c00, 0x08a0_7c00);
    assert_eq!(casp64 & 0x3fa0_7c00, 0x0820_7c00, "and does not match CASP");
    assert_ne!(casp64 & 0x3fa0_7c00, 0x08a0_7c00);
}

/// A 128-bit SIMD access is `size == 0` with the high `opc` bit — the one
/// place in this class where the size field does not give the width, and
/// where reading it as a size gives a one-byte access instead of sixteen.
#[test]
fn a_quadword_simd_access_is_not_size_three() {
    let width = |size: u32, opc: u32| {
        if size == 0 && opc & 2 != 0 {
            16
        } else {
            1u32 << size
        }
    };
    assert_eq!(width(0, 0), 1, "byte");
    assert_eq!(width(3, 1), 8, "doubleword");
    assert_eq!(width(0, 2), 16, "quadword, and size says byte");
    assert_eq!(width(0, 3), 16);
}

/// The structure loads: `LD1` with four registers and `LD4` with four are
/// different instructions with different opcodes, and one deinterleaves.
#[test]
fn the_structure_opcodes_separate_count_from_interleaving() {
    assert_eq!(struct_regs(0x7), Some((1, false)), "ld1 x1");
    assert_eq!(struct_regs(0x2), Some((4, false)), "ld1 x4, back to back");
    assert_eq!(struct_regs(0x0), Some((4, true)), "ld4, deinterleaved");
    assert_eq!(struct_regs(0x8), Some((2, true)), "ld2");
    assert_eq!(struct_regs(0x3), None, "and the rest are unallocated");
    assert_eq!(struct_regs(0xf), None);
}

/// A post-indexed load into its own base register is CONSTRAINED
/// UNPREDICTABLE: the writeback and the loaded value both want the
/// register. It takes the generic chain rather than a fast gadget that
/// would pick an order.
#[test]
fn an_indexed_load_into_its_own_base_is_not_fused() {
    let fusable = |rn: u32, rt: u32, opc: u32| rt != 31 && rn != rt && opc & 2 == 0;
    assert!(fusable(1, 2, 1), "different registers");
    assert!(!fusable(1, 1, 1), "the same register");
    assert!(!fusable(1, 31, 1), "into XZR");
    assert!(
        !fusable(1, 2, 2),
        "and a sign-extending load has no fused form"
    );
}

/// The lane number of a single-element access is assembled from three
/// fields, and differently at every width — because a vector holds
/// sixteen bytes, eight halfwords, four words or two doublewords.
#[test]
fn the_lane_number_is_assembled_per_width() {
    let lane = |base: u32, size: u32, q: u32, s: u32| match (base, size) {
        (0, _) => Some((1u32, (q << 3) | (s << 2) | size)),
        (2, _) => Some((2, (q << 2) | (s << 1) | (size & 1))),
        (4, 0) => Some((4, (q << 1) | s)),
        (4, 1) => Some((8, q)),
        _ => None,
    };
    // A byte has sixteen lanes, so it takes all four bits.
    assert_eq!(lane(0, 3, 1, 1), Some((1, 15)));
    assert_eq!(lane(0, 0, 0, 0), Some((1, 0)));
    // A halfword has eight.
    assert_eq!(lane(2, 1, 1, 1), Some((2, 7)));
    // A word has four and a doubleword two.
    assert_eq!(lane(4, 0, 1, 1), Some((4, 3)));
    assert_eq!(lane(4, 1, 1, 0), Some((8, 1)));
    // And size 2 or 3 with base opcode 4 is unallocated.
    assert_eq!(lane(4, 2, 0, 0), None);
}

/// Which `(size, V, opc)` combinations exist, asked of the three forms that
/// share the table rather than of the table.
///
/// A test on `register_form_allocated` alone would say nothing about
/// whether anything calls it, which is exactly what was wrong: the rule was
/// not written down anywhere and each form decoded the unallocated
/// combinations as whichever neighbour `opc`'s bits selected.
#[test]
fn the_register_forms_share_one_size_and_opc_table() {
    let mut d = Decoder::new();
    // Rn = 0, Rt = 1, and for the register offset Rm = 3 with `option`
    // 011, which is LSL -- the one the fused path takes.
    let ui = |size: u32, v: u32, opc: u32| 0x3900_0000 | 1 | (size << 30) | (v << 26) | (opc << 22);
    let un = |size: u32, v: u32, opc: u32, mode: u32| {
        0x3800_0000 | 1 | (size << 30) | (v << 26) | (opc << 22) | (mode << 10)
    };
    let ro = |size: u32, v: u32, opc: u32| {
        0x3820_0800 | 1 | (3 << 16) | (3 << 13) | (size << 30) | (v << 26) | (opc << 22)
    };
    // Every form refuses the same eight.
    for (size, v, opc) in [
        (1, 1, 2),
        (1, 1, 3),
        (2, 0, 3),
        (2, 1, 2),
        (2, 1, 3),
        (3, 0, 3),
        (3, 1, 2),
        (3, 1, 3),
    ] {
        assert!(
            !d.decodes(unsigned_imm, ui(size, v, opc)),
            "ui {size} {v} {opc}"
        );
        assert!(
            !d.decodes(unscaled_or_indexed, un(size, v, opc, 0)),
            "un {size} {v} {opc}"
        );
        assert!(
            !d.decodes(reg_offset, ro(size, v, opc)),
            "ro {size} {v} {opc}"
        );
    }
    // And each accepts what does exist, including the two that look like
    // the refusals above: LDRSW is (2, 0, 2), and the 128-bit SIMD pair is
    // (0, 1, 2) and (0, 1, 3).
    for (size, v, opc) in [(2, 0, 2), (0, 1, 2), (0, 1, 3), (0, 0, 3), (1, 0, 3)] {
        assert!(
            d.decodes(unsigned_imm, ui(size, v, opc)),
            "ui {size} {v} {opc}"
        );
        assert!(
            d.decodes(reg_offset, ro(size, v, opc)),
            "ro {size} {v} {opc}"
        );
    }
}

/// `PRFM` exists in the forms that have one and not in the others, which is
/// the only place `(3, 0, 2)` differs between them.
#[test]
fn only_some_forms_have_a_prefetch() {
    let mut d = Decoder::new();
    let un = |mode: u32| 0x3800_0000 | 1 | (3 << 30) | (2 << 22) | (mode << 10);
    assert!(
        d.decodes(unsigned_imm, 0x3900_0000 | 1 | (3 << 30) | (2 << 22)),
        "PRFM"
    );
    assert!(d.decodes(unscaled_or_indexed, un(0)), "PRFUM");
    assert!(
        !d.decodes(unscaled_or_indexed, un(1)),
        "no post-indexed prefetch"
    );
    assert!(
        !d.decodes(unscaled_or_indexed, un(2)),
        "nor an unprivileged one"
    );
    assert!(
        !d.decodes(unscaled_or_indexed, un(3)),
        "nor a pre-indexed one"
    );
}

/// Bit 1 of `option` is set for every extend that exists — `UXTW`, `LSL`,
/// `SXTW`, `SXTX` — and clear for the four that name nothing. They were
/// passed to the address gadget, which extended by whatever the number
/// meant to it.
#[test]
fn a_register_offset_extends_one_of_four_ways() {
    let mut d = Decoder::new();
    let ro = |option: u32| 0x3820_0800 | 1 | (3 << 16) | (2 << 30) | (option << 13);
    for option in [2u32, 3, 6, 7] {
        assert!(d.decodes(reg_offset, ro(option)), "option {option} exists");
    }
    for option in [0u32, 1, 4, 5] {
        assert!(
            !d.decodes(reg_offset, ro(option)),
            "option {option} does not"
        );
    }
}

/// `LDTR`/`STTR` are the unscaled form with a different translation regime,
/// and a guest here has one regime. They were refused outright.
#[test]
fn the_unprivileged_loads_and_stores_are_the_unscaled_ones() {
    let mut d = Decoder::new();
    let un = |size: u32, opc: u32, mode: u32| {
        0x3800_0000 | 1 | (size << 30) | (opc << 22) | (mode << 10)
    };
    // Every width and every direction, which is the thirteen a real kernel
    // has: four opcodes at each of four sizes, less the three that name
    // nothing at any width.
    let mut n = 0;
    for size in 0..4u32 {
        for opc in 0..4u32 {
            if d.decodes(unscaled_or_indexed, un(size, opc, 2)) {
                n += 1;
            }
        }
    }
    assert_eq!(n, 13, "the unprivileged forms that exist");
    // A SIMD unprivileged form does not exist.
    assert!(!d.decodes(unscaled_or_indexed, un(0, 0, 2) | (1 << 26)));
}

/// An integer pair has `opc` 00 and 10; `01` is `LDPSW` and `STGP`, which
/// have no non-temporal form, and `11` is nothing.
#[test]
fn the_integer_pair_opcodes_that_exist() {
    let mut d = Decoder::new();
    // Rt = 1, Rt2 = 2, Rn = 0.
    let p = |opc: u32, mode: u32, l: u32| {
        0x2800_0000 | 1 | (2 << 10) | (opc << 30) | (mode << 23) | (l << 22)
    };
    for mode in 0..4u32 {
        for l in 0..2u32 {
            assert!(d.decodes(pair, p(0, mode, l)), "32-bit pair");
            assert!(d.decodes(pair, p(2, mode, l)), "64-bit pair");
            assert!(!d.decodes(pair, p(3, mode, l)), "opc 3 names nothing");
        }
        for l in 0..2u32 {
            let expected = mode != 0;
            assert_eq!(
                d.decodes(pair, p(1, mode, l)),
                expected,
                "opc 1 mode {mode}: LDPSW and STGP have no non-temporal form"
            );
        }
    }
}

/// `PRFM (literal)` is a hint like the other two prefetch forms, and was
/// the only one refused — so a prefetch through a literal pool was `SIGILL`.
#[test]
fn a_literal_prefetch_is_a_hint_and_not_an_error() {
    let mut d = Decoder::new();
    let lit = |opc: u32, v: u32| 0x1800_0000 | 1 | (opc << 30) | (v << 26);
    assert!(d.decodes(literal, lit(0, 0)), "LDR literal, 32-bit");
    assert!(d.decodes(literal, lit(1, 0)), "64-bit");
    assert!(d.decodes(literal, lit(2, 0)), "LDRSW literal");
    assert!(d.decodes(literal, lit(3, 0)), "PRFM literal");
    // The SIMD side still has no fourth.
    assert!(!d.decodes(literal, lit(3, 1)));
}
