//! Pulling an immediate out of an instruction word.
//!
//! Four pure functions, and they are here rather than inline in the class
//! decoders because each is the sort of thing that is wrong in a way nothing
//! notices: an off-by-one in a sign extension is a branch to the wrong place,
//! and a wrong bitmask immediate is a mask that lets the wrong bits through.
//!
//! They were `static inline` in `emu/arch/arm64/decode.h`, which is why the
//! class decoders could not move one at a time — a header inline has no symbol
//! to link to. Reimplemented rather than exported, because they are eight lines
//! each and the tests are the point.

/// Sign-extend the low `bits` of `val` to 64.
pub fn sign_extend(val: u64, bits: u32) -> i64 {
    // The C spells this `val | (~0ULL << bits)`, which is undefined for
    // `bits == 64` -- no caller passes it, and reproducing a shift that
    // overflows is not worth the fidelity.
    if bits >= 64 {
        return val as i64;
    }
    let sign = 1u64 << (bits - 1);
    if val & sign != 0 {
        (val | (!0u64 << bits)) as i64
    } else {
        val as i64
    }
}

/// The 19-bit offset a `B.cond`, `CBZ` or `LDR (literal)` carries, in bytes.
pub(crate) fn branch_imm19(insn: u32) -> i64 {
    sign_extend(((insn as u64 >> 5) & 0x7ffff) << 2, 21)
}

/// `ADR`/`ADRP`'s 21-bit offset, which is split: two low bits at 30:29 and
/// nineteen high ones at 23:5. Assembling it the other way round is a
/// four-byte error on every `adr` and a four-kilobyte one on every `adrp`.
pub(crate) fn adr_imm(insn: u32) -> i64 {
    let immlo = (insn as u64 >> 29) & 0x3;
    let immhi = (insn as u64 >> 5) & 0x7ffff;
    sign_extend((immhi << 2) | immlo, 21)
}

/// The logical-immediate encoding: a repeating run of ones, rotated.
///
/// Thirteen bits — `N:immr:imms` — describe a 64-bit constant, and this is the
/// one piece of AArch64 immediate decoding with real structure in it. `len` is
/// the position of the highest set bit of `N:~imms`, and it gives the *element
/// width*; `s + 1` ones are rotated right by `r` within that element and the
/// element is repeated to fill the register.
///
/// `None` for the two encodings that are not allocated: `len == 0`, and
/// `s == size - 1`, which would be an all-ones element and is reserved because
/// `MOVN` already produces it.
pub(crate) fn bitmask_imm(n: u32, imms: u32, immr: u32, is64: bool) -> Option<u64> {
    // `N = 1` selects a 64-bit element, so a 32-bit operation cannot name it.
    // Without this the length search below found bit 6, computed a 64-bit
    // pattern and then truncated it to 32 -- a mask, but not the one the
    // encoding names, because the encoding names nothing. 252 encodings, and
    // `tests/guest/src/bin/decode_probe.rs` is what asked.
    if n == 1 && !is64 {
        return None;
    }
    let combined = (n << 6) | (!imms & 0x3f);
    let len = (0..=6).rev().find(|i| combined & (1 << i) != 0)?;
    if len < 1 {
        return None;
    }
    let size = 1u32 << len;
    let s = imms & (size - 1);
    let r = immr & (size - 1);
    if s == size - 1 {
        return None;
    }

    let mut pattern = (1u64 << (s + 1)) - 1;
    if r > 0 {
        // Rotate right *within the element*, not within 64 bits — which is why
        // the mask below is by `size` and not by the register width.
        pattern = (pattern >> r) | (pattern << (size - r));
        if size < 64 {
            pattern &= (1u64 << size) - 1;
        }
    }

    let mut out = 0u64;
    let mut i = 0;
    while i < 64 {
        out |= pattern << i;
        i += size;
    }
    if !is64 {
        out &= 0xffff_ffff;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_extension_turns_on_the_bit_above() {
        assert_eq!(sign_extend(0, 8), 0);
        assert_eq!(sign_extend(0x7f, 8), 127);
        assert_eq!(sign_extend(0x80, 8), -128);
        assert_eq!(sign_extend(0xff, 8), -1);
        assert_eq!(sign_extend(1 << 20, 21), -(1 << 20));
        assert_eq!(sign_extend(u64::MAX, 64), -1);
    }

    /// `b.eq` forward 8 bytes and backward 8, which is the encoding a loop
    /// produces at both ends.
    #[test]
    fn a_conditional_branch_offset_is_bytes_and_signed() {
        // B.cond: 0101 0100 imm19 0 cond
        let mk = |imm19: u32| 0x5400_0000 | ((imm19 & 0x7ffff) << 5);
        assert_eq!(branch_imm19(mk(0)), 0);
        assert_eq!(branch_imm19(mk(2)), 8, "two instructions forward");
        assert_eq!(branch_imm19(mk((-2i32) as u32)), -8, "and backward");
        // The extremes of the range, which is ±1 MB.
        assert_eq!(branch_imm19(mk(0x3ffff)), (0x3ffff) * 4);
        assert_eq!(branch_imm19(mk(0x40000)), -(1 << 20));
    }

    /// The split immediate. Assembling it with the halves the other way round
    /// is off by four on every `adr`, which is exactly the kind of thing that
    /// works for a while.
    #[test]
    fn adr_puts_its_low_two_bits_at_the_top_of_the_word() {
        // ADR: 0 immlo 10000 immhi Rd
        let mk =
            |immlo: u32, immhi: u32| 0x1000_0000 | ((immlo & 3) << 29) | ((immhi & 0x7ffff) << 5);
        assert_eq!(adr_imm(mk(0, 0)), 0);
        assert_eq!(adr_imm(mk(1, 0)), 1, "immlo is the *low* bits");
        assert_eq!(adr_imm(mk(3, 0)), 3);
        assert_eq!(adr_imm(mk(0, 1)), 4, "and immhi is shifted above them");
        assert_eq!(adr_imm(mk(1, 1)), 5);
        // Negative: the top bit of immhi is the sign.
        assert_eq!(adr_imm(mk(0, 0x40000)), -(1 << 20));
    }

    /// The four encodings a compiler emits most, checked against what the
    /// instruction means rather than against a table.
    #[test]
    fn a_bitmask_immediate_is_a_rotated_run_of_ones() {
        // `and w0, w0, #0xff`: eight ones, no rotation. `N = 0` with
        // `imms = 0b000111` is element width **32**, so the 64-bit read of the
        // same encoding is the pattern repeated -- which is what the assembler
        // uses for `and w0, w0, #0xff` and not for the `x` form.
        assert_eq!(bitmask_imm(0, 0b000111, 0, false), Some(0xff));
        assert_eq!(bitmask_imm(0, 0b000111, 0, true), Some(0xff_0000_00ff));
        // `and x0, x0, #0xff` is `N = 1`, which is element width 64 -- one
        // copy of the pattern and nothing repeated. Writing this as `N = 0`
        // was the first version of this test, and the failure is the whole
        // reason `N` is worth a comment: it is not a size bit, it is the top
        // bit of the field that gives the width.
        assert_eq!(bitmask_imm(1, 0b000111, 0, true), Some(0xff));
        // `and x0, x0, #0xffffffff`: 32 ones, N=0 and imms=0b011111 gives
        // element width 32 with all-but-one set... which is the reserved case,
        // so the real encoding is N=0, imms=0b011111 refused and the assembler
        // picks the 64-wide one instead.
        assert_eq!(
            bitmask_imm(0, 0b011111, 0, true),
            None,
            "s == size-1 is reserved"
        );
        // The alternating patterns, which are element width 2 and 4.
        assert_eq!(
            bitmask_imm(0, 0b111100, 0, true),
            Some(0x5555_5555_5555_5555)
        );
        assert_eq!(
            bitmask_imm(0, 0b111000, 0, true),
            Some(0x1111_1111_1111_1111)
        );
        // 64-bit element, one bit set, rotated to the top: N=1 selects width 64.
        assert_eq!(bitmask_imm(1, 0, 1, true), Some(0x8000_0000_0000_0000));
        assert_eq!(bitmask_imm(1, 0, 0, true), Some(1));
    }

    /// The rotation is *within the element*, not within the register. A
    /// version that rotated 64 bits gives the same answer for width 64 and a
    /// different one for every other width, which is why this uses a narrow
    /// element.
    #[test]
    fn the_rotation_wraps_inside_the_element() {
        // Element width 8 (N=0, imms = 0b110xxx), two ones, rotated right by 1.
        // 0b00000011 ror 1 within 8 bits is 0b10000001, repeated eight times.
        let v = bitmask_imm(0, 0b110001, 1, true).unwrap();
        assert_eq!(v, 0x8181_8181_8181_8181);
        // Rotating within 64 instead would have put the wrapped bit at bit 63
        // and left the other elements as 0b00000001.
        assert_ne!(v, 0x8000_0000_0000_0181);
    }

    /// The two unallocated shapes, both of which a guest can encode and which
    /// must be an undefined instruction rather than some other constant.
    #[test]
    fn the_reserved_encodings_are_refused() {
        // len == 0: N=0 and imms = 0b1111xx, so N:~imms has no bit above 0.
        assert_eq!(bitmask_imm(0, 0b111111, 0, true), None);
        // s == size - 1 at every width.
        assert_eq!(bitmask_imm(0, 0b111101, 0, true), None, "width 2");
        assert_eq!(bitmask_imm(0, 0b111011, 0, true), None, "width 4");
        assert_eq!(bitmask_imm(1, 0b111111, 0, true), None, "width 64");
    }

    /// The 32-bit form is the 64-bit one truncated, which is what makes
    /// `and w0, w0, #imm` and `and x0, x0, #imm` share an encoding.
    #[test]
    fn the_32_bit_form_is_the_low_half() {
        for imms in 0..64u32 {
            for immr in [0u32, 1, 7, 31] {
                let a = bitmask_imm(0, imms, immr, true);
                let b = bitmask_imm(0, imms, immr, false);
                match (a, b) {
                    (Some(a), Some(b)) => assert_eq!(b, a & 0xffff_ffff),
                    (None, None) => {}
                    _ => panic!("the two widths disagreed about whether {imms}/{immr} is legal"),
                }
            }
        }
    }

    /// `N = 1` selects a 64-bit element, so a 32-bit logical immediate cannot
    /// name it. Without the check the length search found bit 6, built a 64-bit
    /// pattern and truncated it — a mask, but not one the encoding names,
    /// because the encoding names nothing.
    #[test]
    fn a_32_bit_bitmask_immediate_cannot_set_n() {
        for imms in 0..64u32 {
            assert_eq!(bitmask_imm(1, imms, 0, false), None, "imms {imms}");
        }
        // At 64 bits `N = 1` is the whole point: it is how a mask with a
        // 64-bit element is spelled.
        assert_eq!(bitmask_imm(1, 0, 0, true), Some(1));
        // And `N = 0` still works at both widths.
        assert!(bitmask_imm(0, 0, 0, false).is_some());
        assert!(bitmask_imm(0, 0, 0, true).is_some());
    }
}
