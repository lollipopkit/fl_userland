//! Which of the five decoders an instruction belongs to.
//!
//! AArch64 puts the answer in four bits — 28:25 — with two exceptions carved
//! out of the branch group by higher bits. That is the whole top-level
//! encoding, and it is why this decoder has five classes rather than a tree.

/// The five classes, and the two the branch group splits into.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Class {
    /// Nothing allocated: `op0` of 0, 1, 2 or 3.
    Unknown,
    /// `ADR`, the immediate arithmetic, the logical immediates, the moves, the
    /// bitfield family and `EXTR`.
    DpImm,
    /// Every branch, conditional and not.
    Branch,
    /// `SVC`, `BRK`, `HLT` — anything that leaves the guest.
    Exception,
    /// `MRS`, `MSR`, the barriers and the hints.
    System,
    /// Everything that touches memory.
    LdSt,
    /// The register arithmetic, the shifts, the selects and the multiplies.
    DpReg,
    /// SIMD, floating-point and the cryptographic extensions.
    SimdFp,
}

/// Classify by the top-level encoding.
pub fn classify(insn: u32) -> Class {
    match (insn >> 25) & 0xf {
        0b1000 | 0b1001 => Class::DpImm,
        0b1010 | 0b1011 => {
            // Two groups are cut out of the branch space by bits above `op0`.
            // The order matters: the system encoding is a subset of the
            // exception one's eight bits, so testing ten bits first is what
            // keeps `MRS` from being read as a `BRK`.
            if insn >> 22 == 0x354 {
                Class::System
            } else if insn >> 24 == 0xd4 {
                Class::Exception
            } else {
                Class::Branch
            }
        }
        0b0100 | 0b0110 | 0b1100 | 0b1110 => Class::LdSt,
        0b0101 | 0b1101 => Class::DpReg,
        0b0111 | 0b1111 => Class::SimdFp,
        _ => Class::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One real instruction from each class, so that a bit slipped in the
    /// match is a failure rather than a class that quietly never fires.
    #[test]
    fn each_class_has_an_instruction_in_it() {
        assert_eq!(classify(0x9100_0400), Class::DpImm, "add x0, x0, #1");
        assert_eq!(classify(0x1400_0001), Class::Branch, "b .+4");
        assert_eq!(classify(0x5400_0000), Class::Branch, "b.eq .+0");
        assert_eq!(classify(0xd400_0001), Class::Exception, "svc #0");
        assert_eq!(classify(0xd420_0000), Class::Exception, "brk #0");
        assert_eq!(classify(0xd53b_d040), Class::System, "mrs x0, tpidr_el0");
        assert_eq!(classify(0xd503_20df), Class::System, "hint / nop");
        assert_eq!(classify(0xf900_0000), Class::LdSt, "str x0, [x0]");
        assert_eq!(classify(0x8b00_0000), Class::DpReg, "add x0, x0, x0");
        assert_eq!(
            classify(0x4e20_1c00),
            Class::SimdFp,
            "and v0.16b, v0.16b, v0.16b"
        );
        assert_eq!(classify(0x1e60_2800), Class::SimdFp, "fcmp d0, d0");
    }

    /// The exception group is `0xd4` in the top *eight* bits and the system
    /// group `0x354` in the top *ten*, and the two overlap: every system
    /// instruction starts `1101 0101`, which is not `1101 0100`. This is the
    /// check that the wider test does not swallow the narrower one.
    #[test]
    fn the_system_group_is_not_inside_the_exception_group() {
        let mrs = 0xd53b_d040u32;
        assert_eq!(mrs >> 22, 0x354);
        assert_ne!(mrs >> 24, 0xd4, "0xd5, one above");
        let svc = 0xd400_0001u32;
        assert_eq!(svc >> 24, 0xd4);
        assert_ne!(svc >> 22, 0x354);
    }

    /// The four `op0` values with nothing in them. `0` in particular is what an
    /// all-zero word decodes to, which is what a jump into a zeroed page hits.
    #[test]
    fn the_unallocated_op0_values_are_unknown() {
        for op0 in [0b0000u32, 0b0001, 0b0010, 0b0011] {
            assert_eq!(classify(op0 << 25), Class::Unknown, "op0 {op0:#06b}");
        }
        assert_eq!(classify(0), Class::Unknown);
    }
}
