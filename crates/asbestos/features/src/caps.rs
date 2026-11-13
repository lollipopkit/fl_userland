//! What the guest CPU is told it has: one table, three readers.
//!
//! `AT_HWCAP`/`AT_HWCAP2` (`crates/kernel/initstack`), the ID registers a guest
//! reads with `mrs` (`crates/asbestos/gen`'s `system.rs`) and the `Features`
//! line of `/proc/cpuinfo` (`crates/fs/proc`) each described the CPU on their
//! own until 2026-09-30, and disagreed: cpuinfo listed six features, the
//! auxiliary vector eleven, and `ID_AA64ISAR1_EL1` none. A feature is added
//! here, once, and all three follow.
//!
//! # The rule for adding one
//!
//! An entry may be added only when **every** instruction the feature defines
//! executes, because a library that sees the bit emits all of them and an
//! undecoded one kills the process. `tests/guest/src/bin/insn_features.rs`
//! checks the instructions against a real kernel and `hwcap_agree.rs` checks
//! this table against one.

/// The ID registers a guest can read that carry feature fields.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum IdReg {
    Isar0,
    Isar1,
    Pfr0,
    Pfr1,
}

/// A four-bit ID register field: which register, the lowest bit, the value.
///
/// A field takes the **largest** value any entry gives it: `DPB` is 1 for
/// `DC CVAP` and 2 when `DC CVADP` exists as well, and the two entries that say
/// so are independent hwcap bits.
#[derive(Clone, Copy)]
pub struct Field(pub IdReg, pub u32, pub u64);

#[derive(Clone, Copy)]
pub struct Cap {
    /// The name in `/proc/cpuinfo`'s `Features` line, as Linux spells it.
    pub name: &'static str,
    /// The bit in `AT_HWCAP`, or 0.
    pub hwcap: u64,
    /// The bit in `AT_HWCAP2`, or 0.
    pub hwcap2: u64,
    pub fields: &'static [Field],
}

const fn cap(name: &'static str, hwcap: u64, hwcap2: u64, fields: &'static [Field]) -> Cap {
    Cap {
        name,
        hwcap,
        hwcap2,
        fields,
    }
}

use IdReg::*;

/// Every feature that is advertised. Printed in the order Linux prints them:
/// `HWCAP` by bit, then `HWCAP2` by bit.
pub const CAPS: &[Cap] = &[
    cap("fp", 1 << 0, 0, &[]),
    cap("asimd", 1 << 1, 0, &[]),
    cap("evtstrm", 1 << 2, 0, &[]),
    // AES with PMULL, what puts ring's gcm_ghash_clmul on its 64-bit CLMUL path.
    cap("aes", 1 << 3, 0, &[Field(Isar0, 4, 2)]),
    cap("pmull", 1 << 4, 0, &[]),
    cap("sha1", 1 << 5, 0, &[Field(Isar0, 8, 1)]),
    cap("sha2", 1 << 6, 0, &[Field(Isar0, 12, 2)]),
    cap("crc32", 1 << 7, 0, &[Field(Isar0, 16, 1)]),
    cap("atomics", 1 << 8, 0, &[Field(Isar0, 20, 2)]),
    // SQRDMLAH/SQRDMLSH, all forms and both sizes: `features.S`.
    cap("asimdrdm", 1 << 12, 0, &[Field(Isar0, 28, 1)]),
    // FCMLA and FCADD on single and double precision (the half-precision forms
    // need FEAT_FP16, which `fcma` does not imply): `features.S`.
    cap("fcma", 1 << 14, 0, &[Field(Isar1, 16, 1)]),
    // FlagM (cfinv, rmif, setf8, setf16) and FlagM2 (axflag, xaflag): TS = 2
    // says both.
    cap("flagm", 1 << 27, 0, &[Field(Isar0, 52, 2)]),
    cap("flagm2", 0, 1 << 7, &[]),
    // FRINT32Z/X and FRINT64Z/X, scalar and vector, in software
    // (`crates/asbestos/features::frint`).
    cap("frint", 0, 1 << 8, &[Field(Isar1, 32, 1)]),
    // DC CVAP and DC CVADP: no-ops, as the other data cache operations are
    // (`system` in `crates/asbestos/gen/src/features.rs`). DPB = 2 says both.
    cap("dcpop", 1 << 16, 0, &[Field(Isar1, 0, 2)]),
    cap("dcpodp", 0, 1 << 0, &[]),
    // PSTATE.DIT, as state: `cpu_state.dit`.
    cap("dit", 1 << 24, 0, &[Field(Pfr0, 48, 1)]),
    // SMMLA, UMMLA, USMMLA, USDOT and SUDOT: `features.S`.
    cap("i8mm", 0, 1 << 13, &[Field(Isar1, 52, 1)]),
    // BFDOT, BFMMLA, BFMLALB/T, BFCVT, BFCVTN(2) with FPCR.EBF clear
    // (`crates/asbestos/features::bf16`). BF16 = 1, not 2: FEAT_EBF16 (the
    // `ebf16` hwcap) is not implemented.
    cap("bf16", 0, 1 << 14, &[Field(Isar1, 44, 1)]),
    // The ID registers (`MIDR_EL1`, `REVIDR_EL1` and the ID_AA64* block) read
    // at EL0, as Linux emulates them: `system.rs` answers each, and those with no
    // feature to report read as zero.
    cap("cpuid", 1 << 11, 0, &[]),
    // SB as a real speculation barrier: `dsb sy; isb`.
    cap("sb", 1 << 29, 0, &[Field(Isar1, 36, 1)]),
    // Half-precision arithmetic, scalar and AdvSIMD, all in software
    // (`crates/asbestos/features::fp16`), with FPCR.FZ16 kept by
    // `msr_fpcr_fz16`. PFR0.FP and PFR0.AdvSIMD = 1 say half precision.
    cap("fphp", 1 << 9, 0, &[Field(Pfr0, 16, 1)]),
    cap("asimdhp", 1 << 10, 0, &[Field(Pfr0, 20, 1)]),
    // FJCVTZS, in software: `crates/asbestos/features::jscvt`.
    cap("jscvt", 1 << 13, 0, &[Field(Isar1, 12, 1)]),
    // LRCPC2 (`ldapur`, `stlur`) is a superset of LRCPC (`ldapr`), so the one
    // field, at 2, says both. `ilrcpc` is Linux's name for the LRCPC2 half.
    cap("lrcpc", 1 << 15, 0, &[Field(Isar1, 20, 2)]),
    // SDOT/UDOT, vector and by element: `features.S`.
    cap("asimddp", 1 << 20, 0, &[Field(Isar0, 44, 1)]),
    // SHA3: eor3, bcax, rax1, xar.
    cap("sha3", 1 << 17, 0, &[Field(Isar0, 32, 1)]),
    // SHA512: sha512h, sha512h2, sha512su0, sha512su1. SM3 and SM4 are absent
    // because only `sm3partw1` and `sm4e` are decoded, of eight and two.
    cap("sha512", 1 << 21, 0, &[]),
    cap("ilrcpc", 1 << 26, 0, &[]),
];

/// `AT_HWCAP`.
pub const fn hwcap() -> u64 {
    let mut v = 0;
    let mut i = 0;
    while i < CAPS.len() {
        v |= CAPS[i].hwcap;
        i += 1;
    }
    v
}

/// `AT_HWCAP2`.
pub const fn hwcap2() -> u64 {
    let mut v = 0;
    let mut i = 0;
    while i < CAPS.len() {
        v |= CAPS[i].hwcap2;
        i += 1;
    }
    v
}

/// The value of one ID register: the fixed part, plus each field the table
/// sets.
pub const fn id_reg(reg: IdReg) -> u64 {
    // ID_AA64PFR0_EL1: EL0 and EL1 implement AArch64 only.
    let mut v: u64 = match reg {
        Pfr0 => 0x11,
        _ => 0,
    };
    let mut shift = 0;
    while shift < 64 {
        let mut best = 0;
        let mut i = 0;
        while i < CAPS.len() {
            let mut j = 0;
            while j < CAPS[i].fields.len() {
                let Field(r, s, val) = CAPS[i].fields[j];
                if r as u32 == reg as u32 && s == shift && val > best {
                    best = val;
                }
                j += 1;
            }
            i += 1;
        }
        v |= best << shift;
        shift += 4;
    }
    v
}

/// The `Features` line of `/proc/cpuinfo`, without the label.
pub fn cpuinfo_features() -> String {
    let mut names: Vec<(u32, &str)> = CAPS
        .iter()
        .map(|c| {
            let key = if c.hwcap != 0 {
                c.hwcap.trailing_zeros()
            } else {
                64 + c.hwcap2.trailing_zeros()
            };
            (key, c.name)
        })
        .collect();
    names.sort_unstable();
    names.iter().map(|(_, n)| *n).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bit_belongs_to_one_entry() {
        let (mut a, mut b) = (0u64, 0u64);
        for c in CAPS {
            assert_eq!(a & c.hwcap, 0, "{}", c.name);
            assert_eq!(b & c.hwcap2, 0, "{}", c.name);
            assert_eq!(
                c.hwcap.count_ones() + c.hwcap2.count_ones(),
                1,
                "{}: exactly one bit",
                c.name
            );
            a |= c.hwcap;
            b |= c.hwcap2;
        }
        assert_eq!(a, hwcap());
        assert_eq!(b, hwcap2());
    }

    #[test]
    fn cpuinfo_lists_every_cap_once_in_bit_order() {
        let s = cpuinfo_features();
        assert_eq!(s.split(' ').count(), CAPS.len());
        assert!(s.starts_with("fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics"));
    }

    /// Two entries may give one field different values; the larger wins.
    #[test]
    fn a_field_takes_the_largest_value() {
        // The fixed part of PFR0 survives, and so does a plain field.
        assert_eq!(id_reg(Pfr0) & 0xff, 0x11);
        assert_eq!(id_reg(Isar0) & 0xf0, 0x20);
    }
}
