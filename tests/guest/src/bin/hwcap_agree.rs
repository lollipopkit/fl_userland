//! `AT_HWCAP`, `AT_HWCAP2`, the ID registers and `/proc/cpuinfo` say the same
//! thing.
//!
//! A guest may ask any of the three what the CPU can do, and each answer was
//! written separately: cpuinfo listed six features, the auxiliary vector eleven
//! and `ID_AA64ISAR1_EL1` none. The rules below are the Linux arm64 ABI
//! (`Documentation/arch/arm64/elf_hwcaps.rst`): a hwcap bit is set exactly when
//! its ID register field has at least the value that names the feature, and
//! `/proc/cpuinfo` prints its name. They hold on a real kernel, which is what
//! this program is also run on.

use guest_tests::insn::{State, run, setup};
use guest_tests::{Harness, check};
use std::arch::asm;

#[derive(Clone, Copy)]
enum Reg {
    Isar0,
    Isar1,
    Pfr0,
}

/// name, which auxiliary word (1 or 2), the bit in it, and the ID register
/// field that says the same.
type Rule = (&'static str, u32, u32, Option<(Reg, u32, u64)>);

use Reg::*;
const RULES: &[Rule] = &[
    ("fp", 1, 0, None),
    ("asimd", 1, 1, None),
    ("evtstrm", 1, 2, None),
    ("aes", 1, 3, Some((Isar0, 4, 1))),
    ("pmull", 1, 4, Some((Isar0, 4, 2))),
    ("sha1", 1, 5, Some((Isar0, 8, 1))),
    ("sha2", 1, 6, Some((Isar0, 12, 1))),
    ("crc32", 1, 7, Some((Isar0, 16, 1))),
    ("atomics", 1, 8, Some((Isar0, 20, 2))),
    ("fphp", 1, 9, Some((Pfr0, 16, 1))),
    ("asimdhp", 1, 10, Some((Pfr0, 20, 1))),
    ("cpuid", 1, 11, None),
    ("asimdrdm", 1, 12, Some((Isar0, 28, 1))),
    ("jscvt", 1, 13, Some((Isar1, 12, 1))),
    ("fcma", 1, 14, Some((Isar1, 16, 1))),
    ("lrcpc", 1, 15, Some((Isar1, 20, 1))),
    ("dcpop", 1, 16, Some((Isar1, 0, 1))),
    ("sha3", 1, 17, Some((Isar0, 32, 1))),
    ("sm3", 1, 18, Some((Isar0, 36, 1))),
    ("sm4", 1, 19, Some((Isar0, 40, 1))),
    ("asimddp", 1, 20, Some((Isar0, 44, 1))),
    ("sha512", 1, 21, Some((Isar0, 12, 2))),
    ("asimdfhm", 1, 23, Some((Isar0, 48, 1))),
    ("dit", 1, 24, Some((Pfr0, 48, 1))),
    ("ilrcpc", 1, 26, Some((Isar1, 20, 2))),
    ("flagm", 1, 27, Some((Isar0, 52, 1))),
    ("sb", 1, 29, Some((Isar1, 36, 1))),
    ("dcpodp", 2, 0, Some((Isar1, 0, 2))),
    ("flagm2", 2, 7, Some((Isar0, 52, 2))),
    ("frint", 2, 8, Some((Isar1, 32, 1))),
    ("i8mm", 2, 13, Some((Isar1, 52, 1))),
    ("bf16", 2, 14, Some((Isar1, 44, 1))),
];

fn id_reg(r: Reg) -> u64 {
    let v: u64;
    unsafe {
        match r {
            Isar0 => asm!("mrs {}, S3_0_C0_C6_0", out(reg) v),
            Isar1 => asm!("mrs {}, S3_0_C0_C6_1", out(reg) v),
            Pfr0 => asm!("mrs {}, S3_0_C0_C4_0", out(reg) v),
        }
    }
    v
}

fn main() {
    let mut h = Harness::new();
    let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) };
    let hwcap2 = unsafe { libc::getauxval(libc::AT_HWCAP2) };
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let features: Vec<&str> = cpuinfo
        .lines()
        .find(|l| l.starts_with("Features"))
        .and_then(|l| l.split(':').nth(1))
        .map(|l| l.split_whitespace().collect())
        .unwrap_or_default();
    println!("  hwcap {hwcap:#x} hwcap2 {hwcap2:#x}");
    println!("  features: {}", features.join(" "));

    h.group("hwcap-idreg-cpuinfo");
    check!(h, !features.is_empty(), "/proc/cpuinfo has a Features line");
    for &(name, word, bit, field) in RULES {
        let set = (if word == 1 { hwcap } else { hwcap2 }) >> bit & 1 != 0;
        let listed = features.contains(&name);
        check!(h, set == listed, "{name}: hwcap {set}, cpuinfo {listed}");
        if let Some((reg, shift, min)) = field {
            let value = id_reg(reg) >> shift & 0xf;
            check!(
                h,
                (value >= min) == set,
                "{name}: ID register field {value} (needs >= {min} for the bit), hwcap {set}"
            );
        }
    }

    // HWCAP_CPUID promises the ID registers read at EL0 instead of raising
    // SIGILL: Linux emulates MIDR_EL1, REVIDR_EL1 and the whole ID_AA64* block
    // (the ones with nothing to report read as zero).
    h.group("cpuid-registers-read-at-el0");
    unsafe { setup() };
    for (name, crm, op2) in [
        ("ID_AA64PFR0_EL1", 4, 0), ("ID_AA64PFR1_EL1", 4, 1), ("ID_AA64DFR0_EL1", 5, 0),
        ("ID_AA64DFR1_EL1", 5, 1), ("ID_AA64AFR0_EL1", 5, 4), ("ID_AA64AFR1_EL1", 5, 5),
        ("ID_AA64ISAR0_EL1", 6, 0), ("ID_AA64ISAR1_EL1", 6, 1), ("ID_AA64ISAR2_EL1", 6, 2),
        ("ID_AA64MMFR0_EL1", 7, 0), ("ID_AA64MMFR1_EL1", 7, 1), ("ID_AA64MMFR2_EL1", 7, 2),
    ] {
        // mrs x0, S3_0_C0_C<crm>_<op2>
        let insn = 0xd538_0000u32 | crm << 8 | op2 << 5;
        let (_, ill) = unsafe { run(insn, &State::zeroed()) };
        check!(h, !ill, "{name} reads");
    }
    for (name, insn) in [("MIDR_EL1", 0xd538_0000u32), ("REVIDR_EL1", 0xd538_00c0)] {
        let (_, ill) = unsafe { run(insn, &State::zeroed()) };
        check!(h, !ill, "{name} reads");
    }

    std::process::exit(h.finish());
}
