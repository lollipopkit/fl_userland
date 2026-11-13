//! System instructions: the hints, the barriers, cache maintenance and the
//! system registers.
//!
//! These are classified with the branches — `arm64_classify_insn` puts
//! `0b1010`/`0b1011` in one bucket and separates them by their fixed bits — so
//! they arrive through the same entry point and are a module of their own
//! because they are a different subject.
//!
//! # The three that do something
//!
//! Most of what is here is architecturally a no-op in an emulator whose memory
//! is the host's. Three are not:
//!
//! - **`IC IVAU`**, which is the guest saying "I rewrote the code at this
//!   address". It must not be a no-op: the interpreter otherwise only notices
//!   a code change through a write-TLB miss, so a store through an
//!   already-writable entry leaves the translated block stale. JavaScriptCore
//!   repatches its JIT code in place and issues `DC CVAU` + `IC IVAU` per
//!   cache line; treating this as nothing left the pre-patch translation
//!   running.
//! - **The barriers**, because guest threads are real host threads sharing
//!   real memory, so a guest barrier has to be a host barrier.
//! - **`CLREX`**, which clears the exclusive monitor. It was a no-op until
//!   2026-09-02 on the grounds that `STXR` clears it anyway — true, and not
//!   the same thing, because the point of `CLREX` is to make a *later* `STXR`
//!   fail.
//!
//! # The registers
//!
//! `MRS` of an EL0-readable register is how a program asks what machine it is
//! on, and two of the answers are load-bearing rather than informational —
//! `CTR_EL0`'s cache line sizes drive every JIT's publish loop, and
//! `DCZID_EL0`'s block size drives `memset`. `tests/guest/src/bin/sysreg_probe.rs`
//! compares every one of them against a real CPU.

use crate::features::gadget_mrs_const;
use crate::gadgets::*;
use crate::{BLOCK_ENDS, DECODED, Gen};
use std::ffi::c_int;

/// The registers `gadget_mrs_sysreg` in `math.S` reads when the instruction
/// runs, as its code stream spells them. A contract with its branch chain, so
/// written here rather than derived.
mod id {
    pub const FPCR: u64 = 0;
    pub const FPSR: u64 = 1;
    pub const CNTVCT_EL0: u64 = 2;
    pub const CNTFRQ_EL0: u64 = 3;
}

/// What a readable `MRS` reads.
#[derive(Debug, PartialEq)]
enum Read {
    /// A value fixed for the life of the process, emitted into the block.
    Const(u64),
    /// One of [`id`], read when the instruction runs.
    Live(u64),
}

/// Cache Type Register.
///
/// - bit 31: RES1.
/// - DIC (29) = 0: instruction cache invalidation to PoU **is** required. The
///   one load-bearing field: `IC IVAU` is how the interpreter learns a guest
///   JIT rewrote its code, so telling a guest it may skip the loop would break
///   self-modifying code (`tests/guest/src/bin/self_modifying.rs`).
/// - IDC (28) = 1: data cache clean to PoU is not required; there is no
///   separate data cache for `DC CVAU` to clean.
/// - CWG 27:24 = 4, ERG 23:20 = 4, DminLine 19:16 = 4 (64 bytes each).
/// - L1Ip 15:14 = 3 (PIPT), IminLine 3:0 = 4.
///
/// The gadget's comment once said "L1Ip[31:28]" and built the constant from
/// that, which put 8 where RES1 and DIC/IDC belong and read L1Ip as VIPT. This
/// is what a real arm64 CPU reports for the same geometry, checked by
/// `tests/guest/src/bin/sysreg_probe.rs` against the hardware.
const CTR_EL0: u64 = 0x9444_c004;
/// `DC ZVA` prohibited (DZP, bit 4), block size 4 (64 bytes).
const DCZID_EL0: u64 = 0x14;
/// Implementer 0x41 (ARM), architecture 0xf, part number **0**, revision 0. A
/// real part number would put this on an errata list for a bug this
/// interpreter does not have; an unknown part matches none.
const MIDR_EL1: u64 = 0x410f_0000;
/// Bit 31 is RES1 and every affinity field is zero.
const MPIDR_EL1: u64 = 0x8000_0000;

/// The five fields that name a system register, in the order the ARM ARM
/// writes them.
fn sysreg_fields(insn: u32) -> (u32, u32, u32, u32, u32) {
    (
        (insn >> 19) & 0x3, // op0
        (insn >> 16) & 0x7, // op1
        (insn >> 12) & 0xf, // CRn
        (insn >> 8) & 0xf,  // CRm
        (insn >> 5) & 0x7,  // op2
    )
}

/// The feature ID registers, whose value is the table `AT_HWCAP` is built
/// from (`asbestos_features::caps`), so that a guest reading either is told the
/// same thing.
///
fn feature_register(insn: u32) -> Option<u64> {
    use asbestos_features::caps::{IdReg, id_reg};
    Some(match sysreg_fields(insn) {
        (3, 0, 0, 4, 0) => id_reg(IdReg::Pfr0),
        (3, 0, 0, 4, 1) => id_reg(IdReg::Pfr1),
        (3, 0, 0, 6, 0) => id_reg(IdReg::Isar0),
        (3, 0, 0, 6, 1) => id_reg(IdReg::Isar1),
        _ => return None,
    })
}

/// What a readable `MRS` reads, or `None` for a register this does not
/// answer — which is an illegal instruction, and is what a guest gets for
/// asking about a feature that is not modelled.
fn readable(insn: u32) -> Option<Read> {
    use Read::{Const, Live};
    Some(match sysreg_fields(insn) {
        (3, 3, 0, 0, 1) => Const(CTR_EL0),
        (3, 3, 0, 0, 7) => Const(DCZID_EL0),
        (3, 3, 4, 4, 0) => Live(id::FPCR),
        (3, 3, 4, 4, 1) => Live(id::FPSR),
        // RNDR and RNDRRS are not here: FEAT_RNG is not advertised
        // (ID_AA64ISAR0's RNDR field is 0, no HWCAP2_RNG), and on a CPU
        // without it a read is an illegal instruction -- which is what a real
        // arm64 kernel gives (`tests/guest` rndr_undefined). They answered
        // "no random number" until 2026-10-18.
        // ID_AA64ZFR0_EL1: no SVE.
        (3, 0, 0, 4, 4) => Const(0),
        (3, 3, 14, 0, 2) => Live(id::CNTVCT_EL0),
        (3, 3, 14, 0, 0) => Live(id::CNTFRQ_EL0),
        // The three Linux traps and emulates for EL0. They had no arm at all
        // until 2026-09-02, so a guest reading one died — and a library
        // identifying the core to pick a `memcpy` variant does read them.
        (3, 0, 0, 0, 0) => Const(MIDR_EL1),
        (3, 0, 0, 0, 5) => Const(MPIDR_EL1),
        // Read-only at EL0 and left at zero by Linux on aarch64, which is why
        // there is no `MSR` arm below: writing it has to stay the illegal
        // instruction it is on real hardware.
        (3, 3, 13, 0, 3) => Const(0),
        _ => return None,
    })
}

/// Whether an unmodelled register is one Linux answers **zero** for rather than
/// trapping.
///
/// The ID block — `op0 = 3, op1 = 0, CRn = 0` — is emulated for EL0 in its
/// entirety, and that is the point of it: the architecture's forward
/// compatibility rule is that a register naming a feature the CPU lacks reads as
/// zero, so software can ask about a feature that did not exist when it was
/// written and get "no". Linux fills in a sanitised value for the registers a
/// CPU has and zero for the rest.
///
/// Answering `SIGILL` instead breaks exactly the software the scheme is for: a
/// library probing `ID_AA64ISAR2_EL1` for a newer extension died rather than
/// being told the extension is absent. **44 encodings**, swept against a real
/// kernel by `tests/guest/src/bin/decode_probe.rs`.
///
/// Zero is also the *right* value here rather than a placeholder: this
/// interpreter does not implement the features those registers describe, and the
/// five it does implement have arms of their own above.
///
/// The measured extent is `CRm` 2 to 7, plus `REVIDR_EL1` at `CRm = 0,
/// op2 = 6` — an implementation-defined revision id whose zero means "nothing
/// further to say". `CRm = 1` is the AArch32 block and traps on both sides;
/// `CRm >= 8` is not allocated.
fn reads_as_zero(insn: u32) -> bool {
    match sysreg_fields(insn) {
        (3, 0, 0, crm, _) if (2..=7).contains(&crm) => true,
        (3, 0, 0, 0, 6) => true,
        _ => false,
    }
}

pub fn decode(g: &mut Gen, insn: u32) -> c_int {
    // The hint space. **Everything unallocated in it is a no-op**, which is
    // not a convenience: `-mbranch-protection=standard` is the default in
    // Debian, Ubuntu and Fedora's toolchains, so `paciasp`/`autiasp` are in
    // every function's prologue and epilogue and `bti c` at the top of every
    // one. Treating an unknown hint as undefined cannot run those binaries.
    if insn & 0xffff_f01f == 0xd503_201f {
        return DECODED;
    }

    // The barrier space, `1101 0101 0000 0011 0011 CRm op2 11111`, decoded by
    // `op2` rather than by three masks that named three of the six values it
    // has. `decode_probe` swept it and found the other two.
    //
    // Guest threads are host threads sharing host memory, so a guest barrier
    // must issue a real one.
    if insn & 0xffff_f01f == 0xd503_301f {
        let crm = (insn >> 8) & 0xf;
        let op2 = (insn >> 5) & 0x7;
        match op2 {
            // `CLREX`. See the module comment: not a no-op.
            2 => {
                g.gadget(gadget_clrex);
                return DECODED;
            }
            // `DSB`, `DMB`, `ISB`, at any domain and ordering.
            4..=6 => {
                g.gadget(gadget_dmb);
                return DECODED;
            }
            // `DSB nXS` (FEAT_XS), which is a `DSB` over a subset of what an
            // ordinary one covers — so issuing the full barrier is stronger
            // than asked for and correct. `CRm` names the domain and its low
            // two bits are `10` for all four allocated values.
            1 if crm & 3 == 2 => {
                g.gadget(gadget_dmb);
                return DECODED;
            }
            // `SB` (FEAT_SB), the speculation barrier. `features.rs` decodes it
            // first, as a real one (`dsb sy; isb`), and advertises it; this arm
            // is what it falls back to only if that decoder is not asked.
            7 if crm == 0 => {
                g.gadget(gadget_dmb);
                return DECODED;
            }
            _ => return g.undefined(),
        }
    }

    // `IC IVAU`: the guest telling the interpreter it rewrote code here.
    if insn & 0xffff_ffe0 == 0xd50b_7520 {
        g.slow_call(emu_tlb::access::slow_ic_ivau, (insn & 0x1f) as u64);
        return DECODED;
    }

    // The data-cache maintenance operations, which *are* no-ops: host memory
    // is coherent, and only the instruction side needs anything, which
    // `IC IVAU` above is.
    if insn & 0xffff_ffe0 == 0xd50b_7e20   // DC CIVAC
        || insn & 0xffff_ffe0 == 0xd50b_7b20 // DC CVAU
        || insn & 0xffff_ffe0 == 0xd50b_7a20
    // DC CVAC
    {
        return DECODED;
    }

    let rt = (insn & 0x1f) as u64;

    // The registers with a gadget of their own, because each is a field of
    // `struct cpu_state` rather than a value to look up.
    let direct: &[(u32, Gadget)] = &[
        (0xd53b_4200, gadget_mrs_nzcv),
        (0xd51b_4200, gadget_msr_nzcv),
        (0xd51b_4400, gadget_msr_fpcr),
        (0xd51b_4420, gadget_msr_fpsr),
        // `MSR DAIF` masks interrupts, which there are none of here. The Go
        // runtime writes it for async preemption control, so it has to decode.
        (0xd51b_4220, gadget_msr_daif),
        (0xd51b_d040, gadget_msr_tpidr),
        (0xd53b_d040, gadget_mrs_tpidr),
    ];
    for &(pattern, gadget) in direct {
        if insn & 0xffff_ffe0 == pattern {
            g.gadget(gadget);
            g.emit(rt);
            return DECODED;
        }
    }

    // Everything else readable goes through one gadget with a register id.
    if insn & 0xfff0_0000 == 0xd530_0000 {
        if let Some(value) = feature_register(insn) {
            g.gadget(gadget_mrs_const);
            g.emit(rt);
            g.emit(value);
            return DECODED;
        }
        match readable(insn) {
            Some(Read::Const(value)) => {
                g.gadget(gadget_mrs_const);
                g.emit(rt);
                g.emit(value);
                return DECODED;
            }
            Some(Read::Live(which)) => {
                g.gadget(gadget_mrs_sysreg);
                g.emit(rt);
                g.emit(which);
                return DECODED;
            }
            None => {}
        }
        // And the rest of the ID block reads as zero rather than trapping; see
        // `reads_as_zero`. `MOVZ` of nothing is the whole implementation, which
        // is why this needs no gadget or register id of its own.
        if reads_as_zero(insn) {
            g.gadget(gadget_movz);
            g.emit(rt | (1 << 32));
            return DECODED;
        }
    }

    g.interrupt(crate::int::UNDEFINED);
    BLOCK_ENDS
}

use crate::Gadget;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Decoder;

    /// The three registers that had no arm before 2026-09-02, by their
    /// encodings rather than by name — which is the form a guest executes.
    #[test]
    fn the_registers_linux_emulates_for_el0_are_answered() {
        // MRS Xt, MIDR_EL1 is 0xd5380000 | Rt.
        assert_eq!(readable(0xd538_0000), Some(Read::Const(MIDR_EL1)));
        // MPIDR_EL1: op2 = 5.
        assert_eq!(readable(0xd538_00a0), Some(Read::Const(MPIDR_EL1)));
        // TPIDRRO_EL0: op0=3, op1=3, CRn=13, CRm=0, op2=3.
        assert_eq!(readable(0xd53b_d060), Some(Read::Const(0)));
    }

    /// `TPIDR_EL0` and `TPIDRRO_EL0` are one `op2` apart, and one is writable
    /// and the other is not. Reading the field loosely would make `msr
    /// tpidrro_el0` succeed, which a guest cannot do on real hardware.
    #[test]
    fn the_two_thread_pointers_are_told_apart_by_one_field() {
        assert_eq!(sysreg_fields(0xd53b_d040), (3, 3, 13, 0, 2), "TPIDR_EL0");
        assert_eq!(sysreg_fields(0xd53b_d060), (3, 3, 13, 0, 3), "TPIDRRO_EL0");
        // The writable one is not in `readable`: it has its own gadget pair,
        // and the read-only one has no MSR arm at all.
        assert_eq!(readable(0xd53b_d040), None);
    }

    /// A register nothing models is an illegal instruction, not a zero. A
    /// program probing for a feature has to be able to tell "not here" from
    /// "here and empty".
    #[test]
    fn an_unmodelled_register_is_refused() {
        // ID_AA64MMFR0_EL1: op0=3, op1=0, CRn=0, CRm=7, op2=0.
        assert_eq!(readable(0xd538_0700), None);
        // An op1 no EL0-readable register uses.
        assert_eq!(readable(0xd534_0000), None);
    }

    /// Every id is distinct, because they index a branch chain in the gadget
    /// and two names on one number would be one register answering for both.
    #[test]
    fn the_register_ids_are_distinct() {
        let all = [id::FPCR, id::FPSR, id::CNTVCT_EL0, id::CNTFRQ_EL0];
        let mut seen: Vec<u64> = all.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), all.len());
    }

    /// The barrier space has six allocated `op2` values and three were
    /// decoded. `decode_probe` swept it: `SB` and `DSB nXS` answered `SIGILL`
    /// where a real kernel runs them.
    #[test]
    fn every_barrier_that_exists_is_decoded() {
        let mut d = Decoder::new();
        let bar = |crm: u32, op2: u32| 0xd503_301f | (crm << 8) | (op2 << 5);
        // CLREX, DSB, DMB, ISB, at every CRm -- CRm is the domain, not part of
        // the selection.
        for op2 in [2u32, 4, 5, 6] {
            for crm in 0..16u32 {
                assert!(d.decodes(decode, bar(crm, op2)), "op2 {op2} CRm {crm}");
            }
        }
        // `SB` is CRm 0 only.
        assert!(d.decodes(decode, bar(0, 7)), "SB");
        for crm in 1..16u32 {
            assert!(
                !d.decodes(decode, bar(crm, 7)),
                "op2 7 CRm {crm} names nothing"
            );
        }
        // `DSB nXS` is the four domains whose CRm ends in 10.
        for crm in 0..16u32 {
            assert_eq!(
                d.decodes(decode, bar(crm, 1)),
                crm & 3 == 2,
                "DSB nXS CRm {crm}"
            );
        }
        // And the two `op2` values that name nothing at all.
        for op2 in [0u32, 3] {
            for crm in 0..16u32 {
                assert!(!d.decodes(decode, bar(crm, op2)), "op2 {op2} CRm {crm}");
            }
        }
    }

    /// The ID block reads as zero rather than trapping, and the value matters as
    /// much as the fact: zero is the architecture's "this feature is absent",
    /// which is true of every extension this interpreter does not implement.
    ///
    /// Checked by looking at what was emitted, because "it decoded" is what
    /// `decode_probe` already establishes and is not the same claim.
    #[test]
    fn the_unmodelled_id_registers_read_as_zero() {
        let mrs = |op1: u32, crn: u32, crm: u32, op2: u32| {
            0xd530_0000 | (3 << 19) | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5) | 7
        };
        // `CRm` 2 to 7 of the ID block, and `REVIDR_EL1`.
        for crm in 2..8u32 {
            for op2 in 0..8u32 {
                assert!(reads_as_zero(mrs(0, 0, crm, op2)), "CRm {crm} op2 {op2}");
            }
        }
        assert!(reads_as_zero(mrs(0, 0, 0, 6)), "REVIDR_EL1");
        // And what is outside it still traps: the AArch32 block, the
        // unallocated `CRm`s above 7, and anything with another `op1` or `CRn`.
        for op2 in 0..8u32 {
            assert!(!reads_as_zero(mrs(0, 0, 1, op2)), "the AArch32 block");
        }
        for crm in 8..16u32 {
            assert!(!reads_as_zero(mrs(0, 0, crm, 0)), "CRm {crm}");
        }
        assert!(!reads_as_zero(mrs(3, 0, 4, 0)), "another op1");
        assert!(!reads_as_zero(mrs(0, 1, 4, 0)), "another CRn");

        // And the decoder emits a `MOVZ` of nothing for one, into the register
        // the instruction names.
        let mut d = Decoder::new();
        assert!(
            d.decodes(decode, mrs(0, 0, 6, 2)),
            "ID_AA64ISAR2_EL1 decodes"
        );
        let (gadget, operand) = d.last_pair();
        assert_eq!(gadget, gadget_movz as *const () as usize as u64);
        assert_eq!(operand & 0x1f, 7, "into the register MRS names");
        assert_eq!((operand >> 16) & 0xffff, 0, "and the immediate is zero");
    }
}
