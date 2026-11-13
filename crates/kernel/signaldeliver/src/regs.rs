//! CPU register state carried by an AArch64 signal frame.

use kernel_sigframe::Regs;

use crate::ffi;

use taskview::cpu::fp_sync_to_host;

/// Copy the subset of the CPU state that a signal frame carries.
///
/// The condition flags are read from `nzcv` alone: the JIT maintains it
/// directly and the four byte flags are stale.
///
/// A `&cpu_state`, sound since `_poked` is atomic; the caller is the thread
/// that runs it, so nothing else writes the rest.
pub(super) fn snapshot_regs(cpu: &ffi::cpu_state) -> Regs {
    let mut out = Regs {
        fault_address: cpu.segfault_addr,
        regs: cpu.regs,
        sp: cpu.sp,
        pc: cpu.pc,
        pstate: taskview::cpu::pstate(cpu),
        fpsr: cpu.fpsr,
        fpcr: cpu.fpcr,
        ..Regs::default()
    };
    for (v, reg) in out.vregs.iter_mut().zip(&cpu.fp) {
        *v = pack_vreg(reg.d);
    }
    out
}

/// Restore the registers carried by a signal frame.
///
/// No FPSIMD record means leave the floating-point state alone.
///
/// # Safety
/// `cpu` is live, and this is the host thread that runs it.
pub(super) unsafe fn restore_regs(cpu: *mut ffi::cpu_state, regs: &Regs, have_fpsimd: bool) {
    unsafe {
        (*cpu).regs = regs.regs;
        (*cpu).sp = regs.sp;
        (*cpu).pc = regs.pc;
        taskview::cpu::set_pstate(cpu, regs.pstate);
        if have_fpsimd {
            (*cpu).fpsr = regs.fpsr;
            (*cpu).fpcr = regs.fpcr;
            for (reg, v) in (*cpu).fp.iter_mut().zip(regs.vregs.iter()) {
                reg.d = unpack_vreg(*v);
            }
            fp_sync_to_host(&*cpu);
        }
    }
}

fn pack_vreg(d: [u64; 2]) -> u128 {
    u128::from(d[0]) | (u128::from(d[1]) << 64)
}

fn unpack_vreg(v: u128) -> [u64; 2] {
    [v as u64, (v >> 64) as u64]
}

#[cfg(test)]
mod tests {
    use super::*;
    use taskview::cpu::set_nzcv;

    #[test]
    fn set_nzcv_writes_both_places_and_masks_the_rest() {
        let mut cpu = ffi::cpu_state::default();
        unsafe { set_nzcv(&raw mut cpu, 0xa000_0f0f) };
        assert_eq!(cpu.nzcv, 0xa000_0000);
        assert_eq!((cpu.nf, cpu.zf, cpu.cf, cpu.vf), (1, 0, 1, 0));
    }

    #[test]
    fn a_frame_round_trips_through_the_cpu() {
        let mut cpu = ffi::cpu_state::default();
        let mut regs = Regs::default();
        for (i, r) in regs.regs.iter_mut().enumerate() {
            *r = 0x1000 + i as u64;
        }
        regs.sp = 0xffff_e000;
        regs.pc = 0x40_0000;
        regs.pstate = 0x6000_0000;
        regs.fpsr = 0x10;
        regs.fpcr = 0x0040_0000;
        for (i, v) in regs.vregs.iter_mut().enumerate() {
            *v = (i as u128) << 64 | 0xdead_beef;
        }
        unsafe { restore_regs(&raw mut cpu, &regs, true) };
        let back = snapshot_regs(&cpu);
        assert_eq!(back.fault_address, 0);
        assert_eq!(back.regs, regs.regs);
        assert_eq!(
            (back.sp, back.pc, back.pstate),
            (regs.sp, regs.pc, regs.pstate)
        );
        assert_eq!((back.fpsr, back.fpcr), (regs.fpsr, regs.fpcr));
        assert_eq!(back.vregs, regs.vregs);
    }

    /// DIT is bit 24 of the pstate a frame carries: a handler that changes it
    /// in the frame changes it for the interrupted code, and one that leaves it
    /// alone does not lose it.
    #[test]
    fn dit_travels_in_the_pstate_word() {
        let mut cpu = ffi::cpu_state::default();
        let mut regs = Regs {
            pstate: 0x6100_0000,
            ..Default::default()
        };
        unsafe { restore_regs(&raw mut cpu, &regs, false) };
        assert!(cpu.dit);
        assert_eq!(cpu.nzcv, 0x6000_0000);
        assert_eq!(snapshot_regs(&cpu).pstate, 0x6100_0000);
        regs.pstate = 0x6000_0000;
        unsafe { restore_regs(&raw mut cpu, &regs, false) };
        assert!(!cpu.dit);
    }

    #[test]
    fn a_frame_without_fpsimd_leaves_the_floating_point_state_alone() {
        let mut cpu = ffi::cpu_state {
            fpcr: 0x0100_0000,
            ..Default::default()
        };
        cpu.fp[3].d = [7, 8];
        unsafe { restore_regs(&raw mut cpu, &Regs::default(), false) };
        assert_eq!(cpu.fpcr, 0x0100_0000);
        assert_eq!(cpu.fp[3].d, [7, 8]);
    }

    #[test]
    fn a_vector_register_packs_little_endian() {
        assert_eq!(pack_vreg([1, 2]), 1 | (2u128 << 64));
        assert_eq!(unpack_vreg(pack_vreg([0xabc, 0xdef])), [0xabc, 0xdef]);
    }
}
