//! The two places the *hardware* has to be told what `struct cpu_state` says.
//!
//! # Why a view crate has two instructions in it
//!
//! This crate is otherwise field reads, and deliberately: it exists so that a
//! syscall family can see `struct task` without an accessor per field. These
//! two are here because they are the same thing one step further — a field of
//! `cpu_state` is not only read, it is *pushed to the register the guest
//! believes it set* — and because the alternative was three copies of four
//! lines each.
//!
//! There were three. `emu/arch/arm64/cpu.h`'s `cpu_fp_sync_to_host` and
//! `arm64_set_nzcv` are `static inline`, so a crate could not link to either;
//! `kernel/task.c` wrapped the first in `cpu_sync_fp_for_rs` and
//! `cpu_reset_fp_for_rs` for its two Rust callers, and
//! `crates/kernel/signaldeliver` and `crates/kernel/ptrace` each wrote the
//! second out again. Nothing compared them.
//!
//! `docs/remaining-c.md` named the pair as one of `kernel/task.c`'s "different
//! kinds of cannot" — *`task_set_current` and the two fp syncs are `static
//! inline`*. That was true of the C helper and not of the operation: two `msr`
//! instructions are two lines of `core::arch::asm!`, which
//! `crates/kernel/signaldeliver` had already written by 2026-09-05.

use crate::ffi;

/// Set the condition flags from a PSTATE word, in both of the places they are
/// kept: `nzcv` for the JIT and the four bytes for the gadgets. Writing one
/// without the other leaves the guest's condition state disagreeing with
/// itself.
///
/// **Masked to bits 31:28.** Only the four condition flags are modelled, so
/// everything else in PSTATE reads back as zero — and the alternative is worse
/// than lossy, it is inconsistent: `rt_sigreturn` used to store a guest's whole
/// pstate word and the next sync would drop the extra bits, so a guest saw them
/// appear and then vanish. All three copies that existed before this one masked
/// the same way -- masking before or after a `>> 31 & 1` is the same function,
/// so they could not have differed. The test below is what the mask did not
/// have.
///
/// # Safety
/// `cpu` is live and not running.
#[inline]
pub unsafe fn set_nzcv(cpu: *mut ffi::cpu_state, pstate: u32) {
    let nzcv = pstate & 0xf000_0000;
    unsafe {
        (*cpu).nzcv = nzcv;
        (*cpu).nf = ((nzcv >> 31) & 1) as u8;
        (*cpu).zf = ((nzcv >> 30) & 1) as u8;
        (*cpu).cf = ((nzcv >> 29) & 1) as u8;
        (*cpu).vf = ((nzcv >> 28) & 1) as u8;
    }
}

/// `PSTATE.DIT`, bit 24 of the pstate word.
pub const PSTATE_DIT: u64 = 1 << 24;

/// The PSTATE word a signal frame or `PTRACE_GETREGSET` reports: the condition
/// flags and DIT, the only two bits modelled.
///
/// A `&cpu_state` since 2026-10-16, when `_poked` -- the one byte another
/// thread writes -- became atomic and such a reference became sound.
#[inline]
pub fn pstate(cpu: &ffi::cpu_state) -> u64 {
    cpu.nzcv as u64 | if cpu.dit { PSTATE_DIT } else { 0 }
}

/// The inverse of [`pstate`]: the flags in both places (see [`set_nzcv`]) and
/// DIT. Every other bit is dropped, as it always was.
///
/// # Safety
/// `cpu` is live and not running.
#[inline]
pub unsafe fn set_pstate(cpu: *mut ffi::cpu_state, pstate: u64) {
    unsafe {
        set_nzcv(cpu, pstate as u32);
        (*cpu).dit = pstate & PSTATE_DIT != 0;
    }
}

/// Tell the host's floating-point control and status registers what the
/// guest's say.
///
/// The gadgets keep the two in step while guest code runs — `msr fpcr` writes
/// both — but a `sigreturn`, an `execve` and the start of a cloned thread all
/// change `cpu_state`'s copy from outside them, and the host has to be told:
/// the handler may have changed the rounding mode, and what the frame holds is
/// what the interrupted code was using.
///
/// The host registers were not written at all before this existed, so a guest's
/// `fesetround` was recorded, read back correctly by `fegetround`, and ignored
/// by every arithmetic instruction after it.
///
/// # The host runs with the guest's FPCR and FPSR
///
/// `fiber_enter` and `fiber_exit` do not switch them, so the engine's own code
/// runs under the guest's rounding mode, and any flag a host floating-point
/// operation raised would land in the guest's FPSR. That is a design premise,
/// not an oversight, and it holds because the engine does next to no floating
/// point on the syscall paths. Checked on 2026-09-30: with FPSR cleared,
/// `getpid`, `nanosleep`, reads of `/proc/uptime`, `/proc/loadavg` and
/// `/proc/stat`, a file write and a `readdir`, on realfs and fakefs, all left
/// it 0 as a real kernel does, and FPCR=RZ was unchanged across them. A
/// syscall path that starts doing float arithmetic has to save and restore
/// these, or it will leak flags into the guest.
///
/// Call it on the host thread that runs `cpu`: the registers written are the
/// calling thread's. That decides which guest is affected and touches no
/// memory, so it is not a safety condition.
#[inline]
pub fn fp_sync_to_host(cpu: &ffi::cpu_state) {
    let (fpcr, fpsr) = (cpu.fpcr as u64, cpu.fpsr as u64);
    // SAFETY: FPCR and FPSR are this thread's floating-point control and
    // status; writing them touches no memory.
    unsafe {
        core::arch::asm!("msr fpcr, {}", in(reg) fpcr, options(nomem, nostack));
        core::arch::asm!("msr fpsr, {}", in(reg) fpsr, options(nomem, nostack));
    }
}

/// What an `execve` does: the default rounding mode, in `cpu_state` *and* in
/// the hardware.
///
/// One function because it is one rule. It was `cpu_reset_fp_for_rs` in
/// `kernel/task.c`, whose whole content was these three lines.
///
/// # Safety
/// As [`fp_sync_to_host`].
pub unsafe fn fp_reset(cpu: *mut ffi::cpu_state) {
    unsafe {
        (*cpu).fpcr = 0;
        (*cpu).fpsr = 0;
        fp_sync_to_host(&*cpu);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mask, which is the whole content of `set_nzcv` and was written out
    /// three times before this crate had it once.
    #[test]
    fn only_the_four_condition_flags_survive_a_pstate_word() {
        let mut cpu = ffi::cpu_state::default();
        // Every bit set: the four flags and everything this kernel does not
        // model.
        unsafe { set_nzcv(&raw mut cpu, 0xffff_ffff) };
        assert_eq!(cpu.nzcv, 0xf000_0000, "only 31:28 are kept");
        assert_eq!((cpu.nf, cpu.zf, cpu.cf, cpu.vf), (1, 1, 1, 1));

        // And the byte flags follow the word rather than the argument, which is
        // what stops the two disagreeing.
        unsafe { set_nzcv(&raw mut cpu, 0x4000_0000) };
        assert_eq!(cpu.nzcv, 0x4000_0000);
        assert_eq!((cpu.nf, cpu.zf, cpu.cf, cpu.vf), (0, 1, 0, 0));
    }
}
