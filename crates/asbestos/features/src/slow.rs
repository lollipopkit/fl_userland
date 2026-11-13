//! The instructions here that run as `slow_call`s.
//!
//! Until 2026-10-17 each was a gadget in `features.S` that read the host FPCR,
//! called an `extern "C"` helper with pointers into the register file, and ORed
//! the flags it returned into the host FPSR. FPCR is `cpu_state`'s now -- the
//! host's is kept equal to it (`kernel/taskview`'s `fp_sync_to_host`), and the
//! stored copy is the one with the guest's FZ16 -- and the flags are raised
//! here.

use emu_abi::{SLOW_OK, cpu_state, tlb};
use std::ffi::c_int;

/// OR `flags` into the host FPSR, which is the guest's while it runs.
fn raise(flags: u8) {
    if flags != 0 {
        // SAFETY: FPSR is this thread's floating-point status; writing it
        // touches no memory.
        unsafe {
            core::arch::asm!(
                "mrs {t}, fpsr", "orr {t}, {t}, {f}", "msr fpsr, {t}",
                t = out(reg) _, f = in(reg) u64::from(flags), options(nomem, nostack),
            )
        };
    }
}

/// The register file as these modules take it.
///
/// # Safety
/// `cpu` is live and nothing else holds a reference to its vector registers.
unsafe fn fp<'a>(cpu: *mut cpu_state) -> &'a mut [[u64; 2]; 32] {
    // SAFETY: the caller's contract; a vector register is sixteen bytes.
    unsafe { &mut *(&raw mut (*cpu).fp).cast() }
}

macro_rules! slow {
    ($($(#[$m:meta])* fn $name:ident($cpu:ident, $arg:ident) $body:block)*) => {$(
        $(#[$m])*
        ///
        /// # Safety
        /// The `slow_call` gadget's: `cpu` is the running frame's, and nothing
        /// else holds a reference into it.
        pub unsafe extern "C" fn $name($cpu: *mut cpu_state, _tlb: *mut tlb, _addr: u64, $arg: u64) -> c_int {
            $body
            SLOW_OK
        }
    )*};
}

slow! {
    /// `FJCVTZS Wd, Dn`: operand the instruction word.
    fn slow_fjcvtzs(cpu, arg) {
        let (rd, rn) = (arg as usize & 0x1f, (arg >> 5) as usize & 0x1f);
        // SAFETY: the caller's contract; each field is borrowed alone.
        let (fp, x, nzcv, fpcr) = unsafe { (fp(cpu), &mut (*cpu).regs, &mut (*cpu).nzcv, (*cpu).fpcr) };
        let c = crate::jscvt::fjcvtzs(fp[rn][0], u64::from(fpcr));
        if rd != 31 {
            x[rd] = u64::from(c.result);
        }
        // Z from the conversion; N, C and V clear.
        *nzcv = u32::from(c.z) << 30;
        raise(c.flags);
    }

    /// `FRINT32Z/X`, `FRINT64Z/X`: operand `insn | mode << 32`, the mode
    /// [`crate::frint::frintts`]'s.
    fn slow_frintts(cpu, arg) {
        let (rd, rn) = (arg as usize & 0x1f, (arg >> 5) as usize & 0x1f);
        // SAFETY: the caller's contract.
        let (fp, fpcr) = unsafe { (fp(cpu), (*cpu).fpcr) };
        let (out, flags) = crate::frint::frintts(fp[rn], u64::from(fpcr), arg >> 32);
        fp[rd] = out;
        raise(flags);
    }

    /// The BF16 group: operand [`crate::bf16::pack`]'s.
    fn slow_bf16(cpu, arg) {
        let Some(op) = crate::bf16::OPS.get((arg >> 32) as usize).copied() else {
            return SLOW_OK;
        };
        // SAFETY: the caller's contract.
        let (fp, fpcr) = unsafe { (fp(cpu), (*cpu).fpcr) };
        raise(crate::bf16::execute(op, arg as u32, fp, u64::from(fpcr)));
    }

    /// Half-precision arithmetic: operand the instruction word.
    fn slow_fp16(cpu, arg) {
        use crate::fp16::{Decoded, Regs, decode, execute};
        let Decoded::Mine(i) = decode(arg as u32) else {
            return SLOW_OK;
        };
        // SAFETY: the caller's contract; each field is borrowed alone.
        let (fp, x, nzcv, fpcr) = unsafe { (fp(cpu), &mut (*cpu).regs, &mut (*cpu).nzcv, (*cpu).fpcr) };
        raise(execute(&i, &mut Regs { fp, x, nzcv }, u64::from(fpcr)));
    }
}
