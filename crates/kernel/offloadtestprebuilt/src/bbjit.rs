//! The basic-block-JIT ceiling: a hot register loop, run entirely in host
//! registers.
//!
//! No per-instruction `gret`, no `regs[]` traffic, no decode — which is
//! what a basic-block JIT with register allocation would emit, except that here
//! the host compiler does the allocation. It measured **~7x, native speed** for
//! that loop, which is the number this PoC exists to record.
//!
//! The guest binary is a PIE, so its load base is a runtime value:
//! `IUL_BBJIT_BASE` names it and nothing is registered without it.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Cpu, Tlb};

/// Where the guest resumes: the instruction after the loop.
///
/// The prebuilt entry resumes at the link register, so the body has to point it
/// at the fall-through rather than at whatever called the function.
static FALLTHROUGH: AtomicU64 = AtomicU64::new(0);

pub(crate) fn set_fallthrough(pc: u64) {
    FALLTHROUGH.store(pc, Ordering::Relaxed);
}

/// # Safety
/// `cpu` is the running guest's; the TLB is not touched.
pub(crate) unsafe extern "C" fn loop_body(cpu: *mut Cpu, _tlb: *mut Tlb) {
    // SAFETY: the caller's contract.
    let regs = unsafe { &mut (*cpu).regs };
    let (mut x9, mut x10, mut x11) = (regs[9], regs[10], regs[11]);
    let (mut x12, mut x13, mut x14) = (regs[12], regs[13], regs[14]);

    loop {
        x10 = x10.wrapping_add(x11);
        x11 ^= x12;
        x12 = x12.wrapping_add(x13);
        x13 ^= x14;
        x14 = x14.wrapping_add(x10);
        x10 = x10.wrapping_mul(x11);
        x9 = x9.wrapping_sub(1);
        if x9 == 0 {
            break;
        }
    }

    regs[9] = x9;
    regs[10] = x10;
    regs[11] = x11;
    regs[12] = x12;
    regs[13] = x13;
    regs[14] = x14;
    regs[30] = FALLTHROUGH.load(Ordering::Relaxed);
}
