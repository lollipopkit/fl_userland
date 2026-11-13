//! `outer` and `inner` from
//! `tests/offload/prebuilt/guest/src/bin/callbench.rs`: a leaf, and a caller
//! with a stack frame that calls it in a tight loop.
//!
//! The shape the mechanism does **worst** on, and the one that separates its
//! three costs. At 500,000 calls of `outer(i, 16)`, every run bit-identical:
//! threaded 104 ms, `inner` alone 129, `outer` + `inner` 196, and `outer` with
//! the `bl` going through the interpreter 553.
//!
//! The disassembly both bodies were written from, so a rebuild that moves
//! something is visible:
//!
//! ```text
//! inner:
//!     mov  x8, #0x7c15 / movk ... 0x7f4a,0x79b9,0x9e37
//!     mov  w9, #0x1234
//!     madd x0, x0, x8, x9
//!     ret
//!
//! outer:
//!     cbz  x1, ret                       ; nothing saved on this path
//!     stp  x29, x30, [sp, #-0x20]!
//!     stp  x20, x19, [sp, #0x10]
//!     mov  x29, sp
//!     mov  x19, x1
//!     mov  x20, xzr
//! loop:
//!     mov  x8, x20
//!     add  x20, x20, #1
//!     eor  x0, x8, x0
//!     bl   inner                         ; lr = the instruction after it
//!     eor  x0, x0, x0, lsr #31
//!     cmp  x19, x20
//!     b.ne loop
//!     ldp  x20, x19, [sp, #0x10]
//!     ldp  x29, x30, [sp], #0x20
//!     ret
//! ```

use std::sync::atomic::AtomicU64;

use crate::{Cpu, Tlb, base, call, ld, st};

/// `inner`'s two constants.
const MUL: u64 = 0x9e37_79b9_7f4a_7c15;
const ADD: u64 = 0x1234;

/// Offsets inside the binary this was translated against. [`base`] is the bias
/// to where it actually loaded.
const INNER: u64 = 0x223e04;
const OUTER: u64 = 0x223e20;
/// The instruction after `outer`'s `bl`, which is what the callee sees in `lr`.
const RETURN_ADDR: u64 = 0x223e48;

/// # Safety
/// `cpu` is the running guest's; the TLB is not touched.
pub unsafe extern "C" fn inner(cpu: *mut Cpu, _tlb: *mut Tlb) {
    // SAFETY: the caller's contract. The registers only: `cpu_state` has a
    // byte another thread stores to, which a `&mut` of the whole would cover.
    let regs = unsafe { &mut (*cpu).regs };
    regs[8] = MUL;
    regs[9] = ADD;
    regs[0] = regs[0]
        .wrapping_mul(regs[8])
        .wrapping_add(regs[9]);
}

/// The one call site's inline cache. See [`crate::call`].
static IC: AtomicU64 = AtomicU64::new(0);

/// # Safety
/// `cpu` and `tlb` are the running guest's, and this is entered from the
/// interpreter in place of the guest's own `outer`.
pub unsafe extern "C" fn outer(cpu: *mut Cpu, tlb: *mut Tlb) {
    // Raw throughout rather than a borrow at the top, and deliberately: `call`
    // hands `cpu` to the callee, which may be the interpreter running guest
    // code that writes the same struct. A `&mut` held across that is the
    // aliasing UB `docs/changelog/2026-08-31-a-release-build-hung-closing-a-descriptor.md`
    // records. `inner` and the two other fixtures borrow, because nothing in
    // them lets the pointer out.
    //
    // SAFETY: the caller's contract.
    unsafe {
        if (*cpu).regs[1] == 0 {
            return;
        }
        // The guest's own prologue. A spec_fn reaches guest memory through the
        // TLB rather than the host's address space -- which is what makes it
        // fork- and copy-on-write-safe -- so these four saves are four calls,
        // and the epilogue four more. That is the 1.9x.
        (*cpu).sp = (*cpu).sp.wrapping_sub(0x20);
        let sp = (*cpu).sp;
        st(tlb, sp, (*cpu).regs[29]);
        st(tlb, sp + 8, (*cpu).regs[30]);
        st(tlb, sp + 0x10, (*cpu).regs[20]);
        st(tlb, sp + 0x18, (*cpu).regs[19]);
        (*cpu).regs[29] = sp;
        (*cpu).regs[19] = (*cpu).regs[1];
        (*cpu).regs[20] = 0;

        loop {
            (*cpu).regs[8] = (*cpu).regs[20];
            (*cpu).regs[20] = (*cpu).regs[20].wrapping_add(1);
            (*cpu).regs[0] ^= (*cpu).regs[8];
            (*cpu).regs[30] = base() + RETURN_ADDR;
            call(&IC, cpu, tlb, base() + INNER);
            (*cpu).regs[0] ^= (*cpu).regs[0] >> 31;
            if (*cpu).regs[19] == (*cpu).regs[20] {
                break;
            }
        }

        (*cpu).regs[20] = ld(tlb, sp + 0x10);
        (*cpu).regs[19] = ld(tlb, sp + 0x18);
        (*cpu).regs[29] = ld(tlb, sp);
        (*cpu).regs[30] = ld(tlb, sp + 8);
        (*cpu).sp = sp + 0x20;
    }
}

/// The address `outer` was translated at, which is what [`crate::register`]
/// takes the bias from.
pub(crate) const OUTER_ANCHOR: u64 = OUTER;
/// And `inner`'s, for the fallback when the environment names neither.
pub(crate) const INNER_ANCHOR: u64 = INNER;
