//! `mix` from `tests/offload/prebuilt/guest/src/bin/mixbench.rs`: a pure-compute
//! leaf with no stack frame, which is the shape this mechanism wins on.
//!
//! **2.66x** against threaded execution at 5,000,000 calls — see
//! `docs/changelog/2026-09-09-the-offload-fixtures-were-measuring-opt-level-zero.md`,
//! which also records what the mechanism costs on the shapes it loses on.
//!
//! # It is a translation of one build
//!
//! Written from the disassembly, register for register, so the guest's own
//! registers hold what its own code would have left in them. That makes it
//! specific to the binary in `tests/offload/prebuilt/guest`, and the
//! disassembly it was written from is quoted below so a rebuild that moves
//! something is something a reader can see.
//!
//! ```text
//! mix:
//!     mov  x8, #0x6575 / movk x8, #0x7073,lsl 16 / #0x6d65,lsl 32 / #0x736f,lsl 48
//!     eor  x0, x0, x8
//!     cbz  x1, ret
//!     mov  x9, #0x8ccd  / movk ... 0xed55,0xafd7,0xff51      ; MUL
//!     mov  x10, #0x7c15 / movk ... 0x7f4a,0x79b9,0x9e37      ; ADD
//!     mov  w8, #1
//! loop:
//!     eor  x11, x8, x0
//!     subs x1, x1, #1
//!     add  x8, x8, #1
//!     ror  x11, x11, #0x33
//!     madd x0, x11, x9, x10
//!     b.ne loop
//!     ret
//! ```

use crate::{Cpu, Tlb};

/// The three constants the guest assembles with `movk`, four 16-bit inserts
/// each.
const SEED: u64 = 0x736f_6d65_7073_6575;
const MUL: u64 = 0xff51_afd7_ed55_8ccd;
const ADD: u64 = 0x9e37_79b9_7f4a_7c15;

/// # Safety
/// `cpu` is the running guest's; the TLB is not touched, because `mix` has no
/// frame and never reaches memory. That is why it is the fast case.
pub unsafe extern "C" fn mix(cpu: *mut Cpu, _tlb: *mut Tlb) {
    // SAFETY: the caller's contract. Borrowed once: the pointer does not leave
    // this function and nothing else writes the struct while the guest thread
    // is inside it.
    let regs = unsafe { &mut (*cpu).regs };

    regs[8] = SEED;
    regs[0] ^= regs[8];
    if regs[1] == 0 {
        return;
    }
    regs[9] = MUL;
    regs[10] = ADD;
    // `mov w8, #1` is a 32-bit move, which zero-extends.
    regs[8] = 1;

    loop {
        regs[11] = regs[8] ^ regs[0];
        regs[1] = regs[1].wrapping_sub(1);
        regs[8] = regs[8].wrapping_add(1);
        regs[11] = regs[11].rotate_right(51);
        regs[0] = regs[11]
            .wrapping_mul(regs[9])
            .wrapping_add(regs[10]);
        if regs[1] == 0 {
            return;
        }
    }
}
