//! AUTO-GENERATED from guest `outer` — DO NOT EDIT.
//!
//! Source: `tests/offload/prebuilt/guest/target/aarch64-unknown-linux-musl/release/callbench`, symbol at 0x0000000000223e20, registered at 0x0000000000223e20.
//! Produced by `tools/prebuilt_gadget_gen/gen.sh`.
//!
//! It is a translation of **one build**: the addresses are absorbed by
//! [`base`], and the register allocation is not. Regenerate it when the
//! guest binary is rebuilt.
//!
//! # This one is kept as a check on the generator
//!
//! Nothing registers it; `tests/generated.rs` runs it against the hand-written
//! `callbench::outer`. It is the second of the pair because it exercises what
//! `mixgen` does not: guest memory through the TLB, a stack-pointer writeback,
//! and a `bl` through the inline cache.

use std::sync::atomic::AtomicU64;

use crate::spec::*;
use crate::{Cpu, Tlb};

/// The bias between the address this was disassembled at and the one it
/// loaded at. Set by the crate's `register`.
pub static BASE: Base = Base::new();

/// Where `outer` sat in the binary this was translated against.
pub const ANCHOR: u64 = 0x223e20;

#[inline]
pub fn base() -> u64 {
    BASE.get()
}

// One inline cache per call site. See `spec::call`.
static IC1: AtomicU64 = AtomicU64::new(0);

/// # Safety
/// `cpu` and `tlb` are the running guest's, and this is entered from
/// the interpreter in place of the guest's own `outer`.
#[allow(unused_variables, unused_mut, unused_assignments)]
pub unsafe extern "C" fn spec(cpu: *mut Cpu, tlb: *mut Tlb) {
    let r = Regs(cpu);
    let mut f = Flags::default();
    let mut fr = [0.0f64; 32];
    let mut label = 0usize;
    'body: loop {
        match label {
            0 => {
                if r.get(1) == 0 {
                    label = 2;
                    continue 'body;
                }
                r.set(32, add(r.get(32), 0xffffffffffffffe0u64));
                unsafe { st8(tlb, r.get(32), r.get(29)) };
                unsafe { st8(tlb, add(r.get(32), 8), r.get(30)) };
                unsafe { st8(tlb, add(r.get(32), 0x10u64), r.get(20)) };
                unsafe { st8(tlb, add(add(r.get(32), 0x10u64), 8), r.get(19)) };
                r.set(29, r.get(32));
                r.set(19, r.get(1));
                r.set(20, 0u64);
                label = 1;
            }
            1 => {
                r.set(8, r.get(20));
                r.set(20, add(r.get(20), 0x1u64));
                r.set(0, r.get(8) ^ (r.get(0)));
                r.set(30, base() + 0x223e48);
                unsafe { call(&IC1, cpu, tlb, base() + 0x223e04) };
                r.set(0, r.get(0) ^ (shr(r.get(0), 31)));
                f.cmp(r.get(19), r.get(20));
                if f.ne() {
                    label = 1;
                    continue 'body;
                }
                r.set(20, unsafe { ld8(tlb, add(r.get(32), 0x10u64)) });
                r.set(19, unsafe { ld8(tlb, add(add(r.get(32), 0x10u64), 8)) });
                r.set(29, unsafe { ld8(tlb, r.get(32)) });
                r.set(30, unsafe { ld8(tlb, add(r.get(32), 8)) });
                r.set(32, add(r.get(32), 0x20u64));
                label = 2;
            }
            2 => {
                return;
            }
            _ => return,
        }
    }
}
