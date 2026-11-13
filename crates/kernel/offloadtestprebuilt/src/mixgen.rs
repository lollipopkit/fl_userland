//! AUTO-GENERATED from guest `mix` — DO NOT EDIT.
//!
//! Source: `tests/offload/prebuilt/guest/target/aarch64-unknown-linux-musl/release/mixbench`, symbol at 0x0000000000223dc4, registered at 0x0000000000223dc4.
//! Produced by `tools/prebuilt_gadget_gen/gen.sh`.
//!
//! It is a translation of **one build**: the addresses are absorbed by
//! [`base`], and the register allocation is not. Regenerate it when the
//! guest binary is rebuilt.
//!
//! # This one is kept as a check on the generator
//!
//! Nothing registers it. `tests/generated.rs` runs it and the hand-written
//! `mixbench::mix` over the same inputs and requires the whole `cpu_state` to
//! match — which is what says `tools/prebuilt_gadget_gen` still produces a
//! correct spec_fn, and is the only test that tool has ever had.
//!
//! Regenerate with:
//!
//! ```text
//! ( cd tests/offload/prebuilt/guest && cargo build --release --target aarch64-unknown-linux-musl )
//! tools/prebuilt_gadget_gen/gen.sh \
//!     tests/offload/prebuilt/guest/target/aarch64-unknown-linux-musl/release/mixbench mix
//! mv crates/kernel/offloadtestprebuilt/src/mix.rs crates/kernel/offloadtestprebuilt/src/mixgen.rs
//! ```

use crate::spec::*;
use crate::{Cpu, Tlb};

/// The bias between the address this was disassembled at and the one it
/// loaded at. Set by the crate's `register`.
pub static BASE: Base = Base::new();

/// Where `mix` sat in the binary this was translated against.
pub const ANCHOR: u64 = 0x223dc4;

#[inline]
pub fn base() -> u64 {
    BASE.get()
}

/// # Safety
/// `cpu` and `tlb` are the running guest's, and this is entered from
/// the interpreter in place of the guest's own `mix`.
#[allow(unused_variables, unused_mut, unused_assignments)]
pub unsafe extern "C" fn spec(cpu: *mut Cpu, tlb: *mut Tlb) {
    let r = Regs(cpu);
    let mut f = Flags::default();
    let mut fr = [0.0f64; 32];
    let mut label = 0usize;
    'body: loop {
        match label {
            0 => {
                r.set(8, 0x6575u64);
                r.set(8, (r.get(8) & 0xffffffff0000ffffu64) | 0x70730000u64);
                r.set(8, (r.get(8) & 0xffff0000ffffffffu64) | 0x6d6500000000u64);
                r.set(8, (r.get(8) & 0xffffffffffffu64) | 0x736f000000000000u64);
                r.set(0, r.get(0) ^ (r.get(8)));
                if r.get(1) == 0 {
                    label = 2;
                    continue 'body;
                }
                r.set(9, 0x8ccdu64);
                r.set(10, 0x7c15u64);
                r.set(8, 0x1u64);
                r.set(9, (r.get(9) & 0xffffffff0000ffffu64) | 0xed550000u64);
                r.set(10, (r.get(10) & 0xffffffff0000ffffu64) | 0x7f4a0000u64);
                r.set(9, (r.get(9) & 0xffff0000ffffffffu64) | 0xafd700000000u64);
                r.set(10, (r.get(10) & 0xffff0000ffffffffu64) | 0x79b900000000u64);
                r.set(9, (r.get(9) & 0xffffffffffffu64) | 0xff51000000000000u64);
                r.set(10, (r.get(10) & 0xffffffffffffu64) | 0x9e37000000000000u64);
                label = 1;
            }
            1 => {
                r.set(11, r.get(8) ^ (r.get(0)));
                r.set(1, sub(r.get(1), 0x1u64));
                f.cmp(r.get(1), 0);
                r.set(8, add(r.get(8), 0x1u64));
                r.set(11, ror(r.get(11), 51));
                r.set(0, add(mul(r.get(11), r.get(9)), r.get(10)));
                if f.ne() {
                    label = 1;
                    continue 'body;
                }
                label = 2;
            }
            2 => {
                return;
            }
            _ => return,
        }
    }
}
