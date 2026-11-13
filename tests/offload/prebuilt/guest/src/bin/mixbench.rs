//! A pure-compute leaf, called many times, for the prebuilt-gadget offload
//! check.
//!
//! `mix` is what `crates/kernel/offloadtestprebuilt`'s `mixbench` module stands
//! in for: `tests/offload/prebuilt/run.sh` runs this twice, once with the host
//! implementation registered at `mix`'s guest address and once without, and
//! requires the two `acc` values to be identical. So the two are **independent
//! renderings of the same arithmetic** — this one compiled by rustc for the
//! guest, that one written by hand from the disassembly — and the check is that
//! they agree.
//!
//! It is the shape the mechanism wins on, and the measurement in
//! `docs/changelog/2026-09-09-the-offload-fixtures-were-measuring-opt-level-zero.md`
//! says why: a leaf with **no stack frame**, so entering it costs nothing to
//! save and a spec_fn never has to reach guest memory through the TLB.

use std::hint::black_box;

/// The function the offload registry replaces.
///
/// `no_mangle` so `nm` finds it under that name, and `inline(never)` so there
/// is something at that address to replace — the whole point is that the guest
/// *calls* it.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn mix(seed: u64, count: u64) -> u64 {
    let mut h = seed ^ 0x736f_6d65_7073_6575;
    let mut i = 0u64;
    while i < count {
        h ^= i + 1;
        h = (h << 13) | (h >> 51);
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h = h.wrapping_add(0x9e37_79b9_7f4a_7c15);
        i += 1;
    }
    h
}

fn main() {
    let iters: u64 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(2_000_000);
    let mut acc = 0u64;
    for i in 0..iters {
        // `black_box` on the argument, so the optimiser cannot hoist the call
        // out of the loop or const-fold it: without it there is nothing at
        // `mix`'s address to offload.
        acc ^= mix(black_box(i), black_box(64));
    }
    println!("mixbench acc={acc:x} iters={}M", iters / 1_000_000);
}
