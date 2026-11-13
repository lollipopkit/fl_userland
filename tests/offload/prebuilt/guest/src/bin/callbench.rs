//! A function with a stack frame that calls another in a tight loop — the
//! shape the prebuilt-gadget mechanism does **worst** on.
//!
//! `outer` is entered once per iteration of `main`'s loop and calls `inner`
//! sixteen times. Three things cost, and `run.sh` records the measurement:
//! the entry itself, `outer`'s prologue (a spec_fn reaches guest memory
//! through the TLB, so saving four registers is eight calls), and a `bl` whose
//! callee has no host implementation, which re-enters the dispatch loop.
//!
//! As with `mixbench`, the point is that this and
//! `crates/kernel/offloadtestprebuilt`'s `callbench` module are independent
//! renderings that must agree bit for bit.

use std::hint::black_box;

/// The callee, a leaf.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn inner(x: u64) -> u64 {
    x.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(0x1234)
}

/// The caller, which has a frame because it keeps `h` and `count` live across
/// the call.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn outer(seed: u64, count: u64) -> u64 {
    let mut h = seed;
    for i in 0..count {
        // No `black_box` here: `inner` is `inline(never)`, so the call
        // survives without one -- and a `black_box` in this loop would put a
        // store and a load through the stack in it, which would make the
        // benchmark about per-iteration guest memory rather than about the
        // call.
        h = inner(h ^ i);
        h ^= h >> 31;
    }
    h
}

fn main() {
    let iters: u64 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(1_000_000);
    let mut acc = 0u64;
    for i in 0..iters {
        acc ^= outer(black_box(i), black_box(16));
    }
    println!("callbench acc={acc:x} iters={}M", iters / 1_000_000);
}
