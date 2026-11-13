//! The software TLB's hit path: loads and stores that never miss.
//!
//! A measurement, not a check.
//!
//! Every guest access runs the inline lookup in `gadgets.h`'s `read_prep` /
//! `write_prep`: the page compare, then the **coherence check** -- the entry's
//! generation against `tlb->mmu->changes`, which is two dependent loads and a
//! branch on every access, taken for a mid-block remap by another thread.
//! `mem_bench`'s `resident` case is this path too, but at 16,384 iterations
//! per run it is below the noise of anything a change here could move.
//!
//! So this touches four pages, which stay resident, a few hundred million
//! times. `compute_bench` is the control outside it: no memory traffic.
//!
//! Usage: `tlb_hit_bench [millions of accesses]`, default 200.
//!
//! # What the coherence check costs, 2026-09-30
//!
//! Release builds, 12 interleaved pairs, M-series Mac, `compute_bench` as the
//! control (176.1 vs 174.8 ms, t = -0.6: it did not move):
//!
//! ```text
//!               with the check   without   difference
//!   load        10.27 ns          9.42      0.92 ns  (t = 6.9)   8.9%
//!   store        8.11 ns          7.35      0.72 ns  (t = 6.7)   8.9%
//! ```
//!
//! Most of that is the extra load, compare and branch, not the dependent
//! chain: a variant comparing against a value in the TLB itself -- one load,
//! the timing a per-TLB copy of `changes` would have -- recovered 0.33 ns of
//! a load (t = 1.0, not separable) and 0.49 ns of a store (t = 2.5). That
//! design would need the writer to update every sharing thread's copy before
//! the old backing goes, a new cross-thread protocol for at most half of a
//! nanosecond, so the check stays as it is.
//!
//! **Build a variant with `RUSTC_WRAPPER=` and a build dir of its own.** The
//! first "without" build here, in a git worktree, linked the main checkout's
//! gadgets: the cached build-script output named the main repository's
//! `gadgets.h`. Its binary differed from the baseline and still had the check.
//! `objdump -d` the result and look after `ubfx x9, x7, #12, #13` before timing
//! anything.

use std::hint::black_box;
use std::time::Instant;

fn main() {
    let millions: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let n = millions * 1_000_000;

    // Four pages of words. Distinct pages so the lookup's index varies, and
    // few enough that every one is a hit after the first pass.
    let mut buf = vec![0u64; 4 * 4096 / 8];
    let mask = buf.len() - 1;
    // A stride of 513 words walks all four pages; odd, so it visits every word.
    let stride = 513;

    let mut sink = 0u64;
    let mut i = 0usize;
    let start = Instant::now();
    for _ in 0..n {
        sink = sink.wrapping_add(black_box(&buf)[i]);
        i = (i + stride) & mask;
    }
    let load = start.elapsed().as_secs_f64() * 1e9 / n as f64;

    let start = Instant::now();
    for k in 0..n {
        black_box(&mut buf)[i] = k as u64;
        i = (i + stride) & mask;
    }
    let store = start.elapsed().as_secs_f64() * 1e9 / n as f64;

    println!("load  {load:.3} ns/access");
    println!("store {store:.3} ns/access");
    println!("(sink={})", sink.wrapping_add(buf[0]));
}
