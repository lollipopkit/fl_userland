//! Cost of instructions that reach Rust through `slow_call`: the cryptographic
//! and table group (TBL, PMULL, EOR3) with a vector EOR as the control inside
//! the program; the immediate shifts whose wider elements reach Rust the same
//! way, with `shl .16b` (inline in the gadget) as their control; and the
//! interleaved loads and stores.
//!
//! A measurement, not a check. Compare builds interleaved, with
//! `compute_bench` as the control outside this program.
use std::arch::asm;
use std::time::Instant;

fn time(name: &str, n: u64, f: impl Fn(u64)) {
    let start = Instant::now();
    f(n);
    let ns = start.elapsed().as_secs_f64() * 1e9 / n as f64;
    println!("{name}: {ns:.2} ns/iter");
}

fn main() {
    let n: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(2_000_000);
    // SAFETY: the emulator implements these, which is what this measures.
    unsafe { run(n) }
}

#[target_feature(enable = "aes,sha3")]
unsafe fn run(n: u64) {
    time("eor", n, |n| unsafe {
        asm!("2: eor v0.16b, v1.16b, v2.16b", "subs {n}, {n}, #1", "b.ne 2b",
            n = inout(reg) n => _, out("v0") _, out("v1") _, out("v2") _)
    });
    time("tbl", n, |n| unsafe {
        asm!("2: tbl v0.16b, {{v1.16b}}, v2.16b", "subs {n}, {n}, #1", "b.ne 2b",
            n = inout(reg) n => _, out("v0") _, out("v1") _, out("v2") _)
    });
    time("pmull8", n, |n| unsafe {
        asm!("2: pmull v0.8h, v1.8b, v2.8b", "subs {n}, {n}, #1", "b.ne 2b",
            n = inout(reg) n => _, out("v0") _, out("v1") _, out("v2") _)
    });
    time("pmull64", n, |n| unsafe {
        asm!("2: pmull v0.1q, v1.1d, v2.1d", "subs {n}, {n}, #1", "b.ne 2b",
            n = inout(reg) n => _, out("v0") _, out("v1") _, out("v2") _)
    });
    time("eor3", n, |n| unsafe {
        asm!("2: eor3 v0.16b, v1.16b, v2.16b, v3.16b", "subs {n}, {n}, #1", "b.ne 2b",
            n = inout(reg) n => _, out("v0") _, out("v1") _, out("v2") _, out("v3") _)
    });
    time("shl16b", n, |n| unsafe {
        asm!("2: shl v0.16b, v1.16b, #3", "subs {n}, {n}, #1", "b.ne 2b",
            n = inout(reg) n => _, out("v0") _, out("v1") _)
    });
    time("shl2d", n, |n| unsafe {
        asm!("2: shl v0.2d, v1.2d, #3", "subs {n}, {n}, #1", "b.ne 2b",
            n = inout(reg) n => _, out("v0") _, out("v1") _)
    });
    time("ushr4s", n, |n| unsafe {
        asm!("2: ushr v0.4s, v1.4s, #3", "subs {n}, {n}, #1", "b.ne 2b",
            n = inout(reg) n => _, out("v0") _, out("v1") _)
    });
    time("usra4s", n, |n| unsafe {
        asm!("2: usra v0.4s, v1.4s, #3", "subs {n}, {n}, #1", "b.ne 2b",
            n = inout(reg) n => _, out("v0") _, out("v1") _)
    });
    let buf = [0u8; 64];
    let p = buf.as_ptr();
    time("ld2_16b", n, |n| unsafe {
        asm!("2: ld2 {{v0.16b, v1.16b}}, [{p}]", "subs {n}, {n}, #1", "b.ne 2b",
            n = inout(reg) n => _, p = in(reg) p, out("v0") _, out("v1") _)
    });
    time("ld4_16b", n, |n| unsafe {
        asm!("2: ld4 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{p}]", "subs {n}, {n}, #1", "b.ne 2b",
            n = inout(reg) n => _, p = in(reg) p, out("v0") _, out("v1") _, out("v2") _, out("v3") _)
    });
    time("ld4_4s", n, |n| unsafe {
        asm!("2: ld4 {{v0.4s, v1.4s, v2.4s, v3.4s}}, [{p}]", "subs {n}, {n}, #1", "b.ne 2b",
            n = inout(reg) n => _, p = in(reg) p, out("v0") _, out("v1") _, out("v2") _, out("v3") _)
    });
    let mut out = [0u8; 64];
    let q = out.as_mut_ptr();
    time("st4_16b", n, |n| unsafe {
        asm!("2: st4 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [{q}]", "subs {n}, {n}, #1", "b.ne 2b",
            n = inout(reg) n => _, q = in(reg) q, out("v0") _, out("v1") _, out("v2") _, out("v3") _)
    });
}
