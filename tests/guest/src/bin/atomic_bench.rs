//! Cost of the atomics that reach Rust through `slow_call`: tight loops of
//! LDADD, SWP, CAS, an LDXR/STXR pair and CASP, and a plain load as the
//! control inside the program.
//!
//! A measurement, not a check. Compare builds interleaved, with
//! `compute_bench` as the control outside this program.
use std::arch::asm;

use std::time::Instant;

fn time(name: &str, n: u64, f: impl Fn(u64, *mut u64)) {
    let mut cell = 0u64;
    let start = Instant::now();
    f(n, &mut cell);
    let ns = start.elapsed().as_secs_f64() * 1e9 / n as f64;
    println!("{name}: {ns:.2} ns/iter");
}

fn main() {
    // SAFETY: the emulator implements LSE, which is what this measures.
    unsafe { run() }
}

#[target_feature(enable = "lse")]
unsafe fn run() {
    let n: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(5_000_000);
    time("ldr", n, |n, p| unsafe {
        asm!("2: ldr {t}, [{p}]", "subs {n}, {n}, #1", "b.ne 2b",
            p = in(reg) p, n = inout(reg) n => _, t = out(reg) _)
    });
    time("ldadd", n, |n, p| unsafe {
        asm!("2: ldadd {n}, {t}, [{p}]", "subs {n}, {n}, #1", "b.ne 2b",
            p = in(reg) p, n = inout(reg) n => _, t = out(reg) _)
    });
    time("swp", n, |n, p| unsafe {
        asm!("2: swp {n}, {t}, [{p}]", "subs {n}, {n}, #1", "b.ne 2b",
            p = in(reg) p, n = inout(reg) n => _, t = out(reg) _)
    });
    time("ldxr/stxr", n, |n, p| unsafe {
        asm!("2: ldxr {t}, [{p}]", "add {t}, {t}, #1", "stxr {s:w}, {t}, [{p}]", "subs {n}, {n}, #1", "b.ne 2b",
            p = in(reg) p, n = inout(reg) n => _, t = out(reg) _, s = out(reg) _)
    });
    // CASP needs sixteen-byte alignment, which the shared cell does not have.
    #[repr(align(16))]
    struct Pair([u64; 2]);
    let mut pair = Pair([0; 2]);
    let at = pair.0.as_mut_ptr();
    time("casp", n, |n, _| unsafe {
        asm!("2: mov x4, xzr", "mov x5, xzr", "casp x4, x5, x6, x7, [{p}]", "subs {n}, {n}, #1", "b.ne 2b",
            p = in(reg) at, n = inout(reg) n => _, out("x4") _, out("x5") _, out("x6") _, out("x7") _)
    });
    time("cas", n, |n, p| unsafe {
        asm!("2: mov {e}, xzr", "cas {e}, {n}, [{p}]", "subs {n}, {n}, #1", "b.ne 2b",
            p = in(reg) p, n = inout(reg) n => _, e = out(reg) _)
    });
}
