//! Cost of the release/acquire barriers: a tight loop of LDAR, of STLR, of
//! STLR+LDAR and of a plain load (the control inside the same program).
//!
//! A measurement, not a check. Compare builds interleaved, with `compute_bench`
//! as the control outside this program.
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
    let n: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20_000_000);
    time("ldr", n, |n, p| unsafe {
        asm!("2: ldr {t}, [{p}]", "subs {n}, {n}, #1", "b.ne 2b",
            p = in(reg) p, n = inout(reg) n => _, t = out(reg) _)
    });
    time("ldar", n, |n, p| unsafe {
        asm!("2: ldar {t}, [{p}]", "subs {n}, {n}, #1", "b.ne 2b",
            p = in(reg) p, n = inout(reg) n => _, t = out(reg) _)
    });
    time("stlr", n, |n, p| unsafe {
        asm!("2: stlr {n}, [{p}]", "subs {n}, {n}, #1", "b.ne 2b",
            p = in(reg) p, n = inout(reg) n => _)
    });
    time("stlr+ldar", n, |n, p| unsafe {
        asm!("2: stlr {n}, [{p}]", "ldar {t}, [{p}]", "subs {n}, {n}, #1", "b.ne 2b",
            p = in(reg) p, n = inout(reg) n => _, t = out(reg) _)
    });
}
