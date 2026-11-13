//! Pure computation, no syscalls: the interpreter's own overhead.
//!
//! A measurement, not a check. Compare against the same loop built natively.
use std::time::Instant;

#[inline(never)]
fn mix(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x
}

fn main() {
    let n: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20_000_000);
    let start = Instant::now();
    let mut h: u64 = 1;
    for i in 0..n {
        h = mix(h ^ i);
    }
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("{n} mixes in {ms:.1} ms (h={h})");
}
