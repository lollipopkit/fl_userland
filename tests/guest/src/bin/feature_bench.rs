//! ns per instruction of the newer CPU features against a plain `mul`, on
//! whatever runs it (the emulator; on a real kernel it measures the silicon).
//!
//! Eight independent copies of the instruction per loop iteration, so the
//! measurement is throughput and not one dependency chain, and the same loop
//! around `mul v.4s` and `add v.4s` as controls: a gadget costs roughly one
//! dispatch (`add`, the cheapest vector op) plus its own body, so the
//! interesting number is the difference from `add`.
//!
//!   feature_bench [<iterations, millions>]

use std::arch::asm;
use std::time::Instant;

macro_rules! bench {
    ($name:expr, $iters:expr, $($insn:tt)+) => {{
        let n: u64 = $iters;
        let t = Instant::now();
        unsafe {
            asm!(
                ".arch_extension dotprod",
                ".arch_extension i8mm",
                ".arch_extension rdm",
                ".arch_extension fcma",
                ".arch_extension bf16",
                ".arch_extension fp16",
                "2:",
                $($insn)+,
                "subs {n}, {n}, #1",
                "b.ne 2b",
                n = inout(reg) n => _,
                out("v0") _, out("v1") _, out("v2") _, out("v3") _,
                out("v4") _, out("v5") _, out("v6") _, out("v7") _,
                out("v16") _, out("v17") _, out("v18") _, out("v19") _,
                out("v20") _, out("v21") _, out("v22") _, out("v23") _,
                options(nostack),
            );
        }
        let ns = t.elapsed().as_nanos() as f64;
        // 8 instructions plus the loop's own two.
        println!("{:<28} {:7.2} ns/insn", $name, ns / ($iters as f64 * 8.0));
    }};
}

fn main() {
    let millions: u64 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(1);
    let n = millions * 1_000_000 / 8;
    // Each line: eight instructions with distinct destinations.
    macro_rules! group8 {
        ($name:expr, $f:literal) => {
            bench!($name, n,
                concat!($f, " v0.4s, v16.16b, v17.16b"), concat!($f, " v1.4s, v16.16b, v17.16b"),
                concat!($f, " v2.4s, v16.16b, v17.16b"), concat!($f, " v3.4s, v16.16b, v17.16b"),
                concat!($f, " v4.4s, v16.16b, v17.16b"), concat!($f, " v5.4s, v16.16b, v17.16b"),
                concat!($f, " v6.4s, v16.16b, v17.16b"), concat!($f, " v7.4s, v16.16b, v17.16b"));
        };
    }
    macro_rules! group8s {
        ($name:expr, $f:literal) => {
            bench!($name, n,
                concat!($f, " v0.4s, v16.4s, v17.4s"), concat!($f, " v1.4s, v16.4s, v17.4s"),
                concat!($f, " v2.4s, v16.4s, v17.4s"), concat!($f, " v3.4s, v16.4s, v17.4s"),
                concat!($f, " v4.4s, v16.4s, v17.4s"), concat!($f, " v5.4s, v16.4s, v17.4s"),
                concat!($f, " v6.4s, v16.4s, v17.4s"), concat!($f, " v7.4s, v16.4s, v17.4s"));
        };
    }
    macro_rules! group8h {
        ($name:expr, $f:literal) => {
            bench!($name, n,
                concat!($f, " v0.8h, v16.8h, v17.8h"), concat!($f, " v1.8h, v16.8h, v17.8h"),
                concat!($f, " v2.8h, v16.8h, v17.8h"), concat!($f, " v3.8h, v16.8h, v17.8h"),
                concat!($f, " v4.8h, v16.8h, v17.8h"), concat!($f, " v5.8h, v16.8h, v17.8h"),
                concat!($f, " v6.8h, v16.8h, v17.8h"), concat!($f, " v7.8h, v16.8h, v17.8h"));
        };
    }
    group8s!("add v.4s (control)", "add");
    group8s!("mul v.4s (control)", "mul");
    if std::env::args().nth(2).is_some() {
        group8!("sdot", "sdot");
        group8!("udot", "udot");
        group8h!("sqrdmlah 8h", "sqrdmlah");
        group8s!("sqrdmlah 4s", "sqrdmlah");
        bench!("fcmla 4s #90", n,
            "fcmla v0.4s, v16.4s, v17.4s, #90", "fcmla v1.4s, v16.4s, v17.4s, #90",
            "fcmla v2.4s, v16.4s, v17.4s, #90", "fcmla v3.4s, v16.4s, v17.4s, #90",
            "fcmla v4.4s, v16.4s, v17.4s, #90", "fcmla v5.4s, v16.4s, v17.4s, #90",
            "fcmla v6.4s, v16.4s, v17.4s, #90", "fcmla v7.4s, v16.4s, v17.4s, #90");
        bench!("fcadd 4s #90", n,
            "fcadd v0.4s, v16.4s, v17.4s, #90", "fcadd v1.4s, v16.4s, v17.4s, #90",
            "fcadd v2.4s, v16.4s, v17.4s, #90", "fcadd v3.4s, v16.4s, v17.4s, #90",
            "fcadd v4.4s, v16.4s, v17.4s, #90", "fcadd v5.4s, v16.4s, v17.4s, #90",
            "fcadd v6.4s, v16.4s, v17.4s, #90", "fcadd v7.4s, v16.4s, v17.4s, #90");
        group8!("smmla", "smmla");
        group8!("ummla", "ummla");
        group8!("usmmla", "usmmla");
        group8!("usdot", "usdot");
        group8h!("fadd v.8h (soft)", "fadd");
        group8h!("fmla v.8h (soft)", "fmla");
        bench!("fadd h (soft, scalar)", n,
            "fadd h0, h16, h17", "fadd h1, h16, h17", "fadd h2, h16, h17", "fadd h3, h16, h17",
            "fadd h4, h16, h17", "fadd h5, h16, h17", "fadd h6, h16, h17", "fadd h7, h16, h17");
        bench!("bfdot 4s (helper)", n,
            "bfdot v0.4s, v16.8h, v17.8h", "bfdot v1.4s, v16.8h, v17.8h", "bfdot v2.4s, v16.8h, v17.8h",
            "bfdot v3.4s, v16.8h, v17.8h", "bfdot v4.4s, v16.8h, v17.8h", "bfdot v5.4s, v16.8h, v17.8h",
            "bfdot v6.4s, v16.8h, v17.8h", "bfdot v7.4s, v16.8h, v17.8h");
        bench!("bfmmla (helper)", n,
            "bfmmla v0.4s, v16.8h, v17.8h", "bfmmla v1.4s, v16.8h, v17.8h", "bfmmla v2.4s, v16.8h, v17.8h",
            "bfmmla v3.4s, v16.8h, v17.8h", "bfmmla v4.4s, v16.8h, v17.8h", "bfmmla v5.4s, v16.8h, v17.8h",
            "bfmmla v6.4s, v16.8h, v17.8h", "bfmmla v7.4s, v16.8h, v17.8h");
    }
}
