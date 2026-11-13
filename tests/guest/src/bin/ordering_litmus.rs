//! Store-buffering litmus tests for the release/acquire instructions.
//!
//! T0: store 1 to X; load Y.   T1: store 1 to Y; load X.
//! `r0 == 0 && r1 == 0` means a load was satisfied before the earlier store was
//! observed. For every pair below (a release store followed by an RCsc acquire
//! load) the architecture forbids it, and C++/Rust `SeqCst` is exactly this
//! pair on arm64, so Dekker-style locks break when it happens. The expected
//! count is 0 on a real arm64 kernel and is asserted here.
//!
//! `stlr -> ldapr` is the control: LDAPR is RCpc and may pass an earlier STLR,
//! so the count is printed and not asserted (hardware may or may not show it).

use guest_tests::{Harness, check};
use std::arch::asm;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::*};

/// Sixteen-byte aligned so the pair instructions can target it.
#[repr(align(16))]
struct Cell(AtomicU64, AtomicU64);
static X: Cell = Cell(AtomicU64::new(0), AtomicU64::new(0));
static Y: Cell = Cell(AtomicU64::new(0), AtomicU64::new(0));

type Side = unsafe fn(*mut u64, *mut u64) -> u64;

// Fixed registers (t x9, a x10, b x11, u x12, s w13, q x14, r x15) so that
// STLUR can be emitted as a raw word; the assembler here lacks FEAT_LRCPC2.
macro_rules! side {
    ($name:ident, $($asm:literal),+) => {
        #[inline(never)]
        unsafe fn $name(a: *mut u64, b: *mut u64) -> u64 {
            let r: u64;
            unsafe {
                asm!(".arch_extension lse", ".arch_extension rcpc", $($asm),+,
                    in("x10") a, in("x11") b,
                    out("x9") _, out("x12") _, out("x13") _, out("x14") _, out("x15") r,
                    options(nostack));
            }
            r
        }
    };
}

side!(stlr_ldar, "mov x9, #1", "stlr x9, [x10]", "ldar x15, [x11]");
side!(stlur_ldar, "mov x9, #1", ".inst 0xd9000149 /* stlur x9, [x10] */", "ldar x15, [x11]");
side!(stlr_ldapr, "mov x9, #1", "stlr x9, [x10]", "ldapr x15, [x11]");
side!(stlxr_ldaxr, "mov x9, #1",
    "2: ldxr x12, [x10]", "stlxr w13, x9, [x10]", "cbnz w13, 2b", "ldaxr x15, [x11]");
side!(stlr_ldadda, "mov x9, #1", "stlr x9, [x10]", "ldadda xzr, x15, [x11]");
side!(stlr_casa, "mov x9, #1", "stlr x9, [x10]", "mov x15, #0", "casa x15, xzr, [x11]");
side!(stlr_swpa, "mov x9, #1", "stlr x9, [x10]", "swpa xzr, x15, [x11]");
// Release-only RMW, then an acquire: the release half must be ordered too.
side!(ldaddl_ldar, "mov x9, #1", "ldaddl x9, xzr, [x10]", "ldar x15, [x11]");
side!(stlxp_ldaxp, "mov x9, #1",
    "2: ldxp x12, x14, [x10]", "stlxp w13, x9, x9, [x10]", "cbnz w13, 2b",
    "ldaxp x15, x14, [x11]");

fn spin_until(v: &AtomicU32, want: u32) {
    while v.load(Acquire) != want {
        std::hint::spin_loop();
    }
}

/// Runs `n` rounds and returns how many ended with both loads reading 0.
fn litmus(f: Side, n: u32) -> u64 {
    let go = Arc::new(AtomicU32::new(0));
    let done = Arc::new(AtomicU32::new(0));
    let r1s = Arc::new(AtomicU64::new(0));
    let (g2, d2, rr) = (go.clone(), done.clone(), r1s.clone());
    let t = std::thread::spawn(move || {
        for round in 1..=n {
            spin_until(&g2, round);
            let r1 = unsafe { f(Y.0.as_ptr(), X.0.as_ptr()) };
            rr.store(r1, Release);
            d2.store(round, Release);
        }
    });
    let mut forbidden = 0;
    for round in 1..=n {
        for c in [&X, &Y] {
            c.0.store(0, SeqCst);
            c.1.store(0, SeqCst);
        }
        go.store(round, Release);
        let r0 = unsafe { f(X.0.as_ptr(), Y.0.as_ptr()) };
        spin_until(&done, round);
        if r0 == 0 && r1s.load(Acquire) == 0 {
            forbidden += 1;
        }
    }
    t.join().unwrap();
    forbidden
}

fn main() {
    let n: u32 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(100_000);
    let mut h = Harness::new();
    h.group("ordering");
    let cases: [(&str, Side); 8] = [
        ("stlr -> ldar", stlr_ldar),
        ("stlur -> ldar", stlur_ldar),
        ("stlxr -> ldaxr", stlxr_ldaxr),
        ("stlr -> ldadda", stlr_ldadda),
        ("stlr -> casa", stlr_casa),
        ("stlr -> swpa", stlr_swpa),
        ("ldaddl -> ldar", ldaddl_ldar),
        ("stlxp -> ldaxp", stlxp_ldaxp),
    ];
    for (name, f) in cases {
        let bad = litmus(f, n);
        println!("{name}: rounds={n} forbidden={bad}");
        check!(h, bad == 0, "{name}: {bad} of {n} rounds read both old values");
    }
    let bad = litmus(stlr_ldapr, n);
    println!("control stlr -> ldapr (RCpc, allowed): rounds={n} both-old={bad}");
    std::process::exit(h.finish());
}
