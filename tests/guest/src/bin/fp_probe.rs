//! Floating-point *state* — the exception flags, the control bits and what a
//! comparison leaves in `NZCV` — printed rather than asserted.
//!
//! # Why this exists
//!
//! `tests/guest/src/bin/fpu_modes.rs` checks that the FPCR **rounding mode**
//! reaches the arithmetic, which was once wrong. Nothing checks the rest of
//! the register pair:
//!
//! - **FPSR's cumulative exception bits.** `fetestexcept` reads them, and every
//!   numeric library uses it — `libm` to decide whether a result is exact,
//!   Python's `math` to raise `OverflowError`, Go's `strconv` to detect
//!   inexact parses. A bit that never gets set makes an overflow silent; one
//!   that is always set makes a correct result look wrong.
//! - **FPCR's other fields** — flush-to-zero and default-NaN — which change
//!   what arithmetic *produces*, not just how it rounds.
//! - **What a comparison writes to `NZCV`,** and in particular the `unordered`
//!   encoding, which is the only way a program distinguishes "less than" from
//!   "not comparable" and is what every `NaN`-safe sort depends on.
//!
//! # Ground truth
//!
//! The hardware, through `tests/integration/probe_diff.sh`.
//!
//! Each case runs in a forked child, because FPCR and FPSR are *sticky*: a
//! case that sets flush-to-zero and does not clear it changes every case after
//! it, and a case that raises an exception leaves the bit set for the next one
//! to read. A child per case makes each start from the same state, which is
//! the only way the output means what it says.

use std::arch::asm;

/// Where a child leaves its answer.
static mut SLOT: *mut u64 = std::ptr::null_mut();

fn isolated(f: impl FnOnce()) -> bool {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            f();
            libc::_exit(0);
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }
}

/// FPSR's cumulative exception bits, in the order the ARM ARM lists them.
fn fpsr_flags(v: u64) -> String {
    let f = |bit: u32, c: char| if v & (1 << bit) != 0 { c } else { '-' };
    // IDC(7) IXC(4) UFC(3) OFC(2) DZC(1) IOC(0)
    format!(
        "{}{}{}{}{}{}",
        f(7, 'D'),
        f(4, 'X'),
        f(3, 'U'),
        f(2, 'O'),
        f(1, 'Z'),
        f(0, 'I')
    )
}

fn nzcv_flags(v: u64) -> String {
    let f = |bit: u32, c: char| if v & (1 << bit) != 0 { c } else { '-' };
    format!("{}{}{}{}", f(31, 'N'), f(30, 'Z'), f(29, 'C'), f(28, 'V'))
}

/// Run one operation with `d0 = a`, `d1 = b`, FPSR cleared first, and print the
/// result together with the exception bits it raised.
macro_rules! fp {
    ($label:literal, $a:expr, $b:expr, $($op:literal),+ $(,)?) => {{
        let ok = isolated(|| unsafe {
            let (res, fpsr): (u64, u64);
            asm!(
                "fmov d0, {a}",
                "fmov d1, {b}",
                "msr fpsr, xzr",
                $($op,)+
                "fmov {r}, d0",
                "mrs {f}, fpsr",
                a = in(reg) $a,
                b = in(reg) $b,
                r = out(reg) res,
                f = out(reg) fpsr,
                out("d0") _, out("d1") _, out("d2") _,
            );
            *SLOT = res;
            *SLOT.add(1) = fpsr;
        });
        if ok {
            let (r, f) = unsafe { (*SLOT, *SLOT.add(1)) };
            println!("  {:<32} {r:016x}  {}", $label, fpsr_flags(f));
        } else {
            println!("  {:<32} SIGILL", $label);
        }
    }};
}

const ONE: u64 = 0x3ff0_0000_0000_0000;
const THREE: u64 = 0x4008_0000_0000_0000;
const ZERO: u64 = 0;
const NEG_ZERO: u64 = 0x8000_0000_0000_0000;
const INF: u64 = 0x7ff0_0000_0000_0000;
/// A signalling NaN, which is the one an operation is supposed to turn into a
/// quiet one *and* flag as invalid.
const SNAN: u64 = 0x7ff0_0000_0000_0001;
/// A quiet NaN with a payload, so "was the payload preserved" is answerable.
const QNAN: u64 = 0x7ff8_0000_dead_beef;
/// The smallest normal double, and one denormal.
const MIN_NORMAL: u64 = 0x0010_0000_0000_0000;
const DENORMAL: u64 = 0x0000_0000_0000_0001;
/// The largest finite double, for overflow.
const MAX: u64 = 0x7fef_ffff_ffff_ffff;

fn main() {
    unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert!(p as isize != -1, "no shared page");
        SLOT = p.cast();
    }

    println!("########## which operations raise which exception ##########");
    // Each of the six cumulative bits, reached on purpose. A bit that is never
    // set is a `fetestexcept` that never fires.
    fp!("1/3 (inexact)", ONE, THREE, "fdiv d0, d0, d1");
    fp!("1/0 (divide by zero)", ONE, ZERO, "fdiv d0, d0, d1");
    fp!("0/0 (invalid)", ZERO, ZERO, "fdiv d0, d0, d1");
    fp!("inf-inf (invalid)", INF, INF, "fsub d0, d0, d1");
    fp!("max*max (overflow)", MAX, MAX, "fmul d0, d0, d1");
    fp!("min*min (underflow)", MIN_NORMAL, MIN_NORMAL, "fmul d0, d0, d1");
    fp!("sqrt(-1) (invalid)", NEG_ZERO | ONE, ZERO, "fsqrt d0, d0");
    fp!("denormal + 0 (input denorm)", DENORMAL, ZERO, "fadd d0, d0, d1");
    fp!("1+1 (exact, no flags)", ONE, ONE, "fadd d0, d0, d1");
    // A quiet NaN propagates *without* raising invalid; a signalling one
    // raises it and is quieted. That difference is the whole reason there are
    // two kinds.
    fp!("qnan + 1 (propagates)", QNAN, ONE, "fadd d0, d0, d1");
    fp!("snan + 1 (invalid)", SNAN, ONE, "fadd d0, d0, d1");
    fp!("qnan * qnan", QNAN, QNAN, "fmul d0, d0, d1");

    println!("########## the flags are cumulative ##########");
    // FPSR's exception bits are sticky: they accumulate until written. A
    // version that recomputed them per instruction would show only the last.
    let ok = isolated(|| unsafe {
        let fpsr: u64;
        asm!(
            "msr fpsr, xzr",
            "fmov d0, {a}",
            "fmov d1, {b}",
            "fdiv d2, d0, d1",     // inexact
            "fmov d1, xzr",
            "fdiv d2, d0, d1",     // divide by zero
            "fsub d2, d1, d1",     // 0-0, exact
            "mrs {f}, fpsr",
            a = in(reg) ONE,
            b = in(reg) THREE,
            f = out(reg) fpsr,
            out("d0") _, out("d1") _, out("d2") _,
        );
        *SLOT = fpsr;
    });
    println!(
        "  {:<32} {}",
        "three ops, flags accumulated",
        if ok { fpsr_flags(unsafe { *SLOT }) } else { "SIGILL".into() }
    );
    // And writing FPSR clears them, which is what `feclearexcept` is.
    let ok = isolated(|| unsafe {
        let fpsr: u64;
        asm!(
            "fmov d0, {a}",
            "fmov d1, xzr",
            "fdiv d2, d0, d1",
            "msr fpsr, xzr",
            "mrs {f}, fpsr",
            a = in(reg) ONE,
            f = out(reg) fpsr,
            out("d0") _, out("d1") _, out("d2") _,
        );
        *SLOT = fpsr;
    });
    println!(
        "  {:<32} {}",
        "and writing fpsr clears them",
        if ok { fpsr_flags(unsafe { *SLOT }) } else { "SIGILL".into() }
    );

    println!("########## flush to zero and default nan ##########");
    // FPCR.FZ (bit 24) makes a denormal *result* zero and a denormal *input*
    // read as zero. FPCR.DN (bit 25) replaces any NaN result with the default
    // quiet NaN, payload and all. Both change what the arithmetic produces,
    // and an implementation that records the register without applying it
    // agrees with `fegetenv` and disagrees with every value.
    for (label, fpcr) in [
        ("FZ off", 0u64),
        ("FZ on", 1 << 24),
        ("DN on", 1 << 25),
        ("FZ+DN on", (1 << 24) | (1 << 25)),
    ] {
        let ok = isolated(|| unsafe {
            let (denorm, nan): (u64, u64);
            asm!(
                "msr fpcr, {c}",
                "fmov d0, {d}",
                "fmov d1, {o}",
                "fmul d2, d0, d1",       // denormal * 1
                "fmov {dr}, d2",
                "fmov d0, {q}",
                "fadd d2, d0, d1",       // qnan + 1
                "fmov {nr}, d2",
                "msr fpcr, xzr",
                c = in(reg) fpcr,
                d = in(reg) DENORMAL,
                o = in(reg) ONE,
                q = in(reg) QNAN,
                dr = out(reg) denorm,
                nr = out(reg) nan,
                out("d0") _, out("d1") _, out("d2") _,
            );
            *SLOT = denorm;
            *SLOT.add(1) = nan;
        });
        println!(
            "  {:<32} {}",
            label,
            if ok {
                format!("denorm {:016x}  nan {:016x}", unsafe { *SLOT }, unsafe { *SLOT.add(1) })
            } else {
                "SIGILL".into()
            }
        );
    }
    // FPCR must read back what was written, and the bits it does not define
    // must read as zero — a register that stores everything lets a guest
    // believe it enabled trapping, which this kernel does not do.
    let ok = isolated(|| unsafe {
        let v: u64;
        asm!(
            "msr fpcr, {c}",
            "mrs {o}, fpcr",
            "msr fpcr, xzr",
            c = in(reg) 0xffff_ffffu64,
            o = out(reg) v,
        );
        *SLOT = v;
    });
    println!(
        "  {:<32} {}",
        "fpcr after writing all ones",
        if ok { format!("{:08x}", unsafe { *SLOT }) } else { "SIGILL".into() }
    );

    println!("########## what a comparison writes to nzcv ##########");
    // `fcmp` sets NZCV, and the **unordered** result — C and V set, N and Z
    // clear — is the only thing that distinguishes "not comparable" from "less
    // than". Every NaN-safe comparison in every language reads it.
    for (label, a, b) in [
        ("1 vs 3", ONE, THREE),
        ("3 vs 1", THREE, ONE),
        ("1 vs 1", ONE, ONE),
        ("0 vs -0", ZERO, NEG_ZERO),
        ("1 vs qnan", ONE, QNAN),
        ("qnan vs qnan", QNAN, QNAN),
        ("inf vs 1", INF, ONE),
    ] {
        let ok = isolated(|| unsafe {
            let (nzcv, fpsr): (u64, u64);
            asm!(
                "msr fpsr, xzr",
                "fmov d0, {a}",
                "fmov d1, {b}",
                "fcmp d0, d1",
                "mrs {n}, nzcv",
                "mrs {f}, fpsr",
                a = in(reg) a,
                b = in(reg) b,
                n = out(reg) nzcv,
                f = out(reg) fpsr,
                out("d0") _, out("d1") _,
            );
            *SLOT = nzcv;
            *SLOT.add(1) = fpsr;
        });
        println!(
            "  {:<32} {}",
            format!("fcmp {label}"),
            if ok {
                format!("{}  fpsr {}", nzcv_flags(unsafe { *SLOT }), fpsr_flags(unsafe { *SLOT.add(1) }))
            } else {
                "SIGILL".into()
            }
        );
    }
    // `fcmpe` raises invalid for a *quiet* NaN where `fcmp` does not. That one
    // bit is the difference between the two instructions.
    let ok = isolated(|| unsafe {
        let (nzcv, fpsr): (u64, u64);
        asm!(
            "msr fpsr, xzr",
            "fmov d0, {a}",
            "fmov d1, {b}",
            "fcmpe d0, d1",
            "mrs {n}, nzcv",
            "mrs {f}, fpsr",
            a = in(reg) ONE,
            b = in(reg) QNAN,
            n = out(reg) nzcv,
            f = out(reg) fpsr,
            out("d0") _, out("d1") _,
        );
        *SLOT = nzcv;
        *SLOT.add(1) = fpsr;
    });
    println!(
        "  {:<32} {}",
        "fcmpe 1 vs qnan",
        if ok {
            format!("{}  fpsr {}", nzcv_flags(unsafe { *SLOT }), fpsr_flags(unsafe { *SLOT.add(1) }))
        } else {
            "SIGILL".into()
        }
    );
    // Against zero, which is its own encoding and is what `x == 0.0` compiles
    // to.
    for (label, a) in [("0", ZERO), ("-0", NEG_ZERO), ("qnan", QNAN)] {
        let ok = isolated(|| unsafe {
            let nzcv: u64;
            asm!(
                "fmov d0, {a}",
                "fcmp d0, #0.0",
                "mrs {n}, nzcv",
                a = in(reg) a,
                n = out(reg) nzcv,
                out("d0") _,
            );
            *SLOT = nzcv;
        });
        println!(
            "  {:<32} {}",
            format!("fcmp {label} vs #0.0"),
            if ok { nzcv_flags(unsafe { *SLOT }) } else { "SIGILL".into() }
        );
    }
    // `fccmp`, which is what a chained float comparison compiles to.
    let ok = isolated(|| unsafe {
        let nzcv: u64;
        asm!(
            "fmov d0, {a}",
            "fmov d1, {b}",
            "fcmp d0, d1",
            "fccmp d0, d1, #3, eq",
            "mrs {n}, nzcv",
            a = in(reg) ONE,
            b = in(reg) THREE,
            n = out(reg) nzcv,
            out("d0") _, out("d1") _,
        );
        *SLOT = nzcv;
    });
    println!(
        "  {:<32} {}",
        "fccmp after a false condition",
        if ok { nzcv_flags(unsafe { *SLOT }) } else { "SIGILL".into() }
    );

    println!("########## conversions at the edges ##########");
    // A float too large for the integer it is converted to **saturates** on
    // aarch64 — it does not wrap and it does not trap — and a NaN converts to
    // zero. Every language's `as` cast depends on which.
    // The whole answer is in the **upper half** of the printed register as well
    // as the value: a `W` destination zeroes the top 32 bits, so a conversion
    // that sign-extends instead is wrong for every negative result, and one
    // that saturates at 64 bits and then narrows is wrong for every value
    // outside the 32-bit range. Both are shapes an implementation reaches for.
    //
    // `1e300`, `5e9` and `-1.5` are the three that tell them apart: the first
    // exceeds both ranges, the second exceeds 32 bits and not 64, and the
    // third is simply negative.
    const E300: u64 = 0x7e37_e43c_8800_759c; // 1e300
    const E9: u64 = 0x41f2_a05f_2000_0000;   // 5e9
    const NEG1_5: u64 = 0xbff8_0000_0000_0000;
    for (label, v, op) in [
        ("inf -> i64", INF, "fcvtzs {o}, d0"),
        ("-inf -> i64", INF | NEG_ZERO, "fcvtzs {o}, d0"),
        ("nan -> i64", QNAN, "fcvtzs {o}, d0"),
        ("inf -> u64", INF, "fcvtzu {o}, d0"),
        ("-1.5 -> u64", NEG1_5, "fcvtzu {o}, d0"),
        ("1e300 -> i32", E300, "fcvtzs {o:w}, d0"),
        ("5e9 -> i32", E9, "fcvtzs {o:w}, d0"),
        ("-1.5 -> i32", NEG1_5, "fcvtzs {o:w}, d0"),
        ("nan -> i32", QNAN, "fcvtzs {o:w}, d0"),
        ("1e300 -> u32", E300, "fcvtzu {o:w}, d0"),
        ("5e9 -> u32", E9, "fcvtzu {o:w}, d0"),
        ("-1.5 -> u32", NEG1_5, "fcvtzu {o:w}, d0"),
        // The other rounding modes, which are separate instructions with the
        // same narrowing rule.
        ("5e9 -> i32 (round nearest)", E9, "fcvtns {o:w}, d0"),
        ("-1.5 -> i32 (round nearest)", NEG1_5, "fcvtns {o:w}, d0"),
        ("-1.5 -> i32 (round up)", NEG1_5, "fcvtps {o:w}, d0"),
        ("-1.5 -> i32 (round down)", NEG1_5, "fcvtms {o:w}, d0"),
        ("-1.5 -> i32 (ties away)", NEG1_5, "fcvtas {o:w}, d0"),
        ("5e9 -> u32 (round nearest)", E9, "fcvtnu {o:w}, d0"),
        ("-1.5 -> u32 (ties away)", NEG1_5, "fcvtau {o:w}, d0"),
    ] {
        let ok = isolated(|| unsafe {
            let out: u64;
            macro_rules! conv {
                ($i:literal) => {
                    asm!("fmov d0, {v}", $i, v = in(reg) v, o = out(reg) out, out("d0") _)
                };
            }
            match op {
                "fcvtzs {o}, d0" => conv!("fcvtzs {o}, d0"),
                "fcvtzu {o}, d0" => conv!("fcvtzu {o}, d0"),
                "fcvtzs {o:w}, d0" => conv!("fcvtzs {o:w}, d0"),
                "fcvtzu {o:w}, d0" => conv!("fcvtzu {o:w}, d0"),
                "fcvtns {o:w}, d0" => conv!("fcvtns {o:w}, d0"),
                "fcvtps {o:w}, d0" => conv!("fcvtps {o:w}, d0"),
                "fcvtms {o:w}, d0" => conv!("fcvtms {o:w}, d0"),
                "fcvtas {o:w}, d0" => conv!("fcvtas {o:w}, d0"),
                "fcvtnu {o:w}, d0" => conv!("fcvtnu {o:w}, d0"),
                _ => conv!("fcvtau {o:w}, d0"),
            }
            *SLOT = out;
        });
        println!(
            "  {:<32} {}",
            label,
            if ok { format!("{:016x}", unsafe { *SLOT }) } else { "SIGILL".into() }
        );
    }
}
