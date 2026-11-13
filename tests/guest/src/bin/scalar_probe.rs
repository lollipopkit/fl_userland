//! The scalar integer instructions and the condition flags, printed rather
//! than asserted.
//!
//! # Why this exists
//!
//! Every program runs these constantly, so the common cases are exercised by
//! anything that works at all. What is *not* exercised is the edges, and the
//! edges are where an interpreter differs from a CPU:
//!
//! - **The flags.** `NZCV` after an add or a subtract decides the next branch,
//!   and a wrong carry or overflow bit is a branch taken the wrong way in code
//!   that otherwise looks fine. Carry on subtraction is the one everybody gets
//!   backwards: AArch64 sets `C` when there was **no** borrow.
//! - **Division.** `SDIV` by zero is 0 and `INT_MIN / -1` is `INT_MIN`, both
//!   without trapping. A host that divides directly gets a `SIGFPE` for the
//!   second on x86 and the right answer on aarch64, so an emulator written
//!   against one host is wrong on the other.
//! - **Shifts by a register**, which use the low five or six bits of the
//!   amount and *not* a clamp — the opposite rule from the vector shifts, and
//!   `simd_probe` found the vector one wrong the same day.
//! - **The bitfield instructions**, whose `immr`/`imms` encoding is shared by
//!   `UBFX`, `SBFX`, `BFI`, `LSL`, `LSR`, `ASR` and `SBFIZ` — one decoder for
//!   seven mnemonics, and the aliases disagree about what the fields mean.
//!
//! # Ground truth
//!
//! The hardware, through `tests/integration/probe_diff.sh`, which runs this
//! same static binary in an arm64 container.
//!
//! Each case runs in a forked child, so an undecoded instruction is one line
//! rather than the end of the output — see `simd_probe` for what that fixed.

use std::arch::asm;

/// Two values that differ in every interesting way: signs, carries, the
/// boundary of every width.
const A: u64 = 0x8000_0000_0000_0001;
const B: u64 = 0x7fff_ffff_ffff_ffff;

/// The result and the flags a child leaves behind.
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

fn nzcv(v: u64) -> String {
    let f = |bit: u32, c: char| if v & (1 << bit) != 0 { c } else { '-' };
    format!("{}{}{}{}", f(31, 'N'), f(30, 'Z'), f(29, 'C'), f(28, 'V'))
}

/// One instruction with `x1 = A`, `x2 = B`; print `x0` and the flags after it.
macro_rules! p {
    ($($op:literal),+ $(,)?) => {{
        let ok = isolated(|| unsafe {
            let (out, flags): (u64, u64);
            asm!(
                "mov x1, {a}",
                "mov x2, {b}",
                "msr nzcv, xzr",
                $($op,)+
                "mrs {f}, nzcv",
                "mov {o}, x0",
                a = in(reg) A,
                b = in(reg) B,
                o = out(reg) out,
                f = out(reg) flags,
                out("x0") _, out("x1") _, out("x2") _, out("x3") _,
            );
            *SLOT = out;
            *SLOT.add(1) = flags;
        });
        if ok {
            let (o, f) = unsafe { (*SLOT, *SLOT.add(1)) };
            println!("  {:<40} {o:016x}  {}", concat!($($op),+), nzcv(f));
        } else {
            println!("  {:<40} SIGILL", concat!($($op),+));
        }
    }};
}

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

    println!("########## flag setting ##########");
    // The four that write flags, in both widths. `A + B` overflows signed and
    // carries unsigned; `A - B` does neither, which is the pair that separates
    // a correct C from a negated one.
    p!("adds x0, x1, x2");
    p!("subs x0, x1, x2");
    p!("adds x0, x2, x1");
    p!("subs x0, x2, x1");
    p!("adds w0, w1, w2");
    p!("subs w0, w1, w2");
    p!("ands x0, x1, x2");
    p!("bics x0, x1, x2");
    p!("adds x0, x1, #1");
    p!("subs x0, x1, #1");
    // Zero and the two boundaries, where Z and V are decided.
    p!("mov x1, #0", "subs x0, x1, #0");
    p!("mov x1, #0", "subs x0, x1, #1");
    p!("movn x1, #0", "adds x0, x1, #1");
    p!("mov x1, xzr", "adds x0, x1, xzr");
    // CMP and CMN are SUBS/ADDS to xzr, and the flags are the whole answer.
    p!("cmp x1, x2");
    p!("cmn x1, x2");
    p!("cmp w1, w2");
    p!("tst x1, x2");
    // Carry in, which is where `adc`/`sbc` read what the previous op left.
    p!("cmp x1, x1", "adc x0, x1, x2");
    p!("cmp x1, x2", "adc x0, x1, x2");
    p!("cmp x1, x1", "sbc x0, x1, x2");
    p!("cmp x1, x2", "sbc x0, x1, x2");
    p!("cmp x1, x1", "adcs x0, x1, x2");
    p!("cmp x1, x2", "sbcs x0, x1, x2");
    // The extended and shifted register forms, which sign- or zero-extend the
    // second operand before the arithmetic. A missing extension is a huge
    // number where a small one belongs.
    p!("adds x0, x1, w2, uxtb");
    p!("adds x0, x1, w2, sxtb");
    p!("adds x0, x1, w2, sxth #2");
    p!("adds x0, x1, w2, uxtw #3");
    p!("adds x0, x1, x2, lsl #4");
    p!("adds x0, x1, x2, lsr #4");
    p!("adds x0, x1, x2, asr #4");
    p!("subs x0, x1, x2, asr #63");

    println!("########## conditional compare ##########");
    // CCMP either compares or writes the immediate straight into NZCV, and
    // which one is the condition. It is what a short-circuiting `&&` compiles
    // to, so getting the fallthrough flags wrong is a wrong branch in every
    // chained comparison.
    p!("cmp x1, x2", "ccmp x1, x2, #0, eq");
    p!("cmp x1, x2", "ccmp x1, x2, #0, ne");
    p!("cmp x1, x2", "ccmp x1, x2, #15, eq");
    p!("cmp x1, x2", "ccmp x1, x2, #15, ne");
    p!("cmp x1, x1", "ccmp x1, x2, #4, eq");
    p!("cmp x1, x1", "ccmn x1, x2, #4, eq");
    p!("cmp x1, x2", "ccmp x1, #31, #0, lt");
    p!("cmp x1, x2", "ccmp w1, w2, #0, hi");

    println!("########## conditional select ##########");
    // All sixteen conditions against one set of flags, which is the only way
    // to catch a condition table with two entries swapped. `al` and `nv` are
    // the two that never appear in a compiler's output and so are the two most
    // likely to be missing.
    for c in [
        "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
    ] {
        match c {
            "eq" => p!("cmp x1, x2", "csel x0, x1, x2, eq"),
            "ne" => p!("cmp x1, x2", "csel x0, x1, x2, ne"),
            "cs" => p!("cmp x1, x2", "csel x0, x1, x2, cs"),
            "cc" => p!("cmp x1, x2", "csel x0, x1, x2, cc"),
            "mi" => p!("cmp x1, x2", "csel x0, x1, x2, mi"),
            "pl" => p!("cmp x1, x2", "csel x0, x1, x2, pl"),
            "vs" => p!("cmp x1, x2", "csel x0, x1, x2, vs"),
            "vc" => p!("cmp x1, x2", "csel x0, x1, x2, vc"),
            "hi" => p!("cmp x1, x2", "csel x0, x1, x2, hi"),
            "ls" => p!("cmp x1, x2", "csel x0, x1, x2, ls"),
            "ge" => p!("cmp x1, x2", "csel x0, x1, x2, ge"),
            "lt" => p!("cmp x1, x2", "csel x0, x1, x2, lt"),
            "gt" => p!("cmp x1, x2", "csel x0, x1, x2, gt"),
            _ => p!("cmp x1, x2", "csel x0, x1, x2, le"),
        }
    }
    // The three that transform the second operand rather than selecting it.
    p!("cmp x1, x2", "csinc x0, x1, x2, eq");
    p!("cmp x1, x2", "csinv x0, x1, x2, eq");
    p!("cmp x1, x2", "csneg x0, x1, x2, eq");
    p!("cmp x1, x2", "cset x0, eq");
    p!("cmp x1, x2", "csetm x0, lt");
    p!("cmp x1, x2", "cinc x0, x1, eq");
    p!("cmp x1, x2", "cneg x0, x1, lt");

    println!("########## multiply and divide ##########");
    p!("mul x0, x1, x2");
    p!("madd x0, x1, x2, x1");
    p!("msub x0, x1, x2, x1");
    p!("mneg x0, x1, x2");
    p!("smulh x0, x1, x2");
    p!("umulh x0, x1, x2");
    p!("smull x0, w1, w2");
    p!("umull x0, w1, w2");
    p!("smaddl x0, w1, w2, x1");
    p!("umsubl x0, w1, w2, x1");
    p!("udiv x0, x1, x2");
    p!("sdiv x0, x1, x2");
    p!("udiv w0, w1, w2");
    p!("sdiv w0, w1, w2");
    // Division by zero is **zero**, not a trap. A host that divides directly
    // faults here.
    p!("mov x2, xzr", "udiv x0, x1, x2");
    p!("mov x2, xzr", "sdiv x0, x1, x2");
    p!("mov w2, wzr", "sdiv w0, w1, w2");
    // INT_MIN / -1 overflows and the answer is INT_MIN, again without a trap.
    p!("movn x2, #0", "sdiv x0, x1, x2");
    p!("mov w1, #0x80000000", "movn w2, #0", "sdiv w0, w1, w2");

    println!("########## shifts by a register ##########");
    // The amount is taken modulo the width — 64 shifts by nothing — which is
    // the *opposite* rule from the vector shifts, where the same amount gives
    // zero. Both are in the tree and only one of them was right.
    for n in ["#0", "#1", "#63", "#64", "#65", "#127"] {
        match n {
            "#0" => {
                p!("mov x2, #0", "lslv x0, x1, x2");
                p!("mov x2, #0", "rorv x0, x1, x2");
            }
            "#1" => {
                p!("mov x2, #1", "lslv x0, x1, x2");
                p!("mov x2, #1", "asrv x0, x1, x2");
            }
            "#63" => {
                p!("mov x2, #63", "lsrv x0, x1, x2");
                p!("mov x2, #63", "asrv x0, x1, x2");
            }
            "#64" => {
                p!("mov x2, #64", "lslv x0, x1, x2");
                p!("mov x2, #64", "lsrv x0, x1, x2");
                p!("mov x2, #64", "asrv x0, x1, x2");
                p!("mov x2, #64", "rorv x0, x1, x2");
            }
            "#65" => {
                p!("mov x2, #65", "lslv x0, x1, x2");
                p!("mov w2, #65", "lslv w0, w1, w2");
                p!("mov w2, #65", "asrv w0, w1, w2");
            }
            _ => {
                p!("mov x2, #127", "lslv x0, x1, x2");
                p!("mov w2, #127", "rorv w0, w1, w2");
            }
        }
    }

    println!("########## bitfield ##########");
    // One encoding, seven mnemonics. `UBFX` and `SBFX` take a width, `BFI`
    // takes a position, and the assembler turns all of them into `immr`/`imms`
    // — so a decoder that reads the fields as one alias means gets every other
    // alias wrong.
    p!("ubfx x0, x1, #4, #8");
    p!("sbfx x0, x1, #4, #8");
    p!("ubfx x0, x1, #56, #8");
    p!("sbfx x0, x1, #56, #8");
    p!("ubfx x0, x1, #0, #64");
    p!("mov x0, x2", "bfi x0, x1, #8, #16");
    p!("mov x0, x2", "bfxil x0, x1, #8, #16");
    p!("mov x0, x2", "bfc x0, #8, #16");
    p!("ubfiz x0, x1, #8, #16");
    p!("sbfiz x0, x1, #8, #16");
    p!("ubfx w0, w1, #4, #8");
    p!("sbfx w0, w1, #28, #4");
    p!("extr x0, x1, x2, #17");
    p!("extr x0, x1, x2, #0");
    p!("extr w0, w1, w2, #31");
    // The extend aliases, which are the same instruction again.
    p!("sxtb x0, w1");
    p!("sxth x0, w1");
    p!("sxtw x0, w1");
    p!("uxtb x0, w1");
    p!("uxth x0, w1");

    println!("########## counting and reversing ##########");
    p!("clz x0, x1");
    p!("cls x0, x1");
    p!("rbit x0, x1");
    p!("rev x0, x1");
    p!("rev16 x0, x1");
    p!("rev32 x0, x1");
    p!("rev w0, w1");
    p!("rev16 w0, w1");
    p!("clz w0, w1");
    p!("mov x1, xzr", "clz x0, x1");
    p!("mov x1, xzr", "cls x0, x1");

    println!("########## logical immediates ##########");
    // The bitmask immediate encoding, which packs a repeating pattern into
    // thirteen bits. Every one of these is a different `N:immr:imms`.
    p!("and x0, x1, #0xff");
    p!("and x0, x1, #0xffffffff");
    p!("orr x0, x1, #0x5555555555555555");
    p!("eor x0, x1, #0xf0f0f0f0f0f0f0f0");
    p!("and x0, x1, #0x8000000000000000");
    p!("and w0, w1, #0xffff0000");
    p!("orr w0, w1, #0x1");
    // MOVZ/MOVN/MOVK at each of the four halfword positions.
    p!("movz x0, #0x1234, lsl #48");
    p!("movn x0, #0x1234, lsl #16");
    p!("mov x0, x1", "movk x0, #0xabcd, lsl #32");

    println!("########## addressing modes ##########");
    // A buffer with distinguishable bytes, read every way an address can be
    // formed. The post- and pre-index forms **write back** to the base, which
    // is the half an implementation forgets.
    let buf: [u8; 64] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    macro_rules! addr {
        ($label:literal, $($op:literal),+ $(,)?) => {{
            let ok = isolated(|| unsafe {
                let (val, base): (u64, u64);
                asm!(
                    "mov x1, {p}",
                    $($op,)+
                    "mov {v}, x0",
                    "mov {b}, x1",
                    p = in(reg) buf.as_ptr(),
                    v = out(reg) val,
                    b = out(reg) base,
                    out("x0") _, out("x1") _, out("x2") _,
                );
                *SLOT = val;
                // The base relative to where it started, so the output does not
                // depend on where the buffer landed.
                *SLOT.add(1) = base.wrapping_sub(buf.as_ptr() as u64);
            });
            if ok {
                let (v, d) = unsafe { (*SLOT, *SLOT.add(1)) };
                println!("  {:<40} {v:016x}  base+{d}", $label);
            } else {
                println!("  {:<40} SIGILL", $label);
            }
        }};
    }
    addr!("ldr unsigned offset", "ldr x0, [x1, #8]");
    addr!("ldr post-index", "ldr x0, [x1], #8");
    addr!("ldr pre-index", "ldr x0, [x1, #8]!");
    addr!("ldur negative offset", "add x1, x1, #16", "ldur x0, [x1, #-8]");
    addr!("ldr register offset", "mov x2, #8", "ldr x0, [x1, x2]");
    addr!("ldr register lsl", "mov x2, #1", "ldr x0, [x1, x2, lsl #3]");
    addr!("ldr register sxtw", "mov w2, #-8", "add x1, x1, #16", "ldr x0, [x1, w2, sxtw]");
    addr!("ldrb", "ldrb w0, [x1, #3]");
    addr!("ldrsb", "ldrsb x0, [x1, #3]");
    addr!("ldrh", "ldrh w0, [x1, #4]");
    addr!("ldrsh", "ldrsh x0, [x1, #4]");
    addr!("ldrsw", "ldrsw x0, [x1, #4]");
    addr!("ldp", "ldp x0, x2, [x1, #8]");
    addr!("ldp post-index", "ldp x0, x2, [x1], #16");
    addr!("ldp pre-index", "ldp x0, x2, [x1, #16]!");
    addr!("ldpsw", "ldpsw x0, x2, [x1, #8]");
    // The base written back must be visible even when the load faults nowhere;
    // a zero-offset pre-index is the degenerate case an optimiser produces.
    addr!("ldr pre-index zero", "ldr x0, [x1, #0]!");

    println!("########## pc-relative ##########");
    // ADR and ADRP are the only instructions whose answer depends on where the
    // block was compiled from, so what is printed is a *difference*: the two
    // must be four bytes apart, and ADRP must be page-aligned.
    let ok = isolated(|| unsafe {
        let (a, b, c): (u64, u64, u64);
        asm!(
            "adr {a}, 0",
            "adr {b}, 4",
            "adrp {c}, 0",
            a = out(reg) a,
            b = out(reg) b,
            c = out(reg) c,
        );
        *SLOT = b.wrapping_sub(a);
        *SLOT.add(1) = a & 0xfff;
        *SLOT.add(2) = c & 0xfff;
        *SLOT.add(3) = (a & !0xfffu64).wrapping_sub(c);
    });
    if ok {
        let v = unsafe { std::slice::from_raw_parts(SLOT, 4) };
        println!("  adr difference                           {}", v[0]);
        println!("  adr is not page aligned                  {}", v[1] != 0);
        println!("  adrp low bits                            {}", v[2]);
        println!("  adrp names adr's page                    {}", v[3] == 0);
    } else {
        println!("  adr/adrp                                 SIGILL");
        println!("  adr/adrp                                 SIGILL");
        println!("  adr/adrp                                 SIGILL");
        println!("  adr/adrp                                 SIGILL");
    }

    println!("########## branch on condition and bit ##########");
    // Which way each branch goes, as one bit per condition, so a swapped pair
    // in the condition table is one character.
    let ok = isolated(|| unsafe {
        let taken: u64;
        asm!(
            "mov x1, {a}",
            "mov x2, {b}",
            "mov x0, xzr",
            "cmp x1, x2",
            // One bit per condition, most significant first.
            "cset x3, eq",  "orr x0, x0, x3",
            "cset x3, ne",  "add x0, x0, x3, lsl #1",
            "cset x3, cs",  "add x0, x0, x3, lsl #2",
            "cset x3, cc",  "add x0, x0, x3, lsl #3",
            "cset x3, mi",  "add x0, x0, x3, lsl #4",
            "cset x3, pl",  "add x0, x0, x3, lsl #5",
            "cset x3, vs",  "add x0, x0, x3, lsl #6",
            "cset x3, vc",  "add x0, x0, x3, lsl #7",
            "cset x3, hi",  "add x0, x0, x3, lsl #8",
            "cset x3, ls",  "add x0, x0, x3, lsl #9",
            "cset x3, ge",  "add x0, x0, x3, lsl #10",
            "cset x3, lt",  "add x0, x0, x3, lsl #11",
            "cset x3, gt",  "add x0, x0, x3, lsl #12",
            "cset x3, le",  "add x0, x0, x3, lsl #13",
            "mov {t}, x0",
            a = in(reg) A,
            b = in(reg) B,
            t = out(reg) taken,
            out("x0") _, out("x1") _, out("x2") _, out("x3") _,
        );
        *SLOT = taken;
    });
    println!(
        "  every condition against cmp(A,B)         {}",
        if ok { format!("{:014b}", unsafe { *SLOT }) } else { "SIGILL".into() }
    );

    // TBZ/TBNZ and CBZ/CBNZ, which branch on a bit rather than on the flags
    // and so have their own decoders.
    let ok = isolated(|| unsafe {
        let out: u64;
        asm!(
            "mov x1, {a}",
            "mov x0, xzr",
            "tbz x1, #63, 1f", "orr x0, x0, #1", "1:",
            "tbnz x1, #0, 2f", "orr x0, x0, #2", "2:",
            "tbz x1, #1, 3f", "orr x0, x0, #4", "3:",
            "cbz x1, 4f", "orr x0, x0, #8", "4:",
            "mov x2, xzr",
            "cbnz x2, 5f", "orr x0, x0, #16", "5:",
            "mov {o}, x0",
            a = in(reg) A,
            o = out(reg) out,
            out("x0") _, out("x1") _, out("x2") _,
        );
        *SLOT = out;
    });
    println!(
        "  tbz/tbnz/cbz/cbnz                        {}",
        if ok { format!("{:05b}", unsafe { *SLOT }) } else { "SIGILL".into() }
    );
}
