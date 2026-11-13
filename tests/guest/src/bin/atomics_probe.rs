//! The atomic instructions, printed rather than asserted.
//!
//! # Why this exists
//!
//! `AT_HWCAP` advertises `ATOMICS` — FEAT_LSE — so every guest library that
//! checks it emits the single-instruction forms rather than a load-exclusive
//! loop. That is all of them: Rust's `std::sync::atomic`, Go's `sync/atomic`,
//! C++'s `<atomic>`, glibc's and musl's locks, and every allocator's free
//! list. A wrong `ldadd` is a lost increment; a wrong `cas` is a lock that
//! two threads both take.
//!
//! Nothing tested any of it. `crates/emu/tlb` implements `c_atomic_rmw`,
//! `c_atomic_cas` and `c_stxr_cas`, and the guest suite exercises them only
//! through whatever a running program happens to do — which cannot tell a
//! correct `ldsmax` from one that compares unsigned, because nothing in the
//! suite uses a signed maximum on a negative number.
//!
//! # Ground truth
//!
//! The hardware, through `tests/integration/probe_diff.sh`: the same static
//! `aarch64-unknown-linux-musl` binary runs in an arm64 container where the
//! CPU executes each instruction.
//!
//! # What each case prints
//!
//! The **old value the instruction returned** and the **word left in memory**,
//! because an atomic read-modify-write has two answers and an implementation
//! can get either one wrong on its own. A `ldadd` that returns the new value
//! instead of the old is the classic version of this and is invisible to any
//! test that only looks at memory.
//!
//! Every case starts from the same memory contents and runs in a forked child,
//! so one that faults is a line rather than the end of the output.
//!
//! # The operands
//!
//! `SEED` has its top bit set in every width, so the signed and unsigned
//! maxima disagree; `OPERAND` is chosen so `ldsmax` and `ldumax` pick
//! different answers, and so the bit operations all change something.

use std::arch::asm;

/// The word each case starts from. Negative as a signed value of any width,
/// which is what tells `ldsmax` from `ldumax`.
const SEED: u64 = 0xf0e1_d2c3_b4a5_9687;
/// The second operand. Positive as a signed value, so `ldsmax(SEED, OPERAND)`
/// is `OPERAND` and `ldumax(SEED, OPERAND)` is `SEED`.
const OPERAND: u64 = 0x0123_4567_89ab_cdef;

/// Sixteen bytes shared with a forked child: the returned value and the word
/// left in memory.
static mut SLOT: *mut u64 = std::ptr::null_mut();
/// The memory each case operates on, shared so the child's write is visible.
static mut WORD: *mut u64 = std::ptr::null_mut();

/// Run `f` in a forked child and answer whether it finished. See
/// `tests/guest/src/bin/simd_probe.rs` for why every case is isolated.
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

/// One read-modify-write: print what it returned and what it left behind.
macro_rules! rmw {
    ($($op:literal),+ $(,)?) => {{
        let ok = isolated(|| unsafe {
            *WORD = SEED;
            let old: u64;
            asm!(
                $($op,)+
                p = in(reg) WORD,
                s = in(reg) OPERAND,
                o = out(reg) old,
                out("x9") _,
            );
            *SLOT = old;
            *SLOT.add(1) = *WORD;
        });
        if ok {
            let (old, mem) = unsafe { (*SLOT, *SLOT.add(1)) };
            println!("  {:<38} returned {old:016x}  memory {mem:016x}", concat!($($op),+));
        } else {
            println!("  {:<38} SIGILL", concat!($($op),+));
        }
    }};
}

/// A store-only form, which returns nothing: only memory changes.
macro_rules! st {
    ($($op:literal),+ $(,)?) => {{
        let ok = isolated(|| unsafe {
            *WORD = SEED;
            asm!(
                $($op,)+
                p = in(reg) WORD,
                s = in(reg) OPERAND,
                out("x9") _,
            );
            *SLOT = 0;
            *SLOT.add(1) = *WORD;
        });
        if ok {
            println!("  {:<38} memory {:016x}", concat!($($op),+), unsafe { *SLOT.add(1) });
        } else {
            println!("  {:<38} SIGILL", concat!($($op),+));
        }
    }};
}

/// A compare-and-swap, whose comparand may match or not. Both are printed,
/// because a version that always swaps and one that never does each get half
/// the cases right.
macro_rules! cas {
    ($label:literal, $expect:expr, $($op:literal),+ $(,)?) => {{
        let ok = isolated(|| unsafe {
            *WORD = SEED;
            let mut cmp: u64 = $expect;
            asm!(
                $($op,)+
                p = in(reg) WORD,
                s = in(reg) OPERAND,
                c = inout(reg) cmp,
                out("x9") _,
            );
            *SLOT = cmp;
            *SLOT.add(1) = *WORD;
        });
        if ok {
            let (old, mem) = unsafe { (*SLOT, *SLOT.add(1)) };
            println!("  {:<38} comparand {old:016x}  memory {mem:016x}", $label);
        } else {
            println!("  {:<38} SIGILL", $label);
        }
    }};
}

#[target_feature(enable = "lse")]
unsafe fn probe() {
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
        // Sixteen-byte aligned and well away from SLOT, because CASP needs the
        // alignment and an unaligned one is an alignment fault rather than a
        // slow path.
        WORD = p.cast::<u8>().add(256).cast();
    }

    println!("########## lse read-modify-write, 64-bit ##########");
    // Each returns the **old** value. An implementation that returns the new
    // one passes any test that only looks at memory.
    rmw!("ldadd {s}, {o}, [{p}]");
    rmw!("ldclr {s}, {o}, [{p}]");
    rmw!("ldeor {s}, {o}, [{p}]");
    rmw!("ldset {s}, {o}, [{p}]");
    // The signed and unsigned extremes disagree here by construction: SEED is
    // negative and OPERAND is not.
    rmw!("ldsmax {s}, {o}, [{p}]");
    rmw!("ldsmin {s}, {o}, [{p}]");
    rmw!("ldumax {s}, {o}, [{p}]");
    rmw!("ldumin {s}, {o}, [{p}]");
    rmw!("swp {s}, {o}, [{p}]");

    println!("########## lse read-modify-write, 32-bit ##########");
    // The 32-bit forms must leave the upper half of memory alone and zero the
    // upper half of the returned register.
    rmw!("ldadd {s:w}, {o:w}, [{p}]");
    rmw!("ldclr {s:w}, {o:w}, [{p}]");
    rmw!("ldeor {s:w}, {o:w}, [{p}]");
    rmw!("ldset {s:w}, {o:w}, [{p}]");
    rmw!("ldsmax {s:w}, {o:w}, [{p}]");
    rmw!("ldumax {s:w}, {o:w}, [{p}]");
    rmw!("swp {s:w}, {o:w}, [{p}]");

    println!("########## lse read-modify-write, byte and halfword ##########");
    // A byte or halfword form must touch exactly one or two bytes. Getting the
    // width wrong is a neighbouring field corrupted, which nothing notices
    // until the field is read.
    rmw!("ldaddb {s:w}, {o:w}, [{p}]");
    rmw!("ldaddh {s:w}, {o:w}, [{p}]");
    rmw!("ldsetb {s:w}, {o:w}, [{p}]");
    rmw!("ldclrh {s:w}, {o:w}, [{p}]");
    rmw!("swpb {s:w}, {o:w}, [{p}]");
    rmw!("swph {s:w}, {o:w}, [{p}]");
    rmw!("ldumaxb {s:w}, {o:w}, [{p}]");
    rmw!("ldsmaxb {s:w}, {o:w}, [{p}]");

    println!("########## the ordering variants ##########");
    // Acquire, release and both. They are different encodings and a decoder
    // that matched only the plain form would fault here — which is what every
    // real `fetch_add(Ordering::SeqCst)` emits.
    rmw!("ldadda {s}, {o}, [{p}]");
    rmw!("ldaddl {s}, {o}, [{p}]");
    rmw!("ldaddal {s}, {o}, [{p}]");
    rmw!("swpa {s}, {o}, [{p}]");
    rmw!("swpl {s}, {o}, [{p}]");
    rmw!("swpal {s}, {o}, [{p}]");
    rmw!("ldseta {s}, {o}, [{p}]");
    rmw!("ldclral {s}, {o}, [{p}]");
    rmw!("ldeorl {s}, {o}, [{p}]");
    rmw!("ldaddab {s:w}, {o:w}, [{p}]");
    rmw!("ldaddalh {s:w}, {o:w}, [{p}]");

    println!("########## the store-only aliases ##########");
    // STADD and friends are the same instructions with the destination `xzr`,
    // which an assembler encodes differently enough to be worth checking.
    st!("stadd {s}, [{p}]");
    st!("staddl {s}, [{p}]");
    st!("stclr {s}, [{p}]");
    st!("steor {s}, [{p}]");
    st!("stset {s}, [{p}]");
    st!("stsmax {s}, [{p}]");
    st!("stumin {s}, [{p}]");
    st!("staddb {s:w}, [{p}]");
    st!("staddh {s:w}, [{p}]");

    println!("########## compare and swap ##########");
    // Matching and not matching, in both widths, with each ordering. The
    // comparand register is written with the value that was in memory whether
    // or not the swap happened, which is the half an implementation forgets.
    cas!("cas (match)", SEED, "cas {c}, {s}, [{p}]");
    cas!("cas (no match)", 1, "cas {c}, {s}, [{p}]");
    cas!("casa (match)", SEED, "casa {c}, {s}, [{p}]");
    cas!("casl (match)", SEED, "casl {c}, {s}, [{p}]");
    cas!("casal (match)", SEED, "casal {c}, {s}, [{p}]");
    cas!("casal (no match)", 1, "casal {c}, {s}, [{p}]");
    cas!("cas w (match)", SEED & 0xffff_ffff, "cas {c:w}, {s:w}, [{p}]");
    cas!("cas w (no match)", 1, "cas {c:w}, {s:w}, [{p}]");
    cas!("casb (match)", SEED & 0xff, "casb {c:w}, {s:w}, [{p}]");
    cas!("casb (no match)", 1, "casb {c:w}, {s:w}, [{p}]");
    cas!("cash (match)", SEED & 0xffff, "cash {c:w}, {s:w}, [{p}]");
    cas!("casalb (match)", SEED & 0xff, "casalb {c:w}, {s:w}, [{p}]");

    println!("########## the exclusive pair ##########");
    // The load-exclusive/store-exclusive loop, which is what a guest uses when
    // it does not trust FEAT_LSE and what `compare_exchange_weak` compiles to
    // on any pre-LSE target. The store's result -- 0 for stored, 1 for lost --
    // is the whole protocol.
    let ok = isolated(|| unsafe {
        *WORD = SEED;
        let (old, res): (u64, u64);
        asm!(
            "ldxr {o}, [{p}]",
            "stxr w9, {s}, [{p}]",
            "mov {r}, x9",
            p = in(reg) WORD,
            s = in(reg) OPERAND,
            o = out(reg) old,
            r = out(reg) res,
            out("x9") _,
        );
        *SLOT = old;
        *SLOT.add(1) = res;
        *SLOT.add(2) = *WORD;
    });
    if ok {
        let (old, res, mem) = unsafe { (*SLOT, *SLOT.add(1), *SLOT.add(2)) };
        println!("  ldxr/stxr                              loaded {old:016x}  status {res}  memory {mem:016x}");
    } else {
        println!("  ldxr/stxr                              SIGILL");
    }

    // A store-exclusive with no matching load must fail. The monitor is
    // cleared by `clrex`, and an implementation with no monitor at all reports
    // success -- which turns every `compare_exchange` into an unconditional
    // store.
    let ok = isolated(|| unsafe {
        *WORD = SEED;
        let res: u64;
        asm!(
            "ldxr x9, [{p}]",
            "clrex",
            "stxr w9, {s}, [{p}]",
            "mov {r}, x9",
            p = in(reg) WORD,
            s = in(reg) OPERAND,
            r = out(reg) res,
            out("x9") _,
        );
        *SLOT = res;
        *SLOT.add(1) = *WORD;
    });
    if ok {
        let (res, mem) = unsafe { (*SLOT, *SLOT.add(1)) };
        println!("  stxr after clrex                       status {res}  memory {mem:016x}");
    } else {
        println!("  stxr after clrex                       SIGILL");
    }

    println!("########## the ordered load and store ##########");
    // LDAR/STLR carry the ordering without the read-modify-write, and are what
    // a relaxed-vs-acquire load differs by.
    for (label, ops) in [("ldar/stlr", 0), ("ldarb/stlrb", 1), ("ldarh/stlrh", 2)] {
        let ok = isolated(|| unsafe {
            *WORD = SEED;
            let old: u64;
            match ops {
                0 => asm!("ldar {o}, [{p}]", "stlr {s}, [{p}]",
                          p = in(reg) WORD, s = in(reg) OPERAND, o = out(reg) old),
                1 => asm!("ldarb {o:w}, [{p}]", "stlrb {s:w}, [{p}]",
                          p = in(reg) WORD, s = in(reg) OPERAND, o = out(reg) old),
                _ => asm!("ldarh {o:w}, [{p}]", "stlrh {s:w}, [{p}]",
                          p = in(reg) WORD, s = in(reg) OPERAND, o = out(reg) old),
            }
            *SLOT = old;
            *SLOT.add(1) = *WORD;
        });
        if ok {
            let (old, mem) = unsafe { (*SLOT, *SLOT.add(1)) };
            println!("  {label:<38} loaded {old:016x}  memory {mem:016x}");
        } else {
            println!("  {label:<38} SIGILL");
        }
    }

    println!("########## the sixteen-byte pair ##########");
    // CASP and LDXP/STXP move two registers as one atom. `libpas`'s versioned
    // fields are built on this and a torn update breaks them; see
    // crates/emu/tlb's cas128 module (emu/tlb.c until 2026-09-06).
    let ok = isolated(|| unsafe {
        let pair = WORD;
        *pair = SEED;
        *pair.add(1) = OPERAND;
        let (mut lo, mut hi) = (SEED, OPERAND);
        asm!(
            "casp x2, x3, x4, x5, [{p}]",
            p = in(reg) pair,
            inout("x2") lo,
            inout("x3") hi,
            in("x4") 0x1111_1111_1111_1111u64,
            in("x5") 0x2222_2222_2222_2222u64,
        );
        *SLOT = lo;
        *SLOT.add(1) = hi;
        *SLOT.add(2) = *pair;
        *SLOT.add(3) = *pair.add(1);
    });
    if ok {
        let v = unsafe { std::slice::from_raw_parts(SLOT, 4) };
        println!(
            "  casp (match)                           comparand {:016x}{:016x}  memory {:016x}{:016x}",
            v[0], v[1], v[2], v[3]
        );
    } else {
        println!("  casp (match)                           SIGILL");
    }

    let ok = isolated(|| unsafe {
        let pair = WORD;
        *pair = SEED;
        *pair.add(1) = OPERAND;
        let (mut lo, mut hi) = (1u64, 2u64);
        asm!(
            "casp x2, x3, x4, x5, [{p}]",
            p = in(reg) pair,
            inout("x2") lo,
            inout("x3") hi,
            in("x4") 0x1111_1111_1111_1111u64,
            in("x5") 0x2222_2222_2222_2222u64,
        );
        *SLOT = lo;
        *SLOT.add(1) = hi;
        *SLOT.add(2) = *pair;
        *SLOT.add(3) = *pair.add(1);
    });
    if ok {
        let v = unsafe { std::slice::from_raw_parts(SLOT, 4) };
        println!(
            "  casp (no match)                        comparand {:016x}{:016x}  memory {:016x}{:016x}",
            v[0], v[1], v[2], v[3]
        );
    } else {
        println!("  casp (no match)                        SIGILL");
    }

    let ok = isolated(|| unsafe {
        let pair = WORD;
        *pair = SEED;
        *pair.add(1) = OPERAND;
        let res: u64;
        asm!(
            "ldxp x2, x3, [{p}]",
            "stxp w9, x4, x5, [{p}]",
            "mov {r}, x9",
            p = in(reg) pair,
            r = out(reg) res,
            out("x2") _, out("x3") _,
            in("x4") 0x3333_3333_3333_3333u64,
            in("x5") 0x4444_4444_4444_4444u64,
            out("x9") _,
        );
        *SLOT = res;
        *SLOT.add(1) = *pair;
        *SLOT.add(2) = *pair.add(1);
    });
    if ok {
        let v = unsafe { std::slice::from_raw_parts(SLOT, 3) };
        println!(
            "  ldxp/stxp                              status {}  memory {:016x}{:016x}",
            v[0], v[1], v[2]
        );
    } else {
        println!("  ldxp/stxp                              SIGILL");
    }

    println!("########## barriers ##########");
    // These do nothing observable on their own, so what is checked is that
    // they decode: a missing barrier is an illegal instruction in the middle
    // of every lock.
    for b in ["dmb ish", "dmb ishst", "dmb ishld", "dmb sy", "dsb ish", "dsb sy", "isb"] {
        let ok = isolated(|| unsafe {
            match b {
                "dmb ish" => asm!("dmb ish"),
                "dmb ishst" => asm!("dmb ishst"),
                "dmb ishld" => asm!("dmb ishld"),
                "dmb sy" => asm!("dmb sy"),
                "dsb ish" => asm!("dsb ish"),
                "dsb sy" => asm!("dsb sy"),
                _ => asm!("isb"),
            }
        });
        println!("  {b:<38} {}", if ok { "ok" } else { "SIGILL" });
    }
}

fn main() {
    // FEAT_LSE is what `AT_HWCAP`'s ATOMICS bit promises, and this kernel sets
    // it. Every instruction below is inside a function that declares it, so
    // the assembler will encode them; whether the *interpreter* decodes them
    // is the question.
    unsafe { probe() };
}
