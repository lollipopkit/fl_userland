//! Memory accesses that straddle a page boundary, printed rather than
//! asserted.
//!
//! # Why this exists
//!
//! Every guest load and store goes through the software TLB in
//! `crates/emu/tlb`, whose fast path is one entry per page. An access that
//! crosses into the next page cannot use it, and takes a separate path that
//! reads or writes each half — `__tlb_read_cross_page` and its store
//! counterpart. That path is:
//!
//! - **exercised constantly**, by every unaligned `memcpy` tail, every packed
//!   struct field, every `ldp` at an odd offset;
//! - **easy to get wrong in a way nothing notices**, because the two halves
//!   are correct on their own and only the join is not — a byte order swapped
//!   across the boundary, or a length split as `size - off` where it should be
//!   `PAGE - off`, gives the wrong value with no fault;
//! - and **untested**. `mem_probe` covers `mmap` and `mremap` placement, not
//!   what an access across a boundary reads.
//!
//! # The layout
//!
//! Three pages, mapped adjacently, with the middle one available to be
//! unmapped or protected:
//!
//! ```text
//!   [ page 0 : readable ][ page 1 : varies ][ page 2 : readable ]
//! ```
//!
//! Each case reads or writes at `page1_start - k` for small `k`, so the access
//! begins in page 0 and ends in page 1. The bytes are a ramp, so a value that
//! comes back with its halves swapped, or with one half zero, is visible in
//! the printed number rather than needing a comparison to notice.
//!
//! # Ground truth
//!
//! The hardware, through `tests/integration/probe_diff.sh`. A real kernel has
//! no software TLB and no boundary at all, so every case is simply what the
//! CPU does — which is exactly the answer the interpreter has to reproduce.
//!
//! Each case runs in a forked child, so one that faults is a line rather than
//! the end of the output. That matters more here than anywhere: half of these
//! deliberately touch an unmapped page.

use std::arch::asm;
use std::ffi::c_int;

/// The three-page arena. `mid` is the start of the middle page.
struct Arena {
    base: *mut u8,
    mid: *mut u8,
}

const PAGE: usize = 4096;

/// Where a child leaves its answer.
static mut SLOT: *mut u64 = std::ptr::null_mut();

fn isolated(f: impl FnOnce()) -> bool {
    signal_of(f).is_none()
}

/// Run `f` in a forked child and answer which signal killed it, if any.
///
/// The **signal number** rather than a boolean, because for an unaligned
/// atomic the two candidates are different answers: real hardware raises
/// `SIGBUS` for an alignment fault and `SIGSEGV` for an unmapped page, and an
/// emulator that gives the second where the CPU gives the first is telling a
/// guest its pointer was bad when its *alignment* was.
fn signal_of(f: impl FnOnce()) -> Option<c_int> {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            f();
            libc::_exit(0);
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        if libc::WIFSIGNALED(status) {
            return Some(libc::WTERMSIG(status));
        }
        if libc::WEXITSTATUS(status) != 0 {
            return Some(0);
        }
        None
    }
}

fn signal_name(s: c_int) -> &'static str {
    match s {
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGBUS => "SIGBUS",
        libc::SIGILL => "SIGILL",
        0 => "exit != 0",
        _ => "other signal",
    }
}

/// Three adjacent pages filled with a ramp, so any byte says where it came
/// from. `fill` restores them, because a case that writes must not change what
/// the next one reads.
fn arena() -> Arena {
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE * 3,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(base as isize != -1, "no arena");
    let base = base.cast::<u8>();
    Arena { base, mid: unsafe { base.add(PAGE) } }
}

impl Arena {
    fn fill(&self) {
        for i in 0..PAGE * 3 {
            unsafe { *self.base.add(i) = (i as u8).wrapping_mul(31).wrapping_add(7) };
        }
    }
    /// `k` bytes before the boundary between page 0 and page 1.
    fn before(&self, k: usize) -> *mut u8 {
        unsafe { self.mid.sub(k) }
    }
}

/// `ldadd` needs FEAT_LSE, which `AT_HWCAP` advertises here — see
/// `tests/guest/src/bin/atomics_probe.rs`.
#[target_feature(enable = "lse")]
unsafe fn probe() {
    unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert!(p as isize != -1, "no shared page");
        SLOT = p.cast();
    }
    let a = arena();
    a.fill();

    // A load that begins `k` bytes before the boundary, for every width and
    // every straddling offset. The value is the whole answer: a ramp means a
    // swapped or truncated half is legible without a comparison.
    println!("########## loads across the boundary ##########");
    macro_rules! load {
        ($label:literal, $k:expr, $($op:literal),+ $(,)?) => {{
            let p = a.before($k);
            let ok = isolated(|| unsafe {
                let v: u64;
                asm!($($op,)+ p = in(reg) p, o = out(reg) v);
                *SLOT = v;
            });
            println!(
                "  {:<34} {}",
                concat!($label, " @-", stringify!($k)),
                if ok { format!("{:016x}", unsafe { *SLOT }) } else { "SIGSEGV".into() }
            );
        }};
    }
    for k in [1usize, 2, 3, 4, 5, 6, 7] {
        match k {
            1 => load!("ldrh", 1, "ldrh {o:w}, [{p}]"),
            2 => load!("ldr w", 2, "ldur {o:w}, [{p}]"),
            3 => load!("ldr w", 3, "ldur {o:w}, [{p}]"),
            4 => load!("ldr x", 4, "ldur {o}, [{p}]"),
            5 => load!("ldr x", 5, "ldur {o}, [{p}]"),
            6 => load!("ldr x", 6, "ldur {o}, [{p}]"),
            _ => load!("ldr x", 7, "ldur {o}, [{p}]"),
        }
    }
    // A signed load across the boundary, where the sign bit is in the *second*
    // page: a version that sign-extends the first half is wrong only here.
    load!("ldrsh", 1, "ldursh {o}, [{p}]");
    load!("ldrsw", 2, "ldursw {o}, [{p}]");

    println!("########## pairs and vectors across the boundary ##########");
    // `ldp` moves sixteen bytes, so it straddles for fifteen offsets. Two are
    // printed: one where the split lands inside the first register and one
    // where it lands between them, which are different code paths.
    for k in [4usize, 8, 12] {
        let p = a.before(k);
        let ok = isolated(|| unsafe {
            let (x, y): (u64, u64);
            asm!("ldp {x}, {y}, [{p}]", p = in(reg) p, x = out(reg) x, y = out(reg) y);
            *SLOT = x;
            *SLOT.add(1) = y;
        });
        println!(
            "  {:<34} {}",
            format!("ldp @-{k}"),
            if ok {
                format!("{:016x} {:016x}", unsafe { *SLOT }, unsafe { *SLOT.add(1) })
            } else {
                "SIGSEGV".into()
            }
        );
    }
    for k in [1usize, 8, 15] {
        let p = a.before(k);
        let ok = isolated(|| unsafe {
            let mut out = [0u8; 16];
            asm!(
                "ldr q0, [{p}]",
                "str q0, [{d}]",
                p = in(reg) p,
                d = in(reg) out.as_mut_ptr(),
                out("q0") _,
            );
            std::ptr::copy_nonoverlapping(out.as_ptr().cast::<u64>(), SLOT, 2);
        });
        println!(
            "  {:<34} {}",
            format!("ldr q @-{k}"),
            if ok {
                format!("{:016x} {:016x}", unsafe { *SLOT }, unsafe { *SLOT.add(1) })
            } else {
                "SIGSEGV".into()
            }
        );
    }

    println!("########## stores across the boundary ##########");
    // Written, then read back through a *byte* load on each side, so the
    // printed value cannot come from the same code path that wrote it.
    macro_rules! store {
        ($label:literal, $k:expr, $($op:literal),+ $(,)?) => {{
            a.fill();
            let p = a.before($k);
            let ok = isolated(|| unsafe {
                asm!($($op,)+ p = in(reg) p, s = in(reg) 0xa1b2_c3d4_e5f6_0718u64);
                // Read the sixteen bytes around the boundary back one at a
                // time: a store that wrote the wrong half is legible here and
                // is not if the same wide load reads it.
                let mut lo = 0u64;
                let mut hi = 0u64;
                for i in 0..8 {
                    lo |= (*p.add(i) as u64) << (i * 8);
                    hi |= (*p.add(8 + i) as u64) << (i * 8);
                }
                *SLOT = lo;
                *SLOT.add(1) = hi;
            });
            println!(
                "  {:<34} {}",
                concat!($label, " @-", stringify!($k)),
                if ok {
                    format!("{:016x} {:016x}", unsafe { *SLOT }, unsafe { *SLOT.add(1) })
                } else {
                    "SIGSEGV".into()
                }
            );
        }};
    }
    store!("strh", 1, "strh {s:w}, [{p}]");
    store!("str w", 2, "stur {s:w}, [{p}]");
    store!("str x", 3, "stur {s}, [{p}]");
    store!("str x", 7, "stur {s}, [{p}]");
    {
        a.fill();
        let p = a.before(4);
        let ok = isolated(|| unsafe {
            asm!(
                "stp {s}, {s}, [{p}]",
                p = in(reg) p,
                s = in(reg) 0x0102_0304_0506_0708u64,
            );
            let mut lo = 0u64;
            let mut hi = 0u64;
            for i in 0..8 {
                lo |= (*p.add(i) as u64) << (i * 8);
                hi |= (*p.add(8 + i) as u64) << (i * 8);
            }
            *SLOT = lo;
            *SLOT.add(1) = hi;
        });
        println!(
            "  {:<34} {}",
            "stp @-4",
            if ok {
                format!("{:016x} {:016x}", unsafe { *SLOT }, unsafe { *SLOT.add(1) })
            } else {
                "SIGSEGV".into()
            }
        );
    }

    println!("########## when the far side is not there ##########");
    // The second half of the access is unmapped, so the whole thing must fault
    // — and it must fault *before* changing anything, which the byte read back
    // after it is what checks. A cross-page store that wrote its first half and
    // then faulted has torn the guest's memory.
    a.fill();
    let before = unsafe { *a.before(1) };
    unsafe { libc::munmap(a.mid.cast(), PAGE) };
    for k in [1usize, 4, 7] {
        let p = a.before(k);
        let ok = isolated(|| unsafe {
            let v: u64;
            asm!("ldur {o}, [{p}]", p = in(reg) p, o = out(reg) v);
            *SLOT = v;
        });
        println!("  {:<34} {}", format!("load @-{k} into unmapped"), if ok { "no fault" } else { "faulted" });
    }
    for k in [1usize, 4, 7] {
        let p = a.before(k);
        let ok = isolated(|| unsafe {
            asm!("stur {s}, [{p}]", p = in(reg) p, s = in(reg) 0u64);
        });
        println!("  {:<34} {}", format!("store @-{k} into unmapped"), if ok { "no fault" } else { "faulted" });
    }
    println!(
        "  {:<34} {}",
        "the near half is untouched",
        unsafe { *a.before(1) } == before
    );

    println!("########## when the far side is read-only ##########");
    // Mapped but not writable. A load must work and a store must fault, which
    // is a different path from "not mapped at all": the TLB has a readable
    // entry and only the write side misses.
    unsafe {
        let p = libc::mmap(
            a.mid.cast(),
            PAGE,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        );
        assert!(p as isize != -1, "no read-only page");
    }
    let before = unsafe { *a.before(1) };
    for k in [1usize, 4, 7] {
        let p = a.before(k);
        let ok = isolated(|| unsafe {
            let v: u64;
            asm!("ldur {o}, [{p}]", p = in(reg) p, o = out(reg) v);
            *SLOT = v;
        });
        println!(
            "  {:<34} {}",
            format!("load @-{k} into read-only"),
            if ok { format!("{:016x}", unsafe { *SLOT }) } else { "SIGSEGV".into() }
        );
    }
    for k in [1usize, 4, 7] {
        let p = a.before(k);
        let ok = isolated(|| unsafe {
            asm!("stur {s}, [{p}]", p = in(reg) p, s = in(reg) 0u64);
        });
        println!("  {:<34} {}", format!("store @-{k} into read-only"), if ok { "no fault" } else { "faulted" });
    }
    println!(
        "  {:<34} {}",
        "the near half is untouched",
        unsafe { *a.before(1) } == before
    );

    println!("########## atomics at a boundary ##########");
    // An atomic that would straddle is an **alignment fault** on real
    // hardware, not a slow path: an unaligned atomic is not atomic, and
    // answering it anyway would silently lose the guarantee the instruction
    // exists for. Sixteen-byte forms need sixteen-byte alignment for the same
    // reason.
    unsafe {
        let p = libc::mmap(
            a.mid.cast(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        );
        assert!(p as isize != -1, "no writable page");
    }
    a.fill();
    for (label, k) in [("aligned in one page", 8usize), ("straddling", 4)] {
        let p = a.before(k);
        let sig = signal_of(|| unsafe {
            let old: u64;
            asm!("ldadd {s}, {o}, [{p}]", p = in(reg) p, s = in(reg) 1u64, o = out(reg) old);
            *SLOT = old;
        });
        println!(
            "  {:<34} {}",
            format!("ldadd {label}"),
            match sig {
                None => format!("{:016x}", unsafe { *SLOT }),
                Some(s) => signal_name(s).to_string(),
            }
        );
    }
    // Every width unaligned but inside one page, which is the case a straddle
    // does not cover: an unaligned atomic is not atomic, and answering it
    // anyway loses the guarantee the instruction exists for.
    for (label, off) in [("w by 1", 1usize), ("w by 2", 2), ("x by 1", 9), ("x by 4", 12)] {
        let p = unsafe { a.mid.add(64 + off) };
        let wide = label.starts_with('x');
        let sig = signal_of(|| unsafe {
            let old: u64;
            if wide {
                asm!("ldadd {s}, {o}, [{p}]", p = in(reg) p, s = in(reg) 1u64, o = out(reg) old);
            } else {
                asm!("ldadd {s:w}, {o:w}, [{p}]", p = in(reg) p, s = in(reg) 1u64, o = out(reg) old);
            }
            *SLOT = old;
        });
        println!(
            "  {:<34} {}",
            format!("ldadd unaligned {label}"),
            match sig {
                None => format!("{:016x}", unsafe { *SLOT }),
                Some(s) => signal_name(s).to_string(),
            }
        );
    }
    // A **loop**, which is how every real user of an exclusive pair writes it.
    // A single `stxp` may fail for reasons the architecture does not have to
    // explain — a cache eviction, an interrupt — and the hardware's does, every
    // time. Comparing one attempt would be comparing something both an emulator
    // that always succeeds and one that never does are allowed to answer
    // differently; how many attempts it takes is the property that means
    // anything, and it is 1 on both sides.
    for (label, k) in [("aligned", 16usize), ("unaligned", 12)] {
        let p = a.before(k);
        let sig = signal_of(|| unsafe {
            let mut tries = 0u64;
            loop {
                let res: u64;
                asm!(
                    "ldxp x2, x3, [{p}]",
                    "stxp w9, x2, x3, [{p}]",
                    "mov {r}, x9",
                    p = in(reg) p,
                    r = out(reg) res,
                    out("x2") _, out("x3") _, out("x9") _,
                );
                tries += 1;
                if res == 0 || tries >= 100 {
                    break;
                }
            }
            *SLOT = (tries <= 8) as u64;
        });
        println!(
            "  {:<34} {}",
            format!("ldxp/stxp {label}"),
            match sig {
                None => format!("settles quickly: {}", unsafe { *SLOT } == 1),
                Some(s) => signal_name(s).to_string(),
            }
        );
    }
}

fn main() {
    unsafe { probe() };
}
