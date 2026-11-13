//! The system registers a guest may read, and the cache maintenance that
//! depends on them.
//!
//! # Why this exists
//!
//! `mrs` of an `EL0`-readable register is how a program asks what machine it is
//! on, and two of the answers are *load-bearing* rather than informational:
//!
//! - **`CTR_EL0`** carries the instruction and data cache line sizes. A JIT
//!   that has just written code walks its buffer in line-sized steps issuing
//!   `dc cvau` and `ic ivau` — JavaScriptCore, V8, LuaJIT, every `.NET`
//!   runtime. Too large a line and the loop skips bytes it should have
//!   flushed; too small and it merely does extra work. It also carries `IDC`
//!   and `DIC`, which tell the program it may **skip** the maintenance
//!   entirely.
//! - **`DCZID_EL0`** says how much `dc zva` zeroes and whether it is allowed
//!   at all. musl's `memset` uses it. A wrong size zeroes the wrong amount of
//!   the caller's memory, which is silent until something reads it.
//!
//! The rest — `MIDR_EL1`, `MPIDR_EL1`, the ID registers — are answered from an
//! emulated value or trapped, and what matters is that reading one does not
//! kill the process: a `mrs` with no decoder is an illegal instruction, and a
//! library probing for a feature would take the whole guest down.
//!
//! # Ground truth
//!
//! The hardware, through `tests/integration/probe_diff.sh`.
//!
//! **What is compared is deliberately not every value.** `CNTVCT_EL0` is a
//! clock and `MIDR_EL1` names a particular chip; neither can agree between two
//! machines and neither should. Those cases print a *property* — that the
//! counter advances, that the id is non-zero — and the ones that carry a
//! contract print the value.

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

/// Read one system register and print it, or say it faulted.
macro_rules! sysreg {
    ($name:literal, $reg:literal) => {{
        let ok = isolated(|| unsafe {
            let v: u64;
            asm!(concat!("mrs {o}, ", $reg), o = out(reg) v);
            *SLOT = v;
        });
        println!(
            "  {:<26} {}",
            $name,
            if ok { format!("{:016x}", unsafe { *SLOT }) } else { "SIGILL".to_string() }
        );
    }};
}

/// The same, but print only whether it answered — for a register whose value
/// is a property of the machine and cannot agree between two of them.
macro_rules! sysreg_nonzero {
    ($name:literal, $reg:literal) => {{
        let ok = isolated(|| unsafe {
            let v: u64;
            asm!(concat!("mrs {o}, ", $reg), o = out(reg) v);
            *SLOT = v;
        });
        println!(
            "  {:<26} {}",
            $name,
            if ok {
                format!("readable, non-zero: {}", unsafe { *SLOT } != 0)
            } else {
                "SIGILL".to_string()
            }
        );
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

    println!("########## the registers that carry a contract ##########");
    // CTR_EL0's fields: IminLine (3:0, log2 words), L1Ip (15:14), DminLine
    // (19:16), ERG (23:20), CWG (27:24), IDC (28), DIC (29). Printed whole and
    // then decoded, because the decoded form is what a program acts on and a
    // wrong field is legible there and not in the hex.
    sysreg!("CTR_EL0", "ctr_el0");
    let ok = isolated(|| unsafe {
        let v: u64;
        asm!("mrs {o}, ctr_el0", o = out(reg) v);
        *SLOT = v;
    });
    if ok {
        let c = unsafe { *SLOT };
        println!(
            "  {:<26} icache {} bytes, dcache {} bytes, IDC {}, DIC {}",
            "CTR_EL0 decoded",
            4u32 << (c & 0xf),
            4u32 << ((c >> 16) & 0xf),
            (c >> 28) & 1,
            (c >> 29) & 1
        );
    } else {
        println!("  {:<26} SIGILL", "CTR_EL0 decoded");
    }
    // DCZID_EL0: BS (3:0, log2 words) and DZP (4) — set means `dc zva` is
    // **prohibited**, which is what a guest checks before using it.
    sysreg!("DCZID_EL0", "dczid_el0");
    let ok = isolated(|| unsafe {
        let v: u64;
        asm!("mrs {o}, dczid_el0", o = out(reg) v);
        *SLOT = v;
    });
    if ok {
        let d = unsafe { *SLOT };
        println!(
            "  {:<26} zva {} bytes, prohibited {}",
            "DCZID_EL0 decoded",
            4u32 << (d & 0xf),
            (d >> 4) & 1
        );
    } else {
        println!("  {:<26} SIGILL", "DCZID_EL0 decoded");
    }

    println!("########## the registers that name the machine ##########");
    // These cannot agree between two machines and are not supposed to. What is
    // compared is that reading one answers rather than killing the guest — a
    // library probing for a feature must not take the process down.
    sysreg_nonzero!("MIDR_EL1", "midr_el1");
    sysreg_nonzero!("MPIDR_EL1", "mpidr_el1");
    sysreg_nonzero!("ID_AA64ISAR0_EL1", "id_aa64isar0_el1");
    sysreg_nonzero!("ID_AA64PFR0_EL1", "id_aa64pfr0_el1");
    sysreg_nonzero!("CNTFRQ_EL0", "cntfrq_el0");
    sysreg_nonzero!("CNTVCT_EL0", "cntvct_el0");

    println!("########## the thread pointer ##########");
    // TPIDR_EL0 is the guest's TLS base, which every threaded program reads on
    // every access to a `__thread` variable, and it must survive a write.
    let ok = isolated(|| unsafe {
        let (before, after): (u64, u64);
        asm!(
            "mrs {b}, tpidr_el0",
            "msr tpidr_el0, {v}",
            "mrs {a}, tpidr_el0",
            "msr tpidr_el0, {b}",
            b = out(reg) before,
            a = out(reg) after,
            v = in(reg) 0xdead_beef_0000_1234u64,
        );
        *SLOT = (after == 0xdead_beef_0000_1234) as u64;
        *SLOT.add(1) = (before != 0) as u64;
    });
    println!(
        "  {:<26} {}",
        "TPIDR_EL0 round trip",
        if ok {
            format!(
                "reads back: {}, libc set one: {}",
                unsafe { *SLOT } == 1,
                unsafe { *SLOT.add(1) } == 1
            )
        } else {
            "SIGILL".to_string()
        }
    );
    // TPIDRRO_EL0 is read-only at EL0. Reading must work; writing is an
    // illegal instruction, and an emulator that allows it lets a guest
    // corrupt something it cannot on real hardware.
    sysreg_nonzero!("TPIDRRO_EL0", "tpidrro_el0");
    let ok = isolated(|| unsafe {
        asm!("msr tpidrro_el0, {v}", v = in(reg) 1u64);
    });
    println!("  {:<26} {}", "writing TPIDRRO_EL0", if ok { "allowed" } else { "SIGILL" });

    println!("########## cache maintenance ##########");
    // These are what a JIT issues after writing code. None of them has an
    // observable result on its own; what is being checked is that each
    // *decodes*, because one that does not is an illegal instruction in the
    // middle of every guest JIT's publish step.
    let buf = vec![0u8; 4096];
    let p = buf.as_ptr();
    for (label, which) in [
        ("dc cvau", 0),
        ("dc civac", 1),
        ("dc cvac", 2),
        ("ic ivau", 3),
        ("ic iallu", 4),
        ("dsb ish + isb", 5),
    ] {
        let ok = isolated(|| unsafe {
            match which {
                0 => asm!("dc cvau, {p}", p = in(reg) p),
                1 => asm!("dc civac, {p}", p = in(reg) p),
                2 => asm!("dc cvac, {p}", p = in(reg) p),
                3 => asm!("ic ivau, {p}", p = in(reg) p),
                4 => asm!("ic iallu"),
                _ => asm!("dsb ish", "isb"),
            }
        });
        println!("  {label:<26} {}", if ok { "ok" } else { "SIGILL" });
    }
    // `dc zva` zeroes DCZID_EL0's worth of memory at an aligned address. What
    // is printed is **how many bytes actually became zero**, which is the
    // thing musl's memset depends on and the thing a wrong DCZID makes wrong.
    let ok = isolated(|| unsafe {
        let mut mem = vec![0xffu8; 512];
        let base = mem.as_mut_ptr();
        // Align to 128, which is at least as strict as any real ZVA size.
        let aligned = base.add(128 - (base as usize % 128));
        asm!("dc zva, {p}", p = in(reg) aligned);
        let mut zeros = 0u64;
        while zeros < 256 && *aligned.add(zeros as usize) == 0 {
            zeros += 1;
        }
        *SLOT = zeros;
        // And that it did not zero anything *before* the address.
        *SLOT.add(1) = (*aligned.sub(1) == 0xff) as u64;
    });
    println!(
        "  {:<26} {}",
        "dc zva bytes zeroed",
        if ok {
            format!("{}, byte before untouched: {}", unsafe { *SLOT }, unsafe { *SLOT.add(1) } == 1)
        } else {
            "SIGILL".to_string()
        }
    );

    println!("########## hints ##########");
    // The hint space is architecturally a no-op for anything unallocated, so
    // every one of these must run and do nothing. An emulator that treats an
    // unknown hint as undefined kills a guest compiled for a newer CPU.
    for (label, which) in [
        ("prfm pldl1keep", 0),
        ("prfm pstl1strm", 1),
        ("nop", 2),
        ("yield", 3),
        ("wfe", 4),
        ("sevl", 5),
        ("hint #7", 6),
        ("hint #23", 7),
    ] {
        let ok = isolated(|| unsafe {
            match which {
                0 => asm!("prfm pldl1keep, [{p}]", p = in(reg) p),
                1 => asm!("prfm pstl1strm, [{p}]", p = in(reg) p),
                2 => asm!("nop"),
                3 => asm!("yield"),
                4 => asm!("sevl", "wfe"),
                5 => asm!("sevl"),
                6 => asm!("hint #7"),
                _ => asm!("hint #23"),
            }
        });
        println!("  {label:<26} {}", if ok { "ok" } else { "SIGILL" });
    }
}
