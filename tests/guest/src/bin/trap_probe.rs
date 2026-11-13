//! The instructions whose whole purpose is to raise a signal.
//!
//! # Why this exists
//!
//! `brk` is not a debugger curiosity. It is what
//!
//! - **every Rust panic** in a `panic=abort` build reaches — `core`'s abort
//!   intrinsic is `brk #1` on aarch64;
//! - **`__builtin_trap()`** compiles to, which is every `unreachable`,
//!   every UBSan check and every `assert` in a build that traps;
//! - **a debugger** writes over an instruction to set a breakpoint.
//!
//! `udf` is the other half: a permanently undefined encoding, used as a poison
//! value and emitted by LLVM for an `unreachable` it wants to be loud.
//!
//! Nothing tested either. A guest that panics is one of the most ordinary
//! things that can happen, and what it looks like from outside — which signal,
//! which `si_code`, which address — is what a supervisor, a crash reporter or
//! a shell reports.
//!
//! # What is checked
//!
//! The **signal**, its `si_code`, and the fault address, from a handler that
//! records them and exits — a handler that *returns* from a `brk` runs the
//! same instruction again for ever, because the exception is taken with the
//! program counter still on it -- unless the handler moves the pc, which is
//! the one case below that returns, and the one that checks the frame's
//! layout rather than only its `siginfo`.
//!
//! Also whether a handler runs at all: an emulator that turns one of these into
//! its own diagnostic and exits, rather than delivering a signal, is invisible
//! to a program that installed a handler to report the crash.
//!
//! # Ground truth
//!
//! The hardware, through `tests/integration/probe_diff.sh`.

use std::arch::asm;
use std::ffi::c_int;

/// `[signal, si_code, fault address seen by the handler]`, in a page the child
/// shares with the parent.
static mut SLOT: *mut u64 = std::ptr::null_mut();

unsafe extern "C" fn record(sig: c_int, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    unsafe {
        *SLOT = sig as u64;
        *SLOT.add(1) = (*info).si_code as i64 as u64;
        // `si_addr` is the third word of siginfo on Linux after signo/errno/code.
        let addr = *(info.cast::<u8>().add(16).cast::<u64>());
        // Stored relative to the trapping pc, which is what a crash reporter
        // compares it with, and which does not move between builds. It was
        // relative to a `TRAP_PC` nothing assigned until 2026-09-29, so the
        // absolute address was printed and the recorded baseline went stale
        // at the first toolchain update that moved the code.
        let pc = (*ctx.cast::<libc::ucontext_t>()).uc_mcontext.pc;
        *SLOT.add(2) = addr.wrapping_sub(pc);
        *SLOT.add(3) = 1; // the handler ran
        libc::_exit(0);
    }
}

fn install(sig: c_int) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = record as unsafe extern "C" fn(_, _, _) as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

unsafe extern "C" fn step(_sig: c_int, _info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    unsafe { (*ctx.cast::<libc::ucontext_t>()).uc_mcontext.pc += 4 };
}

fn stepped_over() -> String {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = step as unsafe extern "C" fn(_, _, _) as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigaction(libc::SIGTRAP, &sa, std::ptr::null_mut());
            libc::alarm(3);
            asm!("brk #0");
            libc::_exit(7);
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 7 {
            "resumed after it".to_string()
        } else if libc::WIFSIGNALED(status) {
            format!("killed by signal {}", libc::WTERMSIG(status))
        } else {
            format!("exited {}", libc::WEXITSTATUS(status))
        }
    }
}

fn signal_name(s: c_int) -> &'static str {
    match s {
        libc::SIGILL => "SIGILL",
        libc::SIGTRAP => "SIGTRAP",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGBUS => "SIGBUS",
        libc::SIGABRT => "SIGABRT",
        libc::SIGSYS => "SIGSYS",
        _ => "other",
    }
}

/// Run `f` in a child and report what happened: the handler's answer if one
/// ran, otherwise the signal that killed it.
fn trapped(f: impl FnOnce()) -> String {
    unsafe {
        *SLOT = 0;
        *SLOT.add(1) = 0;
        *SLOT.add(2) = 0;
        *SLOT.add(3) = 0;
        let pid = libc::fork();
        if pid == 0 {
            install(libc::SIGILL);
            install(libc::SIGTRAP);
            install(libc::SIGSEGV);
            install(libc::SIGBUS);
            install(libc::SIGSYS);
            f();
            libc::_exit(9); // it did not trap at all
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        if *SLOT.add(3) == 1 {
            let sig = *SLOT as c_int;
            let code = *SLOT.add(1) as i64;
            // `si_addr` as an offset from the trapping pc.
            let rel = match *SLOT.add(2) as i64 {
                0 => "at the instruction".to_string(),
                d => format!("addr pc{d:+}"),
            };
            return format!("{} code {code} {rel}", signal_name(sig));
        }
        if libc::WIFSIGNALED(status) {
            return format!("killed by {} (no handler ran)", signal_name(libc::WTERMSIG(status)));
        }
        match libc::WEXITSTATUS(status) {
            9 => "did not trap".to_string(),
            n => format!("exited {n}"),
        }
    }
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

    println!("########## brk ##########");
    // The immediate is what a debugger, a sanitizer and a language runtime use
    // to tell their own traps apart, and it must not change the signal.
    for (label, which) in [
        ("brk #0", 0),
        ("brk #1 (Rust's abort)", 1),
        ("brk #0x800 (UBSan)", 2),
        ("brk #0xf000 (gdb)", 3),
    ] {
        let out = trapped(|| unsafe {
            match which {
                0 => asm!("brk #0"),
                1 => asm!("brk #1"),
                2 => asm!("brk #0x800"),
                _ => asm!("brk #0xf000"),
            }
        });
        println!("  {label:<26} {out}");
    }

    println!("########## udf and the permanently undefined ##########");
    for (label, which) in [
        ("udf #0", 0),
        ("udf #0xdead", 1),
        // The all-zero word, which is `udf #0` and is what a jump into freshly
        // zeroed memory lands on.
        (".inst 0x00000000", 2),
        // An encoding in a space no extension uses.
        (".inst 0xffffffff", 3),
    ] {
        let out = trapped(|| unsafe {
            match which {
                0 => asm!("udf #0"),
                1 => asm!("udf #0xdead"),
                2 => asm!(".inst 0x00000000"),
                _ => asm!(".inst 0xffffffff"),
            }
        });
        println!("  {label:<26} {out}");
    }

    println!("########## hlt ##########");
    // HLT at EL0 is undefined rather than a halt, and some tools use it as a
    // second breakpoint that a debugger will not step over.
    let out = trapped(|| unsafe { asm!("hlt #0xf000") });
    println!("  {:<26} {out}", "hlt #0xf000");

    println!("########## a handler that moves the pc ##########");
    // What Go's `sigpanic`, V8 and every JIT that uses `brk` as a guard do: the
    // handler rewrites `uc_mcontext.pc` and returns, and `rt_sigreturn` resumes
    // wherever it now points. Here it steps over the `brk`. Unlike the cases
    // above this *writes* the frame, so it is the check that the offset a
    // guest's libc uses for `pc` is the one `rt_sigreturn` reads back; with
    // `mcontext` eight bytes out the write lands on `pstate` and the `brk`
    // repeats until the alarm.
    println!("  {:<26} {}", "brk, pc += 4, return", stepped_over());

    println!("########## svc ##########");
    // A syscall number nothing implements must answer ENOSYS, not die: a libc
    // probing for a newer call does this on every startup.
    let out = trapped(|| unsafe {
        let r: i64;
        asm!(
            "mov x8, #0x1000",
            "svc #0",
            out("x0") r,
            out("x8") _,
        );
        // -ENOSYS is what Linux answers; anything else is the finding.
        *SLOT = 100;
        *SLOT.add(1) = r as u64;
        *SLOT.add(3) = 1;
        libc::_exit(0);
    });
    let _ = out;
    let r = unsafe { *SLOT.add(1) } as i64;
    println!("  {:<26} returned {r}", "svc with syscall 4096");

    // A non-zero SVC immediate. Linux ignores it -- the syscall number is in
    // x8 and nothing else -- so this must behave exactly like `svc #0`.
    let out = trapped(|| unsafe {
        let r: i64;
        asm!(
            "mov x8, #172",     // getpid
            "svc #0x1234",
            out("x0") r,
            out("x8") _,
        );
        *SLOT = 100;
        *SLOT.add(1) = (r > 0) as u64;
        *SLOT.add(3) = 1;
        libc::_exit(0);
    });
    let _ = out;
    println!(
        "  {:<26} getpid worked: {}",
        "svc with a non-zero imm",
        unsafe { *SLOT.add(1) } == 1
    );

    println!("########## the hint space ##########");
    // Every unallocated hint is architecturally a **no-op**, and the allocated
    // ones here are no-ops on a CPU without the feature. That matters more than
    // it sounds: `-mbranch-protection=standard` is the default in Debian,
    // Ubuntu and Fedora's toolchains, so `paciasp`/`autiasp` are in the
    // prologue and epilogue of **every function** in every distro binary, and
    // `bti c` is at the top of every one. An emulator that treats any of them
    // as undefined cannot run those binaries at all.
    //
    // They are written as `hint #n` because the mnemonics need `+pauth` and
    // `+bti`, which this is not built with -- and the encoding is the point:
    // what a guest executes is the hint, whether or not the assembler that
    // produced it knew the name.
    for (label, which) in [
        ("hint #25 (paciasp)", 0),
        ("hint #29 (autiasp)", 1),
        ("hint #27 (pacibsp)", 2),
        ("hint #31 (autibsp)", 3),
        ("hint #32 (bti)", 4),
        ("hint #34 (bti c)", 5),
        ("hint #36 (bti j)", 6),
        ("hint #38 (bti jc)", 7),
        ("hint #24 (xpaclri)", 8),
    ] {
        let out = trapped(|| unsafe {
            match which {
                0 => asm!("hint #25"),
                1 => asm!("hint #29"),
                2 => asm!("hint #27"),
                3 => asm!("hint #31"),
                4 => asm!("hint #32"),
                5 => asm!("hint #34"),
                6 => asm!("hint #36"),
                7 => asm!("hint #38"),
                _ => asm!("hint #24"),
            }
        });
        println!("  {label:<26} {out}");
    }
    // `paciasp` followed by `autiasp` must leave x30 exactly as it was: on a
    // CPU without FEAT_PAuth both are no-ops, and on one with it they are
    // inverse. Either way a `ret` after them has to work, which is what every
    // distro binary's epilogue relies on.
    let out = trapped(|| unsafe {
        let same: u64;
        asm!(
            "mov x9, x30",
            "hint #25",     // paciasp
            "hint #29",     // autiasp
            "cmp x9, x30",
            "cset {s}, eq",
            s = out(reg) same,
            out("x9") _,
        );
        *SLOT = 100;
        *SLOT.add(1) = same;
        *SLOT.add(3) = 1;
        libc::_exit(0);
    });
    let _ = out;
    println!(
        "  {:<26} x30 unchanged: {}",
        "paciasp then autiasp",
        unsafe { *SLOT.add(1) } == 1
    );

    println!("########## after the handler ##########");
    // A handler that **returns** from a `brk` re-executes it, because the
    // exception is taken with the pc still on the instruction. A program that
    // wants to continue has to move the pc itself, which is what a debugger
    // does. What is checked here is that it loops rather than silently
    // stepping over -- an emulator that advanced the pc would let a Rust
    // `panic!` fall through into whatever follows it.
    let out = unsafe {
        *SLOT.add(3) = 0;
        let pid = libc::fork();
        if pid == 0 {
            let mut sa: libc::sigaction = std::mem::zeroed();
            unsafe extern "C" fn count(_s: c_int) {
                unsafe {
                    *SLOT.add(4) += 1;
                    if *SLOT.add(4) > 3 {
                        libc::_exit(7); // it looped, which is correct
                    }
                }
            }
            sa.sa_sigaction = count as unsafe extern "C" fn(_) as usize;
            libc::sigaction(libc::SIGTRAP, &sa, std::ptr::null_mut());
            asm!("brk #1");
            libc::_exit(8); // it stepped over, which is not
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        if libc::WIFEXITED(status) {
            match libc::WEXITSTATUS(status) {
                7 => "re-executes (correct)".to_string(),
                8 => "stepped over".to_string(),
                n => format!("exited {n}"),
            }
        } else {
            format!("killed by {}", signal_name(libc::WTERMSIG(status)))
        }
    };
    println!("  {:<26} {out}", "returning from a brk");
}
