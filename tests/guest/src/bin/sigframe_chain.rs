//! The signal frame's extension chain, from inside a handler.
//!
//! `sigcontext.__reserved` is not a struct. It is a run of `{magic, size}`
//! records, each `size` covering its own header, ending at one with both
//! fields zero — and `rt_sigreturn` has to *walk* it, because the FPSIMD
//! record is not promised to be first. Linux puts an `esr_context` ahead of it
//! whenever the signal came from a fault.
//!
//! This kernel read the FPSIMD record from offset 0 and checked only its
//! magic. That works for exactly as long as the only thing writing the frame is
//! the same code that reads it back, which is a property of the emulator and
//! not of the ABI. The moment a guest rebuilds the chain — and a guest may:
//! `uc_mcontext` is writable and returning from the handler is how you apply it
//! — the floating-point state was silently not restored.
//!
//! What is manipulated here is the *offsets the ABI fixes*, not a libc struct,
//! because the offsets are the thing under test. They are also what
//! `crates/kernel/sigframe` asserts.

use guest_tests::{Harness, check};

/// Offsets within the frame, from `arch/arm64/include/uapi/asm/sigcontext.h`.
const UC_MCONTEXT: usize = 168;
const SC_RESERVED: usize = 280;
const FPSIMD_MAGIC: u32 = 0x4650_8001;
const ESR_MAGIC: u32 = 0x4553_5201;
const FPSIMD_SIZE: usize = 528;
const ESR_SIZE: usize = 16;

/// FPCR's rounding-mode field. A control register, so it survives a call the
/// way a caller-saved vector register does not — which makes it the one piece
/// of FP state a test can watch across `raise()` without fighting the compiler
/// for a register.
const FPCR_RMODE_TOWARD_ZERO: u64 = 0b11 << 22;

fn fpcr() -> u64 {
    let v: u64;
    unsafe { std::arch::asm!("mrs {}, fpcr", out(reg) v, options(nomem, nostack)) };
    v
}

fn set_fpcr(v: u64) {
    unsafe { std::arch::asm!("msr fpcr, {}", in(reg) v, options(nomem, nostack)) };
}

static mut HANDLER_RAN: bool = false;
static mut WANT_FPCR: u64 = 0;

/// Rebuild the chain as `{esr, fpsimd, terminator}`, with the FPSIMD record's
/// saved FPCR changed. Returning from here applies it through `rt_sigreturn`.
unsafe extern "C" fn on_usr1(_sig: i32, _info: *mut libc::siginfo_t, uc: *mut libc::c_void) {
    unsafe {
        HANDLER_RAN = true;
        let reserved = (uc as *mut u8).add(UC_MCONTEXT + SC_RESERVED);

        // The kernel wrote FPSIMD first. Take a copy before anything moves.
        let magic = (reserved as *const u32).read_unaligned();
        if magic != FPSIMD_MAGIC {
            // Nothing to relocate; leave the frame alone and let the check
            // below report it rather than corrupting the stack.
            return;
        }
        let mut saved = [0u8; FPSIMD_SIZE];
        std::ptr::copy_nonoverlapping(reserved, saved.as_mut_ptr(), FPSIMD_SIZE);

        // Change the FPCR the frame will restore. Offset 12 within the record:
        // magic, size, fpsr, fpcr.
        let want = (fpcr() | FPCR_RMODE_TOWARD_ZERO) as u32;
        WANT_FPCR = want as u64;
        saved[12..16].copy_from_slice(&want.to_le_bytes());

        // esr_context first, exactly as Linux writes it for a fault.
        (reserved as *mut u32).write_unaligned(ESR_MAGIC);
        (reserved.add(4) as *mut u32).write_unaligned(ESR_SIZE as u32);
        (reserved.add(8) as *mut u64).write_unaligned(0x9600_0000);
        // then the FPSIMD record,
        std::ptr::copy_nonoverlapping(saved.as_ptr(), reserved.add(ESR_SIZE), FPSIMD_SIZE);
        // then the terminator.
        (reserved.add(ESR_SIZE + FPSIMD_SIZE) as *mut u32).write_unaligned(0);
        (reserved.add(ESR_SIZE + FPSIMD_SIZE + 4) as *mut u32).write_unaligned(0);
    }
}

fn main() {
    let mut h = Harness::new();
    h.group("extension-chain");

    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = on_usr1 as unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) as usize;
    sa.sa_flags = libc::SA_SIGINFO;
    let r = unsafe { libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()) };
    check!(h, r == 0, "install a SA_SIGINFO handler");

    // A known starting point, so the change the handler makes is visible.
    let start = fpcr() & !FPCR_RMODE_TOWARD_ZERO;
    set_fpcr(start);
    check!(h, fpcr() == start, "fpcr starts where we put it: {:#x}", fpcr());

    unsafe { libc::raise(libc::SIGUSR1) };

    check!(h, unsafe { HANDLER_RAN }, "the handler ran");
    // The whole point. The record the handler edited is second in the chain, so
    // a kernel that reads the reserved area at a fixed offset finds the
    // esr_context, does not recognise it, and restores nothing -- leaving fpcr
    // where it started.
    let got = fpcr();
    let want = unsafe { WANT_FPCR };
    check!(
        h,
        got == want,
        "rt_sigreturn walked the chain and restored fpcr from the second record: got {got:#x} want {want:#x} (started {start:#x})"
    );

    // Put it back, so nothing after this runs in a different rounding mode.
    set_fpcr(start);

    h.group("no-fpsimd-record");
    // A chain with no FPSIMD record at all is legal and means "leave the FP
    // state alone". It must not be read as a record full of zeroes, which
    // would wipe fpcr instead of preserving it.
    unsafe extern "C" fn clear_chain(_s: i32, _i: *mut libc::siginfo_t, uc: *mut libc::c_void) {
        unsafe {
            let reserved = (uc as *mut u8).add(UC_MCONTEXT + SC_RESERVED);
            (reserved as *mut u32).write_unaligned(0);
            (reserved.add(4) as *mut u32).write_unaligned(0);
        }
    }
    sa.sa_sigaction = clear_chain as unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void) as usize;
    unsafe { libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()) };

    let marked = start | FPCR_RMODE_TOWARD_ZERO;
    set_fpcr(marked);
    unsafe { libc::raise(libc::SIGUSR1) };
    check!(
        h,
        fpcr() == marked,
        "an empty chain leaves the FP state alone: {:#x} want {marked:#x}",
        fpcr()
    );
    set_fpcr(start);

    h.group("sigaction-bounds");
    // The signal number is the index into a fixed-size array of dispositions,
    // so every value that is not a signal has to be refused before it is used
    // as one.
    //
    // `sys_rt_sigaction` takes it as a `dword_t` -- unsigned -- and hands it to
    // a function whose parameter is `int`. The check there was `sig > MAX_SIG`
    // and nothing else, so 0x80000000 arrived as a large negative number,
    // compared *below* the bound, and was used to index the array. That is a
    // read and a write at a wild offset from `sighand`.
    //
    // Asked through the raw syscall: musl's sigaction() screens the number
    // itself and would answer without the kernel ever seeing it.
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = libc::SIG_DFL;
    for (signum, what) in [
        (0x8000_0000u64, "a signal number with the sign bit set"),
        (0xffff_ffffu64, "a signal number of all ones"),
        (65u64, "one past the highest real signal"),
        (0u64, "signal zero, which is not a signal"),
    ] {
        let r = unsafe {
            libc::syscall(libc::SYS_rt_sigaction, signum, &raw const act,
                          std::ptr::null_mut::<libc::sigaction>(), 8usize)
        };
        check!(h, r == -1 && guest_tests::sys::errno() == libc::EINVAL,
            "rt_sigaction refuses {what}: {r} errno {}", guest_tests::sys::errno());
    }
    // And the ones that are signals still work, so the check above is not
    // satisfied by refusing everything.
    for signum in [1u64, 15, 31, 64] {
        let r = unsafe {
            libc::syscall(libc::SYS_rt_sigaction, signum, std::ptr::null::<libc::sigaction>(),
                          std::ptr::null_mut::<libc::sigaction>(), 8usize)
        };
        check!(h, r == 0, "rt_sigaction accepts signal {signum}: {r} errno {}",
            guest_tests::sys::errno());
    }

    std::process::exit(h.finish());
}
