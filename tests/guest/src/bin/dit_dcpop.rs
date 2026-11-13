//! `PSTATE.DIT` (FEAT_DIT) and `DC CVAP`/`DC CVADP` (FEAT_DPB, FEAT_DPB2).
//!
//! DIT is one bit of state with no timing effect to model, so what is checked is
//! what a program can observe: `mrs`/`msr` in all three forms read and write it
//! (only bit 24 of the register counts), it is inherited by `fork`, reset by
//! `execve`, visible as bit 24 of the pstate a signal frame carries, unchanged on
//! entry to a handler, and restored from the frame by `sigreturn`. Each value is
//! what a real arm64 kernel gives (`scratch` run, 2026-09-30).
//!
//! The cache operations are checked against `DC CVAU`, which this emulator
//! already makes a no-op: a persistence clean must behave like it on the same
//! address, fault or not, whatever the kernel does about it.

use guest_tests::{Harness, check};
use std::arch::asm;

fn mrs_dit() -> u64 {
    let v: u64;
    unsafe { asm!(".arch_extension dit", "mrs {}, S3_3_C4_C2_5", out(reg) v) };
    v
}
fn msr_dit_reg(v: u64) {
    unsafe { asm!(".arch_extension dit", "msr S3_3_C4_C2_5, {}", in(reg) v) };
}

const BIT24: u64 = 1 << 24;

static mut SEEN: [u64; 2] = [0; 2];

extern "C" fn handler(_s: i32, _i: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    unsafe {
        let uc = ctx.cast::<libc::ucontext_t>();
        SEEN[0] = mrs_dit();
        SEEN[1] = (*uc).uc_mcontext.pstate;
        // The frame is what sigreturn restores: turn DIT on in it.
        (*uc).uc_mcontext.pstate |= BIT24;
    }
}

/// The signal number a child died of running `f`, or 0.
fn signal_of(f: impl FnOnce()) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    if libc::WIFSIGNALED(st) { libc::WTERMSIG(st) } else { 0 }
}

macro_rules! dc {
    ($enc:literal, $addr:expr) => {
        unsafe { asm!(concat!(".inst ", $enc), in("x9") $addr as u64) }
    };
}

fn main() {
    // `dit_dcpop exec-child`: what a fresh image sees.
    if std::env::args().nth(1).as_deref() == Some("exec-child") {
        std::process::exit(i32::from(mrs_dit() != 0));
    }

    let mut h = Harness::new();

    h.group("dit-moves");
    check!(h, mrs_dit() == 0, "starts clear: {:#x}", mrs_dit());
    unsafe { asm!(".arch_extension dit", "msr dit, #1") };
    check!(h, mrs_dit() == BIT24, "msr dit, #1: {:#x}", mrs_dit());
    unsafe { asm!(".arch_extension dit", "msr dit, #0") };
    check!(h, mrs_dit() == 0, "msr dit, #0: {:#x}", mrs_dit());
    msr_dit_reg(BIT24);
    check!(h, mrs_dit() == BIT24, "msr dit, x (bit 24): {:#x}", mrs_dit());
    msr_dit_reg(0);
    check!(h, mrs_dit() == 0, "msr dit, x (zero): {:#x}", mrs_dit());
    msr_dit_reg(u64::MAX);
    check!(h, mrs_dit() == BIT24, "msr dit, all ones reads back only bit 24: {:#x}", mrs_dit());
    msr_dit_reg(!BIT24);
    check!(h, mrs_dit() == 0, "only bit 24 counts: {:#x}", mrs_dit());
    unsafe { asm!(".arch_extension dit", "msr S3_3_C4_C2_5, xzr") };
    check!(h, mrs_dit() == 0, "msr dit, xzr");

    h.group("dit-in-signal-frames");
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    }
    // Interrupted with DIT set: the handler runs with it set, the frame has it,
    // and it is still set afterwards.
    msr_dit_reg(BIT24);
    unsafe { libc::raise(libc::SIGUSR1) };
    let seen = unsafe { SEEN };
    check!(h, seen[0] == BIT24, "handler entered with DIT set sees it: {:#x}", seen[0]);
    check!(h, seen[1] & BIT24 == BIT24, "the frame's pstate has bit 24: {:#x}", seen[1]);
    check!(h, mrs_dit() == BIT24, "still set after the handler: {:#x}", mrs_dit());
    // Interrupted with DIT clear: the handler sees it clear, the frame has it
    // clear, and the handler's change to the frame is what sigreturn applies.
    msr_dit_reg(0);
    unsafe { libc::raise(libc::SIGUSR1) };
    let seen = unsafe { SEEN };
    check!(h, seen[0] == 0, "handler entered with DIT clear sees it: {:#x}", seen[0]);
    check!(h, seen[1] & BIT24 == 0, "the frame's pstate has bit 24 clear: {:#x}", seen[1]);
    check!(h, mrs_dit() == BIT24, "sigreturn applies the frame's DIT: {:#x}", mrs_dit());

    h.group("dit-across-fork-and-exec");
    msr_dit_reg(BIT24);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::_exit(i32::from(mrs_dit() != BIT24)) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "a forked child inherits DIT");
    let exe = std::env::args().next().unwrap_or_default();
    let status = std::process::Command::new(&exe).arg("exec-child").status();
    check!(h, status.map(|s| s.success()).unwrap_or(false), "an exec'd image starts with DIT clear");
    msr_dit_reg(0);

    h.group("dcpop-dcpodp");
    // A mapped page: every cache operation, DC CVAP and CVADP included, runs.
    let page = unsafe {
        libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    } as usize;
    for (name, sig) in [
        ("dc cvac", signal_of(|| dc!("0xd50b7a29", page))),
        ("dc cvau", signal_of(|| dc!("0xd50b7b29", page))),
        ("dc civac", signal_of(|| dc!("0xd50b7e29", page))),
        ("dc cvap", signal_of(|| dc!("0xd50b7c29", page))),
        ("dc cvadp", signal_of(|| dc!("0xd50b7d29", page))),
    ] {
        check!(h, sig == 0, "{name} on a mapped page runs (signal {sig})");
    }
    // An address nothing maps: whatever DC CVAU does, DC CVAP and DC CVADP do.
    let unmapped = 0x10usize;
    let cvau = signal_of(|| dc!("0xd50b7b29", unmapped));
    let cvap = signal_of(|| dc!("0xd50b7c29", unmapped));
    let cvadp = signal_of(|| dc!("0xd50b7d29", unmapped));
    println!("  on an unmapped address: cvau signal {cvau}, cvap {cvap}, cvadp {cvadp}");
    check!(h, cvap == cvau, "dc cvap faults as dc cvau does ({cvap} vs {cvau})");
    check!(h, cvadp == cvau, "dc cvadp faults as dc cvau does ({cvadp} vs {cvau})");

    std::process::exit(h.finish());
}
