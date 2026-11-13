//! `RNDR` and `RNDRRS` are illegal instructions here, as on a CPU without
//! FEAT_RNG -- which is the CPU this emulator describes: ID_AA64ISAR0's RNDR
//! field is 0 and there is no HWCAP2_RNG.
//!
//! They answered 0 with Z set, "no random number", until 2026-10-18. A real
//! arm64 kernel on a CPU that does not advertise RNG kills the reader with
//! SIGILL, and that is what a program probing for the register without
//! reading the ID register first gets there.

use guest_tests::{Harness, check};
use std::arch::asm;

/// The signal a child dies of reading the register, or 0.
fn signal_of_read(rndrrs: bool) -> i32 {
    // SAFETY: fork in a single-threaded test program.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let v: u64;
        // SAFETY: a system register read; the fault, if any, ends the child.
        unsafe {
            if rndrrs {
                asm!("mrs {v}, S3_3_C2_C4_1", v = out(reg) v);
            } else {
                asm!("mrs {v}, S3_3_C2_C4_0", v = out(reg) v);
            }
        }
        std::hint::black_box(v);
        // SAFETY: async-signal-safe.
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    // SAFETY: our child.
    unsafe { libc::waitpid(pid, &mut st, 0) };
    if libc::WIFSIGNALED(st) { libc::WTERMSIG(st) } else { 0 }
}

fn main() {
    let mut h = Harness::new();
    h.group("rndr");
    let s = signal_of_read(false);
    check!(h, s == libc::SIGILL, "RNDR: signal {s}");
    let s = signal_of_read(true);
    check!(h, s == libc::SIGILL, "RNDRRS: signal {s}");
    std::process::exit(h.finish());
}
