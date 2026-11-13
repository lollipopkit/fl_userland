//! The guest's FPCR rounding mode, and whether it reaches the arithmetic.
//!
//! `msr fpcr` used to record the value in cpu_state and stop, so `fegetround`
//! agreed with what was set and every instruction after it rounded to nearest
//! regardless. The gadget writes the host register now — and cpu_state's copy
//! also changes from outside the gadgets, when a thread starts, when execve
//! clears it and when sigreturn restores it, so those are checked too.
//!
//! 1.0/3.0 is 0x3FD5555555555555 rounded to nearest and one ulp higher,
//! 0x3FD5555555555556, rounded toward +inf. If the mode is recorded but not
//! applied, fegetround() agrees with what was set and the quotient does not.

unsafe extern "C" {
    fn fesetround(mode: i32) -> i32;
    fn fegetround() -> i32;
}

// aarch64 musl: FE_TONEAREST 0, FE_UPWARD 0x400000, FE_DOWNWARD 0x800000,
// FE_TOWARDZERO 0xc00000 — the FPCR RMode field in place.
const FE_TONEAREST: i32 = 0;
const FE_UPWARD: i32 = 0x400000;
const FE_DOWNWARD: i32 = 0x800000;

#[inline(never)]
fn third(one: f64, three: f64) -> f64 {
    std::hint::black_box(one) / std::hint::black_box(three)
}

use guest_tests::{Harness, check};

fn one_third_bits() -> u64 {
    third(1.0, 3.0).to_bits()
}

const NEAREST: u64 = 0x3FD5555555555555;
const UPWARD: u64 = 0x3FD5555555555556;

fn main() -> std::process::ExitCode {
    // The execve child: it must have been reset to round-to-nearest.
    if std::env::args().nth(1).as_deref() == Some("child") {
        return std::process::ExitCode::from(u8::from(one_third_bits() != NEAREST));
    }

    let mut h = Harness::new();

    h.group("rounding");
    for (name, mode, want) in [
        ("nearest", FE_TONEAREST, 0x3FD5555555555555u64),
        ("upward", FE_UPWARD, 0x3FD5555555555556),
        ("downward", FE_DOWNWARD, 0x3FD5555555555555),
    ] {
        unsafe { fesetround(mode) };
        check!(h, unsafe { fegetround() } == mode, "fegetround after setting {name}");
        let q = one_third_bits();
        check!(h, q == want, "1/3 in {name}: {q:#018x}, wanted {want:#018x}");
    }

    // A thread starts on a fresh host thread, whose FP control begins at the
    // architectural default while cpu_state carries the parent's.
    h.group("threads");
    unsafe { fesetround(FE_UPWARD) };
    let inherited = std::thread::spawn(one_third_bits).join().unwrap_or(0);
    check!(
        h,
        inherited == UPWARD,
        "a new thread inherits the rounding mode: {inherited:#018x}"
    );

    // A signal handler runs with it, and what it changes must not leak back
    // out: sigreturn restores the frame's copy.
    h.group("signals");
    unsafe {
        extern "C" fn handler(_: libc::c_int) {
            unsafe { fesetround(FE_DOWNWARD) };
        }
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
        fesetround(FE_UPWARD);
        libc::raise(libc::SIGUSR1);
    }
    let after = one_third_bits();
    check!(
        h,
        after == UPWARD,
        "the mode survives a handler that changed it: {after:#018x}"
    );

    // execve resets it, in the hardware as well as in cpu_state. Checked by
    // the child below, which re-runs this binary with an argument.
    h.group("execve");
    unsafe { fesetround(FE_UPWARD) };
    let exe = std::env::args().next().unwrap_or_default();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let c = std::ffi::CString::new(exe).unwrap();
        let arg = c"child";
        unsafe {
            libc::execl(c.as_ptr(), c.as_ptr(), arg.as_ptr(), std::ptr::null::<i8>());
            libc::_exit(127);
        }
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    check!(
        h,
        (status >> 8) & 0xff == 0,
        "after execve the new image rounds to nearest (child status {})",
        (status >> 8) & 0xff
    );

    std::process::ExitCode::from(h.finish() as u8)
}
