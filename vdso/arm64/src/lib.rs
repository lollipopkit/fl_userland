//! The AArch64 vDSO the emulator maps into every guest process.
//!
//! A small shared object a real kernel places in a process's address space so
//! that a few calls need no context switch. There is no fast path to offer
//! here — the emulator's `svc #0` *is* the syscall — so each of these is a
//! wrapper, and what matters is that the object exists with the right symbols
//! and versions: glibc and musl both look for `__kernel_*@LINUX_2.6.39` through
//! `AT_SYSINFO_EHDR`, and a process whose `rt_sigreturn` trampoline is not
//! there cannot return from a signal handler.
//!
//! `vdso/arm64/vdso.c` until 2026-09-09, built by whichever clang the machine
//! had that could target `aarch64-linux-gnu`. When there was none, meson
//! `touch`ed an **empty file** and said so in a message nobody reads — so the
//! emulator embedded zero bytes and the failure surfaced as a guest that could
//! not return from a signal. rustc and `rust-lld` need nothing installed beyond
//! the target, which `tests/guest` already requires.
//!
//! # Freestanding, and linked by hand
//!
//! `no_std` with no libc at all: this is compiled to an *object* and linked by
//! `rust-lld` against `vdso.lds`, because a `cdylib` would bring in crt objects
//! and a C library that has no business in a guest's address space. That is
//! what `-nostdlib -shared -Wl,-T` did for the C.

#![no_std]

use core::arch::{asm, global_asm};

/// Unreachable: nothing here allocates, indexes or unwraps. It exists because
/// `no_std` requires one.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// AArch64 Linux syscall numbers.
const NR_CLOCK_GETTIME: i64 = 113;
const NR_CLOCK_GETRES: i64 = 114;
const NR_GETTIMEOFDAY: i64 = 169;

#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
pub struct Timezone {
    pub tz_minuteswest: i32,
    pub tz_dsttime: i32,
}

/// `svc #0` with the number in `x8` and two arguments, which is every call
/// here.
///
/// # Safety
/// The arguments are whatever the syscall requires; the two pointers below are
/// the caller's.
unsafe fn syscall2(n: i64, a0: i64, a1: i64) -> i64 {
    let ret: i64;
    // SAFETY: the AArch64 Linux syscall convention. `nostack` because the
    // kernel does not touch this thread's stack, and the emulator's SVC gadget
    // does not either.
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") a0 => ret,
            in("x1") a1,
            in("x8") n,
            options(nostack),
        );
    }
    ret
}

/// # Safety
/// `ts` is a writable `struct timespec` in the caller's address space.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __kernel_clock_gettime(clk: i32, ts: *mut Timespec) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { syscall2(NR_CLOCK_GETTIME, i64::from(clk), ts as i64) as i32 }
}

/// # Safety
/// `tv` and `tz` are the caller's, and either may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __kernel_gettimeofday(tv: *mut Timeval, tz: *mut Timezone) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { syscall2(NR_GETTIMEOFDAY, tv as i64, tz as i64) as i32 }
}

/// # Safety
/// As [`__kernel_clock_gettime`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __kernel_clock_getres(clk: i32, res: *mut Timespec) -> i32 {
    // SAFETY: the caller's contract.
    unsafe { syscall2(NR_CLOCK_GETRES, i64::from(clk), res as i64) as i32 }
}

// The signal-return trampoline, which stays assembly and must.
//
// The kernel sets a handler's return address to this, so what runs is these two
// instructions and nothing else: a compiler-generated prologue would move the
// stack pointer away from the signal frame `rt_sigreturn` restores from. It
// does not return, so there is no epilogue either.
//
// `vdso/arm64/vdso.S` until 2026-09-09. The three `__vdso_*_asm` wrappers
// beside it, described there as "fallback implementations if the C versions
// can't be used", are gone: the version script's `local: *` hid them, so
// nothing could ever have called one.
global_asm!(
    r#"
.text
.globl __kernel_rt_sigreturn
.type __kernel_rt_sigreturn, @function
.align 4
__kernel_rt_sigreturn:
    mov x8, #139           // __NR_rt_sigreturn
    svc #0
.size __kernel_rt_sigreturn, . - __kernel_rt_sigreturn
"#
);
