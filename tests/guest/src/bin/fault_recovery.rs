//! A null dereference must raise SIGSEGV wherever the code happens to live.
//!
//! `kernel/calls.c`'s fault handler carried a recovery that unwound the guest's
//! frame pointers, zeroed registers and resumed — gated on PC ranges taken from
//! one node build (`0xee270000`, `0xee7e0000`, `0xee3ef000`, `0xeee00000`).
//! Those are addresses, not identities. This program maps four pages into one
//! of them, writes three instructions there, and calls them; nothing about it
//! is node.
//!
//! The mmap hole search grows downward from `0xefffd000`, so a guest with
//! enough shared libraries reaches these addresses without trying —
//! `ld-musl-aarch64.so.1` alone lands at `0xefe4a000`.
//!
//! **This does not discriminate the gate**, and that is deliberate rather than
//! an oversight. With `IUL_V8_FAULT_RECOVERY=1` the recovery *does* fire here
//! — `V8_ZONE_RECOVER pc=0xee280000`, twice — but it then gives up and the
//! signal is delivered anyway, so the guest sees `SIGSEGV` either way. What
//! this file is, is a guard that a null dereference keeps raising `SIGSEGV`
//! wherever the code happens to live. The evidence for the gate itself is the
//! trace, and it is in the changelog.

use guest_tests::{Harness, check};

/// Inside `0xee270000..0xee290000`, one of the ranges the recovery keyed on.
const CODE_AT: usize = 0xee28_0000;

/// ```text
///   d2800000  mov x0, #0
///   f9400000  ldr x0, [x0]     <- faults
///   d65f03c0  ret
/// ```
const DEREF_NULL: [u32; 3] = [0xd280_0000, 0xf940_0000, 0xd65f_03c0];

fn run_in_child(f: impl FnOnce()) -> (bool, i32, i32) {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    (
        libc::WIFEXITED(st),
        if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 },
        if libc::WIFSIGNALED(st) { libc::WTERMSIG(st) } else { 0 },
    )
}

fn main() {
    let mut h = Harness::new();
    h.group("null-deref-in-a-recovered-address-range");

    let (exited, status, sig) = run_in_child(|| unsafe {
        let p = libc::mmap(
            CODE_AT as *mut libc::c_void,
            0x4000,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        );
        if p == libc::MAP_FAILED || p as usize != CODE_AT {
            libc::_exit(7);
        }
        std::ptr::copy_nonoverlapping(DEREF_NULL.as_ptr(), p.cast::<u32>(), DEREF_NULL.len());
        let f: extern "C" fn() -> u64 = std::mem::transmute(p);
        let v = f();
        // Only reached if the fault was recovered rather than delivered.
        libc::_exit(if v == 0 { 8 } else { 9 });
    });

    check!(h, status != 7, "the fixed mapping was placed where asked");
    check!(h, !(exited && (status == 8 || status == 9)),
        "a null dereference at {CODE_AT:#x} is not silently recovered: \
exited={exited} status={status} sig={sig}");
    check!(h, sig == libc::SIGSEGV || sig == libc::SIGBUS,
        "it raises SIGSEGV: sig={sig}");

    h.group("and-the-same-code-elsewhere");
    // The control: identical instructions at an address outside every range
    // must behave identically. If they did not, the difference would be the
    // address rather than the fault.
    let (exited2, status2, sig2) = run_in_child(|| unsafe {
        let p = libc::mmap(
            0x3000_0000 as *mut libc::c_void,
            0x4000,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            libc::_exit(7);
        }
        std::ptr::copy_nonoverlapping(DEREF_NULL.as_ptr(), p.cast::<u32>(), DEREF_NULL.len());
        let f: extern "C" fn() -> u64 = std::mem::transmute(p);
        std::hint::black_box(f());
        libc::_exit(8);
    });
    check!(h, status2 != 7, "the control mapping was placed");
    check!(h, sig2 == libc::SIGSEGV || sig2 == libc::SIGBUS,
        "the same code outside the ranges also raises SIGSEGV: exited={exited2} status={status2} sig={sig2}");

    std::process::exit(h.finish());
}
