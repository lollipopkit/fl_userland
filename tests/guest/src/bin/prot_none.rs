//! A PROT_NONE page must fault on every access, from the guest's own
//! instructions as well as through a syscall.
//!
//! `mem_ptr` refuses one now, which covers the syscall path. The JIT reaches
//! guest memory through the software TLB instead, and that is a separate
//! decision about the same page.

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicBool, Ordering};

static FAULTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_segv(_sig: i32) {
    FAULTED.store(true, Ordering::SeqCst);
    // Nothing here can resume the faulting instruction, so leave by _exit with
    // a status the parent reads. Longjmp out of a signal handler needs
    // sigsetjmp, which is not reachable from stable Rust.
    unsafe { libc::_exit(42) };
}

/// Run `f` in a child, and report how it ended.
fn in_child(f: impl FnOnce()) -> (bool, i32, i32) {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_segv as *const () as usize;
            libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
        }
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

    h.group("guest-load-from-prot-none");
    // The child maps a PROT_NONE page and loads from it. On Linux that is
    // SIGSEGV: either the handler runs (exit 42) or the process dies of the
    // signal. Returning normally means the load succeeded.
    let (exited, status, sig) = in_child(|| {
        let p = unsafe {
            libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_NONE,
                       libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        if p == libc::MAP_FAILED {
            unsafe { libc::_exit(7) };
        }
        let v = unsafe { std::ptr::read_volatile(p.cast::<u8>()) };
        std::hint::black_box(v);
        // Reached only if the load did not fault.
        unsafe { libc::_exit(0) };
    });
    check!(h, !(exited && status == 0),
        "a load from a PROT_NONE page faults: exited={exited} status={status} sig={sig}");
    check!(h, status != 7, "the PROT_NONE mapping itself succeeded");

    h.group("guest-store-to-prot-none");
    let (exited2, status2, sig2) = in_child(|| {
        let p = unsafe {
            libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_NONE,
                       libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        unsafe { std::ptr::write_volatile(p.cast::<u8>(), 1) };
        unsafe { libc::_exit(0) };
    });
    check!(h, !(exited2 && status2 == 0),
        "a store to a PROT_NONE page faults: exited={exited2} status={status2} sig={sig2}");

    h.group("mprotect-none-revokes");
    // The harder case: a page that was readable and is then taken away. The
    // guest has already touched it, so any cached translation for it has to be
    // dropped.
    let (exited3, status3, sig3) = in_child(|| {
        let p = unsafe {
            libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE,
                       libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        unsafe { std::ptr::write_volatile(p.cast::<u8>(), 0x5A) };
        let v = unsafe { std::ptr::read_volatile(p.cast::<u8>()) };
        std::hint::black_box(v);
        unsafe { libc::mprotect(p, 4096, libc::PROT_NONE) };
        let v2 = unsafe { std::ptr::read_volatile(p.cast::<u8>()) };
        std::hint::black_box(v2);
        unsafe { libc::_exit(0) };
    });
    check!(h, !(exited3 && status3 == 0),
        "a read after mprotect(PROT_NONE) faults: exited={exited3} status={status3} sig={sig3}");

    h.group("null-deref-faults");
    // A read of an absent page raised no signal either: the fault handler
    // decoded the load, set its destination register to 0 and advanced the PC.
    // The program carried on with wrong data, and anything built on SIGSEGV --
    // a runtime's nil check, a JIT's guard page, stack-overflow detection --
    // silently stopped working.
    let (exited5, status5, sig5) = in_child(|| {
        let v = unsafe { std::ptr::read_volatile(0x10 as *const u64) };
        std::hint::black_box(v);
        unsafe { libc::_exit(0) };
    });
    check!(h, !(exited5 && status5 == 0),
        "reading a null pointer faults: exited={exited5} status={status5} sig={sig5}");

    h.group("still-usable");
    // The control: PROT_NONE then mprotect back to readable must work, or the
    // checks above are satisfied by a mapping that never works at all.
    let (exited4, status4, _) = in_child(|| {
        let p = unsafe {
            libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_NONE,
                       libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        unsafe { libc::mprotect(p, 4096, libc::PROT_READ | libc::PROT_WRITE) };
        unsafe { std::ptr::write_volatile(p.cast::<u8>(), 0x33) };
        let v = unsafe { std::ptr::read_volatile(p.cast::<u8>()) };
        unsafe { libc::_exit(if v == 0x33 { 0 } else { 9 }) };
    });
    check!(h, exited4 && status4 == 0,
        "mprotect back to RW makes it usable: exited={exited4} status={status4}");

    std::process::exit(h.finish());
}
