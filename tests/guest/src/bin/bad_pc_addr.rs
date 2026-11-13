//! A jump to an address no instruction can be fetched from is a `SIGSEGV`
//! whose `si_addr` is that address.
//!
//! The dispatch loop refuses a pc with any of its top sixteen bits set, and a
//! null one, before compiling from it -- and recorded the address on the
//! caller's CPU just before copying the loop's own CPU over it, so the handler
//! was told an address the program never used.

use guest_tests::{Harness, check};
use std::arch::asm;
use std::sync::atomic::{AtomicI32, Ordering};

/// Where the handler reports: the write end of the parent's pipe.
static REPORT: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_segv(_s: i32, info: *mut libc::siginfo_t, _c: *mut libc::c_void) {
    // SAFETY: the kernel's siginfo for this signal; `write` and `_exit` are
    // async-signal-safe.
    unsafe {
        let addr = (*info).si_addr() as u64;
        libc::write(REPORT.load(Ordering::SeqCst), (&raw const addr).cast(), 8);
        libc::_exit(0);
    }
}

/// The `si_addr` a child reports after branching to `target`, or `None` if it
/// did not fault.
fn fault_address(target: u64) -> Option<u64> {
    let mut pipe = [0; 2];
    // SAFETY: a two-element array.
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    // SAFETY: fork in a single-threaded test program.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: a handler that only stores and exits.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_segv as *const () as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
            REPORT.store(pipe[1], Ordering::SeqCst);
            asm!("blr {t}", t = in(reg) target, clobber_abi("C"));
        }
        // SAFETY: async-signal-safe.
        unsafe { libc::_exit(1) };
    }
    // SAFETY: as above.
    unsafe { libc::close(pipe[1]) };
    let mut v = [0u8; 8];
    // SAFETY: eight writable bytes.
    let n = unsafe { libc::read(pipe[0], v.as_mut_ptr().cast(), 8) };
    let mut st = 0;
    // SAFETY: our child.
    unsafe { libc::waitpid(pid, &mut st, 0) };
    (n == 8).then(|| u64::from_ne_bytes(v))
}

extern "C" fn returns_seven() -> u64 {
    7
}

/// Whether a branch to `f` with `tag` in the top byte runs `f`: whether the top
/// byte is ignored for instruction addresses (TBI), as it is for data.
fn tagged_call_runs(tag: u64) -> Option<u64> {
    // SAFETY: fork in a single-threaded test program.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let target = (returns_seven as *const () as u64) | (tag << 56);
        let r: u64;
        // SAFETY: a call to a function that takes nothing, through a tagged
        // address; a fault ends the child.
        unsafe { asm!("blr {t}", t = in(reg) target, lateout("x0") r, clobber_abi("C")) };
        // SAFETY: async-signal-safe.
        unsafe { libc::_exit(r as i32) };
    }
    let mut st = 0;
    // SAFETY: our child.
    unsafe { libc::waitpid(pid, &mut st, 0) };
    libc::WIFEXITED(st).then(|| libc::WEXITSTATUS(st) as u64)
}

static WORD: u64 = 0x1234_5678;

/// The `si_addr` a child reports after loading from `addr`, or `None` if the
/// load did not fault.
fn load_fault_address(addr: u64) -> Option<u64> {
    let mut pipe = [0; 2];
    // SAFETY: a two-element array.
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    // SAFETY: fork in a single-threaded test program.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: a handler that only writes and exits.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_segv as *const () as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
            REPORT.store(pipe[1], Ordering::SeqCst);
            let v: u64;
            asm!("ldr {v}, [{a}]", a = in(reg) addr, v = out(reg) v);
            std::hint::black_box(v);
            libc::_exit(1);
        }
    }
    // SAFETY: as above.
    unsafe { libc::close(pipe[1]) };
    let mut v = [0u8; 8];
    // SAFETY: eight writable bytes.
    let n = unsafe { libc::read(pipe[0], v.as_mut_ptr().cast(), 8) };
    let mut st = 0;
    // SAFETY: our child.
    unsafe { libc::waitpid(pid, &mut st, 0) };
    (n == 8).then(|| u64::from_ne_bytes(v))
}

fn main() {
    let mut h = Harness::new();
    h.group("bad-pc");
    let tagged = 0x0001_0000_0000_4000u64;
    let got = fault_address(tagged);
    check!(h, got == Some(tagged), "a non-canonical pc: si_addr {got:#x?}");
    // The same with low bits that name real code: a page table asked about it
    // by its low bits alone would call it fetchable.
    let aliased = 0x0001_0000_0000_0000 | returns_seven as *const () as u64;
    let got = fault_address(aliased);
    check!(h, got == Some(aliased), "a non-canonical pc over mapped code: si_addr {got:#x?}");
    let got = fault_address(0);
    check!(h, got == Some(0), "a null pc: si_addr {got:#x?}");
    // A *load* above the address space faults there too, rather than reading
    // the page its low bits name.
    let addr = 0x0001_0000_0000_0000 | (&raw const WORD as u64);
    let got = load_fault_address(addr);
    check!(h, got == Some(addr), "a load from a non-canonical address: si_addr {got:#x?}");
    // And a load through a pointer tagged in its top byte reads the word: the
    // byte is ignored for data as for instructions.
    let tagged_word = (0x5au64 << 56) | (&raw const WORD as u64);
    let v: u64;
    // SAFETY: a load from `WORD` through a tagged pointer.
    unsafe { asm!("ldr {v}, [{a}]", a = in(reg) tagged_word, v = out(reg) v) };
    check!(h, v == WORD, "a load through a top-byte-tagged pointer: {v:#x}");
    // A post- and a pre-indexed load through that pointer write the base back
    // whole, tag included: only the access ignores the top byte.
    let (mut post, mut pre) = (tagged_word, tagged_word - 8);
    let (a, b): (u64, u64);
    // SAFETY: both load `WORD` through a tagged pointer.
    unsafe {
        asm!("ldr {v}, [{p}], #8", p = inout(reg) post, v = out(reg) a);
        asm!("ldr {v}, [{p}, #8]!", p = inout(reg) pre, v = out(reg) b);
    }
    check!(h, a == WORD && post == tagged_word + 8, "post-index writeback keeps the tag: {post:#x}");
    check!(h, b == WORD && pre == tagged_word, "pre-index writeback keeps the tag: {pre:#x}");
    let ran = tagged_call_runs(0x5a);
    check!(h, ran == Some(7), "a call through a top-byte-tagged address: {ran:?}");
    std::process::exit(h.finish());
}
