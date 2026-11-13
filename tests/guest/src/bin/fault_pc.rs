//! A fault taken inside a block must name the faulting instruction, and a
//! handler that repairs the page and returns must resume there.
//!
//! The JIT's ordinary load/store miss path records the threaded-code cursor in
//! `cpu->fault_code_pc`, and the dispatcher turns it back into a guest pc. Every
//! gadget with its own segfault exit (cross-page accesses, LSE atomics,
//! exclusives, LD2-4/ST2-4) left it at zero, so the pc fell back to the block's
//! start and `rt_sigreturn` re-ran everything before the fault.
//!
//! Each case runs this, in a fresh child, with `x0` aimed at a PROT_NONE page:
//!
//! ```text
//!   +0  ldr x9, [x6]      counter++, a store the re-run would repeat
//!   +4  add x9, x9, #1
//!   +8  str x9, [x6]
//!  +12  <the faulting instruction>
//!  +16  ret
//! ```
//!
//! The handler records the pc, makes the page readable and writable, and
//! returns. A correct resume leaves the counter at 1 and the pc at +12, and
//! `si_addr` names the first byte of the PROT_NONE page (a real arm64 kernel
//! does, for the cross-page cases too).

use guest_tests::{Harness, check};
use std::sync::atomic::{AtomicU64, Ordering};

const PAGE: usize = 4096;
const FAULT_AT: u64 = 12;

static FAULT_PC: AtomicU64 = AtomicU64::new(0);
static FAULT_ADDR: AtomicU64 = AtomicU64::new(0);
static DATA: AtomicU64 = AtomicU64::new(0);

extern "C" fn on_segv(_sig: i32, info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    unsafe {
        FAULT_PC.store((*ctx.cast::<libc::ucontext_t>()).uc_mcontext.pc, Ordering::SeqCst);
        FAULT_ADDR.store((*info).si_addr() as u64, Ordering::SeqCst);
        let data = DATA.load(Ordering::SeqCst) as *mut libc::c_void;
        // A second fault in the same case means the repair did not take; stop
        // rather than loop.
        if libc::mprotect(data, 2 * PAGE, libc::PROT_READ | libc::PROT_WRITE) != 0 {
            libc::_exit(3);
        }
    }
}

struct Case {
    name: &'static str,
    insn: u32,
    /// Where `x0` points, relative to the start of the PROT_NONE page.
    offset: isize,
}

/// Run one case in a child; it prints its line and exits 0 when both hold.
fn run(c: &Case) -> bool {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::_exit(child(c)) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    if !libc::WIFEXITED(st) {
        println!("  {}: child died, signal {}", c.name, libc::WTERMSIG(st));
        return false;
    }
    libc::WEXITSTATUS(st) == 0
}

fn child(c: &Case) -> i32 {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_segv as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());

        let code = libc::mmap(std::ptr::null_mut(), PAGE,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
        // Two data pages: the first readable and writable, the second
        // PROT_NONE, so an access at a negative offset straddles them.
        let data = libc::mmap(std::ptr::null_mut(), 2 * PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
        let counter = libc::mmap(std::ptr::null_mut(), PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
        if code == libc::MAP_FAILED || data == libc::MAP_FAILED || counter == libc::MAP_FAILED {
            return 7;
        }
        let none = data.cast::<u8>().add(PAGE);
        if libc::mprotect(none.cast(), PAGE, libc::PROT_NONE) != 0 {
            return 7;
        }
        DATA.store(data as u64, Ordering::SeqCst);

        let words = [0xf940_00c9u32, 0x9100_0529, 0xf900_00c9, c.insn, 0xd65f_03c0];
        std::ptr::copy_nonoverlapping(words.as_ptr(), code.cast::<u32>(), words.len());
        // Fresh code on real hardware needs the caches told; without this one
        // run in three took SIGILL on a real kernel.
        core::arch::asm!("dc cvau, {p}", "dsb ish", "ic ivau, {p}", "dsb ish", "isb", p = in(reg) code);

        let f: extern "C" fn(*mut u8, u64, u64, u64, u64, u64, *mut u64) =
            std::mem::transmute(code);
        let target = none.offset(c.offset);
        f(target, 0, 0, 0, 0, 0, counter.cast());

        let count = *counter.cast::<u64>();
        let pc = FAULT_PC.load(Ordering::SeqCst).wrapping_sub(code as u64);
        let addr = FAULT_ADDR.load(Ordering::SeqCst).wrapping_sub(none as u64) as i64;
        println!("  {}: count={count} pc=+{pc} si_addr=none{addr:+}", c.name);
        i32::from(!(count == 1 && pc == FAULT_AT && addr == 0))
    }
}

fn main() {
    let mut h = Harness::new();
    h.group("fault-pc-names-the-instruction");

    let cases = [
        // The control: the inline miss path, which does record the cursor.
        Case { name: "ldr", insn: 0xf940_0001, offset: 0 },
        Case { name: "str", insn: 0xf900_0001, offset: 0 },
        Case { name: "ldr-crosspage", insn: 0xf940_0001, offset: -4 },
        Case { name: "str-crosspage", insn: 0xf900_0001, offset: -4 },
        Case { name: "ldadd", insn: 0xf821_0002, offset: 0 },
        Case { name: "cas", insn: 0xc8a1_7c02, offset: 0 },
        Case { name: "casp", insn: 0x4822_7c04, offset: 0 },
        Case { name: "ldxr", insn: 0xc85f_7c01, offset: 0 },
        Case { name: "ldxp", insn: 0xc87f_0801, offset: 0 },
        Case { name: "ld4", insn: 0x4c40_0000, offset: 0 },
        Case { name: "ld4-crosspage", insn: 0x4c40_0000, offset: -16 },
        // st2 {v0.16b, v1.16b}, [x0] and st4 {v0.16b-v3.16b}, [x0]
        Case { name: "st2", insn: 0x4c00_8000, offset: 0 },
        Case { name: "st4", insn: 0x4c00_0000, offset: 0 },
        Case { name: "st4-crosspage", insn: 0x4c00_0000, offset: -16 },
        // stxr w2, x1, [x0] and stxp w3, x1, x2, [x0], with no monitor armed
        Case { name: "stxr", insn: 0xc802_7c01, offset: 0 },
        Case { name: "stxp", insn: 0xc823_0801, offset: 0 },
        // FEAT_LRCPC/LRCPC2: ldapr x1, [x0]; ldapur x1, [x0]; ldapursw x1,
        // [x0]; stlur x1, [x0]; stlurb w1, [x0]. Never at a page seam: an
        // ordered access that crosses a 16-byte granule raises SIGBUS on a
        // kernel with FEAT_LSE2.
        Case { name: "ldapr", insn: 0xf8bf_c001, offset: 0 },
        Case { name: "ldapur", insn: 0xd940_0001, offset: 0 },
        Case { name: "ldapursw", insn: 0x9980_0001, offset: 0 },
        Case { name: "stlur", insn: 0xd900_0001, offset: 0 },
        Case { name: "stlurb", insn: 0x1900_0001, offset: 0 },
    ];
    for c in &cases {
        let ok = run(c);
        check!(h, ok, "{}: resumes at the faulting instruction, earlier stores once, si_addr exact", c.name);
    }
    std::process::exit(h.finish());
}
