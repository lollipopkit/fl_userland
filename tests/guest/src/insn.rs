//! Run one instruction on a whole register state, in a stub at a fixed
//! address: x0-x30, NZCV, q0-q31, FPSR and FPCR are loaded from a [`State`],
//! the instruction runs, and they are stored back. An instruction that raises
//! SIGILL is skipped by the handler and reported as such.
//!
//! Fixed addresses keep ADR, ADRP and reads of SP identical on every kernel,
//! so a state after can be compared byte for byte against a real one. The
//! stub runs on SP, so the instruction must not write it.

use std::sync::atomic::{AtomicBool, Ordering};

const CODE: usize = 0x3000_0000;
const STACK: usize = 0x3100_0000;
const STACK_LEN: usize = 0x20000;
/// Where SP points while the case runs: signal frames go below it.
const STATE: usize = STACK + 0x10000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct State {
    pub x: [u64; 31],
    pub nzcv: u64,
    pub q: [[u64; 2]; 32],
    pub fpsr: u64,
    pub fpcr: u64,
    saved_sp: u64,
    _pad: u64,
    callee: [u64; 20],
}

core::arch::global_asm!(
    ".global insn_stub_start", ".global insn_stub_slot", ".global insn_stub_end",
    ".p2align 2",
    "insn_stub_start:",
    "add x9, x0, #800",
    "stp x19, x20, [x9, #0]", "stp x21, x22, [x9, #16]", "stp x23, x24, [x9, #32]",
    "stp x25, x26, [x9, #48]", "stp x27, x28, [x9, #64]", "stp x29, x30, [x9, #80]",
    "stp d8, d9, [x9, #96]", "stp d10, d11, [x9, #112]",
    "stp d12, d13, [x9, #128]", "stp d14, d15, [x9, #144]",
    "mov x1, sp", "str x1, [x0, #784]", "mov sp, x0",
    "ldr x1, [sp, #248]", "msr nzcv, x1",
    "ldr x1, [sp, #776]", "msr fpcr, x1",
    "ldr x1, [sp, #768]", "msr fpsr, x1",
    "ldp q0, q1, [sp, #256]", "ldp q2, q3, [sp, #288]", "ldp q4, q5, [sp, #320]",
    "ldp q6, q7, [sp, #352]", "ldp q8, q9, [sp, #384]", "ldp q10, q11, [sp, #416]",
    "ldp q12, q13, [sp, #448]", "ldp q14, q15, [sp, #480]", "ldp q16, q17, [sp, #512]",
    "ldp q18, q19, [sp, #544]", "ldp q20, q21, [sp, #576]", "ldp q22, q23, [sp, #608]",
    "ldp q24, q25, [sp, #640]", "ldp q26, q27, [sp, #672]", "ldp q28, q29, [sp, #704]",
    "ldp q30, q31, [sp, #736]",
    "ldp x0, x1, [sp, #0]", "ldp x2, x3, [sp, #16]", "ldp x4, x5, [sp, #32]",
    "ldp x6, x7, [sp, #48]", "ldp x8, x9, [sp, #64]", "ldp x10, x11, [sp, #80]",
    "ldp x12, x13, [sp, #96]", "ldp x14, x15, [sp, #112]", "ldp x16, x17, [sp, #128]",
    "ldp x18, x19, [sp, #144]", "ldp x20, x21, [sp, #160]", "ldp x22, x23, [sp, #176]",
    "ldp x24, x25, [sp, #192]", "ldp x26, x27, [sp, #208]", "ldp x28, x29, [sp, #224]",
    "ldr x30, [sp, #240]",
    "insn_stub_slot:",
    "nop",
    "stp x0, x1, [sp, #0]", "stp x2, x3, [sp, #16]", "stp x4, x5, [sp, #32]",
    "stp x6, x7, [sp, #48]", "stp x8, x9, [sp, #64]", "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]", "stp x14, x15, [sp, #112]", "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]", "stp x20, x21, [sp, #160]", "stp x22, x23, [sp, #176]",
    "stp x24, x25, [sp, #192]", "stp x26, x27, [sp, #208]", "stp x28, x29, [sp, #224]",
    "str x30, [sp, #240]",
    "mrs x0, nzcv", "str x0, [sp, #248]",
    "mrs x0, fpsr", "str x0, [sp, #768]",
    "stp q0, q1, [sp, #256]", "stp q2, q3, [sp, #288]", "stp q4, q5, [sp, #320]",
    "stp q6, q7, [sp, #352]", "stp q8, q9, [sp, #384]", "stp q10, q11, [sp, #416]",
    "stp q12, q13, [sp, #448]", "stp q14, q15, [sp, #480]", "stp q16, q17, [sp, #512]",
    "stp q18, q19, [sp, #544]", "stp q20, q21, [sp, #576]", "stp q22, q23, [sp, #608]",
    "stp q24, q25, [sp, #640]", "stp q26, q27, [sp, #672]", "stp q28, q29, [sp, #704]",
    "stp q30, q31, [sp, #736]",
    "mov x0, sp", "ldr x1, [x0, #784]", "mov sp, x1",
    "mov x1, #0", "msr fpcr, x1", "add x9, x0, #800",
    "ldp x19, x20, [x9, #0]", "ldp x21, x22, [x9, #16]", "ldp x23, x24, [x9, #32]",
    "ldp x25, x26, [x9, #48]", "ldp x27, x28, [x9, #64]", "ldp x29, x30, [x9, #80]",
    "ldp d8, d9, [x9, #96]", "ldp d10, d11, [x9, #112]",
    "ldp d12, d13, [x9, #128]", "ldp d14, d15, [x9, #144]",
    "ret",
    "insn_stub_end:",
);

unsafe extern "C" {
    static insn_stub_start: u8;
    static insn_stub_slot: u8;
    static insn_stub_end: u8;
}

static ILLEGAL: AtomicBool = AtomicBool::new(false);

extern "C" fn on_ill(_sig: i32, _info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    ILLEGAL.store(true, Ordering::SeqCst);
    unsafe { (*ctx.cast::<libc::ucontext_t>()).uc_mcontext.pc += 4 };
}

/// Map the stub and the stack, and install the SIGILL handler.
///
/// # Safety
/// Called once, before [`run`]; it maps fixed addresses.
pub unsafe fn setup() {
    unsafe {
        let code = libc::mmap(CODE as *mut _, 0x1000, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED, -1, 0);
        let stack = libc::mmap(STACK as *mut _, STACK_LEN, libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED, -1, 0);
        assert!(code as usize == CODE && stack as usize == STACK, "fixed mappings");
        let start = &raw const insn_stub_start as usize;
        let len = &raw const insn_stub_end as usize - start;
        std::ptr::copy_nonoverlapping(start as *const u8, CODE as *mut u8, len);
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_ill as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigaction(libc::SIGILL, &sa, std::ptr::null_mut());
    }
}

/// The guest address the instruction under test runs at, for ADR and ADRP.
pub fn slot_addr() -> u64 {
    (CODE + (&raw const insn_stub_slot as usize - &raw const insn_stub_start as usize)) as u64
}

/// Run `insn` on `st`; the state afterwards and whether it was illegal.
///
/// # Safety
/// [`setup`] has run, on this thread's process.
pub unsafe fn run(insn: u32, st: &State) -> (State, bool) {
    unsafe {
        let slot = slot_addr() as usize;
        (slot as *mut u32).write_volatile(insn);
        core::arch::asm!("dc cvau, {p}", "dsb ish", "ic ivau, {p}", "dsb ish", "isb", p = in(reg) slot);
        let state = STATE as *mut State;
        state.write(*st);
        ILLEGAL.store(false, Ordering::SeqCst);
        let f: extern "C" fn(*mut State) = std::mem::transmute(CODE);
        f(state);
        (state.read(), ILLEGAL.load(Ordering::SeqCst))
    }
}

impl State {
    /// All zero: registers, flags, FPCR.
    pub fn zeroed() -> State {
        unsafe { std::mem::zeroed() }
    }
}
