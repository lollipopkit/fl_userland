//! Register layouts used by `PTRACE_GETREGSET` and `PTRACE_SETREGSET`.

use super::ffi;
use std::ffi::c_int;

// Moving registers between `struct cpu_state` and the two layouts
// `PTRACE_GETREGSET` and `PTRACE_SETREGSET` transfer.
//
// This was `kernel/ptrace.c` until 2026-09-02, on the grounds that
// `struct cpu_state`'s layout is a contract with the gadgets. It is — through
// `cpu-offsets.h`, which `asbestos/offsets.c` **computes** at build time, so
// what the assembly needs is the same layout and not the same source, and
// bindgen over `kernel/task.h` gives exactly that.
//
// Both layouts were the **i386** ones, left behind by the x86 removal, and
// both accessors were stubs: one memset its output to zero and the other did
// nothing, and both reported success. A debugger asking a stopped child for
// its registers got 68 bytes of zeroes in the wrong shape.

/// One register set, in the layout `PTRACE_GETREGSET` and `PTRACE_SETREGSET`
/// transfer.
///
/// Typed rather than a byte buffer: the caller used to hand both functions a
/// `[u8; 1024]` -- aligned to 1 -- which they cast to these structs, aligned to
/// 8 and 16, and assigned through. That is undefined behaviour whatever the
/// hardware does with an unaligned store; arm64 does it, which is why nothing
/// showed. Found by reading. The bytes the guest sees are [`RegSet::bytes_mut`],
/// which `crates/util/plain` proves are all initialised.
// One at a time, on the stack of one ptrace call: boxing the larger arm
// would cost an allocation to save 264 bytes of stack.
#[allow(clippy::large_enum_variant)]
pub enum RegSet {
    General(ffi::user_regs_struct_),
    Fpsimd(ffi::user_fpsimd_state_),
    /// `NT_ARM_SYSTEM_CALL`: the syscall number in flight, an `int`.
    SystemCall(i32),
}

/// arm64's `NT_ARM_SYSTEM_CALL`.
const NT_ARM_SYSTEM_CALL: u32 = 0x404;

impl RegSet {
    /// The set as the guest reads it; also what a short `iovec` is clamped
    /// against and what the transfer reports back.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        match self {
            RegSet::General(r) => plain::bytes_of_mut(r),
            RegSet::Fpsimd(v) => plain::bytes_of_mut(v),
            RegSet::SystemCall(n) => plain::bytes_of_mut(n),
        }
    }
}

/// The task's set for `note`; `None` for a note nothing defines, which the
/// caller turns into `EINVAL`.
///
/// # Safety
/// `task` is live and stopped, so nothing else writes its registers.
pub unsafe fn get(task: *mut ffi::task, note: c_int) -> Option<RegSet> {
    // Field reads through the pointer, not a `&cpu_state`: a signal sender may
    // store to the tracee's `_poked` meanwhile. It was a `&` until 2026-10-16.
    let cpu = unsafe { (*task).cpu.get().cast_const() };
    // SAFETY: the caller's contract; field reads.
    unsafe {
        match note as u32 {
            ffi::NT_PRSTATUS_ => Some(RegSet::General(ffi::user_regs_struct_ {
                regs: (*cpu).regs,
                sp: (*cpu).sp,
                pc: (*cpu).pc,
                // PSTATE's condition flags are bits 31:28, which is the layout
                // `nzcv` already holds, and DIT is bit 24. Nothing else in
                // PSTATE is modelled.
                pstate: taskview::cpu::pstate(&*cpu),
            })),
            ffi::NT_FPREGSET_ => Some(RegSet::Fpsimd(ffi::user_fpsimd_state_ {
                vregs: std::array::from_fn(|i| (*cpu).fp[i].d),
                fpsr: (*cpu).fpsr,
                fpcr: (*cpu).fpcr,
                __reserved: [0; 2],
            })),
            NT_ARM_SYSTEM_CALL => Some(RegSet::SystemCall((*task).ptrace.as_deref().map_or(-1, |p| p.syscallno()))),
            _ => None,
        }
    }
}

/// Write `set` back into the task's registers.
///
/// # Safety
/// As [`get`].
pub unsafe fn set(task: *mut ffi::task, set: &RegSet) {
    let cpu = unsafe { (*task).cpu.get() };
    // SAFETY: the caller's contract; field writes.
    unsafe {
        match set {
            RegSet::General(r) => {
                (*cpu).regs = r.regs;
                (*cpu).sp = r.sp;
                (*cpu).pc = r.pc;
                // `nf`/`zf`/`cf`/`vf` and `nzcv` are two views of the same
                // four bits and have to agree: the gadgets read the bytes,
                // the JIT reads the word. One call writes both, and it is
                // the one `rt_sigreturn` uses.
                taskview::cpu::set_pstate(cpu, r.pstate);
            }
            RegSet::Fpsimd(v) => {
                for (reg, value) in (*cpu).fp.iter_mut().zip(v.vregs) {
                    reg.d = value;
                }
                (*cpu).fpsr = v.fpsr;
                (*cpu).fpcr = v.fpcr;
            }
            RegSet::SystemCall(n) => {
                if let Some(p) = (*task).ptrace.as_deref() {
                    p.set_syscallno(*n);
                }
            }
        }
    }
}
