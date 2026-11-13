//! Fatal signal policy and process termination.

use std::ffi::c_int;

use super::ffi;

/// The exit status a fatal signal becomes.
///
/// Three of these are policy for V8, and are here rather than deleted because
/// the workload they were written for is node, which no suite here runs:
///
/// - `v8_aborting` says this process has already printed V8's fatal preamble
///   (`crates/kernel/v8mute`), so its side effects have landed and a
///   `SIGTRAP`, `SIGABRT` or `SIGSEGV` after that is a clean exit. npm's inner
///   V8 throws non-fatal `CHECK`s during worker teardown *after* the install
///   is on disk, and `npx` reads the exit status.
/// - A `SIGILL` or `SIGBUS` with the pc in `0xb0000000..0xf0000000` exits 1
///   rather than dying by signal, for a background thread whose pc a V8 frame
///   unwind left pointing into the heap. That range is the mmap region, so it
///   is every JIT and every program that crashes in a shared library; it is
///   behind `IUL_V8_FAULT_RECOVERY` since 2026-09-02 with the unwind that
///   produces the condition.
///
/// Pure, so that the table is testable without a process.
pub(super) fn fatal_exit_status(
    sig: c_int,
    v8_aborting: bool,
    pc: u64,
    v8_recovery: bool,
) -> c_int {
    let sigtrap = ffi::SIGTRAP_ as c_int;
    let sigabrt = ffi::SIGABRT_ as c_int;
    let sigsegv = ffi::SIGSEGV_ as c_int;
    let sigill = ffi::SIGILL_ as c_int;
    let sigbus = ffi::SIGBUS_ as c_int;
    if v8_aborting && (sig == sigtrap || sig == sigabrt || sig == sigsegv) {
        return 0;
    }
    if v8_recovery && (sig == sigill || sig == sigbus) && (0xb000_0000..0xf000_0000).contains(&pc) {
        return 1 << 8;
    }
    sig
}

/// The default action that ends the process. Never returns.
///
/// **`task` is raw, and so is it in every caller up to `receive_signals`.** A
/// reference argument is asserted valid until its function returns, and this
/// one does not: `do_exit` destroys the task with the frame still live, which
/// is a write to and a free of borrowed memory however unused the borrow is.
///
/// # Safety
/// Called on the guest thread, with sighand's lock **not** held: `do_exit_group`
/// takes it.
pub(super) unsafe fn terminate(task: *mut ffi::task, sig: c_int) -> ! {
    let cpu = unsafe { (*task).cpu.get().cast_const() };
    let (pc, sp, regs) = unsafe { ((*cpu).pc, (*cpu).sp, (*cpu).regs) };
    let v8_aborting = taskview::with_current_group(ffi::tgroup::v8_aborting).unwrap_or(false);
    let env = util_iulenv::env();
    let (exec_trace, v8_recovery) = (env.exec_trace, env.v8_fault_recovery);
    if exec_trace {
        // Where a V8 crash gets correlated with the guest pc that produced it.
        if sig == ffi::SIGTRAP_ as c_int {
            eprintln!(
                "V8_SIGTRAP: pc={pc:#x} x0={:#x} sp={sp:x} fp={:x} lr={:x}",
                regs[0], regs[29], regs[30]
            );
        } else if sig == ffi::SIGABRT_ as c_int {
            eprintln!(
                "V8_SIGABRT: pc={pc:#x} sp={sp:x} fp={:x} lr={:x}",
                regs[29], regs[30]
            );
        }
    }
    crate::do_exit_group(fatal_exit_status(sig, v8_aborting, pc, v8_recovery));
    // `noreturn` in the C, which bindgen does not carry across.
    unreachable!("do_exit_group returned");
}
