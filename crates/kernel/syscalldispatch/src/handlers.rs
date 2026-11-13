//! Interrupt handlers for guest breakpoints and unsupported instructions.

use std::ffi::c_int;

use crate::{current, ffi};

use super::{dump_stack, insn_at, u64_at};

/// `TRAP_BRKPT` and `ILL_ILLOPC`, the `si_code`s for a breakpoint and for an
/// opcode that does not exist. Both are 1, both are the same on every Linux
/// architecture, and neither has a definition in this tree to generate from.
/// A crash reporter reads these to say *why*, and `SI_KERNEL` -- which is what
/// both were -- says only that the kernel sent it.
const TRAP_BRKPT: c_int = 1;
const ILL_ILLOPC: c_int = 1;

/// The guest's frame-pointer chain, printed for `IUL_GPF_BT`.
///
/// A histogram beside the list, because an unbounded recursion shows itself as
/// a cycle rather than as a long list — the list alone is 64 addresses that
/// look different and are the same three frames.
///
/// The JSC-specific probes that stood beside this went with the C: they read
/// `x1 + 0x38` as `CodeBlock::m_unlinkedCode` and dumped `x19 + 0x18` as
/// `numVars`, which are one investigation's struct offsets in one build and
/// mean nothing anywhere else.
///
/// Takes the frame pointer, `x29`, which is all it read of the CPU state; it
/// took the whole `*mut cpu_state` and was `unsafe` for it until 2026-10-01.
pub(super) fn backtrace(frame: u64) {
    // The window the store watchpoint filters its records on, set by the CLI.
    let (lo, hi) = asbestos_diag::watch_window();
    asbestos_diag::dump_watch_hits(lo, hi);

    let mut fp = frame;
    let mut pcs: Vec<u64> = Vec::new();
    let mut seen: Vec<(u64, u32)> = Vec::new();
    while fp != 0 && pcs.len() < 64 {
        let (Some(next), Some(ret)) = (u64_at(fp), u64_at(fp + 8)) else {
            break;
        };
        pcs.push(ret);
        match seen.iter_mut().find(|(pc, _)| *pc == ret) {
            Some((_, n)) => *n += 1,
            None => seen.push((ret, 1)),
        }
        if next <= fp {
            break;
        }
        fp = next;
    }
    eprintln!("  [bt] first {} return PCs:", pcs.len());
    for (i, pc) in pcs.iter().enumerate() {
        eprintln!("    #{i} {pc:#x}");
    }
    eprintln!("  [bt] return PC histogram (unique among walked frames):");
    for (pc, n) in &seen {
        eprintln!("    {pc:#x} x{n}");
    }
    // The tail of a JIT-generated caller, which is where a corrupt return
    // address usually comes from.
    for pc in pcs.iter().take(12) {
        if !(0xc000_0000..0xe000_0000).contains(pc) {
            continue;
        }
        eprintln!("  [bt] JIT code before ret pc {pc:#x}:");
        for k in -24i64..=2 {
            let at = pc.wrapping_add((k * 4) as u64);
            if let Some(insn) = insn_at(at) {
                eprintln!("    {at:#x}: {insn:#010x}");
            }
        }
    }
}

/// A `BRK`.
///
/// # Safety
/// As [`super::handle_int_gpf`].
pub unsafe fn handle_int_breakpoint() {
    let task = current();
    let cpu = unsafe { (*task).cpu.get() };
    let pc = unsafe { (*cpu).pc };
    let imm = insn_at(pc).map(|insn| (insn >> 5) & 0xffff).unwrap_or(0);

    // musl's malloc-corruption `BRK #0x3e8`, inside the malloc family. On a
    // real kernel this is a genuine abort; here it is a transient read-side
    // anomaly from a copy-on-write or TLB race presenting stale arena
    // metadata, and V8's TracedNodeBlock::Create calls malloc_usable_size
    // right after a malloc, so it kills node before anything runs.
    //
    // The answer is a plausible small size: V8 bounds an internal array by it
    // and reallocates when full, and `0x1020` passes its sanity check
    // (`usable_size - 0x30 < 0xffff0`).
    //
    // The pc range is musl's .text covering the malloc family at one load
    // base, which is an address rather than an identity -- the same objection
    // that deleted the V8 unwind, and it stays only because what it does is
    // set one register rather than forge a whole frame.
    if imm == 0x3e8 && (0xed12_d560..0xed18_7b78).contains(&pc) {
        unsafe {
            let regs = &mut (*cpu).regs;
            regs[0] = 0x1020;
            (*cpu).pc = regs[30];
        }
        return;
    }

    // `BRK` is a synchronous exception, and Linux delivers `SIGTRAP` to
    // whatever handler is installed. The handler must then advance the pc or
    // exit: one that *returns* re-executes the same `BRK` for ever, because
    // the exception is taken with the pc still on the instruction. That loop
    // is the architecture's, and `tests/guest/src/bin/trap_probe.rs` confirms
    // a real kernel does it.
    //
    // **This forced the disposition back to the default until 2026-09-02**, so
    // no handler ran at all. The reason was V8: it installs a crash reporter
    // that returns normally, which is exactly that loop, a million times over
    // in one `npx install`. But `brk` is what every Rust panic in a
    // `panic=abort` build reaches, what `__builtin_trap()` compiles to, and
    // what every sanitizer check and every debugger breakpoint is -- so the
    // workaround silenced every legitimate handler to stop one program
    // looping, which is the same objection that made the V8 zone unwind
    // opt-in. `IUL_BRK_FORCE_DEFAULT=1` restores it.
    // `current_sighand()` rather than the field: `task` is `current()`, and
    // a read of that field from the task's own thread holding no lock
    // races the group-exit valve. See `crates/kernel/taskview`'s accessor.
    if util_iulenv::env().brk_force_default {
        taskview::with_current_queue(|queue| queue.force_default(ffi::SIGTRAP_ as c_int));
    }
    // `mut`: a union member is written below, and a bindgen union
    // field cannot be named in a struct literal.
    let mut info = ffi::siginfo_ {
        sig: ffi::SIGTRAP_ as c_int,
        ..Default::default()
    };
    // `TRAP_BRKPT`: a breakpoint, which is what a crash reporter prints
    // and what tells this apart from a single-step or a watchpoint. It was
    // `SI_KERNEL` (128), which says only "the kernel sent it".
    info.code = TRAP_BRKPT;
    info.__bindgen_anon_1.fault.addr = pc;
    signaldeliver::send_signal(signaldeliver::Target::Me, ffi::SIGTRAP_ as c_int, info);
}

/// An encoding with no gadget.
///
/// # Safety
/// As [`super::handle_int_gpf`].
pub unsafe fn handle_int_undefined() {
    let task = current();
    let cpu = unsafe { (*task).cpu.get() };
    let pc = unsafe { (*cpu).pc };
    let insn = insn_at(pc).unwrap_or(0);
    let pid = taskview::current_pid();
    eprintln!("{pid} illegal instruction at {pc:#x}: insn={insn:#010x}");
    // The word is the whole of the evidence and on its own is not something a
    // person can act on. Naming the tool is the difference between a bug report
    // that says "it crashed" and one that says which instruction has no gadget
    // -- see issue #7.
    eprintln!("  decode it with: tools/decode-insn.sh {insn:#010x}");
    eprintln!();
    dump_stack(8);

    // `mut`: a union member is written below, and a bindgen union

    // field cannot be named in a struct literal.

    let mut info = ffi::siginfo_ {
        code: ILL_ILLOPC,
        ..Default::default()
    };
    info.__bindgen_anon_1.fault.addr = pc;
    signaldeliver::deliver_signal(signaldeliver::Target::Me, ffi::SIGILL_ as c_int, info);
}
