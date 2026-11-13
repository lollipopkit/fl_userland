//! Optional register, stack, memory, and map diagnostics for faults.

use std::ffi::c_uint;

use super::*;

// ---------------------------------------------------------------------------
// The diagnostics the arms print with
// ---------------------------------------------------------------------------

/// `/proc/self/maps` for the faulting task.
///
/// Plain Rust: the three functions here were a C ABI while `kernel/calls.c`
/// called them, and it was their only caller.
pub(super) fn dump_maps() {
    // `proc::data::ProcData` owns its bytes since 2026-09-05, so there is no
    // `libc::free` here and no second bindgen rendering of one header struct.
    let mut buf = proc::data::ProcData::default();
    proc::pidmem::proc_maps_dump(&mut buf);
    eprint!("{}", String::from_utf8_lossy(buf.as_slice()));
}

/// Words of guest memory, eight to a line.
fn dump_mem(start: u64, len: c_uint) {
    const WIDTH: u64 = 8;
    let mut line = String::new();
    let mut i = 0u64;
    while i * 4 < len as u64 {
        let addr = start + i * 4;
        let mut word = [0u8; 4];
        if GuestMem::current().read(addr, &mut word) != 0 {
            break;
        }
        if i.is_multiple_of(WIDTH) {
            line = format!("{addr:012x}: ");
        }
        line.push_str(&format!("{:08x} ", u32::from_le_bytes(word)));
        if i % WIDTH == WIDTH - 1 {
            eprintln!("{line}");
            line.clear();
        }
        i += 1;
    }
    if !line.is_empty() {
        eprintln!("{line}");
    }
}

/// The top of the guest's stack, and where it is.
pub(super) fn dump_stack(lines: c_int) {
    let Some((sp, pc, fp)) = taskview::with_current_cpu(|c| (c.sp, c.pc, c.regs[29])) else {
        return;
    };
    eprintln!("stack at {sp:x}, base at {fp:x}, ip at {pc:x}");
    dump_registers();
    dump_mem(sp, (lines.max(0) as u32) * 8 * 8);
}

/// Every general register, four to a line.
///
/// Added on 2026-09-03 while diagnosing a fault in a guest's dynamic loader.
/// The stack dump above it was not enough: the faulting instruction was
/// `ldr x2, [x1, #8]`, and what mattered was *which object* `x1` and its
/// neighbours pointed at — a question the stack cannot answer, because the
/// value had already been loaded into a register. Half an hour of
/// disassembling to work out which registers the instruction used, and then no
/// way to see them.
///
/// Behind `IUL_EXEC_TRACE` with the rest of the dump, so it costs nothing
/// unless somebody is looking.
fn dump_registers() {
    let Some((regs, sp, pc)) = taskview::with_current_cpu(|c| (c.regs, c.sp, c.pc)) else {
        return;
    };
    let mut line = String::new();
    for (i, r) in regs.iter().enumerate() {
        line.push_str(&format!("x{i:<2}={r:016x} "));
        if i % 4 == 3 {
            eprintln!("  {line}");
            line.clear();
        }
    }
    if !line.is_empty() {
        eprintln!("  {line}");
    }
    eprintln!("  sp ={sp:016x} pc ={pc:016x}");
}
