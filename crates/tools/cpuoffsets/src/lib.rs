//! `cpu-offsets.h`, which is how the gadgets index into the structs the
//! emulator hands them.
//!
//! # What this replaces
//!
//! `asbestos/offsets.c` was 92 lines of `OFFSET(CPU, cpu_state, x0)` macros
//! that expanded to `asm volatile(".ascii \"->CPU_x0 %0 ...\"")`, compiled to
//! *assembly* and then scraped by `tools/staticdefine.sh` with a sed script
//! copied from the Linux kernel build. Three steps, one of them a regular
//! expression over compiler output, to answer `offsetof`.
//!
//! This asks the same question of the same headers and prints the answer.
//! `offset_of!` has been stable since 1.77.
//!
//! # It does not own the layout, yet
//!
//! `struct cpu_state` is still `emu/arch/arm64/cpu.h`'s and still what the C
//! compiler sees; `build.rs` runs bindgen over the same headers with the same
//! `-D` flags.
//!
//! This used to say that inverting the ownership had been "considered and
//! declined", because it would mean hand-writing the layout in Rust and
//! **putting cargo on the critical path of the assembly**. The second half of
//! that is no longer an objection: putting cargo on that path is the point, so
//! that `cargo build` alone produces a working `iul` — which by 2026-09-11 was
//! the only way to build this repository. `crates/asbestos/gadgets` does it by
//! calling [`text`] from its `build.rs`.
//!
//! What has not moved is the layout itself. That is a separate step, and the
//! check for it is this file's output: it is text, so the change is verifiable
//! by diffing it.

use std::fmt::Write as _;
use std::mem::offset_of;

use taskview::ffi::cpu_state;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

/// `CPU_x0` .. `CPU_x30`.
///
/// This was a macro over thirty-one literal field names, because the registers
/// were an unnamed union of an unnamed struct and `offset_of!` needs a literal
/// path. They are `regs: [u64; 31]` now — `crates/kernel/taskview`'s
/// `cpustate` module says why — so the thirty-one names are a loop and the
/// header's `static_assert(CPU_OFFSET(x0) == CPU_OFFSET(regs[0]))` is
/// structurally true rather than asserted.
fn gp_regs() -> Vec<(String, usize)> {
    let base = offset_of!(cpu_state, regs);
    (0..31).map(|i| (format!("x{i}"), base + i * 8)).collect()
}

/// The whole of `cpu-offsets.h`, as text.
///
/// A function rather than a `main` since 2026-09-08: `crates/asbestos/gadgets`
/// calls it from its `build.rs` so that **cargo can assemble the gadgets on its
/// own**, which is what a nested `cargo run` cannot be made to do. The binary
/// beside it is a two-line wrapper for printing the header by hand; meson's
/// generator called it until 2026-09-11, and one function for both is what
/// stopped the two paths drifting while there were two.
pub fn text() -> String {
    let mut out = String::new();

    // The order is `asbestos/offsets.c`'s, so that a diff against the file it
    // replaces is empty rather than a reordering.
    let gp = gp_regs();
    let gp: Vec<(&str, usize)> = gp.iter().map(|(n, o)| (n.as_str(), *o)).collect();
    emit(&mut out, "CPU", "cpu_state", &gp);
    emit(
        &mut out,
        "CPU",
        "cpu_state",
        &[
            ("sp", offset_of!(cpu_state, sp)),
            ("pc", offset_of!(cpu_state, pc)),
            ("tls_ptr", offset_of!(cpu_state, tls_ptr)),
            ("nf", offset_of!(cpu_state, nf)),
            ("zf", offset_of!(cpu_state, zf)),
            ("cf", offset_of!(cpu_state, cf)),
            ("vf", offset_of!(cpu_state, vf)),
            ("nzcv", offset_of!(cpu_state, nzcv)),
            ("fp", offset_of!(cpu_state, fp)),
            ("fpcr", offset_of!(cpu_state, fpcr)),
            ("fpsr", offset_of!(cpu_state, fpsr)),
            ("excl_addr", offset_of!(cpu_state, excl_addr)),
            ("excl_val", offset_of!(cpu_state, excl_val)),
            ("excl_val2", offset_of!(cpu_state, excl_val2)),
            ("cycle", offset_of!(cpu_state, cycle)),
            ("segfault_addr", offset_of!(cpu_state, segfault_addr)),
            (
                "segfault_was_write",
                offset_of!(cpu_state, segfault_was_write),
            ),
            ("fault_code_pc", offset_of!(cpu_state, fault_code_pc)),
            ("poked_ptr", offset_of!(cpu_state, poked_ptr)),
            ("dit", offset_of!(cpu_state, dit)),
        ],
    );

    emit(
        &mut out,
        "LOCAL",
        "fiber_frame",
        &[
            ("bp", offset_of!(ffi::fiber_frame, bp)),
            ("value", offset_of!(ffi::fiber_frame, value)),
            ("value_addr", offset_of!(ffi::fiber_frame, value_addr)),
            ("last_block", offset_of!(ffi::fiber_frame, last_block)),
            ("jit_exit_sp", offset_of!(ffi::fiber_frame, jit_exit_sp)),
            ("ret_cache", offset_of!(ffi::fiber_frame, ret_cache)),
        ],
    );

    emit(
        &mut out,
        "FIBER_BLOCK",
        "fiber_block",
        &[
            ("addr", offset_of!(ffi::fiber_block, addr)),
            ("code", offset_of!(ffi::fiber_block, code)),
        ],
    );

    emit(
        &mut out,
        "TLB",
        "tlb",
        &[
            ("entries", offset_of!(ffi::tlb, entries)),
            ("mmu", offset_of!(ffi::tlb, mmu)),
            ("mem_changes", offset_of!(ffi::tlb, mem_changes)),
            ("dirty_page", offset_of!(ffi::tlb, dirty_page)),
            ("segfault_addr", offset_of!(ffi::tlb, segfault_addr)),
            ("block_cache", offset_of!(ffi::tlb, block_cache)),
            ("block_cache_gen", offset_of!(ffi::tlb, block_cache_gen)),
        ],
    );

    emit(
        &mut out,
        "TLB_ENTRY",
        "tlb_entry",
        &[
            ("page", offset_of!(ffi::tlb_entry, page)),
            (
                "page_if_writable",
                offset_of!(ffi::tlb_entry, page_if_writable),
            ),
            (
                "data_minus_addr",
                offset_of!(ffi::tlb_entry, data_minus_addr),
            ),
            ("gen", offset_of!(ffi::tlb_entry, gen_)),
        ],
    );

    emit(
        &mut out,
        "MMU",
        "mmu",
        &[("changes", offset_of!(ffi::mmu, changes))],
    );

    // Two plain constants the gadgets compare against, not offsets.
    let _ = writeln!(out, "#define MEM_READ {}", taskview::ffi::MEM_READ);
    let _ = writeln!(out, "#define MEM_WRITE {}", taskview::ffi::MEM_WRITE);

    out
}

/// One struct's worth of `#define`s.
///
/// The comment names the Rust expression rather than the C one the old
/// generator printed — `offset_of!(cpu_state, x0)` is what would be edited if
/// this were wrong, and `__builtin_offsetof` no longer appears anywhere.
fn emit(out: &mut String, prefix: &str, struct_name: &str, fields: &[(&str, usize)]) {
    for (name, off) in fields {
        let _ = writeln!(
            out,
            "#define {prefix}_{name} {off} /* offset_of!({struct_name}, {name}) */"
        );
    }
}
