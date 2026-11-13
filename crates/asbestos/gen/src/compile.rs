//! Compiling one block: run the decoder until it says the block ends.
//!
//! This was `fiber_block_compile` in `asbestos/asbestos.c`, where it stayed
//! because it reached `gen.c`'s decoder. The decoder is this crate, so the loop
//! belongs here and the two C ABI shims it needed — one to call it and one to
//! free a block the caller threw away — are gone.
//!
//! # The block is bounded to a page
//!
//! A block that spanned two pages would have to be invalidated when either
//! changed, and the page index in `crates/asbestos/blockcache` records one. So
//! the loop stops as soon as the *next* instruction could cross, which on a
//! fixed-width instruction set is a page less one instruction's worth of slack.

use crate::ffi;

/// Compile the block starting at `ip`, or `None` if the allocation failed.
///
/// # Safety
/// `tlb` is this thread's, and the caller holds `asbestos->lock` — the W^X
/// protocol in `crates/asbestos/dispatch` is what establishes that the page
/// being read has not changed underneath.
pub unsafe fn compile(ip: u64, tlb: *mut ffi::tlb) -> Option<*mut ffi::fiber_block> {
    // Ends at whichever of this function's three exits is taken. It was a
    // `finish` closure called at each of them until 2026-09-06, which is the
    // hand-written half of what a guard does.
    let _interval = signpost::enabled()
        .then(|| signpost::Interval::begin(signpost::Category::Jit, c"block_compile"));

    // A `cfg` since 2026-09-06: the whole block, `format!` included, is gone
    // in a build without the channel. It was a call into `kernel/log.c`
    // returning a folded constant, so the format was skipped but the call was
    // not.
    if logchan::Channel::Instr.enabled() {
        logchan::line(
            logchan::Channel::Instr,
            &format!("{} {:08x} --- compiling:", currentpid::current_pid(), ip),
        );
    }

    let mut b = crate::Builder::start(ip);

    // A guest function with a host implementation compiles to one gadget that
    // runs it and resumes at the guest's link register. Lossless: no
    // registration means the ordinary compile below.
    if offloadprebuilt::native_offload_prebuilt_active() {
        // `Option<SpecFn>` rather than a null pointer: the Rust signature says
        // "there may be no spec", which the C prototype could only say by
        // convention.
        if let Some(spec) = offloadprebuilt::native_offload_prebuilt_lookup(ip) {
            crate::block::gen_prebuilt_block(&mut b, spec);
            return b.finish().map(std::ptr::NonNull::as_ptr);
        }
    }

    loop {
        // SAFETY: the caller's contract.
        if unsafe { crate::step::gen_step(&mut b, tlb) } == crate::BLOCK_ENDS {
            break;
        }
        // No block may span two pages: the invalidation index records one page
        // per block. Stopping with an instruction's worth of slack left is what
        // guarantees it.
        if b.ip() - ip >= ffi::PAGE_SIZE as u64 - 15 {
            crate::block::gen_exit(&mut b);
            break;
        }
    }
    debug_assert!(b.ip() - ip <= ffi::PAGE_SIZE as u64);
    b.finish().map(std::ptr::NonNull::as_ptr)
}

/// Compile, as `crates/asbestos/dispatch`'s seqlock calls it: a null pointer
/// rather than an `Option`, because the C protocol it implements had one.
///
/// # Safety
/// As [`compile`].
pub unsafe fn compile_raw(ip: u64, tlb: *mut ffi::tlb) -> *mut ffi::fiber_block {
    unsafe { compile(ip, tlb) }.unwrap_or(std::ptr::null_mut())
}

/// Which guest instruction produced the code word at `offset` in the block that
/// starts at `ip`.
///
/// # Why this exists
///
/// The JIT reports a fault with `cpu->pc` at the **start of the block**:
/// `inline_chain` stores `block->addr` there on entry and nothing writes it
/// again until the block ends. So a `SIGSEGV` delivered to the guest named the
/// wrong instruction, and `rt_sigreturn` resumed at the block's start — every
/// store in it before the fault ran a second time.
///
/// What the gadget knows is the threaded-code cursor, `cpu->fault_code_pc`.
/// Turning that into a guest pc needs a map from code offset to instruction,
/// and this builds one **by compiling the block again** — the decoder is
/// deterministic, so the second pass lays the words out exactly as the first
/// did, and `Gen::begin` already records each instruction's address in
/// `orig_ip`.
///
/// Recompiling costs a `malloc` and a few hundred decoder steps, and it happens
/// once per fault that reaches the guest. The alternatives were a store per
/// memory access — on the hottest path in the emulator — or a side table on
/// every block, which grows the block cache by about a quarter. The costed
/// comparison is in the changelog above.
///
/// # The offset is a strict upper bound
///
/// A gadget's operands are consumed with post-increment, so by the time it
/// faults the cursor has moved past its own words — at least past the gadget
/// pointer itself. The answer is therefore the **last** instruction whose words
/// begin *strictly before* `offset`, not the one whose range contains it: a
/// memory gadget that is the last thing its instruction emits leaves the cursor
/// exactly at the next instruction's first word.
///
/// # Safety
/// `tlb` is this thread's, and the guest page holding the block is readable.
pub unsafe fn guest_pc_at_offset(ip: u64, tlb: *mut ffi::tlb, offset: usize) -> Option<u64> {
    // A scratch decode: never finished, so no block is made.
    let mut b = crate::Builder::start(ip);

    let mut found = None;
    loop {
        if b.code().len() >= offset {
            // Past it already, and every later instruction is further past.
            break;
        }
        // SAFETY: the caller's contract.
        let more = unsafe { crate::step::gen_step(&mut b, tlb) };
        // `orig_ip` is this instruction's address, recorded by `Gen::begin`.
        found = Some(b.orig_ip());
        if more == crate::BLOCK_ENDS {
            break;
        }
        if b.ip() - ip >= ffi::PAGE_SIZE as u64 - 15 {
            break;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::with_guest_memory;

    /// The map from a code offset back to the instruction that produced it.
    ///
    /// This is what turns `cpu->fault_code_pc` into a pc a `SIGSEGV` can carry,
    /// so the property that matters is that it is **monotonic and in range**:
    /// every offset in a block names an instruction of that block, and a later
    /// offset never names an earlier instruction.
    #[test]
    fn a_code_offset_maps_back_to_the_instruction_that_made_it() {
        const BASE: u64 = 0x1000;
        // add x0, x0, #1 / add x1, x1, #2 / add x2, x2, #3 / ret
        let words = [0x9100_0400u32, 0x9100_0821, 0x9100_0c42, 0xd65f_03c0];
        let last_insn = BASE + (words.len() as u64 - 1) * 4;
        with_guest_memory(BASE, &words, || {
            let at = |offset| unsafe { guest_pc_at_offset(BASE, std::ptr::null_mut(), offset) };

            // Nothing has started at offset 0.
            assert_eq!(at(0), None);
            // The first word is the first instruction's gadget pointer, and the
            // cursor is always at least one past it when a gadget faults.
            assert_eq!(at(1), Some(BASE));

            let mut previous = BASE;
            let mut reached_each = vec![BASE];
            for offset in 1..64usize {
                let Some(pc) = at(offset) else {
                    panic!("offset {offset} named no instruction");
                };
                assert!(
                    pc >= previous,
                    "offset {offset}: {pc:#x} after {previous:#x}"
                );
                assert!(
                    (BASE..=last_insn).contains(&pc),
                    "offset {offset}: {pc:#x} is outside the block"
                );
                if pc != previous {
                    reached_each.push(pc);
                }
                previous = pc;
            }
            // Every instruction in the block is named by some offset — if the
            // walk skipped one, a fault in it would be reported as its
            // neighbour.
            assert_eq!(
                reached_each,
                (0..words.len() as u64)
                    .map(|i| BASE + i * 4)
                    .collect::<Vec<_>>(),
                "each instruction owns a range of offsets"
            );
            // Past the end, the last instruction is the answer rather than
            // nothing: an offset that large can only come from a corrupt
            // cursor, and the caller bounds it against `block->used` anyway.
            assert_eq!(at(1000), Some(last_insn));
        });
    }

    /// Without readable memory the decoder cannot get past the first
    /// instruction, so every block is one long. Asserted because it is what the
    /// *other* tests in this crate depend on — a stub that started returning
    /// zeroes would make them fuse and decode `udf`.
    #[test]
    fn unreadable_guest_memory_ends_the_block_at_once() {
        assert_eq!(
            unsafe { guest_pc_at_offset(0x2000, std::ptr::null_mut(), 4) },
            Some(0x2000)
        );
    }
}
