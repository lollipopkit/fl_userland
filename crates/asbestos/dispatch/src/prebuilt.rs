use super::*;

/// Put `cpu->pc` on the instruction that faulted, rather than on the block it
/// is in.
///
/// # What this is for
///
/// `inline_chain` stores `block->addr` into `cpu->pc` when it enters a block and
/// nothing writes it again until the block ends, so a fault raised halfway
/// through reports the block's first instruction. Everything downstream reads
/// that pc: the `SIGSEGV` handed to the guest carries it in `uc_mcontext.pc`,
/// and `rt_sigreturn` resumes there — so a handler that repairs the page and
/// returns re-runs every instruction in the block before the fault. A store to
/// a counter, a flag or a queue index is silently doubled, and a `sub sp, sp, #N`
/// compounds.
///
/// The gadget's segfault path records the threaded-code cursor in
/// `cpu->fault_code_pc`, which is the one thing only it knows: the fault is not
/// a host `SIGSEGV`, so nothing has been unwound and the cursor is still in a
/// register. `asbestos_gen::guest_pc_at_offset` turns the offset back into a
/// guest address by compiling the block a second time.
///
/// # The block comes from `last_block`, not from `pc`
///
/// `cpu->pc` is not even reliably the *current block's* address. `inline_chain`
/// writes it, and the other two ways into a block — `fiber_ret_chain` and the
/// return cache's hit path — do not: both set `last_block` and keep running. So
/// after a chained transition the pc names some earlier block entirely, which
/// makes the defect wider than "the start of the block it is in".
///
/// `last_block` is maintained on every path, and the cursor check ties the two
/// together: a cursor written by the faulting gadget that lands inside
/// `last_block`'s code is proof that block was the one running.
///
/// # Everything is checked rather than assumed
///
/// Three things have to hold, and each is a reason to leave the pc alone rather
/// than to trust it: there has to be a block, the cursor has to lie inside its
/// code, and the re-decode has to reach an instruction at or after the block's
/// start. A fault that did not come from a memory gadget — a `block_for`
/// failure, a tagged pc, a null pc — never reaches here, and `fault_code_pc` is
/// cleared on every visit so a stale one cannot be believed.
///
/// # Safety
/// Called on the guest thread, between `fiber_enter` returning and anything
/// reading the pc.
#[cold]
#[inline(never)]
pub(super) unsafe fn name_the_faulting_instruction(frame: *mut Frame, tlb: *mut Tlb) {
    let cursor = unsafe { (*frame).cpu.fault_code_pc };
    // Cleared every time, so a later fault of a different kind cannot be given
    // this one's answer.
    unsafe { (*frame).cpu.fault_code_pc = 0 };
    if cursor == 0 {
        return;
    }
    let block = unsafe { (*frame).last_block };
    if block.is_null() {
        return;
    }
    let pc = unsafe { (*block).addr };
    let code = unsafe { (&raw mut (*block).code).cast::<u64>() } as u64;
    if cursor <= code {
        return;
    }
    let offset = ((cursor - code) / size_of::<u64>() as u64) as usize;
    if offset >= unsafe { (*block).used } {
        return;
    }
    if let Some(at) = unsafe { asbestos_gen::compile::guest_pc_at_offset(pc, tlb, offset) }
        && at >= pc
    {
        unsafe { (*frame).cpu.pc = at };
    }
}

// A frame per nesting depth, kept for the life of the thread.
//
// The frame is 48 KB, so allocating one per nested call is a cost
// `prebuilt_call` cannot carry: `spec_outer` calls it once per loop iteration.
// Depth is 1 in every case that exists — a spec_fn running a guest callee —
// and the vector grows if one ever nests further.
//
// Owned since 2026-10-01. The vector held `usize` addresses from
// `libc::calloc` that nothing freed, so a thread that ever ran a nested
// prebuilt call leaked its frames when it exited; the `Box`es go with the
// thread-local now.
thread_local! {
    static NESTED_FRAMES: std::cell::RefCell<Vec<Box<Frame>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// The frame for nesting `depth` (1 or more), made on first use. The address
/// is stable for the life of the thread: a `Box` does not move when the
/// vector holding it grows.
pub(super) fn nested_frame(depth: u32) -> *mut Frame {
    NESTED_FRAMES.with(|f| {
        let mut v = f.borrow_mut();
        while v.len() < depth as usize {
            v.push(Frame::new_boxed());
        }
        &raw mut *v[depth as usize - 1]
    })
}

thread_local! {
    /// How many dispatch loops this thread is inside. Zero for the ordinary
    /// case; one while a prebuilt spec_fn is running a guest callee through
    /// [`prebuilt_call`]. Read by `cpu_step_to_interrupt` to decide whether the
    /// TLB's reusable frame is free to use.
    static DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

pub(super) fn current_depth() -> u32 {
    DEPTH.with(|d| d.get())
}

/// Run guest function `target_pc` to completion and answer its result (x0).
///
/// **Mixed execution.** A prebuilt spec_fn — `crates/asbestos/offloadprebuilt`'s
/// third offload mechanism — is host code standing in for one guest function.
/// When it reaches a `bl` or `blr` it cannot call the callee itself, because the
/// callee is still guest code; it calls it *the guest way* through this, which
/// points the callee's return address at [`ffi::PREBUILT_SENTINEL`] and drives
/// the ordinary dispatch loop until the interpreter hands control back with
/// `INT_PREBUILT_RET`. `pc` and the link register are saved and restored so the
/// spec_fn resumes where it was.
///
/// Interrupts other than the sentinel are serviced the way the kernel's run
/// loop would and the nested call continues: a syscall inside the callee is
/// still a syscall.
///
/// # It was missing between 2026-09-06 and 2026-09-08
///
/// `asbestos/asbestos.c` had it, and the declaration in `kernel/native_offload.h`
/// went with the sweep in `docs/changelog/2026-09-06-a-header-declaration-is-not-a-caller.md`
/// — correctly by that check's rule, since the only callers are the offload
/// fixtures and **those have never compiled in this repository**. So the
/// mechanism kept its registry, its sentinel and its unwind, and lost the entry
/// point between them; nothing said so, because the build that would have said
/// so was already broken for a different reason.
///
/// # Safety
/// `cpu` and `tlb` are the running guest's, and this is called from a spec_fn
/// the interpreter entered — so the dispatch loop is re-entered on a thread
/// that is already inside it, which is what the sentinel exists to unwind.
pub unsafe fn prebuilt_call(cpu: *mut Cpu, tlb: *mut Tlb, target_pc: u64) -> u64 {
    // SAFETY: the caller's contract.
    unsafe {
        let save_pc = (*cpu).pc;
        let save_lr = (*cpu).regs[30];

        (*cpu).regs[30] = ffi::PREBUILT_SENTINEL; // the callee returns here
        (*cpu).pc = target_pc;

        DEPTH.with(|d| d.set(d.get() + 1));
        loop {
            let interrupt = cpu_step_to_interrupt(cpu, tlb);
            if interrupt == INT_PREBUILT_RET {
                break;
            }
            // A syscall, a timer or a fault fired inside the callee. The outer
            // run loop is not going to see it, so service it here and carry on.
            (*cpu).trapno = interrupt as ffi::dword_t;
            (HANDLE_INTERRUPT.get().expect(
                "crates/asbestos/dispatch: the interrupt hook was never \
                 installed. `become_first_process` does it; an interrupt \
                 inside a prebuilt gadget cannot be serviced without it, and \
                 the outer run loop will not see it either.",
            ))(interrupt);
        }

        DEPTH.with(|d| d.set(d.get() - 1));

        let ret = (*cpu).regs[0];
        (*cpu).pc = save_pc;
        (*cpu).regs[30] = save_lr;
        ret
    }
}

/// Dispatch an interrupt that fired *inside* a prebuilt gadget's callee.
///
/// A hook. `crates/kernel/syscalldispatch` owns the dispatcher and depends on
/// this crate through the interpreter it drives, so a dependency either way is
/// a cycle — and this crate is `asbestos`, two layers below `kernel`, so the
/// edge could not be a cargo one whichever direction gave way. It was an
/// `extern "C"` declaration until 2026-09-09.
///
/// **`expect` rather than a default**, as with the two in
/// `crates/kernel/taskcalls`: an interrupt this loop cannot service is one the
/// outer run loop will not see either, so ignoring it spins here for ever.
static HANDLE_INTERRUPT: OnceLock<unsafe fn(c_int)> = OnceLock::new();

/// Install it. `crates/kernel/boot`'s `become_first_process` does, beside the
/// two the run loop needs.
pub fn set_interrupt_hook(f: unsafe fn(c_int)) {
    let _ = HANDLE_INTERRUPT.set(f);
}

/// Whether it is installed — for the test in `crates/kernel/boot`.
pub fn interrupt_hook_installed() -> bool {
    HANDLE_INTERRUPT.get().is_some()
}
