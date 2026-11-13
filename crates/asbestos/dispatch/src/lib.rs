//! The loop a guest thread runs in: find the block for the pc, enter it, and
//! come back when something interrupts.
//!
//! `fiber_enter` is assembly and stays that way; everything around it is here.
//! This is the most-executed code in the tree after the gadgets themselves, and
//! it is where two of this emulator's worst hangs were — read the comment on
//! [`quantum_over`] before touching the counters.
//!
//! # What a quantum is, and why letting go matters
//!
//! `task_run_current` holds `mem->lock` for **reading** across a quantum, so a
//! quantum is how long this thread keeps the address space pinned. A writer —
//! `mmap`, `munmap`, `mprotect`, a copy-on-write break — cannot block for it,
//! so it spins on `trywrlock` and only gets in when every reader has let go.
//!
//! # Three caches, and what makes each stale
//!
//! - `tlb->block_cache`, 4096 entries of "the block at this pc", thrown away
//!   when `asbestos->invalidate_gen` moves — a block may have been jetsam'd.
//! - `frame->ret_cache`, which holds pointers *into* block code, thrown away
//!   for the same reason.
//! - The TLB itself, thrown away when `mmu->changes` moves — another thread
//!   remapped a page and the host pointers are stale.
//!
//! The first two are checked at the top of every iteration, not just on entry,
//! because an invalidation can land between two `fiber_enter` calls.


use asbestos_diag::stage_trace_on;
use std::ffi::c_int;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

pub mod compile;
mod prebuilt;
mod run;
pub use prebuilt::{interrupt_hook_installed, prebuilt_call, set_interrupt_hook};

// The shared Rust types and constants are re-exported by kernel-taskview.
use emu_abi as ffi;

type Block = ffi::fiber_block;
type Cpu = ffi::cpu_state;
type Frame = ffi::fiber_frame;
type Tlb = ffi::tlb;
use asbestos_blockcache::Asbestos;

/// The fiber frame is `libc::calloc`ed by `cpu_step_to_interrupt` and
/// `libc::free`d by `crates/emu/tlb`, and **`free` runs no destructor** — so a
/// field of it that owned something would be leaked with nothing to say so.
///
/// Unlike `struct fiber_block` beside it this one *is* a fixed-size struct and
/// could be a `Box`. What stops it is the ownership rather than the shape: the
/// frame is cached on `tlb->frame` across a syscall — which is what stops a
/// `malloc`, a `free` and a 48 KB zeroing on every one — and `struct tlb` is
/// `crates/emu/abi`'s, a layer below this crate, so the field cannot name a
/// type defined here. Moving the frame's definition down is the fix and is not
/// this change. `tools/hand-allocated-drop.py` is what keeps the question
/// asked.
const _: () = assert!(
    !std::mem::needs_drop::<Frame>(),
    "a field of `struct fiber_frame` has grown a destructor, and \
     `crates/emu/tlb` frees the frame with `libc::free`, which runs none."
);

const INT_NONE: c_int = ffi::INT_NONE;
const INT_GPF: c_int = ffi::INT_GPF as c_int;
const INT_TIMER: c_int = ffi::INT_TIMER as c_int;
const INT_JIT_CRASH: c_int = ffi::INT_JIT_CRASH as c_int;
const INT_PREBUILT_RET: c_int = ffi::INT_PREBUILT_RET as c_int;

use run::cpu_step_to_interrupt;

unsafe extern "C" {
    /// Enter the gadget program. `asbestos/guest-arm64/gadgets-aarch64/entry.S`.
    fn fiber_enter(block: *mut Block, frame: *mut Frame, tlb: *mut Tlb) -> c_int;
}

// The counters `crates/asbestos/diag` owns and this increments. Named through
// the dependency since 2026-10-17; they were `extern` statics resolved by the
// linker from `#[no_mangle]` exports, so every touch was `unsafe` and the edge
// was one cargo could not see.
use asbestos_diag::{
    S_DISPATCH_ITERATIONS, ST_BLOCK_CACHE_MISS, ST_BLOCK_COMPILE, ST_CHAIN_ATTEMPTS, ST_INT_CYCLE,
    ST_INT_POKE, ST_INT_POKE_FOREIGN, ST_POKE_CALLS, ST_WX_GIVEUPS, ST_WX_MARKS, ST_WX_RETRIES,
};

/// `emu/mmu.h`. A guest page is 4 KB here whatever the host's is.
const PAGE_BITS: u32 = 12;

/// One quantum, from the kernel's side: enter the JIT, come back with an
/// interrupt, and take a turn at collecting jetsam on the way out.
///
/// The kernel's run loop calls this; [`cpu_step_to_interrupt`] is the loop
/// inside it.
///
/// # Safety
/// Called on a guest thread, with `cpu` and `tlb` its own.
pub unsafe fn cpu_run_to_interrupt(cpu: *mut Cpu, tlb: *mut Tlb) -> c_int {
    // Marks this as a guest thread: a thread with no slot is an embedder's,
    // which is what `iul_thread_marker` said with a variable of its own.
    jitstate::install();
    // The flag another thread pokes to make this one leave. It lives in the
    // `cpu` unless something has pointed it elsewhere.
    unsafe {
        if (*cpu).poked_ptr.is_null() {
            (*cpu).poked_ptr = &raw const (*cpu)._poked;
        }
    }
    // The exclusive monitor is deliberately **not** invalidated here. This runs
    // once per quantum but `fiber_enter` runs per block, and an `ldxr`/`stxr`
    // pair can span two of them when the blocks are not chained. `stxr`
    // invalidates it either way, and so do context switches and signal
    // delivery.
    // SAFETY: the running address space's JIT, which `mem_destroy` frees
    // only once nothing runs in it.
    let asbestos = unsafe { Asbestos::of((*(*cpu).mmu).asbestos) }.expect("a running address space has a JIT");
    let active = &asbestos.active_threads;
    active.fetch_add(1, Ordering::Relaxed);
    unsafe { emu_tlb::tlb_refresh(tlb, (*cpu).mmu) };
    let interrupt = unsafe { cpu_step_to_interrupt(cpu, tlb) };
    unsafe { (*cpu).trapno = interrupt as u32 };
    active.fetch_sub(1, Ordering::Relaxed);

    asbestos.collect_jetsam();
    interrupt
}

/// Make a thread leave the JIT at its next block boundary.
///
/// # Safety
/// `cpu` is live and its `poked_ptr` points at a live flag.
pub unsafe fn cpu_poke(cpu: *mut Cpu) {
    if stage_trace_on() != 0 {
        ST_POKE_CALLS.fetch_add(1, Ordering::Relaxed);
    }
    unsafe { (*(*cpu).poked_ptr).store(true, Ordering::SeqCst) };
}
