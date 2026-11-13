//! The slow-call protocol: what `memory.S`'s `slow_call` gadget calls.
//!
//! Here rather than in `crates/emu/tlb`, where it began, because the helpers
//! live in more than one crate -- the memory ones in `emu-tlb`, the
//! cryptographic ones in `asbestos-crypto` -- and both can name this one.

use crate::{cpu_state, tlb};

/// A slow path the `slow_call` gadget runs: `memory.S`'s one exit to Rust that
/// is not the miss handler.
///
/// The gadget passes the CPU, the TLB, the address the block computed and the
/// one operand word the decoder emitted, and the helper does the rest itself --
/// reads the registers it needs from `cpu`, writes the ones it answers. That is
/// what each family's gadget did by hand in assembly until 2026-10-17: decode
/// `rs`/`rt` out of the operand, load them, `save_c`, call, `restore_c`, store
/// the result, and carry a `segfault_exit` of its own. See CLAUDE.md, Assembly.
///
/// The answer is [`SLOW_OK`] or a fault, with `tlb->segfault_addr` set (which
/// `read_ptr`/`write_ptr` and the alignment check already do); the gadget's
/// one `segfault_exit` reports it.
pub type SlowFn = unsafe extern "C" fn(cpu: *mut cpu_state, tlb: *mut tlb, addr: u64, arg: u64) -> std::ffi::c_int;

pub const SLOW_OK: std::ffi::c_int = 0;
pub const SLOW_READ_FAULT: std::ffi::c_int = 1;
pub const SLOW_WRITE_FAULT: std::ffi::c_int = 2;
