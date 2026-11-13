//! `struct cpu_state` — Rust's, since 2026-09-08.
//!
//! # Why it moved, and why it had not
//!
//! `crates/kernel/taskview`'s `task` module said what stayed generated and
//! why: "`struct cpu_state`, whose layout `asbestos/offsets.c` publishes to the
//! assembly". **`asbestos/offsets.c` has not existed since 2026-09-06** —
//! `crates/tools/cpuoffsets` publishes that layout, with `offset_of!`, in Rust.
//! The reason outlived the file it was about, which is the shape
//! `docs/remaining-c.md` is kept for.
//!
//! # The assembly is the consumer, so the offsets are asserted here
//!
//! Six `.S` files index this struct through `cpu-offsets.h`, and a wrong offset
//! is not a compile error anywhere — it is a gadget reading the field next to
//! the one it wanted. Every offset the gadgets use is a `const` assertion
//! below, so the *definition* carries its own contract rather than relying on
//! the generator to notice.
//!
//! # Two C aggregates that Rust does not need
//!
//! **The general-purpose registers were an anonymous union** of a struct of
//! `x0..x30` and a `regs[31]` array over the same bytes, with a
//! `static_assert` in the header pinning `offsetof(x0) == offsetof(regs[0])`.
//! Here they are the array, and `CPU_x0` is `offset_of!(cpu_state, regs)`: the
//! assertion is structurally true and there is nothing to assert. Twenty-eight
//! call sites lost a `.__bindgen_anon_1` and two `.x21`s became `.regs[21]`.
//!
//! **`union arm64_vreg` had seven members and Rust reads two.** `q`, `s`, `h`,
//! `f32` and `f64` were views nothing here takes; what is left is `d` for the
//! register-file copies and `bytes` for a whole-register load. It keeps
//! `align(16)`, because `__uint128_t q` is what gave the C union its alignment
//! and `fp`'s offset depends on it — dropping it moves every field after `fp`
//! by eight bytes and the gadgets read the wrong ones. The check is that
//! `cpu-offsets.h` comes out byte-identical, and it does.

#![allow(non_camel_case_types)]

use crate::{addr_t, dword_t, mmu};
use std::sync::atomic::AtomicBool;

/// One NEON register: 128 bits, as two halves or as sixteen bytes.
///
/// The C union had seven — `q`, `d`, `s`, `h`, `b`, `f32`, `f64` — and only
/// two are ever taken here: `d` for the register-file copies a signal frame
/// and `PTRACE_GETREGSET` make, and the bytes for the vector loads and
/// stores in `crates/emu/tlb`. The other five were views nothing takes; the
/// bytes are the same either way and the *assembly* addresses them by offset,
/// not by name.
///
/// `align(16)` is load-bearing: `__uint128_t q` is what gave the C union its
/// alignment, and `fp`'s offset — and so every field after it — depends on it.
///
/// A struct since 2026-10-17, with the byte view as methods: a union made every
/// read `unsafe` for a fact (any bit pattern is valid for either member) that
/// `to_ne_bytes` states without one. Native-endian is the union's own meaning:
/// the bytes as they sit in memory.
#[repr(C, align(16))]
#[derive(Copy, Clone, Default, Debug)]
pub struct arm64_vreg {
    /// The two 64-bit halves: `d[0]` is the low one.
    pub d: [u64; 2],
}

impl arm64_vreg {
    /// The sixteen bytes, for a whole-register load or store.
    ///
    /// `#[inline]`, and measured: this crate is built at `opt-level = "z"`,
    /// and called across crates from the `slow_call` crypto helpers (which are
    /// built at 3) these two stayed calls -- `EOR3` cost 12.1 ns against 7.3
    /// for the gadget it replaced.
    #[inline]
    pub fn bytes(&self) -> [u8; 16] {
        let [lo, hi] = self.d.map(u64::to_ne_bytes);
        let mut b = [0; 16];
        b[..8].copy_from_slice(&lo);
        b[8..].copy_from_slice(&hi);
        b
    }

    #[inline]
    pub fn from_bytes(b: [u8; 16]) -> arm64_vreg {
        let (lo, hi) = b.split_at(8);
        arm64_vreg { d: [lo, hi].map(|h| u64::from_ne_bytes(h.try_into().expect("eight bytes"))) }
    }
}

/// The guest CPU.
///
/// **Not `Copy` since 2026-10-16**, because `_poked` is an atomic another
/// thread stores to. `crates/asbestos/dispatch` saves and restores the state
/// across a fiber switch with [`copy_state`], which is the 896-byte memcpy it
/// always was with that one byte left out.
#[repr(C)]
pub struct cpu_state {
    pub mmu: *mut mmu,
    pub cycle: std::ffi::c_long,
    /// `x0`..`x30`. The link register is `regs[30]`.
    ///
    /// `x31` is not here: it reads as zero or as the stack pointer depending
    /// on the instruction, which is a decoding question and not a register.
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    /// The condition flags, one byte each so that a gadget can address them.
    ///
    /// **Stale in a running guest.** The JIT maintains `nzcv` directly and
    /// these four are not written on the fast path, so anything reading the
    /// flags reads `nzcv` — `crates/kernel/signaldeliver`'s `snapshot_regs`
    /// says so at the one place it matters.
    pub nf: u8,
    pub zf: u8,
    pub cf: u8,
    pub vf: u8,
    /// The four flags packed as the CPSR has them, bits 31:28.
    pub nzcv: u32,
    pub fp: [arm64_vreg; 32],
    pub fpcr: u32,
    pub fpsr: u32,
    /// `TPIDR_EL0`.
    pub tls_ptr: u64,
    /// The exclusive monitor for `LDXR`/`STXR`. `excl_val2` is the second half
    /// of an `LDXP`.
    pub excl_addr: u64,
    pub excl_val: u64,
    pub excl_val2: u64,
    pub segfault_addr: addr_t,
    pub segfault_was_write: bool,
    /// An **alignment** fault rather than a mapping one, which is a different
    /// signal: an atomic crossing a sixteen-byte granule raises `SIGBUS` on
    /// real hardware, because an unaligned atomic is not atomic. Set by the
    /// atomic helpers in `crates/emu/tlb`, read and cleared by `handle_int_gpf`.
    /// Before 2026-09-02 there was no check and the helper performed the access
    /// anyway, which killed the *emulator*: any guest could do it with one
    /// instruction.
    pub segfault_was_align: bool,
    /// Where in the block's gadget array the fault happened — the threaded-code
    /// cursor, `_pc`, as the segfault path in `gadgets.h` leaves it.
    ///
    /// The JIT reports `pc` as the **start of the block**, because that is what
    /// `inline_chain` stores on entry and nothing writes it again until the
    /// block ends. So a `SIGSEGV` delivered to the guest named the wrong
    /// instruction, `rt_sigreturn` resumed there, and everything in the block
    /// before the fault ran a second time — a store to a counter, a flag or a
    /// queue index silently doubled.
    ///
    /// This is the one thing the gadget knows and the handler cannot work out:
    /// the fault is not a host `SIGSEGV`, so nothing has been unwound and the
    /// cursor is still live in a register. Turning it back into a guest pc is
    /// `crates/asbestos/gen`'s `guest_pc_at_offset`, which re-decodes the block.
    ///
    /// A field of its own since it was moved out of `LOCAL_value`, the
    /// crosspage scratch buffer — any access straddling a page overwrote it,
    /// and that buffer's own comment said "for debugging".
    pub fault_code_pc: u64,
    pub trapno: dword_t,
    /// Where the poke flag the gadgets test is: `_poked` below, of the task's
    /// own `cpu_state` -- a fiber frame's copy points at the task's.
    pub poked_ptr: *const AtomicBool,
    /// Written by another thread to make this one leave the interpreter.
    ///
    /// An `AtomicBool` since 2026-10-16, where it was a `bool` that the poker
    /// stored to through `AtomicBool::from_ptr` and this crate's users read
    /// and wrote plainly -- `hand_back` read it, overwrote the whole struct and
    /// wrote the old value back, so a poke landing between the two was lost.
    /// Being an atomic also makes a `&cpu_state` sound: every byte another
    /// thread writes is now inside an `UnsafeCell`. A `&mut` still is not.
    /// The gadgets read it with a plain `ldrb`, which is a relaxed load.
    pub _poked: AtomicBool,
    /// `PSTATE.DIT` (FEAT_DIT), which is bit 24 of the pstate word a signal
    /// frame and `PTRACE_GETREGSET` carry. It is state and no more: nothing here
    /// has data-dependent timing to switch off. Not with the flags in `nzcv`,
    /// because the gadgets that set the flags store that whole word.
    pub dit: bool,
}

impl Default for cpu_state {
    fn default() -> Self {
        Self {
            mmu: std::ptr::null_mut(),
            cycle: 0,
            regs: [0; 31],
            sp: 0,
            pc: 0,
            nf: 0,
            zf: 0,
            cf: 0,
            vf: 0,
            nzcv: 0,
            fp: [arm64_vreg::default(); 32],
            fpcr: 0,
            fpsr: 0,
            tls_ptr: 0,
            excl_addr: 0,
            excl_val: 0,
            excl_val2: 0,
            segfault_addr: 0,
            segfault_was_write: false,
            segfault_was_align: false,
            fault_code_pc: 0,
            trapno: 0,
            poked_ptr: std::ptr::null(),
            _poked: AtomicBool::new(false),
            dit: false,
        }
    }
}

/// Copy every field of `src` but `_poked` into `dst`.
///
/// The flag belongs to the `poked_ptr` channel and is never copied: a copy
/// would resurrect a stale `true`, or overwrite a poke another thread has just
/// stored. Two byte copies around it, which is what the struct copy this
/// replaced was, less one byte.
///
/// A pointer and not a `&` for `src` too: a fork reads its parent's, and the
/// parent may be running on another thread -- `become_new_init_child`'s is init.
///
/// # Safety
/// Both are live, and no other thread writes any field of `dst` but `_poked`.
pub unsafe fn copy_state(dst: *mut cpu_state, src: *const cpu_state) {
    const POKED: usize = std::mem::offset_of!(cpu_state, _poked);
    const SIZE: usize = size_of::<cpu_state>();
    let s = src.cast::<u8>();
    let d = dst.cast::<u8>();
    // SAFETY: the caller's contract; both ranges are inside the struct and
    // skip the one atomic byte. An untyped copy, so padding is copied as is.
    unsafe {
        std::ptr::copy_nonoverlapping(s, d, POKED);
        std::ptr::copy_nonoverlapping(s.add(POKED + 1), d.add(POKED + 1), SIZE - POKED - 1);
    }
}

/// The offsets the gadgets index with, asserted where the struct is defined.
///
/// A wrong one is a gadget reading the field beside the one it wanted, and
/// nothing else in the build would say so. The numbers are the ones
/// `cpu-offsets.h` held on 2026-09-08, before this definition replaced
/// bindgen's — and these are what checks that the struct still fits what the
/// vector gadgets can address.
///
/// `emu/arch/arm64/cpu.h` also had `collapse_flags` and `expand_flags`, two
/// empty bodies "for compatibility with the x86 interface"; that backend was
/// removed before this fork was published.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<arm64_vreg>() == 16);
    assert!(align_of::<arm64_vreg>() == 16, "fp's offset depends on it");

    assert!(offset_of!(cpu_state, cycle) == 8);
    assert!(offset_of!(cpu_state, regs) == 16, "CPU_x0");
    assert!(offset_of!(cpu_state, sp) == 264);
    assert!(offset_of!(cpu_state, pc) == 272);
    assert!(offset_of!(cpu_state, nf) == 280);
    assert!(offset_of!(cpu_state, zf) == 281);
    assert!(offset_of!(cpu_state, cf) == 282);
    assert!(offset_of!(cpu_state, vf) == 283);
    assert!(offset_of!(cpu_state, nzcv) == 284);
    assert!(offset_of!(cpu_state, fp) == 288);
    assert!(offset_of!(cpu_state, fpcr) == 800);
    assert!(offset_of!(cpu_state, fpsr) == 804);
    assert!(offset_of!(cpu_state, tls_ptr) == 808);
    assert!(offset_of!(cpu_state, excl_addr) == 816);
    assert!(offset_of!(cpu_state, excl_val) == 824);
    assert!(offset_of!(cpu_state, excl_val2) == 832);
    assert!(offset_of!(cpu_state, segfault_addr) == 840);
    assert!(offset_of!(cpu_state, segfault_was_write) == 848);
    assert!(offset_of!(cpu_state, segfault_was_align) == 849);
    assert!(offset_of!(cpu_state, fault_code_pc) == 856);
    assert!(offset_of!(cpu_state, trapno) == 864);
    assert!(offset_of!(cpu_state, poked_ptr) == 872);
    assert!(offset_of!(cpu_state, _poked) == 880);
    assert!(offset_of!(cpu_state, dit) == 881);

    // `emu/arch/arm64/cpu.h`'s own assertion: the vector gadgets address this
    // struct with a 16-bit immediate.
    assert!(size_of::<cpu_state>() < 0xffff);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_state_default_has_zero_register_state() {
        let cpu = cpu_state::default();
        assert!(cpu.mmu.is_null());
        assert!(cpu.regs.iter().all(|&register| register == 0));
        assert_eq!(cpu.sp, 0);
        assert_eq!(cpu.pc, 0);
        assert_eq!(cpu.nzcv, 0);
        assert_eq!(cpu.fp.len(), 32);
        assert!(!cpu.segfault_was_write);
        assert!(!cpu.segfault_was_align);
        assert!(cpu.poked_ptr.is_null());
        assert!(!cpu._poked.load(std::sync::atomic::Ordering::Relaxed));
        assert!(!cpu.dit);
    }
}
