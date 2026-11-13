//! Loads and stores: every way a guest reaches memory.
//!
//! The largest class, and the one where a mistake is quietest — a load from
//! the wrong address returns *something*, and a store to one corrupts memory
//! that is read much later. Eight groups:
//!
//! | | |
//! | --- | --- |
//! | atomics | the LSE read-modify-writes, `CAS` and `CASP` |
//! | exclusives | `LDXR`/`STXR`, the pair forms, and the ordered `LDAR`/`STLR` |
//! | literal | `LDR` from a pc-relative address |
//! | unsigned immediate | the scaled offset form, which is most of them |
//! | register offset | with an extend and a scale |
//! | unscaled and indexed | `LDUR`/`STUR` and the pre- and post-index forms |
//! | pair | `LDP`/`STP`, including the prologue and epilogue idioms |
//! | SIMD structures | `LD1`–`LD4` and their single-lane and replicating forms |
//!
//! # The three-gadget shape, and what a fused gadget replaces
//!
//! The general form of a memory access here is three gadgets: compute the
//! address, do the access, write the result back to a register. Most of the
//! code below is recognising the cases where one gadget can do all three,
//! because that is three dispatches saved on the single commonest kind of
//! instruction there is.
//!
//! The condition is nearly always the same: **no register 31 and no
//! sign-extension of a narrow load**. Register 31 is `SP` in the base position
//! and `XZR` in the data position, and the fused gadgets are the ones that
//! assume neither.
//!
//! # The three that are not an optimisation
//!
//! - **`CASP` at `sz = 1` is a true sixteen-byte atomic**, and it is matched
//!   before the single-register `CAS` for that reason: handling it as a 64-bit
//!   compare-and-swap tears the pair. That is exactly the `libpas`
//!   `pas_versioned_field {value, version}` corruption that hangs Bun.
//! - **`STXP` must be a real compare-and-swap** against what `LDXP` loaded.
//!   Emulating it as a store pair that always succeeds tears every lock-free
//!   algorithm built on the exclusive pair.
//! - **The barriers around the ordered forms are real**, because guest threads
//!   are host threads sharing host memory.
//!
//! # What checks it
//!
//! `atomics_probe` and `xpage_probe` for the first two groups, against a real
//! CPU; and every other guest test for the rest, because a program whose loads
//! and stores are wrong does not run at all.

use crate::gadgets::*;
use crate::{DECODED, Gadget, Gen, decode};
use std::ffi::c_int;

#[path = "addressed.rs"]
mod addressed;
#[path = "atomics.rs"]
mod atomics;
#[path = "simd_access.rs"]
mod simd_access;

pub fn decode(g: &mut Gen, insn: u32) -> c_int {
    // The LSE read-modify-writes.
    if insn & 0x3f20_0c00 == 0x3820_0000 {
        return atomics::atomic_rmw(g, insn);
    }
    // `CASP` at both widths, **before** the single-register `CAS`: the 64-bit
    // one is a sixteen-byte atomic and the plain `CAS` mask would swallow it.
    if insn & 0xffa0_7c00 == 0x4820_7c00 {
        return atomics::casp(g, insn, true);
    }
    if insn & 0xffa0_7c00 == 0x0820_7c00 {
        return atomics::casp(g, insn, false);
    }
    if insn & 0x3fa0_7c00 == 0x08a0_7c00 {
        return atomics::cas(g, insn);
    }
    if insn & 0x3b00_0000 == 0x1800_0000 {
        return addressed::literal(g, insn);
    }
    if insn & 0x3b00_0000 == 0x3900_0000 {
        return addressed::unsigned_imm(g, insn);
    }
    if insn & 0x3b20_0c00 == 0x3820_0800 {
        return addressed::reg_offset(g, insn);
    }
    if insn & 0x3a00_0000 == 0x2800_0000 {
        return addressed::pair(g, insn);
    }
    if insn & 0x3b20_0000 == 0x3800_0000 {
        return addressed::unscaled_or_indexed(g, insn);
    }
    if insn & 0x3f00_0000 == 0x0800_0000 {
        return atomics::exclusive(g, insn);
    }
    if insn & 0xbfbf_0000 == 0x0c00_0000 {
        return simd_access::simd_structs(g, insn, false);
    }
    if insn & 0xbfa0_0000 == 0x0c80_0000 {
        return simd_access::simd_structs(g, insn, true);
    }
    if insn & 0xbf80_0000 == 0x0d00_0000 {
        return simd_access::simd_single(g, insn, false);
    }
    if insn & 0xbf80_0000 == 0x0d80_0000 {
        return simd_access::simd_single(g, insn, true);
    }

    g.undefined()
}

// ---------------------------------------------------------------------------
// The address helpers, which every group starts with
// ---------------------------------------------------------------------------

impl Gen<'_> {
    /// Address = `Xn + offset`. The offset is packed above the register and is
    /// signed, so it goes through `as u64` rather than a shift of a negative.
    pub(super) fn addr_imm(&mut self, rn: u32, offset: i64) {
        self.gadget(gadget_calc_addr_imm);
        self.emit(rn as u64 | ((offset as u64) << 8));
    }

    /// Address = `Xn`, for a post-indexed access where the offset applies
    /// afterwards.
    pub(super) fn addr_base(&mut self, rn: u32) {
        self.gadget(gadget_calc_addr_base);
        self.emit(rn as u64);
    }

    /// Address = `Xn + extend(Xm) << shift`.
    pub(super) fn addr_reg(&mut self, rn: u32, rm: u32, option: u32, shift: u32) {
        self.gadget(gadget_calc_addr_reg);
        self.emit(
            rn as u64 | ((rm as u64) << 8) | ((option as u64) << 16) | ((shift as u64) << 24),
        );
    }

    /// Move the computed address on by a constant, for the structure loads.
    pub(super) fn addr_advance(&mut self, by: u64) {
        self.gadget(gadget_advance_addr);
        self.emit(by);
    }

    /// Write the scratch value into a register.
    pub(super) fn store_reg(&mut self, rt: u32) {
        self.gadget(gadget_store_reg);
        self.emit(rt as u64);
    }

    /// Read a register into the scratch value.
    pub(super) fn load_reg(&mut self, rt: u32) {
        self.gadget(gadget_load_reg);
        self.emit(rt as u64);
    }

    /// A barrier, for the acquire and release forms.
    pub(super) fn barrier(&mut self) {
        self.gadget(gadget_dmb);
    }
}

/// Whether `(size, V, opc)` names a load or store that exists.
///
/// The unsigned-immediate, unscaled, indexed, unprivileged and register-offset
/// forms all share this table, and **none of them was applying it**: `opc` was
/// read for the bits that pick load-against-store and sign-extension, and the
/// combinations that name nothing were decoded as whichever neighbour those
/// bits happened to select. `tests/guest/src/bin/decode_probe.rs` swept the
/// group and found 205 encodings a real kernel answers `SIGILL` for.
///
/// The rules, and each is a width rule:
///
/// - A **SIMD** access has a load and a store at every size, and only at
///   `size == 0` the two extra opcodes — which are the 128-bit pair, the one
///   place the size field does not give the width.
/// - A 32-bit integer load can sign-extend to 64 (`LDRSW`); there is nothing
///   for a 64-bit one to extend to, so `(2, 3)` and `(3, 3)` name nothing.
/// - `(3, 2)` is `PRFM`, which exists only in the forms that have one.
///
/// `prefetch` is that last distinction: the unsigned-immediate, unscaled and
/// register-offset forms have a prefetch and the pre-indexed, post-indexed and
/// unprivileged ones do not.
pub(super) fn register_form_allocated(size: u32, v: u32, opc: u32, prefetch: bool) -> bool {
    if v != 0 {
        return opc < 2 || size == 0;
    }
    match (size, opc) {
        (2, 3) | (3, 3) => false,
        (3, 2) => prefetch,
        _ => true,
    }
}

/// The plain load gadget for a width, and whether it sign-extends.
pub(super) fn load_gadget(size: u32, sign_extend: bool, to64: bool) -> Option<Gadget> {
    Some(match (size, sign_extend) {
        (0, false) => gadget_load8,
        (1, false) => gadget_load16,
        (2, false) => gadget_load32,
        (3, _) => gadget_load64,
        (0, true) => {
            if to64 {
                gadget_load8_sx64
            } else {
                gadget_load8_sx32
            }
        }
        (1, true) => {
            if to64 {
                gadget_load16_sx64
            } else {
                gadget_load16_sx32
            }
        }
        (2, true) => gadget_load32_sx,
        _ => return None,
    })
}

pub(super) fn store_gadget(size: u32) -> Option<Gadget> {
    Some(match size {
        0 => gadget_store8,
        1 => gadget_store16,
        2 => gadget_store32,
        3 => gadget_store64,
        _ => return None,
    })
}

/// The SIMD load and store for a width in bytes.
pub(super) fn simd_gadget(bytes: u32, is_load: bool) -> Option<Gadget> {
    Some(match (bytes, is_load) {
        (1, true) => gadget_ldr_simd_b,
        (2, true) => gadget_ldr_simd_h,
        (4, true) => gadget_ldr_simd_s,
        (8, true) => gadget_ldr_simd_d,
        (16, true) => gadget_ldr_simd_q,
        (1, false) => gadget_str_simd_b,
        (2, false) => gadget_str_simd_h,
        (4, false) => gadget_str_simd_s,
        (8, false) => gadget_str_simd_d,
        (16, false) => gadget_str_simd_q,
        _ => return None,
    })
}

#[cfg(test)]
#[path = "ldst_tests.rs"]
mod tests;
