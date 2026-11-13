//! The cryptographic, table and vector immediate-shift instructions as
//! `slow_call`s.
//!
//! Each reads the vector registers its operand word names out of the running
//! frame's register file and writes its destination there. Until 2026-10-17
//! every one of these was a forty-line gadget in `crypto.S` -- save x19-x28 and
//! the link register, `save_c`, compute four register addresses, `bl` an
//! `extern "C"` helper here that took raw pointers into the register file, and
//! put everything back. The register file is an array now, borrowed once, and
//! `TBL`'s wrap from `v31` to `v0` is an index modulo 32 rather than pointer
//! arithmetic against the file's base.
//!
//! The operand layouts are the decoder's, unchanged: `rd | rn << 8 | rm << 16`,
//! with a fourth field at bit 24 where an instruction has one.

use crate::simd::{Shift, shift_imm};
use crate::{pmull, sha3, sm};
use emu_abi::{SLOW_OK, arm64_vreg, cpu_state, tlb};
use std::ffi::c_int;

type File = [arm64_vreg; 32];

/// The register a five-bit field at `at` names.
fn field(arg: u64, at: u32) -> usize {
    (arg >> at) as usize & 0x1f
}

fn words(v: &arm64_vreg) -> [u32; 4] {
    let b = v.bytes();
    let (chunks, _) = b.as_chunks::<4>();
    std::array::from_fn(|i| u32::from_ne_bytes(chunks[i]))
}

fn from_words(w: [u32; 4]) -> arm64_vreg {
    arm64_vreg::from_bytes(w.map(u32::to_ne_bytes).as_flattened().try_into().expect("sixteen bytes"))
}

/// Define a slow call over the register file: `$file` is it, `$arg` the
/// operand word.
macro_rules! slow {
    ($($(#[$m:meta])* fn $name:ident($file:ident, $arg:ident) $body:block)*) => {$(
        $(#[$m])*
        ///
        /// # Safety
        /// The `slow_call` gadget's: `cpu` is the running frame's, and nothing
        /// else holds a reference to its vector registers.
        pub unsafe extern "C" fn $name(cpu: *mut cpu_state, _tlb: *mut tlb, _addr: u64, $arg: u64) -> c_int {
            // SAFETY: the caller's contract. Only `fp` is borrowed, so the
            // atomic another thread pokes is not covered by it.
            let $file: &mut File = unsafe { &mut (*cpu).fp };
            $body
            SLOW_OK
        }
    )*};
}

slow! {
    /// `EOR3 Vd.16B, Vn.16B, Vm.16B, Va.16B`.
    fn slow_eor3(f, arg) {
        let (d, n, m, a) = (field(arg, 0), field(arg, 8), field(arg, 16), field(arg, 24));
        f[d] = arm64_vreg::from_bytes(sha3::eor3(f[n].bytes(), f[m].bytes(), f[a].bytes()));
    }

    /// `BCAX Vd.16B, Vn.16B, Vm.16B, Va.16B`.
    fn slow_bcax(f, arg) {
        let (d, n, m, a) = (field(arg, 0), field(arg, 8), field(arg, 16), field(arg, 24));
        f[d] = arm64_vreg::from_bytes(sha3::bcax(f[n].bytes(), f[m].bytes(), f[a].bytes()));
    }

    /// `RAX1 Vd.2D, Vn.2D, Vm.2D`.
    fn slow_rax1(f, arg) {
        let (d, n, m) = (field(arg, 0), field(arg, 8), field(arg, 16));
        f[d].d = sha3::rax1(f[n].d, f[m].d);
    }

    /// `XAR`, Advanced SIMD and SVE: the rotate is the byte at bit 24.
    fn slow_xar(f, arg) {
        let (d, n, m) = (field(arg, 0), field(arg, 8), field(arg, 16));
        f[d].d = sha3::xar(f[n].d, f[m].d, (arg >> 24) as u32 & 0xff);
    }

    /// SVE `EOR Zd.D, Zn.D, Zm.D`, over the 128 bits this emulator has.
    fn slow_sve_eor(f, arg) {
        let (d, n, m) = (field(arg, 0), field(arg, 8), field(arg, 16));
        f[d].d = [f[n].d[0] ^ f[m].d[0], f[n].d[1] ^ f[m].d[1]];
    }

    /// `SM3PARTW1`.
    fn slow_sm3partw1(f, arg) {
        let (d, n, m) = (field(arg, 0), field(arg, 8), field(arg, 16));
        f[d] = from_words(sm::sm3partw1(words(&f[d]), words(&f[n]), words(&f[m])));
    }

    /// `SM4E`.
    fn slow_sm4e(f, arg) {
        let (d, n) = (field(arg, 0), field(arg, 8));
        f[d] = from_words(sm::sm4e(words(&f[d]), words(&f[n])));
    }

    /// `PMULL{2}`: operand `rd | rn << 8 | rm << 16 | q << 24 | size << 26`.
    /// `size` 0 is eight byte products and 3 is one 64-bit product; 1 and 2,
    /// which no encoding produces, do nothing, as they did in C.
    fn slow_pmull(f, arg) {
        let (d, n, m) = (field(arg, 0), field(arg, 8), field(arg, 16));
        let high = (arg >> 24) & 1 != 0;
        match (arg >> 26) & 3 {
            0 => f[d] = arm64_vreg::from_bytes(pmull::mul8x8(f[n].bytes(), f[m].bytes(), high)),
            3 => {
                let i = usize::from(high);
                let p = pmull::mul64(f[n].d[i], f[m].d[i]);
                f[d].d = [p as u64, (p >> 64) as u64];
            }
            _ => {}
        }
    }

    /// `TBL`: an index past the end of the table gives zero.
    fn slow_tbl(f, arg) {
        f[field(arg, 0)] = arm64_vreg::from_bytes(table_lookup(f, arg, false));
    }

    /// `TBX`: an index past the end **leaves the destination byte alone**,
    /// which is the whole difference from `TBL`.
    fn slow_tbx(f, arg) {
        f[field(arg, 0)] = arm64_vreg::from_bytes(table_lookup(f, arg, true));
    }
}

/// The immediate shifts: operand `rd | rn << 8 | shift << 16 | esize << 24 |
/// q << 28`, `shift` eight bits wide because a right shift can be by 64.
/// These were `extern "C"` helpers behind a gadget each until 2026-10-17, with
/// the same save-everything glue `slow_call` has once.
fn shift(f: &mut File, arg: u64, op: Shift, signed: bool) {
    let (d, n) = (field(arg, 0), field(arg, 8));
    let amount = (arg >> 16) as u32 & 0xff;
    let esize = (arg >> 24) as u32 & 0xf;
    let q = (arg >> 28) & 1 != 0;
    f[d] = arm64_vreg::from_bytes(shift_imm(op, signed, f[d].bytes(), f[n].bytes(), amount, esize, q));
}

slow! {
    /// `SHL` (vector): 32- and 64-bit elements; the gadget does the narrower.
    fn slow_shl(f, arg) { shift(f, arg, Shift::Left, false) }
    /// `SLI` (vector).
    fn slow_sli(f, arg) { shift(f, arg, Shift::LeftInsert, false) }
    /// `USHR` (vector).
    fn slow_ushr(f, arg) { shift(f, arg, Shift::Right, false) }
    /// `SSHR` (vector).
    fn slow_sshr(f, arg) { shift(f, arg, Shift::Right, true) }
    /// `USRA` (vector).
    fn slow_usra(f, arg) { shift(f, arg, Shift::RightAccumulate, false) }
    /// `SSRA` (vector).
    fn slow_ssra(f, arg) { shift(f, arg, Shift::RightAccumulate, true) }
    /// `SRI` (vector).
    fn slow_sri(f, arg) { shift(f, arg, Shift::RightInsert, false) }
}

/// The table lookups: operand `rd | rn << 8 | rm << 16 | len << 24 | q << 28`.
/// The table is `len + 1` consecutive registers from `rn`, and the register
/// file wraps: `v31` is followed by `v0`. On the host's own `TBL`/`TBX`, which
/// is base Advanced SIMD.
fn table_lookup(f: &File, arg: u64, keep: bool) -> [u8; 16] {
    let (d, n, m) = (field(arg, 0), field(arg, 8), field(arg, 16));
    let len = (arg >> 24) as usize & 3;
    let q = (arg >> 28) & 1 != 0;
    let table: [[u8; 16]; 4] = std::array::from_fn(|k| f[(n + k) % 32].bytes());
    // SAFETY: `neon` is on for every target, as `pmull` checks at compile time.
    let mut out = unsafe { lookup(table, len, f[m].bytes(), f[d].bytes(), keep) };
    if !q {
        out[8..].fill(0);
    }
    out
}

/// `TBL`, or `TBX` when `keep`, over the first `len + 1` registers of `table`.
#[target_feature(enable = "neon")]
fn lookup(table: [[u8; 16]; 4], len: usize, idx: [u8; 16], dest: [u8; 16], keep: bool) -> [u8; 16] {
    use core::arch::aarch64::*;
    let t: [uint8x16_t; 4] = table.map(|r| to_vec(r));
    let (i, d) = (to_vec(idx), to_vec(dest));
    let r = match (len, keep) {
        (0, false) => vqtbl1q_u8(t[0], i),
        (1, false) => vqtbl2q_u8(uint8x16x2_t(t[0], t[1]), i),
        (2, false) => vqtbl3q_u8(uint8x16x3_t(t[0], t[1], t[2]), i),
        (_, false) => vqtbl4q_u8(uint8x16x4_t(t[0], t[1], t[2], t[3]), i),
        (0, true) => vqtbx1q_u8(d, t[0], i),
        (1, true) => vqtbx2q_u8(d, uint8x16x2_t(t[0], t[1]), i),
        (2, true) => vqtbx3q_u8(d, uint8x16x3_t(t[0], t[1], t[2]), i),
        (_, true) => vqtbx4q_u8(d, uint8x16x4_t(t[0], t[1], t[2], t[3]), i),
    };
    from_vec(r)
}

#[target_feature(enable = "neon")]
fn to_vec(b: [u8; 16]) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::*;
    let x = u128::from_le_bytes(b);
    vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(x as u64), vcreate_u64((x >> 64) as u64)))
}

#[target_feature(enable = "neon")]
fn from_vec(v: core::arch::aarch64::uint8x16_t) -> [u8; 16] {
    use core::arch::aarch64::*;
    let q = vreinterpretq_u64_u8(v);
    (u128::from(vgetq_lane_u64::<0>(q)) | u128::from(vgetq_lane_u64::<1>(q)) << 64).to_le_bytes()
}
