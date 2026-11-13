//! The AArch64 cryptographic and permute instructions, in software.
//!
//! The gadgets in `asbestos/guest-arm64/gadgets-aarch64/crypto.S` and
//! `math.S` call these by name, one per instruction, with pointers into the
//! guest's `struct cpu_state` FP register file. Each takes the registers the
//! instruction names and leaves the result in the destination.
//!
//! # Why these are worth having at all
//!
//! `AT_HWCAP` tells a guest which extensions the CPU has, and every crypto
//! library on aarch64 branches on it: OpenSSL, BoringSSL, Go's `crypto`, the
//! Rust `sha2` and `sha3` crates. A bit that is set means the library emits
//! these instructions instead of a table-driven fallback several times slower.
//!
//! Until 2026-09-02 the interpreter advertised only `AES` and `PMULL` while
//! implementing SHA-1, SHA-256, SHA-512 and CRC32 as well — so those four were
//! **dead in practice**, correct and never executed, which is why nothing had
//! ever tested them.
//!
//! # Structure, and what is not here
//!
//! Every instruction is a *pure function over arrays* in one of the modules
//! below, and the `slow_call` entry points in [`slow`] do nothing but read
//! the registers, call one, and write it back. That split is the whole point:
//! a function from `[u32; 4]` to `[u32; 4]` can be tested, and the pointer
//! shim has nothing in it to get wrong.
//!
//! The expected values in the tests are **measured, not recited**. They come
//! from running `tests/guest/src/bin/crypto_probe.rs` on real Apple Silicon —
//! the same static aarch64 binary the emulator runs, in an arm64 container, so
//! the CPU executes the instruction these functions imitate. The first attempt
//! at this used FIPS-197 constants written from memory and four of them were
//! the AES state serialised row-major where a `q` register holds it
//! column-major; they failed against the hardware before the emulator was ever
//! reached.
//!
//! # Untested corners are marked
//!
//! `esize` and `Q` arguments select a lane width and a half-register mode.
//! `crypto_probe` exercises the widths a guest actually emits; the rest are
//! ported as they were. `SHL` on 8- and 16-bit elements stays inline in its
//! gadget, so [`slow::slow_shl`] sees only the wider ones, although
//! [`simd::shift_imm`] answers every width.


mod tables;
pub mod slow;


// ---------------------------------------------------------------------------
// SHA-3
// ---------------------------------------------------------------------------

pub mod sha3 {
    /// `EOR3 Vd, Vn, Vm, Va` — a three-way xor.
    pub fn eor3(n: [u8; 16], m: [u8; 16], a: [u8; 16]) -> [u8; 16] {
        std::array::from_fn(|i| n[i] ^ m[i] ^ a[i])
    }

    /// `BCAX Vd, Vn, Vm, Va` — `Vn EOR (Vm AND NOT Va)`.
    ///
    /// New on 2026-09-02: nothing decoded it, and it is one of the four
    /// instructions a Keccak round emits, so `AT_HWCAP`'s SHA3 bit could not
    /// be set without it.
    pub fn bcax(n: [u8; 16], m: [u8; 16], a: [u8; 16]) -> [u8; 16] {
        std::array::from_fn(|i| n[i] ^ (m[i] & !a[i]))
    }

    /// `RAX1 Vd.2D, Vn.2D, Vm.2D` — `Vn EOR ROL(Vm, 1)`. New for the same
    /// reason as [`bcax`].
    pub fn rax1(n: [u64; 2], m: [u64; 2]) -> [u64; 2] {
        [n[0] ^ m[0].rotate_left(1), n[1] ^ m[1].rotate_left(1)]
    }

    /// `XAR Vd.2D, Vn.2D, Vm.2D, #imm` — xor, then rotate right.
    ///
    /// Serves both encodings: the SVE one is destructive and passes `vn == vd`,
    /// the Advanced SIMD one names three registers. Only the SVE encoding was
    /// decoded until 2026-09-02.
    pub fn xar(n: [u64; 2], m: [u64; 2], imm: u32) -> [u64; 2] {
        let r = imm & 63;
        [(n[0] ^ m[0]).rotate_right(r), (n[1] ^ m[1]).rotate_right(r)]
    }
}

// ---------------------------------------------------------------------------
// SM3 and SM4
// ---------------------------------------------------------------------------

pub mod sm {
    use crate::tables::SM4_SBOX;

    pub fn sm3partw1(vd: [u32; 4], vn: [u32; 4], vm: [u32; 4]) -> [u32; 4] {
        let t: [u32; 4] = std::array::from_fn(|i| vd[i] ^ vn[i]);
        let r0 = t[0] ^ vm[1].rotate_left(15);
        let r1 = t[1] ^ vm[2].rotate_left(15);
        let r2 = t[2] ^ vm[3].rotate_left(15);
        let r3 = t[3] ^ r0.rotate_left(15);
        [r0, r1, r2, r3].map(|r| r ^ r.rotate_left(15) ^ r.rotate_left(23))
    }

    fn sbox_word(x: u32) -> u32 {
        u32::from_le_bytes(x.to_le_bytes().map(|b| SM4_SBOX[b as usize]))
    }

    /// `SM4E` — four SM4 rounds, one per lane of the round-key vector.
    pub fn sm4e(vd: [u32; 4], vn: [u32; 4]) -> [u32; 4] {
        let [mut r0, mut r1, mut r2, mut r3] = vd;
        for &rk in vn.iter() {
            let mut x = sbox_word(r1 ^ r2 ^ r3 ^ rk);
            x = x ^ x.rotate_left(2) ^ x.rotate_left(10) ^ x.rotate_left(18) ^ x.rotate_left(24);
            x ^= r0;
            r0 = r1;
            r1 = r2;
            r2 = r3;
            r3 = x;
        }
        [r0, r1, r2, r3]
    }
}

// ---------------------------------------------------------------------------
// Carry-less multiply
// ---------------------------------------------------------------------------

pub mod pmull {
    //! Carry-less multiplication, on the host's own `PMULL`.
    //!
    //! Every host this builds for has it: the iOS 13 floor is an A9, which has
    //! the crypto extension, and `aes` and `neon` are on in all three targets'
    //! default features -- checked below rather than assumed. It was a
    //! schoolbook loop until 2026-10-17: 54 ns for a 64-bit product against
    //! 0.4, and `PMULL .8B` 13% slower through `slow_call` than in assembly.

    #[cfg(not(all(target_arch = "aarch64", target_feature = "neon", target_feature = "aes")))]
    compile_error!("PMULL needs the host's `aes` and `neon` features");

    /// The instructions, where `#[target_feature]` makes them safe to call.
    mod hw {
        use core::arch::aarch64::{vcreate_p8, vgetq_lane_u64, vmull_p8, vmull_p64, vreinterpretq_u64_p16};

        #[target_feature(enable = "neon,aes")]
        pub(super) fn mul64(a: u64, b: u64) -> u128 {
            vmull_p64(a, b)
        }

        /// Eight byte products, each the halfword at the same index.
        #[target_feature(enable = "neon")]
        pub(super) fn mul8(a: u64, b: u64) -> [u64; 2] {
            let q = vreinterpretq_u64_p16(vmull_p8(vcreate_p8(a), vcreate_p8(b)));
            [vgetq_lane_u64::<0>(q), vgetq_lane_u64::<1>(q)]
        }
    }

    /// Multiply in GF(2)[x].
    #[inline]
    pub fn mul64(a: u64, b: u64) -> u128 {
        // SAFETY: the features `hw` needs are on for every target, as the
        // `compile_error!` above checks.
        unsafe { hw::mul64(a, b) }
    }

    /// Eight byte-by-byte products into eight halfwords. `high` picks the
    /// upper half of each source, which is what `PMULL2` is.
    #[inline]
    pub fn mul8x8(n: [u8; 16], m: [u8; 16], high: bool) -> [u8; 16] {
        let half = |v: [u8; 16]| {
            let (lo, hi) = v.split_at(8);
            u64::from_le_bytes((if high { hi } else { lo }).try_into().expect("eight bytes"))
        };
        // SAFETY: as in `mul64`.
        let [lo, hi] = unsafe { hw::mul8(half(n), half(m)) };
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&lo.to_le_bytes());
        out[8..].copy_from_slice(&hi.to_le_bytes());
        out
    }

    #[cfg(test)]
    mod tests {
        /// The schoolbook definition, as the reference the instruction is
        /// checked against.
        fn reference(a: u64, b: u64) -> u128 {
            (0..64).filter(|i| b >> i & 1 != 0).fold(0, |r, i| r ^ (a as u128) << i)
        }

        #[test]
        fn the_instruction_is_the_definition() {
            let mut x = 0x9e37_79b9_7f4a_7c15u64;
            for _ in 0..10_000 {
                x = x.rotate_left(7) ^ 0x0123_4567;
                let y = x.wrapping_mul(0x2545_f491_4f6c_dd1d);
                assert_eq!(super::mul64(x, y), reference(x, y), "{x:#x} * {y:#x}");
                let (n, m) = ((x as u128 | (y as u128) << 64).to_le_bytes(), (y as u128 | (x as u128) << 64).to_le_bytes());
                for high in [false, true] {
                    let got = super::mul8x8(n, m, high);
                    let off = if high { 8 } else { 0 };
                    for i in 0..8 {
                        let want = reference(n[off + i] as u64, m[off + i] as u64) as u16;
                        assert_eq!(u16::from_le_bytes([got[2 * i], got[2 * i + 1]]), want);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The shifts and the table lookups
// ---------------------------------------------------------------------------

pub mod simd {
    /// What a shift instruction does to one lane.
    #[derive(Clone, Copy)]
    pub enum Shift {
        /// `SHL`.
        Left,
        /// `USHR`, and `SSHR` when `signed`.
        Right,
        /// `USRA`/`SSRA` — shift right and add to the destination.
        RightAccumulate,
        /// `SRI` — shift right and insert, keeping the destination's top bits.
        RightInsert,
        /// `SLI` — shift left and insert, keeping the destination's low bits.
        LeftInsert,
    }

    /// One lane of any of the immediate shifts, at `bits` wide.
    ///
    /// A right shift may be by the full element width (`SSRA Vd.8H, Vn.8H,
    /// #16`): every bit is shifted out and an arithmetic shift leaves the sign.
    /// `x >> 64` is not a shift in Rust or in the host's `lsr`/`asr`, which take
    /// the amount modulo the width, so the full-width case is written out; it
    /// used to accumulate the lane unshifted.
    #[inline(always)]
    fn lane(op: Shift, signed: bool, d: u64, n: u64, shift: u32, bits: u32) -> u64 {
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        let shr = |x: u64| x.checked_shr(shift).unwrap_or(0);
        let sra = |x: u64| {
            if signed {
                // Sign-extend to 64, shift arithmetically, mask back.
                let sh = 64 - bits;
                (((x << sh) as i64) >> (sh + shift).min(63)) as u64 & mask
            } else {
                shr(x & mask)
            }
        };
        match op {
            Shift::Left => (n << shift) & mask,
            Shift::Right => sra(n),
            Shift::RightAccumulate => d.wrapping_add(sra(n)) & mask,
            Shift::RightInsert => {
                // The bits that receive the shifted value are the low
                // `bits - shift` ones; a shift by the whole width inserts
                // nothing and leaves the destination as it was.
                let ins = shr(mask);
                (d & !ins & mask) | (shr(n & mask) & ins)
            }
            Shift::LeftInsert => {
                let ins = (mask << shift) & mask;
                (d & !ins) | ((n << shift) & ins)
            }
        }
    }

    /// Apply `op` to every lane. `size` is the log2 element width in bytes.
    ///
    /// The accumulate and insert forms read the destination, which is why `d`
    /// is a parameter rather than an output only.
    ///
    /// Inlined, and the lane loop specialised per width, so each `slow_call`
    /// entry is a loop over one operation on one width: with all four values
    /// read at run time `USHR .4S` cost 28 ns, against 15 for `SHL .2D`.
    #[inline]
    pub fn shift_imm(
        op: Shift,
        signed: bool,
        d: [u8; 16],
        n: [u8; 16],
        shift: u32,
        size: u32,
        q: bool,
    ) -> [u8; 16] {
        match size {
            0 => lanes::<1>(op, signed, d, n, shift, q),
            1 => lanes::<2>(op, signed, d, n, shift, q),
            2 => lanes::<4>(op, signed, d, n, shift, q),
            _ => lanes::<8>(op, signed, d, n, shift, q),
        }
    }

    /// [`shift_imm`] over `E`-byte lanes.
    #[inline(always)]
    fn lanes<const E: usize>(op: Shift, signed: bool, d: [u8; 16], n: [u8; 16], shift: u32, q: bool) -> [u8; 16] {
        // A 64-bit destination (`.8B`, `.4H`, `.2S`, or a scalar) is written
        // as a whole register: its top half is zeroed for every form, the
        // insert and accumulate ones included, although those *read* the whole
        // of `d`. Keeping `d`'s top half was a defect the C had and this
        // carried (`SLI Vd.8B` left bits 127:64), found against a real kernel.
        let len = if q { 16 } else { 8 };
        let widen = |b: &[u8; E]| {
            let mut w = [0u8; 8];
            w[..E].copy_from_slice(b);
            u64::from_le_bytes(w)
        };
        let mut out = [0u8; 16];
        let lanes = out[..len].as_chunks_mut::<E>().0.iter_mut();
        for ((o, d), n) in lanes.zip(d[..len].as_chunks::<E>().0).zip(n[..len].as_chunks::<E>().0) {
            let r = lane(op, signed, widen(d), widen(n), shift, (E * 8) as u32);
            o.copy_from_slice(&r.to_le_bytes()[..E]);
        }
        out
    }
}

// The `extern "C"` entry points the gadgets called with raw pointers into the
// FP register file were here until 2026-10-17; every instruction above is a
// `slow_call` into [`slow`] now.

#[cfg(test)]
mod tests;
