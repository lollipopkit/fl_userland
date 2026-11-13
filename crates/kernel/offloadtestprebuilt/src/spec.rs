//! What a generated spec_fn is written against.
//!
//! `tools/prebuilt_gadget_gen/gen.sh` turns a guest function's disassembly into
//! a Rust module, and every operation it emits is one call into this one — so
//! the *generator* only has to decide which helper, and the semantics of each
//! live here where they can be read and tested.
//!
//! It was a 30-line block of `PB_*` macros pasted into the top of every
//! generated C file until 2026-09-09. Six copies of `#define PB_LDR`, and a
//! rule enforced by repetition is enforced once per copy.
//!
//! # Why every arithmetic operation is a function
//!
//! C's unsigned arithmetic wraps and Rust's panics in a debug build, so a
//! translated `add x0, x0, x1` written as `+` would abort the emulator the
//! first time a guest register overflowed — which for a hash function is
//! immediately. Naming the operation also makes the generator's output say
//! *which* AArch64 semantics it meant: `sar` and `shr` are the same `>>` in C
//! and different functions here.
//!
//! Shift amounts are masked to the register width, which is what AArch64 does
//! for a register shift and what Rust panics on.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Cpu, Tlb};

/// The guest's registers, reached through the raw `cpu` pointer.
///
/// Not a `&mut Cpu`: a generated body hands `cpu` to [`crate::call`], which may
/// re-enter the interpreter and run guest code that writes the same struct, and
/// a borrow held across that is the aliasing UB
/// `docs/changelog/2026-08-31-a-release-build-hung-closing-a-descriptor.md` records.
/// Every access is its own dereference for that reason.
#[derive(Clone, Copy)]
pub struct Regs(pub *mut Cpu);

impl Regs {
    /// `xN`. Index 32 is the stack pointer, which is a field of its own.
    #[inline]
    pub fn get(self, i: usize) -> u64 {
        // SAFETY: the pointer is the running guest's `cpu_state`, and `i` comes
        // from a register number the disassembler produced, so it is 0..=32.
        unsafe {
            if i == 32 {
                (*self.0).sp
            } else {
                (*self.0).regs[i]
            }
        }
    }

    #[inline]
    pub fn set(self, i: usize, v: u64) {
        // SAFETY: as [`Regs::get`].
        unsafe {
            if i == 32 {
                (*self.0).sp = v;
            } else {
                (*self.0).regs[i] = v;
            }
        }
    }

    /// `TPIDR_EL0`, which is the guest's thread pointer.
    #[inline]
    pub fn tls(self) -> u64 {
        // SAFETY: as above.
        unsafe { (*self.0).tls_ptr }
    }

    #[inline]
    pub fn set_tls(self, v: u64) {
        // SAFETY: as above.
        unsafe { (*self.0).tls_ptr = v };
    }
}

/// The flags, as the two operands of the comparison that set them.
///
/// AArch64's NZCV is not modelled: what a translated body reads is a condition
/// code, and every condition this generator emits is decidable from the pair a
/// `cmp` was given. `ccmp`'s `#nzcv` fallback is encoded as a pair that answers
/// the same way — see the generator, which is where the mapping is written
/// down.
#[derive(Clone, Copy, Default)]
pub struct Flags {
    pub a: u64,
    pub b: u64,
}

impl Flags {
    #[inline]
    pub fn cmp(&mut self, a: u64, b: u64) {
        self.a = a;
        self.b = b;
    }

    #[inline]
    pub fn eq(self) -> bool {
        self.a == self.b
    }
    #[inline]
    pub fn ne(self) -> bool {
        self.a != self.b
    }
    #[inline]
    pub fn hi(self) -> bool {
        self.a > self.b
    }
    #[inline]
    pub fn lo(self) -> bool {
        self.a < self.b
    }
    #[inline]
    pub fn hs(self) -> bool {
        self.a >= self.b
    }
    #[inline]
    pub fn ls(self) -> bool {
        self.a <= self.b
    }
    #[inline]
    pub fn gt(self) -> bool {
        (self.a as i64) > (self.b as i64)
    }
    #[inline]
    pub fn lt(self) -> bool {
        (self.a as i64) < (self.b as i64)
    }
    #[inline]
    pub fn ge(self) -> bool {
        (self.a as i64) >= (self.b as i64)
    }
    #[inline]
    pub fn le(self) -> bool {
        (self.a as i64) <= (self.b as i64)
    }

    /// A float comparison, encoded into the pair so the integer conditions
    /// above answer correctly.
    ///
    /// Unordered (either operand NaN) becomes `(0, 1)`, so `gt` and `ge` are
    /// false — which is what AArch64 does, since an unordered `fcmp` clears N
    /// and Z and sets C and V.
    #[inline]
    pub fn fcmp(&mut self, x: f64, y: f64) {
        let (a, b) = if x.is_nan() || y.is_nan() {
            (0, 1)
        } else if x > y {
            (1, 0)
        } else if x < y {
            (0, 1)
        } else {
            (0, 0)
        };
        self.a = a;
        self.b = b;
    }
}

// ---------------------------------------------------------------------------
// Arithmetic. Every one wraps, which is what the guest's does.
// ---------------------------------------------------------------------------

#[inline]
pub fn add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

#[inline]
pub fn sub(a: u64, b: u64) -> u64 {
    a.wrapping_sub(b)
}

#[inline]
pub fn mul(a: u64, b: u64) -> u64 {
    a.wrapping_mul(b)
}

#[inline]
pub fn neg(a: u64) -> u64 {
    (a as i64).wrapping_neg() as u64
}

/// Truncate to 32 bits, which is what writing a `w` register does.
#[inline]
pub fn w32(v: u64) -> u64 {
    u64::from(v as u32)
}

/// Sign-extend the low `bits` of `v`.
#[inline]
pub fn sx(bits: u32, v: u64) -> u64 {
    if bits >= 64 {
        return v;
    }
    let sh = 64 - bits;
    (((v << sh) as i64) >> sh) as u64
}

/// Zero-extend the low `bits` of `v`.
#[inline]
pub fn zx(bits: u32, v: u64) -> u64 {
    if bits >= 64 {
        v
    } else {
        v & ((1u64 << bits) - 1)
    }
}

#[inline]
pub fn shl(v: u64, n: u64) -> u64 {
    v.wrapping_shl(n as u32)
}

/// Logical right shift.
#[inline]
pub fn shr(v: u64, n: u64) -> u64 {
    v.wrapping_shr(n as u32)
}

/// Arithmetic right shift.
#[inline]
pub fn sar(v: u64, n: u64) -> u64 {
    ((v as i64) >> (n & 63)) as u64
}

#[inline]
pub fn ror(v: u64, n: u64) -> u64 {
    v.rotate_right((n & 63) as u32)
}

/// The high 64 bits of an unsigned 128-bit product.
#[inline]
pub fn umulh(a: u64, b: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) >> 64) as u64
}

/// And of a signed one.
#[inline]
pub fn smulh(a: u64, b: u64) -> u64 {
    (((i128::from(a as i64)) * (i128::from(b as i64))) >> 64) as u64
}

/// Division by zero answers zero, which is what AArch64 does rather than
/// trapping.
#[inline]
pub fn udiv(a: u64, b: u64) -> u64 {
    a.checked_div(b).unwrap_or(0)
}

#[inline]
pub fn sdiv(a: u64, b: u64) -> u64 {
    if b == 0 {
        return 0;
    }
    // The one overflowing case, which AArch64 answers with the dividend.
    (a as i64).wrapping_div(b as i64) as u64
}

#[inline]
pub fn clz(bits: u32, v: u64) -> u64 {
    if bits == 32 {
        u64::from((v as u32).leading_zeros())
    } else {
        u64::from(v.leading_zeros())
    }
}

#[inline]
pub fn rev64(v: u64) -> u64 {
    v.swap_bytes()
}

#[inline]
pub fn rev32(v: u64) -> u64 {
    u64::from((v as u32).swap_bytes())
}

/// Byte-swap within each 16-bit halfword.
#[inline]
pub fn rev16(v: u64) -> u64 {
    ((v & 0xff00_ff00_ff00_ff00) >> 8) | ((v & 0x00ff_00ff_00ff_00ff) << 8)
}

// ---------------------------------------------------------------------------
// Guest memory, through the TLB.
//
// Not the host's address space: that is what makes a spec_fn fork- and
// copy-on-write-safe, and it is also the cost -- a function with a stack frame
// pays eight of these on entry and exit.
// ---------------------------------------------------------------------------

macro_rules! loads {
    ($($name:ident, $signed:ident, $ty:ty, $bytes:expr;)*) => {$(
        /// # Safety
        /// `tlb` is the running guest's.
        #[inline]
        pub unsafe fn $name(tlb: *mut Tlb, addr: u64) -> u64 {
            let mut v = [0; $bytes];
            // SAFETY: the caller's contract.
            unsafe { emu_tlb::access::Tlb::new(tlb.cast()).read(addr, &mut v) };
            u64::from(<$ty>::from_ne_bytes(v))
        }

        /// Sign-extending, for `ldrsb`/`ldrsh`/`ldrsw`.
        ///
        /// # Safety
        /// As above.
        #[inline]
        pub unsafe fn $signed(tlb: *mut Tlb, addr: u64) -> u64 {
            // SAFETY: the caller's contract.
            let raw = unsafe { $name(tlb, addr) };
            sx($bytes * 8, raw)
        }
    )*};
}

loads! {
    ld1, lds1, u8,  1;
    ld2, lds2, u16, 2;
    ld4, lds4, u32, 4;
}

/// # Safety
/// `tlb` is the running guest's.
#[inline]
pub(crate) unsafe fn ld8(tlb: *mut Tlb, addr: u64) -> u64 {
    // SAFETY: the caller's contract.
    unsafe { crate::ld(tlb, addr) }
}

macro_rules! stores {
    ($($name:ident, $ty:ty, $bytes:expr;)*) => {$(
        /// # Safety
        /// `tlb` is the running guest's.
        #[inline]
        pub unsafe fn $name(tlb: *mut Tlb, addr: u64, value: u64) {
            // SAFETY: the caller's contract.
            unsafe { emu_tlb::access::Tlb::new(tlb.cast()).write(addr, &(value as $ty).to_ne_bytes()) };
        }
    )*};
}

stores! {
    st1, u8,  1;
    st2, u16, 2;
    st4, u32, 4;
}

/// # Safety
/// `tlb` is the running guest's.
#[inline]
pub(crate) unsafe fn st8(tlb: *mut Tlb, addr: u64, value: u64) {
    // SAFETY: the caller's contract.
    unsafe { crate::st(tlb, addr, value) };
}

// ---------------------------------------------------------------------------
// Calls
// ---------------------------------------------------------------------------

/// A guest `bl`/`blr`, with this call site's inline cache.
///
/// # Safety
/// `cpu` and `tlb` are the running guest's.
#[inline]
pub unsafe fn call(cache: &AtomicU64, cpu: *mut Cpu, tlb: *mut Tlb, target: u64) {
    // SAFETY: the caller's contract.
    unsafe { crate::call(cache, cpu, tlb, target) };
}

/// A guest `br xN` — a tail call, which returns to the *current* `lr` rather
/// than to here.
///
/// Running it through the interpreter preserves that: it executes the callee to
/// completion and comes back, and the generated body then returns so the
/// prebuilt entry resumes at the real `lr`. Setting `regs[30]` to the target
/// instead would clobber the return address and make the callee's `ret` loop on
/// itself.
///
/// # Safety
/// As [`call`].
#[inline]
pub unsafe fn tail(cpu: *mut Cpu, tlb: *mut Tlb, target: u64) {
    // SAFETY: the caller's contract.
    unsafe { asbestos_dispatch::prebuilt_call(cpu, tlb, target) };
}

/// Where a generated body's `adrp`, `adr` and call targets are measured from:
/// the difference between the address the binary loaded at and the one it was
/// disassembled at.
#[derive(Debug)]
pub struct Base(AtomicU64);

impl Base {
    pub const fn new() -> Base {
        Base(AtomicU64::new(0))
    }

    /// Set from the registered address and the one in the file.
    pub fn set(&self, at: u64, anchor: u64) {
        self.0.store(at.wrapping_sub(anchor), Ordering::Relaxed);
    }

    #[inline]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for Base {
    fn default() -> Base {
        Base::new()
    }
}
