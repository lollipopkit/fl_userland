//! Reaching guest memory through the TLB: the lookup, and the operations the
//! gadgets call when their inline fast path will not do.
//!
//! # One lookup, not three
//!
//! `emu/tlb.h` used to carry `__tlb_read_ptr` and `__tlb_write_ptr` as
//! `forceinline` functions, because `emu/tlb.c`'s operations below inlined them
//! on every call. With those operations here that reason is gone, and the two C
//! callers left — `asbestos/guest-arm64/gen.c`, which reads four bytes per
//! guest instruction while *compiling* a block, and
//! `kernel/native_offload_sym.c`, which an embedder's handler reaches — pay a
//! call each instead. Compilation happens once per block and is amortised over
//! every execution of it; the handler path is cold.
//!
//! So there are two implementations of the lookup rather than three, and the
//! other one is the assembly, which is a contract this cannot help. [`index`]
//! has a test saying what the formula is.
//!
//! # What the gadgets call, and what they do not
//!
//! The gadgets have inline fast paths for plain loads and stores. What reaches
//! here is what they will not do inline: the atomics, the exclusive pair, the
//! interleaved SIMD, `ic ivau`, and `ldp`/`stp`. Thirteen `c_load`/`c_store`
//! functions sat beside these until 2026-09-02 and **nothing called any of
//! them**.
//!
//! # A returned `-1` is a fault, and the caller raises it
//!
//! Every operation answers 0 or -1, with `tlb->segfault_addr` left by the miss
//! handler for the fault arm to report. The exclusive stores answer 1 as well,
//! which is the guest-visible "your exclusive was lost" and not an error.

use std::ffi::c_int;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};

use crate::ffi;
use crate::{index, page_base, tlb_handle_miss};

const PAGE_SIZE: u64 = ffi::PAGE_SIZE as u64;

// ---------------------------------------------------------------------------
// Atomics
// ---------------------------------------------------------------------------

/// What `atomic_rmw`'s `op` selects. The numbering is the decoder's, which is
/// why it is written out: the operand word carries a small integer and nothing
/// else records what each one means.
///
/// `Clr` is `fetch_and(!value)`, which is what `LDCLR` is: the operand names
/// the bits to clear, not the mask to keep.
mod op {
    pub const ADD: u32 = 0;
    pub const CLR: u32 = 1;
    pub const EOR: u32 = 2;
    pub const SET: u32 = 3;
    pub const SMAX: u32 = 4;
    pub const SMIN: u32 = 5;
    pub const UMAX: u32 = 6;
    pub const UMIN: u32 = 7;
    pub const SWP: u32 = 8;
}

/// One size's worth of the read-modify-write matrix: the old value, or `None`
/// for an `op` that does not exist.
///
/// The four sizes were four near-identical thirty-line blocks in C. The signed
/// and unsigned maximum and minimum are `fetch_max`/`fetch_min` on the atomic
/// of the type the comparison is in, which is the same bits.
macro_rules! rmw {
    ($ty:ty, $signed:ty, $atomic:ty, $ptr:expr, $value:expr, $op:expr) => {{
        // SAFETY: a translated, granule-aligned host address with the width in
        // its page; guest memory is shared, hence the atomic.
        let a = unsafe { <$atomic>::from_ptr($ptr.cast::<$ty>()) };
        let v = $value as $ty;
        let sc = Ordering::SeqCst;
        Some(match $op {
            op::ADD => a.fetch_add(v, sc),
            op::CLR => a.fetch_and(!v, sc),
            op::EOR => a.fetch_xor(v, sc),
            op::SET => a.fetch_or(v, sc),
            op::SWP => a.swap(v, sc),
            op::UMAX => a.fetch_max(v, sc),
            op::UMIN => a.fetch_min(v, sc),
            op::SMAX | op::SMIN => {
                let mut cur = a.load(sc);
                loop {
                    let (c, w) = (cur as $signed, v as $signed);
                    let want = if $op == op::SMAX { c.max(w) } else { c.min(w) } as $ty;
                    match a.compare_exchange_weak(cur, want, sc, sc) {
                        Ok(_) => break cur,
                        Err(seen) => cur = seen,
                    }
                }
            }
            _ => return None,
        } as u64)
    }};
}

/// The calling thread's TLB, for one call from it.
///
/// It holds the pointer, not a reference: the miss handler writes the TLB
/// through its own pointer while this is live, and a `&mut` held across that
/// is the aliasing release builds act on. What makes the methods safe is the
/// promise [`Tlb::new`] takes once, at the boundary -- the slow-call entry, the
/// compiler, an offload handler -- where it used to be repeated by every
/// function between there and the lookup.
///
/// Guest memory stays raw pointers and atomics: other guest threads write it
/// while this reads it.
#[derive(Clone, Copy)]
pub struct Tlb<'a> {
    p: NonNull<ffi::tlb>,
    _life: PhantomData<&'a ffi::tlb>,
}

impl Tlb<'_> {
    /// # Safety
    /// `p` is a live TLB that belongs to the calling thread, with its `mmu`
    /// live, and both stay so while the handle is.
    #[inline]
    pub unsafe fn new(p: *mut ffi::tlb) -> Self {
        // SAFETY: the caller's contract includes non-null.
        Self { p: unsafe { NonNull::new_unchecked(p) }, _life: PhantomData }
    }

    fn raw(self) -> *mut ffi::tlb {
        self.p.as_ptr()
    }

    /// Whether the entry cached for `addr` is still good.
    ///
    /// Two questions, and the second is the one that is easy to forget: the
    /// page has to match, **and** the mapping generation the entry was taken at
    /// has to be the current one. A partial `munmap` or a copy-on-write leaves
    /// the old host page readable through its lingering refcount, so a stale
    /// pointer does not fault — it silently reads the wrong bytes.
    #[inline]
    fn cached(self, addr: u64, writable: bool) -> Option<*mut u8> {
        // SAFETY: `new`'s contract; only this thread writes the entries, and
        // not during this call.
        let entry = unsafe { &(*self.raw()).entries[index(addr)] };
        let want = if writable { entry.page_if_writable } else { entry.page };
        if want != page_base(addr) {
            return None;
        }
        // SAFETY: as above; `changes` is an atomic other threads bump.
        let now = unsafe { (*(*self.raw()).mmu).changes.load(Ordering::Acquire) };
        if entry.gen_ as u64 != now {
            return None;
        }
        Some(entry.data_minus_addr.wrapping_add(addr as usize) as *mut u8)
    }

    /// A host pointer to read `addr` through, resolving a miss.
    pub(crate) fn read_ptr(self, addr: u64) -> Option<*mut u8> {
        if let Some(p) = self.cached(addr, false) {
            return Some(p);
        }
        // SAFETY: `new`'s contract is the miss handler's.
        let p = unsafe { tlb_handle_miss(self.raw(), addr, ffi::MEM_READ as c_int) };
        (!p.is_null()).then(|| p.cast())
    }

    /// A host pointer to write `addr` through, resolving a miss.
    ///
    /// Records the page as dirty, which is what the JIT's coherence check reads.
    pub(crate) fn write_ptr(self, addr: u64) -> Option<*mut u8> {
        if let Some(p) = self.cached(addr, true) {
            // SAFETY: `new`'s contract.
            unsafe { (*self.raw()).dirty_page = page_base(addr) };
            return Some(p);
        }
        // SAFETY: `new`'s contract is the miss handler's.
        let p = unsafe { tlb_handle_miss(self.raw(), addr, ffi::MEM_WRITE as c_int) };
        (!p.is_null()).then(|| p.cast())
    }

    /// Record that the fault about to be reported is an alignment one, so the
    /// handler delivers `SIGBUS` rather than `SIGSEGV`.
    ///
    /// The CPU state is reachable from the TLB — `tlb->frame->cpu` — which is
    /// what makes this possible without touching a single gadget.
    ///
    /// And the address, into `tlb->segfault_addr`, which is where the gadget's
    /// fault exit reads it from -- a translation failure leaves it there by way
    /// of the miss handler, and without this an alignment fault reported
    /// whatever address the last miss had.
    fn note_alignment_fault(self, addr: u64) {
        // SAFETY: `new`'s contract; the frame is this thread's.
        unsafe {
            (*self.raw()).segfault_addr = addr;
            if let Some(frame) = (*self.raw()).frame.as_deref_mut() {
                frame.cpu.segfault_was_align = true;
            }
        }
    }

    /// A pointer to write an atomic of `size` bytes at `addr` through, or
    /// `None` with the fault recorded.
    ///
    /// An atomic that crosses a sixteen-byte granule is an alignment fault, not
    /// a slow path. There was no check at all until 2026-09-02, and the helper
    /// went ahead: an eight-byte atomic four bytes from the end of a page ran
    /// off the end of that page's *host* mapping and took the emulator down,
    /// which any guest could do with one instruction.
    fn atomic_ptr(self, addr: u64, size: usize) -> Option<*mut u8> {
        if !atomic_aligned(addr, size) {
            self.note_alignment_fault(addr);
            return None;
        }
        self.write_ptr(addr)
    }

    /// Guest memory into `out`, which is at most a page. False on a fault.
    ///
    /// Both pages are translated before anything is copied, so a fault on the
    /// second leaves nothing half done.
    pub fn read(self, addr: u64, out: &mut [u8]) -> bool {
        assert!(out.len() <= PAGE_SIZE as usize, "an access of more than a page");
        let (head, tail) = out.split_at_mut(first_part(addr).min(out.len()));
        let Some(a) = self.read_ptr(addr) else { return false };
        let b = match tail.is_empty() {
            true => a,
            false => match self.read_ptr(page_base(addr) + PAGE_SIZE) {
                Some(b) => b,
                None => return false,
            },
        };
        // SAFETY: translated host addresses, `head` bytes left in the first
        // page and `tail`, at most a page, from the start of the second.
        unsafe {
            head.copy_from_slice(std::slice::from_raw_parts(a, head.len()));
            tail.copy_from_slice(std::slice::from_raw_parts(b, tail.len()));
        }
        true
    }

    /// `N` bytes of guest memory, or `None` on a fault.
    ///
    /// [`Tlb::read`] with the size a constant: one unaligned load when the
    /// bytes are in one page, where the slice version's two copies of runtime
    /// length were a `memcpy` call each. The compiler reads every instruction
    /// word through this.
    #[inline]
    pub fn read_array<const N: usize>(self, addr: u64) -> Option<[u8; N]> {
        if first_part(addr) >= N {
            let p = self.read_ptr(addr)?;
            // SAFETY: a translated host address with `N` bytes left in its
            // page; guest memory is plain bytes.
            return Some(unsafe { p.cast::<[u8; N]>().read_unaligned() });
        }
        let mut out = [0u8; N];
        self.read(addr, &mut out).then_some(out)
    }

    /// `value` into guest memory, at most a page. False on a fault, with
    /// nothing written.
    pub fn write(self, addr: u64, value: &[u8]) -> bool {
        assert!(value.len() <= PAGE_SIZE as usize, "an access of more than a page");
        let (head, tail) = value.split_at(first_part(addr).min(value.len()));
        let Some(a) = self.write_ptr(addr) else { return false };
        let b = match tail.is_empty() {
            true => a,
            false => match self.write_ptr(page_base(addr) + PAGE_SIZE) {
                Some(b) => b,
                None => return false,
            },
        };
        // SAFETY: as in `read`.
        unsafe {
            std::slice::from_raw_parts_mut(a, head.len()).copy_from_slice(head);
            std::slice::from_raw_parts_mut(b, tail.len()).copy_from_slice(tail);
        }
        true
    }

    /// `LDXP`'s load: two `T`s at `addr` and `addr + size_of::<T>()`, or `None`
    /// on a fault, which is recorded.
    ///
    /// The exclusive pair load is the only caller, so the granule rule is here:
    /// the load half is what faults first at an unaligned address, and it did
    /// not until 2026-09-02 -- `xpage_probe` reported `SIGSEGV` where the CPU
    /// gives `SIGBUS`. A plain `ldp` may straddle anything and takes the inline
    /// path instead. Inside one granule both halves are in one page.
    fn load_pair<T: Copy>(self, addr: u64) -> Option<(T, T)> {
        let stride = size_of::<T>();
        if !atomic_aligned(addr, 2 * stride) {
            self.note_alignment_fault(addr);
            return None;
        }
        let p = self.read_ptr(addr)?.cast::<T>();
        // SAFETY: a translated host address with `2 * stride` bytes in its page.
        Some(unsafe { (p.read_unaligned(), p.add(1).read_unaligned()) })
    }

    /// The `LD<op>` family: an atomic read-modify-write that answers the old
    /// value, or `None` on a fault. `size` is the log2 of the width in bytes;
    /// `op` is [`mod@op`].
    fn atomic_rmw(self, addr: u64, value: u64, size: u32, op: u32) -> Option<u64> {
        let ptr = self.atomic_ptr(addr, 1 << size)?;
        match size {
            0 => rmw!(u8, i8, AtomicU8, ptr, value, op),
            1 => rmw!(u16, i16, AtomicU16, ptr, value, op),
            2 => rmw!(u32, i32, AtomicU32, ptr, value, op),
            _ => rmw!(u64, i64, AtomicU64, ptr, value, op),
        }
    }

    /// A compare-and-swap of `1 << size` bytes: the value found, and whether
    /// it swapped. `None` on a fault.
    fn atomic_cas(self, addr: u64, expected: u64, desired: u64, size: u32) -> Option<(u64, bool)> {
        let ptr = self.atomic_ptr(addr, 1 << size)?;
        macro_rules! cas {
            ($ty:ty, $atomic:ty) => {{
                // SAFETY: a translated, granule-aligned host address with the
                // width in its page; guest memory is shared, hence the atomic.
                let a = unsafe { <$atomic>::from_ptr(ptr.cast::<$ty>()) };
                match a.compare_exchange(expected as $ty, desired as $ty, Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(v) => (v as u64, true),
                    Err(v) => (v as u64, false),
                }
            }};
        }
        Some(match size {
            0 => cas!(u8, AtomicU8),
            1 => cas!(u16, AtomicU16),
            2 => cas!(u32, AtomicU32),
            _ => cas!(u64, AtomicU64),
        })
    }

    /// `CASP`: a sixteen-byte compare-and-swap, which **must be one atomic
    /// operation** and not two of eight bytes. Answers the pair found.
    ///
    /// A torn update breaks any lock-free algorithm that relies on the pair
    /// moving together — libpas's `pas_versioned_field` is `{value, version}`
    /// and is exactly that.
    fn atomic_cas128(self, addr: u64, exp: [u64; 2], des: [u64; 2]) -> Option<([u64; 2], bool)> {
        if !pair16_ok(addr) {
            return None;
        }
        let ptr = self.write_ptr(addr)?;
        // SAFETY: a translated, sixteen-byte-aligned host address with the
        // sixteen bytes in its page.
        let (lo, hi, swapped) = unsafe { crate::cas128::cas128(ptr, exp[0], exp[1], des[0], des[1]) };
        Some(([lo, hi], swapped))
    }

    /// `STXP`'s store half: both registers land, or neither does. `Some(true)`
    /// when it stored, `Some(false)` when it lost the race -- which is what the
    /// guest is told and what its loop retries on -- and `None` on a fault.
    ///
    /// Emulating it as a plain store pair that always succeeds tears any
    /// lock-free algorithm built on `LDXP`/`STXP` — libpas's versioned fields
    /// reach it through `__atomic_compare_exchange_16`'s out-of-line fallback.
    ///
    /// `size` 2 is a 32-bit pair, which is **one 64-bit compare-exchange** and
    /// needs no 128-bit primitive and no alignment rule beyond the hardware's
    /// own; 3 is a 64-bit pair, which needs both.
    fn stxp_cas(self, addr: u64, exp: [u64; 2], new: [u64; 2], size: u32) -> Option<bool> {
        match size {
            2 => {
                let word = |p: [u64; 2]| p[0] as u32 as u64 | ((p[1] as u32 as u64) << 32);
                self.atomic_cas(addr, word(exp), word(new), 3).map(|(_, swapped)| swapped)
            }
            3 => self.atomic_cas128(addr, exp, new).map(|(_, swapped)| swapped),
            _ => None,
        }
    }

    /// The access check an exclusive store makes when its monitor is **not**
    /// armed: whether `bytes` at `addr` could be written, with a fault recorded
    /// as any other would be.
    ///
    /// The store does not happen either way -- the guest is told 1 -- but the
    /// hardware still checks the address first. `STXR` to a `PROT_NONE` page
    /// with no `LDXR` before it takes `SIGSEGV` on a real arm64 kernel, three
    /// runs of three, and answered 1 here, so a handler never ran and the
    /// program's retry loop went round on an address that could never succeed.
    /// `tests/guest/src/bin/fault_pc.rs` has the case.
    fn exclusive_probe(self, addr: u64, bytes: usize) -> bool {
        self.atomic_ptr(addr, bytes).is_some()
    }
}

/// Does an access of `size` bytes at `addr` run past the end of its page?
#[cfg(test)]
fn crosses(addr: u64, size: usize) -> bool {
    (addr & (PAGE_SIZE - 1)) > PAGE_SIZE - size as u64
}

/// The granule an atomic access may not cross.
///
/// FEAT_LSE2, which every Apple Silicon core has, allows an *unaligned* atomic
/// as long as it stays inside one sixteen-byte block; crossing one raises
/// `SIGBUS`, because two halves done separately are not one atomic operation.
/// Measured against the CPU rather than read from the manual — see
/// `tests/guest/src/bin/xpage_probe.rs`, where a 32-bit `ldadd` at offset 1
/// works and a 64-bit one at offset 9 does not.
const ATOMIC_GRANULE: u64 = 16;

/// May an atomic of `size` bytes at `addr` be done as one operation?
fn atomic_aligned(addr: u64, size: usize) -> bool {
    addr / ATOMIC_GRANULE == (addr + size as u64 - 1) / ATOMIC_GRANULE
}

/// How much of an access at `addr` lands in its own page.
fn first_part(addr: u64) -> usize {
    (PAGE_SIZE - (addr & (PAGE_SIZE - 1))) as usize
}

// ---------------------------------------------------------------------------
// What the assembly calls by name
// ---------------------------------------------------------------------------

/// The cross-page half of a gadget's inline load.
///
/// # Safety
/// `tlb` as [`Tlb::new`]; `out` addresses `size` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __tlb_read_cross_page(tlb: *mut ffi::tlb, addr: u64, out: *mut u8, size: u32) -> bool {
    // SAFETY: the caller's contract.
    unsafe { Tlb::new(tlb).read(addr, std::slice::from_raw_parts_mut(out, size as usize)) }
}

/// The cross-page half of a gadget's inline store.
///
/// # Safety
/// `tlb` as [`Tlb::new`]; `value` addresses `size` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __tlb_write_cross_page(tlb: *mut ffi::tlb, addr: u64, value: *const u8, size: u32) -> bool {
    // SAFETY: the caller's contract.
    unsafe { Tlb::new(tlb).write(addr, std::slice::from_raw_parts(value, size as usize)) }
}

/// [`Tlb::exclusive_probe`] for the `stxr` gadget: 0, or -1 on a fault.
///
/// # Safety
/// `tlb` as [`Tlb::new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_exclusive_probe(tlb: *mut ffi::tlb, addr: u64, bytes: u32) -> c_int {
    // SAFETY: the caller's contract.
    if unsafe { Tlb::new(tlb) }.exclusive_probe(addr, bytes as usize) { 0 } else { -1 }
}

/// `STXR`'s store half, as a compare-and-swap against the value `LDXR` saw.
///
/// 0 when it stored, 1 when it lost the race, -1 on a fault. **1 is not an
/// error**: it is what the guest is told, and its loop retries. The granule
/// rule is the LSE forms', for the same reason.
///
/// # Safety
/// `tlb` as [`Tlb::new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_stxr_cas(tlb: *mut ffi::tlb, addr: u64, expected: u64, desired: u64, size: u32) -> c_int {
    // SAFETY: the caller's contract.
    match unsafe { Tlb::new(tlb) }.atomic_cas(addr, expected, desired, size & 3) {
        Some((_, true)) => 0,
        Some((_, false)) => 1,
        None => -1,
    }
}


// ---------------------------------------------------------------------------
// The slow-call protocol
// ---------------------------------------------------------------------------

pub use crate::ffi::{SLOW_OK, SLOW_READ_FAULT, SLOW_WRITE_FAULT, SlowFn};

/// The running frame's CPU state, as a `slow_call` entry reaches it.
///
/// A pointer and not a `&mut`: `_poked` is an atomic other threads write, and
/// the alignment fault writes `segfault_was_align` through the TLB's frame.
#[derive(Clone, Copy)]
struct Cpu(NonNull<ffi::cpu_state>);

impl Cpu {
    /// # Safety
    /// `cpu` is the running frame's, live for the call.
    unsafe fn new(cpu: *mut ffi::cpu_state) -> Self {
        // SAFETY: the caller's contract includes non-null.
        Self(unsafe { NonNull::new_unchecked(cpu) })
    }

    /// Guest register `n` as an operand: 31 is the zero register here, which
    /// is what every instruction this protocol carries means by it.
    fn reg(self, n: u64) -> u64 {
        match n & 0x1f {
            31 => 0,
            // SAFETY: `new`'s contract; only this thread writes the registers.
            n => unsafe { (*self.0.as_ptr()).regs[n as usize] },
        }
    }

    /// Write guest register `n`; 31 discards.
    fn set_reg(self, n: u64, value: u64) {
        match n & 0x1f {
            31 => {}
            // SAFETY: as in `reg`.
            n => unsafe { (*self.0.as_ptr()).regs[n as usize] = value },
        }
    }

    /// The exclusive monitor: address and the pair `LDXP` loaded.
    fn monitor(self) -> (u64, [u64; 2]) {
        // SAFETY: as in `reg`.
        unsafe {
            let c = self.0.as_ptr();
            ((*c).excl_addr, [(*c).excl_val, (*c).excl_val2])
        }
    }

    fn set_monitor(self, addr: u64, val: [u64; 2]) {
        // SAFETY: as in `reg`.
        unsafe {
            let c = self.0.as_ptr();
            (*c).excl_addr = addr;
            [(*c).excl_val, (*c).excl_val2] = val;
        }
    }

    fn vreg(self, n: usize) -> [u8; 16] {
        // SAFETY: as in `reg`.
        unsafe { (*self.0.as_ptr()).fp[n & 0x1f] }.bytes()
    }

    fn set_vreg(self, n: usize, value: [u8; 16]) {
        // SAFETY: as in `reg`.
        unsafe { (*self.0.as_ptr()).fp[n & 0x1f] = ffi::arm64_vreg::from_bytes(value) };
    }
}

/// Define `slow_call` entries over [`Cpu`] and [`Tlb`].
macro_rules! slow {
    ($($(#[$m:meta])* fn $name:ident($cpu:ident, $tlb:ident, $addr:ident, $arg:ident) $body:block)*) => {$(
        $(#[$m])*
        ///
        /// # Safety
        /// The `slow_call` gadget's: `cpu` and `tlb` are the running frame's.
        pub unsafe extern "C" fn $name(cpu: *mut ffi::cpu_state, tlb: *mut ffi::tlb, $addr: u64, $arg: u64) -> c_int {
            // SAFETY: the caller's contract.
            let ($cpu, $tlb) = unsafe { (Cpu::new(cpu), Tlb::new(tlb)) };
            $body
        }
    )*};
}

/// The exclusive monitor's "not armed" address: every exit from a store
/// exclusive leaves it, and `CLREX` writes it.
const EXCL_NONE: u64 = u64::MAX;

slow! {
    /// `LD<op>` and `SWP`: operand `rs | size << 8 | op << 16 | rt << 24`. The
    /// old value goes to `Rt`.
    fn slow_atomic_rmw(cpu, tlb, addr, arg) {
        let (size, op) = ((arg >> 8) as u32 & 0x3, (arg >> 16) as u32 & 0xf);
        let Some(old) = tlb.atomic_rmw(addr, cpu.reg(arg), size, op) else {
            return SLOW_WRITE_FAULT;
        };
        cpu.set_reg(arg >> 24, old);
        SLOW_OK
    }

    /// `CAS`: operand `rs | rt << 8 | size << 16`. `Rs` is the expected value
    /// and takes the value found; `Rt` is the new one.
    fn slow_atomic_cas(cpu, tlb, addr, arg) {
        let size = (arg >> 16) as u32 & 0x3;
        let Some((old, _)) = tlb.atomic_cas(addr, cpu.reg(arg), cpu.reg(arg >> 8), size) else {
            return SLOW_WRITE_FAULT;
        };
        cpu.set_reg(arg, old);
        SLOW_OK
    }

    /// `LDXP`: operand `rt | rt2 << 8 | size << 16`, size 2 or 3. Loads the
    /// pair and arms the monitor with it, so `STXP` can compare-and-swap on it.
    fn slow_ldxp(cpu, tlb, addr, arg) {
        let loaded = if (arg >> 16) & 0x3 == 3 {
            tlb.load_pair::<u64>(addr)
        } else {
            tlb.load_pair::<u32>(addr).map(|(a, b)| (u64::from(a), u64::from(b)))
        };
        let Some((v1, v2)) = loaded else {
            return SLOW_READ_FAULT;
        };
        cpu.set_monitor(addr, [v1, v2]);
        cpu.set_reg(arg, v1);
        cpu.set_reg(arg >> 8, v2);
        SLOW_OK
    }

    /// `STXP`: operand `rt | rt2 << 8 | rs << 16 | size << 24`. A true atomic
    /// pair store against what `LDXP` loaded -- never a plain store pair, which
    /// tears lock-free algorithms under threads (observed: JSC concurrent-JIT
    /// `CodeBlock` corruption in bun). `Rs` takes 0 or 1, as the `stxr` gadget
    /// does.
    fn slow_stxp(cpu, tlb, addr, arg) {
        let size = (arg >> 24) as u32 & 0x3;
        let (armed, exp) = cpu.monitor();
        let stored = if armed == addr {
            tlb.stxp_cas(addr, exp, [cpu.reg(arg), cpu.reg(arg >> 8)], size)
        } else {
            tlb.exclusive_probe(addr, 2 << size).then_some(false)
        };
        cpu.set_monitor(EXCL_NONE, exp);
        let Some(stored) = stored else {
            return SLOW_WRITE_FAULT;
        };
        cpu.set_reg(arg >> 16, u64::from(!stored));
        SLOW_OK
    }

    /// `CASP` with `sz = 1`: operand `rs | rt << 8`. A sixteen-byte atomic over
    /// `{Xs, Xs+1}` against `{Xt, Xt+1}`; the old pair goes back into `Xs, Xs+1`.
    /// Two eight-byte compare-and-swaps would tear the pair, which is the
    /// libpas versioned-field corruption that hangs Bun.
    fn slow_casp(cpu, tlb, addr, arg) {
        let (rs, rt) = (arg & 0x1f, (arg >> 8) & 0x1f);
        // Register 31 names the zero *pair*: `rs + 1` must not wrap to x0.
        let pair = |r: u64| if r == 31 { [0, 0] } else { [cpu.reg(r), cpu.reg(r + 1)] };
        let Some(([lo, hi], _)) = tlb.atomic_cas128(addr, pair(rs), pair(rt)) else {
            return SLOW_WRITE_FAULT;
        };
        if rs != 31 {
            cpu.set_reg(rs, lo);
            cpu.set_reg(rs + 1, hi);
        }
        SLOW_OK
    }

    /// `CASP` with `sz = 0`: an eight-byte atomic over the word pairs
    /// `{Ws, Ws+1}` / `{Wt, Wt+1}`, `Ws` the low half. Operand as [`slow_casp`].
    fn slow_casp32(cpu, tlb, addr, arg) {
        let (rs, rt) = (arg & 0x1f, (arg >> 8) & 0x1f);
        let pair = |r: u64| match r {
            31 => 0,
            r => cpu.reg(r) as u32 as u64 | ((cpu.reg(r + 1) as u32 as u64) << 32),
        };
        let Some((old, _)) = tlb.atomic_cas(addr, pair(rs), pair(rt), 3) else {
            return SLOW_WRITE_FAULT;
        };
        if rs != 31 {
            // Thirty-two-bit writes, which zero the top halves.
            cpu.set_reg(rs, old as u32 as u64);
            cpu.set_reg(rs + 1, old >> 32);
        }
        SLOW_OK
    }

    /// `ic ivau`: the guest asking for an instruction-cache line to be
    /// invalidated, which is how it says it has written code. Operand: `Xt`.
    fn slow_ic_ivau(cpu, tlb, _addr, arg) {
        // The page's compiled blocks are invalidated by the *store* that wrote
        // the code, through `mem_ptr`'s W^X path. What this has to do is make
        // sure the store is visible, which reading the page through the TLB
        // does -- and answer a fault by doing nothing, because `ic ivau` on an
        // unmapped address is the guest's problem and not a fault this can
        // report.
        let _ = tlb.read_ptr(cpu.reg(arg));
        SLOW_OK
    }

    /// `LD2`/`LD3`/`LD4`: read interleaved elements and deal them out into
    /// consecutive vector registers. Operand: [`simd_operand`].
    fn slow_simd_load_interleaved(cpu, tlb, addr, arg) {
        let (rt, num_regs, elem_size, q) = simd_operand(arg);
        let Some((elems, total)) = simd_shape(num_regs, elem_size, q) else {
            return SLOW_READ_FAULT;
        };
        let mut buf = [0u8; SIMD_MAX];
        if !tlb.read(addr, &mut buf[..total]) {
            return SLOW_READ_FAULT;
        }
        let mut regs = [[0u8; 16]; 4];
        shape(num_regs, elem_size, Deal { buf: &buf, lanes: elems, regs: &mut regs });
        // Whole registers, so the upper half of a 64-bit form is zeroed --
        // which is what the architecture says a `Q == 0` write does.
        for (r, reg) in regs.into_iter().take(num_regs as usize).enumerate() {
            cpu.set_vreg(rt + r, reg);
        }
        SLOW_OK
    }

    /// `ST2`/`ST3`/`ST4`: the same in reverse.
    fn slow_simd_store_interleaved(cpu, tlb, addr, arg) {
        let (rt, num_regs, elem_size, q) = simd_operand(arg);
        let Some((elems, total)) = simd_shape(num_regs, elem_size, q) else {
            return SLOW_WRITE_FAULT;
        };
        let regs: [[u8; 16]; 4] = std::array::from_fn(|r| cpu.vreg(rt + r));
        let mut buf = [0u8; SIMD_MAX];
        shape(num_regs, elem_size, Gather { regs: &regs, lanes: elems, buf: &mut buf });
        if tlb.write(addr, &buf[..total]) { SLOW_OK } else { SLOW_WRITE_FAULT }
    }
}

// The sixteen-byte compare-exchange was a call into `emu/tlb.c` until
// 2026-09-06 and is [`crate::cas128`] now. The reason written here — that the
// C compiler picks `casp` or an `ldaxp`/`stlxp` loop depending on FEAT_LSE, and
// an `asm!` block would have to pick one — was true, and is answered rather
// than ignored: `cfg(target_feature = "lse")` is the same judgement from the
// same table, and the three targets this tree builds for were checked one by
// one against `clang -O2`. That module has the measurement.
//
// **The rules are here, not there.** Which accesses are allowed, what a 32-bit
// pair means, and where the pointer comes from are all in this file, because
// that is where the defects would be.

/// A sixteen-byte access must be aligned and must not straddle a page.
///
/// Both are refusals rather than fallbacks. Real hardware raises an alignment
/// fault for an unaligned `CASP` or `STXP`, and answering -1 is how the caller
/// raises the same thing — while doing it anyway would be worse than slow: an
/// unaligned 128-bit compare-exchange is **not lock-free**, it takes
/// libatomic's global lock, so it would silently lose atomicity against a
/// correctly aligned one from another thread.
fn pair16_ok(addr: u64) -> bool {
    addr.is_multiple_of(16) && addr % PAGE_SIZE <= PAGE_SIZE - 16
}

/// The interleaved access an operand names: `rt | regs << 8 | elem_size << 16
/// | q << 24`, the decoder's packing.
fn simd_operand(arg: u64) -> (usize, u32, u32, u32) {
    let byte = |at: u32| (arg >> at) as u32 & 0xff;
    (byte(0) as usize, byte(8), byte(16), byte(24))
}

/// One direction of an interleaved access, for `N` registers of `E`-byte
/// lanes. The shape is a const generic so every element copy is a fixed-size
/// move: with both read at run time each was a `memcpy` call, and `LD4 .16B`
/// cost 178 ns against `PMULL`'s 4.
trait Interleave {
    fn run<const N: usize, const E: usize>(self);
}

/// Memory to registers: element `k` is lane `k / N` of register `k % N`.
struct Deal<'a> {
    buf: &'a [u8],
    lanes: usize,
    regs: &'a mut [[u8; 16]; 4],
}

impl Interleave for Deal<'_> {
    fn run<const N: usize, const E: usize>(self) {
        let src = self.buf.as_chunks::<E>().0;
        for e in 0..self.lanes {
            for r in 0..N {
                self.regs[r].as_chunks_mut::<E>().0[e] = src[e * N + r];
            }
        }
    }
}

/// Registers to memory, the same mapping in reverse.
struct Gather<'a> {
    regs: &'a [[u8; 16]; 4],
    lanes: usize,
    buf: &'a mut [u8],
}

impl Interleave for Gather<'_> {
    fn run<const N: usize, const E: usize>(self) {
        let dst = self.buf.as_chunks_mut::<E>().0;
        for e in 0..self.lanes {
            for r in 0..N {
                dst[e * N + r] = self.regs[r].as_chunks::<E>().0[e];
            }
        }
    }
}

/// Run `op` at the shape [`simd_shape`] accepted.
fn shape(num_regs: u32, elem_size: u32, op: impl Interleave) {
    fn width<const N: usize>(elem_size: u32, op: impl Interleave) {
        match elem_size {
            0 => op.run::<N, 1>(),
            1 => op.run::<N, 2>(),
            2 => op.run::<N, 4>(),
            _ => op.run::<N, 8>(),
        }
    }
    match num_regs {
        1 => width::<1>(elem_size, op),
        2 => width::<2>(elem_size, op),
        3 => width::<3>(elem_size, op),
        _ => width::<4>(elem_size, op),
    }
}

/// The largest interleaved SIMD access: four registers of sixteen bytes.
const SIMD_MAX: usize = 64;

/// How an interleaved access is shaped: `LD2`/`LD3`/`LD4` and their stores
/// move `num_regs` registers of `elems` elements each.
///
/// `None` for a combination the encoding cannot produce, which is what the
/// helper's fault answer means.
fn simd_shape(num_regs: u32, elem_size: u32, q: u32) -> Option<(usize, usize)> {
    if !(1..=4).contains(&num_regs) || elem_size > 3 {
        return None;
    }
    let elem_bytes = 1usize << elem_size;
    let elems = (if q != 0 { 16 } else { 8 }) / elem_bytes;
    let total = num_regs as usize * elems * elem_bytes;
    (total <= SIMD_MAX).then_some((elems, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sixteen-byte rule, which is a *refusal* and not a fallback: an
    /// unaligned 128-bit compare-exchange is not lock-free, so doing it anyway
    /// would silently lose atomicity against a correctly aligned one from
    /// another thread. It lived in `emu/tlb.c` until 2026-09-03 and had no test
    /// there, because a standalone binary cannot link that file.
    #[test]
    fn a_sixteen_byte_pair_must_be_aligned_and_inside_one_page() {
        assert!(pair16_ok(0));
        assert!(pair16_ok(16));
        assert!(pair16_ok(PAGE_SIZE - 16), "the last aligned pair in a page");
        // Every misalignment, including the ones a caller most easily produces.
        for off in [1u64, 2, 4, 8, 12, 15] {
            assert!(!pair16_ok(off), "offset {off}");
            assert!(!pair16_ok(PAGE_SIZE + off), "offset {off} in the next page");
        }
        // Aligned but straddling: impossible on a 4096-byte page, since 4096 is
        // a multiple of 16 -- which is why the check is written as two
        // conditions rather than one, and why this asserts the *reason*.
        assert_eq!(PAGE_SIZE % 16, 0);
        assert!(!pair16_ok(PAGE_SIZE - 8), "unaligned and straddling");
    }

    #[test]
    fn an_access_crosses_when_it_runs_past_its_page() {
        assert!(!crosses(0, 8));
        assert!(!crosses(4088, 8), "the last aligned word is inside");
        assert!(crosses(4089, 8));
        assert!(crosses(4095, 2));
        assert!(!crosses(4095, 1), "a byte never crosses");
    }

    #[test]
    fn the_first_part_is_what_fits_before_the_boundary() {
        assert_eq!(first_part(4090), 6);
        assert_eq!(first_part(0), 4096);
    }

    #[test]
    fn the_interleaved_shapes_are_the_ones_the_encoding_has() {
        // LD4 of sixteen bytes each is the largest, and it is exactly the
        // buffer: a shape that did not fit would be a stack overrun.
        assert_eq!(simd_shape(4, 0, 1), Some((16, 64)));
        assert_eq!(simd_shape(2, 3, 1), Some((2, 32)), "LD2 of doublewords");
        assert_eq!(simd_shape(3, 2, 0), Some((2, 24)), "LD3, 64-bit form");
        // And the ones it does not.
        assert_eq!(simd_shape(5, 0, 1), None);
        assert_eq!(simd_shape(4, 4, 1), None);
        assert_eq!(simd_shape(0, 0, 1), None, "no registers");
        for regs in 1..=4 {
            for size in 0..=3 {
                for q in 0..=1 {
                    let (_, total) = simd_shape(regs, size, q).expect("a real shape");
                    assert!(total <= SIMD_MAX, "{regs} {size} {q}");
                }
            }
        }
    }

    /// Element `k` of memory is lane `k / N` of register `k % N`, at the
    /// element's width: `LD4 .16B` over bytes 0..64, and `LD2 .8H`.
    #[test]
    fn an_interleaved_load_deals_elements_round_robin() {
        let buf: [u8; 64] = std::array::from_fn(|i| i as u8);
        let mut regs = [[0u8; 16]; 4];
        shape(4, 0, Deal { buf: &buf, lanes: 16, regs: &mut regs });
        for (r, reg) in regs.iter().enumerate() {
            assert_eq!(*reg, std::array::from_fn(|e| (e * 4 + r) as u8), "v{r}");
        }
        let mut regs = [[0u8; 16]; 4];
        shape(2, 1, Deal { buf: &buf, lanes: 8, regs: &mut regs });
        let half = |k: usize| [2 * k as u8, 2 * k as u8 + 1];
        assert_eq!(regs[0][..4], [half(0), half(2)].concat()[..], "v0 lanes 0 and 1");
        assert_eq!(regs[1][..4], [half(1), half(3)].concat()[..], "v1 lanes 0 and 1");
    }

    /// A store is the load's inverse at every shape.
    #[test]
    fn an_interleaved_store_undoes_the_load() {
        let buf: [u8; 64] = std::array::from_fn(|i| (i * 7 + 3) as u8);
        for n in 1..=4 {
            for size in 0..=3 {
                for q in 0..=1 {
                    let (lanes, total) = simd_shape(n, size, q).unwrap();
                    let mut regs = [[0u8; 16]; 4];
                    shape(n, size, Deal { buf: &buf, lanes, regs: &mut regs });
                    let mut back = [0u8; 64];
                    shape(n, size, Gather { regs: &regs, lanes, buf: &mut back });
                    assert_eq!(back[..total], buf[..total], "{n} regs, size {size}, q {q}");
                }
            }
        }
    }

    #[test]
    fn the_read_modify_write_operations_are_the_gadgets_numbering() {
        // memory.S passes a small integer and nothing else records what each
        // one is. LDCLR clears the bits its operand names, which is why CLR is
        // `fetch_and(!v)` and not `fetch_and(v)`.
        assert_eq!(
            (op::ADD, op::CLR, op::EOR, op::SET, op::SWP),
            (0, 1, 2, 3, 8)
        );
        assert_eq!((op::SMAX, op::SMIN, op::UMAX, op::UMIN), (4, 5, 6, 7));
    }
}
