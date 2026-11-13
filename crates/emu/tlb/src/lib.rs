//! The software TLB's misses and its lifetime.
//!
//! Every guest load and store goes through a lookup, and what that lookup does
//! on a *miss* is call [`tlb_handle_miss`] — the gadgets call it too, as
//! `entry.S`'s `bl NAME(tlb_handle_miss)`. So it is a call either way, and the
//! translate it performs reaches `mem_ptr`, which has been
//! `crates/kernel/pagetable`'s since 2026-09-02.
//!
//! # There is one implementation of the lookup, and the other one is assembly
//!
//! `emu/tlb.h` kept `__tlb_read_ptr` and `__tlb_write_ptr` as `forceinline`
//! functions, because `emu/tlb.c`'s operations inlined them on every call.
//! Those operations are [`access`] and the header went on 2026-09-09 with its
//! last reader; the two C callers it was kept for — `asbestos/guest-arm64/gen.c`,
//! which read four bytes per guest instruction while *compiling* a block, and
//! `kernel/native_offload_sym.c` — are Rust and gone respectively. Compilation
//! happens once per block and is amortised over every execution of it, so the
//! call it now pays is not on a hot path.
//!
//! What is left is the assembly's own copy of the lookup, which is a contract
//! no header could have helped with.
//!
//! `emu/tlb.c` itself went on 2026-09-06 with the last thing in it, a
//! sixteen-byte compare-exchange that is [`cas128`] now — which picks `caspal`
//! or the `ldaxp`/`stlxp` loop off `cfg(target_feature = "lse")`, the same
//! input clang chose from, checked target by target against it.
//!
//! # A cached translation is only as good as the generation it was taken at
//!
//! `mmu->changes` counts every mapping change, from whichever thread made it.
//! An entry records the generation its host pointer was valid for, and a hit is
//! rejected when the two differ — a partial `munmap` or a copy-on-write leaves
//! the old host page readable through its lingering refcount, so a stale
//! pointer does not fault, it silently reads the wrong bytes.
//!
//! [`tlb_handle_miss`] therefore translates under a **seqlock**: read the
//! generation, translate, read it again, and retry if it moved. A write miss on
//! a copy-on-write page does the copy inside the translate and bumps the
//! generation itself, so the first pass essentially always retries once. The
//! loop is bounded at eight, because a thread that keeps remapping could
//! otherwise livelock this one — past the cap it takes the last translation and
//! stamps the generation that goes with it, and the per-block coherence check
//! catches anything later.


use std::ffi::{c_int, c_void};
use std::sync::atomic::Ordering;

// The shared Rust types and constants are re-exported by kernel-taskview.
use emu_abi as ffi;

pub mod access;
pub mod cas128;

/// `struct tlb` as bindgen generates it, for a crate that holds one — the
/// symbol-level offload's handler context carries a `struct tlb *`.
pub use ffi::tlb as ffi_tlb;

/// What a miss asks of the address space above it, which is
/// `crates/kernel/pagetable`'s and so cannot be called from here directly.
///
/// It was `mmu.ops`, a `#[repr(C)]` table of `Option<extern "C" fn>` stored in
/// every address space, until 2026-10-16: one table, filled only by Rust and
/// read only here, with a `None` arm nothing could reach and a null `ops` that
/// would have been dereferenced. A hook installed once says the same thing.
#[derive(Clone, Copy)]
pub struct Translator {
    /// The host address for `page` as `kind` (`MEM_READ` or `MEM_WRITE`),
    /// resolving a fault -- a stack to grow, a copy-on-write to break. Null if
    /// the guest may not have it.
    ///
    /// # Safety
    /// `mmu` is live, and this thread holds its address space's read lock.
    pub translate: unsafe fn(mmu: *mut ffi::mmu, page: u64, kind: c_int) -> *mut c_void,
    /// As `translate` for `MEM_WRITE`, but null instead of resolving a fault:
    /// a read miss uses it to fill write permission speculatively.
    ///
    /// # Safety
    /// As `translate`.
    pub translate_write_nofault: unsafe fn(mmu: *mut ffi::mmu, page: u64) -> *mut c_void,
}

static TRANSLATOR: std::sync::OnceLock<Translator> = std::sync::OnceLock::new();

/// Install the translator. `crates/kernel/pagetable`'s `mem_init` does, before
/// the first address space exists; a second install is ignored.
pub fn install_translator(t: Translator) {
    let _ = TRANSLATOR.set(t);
}

/// Whether [`install_translator`] has run, for the wiring test.
pub fn translator_installed() -> bool {
    TRANSLATOR.get().is_some()
}

/// A panic and not a null when missing: a TLB exists only for an address space
/// `mem_init` made, so a miss without a translator is a broken build, and a
/// null would read as a guest segfault far from the cause.
#[inline]
fn translator() -> &'static Translator {
    TRANSLATOR
        .get()
        .expect("emu_tlb: no translator installed; crates/kernel/pagetable's mem_init installs it")
}

/// Which entry an address hashes to.
///
/// The write watchpoint that used to live beside this is the assembly's alone:
/// `emu/tlb.h`'s `ENABLE_C_WRITE_WATCHPOINT` was keyed on the C lookup, and
/// `gadgets.h`'s `ENABLE_WRITE_WATCHPOINT` is the counterpart that remains.
/// The two globals it compares against are `crates/asbestos/diag`'s.
///
/// **This is a contract with the gadgets**, which compute the same index in
/// assembly, and with `emu/tlb.h`, which computes it in a `forceinline`. The
/// two halves of an address are exclusive-ored so that a stride of exactly
/// `TLB_SIZE` pages — which a page-table walk or a large `memset` produces —
/// does not hit one entry over and over.
pub(crate) fn index(addr: u64) -> usize {
    let bits = ffi::PAGE_BITS as u64;
    (((addr >> bits) ^ (addr >> (bits + ffi::TLB_BITS as u64))) & (ffi::TLB_SIZE as u64 - 1))
        as usize
}

/// The page an address is in, as an entry's `page` field holds it: the address
/// with its offset cleared, **not** a page number.
///
/// Named `page_of` until 2026-09-15, which is what three other crates
/// (`kernel/mmapcalls`, `asbestos/dispatch`, `asbestos/blockcache`) call a
/// function that answers `addr >> PAGE_BITS` — a page *number*. One name, two
/// meanings, in a tree where both appear. Nothing could confuse them (they are
/// private to their crates) except a reader, which is who the name is for.
///
/// The mask was written out as `0xffff_ffff_ffff_f000`, a 4096 spelled in hex
/// beside an `index` that derives its shift from `ffi::PAGE_BITS`. Derived
/// now, so the two cannot disagree — and `index` says why that matters: it is
/// a contract with the gadgets, which compute the same thing in assembly.
pub(crate) fn page_base(addr: u64) -> u64 {
    addr & !(ffi::PAGE_SIZE as u64 - 1)
}

/// The derived mask is the constant that was written out, to the bit. This is
/// a contract with the gadgets rather than an internal convenience, so the
/// value is asserted at compile time rather than left to a test that might not
/// be run on the build that matters.
const _: () = assert!(
    !(ffi::PAGE_SIZE as u64 - 1) == 0xffff_ffff_ffff_f000,
    "page_base's mask stopped being the one the gadgets compute"
);

/// What `page` and `page_if_writable` hold for an entry that matches nothing.
/// 1 is not a page-aligned address, so no real page can collide with it.
const EMPTY: u64 = ffi::TLB_PAGE_EMPTY as u64;

/// The address space's change counter.
///
/// Acquire on every read: this is the check that decides whether a thread's
/// entries still describe the address space, so a stale or torn read is a
/// thread going on to use translations for memory that has been unmapped or
/// remapped. Three reads here were plain until ThreadSanitizer reported the
/// pair against `mem_changed`'s release store.
///
/// # Safety
/// `mmu` is live.
unsafe fn generation(mmu: *mut ffi::mmu) -> u64 {
    unsafe { (*mmu).changes.load(Ordering::Acquire) }
}

/// Point a TLB at an address space, flushing it if anything has changed.
///
/// An `execve` gives a thread a *different* `mmu`, which invalidates more than
/// the entries: the block cache and the reusable frame both describe code in
/// the old address space.
///
/// # Safety
/// `tlb` and `mmu` are live and this is the thread that owns `tlb`.
pub unsafe fn tlb_refresh(tlb: *mut ffi::tlb, mmu: *mut ffi::mmu) {
    unsafe {
        if (*tlb).mmu == mmu && (*tlb).mem_changes as u64 == generation(mmu) {
            return;
        }
        // A new address space is flushed whole: its generations count from
        // where its own counter is, so an old entry's stamp could match one.
        // The same address space moving on needs nothing more than the new
        // generation recorded -- every entry carries the generation it was
        // filled at, and the lookups (here, `cached`, and the gadgets' inline
        // one) refuse one that is not current. Flushing on that too wrote all
        // 256 KB of the table on every mmap, munmap and mprotect, in every
        // thread of the process.
        if (*tlb).mmu != mmu {
            (*tlb).block_cache.fill(std::ptr::null_mut());
            (*tlb).block_cache_gen = 0;
            (*tlb).frame = None;
            (*tlb).mmu = mmu;
            tlb_flush(tlb);
        }
        (*tlb).dirty_page = EMPTY;
        (*tlb).mem_changes = generation(mmu) as _;
    }
}

/// An entry that matches nothing.
///
/// **Written whole**, which is what makes the flush below a vectorised fill
/// rather than 8192 pairs of strided stores. Setting only the two page fields
/// is less work on paper and measured 1.8x worse: a one-page `mprotect`, which
/// bumps the generation and so flushes on the way back to the guest, went 12.9
/// to 23.6 us. The C this replaces assigned the whole 32-byte struct and got
/// the good shape by accident.
const CLEAR: ffi::tlb_entry = ffi::tlb_entry {
    page: EMPTY,
    page_if_writable: EMPTY,
    data_minus_addr: 0,
    gen_: 0,
};

/// Forget every cached translation.
///
/// # Safety
/// As [`tlb_refresh`].
pub unsafe fn tlb_flush(tlb: *mut ffi::tlb) {
    unsafe {
        (*tlb).mem_changes = generation((*tlb).mmu) as _;
        (*tlb).entries.fill(CLEAR);
    }
}

/// How many TLBs are allocated right now, for `/proc/iul/objects`.
///
/// One per guest thread, and freed by that thread's own `pthread_exit`
/// handler — so a leak here is 288 KB per thread that ever ran, which is the
/// size that made this worth counting rather than reasoning about.
static LIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many TLBs exist.
pub fn tlb_live_count() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// A TLB for one guest thread. Null if the allocation failed.
///
/// It was `libc::calloc` in `crates/kernel/taskcalls` until 2026-09-12, with
/// the free here and the allocation two crates away. The pair is one place
/// now, and the allocation is Rust's — so a field that acquires a destructor is
/// run by [`tlb_free`]'s `Box` rather than silently leaked by `libc::free`.
///
/// **`alloc_zeroed` and not `Box::new(tlb { .. })`.** The struct is 288 KB and
/// that expression builds it on the *caller's stack* first, where a guest
/// thread has 512 KB. `Box::new_zeroed` is the `calloc` this replaces — Rust's
/// system allocator calls `calloc` for an aligned request — so an allocation
/// this size still comes back as fresh zero pages instead of 288 KB of stores.
/// What is given up is the compiler naming a field nobody initialised, which is
/// why the paragraph below exists.
///
/// **All-zero is not a usable TLB, and never was.** A zeroed entry says guest
/// page 0 is cached at host address 0, and `dirty_page` names page 0 rather
/// than "none" — `EMPTY` is 1 for exactly that reason. What makes it usable is
/// [`tlb_refresh`], which every caller runs before the first guest access:
/// `task_run_current`'s loop does it at the top of every iteration, and the
/// first one always flushes because a fresh TLB's `mmu` is null and the address
/// space's is not. That was as true of the `calloc` as it is of this; it was
/// nowhere written down.
pub fn tlb_new() -> *mut ffi::tlb {
    // SAFETY: all-zero is a valid `tlb` -- every field is a pointer, an
    // integer, an array of those, or the frame's `Option<Box>`, whose `None`
    // is zero. `Box::new_zeroed` is the `alloc_zeroed` this spelled out by
    // hand, with the layout and the null test `Box`'s own.
    let tlb = unsafe { Box::<ffi::tlb>::new_zeroed().assume_init() };
    LIVE.fetch_add(1, Ordering::Relaxed);
    Box::into_raw(tlb)
}

/// # Safety
/// Nothing holds `tlb` any more.
pub unsafe fn tlb_free(tlb: *mut ffi::tlb) {
    unsafe {
        // The whole point of [`tlb_new`]'s `Box`: a field that grows a
        // destructor is run here, where `libc::free` would have leaked it with
        // nothing to say so.
        drop(Box::from_raw(tlb));
    }
    LIVE.fetch_sub(1, Ordering::Relaxed);
}

/// Translate `addr` and cache the result. Null if the guest may not have it,
/// with `segfault_addr` left for the caller to report.
///
/// Called from the header's inline lookup and from `entry.S` by `bl`.
///
/// # Safety
/// `tlb` is live, this is the thread that owns it, and its `mmu` is live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tlb_handle_miss(
    tlb: *mut ffi::tlb,
    addr: u64,
    kind: c_int,
) -> *mut c_void {
    let mmu = unsafe { (*tlb).mmu };
    let page = page_base(addr);

    // The seqlock; see the module comment.
    // `gen` is a keyword in edition 2024, which is why the local is `at` and
    // the generated field is `gen_`.
    let mut at;
    let mut ptr;
    let mut attempt = 0;
    loop {
        at = unsafe { generation(mmu) };
        // No flush when the generation has moved: the entry is stamped below
        // and a stale one is refused by its stamp. See `tlb_refresh`.
        unsafe { (*tlb).mem_changes = at as _ };
        ptr = unsafe { (translator().translate)(mmu, page, kind) };
        if unsafe { generation(mmu) } == at {
            break;
        }
        if attempt >= 8 {
            // Take the post-translate generation, so the entry stamped below is
            // at least self-consistent with this last translation.
            at = unsafe { generation(mmu) };
            unsafe { (*tlb).mem_changes = at as _ };
            break;
        }
        attempt += 1;
    }

    if ptr.is_null() {
        unsafe { (*tlb).segfault_addr = addr };
        return std::ptr::null_mut();
    }

    unsafe {
        (*tlb).dirty_page = page;
        let entry = &mut (*tlb).entries[index(addr)];
        entry.page = page;
        entry.data_minus_addr = (ptr as usize).wrapping_sub(page as usize);
        // The generation this host pointer is valid for. A hit is trustworthy
        // only while `mmu->changes` still equals it.
        // bindgen renames `gen` to `gen_`: it is a keyword in edition 2024.
        entry.gen_ = at as usize;

        entry.page_if_writable = if kind == ffi::MEM_WRITE as c_int {
            page
        } else {
            // A read miss asks speculatively whether the page is writable too,
            // so that the store which usually follows a load does not miss
            // again. It must not *fault*: this is the no-fault entry point, and
            // a copy-on-write break here would do the copy for a read.
            if (translator().translate_write_nofault)(mmu, page).is_null() {
                EMPTY
            } else {
                page
            }
        };
        (entry.data_minus_addr.wrapping_add(addr as usize)) as *mut c_void
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_index_is_what_the_gadgets_compute() {
        // `((addr >> 12) ^ (addr >> 25)) & 8191`. Written out here because the
        // assembly computes it independently -- this is one of the two places
        // that have to agree, and the other cannot be tested from Rust.
        assert_eq!(ffi::TLB_BITS, 13);
        assert_eq!(ffi::TLB_SIZE, 8192);
        for addr in [
            0u64,
            0x1000,
            0x1fff,
            0xdead_b000,
            0xffff_f000,
            0x1_2345_6789,
        ] {
            let want = (((addr >> 12) ^ (addr >> 25)) & 8191) as usize;
            assert_eq!(index(addr), want, "{addr:#x}");
        }
    }

    #[test]
    fn the_two_halves_of_an_address_are_mixed() {
        // Which is the point of the exclusive-or: a stride of exactly TLB_SIZE
        // pages -- what a page-table walk or a large memset produces -- would
        // otherwise land on one entry every time.
        let stride = 8192u64 << 12;
        let hits: std::collections::BTreeSet<usize> =
            (0..8).map(|i| index(0x1000_0000 + i * stride)).collect();
        assert!(
            hits.len() > 1,
            "a TLB_SIZE stride must not alias to one entry"
        );
    }

    #[test]
    fn an_empty_entry_cannot_be_confused_with_a_page() {
        // `page` holds an address with its offset cleared, so the sentinel just
        // has to be unaligned. 1 is, and 0 would not be -- address zero is a
        // page a guest can map.
        assert_eq!(EMPTY, 1);
        assert_ne!(EMPTY, page_base(0));
        for addr in [0u64, 0x1000, 0xffff_ffff_ffff_ffff] {
            assert_ne!(page_base(addr), EMPTY);
            assert_eq!(page_base(addr) & 0xfff, 0);
        }
    }

    #[test]
    fn the_page_is_an_address_and_not_a_page_number() {
        // The entry compares against `addr & ~0xfff`, not `addr >> 12`, because
        // `data_minus_addr` is the difference between a host pointer and the
        // guest *address* -- a hit adds the full address back.
        assert_eq!(page_base(0x1234_5678), 0x1234_5000);
    }
}
