//! Which guest *functions* have a whole-block host implementation.
//!
//! The third offload granularity, after the binary (`crates/kernel/offloadexec`)
//! and the symbol (`crates/asbestos/offloadsym`). A registered guest function's
//! entry block is replaced at compile time by a single gadget that calls a
//! `spec_fn` reproducing the function in **guest semantics**: it reads and
//! writes `struct cpu_state` and guest memory through the TLB and never crosses
//! the host/guest object boundary, so it works for a function returning a guest
//! pointer, which symbol-level offload cannot.
//!
//! # What a `spec_fn` must do
//!
//! It is `fn(*mut cpu_state, *mut tlb)`: read its arguments out of
//! `cpu.regs[]`, do the work, write the results back to `cpu.regs[]` and to
//! guest memory through the TLB, and **leave the CPU otherwise as the guest's
//! own instructions would**. The trampoline resumes at the guest link register
//! on return, so a body that means to tail-call sets that itself.
//!
//! The `spec_fn`s are generated offline from the guest function's disassembly
//! by `tools/prebuilt_gadget_gen` and compiled in. None is shipped; the ones
//! that exist are `crates/kernel/offloadtestprebuilt`, which self-registers
//! from a constructor and only with `-Doffload_test_prebuilt=true`.
//!
//! # Mixed execution: a guest call from inside a `spec_fn`
//!
//! When a `spec_fn` reaches a guest `bl` or `blr` it cannot translate the
//! callee, which is another function. It calls it *the guest way* instead:
//! `asbestos_dispatch::prebuilt_call` sets the guest link register to
//! `PREBUILT_SENTINEL`, points the guest pc at the target and re-enters the
//! dispatch loop, which comes back when it reaches the sentinel.
//!
//! `PREBUILT_SENTINEL` is a canonical non-zero guest address inside the low
//! guard region that real code never executes — page-aligned, inside the
//! 48-bit guest space, and high enough not to collide with a real entry. The
//! dispatch loop reads reaching it as `INT_PREBUILT_RET`.
//!
//! It is not cheap: a read lock, a frame, a block lookup and an unwind per
//! guest call, which measured **5.3x slower than threaded execution** on a
//! tight call loop. Registering the callee too takes the inline-cache path
//! instead and costs 1.9x.
//!
//! # Lossless is the gate
//!
//! An unregistered address compiles normally. That is the whole safety
//! argument, and it is why [`native_offload_prebuilt_active`] exists: with no
//! registrations, `crates/asbestos/gen`'s compile does not even look.
//!
//! # The table is read without a lock
//!
//! Every thread's block compiler reads it and registration happens once, from a
//! constructor, before any guest runs. An entry is filled in before the count
//! that publishes it, and nothing is ever removed — the same shape as
//! `crates/asbestos/offloadsym`, for the same reason.
//!
//! Two things the C got wrong and neither could be observed while the table is
//! empty. `native_offload_prebuilt_active` ran its lazy initialisation behind a
//! plain `static bool`, which two threads compiling at once both pass — the
//! shape `asbestos/asbestos.c`'s fused-bcond tables had and which this tree has
//! already written down once. And the per-entry hit counter was a plain `++`
//! from every compiling thread.

use std::ffi::{CStr, c_char, c_int};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use util_appendonly::AppendOnly;

// `struct cpu_state` and `struct tlb`, from the layer below. Naming them is
// what stopped `crates/kernel/offloadtestprebuilt` having to `transmute` its
// registrations into this table; see [`SpecFn`].
use emu_abi::{cpu_state, tlb};

// No bindgen: the one C thing this crate read was `iul_env.offload_stats`,
// which is `util_iulenv::env()` since 2026-09-04. The build script and the
// generated module went with it.

/// The most prebuilt targets that may be registered.
///
/// The C had 4096, which is 128 KB of `.bss` for a table this tree ships none
/// of. It is the same number, because an embedder's generated set is what fills
/// it and nothing here knows how large that is.
const MAX: usize = 4096;

/// One translated guest function: `prebuilt_fn` in `iul.h`, which spells it
/// `void (*)(struct cpu_state *cpu, struct tlb *tlb)`.
///
/// This crate dereferences neither — it hands both pointers to the gadget — and
/// said so as `*mut c_void, *mut c_void` until 2026-09-12. **An argument being
/// opaque to the registry is not a reason for the registry to erase it**, and
/// erasing it here made three renderings of one signature: `iul.h`'s, this, and
/// `crates/kernel/offloadtestprebuilt`'s, which named the real types and
/// `transmute`d into this one. This alias was made `pub` on 2026-09-08 for
/// exactly that reason — "so that `crates/kernel/offloadtestprebuilt` can name
/// the shape it registers rather than transmuting into it" — and the transmute
/// stayed, because the shape it could then name was still the erased one.
/// **Publishing a wrong rendering does not remove the second rendering.**
///
/// A `transmute` between two function pointers is the one place a signature
/// mismatch is completely silent. Naming the types is what removes it: the two
/// crates now share one alias and a registration is a type check.
pub type SpecFn = unsafe extern "C" fn(*mut cpu_state, *mut tlb);

/// One registration. The strings are the caller's and outlive the process,
/// which the header says; they are only ever read, and only to report a hit.
struct Target {
    /// Read once at registration, where "they outlive the process" is the
    /// caller's contract; `None` for a null. A `usize` read back through
    /// `CStr::from_ptr` in the report until 2026-10-01.
    binary: Option<&'static CStr>,
    symbol: Option<&'static CStr>,
    guest_addr: u64,
    spec_fn: SpecFn,
    hits: AtomicU64,
}

/// The registrations. A `static mut` array and a published count until
/// 2026-10-01, with no lock between two registrations: a constructor was
/// assumed to be the only caller. See `util_appendonly`.
static TABLE: AppendOnly<Target, MAX> = AppendOnly::new();
/// Whether the shipped registrations have been made. An `AcqRel` swap rather
/// than the C's plain `bool`: two threads compiling at once both passed that.
static INIT_DONE: AtomicBool = AtomicBool::new(false);

/// Register one. Answers its id, or -1 if the table is full.
///
/// # Safety
/// `binary` and `symbol` are NUL-terminated and outlive the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn native_offload_add_prebuilt(
    binary: *const c_char,
    symbol: *const c_char,
    guest_addr: u64,
    spec_fn: Option<SpecFn>,
) -> c_int {
    let Some(spec_fn) = spec_fn else {
        return -1;
    };
    // SAFETY: the caller's contract -- null, or NUL-terminated and static.
    let [binary, symbol] = [binary, symbol].map(|p| (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }));
    let target = Target {
        binary,
        symbol,
        guest_addr,
        spec_fn,
        hits: AtomicU64::new(0),
    };
    TABLE.push(target).map_or(-1, |id| id as c_int)
}

/// The implementation registered at `pc`, if any.
///
/// A linear scan over a table that is almost always empty, on a path only a
/// block *compile* reaches — so it costs nothing per guest instruction and a
/// miss costs one predictable branch per compile.
pub fn native_offload_prebuilt_lookup(pc: u64) -> Option<SpecFn> {
    for t in TABLE.iter() {
        if t.guest_addr != pc {
            continue;
        }
        if t.hits.fetch_add(1, Ordering::Relaxed) == 0 && util_iulenv::env().offload_stats {
            report(t, pc);
        }
        return Some(t.spec_fn);
    }
    None
}

/// The first-hit line, out of line so the lookup stays small.
fn report(t: &Target, pc: u64) {
    let name = |n: Option<&'static CStr>| n.map_or("?".into(), CStr::to_string_lossy);
    eprintln!("[offload:prebuilt] first hit: {}:{} @ {pc:x}", name(t.binary), name(t.symbol));
}

/// Whether anything is registered, running the shipped registrations first.
///
/// The block compiler asks this before it looks anything up, so a build with no
/// prebuilt targets — which is every build of this tree — does one relaxed load
/// and no scan.
pub fn native_offload_prebuilt_active() -> bool {
    if !INIT_DONE.swap(true, Ordering::AcqRel) {
        native_offload_prebuilt_init();
    }
    !TABLE.is_empty()
}

/// Register the shipped prebuilt targets. There are none.
///
/// It stays as an entry point because the header declares it and because that
/// is where a generated set would be registered: an embedder's build adds the
/// `extern` declarations of its `spec_fn`s and the calls here. The test
/// handlers under `kernel/offload_tests/prebuilt/` do not use it — they
/// self-register from a constructor, which needs no hook.
pub(crate) fn native_offload_prebuilt_init() {}

// This header used to document a `#[no_mangle] static iul_env` double, "the C
// global this crate reads, for a test binary that links no C" -- the shape
// `tools/dup-stubs.py` reports, and it went when `crates/util/iulenv` made that
// read a safe Rust call on 2026-09-04. The double is gone; the comment was left
// behind, describing an item that is not there, and had acquired a duplicate
// `#[cfg(test)]` under it. A stale reason reads as a live one, which is why
// this says what it is rather than being deleted.
#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn spec(_cpu: *mut cpu_state, _tlb: *mut tlb) {}

    /// The whole lifecycle, in one test because the table is a process-wide
    /// `static` and `cargo test` runs tests in parallel: two tests that both
    /// looked at it would see each other. The first version of this file had
    /// two and the empty-table one failed about half the time.
    #[test]
    fn an_empty_table_answers_nothing_and_a_registration_answers_once() {
        // Nothing registered means no scan, which is the gate the whole design
        // rests on: an unregistered address compiles normally.
        assert!(TABLE.is_empty());
        assert!(native_offload_prebuilt_lookup(0x1000).is_none());
        assert!(!native_offload_prebuilt_active(), "and nothing to look up");

        let name = c"probe";
        let id = unsafe {
            native_offload_add_prebuilt(name.as_ptr(), name.as_ptr(), 0x4000, Some(spec))
        };
        assert_eq!(id, 0);
        assert!(native_offload_prebuilt_lookup(0x4000).is_some());
        assert!(
            native_offload_prebuilt_lookup(0x4001).is_none(),
            "and nowhere else"
        );
        assert!(native_offload_prebuilt_active());

        // A registration with no implementation is refused rather than stored:
        // a null in the table would be looked up and jumped to.
        assert_eq!(
            unsafe { native_offload_add_prebuilt(name.as_ptr(), name.as_ptr(), 0x5000, None) },
            -1
        );
        assert_eq!(TABLE.len(), 1);
    }
}
