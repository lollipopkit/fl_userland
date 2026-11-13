//! Atomic and exclusive load/store instruction decoders.
//!
//! # Release and acquire
//!
//! Guest threads are host threads, so acquire and release become `dmb ish`
//! around a plain access. The placement matters, because the architecture
//! orders a **release followed by an RCsc acquire** (`STLR; LDAR`, and the
//! `STLXR`/`LDAXR`, `STLXP`/`LDAXP` and atomic `A`/`L` forms of the same):
//! the load may not be satisfied before the store is observed. Store buffering
//!
//! ```text
//! T0: stlr 1, [x]; ldar r0, [y]      T1: stlr 1, [y]; ldar r1, [x]
//! ```
//!
//! must never end with `r0 == r1 == 0`, and C++/Rust `SeqCst` stores and loads
//! are exactly this pair on arm64, so Dekker-style locks rely on it. With
//! `dmb; str` for the release and `ldr; dmb` for the acquire there is no
//! barrier between the store and the load, and the host reorders them (observed
//! in `tests/guest/src/bin/ordering_litmus.rs`: 15 to 115 of 100000-200000
//! rounds).
//!
//! The fix is a **trailing** `dmb ish` on every release (`dmb; str; dmb`), not
//! a leading one on every RCsc acquire: acquires (mutex lock, `atomic.load`)
//! are far more frequent than releases, and every acquire already pays its
//! trailing `dmb`. LDAPR and LDAPUR are RCpc, may pass an earlier STLR, and
//! stay at one barrier; the release's trailing one happens to order them too,
//! which is allowed.
//!
//! The LSE read-modify-write and compare-and-swap helpers (`atomic_rmw`,
//! `atomic_cas`, `atomic_cas128`, `c_stxr_cas`, `stxp_cas`) already use
//! `SeqCst` host atomics, which are `ldaddal`/`casal` or an `ldaxr`/`stlxr`
//! loop, so an atomic acquire after an earlier `STLR` needs nothing more (the
//! litmus is clean for them before this change). An atomic that is itself a
//! release is followed by the same `dmb` so that a later plain-load acquire
//! (`LDAR` here is `ldr; dmb`) cannot pass its store.

use super::*;

// ---------------------------------------------------------------------------
// Atomics
// ---------------------------------------------------------------------------

/// `LDADD`, `LDCLR`, `LDEOR`, `LDSET`, the four extremes and `SWP`.
///
/// The acquire and release bits become real barriers (see the module comment):
/// release ahead of the operation and, for the RCsc pairing, behind it too.
pub(super) fn atomic_rmw(g: &mut Gen, insn: u32) -> c_int {
    let size = (insn >> 30) & 0x3;
    let acquire = (insn >> 23) & 1;
    let release = (insn >> 22) & 1;
    let rs = (insn >> 16) & 0x1f;
    let rn = (insn >> 5) & 0x1f;
    let rt = insn & 0x1f;
    let op = (insn >> 12) & 0xf;

    // Nine operations, 0 through 8. Anything above is unallocated.
    if op > 0x8 {
        return g.undefined();
    }

    g.addr_imm(rn, 0);
    if release != 0 {
        g.barrier();
    }
    g.slow_call(
        emu_tlb::access::slow_atomic_rmw,
        rs as u64 | ((size as u64) << 8) | ((op as u64) << 16) | ((rt as u64) << 24),
    );
    if acquire != 0 || release != 0 {
        g.barrier();
    }
    DECODED
}

/// `CASP`, at both widths.
///
/// `wide` is the `sz` bit, and it is the whole difference: the 64-bit form is
/// a **true sixteen-byte atomic** over `{Rs, Rs+1}` against sixteen bytes of
/// memory, and the 32-bit one is an eight-byte atomic over a pair of words.
/// Treating the first as a 64-bit compare-and-swap tears the pair, which is
/// the `libpas` versioned-field corruption that hangs Bun.
pub(super) fn casp(g: &mut Gen, insn: u32, wide: bool) -> c_int {
    let acquire = (insn >> 22) & 1;
    let release = (insn >> 15) & 1;
    let rs = (insn >> 16) & 0x1f;
    let rn = (insn >> 5) & 0x1f;
    let rt = insn & 0x1f;

    g.addr_imm(rn, 0);
    if release != 0 {
        g.barrier();
    }
    let f: emu_tlb::access::SlowFn =
        if wide { emu_tlb::access::slow_casp } else { emu_tlb::access::slow_casp32 };
    g.slow_call(f, rs as u64 | ((rt as u64) << 8));
    if acquire != 0 || release != 0 {
        g.barrier();
    }
    DECODED
}

/// `CAS` at any width. The old value goes back into `Rs`, which is what the
/// instruction does — the expected register is also the result.
pub(super) fn cas(g: &mut Gen, insn: u32) -> c_int {
    let size = (insn >> 30) & 0x3;
    let acquire = (insn >> 22) & 1;
    let release = (insn >> 15) & 1;
    let rs = (insn >> 16) & 0x1f;
    let rn = (insn >> 5) & 0x1f;
    let rt = insn & 0x1f;

    g.addr_imm(rn, 0);
    if release != 0 {
        g.barrier();
    }
    g.slow_call(emu_tlb::access::slow_atomic_cas, rs as u64 | ((rt as u64) << 8) | ((size as u64) << 16));
    if acquire != 0 || release != 0 {
        g.barrier();
    }
    DECODED
}

// ---------------------------------------------------------------------------
// The exclusives
// ---------------------------------------------------------------------------

/// `LDXR`/`STXR` and their pair and ordered relatives, which share one
/// encoding separated by three single bits.
pub(super) fn exclusive(g: &mut Gen, insn: u32) -> c_int {
    let size = (insn >> 30) & 0x3;
    let o2 = (insn >> 23) & 1; // 1: the ordered, non-exclusive forms
    let l = (insn >> 22) & 1; // 1: load
    let o1 = (insn >> 21) & 1; // 1: a pair
    let rs = (insn >> 16) & 0x1f;
    let o0 = (insn >> 15) & 1; // 1: with acquire or release
    let rt2 = (insn >> 10) & 0x1f;
    let rn = (insn >> 5) & 0x1f;
    let rt = insn & 0x1f;

    if o2 == 0 && o1 == 1 {
        // The pair forms move sixteen bytes, so only the two wide sizes exist.
        if size != 2 && size != 3 {
            return g.undefined();
        }
        if l != 0 {
            g.addr_imm(rn, 0);
            g.slow_call(emu_tlb::access::slow_ldxp, rt as u64 | ((rt2 as u64) << 8) | ((size as u64) << 16));
            if o0 != 0 {
                g.barrier();
            }
        } else {
            // `STXP` is a real compare-and-swap against what `LDXP` loaded.
            // A store pair that always reports success tears every lock-free
            // algorithm built on the exclusive pair — the 128-bit
            // `__atomic_compare_exchange` fallback is exactly one.
            if o0 != 0 {
                g.barrier();
            }
            g.addr_imm(rn, 0);
            g.slow_call(
                emu_tlb::access::slow_stxp,
                rt as u64 | ((rt2 as u64) << 8) | ((rs as u64) << 16) | ((size as u64) << 24),
            );
            if o0 != 0 {
                g.barrier(); // STLXP: a release, ordered before a later LDAXP
            }
        }
        return DECODED;
    }

    if o2 == 1 {
        // `LDAR`/`STLR`: ordered but not exclusive, so no `Rs` and no result.
        if l != 0 {
            g.addr_imm(rn, 0);
            let Some(load) = load_gadget(size, false, false) else {
                return g.undefined();
            };
            g.gadget(load);
            g.barrier();
            g.store_reg(rt);
        } else {
            g.load_reg(rt);
            g.addr_imm(rn, 0);
            g.barrier();
            let Some(store) = store_gadget(size) else {
                return g.undefined();
            };
            g.gadget(store);
            g.barrier(); // STLR: a release, ordered before a later LDAR
        }
        return DECODED;
    }

    if l != 0 {
        g.addr_imm(rn, 0);
        g.gadget(gadget_ldxr);
        g.emit(rt as u64 | ((size as u64) << 8));
        if o0 != 0 {
            g.barrier();
        }
    } else {
        if o0 != 0 {
            g.barrier();
        }
        g.addr_imm(rn, 0);
        g.gadget(gadget_stxr);
        g.emit(rt as u64 | ((rs as u64) << 8) | ((size as u64) << 16));
        if o0 != 0 {
            g.barrier(); // STLXR: a release, ordered before a later LDAXR
        }
    }
    DECODED
}
