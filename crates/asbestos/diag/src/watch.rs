//! Store watchpoint state and the assembly-facing diagnostic hooks.

use super::*;

// ---------------------------------------------------------------------------
// The store watchpoint
// ---------------------------------------------------------------------------

/// How many hits the ring keeps. It wraps, so what survives is the *last*
/// `WATCH_RING` — the opposite of the pc trace, because a watchpoint is armed
/// to find out what happened just before something went wrong.
const WATCH_RING: usize = 8192;

#[derive(Clone, Copy, Default)]
struct Hit {
    addr: u64,
    block_pc: u64,
    cpu_pc: u64,
    field: u32,
    /// 0 from a store gadget, 1 from a C helper, 2 from `mem_ptr`.
    from: u8,
}

/// A `Mutex` rather than an array of atomics: a record is six fields and has to
/// land as one, and the ring is only written when a watchpoint is armed — which
/// is never, in a build nobody is debugging.
static WATCH: std::sync::Mutex<(Vec<Hit>, u64)> = std::sync::Mutex::new((Vec::new(), 0));

// ---------------------------------------------------------------------------
// The globals the gadgets read
// ---------------------------------------------------------------------------
//
// `asbestos/asbestos.c` defined these until 2026-09-06, and the reason given
// was that the *assembly* reads them. It does — `gadgets.h`'s store fast path
// does an `adrp`/`add` on `g_watch_pages` and an `ldp` of the pair — and that
// is a statement about the **symbol**, not about the language that defines it.
// A `#[unsafe(no_mangle)] static` produces the same symbol at the same
// alignment, and the assembler cannot tell.
//
// They are here because this crate is the watchpoint: `diag_arm_watchpoint`
// sets them and `record_hit` reads them.
//
// **Atomics since 2026-09-06, and the symbol is unchanged.** An `AtomicU64` has
// the layout and alignment of a `u64` and an `[AtomicU64; 2]` of a `[u64; 2]`,
// so the `adrp`/`add`/`ldp` above still works — but the Rust side stops needing
// `unsafe` to read one, and stops being a data race on paper when the arming
// thread and a guest thread overlap. `Relaxed` is right: these are compared
// against, never used to order anything.
//
// Three other crates used to declare them `extern` — a dependency edge cargo
// cannot see, and each got to spell the type itself. They call the accessors
// below now.

/// The sub-page windows a record must fall in, and the guest `u32` to snapshot
/// at every hit. Set by [`diag_arm_watchpoint`].
#[unsafe(no_mangle)]
pub static g_watch_lo: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
pub static g_watch_hi: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
pub static g_watch_lo2: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
pub static g_watch_hi2: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
pub static g_watch_field: AtomicU64 = AtomicU64::new(0);

/// The page the assembly compares a store against.
///
/// `g_watch_pages[0]` is a shadow copy of it, which is why the two are set
/// together: the fast path reads the *pair* with one `ldp` and compares both,
/// so a second watched page costs no extra load.
#[unsafe(no_mangle)]
pub static g_watch_page_val: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
pub static g_watch_pages: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// Report the register state at a gadget boundary.
///
/// Called **from the assembly** (`entry.S`) and a no-op: the hook is there so
/// a build under investigation can put something in it without touching a
/// gadget.
#[unsafe(no_mangle)]
pub extern "C" fn jit_trace_regs(_cpu: *mut std::ffi::c_void) {}

/// The gadget call profile's ring, written by the `gret` gadget.
///
/// Half a megabyte of BSS that exists only under `-DIUL_GADGET_PROFILE`, which
/// reaches this crate as a `cfg` — see `crates/util/buildcfg`. The 64-byte
/// alignment is the gadget's: it indexes without a bounds check.
#[cfg(iul_iul_gadget_profile)]
pub mod profile {
    #[repr(C, align(64))]
    pub struct Ring(pub [u64; 65536]);

    #[unsafe(no_mangle)]
    pub static mut g_profile_buf: Ring = Ring([0; 65536]);

    #[repr(C, align(64))]
    pub struct Index(pub u64);

    #[unsafe(no_mangle)]
    pub static mut g_profile_idx: Index = Index(0);
}

/// Print the gadget call profile, if this build has one.
///
/// The gate is a `cfg` rather than a runtime test: without
/// `-DIUL_GADGET_PROFILE` there is no ring to read and this compiles to
/// nothing, which is what the C's `#ifdef` did.
/// Not `#[no_mangle]` since 2026-09-06: `crates/tools/iul` declared it in a
/// hand-written `extern` block and calls it directly now.
pub fn dump_gadget_profile_if_built() {
    #[cfg(iul_iul_gadget_profile)]
    // SAFETY: the run is over -- this is called from the exit path -- so the
    // gadgets are no longer writing.
    unsafe {
        super::gadget::gadget_profile(
            (&raw const profile::g_profile_buf).cast::<u64>(),
            (&raw const profile::g_profile_idx.0).read(),
        );
    }
}

/// Stage tracing was an in-progress instrumentation whose definitions lived in
/// a scratch file. These are the no-op stubs that keep the tree linking, and
/// they stay because whether the instrumentation exists at all is a build
/// flag.
/// As [`dump_gadget_profile_if_built`]: `crates/asbestos/dispatch` was the
/// declaring caller.
pub fn stage_trace_on() -> std::ffi::c_int {
    0
}

/// See [`stage_trace_on`]. Plain Rust: its only caller is in this crate, and
/// an export no C reaches is an optimisation barrier rather than an interface.
pub(super) fn dump_stage_trace() {}

/// Arm the store watchpoint from `IUL_WATCH_*`.
///
/// **Not `#[no_mangle]`**: its one caller is `crates/tools/iul`, which is Rust
/// since 2026-09-03, and a C ABI export nothing on the C side reaches is what
/// `tools/dead-exports.py` reports. It keeps `extern "C"` because it is
/// installed by address in one place and the ABI costs nothing.
///
/// Called once, from `main`, before any guest thread. It was seven
/// `getenv`+`strtoull` pairs written out inline there until 2026-09-03 — the
/// only `IUL_*` variables read anywhere but `crates/util/iulenv`, so they
/// followed none of its rules and the page mask that makes the whole thing work
/// could not be tested. The values come from `iul_env` now, masked where they
/// are parsed.
///
/// The two globals holding the first page are set **together**: the assembly's
/// store fast path does an `ldp` of `g_watch_pages`, and `g_watch_page_val` is
/// the copy the C-side checks read, so a divergence arms one and not the other.
///
/// Called before any guest thread exists. No longer `unsafe`: the globals are
/// atomics, so writing them needs no contract from the caller.
pub fn diag_arm_watchpoint() {
    let w = util_iulenv::watch();
    g_watch_page_val.store(w.pages[0], Relaxed);
    g_watch_pages[0].store(w.pages[0], Relaxed);
    g_watch_pages[1].store(w.pages[1], Relaxed);
    g_watch_lo.store(w.lo, Relaxed);
    g_watch_hi.store(w.hi, Relaxed);
    g_watch_lo2.store(w.lo2, Relaxed);
    g_watch_hi2.store(w.hi2, Relaxed);
    g_watch_field.store(w.field, Relaxed);
}

/// The watched sub-page window, for a reader in another crate.
///
/// A function rather than an `extern "C" { static g_watch_lo: u64; }` in each
/// of them: that declaration is a dependency edge cargo cannot see, and it lets
/// every reader spell the type itself. See `CLAUDE.md` on why the graph
/// matters.
pub fn watch_window() -> (u64, u64) {
    (g_watch_lo.load(Relaxed), g_watch_hi.load(Relaxed))
}

/// The two watched pages. `[0]` is zero when nothing is armed, which is what
/// every reader checks first.
pub fn watch_pages() -> [u64; 2] {
    [
        g_watch_pages[0].load(Relaxed),
        g_watch_pages[1].load(Relaxed),
    ]
}

/// Is this address inside the window a watchpoint was armed with?
///
/// **The filter applies to the `mem_ptr` records too.** It used to exempt them,
/// and a sub-page window then filled the whole ring with page-granular fault
/// records that could never match it — 102,953 of them and not one store to the
/// word being asked about, which is how the third instrument aimed at the
/// `task_race` deadlock came back empty. A filter narrower than a page excludes
/// them by construction, which is what somebody arming one wants; arm it at
/// page granularity to keep them.
fn in_window(addr: u64) -> bool {
    let (lo, hi) = watch_window();
    if hi == 0 {
        return true;
    }
    if addr >= lo && addr < hi {
        return true;
    }
    let (lo2, hi2) = (g_watch_lo2.load(Relaxed), g_watch_hi2.load(Relaxed));
    hi2 != 0 && addr >= lo2 && addr < hi2
}

/// A racy, unlocked read of a guest `u32`, installed by
/// `crates/kernel/pagetable`, which is the only thing that can walk a page
/// table.
///
/// # Why a hook
///
/// A diagnostic must not pull the thing it instruments into its dependency
/// graph, and this one did: the page table records host-side writes *here*, so
/// calling `mem_watch_peek32` from here closed a cycle the moment both calls
/// were Rust calls rather than C ones. It stayed invisible for as long as one
/// of them went through the linker.
///
/// Unset means the watchpoint has recorded nothing, so there is nothing to read
/// a field for.
static PEEK32: std::sync::OnceLock<unsafe fn(u64) -> u32> = std::sync::OnceLock::new();

/// Install it. The first call wins.
pub fn set_peek32_hook(f: unsafe fn(u64) -> u32) {
    let _ = PEEK32.set(f);
}

fn record(addr: u64, cpu_pc: u64, from: u8) {
    if !in_window(addr) {
        return;
    }
    let field = match g_watch_field.load(Relaxed) {
        0 => 0,
        at => PEEK32.get().map_or(0, |f| unsafe { f(at) }),
    };
    let hit = Hit {
        addr,
        // The block pc the JIT is executing, for a record to be symbolised
        // against the guest binary. A `__thread` in `asbestos.c` until
        // 2026-09-06; `crates/asbestos/jitstate` owns it now, and a thread
        // that never entered the dispatch loop has none.
        block_pc: {
            let jit = jitstate::current();
            if jit.is_null() {
                0
            } else {
                unsafe { (*jit).saved_pc.load(std::sync::atomic::Ordering::Relaxed) }
            }
        },
        cpu_pc,
        field,
        from,
    };
    let Ok(mut w) = WATCH.lock() else { return };
    w.1 += 1;
    if w.0.len() < WATCH_RING {
        w.0.push(hit);
    } else {
        let at = ((w.1 - 1) as usize) % WATCH_RING;
        w.0[at] = hit;
    }
}

/// A store this emulator's own C made — `user_write`, `madvise`'s zeroing, a
/// copy-on-write copy. These bypass the store gadgets, so they are recorded
/// separately and shown as `(mem_ptr)`.
pub fn watch_record_memptr(addr: u64) {
    record(addr, 0, 2);
}

// `c_watch_write_hit` was here, recording a store made by a C helper rather
// than a gadget. Its only caller was `emu/tlb.h`'s `ENABLE_C_WRITE_WATCHPOINT`
// block, which went with the inline lookup on 2026-09-02; the `(C)` tag a
// record can carry is what is left of it, and `watch_record_memptr` below is
// the host-side path that remains.

#[derive(Default)]
struct FieldRegs {
    hits: u32,
    first: [u64; 31],
    first_pc: u64,
    last: [u64; 31],
    last_pc: u64,
}

static FIELD_REGS: std::sync::Mutex<FieldRegs> = std::sync::Mutex::new(FieldRegs {
    hits: 0,
    first: [0; 31],
    first_pc: 0,
    last: [0; 31],
    last_pc: 0,
});

/// Print the ring, filtered to `[lo, hi)` — or all of it when `hi` is zero.
pub fn dump_watch_hits(filter_lo: u64, filter_hi: u64) {
    let Ok(w) = WATCH.lock() else { return };
    let (ring, total) = (&w.0, w.1);
    let kept = ring.len();
    let mut err = std::io::stderr().lock();
    let _ = writeln!(
        err,
        "[watch] {total} total hits, showing last {kept} in [{filter_lo:#x},{filter_hi:#x})"
    );
    let first = total as usize - kept;
    for k in 0..kept {
        let h = ring[(first + k) % WATCH_RING];
        if filter_hi != 0 && (h.addr < filter_lo || h.addr >= filter_hi) {
            continue;
        }
        let from = match h.from {
            2 => "(mem_ptr)",
            1 => "(C)",
            _ => "(jit)",
        };
        let _ = writeln!(
            err,
            "[watch] #{} addr={:#x} block_pc={:#x} cpu_pc={:#x} field={:#x} {from}",
            first + k,
            h.addr,
            h.block_pc,
            h.cpu_pc,
            h.field
        );
    }

    let Ok(f) = FIELD_REGS.lock() else { return };
    if f.hits == 0 {
        return;
    }
    let _ = writeln!(
        err,
        "[watch-field] store hit count={}, regs at the first hit (pc={:#x}):",
        f.hits, f.first_pc
    );
    for (i, chunk) in f.first.chunks(4).enumerate() {
        let mut line = String::from("   ");
        for (j, v) in chunk.iter().enumerate() {
            line.push_str(&format!(" x{}={v:#x}", i * 4 + j));
        }
        let _ = writeln!(err, "{line}");
    }
    let _ = writeln!(
        err,
        "[watch-field] and at the last (pc={:#x}): x0={:#x} x8={:#x} x9={:#x} x19={:#x}",
        f.last_pc, f.last[0], f.last[8], f.last[9], f.last[19]
    );
}
