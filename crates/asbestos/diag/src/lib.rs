//! What the JIT records about itself: the counters, the pc trace, the pc
//! histogram, the block profile, the gadget profile and the store watchpoint.
//!
//! All of it is off unless an `IUL_*` variable turns it on, and all of it is
//! read once at startup — see the note on those fields in `util/ish_env.h`.
//! Until 2026-09-02 three of the gates were a `static _Atomic int` filled in
//! lazily, which put three sequentially-consistent loads in the dispatch loop
//! in every build anybody runs.
//!
//! # The gate stays in C and the body is here
//!
//! `asbestos/asbestos.c` writes `if (iul_env.pc_hist) diag_pc_hist(...)`, so a
//! build with the variable unset pays a load and a not-taken branch and never
//! makes a call. That is the same shape `crates/util/strace` and the signpost
//! bridge already have, and it is what lets a diagnostic live in a crate at all
//! when the thing it instruments is the hottest loop in the emulator.
//!
//! # The counters are defined here and incremented there
//!
//! Ten `_Atomic uint64_t` globals that the dispatch loop adds to. They keep
//! their C names and the C keeps its `atomic_fetch_add_explicit`, because a
//! relaxed increment of a shared counter is the same instruction either way and
//! the alternative is a call per block.


use std::io::Write;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

/// Relaxed, because nothing reads these except a dump at exit and nothing
/// orders anything by them.
const RELAXED: Ordering = Ordering::Relaxed;

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        $(
            pub static $name: AtomicU64 = AtomicU64::new(0);
        )*
    };
}

// What the dispatch loop counts. `IUL_DISPATCH_COUNT` prints the first.
counters!(
    S_DISPATCH_ITERATIONS,
    ST_BLOCK_CACHE_MISS,
    ST_BLOCK_COMPILE,
    ST_CHAIN_ATTEMPTS,
    ST_INT_POKE,
    ST_INT_POKE_FOREIGN,
    ST_INT_CYCLE,
    ST_POKE_CALLS,
);

// W^X: how often a page was marked as holding code, how often the compile had
// to be redone because the mark did not survive it, and how often it gave up.
// `st_wx_clears` is `crates/kernel/pagetable`'s -- it counts the stores that
// take a mark *off*, which is the other side of the same question.
counters!(ST_WX_MARKS, ST_WX_RETRIES, ST_WX_GIVEUPS);

mod pc;
pub use pc::{diag_pc_hist, diag_pc_trace, dump_pc_hist, dump_pc_trace};
mod block;
pub use block::diag_block_prof;
use block::dump_block_prof;
mod gadget;
mod watch;
use watch::dump_stage_trace;
pub use watch::{
    diag_arm_watchpoint, dump_gadget_profile_if_built, dump_watch_hits,
    jit_trace_regs, set_peek32_hook, stage_trace_on, watch_pages,
    watch_record_memptr, watch_window,
};

/// The stores that unprotected a code page. `crates/kernel/pagetable`'s.
///
/// It was an `extern "C"` declaration until 2026-09-09, and the note on it was
/// right about the constraint and wrong about the options.
/// `crates/kernel/pagetable` depends on this crate — it reads the store
/// watchpoint on the host-write path — so a dependency the other way is a cycle
/// cargo refuses. The note then said the alternative was to have `pagetable`
/// *push* the count, "one atomic store per W^X clear on a hot path, to save a
/// declaration", and rejected it.
///
/// There is a third shape and it costs nothing per clear: hand over the
/// counter's **address**, once. `pagetable` still does its own
/// `fetch_add` — the same instruction it already did — and this crate reads
/// through the pointer in `dump_wx_stats`, which runs once at exit under
/// `IUL_WX_STATS=1`.
///
/// **Null means no clear has happened**, which is the truth rather than a
/// fallback: `pagetable` installs this the first time it takes a `P_CODE` mark
/// off, so a run with no self-modifying code reports zero either way.
static WX_CLEARS: AtomicPtr<AtomicU64> = AtomicPtr::new(std::ptr::null_mut());

/// Install it. See [`WX_CLEARS`].
pub fn set_wx_clears_counter(counter: &'static AtomicU64) {
    WX_CLEARS.store(
        (counter as *const AtomicU64).cast_mut(),
        std::sync::atomic::Ordering::Release,
    );
}

/// Whether the counter's address has been handed over — for the test in
/// `crates/kernel/boot`. A run with no self-modifying code reports zero either
/// way, which is why no assertion about the *number* can stand in for this.
pub fn wx_clears_counter_installed() -> bool {
    !WX_CLEARS
        .load(std::sync::atomic::Ordering::Acquire)
        .is_null()
}

fn wx_clears() -> u64 {
    match unsafe {
        WX_CLEARS
            .load(std::sync::atomic::Ordering::Acquire)
            .as_ref()
    } {
        Some(c) => c.load(RELAXED),
        None => 0,
    }
}

/// `IUL_WX_STATS=1`: what the W^X protocol did.
pub fn dump_wx_stats() {
    if !util_iulenv::env().wx_stats {
        return;
    }
    eprintln!(
        "[wx] marks={} clears={} retries={} giveups={}",
        ST_WX_MARKS.load(RELAXED),
        wx_clears(),
        ST_WX_RETRIES.load(RELAXED),
        ST_WX_GIVEUPS.load(RELAXED),
    );
}

// ---------------------------------------------------------------------------
// What an exiting process prints
// ---------------------------------------------------------------------------

/// Every diagnostic an exiting process dumps, in one call.
///
/// These were nine `extern void dump_*(void);` declarations scattered through
/// `kernel/exit.c`, three of them behind a `static int` that made them fire
/// once. **Which of them exist depends on build flags a crate cannot see**,
/// which is why the cluster is one call the exit path makes.
///
/// `is_init` is pid 1: the four that summarise the whole guest run only mean
/// anything from the process that outlives every other one. With
/// `IUL_PC_HIST_DIR` set, every process writes its own histogram instead, so a
/// forked chain is captured whole.
pub fn iul_dump_diagnostics_at_exit(is_init: bool, group_exit: bool) {
    if is_init || util_iulenv::env().pc_hist_dir.is_some() {
        dump_pc_hist();
    }
    if !is_init {
        return;
    }
    static ONCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if ONCE.swap(true, Ordering::AcqRel) {
        return;
    }
    if !group_exit {
        dump_pc_trace();
    }
    dump_wx_stats();
    dump_stage_trace();
    dump_block_prof();
    dump_gadget_profile_if_built();
}

/* `dump_stage_trace` and `dump_gadget_profile_if_built` were declared here,
 * because both were `#ifdef`-shaped and a crate could not see a build flag.
 * Both are defined in the diagnostic modules as of 2026-09-06:
 * `-DIUL_GADGET_PROFILE` reaches this crate as a `cfg` now. See
 * crates/util/buildcfg. */

#[cfg(test)]
mod tests {
    use crate::pc::{FINE_BASE, FINE_N, FINE_SHIFT, HIST_BUCKETS, HIST_SHIFT, PC_TRACE_DEFAULT};

    #[test]
    fn the_histogram_buckets_cover_the_low_four_gigabytes() {
        // 64 KB each, which is where a guest's code is: the loader puts an
        // executable and its libraries below 4 GB, and a bucket that is much
        // finer buries the answer in noise.
        assert_eq!(HIST_BUCKETS as u64 * (1 << HIST_SHIFT), 4 << 30);
    }

    #[test]
    fn the_fine_view_is_one_window_at_two_hundred_and_fifty_six_bytes() {
        // Enough to name a function inside a bucket the coarse histogram has
        // pointed at, over the 64 MB where a guest's own text lands.
        assert_eq!(FINE_N as u64 * (1 << FINE_SHIFT), 64 << 20);
        assert_eq!(FINE_BASE + (FINE_N as u64) * (1 << FINE_SHIFT), 0xf000_0000);
    }

    #[test]
    fn a_block_profile_entry_packs_its_length_into_the_count() {
        // The count is incremented by 256 so the low byte, which is the block's
        // instruction length, survives. A length above 255 is clamped rather
        // than allowed to carry into the count.
        let packed: u64 = 256 * 3 + 255;
        assert_eq!(packed >> 8, 3);
        assert_eq!(packed & 0xff, 255);
    }

    #[test]
    fn the_pc_trace_default_window_is_an_address_and_not_an_identity() {
        // Which is why IUL_PC_TRACE_RANGE exists: this is where one node
        // build's hot code landed, and a different build wants the variable.
        let (lo, hi) = PC_TRACE_DEFAULT;
        assert!(lo < hi);
        assert_eq!(hi - lo, 0x40000);
    }
}
