//! Program-counter trace and instruction-weighted histogram diagnostics.

use super::*;
use std::sync::atomic::{AtomicU32, AtomicU64};

// ---------------------------------------------------------------------------
// The pc trace
// ---------------------------------------------------------------------------

/// How many guest pcs the trace keeps. The first `N` in the window, not the
/// last: it exists to seed a micro-benchmark harness with a realistic dispatch
/// sequence, and the beginning of a run is what that wants.
const PC_TRACE_MAX: usize = 4096;

/// The window, when `IUL_PC_TRACE_RANGE` says nothing. **An address from one
/// node build**, which is not an identity — a different build wants the
/// variable set. Kept because the harness this feeds was written against that
/// build and the number is its only documentation.
pub(crate) const PC_TRACE_DEFAULT: (u64, u64) = (0xee90_0000, 0xee94_0000);

static PC_TRACE: [AtomicU64; PC_TRACE_MAX] = [const { AtomicU64::new(0) }; PC_TRACE_MAX];
static PC_TRACE_N: AtomicU32 = AtomicU32::new(0);

fn pc_trace_window() -> (u64, u64) {
    let env = *util_iulenv::env();
    if env.pc_trace_lo != 0 {
        (env.pc_trace_lo, env.pc_trace_hi)
    } else {
        PC_TRACE_DEFAULT
    }
}

/// Record one dispatched pc. The caller has already tested
/// `iul_env.pc_trace_file`.
pub fn diag_pc_trace(pc: u64) {
    let (lo, hi) = pc_trace_window();
    if pc < lo || pc >= hi {
        return;
    }
    let n = PC_TRACE_N.fetch_add(1, RELAXED) as usize;
    if n < PC_TRACE_MAX {
        PC_TRACE[n].store(pc, RELAXED);
    }
}

/// Write the trace to `IUL_PC_TRACE_FILE`.
///
/// Only reached for pid 1 leaving through a path that is not a group exit,
/// which is `iul_dump_diagnostics_at_exit`'s rule and not this function's — a
/// `/bin/true` leaves through `exit_group` and writes nothing.
pub fn dump_pc_trace() {
    let Some(path) = util_iulenv::env().pc_trace_file else {
        return;
    };
    let n = (PC_TRACE_N.load(RELAXED) as usize).min(PC_TRACE_MAX);
    let mut out = String::new();
    for entry in PC_TRACE.iter().take(n) {
        out.push_str(&format!("{:x}\n", entry.load(RELAXED)));
    }
    if std::fs::write(path, out).is_ok() {
        eprintln!("[pc_trace] wrote {n} PCs to {path}");
    }
}


// ---------------------------------------------------------------------------
// The pc histogram
// ---------------------------------------------------------------------------

/// 64 KB buckets over the low 4 GB, which is where the guest's code is.
pub(crate) const HIST_BUCKETS: usize = 65536;
pub(crate) const HIST_SHIFT: u32 = 16;

/// And a 256-byte view of one 64 MB window, for finding the function inside a
/// bucket the coarse histogram has pointed at.
pub(crate) const FINE_N: usize = 262144;
pub(crate) const FINE_SHIFT: u32 = 8;
pub(crate) const FINE_BASE: u64 = 0xec00_0000;

static HIST: [AtomicU64; HIST_BUCKETS] = [const { AtomicU64::new(0) }; HIST_BUCKETS];
static FINE: [AtomicU64; FINE_N] = [const { AtomicU64::new(0) }; FINE_N];

/// Add `insns` to the bucket `pc` is in. Weighted by instruction count rather
/// than by dispatch, so a long block counts for what it runs.
///
/// The caller has already tested `iul_env.pc_hist`.
pub fn diag_pc_hist(pc: u64, insns: u64) {
    let bucket = (pc >> HIST_SHIFT) as usize;
    if bucket < HIST_BUCKETS {
        HIST[bucket].fetch_add(insns, RELAXED);
    }
    if util_iulenv::env().pc_hist_fine && pc >= FINE_BASE {
        let i = ((pc - FINE_BASE) >> FINE_SHIFT) as usize;
        if i < FINE_N {
            FINE[i].fetch_add(insns, RELAXED);
        }
    }
}

/// `IUL_PC_HIST=1`, and with `IUL_PC_HIST_DIR` a file per exiting process — so
/// a forked chain, which is what a `pip` wheel build is, is captured whole.
pub fn dump_pc_hist() {
    if !util_iulenv::env().pc_hist {
        return;
    }
    let total: u64 = HIST.iter().map(|b| b.load(RELAXED)).sum();
    if total == 0 {
        return;
    }
    let fine = util_iulenv::env().pc_hist_fine;

    if let Some(dir) = util_iulenv::env().pc_hist_dir {
        // The total is in the name as a nonce, so two processes that exit in
        // the same second do not collide.
        let path = format!("{dir}/hist.{}.{total}", currentpid::current_pid());
        let mut body = String::new();
        if fine {
            // Absolute addresses, because a fine bucket index means nothing
            // without the base.
            for (i, b) in FINE.iter().enumerate() {
                let c = b.load(RELAXED);
                if c != 0 {
                    body.push_str(&format!(
                        "{:x} {c}\n",
                        FINE_BASE + ((i as u64) << FINE_SHIFT)
                    ));
                }
            }
        } else {
            for (i, b) in HIST.iter().enumerate() {
                let c = b.load(RELAXED);
                if c != 0 {
                    body.push_str(&format!("{i} {c}\n"));
                }
            }
        }
        let _ = std::fs::write(path, body);
    }

    let mut err = std::io::stderr().lock();
    let _ = writeln!(
        err,
        "=== PC histogram (insn-weighted, dispatched blocks, total={total}) ==="
    );
    for (i, b) in HIST.iter().enumerate() {
        let c = b.load(RELAXED);
        if c == 0 {
            continue;
        }
        let pct = 100.0 * c as f64 / total as f64;
        // Below a tenth of a percent is noise, and printing it buries the
        // buckets that are the answer.
        if pct < 0.1 {
            continue;
        }
        let _ = writeln!(
            err,
            "  0x{:08x}-0x{:08x}  {c:8}  {pct:6.2}%",
            i << HIST_SHIFT,
            ((i + 1) << HIST_SHIFT) - 1
        );
    }
}
