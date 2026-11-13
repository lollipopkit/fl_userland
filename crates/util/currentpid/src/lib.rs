//! The calling thread's guest pid, for a diagnostic that is below the layer
//! that knows it.
//!
//! Three crates want it and none of them is the kernel: `crates/util/locks`
//! puts it in every `lock_t` under `-DLOCK_DEBUG=1`, `crates/asbestos/diag`
//! names a histogram file with it, and `crates/asbestos/gen` prefixes a
//! compile trace. All three are below `kernel` — layer 0 and layer 2 — and the
//! answer is a `thread_local!` in `crates/kernel/abi`.
//!
//! So they named a `kernel` crate for a debug line, which is one of the two
//! reasons `tools/crate-layers.py` exempts `kernel-abi` everywhere. A hook is
//! the same answer this tree gives everywhere else the news is below the layer
//! that has it.
//!
//! # `-1` before anything installs one is the truth, not a fallback
//!
//! That is exactly what `kernel-abi`'s `current_pid` answers for a thread with
//! no task — the timer service, a test binary, anything before the first
//! process. It answered `0` to a Rust caller and `-1` to a C one until
//! 2026-09-05, and `-1` is what the lock-debug macros have always printed and
//! what every caller wants: each compares against a real pid, and `0` is not
//! one.
//!
//! # Cost
//!
//! One acquire load and an indirect call, on paths that are off by default:
//! `LOCK_DEBUG` is a build flag and both trace lines are behind an `IUL_*`
//! variable. Nothing on the syscall path reads this.

use std::ffi::c_int;
use std::sync::OnceLock;

static HOOK: OnceLock<fn() -> c_int> = OnceLock::new();

/// Install it. `crates/kernel/boot`'s `install_run_hooks` does, from the
/// thread-local that holds the current task.
pub fn set_hook(f: fn() -> c_int) {
    let _ = HOOK.set(f);
}

/// Whether it has been installed — for the test in `crates/kernel/boot`. A
/// thread with no task reads `-1` either way, so no answer distinguishes them.
pub fn hook_installed() -> bool {
    HOOK.get().is_some()
}

/// The calling thread's guest pid, or `-1`.
#[inline]
pub fn current_pid() -> c_int {
    match HOOK.get() {
        Some(f) => f(),
        None => -1,
    }
}
