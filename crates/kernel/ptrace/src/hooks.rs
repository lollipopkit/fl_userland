//! Hooks crossing the ptrace crate's one-way dependency boundary.

use std::ffi::c_int;
use std::sync::OnceLock;

/// Send a signal to one thread, for `PTRACE_KILL`'s `SIGKILL` and
/// `PTRACE_ATTACH`'s `SIGSTOP`. A hook because `crates/kernel/signaldeliver`
/// calls into this crate on every ptrace stop, so the direct call would be a
/// cycle.
///
/// It takes the task as a `kernel_pids::Task`, the proof that `pids_lock` is
/// held. Installed by `crates/kernel/boot`'s `install_run_hooks`: it was armed
/// by the first signal anything sent until 2026-11-13, which `PTRACE_ATTACH`
/// can come before.
static SIGNAL: OnceLock<fn(kernel_pids::Task<'_>, c_int)> = OnceLock::new();

/// Install the signal operation. The first call wins.
pub fn set_signal_hook(f: fn(kernel_pids::Task<'_>, c_int)) {
    let _ = SIGNAL.set(f);
}

/// Whether the signal operation has been installed.
pub fn signal_hook_installed() -> bool {
    SIGNAL.get().is_some()
}

/// Send `sig` to `task` through the installed signal layer.
pub(crate) fn signal(task: kernel_pids::Task<'_>, sig: c_int) {
    if let Some(f) = SIGNAL.get() {
        f(task, sig);
    }
}

/// Wake a task to take a trap: `PTRACE_INTERRUPT`. Installed with
/// [`set_signal_hook`], for the same reason.
static WAKE: OnceLock<fn(kernel_pids::Task<'_>)> = OnceLock::new();

/// Install the wake operation. The first call wins.
pub fn set_wake_hook(f: fn(kernel_pids::Task<'_>)) {
    let _ = WAKE.set(f);
}

/// Whether the wake operation has been installed.
pub fn wake_hook_installed() -> bool {
    WAKE.get().is_some()
}

/// Wake `task` through the installed signal layer.
pub(crate) fn wake(task: kernel_pids::Task<'_>) {
    if let Some(f) = WAKE.get() {
        f(task);
    }
}
