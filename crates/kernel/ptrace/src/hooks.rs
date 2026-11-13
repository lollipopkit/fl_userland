//! Hooks crossing the ptrace crate's one-way dependency boundary.

use std::sync::OnceLock;


/// The signal-delivery operation used by `PTRACE_KILL`.
///
/// It takes the task as a `kernel_pids::Task`, the proof that `pids_lock` is
/// held; it took a `*mut ffi::task`, and the installer conjured that proof
/// with `PidsHeld::assume` until 2026-10-16.
static KILL: OnceLock<fn(kernel_pids::Task<'_>)> = OnceLock::new();

/// Install the kill operation. The first call wins.
pub fn set_kill_hook(f: fn(kernel_pids::Task<'_>)) {
    let _ = KILL.set(f);
}

/// Whether the signal-delivery operation has been installed.
pub fn kill_hook_installed() -> bool {
    KILL.get().is_some()
}

/// Deliver `SIGKILL` through the installed signal layer.
pub(crate) fn kill(task: kernel_pids::Task<'_>) {
    if let Some(kill) = KILL.get() {
        kill(task);
    }
}
