//! The host CLI, and the only in-repo example of driving the engine.
//!
//! `mount_root()` → `become_first_process()` → `do_execve()` → `task_run_current()`.
//! An embedder writes its own; ServerBox's is `ios/Runner/iul/sbm_iul.c`, and
//! `tests/integration/sbm_api_test.c` is the C example that stays C.
//!
//! `main.c` and `xX_main_Xx.h` until 2026-09-03. It links the engine as an
//! rlib through `iul`; see `Cargo.toml` for why that is not `libiul.a`.

mod boot;
mod crash;
mod diag;
mod opts;

#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    dead_code,
    clippy::all
)]
pub mod ffi {
    pub use taskview::ffi::*;
}

// The Rust half of the kernel. Named so the linker keeps it: the C archives
// reference its exports, and without this the rlib is not on the link line at
// all.
use iul as _;
// The gadgets, which are assembly and have no Rust to call. Named so that
// rustc loads the rlib and sees its `cargo:rustc-link-lib` -- an `--extern`
// nothing mentions is not loaded, and the archive never reaches the linker.
// That is a wall of `Undefined symbols: _gadget_*`, not a missing feature.
use asbestos_diag::dump_gadget_profile_if_built;
use asbestos_gadgets as _;

fn main() -> std::process::ExitCode {
    // SAFETY: nothing else is running yet, which is the requirement every one
    // of these has.
    // `crates/util/signpost` needs no init call: its log handles are a
    // `OnceLock`, where the C read `logs[cat]` unsynchronised to decide
    // whether to run its `pthread_once`.
    unsafe {
        diag::install_exit_dumps();
        asbestos_diag::diag_arm_watchpoint();
        diag::start_poller();
        diag::install_sigterm_dump();
        crash::save_terminal();
        crash::install_handlers();
        // `printk` writes to descriptor 666 under `LOG_HANDLER_DPRINTF`, which
        // is a number rather than a stream so that a guest cannot reach it by
        // opening one. Point it at stderr; without this the kernel's own log
        // goes nowhere in that build.
        libc::dup2(libc::STDERR_FILENO, 666);
    }

    let args: Vec<String> = std::env::args().collect();
    match boot::boot(&args) {
        Ok(()) => {}
        Err(e) => {
            // Only when nothing more specific has been said: the step that
            // knows which path failed has already printed it, and a second
            // line naming only the errno makes that harder to read rather than
            // easier.
            if !e.reported {
                eprintln!("iul: {}", boot::describe(e.errno));
            }
            return std::process::ExitCode::from((-e.errno).clamp(1, 255) as u8);
        }
    }

    // Does not return: the guest's first thread runs here and leaves through
    // `set_exit_hook`, which receives `boot::exit_handler`.
    unsafe { taskcalls::task_run_current() };
    std::process::ExitCode::SUCCESS
}
