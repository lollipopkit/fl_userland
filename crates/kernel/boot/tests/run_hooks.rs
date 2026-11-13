//! `become_first_process` installs the five hooks whose two ends cannot be a
//! cargo edge in either direction.
//!
//! `crates/kernel/exitcalls` and `crates/kernel/syscalldispatch` both depend on
//! `crates/kernel/taskcalls` — the second through the syscall table, which
//! names every family — and `exitcalls` depends on `crates/kernel/signaldeliver`
//! for the signals an exit sends. `crates/asbestos/dispatch` is two layers below
//! `kernel` outright. So all four calls go through a `OnceLock` that
//! `crates/kernel/boot` fills, because it is the one crate that can see both
//! ends.
//!
//! **These four are the one place in the tree where a missing hook is not a
//! meaningful answer.** Everywhere else "not installed" means something true —
//! no signal is pending, no lock is held, no filesystem is registered. A guest
//! thread that cannot dispatch an interrupt cannot run at all, and a fatal
//! signal that does not end the process leaves a task executing the code it was
//! killed for. So they `expect`, and this test is about the *install* rather
//! than about a wrong answer, because there is no wrong answer to observe.
//!
//! An **integration** test rather than a `#[cfg(test)] mod`, because linking
//! `crates/asbestos/dispatch` pulls in the gadget assembly, and the gadgets call
//! `crates/asbestos/crypto`'s helpers — the whole engine, which is what
//! `iul` is. `CLAUDE.md`'s rule: a test that needs the product is a
//! `tests/` binary.

// The engine, for the symbols the gadget assembly names. `_` because nothing
// here calls it: an `--extern` nothing mentions is not loaded.
use iul as _;

#[test]
fn becoming_the_first_process_installs_the_hooks_no_cargo_edge_can_carry() {
    kernel_boot::install_run_hooks();
    assert!(
        taskcalls::run_hooks_installed(),
        "do_exit and handle_interrupt"
    );
    assert!(signaldeliver::exit_group_hook_installed(), "do_exit_group");
    assert!(kernel_ptrace::signal_hook_installed(), "PTRACE_KILL and PTRACE_ATTACH");
    assert!(kernel_ptrace::wake_hook_installed(), "PTRACE_INTERRUPT");
    assert!(
        asbestos_dispatch::interrupt_hook_installed(),
        "prebuilt re-entry"
    );
    // The fifth is only a diagnostic, and is here for the reason it is
    // installed here rather than at the first clear: a run with no
    // self-modifying code reports `clears=0` whether the install happened or
    // not, so nothing else can tell.
    assert!(
        asbestos_diag::wx_clears_counter_installed(),
        "IUL_WX_STATS clears"
    );
}
