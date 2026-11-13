//! Which output handler this build was configured with.
//!
//! A build names one with `-DLOG_HANDLER_<NAME>=1` in `TMPFS_RS_CLANG_ARGS`,
//! and **naming none is the ordinary case**: the default is `dprintf`.
//!
//! # Why dprintf, and what the other default cost
//!
//! It was `stderr` until 2026-09-09, with the reason "the only handler that
//! needs nothing set up" — and `meson_options.txt` defaulted to `dprintf`, so a
//! cargo-only `libiul.a` was a **different library** from meson's.
//! `tests/integration/sbm_api_test.c` captures descriptor 666, which is where
//! `dprintf` writes and `stderr` does not, so the example linked against the
//! cargo build failed its `vprintk` check while printing the line to the
//! terminal.
//!
//! There is one build path since 2026-09-11 and meson has no default to differ
//! from, so that particular disagreement cannot recur — but the handler is part
//! of what an embedder links, and 666 is the embedder contract, so `dprintf` is
//! what stays.
//!
//! # Why this is not a cargo feature
//!
//! The five handlers are **mutually exclusive**, and cargo features are
//! additive: a feature cannot deselect another crate's, so two dependents
//! asking for different handlers would union them. That is caught — two `cfg`s
//! set means two definitions of `write_line` and the build fails — but it is
//! caught as a duplicate-symbol-shaped error at the bottom of a workspace
//! rather than as "you asked for two". A `-D` is a choice with one value, which
//! is what this is, and it travels down the channel that already exists rather
//! than adding a second one. CLAUDE.md records that widening the build-time
//! channel rather than auditing it is what produced the third failure of it.
//!
//! There used to be a `cargo:warning` here when no handler was named, because
//! under meson that meant either a hand-run build *or a broken channel*, and
//! the two were indistinguishable. Nothing constructs `TMPFS_RS_CLANG_ARGS`
//! now — a person sets it or does not — so an unset variable is not evidence of
//! anything and the warning was on every build.
const HANDLERS: &[&str] = &[
    "LOG_HANDLER_DPRINTF",
    "LOG_HANDLER_SYSLOG",
    "LOG_HANDLER_STDERR",
    "LOG_HANDLER_NSLOG",
    "LOG_HANDLER_OS_LOG",
];

/// The one a build gets when it names none. `sink.rs` has a `compile_error!`
/// for "no handler at all", so removing this line is loud rather than silent.
const DEFAULT: &str = "LOG_HANDLER_DPRINTF";

fn main() {
    buildcfg::emit_cfgs(HANDLERS);
    if !HANDLERS.iter().any(|h| buildcfg::is_defined(h)) {
        println!("cargo::rustc-cfg={}", buildcfg::cfg_name(DEFAULT));
    }
}
