//! The debug channels, as `cfg`s rather than as calls into C.
//!
//! # What this replaces
//!
//! `debug.h`'s `TRACE()` routes to a channel decided by a `#define`, and a
//! crate could not see one — so `kernel/log.c` grew three pairs of functions,
//! `iul_strace_enabled`/`iul_strace_line` and the same for `sock` and `instr`.
//! The `enabled` half returned a folded constant and the caller cached it.
//!
//! That worked and it was a runtime call standing in for a compile-time fact.
//! Since 2026-09-06 a build's own `-D` flags travel down the same
//! channel, so `#[cfg(iul_debug_strace)]` is the same question
//! asked where it can be answered — and a channel that is off compiles to
//! nothing at all rather than to a call that returns 0.
//!
//! # The output side is `crates/util/logline`
//!
//! It was in the kernel layer until 2026-10-17, which a `util` crate may not
//! reach, so this called `iul_printk` -- logline's own C-ABI variadic entry --
//! by name, through an `extern "C"` block: a Rust-to-Rust call through a C
//! format string, and an edge cargo could not see. logline depends on nothing
//! above `util`, so it moved down and is a dependency here.

/// Hand a finished line to the log.
///
/// Split out so the formatting above is testable: the test build records
/// instead of printing.
#[cfg(not(test))]
fn emit(line: &str) {
    logline::printk(line);
}

#[cfg(test)]
fn emit(line: &str) {
    tests::RECORDED.with(|r| r.borrow_mut().push(line.to_owned()));
}

/// The channels a build can compile in.
///
/// An enum rather than three functions, so that adding a channel is one arm
/// and a caller cannot ask for one that does not exist.
///
/// Two of them exist because the diagnostics **shipped**, which is the reason
/// `debug.h` gave for adding each and is worth keeping now that the header is
/// gone: `sock` was a run of unconditional `printk("NETDIAG ...")` in
/// `fs/sock.c`, one of them on every blocking `recv`. `debug.h` had a `fakefs`
/// channel for the same reason — twenty unconditional `fprintf(stderr)` in
/// `fs/fake.c` covering rootfs registration, bind mounts and the
/// relative-symlink rewrite, two of them guarded by a `strstr` for one
/// embedder's directory names, on every entry of every `readdir` — and it has
/// no arm here because nothing in the Rust ever routed to it. Add one when
/// something does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// Syscall tracing, for a syscall whose body is Rust.
    Strace,
    /// The `NETDIAG` lines a blocking socket wait prints: which thread is
    /// stuck on which descriptor, and for how long.
    Sock,
    /// One line per block the compiler translates.
    Instr,
}

impl Channel {
    /// Did this build compile the channel in?
    ///
    /// A `const fn` over a `cfg`, so a caller's `if` folds away entirely.
    #[inline]
    pub const fn enabled(self) -> bool {
        match self {
            Channel::Strace => cfg!(iul_debug_strace),
            Channel::Sock => cfg!(iul_debug_sock),
            Channel::Instr => cfg!(iul_debug_instr),
        }
    }

    /// The prefix `debug.h`'s `TRACE_(channel, ...)` puts on a line.
    const fn prefix(self) -> &'static str {
        match self {
            // `STRACE()` prints the line as it stands; the other two are
            // `TRACE_(name, ...)`, which does not prefix either. Kept as a
            // method so that a channel that wants one has somewhere to say so.
            Channel::Strace | Channel::Sock | Channel::Instr => "",
        }
    }
}

/// Print `line` on `channel`, if this build has it.
///
/// Does nothing — and formats nothing — when the channel is off, which is the
/// point: the `enabled` test folds, so the call disappears.
///
/// A NUL in `line` truncates it rather than dropping the line: a trace point
/// that cannot print is worse than one that prints less.
pub fn line(channel: Channel, line: &str) {
    if !channel.enabled() {
        return;
    }
    let text = match channel.prefix() {
        "" => line,
        p => &format!("{p}{line}"),
    };
    emit(before_nul(text));
}

/// `text` up to its first NUL: the backends hand a line on as a C string, and
/// losing a diagnostic to a stray byte is the wrong trade in the only kind of
/// build that has the diagnostic at all.
fn before_nul(text: &str) -> &str {
    text.split('\0').next().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        pub(super) static RECORDED: std::cell::RefCell<Vec<String>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    fn taken() -> Vec<String> {
        RECORDED.with(|r| std::mem::take(&mut *r.borrow_mut()))
    }

    /// A test build defines no channel, so every one is off. That is what makes
    /// the next test meaningful and it is worth asserting rather than assuming.
    #[test]
    fn a_test_build_has_every_channel_off() {
        for ch in [Channel::Strace, Channel::Sock, Channel::Instr] {
            assert!(!ch.enabled(), "{ch:?} should be off in a build with no -D");
        }
    }

    /// The whole point: a channel that is off formats nothing and emits
    /// nothing. If `enabled()` stopped folding this would still pass, but the
    /// cost would move — which is why the fold is asserted separately below.
    #[test]
    fn a_channel_that_is_off_emits_nothing() {
        let _ = taken();
        line(Channel::Strace, "should not appear");
        line(Channel::Sock, "nor this");
        assert!(taken().is_empty());
    }

    /// `enabled()` is `const`, so a caller's `if` is folded at compile time
    /// rather than tested at run time. Using it in a `const` context is what
    /// proves it — a non-`const` function would not compile here.
    #[test]
    fn enabled_is_a_compile_time_constant() {
        const S: bool = Channel::Strace.enabled();
        const K: bool = Channel::Sock.enabled();
        const I: bool = Channel::Instr.enabled();
        assert_eq!([S, K, I], [false, false, false]);
    }

    /// A NUL truncates rather than dropping the line.
    ///
    /// `CString::new` refused the whole string, and the first version of this
    /// returned early on that — losing a diagnostic to a stray byte, in the
    /// only kind of build where the diagnostic exists.
    #[test]
    fn a_nul_truncates_and_does_not_lose_the_line() {
        // Reach the formatting directly: every channel is off in a test build,
        // so `line` would return before doing any of it.
        assert_eq!(super::before_nul("before\0after"), "before");
        assert_eq!(super::before_nul("no nul here"), "no nul here");
        assert_eq!(super::before_nul("\0all gone"), "");
    }
}
