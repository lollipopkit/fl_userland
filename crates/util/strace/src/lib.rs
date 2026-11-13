//! The `strace` log channel, for a syscall implemented in Rust.
//!
//! `STRACE()` in C is a macro over a channel that is *compiled in or out*, so a
//! build without it pays nothing and a build with it prints. A Rust crate
//! cannot see that `#define`, which left every migrated syscall silently
//! missing from the trace — and the strace channel is how a guest program's
//! behaviour gets diagnosed here, so losing a family from it costs more than
//! the family's code is worth.
//!
//! The bridge is one C function, [`iul_strace_enabled`], which the C compiles
//! as a constant `false` when the channel is off. Formatting happens only when
//! it answers true: the macro is
//!
//! ```ignore
//! strace!("socket({}, {}, {})", domain, ty, protocol);
//! ```
//!
//! and the arguments are not evaluated at all in a build with the channel off,
//! which is the property the C macro has.
//!
//! The answer is cached after the first call. It is decided at compile time on
//! the C side, so it cannot change, and the syscall path should not pay a call
//! per trace point to be told the same thing.

use logchan::Channel;

/// Whether the channel is on.
///
/// A folded constant since 2026-09-06. It was a cached call into
/// `iul_strace_enabled`, which returned a `#if`'d constant the crate could not
/// see; the same `-D` reaches cargo through `TMPFS_RS_CLANG_ARGS` now, so this
/// is a `cfg`.
/// The `AtomicU8` cache the call needed went with it.
#[inline]
pub const fn enabled() -> bool {
    Channel::Strace.enabled()
}

/// Prints one already-formatted line. Use [`strace!`] rather than this.
pub fn line(text: &str) {
    // A guest path can contain anything, and an interior NUL would otherwise
    // cut the line short at it. Escaped rather than truncated, because a path
    // is what is being traced and losing its tail loses the point.
    logchan::line(Channel::Strace, &text.replace('\0', "\\0"));
}

/// One trace line, formatted only when the channel is on.
#[macro_export]
macro_rules! strace {
    ($($arg:tt)*) => {
        if $crate::enabled() {
            $crate::line(&format!($($arg)*));
        }
    };
}
