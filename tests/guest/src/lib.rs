//! Shared harness for the guest-side test programs.
//!
//! Each of them runs inside the emulator and reports how many checks it made
//! and how many failed, exiting non-zero if any did. Checks are independent: a
//! failure records and continues, so one broken operation does not hide the
//! state of everything after it.

use std::ffi::CString;
use std::fmt;

pub mod caps;
pub mod insn;
pub mod sys;

pub struct Harness {
    checks: u32,
    failures: u32,
    group: &'static str,
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

impl Harness {
    pub fn new() -> Harness {
        Harness {
            checks: 0,
            failures: 0,
            group: "?",
        }
    }

    pub fn group(&mut self, name: &'static str) {
        self.group = name;
    }

    #[track_caller]
    pub fn check(&mut self, ok: bool, what: fmt::Arguments<'_>) {
        self.checks += 1;
        if !ok {
            self.failures += 1;
            let loc = std::panic::Location::caller();
            println!(
                "  FAIL  [{}] {}  ({}:{})",
                self.group,
                what,
                loc.file(),
                loc.line()
            );
        }
    }

    /// A call that must fail, with a specific errno.
    ///
    /// The two are checked together because errno only means anything when the
    /// call actually failed.
    #[track_caller]
    pub fn check_fails(&mut self, result: i64, want: i32, what: fmt::Arguments<'_>) {
        self.checks += 1;
        let got = sys::errno();
        if result >= 0 || got != want {
            self.failures += 1;
            let loc = std::panic::Location::caller();
            println!(
                "  FAIL  [{}] {}: returned {} errno {} ({}), wanted -1 errno {} ({})  ({}:{})",
                self.group,
                what,
                result,
                got,
                sys::strerror(got),
                want,
                sys::strerror(want),
                loc.file(),
                loc.line()
            );
        }
    }

    pub fn finish(self) -> i32 {
        println!("  {} checks, {} failed", self.checks, self.failures);
        i32::from(self.failures != 0)
    }
}

#[macro_export]
macro_rules! check {
    ($h:expr, $cond:expr, $($arg:tt)*) => {
        $h.check($cond, format_args!($($arg)*))
    };
}

/// Assert that a call fails with a given errno.
///
/// **`$call` must be the call itself, not a result computed earlier.** This
/// clears errno before evaluating it, so handing over an already-computed `r`
/// wipes the errno that call set and the check reads 0 — reporting `errno 0
/// (No error information)` for a syscall that failed correctly. That happened
/// once, in `fs_metadata`'s `renameat2` check, and the report was unreadable
/// enough that the syscall looked broken rather than the assertion.
///
/// Where the call cannot be re-issued inside the macro because it is not
/// idempotent, capture `sys::errno()` on the line after it and use [`check!`].
#[macro_export]
macro_rules! check_fails {
    ($h:expr, $call:expr, $errno:expr, $($arg:tt)*) => {{
        $crate::sys::clear_errno();
        let r_ = ($call) as i64;
        $h.check_fails(r_, $errno, format_args!($($arg)*))
    }};
}

/// A NUL-terminated path for the raw syscalls.
pub fn cpath(path: &str) -> CString {
    CString::new(path).expect("path with an interior NUL")
}
