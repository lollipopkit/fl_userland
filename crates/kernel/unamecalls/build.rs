//! The two guest structs `uname(2)` and `sysinfo(2)` answer into, and the build
//! stamp that goes in the version string.
//!
//! Generated rather than mirrored: `struct sys_info` is 112 bytes with **three
//! explicit padding fields**, one of which sits between a `uint16_t` and a
//! `uint64_t`, and `struct uname` is six 65-byte character arrays whose total is
//! not a multiple of anything. Either is a layout a hand-written Rust copy would
//! get wrong without a compiler saying so.

use std::process::Command;

/// `__DATE__ " " __TIME__`, which is what the C put in `uts.version`.
///
/// The C preprocessor has no Rust equivalent, so it is a build script's job.
/// `date` is asked for exactly C's formats — a space-padded day, so a build on
/// the 3rd reads `Sep  3 2026` as it always did.
fn build_stamp() -> String {
    Command::new("date")
        .args(["+%b %e %Y %H:%M:%S"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn main() {
    println!("cargo:rustc-env=IUL_BUILD_STAMP={}", build_stamp());
}
