//! Hands `table_probe` the set of syscall numbers this kernel implements.
//!
//! The probe sweeps syscall numbers and compares each answer against a real
//! kernel, so the set it sweeps has to be *the numbers where a difference means
//! something*. A number this kernel does not implement answers `ENOSYS` here
//! and whatever Linux does there — 240 lines of "we have not implemented that",
//! which is a coverage fact and is already knowable from the table.
//!
//! The set is generated rather than written down for the reason every list in
//! this tree is: two hand-written lists drift, and this one would drift every
//! time a syscall is implemented. `crates/kernel/syscalltable` is the only
//! place that knows which number reaches what.
//!
//! This is a host build script for a package cross-compiled to
//! `aarch64-unknown-linux-musl`, which is fine — it only writes a list.

use std::fmt::Write as _;
use std::path::Path;

/// Targets whose numbers are left out of the sweep, and why each one.
///
/// A target that no longer appears in the table fails this build, which is the
/// rule every allowlist in this tree has: an entry that suppresses nothing has
/// stopped recording a decision and started waiting to cover something else.
const EXCLUDED: &[(&str, &str)] = &[
    (
        "syscall_stub",
        "unimplemented: answers ENOSYS for every argument, and comparing that \
         against a kernel that implements it says only that it is unimplemented",
    ),
    ("syscall_silent_stub", "unimplemented, without the log line"),
    (
        "not_configured",
        "ENOSYS on purpose, as a kernel built without the feature answers; \
         what Linux answers instead is compared case by case in the probe that \
         names the call (procsec_probe, mm_modern_probe)",
    ),
];

fn main() {
    // **Every file of the crate, not one named file.** This read
    // `syscalltable/src/lib.rs` by path until 2026-09-11, and the table had
    // moved to `table.rs` in a module split: 292 entries became 0 and this
    // build script's own assertion is what said so. `tools/syscall-abi.py` had
    // the identical line and no assertion, so it printed "0 wired syscalls" and
    // exited 0 for five days. Two readers of one file, one loud and one silent.
    let dir = Path::new("../../crates/kernel/syscalltable/src");
    println!("cargo:rerun-if-changed={}", dir.display());
    println!("cargo:rerun-if-changed=build.rs");

    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("the syscall table crate's sources")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    files.sort();
    let src: String = files
        .iter()
        .map(|p| std::fs::read_to_string(p).expect("a syscall table source"))
        .collect();

    // `at!(t, 62, sys_lseek)` and `at!(t, 5..=16, sys_xattr_stub)`, and the
    // two macros that carry an arity as well: `at_res!(t, 57, sys_close, 1)`
    // for an implementation that answers a `Result` and `at_val!` for one that
    // cannot fail.
    //
    // **Matched by shape rather than by name.** It was `strip_prefix("at!(t, ")`,
    // so every entry registered with one of the other two macros was dropped --
    // 204 of 450 read on the day `at_val!` arrived. The count assertion below
    // is what said so, in the same minute; `crates/kernel/syscallrestart`'s
    // reader is the same parse with no such assertion and lost eleven entries
    // silently. Keep the assertion, and do not add a fourth macro name to a
    // list.
    let mut entries: Vec<(i64, String)> = Vec::new();
    for line in src.lines() {
        let line = line.trim();
        if !line.starts_with("at") {
            continue;
        }
        let Some(at) = line.find("!(t, ") else {
            continue;
        };
        let rest = &line[at + "!(t, ".len()..];
        // The arguments contain no parentheses of their own.
        let Some(end) = rest.find(')') else {
            continue;
        };
        let mut parts = rest[..end].split(", ");
        let (Some(num), Some(target)) = (parts.next(), parts.next()) else {
            continue;
        };
        let target = target.trim().to_string();
        if let Some((lo, hi)) = num.split_once("..=") {
            let (lo, hi) = (parse(lo), parse(hi));
            for n in lo..=hi {
                entries.push((n, target.clone()));
            }
        } else {
            entries.push((parse(num), target));
        }
    }
    assert!(
        entries.len() > 400,
        "read {} entries out of the syscall table, which is too few to be right",
        entries.len()
    );

    for (name, _) in EXCLUDED {
        assert!(
            entries.iter().any(|(_, t)| t == name),
            "`{name}` is in this file's EXCLUDED list and in no `at!` line of the \
             syscall table: an entry that excludes nothing suppresses whatever \
             lands on that name next"
        );
    }

    let mut swept: Vec<i64> = entries
        .iter()
        .filter(|(_, t)| !EXCLUDED.iter().any(|(name, _)| t == name))
        .map(|(n, _)| *n)
        .collect();
    swept.sort_unstable();
    swept.dedup();

    let mut out = String::new();
    let _ = writeln!(
        out,
        "/// The syscall numbers this kernel implements, from the table. Generated."
    );
    let _ = write!(out, "pub const IMPLEMENTED: &[i64] = &[");
    for (i, n) in swept.iter().enumerate() {
        if i % 16 == 0 {
            let _ = write!(out, "\n    ");
        }
        let _ = write!(out, "{n}, ");
    }
    let _ = writeln!(out, "\n];");

    let dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(Path::new(&dir).join("syscall_table.rs"), out).expect("write the list");
}

fn parse(s: &str) -> i64 {
    s.trim().parse().unwrap_or_else(|_| panic!("not a syscall number: {s:?}"))
}
