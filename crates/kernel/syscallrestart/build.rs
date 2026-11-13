//! The syscall numbers, generated from the table rather than written down.
//!
//! This crate has to name syscalls — which ones re-execute correctly and which
//! carry a deadline that a naive re-run would restart from the beginning. A
//! list of numbers written out by hand is the shape `guessed_constants` exists
//! to find: `crates/kernel/syscalltable` is the one place that says what number
//! a syscall has, and a second copy is something two files can disagree about
//! with no warning from either compiler.
//!
//! So the table is parsed. A name that leaves it breaks this build, which is
//! the whole point: a classification naming a syscall that no longer exists is
//! a classification that silently stops applying.
//!
//! The table moved to `crates/kernel/syscalltable` on 2026-09-03 and this reads
//! it there. Depending on the crate instead would be circular — that crate is
//! the table, and this generates constants *about* it before either compiles —
//! so what is read is still the source text, one line per entry, the same way.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

/// Whether a line is a table entry at all, whichever macro registers it.
///
/// Separate from [`entry`] so that a line this *is* an entry and [`entry`]
/// cannot read is a build failure rather than a missing constant. See the
/// assertion in `main`, and the defect it was written for.
///
/// **Not a list of macro names.** It was `at!` and `at_res!` written out, and
/// the third one -- `at_val!`, for a syscall that cannot fail -- matched
/// neither, so nine entries were *neither* readable nor recognised as entries
/// and the assertion below said nothing about them. That is the same defect
/// the assertion exists for, one level up: a check that enumerates what it
/// knows about cannot report what it has never heard of. Anything shaped
/// `at...!(t, ...sys_...)` is an entry now.
fn looks_like_an_entry(line: &str) -> bool {
    let line = line.trim();
    line.starts_with("at") && line.contains("!(t, ") && line.contains("sys_")
}

/// `at!(t, 63, sys_read);` -> `("read", 63)`.
///
/// A range — `at!(t, 5..=16, sys_xattr_stub)` — takes its low number, which is
/// what the C form `[5 ... 16]` did too: the name is one implementation and the
/// number this needs is a number it answers at.
///
/// `at_res!(t, 57, sys_close, 1);` is the same entry for an implementation that
/// answers `Result<T, Errno>`, and `at_val!(t, 172, sys_getpid, 0);` for one
/// that cannot fail; the trailing number is the implementation's arity and is
/// nothing to do with the syscall number.
///
/// The prefix is taken up to `!(t, ` rather than matched against a list of
/// macro names, for the reason [`looks_like_an_entry`] gives.
fn entry(line: &str) -> Option<(String, u64)> {
    let line = line.trim();
    if !line.starts_with("at") {
        return None;
    }
    let rest = &line[line.find("!(t, ")? + "!(t, ".len()..];
    let (num, rest) = rest.split_once(',')?;
    let num = num.split("..=").next()?;
    let num: u64 = num.trim().parse().ok()?;
    let at = rest.find("sys_")? + "sys_".len();
    let name: String = rest[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    Some((name, num))
}

fn main() {
    let root = buildcfg::repo_root();
    // TODO(migration): replace source-text parsing with a shared generated
    // syscall-number artifact once the table no longer needs build-time access.
    let table = root.join("crates/kernel/syscalltable/src/table.rs");
    println!("cargo:rerun-if-changed={}", table.display());

    let text = fs::read_to_string(&table).expect("the aarch64 syscall table");
    // A name can appear at more than one number (`sys_ni_syscall`, aliases);
    // the first wins, which is what the C reader would take it to mean.
    let mut nums: BTreeMap<String, u64> = BTreeMap::new();
    let mut unreadable = Vec::new();
    for line in text.lines() {
        match entry(line) {
            Some((name, num)) => {
                nums.entry(name).or_insert(num);
            }
            None if looks_like_an_entry(line) => unreadable.push(line.trim().to_string()),
            None => {}
        }
    }
    // **Every line that is an entry must parse as one.**
    //
    // `nums.len() > 100` was the whole check until 2026-09-11, and it does not
    // notice a *subset* going missing. Registering six syscalls with a second
    // macro -- `at_res!`, for the ones that answer a `Result` -- dropped
    // `NR_FCNTL`, `NR_IOCTL`, `NR_CLOSE`, `NR_DUP`, `NR_DUP3` and
    // `NR_CLOSE_RANGE` from this file while 224 others still parsed, and the
    // count stayed comfortably above 100.
    //
    // What made it loud was luck: `NR_FCNTL` and `NR_IOCTL` appear in a `match`
    // arm, so rustc read them as *bindings* and refused the arm. The other four
    // are named nowhere here, so their loss was silent -- and the silent loss
    // is the dangerous half, because `classify` answering `Restart::Never` for
    // a syscall that should restart is a hang a guest sees and no test asks
    // about.
    assert!(
        unreadable.is_empty(),
        "the table has entries this build script cannot read, so the syscall \
         numbers below would be missing and nothing else would say so:\n  {}",
        unreadable.join("\n  ")
    );
    assert!(
        nums.len() > 100,
        "parsed only {} syscalls out of the table -- the shape of it changed",
        nums.len()
    );

    let mut out =
        String::from("// Generated by build.rs from crates/kernel/syscalltable. Do not edit.\n");
    for (name, num) in &nums {
        out.push_str(&format!(
            "pub const NR_{}: u64 = {};\n",
            name.to_uppercase(),
            num
        ));
    }
    let dest = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("syscall_numbers.rs");
    fs::write(&dest, out).expect("write the generated syscall numbers");
}
