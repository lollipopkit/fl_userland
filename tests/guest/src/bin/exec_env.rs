//! The environment this kernel forces onto a process, asked of the **first**
//! process and of a later `execve`.
//!
//! This kernel injects a handful of environment variables and, for `node`, a
//! handful of V8 flags — workarounds for things that misbehave under emulation.
//! The list is `crates/kernel/execcalls`.
//!
//! # Why the first process is the interesting one
//!
//! Until 2026-09-03 there were **two** lists: the one in the crate, applied by
//! `sys_execve`, and a copy in `xX_main_Xx.h` applied by the CLI to its first
//! process. They had drifted — the copy was missing `PIP_PROGRESS_BAR`, carried
//! a `--no-expose-wasm` no later exec passed, and had no notion of *replacing*
//! a value, so a caller's `PYTHONMALLOC` survived into the first process and
//! was overridden in every one after it. An embedder that is not this CLI got
//! **no** injection at all, so its first process differed from its second.
//!
//! Nothing tested any of it. The check that matters is not "is this variable
//! set" — it is that the answer is the **same** before and after an exec, which
//! is what a second list can never guarantee.
//!
//! # Not comparable against a real kernel
//!
//! Linux injects nothing. This is in `differential.sh`'s `not_comparable()`.

use guest_tests::{Harness, check};
use std::ffi::CString;

/// The names, without their values. The values are this kernel's business and
/// change; that every one of them reaches both sides is the contract.
const INJECTED: &[&str] = &[
    "PYTHONMALLOC",
    "NO_COLOR",
    "PIP_PROGRESS_BAR",
    "PYTHONDONTWRITEBYTECODE",
    "GODEBUG",
    "GOMAXPROCS",
    "UV_THREADPOOL_SIZE",
];

/// Every injected name and the value it has here, as `NAME=value` lines in the
/// order of [`INJECTED`], so two runs can be compared as text.
fn snapshot() -> Vec<String> {
    INJECTED
        .iter()
        .map(|n| match std::env::var(n) {
            Ok(v) => format!("{n}={v}"),
            Err(_) => format!("{n}=<unset>"),
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // The second half: re-executed with a marker, so this is a process the
    // kernel reached through `sys_execve` rather than through the boot path.
    if args.len() > 1 && args[1] == "--after-exec" {
        for line in snapshot() {
            println!("{line}");
        }
        return;
    }

    let mut h = Harness::new();
    h.group("injected-environment");

    // The first process. Every name has to be here: this is the path that had
    // its own list.
    let before = snapshot();
    for (name, line) in INJECTED.iter().zip(&before) {
        check!(h, !line.ends_with("<unset>"), "{name} is set in the first process");
    }

    // And after an exec, which is the path the crate's list has always covered.
    // Comparing the two is the point: a second list somewhere can pass both
    // halves separately and still disagree.
    let me = CString::new(args[0].clone()).expect("no NUL in argv[0]");
    let out = std::process::Command::new(me.to_str().unwrap())
        .arg("--after-exec")
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let after: Vec<String> = String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::to_string)
                .collect();
            check!(
                h,
                after.len() == INJECTED.len(),
                "the exec'd child reported every name: {} of {}",
                after.len(),
                INJECTED.len()
            );
            for (b, a) in before.iter().zip(&after) {
                check!(h, b == a, "the same before and after an exec: {b} against {a}");
            }
        }
        Ok(o) => check!(h, false, "the exec'd child ran: status {:?}", o.status),
        Err(e) => check!(h, false, "the exec'd child ran: {e}"),
    }

    std::process::exit(h.finish());
}
