//! The one build-time channel into cargo, read in one place.
//!
//! # Why this crate exists
//!
//! A `#define` that changes a layout has to reach every crate that depends on
//! it, and failing to has cost this tree twice — `meson.build` not passing
//! `c_args` to the crates, and `tools/build-ish-cli.sh` inventing a second
//! variable name. Both times the failure was **silent**: the crate compiled a
//! struct with different offsets and nothing complained.
//!
//! **There is no writer since 2026-09-11.** All three recorded breaks of this
//! channel were a build system constructing the variable from its own options,
//! and each repair widened the channel rather than auditing it, which is why
//! there was a third. meson is gone; a person sets the variable or does not,
//! and there is no second party to disagree with.
//!
//! The answer was one variable, `TMPFS_RS_CLANG_ARGS`, with
//! `tools/bindgen-shadowed.py` asserting every `build.rs` reads it. That works
//! and it left 67 copies of the same six lines, each free to get it slightly
//! wrong. This is those six lines, once.
//!
//! # Two things travel down the same channel
//!
//! [`clang_args`] is what bindgen needs: the include path and every `-D` the C
//! compiler was given, so the generated Rust sees the layout the C sees.
//!
//! [`emit_cfgs`] is the other half and is newer. A `#if` in C — `DEBUG_strace`,
//! `LOG_HANDLER_OS_LOG` — decides whether code exists, and a crate that cannot
//! see it has to ask C at runtime through a function returning a constant. That
//! is what `kernel/log.c`'s `iul_strace_enabled` was. Turning the same `-D`
//! into a `cfg` lets the code be Rust and still compile to nothing when the
//! channel is off.
//!
//! **It is deliberately not automatic.** A caller names the flags it cares
//! about, because a `cfg` that nothing declares is a warning in Rust 1.80+ and
//! because a build script silently reacting to any `-D` in the environment is
//! how the two failures above happened in the first place.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The repository root, found by walking up for a file only it has.
///
/// 65 build scripts had a byte-identical copy of this. Counting `parent()`
/// calls is what it did before that, and it broke the moment the crates moved
/// from `fs/<name>-rs` to `crates/fs/<name>` — a marker survives the next move
/// too.
///
/// **The marker was `kernel/fs.h` until 2026-09-08**, and it survived the move
/// it was chosen for and not the one nobody expected: that header was deleted
/// the day no crate read a header any more, and every build script in the tree
/// panicked at once. `iul.h` is the marker now — the engine's interface, which
/// is the last C file that can go — and a build script is a Rust thing, so
/// `Cargo.toml` would be the other candidate; it is not, because a crate has
/// one too and the walk would stop at the first one above it.
///
/// Panics rather than answering `None`: a build script that cannot find the
/// root has nothing useful left to do, and the message names the cause.
pub fn repo_root() -> PathBuf {
    const MARKER: &str = "iul.h";
    let start = std::env::var_os("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is set by cargo for every build script");
    let mut dir = PathBuf::from(&start);
    loop {
        if dir.join(MARKER).is_file() {
            return dir;
        }
        if !dir.pop() {
            panic!(
                "no repository root above {}: looked for {MARKER} in it and every parent",
                Path::new(&start).display()
            );
        }
    }
}

/// The environment variable a build's `-D` flags arrive in. There is exactly
/// one, and that is the finding rather than the convention — see the module
/// comment.
///
/// The name is `tmpfs`'s because that crate was the first to need it, and it
/// is **not** renamed: nothing outside this repository is known to set it, but
/// a rename's failure mode is that an old invocation silently passes no flags,
/// which is precisely the class of failure this crate exists to end.
pub const CLANG_ARGS_VAR: &str = "TMPFS_RS_CLANG_ARGS";

/// Everything the build was configured with, as bindgen wants it.
///
/// `root` is the repository root, which every crate needs on the include path
/// because the headers include each other by `kernel/...` and `fs/...`.
pub fn clang_args(root: &Path) -> Vec<String> {
    println!("cargo:rerun-if-env-changed={CLANG_ARGS_VAR}");
    let mut args = vec![
        format!("-I{}", root.display()),
        "-DIUL_INTERNAL".into(),
        "-DGUEST_ARM64=1".into(),
    ];
    args.extend(from_env().split_whitespace().map(str::to_string));
    args
}

/// Declare `names` as `cfg`s and set the ones this build defines.
///
/// A name is set when the build passes `-DNAME` or `-DNAME=<anything but 0>`,
/// which is what `#if NAME` means in C. `-DNAME=0` is *not* set, because
/// `#if 0` is false — the C and the Rust have to agree about that or the two
/// halves of a channel disagree about whether it exists.
///
/// The `cfg` is the name lowercased with an `iul_` prefix: `DEBUG_strace`
/// becomes `iul_debug_strace`. The prefix is so that a `cfg` from this channel
/// is recognisable as one, and so it cannot collide with a cargo feature.
pub fn emit_cfgs(names: &[&str]) {
    let defines = defines(&from_env());
    for name in names {
        let cfg = cfg_name(name);
        // Rust 1.80+ warns on a `cfg` nothing declared, which is the check that
        // catches a typo in this list — without it a misspelled name is simply
        // never set and the code it guards silently never compiles.
        println!("cargo::rustc-check-cfg=cfg({cfg})");
        if is_set(&defines, name) {
            println!("cargo::rustc-cfg={cfg}");
        }
    }
}

/// Would `#if NAME` be true in this build?
///
/// For a build script that has to *decide* something from a flag rather than
/// only pass it on — `crates/util/logline` picks a default when the build
/// named no log handler, and says so.
pub fn is_defined(name: &str) -> bool {
    is_set(&defines(&from_env()), name)
}

/// The `cfg` name for a C macro name.
pub fn cfg_name(c_name: &str) -> String {
    format!("iul_{}", c_name.to_ascii_lowercase())
}

fn from_env() -> String {
    println!("cargo:rerun-if-env-changed={CLANG_ARGS_VAR}");
    std::env::var(CLANG_ARGS_VAR).unwrap_or_default()
}

/// Every `-D` in a clang argument string, as name → value.
///
/// A bare `-DNAME` has the value `"1"`, which is what the C preprocessor gives
/// it. A later definition wins, as it does on a command line.
fn defines(args: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut it = args.split_whitespace();
    while let Some(a) = it.next() {
        // `-DNAME=v`, `-DNAME`, or `-D NAME` — the last because a person
        // setting this variable by hand may well write the separated spelling,
        // which the C preprocessor accepts.
        let body = match a.strip_prefix("-D") {
            Some("") => match it.next() {
                Some(next) => next,
                None => break,
            },
            Some(rest) => rest,
            None => continue,
        };
        let (name, value) = match body.split_once('=') {
            Some((n, v)) => (n, v),
            None => (body, "1"),
        };
        out.insert(name.to_string(), value.to_string());
    }
    out
}

/// Would `#if NAME` be true?
fn is_set(defines: &BTreeMap<String, String>, name: &str) -> bool {
    defines.get(name).is_some_and(|v| v.trim() != "0")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(args: &str) -> BTreeMap<String, String> {
        defines(args)
    }

    #[test]
    fn a_bare_define_is_one_as_the_preprocessor_has_it() {
        let m = d("-DLOCK_DEBUG");
        assert_eq!(m.get("LOCK_DEBUG").map(String::as_str), Some("1"));
        assert!(is_set(&m, "LOCK_DEBUG"));
    }

    #[test]
    fn a_value_is_kept_and_zero_is_not_set() {
        let m = d("-DDEBUG_strace=1 -DDEBUG_sock=0");
        assert!(is_set(&m, "DEBUG_strace"));
        // `#if DEBUG_sock` is false, so the cfg must not be set. Treating any
        // definition as "on" would turn a channel the build switched *off*
        // back on in the Rust half only.
        assert!(!is_set(&m, "DEBUG_sock"), "-DNAME=0 means #if is false");
    }

    #[test]
    fn an_undefined_name_is_not_set() {
        assert!(!is_set(&d("-DOTHER=1"), "DEBUG_strace"));
    }

    #[test]
    fn a_separated_define_is_read() {
        // `-D NAME=v`, the separated spelling a person may well type.
        let m = d("-D LOG_HANDLER_OS_LOG=1 -isysroot /x");
        assert!(is_set(&m, "LOG_HANDLER_OS_LOG"));
    }

    #[test]
    fn a_later_definition_wins_as_on_a_command_line() {
        assert!(!is_set(&d("-DX=1 -DX=0"), "X"));
        assert!(is_set(&d("-DX=0 -DX=1"), "X"));
    }

    /// The arguments that are not `-D` must not be mistaken for one — a
    /// sysroot path containing `-D` would otherwise define something.
    #[test]
    fn only_dash_d_arguments_define_anything() {
        let m = d("-isysroot /Applications/Xcode.app/SDKs -O2 -Wall");
        assert!(m.is_empty(), "got {m:?}");
    }

    /// The root is where the headers are, and it is above this crate.
    /// `-I` is read the same two ways `-D` is, and a non-`-I` argument is not
    /// mistaken for one.
    #[test]
    fn include_dirs_reads_both_spellings() {
        // Exercised through the same parsing `include_dirs` uses, with the
        // environment left alone: the shape is what is being checked.
        fn dirs(args: &str) -> Vec<String> {
            let mut out = Vec::new();
            let mut it = args.split_whitespace();
            while let Some(a) = it.next() {
                match a.strip_prefix("-I") {
                    Some("") => {
                        if let Some(d) = it.next() {
                            out.push(d.to_string());
                        }
                    }
                    Some(rest) => out.push(rest.to_string()),
                    None => {}
                }
            }
            out
        }
        assert_eq!(dirs("-I/a -I /b -DX=1 -isysroot /c"), vec!["/a", "/b"]);
    }

    #[test]
    fn the_repo_root_is_the_directory_holding_the_marker() {
        let root = repo_root();
        assert!(root.join("iul.h").is_file());
        // Not the crate's own directory: this crate lives three levels down.
        assert!(root.join("crates/util/buildcfg/Cargo.toml").is_file());
    }

    #[test]
    fn the_cfg_name_is_the_c_name_lowercased_with_a_prefix() {
        assert_eq!(cfg_name("DEBUG_strace"), "iul_debug_strace");
        assert_eq!(cfg_name("LOG_HANDLER_OS_LOG"), "iul_log_handler_os_log");
    }
}
