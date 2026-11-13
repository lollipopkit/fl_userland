//! Generate `cpu-offsets.h` and assemble the six gadget files.
//!
//! The whole of what meson's `libish_emu` target did, in a build script, so
//! that `cargo build` alone produces a working `iul`. Since 2026-09-11 it is
//! the only thing that assembles them.

use std::path::PathBuf;

/// The gadget set. Named for the **host** they run on, not the guest they
/// implement: same-architecture dispatch is the point of this engine, and
/// `gadgets-aarch64` is the only set that exists.
const GADGETS: &[&str] = &["entry", "memory", "control", "math", "crypto", "features"];

fn main() {
    // The host, checked here rather than left to fail as an unrecognised
    // mnemonic three hundred lines into `entry.S`. meson said this in a comment
    // for a year -- "on any other host meson stops here with a missing file" --
    // over a variable nothing read, so it stopped being true the moment the
    // gadgets became cargo's and nothing noticed.
    let host = std::env::var("TARGET").unwrap_or_default();
    assert!(
        host.starts_with("aarch64") || host.starts_with("arm64"),
        "the gadgets are assembly and `gadgets-aarch64` is the only set that \
         exists: same-architecture dispatch is the point of this engine, so a \
         {host} build has nothing to run. This is a host check, not a guest \
         one -- the guest is always arm64."
    );

    let root = buildcfg::repo_root();
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let dir = root.join("asbestos/guest-arm64/gadgets-aarch64");

    // The offsets, from `cpuoffsets::text()` -- a function rather than a
    // nested `cargo run`, which is what lets cargo assemble the gadgets on its
    // own. `crates/tools/cpuoffsets`' binary prints the same string for reading
    // by hand.
    std::fs::write(out.join("cpu-offsets.h"), cpuoffsets::text()).expect("writing cpu-offsets.h");

    let mut build = cc::Build::new();
    build
        // `cc` emits its own `cargo:rustc-link-lib=static=iul_gadgets`, which
        // collides with the modified one below: two `-l` for one name with
        // different modifiers is "overriding linking modifiers from command
        // line is not supported". The directives are emitted by hand instead.
        .cargo_metadata(false)
        // `emu/interrupt.h` is named from the repo root; `gadgets.h` and
        // `../../gadgets-generic.h` are relative to each `.S` file's own
        // directory, which the assembler resolves itself.
        .include(&root)
        .include(&out)
        .include(&dir);
    for arg in buildcfg::clang_args(&root) {
        // `clang_args` is bindgen's list and carries `-I` entries as well as
        // the `-D`s; both are what the assembler wants, and an argument it
        // does not understand would fail the build rather than be ignored.
        build.flag(&arg);
    }
    for g in GADGETS {
        let f = dir.join(format!("{g}.S"));
        println!("cargo:rerun-if-changed={}", f.display());
        build.file(f);
    }
    println!("cargo:rerun-if-changed={}", dir.join("gadgets.h").display());
    println!(
        "cargo:rerun-if-changed={}",
        root.join("asbestos/guest-arm64/gadgets-generic.h")
            .display()
    );
    // `compile` rather than `try_compile` so a bad flag stops the build here
    // rather than at a link error four crates later.
    build.compile("iul_gadgets");

    // **`+whole-archive`, and it has to be a `link-lib` rather than a
    // `link-arg`.** Two separate reasons, and getting either wrong is a wall
    // of `Undefined symbols: _gadget_*` at the final link:
    //
    // - A gadget is reached through a table `crates/asbestos/gen` fills in by
    //   name. Most are referenced, so a plain `-l` would pull them in -- but
    //   the ones that are not would be dropped, and which those are changes
    //   with the decoder. Whole-archive makes that not a question.
    // - `cargo:rustc-link-arg` applies to the package whose build script
    //   emitted it and **does not propagate to dependents**;
    //   `cargo:rustc-link-lib` does. `cc`'s own `compile` emits the second,
    //   without the modifier, so it is re-emitted here.
    println!("cargo:rustc-link-search=native={}", out.display());
    // **`+bundle`**, so the gadget objects go *into* whatever rlib or staticlib
    // links this. It was `-bundle` until 2026-09-08, which leaves them in a
    // separate `libiul_gadgets.a` beside the output -- fine for a binary cargo
    // links itself, and useless for `libiul.a`, which is an archive somebody
    // else links. Bundling is what lets one archive be the whole engine.
    println!("cargo:rustc-link-lib=static:+whole-archive,+bundle=iul_gadgets");
}
