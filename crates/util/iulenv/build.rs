//! Nothing to generate.
//!
//! This ran bindgen over `util/ish_env.h` for `struct iul_env`, which is
//! `src/env_struct.rs` since 2026-09-08 -- and which `crates/asbestos/diag`
//! generated a second copy of. The module comment there says why the
//! generation was worth having and why it stopped being.
//!
//! The file stays because cargo re-runs a build script when its inputs change,
//! and this crate has none: without it, `cargo` would have nothing to hang the
//! `rerun-if-changed` on if one is ever needed again.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
