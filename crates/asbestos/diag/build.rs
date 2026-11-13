//! One line, and it is not bindgen.
//!
//! This crate generated `struct cpu_state` and `struct iul_env`. The first is
//! `crates/kernel/taskview`'s own Rust since 2026-09-08 and the second
//! `crates/util/iulenv`'s since 2026-09-04, so there is nothing left to read a
//! header for -- and a bindgen run costs about twelve seconds of every build
//! that touches this crate.
//!
//! What is left is the `cfg` for `-DIUL_GADGET_PROFILE`, which is a build flag
//! rather than a type.

fn main() {
    buildcfg::emit_cfgs(&["IUL_GADGET_PROFILE"]);
}
