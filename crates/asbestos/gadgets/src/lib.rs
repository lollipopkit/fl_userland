//! The threaded-code gadgets: six `.S` files, assembled by cargo.
//!
//! # Why this crate is empty
//!
//! It has no Rust in it at all. What it has is a `build.rs` that generates
//! `cpu-offsets.h` and assembles
//! `asbestos/guest-arm64/gadgets-aarch64/*.S` into an archive cargo links.
//! Depending on it is how a binary gets `fiber_enter` and the four hundred
//! `gadget_*` symbols.
//!
//! # What it replaces
//!
//! meson's `libish_emu` target, and with it the last thing `cargo build` could
//! not do. Before 2026-09-08 `cargo build -p iul-cli` failed at the link with
//! `Undefined symbols: _fiber_enter, _gadget_abs_scalar, ...` — every Rust
//! crate compiled, and the product could still only be built one way.
//!
//! This is the only thing that assembles them since 2026-09-11. The gadgets
//! are bundled into `libiul.a`, so an embedder links one archive that is the
//! whole engine.
//!
//! # The link is not automatic
//!
//! A gadget is reached from a *table* built by name in `crates/asbestos/gen`,
//! not from a call the linker can see, so `-dead_strip` would drop most of
//! them if they were merely available. `build.rs` emits
//! `cargo:rustc-link-arg` for the whole archive rather than letting cargo add
//! it as an ordinary `-l`.
