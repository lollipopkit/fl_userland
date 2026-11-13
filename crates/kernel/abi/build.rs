//! One `cfg`, and nothing else.
//!
//! `-DLOCK_DEBUG=1` adds a field to `lock_t`, so `crates/util/synctypes` has
//! two layouts and this crate re-exports the extra type behind the same `cfg`.
//! The flag has to reach both.
//!
//! The shared-type check that used to be here is `crates/kernel/taskview`'s
//! since 2026-09-09, with `struct task`: it is about what a consumer gets from
//! `taskview::ffi`, and that is the crate which assembles it.

fn main() {
    buildcfg::emit_cfgs(&["LOCK_DEBUG"]);
}
