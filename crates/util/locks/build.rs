//! One line, and no bindgen since 2026-09-08.
//!
//! This crate generated `lock_t`, `wrlock_t` and `struct lock_debug` from
//! `util/sync.h` because both locks **grow under `-DLOCK_DEBUG=1`**, and a
//! hand-written mirror of a layout that moves is a contract neither compiler
//! checks. `crates/kernel/taskview` owns all three now, with the `#if` as a
//! `#[cfg(iul_lock_debug)]` field and the two sizes asserted — so there is one
//! definition rather than a generator per crate, and what is left here is
//! turning the flag into the `cfg` the code reads.

fn main() {
    buildcfg::emit_cfgs(&["LOCK_DEBUG", "LOCK_SLOW_TRACE"]);
}
