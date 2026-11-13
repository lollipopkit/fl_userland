//! One `cfg`, and nothing else.
//!
//! `-DLOCK_DEBUG=1` adds a field to `lock_t`, so this crate has two layouts and
//! the flag has to reach it. `crates/util/buildcfg` is the one reader of the
//! `TMPFS_RS_CLANG_ARGS` channel; see `CLAUDE.md` on why there is exactly one.

fn main() {
    buildcfg::emit_cfgs(&["LOCK_DEBUG"]);
}
