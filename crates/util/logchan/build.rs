//! The debug channels this build compiled in.
//!
//! `TMPFS_RS_CLANG_ARGS='-DDEBUG_strace=1 -DDEBUG_sock=1'` reaches here through
//! `crates/util/buildcfg`. It was `-Dlog='strace sock'` until 2026-09-11, which
//! meson expanded to the same pair; before 2026-09-06 it did not reach cargo at
//! all and a crate asked C at runtime instead.
fn main() {
    buildcfg::emit_cfgs(&["DEBUG_strace", "DEBUG_sock", "DEBUG_instr"]);
}
