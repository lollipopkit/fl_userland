//! Whether this build compiled signposts in.
//!
//! `-DIUL_OS_SIGNPOST=1` reaches here through `TMPFS_RS_CLANG_ARGS` — see
//! `crates/util/buildcfg`. It is off in every build in the tree; what the flag
//! buys is a profile in Instruments, and what it costs is described in the
//! module comment.
fn main() {
    buildcfg::emit_cfgs(&["IUL_OS_SIGNPOST"]);
}
