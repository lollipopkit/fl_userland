#!/bin/sh
# The host CLI, `crates/tools/iul`.
#
# usage: build-cli.sh [--release] [--features <list>] [-o <dir>]
#
# It is the one Rust target here that **links**: everything else is a staticlib
# or an rlib. It does not link `libiul.a` -- it has
# the Rust half as an rlib through `iul`, and linking `libiul.a` beside
# that would put two standard libraries in one image.
#
# `tools/build-ish-cli.sh` until 2026-09-11, where it took seven positional
# arguments from meson and set `IUL_CLI_BUILD_DIR` so that
# `crates/tools/iul/build.rs` could put meson's build directory on the link
# search path and name meson's `libish_emu.a` and `libfakefs.a` there. Both
# were empty by then, so what that bought was `-lsqlite3`, which
# `libsqlite3-sys` emits anyway. The variable is gone and so is the build
# script that read it -- one fewer build-time channel, which is the thing
# CLAUDE.md says has silently broken three times.
set -eu
cd "$(dirname "$0")/.."

. tools/build-common.sh
parse_build_args "$@"
[ -n "$OUT" ] || OUT=build

# shellcheck disable=SC2046 # feature_args prints one argument per line on purpose
cargo build -p iul-cli --bin iul $PROFILE_ARGS \
    ${RUST_TARGET:+--target "$RUST_TARGET"} \
    $(feature_args)

install_output "$(cargo_out_dir)/iul" "$OUT/iul"
echo "$OUT/iul"
