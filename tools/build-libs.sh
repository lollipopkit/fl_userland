#!/bin/sh
# The static library a consumer links.
#
# usage: build-libs.sh <outdir> [--release] [--target <rust-target>] [--features <list>]
#
#   libiul.a        the whole engine: crates/iul's staticlib, which carries the
#                   gadgets, the vDSO image and the Rust standard library
#
# `libish_emu.a` and `libfakefs.a` were meson's split of the C (the CPU/TLB
# layer, and the fakefs schema `fakefsify` shared with the kernel). Both became
# Rust inside libiul.a and were eight-byte empty archives until 2026-09-30.
set -eu
cd "$(dirname "$0")/.."

case "${1:-}" in
    ''|-*) echo "usage: build-libs.sh <outdir> [--release] [--target <t>] [--features <f>]" >&2; exit 2 ;;
esac
OUT_ARG=$1
shift

. tools/build-common.sh
parse_build_args "$@"
OUT=$OUT_ARG

mkdir -p "$OUT"
# shellcheck disable=SC2046 # feature_args prints one argument per line on purpose
cargo build -p iul $PROFILE_ARGS \
    ${RUST_TARGET:+--target "$RUST_TARGET"} \
    $(feature_args)

install_output "$(cargo_out_dir)/libiul.a" "$OUT/libiul.a"

ls -l "$OUT/libiul.a"
