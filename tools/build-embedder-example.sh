#!/bin/sh
# `tests/integration/sbm_api_test.c`, compiled from C and linked against the
# three archives -- which is the whole of what it is for.
#
# usage: build-embedder-example.sh [--release] [--features <list>] [-o <dir>]
#                                  [--libs <dir>] [--run <rootfs>]
#
#   -o <dir>       where to put sbm_api_test. Default: build
#   --libs <dir>   where the archives already are. Default: build them into -o
#   --run <rootfs> run it against a rootfs directory afterwards
#
# # Why this is a gate and not an example
#
# This is the **only** thing in the tree that compiles `iul.h` with a C
# compiler and links the result. Nothing under `crates/` can fail when the C
# ABI surface breaks, and on 2026-09-11 that was not hypothetical: `iul.h`
# declared `extern void (*exit_hook)(...)` for a commit after the Rust that
# defined it became a `OnceLock` behind `set_exit_hook`, so the header named a
# symbol nothing defined -- and `cargo build`, `cargo test` and
# `cargo clippy --workspace` were all green while this failed to link.
#
# `tools/header-symbols.py` asks the same question from source and is in
# `tools/checks.sh`; this is the one that asks the linker.
#
# It was `executable('sbm_api_test', ...)` in meson.build until 2026-09-11, the
# one `executable()` in that file and the one C file it compiled.
set -eu
cd "$(dirname "$0")/.."

LIBS=""
ROOTFS=""
ARGS=""
while [ $# -gt 0 ]; do
    case $1 in
        --libs) LIBS="$2"; shift 2 ;;
        --run)  ROOTFS="$2"; shift 2 ;;
        *) ARGS="$ARGS $1"; shift ;;
    esac
done

. tools/build-common.sh
# shellcheck disable=SC2086 # ARGS is a deliberately word-split accumulator
parse_build_args $ARGS
[ -n "$OUT" ] || OUT=build

if [ -z "$LIBS" ]; then
    LIBS=$OUT
    tools/build-libs.sh "$OUT" \
        ${PROFILE_ARGS:+$PROFILE_ARGS} \
        ${RUST_TARGET:+--target "$RUST_TARGET"} \
        ${FEATURES:+--features "$FEATURES"} >/dev/null
fi
[ -f "$LIBS/libiul.a" ] || { echo "no $LIBS/libiul.a; run tools/build-libs.sh first" >&2; exit 1; }

mkdir -p "$OUT"

# The flags meson gave it, which are what an embedder's build gives it.
#
# `-DGUEST_ARM64=1` decides `addr_t` and `time_t_` where the headers still read
# it; ServerBox sets the same in ios/Flutter/Ish.xcconfig, so compiling without
# it here would be testing a configuration nobody ships. `-DLOG_HANDLER_DPRINTF`
# is the default `crates/util/logline` compiles with -- see that crate's
# build.rs for why a fallback that differs from the default it stands in for is
# not a fallback, and what it cost.
#
# `-Wall -Wextra` and not `-Werror`: warning_level=2 was meson's setting, and
# this file is an example an embedder reads as much as a link check.
${CC:-cc} -std=gnu11 -Wall -Wextra -Wno-switch \
    -Wimplicit-fallthrough -Wtautological-constant-in-range-compare \
    -DGUEST_ARM64=1 -DLOG_HANDLER_DPRINTF=1 \
    -I. \
    -o "$OUT/sbm_api_test.tmp" \
    tests/integration/sbm_api_test.c \
    "$LIBS/libiul.a" \
    -lm -ldl -lsqlite3
# Renamed into place; see install_output in tools/build-common.sh for why a
# `cp` over a binary that has been run gets the next one SIGKILLed.
mv -f "$OUT/sbm_api_test.tmp" "$OUT/sbm_api_test"
echo "$OUT/sbm_api_test"

# It links, which is the gate. That it *starts* is one more line and catches a
# missing constructor or a bad relocation, which a link does not.
if ! "$OUT/sbm_api_test" 2>&1 | grep -q '^usage:'; then
    echo "sbm_api_test did not print its usage; it links but does not run" >&2
    exit 1
fi

if [ -n "$ROOTFS" ]; then
    "$OUT/sbm_api_test" "$ROOTFS"
fi
