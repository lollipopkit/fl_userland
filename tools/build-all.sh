#!/bin/sh
# Everything a test or a developer runs, into one directory. `ninja -C build`
# until 2026-09-11.
#
# usage: build-all.sh [<outdir>] [--release] [--features <list>]
#
# Default outdir is `build`, which is the path CLAUDE.md, the integration
# scripts and every habit in this repository already name.
#
#   build/iul                        the host CLI
#   build/libiul.a                   the whole engine, what an embedder links
#   build/sbm_api_test               the embedder example, and the one C link
#   build/libfakefs_redirect.dylib   the interpose library (macOS)
#   build/tools/fakefsify            rootfs tarball <-> fakefs
#   build/tools/unfakefsify          the same binary under the other name
#
# and `build/iul-build.env`, which records how it was built so that
# `tests/integration/guest_tests.sh` and friends can rebuild before they run.
# They keyed on `build.ninja` being present until 2026-09-11; the reason for
# rebuilding is the same and is worth restating, because the failure it fixes
# happened three times in three scripts: **a run that answers about a different
# build from the one you changed**. A five-day-old binary in
# `build-arm64-release/` passed a deliberately broken smoke test.
#
# It records the **environment** as well as the flags, and that is not padding.
# A directory built with `TMPFS_RS_CLANG_ARGS=-DLOCK_DEBUG=1` holds an emulator
# with a different `struct task` layout; rebuilding it from the flags alone
# would quietly produce an ordinary one, so `guest_tests.sh -i
# build-lockdebug/iul` would report on the layout it was meant to be checking
# the *other* of. `meson configure` kept its own options, which is the property
# being replaced here rather than dropped.
#
# # Build flags
#
# There are no options here. What meson spelled `-Dc_args=-DLOCK_DEBUG=1` is an
# environment variable now, and it is the same one the crates have read since
# 2026-09-06:
#
#   TMPFS_RS_CLANG_ARGS='-DLOCK_DEBUG=1' CARGO_TARGET_DIR=target-lockdebug \
#       tools/build-all.sh build-lockdebug --release
#
# One name and one reader, which is the property CLAUDE.md says has been lost
# three times -- each time by *widening* the channel rather than auditing it.
# Nothing in this repository constructs that variable any more; a person sets
# it, `crates/util/buildcfg` reads it, and there is no third party to disagree.
#
# Give a build with different flags its own `CARGO_TARGET_DIR`, or cargo
# invalidates every build script each time you switch and recompiles the tree.
# Profiles do not need one: cargo separates debug from release by itself.
set -eu
cd "$(dirname "$0")/.."

# The output directory is the first argument if it is not a flag, so that
# `--features <list>`'s value is never mistaken for one. Everything after goes
# to the four scripts below unread.
OUT=build
case "${1:-}" in
    ''|-*) ;;
    *) OUT=$1; shift ;;
esac
mkdir -p "$OUT"
ARGS="$*"

say() { printf '\n==> %s\n' "$*"; }

say "libiul.a"
tools/build-libs.sh "$OUT" "$@"

say "iul"
tools/build-cli.sh -o "$OUT" "$@"

say "sbm_api_test"
tools/build-embedder-example.sh -o "$OUT" --libs "$OUT" "$@"

if [ "$(uname -s)" = Darwin ]; then
    say "libfakefs_redirect.dylib"
    tools/build-redirect-dylib.sh -o "$OUT" "$@"
fi

# fakefsify is a host tool -- it turns a rootfs tarball into a fakefs on the
# machine that builds one -- so a cross build skips it. (It linked the host's
# libarchive until 2026-10-17, which was the first reason.)
case " $* " in
    *" --target "*) say "skipping fakefsify: it is a host tool" ;;
    *) say "fakefsify"; tools/build-fakefsify.sh -o "$OUT/tools" "$@" ;;
esac

# How to reproduce this directory: the flags and the two environment variables
# that change what is in it. Sourced by the integration scripts before they
# rebuild; see the header for why the environment is half of it.
#
# Only what is actually set: an exported `CARGO_TARGET_DIR=''` is not the same
# as an unset one -- cargo takes the empty string literally and writes beside
# the manifest.
{
    printf "IUL_BUILD_ARGS='%s'\n" "$ARGS"
    [ -n "${TMPFS_RS_CLANG_ARGS:-}" ] &&
        printf "export TMPFS_RS_CLANG_ARGS='%s'\n" "$TMPFS_RS_CLANG_ARGS"
    [ -n "${CARGO_TARGET_DIR:-}" ] &&
        printf "export CARGO_TARGET_DIR='%s'\n" "$CARGO_TARGET_DIR"
    :
} > "$OUT/iul-build.env"

say "done: $OUT"
[ -n "${TMPFS_RS_CLANG_ARGS:-}" ] && echo "built with TMPFS_RS_CLANG_ARGS='$TMPFS_RS_CLANG_ARGS'"
ls -1 "$OUT"
