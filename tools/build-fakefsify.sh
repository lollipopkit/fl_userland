#!/bin/sh
# `crates/tools/fakefsify`: rootfs tarball -> fakefs directory, and back.
#
# usage: build-fakefsify.sh [--release] [-o <dir>] [--sanitize <list>]
#
# One binary under two names; it reads argv[0] to decide which way to convert,
# so `unfakefsify` is a symlink beside it.
#
# `--sanitize` was meson's `-Db_sanitize` until 2026-09-11 and is spelled out
# here now. It is not decoration: **rustc drives this crate's final link**, and
# it is the only Rust target in the tree that has one -- the others are
# staticlibs something else links -- so it has to be told by hand.
set -eu
cd "$(dirname "$0")/.."

SANITIZE=""
ARGS=""
while [ $# -gt 0 ]; do
    case $1 in
        --sanitize) SANITIZE="$2"; shift 2 ;;
        *) ARGS="$ARGS $1"; shift ;;
    esac
done

. tools/build-common.sh
# shellcheck disable=SC2086 # ARGS is a deliberately word-split accumulator
parse_build_args $ARGS
[ -n "$OUT" ] || OUT=build/tools

# -fsanitize= alone is not enough: rustc passes -nodefaultlibs, which is exactly
# what stops the clang driver from adding the sanitizer runtime the flag would
# otherwise pull in. The runtime has to be named outright, so ask the compiler
# where it keeps it. A sanitizer whose runtime cannot be found is passed as the
# bare flag and left to fail with the linker's own message rather than a
# guessed path.
rustflags=''
if [ -n "$SANITIZE" ]; then
    for san in $(echo "$SANITIZE" | tr ',' ' '); do
        rustflags="$rustflags -C link-arg=-fsanitize=$san"
        # meson named the sanitizer, clang names the runtime, and the two do
        # not agree: -fsanitize=address wants libclang_rt.asan_*.
        case "$san" in
            address)   rt_short=asan  ;;
            thread)    rt_short=tsan  ;;
            undefined) rt_short=ubsan ;;
            memory)    rt_short=msan  ;;
            *)         rt_short=""    ;;
        esac
        [ -n "$rt_short" ] || continue
        rt_name="libclang_rt.${rt_short}_osx_dynamic.dylib"
        rt=$("${CC:-cc}" -print-file-name="$rt_name" 2>/dev/null || true)
        if [ -n "$rt" ] && [ "$rt" != "$rt_name" ] && [ -f "$rt" ]; then
            # The runtime is a dylib recorded by its install name, so the
            # directory holding it has to be on the runtime search path as
            # well -- naming it at link time only gets as far as a dyld
            # "Library not loaded: @rpath/libclang_rt.asan_osx_dynamic.dylib".
            rustflags="$rustflags -C link-arg=$rt"
            rustflags="$rustflags -C link-arg=-Wl,-rpath,$(dirname "$rt")"
        fi
    done
fi

# `cargo rustc -- <args>` rather than RUSTFLAGS, because RUSTFLAGS reaches the
# dependencies and the build scripts too -- and a build script linked against
# the ASan runtime aborts the moment cargo runs it, which is how libsqlite3-sys
# and libc failed with SIGABRT before this was narrowed. `cargo rustc` passes
# its trailing arguments to the final crate's rustc alone, which is the only
# one that links.
#
# libarchive's directory is not passed: build.rs probes the two Homebrew
# prefixes itself -- it is keg-only, so it is on neither the default search path
# nor pkg-config's -- and needs no help when it is on the default search path.
# `tools/meson.build` probed the same two and is gone.
# shellcheck disable=SC2086 # rustflags is a deliberately word-split accumulator
cargo rustc -p fakefsify --bin fakefsify $PROFILE_ARGS \
    ${RUST_TARGET:+--target "$RUST_TARGET"} -- $rustflags

install_output "$(cargo_out_dir)/fakefsify" "$OUT/fakefsify"
ln -sf fakefsify "$OUT/unfakefsify"
echo "$OUT/fakefsify"
