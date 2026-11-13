#!/bin/sh
# `libfakefs_redirect.dylib`, the DYLD interpose library native offload injects
# into a spawned host process, so that a guest absolute path reaches the rootfs
# directory instead of the host's own filesystem.
#
# usage: build-redirect-dylib.sh [--release] [-o <dir>]
#
# macOS only, and by construction: `__DATA,__interpose` is a Mach-O section and
# DYLD_INSERT_LIBRARIES is dyld's.
#
# # -Wl,-force_load, and why it is not optional
#
# This is `link_whole` in the meson.build that held it until 2026-09-11, and the
# reason is the same one: **an interpose entry is a `static` in a section
# nothing references.** The linker's ordinary rule for an archive is to pull in
# only the objects that resolve an undefined symbol, so a plain `-l` drops every
# object holding one of these and the library interposes nothing at all --
# links clean, loads clean, does nothing. `-Wl,-force_load` is cc's spelling of
# link_whole.
#
# The failure it prevents has happened here before at one remove: **nothing
# built this library at all until 2026-09-01**, and `crates/kernel/offloadexec`
# warned and carried on with redirection off, so an offloaded ffmpeg asked to
# read `/tmp/in.mp4` read the *host's* `/tmp`. A library that loads and
# interposes nothing looks exactly the same from the outside.
#
# # Two staticlibs, and the rule about one
#
# CLAUDE.md says there is exactly one Rust `staticlib` in the product, because a
# Rust staticlib bundles the standard library and the release profile's LTO
# makes std's symbols strong globals -- so two in one link is a duplicate-symbol
# error. That rule is about `libiul.a`'s link. This library links nothing else
# of this tree; it runs inside somebody else's process, and its standard library
# meets no other.
set -eu
cd "$(dirname "$0")/.."

. tools/build-common.sh
parse_build_args "$@"
[ -n "$OUT" ] || OUT=build

if [ "$(uname -s)" != Darwin ]; then
    echo "build-redirect-dylib.sh: macOS only (Mach-O __interpose, dyld)" >&2
    exit 2
fi

cargo build -p fakefs-redirect $PROFILE_ARGS ${RUST_TARGET:+--target "$RUST_TARGET"}

archive="$(cargo_out_dir)/libfakefs_redirect.a"
[ -f "$archive" ] || { echo "cargo did not produce $archive" >&2; exit 1; }

mkdir -p "$OUT"
${CC:-cc} -dynamiclib \
    -Wl,-install_name,@rpath/libfakefs_redirect.dylib \
    -Wl,-force_load "$archive" \
    -o "$OUT/libfakefs_redirect.dylib.tmp"
mv -f "$OUT/libfakefs_redirect.dylib.tmp" "$OUT/libfakefs_redirect.dylib"

# That the interposes are actually in there, which is the property -force_load
# exists for and the one a successful link does not show. A dylib built with
# `link_with` instead reaches this line with no such section at all.
#
# The section's *size*, not a count of hexdump lines: an entry is a pair of
# pointers, so the count is the size over sixteen, and asking for the size means
# not caring which segment the linker put it in. It is `__DATA_CONST` on this
# toolchain and was `__DATA` on older ones.
size=$(otool -l "$OUT/libfakefs_redirect.dylib" |
    awk '/sectname __interpose/ { found = 1 } found && /^ *size / { print $2; exit }')
if [ -z "$size" ] || [ "$((size))" -eq 0 ]; then
    echo "no __interpose section in $OUT/libfakefs_redirect.dylib:" >&2
    echo "  it links, it loads, and it would interpose nothing -- which is what" >&2
    echo "  a plain link of this archive produces. See -Wl,-force_load above." >&2
    exit 1
fi
echo "$OUT/libfakefs_redirect.dylib ($(( size / 16 )) interposes)"
