#!/bin/bash
# Build the guest vDSO: rustc to an object, rust-lld to a shared library.
#
# usage: build.sh <out.elf>
#
# Not cargo, and not a `cdylib`: a cdylib brings in crt objects and a C library,
# and this object is mapped into a *guest* address space where neither belongs.
# rustc emits the object and `rust-lld` -- which ships inside the toolchain, so
# nothing has to be installed -- links it against vdso.lds. That is what
# `clang -target aarch64-linux-gnu -nostdlib -shared -Wl,-T` did until
# 2026-09-09, when it needed a cross-capable clang that most machines do not
# have and meson `touch`ed an empty file when it was missing.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=$1
target=aarch64-unknown-linux-musl

sysroot=$(rustc --print sysroot)
host=$(rustc -vV | awk '/^host:/{print $2}')
lld="$sysroot/lib/rustlib/$host/bin/rust-lld"
[ -x "$lld" ] || { echo "no rust-lld at $lld" >&2; exit 1; }

obj=$(mktemp -t vdso.XXXXXX).o
trap 'rm -f "$obj"' EXIT

# Each of the two steps says which one it was. They fail for unrelated reasons
# -- the compile wants the guest target installed, the link wants a working
# `rust-lld` -- and naming one cause for both is how a broken nightly toolchain
# read as a missing target for two builds running. See
# docs/changelog/2026-09-11-one-error-message-for-two-failures.md.
rustc --target "$target" --edition 2024 --crate-name vdso --crate-type lib \
    --emit=obj -O -C panic=abort -C relocation-model=pic \
    -o "$obj" "$here/src/lib.rs" \
    || { echo "vdso: rustc failed for $target." \
              "It needs that target: \`rustup target add $target\`" >&2; exit 1; }

# Renamed into place rather than written there: macOS caches a Mach-O's
# signature against its inode, and while this is an ELF the same rule keeps the
# build's outputs consistent. See
# docs/changelog/2026-09-03-copying-a-binary-over-itself-got-it-sigkilled.md.
#
# `DYLD_FALLBACK_LIBRARY_PATH` is what rustc sets when it runs a linker itself:
# rust-lld links `@rpath/libLLVM.dylib`, and on 1.98.1 its rpaths are
# `@loader_path/../lib` (which is `rustlib/<host>/lib`, where no libLLVM is) and
# the CI builder's own path. The dylib is in `$sysroot/lib`.
DYLD_FALLBACK_LIBRARY_PATH="$sysroot/lib${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}" \
"$lld" -flavor gnu -shared -T "$here/vdso.lds" --hash-style=sysv \
    -o "$out.tmp" "$obj" \
    || { echo "vdso: $lld failed. The toolchain's own linker, not this tree's;" \
              "a rustup toolchain missing libLLVM.dylib is the known case" >&2; exit 1; }
mv -f "$out.tmp" "$out"
