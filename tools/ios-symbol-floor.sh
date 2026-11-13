#!/usr/bin/env bash
# Every host symbol an iOS `libiul.a` references exists on the oldest iOS it
# claims to support.
#
#   tools/ios-symbol-floor.sh build-ios/libiul.a
#
# A strong reference to a function newer than IPHONEOS_DEPLOYMENT_TARGET is not
# an error anywhere in the build: the SDK declares it, rustc links it, and
# every test passes on a Mac and on a current simulator. It is an error on the
# phone, where dyld refuses to launch the app at all. `mkfifoat` was one from
# 2026-08-29 to 2026-09-29 (`ios(16.0)` against a floor of 13.0).
#
# The judge is clang, not a parse of the headers: each referenced symbol is
# compiled as `&name` against the SDK with the deployment floor and
# `-Werror=unguarded-availability-new`, which is the compiler's own reading of
# the `__API_AVAILABLE` on the declaration. A symbol no included header
# declares is reported as unchecked rather than passed, and the run asserts
# that it checked something.
set -euo pipefail

lib=${1:?usage: $0 <libiul.a for aarch64-apple-ios>}
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=build-common.sh
. "$here/build-common.sh"
RUST_TARGET=aarch64-apple-ios apple_deployment_target
floor=$IPHONEOS_DEPLOYMENT_TARGET

# rustup's, because it is rustc's own LLVM: Apple's nm cannot read the bitcode
# rustc writes into the archive -- it says so per member and answers nothing
# for it -- and an older LLVM's cannot either.
nm="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-nm"
[ -x "$nm" ] || { echo "ios-symbol-floor: needs rustup component add llvm-tools" >&2; exit 2; }

sdk=$(xcrun --sdk iphoneos --show-sdk-path)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$nm" -u "$lib" 2>/dev/null | awk '$1=="U"{print $2} NF==1 && $1 !~ /:$/ {print $1}' | sort -u > "$work/undef"
"$nm" -g --defined-only "$lib" 2>/dev/null | awk 'NF>=3{print $3}' | sort -u > "$work/def"
# `realpath$DARWIN_EXTSN` is `realpath`: the suffix picks a variant of one
# declaration, and the declaration is what carries the availability.
comm -23 "$work/undef" "$work/def" | sed -n 's/^_//p' | grep -v -e '^_' -e '^RNv' \
    | sed 's/\$.*//' | sort -u > "$work/ext" || true

cat > "$work/all.h" <<'EOF'
#include <CommonCrypto/CommonRandom.h>
#include <copyfile.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <malloc/malloc.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <net/if.h>
#include <netdb.h>
#include <os/log.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <syslog.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <util.h>
EOF

cc=(xcrun --sdk iphoneos clang -target "arm64-apple-ios$floor" -isysroot "$sdk"
    -fsyntax-only -Werror=unguarded-availability-new -Werror=unguarded-availability)

checked=0 unchecked=() newer=()
while read -r name; do
    printf '#include "%s"\nvoid *ref_%s = (void *)&%s;\n' "$work/all.h" "$name" "$name" > "$work/t.c"
    if out=$("${cc[@]}" "$work/t.c" 2>&1); then
        checked=$((checked + 1))
    elif grep -q 'only available on' <<<"$out"; then
        checked=$((checked + 1))
        newer+=("$name: $(grep -o "'$name' is only available on [^;]*" <<<"$out" | head -1)")
    else
        unchecked+=("$name")
    fi
done < "$work/ext"

echo "ios-symbol-floor: $checked host symbols checked against iOS $floor, ${#unchecked[@]} not declared by any included header"
[ "$checked" -gt 0 ] || { echo "ios-symbol-floor: checked nothing" >&2; exit 2; }
if [ ${#unchecked[@]} -gt 0 ]; then
    printf '  unchecked: %s\n' "${unchecked[@]}"
fi
if [ ${#newer[@]} -gt 0 ]; then
    echo "ios-symbol-floor: newer than the deployment target, so the app does not launch below it:" >&2
    printf '  %s\n' "${newer[@]}" >&2
    exit 1
fi
