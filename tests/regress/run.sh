#!/bin/bash
# Run the `cp` regressions inside iul, against a fakefs mount point.
#
# **The compiled half of this lives in `tests/guest` since 2026-09-09**:
# `regress_syscall` and `asimd_fcvt`, which `tests/integration/guest_tests.sh`
# builds and runs and `differential.sh` compares against a real kernel. They
# were C here, cross-compiled with `aarch64-linux-musl-gcc` -- and when that was
# absent, which is the usual case, this script *skipped* them and exited 0.
#
# What is left is the part a compiled binary cannot do: staging a shell script
# into a fakefs through the guest itself, so `meta.db` has a row for it, and
# running `cp` against a bind-mounted path the host provides.
#
# Usage:
#   tests/regress/run.sh [-i <iul binary>] [-r <rootfs>] [-f <fakefs path>]
#
#   -i  iul binary to test. Default: the first of build-arm64-release/iul,
#       build/iul that exists.
#   -r  rootfs to run against, passed to iul as -r. Default alpine-arm64-321.
#   -m  how to mount the rootfs: -r (default) or -f. Takes the flag itself as
#       its argument, so it is written `-m -f`.
#   -f  a file under a fakefs mount point (e.g. /var/minis/shared/doc.txt) to
#       check `cp` against. Only meaningful when the rootfs is mounted with -f
#       and a path-translate hook is installed, so it is optional.
#

set -u
cd "$(dirname "$0")/../.."

IUL=""
ROOTFS="alpine-arm64-321"
FAKEFS_PATH=""
MOUNT_FLAG="-r"

while getopts "i:r:f:m:h" opt; do
    case $opt in
        i) IUL="$OPTARG" ;;
        r) ROOTFS="$OPTARG" ;;
        f) FAKEFS_PATH="$OPTARG" ;;
        m) MOUNT_FLAG="$OPTARG" ;;
        h) sed -n '2,28p' "$0"; exit 0 ;;
        *) exit 2 ;;
    esac
done

if [ -z "$IUL" ]; then
    for cand in build-arm64-release/iul build/iul; do
        if [ -x "$cand" ]; then IUL="$cand"; break; fi
    done
fi
if [ -z "$IUL" ] || [ ! -x "$IUL" ]; then
    echo "no iul binary found; build one or pass -i <path>" >&2
    exit 2
fi
if [ ! -d "$ROOTFS" ]; then
    echo "rootfs $ROOTFS not found; pass -r <path>" >&2
    exit 2
fi

# With -f the guest's / lives under <rootfs>/data; with -r it is <rootfs> itself.
GUEST_ROOT="$ROOTFS"
if [ "$MOUNT_FLAG" = "-f" ]; then
    GUEST_ROOT="$ROOTFS/data"
fi
# Everything this run stages goes in a directory of its own, named for the pid.
# Fixed names under the rootfs's /tmp were overwritten on the way in and deleted
# on the way out, so a rootfs that happened to hold a file called
# regress_syscall lost it to a test run.
GUEST_ART="/tmp/iul-regress-$$"
HOST_ART="$GUEST_ROOT$GUEST_ART"
mkdir -p "$HOST_ART"
trap 'rm -rf "$HOST_ART"' EXIT

cp tests/regress/regress_cp.sh "$HOST_ART/regress_cp.sh"

# A fakefs keeps its own metadata in meta.db, so files dropped straight into
# data/ are invisible to the guest. Register the script by copying it through
# the guest itself.
if [ "$MOUNT_FLAG" = "-f" ]; then
    b64_sh=$(base64 < tests/regress/regress_cp.sh | tr -d '\n')
    rm -f "$HOST_ART/regress_cp.sh"
    if ! "$IUL" "$MOUNT_FLAG" "$ROOTFS" /bin/sh -c \
        "mkdir -p $GUEST_ART && printf %s '$b64_sh' | base64 -d > $GUEST_ART/regress_cp.sh"; then
        echo "failed to stage regress_cp.sh into the fakefs" >&2
        exit 1
    fi
fi

status=0

echo
echo "########## cp regressions ##########"
"$IUL" "$MOUNT_FLAG" "$ROOTFS" /bin/sh "$GUEST_ART/regress_cp.sh" ${FAKEFS_PATH:+"$FAKEFS_PATH"} || status=1

echo
if [ "$status" != "0" ]; then
    echo "regress: FAILURES (see above)"
    exit "$status"
fi
echo "regress: the cp cases passed"
exit 0
