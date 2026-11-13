#!/bin/sh
# Compare the instruction probes between two builds.
#
# Their output is a byte-for-byte constant, so the comparison is an md5. The
# pair that matters is a default build against `-DLOCK_DEBUG=1`, which grows
# `lock_t` and therefore `struct task`: it is the only build in this tree that
# exercises a second layout, which is what makes it the check to run after
# anything that changes a field of that struct. `cpu-offsets.h` is generated
# from `cpu_state` alone and `struct task` is `#[repr(Rust)]`, so a probe that
# moves means a field reordering reached the gadgets — which should be
# impossible and is worth knowing about immediately.
#
# Usage: tools/probe-both-layouts.sh [<rootfs>] [<iul-a>] [<iul-b>]
set -eu

ROOTFS="${1:-build/integration/alpine}"
A="${2:-./build/iul}"
B="${3:-./build-lockdebug/iul}"

# `xpage_probe` is in this list and was not in `CLAUDE.md`'s: the seven names
# there are the seven that existed when it was written. A probe missing from
# the rootfs is reported rather than skipped, because a silent skip is the
# "filter that makes an assertion vacuous" this tree keeps finding.
PROBES="simd_probe atomics_probe xpage_probe fp_probe sysreg_probe crypto_probe scalar_probe"

differ=0
ran=0
for p in $PROBES; do
    if [ ! -e "$ROOTFS/tmp/$p" ]; then
        echo "missing from the rootfs: $p" >&2
        differ=1
        continue
    fi
    a=$("$A" -r "$ROOTFS" "/tmp/$p" 2>/dev/null | md5)
    b=$(IUL_NO_BUILD=1 "$B" -r "$ROOTFS" "/tmp/$p" 2>/dev/null | md5)
    ran=$((ran + 1))
    if [ "$a" != "$b" ]; then
        echo "$p differs: $a vs $b" >&2
        differ=1
    fi
done

if [ "$ran" -eq 0 ]; then
    echo "no probe ran; this compared nothing" >&2
    exit 1
fi
echo "$ran probes, byte-identical under both layouts"
exit $differ
