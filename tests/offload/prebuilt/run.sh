#!/bin/bash
# Pre-built gadget offload test: verify that a host implementation registered at
# a guest function's address produces bit-identical results to normal threaded
# execution, and measure what it costs.
#
# The two sides are independent renderings of the same arithmetic --
# tests/offload/prebuilt/guest/ compiled by rustc for the guest, and
# crates/kernel/offloadtestprebuilt written by hand from its disassembly -- so
# agreement means something.
#
# Usage:  tests/offload/prebuilt/run.sh [iters]
# Requires: a built base iul, a build dir, and the aarch64-unknown-linux-musl
# target (`rustup target add aarch64-unknown-linux-musl`). It needed Docker and
# the network until 2026-09-09, to run `apk add gcc musl-dev` and build a forty-
# line program.
set -u
cd "$(dirname "$0")/../../.."          # repo root
ITERS="${1:-5000000}"
# Overridable, because the two names below are one machine's: `alpine-arm64` is
# not what `guest_tests.sh` unpacks and `build-arm64-release` is not what a
# working tree usually has. Both were hardcoded until 2026-09-08, so this script
# could not run here at all.
ROOTFS="${IUL_ROOTFS:-build/integration/alpine}"
HERE="tests/offload/prebuilt"
# A fresh directory per run, and not two fixed paths in /tmp. macOS caches a
# Mach-O's code signature against its **inode**, so `cp` onto a path whose older
# contents have been executed leaves a file the kernel SIGKILLs at execve --
# before main, with no output at all. That is what "result mismatch: base=
# prebuilt=" was: two empty strings compared unequal to nothing, on every run of
# this script after the first.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
BASE_IUL="$TMP/iul_base"; TEST_IUL="$TMP/iul_test"
PASS=0; FAIL=0
say() { printf '%s\n' "$*"; }
ok()  { PASS=$((PASS+1)); say "  PASS: $*"; }
bad() { FAIL=$((FAIL+1)); say "  FAIL: $*"; }

# 1. Cross-compile the two guest programs. Non-PIE and unstripped, which is
#    what lets `nm` answer the address the function will run at.
say "== building the guest programs =="
GUEST="$HERE/guest"
GTARGET=aarch64-unknown-linux-musl
( cd "$GUEST" && cargo build --release --target "$GTARGET" ) >/dev/null 2>&1 || {
    say "could not cross-compile the guest programs"
    say "  rustup target add $GTARGET"
    exit 2
}
GBIN="$GUEST/target/$GTARGET/release"
# The address is **told** to the fixture rather than compared against a literal.
# It was compared until 2026-09-08, and when the toolchain moved `mix` this
# reported the drift and then went on to "pass" the bit-identical check below --
# which is trivially true when the gadget never runs.
addr_of() { nm "$1" 2>/dev/null | awk -v f="$2" '$3==f && $2=="T" {print "0x"$1; exit}'; }
ADDR=$(addr_of "$GBIN/mixbench" mix)
[ -n "$ADDR" ] || { say "no mix symbol in the built binary"; exit 2; }
say "  mix @ $ADDR"
export IUL_MIXBENCH_MIX="$ADDR"
cp "$GBIN/mixbench" "$ROOTFS/root/mixbench"

# 2. Build the prebuilt-test iul and a base iul.
#
# Straight into the scratch directory, both of them. This was
# `meson configure -Doffload_test_prebuilt=true` and back again until
# 2026-09-11, which reconfigured the *shared* build directory three times and
# had to restore the default afterwards -- "so the tree is not left holding a
# binary with the handlers in it, which is how a later hand-run gets a hit it
# did not ask for". A cargo feature is an argument rather than a setting, so
# there is nothing left over to restore and a run that dies half way leaves
# nothing behind.
say "== building base + prebuilt-test iul =="
tools/build-cli.sh -o "$TMP/base" >/dev/null 2>&1 || { say "base build failed"; exit 2; }
mv "$TMP/base/iul" "$BASE_IUL"
tools/build-cli.sh -o "$TMP/test" --features offload-test-prebuilt >/dev/null 2>&1 || {
    say "prebuilt build failed"; exit 2; }
mv "$TMP/test/iul" "$TEST_IUL"

# 3. Correctness: prebuilt gadget hit + bit-identical acc.
say "== correctness =="
HIT=$(IUL_OFFLOAD_STATS=1 "$TEST_IUL" -r "$ROOTFS" /root/mixbench 100000 2>&1 | grep -c 'offload:prebuilt.*mix')
[ "$HIT" -ge 1 ] && ok "prebuilt gadget hit (mix)" || bad "prebuilt gadget did not hit"
ACC_BASE=$("$BASE_IUL" -r "$ROOTFS" /root/mixbench "$ITERS" 2>&1 | grep -oE 'acc=[0-9a-f]+')
ACC_TEST=$("$TEST_IUL" -r "$ROOTFS" /root/mixbench "$ITERS" 2>&1 | grep -oE 'acc=[0-9a-f]+')
[ -n "$ACC_BASE" ] && [ "$ACC_BASE" = "$ACC_TEST" ] \
    && ok "bit-identical result ($ACC_TEST)" \
    || bad "result mismatch: base=$ACC_BASE prebuilt=$ACC_TEST"

# 4. Performance: prebuilt should be faster.
say "== performance =="
ms() { local t0 t1; t0=$(python3 -c 'import time;print(int(time.time()*1000))')
       "$1" -r "$ROOTFS" /root/mixbench "$ITERS" >/dev/null 2>&1
       t1=$(python3 -c 'import time;print(int(time.time()*1000))'); echo $((t1-t0)); }
B=$(ms "$BASE_IUL"); T=$(ms "$TEST_IUL")
say "  threaded=${B}ms  prebuilt=${T}ms"
[ "$T" -lt "$B" ] && ok "prebuilt faster ($(python3 -c "print(f'{$B/$T:.2f}x')"))" \
                  || bad "prebuilt not faster (threaded=$B prebuilt=$T)"

# 5. Mixed execution: outer's spec_fn calls inner via prebuilt_call (nested
#    dispatch). Correctness only — this path exercises the bl/blr boundary.
say "== mixed execution (callbench: spec_outer bl inner) =="
cp "$GBIN/callbench" "$ROOTFS/root/callbench"
CB_OUTER=$(addr_of "$GBIN/callbench" outer)
CB_INNER=$(addr_of "$GBIN/callbench" inner)
say "  outer @ $CB_OUTER  inner @ $CB_INNER"
export IUL_CALLBENCH_OUTER="$CB_OUTER" IUL_CALLBENCH_INNER="$CB_INNER"
# It completes, and it is 1.9x **slower** than threaded execution -- which is
# the finding, not a failure. Registering the callee as well is what keeps it to
# 1.9x: with `inner` unregistered the `bl` goes through `prebuilt_call`, which
# re-enters the dispatch loop per guest call, and the same run takes 5.3x.
#
# Measured 2026-09-09, 500,000 iterations of `outer(i, 16)`, all four
# bit-identical at acc=950dab97ebb30a60:
#
#   threaded                      104 ms
#   inner only (a leaf)           129 ms   1.24x
#   outer + inner                 196 ms   1.9x
#   outer only, bl -> dispatch    553 ms   5.3x
#
# `mix` wins 2.66x on the same machine because it is a leaf with no frame.
# `outer` has one, and a spec_fn reaches guest memory through the TLB, so its
# prologue and epilogue are eight `tlb_read`/`tlb_write` calls per entry against
# sixteen iterations of a multiply and an add.
#
# The check below is correctness only for that reason. It ran for the first time
# on 2026-09-08 (until then the handlers were not linked into `iul` at all) and
# said "does not complete", which was true of a fixture built at `opt-level = 0`
# -- see the root Cargo.toml.
#
# A hundredth of $ITERS for that reason: the case used 500,000 when nothing was
# linked and it returned instantly.
CB_ITERS=$((ITERS / 100)); [ "$CB_ITERS" -lt 100 ] && CB_ITERS=100
CB_HIT=$(IUL_OFFLOAD_STATS=1 "$TEST_IUL" -r "$ROOTFS" /root/callbench "$CB_ITERS" 2>&1 | grep -c 'offload:prebuilt.*outer')
[ "$CB_HIT" -ge 1 ] && ok "prebuilt hit (outer, mixed execution)" || bad "outer did not hit"
CB_BASE=$("$BASE_IUL" -r "$ROOTFS" /root/callbench "$CB_ITERS" 2>&1 | grep -oE 'acc=[0-9a-f]+')
CB_TEST=$("$TEST_IUL" -r "$ROOTFS" /root/callbench "$CB_ITERS" 2>&1 | grep -oE 'acc=[0-9a-f]+')
[ -n "$CB_BASE" ] && [ "$CB_BASE" = "$CB_TEST" ] \
    && ok "mixed-execution bit-identical ($CB_TEST)" \
    || bad "mixed-execution mismatch: base=$CB_BASE prebuilt=$CB_TEST"

say ""
say "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
