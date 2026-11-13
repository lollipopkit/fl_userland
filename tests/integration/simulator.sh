#!/bin/sh
# Run the guest suite and the recorded probes with `iul` built for the iOS
# **simulator**, inside an existing iPhone simulator (see below).
#
# Usage: tests/integration/simulator.sh [guest|probes|all]    (default: all)
#
# Why: everything else here runs the macOS build, and the product is iOS. The
# two share a kernel but not every constant, and a `cfg(target_os = "macos")`
# branch means the other branch is what a phone runs. On 2026-09-29
# `lseek(SEEK_DATA)` asked an iPhone for SEEK_HOLE -- a `not(macos)` branch
# held Linux's numbers -- and no test could see it, because none ran the iOS
# build. On the simulator the probe showed it at once: `lseek(SEEK_DATA, 0) -> 4`
# before the fix, `-> 0` after, which is what the recorded kernel says.
#
# A simulator process is an arm64 macOS process with the iOS runtime and
# libSystem, which is the half that differs; it is not the device's sandbox or
# memory limits, so this is a check of the build and not of the phone.
#
# `simctl spawn` does not start in this directory and forwards only
# SIMCTL_CHILD_-prefixed variables, which is what the wrapper below undoes.
# `IUL_SIMULATOR` tells guest_tests.sh which of its checks cannot apply.
set -eu
cd "$(dirname "$0")/../.."
what=${1:-all}
root=$(pwd)
scratch=$(mktemp -d)
# An existing iPhone simulator, never a new one: a booted one if there is
# one, else an available one on the newest runtime, which is booted here and
# shut down again afterwards. `IUL_SIM_UDID` names one explicitly.
udid=${IUL_SIM_UDID:-$(xcrun simctl list devices available -j | python3 -c '
import json, sys
ds = json.load(sys.stdin)["devices"]
phones = [(rt, d) for rt, l in ds.items() if ".iOS-" in rt
          for d in l if d["name"].startswith("iPhone")]
booted = [d for _, d in phones if d["state"] == "Booted"]
key = lambda p: [int(x) for x in p[0].rsplit(".iOS-", 1)[1].split("-")]
pick = booted[0] if booted else (max(phones, key=key)[1] if phones else None)
print(pick["udid"] if pick else "")
')}
[ -n "$udid" ] || { echo "simulator.sh: no iPhone simulator exists; create one in Xcode" >&2; exit 2; }
booted_here=
if ! xcrun simctl list devices booted | grep -q "$udid"; then
    xcrun simctl boot "$udid"
    booted_here=1
fi
cleanup() {
    [ -z "$booted_here" ] || xcrun simctl shutdown "$udid" >/dev/null 2>&1 || true
    rm -rf "$scratch"
}
trap cleanup EXIT INT TERM HUP

rustup target add aarch64-apple-ios-sim >/dev/null 2>&1 || true
cargo build --release -p iul-cli --target aarch64-apple-ios-sim
bin="$root/target/aarch64-apple-ios-sim/release/iul"

cat > "$scratch/iul" <<WRAP
#!/bin/sh
for a in "\$@"; do
    case "\$a" in
        /*) ;;
        *) [ -e "\$a" ] && a="$root/\$a" ;;
    esac
    set -- "\$@" "\$a"
    shift
done
for v in \$(env | sed -n 's/^\(IUL_[A-Za-z0-9_]*\)=.*/\1/p'); do
    eval "export SIMCTL_CHILD_\$v=\"\\\$\$v\""
done
exec xcrun simctl spawn "$udid" "$bin" "\$@"
WRAP
chmod +x "$scratch/iul"
# guest_tests.sh indexes its fakefs with the `tools/fakefsify` beside the
# `iul` it is given; that is a host tool, so it is the macOS build.
tools/build-fakefsify.sh -o "$scratch/tools" --release >/dev/null

export IUL_NO_BUILD=1 IUL_SIMULATOR=1
rc=0
case "$what" in
    guest|all) tests/integration/guest_tests.sh -i "$scratch/iul" || rc=$? ;;
esac
case "$what" in
    probes|all) tests/integration/probe_diff.sh --recorded -i "$scratch/iul" || rc=$? ;;
esac
exit $rc
