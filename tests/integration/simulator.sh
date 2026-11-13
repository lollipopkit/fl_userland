#!/bin/sh
# Run the guest suite and the recorded probes with `iul` built for the iOS
# **simulator**, inside a simulator this script creates and deletes.
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
# The newest iOS runtime, and an iPhone *that runtime supports*: the newest
# device type is not always one, and `simctl create` answers "Incompatible
# device" for it.
pick=$(xcrun simctl list runtimes -j | python3 -c '
import json, sys
rs = [r for r in json.load(sys.stdin)["runtimes"]
      if r.get("platform") == "iOS" and r.get("isAvailable")]
if not rs:
    sys.exit(1)
r = rs[-1]
phones = [d["identifier"] for d in r.get("supportedDeviceTypes", [])
          if d.get("productFamily") == "iPhone"]
print(r["identifier"], phones[0] if phones else "")
') || { echo "simulator.sh: no iOS simulator runtime installed" >&2; exit 2; }
runtime=${pick% *}
model=${pick#* }
[ -n "$model" ] || { echo "simulator.sh: $runtime supports no iPhone" >&2; exit 2; }
udid=$(xcrun simctl create "shellbox-$$" "$model" "$runtime")
cleanup() {
    xcrun simctl shutdown "$udid" >/dev/null 2>&1 || true
    xcrun simctl delete "$udid" >/dev/null 2>&1 || true
    rm -rf "$scratch"
}
trap cleanup EXIT INT TERM HUP
xcrun simctl boot "$udid"

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

export IUL_NO_BUILD=1 IUL_SIMULATOR=1
rc=0
case "$what" in
    guest|all) tests/integration/guest_tests.sh -i "$scratch/iul" || rc=$? ;;
esac
case "$what" in
    probes|all) tests/integration/probe_diff.sh --recorded -i "$scratch/iul" || rc=$? ;;
esac
exit $rc
