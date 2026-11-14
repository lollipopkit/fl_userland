#!/usr/bin/env bash
# Build libiul.a for aarch64-apple-ios and run the embedder end-to-end test
# suite (sbm_api_test) on a connected physical iOS device via XCTest.
#
# Usage: tests/integration/device.sh [--udid <device-udid>] [--team <team-id>] [--ubuntu] [--no-build]
set -euo pipefail
cd "$(dirname "$0")/../.."

UDID="${IUL_DEVICE_UDID:-}"
TEAM="${DEVELOPMENT_TEAM:-}"
NO_BUILD=0
UBUNTU=0
while [ $# -gt 0 ]; do
    case "$1" in
        --udid) UDID="$2"; shift 2 ;;
        --team) TEAM="$2"; shift 2 ;;
        --ubuntu) UBUNTU=1; shift ;;
        --no-build) NO_BUILD=1; shift ;;
        -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
        *) echo "device.sh: unknown option $1" >&2; exit 2 ;;
    esac
done

if [ -z "$UDID" ]; then
    UDID=$(xcrun devicectl list devices 2>/dev/null | awk '/physical/ && /available/ { for (i=1;i<=NF;i++) if ($i ~ /^[0-9A-F]{8}-[0-9A-F]{16}$/) { print $i; exit } }')
fi
[ -n "$UDID" ] || { echo "device.sh: no paired physical iOS device found (pass --udid <udid>)" >&2; exit 2; }
echo "device: $UDID"

if [ "$NO_BUILD" = 0 ]; then
    tools/build-libs.sh build-ios --release --target aarch64-apple-ios
    tools/ios-symbol-floor.sh build-ios/libiul.a
fi
[ -f build-ios/libiul.a ] || { echo "device.sh: missing build-ios/libiul.a" >&2; exit 2; }

if [ "$UBUNTU" = 1 ]; then
    tests/integration/rootfs.sh ubuntu >/dev/null
    TARBALL=$(ls -t build/integration/ubuntu-base-*.tar.gz 2>/dev/null | head -n 1)
    [ -f "$TARBALL" ] || { echo "device.sh: ubuntu-base tarball not found in build/integration" >&2; exit 2; }
    ONLY_TEST="-only-testing:IulDeviceTests/IulDeviceTests/testUbuntuFullOnDevice"
else
    tests/integration/rootfs.sh alpine >/dev/null
    TARBALL=$(ls -t build/integration/alpine-minirootfs-*.tar.gz 2>/dev/null | head -n 1)
    [ -f "$TARBALL" ] || { echo "device.sh: alpine-minirootfs tarball not found in build/integration" >&2; exit 2; }
    ONLY_TEST="-only-testing:IulDeviceTests/IulDeviceTests/testSbmApiSuiteOnDevice"
fi
cp -f "$TARBALL" build-ios/rootfs.tar.gz

command -v xcodegen >/dev/null || { echo "device.sh: xcodegen is required (brew install xcodegen)" >&2; exit 2; }
xcodegen generate --spec tests/ios/project.yml --project tests/ios >/dev/null

xcodebuild test \
    -project tests/ios/IulDeviceHarness.xcodeproj \
    -scheme IulDeviceHost \
    -destination "platform=iOS,id=$UDID" \
    -derivedDataPath build-ios/DerivedData \
    "$ONLY_TEST" \
    ${TEAM:+DEVELOPMENT_TEAM="$TEAM"} \
    -allowProvisioningUpdates
