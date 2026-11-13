# Shared by the tools/build-*.sh scripts. Sourced, not run.
#
# There were four copies of the `case "$buildtype" in release|minsize)` block
# and three of the "rename into place, never copy over" note, because meson
# called four scripts with four positional argument lists. One is enough, and a
# rule enforced by repetition is enforced once per copy -- which is the finding
# `crates/util/buildcfg`'s module comment records about the 68 build scripts it
# replaced.
#
# What a caller gets after `parse_build_args "$@"`:
#
#   PROFILE       debug | release
#   PROFILE_ARGS  "" | --release          (for cargo)
#   RUST_TARGET   "" | aarch64-apple-ios  (--target, empty for a host build)
#   FEATURES      "" | comma,separated
#   OUT           the output directory, if -o was given
#   ARGS_SEEN     the arguments as given, for build-all.sh's marker file
#
# and `cargo_out_dir` answers where cargo put the result, which differs by one
# directory level on a cross build.

# The flags every build script here takes.
#
#   --release             the release profile, which is what ships: opt-level=z
#                         plus LTO. See the root Cargo.toml for why.
#   --target <triple>     a cross build. The iOS cross files named darwin and
#                         aarch64 for the host, the device and the simulator
#                         alike, so meson had to guess the target from the SDK
#                         path in c_args; naming it outright is what replaced
#                         that guess.
#   --features <list>     cargo features, comma-separated. The two offload
#                         verification handlers were meson options and are
#                         `offload-test-symbol` and `offload-test-prebuilt`.
#   -o|--out <dir>        where to put the output.
parse_build_args() {
    PROFILE=debug
    PROFILE_ARGS=""
    RUST_TARGET=""
    FEATURES=""
    OUT=""
    ARGS_SEEN="$*"
    while [ $# -gt 0 ]; do
        case $1 in
            --release)  PROFILE=release; PROFILE_ARGS="--release"; shift ;;
            --debug)    PROFILE=debug;   PROFILE_ARGS="";          shift ;;
            --target)   RUST_TARGET="$2"; shift 2 ;;
            --features) FEATURES="$2";    shift 2 ;;
            -o|--out)   OUT="$2";         shift 2 ;;
            -h|--help)  sed -n '2,40p' "$0"; exit 0 ;;
            *) echo "$(basename "$0"): unknown argument: $1" >&2; exit 2 ;;
        esac
    done
    apple_deployment_target
}

# The minimum iOS an object says it needs, for an iOS cross build.
#
# **Both halves of the build have to be told, and under meson only one was.**
# The cross file passed `-miphoneos-version-min=13.0` in `c_args`, which reached
# the C compiler and -- through `TMPFS_RS_CLANG_ARGS` -- the `cc::Build` that
# assembles the gadgets, so those said 13.0. It reached **rustc not at all**,
# and rustc's own default for `aarch64-apple-ios` is 10.0, so every Rust object
# in the same archive said 10.0. Two answers in one `libiul.a`, measured on
# 2026-09-11 by `vtool -show-build` on its members.
#
# Without it the gadgets are worse rather than better: `cc` with no version
# argument takes the **SDK's** default, which on this machine is 26.5 -- an
# archive an app targeting iOS 13 links with a warning per object, and objects
# free to use instructions and APIs a phone on iOS 13 does not have.
#
# `IPHONEOS_DEPLOYMENT_TARGET` is the one name both honour, so this is the first
# setting that makes the two halves agree. 13.0 because that is what
# ServerBox's app is built for and what the cross files passed; the environment
# wins if a caller sets it, so raising the floor is a variable rather than an
# edit here.
apple_deployment_target() {
    case "$RUST_TARGET" in
        *-apple-ios|*-apple-ios-sim)
            export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-13.0}"
            ;;
    esac
}

# Where cargo wrote the output. `CARGO_TARGET_DIR` is honoured because that is
# how two builds with different `TMPFS_RS_CLANG_ARGS` -- a -DLOCK_DEBUG=1 one
# and an ordinary one -- avoid invalidating each other's build scripts on every
# switch. meson gave each of its four cargo invocations a directory of its own
# for the same reason and paid for it with four compiles of the workspace.
cargo_out_dir() {
    printf '%s/%s%s\n' \
        "${CARGO_TARGET_DIR:-target}" \
        "${RUST_TARGET:+$RUST_TARGET/}" \
        "$PROFILE"
}

# cargo's feature flag, or nothing. An empty `--features ''` is not the same as
# no flag to every cargo version, so it is built rather than interpolated.
feature_args() {
    [ -n "$FEATURES" ] && printf -- '--features\n%s\n' "$FEATURES"
}

# Put a freshly built file at `dst` by **renaming**, never by copying over it.
#
# macOS caches a Mach-O's code signature against its *inode*, so `cp` onto a
# path whose older contents have been executed leaves a file the kernel kills at
# `execve` -- signal 9, before `main`, with no output at all, while the same
# bytes in cargo's own directory run perfectly. `mv` within one filesystem is a
# rename: new inode, nothing cached about it. It cost an hour the first time,
# arriving as what looked like a defect in the migration under test.
install_output() {
    src=$1
    dst=$2
    [ -f "$src" ] || { echo "$(basename "$0"): cargo did not produce $src" >&2; exit 1; }
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst.tmp"
    mv -f "$dst.tmp" "$dst"
}
