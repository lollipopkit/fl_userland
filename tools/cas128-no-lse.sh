#!/bin/sh
# `crates/emu/tlb`'s 128-bit CAS, built the way it is built for a **phone**.
#
# `cas128.rs` has two arms chosen by `cfg(target_feature = "lse")`, which is the
# same input clang uses to pick between `caspal` and an `ldaxp`/`stlxp` loop.
# The table in that file's comment records the answer per target:
#
#     aarch64-apple-darwin      caspal            lse set
#     aarch64-apple-ios         ldaxp/stlxp       lse not set
#     aarch64-apple-ios-sim     caspal            lse set
#
# A development machine is `aarch64-apple-darwin`, so an ordinary
# `cargo test -p emu-tlb` compiles the `caspal` arm and **never the other one** --
# which is the arm that ships to a device. This runs the same thirteen tests
# with the feature turned off, so the loop clang was transcribed from is
# executed rather than only read.
#
# usage: cas128-no-lse.sh <source-root>
set -e
cd "$1"
RUSTFLAGS='-C target-feature=-lse' exec cargo test --quiet -p emu-tlb
