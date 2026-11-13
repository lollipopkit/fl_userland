#!/bin/bash
# The source analyses, as one suite. `meson test -C build` until 2026-09-11.
#
# usage: tools/checks.sh [-l] [name ...]
#
#   -l          list the checks and exit
#   name ...    run only these, by the name meson registered them under
#
# Every check is registered here. A check that fails fails the run, and the
# **count is printed either way** -- because a suite that covers nothing and a
# suite that is clean produce the same "no failures", and only the count says
# which. `tools/lock-order.py` printed "0 locks with nesting, 0 cycles" and
# passed for the whole of the period its subject was being deleted; that is the
# shape this line exists to make visible.
#
# # Why a registration check
#
# The individual analyses each assert they found their own subject -- CLAUDE.md
# requires it, and `tools/fork-inherit.py` (removed 2026-09-30) and
# `tools/unread-fields.py` failing loudly the minute `struct task` moved is what that assertion buys. What none
# of them can assert is that **anybody runs them**. `tools/syscall-abi.py` was
# silent for five days because nothing called it, and a tool nothing calls looks
# exactly like a tool with nothing to report.
#
# So the suite asserts its own coverage: every `tools/*.py` is either in CHECKS
# below or in NOT_A_CHECK with a reason, and a script in neither fails the run.
# Adding an analysis and forgetting to register it is then a red suite rather
# than silence.
set -uo pipefail
cd "$(dirname "$0")/.."
root=$(pwd)

# name|command...
#
# The comment above each says what it reports; the long-form reasoning is in
# each script's own header.
CHECKS=(
    # Lock-order cycles. Follows source order rather than control flow, so a
    # clean run is not a proof -- read every cycle before believing it. The
    # `--calls` mode that found both deadlocks so far gates nothing and is run
    # by hand.
    "lock_order|python3 tools/lock-order.py --quiet"
    # A syscall parameter narrower than the 64-bit register the ABI passes it
    # in. The class that turned an mremap grow into a shrink.
    "syscall_abi|python3 tools/syscall-abi.py --quiet"
    # An array indexed by a syscall argument whose bound check is off by one or
    # missing below. Two crashed the emulator from one syscall.
    "index_bounds|python3 tools/index-bounds.py --quiet"
    # A flag a caller passes and the callee never reads. N_PARENT_DIR_WRITE was
    # one at nine call sites since 2019.
    "unread_flags|python3 tools/unread-flags.py --quiet"
    # The same question about a struct field: written where a guest reaches it,
    # read nowhere.
    "unread_fields|python3 tools/unread-fields.py --quiet"
    # An export no C source, no assembly, no `ffi::` and no header the embedder
    # compiles against names. Reported, not failed: what to do about one needs
    # a fact this repository does not hold.
    "dead_exports|python3 tools/dead-exports.py"
    # Which crates still read a C header, and for what. Reported, not failed.
    "bindgen_need|python3 tools/bindgen-need.py"
    # A dependency that points *up* the layering. Cargo refuses only a cycle.
    "crate_layers|python3 tools/crate-layers.py"
    # The workspace's shape: every crate a member, one staticlib, every crate
    # reachable, no two lib targets sharing a name.
    "crate_graph|python3 tools/crate-graph.py"
    # An opaque `_unused: [u8; 0]` placeholder whose owning crate the layering
    # already allows naming. Every reader of such a field writes a `.cast()`,
    # and a cast between two raw pointers is accepted whatever is on either end.
    "placeholder_owners|python3 tools/placeholder-owners.py"
    # A rule this tree deliberately consolidated, defined in a second crate.
    # Narrow on purpose: every duplicate name is 151 and mostly ordinary verbs.
    # `dev_make` was consolidated on 2026-09-01 and had four copies again by
    # 2026-09-15, one of which disagreed.
    "one_owner|python3 tools/one-owner.py"
    # An `unsafe fn` with nothing for a caller to guarantee.
    "unsafe_without_contract|python3 tools/unsafe-without-contract.py"
    # A `*mut c_void` parameter the body casts back on its first use.
    "void_erases_nothing|python3 tools/void-that-erases-nothing.py"
    # A `#[cfg(test)]` stub standing in for a symbol nothing exports.
    "dead_stubs|python3 tools/dead-stubs.py"
    # A suppression of `clippy::missing_safety_doc`. Fifty-nine crates had one
    # and the lint's recorded count of zero was a count of nothing.
    "safety_doc_allows|python3 tools/safety-doc-allows.py"
    # A Rust crate reaching another through the C ABI.
    "rust_c_abi|python3 tools/rust-c-abi.py"
    # An fd_ops entry set without the companion field that makes it reachable.
    "ops_table_pairs|python3 tools/ops-table-pairs.py"
    # One implementation registered at two syscall numbers with different
    # arities. Two of three were wrong on 2026-09-03.
    "syscall_aliases|python3 tools/syscall-aliases.py"
    # A Rust `extern "C"` declaration that disagrees with the definition it
    # names. 1,384 declarations; the slowest check here at about fifteen
    # seconds, and it was killed three times under meson's thirty-second
    # default while a cargo build ran beside it. There is no timeout here.
    "extern_signatures|python3 tools/extern-signatures.py"
    # A header that declares a symbol nothing defines. `iul.h` declared
    # `exit_hook` for a commit, and `sbm_api_test` was the only thing that
    # noticed -- on a tree whose cargo build, test and clippy were all green.
    "header_symbols|python3 tools/header-symbols.py --quiet"
    # A Rust constant that restates a C `#define` and disagrees with it.
    "guessed_constants|python3 tools/guessed-constants.py"
    # A `#[no_mangle]` whose name the host libc also exports. The linker picks
    # one definition, so it replaces libc's for every caller in the image --
    # including this tree's own `libc::` calls.
    "libc_shadow|python3 tools/libc-shadow.py"
    # An `iul.h` call that answers a pointer-shaped errno without saying so.
    # None of the three ever answers NULL, so an embedder writing the ordinary
    # `if (!p)` dereferences an address like -2. The header said "several calls
    # answer one" and named none, and two of the three Rust sites each said
    # they were "one of the two places" -- wrong, because the third spelled the
    # encoding out by hand.
    "err_ptr|python3 tools/err-ptr.py"
    # A lock or condvar initialised into a struct field and never destroyed,
    # immediately before a free().
    "init_destroy|python3 tools/init-destroy.py --quiet"
    # A struct still `libc::calloc`ed whose crate does not assert its fields
    # own nothing. `libc::free` runs no destructor, so one that grows an `Arc`
    # leaks it silently -- which is what the object model's remaining steps add.
    "hand_allocated_drop|python3 tools/hand-allocated-drop.py"
    # A `struct task` field the group-exit valve takes from a *running* thread
    # while that thread may be reading it. Three field groups were protected by
    # a comment naming `pids_lock`, which is the wrong property, in four days.
    "valve_fields|python3 tools/valve-fields.py"
    # `fork_inherit` and `fork_owned_fields` were here until 2026-09-30: a
    # fork built the child by byte-copying the parent and they read for the
    # fields nobody undid. `task_create_` builds it from a struct literal now,
    # `taskcalls`' `forked_task`, which does not compile without every field.
    # `sec * 1_000_000_000 + nsec` in an i64, from a timespec Linux does not
    # bound. A panic inside an `extern "C"` fn is an abort of the emulator.
    "deadline_overflow|python3 tools/deadline-overflow.py --quiet"
    # The only check here that compiles anything, and what it compiles is the
    # arm a **phone** gets: `cas128.rs` picks between `caspal` and an
    # ldaxp/stlxp loop on `cfg(target_feature = "lse")`, and this machine is
    # aarch64-apple-darwin, where lse is set. aarch64-apple-ios is where it is
    # not.
    "cas128_no_lse|tools/cas128-no-lse.sh $root"
)

# A `tools/*.py` that is deliberately not in the suite, and why. The list is
# what makes the coverage assertion below mean something: an entry here is a
# decision somebody wrote down, where an unlisted script is an oversight.
#
# `filename|reason`, and not an associative array: macOS ships bash 3.2 as
# /bin/bash and `declare -A` is bash 4. That is the same constraint
# tools/build-libs.sh records about empty arrays under `set -u`.
NOT_A_CHECK=(
    # Needs a link log to answer its question -- which duplicate symbol the
    # linker picked -- so it cannot run from source alone. The pure-source
    # complement is dead-stubs.py, which is in the suite.
    "dup-stubs.py|needs a link log, not source"
)

list_only=0
if [ "${1:-}" = "-l" ]; then
    list_only=1
    shift
fi

# Every analysis is registered. See the header for what this is worth.
registered=""
for entry in "${CHECKS[@]}"; do
    registered="$registered ${entry#*|}"
done
exempt=""
for entry in "${NOT_A_CHECK[@]}"; do
    exempt="$exempt tools/${entry%%|*}"
done
missing=0
for f in tools/*.py; do
    case " $registered " in *" $f "*) continue ;; esac
    case " $exempt " in *" $f "*) continue ;; esac
    echo "checks.sh: $f is not registered in CHECKS and not in NOT_A_CHECK." >&2
    echo "  Add it to the suite, or say there why it is not one." >&2
    missing=1
done
# An exemption whose file is gone is a stale decision, and the same rule
# `tools/crate-layers.py`'s ALLOWED set follows: an entry that no longer names
# anything fails the run rather than being ignored.
for entry in "${NOT_A_CHECK[@]}"; do
    if [ ! -f "tools/${entry%%|*}" ]; then
        echo "checks.sh: NOT_A_CHECK names tools/${entry%%|*}, which does not exist" >&2
        missing=1
    fi
done
if [ "$missing" -ne 0 ]; then
    exit 2
fi
# And every registered command names a file that is there. A check whose script
# was renamed would otherwise fail with "command not found" counted as a
# finding, which is the shape CLAUDE.md calls "a gate that fails on load reads
# as a finding and is not one".
#
# Read with `read`, not `set --`: the positional parameters are this script's
# own arguments and are needed below.
for entry in "${CHECKS[@]}"; do
    read -r first second _rest <<<"${entry#*|}"
    prog=$first
    [ "$prog" = python3 ] && prog=$second
    if [ ! -f "$prog" ]; then
        echo "checks.sh: ${entry%%|*} names $prog, which does not exist" >&2
        exit 2
    fi
done

if [ "$list_only" -eq 1 ]; then
    for entry in "${CHECKS[@]}"; do
        printf '%s\n' "${entry%%|*}"
    done
    exit 0
fi

# Named checks only, if any were named. An unknown name is an error rather than
# an empty run: `tools/checks.sh sock` after a rename would otherwise report
# "0 checks, 0 failed" and exit 0.
selected=()
if [ $# -gt 0 ]; then
    for want in "$@"; do
        found=0
        for entry in "${CHECKS[@]}"; do
            if [ "${entry%%|*}" = "$want" ]; then
                selected+=("$entry")
                found=1
            fi
        done
        if [ "$found" -eq 0 ]; then
            echo "checks.sh: no check named '$want'. tools/checks.sh -l lists them." >&2
            exit 2
        fi
    done
else
    selected=("${CHECKS[@]}")
fi

ran=0
failed=0
failed_names=""
for entry in "${selected[@]}"; do
    name=${entry%%|*}
    cmd=${entry#*|}
    start=$SECONDS
    # Output is kept and printed only on failure, so a clean run is the summary
    # line and nothing else -- the analyses that are *reported* rather than
    # failed print a number every time, and twenty-two of those scroll the
    # failure off the screen. IUL_CHECKS_VERBOSE=1 prints all of it.
    log=$(mktemp "${TMPDIR:-/tmp}/iul-check.XXXXXX")
    # shellcheck disable=SC2086
    if $cmd >"$log" 2>&1; then
        status=OK
    else
        status=FAIL
        failed=$((failed + 1))
        failed_names="$failed_names $name"
    fi
    ran=$((ran + 1))
    printf '%2d/%d %-24s %-4s %ds\n' "$ran" "${#selected[@]}" "$name" "$status" "$((SECONDS - start))"
    if [ "$status" = FAIL ] || [ -n "${IUL_CHECKS_VERBOSE:-}" ]; then
        sed 's/^/    /' "$log"
    fi
    rm -f "$log"
done

echo
# The count, not just the verdict. See the header.
echo "$ran checks, $((ran - failed)) passed, $failed failed"
if [ "$failed" -ne 0 ]; then
    echo "failed:$failed_names" >&2
    exit 1
fi
