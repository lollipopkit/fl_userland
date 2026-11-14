#!/bin/sh
# Build the guest-side test programs and run them inside the emulator.
#
# They live in tests/guest/, are Rust, and are cross-compiled for
# aarch64-unknown-linux-musl with rust-lld. Nothing is installed in the guest:
# the C versions of these needed `apk add gcc musl-dev` on every run, which
# needs the network, and CLAUDE.md counts a network step on a cold cache as a
# red gate.
#
# Three programs, three things:
#
#   fs_conformance  one set of POSIX assertions against realfs, fakefs and
#                   tmpfs in turn. The comparison is the point: three unrelated
#                   implementations of one interface, so a check that passes on
#                   two and fails on the third is a bug in the third.
#   fs_race         chdir against relative-path resolution, asserting the
#                   emulator is still alive afterwards.
#   tty_ldisc       the terminal line discipline, through a real pty.
#
# Usage:  tests/integration/guest_tests.sh [-i <iul>] [-r <rootfs>]
set -eu

# One at a time. Two concurrent runs used to hang -- `task_race` called
# `std::thread::spawn` in a child of `fork` and inherited a Rust `std` lock that
# a thread which did not survive the fork was holding. That is fixed (the child
# execs first; see the 2026-09-01 section of
# docs/changelog/2026-08-22-a-deadlock-seen-once-in-task-race.md), and the lock
# stays because serialising the suite is worth having anyway: several of these
# tests measure timing, and two suites on one machine make those flaky for
# reasons that are nobody's bug.
#
# The lock is the directory rather than a file, because mkdir is the one
# filesystem operation that is atomic and tells you whether it won. Removed on
# every exit, including a signal, so a killed run does not lock the next one
# out.
#
# The owner's pid goes inside it, because a run killed with SIGKILL -- or one
# whose terminal went away -- never reaches the trap, and the next run then
# refuses for ever. A lock whose owner is gone is taken over rather than
# reported: the first version of this reported it, and cost twenty minutes the
# first time it happened.
GUEST_TESTS_LOCK="${TMPDIR:-/tmp}/iul-guest-tests.lock"
if ! mkdir "$GUEST_TESTS_LOCK" 2>/dev/null; then
    owner=$(cat "$GUEST_TESTS_LOCK/pid" 2>/dev/null || echo "")
    if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
        echo "another guest_tests.sh is running (pid $owner)." >&2
        echo "two at once deadlock task_race; wait for it, or kill it." >&2
        exit 2
    fi
    echo "taking over a lock whose owner (${owner:-unknown}) is gone." >&2
fi
echo $$ > "$GUEST_TESTS_LOCK/pid"
trap 'rm -rf "$GUEST_TESTS_LOCK" 2>/dev/null' EXIT INT TERM HUP

IUL=""; ROOTFS=""; IUL_GIVEN=0
while [ $# -gt 0 ]; do
    case "$1" in
        -i) IUL="$2"; IUL_GIVEN=1; shift 2 ;;
        -r) ROOTFS="$2"; shift 2 ;;
        *) echo "usage: $0 [-i <iul>] [-r <rootfs>]" >&2; exit 2 ;;
    esac
done

# **`build-release/` first, and a directory this script chose that cannot be
# rebuilt is a setup error.** Both halves were wrong until 2026-09-16:
# `build-arm64-release/` came first and is the *meson* name, which nothing has
# written since 2026-09-11 -- and because that directory predates
# `iul-build.env`, the rebuild below silently skipped. So this ran a week-old
# emulator and a ten-day-old embedder harness, and reported 34 passed with a
# deliberately broken `pty_open_fake` in the tree.
#
# The comment further down records the *same* defect being fixed on 2026-08-28.
# That fix made the rebuild conditional on a marker file, and the marker is
# exactly what the stale directory does not have -- so the guard did nothing
# for the one directory it was written to protect.
#
# The rule is `probe_diff.sh`'s, which reasoned it out first: **`-i` warns and
# a binary this script picked for itself is fatal.** Nobody chose the stale
# one, so a clean run against it is an accident rather than a decision.
IUL_CHOSEN=0
if [ -z "$IUL" ]; then
    IUL_CHOSEN=1
    for cand in build-release/iul build/iul build-arm64-release/iul; do
        [ -x "$cand" ] && { IUL="$cand"; break; }
    done
fi
# Built before it is used, not assumed to be current.
#
# This prefers build-arm64-release/ where the gate used build/, and nothing
# kept the second in step with the first. Three tests failed here against a
# release binary from before the fix under test while the same tests passed
# against build/iul -- which reads as "the bug is in the optimiser" and is not.
# differential.sh had the same defect and the same fix.
#
# IUL_NO_BUILD=1 skips it, for running a binary kept deliberately.
#
# The marker was `build.ninja` until 2026-09-11 and is `iul-build.env` now,
# which `tools/build-all.sh` writes with the flags *and the environment* it was
# given -- so a rebuild reproduces the directory rather than replacing it with a
# default build. That matters most for the one case this rebuild would otherwise
# ruin: `build-lockdebug/` holds an emulator whose `struct task` has a different
# layout, and rebuilding it without `TMPFS_RS_CLANG_ARGS` would answer about the
# layout it was meant to be checking the other of.
#
# **In a subshell**, so that the `CARGO_TARGET_DIR` in that file reaches this
# rebuild and nothing else. It is a relative path, and the cargo invocation
# below that cross-compiles the guest programs would otherwise put them in
# `tests/guest/target-lockdebug/` while `$BINDIR` still names
# `tests/guest/target/` -- so the suite would copy whatever was in the second
# from an earlier run, or fail outright on a fresh checkout.
if [ -z "${IUL_NO_BUILD:-}" ] && [ ! -f "$(dirname "$IUL")/iul-build.env" ]; then
    printf 'no %s/iul-build.env, so this binary cannot be rebuilt.\n' \
        "$(dirname "$IUL")" >&2
    if [ "$IUL_CHOSEN" = 1 ]; then
        printf 'Nothing chose it -- it is the first of the candidates that\n' >&2
        printf 'happened to exist, and running it would report on whatever it\n' >&2
        printf 'was built from. Build one with tools/build-all.sh, or pass\n' >&2
        printf '-i <iul> to say you mean this one.\n' >&2
        exit 2
    fi
    printf 'Running it anyway: you passed -i, so the choice is yours.\n' >&2
fi
if [ -z "${IUL_NO_BUILD:-}" ] && [ -f "$(dirname "$IUL")/iul-build.env" ]; then
    if ! (
        # shellcheck disable=SC1090,SC2046 # a generated file; the flags word-split
        . "$(dirname "$IUL")/iul-build.env"
        tools/build-cli.sh -o "$(dirname "$IUL")" $IUL_BUILD_ARGS >/dev/null
        tools/build-fakefsify.sh -o "$(dirname "$IUL")/tools" $IUL_BUILD_ARGS >/dev/null
    ); then
        echo "could not build $IUL" >&2
        exit 1
    fi
fi
[ -n "$IUL" ] && [ -x "$IUL" ] || { echo "no iul binary; build one or pass -i" >&2; exit 2; }
# Which binary, said out loud. A run that answers about a different build from
# the one you changed is the failure mode this has actually had -- twice, in
# opposite directions: a stale release binary reported three failures that were
# already fixed, and a suite started before a change passed against the tree as
# it was when it began.
printf 'iul: %s\n' "$IUL"

# And whether it is *current*, which saying its name does not answer.
#
# The rebuild above only runs when the directory has an `iul-build.env`, so
# there are two ways to get here with a binary older than the tree: a directory
# without that marker, and `IUL_NO_BUILD=1`. On 2026-09-16 the first of those
# cost four runs -- a `build/` left by an earlier session reported 13 failures
# across `copy_file_range`, `/proc` seeks, futex counts and a unix bind, none of
# them reachable from the commit under test, and all of them gone after
# `tools/build-all.sh`. See
# `docs/changelog/2026-09-16-pids-lock-from-a-comment-to-a-type.md`, which also
# records that the mechanism was never established -- which is the argument for
# refusing rather than explaining.
#
# `probe_diff.sh` has had this check for some time and it fired, correctly, in
# that same session. This is that check, with its three rules: a binary the
# script picked for itself is an error, one named with `-i` is advice because
# somebody chose it, and **`rg` missing says so** rather than passing quietly --
# "nothing" and "not looked at" must not read the same.
newest_src=$(rg --files -g '*.S' -g '*.h' -g '*.rs' crates asbestos 2>/dev/null \
    | xargs stat -f '%m %N' 2>/dev/null | sort -rn | head -1)
if [ -z "$newest_src" ]; then
    echo "  (cannot tell whether this binary is current: rg is not installed)"
elif [ "${newest_src%% *}" -gt "$(stat -f '%m' "$IUL")" ]; then
    if [ "$IUL_GIVEN" = 1 ]; then
        echo "  WARNING: ${newest_src#* } is newer than this binary."
        echo "  You named it with -i, so this is advice: the failures below"
        echo "  are that binary's and not the tree's."
    else
        echo "guest_tests: ${newest_src#* } is newer than $IUL," >&2
        echo "  which this script picked for itself -- so nobody chose to" >&2
        echo "  test an old build. Rebuild, or name one with -i." >&2
        exit 2
    fi
fi
[ -n "$ROOTFS" ] || ROOTFS="$(tests/integration/rootfs.sh alpine)" || exit 1

TARGET=aarch64-unknown-linux-musl
BINDIR="tests/guest/target/$TARGET/release"

echo "########## building the guest tests ##########"
( cd tests/guest && cargo build --release --target "$TARGET" ) || {
    echo "could not cross-compile the guest tests" >&2
    echo "  rustup target add $TARGET" >&2
    exit 1
}

# Every guest test binary, taken from the source directory rather than a list.
#
# It used to be a hand-maintained list of a hundred names, and it had drifted
# both ways. Fourteen binaries this file runs were never copied -- they worked
# only because a hand-copy from some earlier session was still lying in the
# rootfs, so a clean rootfs would have failed outright and a dirty one ran
# whatever build happened to be there. And `clone3_abi` was copied on every run
# and executed by nothing.
#
# A list that has to be edited twice to add one test will be edited once.
for src in tests/guest/src/bin/*.rs; do
    t="$(basename "$src" .rs)"
    cp "$BINDIR/$t" "$ROOTFS/tmp/$t"
done

HOST_SCRATCH="$(mktemp -d)"
# The lock goes too: this trap replaces the one that took it, and a lock left
# behind makes every later run report taking over from a dead owner.
cleanup() { rm -rf "$HOST_SCRATCH" "$GUEST_TESTS_LOCK" 2>/dev/null; }
trap cleanup EXIT INT TERM HUP

# fakefs needs a directory of its own, with the rootfs as its data/. Copied
# after the binaries are in place, so they are inside it.
FAKEFS="$HOST_SCRATCH/fakefs"
mkdir -p "$FAKEFS"

# What previous runs left in the rootfs's /tmp is scratch, and copying it is
# both slow and racy: a straggler from the run before can still be writing
# there, and `cp -R` reporting "no such file" for a name that vanished under it
# took the whole suite down with it on 2026-08-29 (`tmp/inodl/f0`).
#
# The test binaries were copied in above and are kept; everything else under
# /tmp is a scratch directory some test made and did not need afterwards.
for leftover in "$ROOTFS"/tmp/*/; do
    [ -d "$leftover" ] && rm -rf "$leftover"
done

# Reported, not fatal. The copy is of a scratch rootfs and a file that
# disappeared from it is not a reason to lose ninety tests -- but it is a
# reason to say so, because a *systematically* incomplete fakefs would make the
# fakefs run measure something else.
if ! cp -R "$ROOTFS" "$FAKEFS/data" 2>"$HOST_SCRATCH/cp-err"; then
    echo "note: copying the rootfs into the fakefs reported:" >&2
    sed 's/^/  /' "$HOST_SCRATCH/cp-err" >&2
    echo "  (the fakefs run below is against whatever did copy)" >&2
fi
"$(dirname "$IUL")/tools/fakefsify" --index "$FAKEFS"

fail=0
# Records the name as well as the count. Reporting only "N FAILED" at the end
# means an intermittent failure -- which is what the race probes produce -- is
# unattributable by the time anyone reads it, and re-running to find out is
# exactly what will not reproduce it.
failed_names=""
note_fail() {
    fail=$((fail+1))
    failed_names="$failed_names
  - $1"
    # The output goes to FAILLOG here as well as to stdout.
    #
    # The wrapper below already did this for the tests that go through it. The
    # race blocks at the bottom of this file are written by hand and did not:
    # they printed `tail -6` of the run to stdout and nothing else, so anyone
    # piping this script through a grep -- which is how a long run gets read --
    # lost the reason. That happened on 2026-08-28 to a release-only sock_race
    # failure, and the reason it failed is not recoverable.
    #
    # $2 is the output, when the caller has it.
    if [ -n "${2:-}" ]; then
        { printf '########## %s ##########\n' "$1"; printf '%s\n\n' "$2"; } >> "$FAILLOG"
    fi
}
# A failing test's own output, kept.
#
# The summary at the end names what failed; the FAIL lines that say *why* went
# to stdout and were gone as soon as anyone piped this through `tail`. That is
# not hypothetical: an intermittent failure here fired once with a probe that
# had just been improved to report its cause, and the cause was lost to a
# `tail -3`. An intermittent failure is precisely the one that will not
# reproduce when you go looking for it again.
FAILLOG="${FAILLOG:-$(mktemp -t guest_tests_failures)}"
: > "$FAILLOG"
# Seconds any one test gets before it is killed.
#
# Not optional, and the reason is a defect this suite found: a ptrace request
# whose failure path returned without releasing the child's ptrace lock made
# every later ptrace on that child block for ever. The test that probes it does
# not fail -- it *hangs*, and with no deadline the whole suite hangs with it,
# which is a worse failure than the one it was reporting. A guest test that has
# not finished in two minutes is not going to.
#
# differential.sh has had this since a stale binary blocked a whole sweep by
# reading for ever; the primary suite needed it more.
TEST_TIMEOUT="${TEST_TIMEOUT:-120}"

# Run "$@" with a deadline, into $out, and report its status. macOS has no
# timeout(1), hence the polling.
with_deadline() {
    "$@" >"$HOST_SCRATCH/run" 2>&1 &
    _pid=$!
    _waited=0
    while kill -0 "$_pid" 2>/dev/null; do
        if [ "$_waited" -ge "$TEST_TIMEOUT" ]; then
            kill -9 "$_pid" 2>/dev/null
            wait "$_pid" 2>/dev/null
            printf '\nTIMED OUT after %ss -- a test that hangs is a test that failed\n' \
                "$TEST_TIMEOUT" >> "$HOST_SCRATCH/run"
            return 1
        fi
        sleep 1
        _waited=$((_waited + 1))
    done
    wait "$_pid" 2>/dev/null
}

# with_deadline for a command substitution: the output on stdout, the status
# kept. Every hand-written block below that checks the output itself runs
# through this, so a hang there is a failure with the run's output rather than
# a suite that never finishes -- `thread_start_signal` blocked the whole suite
# that way on 2026-11-13.
bounded() {
    if with_deadline "$@"; then _rc=0; else _rc=$?; fi
    cat "$HOST_SCRATCH/run"
    return "$_rc"
}

run() {
    printf '\n########## %s ##########\n' "$1"
    name=$1
    shift
    # `if`, not `out=$(...); rc=$?`. This script runs under `set -e`, and the
    # exit status of an assignment is the exit status of its command
    # substitution — so the plain form aborted the whole run at the *first*
    # failing test, before printing its output. Everything below this line,
    # including FAILLOG and the summary that names what failed, was
    # unreachable: "guest tests: all passed" was the only ending the script
    # could reach. A run that stopped at `########## setpgid rules ##########`
    # with nothing after it is what showed this.
    if with_deadline "$@"; then rc=0; else rc=$?; fi
    out=$(cat "$HOST_SCRATCH/run")
    printf '%s\n' "$out"
    if [ $rc -ne 0 ]; then
        note_fail "$name" "$out"
    fi
}

# The ownership checks need groups the *host* process belongs to: a passthrough
# mount cannot grant a chgrp the host would refuse, and the guest's own group
# list says nothing about the host's. Passed as arguments because `iul` builds
# a fixed environment for the guest and does not forward this one.
HOST_GIDS="$(id -G)"

run "fs_conformance: realfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    "rm -rf /tmp/conf-real; /tmp/fs_conformance /tmp/conf-real $HOST_GIDS"
run "fs_conformance: fakefs" "$IUL" -f "$FAKEFS" /bin/sh -c \
    "rm -rf /tmp/conf-fake; /tmp/fs_conformance /tmp/conf-fake $HOST_GIDS"
run "fs_conformance: tmpfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    "mkdir -p /mnt/conf && mount -t tmpfs none /mnt/conf && /tmp/fs_conformance /mnt/conf/s $HOST_GIDS"
run "syscall ABI" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/abi; /tmp/syscall_abi /tmp/abi'
run "scheduling and I/O hints" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/schedabi; /tmp/sched_abi /tmp/schedabi'
run "inotify arguments" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/inotify_args'
run "floating-point modes" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/fpu_modes'
run "TCP, UDP and socketpair" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/sock_net'
run "socket semantics" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/socks; /tmp/sock_semantics /tmp/socks'
run "tty line discipline" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/tty_ldisc'
run "pending signals and signalfd" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/signal_pending'
run "/proc/<pid>/maps" "$IUL" -r "$ROOTFS" /bin/sh -c 'rm -f /tmp/maps-probe; /tmp/proc_maps /tmp'
run "mmap and mremap semantics" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -f /tmp/mremap-probe; /tmp/mmap_semantics /tmp'
run "self-modifying code" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/self_modifying'
run "fault pc" "$IUL" -r "$ROOTFS" /tmp/fault_pc
run "instruction semantics" "$IUL" -r "$ROOTFS" /tmp/insn_semantics
run "TIOCSPGRP argument rules" "$IUL" -r "$ROOTFS" /tmp/tty_pgrp
run "terminal hangup" "$IUL" -r "$ROOTFS" /tmp/tty_hangup
run "vhangup, and what a hangup reaches" "$IUL" -r "$ROOTFS" /tmp/tty_vhangup
# The session leader's SIGHUP and an orphaned group's SIGHUP+SIGCONT are sent
# before the parent can see the exit.
run "what an exit has sent before its parent hears" "$IUL" -r "$ROOTFS" /tmp/exit_order
run "background terminal access" "$IUL" -r "$ROOTFS" /tmp/tty_tostop
run "RLIMIT_NPROC" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/nproc_limit'
run "wait across threads" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/wait_threads'
run "setpgid rules" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/setpgid_rules'
run "the signal-wait family" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/signal_wait'
# The end-to-end half of the two wiring tests in crates/util/waitfor and
# crates/kernel/taskview, neither of which can be checked by its answer: in a
# test binary there is no current task, so an absent hook and the real one give
# the same reply.
#
# Backed out both ways on 2026-09-12. Removing waitfor's hook install is the
# quiet failure this is here for. Removing set_current's cached reference is
# loud instead -- rt_sigaction fails too, and Rust's runtime start-up asserts on
# signal(SIGPIPE), so every Rust guest program aborts before main; see the
# program's own comment.
run "blocking syscalls are interruptible" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/blocking_interrupt'
run "default signal actions" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/signal_defaults'
run "sigaltstack is per thread" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/sigaltstack_threads'
run "sendfile" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/sendfile_abi'
run "splice and copy_file_range positions" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/copy_positions'
run "interval timers" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/itimer_abi'
run "the clocks" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/clock_abi'
run "POSIX timers across fork and exec" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/posix_timer_fork'
run "signals interrupt blocking calls" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/signal_interrupt'
run "/proc file shapes" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/proc_files'
run "sysinfo" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/sysinfo_abi'
run "getrandom accepts what Linux accepts and delivers a count" "$IUL" -r "$ROOTFS" /tmp/getrandom_abi
run "V8 abort chatter is dropped and nothing else is" "$IUL" -r "$ROOTFS" /tmp/v8_mute
# Deliberately run as the *first* process, not through /bin/sh: what it checks
# is that the boot exec injects what every later one does, and a shell in
# between would make both sides the later case.
run "the environment this kernel injects" "$IUL" -r "$ROOTFS" /tmp/exec_env
run "/proc/<pid>/stat fields" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/proc_stat_fields'
run "/proc state letter of a blocked process" "$IUL" -r "$ROOTFS" /tmp/proc_state
run "fchmod survives dup; stdio has a type" "$IUL" -r "$ROOTFS" /tmp/adhoc_attrs
run "each mount has its own st_dev" "$IUL" -r "$ROOTFS" /tmp/mount_dev
run "timerfd" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/timerfd_abi'
run "signals across threads" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/signal_threads'
# The process's shared pending set beside each thread's own: who may take a
# kill, what sigpending and /proc report, and what exec, fork and exit keep.
run "shared pending signals" "$IUL" -r "$ROOTFS" /tmp/signal_shared
run "dup, dup2 and dup3" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/dup_semantics'
run "every fcntl command" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/fcntl_abi'
run "blocking poll and select" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/poll_blocking'
run "epoll and poll semantics" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -f /tmp/epoll-probe; /tmp/epoll_semantics /tmp'
# epoll_pwait2's nanosecond timeout, its temporary mask, and the busy-poll ioctls.
run "epoll_pwait2" "$IUL" -r "$ROOTFS" /tmp/epoll_pwait2_abi
# Native AIO: the ring, the transfers, IOCB_CMD_POLL completing on its own,
# io_cancel, io_destroy, fork and exit, and a multi-threaded submit/reap.
run "native AIO" "$IUL" -r "$ROOTFS" /tmp/aio_abi
run "Rust-owned descriptor lifetimes" "$IUL" -r "$ROOTFS" /tmp/eventfd_leak
run "the anonymous-page budget balances" "$IUL" -r "$ROOTFS" /tmp/anon_budget_leak
run "epoll destruction race" "$IUL" -r "$ROOTFS" /tmp/poll_race
# MallocScribble so that a freed description crashes the wakeup that reads it:
# without it the race read stale memory quietly.
run "signalfd closed while a signal is sent" env MallocScribble=1 "$IUL" -r "$ROOTFS" /tmp/signalfd_close_race
run "pselect and ppoll ABI" "$IUL" -r "$ROOTFS" /tmp/pselect_abi
run "nested epoll" "$IUL" -r "$ROOTFS" /tmp/epoll_nested
run "pipes, eventfd and timerfd" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/pipe_eventfd'
run "ABI struct sizes" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/abi_structs'
run "sleeping and timers" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/time_semantics'
# getdents64 is a wire format too, and a stream of variable-length records
# rather than a struct, so abi_structs cannot see it. Three mount types, for
# the same reason fs_conformance runs three times.
run "getdents64: realfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/dents; /tmp/getdents /tmp/dents'
run "getdents64: fakefs" "$IUL" -f "$FAKEFS" /bin/sh -c \
    'rm -rf /tmp/dents; /tmp/getdents /tmp/dents'
run "getdents64: tmpfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'mkdir -p /mnt/dents && mount -t tmpfs none /mnt/dents && /tmp/getdents /mnt/dents'
# Two threads listing one directory descriptor. `sys_getdents64` held no
# `fd->lock`, and both of these mounts install their per-descriptor state on
# the *first* listing -- so two threads reaching it together both built one and
# both stored it. realfs leaked a `DIR *` and the host descriptor inside it,
# 1990 times in 2000 rounds; fakefs leaked a four-kilobyte path cache.
#
# **Under an explicit `ulimit -n`**, because that is what makes the leak
# observable rather than merely present. 256 is macOS's default and is the
# order of what an app gets; this machine's login shell has it at a million, and
# without the limit the test passes against the bug. `sh -c` with `$0`/`$1`
# rather than a subshell so that `run`'s deadline and failure log still apply.
# A real arm64 kernel answers 0 errors at these counts.
run "two threads listing one directory: realfs" \
    sh -c 'ulimit -n 256; exec "$0" -r "$1" /bin/sh -c "/tmp/dir_read_race /usr/bin 400"' \
    "$IUL" "$ROOTFS"
run "two threads listing one directory: fakefs" \
    sh -c 'ulimit -n 256; exec "$0" -f "$1" /bin/sh -c "/tmp/dir_read_race /usr/bin 400"' \
    "$IUL" "$FAKEFS"
# What an open descriptor survives when the namespace moves under it. Three
# mounts, because each keeps different state on a descriptor -- tmpfs an
# Arc<Dirent>, fakefs a cached guest path, realfs a host descriptor.
run "open descriptors: realfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/fdsurv; /tmp/fd_survives /tmp/fdsurv'
run "open descriptors: fakefs" "$IUL" -f "$FAKEFS" /bin/sh -c \
    'rm -rf /tmp/fdsurv; /tmp/fd_survives /tmp/fdsurv'
run "open descriptors: tmpfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'mkdir -p /mnt/fdsurv && mount -t tmpfs none /mnt/fdsurv && /tmp/fd_survives /mnt/fdsurv'
# Vectored and bulk file I/O -- readv/writev, the positional forms, sendfile,
# copy_file_range, fallocate. Three mounts: fakefs forwards contents to realfs,
# so its bulk paths are a different implementation from the ones it shares.
run "file I/O: realfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/fio; /tmp/file_io /tmp/fio'
run "file I/O: fakefs" "$IUL" -f "$FAKEFS" /bin/sh -c \
    'rm -rf /tmp/fio; /tmp/file_io /tmp/fio'
run "file I/O: tmpfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'mkdir -p /mnt/fio && mount -t tmpfs none /mnt/fio && /tmp/file_io /mnt/fio'
# openat2's RESOLVE_* containment, faccessat2, fchmodat2, the *xattrat calls,
# file_getattr, cachestat, statmount/listmount and the file-handle pair. Two
# mounts, because the walk's refusals ask each mount what a name is and realfs
# and fakefs answer through different code.
run "post-5.6 filesystem calls: realfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/fsat; /tmp/fs_at_calls /tmp/fsat'
run "post-5.6 filesystem calls: fakefs" "$IUL" -f "$FAKEFS" /bin/sh -c \
    'rm -rf /tmp/fsat; /tmp/fs_at_calls /tmp/fsat'
# What a language runtime reads at startup to size itself: the affinity mask,
# the descriptor and stack limits, umask, credentials, getrandom. A wrong
# answer here is a performance or security problem that never reports itself.
# Whether inotify reports anything. inotify_args checks that a watch validates
# its arguments and passed throughout while the implementation said outright
# that nothing generated events.
run "inotify events" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/inoev; /tmp/inotify_events /tmp/inoev'

# FUTEX_WAIT_BITSET's absolute deadline is a CLOCK_MONOTONIC one unless
# FUTEX_CLOCK_REALTIME says otherwise. Probed with the raw syscall: musl works
# out its own relative timeout and never issues this command, so a musl rootfs
# cannot reach the path a glibc one takes.
# A futex on a page two processes share -- every PTHREAD_PROCESS_SHARED mutex
# and every sem_t in shared memory is this shape. Every other futex test here
# is within one process, where the two keyings are indistinguishable.
run "a futex two processes share" "$IUL" -r "$ROOTFS" /tmp/futex_shared
run "futex timeouts" "$IUL" -r "$ROOTFS" /tmp/futex_timeout
# The robust list is what a mutex whose owner died depends on, and storing it
# without walking it is a hang rather than a wrong answer. It was written and
# never registered here, so nothing ran it.
run "robust futexes" "$IUL" -r "$ROOTFS" /tmp/robust_futex
# futex2 (futex_wait/wake/waitv/requeue), the PI operations, PR_FUTEX_HASH,
# and the threads-against-each-other stress cases for all three.
run "futex2 and PI futexes" "$IUL" -r "$ROOTFS" /tmp/futex2_abi

# mincore's three answers, and close_range's flags. Both used to answer 0 for
# everything they were given.
run "mincore and close_range" "$IUL" -r "$ROOTFS" /tmp/mem_query

# setreuid/setregid and the saved set-user-ID. Each case forks, because a
# credential change cannot be undone once the privilege to undo it is gone.
run "credentials" "$IUL" -r "$ROOTFS" /tmp/cred_semantics

# What a credential change and an exec leave `dumpable` at, and who owns and
# may enter /proc/<pid> afterwards.
run "dumpable" "$IUL" -r "$ROOTFS" /tmp/dumpable_rules
# /proc/sys/fs/suid_dumpable: what a write is taken as, and what 0, 1 and 2
# leave a process at. It writes the value back.
run "fs.suid_dumpable" "$IUL" -r "$ROOTFS" /tmp/suid_dumpable
# Who may reach another process -- the ptrace rule with its two credential
# modes, the signal, scheduling, ioprio and prlimit rules -- and what
# /proc/<pid>/{io,personality,syscall,timerslack_ns,ns,map_files} report.
run "cross-process permissions" "$IUL" -r "$ROOTFS" /tmp/crossproc_rules

# POSIX permission resolution, on the two mounts where this kernel's own
# access_check is the answer. On a passthrough mount the host applies its
# permissions underneath, which masks the check rather than testing it.
run "permissions: tmpfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'mkdir -p /mnt/perm && mount -t tmpfs none /mnt/perm && /tmp/perm_semantics /mnt/perm'
run "permissions: fakefs" "$IUL" -f "$FAKEFS" /bin/sh -c \
    'rm -rf /tmp/perm; /tmp/perm_semantics /tmp/perm'

# Who may signal whom, and the sticky bit. Both need an unprivileged caller, so
# each forks and drops before asking.
run "signal permission" "$IUL" -r "$ROOTFS" /tmp/signal_perm
run "sticky bit: tmpfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /mnt/sticky; mkdir -p /mnt/sticky && mount -t tmpfs none /mnt/sticky && /tmp/sticky_dir /mnt/sticky'
run "sticky bit: fakefs" "$IUL" -f "$FAKEFS" /bin/sh -c \
    'rm -rf /tmp/sticky; /tmp/sticky_dir /tmp/sticky'

# What execve does to the credentials. fakefs only: on a passthrough mount the
# host owns the setuid bit and will not let a guest set one.
run "set-id exec" "$IUL" -f "$FAKEFS" /bin/sh -c 'rm -rf /tmp/setid; /tmp/setid_exec'

# Who may chmod and chown. The last group runs the escalation this closes:
# chown a binary to root, chmod it setuid, execute it.
run "setattr permission" "$IUL" -f "$FAKEFS" /bin/sh -c 'rm -rf /tmp/setattr; /tmp/setattr_perm'

# chroot, mount and umount2 need a capability, not a permission bit. The child
# does chroot last: if it succeeds -- which was the defect -- every later path
# resolves against a different root and the mount checks report the wrong errno.
run "privileged operations" "$IUL" -r "$ROOTFS" /tmp/priv_ops

# setpriority has two different refusals with two different errnos: EPERM for
# another user's process, EACCES for lowering a nice value.
run "priority permission" "$IUL" -r "$ROOTFS" /tmp/priority_perm

# capget reports the *target's* capability set, not the caller's. Only
# observable now that a guest process can hold an unprivileged uid.
run "capget across processes" "$IUL" -r "$ROOTFS" /tmp/cap_cross

# The five capability sets: capset, the capability prctls, what a uid change
# and an exec do to them, file capabilities, and one operation per capability
# with that capability dropped -- on both mounts. A set-user-ID-root program
# and chmod g+s need the mount to record the owner, which is fakefs.
run "capabilities: realfs" "$IUL" -r "$ROOTFS" /tmp/caps_rules
run "capabilities: fakefs" "$IUL" -f "$FAKEFS" /tmp/caps_rules
run "capabilities and set-id files: fakefs" "$IUL" -f "$FAKEFS" /tmp/caps_setid
# A write removes set-id bits and the file capability (file_remove_privs).
# fakefs: realfs cannot give a file to another user, and the host clears
# set-id bits on its own writes.
run "a write removes privileges: fakefs" "$IUL" -f "$FAKEFS" /tmp/killpriv
# O_TMPFILE and linkat naming it, on each mount type. realfs names it by a
# copy, so the inode is not asserted there.
run "O_TMPFILE: realfs" "$IUL" -r "$ROOTFS" /tmp/tmpfile /tmp/tmpfile-real realfs
run "O_TMPFILE: fakefs" "$IUL" -f "$FAKEFS" /tmp/tmpfile /tmp/tmpfile-fake
run "O_TMPFILE: tmpfs" "$IUL" -f "$FAKEFS" /tmp/tmpfile tmpfs
run "UTS namespaces" "$IUL" -r "$ROOTFS" /tmp/utsns

# Which id a newly created object is stamped with. Linux uses the fsuid, which
# tracks the effective uid; a pipe used the real one.
run "creation stamps the effective id" "$IUL" -r "$ROOTFS" /tmp/fsuid_stamp

# What one user can see of another's process through /proc. The mode in the
# entry table is the whole access policy, since the entries carry the task's uid.
run "proc visibility" "$IUL" -r "$ROOTFS" /tmp/proc_visibility

# Constant materialisation in every shape, written in inline assembly so the
# instruction sequences are the ones under test rather than whatever the
# compiler chose.
run "movz/movk shapes" "$IUL" -r "$ROOTFS" /tmp/movw_shapes

# A guest cannot reach outside the fakefs data/ directory. The bait goes beside
# data/ and outside the fakefs entirely; `ghost` is written into data/ *after*
# meta.db was built, so it exists on the host with no row -- which is the layer
# that actually contains a guest.
printf 'SHELLBOX-BAIT\n' > "$FAKEFS/secret_sibling"
printf 'SHELLBOX-BAIT\n' > "$HOST_SCRATCH/secret_outside"
printf 'SHELLBOX-BAIT\n' > "$FAKEFS/data/tmp/ghost"
run "fakefs containment" "$IUL" -f "$FAKEFS" /bin/sh -c \
    'rm -rf /tmp/containment; /tmp/fakefs_containment'

# Device nodes with a major or minor past the tables the kernel dispatches
# through. Against the fakefs, because a guest's mknod is only real there.
run "device node bounds" "$IUL" -f "$FAKEFS" /bin/sh -c '/tmp/dev_bounds'

# The address length getsockname reports for a unix socket: the name's, not the
# one the caller passed to bind. An abstract name keeps the caller's.
run "unix address length" "$IUL" -r "$ROOTFS" /tmp/unix_addrlen
# Cycles through the whole pid table, which is what makes a reused number
# reachable at all; about five seconds of thread churn.
run "a timer does not follow a reused tid" "$IUL" -r "$ROOTFS" /tmp/timer_pid_reuse
# Deadlocked the whole guest until 2026-09-16, so a failure here is a *timeout*
# rather than a failed check: pids_lock is kernel-wide, and the exit path waited
# for a timer under it while the timer's expiry waited for it. See
# docs/changelog/2026-09-16-the-exit-path-waited-for-a-timer-under-the-lock-the-timer-needed.md
run "exit while a timer is firing" "$IUL" -r "$ROOTFS" /tmp/timer_exit_race
run "POSIX shared memory and named semaphores through /dev/shm" "$IUL" -r "$ROOTFS" /tmp/shm_abi
# /proc/<pid>/fdinfo, and what anonymous descriptors report as mount and inode.
run "/proc/<pid>/fdinfo" "$IUL" -r "$ROOTFS" /tmp/fdinfo_abi
# The RWF_* flags a 7.x kernel takes, and where a write on O_APPEND lands.
run "preadv2 and pwritev2 flags" "$IUL" -r "$ROOTFS" /tmp/rwf_abi
# vmsplice, remap_file_pages, swapon/swapoff and quotactl/quotactl_fd.
run "vmsplice, remap_file_pages, swap and quota calls" "$IUL" -r "$ROOTFS" /tmp/rarecalls_abi

# A host process that connects to a guest's unix listener and sends nothing.
#
# A guest unix listener is a host socket at /tmp/iulsock<host pid>.<id>, which
# any process on the host can connect to. Two guest sockets find each other
# through a handshake over it, and `accept` used to read that handshake from
# every peer -- so a foreign one that sent nothing parked every later accept on
# the listener for ever. This is the only test that can reach that: the peer has
# to be outside the emulator's process, which no guest program is. It is driven
# from here because this script knows the emulator's pid and so where the host
# socket is; the program is tests/guest/src/bin/unix_foreign_peer.rs, and the
# order -- the host's connection first, the guest client's second -- is
# enforced by the program rather than by timing.
printf '\n########## unix socket: a silent foreign peer ##########\n'
if [ -n "${IUL_SIMULATOR:-}" ]; then
    # `$!` is simctl's pid, not the emulator's, so there is no host socket name
    # to look for. Set by tests/integration/simulator.sh.
    echo "  SKIP  the emulator's pid is not this script's to know on the simulator"
elif command -v nc >/dev/null 2>&1; then
    "$IUL" -r "$ROOTFS" /tmp/unix_foreign_peer >"$HOST_SCRATCH/run" 2>&1 &
    iul_pid=$!
    sock=""
    _waited=0
    while [ -z "$sock" ] && [ "$_waited" -lt 300 ]; do
        sock=$(ls /tmp/iulsock"$iul_pid".* 2>/dev/null | head -1)
        if [ -z "$sock" ]; then
            sleep 0.1
            _waited=$((_waited + 1))
        fi
    done
    if [ -z "$sock" ]; then
        kill -9 "$iul_pid" 2>/dev/null || true
        wait "$iul_pid" 2>/dev/null || true
        note_fail "unix socket: a silent foreign peer (no host socket appeared)" \
            "$(cat "$HOST_SCRATCH/run")"
    else
        # Connected, and silent for longer than the deadline below. `$!` is
        # nc's pid; the sleep ends on its own.
        sleep 60 | nc -U "$sock" >/dev/null 2>&1 &
        nc_pid=$!
        _waited=0
        rc=0
        while kill -0 "$iul_pid" 2>/dev/null; do
            if [ "$_waited" -ge 30 ]; then
                kill -9 "$iul_pid" 2>/dev/null || true
                rc=1
                break
            fi
            sleep 1
            _waited=$((_waited + 1))
        done
        wait "$iul_pid" 2>/dev/null || rc=$?
        kill "$nc_pid" 2>/dev/null || true
        out=$(cat "$HOST_SCRATCH/run")
        printf '%s\n' "$out"
        case "$out" in
            *"served after a silent peer: hello"*) [ "$rc" = 0 ] || note_fail "unix socket: a silent foreign peer" "$out" ;;
            *) note_fail "unix socket: a silent foreign peer" "$out (the silent peer held accept: status $rc)" ;;
        esac
    fi
else
    printf '  skipped: no nc(1) on the host to be the foreign peer\n'
fi

# A reader of an inotify descriptor against threads generating events.
# inotify_read and inotify_notify_path took fd->lock and inotify_lock in
# opposite orders; this hung on the first attempt.
run "inotify lock order" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/inodl; /tmp/inotify_deadlock /tmp/inodl 3'

# Signal delivery against a reader of /proc/<pid>/stat. receive_signals holds
# sighand->lock and takes group->lock under it; the snapshot took them the other
# way. pids_lock does not serialise them -- the signal path never takes it.
run "signal vs proc lock order" "$IUL" -r "$ROOTFS" /tmp/signal_proc_deadlock 3

# Job control: an orphaned background process group reading from its
# controlling terminal must get EIO, not SIGTTIN -- stopping it is a hang,
# because nothing is left that would continue it.
run "tty job control" "$IUL" -r "$ROOTFS" /tmp/tty_jobctl

# rlimit, prlimit and the cpu-time accounting behind getrusage/times. Several of
# these read a *delta* over a child that burns cpu, so they need a real process
# and cannot be a unit test.
# What a reaped child's CPU time is credited to. abi_structs checks that
# getrusage and times answer and that the structs are the right shape, which
# passes against an implementation that always says zero.
run "a reaped child's time is credited to its parent" "$IUL" -r "$ROOTFS" /tmp/rusage_children
run "resource abi" "$IUL" -r "$ROOTFS" /tmp/resource_abi

# Sleeps, itimers and alarm. The sleep checks are wall-clock lower bounds -- a
# sleep that does not sleep is only visible as elapsed time -- so this one is
# slower than the rest and cannot be a unit test.
run "time abi" "$IUL" -r "$ROOTFS" /tmp/time_abi
# adjtimex and clock_adjtime (read-only, and every setting mode refused in
# Linux's order), the clock ids each clock syscall takes, and a process CPU
# clock that counts running sibling threads.
run "adjtimex and the clock ids" "$IUL" -r "$ROOTFS" /tmp/adjtime_abi

# The memory syscalls' lengths are size_t. Several were declared 32-bit, and a
# truncated mremap length turned a grow into a shrink that unmapped live pages
# and reported success.
run "mm abi" "$IUL" -r "$ROOTFS" /tmp/mm_abi

# read/write counts, and what happens when one runs off the end of its buffer.
# A count larger than the mapping used to reach a PROT_NONE guard page, which
# mem_ptr handed out a pointer to -- taking the emulator down, not the guest.
run "read/write abi" "$IUL" -r "$ROOTFS" /tmp/rw_abi

# PROT_NONE, and what a fault on an absent page does. Both were answered with
# zero rather than a signal: the fault handler decoded the load, cleared its
# destination register and advanced the PC, for every read fault there was.
run "prot none" "$IUL" -r "$ROOTFS" /tmp/prot_none

# sigsetsize: Linux requires exactly sizeof(sigset_t). This accepted any
# multiple of 8, so a guest passing 16 or 128 was told its mask had been set.
run "sigset size" "$IUL" -r "$ROOTFS" /tmp/sigset_size

# ptrace register access. GETREGS is an x86 request and was implemented here
# against the i386 struct by accessors that returned zeroes; GETREGSET, which
# is what an aarch64 debugger uses, did not exist.
run "ptrace registers" "$IUL" -r "$ROOTFS" /tmp/ptrace_regs

# PTRACE_SETOPTIONS and the two event stops. strace sets TRACESYSGOOD |
# TRACEEXEC | TRACEEXIT in one call and detaches on an EINVAL, so refusing the
# word cost the whole tool; and a peek was four bytes, i386's, so every second
# half of every string a tracer read was skipped.
run "ptrace options and event stops" "$IUL" -r "$ROOTFS" /tmp/ptrace_events

# System V semaphores. All four calls were syscall_stub, so `ipcs -s` said the
# kernel was not configured for them. The probe beside this covers the answer
# table; what is checked here is what needs two processes -- blocking, waking,
# a batch that must take both or neither, and SEM_UNDO.
run "System V semaphores" "$IUL" -r "$ROOTFS" /tmp/sysvsem

# System V message queues, the other half of what `ipcs` reported. The probe
# beside this covers the type selector's answer table; what is checked here is
# a receiver parking on a type, a send that is not for it, and a full queue.
run "System V message queues" "$IUL" -r "$ROOTFS" /tmp/sysvmsg

# POSIX message queues. All six calls were syscall_stub. The probe covers the
# answer table; what is checked here needs a second thread or process:
# blocking and deadlines, EINTR and SA_RESTART, poll/epoll wakeups, mq_notify
# by signal and through musl's SIGEV_THREAD, the owner's close dropping a
# registration, and producers and consumers across a fork.
run "POSIX message queues" "$IUL" -r "$ROOTFS" /tmp/mqueue_abi

# The syscall dispatcher skipped the x0 writeback for 139 and 119, the second
# commented "sigreturn" -- which is its i386 number. On aarch64 119 is
# sched_setscheduler, so its result never reached the guest.
run "sched_setscheduler return" "$IUL" -r "$ROOTFS" /tmp/sched_ret

# Crafted ELF files whose segments do not fit the guest address space. This one
# is *expected* to print illegal-instruction reports and a register dump: one of
# its cases is an image that must be loaded and then dies on a garbage entry
# point, which is exactly what that report is for.
run "elf bounds" "$IUL" -r "$ROOTFS" /tmp/elf_bounds

# The poll bits that are not POLLIN/POLLOUT. POLL_* here are the guest's own
# values used directly, so there is no translation step -- and nowhere an
# unknown bit gets noticed either.
run "poll events" "$IUL" -r "$ROOTFS" /tmp/poll_events

# A null dereference raises SIGSEGV wherever the code lives. The fault handler
# carried a recovery gated on PC ranges from one node build, and those are
# addresses rather than identities.
run "fault recovery" "$IUL" -r "$ROOTFS" /tmp/fault_recovery

# Run under macOS's own default -- soft 256, hard unlimited -- because that is
# the condition the fix is for, and a developer shell has usually raised the
# soft limit already. `ulimit -Sn`, not `ulimit -n`: the latter sets the hard
# limit too, and then nothing can raise it back and the test proves nothing.
run "descriptor limit" sh -c \
    "ulimit -Sn 256; exec '$IUL' -r '$ROOTFS' /tmp/fd_limit"

# /proc/<pid>/status, which did not exist. Every check compares a field against
# something the guest can ask for directly, so a formatter that is internally
# consistent and wrong does not pass.
run "proc status" "$IUL" -r "$ROOTFS" /bin/sh -c 'mkdir -p /mnt; exec /tmp/proc_status'
run "proc status signal masks" "$IUL" -r "$ROOTFS" /tmp/proc_sigmask
run "rt_sigprocmask and rt_sigaction at the syscall boundary" "$IUL" -r "$ROOTFS" /tmp/signal_abi
run "nanosleep and clock_nanosleep at the syscall boundary" "$IUL" -r "$ROOTFS" /tmp/sleep_abi
run "the auxiliary vector and the block it sits in" "$IUL" -r "$ROOTFS" /tmp/auxv_abi
# AT_HWCAP, AT_HWCAP2, the ID registers and /proc/cpuinfo describe one CPU.
run "hwcap, ID registers and cpuinfo agree" "$IUL" -r "$ROOTFS" /tmp/hwcap_agree
# The instructions of the features beyond ARMv8.0, as one hash per group
# recorded from a real arm64 kernel.
run "instructions of the newer CPU features" "$IUL" -r "$ROOTFS" /tmp/insn_features
# Store buffering through STLR/LDAR and the other release/acquire pairs: the
# forbidden outcome must never occur (0 of N, as on a real arm64 kernel).
run "memory ordering litmus" "$IUL" -r "$ROOTFS" /tmp/ordering_litmus
# PSTATE.DIT across signals, fork and exec; DC CVAP/CVADP against DC CVAU.
run "DIT and the persistence cache operations" "$IUL" -r "$ROOTFS" /tmp/dit_dcpop
run "RNDR is an illegal instruction without FEAT_RNG" "$IUL" -r "$ROOTFS" /tmp/rndr_undefined
run "a pc or address above the address space faults there" "$IUL" -r "$ROOTFS" /tmp/bad_pc_addr
run "the shebang line and the end of the kernel's buffer" "$IUL" -r "$ROOTFS" /tmp/shebang_abi

# A terminal that reports itself writable has to accept a write. tty_poll set
# POLL_WRITE unconditionally, under a comment saying it was wrong.
run "tty pollout" "$IUL" -r "$ROOTFS" /tmp/tty_pollout

# File modes at creation, on all three mounts for the same reason
# fs_conformance runs three times: fakefs reports the mode it stored in meta.db
# and realfs reports the host's, so only one of them can see a host umask
# leaking in.
run "umask: realfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    "rm -rf /tmp/um-real; mkdir -p /tmp/um-real; /tmp/umask_modes /tmp/um-real"
run "umask: fakefs" "$IUL" -f "$FAKEFS" /bin/sh -c \
    "rm -rf /tmp/um-fake; mkdir -p /tmp/um-fake; /tmp/umask_modes /tmp/um-fake"
run "umask: tmpfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    "mkdir -p /mnt/um && mount -t tmpfs none /mnt/um && /tmp/umask_modes /mnt/um"

# Passing descriptors over a unix socket. The wire format was the i386 one, so
# this reported success and passed nothing -- and once it started working, the
# send path's wait for a peer turned into a hang. sock_race sent descriptors
# this way throughout and never checked that any arrived.
run "descriptor passing" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/fdpass; /tmp/fd_passing /tmp/fdpass'

# Timestamps, access checks, filesystem statistics and the rename flags -- what
# a build system compares to decide what to rebuild, and what an atomic write
# depends on. Three mounts: each keeps its timestamps somewhere different.
run "file metadata: realfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/fsmeta; /tmp/fs_metadata /tmp/fsmeta'
run "file metadata: fakefs" "$IUL" -f "$FAKEFS" /bin/sh -c \
    'rm -rf /tmp/fsmeta; /tmp/fs_metadata /tmp/fsmeta'
run "file metadata: tmpfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'mkdir -p /mnt/fsm && mount -t tmpfs none /mnt/fsm && /tmp/fs_metadata /mnt/fsm'
# Twice, for the same reason wait_semantics runs twice: `sh -c` execs the last
# command, so the test is pid 1 and a subreaper cannot be told from init.
# `wait $!`, not `wait`: a bare `wait` answers 0 whatever the job did, so
# until 2026-11-13 the four `& wait` runs here could not fail.
run "process attributes (as pid 1)" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/pattrs; /tmp/proc_attrs /tmp/pattrs'
run "process attributes (not pid 1)" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/pattrs; /tmp/proc_attrs /tmp/pattrs & wait $!'
run "execve and #!" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/es; /tmp/exec_semantics --run-tests /tmp/es'
# execve from a process with more than one thread: the others end and the pid
# moves to the exec'ing thread (Linux's de_thread). On fakefs too, because the
# program the exec opens is reached through the mount. The stress alternates
# an exec from the leader and from another thread while five threads park in
# read, futex, nanosleep, epoll_wait and accept and one spins; a hang there is
# the failure, which TEST_TIMEOUT turns into one.
run "execve from a threaded process: realfs" "$IUL" -r "$ROOTFS" /tmp/exec_threads
run "execve from a threaded process: fakefs" "$IUL" -f "$FAKEFS" /tmp/exec_threads
run "execve ending parked and spinning threads, 200 rounds" "$IUL" -r "$ROOTFS" /tmp/exec_threads --stress 200
# A fatal signal ends the process when it is sent (Linux's complete_signal):
# the status is the signal whatever the process does next, and an execve in
# progress loses. Twice: as pid 1, which ignores what it has not caught, and
# with a shell in between. The stress races SIGTERM against a thread's exec;
# every round has its own 10 s limit, so a hang is a failure.
run "fatal signals at send time (as pid 1)" "$IUL" -r "$ROOTFS" /tmp/signal_fatal
run "fatal signals at send time (not pid 1)" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/signal_fatal & wait $!'
run "execve against SIGTERM, 1000 rounds" "$IUL" -r "$ROOTFS" /tmp/signal_fatal --stress 1000
# Twice: as pid 1, where an orphan is reparented to the test itself, and with a
# shell in between, where it is not. The two take different branches.
run "wait and exit (as pid 1)" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/wait_semantics'
run "wait and exit (not pid 1)" "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/wait_semantics & wait $!'
# The fixes that had a user-visible symptom, pinned. tests/regress/run.sh's
# compiled half until 2026-09-09, where it needed a cross-compiler that is
# usually not installed -- so it skipped, with status 0, on most machines.
# Not as pid 1: several cases fork and want an ordinary parent.
run "regressions with a symptom" "$IUL" -r "$ROOTFS" /bin/sh -c \
    '/tmp/regress_syscall & wait $!'
# The AdvSIMD lane conversions, which nothing else exercises: the gadgets they
# cover are only reachable by executing guest code.
run "AdvSIMD FCVT conversions" "$IUL" -r "$ROOTFS" /tmp/asimd_fcvt
# The vDSO, which nothing checked: every binary in this rootfs is static musl
# and never reads it, so replacing the image with zero bytes changed no test's
# answer. This one walks it the way a libc does and calls what it finds.
run "the vDSO's symbols" "$IUL" -r "$ROOTFS" /tmp/vdso_symbols
# One set of lock assertions against each mount type, for the same reason
# fs_conformance runs three times: three unrelated implementations of one
# interface, so a check that passes on two and fails on the third is a bug in
# the third.
run "file locks: realfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'rm -rf /tmp/lk-real; /tmp/file_locks /tmp/lk-real'
run "file locks: fakefs" "$IUL" -f "$FAKEFS" /bin/sh -c \
    'rm -rf /tmp/lk-fake; /tmp/file_locks /tmp/lk-fake'
run "file locks: tmpfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    'mkdir -p /mnt/lk && mount -t tmpfs none /mnt/lk && /tmp/file_locks /mnt/lk'

# Its own step because it asserts the emulator is still alive rather than
# counting checks.
printf '\n########## chdir race ##########\n'
if out="$(bounded "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/fs_race' 2>&1)" && \
   [ "$(printf '%s' "$out" | tail -1)" = "survived" ]; then
    echo "  PASS  path resolution survived concurrent chdir"
else
    note_fail "path resolution did not survive concurrent chdir" "$out"
    echo "  FAIL  path resolution did not survive concurrent chdir"
    printf '%s\n' "$out" | tail -5 | sed 's/^/        | /'
fi

# Same shape: one thread mounts and unmounts while others read /proc/mounts
# and rmdir. Both traversals used to run without mounts_lock, and this took
# the emulator down in three runs out of three.
printf '\n########## mount race ##########\n'
if out="$(bounded "$IUL" -r "$ROOTFS" /bin/sh -c 'mkdir -p /mnt; /tmp/mount_race 3' 2>&1)" && \
   [ "$(printf '%s' "$out" | tail -1)" = "survived" ]; then
    echo "  PASS  the mount list survived concurrent mount and umount"
else
    note_fail "the mount list did not survive concurrent mount and umount" "$out"
    echo "  FAIL  the mount list did not survive concurrent mount and umount"
    printf '%s\n' "$out" | tail -5 | sed 's/^/        | /'
fi

# The descriptor table from seven threads at once: opening, closing,
# duplicating every way there is to, and setting close-on-exec throughout. Any
# LOST line is a descriptor number that stopped being its owner's.
printf '\n########## fd table race ##########\n'
if out="$(bounded "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/fd_race 3' 2>&1)" && \
   [ "$(printf '%s' "$out" | tail -1)" = "survived" ] && \
   ! printf '%s' "$out" | grep -q LOST; then
    echo "  PASS  the descriptor table survived concurrent dup and close"
else
    note_fail "the descriptor table did not survive concurrent dup and close" "$out"
    echo "  FAIL  the descriptor table did not survive concurrent dup and close"
    printf '%s\n' "$out" | tail -5 | sed 's/^/        | /'
fi

# Task lifetime: forking, execing, exiting a group from a non-leader thread and
# signalling, while another thread reads /proc over the top. Any LOST line is a
# child that was not reaped as itself.
# /proc/<pid>/fd read for a process that is exiting. do_exit released the
# descriptor table before it set `exiting`, and without the lock the reader
# holds -- so a reader could retain a table being freed, or read the pointer as
# NULL just after it was cleared. It crashed at address zero in getdents64.
printf '\n########## proc fd race ##########\n'
if out="$(bounded "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/proc_fd_race 2' 2>&1)" && \
   [ "$(printf '%s' "$out" | tail -1)" = "survived" ]; then
    echo "  PASS  /proc/<pid>/fd survived concurrent process exit"
else
    note_fail "/proc/<pid>/fd did not survive concurrent process exit" "$out"
    echo "  FAIL  /proc/<pid>/fd did not survive concurrent process exit"
    printf '%s\n' "$out" | tail -6 | sed 's/^/        | /'
fi

# Two threads reading one procfs descriptor. `sys_read` holds no `fd->lock`
# and procfs's `read` falls through to `pread`, so `state(fd)` handed out two
# live `&mut ProcFd` and both threads cleared and refilled one `Vec`. It
# panicked inside a syscall shim -- which aborts -- with a slice range twice
# the length of the buffer.
printf '\n########## two threads on one procfs descriptor ##########\n'
if out="$(bounded "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/proc_read_race 5000' 2>&1)" && \
   [ "$(printf '%s' "$out" | tail -1)" = "survived" ]; then
    echo "  PASS  a procfs descriptor survived two readers"
else
    note_fail "two threads reading one procfs descriptor took the emulator down" "$out"
    echo "  FAIL  two threads reading one procfs descriptor took the emulator down"
    printf '%s\n' "$out" | tail -6 | sed 's/^/        | /'
fi

# Two threads mutating one socket's state. `SocketState` was reached through a
# `&mut` with a lifetime the caller chose, and no socket syscall takes a lock,
# so `bind` tested "has this socket a name?" and took one with a second thread
# free to run between the two: both claimed, the loser's claim went over the
# winner's, and the winner's name was never released. Its own count is the
# check -- a name a closed socket still holds is otherwise invisible.
printf '\n########## two threads binding one socket ##########\n'
if out="$(bounded "$IUL" -r "$ROOTFS" /tmp/sock_state_race 400 2>&1)" && \
   [ "$(printf '%s' "$out" | tail -1)" = "survived" ]; then
    echo "  PASS  a socket survived two threads binding it"
else
    note_fail "two threads binding one socket leaked its address" "$out"
    echo "  FAIL  two threads binding one socket leaked its address"
    printf '%s\n' "$out" | tail -6 | sed 's/^/        | /'
fi

printf '\n########## a thread signalled as it starts ##########\n'
if out="$(bounded "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/thread_start_signal 300' 2>&1)" && \
   printf '%s' "$out" | grep -q survived; then
    echo "  PASS  threads started under a signal storm"
else
    note_fail "a thread signalled as it starts took the emulator down" "$out"
    echo "  FAIL  a thread signalled as it starts took the emulator down"
    printf '%s\n' "$out" | tail -6 | sed 's/^/        | /'
fi

printf '\n########## task lifetime race ##########\n'
if out="$(bounded "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/task_race 3' 2>&1)" && \
   [ "$(printf '%s' "$out" | tail -1)" = "survived" ] && \
   ! printf '%s' "$out" | grep -q LOST; then
    echo "  PASS  task lifetime survived concurrent fork, exec and /proc"
else
    note_fail "task lifetime did not survive concurrent fork, exec and /proc" "$out"
    echo "  FAIL  task lifetime did not survive concurrent fork, exec and /proc"
    printf '%s\n' "$out" | tail -6 | sed 's/^/        | /'
fi

# Exiting a group while threads are stuck in an uninterruptible host syscall:
# the path the safety valve exists for, which hands their address space,
# descriptor table and signal dispositions to their own pthread cleanup. Each
# round waits for the valve's timeout, so the count is small.
#
# **IUL_EXEC_TRACE=1, and how many rounds reached the valve is printed**, since
# 2026-09-12. Two different claims were being made by one check:
#
#   - a group exit with threads in blocking syscalls completes and reports the
#     right status. True, checked, and what pass/fail is about.
#   - it exercises `abandon_stuck_threads`. **Measured on 2026-09-12 over 40
#     rounds: it does not, ever.** The valve runs only when a thread has not
#     reported in after ~520 ms and three rounds of `SIGUSR1`, and the
#     emulator's own `SIGUSR1` handler carries no `SA_RESTART` on purpose — so
#     every host syscall it lands in returns `EINTR` and the thread leaves.
#
# The count is printed rather than asserted, because a gate that is
# permanently red is read as often as one that is permanently green, and the
# thing it would be red about is the absence of a workload nobody has written.
# See docs/changelog/2026-09-12-the-safety-valve-test-never-reaches-the-valve.md
# and `exit_stuck.rs`'s own comment.
printf '\n########## group exit with stuck threads ##########\n'
if out="$(bounded env IUL_EXEC_TRACE=1 "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/exit_stuck 6' 2>&1)" && \
   [ "$(printf '%s' "$out" | grep -v '^SAFETY-VALVE' | tail -1)" = "survived" ] && \
   ! printf '%s' "$out" | grep -q LOST; then
    n="$(printf '%s' "$out" | grep -cE 'leaked [1-9][0-9]* stuck host threads' || true)"
    echo "  PASS  group exit completed with threads stuck in host syscalls"
    if [ "$n" -eq 0 ]; then
        echo "        | valve rounds: 0 -- abandon_stuck_threads did not run, so"
        echo "        | nothing here covers it. Not a failure; see the changelog."
    else
        echo "        | valve rounds: $n"
    fi
else
    note_fail "group exit with stuck threads" "$out"
    echo "  FAIL  group exit with stuck threads"
    printf '%s\n' "$out" | tail -6 | sed 's/^/        | /'
fi

# Signals from several threads: delivering, replacing handlers under delivery,
# blocking and unblocking, and taking them inside blocking syscalls. A LOST
# line is a handler that ran for the wrong signal or while it was blocked.
printf '\n########## signal race ##########\n'
if out="$(bounded "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/signal_race 3' 2>&1)" && \
   [ "$(printf '%s' "$out" | tail -1)" = "survived" ] && \
   ! printf '%s' "$out" | grep -q LOST; then
    echo "  PASS  signals survived concurrent delivery and handler changes"
else
    note_fail "signals did not survive concurrent delivery and handler changes" "$out"
    echo "  FAIL  signals did not survive concurrent delivery and handler changes"
    printf '%s\n' "$out" | tail -6 | sed 's/^/        | /'
fi

# Unix sockets from several threads: connecting and accepting on one listener,
# passing descriptors over SCM_RIGHTS, and closing out from under peers. A LOST
# line is a passed descriptor that arrived pointing at the wrong file.
printf '\n########## unix socket race ##########\n'
printf '\n########## pty race ##########\n'
if out="$(bounded "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/tty_race 3' 2>&1)" && \
   [ "$(printf '%s' "$out" | tail -1)" = "survived" ] && \
   ! printf '%s' "$out" | grep -q LOST; then
    echo "  PASS  a pty survived concurrent termios ioctls and writes"
else
    note_fail "pty race" "$out"
    echo "  FAIL  pty race"
    printf '%s\n' "$out" | tail -6 | sed 's/^/        | /'
fi

printf '\n########## address space race ##########\n'
if out="$(bounded "$IUL" -r "$ROOTFS" /bin/sh -c '/tmp/mmap_race 3' 2>&1)" && \
   [ "$(printf '%s' "$out" | tail -1)" = "survived" ] && \
   ! printf '%s' "$out" | grep -q LOST; then
    echo "  PASS  the page table survived concurrent mmap, mremap and mprotect"
else
    note_fail "address space race" "$out"
    echo "  FAIL  address space race"
    printf '%s\n' "$out" | tail -6 | sed 's/^/        | /'
fi

# Creating a thread while others are running. Not a race probe like the ones
# above: a *deadline*. The JIT holds the address-space read lock across a
# quantum and mmap cannot block for it, so a quantum that never ends starves
# every pthread_create in the process -- which is what happened until
# 2026-08-29, at over twenty seconds for one spawn. Four background threads and
# five spawns is under 10 ms; the binary fails itself above two seconds.
run "creating a thread while four others run" "$IUL" -r "$ROOTFS" /tmp/thread_spawn 4 5

# A failed pipe2 must not close somebody else's descriptor. Eight threads
# opening files against one calling pipe2 with an unmapped address: the error
# path used to close host descriptors the struct fds already owned, and the
# second close landed on whatever had been opened at that number since.
run "a failed pipe2 keeps its hands off other descriptors" "$IUL" -r "$ROOTFS" /tmp/pipe_badaddr

# syslog(2) must not write past what it read. The log is a megabyte and the
# read was clamped to its capacity rather than its contents, so a guest could
# ask for the lot and be handed the emulator's heap.
run "syslog reads no more than the log holds" "$IUL" -r "$ROOTFS" /tmp/syslog_abi

run "prctl remembers what it is told" "$IUL" -r "$ROOTFS" /tmp/prctl_abi
run "personality accepts and returns the old one" "$IUL" -r "$ROOTFS" /tmp/personality_abi

run "a thread is not a child" "$IUL" -r "$ROOTFS" /tmp/thread_exit
run "a vfork parent outlives its child's task" "$IUL" -r "$ROOTFS" /tmp/vfork_race
run "a stop and a continue reach a waiting parent" "$IUL" -r "$ROOTFS" /tmp/wait_stop_cont

# Registered on 2026-08-29. It was written, built and copied into the rootfs on
# every run, and executed by nothing -- the staging list and the run list were
# separate, and it made it into only one of them.
run "clone3's extensible argument struct" "$IUL" -r "$ROOTFS" /tmp/clone3_abi
run "pidfds: PIDFD_THREAD, PIDFD_NONBLOCK, pidfd_getfd, PIDFD_GET_INFO" "$IUL" -r "$ROOTFS" /tmp/pidfd_semantics
run "kcmp, sched_setattr, unshare, seccomp and the LSM list" "$IUL" -r "$ROOTFS" /tmp/procsec_semantics
run "a multithreaded process exits promptly" "$IUL" -r "$ROOTFS" /tmp/exit_latency
run "mprotect over a mixed range" "$IUL" -r "$ROOTFS" /tmp/mprotect_runs
run "mseal, guard pages, fork dispositions and process_madvise" "$IUL" -r "$ROOTFS" /tmp/mm_seal_guard
run "mprotect does not cost per page" "$IUL" -r "$ROOTFS" /tmp/mprotect_scaling
# Where mprotect stops and what a page past the end of its file raises, on
# both mounts a file mapping can come from (and a memfd, in each run).
run "mprotect partway, and pages past the end of a file: realfs" "$IUL" -r "$ROOTFS" /tmp/mm_partial /tmp
run "mprotect partway, and pages past the end of a file: fakefs" "$IUL" -f "$FAKEFS" /tmp/mm_partial /tmp
run "file mappings follow the file, and tmpfs files map: realfs" "$IUL" -r "$ROOTFS" /tmp/mm_file_follow /tmp
run "file mappings follow the file, and tmpfs files map: fakefs" "$IUL" -f "$FAKEFS" /tmp/mm_file_follow /tmp
run "setfsuid and setfsgid" "$IUL" -r "$ROOTFS" /tmp/fsuid_abi
run "changing a directory needs write permission on it" "$IUL" -r "$ROOTFS" /tmp/dir_write_perm
run "hardlinks, the sticky bit and a file just created" "$IUL" -r "$ROOTFS" /tmp/perm_rules
run "O_PATH names a file without opening it" "$IUL" -r "$ROOTFS" /tmp/o_path

# Two runs of one file. The first asks for the idle-exit valve and checks that
# it does what it says; the second asks for nothing and checks that a process
# which is only waiting is left alone -- and has to outlast the sixty seconds
# that valve used to be set to, or it would pass against it.
run "the idle-exit valve, when asked for" env IUL_IDLE_EXIT=3 "$IUL" -r "$ROOTFS" /tmp/idle_wait killed
run "a process that only waits is not killed for it" "$IUL" -r "$ROOTFS" /tmp/idle_wait alive

# What a *file* is stamped with, which is the filesystem's answer rather than
# the kernel's -- fakefs stamped the effective ids at all four of its creation
# sites where tmpfs asked for the filesystem ones, so the two mounts answered
# the same call differently. realfs is not asked: it reports the host's
# ownership, so the only id it can give is the host user's, which is neither of
# the two this is about.
run "what a file is stamped with: fakefs" "$IUL" -f "$FAKEFS" /tmp/fsuid_stamp /tmp/stamp-fake
run "what a file is stamped with: tmpfs" "$IUL" -r "$ROOTFS" /bin/sh -c \
    "mkdir -p /mnt/stamp && mount -t tmpfs none /mnt/stamp && /tmp/fsuid_stamp /mnt/stamp/d"
run "the syscalls answered without being implemented" "$IUL" -r "$ROOTFS" /tmp/misc_abi

if out="$(bounded "$IUL" -r "$ROOTFS" /bin/sh -c 'rm -rf /tmp/sockrace; /tmp/sock_race 3 /tmp/sockrace' 2>&1)" && \
   [ "$(printf '%s' "$out" | tail -1)" = "survived" ] && \
   ! printf '%s' "$out" | grep -q LOST; then
    echo "  PASS  unix sockets survived concurrent connect, accept and fd passing"
else
    note_fail "unix sockets did not survive concurrent connect, accept and fd passing" "$out"
    echo "  FAIL  unix sockets did not survive concurrent connect, accept and fd passing"
    printf '%s\n' "$out" | tail -6 | sed 's/^/        | /'
fi

echo
if [ "$fail" = 0 ]; then
    echo "guest tests: all passed"
    exit 0
fi
echo "guest tests: $fail FAILED"
if [ -n "$failed_names" ]; then
    printf 'failed:%s\n' "$failed_names"
fi
echo "their output: $FAILLOG"
exit 1
