#!/bin/sh
# Run the guest tests against a real Linux kernel as well as against the
# emulator, and report where the two disagree.
#
# The guest tests are static `aarch64-unknown-linux-musl` binaries, and an
# Apple Silicon machine runs arm64 Linux containers natively — so the *same*
# binary can be given a real kernel with no cross-compilation and no emulation
# in between. That makes "what does Linux actually do here" a thing the machine
# answers instead of something to be looked up.
#
# What it is for, in order of what it has actually caught:
#
#   1. **Assertions that are wrong about Linux.** A test that passes here and
#      fails on Linux is asserting emulator behaviour as if it were the ABI —
#      and would reject a correct fix later. The first run found two.
#   2. **Gaps.** A test that passes on Linux and fails here is a real
#      difference, and the failure text names it.
#   3. Neither: a test about something a container does not have (a pty it
#      controls, /proc/1 being this kernel's init, a mount it may perform).
#      Those go in `not_comparable()` below, with the reason. A test that is
#      worth comparing and has *one* line that cannot agree goes in KNOWN
#      instead, which costs the rest of that program nothing.
#
# Usage:  tests/integration/differential.sh [test ...]
#         (no arguments: every comparable test)
#
# ## Exit codes, and the argument this file used to make against having any
#
# Until 2026-09-12 it **reported and did not gate**: a disagreement was printed
# and counted and the exit status was 0 regardless, so nothing that ran this
# could fail on one and a regression in guest-visible behaviour passed it in
# silence. The argument written here for that is worth keeping, because it is
# right about everything except the conclusion:
#
#   - probe_diff.sh compares against a **recording**, so its two sides are
#     deterministic and a difference is a change somebody made. This runs a
#     container per test, live, and several of its 95 subjects are timing- or
#     scheduling-dependent on the Linux side.
#   - the answer to a disagreement here is a judgement — five of the first nine
#     were defects in the *tests* — and a gate that wants a judgement is a gate
#     that gets clicked through.
#
# It also said what would settle it: "evidence that a full sweep is
# deterministic, and **one clean sweep is not it** ... Several sweeps, or a
# named list of the subjects that can move on their own." Both halves are here
# now. Six consecutive full sweeps on 2026-09-12 each reported 95 compared and
# 0 disagree, against one build and one rootfs, run one at a time so that the
# load of one sweep is not an input to the next. And KNOWN below **is** the
# named list, with probe_diff.sh's discipline — which is the answer to the
# second objection rather than a dodge of it: a disagreement somebody has judged
# is written down *with the judgement*, and one that is not written down is the
# run going red. A gate that gets clicked through is one whose output is a
# number; this one's is a sentence somebody had to write.
#
#   0  every comparable test agrees, or its disagreement is in KNOWN, and every
#      KNOWN entry fired
#   1  a disagreement that is not in KNOWN                          <- the gate
#   2  a setup error: no docker, no binary, nothing compared, an option, a name
#      that is not a test, stale build output, a stale `not_comparable()` entry
#   3  every disagreement is explained, but a KNOWN entry suppressed nothing
#
# The four codes, and the order they are decided in, are probe_diff.sh's, and
# the order is there for a reason this script would otherwise have repeated: in
# that script the stale-entry check once ran **first** and exited before the
# comparison's own verdict was printed, so a single entry nobody could explain
# made the whole thing red and hid the findings behind it. A permanently red
# gate is read exactly as often as a permanently green one, which is never. So
# everything is printed first and the verdict is chosen last.
#
# **Six sweeps is six data points and not a proof**, and this tree has a
# changelog entry about a bisect run over a test nobody had shown was
# deterministic. What a flake costs here is a red run that *names its subject*,
# which is diagnosable and re-runnable; what the old behaviour cost is a
# regression nobody sees, which is neither. When a subject does turn out to move
# on its own the answer is an entry in KNOWN saying so, or in OBSERVING when the
# reason it moves is not established.
#
# ## What it still cannot see
#
# The comparison is over *failing* check names and the *number* of checks,
# because the harness prints a line per failure and a count, and nothing names a
# check that passed. So a test that runs a different N checks on each side with
# the same N and no failures on either reads as agreement. The count is what
# catches the realistic form of that — `renameat2` skipped seven checks on one
# side — and this residue is stated rather than papered over: closing it means
# the harness printing every check's name, which is a change to 215 programs'
# output and to every recorded probe baseline.
set -u

BINDIR="tests/guest/target/aarch64-unknown-linux-musl/release"
# Whether the caller named one, recorded before the default is applied: the
# staleness check below treats "you chose this" and "the script chose this"
# differently, and comparing against the default's *path* would read a caller
# who named that path as not having chosen it.
IUL_GIVEN=${IUL:+1}
IUL_GIVEN=${IUL_GIVEN:-0}
# `build-release/`, which is what `tools/build-all.sh` and `CLAUDE.md` name.
# It was `build-arm64-release/` -- the meson directory, which nothing has
# written since 2026-09-11 -- until 2026-09-16; see the note in `smoke.sh`,
# where the same default ran a week-old emulator all session.
IUL="${IUL:-build-release/iul}"
ROOTFS="${ROOTFS:-build/integration/alpine}"
IMAGE="${IMAGE:-alpine:3.20}"

# The arguments, before anything about the environment: "you asked for something
# that does not exist" is the caller's answer and "there is no docker daemon" is
# the machine's, and a run that is wrong in both ways should say the first.
#
# An option is refused by name rather than left to fail as a test name, because
# the two sibling scripts *do* take `-i` and `-r` and the message
# "no such test: -i" is a worse answer than saying so. The binary and the rootfs
# are `IUL=` and `ROOTFS=` here.
for a in "$@"; do
    case "$a" in
        -h|--help)
            echo "usage: $0 [test ...]      (no arguments: every comparable test)"
            echo "  IUL=<path>     the emulator to compare      (default build-release/iul)"
            echo "  ROOTFS=<path>  the guest root it is given   (default build/integration/alpine)"
            echo "  IMAGE=<image>  the container to compare with (default alpine:3.20)"
            echo "  TIMEOUT=<s>    deadline per run             (default 60)"
            echo "  IUL_NO_BUILD=1 do not rebuild first"
            exit 0 ;;
        -*)
            echo "differential: unknown option $a; it takes test names, not flags" >&2
            echo "  the binary and the rootfs are IUL= and ROOTFS= here" >&2
            exit 2 ;;
    esac
done

# No docker is a setup error and not a skip, since 2026-09-12.
#
# It exited 0 and said "skipping", which was consistent while nothing read the
# status and is not now: without a container nothing is compared, and this
# script already refuses to call that agreement at the bottom ("Nothing compared
# is not agreement"). The two answers have to be the same one. probe_diff.sh
# *does* exit 0 without docker and is right to, because it has a --recorded mode
# that is the gate; there is no recorded mode here, so there is nothing left to
# have run.
#
# Docker on this machine is OrbStack: `orb start` revives it.
if ! docker info >/dev/null 2>&1; then
    echo "differential: no docker daemon, so there is nothing to compare against" >&2
    echo "  (OrbStack: orb start)" >&2
    exit 2
fi
# Built before it is used, not assumed to be current.
#
# This ran three sweeps against a binary from before the change under test.
# Every one reported agreement, which was true of the binary it ran and said
# nothing about the tree -- the emulator's side of a differential is only
# evidence if it is the emulator you just edited. guest_tests.sh uses build/,
# this uses build-arm64-release/, and nothing kept the second in step with the
# first.
#
# The marker was `build.ninja` until 2026-09-11 and is `iul-build.env` now,
# which `tools/build-all.sh` writes with the flags *and the environment* it was
# given, so a rebuild reproduces the directory rather than replacing it with a
# default build.
#
# IUL_NO_BUILD=1 skips it, for comparing a binary kept deliberately.
#
# In a subshell: that file's `CARGO_TARGET_DIR` is a relative path and must not
# reach the cargo invocation below, which cross-compiles the guest tests into
# `$BINDIR`.
if [ -z "${IUL_NO_BUILD:-}" ] && [ -f "$(dirname "$IUL")/iul-build.env" ]; then
    if ! (
        # shellcheck disable=SC1090,SC2046 # a generated file; the flags word-split
        . "$(dirname "$IUL")/iul-build.env"
        tools/build-cli.sh -o "$(dirname "$IUL")" $IUL_BUILD_ARGS >/dev/null
    ); then
        echo "differential: could not build $IUL" >&2
        exit 2
    fi
fi
if [ ! -x "$IUL" ]; then
    echo "differential: no $IUL; build it first" >&2
    exit 2
fi

# And whether it is *current*. The rebuild above runs only when the directory
# has an `iul-build.env`, and the default `build-arm64-release/` is a directory
# this repository never creates -- so the usual way to reach here with a stale
# binary is to have one lying about from an earlier session and run this script
# with no arguments.
#
# On 2026-09-16 that is exactly what happened: a week-old default reported 21
# disagreements over 11 tests, including one that the change under test had just
# fixed, and the same sweep against the current binary reported 3. A sweep whose
# verdict is a gate (exit 1 on a disagreement not in KNOWN, since 2026-09-12)
# must not be able to answer about a build nobody made.
#
# `probe_diff.sh` has had this check since 2026-09-11 and `guest_tests.sh` since
# 2026-09-16, with the same three rules: picked-for-itself is an error, named
# deliberately is advice, and a missing `rg` says so rather than passing quietly.
newest_src=$(rg --files -g '*.S' -g '*.h' -g '*.rs' crates asbestos 2>/dev/null \
    | xargs stat -f '%m %N' 2>/dev/null | sort -rn | head -1)
if [ -z "$newest_src" ]; then
    echo "differential: (cannot tell whether $IUL is current: rg is not installed)"
elif [ "${newest_src%% *}" -gt "$(stat -f '%m' "$IUL")" ]; then
    if [ "$IUL_GIVEN" = 1 ]; then
        echo "differential: WARNING: ${newest_src#* } is newer than $IUL."
        echo "  You named it, so this is advice: the disagreements below are"
        echo "  that binary's and not the tree's."
    else
        echo "differential: ${newest_src#* } is newer than $IUL," >&2
        echo "  which is this script's default -- so nobody chose to compare" >&2
        echo "  an old build against a live kernel. Rebuild, or set IUL=." >&2
        exit 2
    fi
fi

# And the test programs, for the same reason and with more force: they are the
# *subject* of the comparison. A check added to a test was invisible to the
# sweep until somebody happened to run guest_tests.sh, which is the script that
# builds them -- so a new assertion could be written, compared, and reported as
# agreement, all against the binary from before it was written. That is exactly
# the failure the paragraph above describes, one level further in.
if [ -z "${IUL_NO_BUILD:-}" ]; then
    if ! ( cd tests/guest && cargo build --release --target aarch64-unknown-linux-musl ) >/dev/null 2>&1; then
        echo "differential: could not cross-compile the guest tests" >&2
        echo "  rustup target add aarch64-unknown-linux-musl" >&2
        exit 2
    fi
fi

# Tests whose subject the container does not have. Each line is a name and the
# reason, because a skip list without one is a way to stop looking.
not_comparable() {
    case "$1" in
        # A probe asserts nothing: it prints one line per case and never fails,
        # and the diff between the two sides *is* the finding. That is
        # tests/integration/probe_diff.sh's job, and this harness -- which
        # compares failing check names and check counts -- reads every one of
        # them as "neither side ran a check". Fifteen of them, which is enough
        # noise to hide the one real disagreement in a sweep: the run that
        # added this rule had exactly one, and it was a getrandom flag pair
        # Linux refuses.
        *_probe) return 0 ;;
        # The same, for the ones that report a survival or a duration rather
        # than checks. `thread_start_signal` prints "survived", `futex_idle` a
        # parked time, `mem_bench` a table.
        thread_start_signal|futex_idle|mem_bench) return 0 ;;
        # `exit_group_blocked` fails by *hanging*, so the timeout is its
        # assertion and it runs no check by design -- see the note at the top of
        # it, which also records what it was written to check and does not.
        exit_group_blocked) return 0 ;;
        # `timer_pid_reuse`'s second half needs a tid to *come round again*,
        # which is the allocator's range: this kernel's `MAX_PID` is 32768 and
        # wraps in a second, Linux's `pid_max` defaults to 4194304 and does not
        # come round inside any budget a test can spend. So the emulator runs
        # three checks Linux cannot reach, and the counts differ for a reason
        # that has nothing to do with POSIX timers. The test says "skipped" and
        # names the `pid_max` it read, rather than failing a check about the
        # allocator.
        timer_pid_reuse) return 0 ;;
        # `unix_foreign_peer` is driven by `tests/integration/guest_tests.sh`,
        # which is the half that knows the emulator's host pid and so where the
        # guest listener's host socket is. Run on its own -- which is what this
        # harness does -- it prints "listening" and waits sixty seconds for a
        # connection nobody makes, on both sides. It said "TIMED OUT ON LINUX"
        # and "TIMED OUT ON THE EMULATOR", which is agreement about nothing.
        unix_foreign_peer) return 0 ;;
        # Need to be pid 1, or to see this kernel's process table.
        task_race|exit_stuck|signal_race|wait_semantics|proc_visibility|proc_fd_race) return 0 ;;
        # Need a controlling terminal the test itself owns.
        tty_ldisc|tty_race|tty_jobctl|tty_pollout) return 0 ;;
        # tty_pgrp, tty_hangup and tty_vhangup are *not* here: they build their own session
        # and their own pty, so they need nothing they were given and the two
        # sides run the same program in the same shape.
        # Mount, chroot, or device nodes a container refuses.
        mount_race|fs_conformance|fakefs_containment|priv_ops|setid_exec|cap_cross) return 0 ;;
        # About this emulator rather than about Linux.
        movw_shapes|self_modifying|fpu_modes|mem_query|fault_recovery|elf_bounds) return 0 ;;
        # Measure time rather than assert anything. They print no checks, so
        # the sweep compared two empty results and called it agreement -- which
        # is true and says nothing, at the cost of running them.
        poll_bench|epoll_bench|compute_bench|syscall_bench|tty_bench|tlb_hit_bench) return 0 ;;
        atomic_bench|crypto_bench|feature_bench|mprotect_bench|ordering_bench) return 0 ;;
        # Race hammers that report survival and counts, not checks.
        dir_read_race|proc_read_race|signalfd_close_race|sock_state_race) return 0 ;;
        # A fuzzer whose *output* is the comparison: diff the two sides' lines
        # by hand. Measured 2026-10-18: every difference was an encoding of an
        # extension this kernel does not advertise and the host CPU has
        # (FEAT_CSSC, FEAT_FHM, MTE), which the container runs and this refuses.
        insn_diff) return 0 ;;
        # Docker's default seccomp profile answers clone3 with ENOSYS, so the
        # container cannot run what this tests (25 of 30 fail there with
        # errno 38).
        clone3_abi) return 0 ;;
        # A deadline about this emulator, like thread_spawn below: a real
        # kernel's exit_group has no wait a userspace program can observe, so
        # every shape it measures answers in under 150 us there and the run
        # says nothing. What it guards is a 50 ms sleep on our own exit path.
        exit_latency) return 0 ;;
        # Also a deadline about this emulator: it applies a guest mprotect to
        # the host mapping underneath and a real kernel has no second mapping
        # to update, so the per-page cost it measures does not exist there.
        # mprotect_runs is the comparable half and is not listed.
        mprotect_scaling) return 0 ;;
        # A deadline rather than an assertion, and one about this emulator: a
        # host pthread_create has no address-space lock to lose against, so
        # Linux answers it in microseconds whatever else is running. It prints
        # timings and no checks, which this harness reads as "neither side ran
        # a check".
        thread_spawn) return 0 ;;
        # Timings, no checks. Kept because the comparison is worth having by
        # hand: run the same binary in the container and read both. On
        # 2026-08-29 that said this emulator's futex round-trip is 8.7 us
        # against native Linux's 13.0 -- faster, for the same reason fork+exec
        # is, and the reason nothing was changed there.
        futex_pingpong) return 0 ;;
        # This emulator drops V8's fatal-abort chatter on stderr, because V8
        # prints it before the BRK the trap handler sees. Linux drops nothing,
        # so every check here is about a difference that is the point.
        v8_mute) return 0 ;;
        # This kernel forces a handful of environment variables onto every
        # process -- workarounds for things that misbehave under emulation.
        # Linux injects nothing, so every check here is about a difference that
        # is the point.
        exec_env) return 0 ;;
        # A container answers EPERM to every syslog(2), whatever the arguments:
        # reading the kernel log needs CAP_SYSLOG, which Docker does not grant.
        # That is the container's answer and not the kernel's -- the same shape
        # as clock_settime and the seccomp profile. Granting the capability
        # would not help either: the container would then read the *host's*
        # kernel log, which is a different thing to be asking about.
        syslog_abi) return 0 ;;
        # Reads /proc/iul/objects, which is this emulator's own accounting of
        # the kernel objects Rust allocates. Linux has nothing to count.
        eventfd_leak) return 0 ;;
        # Reads /proc/iul/objects too: the anonymous-page budget is this
        # emulator's own cap on how much host memory a guest may map, so that a
        # guest which maps until it stops gets ENOMEM rather than the host being
        # killed by jetsam. Linux has no equivalent counter.
        anon_budget_leak) return 0 ;;
        # About this kernel's *policy set*: it implements SCHED_OTHER only, so
        # a realtime policy is EINVAL. Linux implements them, and answers
        # EPERM without CAP_SYS_NICE or succeeds with it.
        sched_ret) return 0 ;;
        # Needs the guest's idea of who owns a file to be real, which only
        # fakefs gives. This runs against `-r`, a passthrough mount, where a
        # chown to uid 1000 cannot happen -- the host would need to be root --
        # and realfs deliberately reports success for it rather than breaking
        # every archive extraction that restores ownership. So the test's
        # subject does not exist on the mount the sweep uses, and the emulator
        # refusing a chmod by a uid that does not own the file is correct.
        setattr_perm|sticky_dir|perm_semantics|caps_setid) return 0 ;;
        # Needs a mount where the guest's own mknod is real, which is fakefs.
        # The sweep runs the emulator against `-r`, a passthrough mount, where
        # a device node cannot be created at all -- so the subject does not
        # exist on the mount this uses.
        dev_bounds) return 0 ;;
        # Measures the host's own limits, which the container sets differently.
        fd_limit|umask_modes|resource_abi|time_abi) return 0 ;;
        # Report by *surviving* rather than by checking: a race probe whose
        # whole assertion is that this emulator did not deadlock, crash or lose
        # an object. Linux surviving one says nothing about this kernel, and
        # there is no check line for the sweep to compare either way.
        fd_race|fs_race|mmap_race|sock_race|inotify_deadlock|signal_proc_deadlock) return 0 ;;
        # Report by *measuring*. The same category as the benchmarks above, and
        # they were only outside it because nobody had noticed: they print
        # timings and region counts, not checks.
        mmap_scaling|proc_lock_hold|proc_maps_lock|proc_read_scaling) return 0 ;;
        # Needs a root that has CAP_SYS_NICE. A container's root does not:
        # `nice -n -5 true` there is EACCES, so every check about what root may
        # do to a priority fails on Linux and passes here, and the emulator is
        # the one behaving like a real kernel.
        priority_perm) return 0 ;;
        *) return 1 ;;
    esac
}

# Seconds any one run gets before it is killed.
#
# Not optional. A stale binary left in the target directory by a test that was
# deleted -- cargo does not remove those -- blocked a whole sweep by reading
# forever, and because both sides were started before either was waited on,
# the sweep sat there rather than reporting anything at all. macOS has no
# timeout(1), hence the polling below.
TIMEOUT="${TIMEOUT:-60}"

# Run "$@" with a deadline. Prints the output, or a marker if it was killed.
with_timeout() {
    "$@" >"$tmp/run" 2>&1 &
    pid=$!
    waited=0
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$waited" -ge "$TIMEOUT" ]; then
            kill -9 "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
            cat "$tmp/run"
            printf '\nTIMED OUT after %ss\n' "$TIMEOUT"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    wait "$pid" 2>/dev/null
    cat "$tmp/run"
}

# Tests that will not do anything without arguments.
#
# The sweep ran every test with none, so these printed a usage line -- or, for
# exec_semantics, the argument vector it prints when it is being run as a `#!`
# interpreter -- on *both* sides, ran no checks on either, and were counted as
# agreement. Five of them, including the one about AF_UNIX addressing. Most
# tests default their directory (`unwrap_or("/tmp/...")`) and are unaffected
# either way; these made it required, which is the better design and which the
# harness did not honour.
#
# Not passed to everything, because `$1` means something else to a handful: an
# iteration count, a mode word, a re-exec marker.
test_args() {
    case "$1" in
        exec_semantics) printf -- '--run-tests /tmp/diff-%s' "$1" ;;
        perm_semantics|syscall_abi|sock_semantics|fs_conformance) printf '/tmp/diff-%s' "$1" ;;
        # Six seconds, not the sixty-five the guest suite uses. The claim being
        # compared is only that a process which is only waiting is left alone on
        # both sides, and a container has no such valve to outlast -- the
        # *strong* version, which has to outlast the sixty seconds this used to
        # be set to, belongs where it can be read as a regression check.
        idle_wait) printf 'alive 6' ;;
        *) printf '' ;;
    esac
}

# The directory those arguments name, for the cleanup below.
test_scratch() {
    case "$1" in
        # Its arguments are not a directory.
        idle_wait) printf '' ; return ;;
    esac
    case "$(test_args "$1")" in
        '') printf '' ;;
        *) printf '/tmp/diff-%s' "$1" ;;
    esac
}

# Tests the default seccomp profile answers for, rather than the kernel.
#
# The profile returns ENOSYS for some syscalls whatever their arguments, so a
# sweep over one measures Docker and reports it as the kernel's answer. clone3
# is the case: every check in clone3_abi came back ENOSYS, which reads as "this
# kernel does not have clone3" and is a statement about the container.
#
# Turning the profile off for a named test is not weakening it -- the test then
# asks the kernel, which is the whole point of this harness. It is listed
# rather than applied everywhere because the profile is also what keeps a test
# with a mistake in it from reaching the host.
seccomp_off() {
    case "$1" in
        clone3_abi) printf -- '--security-opt seccomp=unconfined' ;;
        # The profile answers ENOSYS for file_getattr and EPERM for
        # open_by_handle_at, whatever their arguments.
        fs_at_calls) printf -- '--security-opt seccomp=unconfined' ;;
        # The profile allows `personality` for five argument values and answers
        # EPERM for the rest, ADDR_NO_RANDOMIZE among them -- so a sweep over it
        # reports the filter's list rather than the kernel's rule, which is that
        # there is no list.
        personality_abi) printf -- '--security-opt seccomp=unconfined' ;;
        # The profile answers EPERM to every clock_settime and settimeofday
        # without CAP_SYS_TIME, before the kernel checks the clock, the pointer
        # and the time -- which is the order this test asserts. Unconfined is
        # still without CAP_SYS_TIME, so nothing can set a clock.
        adjtime_abi) printf -- '--security-opt seccomp=unconfined' ;;
        # process_madvise of another process wants CAP_SYS_NICE, which the
        # guest's root has, and the profile gates it on that capability too.
        mm_seal_guard) printf -- '--security-opt seccomp=unconfined --cap-add SYS_NICE' ;;
        # pidfd_getfd and clone3 are the profile's; kcmp, seccomp, unshare and
        # sched_setattr too, and a negative nice is CAP_SYS_NICE's, which the
        # guest's root has.
        pidfd_semantics) printf -- '--security-opt seccomp=unconfined' ;;
        procsec_semantics) printf -- '--security-opt seccomp=unconfined --cap-add SYS_NICE' ;;
        # swapon, swapoff and quotactl are CAP_SYS_ADMIN's, which the guest's
        # root has; every case is an error path.
        rarecalls_abi) printf -- '--privileged' ;;
        # vhangup is CAP_SYS_TTY_CONFIG's, which the guest's root has.
        tty_vhangup) printf -- '--privileged' ;;
        # It mounts a tmpfs to map files on, which the guest's root may.
        mm_file_follow) printf -- '--privileged' ;;
        # It writes /proc/sys/fs/suid_dumpable, which docker mounts read-only
        # otherwise, and puts the value it found back.
        suid_dumpable) printf -- '--privileged' ;;
        # Root's rows need CAP_SYS_PTRACE and CAP_SYS_NICE, and the
        # cross-process calls the seccomp profile off.
        crossproc_rules) printf -- '--privileged' ;;
        # Every case starts from a root with full sets, as the guest's does,
        # and ip_unprivileged_port_start is the netns's to set.
        caps_rules) printf -- '--privileged' ;;
        *) printf '' ;;
    esac
}

run_linux() {
    # Named so the container can be killed too: killing the `docker run`
    # client leaves what it started running, which is how four of them
    # accumulated across three sweeps.
    name="differential-$1-$$"
    with_timeout docker run --rm --name "$name" --platform linux/arm64 \
        $(seccomp_off "$1") \
        -v "$PWD/$BINDIR:/w:ro" "$IMAGE" "/w/$1" $(test_args "$1")
    docker kill "$name" >/dev/null 2>&1
    return 0
}

run_iul() {
    with_timeout "$IUL" -r "$ROOTFS" "/tmp/$1" $(test_args "$1")
}

# Just the failing-check lines, which is what a disagreement looks like. The
# summary count moves for uninteresting reasons (a container has more
# filesystems, say) and the *names* are the comparable part.
#
# The harness prints `  FAIL  [group] what  (file:line)`, and `what` is followed
# by `: returned ... errno ...` when the check was a `check_fails!`. Two
# normalisations, in this order:
#
#   1. **Drop the `  (file:line)` the harness appends.** Both sides run the same
#      binary so it is identical on each and never *was* a difference, but it
#      leaked into the signature whenever `what` held no colon -- a check called
#      "plain message" came out as `grp: plain message  (tests/guest/src/bin/x.rs`,
#      because the `[^:]*` below stops at the colon in `file:line`. That is an
#      allowlist key nobody would write by hand. Measured before and after on a
#      full sweep: 95 compared and 0 disagree either way, which is what says the
#      comparison did not move.
#   2. **Cut at the first colon**, which is what was already happening and is
#      kept: the text after it is the *values* a check_fails! reports, and those
#      carry pids, addresses and sizes that differ between two machines for
#      reasons that are not about this kernel.
#
# What 2 costs is stated rather than fixed: two runs that fail the *same* check
# for *different* reasons compare equal, so "both sides think this assertion is
# wrong" hides "and they disagree about why". Widening it means comparing text
# that is not stable across two machines, which is the trade probes.md records
# for statx_probe -- printing the raw value gave 62 differences and one finding.
failures() {
    printf '%s\n' "$1" \
        | sed -e 's/  ([^()]*:[0-9][0-9]*)$//' \
              -n -e 's/.*FAIL  \[\([^]]*\)\] \([^:]*\).*/\1: \2/p' \
        | sort -u
}

# How many checks ran at all.
#
# Compared separately and reported rather than counted as a disagreement,
# because a test that *skips* a block on one side and runs it on the other
# produces no failure on either and looked like perfect agreement. renameat2
# was exactly that: the emulator answered EINVAL, the test read that as "not
# implemented" and skipped seven checks, and the harness said the two agreed.
# A gap that hides by not being tested is the one this whole script is for.
# Anchored at the start of the line, not `.*`: a leading `.*` is greedy, so it
# eats all but the last digit and `40 checks` counts as 4 -- which reported a
# difference between "0" and "3" for a run whose real numbers were 40 and 33.
# Any sign the program did its work at all: a check count, or a PASS/FAIL line
# from the race tests, which report that way and print no count.
evidence() {
    printf '%s\n' "$1" | grep -c -E '(^ *[0-9]+ checks,)|PASS  |FAIL  '
}

count() {
    printf '%s\n' "$1" | sed -n 's/^ *\([0-9][0-9]*\) checks,.*/\1/p' | tail -1
}

# ## The allowlist
#
# A disagreement that has been read and is not a defect goes here **with its
# reason**, exactly as in probe_diff.sh's KNOWN and lock-order.py's ALLOWED. A
# disagreement that is not in it fails this script -- and so does an entry that
# suppressed nothing, because an allowlist that outlives its reason hides
# whatever lands on that case next.
#
# The argument each entry is answering is `not_comparable()`'s, one level finer.
# That function suppresses a **whole test** and is the right tool when the
# test's whole subject is missing on one side; this is for a test that is worth
# comparing and has one line that cannot agree. Prefer this to adding a name
# there: a `not_comparable` entry costs every other check in that program.
#
# `known_ok` is handed one finding, in the form
#
#     <test>  <KIND>  <detail>
#
# -- two spaces between the fields, which is the shape a `case` glob is written
# against. The kinds are the eight this script can report:
#
#     TEST IS WRONG ABOUT LINUX    a check Linux fails and the emulator does not
#     EMULATOR DIFFERS             a check the emulator fails and Linux does not
#     DIFFERENT NUMBER OF CHECKS   linux ran N, emulator ran M
#     NEITHER SIDE RAN A CHECK     the program did not do its work
#     LINUX RAN NOTHING            the container produced no checks
#     THE EMULATOR RAN NOTHING     the emulator produced no checks
#     TIMED OUT ON LINUX
#     TIMED OUT ON THE EMULATOR
#
# So an entry reads, for instance,
#
#     "some_test  DIFFERENT NUMBER OF CHECKS"*) echo some-test-skips-a-block ;;
#
# **It is empty, and that is a measurement rather than an omission.** Six full
# sweeps on 2026-09-12 reported 95 compared and 0 disagree, so there is nothing
# yet that has been read and justified. The mechanism was checked by putting an
# entry in, watching a deliberately broken test go green, and watching the entry
# be reported as stale once the break was backed out -- which is the only way to
# check an allowlist with no members.
known_ok() {
    case "$1" in
        # (no entries; see above)
        *) ;;
    esac
}

# Every tag known_ok can print, so that one which suppressed nothing can be
# named. Space-separated.
ALL_KNOWN=""

# A KNOWN entry whose case has stopped happening and whose cause is **not
# established**. `tag|since|what is unexplained`, one per line.
#
# The staleness rule above -- an entry that suppresses nothing is stale, delete
# it -- is right, and it is the wrong rule for an entry nobody can explain the
# silence of. probe_diff.sh carries `writev-partial-fault`, which looked stale
# three times and was correct each time; deleting it on a fourth reading with no
# cause would have thrown away the only record of a rule somebody measured. An
# OBSERVING entry still suppresses, so it cannot fail the gate, and **prints
# every line it suppresses**, where an active entry's are counted and thrown
# away -- which is the half of the staleness rule that was doing the work, since
# the danger of an inert entry is that it silently covers the next thing to land
# on its case.
OBSERVING=""
fired=""
observed=""

# A tag is active or under observation, never both: the two say opposite things
# about what its silence means, so a name in both would make the staleness rule
# depend on which loop ran last. And an OBSERVING tag `known_ok` cannot print is
# a name watching nothing, which is the stale-entry problem one level up.
printf '%s\n' "$OBSERVING" | while IFS='|' read -r tag _rest; do
    [ -n "$tag" ] || continue
    case " $ALL_KNOWN " in
        *" $tag "*)
            echo "differential: $tag is in ALL_KNOWN and in OBSERVING" >&2
            exit 2 ;;
    esac
    # `echo <tag>`, not the bare tag: the bare tag matches this list itself, so
    # the check would pass for a name known_ok has never heard of.
    grep -q "echo $tag" "$0" || {
        echo "differential: OBSERVING names $tag, which known_ok never prints" >&2
        exit 2
    }
done || exit 2

# A name that is not a test. `-i build/iul` reads as two of them, and every
# argument then failed the `-f` check below and was skipped in silence -- so a
# sweep invoked with the flags the *other* two scripts take reported
# "0 compared, 0 disagree" and exited 0. Agreement over nothing is the failure
# this whole script exists to catch; it must not be able to report it. An option
# is refused by name, at the top of the file.
named="$*"
tests="$*"
if [ -z "$tests" ]; then
    tests=$(ls "$BINDIR" 2>/dev/null \
        | grep -v '\.d$' | grep -v '\.rlib$' \
        | grep -v '^deps$' | grep -v '^build$' | grep -v '^examples$' \
        | grep -v '^incremental$')
fi

# `not_comparable()` is an allowlist and gets the rule every allowlist in this
# tree gets: an entry naming a test that no longer exists suppresses nothing and
# waits to cover whatever takes the name next. Nothing checked that until
# 2026-09-12, and it is 63 entries.
#
# Read out of this file's own source, which is the only place the list exists.
# The `*_probe` arm is a class rather than a name and is skipped; every other
# arm names one test or several separated by `|`.
nc_stale=""
for n in $(sed -n '/^not_comparable()/,/^}/p' "$0" \
        | sed -n 's/^ *\([a-z0-9_|]*\)) return 0 ;;$/\1/p' | tr '|' ' '); do
    [ -f "tests/guest/src/bin/$n.rs" ] || nc_stale="$nc_stale $n"
done
if [ -n "$nc_stale" ]; then
    echo "differential: not_comparable() names tests that do not exist:$nc_stale" >&2
    echo "  Each entry records a reason somebody read and justified. Once the" >&2
    echo "  test is gone the entry covers whatever lands on the name next." >&2
    exit 2
fi

# Stale build output, checked before anything is run rather than as it is met.
#
# `cargo build` does not remove the output of a deleted bin target, so the
# target directory accumulates them -- `readloop` sat there reading forever and
# stalled three sweeps. It used to be skipped and mentioned in a line after the
# summary, which is where a message goes to be missed; it is a setup error now,
# by the same rule probe_diff.sh applies to a baseline file for a probe that no
# longer exists. The fix is `rm`, and nothing else in the tree will say it is
# there.
#
# Only on a full sweep: a caller who named tests said what it wanted compared,
# and a leftover elsewhere in the directory is not that run's business.
if [ -z "$named" ]; then
    stale=""
    for t in $tests; do
        [ -f "$BINDIR/$t" ] || continue
        [ -f "tests/guest/src/bin/$t.rs" ] || stale="$stale $t"
    done
    if [ -n "$stale" ]; then
        echo "differential: no source for$stale" >&2
        echo "  Stale build output: cargo leaves the binary of a deleted test" >&2
        echo "  behind. Delete it -- one of them once blocked a whole sweep by" >&2
        echo "  reading forever." >&2
        exit 2
    fi
fi

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT INT TERM

differ=0
compared=0
unexplained=0
missing=0
for t in $tests; do
    if [ ! -f "$BINDIR/$t" ]; then
        # Only a complaint for a name the caller chose. The unfiltered listing
        # of $BINDIR has directories and .d files in it.
        [ -z "$named" ] || { echo "differential: no such test: $t" >&2; missing=1; }
        continue
    fi
    if not_comparable "$t"; then continue; fi
    # A named test whose source is gone: the scan above covers a full sweep, and
    # this covers the caller who asked for one by name.
    if [ ! -f "tests/guest/src/bin/$t.rs" ]; then
        echo "differential: no source for $t -- stale build output, delete it" >&2
        missing=1
        continue
    fi
    # Unconditionally, not `[ -f ] ||`: the copy in the rootfs is a *build
    # artefact*, and comparing a fix against the binary that predates it
    # reports the disagreement it was meant to settle. That happened.
    cp "$BINDIR/$t" "$ROOTFS/tmp/$t" 2>/dev/null || continue

    # The scratch directory is inside the rootfs, and what a test leaves there
    # outlives the sweep. perm_semantics leaves a file at mode 0040 owned by
    # nobody in particular, and guest_tests.sh copies the whole rootfs into a
    # fakefs afterwards -- so the next run of *that* died on "Permission
    # denied" for a file this script had left behind. Cleared either side of
    # the run: before, so a leftover cannot be read as this run's work.
    scratch=$(test_scratch "$t")
    if [ -n "$scratch" ]; then
        chmod -R u+rwX "$ROOTFS$scratch" 2>/dev/null
        rm -rf "$ROOTFS$scratch"
    fi

    linux_out=$(run_linux "$t")
    iul_out=$(run_iul "$t")

    if [ -n "$scratch" ]; then
        chmod -R u+rwX "$ROOTFS$scratch" 2>/dev/null
        rm -rf "$ROOTFS$scratch"
    fi
    failures "$linux_out" >"$tmp/linux"
    failures "$iul_out"   >"$tmp/iul"
    lc=$(count "$linux_out"); ic=$(count "$iul_out")
    compared=$((compared + 1))

    same_count=1
    [ "$lc" = "$ic" ] || same_count=0
    # Two runs that reported nothing are not two runs that agree. Reaching here
    # with no evidence on either side means the program did not do its work: a
    # required argument it was not given, a rootfs it could not write, a binary
    # that died at startup. Three tests hid here for months, printing their
    # usage line to both kernels in turn and being counted as agreement.
    #
    # Evidence is a check count *or* a PASS/FAIL line, because the race tests
    # report the second way and have no count at all.
    ran_nothing=0
    [ "$(evidence "$linux_out")" = 0 ] && [ "$(evidence "$iul_out")" = 0 ] && ran_nothing=1
    if [ "$ran_nothing" = 0 ] && cmp -s "$tmp/linux" "$tmp/iul" && [ "$same_count" = 1 ]; then
        continue
    fi

    # Every finding this test produced, one per line, as `KIND|detail`. Built
    # first and judged afterwards, rather than printed as it is found, because
    # the allowlist decides both whether a line is shown and whether it is the
    # run's verdict -- and the `########## name ##########` header must not be
    # printed for a test whose only finding is explained.
    : > "$tmp/findings"
    [ "$ran_nothing" = 0 ] || echo "NEITHER SIDE RAN A CHECK|" >>"$tmp/findings"
    # *One* side ran nothing. That is not a disagreement about behaviour, it is
    # a run that did not happen, and saying so is the difference between a
    # useful message and a `?` in the count line. A container that failed to
    # start under the load of a full sweep is the case seen twice on 2026-09-01;
    # printing its output shows the daemon's error instead of nothing.
    if [ "$ran_nothing" = 0 ]; then
        [ "$(evidence "$linux_out")" != 0 ] || echo "LINUX RAN NOTHING|" >>"$tmp/findings"
        [ "$(evidence "$iul_out")" != 0 ] || echo "THE EMULATOR RAN NOTHING|" >>"$tmp/findings"
    fi
    case "$linux_out" in *"TIMED OUT"*) echo "TIMED OUT ON LINUX|" >>"$tmp/findings" ;; esac
    case "$iul_out"   in *"TIMED OUT"*) echo "TIMED OUT ON THE EMULATOR|" >>"$tmp/findings" ;; esac
    [ "$same_count" = 1 ] || printf 'DIFFERENT NUMBER OF CHECKS|linux ran %s, emulator ran %s\n' \
        "${lc:-?}" "${ic:-?}" >>"$tmp/findings"
    # Checks Linux fails and the emulator does not: the test is asserting
    # something Linux does not do.
    comm -23 "$tmp/linux" "$tmp/iul" | sed 's/^/TEST IS WRONG ABOUT LINUX|/' >>"$tmp/findings"
    # Checks the emulator fails and Linux does not: a real gap.
    comm -13 "$tmp/linux" "$tmp/iul" | sed 's/^/EMULATOR DIFFERS|/' >>"$tmp/findings"

    said=0
    here=0
    # `< file`, never `printf | while`: a pipe puts the loop in a subshell and
    # `fired`, `observed` and `unexplained` would be counted there and thrown
    # away, which is a gate that can only ever say "everything agreed".
    while IFS='|' read -r kind detail; do
        [ -n "$kind" ] || continue
        # The form a KNOWN glob is written against: two spaces between the
        # fields, and no trailing pair when there is no detail.
        key="$t  $kind"
        [ -z "$detail" ] || key="$key  $detail"
        tag=$(known_ok "$key")
        if [ -n "$tag" ]; then
            fired="$fired $tag"
            case "$OBSERVING" in
                *"$tag|"*) ;;
                *) continue ;;
            esac
            # An OBSERVING tag suppresses like any other and, unlike any other,
            # says what it suppressed.
            observed="$observed $tag"
            [ "$said" = 1 ] || { printf '\n########## %s ##########\n' "$t"; said=1; }
            printf '  [%s, under observation]\n' "$tag"
        else
            [ "$said" = 1 ] || { printf '\n########## %s ##########\n' "$t"; said=1; }
            unexplained=$((unexplained + 1))
            here=$((here + 1))
        fi
        case "$kind" in
            "TEST IS WRONG ABOUT LINUX") printf '  TEST IS WRONG ABOUT LINUX  %s\n' "$detail" ;;
            "EMULATOR DIFFERS")          printf '  EMULATOR DIFFERS           %s\n' "$detail" ;;
            "DIFFERENT NUMBER OF CHECKS") printf '  DIFFERENT NUMBER OF CHECKS %s\n' "$detail" ;;
            "NEITHER SIDE RAN A CHECK")
                printf '  NEITHER SIDE RAN A CHECK   the program did not do its work; its output was:\n%s\n' \
                    "$(printf '%s\n' "$iul_out" | sed 's/^/    /')" ;;
            "LINUX RAN NOTHING")
                printf '  LINUX RAN NOTHING          the container produced no checks; its output was:\n%s\n' \
                    "$(printf '%s\n' "$linux_out" | sed 's/^/    /')" ;;
            "THE EMULATOR RAN NOTHING")
                printf '  THE EMULATOR RAN NOTHING   it produced no checks; its output was:\n%s\n' \
                    "$(printf '%s\n' "$iul_out" | sed 's/^/    /')" ;;
            *) printf '  %s\n' "$kind" ;;
        esac
    done <"$tmp/findings"
    [ "$here" = 0 ] || differ=$((differ + 1))
done

printf '\ndifferential: %d compared, %d disagree\n' "$compared" "$differ"

# Every entry under observation, whichever way it went, with the date it went
# there -- so that an entry's *age* is in the output rather than only in this
# file. An exception whose cost nobody sees is one nobody closes.
if [ -z "$named" ]; then
    printf '%s\n' "$OBSERVING" | while IFS='|' read -r tag since why; do
        [ -n "$tag" ] || continue
        case " $observed " in
            *" $tag "*) state="fired -- the case is back, and this is the reading it was waiting for" ;;
            *) state="did not fire, as on the run that put it here" ;;
        esac
        echo "differential: under observation since $since: $tag"
        echo "  $why"
        echo "  this run: $state"
    done
fi

# A KNOWN entry that suppressed nothing this run. Either the disagreement was
# fixed -- in which case delete the entry -- or the case that produced it is
# gone, in which case the reason it records is no longer being tested.
#
# Computed here and acted on **after** the comparison's own verdict, because the
# two are different findings and in probe_diff.sh the first used to hide the
# second. Only on a full sweep: a run that named three tests has said nothing
# about the entries belonging to the other ninety-two.
stale=""
for k in $ALL_KNOWN; do
    case " $fired " in *" $k "*) ;; *) stale="$stale $k" ;; esac
done

# Nothing compared is not agreement. It means the arguments named nothing, or
# the build directory is empty, and either way the sweep answered a question it
# never asked.
if [ "$compared" = 0 ]; then
    echo "differential: nothing was compared" >&2
    exit 2
fi

# The comparison's verdict outranks a mistyped name, which is the same rule as
# the stale-entry one below and for the same reason: a run that named four tests,
# misspelt one of them and found a real disagreement in another has two findings,
# and the one to answer first is the disagreement. Both are printed either way --
# "no such test: x" went to stderr as it happened -- so this only decides which
# of the two the exit code speaks about.
if [ "$unexplained" != 0 ]; then
    echo "differential: $unexplained disagreement(s) not in KNOWN, over $differ test(s)"
    echo "  Each is a question: which of the two is right? Measure before assuming"
    echo "  it is Linux -- five of the first nine differences a sweep like this"
    echo "  found were in the *tests*."
    [ -z "$stale" ] || [ -n "$named" ] || \
        echo "  (and KNOWN entries that suppressed nothing:$stale)"
    exit 1
fi
[ "$missing" = 0 ] || exit 2

if [ -n "$stale" ] && [ -z "$named" ]; then
    echo "differential: every comparable test agrees with a real kernel or is in"
    echo "  KNOWN, but these entries suppressed nothing:$stale"
    echo "  Each was a disagreement somebody read and justified. If it no longer"
    echo "  happens, delete the entry -- an allowlist that outlives its reason"
    echo "  hides the next difference that lands on the same case. If the reason"
    echo "  it stopped is not established, move it to OBSERVING with a date."
    exit 3
fi

n_known=$(echo "$fired" | wc -w | tr -d ' ')
echo "differential: every comparable test agrees with a real kernel, or its"
echo "  disagreement is one of the $n_known in KNOWN, each with a reason"
exit 0
