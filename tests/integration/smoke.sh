#!/usr/bin/env bash
#
# The gate: does a guest boot, run things, and answer correctly.
#
# Usage:  tests/integration/smoke.sh [-i <iul binary>] [-r <rootfs>]
#
# ## What it does and does not reach for
#
# Every *case* runs against what the base rootfs already ships: nothing installs
# a package, and no case talks to the network. Installing toolchains and
# compiling with them is the full tier's job (tests/integration/full.sh), where
# a network failure is a person reading a log rather than a blocked pull
# request.
#
# One network step remains, and calling this suite "offline" would be a lie
# without saying so: the rootfs itself is fetched, once, by rootfs.sh. CI caches
# the tarball on its pinned digest so an ordinary run does not repeat it, and
# `-r` skips it entirely for a tree that is already on disk. A dl-cdn outage on
# a cold cache is therefore still a red gate — smaller than a gate that installs
# packages, not zero.
#
# The rootfs is Alpine because that is what ServerBox ships. The other two are
# in the full tier.

set -uo pipefail
cd "$(dirname "$0")/../.."

IUL=""
ROOTFS=""
SBM=""
while getopts "i:r:s:h" opt; do
    case $opt in
        i) IUL="$OPTARG" ;;
        s) SBM="$OPTARG" ;;
        r) ROOTFS="$OPTARG" ;;
        h) sed -n '2,20p' "$0"; exit 0 ;;
        *) exit 2 ;;
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
[ -n "$IUL" ] && [ -x "$IUL" ] || { echo "no iul binary; build one or pass -i" >&2; exit 2; }
[ -n "$ROOTFS" ] || ROOTFS="$(tests/integration/rootfs.sh alpine)" || exit 1

# The embedder harness sits next to the iul binary in the build directory,
# unless it was pointed somewhere else.
if [ -z "$SBM" ]; then
    SBM="$(dirname "$IUL")/sbm_api_test"
fi

# Build what is about to be run.
#
# The loop above prefers build-arm64-release/iul, which is a directory somebody
# has to create and which nothing then keeps current. On 2026-08-28 it was five
# days old, so every smoke run since had been reporting on a binary from before
# the changes under test -- including a deliberately broken one, which passed.
# guest_tests.sh and differential.sh both had this defect and both had this
# fix; this one was missed because it builds two targets rather than one.
#
# IUL_NO_BUILD=1 skips it, for running a binary kept deliberately.
#
# The marker was `build.ninja` until 2026-09-11 and is `iul-build.env` now,
# which `tools/build-all.sh` writes with the flags *and the environment* it was
# given. This one builds everything rather than naming targets: it needs the
# CLI, the embedder example and -- on macOS -- the interpose dylib, which is
# three of the four things `build-all.sh` makes, and the fourth is `fakefsify`,
# which takes a second.
#
# In a subshell, so that file's `CARGO_TARGET_DIR` -- a relative path -- reaches
# this rebuild and no later cargo invocation.
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
    dir="$(dirname "$IUL")"
    if ! (
        # shellcheck disable=SC1090,SC2046 # a generated file; the flags word-split
        . "$dir/iul-build.env"
        tools/build-all.sh "$dir" $IUL_BUILD_ARGS >/dev/null
    ); then
        echo "could not build $dir" >&2
        exit 1
    fi
fi

# A rootfs is a directory on the host and it keeps whatever a run leaves in it.
# Fixed paths meant this suite collided with itself: full.sh's go case makes
# /tmp/g a directory, and the `unlink` case below then could not create /tmp/g
# as a file — a failure that had nothing to do with the code under test, and one
# that only appeared once both had been run. Everything writes under here, and
# it is removed at the end.
#
# The cases below name it as $SCRATCH inside single quotes, so it reaches the
# guest's shell unexpanded and is expanded there against the assignment the
# wrapper prepends. Expanding it here instead would work too; leaving it to the
# guest keeps the cases readable as the shell commands they are.
SCRATCH="/tmp/iul-smoke-$$"
# Host-side scratch, for artefacts a case builds outside the guest.
SCRATCH_HOST="$(mktemp -d)"
cleanup() {
    rm -rf "$SCRATCH_HOST"
    "$IUL" -r "$ROOTFS" /bin/sh -c "rm -rf $SCRATCH" >/dev/null 2>&1 || true; }
trap cleanup EXIT

pass=0; fail=0

# Runs a shell command in the guest and compares stdout and the exit status.
# Both, because a case that asserts only on output passes when the guest prints
# the right thing on its way to dying.
check() {
    local name="$1" want_out="$2" want_status="$3" cmd="$4"
    local out status errfile
    # stderr to a file rather than to /dev/null: a case that fails because the
    # emulator died says so on stderr, and discarding it left CI reporting
    # fourteen identical "status 139, wanted 0" lines with no reason attached.
    # Kept out of $out so that a guest writing to stderr does not fail a case
    # that is about stdout.
    errfile="$(mktemp)"
    out="$("$IUL" -r "$ROOTFS" /bin/sh -c "SCRATCH=$SCRATCH; mkdir -p \$SCRATCH; $cmd" 2>"$errfile")"
    status=$?
    if [ "$out" = "$want_out" ] && [ "$status" = "$want_status" ]; then
        pass=$((pass+1)); printf '  PASS  %s\n' "$name"
    else
        fail=$((fail+1))
        printf '  FAIL  %s\n' "$name"
        printf '        output: %q\n        want:   %q\n' "$out" "$want_out"
        printf '        status: %s  want: %s\n' "$status" "$want_status"
        # 139 is 128+SIGSEGV: the emulator, not the guest.
        [ "$status" = 139 ] && printf '        (128+11: the host process segfaulted)\n'
        [ -s "$errfile" ] && sed 's/^/        | /' "$errfile" | head -20
    fi
    rm -f "$errfile"
}

echo "########## smoke ($IUL -r $ROOTFS) ##########"

# The guest runs at all, and the interpreter reports the architecture it is
# emulating rather than the one it is running on. Both are aarch64 here, which
# is the point of the fork, so this asserts the guest's own uname rather than
# a difference.
check "boot and print"        "hello"   0 'echo hello'
check "uname is aarch64"      "aarch64" 0 'uname -m'

# An exit status has to survive do_execve, task_start, the wait and the host
# process's own exit. 42 rather than 1: a status that arrives as "nonzero"
# would pass against 1 by accident.
check "exit status"           ""        42 'exit 42'
check "exit status from a child" ""     7  'sh -c "exit 7"'

# `$(...)` makes the host's stdout a pipe, and a guest reading
# /proc/<pid>/fd/1 should see one: a pipe, not an anonymous inode
# (`anon_inode:[unknown]` until 2026-10-18). The shell's own descriptor,
# because a pipe in the guest command would be the guest's.
check "a host pipe on stdout is a pipe"    "pipe"  0 'readlink /proc/$$/fd/1 | cut -d: -f1'
check "and fstat says fifo"                "fifo"  0 'stat -L -c %F /proc/$$/fd/1'
# /dev/stdin and /dev/stderr are links into /proc/self/fd, which Linux follows
# to the open file: both were ENOENT on a pipe until 2026-10-18.
check "cat /dev/stdin on a pipe"           "hi"    0 'echo hi | cat /dev/stdin'
check "a write to /dev/stdout on a pipe"   "out"   0 'echo out > /dev/stdout'
# A UDP round trip through busybox nc, whose listener peeks the first
# datagram with an empty buffer and whose client polls after shutting its
# write side: the first returned at once and the second never woke, until
# 2026-10-18 (`tests/guest` udp_probe).
check "nc -u reaches an nc -lu listener"   "udp"   0 \
    'cd $SCRATCH; nc -lu -p 18089 > u </dev/null & L=$!; sleep 0.3; echo udp | nc -u -w1 127.0.0.1 18089; sleep 0.3; kill $L; head -1 u'

# A shell pipeline is fork, exec, two pipes and a wait for each side. This is
# also the shape apt's method workers use, which is known not to work on the
# Ubuntu rootfs -- see the note in full.sh.
# The environment this kernel forces onto every execve. Not Linux behaviour --
# these are workarounds for the emulator, so they live here rather than in
# tests/guest/, which differential.sh compares against a real kernel.
#
# crates/kernel/execargs does the insertion; what is checked here is the two
# modes it is asked for. A replace that appended instead of replacing, or a
# keep that overwrote, both leave the variable *set* and would pass a check
# that only asked whether it was there -- so the count matters as much as the
# value.
check "an injected variable is set"        "1"       0 'echo $NO_COLOR'
check "and appears exactly once"           "1"       0 'env | grep -c NO_COLOR'
check "a forced variable replaces the caller's" "PYTHONMALLOC=malloc" 0 \
    'PYTHONMALLOC=pymalloc env | grep PYTHONMALLOC'
check "and still exactly once"             "1"       0 \
    'PYTHONMALLOC=pymalloc env | grep -c PYTHONMALLOC'
check "a deferring one keeps the caller's" "NO_COLOR=0" 0 \
    'NO_COLOR=0 env | grep NO_COLOR'
check "and does not add a second"          "1"       0 \
    'NO_COLOR=0 env | grep -c NO_COLOR'

check "pipe between processes" "world" 0 'echo world | cat'
check "pipeline of three"      "3"     0 'printf "a\nb\nc\n" | wc -l | tr -d " "'

# Files, through realfs and the host filesystem underneath it.
check "write then read a file" "content" 0 'echo content > $SCRATCH/f && cat $SCRATCH/f'
check "unlink"                 "gone"    0 'echo x > $SCRATCH/g && rm $SCRATCH/g && { [ -e $SCRATCH/g ] || echo gone; }'
check "mkdir and list"         "in-dir"  0 'mkdir -p $SCRATCH/d && echo x > $SCRATCH/d/in-dir && ls $SCRATCH/d'

# The two flag values a review found wrong, from the guest side this time:
# O_DIRECTORY on a file, and a symlink opened without following it.
# crates/fs/generic's tests/open_flags.rs asserts these against generic_openat
# directly; this asserts that a real guest program sees the same answers.
check "O_DIRECTORY on a file"  "ok" 0 \
    'echo x > $SCRATCH/f2; cd $SCRATCH/f2 2>/dev/null && echo bad || echo ok'
check "symlink resolves"       "target" 0 \
    'echo target > $SCRATCH/t; ln -sf $SCRATCH/t $SCRATCH/l; cat $SCRATCH/l'

# /dev. `iul -r` used to give the guest none of this: the CLI created device
# nodes only for a fakefs root, because realfs cannot mknod without host root.
# The effect was worse than absence — a redirect to /dev/null created a regular
# file at that path *in the rootfs on disk* — and it stopped dnf (no entropy
# source for libstdc++) and apt (its download methods) outright.
check "/dev/null swallows"     "after"   0 'echo gone > /dev/null; echo after'
check "/dev/zero reads"        "8"       0 'head -c 8 /dev/zero | wc -c | tr -d " "'
check "/dev/urandom reads"     "8"       0 'head -c 8 /dev/urandom | wc -c | tr -d " "'
# ...and the rootfs is left alone: with no device node behind it, the redirect
# above would have created this file.
check "/dev/null is a device"  "device"  0 \
    '[ -c /dev/null ] && echo device || echo regular-file'
# And the directory itself can be *listed*, which the four checks above do not
# cover: each of them opens a node by name, and a name resolves through the
# mount's own lookup. Reading the directory needs the meta.db row for the mount
# point, which fake_db_create writes as the empty blob -- and without it `ls
# /dev` answers "No such file or directory" while `> /dev/null` still works.
#
# The comment in xX_main_Xx.h records that a recycled pid used to leave a stale
# directory behind and cost the guest its /dev, one smoke run in four. That was
# fixed by using mkdtemp; this is the check that would have caught it.
check "/dev can be listed"     "yes"     0 \
    'ls /dev >/dev/null 2>&1 && [ -n "$(ls /dev)" ] && echo yes || echo no'

# Signals: a killed child is reported as killed, and the shell renders it as
# 128+signal. This is the wait(2) status encoding that waitid_decode_status
# reads, seen from the other end. The `exit` keeps the shell from exec'ing the
# child: as pid 1 it would ignore its own SIGTERM, as a container's init does,
# and answer 0.
check "child killed by a signal" "" 143 'sh -c "kill -TERM \$\$"; exit $?'

# Environment and argv survive execve.
check "argv"                   "a b c" 0 'sh -c "echo \$1 \$2 \$3" _ a b c'
check "environment"            "value" 0 'X=value sh -c "echo \$X"'

# One case that needs a fakefs rather than the realfs everything above uses.
#
# path_normalize expands a symlink into a MAX_PATH buffer together with
# whatever of the input path is still unconsumed, and used to bound neither. A
# target near MAX_PATH plus any path under it overran it and the process died on
# the stack guard — on any mount, since path_normalize is the entry point every
# filesystem shares. It is only reachable through a fakefs: a realfs symlink
# target goes through the host, which caps it far below MAX_PATH.
echo
echo "########## path normalization (fakefs) ##########"
# `fakefsify --index` writes only meta.db, describing a data/ the caller supplies,
# so the rootfs is copied in rather than referenced — the guest writes to it.
FAKEFS="$SCRATCH_HOST/fakefs"
# Scratch directories the guest suite and the probes left under /tmp hold
# sockets and mode-0 files, which `cp -R` refuses; see guest_tests.sh.
for leftover in "$ROOTFS"/tmp/*/; do
    [ "${leftover%/}" = "$ROOTFS$SCRATCH" ] && continue
    [ -d "$leftover" ] && rm -rf "$leftover"
done
if mkdir -p "$FAKEFS" \
   && cp -R "$ROOTFS" "$FAKEFS/data" 2>/dev/null \
   && "$(dirname "$IUL")/tools/fakefsify" --index "$FAKEFS" >/dev/null 2>&1; then
    errfile="$(mktemp)"
    out="$("$IUL" -f "$FAKEFS" /bin/sh -c '
        s=aaaaaaaaaa; s=$s$s$s$s$s$s$s$s$s$s; t=$s$s$s$s$s$s$s$s$s$s
        ln -s "/$(printf %.4091s "$t$t$t$t$t")" /L 2>/dev/null
        cat /L/abcdefghij >/dev/null 2>&1
        echo alive' 2>"$errfile")"
    status=$?
    if [ "$out" = "alive" ] && [ "$status" = "0" ]; then
        pass=$((pass+1)); printf '  PASS  symlink expansion stays inside MAX_PATH\n'
    else
        fail=$((fail+1))
        printf '  FAIL  symlink expansion stays inside MAX_PATH\n'
        printf '        output: %q  status: %s\n' "$out" "$status"
        [ "$status" = 134 ] && printf '        (128+6: aborted on the stack guard)\n'
        [ -s "$errfile" ] && sed 's/^/        | /' "$errfile" | head -10
    fi
    rm -f "$errfile"
else
    fail=$((fail+1))
    printf '  FAIL  could not build a fakefs with fakefsify --index\n'
fi
rm -rf "$FAKEFS"

# The console: the guest's stdio on the host terminal, which only happens when
# both ends are one -- so `check`, which pipes, never reached it. Three things
# ride on it and each was checked by hand before this: `crates/fs/ttyreal`'s
# reader thread (a line typed on the host arrives), its initial state (the host
# window size), and `create_stdio` opening the console by path, without which
# `/proc/self/fd/0` was `anon_inode:[unknown]` and `tty` said "not a tty".
echo
echo "########## console ##########"
out="$(python3 - "$IUL" "$ROOTFS" <<'PY' 2>&1
import os, pty, select, struct, sys, time, fcntl, termios
iul, root = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid == 0:
    os.execv(iul, [iul, "-r", root, "/bin/sh", "-c", "tty; stty size; read x; echo got-$x"])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 33, 101, 0, 0))
out, sent, end = b"", False, time.time() + 20
while time.time() < end:
    if not sent and b"101" in out:
        os.write(fd, b"typed\n")
        sent = True
    r, _, _ = select.select([fd], [], [], 0.1)
    if r:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
os.waitpid(pid, 0)
sys.stdout.write(out.decode(errors="replace").replace("\r", ""))
PY
)"
for want in "/dev/tty1" "33 101" "got-typed"; do
    if printf '%s\n' "$out" | grep -qx -- "$want"; then
        pass=$((pass+1)); printf '  PASS  console answers %s\n' "$want"
    else
        fail=$((fail+1)); printf '  FAIL  console answers %s\n' "$want"
        printf '%s\n' "$out" | sed 's/^/        | /' | head -10
    fi
done

# Native offload: an `execve` of a registered name runs a **host** binary
# instead of being emulated. macOS only, and reachable only through `-n`, so
# nothing else in any suite has ever run a line of it -- it had no automated
# coverage at all until 2026-09-01, when it moved to
# crates/kernel/offloadexec.
#
# `check` cannot be used: these need their own `-n` arguments, and the
# emulator prints its own progress on stderr, which a case about the guest's
# stdout must not see.
echo
echo "########## native offload ##########"
offload() {
    local name="$1" want_out="$2" want_status="$3" spec="$4" cmd="$5"
    local out status errfile
    errfile="$(mktemp)"
    out="$("$IUL" -r "$ROOTFS" -n "$spec" /bin/sh -c "$cmd" 2>"$errfile")"
    status=$?
    if [ "$out" = "$want_out" ] && [ "$status" = "$want_status" ]; then
        pass=$((pass+1)); printf '  PASS  %s\n' "$name"
    else
        fail=$((fail+1))
        printf '  FAIL  %s\n' "$name"
        printf '        output: %q\n        want:   %q\n' "$out" "$want_out"
        printf '        status: %s  want: %s\n' "$status" "$want_status"
        [ -s "$errfile" ] && sed 's/^/        | /' "$errfile" | head -20
    fi
    rm -f "$errfile"
}

case "$(uname -s)" in
Darwin)
    # The whole path: the spec parses, the basename matches, posix_spawn runs
    # the host binary, its stdout reaches the guest through the forwarding
    # thread, and waitpid's status becomes the guest's exit code.
    offload "a registered name runs the host binary" "Darwin" 0 \
        "uname=/usr/bin/uname" '/bin/uname -s'
    # The status, which is a different path through the wait: WIFEXITED rather
    # than the output pipe.
    offload "a non-zero host exit reaches the guest" "rc=3" 0 \
        "exiter=/bin/sh" '/bin/exiter -c "exit 3"; echo rc=$?'
    # argv past argv[0] is the guest's, and argv[0] is the *host* path.
    offload "arguments are passed through" "a b c" 0 \
        "echoer=/bin/echo" '/bin/echoer a b c'
    # stderr has a forwarding thread of its own, and it must not land on
    # stdout: a case that conflated them passed against a version that wrote
    # everything to fd 1.
    offload "host stderr does not reach guest stdout" "out" 0 \
        "both=/bin/sh" '/bin/both -c "echo out; echo err >&2" 2>/dev/null'
    # Output into a *guest* pipe. Every case above writes to the emulator's
    # own stdout, a host descriptor the child can be handed; a guest pipe has
    # none, and until 2026-09-29 the child was handed `real_fd` anyway -- 0,
    # `calloc`'s, which is the emulator's stdin -- so this printed nothing.
    offload "output into a guest pipe reaches the reader" "a b c" 0 \
        "echoer=/bin/echo" '/bin/echoer a b c | cat'
    # An unregistered name is emulated as usual -- the lookup is by basename,
    # so this also says a *different* name does not match.
    offload "an unregistered name is still emulated" "aarch64" 0 \
        "uname=/usr/bin/uname" '/bin/arch'

    # Path redirection: libfakefs_redirect.dylib is injected through
    # DYLD_INSERT_LIBRARIES so that a guest absolute path reaches the rootfs
    # directory rather than the host's own filesystem. **Nothing built the
    # dylib until 2026-09-01**, so this half had never run.
    #
    # The helper is compiled here rather than borrowed from the host, and the
    # reason is specific: every binary in /bin and /usr/bin on Apple Silicon is
    # arm64e, and an arm64e process cannot load a plain arm64 dylib -- dyld
    # refuses with "incompatible architecture" and kills it. Homebrew binaries
    # are arm64 and would work, and are not something a CI runner has.
    helper="$SCRATCH_HOST/catfile"
    if cc -O0 -o "$helper" -x c - <<'EOF' 2>/dev/null
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "r");
    if (!f) return 1;
    int c;
    while ((c = fgetc(f)) != EOF) putchar(c);
    fclose(f);
    return 0;
}
EOF
    then
        "$IUL" -r "$ROOTFS" /bin/sh -c "echo redirected > $SCRATCH/probe" >/dev/null 2>&1
        offload "a guest path reaches the guest's file" "redirected" 0 \
            "catfile=$helper" "/bin/catfile $SCRATCH/probe"
        # And the host's own file of that name is *not* what it reads. The
        # file below exists on the host and not in the guest's tree, so with
        # redirection on the helper cannot open it -- status 1, nothing
        # printed. Without it, it would print `host-side` and exit 0, which is
        # exactly the failure this is here to catch.
        echo host-side > "/tmp/iul-smoke-redirect-$$"
        offload "and not the host's file of that name" "" 1 \
            "catfile=$helper" "/bin/catfile /tmp/iul-smoke-redirect-$$"
        rm -f "/tmp/iul-smoke-redirect-$$"
    else
        fail=$((fail+1))
        printf '  FAIL  could not compile the offload helper\n'
    fi
    ;;
*)
    # Not a skip that passes quietly, and not a failure either: the feature is
    # macOS-only by construction (posix_spawn plus a DYLD interpose), so there
    # is nothing to run and nothing to report.
    printf '  ....  skipped: native offload is macOS only\n'
    ;;
esac

# The interface ServerBox links, rather than the CLI everything above goes
# through: boot, a pty session under init, a command, its output and its exit
# code. See the header of sbm_api_test.c.
echo
echo "########## embedder interface ##########"
if [ -x "$SBM" ]; then
    if "$SBM" "$ROOTFS"; then
        pass=$((pass+1)); printf '  PASS  sbm_api_test\n'
    else
        fail=$((fail+1)); printf '  FAIL  sbm_api_test\n'
    fi
else
    # Not a skip that passes quietly: this is half of what the gate is for, and
    # a build that did not produce it is a build that changed something.
    fail=$((fail+1))
    printf '  FAIL  sbm_api_test not found at %s\n' "$SBM"
fi

echo
if [ "$fail" = "0" ]; then
    echo "smoke: $pass passed"
    exit 0
fi
echo "smoke: $fail FAILED, $pass passed"
exit 1
