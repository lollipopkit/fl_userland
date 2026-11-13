#!/bin/sh
# Run every `*_probe` guest program here and on a real arm64 kernel, and report
# where the two disagree.
#
# A probe is a program that prints one line per case and never fails. That is
# the whole idea: `differential.sh` compares *checks*, so it can only find a
# difference someone already thought to assert. A probe asserts nothing, so the
# diff is the finding — and the first five probes produced 49 differences, of
# which 44 were defects. One was a `kill(0)` that signalled every process on
# the system; eight were in one 56-byte struct.
#
#   tests/integration/probe_diff.sh                 # all of them
#   tests/integration/probe_diff.sh mmap sock       # named ones
#   tests/integration/probe_diff.sh --record        # ...and write the baseline
#   tests/integration/probe_diff.sh --recorded      # against the baseline, no docker
#
# Needs docker with linux/arm64. Skips, loudly, without it — the binaries are
# static aarch64-musl and this is an Apple Silicon machine, so the *same
# binary* gets a real kernel with no cross-compilation in between.
#
# ## Why there is a recorded baseline
#
# **A wrong errno had nothing that would catch it.** `cargo test --workspace`
# and `guest_tests.sh` are both green against `getdents64` on an `O_PATH`
# descriptor answering `EINVAL` where it answers `EBADF`; this script is the one
# thing that goes red, and it was in no CI workflow, because docker is not
# available on a GitHub macOS runner — confirmed against the runner image's own
# software list on 2026-09-11, which names no container runtime at all. So the
# check that covers the syscall ABI ran when somebody remembered to run it.
#
# `--record` writes each probe's *container* output under
# `tests/integration/probe-baseline/`, and `--recorded` compares the emulator
# against those files with the same allowlist. That runs anywhere, needs no
# docker, and is what ci.yml drives.
#
# What is lost by recording, said plainly: **liveness**. A recorded reference
# cannot notice Linux changing its mind — a new kernel that answers a case
# differently is invisible until somebody runs the docker mode again. What is
# kept is the property the reference exists for: every expected value in those
# files was **produced by a real kernel**, not written from a man page. Five of
# the first nine differences a sweep like this found were in the *tests*, every
# one written from a page that was silent about the case.
#
# The two modes are therefore not substitutes and the division of labour is:
# the recorded mode is the gate, and the docker mode is the only way to *move*
# what the gate expects. Changing an errno cannot be made green by editing a
# baseline file, because the header of `recorded-with.txt` says which kernel
# produced it and re-recording asks that kernel again.
#
# ## The allowlist
#
# A difference that has been read and is not a defect goes in KNOWN below
# **with its reason**, in the same spirit as lock-order.py's ALLOWED. A
# difference that is not in it fails this script — and so does a KNOWN entry
# that suppressed nothing, because an allowlist that outlives its reason hides
# whatever lands on that case next.
#
# ## Exit codes, and why a stale entry is not a failed comparison
#
#   0  every case agrees or is explained, and every KNOWN entry fired
#   1  a difference that is not in KNOWN        <- the gate
#   2  a setup error: no binary, no rootfs, no baseline for a probe, or a
#      binary older than the sources that this script picked for itself
#   3  every difference is explained, but a KNOWN entry suppressed nothing
#
# Those were one code until 2026-09-11, and the stale check ran **first**: a
# single entry whose case had stopped happening exited 1 before the comparison's
# own verdict was printed, so the script had been red for a difference it was
# not reporting. That is worse than either finding on its own — a gate that is
# permanently red is read exactly as often as one that is permanently green,
# which is never, and this one could not be put in CI at all while it was.
#
# The entry in question is `writev-partial-fault`, and it could not simply be
# deleted: see OBSERVING below.
set -eu

IUL=""; ROOTFS=""; MODE=docker; RECORD=0; IUL_GIVEN=0
while [ $# -gt 0 ]; do
    case "$1" in
        -i) IUL="$2"; IUL_GIVEN=1; shift 2 ;;
        -r) ROOTFS="$2"; shift 2 ;;
        --record) RECORD=1; shift ;;
        --recorded) MODE=recorded; shift ;;
        -h|--help)
            echo "usage: $0 [-i <iul>] [-r <rootfs>] [--record|--recorded] [probe ...]"
            echo "  (no flag)    compare against a linux/arm64 container"
            echo "  --record     the same, and write tests/integration/probe-baseline"
            echo "  --recorded   compare against that baseline; needs no docker"
            exit 0 ;;
        -*) echo "probe_diff: unknown option $1" >&2; exit 2 ;;
        *) break ;;
    esac
done
WANT="$*"

# Where `--record` writes and `--recorded` reads. One file per probe, holding
# that probe's output from the container, verbatim -- including the lines KNOWN
# suppresses, because the file is a measurement of Linux and not a statement
# about this kernel.
BASELINE="tests/integration/probe-baseline"

if [ "$MODE" = recorded ] && [ "$RECORD" = 1 ]; then
    echo "probe_diff: --record needs the container; it cannot run with --recorded" >&2
    exit 2
fi

# The **newest** build, not the first one that exists. A stale binary answers
# every case with the behaviour of whatever was fixed since, which reads as a
# pile of differences that are already fixed -- and, the other way round, as a
# clean run for a fix that was never compiled. The first version of this script
# preferred `build-arm64-release/` and reported 23 differences from a binary
# three hours old.
if [ -z "$IUL" ]; then
    for c in build-arm64-release/iul build-release/iul build/iul build-lockdebug/iul; do
        [ -x "$c" ] || continue
        [ -z "$IUL" ] || [ "$c" -nt "$IUL" ] && IUL="$c"
    done
fi
[ -n "$IUL" ] && [ -x "$IUL" ] || { echo "no iul binary; build one or pass -i" >&2; exit 2; }
echo "iul: $IUL"

# And say so if it is older than the sources.
#
# `kernel fs util` were three of the five names here until 2026-09-11 and have
# not existed since 2026-09-09; `rg` reported each as missing to /dev/null and
# listed the rest, so the check kept working and nothing said it had lost three
# fifths of its subject. What is left is where the engine is: `crates` and the
# gadget assembly.
#
# **Which of the two cases it is decides whether this is fatal**, and until
# 2026-09-12 it was a warning in both. "A deliberate comparison against an old
# build is a legitimate thing to want" is true and is a statement about the
# caller who passed `-i`; when this script *chose* the binary itself, out of the
# four candidate directories above, nobody chose anything and a stale one is an
# accident. The whole of the difference this script reports would then be a
# previous version's -- including a clean run, which is the direction that
# matters: a fix that was never compiled reads as a fix that works.
#
# So: `-i` warns, and a binary this script picked for itself exits 2, which is
# this file's code for a setup error. ci.yml passes `-i build-release/iul` and
# is unaffected.
#
# It is also **silent when `rg` is not installed**, which is the case on a
# GitHub runner -- and silence there used to be indistinguishable from having
# checked. It says which it was now, by the same rule this file applies to a
# suppressed stderr further down: "nothing" and "a lot that was suppressed" must
# not read the same.
newest_src=$(rg --files -g '*.S' -g '*.h' -g '*.rs' crates asbestos 2>/dev/null \
    | xargs stat -f '%m %N' 2>/dev/null | sort -rn | head -1)
if [ -z "$newest_src" ]; then
    echo "  (cannot tell whether this binary is current: rg is not installed)"
else
    src_t=${newest_src%% *}
    iul_t=$(stat -f '%m' "$IUL")
    if [ "$src_t" -gt "$iul_t" ]; then
        if [ "$IUL_GIVEN" = 1 ]; then
            echo "  WARNING: ${newest_src#* } is newer than this binary."
            echo "  You named it with -i, so this is advice: the differences"
            echo "  below are that binary's and not the tree's."
        else
            echo "probe_diff: ${newest_src#* } is newer than $IUL," >&2
            echo "  which this script picked for itself -- so nobody chose to" >&2
            echo "  compare against an old build. Rebuild, or name one with -i." >&2
            exit 2
        fi
    fi
fi
[ -n "$ROOTFS" ] || ROOTFS="build/integration/alpine"
[ -d "$ROOTFS" ] || { echo "no rootfs at $ROOTFS; pass -r" >&2; exit 2; }

if [ "$MODE" = docker ] && ! docker info >/dev/null 2>&1; then
    echo "probe_diff: docker is not available, skipping" >&2
    echo "  (the point of this script is the comparison; there is nothing to do without it)" >&2
    echo "  --recorded compares against tests/integration/probe-baseline instead" >&2
    exit 0
fi

TARGET=aarch64-unknown-linux-musl
BINDIR="tests/guest/target/$TARGET/release"
echo "########## building the probes ##########"
( cd tests/guest && cargo build --release --target "$TARGET" ) >/dev/null || {
    echo "could not cross-compile the guest tests" >&2
    exit 1
}

IMAGE="${IMAGE:-alpine:latest}"

# Recording is all or nothing.
#
# A subset re-record would leave the directory holding answers from two kernels
# with one header naming one of them, which is the quiet inconsistency this tree
# spends most of its allowlists guarding against. Re-recording is cheap -- about
# a minute of container time for all fifty-eight -- so there is nothing to buy.
if [ "$RECORD" = 1 ] && [ -n "$WANT" ]; then
    echo "probe_diff: --record takes no probe names: the baseline is one" >&2
    echo "  measurement on one kernel, and a subset would mix two." >&2
    exit 2
fi
if [ "$RECORD" = 1 ]; then
    mkdir -p "$BASELINE"
    # Which kernel answered, said in the directory itself. `--recorded` prints
    # this on every run: a reference nobody can name is one nobody can re-take,
    # and "what does Linux do" is a question with a version in it.
    {
        echo "recorded: $(date -u '+%Y-%m-%d')"
        echo "image:    $IMAGE"
        echo "kernel:   $(docker run --rm --platform linux/arm64 "$IMAGE" uname -r 2>/dev/null)"
        echo "probes:   $(ls tests/guest/src/bin/*_probe.rs | wc -l | tr -d ' ')"
        echo "by:       tests/integration/probe_diff.sh --record"
    } > "$BASELINE/recorded-with.txt"
fi

# A difference that is not a defect. Echoes a tag naming the rule, or nothing.
#
# Keep these in step with the probe module comments, which explain them at
# length; this list is what the script tests against.
known_ok() {
    case "$1" in
        # mmap: where an anonymous mapping lands. This kernel allocates from
        # low addresses and Linux from high ones, and nothing portable depends
        # on it.
        *"low4g="*) echo mmap-placement ;;
        # mmap: Linux overcommits and this kernel cannot -- the pages it hands
        # out are host pages.
        "mmap(NULL, 1<<47)"*) echo mmap-overcommit ;;
        # fs: O_TMPFILE is not implemented; it is refused rather than answered
        # with a descriptor onto the directory, which is what it used to do.
        "open(dir, O_TMPFILE|O_RDWR)"*) echo o-tmpfile ;;
        # openat2: the same O_TMPFILE, through openat2's argument rules, which
        # it passes -- the refusal is the filesystem's EOPNOTSUPP.
        "O_TMPFILE|O_RDWR in sub"*) echo openat2-o-tmpfile ;;
        # openat2: an access mode of 3, O_WRONLY|O_RDWR. Linux opens it as a
        # descriptor that can neither read nor write, for ioctls; this kernel
        # refuses it with EINVAL for openat and openat2 alike, because a host
        # open() would refuse the same word and the descriptor would need a
        # fourth access mode everywhere a read or write checks one.
        "O_WRONLY|O_RDWR "*) echo open-accmode-3 ;;
        # fsat: statmount's parent of the root. A container's root is
        # pivot_root'ed onto a mount whose parent is outside its namespace;
        # here the root is the namespace's own, which is its own parent, as
        # Linux's is in a namespace nothing was pivoted into.
        "  the root's parent is itself"*) echo statmount-container-root-is-pivoted ;;
        # msg: MSG_OOB on a unix stream. Linux carries an urgent byte that a
        # receiver asks for separately; a host unix socket has nowhere to put
        # one, so dropping the flag would send the data as ordinary bytes and
        # lose the distinction silently. EOPNOTSUPP until there is somewhere
        # to put it. "every bit" is the same case, since -1 includes MSG_OOB.
        "sendmsg(flags=MSG_OOB"*) echo msg-oob ;;
        "sendmsg(flags=every bit)"*) echo msg-oob-in-every-bit ;;
        # io: RWF_NOWAIT. Linux answers EOPNOTSUPP when the *filesystem* has
        # no FMODE_NOWAIT, which the container's overlayfs does not -- so this
        # measures the mount rather than the kernel, the way the seccomp
        # profile does for clock_settime.
        "preadv2(flags=RWF_NOWAIT"*) echo rwf-nowait-is-a-mount-property ;;
        # io: how large a file may be is s_maxbytes, also a property of the
        # filesystem: 2^63-1 on tmpfs and overlayfs, about 16 TB on ext4.
        # This one is the host's.
        "ftruncate(len=0x7fff_ffff_ffff_ffff)"*) echo ftruncate-max-file-size ;;
        # io: a vector longer than the buffer behind it. Linux copies what it
        # can and the write reports that count; the copy here is
        # all-or-nothing per bounce-buffer chunk, so a fault partway through
        # one loses that chunk and answers EFAULT. Nothing is written that
        # should not be -- it is a smaller answer, not a wrong one -- and
        # matching it exactly would mean copying at page granularity for a
        # case only a broken program reaches.
        # The probe maps three pages and takes the last one away, so the
        # readable extent is exactly two whatever else is nearby. It used to be
        # a 4096-byte `vec!`, and how far past it a kernel could read before
        # faulting was whatever the allocator happened to leave there -- so the
        # two sides agreed on some runs and not others, and this entry looked
        # stale about a third of the time. A flaky gate is worse than none.
        #
        # **It flaked again on 2026-09-04**, in a full sweep run while the four
        # gates were running beside it, and fired on its own a minute later --
        # which is the same shape as the 2026-09-03 flake and the same suspect.
        #
        # **It flaked once more on 2026-09-03 and the cause was not
        # established.** A full run reported this entry as suppressing nothing,
        # which means the two sides agreed about the case that run. Measured
        # afterwards: four container runs and three of each emulator build all
        # answered the same way they always do -- "wrote something" against
        # `EFAULT` -- and ten consecutive `probe_diff.sh io` runs fired the
        # entry every time. What was different about the failing run is that the
        # machine was carrying 52 stray `sleep` processes and three hung
        # containers left behind by the session, so *load* is the suspect and
        # nothing more than a suspect. Written down rather than guessed at.
        #
        # **"A writev that copies what it can" was tried on 2026-09-03 and is
        # not the rule.** The gather was changed to copy the readable prefix and
        # report that count, which fixed this case and broke three others: a
        # four-byte good vector followed by a faulting one is `EFAULT` on Linux
        # and became 4 here, and two more `writev` length cases went the same
        # way. Linux's write path copies into the page cache in page-sized
        # batches and **rolls a batch back** when it faults partway, so a fault
        # in the first batch loses everything and only a *completed* earlier
        # batch makes the answer partial. Matching that means emulating the
        # batching, not clamping the copy.
        #
        # The probe's own comment on the good-vector-then-faulting-one case says
        # "Linux copies what it can and reports that count" -- it does not, and
        # the measurement is what says so. See the module comment there.
        #
        # **2026-09-11: this is no longer a difference, and it is not a flake.**
        # A full sweep reported the entry as suppressing nothing again, and this
        # time the measurement does not match the three above: the emulator
        # answers `EFAULT` here, ten runs out of ten on an idle machine, where
        # every earlier reading of it says "wrote something". The container says
        # `EFAULT` as it always has, so the two agree.
        #
        # It is **not** the errno conversion that landed the same day: a release
        # build of `bc0b98e8`, the commit before it, answers `EFAULT` too, and
        # `sys_writev`'s gather path is unchanged across it -- the partial rule
        # is the same three lines with `Ok`/`Err` around them.
        #
        # **What changed is not established.** The entry stays until it is: it
        # has looked stale three times before and been right each time, and
        # deleting it on a fourth reading with no cause would throw away the
        # only record of a rule somebody measured. What is new is that this
        # reading is stable and unloaded, which the other three were not, so the
        # next person to look should start by asking what moved between the
        # 2026-09-04 entry above and `bc0b98e8` -- not by re-running it.
        #
        # It is in **OBSERVING** rather than ALL_KNOWN for exactly that reason,
        # and what that costs is written down there: it no longer fails the run
        # by being silent, and in exchange every line it suppresses is printed,
        # so the case coming back is visible rather than counted.
        "writev(two vectors summing past INT_MAX)"*) echo writev-partial-fault ;;
        # pipe: a non-blocking write above PIPE_BUF into a pipe with a little
        # room. Linux's pipe is a ring of *pages* and a partially-consumed page
        # cannot take new bytes, so reading 200 bytes out of a full one leaves
        # no room there at all and the write is EAGAIN. This pipe is
        # byte-granular, so it writes the 200 -- which is what POSIX specifies
        # for the case ("if there is room for at least one byte, write() shall
        # write what it can"). Neither answer breaks a caller: both are
        # retried.
        "an 8192-byte write with 100 bytes of room"*) echo pipe-page-granularity ;;
        # procfs: AT_RSEQ_FEATURE_SIZE (27) and AT_RSEQ_ALIGN (28) are
        # deliberately absent from the auxiliary vector. glibc reads them to
        # decide whether to register a restartable sequence, and rseq(2) is not
        # implemented here -- advertising the feature would make every glibc
        # program make a syscall that fails at startup. A missing pair is the
        # answer that means "no". Two lines: the count and the key list.
        "entry count"*) echo auxv-no-rseq ;;
        "the keys present"*) echo auxv-no-rseq-keys ;;
        # tty: TIOCGPTPEER returns a new *descriptor*, so it cannot be answered
        # from fd_ops the way every other tty ioctl is -- it needs the syscall
        # body and f_install. Its purpose is to reach the slave when /dev/pts
        # is not mounted where the caller expects, which in this guest it
        # always is, and glibc's openpty falls back to ptsname+open on ENOTTY.
        "TIOCGPTPEER"*) echo tiocgptpeer ;;
        # atcall: membarrier's restartable-sequence commands and
        # GET_REGISTRATIONS. rseq(2) is not implemented here -- the auxiliary
        # vector deliberately omits its keys for the same reason, two entries up
        # -- so claiming the two RSEQ commands would make a runtime issue a
        # barrier that cannot mean what it says. GET_REGISTRATIONS reports which
        # commands *this thread* has registered for, and registration here is a
        # no-op because any thread may issue the expedited barrier; answering it
        # would mean keeping per-task state whose only reader is the answer.
        "  QUERY PRIVATE_EXPEDITED_RSEQ"*) echo membarrier-no-rseq ;;
        "  QUERY REGISTER_PRIVATE_EXPEDITED_RSEQ"*) echo membarrier-no-rseq-register ;;
        "  QUERY GET_REGISTRATIONS"*) echo membarrier-no-registrations ;;
        # atcall: mknod of a block device. The container runs as root on a real
        # filesystem; probe_diff runs the emulator with -r, which is realfs, so
        # the host `mknod` is made by whatever user is running the build and the
        # host refuses it. On a fakefs the node is a row in meta.db and this
        # succeeds, which is the mount every real guest uses. It is the host's
        # answer, not this kernel's.
        "  mknodat(S_IFBLK)"*) echo mknod-block-needs-host-root ;;
        # caps: the same host refusal for a character device made with
        # CAP_MKNOD. The capability itself is asked first, and the case
        # without it agrees; `caps_rules` asserts both halves on fakefs.
        "mknod char 1:3: with"*) echo caps-mknod-needs-host-root ;;
        # caps: realfs reports the host's owner and group for every file, so a
        # file chowned to root, or to group 0, is the host user's: the
        # set-user-ID-root execs run as that uid, the set-group-ID one sets a
        # group the caller is not in, and uid 1000 does not own the file it
        # chmods. The rules are asserted on fakefs by `caps_setid`, and the
        # probe agrees there (`-f`, measured 2026-11-13).
        "exec uid 1000, setuid-root"*) echo caps-realfs-owner-is-the-hosts ;;
        "exec uid 1000 groups [0], setgid-0"*) echo caps-realfs-group-is-the-hosts ;;
        "uid 1000: chmod g+s own file of group 0"*) echo caps-realfs-chmod-owner-is-the-hosts ;;
        # caps: a write takes `security.capability` off the file on Linux
        # (`file_remove_privs`), as it takes the set-id bits from a writer
        # without CAP_FSETID. Neither is done here on write: it needs a per-inode
        # "nothing to remove" cache, as Linux's IS_NOSEC, to stay off the write
        # path. A chown takes both, and agrees.
        "file caps after a write"*) echo caps-write-keeps-file-caps ;;
        # poll: a select() bit above the *descriptor table's* size. Linux clamps
        # nfds to `files_fdtable(current->files)->max_fds` -- the allocated
        # table, not RLIMIT_NOFILE -- so a bit past it is never looked at and
        # the call answers 0. This kernel bounds nfds by RLIMIT_NOFILE and then
        # reports EBADF for a closed descriptor, which is what Linux does for
        # every bit *below* max_fds.
        #
        # The two therefore agree for any program that sets a bit for a
        # descriptor it has ever had open, because the table does not shrink.
        # Matching the rest would mean exposing the table's growth policy as an
        # ABI, which is an implementation detail on both sides.
        "  a closed descriptor in the set"*) echo select-nfds-clamped-to-table ;;
        # decode: the encodings that belong to extensions this kernel does not
        # advertise. `AT_HWCAP` says FP, ASIMD, AES, PMULL, SHA1, SHA2, CRC32,
        # ATOMICS, SHA3 and SHA512, and `AT_HWCAP2` says nothing -- so FEAT_FHM,
        # FEAT_FRINTTS, FEAT_BF16 and FEAT_FP16 are absent on purpose. The rule
        # in crates/kernel/initstack is that a HWCAP bit may be set only when
        # *every* instruction the extension defines is decoded, so the CPU
        # running one this kernel refuses is the correct state, not a gap.
        #
        # Every entry below matches only the direction "this refuses and Linux
        # runs". The other way round -- this running something a real kernel
        # refuses -- is never allowed, and there is nothing in the list for it.
        "  vec3s U0 size0 op29 -> SIGILL"|"  vec3s U0 size2 op29 -> SIGILL") echo decode-no-fhm ;;
        "  vec3s U1 size0 op25 -> SIGILL"|"  vec3s U1 size2 op25 -> SIGILL") echo decode-no-fhm2 ;;
        # decode: the by-element group's extension forms that are left: FEAT_FHM's
        # FMLAL2 and FMLSL2 (FCMA, RDM, DotProd, I8MM, BF16 and FP16 are all
        # implemented and advertised now). The sixteen baseline instructions
        # this group was missing all landed on 2026-09-03 -- FMULX by element
        # was the last, decoded as a scalar and not as a vector.
        "  byelem "*" -> SIGILL") echo decode-by-element-extensions ;;
        # atcall: linkat(fd, "", AT_EMPTY_PATH) links the *description* rather
        # than the path it was opened by, which is not the same operation: a
        # rename in between would give the caller a link to a different file,
        # and answering "ok" for that is worse than refusing. Linux needs
        # CAP_DAC_READ_SEARCH for it and the container is root, so it succeeds
        # there.
        #
        # The errno is the load-bearing part. Every caller has the same
        # fallback -- systemd's `link_fd` retries with `/proc/self/fd/<n>` as
        # the source and AT_SYMLINK_FOLLOW -- and it triggers on ENOENT, which
        # is what this answers and what works here, because `/proc/<pid>/fd/<n>`
        # is a symlink to the path.
        #
        # What the flag is really for is naming an O_TMPFILE file, and this
        # kernel has no O_TMPFILE either; the two go together, and the TODO is
        # in crates/kernel/pathcalls beside the arm.
        "  linkat(fd, \"\", AT_EMPTY_PATH)"*) echo linkat-empty-path ;;
        # procsec_probe: KCMP_EPOLL_TFD asks for an epoll set's target by
        # descriptor number and position, which crates/kernel/epoll has no
        # lookup for; EOPNOTSUPP is a kernel without epoll's half of kcmp.
        # See crates/kernel/forkcalls' share module.
        "EPOLL_TFD, "*) echo kcmp-no-epoll-tfd ;;
        # procsec_probe: installing a filter without no_new_privs needs
        # CAP_SYS_ADMIN, which the container's root lacks and the guest's root
        # has. Both refuse an unprivileged caller with EACCES.
        "in a child: SET_MODE_FILTER without no_new_privs, as root"*) echo seccomp-root-has-cap-sys-admin ;;
        # procsec_probe: no namespaces here. The container refuses for want of
        # CAP_SYS_ADMIN before it looks; the guest is root, gets past that, and
        # meets a kernel with the namespace configured out (EINVAL), which is
        # how clone answers the same flags.
        "unshare(CLONE_NEW"*) echo unshare-namespaces-not-configured ;;
        "setns(pidfd of self, CLONE_NEWUTS)"*) echo setns-namespaces-not-configured ;;
        # procsec_probe: /proc/<pid>/ns opens a namespace (since 2026-11-13),
        # and setns refuses to join one: EINVAL, the namespace code it would
        # need not being here, as for a pidfd above. The container's root is
        # refused first for want of CAP_SYS_ADMIN; a kind that does not match
        # the descriptor's is EINVAL on both.
        "setns(own uts ns, CLONE_NEWUTS)"*) echo setns-no-nsfs ;;
        # procsec_probe: the calls this kernel answers as built without the
        # feature -- ENOSYS, each with its reason in
        # crates/kernel/syscalltable's table.
        "listns("*) echo listns-not-configured ;;
        "landlock_"*) echo landlock-not-configured ;;
        "bpf("*) echo bpf-not-configured ;;
        "perf_event_open("*) echo perf-not-configured ;;
        "userfaultfd("*|"open /dev/userfaultfd"*) echo userfaultfd-not-configured ;;
        "keyctl("*|"add_key("*|"request_key("*) echo keys-not-configured ;;
        # procsec_probe: a process here may have 32 supplementary groups, the
        # limit setgroups enforces, where Linux allows 65536 -- the credential
        # set is copied by value with every task, and a fixed array that large
        # is a quarter of a megabyte per thread.
        "/proc/sys/kernel/ngroups_max "*) echo ngroups-max-is-32 ;;
        # procsec_probe: /proc/sys has only what this kernel decides (see
        # crates/fs/proc's sysctl module): a knob for a feature that is
        # configured out (perf, bpf, keys, userfaultfd, Yama) is absent as it is
        # on such a kernel, and one whose value would be invented is absent
        # rather than a promise.
        "/proc/sys/kernel/overflowuid "*|"/proc/sys/kernel/overflowgid "*|"/proc/sys/kernel/threads-max "*)
            echo procsys-only-what-this-kernel-decides ;;
        "/proc/sys/kernel/yama/"*|"/proc/sys/kernel/perf_event_paranoid "*|"/proc/sys/kernel/unprivileged_bpf_disabled "*)
            echo procsys-only-what-this-kernel-decides ;;
        "/proc/sys/kernel/keys/"*|"/proc/sys/kernel/kptr_restrict "*|"/proc/sys/kernel/dmesg_restrict "*)
            echo procsys-only-what-this-kernel-decides ;;
        "/proc/sys/kernel/randomize_va_space "*|"/proc/sys/kernel/shm"*|"/proc/sys/kernel/msg"*|"/proc/sys/kernel/sem "*)
            echo procsys-only-what-this-kernel-decides ;;
        "/proc/sys/kernel/core_pattern "*|"/proc/sys/kernel/tainted "*|"/proc/sys/kernel/printk "*)
            echo procsys-only-what-this-kernel-decides ;;
        "/proc/sys/user/"*|"/proc/sys/vm/max_map_count "*|"/proc/sys/vm/mmap_min_addr "*|"/proc/sys/vm/unprivileged_userfaultfd "*)
            echo procsys-only-what-this-kernel-decides ;;
        "/proc/sys/fs/file-max "*|"/proc/sys/fs/nr_open "*|"/proc/sys/fs/inotify/max_user_watches "*|"/proc/sys/fs/protected_symlinks "*)
            echo procsys-only-what-this-kernel-decides ;;
        # pidfd_modern_probe: the container is in cgroup v2 and this kernel has
        # no cgroups, so PIDFD_INFO_CGROUPID is never in the mask here -- which
        # is what a kernel built without CONFIG_CGROUPS answers.
        *": cgroupid reported "*) echo pidfd-info-no-cgroups ;;
        # pidfd_modern_probe: the namespace ioctls hand back an nsfs descriptor,
        # and there are no namespaces here and no nsfs: EOPNOTSUPP, which is
        # pidfd_ioctl's answer for a namespace type configured out.
        "PIDFD_GET_"*"_NAMESPACE "*) echo pidfd-no-namespaces ;;
        # xattr: `trusted.*` and `security.*` need CAP_SYS_ADMIN, which docker's
        # default capability set does not include and this kernel's root has.
        # The third line is the consequence of the first: a name the container
        # was not allowed to set is a name that is not there to read.
        "setxattr trusted.a"*) echo xattr-trusted-needs-cap-sys-admin ;;
        "setxattr security.a"*) echo xattr-security-needs-cap-sys-admin ;;
        "getxattr trusted.a"*) echo xattr-trusted-not-set-in-the-container ;;
        # xattr: Linux allows a 255-byte name and **Darwin allows 127** -- 128
        # answers ENAMETOOLONG, measured on the host. Passed through rather than
        # translated: inventing a Linux errno for a host limit would say the
        # name was wrong when it was the disk. crates/fs/tmpfs has no such
        # limit, and fs_conformance checks the rule there.
        "setxattr a 255-byte name"*) echo xattr-name-limit-is-the-hosts ;;
        # xattr: a 64 KiB value. The *kernel* cap is E2BIG at one byte more and
        # both sides agree on it; whether 64 KiB itself fits is the filesystem's
        # answer, and the container's overlayfs says ENOSPC where APFS stores it.
        "setxattr a 64 KiB value"*) echo xattr-value-limit-is-the-filesystems ;;
        # prio: lowering a nice value needs CAP_SYS_NICE, which docker's
        # default capability set does not include -- so a container's root gets
        # EACCES where this kernel's root, which has every capability,
        # succeeds. Same shape as clock_settime, which had its checks removed
        # for it rather than weakened. The *clamping* is compared and agrees:
        # both sides pull -100 to -20 rather than refusing it.
        "setpriority(PRIO_PROCESS, 0, -"*) echo prio-lowering-needs-cap-sys-nice ;;
        # prio: SCHED_FIFO with a realtime priority. Linux checks the range for
        # the policy first and then the privilege, so a container without
        # CAP_SYS_NICE gets EPERM; this kernel has no realtime policy at all, so
        # the policy is what is missing and EINVAL is what says so. The
        # non-realtime policies agree -- SCHED_BATCH and SCHED_IDLE are accepted
        # and read back on both sides.
        "sched_setscheduler(0, SCHED_FIFO, prio 50)"*) echo prio-no-realtime-policy ;;
        # prio: sched_rr_get_interval under SCHED_OTHER. The man page says the
        # answer is 0 for a thread that is not SCHED_RR and this kernel says 0;
        # Linux's fair class answers the CFS slice when the runqueue has weight
        # on it, which is a property of what else is running on the machine.
        "  the interval is not zero"*) echo prio-rr-interval-is-machine-state ;;
        # prio: IOPRIO_CLASS_RT needs CAP_SYS_ADMIN, which a container's root
        # does not have and this kernel's root does. crates/kernel/rescalls'
        # ioprio.rs carries the same note beside the check.
        "ioprio_set(class 1,"*) echo prio-rt-class-needs-cap-sys-admin ;;
        # statx: the container's kernel is 6.10 or newer and reports
        # STATX_SUBVOL (0x8000) in stx_mask -- a btrfs subvolume id. This
        # kernel has no subvolumes and never will, so the bit is clear, which
        # is the honest answer and what a caller checks the mask for. The rest
        # of the probe compares "did the fields I asked for arrive", which does
        # not depend on the filesystem underneath; this is the one line that
        # prints the raw word, and it is here so that the other forty do not
        # each need an entry.
        "stx_mask for STATX_ALL, raw"*) echo statx-subvol ;;
        # statx: stx_attributes_mask says which STATX_ATTR_* bits a filesystem
        # can report on -- compression, encryption, verity, DAX. This kernel
        # implements none of them, so it answers 0, meaning "the attributes
        # word says nothing". Linux answers whatever the host filesystem
        # supports, which is a property of the disk rather than of the kernel
        # under test.
        "stx_attributes_mask"*) echo statx-no-attributes ;;
        # ptrace: PTRACE_SETOPTIONS with an option this kernel cannot honour.
        # Linux validates the bits and stores them; none of the events they ask
        # for -- fork, vfork, clone, exec, exit -- is generated here, so a
        # tracer told "yes" would wait for one that never arrives. EINVAL makes
        # it say the kernel is too old and carry on, which is what strace and
        # gdb both do. An empty request still succeeds, as it does on Linux.
        "SETOPTIONS asking for TRACEFORK"*) echo ptrace-setoptions ;;
        # sysreg: CTR_EL0's bits 35:32 are TminLine, the memory-tagging granule.
        # This interpreter does not implement FEAT_MTE, so zero is the honest
        # answer and the host's 9 is its own. Every field below bit 32 -- the
        # cache line sizes, IDC, DIC and L1Ip, which are the ones a JIT acts on
        # -- agrees exactly, and the decoded line beside this one is what checks
        # that.
        "  CTR_EL0 "*) echo ctr-no-mte-granule ;;
        # rlimit: raising a hard limit back after lowering it needs
        # CAP_SYS_RESOURCE, which docker's default profile drops and which the
        # guest's root has -- so this measures the container's capabilities
        # rather than either kernel's rule, the same way `mount` and `mbind` do.
        # The rule itself is checked by the case above it, which lowers the hard
        # limit and is allowed on both sides.
        "  raise it back to infinity"*) echo rlimit-raise-needs-cap-sys-resource ;;
        # decode: four architectural extensions this interpreter does not
        # implement, in the scalar integer groups. Each is correctly **absent
        # from `AT_HWCAP`** — which is the half that matters, and the half that
        # was wrong the other way round on 2026-09-02, when SHA-1, SHA-256,
        # SHA-512 and CRC32 were all decoded and none was claimed. A guest that
        # reads the word before it branches will not emit any of these; the CPU
        # under the container has them, so it runs them.
        #
        # FEAT_PAuth: PACIA/PACIB/PACDA/PACDB and their AUT counterparts, and
        # PACGA. HWCAP_PACA is bit 30 and HWCAP_PACG bit 31; neither is set.
        "  dp1s sf1 S0 op2_1 op0"*) echo decode-no-pauth ;;
        "  dp2s sf1 S0 op12 "*) echo decode-no-pauth ;;
        # FEAT_CSSC: CTZ, CNT and ABS in the one-source group, SMAX/UMAX/SMIN/
        # UMIN in the two-source one. HWCAP2 is zero.
        # Both widths are spelled out: a `?` inside the quotes of a `case`
        # pattern is a literal question mark, not a wildcard, and the first
        # version of these two entries suppressed nothing for that reason.
        "  dp1s sf0 S0 op2_0 op06 "*|"  dp1s sf0 S0 op2_0 op07 "*|"  dp1s sf0 S0 op2_0 op08 "*)
            echo decode-no-cssc ;;
        "  dp1s sf1 S0 op2_0 op06 "*|"  dp1s sf1 S0 op2_0 op07 "*|"  dp1s sf1 S0 op2_0 op08 "*)
            echo decode-no-cssc ;;
        "  dp2s sf0 S0 op24 "*|"  dp2s sf0 S0 op25 "*|"  dp2s sf0 S0 op26 "*|"  dp2s sf0 S0 op27 "*)
            echo decode-no-cssc ;;
        "  dp2s sf1 S0 op24 "*|"  dp2s sf1 S0 op25 "*|"  dp2s sf1 S0 op26 "*|"  dp2s sf1 S0 op27 "*)
            echo decode-no-cssc ;;
        # FEAT_MTE: SUBP, SUBPS, IRG and GMI. There is no memory tagging here --
        # a guest page is a host page and there are no tag bits to check against
        # -- so this is not a gap that could be filled without the address space
        # growing a tag store. HWCAP2_MTE is zero.
        "  dp2s sf1 S0 op00 "*|"  dp2s sf1 S1 op00 "*|"  dp2s sf1 S0 op04 "*|"  dp2s sf1 S0 op05 "*)
            echo decode-no-mte ;;
        # ...and `ADDG`/`SUBG`, the immediate forms of the same feature.
        "  addsubg "*) echo decode-no-mte ;;
        # faultread: a `read` into a buffer the caller cannot write. Linux's
        # answer is not one rule, it is one per driver: a pipe keeps its bytes
        # and a regular file keeps its offset, while an eventfd, a signalfd, a
        # unix socket and an inotify all drop the item they had taken out.
        #
        # This kernel keeps it in all six, and the reason is the shape rather
        # than a choice about these four: a read here bounces through a host
        # buffer and copies to the guest afterwards, so "consume what landed" is
        # not expressible per driver -- the driver never sees the copy. What is
        # expressible is not consuming what cannot be delivered, and that is one
        # rule for every descriptor. The two Linux keeps, it now keeps too, which
        # is the half that loses data irrecoverably; these four are the half
        # where being more careful than Linux costs a guest nothing, because it
        # can only be reached by passing a pointer the caller does not own.
        #
        "  eventfd:   still pending"*|"  eventfd: read into a good buffer"*)
            echo faultread-kept-where-linux-drops ;;
        "  signalfd:   still pending"*|"  signalfd: read into a good buffer"*)
            echo faultread-kept-where-linux-drops ;;
        "  unix datagram socket:   still pending"*|"  unix datagram socket: read into a good buffer"*)
            echo faultread-kept-where-linux-drops ;;
        "  inotify:   still pending"*|"  inotify: read into a good buffer"*)
            echo faultread-kept-where-linux-drops ;;
        # faultread: the blocking form. Linux copies only after it has data, so a
        # blocking read into a wholly unwritable buffer waits -- possibly for
        # ever -- and reports the fault when something finally arrives. This
        # answers EFAULT at once. Reproducing the wait means parking a thread in
        # order to deliver an error to a buffer that cannot receive anything
        # either way. The *non-blocking* form is reproduced exactly, which is the
        # case a program can be written around: EAGAIN when there is nothing to
        # give and EFAULT when there is.
        "  blocking read(an empty pipe, unmapped, 64)"*)
            echo faultread-blocking-answers-at-once ;;
        # uring: io_uring and rseq are not implemented, and the table says why
        # at 293 and 425-427. This kernel answers as one built without them,
        # `ENOSYS`; the container answers `EPERM` to io_uring through docker's
        # seccomp profile (a real descriptor without it), and `EFAULT` to an
        # rseq registration of NULL because it has rseq. The PI futex family
        # had an entry here until 2026-11-11; it is implemented now.
        "  io_uring_"*) echo uring-not-implemented ;;
        # mm_modern: memfd_secret is ENOSYS here, which is what a kernel with
        # `secretmem.enable=0` answers. Its promise is that the kernel cannot
        # read the memory (process_vm_readv of it is EFAULT on the reference),
        # and ordinary shared memory behind the descriptor would not keep it.
        # Every line of the section, so both sides print as many.
        "memfd_secret"*) echo memfd-secret-not-configured ;;
        "  rseq(NULL"*) echo rseq-not-implemented ;;
        # table: three of these are the **container** rather than the kernel,
        # in the shape this file already carries for `clock_settime` -- calls
        # docker's dropped capabilities refuse for every argument. 161
        # `sethostname` and 162 `setdomainname` want CAP_SYS_ADMIN and 116
        # `syslog` CAP_SYSLOG; the guest is root in its own kernel and gets the
        # real answer. The sweep runs with docker's seccomp profile off since
        # 2026-11-11 (see `docker_opts`), which is what retired the entry for
        # 435 `clone3` -- the profile answered it ENOSYS on purpose -- and made
        # 39 `umount2` and 40 `mount` agree. (235 `mbind` is ENOSYS here now,
        # as on the reference kernel, which has no NUMA, and is not swept.)
        # 224 `swapon` and 225 `swapoff` want CAP_SYS_ADMIN before the path,
        # so the container says EPERM where the guest gets EFAULT for NULL.
        "  161 -> "*|"  162 -> "*|"  224 -> "*|"  225 -> "*) echo table-needs-cap-sys-admin ;;
        # 58 `vhangup` wants CAP_SYS_TTY_CONFIG, which the container drops and
        # the guest's root has: EPERM there, and 0 here for a caller with no
        # controlling terminal, which is Linux's answer with the capability.
        "   58 -> "*) echo table-vhangup-needs-cap-sys-tty-config table-settimeofday-needs-cap-sys-time ;;
        # 170 `settimeofday(NULL, NULL)` wants CAP_SYS_TIME and changes
        # nothing: EPERM in the container, which drops it, and 0 for the
        # guest's root, which is Linux's answer with it (`caps_probe`, run
        # privileged, agrees).
        "  170 -> "*) echo table-settimeofday-needs-cap-sys-time ;;
        # atcall: sethostname's length rule is behind CAP_SYS_ADMIN, which
        # docker's container lacks, so it answers EPERM to every length; the
        # guest is root in its own kernel and gets EINVAL past 64 and success
        # otherwise. It used to be EPERM here for everyone, root included.
        "  sethostname, "*) echo atcall-sethostname-needs-cap-sys-admin ;;
        # atcall: `setdomainname` is the same call writing the other field of
        # the same struct -- one helper, `set_name_ok`, which checks the
        # capability first and the length second, in Linux's order. Probed
        # since 2026-09-06 because it had nothing at all, and a pair that
        # shares a helper and differs by one field is where a swap hides.
        "  setdomainname, "*) echo atcall-setdomainname-needs-cap-sys-admin ;;
        # fcntl: the SIGIO family, which this kernel does not have. F_SETOWN,
        # F_GETOWN, F_SETOWN_EX, F_GETOWN_EX, F_SETSIG, F_GETSIG and F_NOTIFY
        # all exist to arrange for a *signal* when a description becomes ready,
        # and nothing here raises one -- so accepting them would leave a program
        # that asked for the signal waiting for ever, which is worse than being
        # told the kernel does not do it. EINVAL is what an fcntl command this
        # kernel does not know answers, and unlike a socket option there is no
        # room for anything better: F_GETOWN legitimately returns negatives, so
        # an errno and a result are not separable. See the TODO in sys_fcntl.
        "F_SETOWN"*|"F_GETOWN"*|"  F_GETOWN after"*|"F_SETSIG"*|"F_GETSIG"*|"  F_GETSIG after"*)
            echo fcntl-no-sigio ;;
        "F_NOTIFY"*) echo fcntl-no-dnotify ;;
        # timer: ITIMER_VIRTUAL and ITIMER_PROF count **CPU** time, and this
        # kernel has no running total to hang a deadline on -- user and system
        # time are sampled from the host on demand, not accumulated, and one
        # host process runs every guest process, so the host's own CPU timers
        # count the wrong thing. Firing them would mean polling the rusage on a
        # timer, whose resolution would be the poll interval.
        #
        # EINVAL rather than a timer that never fires, which is the choice with
        # the better failure: a program refused falls back (Go's CPU profiler
        # and gprof both do), where one that is accepted and never signalled
        # waits for ever. `getitimer` still answers for them -- asking whether
        # one is armed is a question with an answer, and it is "no". See the
        # module comment in crates/kernel/timecalls/src/timers.rs.
        "  ITIMER_VIRTUAL"*|"  ITIMER_PROF"*) echo itimer-no-cpu-clocks ;;
        # path: a guest path longer than the **host's** PATH_MAX, which on macOS
        # is 1024 where Linux's is 4096. Every mount that keeps a file's bytes
        # in a host file -- realfs, and fakefs through it -- has to hand the
        # path to the host in one call, so a 1804-byte path is ENAMETOOLONG
        # here and ENOENT there. Measured: the boundary is at 1024 bytes and
        # not at a component count.
        #
        # Fixable, and not cheaply: it would mean walking the host tree with
        # `openat` on a directory descriptor per component, since a component
        # is bounded by NAME_MAX and always fits. What is lost meanwhile is an
        # errno for a path nobody has, on a path no distribution builds.
        "  900 one-byte components"*) echo path-hosts-shorter-path-max ;;
        # statfs: *which* filesystem, and how it was mounted. A container's root
        # is overlayfs and its /dev is tmpfs, mounted relatime and nosuid; this
        # kernel's root is a passthrough of a host directory and its /dev is a
        # fakefs, and it has no mount options to report beyond the four
        # `MS_*` a guest can pass. The magic is this kernel's own on purpose --
        # impersonating ext4 would invite a program to use ext4 ioctls -- and
        # what the field is actually *for* is compared and agrees: /proc
        # differs from the root, a pipe differs from a socket, and a path and a
        # descriptor onto the same file agree.
        #
        # Claiming RELATIME would close two of these lines and would be the
        # "stored instead of applied" mistake this tree already records: the
        # behaviour happens to match because the host's does, not because this
        # kernel implements the option.
        "  the root "*|"  the scratch directory "*|"  /dev "*) echo statfs-not-a-linux-filesystem ;;
        "  a regular file "*) echo statfs-not-a-linux-filesystem ;;
        "  /proc "*|"  /proc/self/stat, a file on it "*) echo statfs-no-mount-options ;;
        "  116 -> "*) echo table-syslog-epperm-in-a-container ;;
        # table: 158 `getgroups(0, NULL)` answers how many supplementary groups
        # the caller has, which is a property of the process and not of the
        # kernel. A container's first process inherits some; a guest's first
        # process has nothing to inherit from and has none. The same shape as
        # signalfd_probe's signal 34.
        "  158 -> "*) echo table-getgroups-counts-the-processs-own ;;
        # table: 92 `personality(0xffffffff)` reports the current personality,
        # and this kernel's default is ADDR_NO_RANDOMIZE where Linux's is
        # PER_LINUX. Deliberate, and documented in crates/kernel/procattr: there
        # is no address randomisation here, so the bit is *true*, and a program
        # that checks it before re-executing itself under `setarch` can skip
        # that.
        "   92 -> "*) echo table-personality-no-randomize ;;
        # sysreg: `dc zva` is refused and DCZID_EL0 says so, which is the pair
        # that matters: a guest reads DZP before using the instruction, and
        # musl and glibc both do. Answering "prohibited" and then refusing is
        # self-consistent; the alternative is a gadget that zeroes 64 bytes
        # through the TLB, which is a feature and not a fix. Three lines: the
        # register, its decoding, and the instruction.
        "  DCZID_EL0"*) echo dczid-zva-prohibited ;;
        "  dc zva bytes zeroed"*) echo dczid-zva-prohibited ;;
        # prctl: PR_GET_SECCOMP answers the container's own filter mode (2):
        # docker installs a filter before the probe runs. The guest's first
        # process runs under none, and says 0.
        "PR_GET_SECCOMP "*) echo prctl-seccomp-is-the-containers ;;
        # prctl: the capability bounding set. Docker drops CAP_SYS_ADMIN and
        # CAP_CHECKPOINT_RESTORE from a container's; a guest's first process
        # has a full one, as init's is. The drop test uses CAP_CHOWN, which
        # both have.
        "PR_CAPBSET_READ(CAP_SYS_ADMIN) "*) echo prctl-bounding-set-is-the-containers ;;
        "PR_CAPBSET_READ(CAP_CHECKPOINT_RESTORE)"*) echo prctl-bounding-set-is-the-containers ;;
        # prctl: PR_SET_MM and PR_{GET,SET}_IO_FLUSHER want CAP_SYS_RESOURCE,
        # which docker's default set lacks, so the container answers EPERM to
        # every argument -- the seccomp-profile shape again. The guest is root
        # in its own kernel and gets the argument rules.
        "PR_SET_MM(99) "*) echo prctl-set-mm-needs-cap-sys-resource ;;
        "PR_GET_IO_FLUSHER"*|"PR_SET_IO_FLUSHER"*) echo prctl-io-flusher-needs-cap-sys-resource ;;
        # prctl: PR_TSC_SIGSEGV asks for every cntvct_el0 read to trap, which
        # 7.0 arm64 can do; honouring it would put a test on the counter-read
        # gadget every clock_gettime goes through. Refused as EINVAL, which is
        # what every kernel before 7.0 answered.
        "PR_SET_TSC(PR_TSC_SIGSEGV)"*) echo prctl-counter-cannot-trap ;;
        # prctl: the host CPU has SME and the container's kernel reports its
        # vector length; this kernel advertises no SME in AT_HWCAP2 and
        # implements none of it, so the honest answer is EINVAL.
        "PR_SME_GET_VL"*) echo prctl-sme-is-the-hosts ;;
        # prctl: tagged addresses. The memory path here hashes and indexes on
        # the top byte, so enabling TBI would fault on the first tagged
        # pointer. This kernel answers as one whose abi.tagged_addr_disabled
        # sysctl is set -- EINVAL to enable, 0 to a query -- which is a state
        # a portable program already handles. See crates/kernel/procattr.
        "PR_SET_TAGGED_ADDR_CTRL(PR_TAGGED_ADDR_ENABLE)"*) echo prctl-tagged-addr-disabled ;;
        "PR_GET_TAGGED_ADDR_CTRL after"*) echo prctl-tagged-addr-disabled ;;
        # exec: the container's kernel has a binfmt_misc handler for x86-64
        # (Rosetta), so a file that is only an x86-64 ELF *header* is handed to
        # it and dies there -- "rosetta error: no program header table
        # entries found" on stderr. A kernel with no such handler answers
        # ENOEXEC, which is what this one does.
        "an x86-64 ELF header"*) echo exec-container-has-binfmt-misc-for-x86 ;;
        # clone: every namespace flag. Docker's seccomp profile answers EPERM
        # to a clone naming one before the kernel sees it -- including the
        # pairs the kernel itself refuses with EINVAL, CLONE_NEWNS|CLONE_FS
        # among them. This kernel has no namespaces and answers EINVAL to all
        # of them, which is what a kernel built without them answers.
        "CLONE_NEW"*) echo clone-namespaces-are-seccomp-in-the-container ;;
        "CLONE_THREAD | CLONE_VM | CLONE_SIGHAND | CLONE_NEW"*) echo clone-namespaces-are-seccomp-in-the-container ;;
        "CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_NEWNS"*) echo clone-namespaces-are-seccomp-in-the-container ;;
        # shm: nattch after a fork. Linux counts attaches per process, so a
        # child that inherits one makes it two; here the child shares the
        # parent's mapping record and it stays one until both have detached.
        # It reaches zero at the same moment either way, which is what
        # SHM_DEST and PostgreSQL's stale-segment check look at. See the
        # module comment in crates/kernel/sysvshm.
        "  nattch in the child"*) echo shm-nattch-is-per-mapping-not-per-process ;;
        # shm: a segment of 2^62 bytes. Linux's is a sparse tmpfs file and
        # costs nothing until touched; a segment here is a host file, and
        # APFS answers EFBIG to a truncate that large -- the same shape as
        # `ftruncate-max-file-size` above, and the same host limit.
        "size 2^62"*) echo shm-segment-size-is-the-hosts-file-size-limit ;;
        # clock2: clock_settime and settimeofday. Docker's default seccomp
        # profile answers EPERM to both for every argument without
        # CAP_SYS_TIME; the kernel validates the clock, the pointer and the
        # time first. These lines were compared against an unconfined
        # container by hand (2026-11-11) and agree there.
        "  clock_settime("*|"  settimeofday("*) echo clock-settime-is-seccomp-in-the-container ;;
        # clock2: clock_getres. These clocks are the host's, and macOS says a
        # microsecond for every one of them; Linux with high-resolution timers
        # says a nanosecond, and a tick for the coarse clocks. Reporting the
        # host's is reporting the truth about the clock a guest reads.
        *"gettime ok getres 0s 1000ns") echo clock-res-is-the-hosts ;;
        # clock2: timer_create on a CPU-time clock. A deadline on CPU time
        # needs a running total to hang it on, and CPU time here is sampled
        # from the host on demand -- the reason ITIMER_VIRTUAL and ITIMER_PROF
        # are refused (itimer-no-cpu-clocks). EOPNOTSUPP is what Linux answers
        # for a clock with no timers; Go falls back to setitimer on any error.
        "  PROCESS_CPUTIME_ID "*"-EOPNOTSUPP"|"  THREAD_CPUTIME_ID "*"-EOPNOTSUPP") echo timer-create-no-cpu-clocks ;;
        "  own process, "*"-EOPNOTSUPP"|"  own thread, "*"-EOPNOTSUPP") echo timer-create-no-cpu-clocks ;;
        "  pid 0, SCHED "*"-EOPNOTSUPP"|"  tid 0, SCHED "*"-EOPNOTSUPP") echo timer-create-no-cpu-clocks ;;
        # epoll2: EPOLLEXCLUSIVE across separate sets. Linux wakes the first
        # set that has a waiter and stops; here each set has its own host
        # kqueue and every one of them hears the event, so all four wake. The
        # flag's contract is "one or more", which this meets: it avoids a
        # thundering herd, and a program using it reads non-blocking and
        # takes EAGAIN from the wakeups that lose. Waking exactly one would
        # need the member to pick a set, which a host descriptor (the pipe
        # case) cannot.
        "  "*"EPOLLEXCLUSIVE"*": exactly one woke"*|"  "*"EPOLLEXCLUSIVE"*": all four woke"*)
            echo epoll-exclusive-wakes-every-set ;;
        # mqueue: the queues' filesystem is not mountable here, so
        # /proc/filesystems does not list it and nothing is at /dev/mqueue --
        # which a container runtime mounts and a bare kernel does not. The six
        # syscalls do not depend on either; see crates/kernel/mqueuecalls.
        "  /proc/filesystems lists mqueue "*" false"|"  /dev/mqueue (a container mounts one) "*" absent")
            echo mqueue-not-mountable ;;
        # aio: RWF_NOWAIT on an IOCB_CMD_PREAD is the same mount property as
        # preadv2's above; IOCB_FLAG_IOPRIO's realtime class needs
        # CAP_SYS_NICE, which the container's root lacks.
        "  RWF_NOWAIT read "*) echo aio-rwf-nowait-is-a-mount-property ;;
        "  IOCB_FLAG_IOPRIO realtime "*) echo aio-ioprio-rt-needs-cap-sys-nice ;;
        # aio: a poll completed by a driver's wakeup. Linux reports the
        # wakeup's key unfiltered; this kernel's drivers do not notify with
        # Linux's keys, so it reports readiness masked by what was asked. See
        # crates/kernel/aio's poll module.
        "    res, after a "*" write woke it "*) echo aio-poll-result-is-not-the-wake-key ;;
        # rarecalls_probe: the calls this kernel answers as built without the
        # feature (acct, modules) or leaves unimplemented (pivot_root), each
        # with its reason at its line in crates/kernel/syscalltable's table.
        # The reference has all three.
        "acct("*) echo acct-not-configured ;;
        "init_module("*|"delete_module("*|"finit_module("*) echo modules-not-configured ;;
        "pivot_root("*) echo pivot-root-not-implemented ;;
        # procaccess_probe: /proc/<pid>/stack and /proc/<pid>/pagemap, which
        # this kernel does not have, so they are ENOENT whoever asks; Linux's
        # are 0400 and ask ptrace access. `stack` is the task's kernel stack,
        # and `pagemap` gives a privileged reader physical frame numbers (an
        # unprivileged one reads 0 for them, measured): a guest task has no
        # kernel stack and its pages are host memory the host does not
        # number, so neither has an honest answer. Last, because the arms
        # below them are general.
        "mode of pagemap "*|"mode of stack "*) echo procpid-stack-pagemap-not-here ;;
        "1000 -> "*|"fs 1000 -> "*|"root -> "*|"own, undumpable: "*)
            case "$1" in
                *": pagemap "*|*": stack "*) echo procpid-stack-pagemap-not-here ;;
            esac ;;
    esac
}

# Every tag known_ok can print. An entry that suppresses nothing is a *stale*
# entry, and this script reports one as its own verdict (exit 3) -- because an
# allowlist nobody checks is how a check becomes vacuous. That has happened here
# before: a rule written as "every line longer than 73 characters has a space at
# 72" ran over an empty set and passed with the column deliberately wrong.
ALL_KNOWN="kcmp-no-epoll-tfd seccomp-root-has-cap-sys-admin unshare-namespaces-not-configured setns-namespaces-not-configured setns-no-nsfs listns-not-configured landlock-not-configured bpf-not-configured perf-not-configured userfaultfd-not-configured keys-not-configured ngroups-max-is-32 procsys-only-what-this-kernel-decides memfd-secret-not-configured pidfd-info-no-cgroups pidfd-no-namespaces xattr-trusted-needs-cap-sys-admin xattr-security-needs-cap-sys-admin xattr-trusted-not-set-in-the-container xattr-name-limit-is-the-hosts xattr-value-limit-is-the-filesystems prio-lowering-needs-cap-sys-nice prio-no-realtime-policy prio-rr-interval-is-machine-state prio-rt-class-needs-cap-sys-admin statx-subvol statx-no-attributes linkat-empty-path ctr-no-mte-granule dczid-zva-prohibited mmap-placement mmap-overcommit o-tmpfile msg-oob msg-oob-in-every-bit rwf-nowait-is-a-mount-property ftruncate-max-file-size pipe-page-granularity auxv-no-rseq auxv-no-rseq-keys tiocgptpeer ptrace-setoptions membarrier-no-rseq membarrier-no-rseq-register membarrier-no-registrations mknod-block-needs-host-root select-nfds-clamped-to-table decode-no-fhm decode-no-fhm2 decode-by-element-extensions table-needs-cap-sys-admin table-vhangup-needs-cap-sys-tty-config table-syslog-epperm-in-a-container table-getgroups-counts-the-processs-own table-personality-no-randomize uring-not-implemented rseq-not-implemented rlimit-raise-needs-cap-sys-resource faultread-kept-where-linux-drops faultread-blocking-answers-at-once decode-no-pauth decode-no-cssc decode-no-mte openat2-o-tmpfile open-accmode-3 statmount-container-root-is-pivoted clock-settime-is-seccomp-in-the-container clock-res-is-the-hosts timer-create-no-cpu-clocks epoll-exclusive-wakes-every-set mqueue-not-mountable aio-rwf-nowait-is-a-mount-property aio-ioprio-rt-needs-cap-sys-nice aio-poll-result-is-not-the-wake-key acct-not-configured modules-not-configured pivot-root-not-implemented procpid-stack-pagemap-not-here caps-mknod-needs-host-root caps-realfs-owner-is-the-hosts caps-realfs-group-is-the-hosts caps-realfs-chmod-owner-is-the-hosts caps-write-keeps-file-caps"

# A KNOWN entry whose case has stopped happening and whose cause is **not
# established**. `tag|since|what is unexplained`.
#
# The rule above -- an entry that suppresses nothing is stale, delete it -- is
# right, and it is the wrong rule for an entry nobody can explain the silence
# of. `writev-partial-fault` has looked stale three times and been correct each
# time; the fourth reading, on 2026-09-11, is the first that is *stable* (ten
# runs out of ten on an idle machine, and the same on a release build of the
# previous commit), so "a flake under load" no longer covers it and nothing else
# does either. This repository's own rule is that a clean re-run is evidence of
# nothing, which cuts both ways: it is not evidence that the entry may go.
#
# So it is neither deleted nor allowed to fail the run. What an OBSERVING entry
# buys, and it is less than an active one:
#
#   - it still suppresses, so a difference on that case cannot fail the gate;
#   - but every line it suppresses is **printed**, where an active entry's are
#     counted and thrown away. So the case coming back is visible in the output
#     rather than silent, which is the half of the staleness rule that was
#     actually doing work.
#
# An entry here is not a resting place. It carries the date it went under
# observation so that its age is in every run's output, and the next person to
# look should start from the question in the comment beside the case -- what
# moved between 2026-09-04 and bc0b98e8 -- and not from re-running it.
#
# One entry per line, `tag|since|why`. Newline-separated and not
# space-separated, because the third field is a sentence.
OBSERVING="writev-partial-fault|2026-09-11|it answers EFAULT here now, stably, where every earlier reading said it wrote something; what changed is not established"
fired=""
observed=""

# A tag is active or under observation, never both -- the two say opposite
# things about what its silence means, and a name in both lists would make the
# staleness rule depend on which loop ran last. And an OBSERVING tag that
# `known_ok` cannot print is a name watching nothing, which is the stale-entry
# problem one level up.
printf '%s\n' "$OBSERVING" | while IFS='|' read -r tag _rest; do
    [ -n "$tag" ] || continue
    case " $ALL_KNOWN " in
        *" $tag "*)
            echo "probe_diff: $tag is in ALL_KNOWN and in OBSERVING" >&2
            exit 2 ;;
    esac
    # `echo <tag>`, not the bare tag: the bare tag matches this list itself, so
    # the check would pass for a name known_ok has never heard of.
    grep -q "echo $tag" "$0" || {
        echo "probe_diff: OBSERVING names $tag, which known_ok never prints" >&2
        exit 2
    }
done || exit 2

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT INT TERM

probes=""
for src in tests/guest/src/bin/*_probe.rs; do
    n="$(basename "$src" .rs)"
    if [ -n "$WANT" ]; then
        for w in $WANT; do
            case "$n" in *"$w"*) probes="$probes $n" ;; esac
        done
    else
        probes="$probes $n"
    fi
done
[ -n "$probes" ] || { echo "no probes matched" >&2; exit 2; }

# The baseline covers exactly the probes there are.
#
# Both halves are load-bearing and neither is symmetric with the other. A probe
# with **no** baseline file would otherwise be skipped, which is the shape this
# tree calls a check that covers nothing: a new probe would be added, compared
# against nothing, and counted as agreement -- and `renameat2` already hid for a
# full sweep by being skipped on one side and run on the other. A baseline file
# naming a probe that is **gone** is the stale-build-output shape
# differential.sh reports: it records a kernel's answer about a program nobody
# can run any more.
if [ "$MODE" = recorded ]; then
    [ -d "$BASELINE" ] || {
        echo "probe_diff: no baseline at $BASELINE" >&2
        echo "  record one on a machine with docker: probe_diff.sh --record" >&2
        exit 2
    }
    missing=""
    for p in $probes; do
        [ -f "$BASELINE/$p.txt" ] || missing="$missing $p"
    done
    if [ -n "$missing" ]; then
        echo "probe_diff: no recorded baseline for:$missing" >&2
        echo "  A probe with no baseline is a probe nothing compares. Record one" >&2
        echo "  on a machine with docker: tests/integration/probe_diff.sh --record" >&2
        exit 2
    fi
    if [ -z "$WANT" ]; then
        orphan=""; stray=""
        for f in "$BASELINE"/*.txt; do
            b="$(basename "$f" .txt)"
            case "$b" in
                recorded-with) continue ;;
                # Anything that is not a probe's recording and not the header.
                # Named rather than ignored: a file nobody can account for in a
                # directory a gate reads is how the next one gets ignored too.
                *_probe) [ -f "tests/guest/src/bin/$b.rs" ] || orphan="$orphan $b" ;;
                *) stray="$stray $b.txt" ;;
            esac
        done
        if [ -n "$orphan" ]; then
            echo "probe_diff: baseline files for probes that no longer exist:$orphan" >&2
            echo "  Delete them; they record a kernel's answer about a program" >&2
            echo "  nobody can run." >&2
            exit 2
        fi
        if [ -n "$stray" ]; then
            echo "probe_diff: $BASELINE holds files that are neither a probe's" >&2
            echo "  recording nor recorded-with.txt:$stray" >&2
            exit 2
        fi
    fi
    # Which kernel the expected values came from, on every run. A reference
    # nobody can name is one nobody can re-take.
    if [ -f "$BASELINE/recorded-with.txt" ]; then
        sed 's/^/  /' "$BASELINE/recorded-with.txt"
    else
        echo "  WARNING: $BASELINE/recorded-with.txt is missing, so nothing says" >&2
        echo "  which kernel these files came from." >&2
    fi
fi

# The Linux side of one probe, into $2. Either a container or the recording.
# The container options a probe is recorded with, when the defaults would
# answer for docker rather than for the kernel -- the shape differential.sh's
# `seccomp_off` has. The default profile refuses most of the calls these name
# with EPERM or ENOSYS whatever their arguments, and the guest is root with
# every capability in its own kernel, so each probe gets the capabilities its
# subject is gated on. A recording made without them would put the
# container's refusals in the baseline as the kernel's answers.
docker_opts() {
    case "$1" in
        # set_tid is gated on CAP_CHECKPOINT_RESTORE; pidfd_getfd on the
        # seccomp profile.
        pidfd_modern_probe) printf -- '--security-opt seccomp=unconfined --cap-add CHECKPOINT_RESTORE' ;;
        # A remote process_madvise and the NUMA calls are CAP_SYS_NICE's.
        mm_modern_probe) printf -- '--security-opt seccomp=unconfined --cap-add SYS_NICE' ;;
        # seccomp, unshare, kcmp, keyctl, bpf, perf and the rest are the
        # profile's; sched_setattr lowering a nice value is CAP_SYS_NICE's.
        procsec_probe) printf -- '--security-opt seccomp=unconfined --cap-add SYS_NICE' ;;
        # Every number with zero arguments: the profile answers EPERM or
        # ENOSYS for a third of the newer ones whatever they are given -- it
        # was why 435 clone3 had a KNOWN entry -- so the sweep asks the kernel.
        # The capabilities stay docker's, and the entries that differ for want
        # of one (116, 161, 162) are KNOWN with that reason.
        table_probe) printf -- '--security-opt seccomp=unconfined' ;;
        # The profile answers ENOSYS for file_getattr and file_setattr and
        # EPERM for open_by_handle_at, which is a statement about the
        # container.
        fsat_probe) printf -- '--security-opt seccomp=unconfined' ;;
        # The container's overlayfs re-opens the lower file for every write,
        # with the description's O_APPEND, so RWF_NOAPPEND appends there and
        # writes at the offset on tmpfs or ext4. A tmpfs /tmp asks the rule
        # rather than the overlay.
        rwf_probe) printf -- '--tmpfs /tmp' ;;
        # The swap, quota, accounting, module and hangup calls are
        # CAP_SYS_ADMIN's, CAP_SYS_PACCT's, CAP_SYS_MODULE's and
        # CAP_SYS_TTY_CONFIG's, all of which the guest's root has. Every case
        # that reaches the kernel is an error path or the probe's own objects.
        # A tmpfs /tmp so quotactl_fd asks a filesystem rather than the overlay.
        rarecalls_probe) printf -- '--privileged --tmpfs /tmp' ;;
        # vhangup is CAP_SYS_TTY_CONFIG's.
        ttyhup_probe) printf -- '--privileged' ;;
        # The probe mounts a tmpfs of its own to map a file on.
        mapsdev_probe) printf -- '--privileged' ;;
        # And so does this one, to map files on a tmpfs.
        mmfault_probe) printf -- '--privileged' ;;
        # The guest's root reads an undumpable process of another user by
        # CAP_SYS_PTRACE, which docker's default set drops.
        procaccess_probe) printf -- '--privileged' ;;
        # Every caller is a dropped identity of the container's root, which
        # needs CAP_SETUID; the root rows need CAP_SYS_PTRACE and
        # CAP_SYS_NICE, and process_vm_readv, kcmp and pidfd_getfd the
        # seccomp profile off.
        crossperm_probe) printf -- '--privileged' ;;
        # Root writes another process's timerslack_ns by CAP_SYS_NICE and
        # follows map_files links by CAP_SYS_ADMIN.
        procstate_probe) printf -- '--privileged' ;;
        # /proc/sys is read-only in a container that is not privileged. The
        # probe puts back the value it found, which is the VM's own.
        suiddump_probe) printf -- '--privileged' ;;
        # Every case starts from a root with full sets, as the guest's does;
        # docker's default bounding set is fourteen capabilities.
        caps_probe) printf -- '--privileged' ;;
        *) printf '' ;;
    esac
}

linux_side() {
    if [ "$MODE" = recorded ]; then
        cat "$BASELINE/$1.txt" > "$2"
        return 0
    fi
    # shellcheck disable=SC2046 # the options word-split on purpose
    docker run --rm --platform linux/arm64 $(docker_opts "$1") -v "$PWD/$BINDIR:/t:ro" "$IMAGE" \
        "/t/$1" > "$2" || true
    # Written before the comparison, not after it, and unconditionally: the file
    # is a measurement of what a real kernel answered and does not depend on
    # whether this kernel agreed. Recording only the agreeing half would make the
    # baseline a record of this emulator with a container's name on it.
    if [ "$RECORD" = 1 ]; then
        mkdir -p "$BASELINE"
        cp "$2" "$BASELINE/$1.txt"
    fi
}

# The emulator's own diagnostics for the probe just run, printed where they are
# the explanation of a difference rather than everywhere.
show_stderr() {
    [ -s "$tmp/iul.err" ] || return 0
    echo "  the emulator's stderr during this probe:"
    sed 's/^/    /' "$tmp/iul.err"
}

differ=0
for p in $probes; do
    printf '\n########## %s ##########\n' "$p"
    # Standard output only. A probe's report is what is being compared, and
    # the emulator writes its own diagnostics to stderr -- one "stub syscall
    # 77" line for an unimplemented call was enough to make the two sides
    # disagree about how many lines they had printed, which reads as "one of
    # them died early".
    #
    # stderr is **kept and printed only when the probe differs**, which is not
    # the same as throwing it away. It used to go straight to the terminal so
    # that a crash was visible, and that is still true: a crash truncates the
    # probe's output, which makes the line counts disagree, which is a
    # difference -- so the stderr is printed exactly where it is the
    # explanation. What it stops being is 390,000 lines of register dump from
    # `decode_probe`, which raises `SIGILL` once per encoding it deliberately
    # does not implement. That is 30 MB of log for a run whose finding is one
    # line, and this is the gate a CI job reads; a report nobody can scroll to
    # is a report nobody reads.
    #
    # IUL_PROBE_STDERR=1 prints all of it, and a run that suppresses any says
    # how much it suppressed.
    # Copy beside and rename, never over the top. macOS caches a binary's code
    # signature by inode, so writing new bytes into a file that has been
    # executed gets the next exec SIGKILLed with no output at all -- see
    # docs/changelog/2026-09-03-copying-a-binary-over-itself-got-it-sigkilled.md,
    # which cost an hour of diagnosing a lock bug that was not there. `mv` gives
    # the new contents a new inode.
    cp "$BINDIR/$p" "$ROOTFS/tmp/$p.new"
    mv -f "$ROOTFS/tmp/$p.new" "$ROOTFS/tmp/$p"
    # Stdin from /dev/null, as `docker run` without `-i` gives the recorded
    # side. `deadline_probe` polls fd 0 and a pipe whose writer has gone
    # answers POLLHUP, so a run from a caller whose stdin was a finished pipe
    # reported ppoll returning where Linux "blocked" -- a difference about how
    # the gate was launched, found on 2026-09-30 by a background verify.
    if [ -n "${IUL_PROBE_STDERR:-}" ]; then
        "$IUL" -r "$ROOTFS" "/tmp/$p" < /dev/null > "$tmp/iul" || true
        : > "$tmp/iul.err"
    else
        "$IUL" -r "$ROOTFS" "/tmp/$p" < /dev/null > "$tmp/iul" 2> "$tmp/iul.err" || true
    fi
    linux_side "$p" "$tmp/linux"

    # Paired line by line: a probe prints the same cases in the same order on
    # both sides, so a diff that is not one-to-one means one of them died
    # early -- which is worth saying rather than drowning in.
    if [ "$(wc -l < "$tmp/iul")" != "$(wc -l < "$tmp/linux")" ]; then
        echo "  the two runs printed different numbers of lines:"
        echo "    here:  $(wc -l < "$tmp/iul") lines"
        if [ "$MODE" = recorded ]; then
            echo "    recorded: $(wc -l < "$tmp/linux") lines"
            # The commonest cause by far, and worth naming rather than leaving
            # to be worked out: a probe gained a case and the recording is from
            # before it. Silently accepting that is how a new case gets compared
            # against nothing.
            echo "  (a case was added or removed since the baseline was recorded,"
            echo "   or one of them stopped early; re-record with --record on a"
            echo "   machine with docker. The diff follows.)"
        else
            echo "    linux: $(wc -l < "$tmp/linux") lines"
            echo "  (one of them stopped early; the diff follows)"
        fi
        diff "$tmp/iul" "$tmp/linux" | sed 's/^/    /' || true
        show_stderr
        differ=$((differ+1))
        continue
    fi

    n=0
    said=0
    differ_before=$differ
    while IFS= read -r mine && IFS= read -r theirs <&3; do
        n=$((n+1))
        [ "$mine" = "$theirs" ] && continue
        case "$mine" in \#\#*) continue ;; esac
        tag=$(known_ok "$mine")
        if [ -n "$tag" ]; then
            fired="$fired $tag"
            # An OBSERVING tag suppresses like any other and, unlike any other,
            # says what it suppressed. The entry is there because its case had
            # *stopped* differing for a reason nobody established, so the case
            # coming back is the observation it is waiting for -- and an
            # observation that only increments a counter is one nobody reads.
            case "$OBSERVING" in
                *"$tag|"*)
                    observed="$observed $tag"
                    if [ "$said" = 0 ]; then echo "  differences:"; said=1; fi
                    printf '    [%s, under observation]\n' "$tag"
                    printf '    here:  %s\n' "$mine"
                    printf '    linux: %s\n' "$theirs"
                    ;;
            esac
            continue
        fi
        if [ "$said" = 0 ]; then echo "  differences:"; said=1; fi
        printf '    here:  %s\n' "$mine"
        printf '    linux: %s\n' "$theirs"
        differ=$((differ+1))
    done < "$tmp/iul" 3< "$tmp/linux"
    if [ "$differ" != "$differ_before" ]; then
        show_stderr
    elif [ -s "$tmp/iul.err" ]; then
        # Said, not shown. "Nothing on stderr" and "a lot on stderr that was
        # suppressed" must not read the same, which is this file's own rule
        # about counts one level down.
        echo "  ($(wc -l < "$tmp/iul.err" | tr -d ' ') lines on the emulator's stderr," \
             "suppressed; IUL_PROBE_STDERR=1 shows them)"
    fi
    [ "$said" = 0 ] && echo "  $n cases, none unexplained"
done

echo
# Every entry under observation, whichever way it went. Printed on every full
# run, with the date, so that an entry's *age* is in the output rather than
# only in this file -- an exception whose cost nobody sees is one nobody closes.
if [ -z "$WANT" ]; then
    printf '%s\n' "$OBSERVING" | while IFS='|' read -r tag since why; do
        [ -n "$tag" ] || continue
        case " $observed " in
            *" $tag "*) state="fired -- the case is back, and this is the reading it was waiting for" ;;
            *) state="did not fire, as on the run that put it here" ;;
        esac
        echo "probe_diff: under observation since $since: $tag"
        echo "  $why"
        echo "  this run: $state"
    done
fi

# A KNOWN entry that suppressed nothing this run. Either the difference was
# fixed -- in which case delete the entry -- or the case that produced it is
# gone, in which case the reason it records is no longer being tested.
#
# Reported **after** the comparison's own verdict and with its own exit code,
# because the two are different findings and the first used to hide the second:
# this ran first and exited before `$differ` was looked at, so a stale entry
# turned a run with real differences into a run that reported an allowlist
# problem. See the exit-code table at the top.
stale=""
for k in $ALL_KNOWN; do
    case " $fired " in *" $k "*) ;; *) stale="$stale $k" ;; esac
done

if [ "$differ" != 0 ]; then
    echo "probe_diff: $differ difference(s) not in KNOWN"
    echo "  Each is a question: which of the two is right? Measure before assuming"
    echo "  it is Linux -- five of the first nine differences a sweep like this"
    echo "  found were in the *tests*."
    [ -z "$stale" ] || [ -n "$WANT" ] || \
        echo "  (and KNOWN entries that suppressed nothing:$stale)"
    exit 1
fi

n_known=$(echo "$fired" | wc -w | tr -d ' ')
if [ -n "$stale" ] && [ -z "$WANT" ]; then
    echo "probe_diff: every case agrees with a real kernel or is in KNOWN, but"
    echo "  these entries suppressed nothing:$stale"
    echo "  Each was a difference someone read and justified. If it no longer"
    echo "  happens, delete the entry -- an allowlist that outlives its reason"
    echo "  hides the next difference that lands on the same case. If the reason"
    echo "  it stopped is not established, move it to OBSERVING with a date."
    exit 3
fi
echo "probe_diff: every case agrees with a real kernel, or is one of the"
echo "  $n_known differences in KNOWN, each with a reason"
exit 0
