#!/usr/bin/env bash
#
# The matrix: install real software in a real userland and use it.
#
# Usage:  tests/integration/full.sh [-i <iul>] [-d alpine,rocky,ubuntu]
#                                  [-s cc,node,go,rust,postgres,git,sqlite,redis,nginx,ssh]
#
# Everything here needs the network, which is why it is not the pull-request
# gate — see tests/integration/smoke.sh. Run it by hand or from the nightly
# workflow, and read a failure as "this suite has an opinion", not "the branch
# is broken", until the log says which.
#
# ## What is under test
#
# Not the package manager's authors' work. The package manager *is* the test:
# apk, dnf and apt each fork and exec their way through hundreds of processes,
# hit the filesystem constantly, and use syscalls no benchmark thinks to. That
# a toolchain then compiles and runs a program is the second half. Since
# 2026-09-04 a database server is the third: PostgreSQL's initdb, a daemonised
# start, queries and a clean stop, as a non-root guest user on a fakefs -- the
# one cell on the mount type the product ships.
#
# The fourth is the five programs that reach parts of this kernel nothing else
# here does. **git** renames its index into place, hardlinks an object store for
# a local clone, reads packfiles through `mmap` and forks hundreds of processes
# doing it; **sqlite** in WAL mode is a shared file mapping and `fcntl` record
# locking used together, by two processes at once, which is the combination a
# database is; **redis** forks to save, so `BGSAVE` walks the whole heap in a
# child while the parent keeps writing it, and it refuses to start at all unless
# `/proc/<pid>/smaps` can answer what a forked page is; **nginx** is a
# master/worker server whose master talks to its workers over a signal-driven
# `socketpair`, and which treated the two calls that arm it as fatal; **ssh** is
# the only cell with a **pty** in it end to end, and sshd refuses a session when
# `ttyname` on the slave fails, which it did because `isatty` on a modern glibc
# is `ioctl(TCGETS2)` and that was `ENOTTY`. None is a toolchain and none is a
# package manager, so all five fail differently from everything above.
#
# ## Known failures, so a run reads as a result rather than a mess
#
# The /dev gap that stopped both glibc distributions outright is fixed: `iul -r`
# mounts a small fakefs at /dev and creates the nodes in it. **All twelve cells
# pass on a case-sensitive volume** as of 2026-09-04 -- the first time any
# ubuntu case had, and the first time the matrix was green. What is left:
#
#   rocky / dnf    Pass on a case-sensitive filesystem and **cannot pass on
#   ubuntu / cc    macOS's default one**: the kernel headers -- rocky's
#                  `kernel-headers`, Ubuntu's `linux-libc-dev`, which
#                  `libc6-dev` pulls in -- ship both `xt_CONNMARK.h` and
#                  `xt_connmark.h`, and a realfs mount is the host's names.
#                  This file said for two weeks that "rpm holds directory
#                  descriptors and openat()s through them"; that was a guess,
#                  and the measurement that replaced it is in rootfs.sh's
#                  header along with the volume that fixes it. rootfs.sh
#                  warns when the cache folds case.
#
# Fixed along the way, and listed here because the failures they caused looked
# like distribution problems rather than emulator ones:
#
#   PostgreSQL 18 could not answer a query under its default
#   `io_method = worker`: `SetLatch` is `kill(pid, SIGURG)` with SIGURG blocked
#   and read through a `signalfd` in an epoll set, and a signalfd in an epoll
#   set never became readable -- delivery woke the thread, which is enough for
#   a `poll()` and not for epoll. A backend waited for an IO worker until its
#   authentication timeout.
#
#   `apt-get update` failed with "Dynamic MMap ran out of room" -- this file
#   said "fails on the fetch itself", and it was mremap: apt forks its fetch
#   methods and then writes its 24 MB cache one page at a time, so by the
#   first growth some pages were copy-on-write and some were not, and this
#   kernel read that per-page state as a mapping boundary and answered
#   EFAULT. **No Ubuntu package could be installed**, ever.
#   Behind it, three of the four package names in this table were rocky's
#   spelled at ubuntu: libc6-dev, golang-go and rustc are Debian's.
#
#   A rootfs ships directories at 555 -- rocky's /usr/bin is `dr-xr-xr-x` --
#   and a guest running as root on a realfs mount cannot write into one,
#   because the guest's root is not the host's user. rpm's cpio answered
#   "symlink failed - No such file or directory" for every package, and that
#   was recorded above as the emulator's failure for as long as this file has
#   existed. rootfs.sh `chmod -R u+w`s the tree now; the guest's view of the
#   modes is unchanged, because it sees the host's.
#
#   The ELF loader zeroed a segment's last page only as far as its bss, where
#   Linux's padzero clears the whole rest of the page. glibc's loader bumps brk
#   from the end of its own image, into exactly those bytes, and calloc there
#   assumes they are zero -- so the main link_map landed on the .comment
#   section and **no dynamically-linked glibc program ran at all**. rocky died
#   with SIGSEGV before printing anything; musl never reads those bytes, which
#   is why alpine was unaffected.
#
#   fchownat(AT_SYMLINK_NOFOLLOW) on a realfs mount passed 0 for the *host's*
#   flags, so the host followed a link the VFS had already resolved. apk sets
#   ownership on every file it extracts, under its temporary `.apk.<hash>`
#   name, and a package's symlinks point at names that are not there yet --
#   so ENOENT, and **every alpine suite failed at its first `apk add`**. The
#   VFS has already applied the caller's follow semantics by the time a mount
#   sees the path; following again is a second resolution nobody asked for.
#
#   setsockopt(IPPROTO_IP, IP_RECVERR) answered EINVAL, and glibc treats that as
#   fatal in its resolver — socket, setsockopt, close, and not one DNS query on
#   the wire. Every glibc distribution could not resolve a name.
#
#   syncfs was a stub returning ENOSYS, which ended a dnf transaction that had
#   already downloaded everything.
#
# Nothing is skipped on account of the remaining failure. A known failure
# that stops being run is a known failure that never gets fixed.
#
# ## The cache is not pristine
#
# Packages installed by a run stay in the tree, so running this twice locally
# does not test installation the second time — the compile and the run still
# are. CI gets a fresh runner, which is where installation is really under
# test. To reset by hand: rm -rf build/integration/<name> (chmod -R u+w first;
# a rootfs ships 555 directories).

set -uo pipefail
cd "$(dirname "$0")/../.."

IUL=""
DISTROS="alpine,rocky,ubuntu"
SUITES="cc,node,go,rust,postgres,git,sqlite,redis,nginx,ssh"
# -v prints a failing case's whole output rather than its last twelve lines.
# A package manager's real complaint is often hundreds of lines above the
# summary it ends with, and the tail alone said "exit 100" for an apt run whose
# cause was in a maintainer script.
VERBOSE=0
while getopts "i:d:s:vh" opt; do
    case $opt in
        i) IUL="$OPTARG" ;;
        d) DISTROS="$OPTARG" ;;
        s) SUITES="$OPTARG" ;;
        v) VERBOSE=1 ;;
        h) sed -n '2,30p' "$0"; exit 0 ;;
        *) exit 2 ;;
    esac
done

if [ -z "$IUL" ]; then
    for cand in build-arm64-release/iul build/iul; do
        [ -x "$cand" ] && { IUL="$cand"; break; }
    done
fi
[ -n "$IUL" ] && [ -x "$IUL" ] || { echo "no iul binary; build one or pass -i" >&2; exit 2; }

# Per-run, for the reason smoke.sh gives at greater length: the rootfs keeps
# what a run leaves in it, and two cases writing /tmp/g collided.
SCRATCH="/tmp/iul-full-$$"

pass=0; fail=0; failed_names=""

# Runs a script in the guest and requires a marker in its output. A marker
# rather than the whole of stdout, because a package manager prints progress
# nobody should have to predict; the marker is printed by the thing under test
# after it has worked.
run_case() {
    local distro="$1" rootfs="$2" name="$3" marker="$4" script="$5" rootflag="${6:--r}"
    local out started elapsed status
    started=$SECONDS
    # `set -e` inside the guest, and the status carried back out: a marker alone
    # is not a result. gcc printing CC-OK after `apk add` failed is a pass by
    # accident — the tree is reused between runs, so the compiler may already be
    # there from a previous one, and the install being under test is the whole
    # point of this tier.
    out="$("$IUL" "$rootflag" "$rootfs" /bin/sh -c "set -e; mkdir -p $SCRATCH; $script; rm -rf $SCRATCH" 2>&1)"
    status=$?
    elapsed=$((SECONDS - started))
    if [ "$status" != 0 ]; then
        fail=$((fail+1)); failed_names="$failed_names $distro/$name"
        printf '  FAIL  %-8s %-12s %3ds  (exit %s)\n' "$distro" "$name" "$elapsed" "$status"
        show_failure "$out"
    elif printf '%s' "$out" | grep -q "$marker"; then
        pass=$((pass+1)); printf '  PASS  %-8s %-12s %3ds\n' "$distro" "$name" "$elapsed"
    else
        fail=$((fail+1)); failed_names="$failed_names $distro/$name"
        printf '  FAIL  %-8s %-12s %3ds\n' "$distro" "$name" "$elapsed"
        show_failure "$out"
    fi
}

show_failure() {
    if [ "$VERBOSE" = 1 ]; then
        printf '%s\n' "$1" | sed 's/^/        | /'
    else
        printf '%s\n' "$1" | tail -12 | sed 's/^/        | /'
    fi
}

# How each distro installs things. The commands differ, the assertion does not.
#
# Each ends by throwing the downloaded packages away. The tree is cached
# between runs and the *packages* are re-downloadable, so keeping them costs
# disk for nothing — and running out of it does not read as running out of it:
# `apt` answers "E: Write error - write (28: No space left on device)" from
# inside the guest, which looks like an emulator defect until someone runs
# `df`. Three trees plus their fakefs copies had 700 MB of `.deb` and `.rpm`
# between them on 2026-09-04, on a 5.8 GB volume.
install_cmd() {
    case "$1" in
        alpine) echo "apk add --no-progress -q" ;;
        rocky)  echo "dnf install -y -q" ;;
        ubuntu) echo "apt-get update >/dev/null 2>&1; apt-get install -y -q" ;;
    esac
}

# The other half of the line above: run after the install in each cell.
clean_cmd() {
    case "$1" in
        alpine) echo "rm -rf /var/cache/apk/* 2>/dev/null || true" ;;
        rocky)  echo "dnf clean packages -q 2>/dev/null || true" ;;
        ubuntu) echo "apt-get clean 2>/dev/null || true" ;;
    esac
}

# Package names, which are the same idea under three spellings.
pkg_for() {
    case "$1/$2" in
        alpine/cc)   echo "gcc musl-dev" ;;
        rocky/cc)    echo "gcc glibc-devel" ;;
        ubuntu/cc)   echo "gcc libc6-dev" ;;
        */node)      echo "nodejs" ;;
        ubuntu/go)   echo "golang-go" ;;
        rocky/go)    echo "golang" ;;
        */go)        echo "go" ;;
        ubuntu/rust) echo "rustc cargo" ;;
        */rust)      echo "rust cargo" ;;
        alpine/postgres) echo "postgresql16" ;;
        rocky/postgres)  echo "postgresql-server" ;;
        ubuntu/postgres) echo "postgresql" ;;
        */git)           echo "git" ;;
        ubuntu/sqlite)   echo "sqlite3" ;;
        */sqlite)        echo "sqlite" ;;
        ubuntu/redis)    echo "redis-server redis-tools" ;;
        */redis)         echo "redis" ;;
        # rocky spells the client package plural.
        rocky/ssh)       echo "openssh-server openssh-clients" ;;
        */ssh)           echo "openssh-server openssh-client" ;;
        ubuntu/nginx)    echo "nginx-light curl" ;;
        # Not `curl` on rocky: the base image ships `curl-minimal`, which
        # provides the same binary and *conflicts* with the full package, so
        # asking for it fails the transaction rather than being a no-op.
        rocky/nginx)     echo "nginx" ;;
        */nginx)         echo "nginx curl" ;;
    esac
}

# A fakefs for the one suite that has to run as a non-root guest user. Every
# other cell runs on a tree as a realfs, which reports the *host's* ownership --
# fine for root, and what made PostgreSQL's `initdb` fail its first chmod as
# `postgres`. The fakefs keeps ownership and modes in meta.db, which is also what
# the product ships.
#
# **Its own tree, from the same tarball**, cached beside the others and built
# once. Not the realfs tree: the two mounts disagree about where a file's mode
# lives -- meta.db for a fakefs, the host inode for a realfs -- so a tree used
# both ways loses the modes of everything the fakefs installed as soon as meta.db
# is rebuilt from the host. That is not hypothetical: it left /usr/sbin/adduser
# at 0666 and ssl-cert's postinst answering "addgroup: Permission denied", which
# read as an emulator defect for a day.
#
# Built once and kept, like the realfs trees and for the same reason: what a run
# installs stays for the next one, and this file says so under "The cache is not
# pristine". meta.db is built when the tree is, and not again.
fakefs_of() {
    local distro="$1" tree fake
    tree="$(tests/integration/rootfs.sh "$distro" fakefs)" || return 1
    # A *different* name from the tree's, which is `<distro>-fakefs`: the two
    # collided in the first version, so `data` was a symlink to the directory
    # holding it and `meta.db` was written inside the tree.
    fake="$(dirname "$tree")/$distro-fakemount"
    if [ ! -f "$fake/meta.db" ]; then
        mkdir -p "$fake" || return 1
        # The tree *is* the fakefs data. A symlink rather than a copy, so the
        # two names are one directory and rootfs.sh's cache rules still apply.
        [ -e "$fake/data" ] || ln -s "$tree" "$fake/data" || return 1
        "$(dirname "$IUL")/tools/fakefsify" --index "$fake" >/dev/null 2>&1 || return 1
    fi
    echo "$fake"
}

for distro in ${DISTROS//,/ }; do
    echo
    echo "########## $distro ##########"
    install="$(install_cmd "$distro")"
    clean="$(clean_cmd "$distro")"

    # Once per distro rather than once per case. The tree is cached, so a
    # second call is a stat; what changes is that rootfs.sh's warning about
    # the host filesystem prints once, above the results it explains, instead
    # of four times.
    if ! rootfs="$(tests/integration/rootfs.sh "$distro")"; then
        fail=$((fail+1)); failed_names="$failed_names $distro/rootfs"
        printf '  FAIL  %-8s %-12s  no rootfs\n' "$distro" "rootfs"
        continue
    fi

    for suite in ${SUITES//,/ }; do
        pkg="$(pkg_for "$distro" "$suite")"
        # rocky spells glibc's headers differently and has no `go` in the base
        # repos; a missing name is a failure of this table, so say so rather
        # than reporting the suite as broken.
        # A distro or suite this table does not know is a typo in the
        # invocation. Counted as a failure: a workflow_dispatch with a bad input
        # used to report "full: 0 passed" and exit 0.
        if [ -z "$pkg" ]; then
            fail=$((fail+1)); failed_names="$failed_names $distro/$suite"
            printf '  FAIL  %-8s %-12s  no package name in this table\n' "$distro" "$suite"
            continue
        fi

        case "$suite" in
            cc)
                # A quoted heredoc, not printf: the source travels through
                # bash and then the guest's shell, and a %d in it is a format
                # specifier to both of them before it is ever C.
                run_case "$distro" "$rootfs" cc "CC-OK 42" "
                    $install $pkg >/dev/null; $clean
                    cat > $SCRATCH/h.c <<'SRC'
#include <stdio.h>
int main(void) { printf(\"CC-OK %d\\n\", 6 * 7); return 0; }
SRC
                    gcc -O2 -o $SCRATCH/h $SCRATCH/h.c && $SCRATCH/h"
                ;;
            node)
                run_case "$distro" "$rootfs" node "NODE-OK" "
                    $install $pkg >/dev/null; $clean
                    node -e 'console.log(\"NODE-OK\", process.version)'"
                ;;
            go)
                run_case "$distro" "$rootfs" go "GO-OK" "
                    $install $pkg >/dev/null; $clean
                    mkdir -p $SCRATCH/g && cd $SCRATCH/g
                    cat > main.go <<'SRC'
package main

import \"fmt\"

func main() { fmt.Println(\"GO-OK\", 6*7) }
SRC
                    go mod init x >/dev/null 2>&1
                    # No network for modules: the program imports only the
                    # standard library, so the toolchain is what is being
                    # tested, not the module proxy.
                    GOFLAGS=-mod=mod GOPROXY=off go build -o $SCRATCH/g/x . && $SCRATCH/g/x"
                ;;
            rust)
                run_case "$distro" "$rootfs" rust "RUST-OK" "
                    $install $pkg >/dev/null; $clean
                    cat > $SCRATCH/r.rs <<'SRC'
fn main() { println!(\"RUST-OK {}\", 6 * 7); }
SRC
                    rustc -O -o $SCRATCH/r $SCRATCH/r.rs && $SCRATCH/r"
                ;;
            postgres)
                # A database server: initdb, a start through pg_ctl -- which
                # daemonises, waits on the pid file and connects -- a table,
                # an index-free aggregate over a thousand rows, and a clean
                # stop. It needs System V shared memory for the postmaster's
                # interlock, /dev/shm for its dynamic shared memory, and a
                # non-root user that owns what it makes; the first two were
                # missing until 2026-09-04 and the third is why this cell runs
                # on a fakefs. Debian puts the binaries under
                # /usr/lib/postgresql/<v>/bin and not on PATH.
                if ! fake="$(fakefs_of "$distro")"; then
                    fail=$((fail+1)); failed_names="$failed_names $distro/postgres"
                    printf '  FAIL  %-8s %-12s  could not build the fakefs tree\n' "$distro" postgres
                    continue
                fi
                run_case "$distro" "$fake" postgres "PG-OK 500500" "
                    $install $pkg >/dev/null; $clean
                    PGBIN=\$(dirname \"\$(command -v initdb 2>/dev/null || ls /usr/lib/postgresql/*/bin/initdb | head -1)\")
                    # A directory of its own under the scratch, because the
                    # scratch is root's and pg_ctl writes its log as postgres.
                    mkdir -p $SCRATCH/pg /run/postgresql
                    chown postgres $SCRATCH/pg /run/postgresql
                    su postgres -s /bin/sh -c \"\$PGBIN/initdb -D $SCRATCH/pg/data >$SCRATCH/pg/initdb.log 2>&1\"
                    su postgres -s /bin/sh -c \"\$PGBIN/pg_ctl -D $SCRATCH/pg/data -l $SCRATCH/pg/pg.log -w -t 180 start\" >/dev/null
                    r=\$(\$PGBIN/psql -U postgres -h /run/postgresql -qtAc 'create table t(a int); insert into t select generate_series(1,1000); select sum(a) from t')
                    su postgres -s /bin/sh -c \"\$PGBIN/pg_ctl -D $SCRATCH/pg/data -w stop\" >/dev/null
                    echo PG-OK \$r" -f
                ;;
            git)
                # git is the widest exercise of the filesystem layer there is
                # in one program: hundreds of forks and execs, packfiles read
                # through mmap, the index written to a temporary and renamed,
                # `gc` hardlinking objects, `fsck` reading every one back, and
                # a local clone that hardlinks the whole object store. None of
                # the other cells touches rename, link or mmap-of-a-file at
                # all.
                #
                # `safe.directory` is the host's answer and not this kernel's:
                # a realfs reports the host user as the owner of every file,
                # the guest is root, and git refuses a repository it does not
                # own. The postgres cell runs on a fakefs for the same reason
                # from the other side.
                run_case "$distro" "$rootfs" git "GIT-OK 2 0" "
                    $install $pkg >/dev/null; $clean
                    export HOME=$SCRATCH GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t
                    export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
                    git config --global --add safe.directory '*'
                    mkdir -p $SCRATCH/r && cd $SCRATCH/r && git init -q .
                    for i in 1 2 3 4 5; do
                        mkdir -p d\$i
                        head -c 20000 /dev/urandom > d\$i/f.bin
                        echo \"line \$i\" > d\$i/f.txt
                    done
                    git add -A && git commit -q -m one
                    echo more >> d1/f.txt && git add -A && git commit -q -m two
                    git gc -q
                    git fsck --no-progress
                    git clone -q $SCRATCH/r $SCRATCH/c && cd $SCRATCH/c
                    echo GIT-OK \$(git log --oneline | wc -l) \$(git status --porcelain | wc -l)"
                ;;
            sqlite)
                # A write-ahead log is the one thing in this matrix that uses
                # a shared file mapping and record locking together: the -shm
                # file is mmap'd MAP_SHARED by every connection and the lock
                # bytes in it are how they agree on who is writing. A reader
                # runs against the writer for the same reason.
                # `-cmd '.timeout 5000'` on every invocation, because two of
                # them run at once and the CLI's default busy timeout is **0**:
                # a reader and a writer that touch the WAL index in the same
                # instant give "database is locked" immediately rather than
                # waiting, which is what every real application sets a timeout
                # to avoid. It is not a weaker test -- the concurrency is still
                # there, and five seconds is long enough that a *real* lock
                # failure still fails.
                run_case "$distro" "$rootfs" sqlite "SQLITE-OK 5001 ok" "
                    $install $pkg >/dev/null; $clean
                    db=$SCRATCH/t.db
                    sq() { sqlite3 -cmd '.timeout 5000' \"\$db\" \"\$1\"; }
                    sq 'pragma journal_mode=wal;' >/dev/null
                    sq 'create table a(x integer primary key, y text);'
                    sq 'with recursive c(i) as (select 1 union all select i+1 from c where i<5000) insert into a select i, '\"'\"'v'\"'\"'||i from c;'
                    sq 'select count(*) from a;' >/dev/null &
                    sq 'insert into a values(999999,'\"'\"'z'\"'\"');'
                    wait
                    sq 'pragma wal_checkpoint(truncate);' >/dev/null
                    echo SQLITE-OK \$(sq 'select count(*) from a;') \$(sq 'pragma integrity_check;')"
                ;;
            redis)
                # A server that forks to save. `BGSAVE` is a `fork` whose child
                # walks the whole heap while the parent keeps writing it, which
                # is the copy-on-write path under load and is not exercised
                # anywhere else here.
                #
                # It also will not start on arm64 unless `/proc/<pid>/smaps`
                # answers -- `checkLinuxMadvFreeForkBug` reads `Shared_Dirty`
                # for a page it forked over, and exits when it cannot. That is
                # what this cell is really guarding.
                run_case "$distro" "$rootfs" redis "REDIS-OK ok" "
                    $install $pkg >/dev/null; $clean
                    mkdir -p $SCRATCH/rd
                    redis-server --port 6399 --save '' --appendonly no \\
                        --dir $SCRATCH/rd --daemonize no &
                    i=0
                    while [ \$i -lt 100 ]; do
                        redis-cli -p 6399 ping 2>/dev/null | grep -q PONG && break
                        i=\$((i+1)); sleep 0.2
                    done
                    redis-benchmark -p 6399 -n 2000 -c 10 -t set,get -q >/dev/null
                    redis-cli -p 6399 bgsave >/dev/null
                    sleep 2
                    s=\$(redis-cli -p 6399 info persistence | tr -d '\\r' |
                         sed -n 's/^rdb_last_bgsave_status://p')
                    redis-cli -p 6399 shutdown nosave 2>/dev/null || true
                    echo REDIS-OK \$s"
                ;;
            ssh)
                # A full SSH session, which is the only cell with a **pty** in
                # it end to end: sshd allocates one with `openpty`, calls
                # `ttyname` on the slave, and refuses the session if that
                # fails. It did, because `isatty` on a modern glibc is
                # `ioctl(TCGETS2)` and that was `ENOTTY`.
                #
                # On a fakefs for the reason the postgres cell is: sshd refuses
                # to start when `/run/sshd` is not owned by root, and a realfs
                # reports the host user as the owner of everything.
                if ! fake="$(fakefs_of "$distro")"; then
                    fail=$((fail+1)); failed_names="$failed_names $distro/ssh"
                    printf '  FAIL  %-8s %-12s  could not build the fakefs tree\n' "$distro" ssh
                    continue
                fi
                run_case "$distro" "$fake" ssh "SSH-OK root /dev/pts/" "
                    $install $pkg >/dev/null; $clean
                    S=$SCRATCH/ssh
                    mkdir -p \$S /run/sshd /root/.ssh
                    ssh-keygen -q -t ed25519 -f \$S/hostkey -N ''
                    ssh-keygen -q -t ed25519 -f \$S/id -N ''
                    cp \$S/id.pub /root/.ssh/authorized_keys
                    chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys
                    cat > \$S/sshd_config <<CONF
Port 2222
ListenAddress 127.0.0.1
HostKey \$S/hostkey
PidFile \$S/sshd.pid
PermitRootLogin prohibit-password
AuthorizedKeysFile /root/.ssh/authorized_keys
UsePAM no
StrictModes no
CONF
                    sshd_bin=\$(command -v sshd || echo /usr/sbin/sshd)
                    \$sshd_bin -f \$S/sshd_config -E \$S/sshd.log
                    sleep 2
                    O='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
                    a=\$(ssh \$O -i \$S/id -p 2222 root@127.0.0.1 'echo \$(id -un)' 2>/dev/null)
                    # -tt forces a pty, which is the half that was broken.
                    b=\$(ssh -tt \$O -i \$S/id -p 2222 root@127.0.0.1 'tty' 2>/dev/null | tr -d '\\r')
                    kill \$(cat \$S/sshd.pid) 2>/dev/null || true
                    echo SSH-OK \$a \$b" -f
                ;;
            nginx)
                # A master/worker server. The master forks workers and talks to
                # them over a `socketpair`, which it puts in signal-driven mode
                # with `ioctl(FIOASYNC)` and `fcntl(F_SETOWN)` -- and treats
                # either failure as fatal, so nginx did not start at all until
                # those two were answered.
                #
                # Then: `epoll` and `accept4` in two workers at once, `sendfile`
                # of a 100 KB file, and a signal to shut down.
                run_case "$distro" "$rootfs" nginx "NGINX-OK 50 100000" "
                    $install $pkg >/dev/null; $clean
                    # rocky's nginx runs its workers as \`nginx\`, and the
                    # rpm scriptlet that makes that user runs once -- so a tree
                    # where it failed stays broken after the cause is fixed.
                    # Making it here is idempotent and is also the check that
                    # useradd works at all, which needs /etc/gshadow readable.
                    getent passwd nginx >/dev/null 2>&1 || {
                        groupadd -r nginx 2>/dev/null
                        useradd -r -g nginx -d /var/lib/nginx -s /sbin/nologin nginx 2>/dev/null
                    } || true
                    mkdir -p $SCRATCH/nx/logs $SCRATCH/nx/html $SCRATCH/nx/tmp
                    head -c 100000 /dev/urandom > $SCRATCH/nx/html/big.bin
                    echo ok > $SCRATCH/nx/html/index.html
                    cat > $SCRATCH/nx/nginx.conf <<CONF
worker_processes 2;
daemon off;
error_log $SCRATCH/nx/logs/error.log warn;
pid $SCRATCH/nx/nginx.pid;
events { worker_connections 64; }
http {
  access_log off;
  client_body_temp_path $SCRATCH/nx/tmp;
  proxy_temp_path $SCRATCH/nx/tmp2;
  fastcgi_temp_path $SCRATCH/nx/tmp3;
  uwsgi_temp_path $SCRATCH/nx/tmp4;
  scgi_temp_path $SCRATCH/nx/tmp5;
  sendfile on;
  server { listen 8099; root $SCRATCH/nx/html; }
}
CONF
                    nginx -c $SCRATCH/nx/nginx.conf -e $SCRATCH/nx/logs/error.log &
                    i=0
                    while [ \$i -lt 100 ]; do
                        curl -s -m 2 -o /dev/null http://127.0.0.1:8099/ && break
                        i=\$((i+1)); sleep 0.2
                    done
                    ok=0; i=0
                    while [ \$i -lt 50 ]; do
                        curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8099/ |
                            grep -q 200 && ok=\$((ok+1))
                        i=\$((i+1))
                    done
                    n=\$(curl -s -m 10 http://127.0.0.1:8099/big.bin | wc -c)
                    kill \$(cat $SCRATCH/nx/nginx.pid) 2>/dev/null || true
                    sleep 1
                    echo NGINX-OK \$ok \$n"
                ;;
            *)
                fail=$((fail+1)); failed_names="$failed_names $distro/$suite"
                printf '  FAIL  %-8s %-12s  unknown suite\n' "$distro" "$suite"
                ;;
        esac
    done
done

echo
if [ "$pass" = "0" ] && [ "$fail" = "0" ]; then
    echo "full: nothing ran — check -d and -s" >&2
    exit 2
fi
if [ "$fail" = "0" ]; then
    echo "full: $pass passed"
    exit 0
fi
echo "full: $fail FAILED, $pass passed —$failed_names"
exit 1
