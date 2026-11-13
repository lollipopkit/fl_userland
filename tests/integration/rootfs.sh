#!/usr/bin/env bash
#
# Puts a guest filesystem on disk and prints the path to it.
#
# Usage:  tests/integration/rootfs.sh <alpine|rocky|ubuntu>
#
# Each tree is unpacked once into build/integration/<name>/ and reused. `build/`
# is ignored by git, so this leaves no trace in the checkout.
# `IUL_INTEGRATION_DIR` moves the whole cache -- tarballs and trees -- elsewhere,
# and the reason to want that is the next section.
#
# ## The host filesystem has to be case-sensitive
#
# A realfs mount is the host's files under the host's names, and so is a
# fakefs's `data/` directory. On a filesystem that folds case -- macOS's
# default APFS volume, including the one a GitHub macOS runner boots from --
# a guest that creates `xt_CONNMARK.h` and then `xt_connmark.h` gets **one
# file**, with the second's contents and the first's name, and no error from
# either call. A program that checks, as rpm does with `O_CREAT|O_EXCL`,
# is refused instead.
#
# rocky's `kernel-headers` and Ubuntu's `linux-libc-dev` both ship exactly
# that pair -- it is the Linux kernel's own `include/uapi/linux/netfilter/`
# -- so `dnf install gcc` and `apt-get install libc6-dev` could not complete
# on this host, and the same packages install on a case-sensitive volume
# without a change to the emulator (measured 2026-09-04, see
# docs/changelog/). There is nothing for the emulator to do: on a passthrough
# mount the names *are* the host's. The fix is the fixture:
#
#   hdiutil create -size 8g -fs 'Case-sensitive APFS' -type SPARSE \
#       -volname iul-integration /tmp/iul-integration
#   hdiutil attach /tmp/iul-integration.sparseimage
#   IUL_INTEGRATION_DIR=/Volumes/iul-integration tests/integration/full.sh
#
# This script checks, and warns; it does not refuse, because alpine's cases
# pass either way and the smoke gate is one of them. Nor does it create the
# volume itself: a mount inside `build/` makes `rm -rf build` fail, and one
# outside it is a host-wide side effect a test script should not have.
#
# ## Why these three
#
# They are the three userland stacks a guest can be, and each exercises a
# different half of the kernel:
#
#   alpine   musl,  apk    — what ServerBox actually ships on iOS
#   rocky    glibc, dnf    — glibc's syscall use differs from musl's throughout,
#                            and dnf is Python, so the package manager is itself
#                            a large workload
#   ubuntu   glibc, apt    — dpkg's maintainer scripts fork and exec far more
#                            than the other two
#
# Ubuntu stands in for Debian, which has no plain rootfs tarball to download:
# debuerreotype publishes only metadata and an OCI layout on its artifact
# branches, and the Docker Hub route needs a registry token. Ubuntu base is the
# same apt/dpkg/glibc stack behind a versioned URL, which is what this needed.
#
# ## Digests
#
# Pinned, and checked before anything is unpacked. This downloads a root
# filesystem and then runs its binaries, so "it came from the right host over
# TLS" is not the standard being applied — the same standard ServerBox holds its
# own rootfs to.
#
# To move one: change the URL and the digest together, and say in the commit
# message which upstream release it is.

set -euo pipefail

cd "$(dirname "$0")/../.."
CACHE="${IUL_INTEGRATION_DIR:-build/integration}"

# The path this prints is what `iul -r` is given, from whatever directory the
# caller is in.
absolute() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *)  printf '%s\n' "$PWD/$1" ;;
  esac
}

# Two names differing only by case, and whether the directory holds both.
# `ls -a` rather than `-e` on each, because on a folding filesystem both
# names *exist* -- they are the same file -- and the count is the question.
case_sensitive() {
  local a="$1/.CaseProbe.$$" b="$1/.caseprobe.$$" n
  touch "$a" "$b" 2>/dev/null || return 0
  n=$(ls -a "$1" | grep -ci "caseprobe\.$$")
  rm -f "$a" "$b"
  [ "$n" = 2 ]
}

case "${1:-}" in
  alpine)
    URL="https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.5-aarch64.tar.gz"
    SHA=3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70
    LAYOUT=plain
    ;;
  rocky)
    # `.latest.` in the name, because Rocky publishes the versioned file with an
    # `.oci.` infix and a build date this would have to chase. The digest below
    # is what that URL served on 2026-08-21; when Rocky publishes a new build it
    # stops matching, and the failure says so rather than running an unknown
    # tree.
    URL="https://dl.rockylinux.org/pub/rocky/9/images/aarch64/Rocky-9-Container-Base.latest.aarch64.tar.xz"
    SHA=254dc06377bb63a5ab390cea33c2f26d71c4e0ff6ae1bc8a0fb0fbb86d992e89
    LAYOUT=oci
    ;;
  ubuntu)
    URL="https://cdimage.ubuntu.com/ubuntu-base/releases/26.04/release/ubuntu-base-26.04-base-arm64.tar.gz"
    SHA=b2b46a37324ea1954e93f293fe6d7c2241daf2fc298c4022e6e4caceeed74cab
    LAYOUT=plain
    ;;
  *)
    echo "usage: $0 <alpine|rocky|ubuntu> [variant]" >&2
    exit 2
    ;;
esac

# A second argument names a *separate* tree from the same tarball -- the same
# distribution, unpacked twice. `full.sh`'s PostgreSQL cell needs one: it mounts
# its tree as a **fakefs**, where a file's mode lives in meta.db and the host
# file is whatever the create left behind, and every other cell mounts the same
# distribution as a realfs, where the host's mode *is* the guest's. Sharing one
# tree between the two models loses the modes of everything the fakefs installed
# the moment meta.db is rebuilt from the host: `/usr/sbin/adduser` came back as
# 0666 and `ssl-cert`'s postinst answered "addgroup: Permission denied".
NAME="$1"
TREE="$CACHE/$NAME${2:+-$2}"
TARBALL="$CACHE/$(basename "$URL")"

# The marker, not the directory: an interrupted unpack leaves a directory that
# looks finished. Written last, and named for the digest so that changing the
# pin above re-unpacks rather than reusing the previous tree.
STAMP="$TREE/.rootfs-sha"

mkdir -p "$CACHE"

# Every run, not only the unpack: the consumer that fails on it is `full.sh`,
# whose trees are cached, so the warning has to be printed on the run that
# fails and not on the one three days earlier that set the tree up.
if ! case_sensitive "$CACHE"; then
  echo "warning: $CACHE folds case, so a guest cannot hold two names differing only by case; the kernel headers (rocky's kernel-headers, Ubuntu's linux-libc-dev) have such a pair. See the header of $0." >&2
fi

# Everything a tree needs that the tarball does not carry, in one place and
# **applied to a cached tree as well as a fresh one**.
#
# That is the whole reason this is a function. Every one of these was added
# because a cell failed without it, and every one was added *after* the trees
# on this machine had been unpacked -- so the fixup shipped, the cache did not
# get it, and the next failure read as an emulator defect rather than a stale
# fixture. nginx on rocky is the one that made the point: `groupadd` answered
# "cannot open /etc/gshadow", the rpm scriptlet could not make its user, and
# nginx refused to start with `getpwnam("nginx") failed` -- against a
# `chmod -R u+rw` that was already in this file and had never run on that tree.
#
# `FIXUPS` is what keeps that cheap: a cached tree re-runs them only when this
# number changes, so the common case is one `cat`. **Bump it when you add one.**
FIXUPS=1

fixups() {
  # **Writable by the host user, because a realfs mount is the host's
  # permissions.** A rootfs ships directories at 555 -- /usr/bin in the rocky
  # image is `dr-xr-xr-x` -- and a guest running as root on a realfs mount cannot
  # write into one, because the guest's root is not the host's. So rpm's cpio
  # answered "symlink failed - No such file or directory" for every package, and
  # `full.sh -d rocky` recorded that as a known *emulator* failure for as long as
  # this suite has existed. It is the fixture: `chmod -R u+w` and dnf installs.
  #
  # The chmod above does the same thing before a re-unpack, for the same reason
  # one directory up -- `rm` cannot unlink from a directory it cannot write.
  #
  # Not a lie about the guest's view: the *modes the guest sees* are unchanged,
  # because it sees the host's, and it is root, so its own permission check
  # already said yes. What this removes is the second check, the host's, which a
  # passthrough mount cannot express the guest's answer through. That is the same
  # argument `realfs`'s `chown_result` makes when it swallows EPERM.
  # `u+rw`, not `u+w`. The write half is argued above; the read half is the same
  # argument for the same reason, and it took a database to find. A rootfs ships
  # `/etc/shadow` and `/etc/gshadow` as `--w-------` -- write-only, no read bit --
  # because on a real system root reads them through CAP_DAC_OVERRIDE. Here the
  # *host* still applies its own permissions to the file underneath, and the host
  # user is not root: `groupadd` answered "cannot open /etc/gshadow", the
  # postgresql-server RPM's scriptlet could not make its user, and the cell failed
  # three steps later with "chown: invalid user: 'postgres'".
  chmod -R u+rw "$TREE" 2>/dev/null || true

  # /tmp is 1777 in every distribution and is **not** what comes out of the
  # tarball here: bsdtar drops the sticky bit when it is not extracting as root,
  # so a fresh tree has a 0755 root-owned /tmp. Anything that drops privilege then
  # cannot use it -- `apt-get update` runs its gpgv method as `_apt`, which needs
  # a temporary directory, and reports "Could not execute 'gpgv' to verify
  # signature (is gnupg installed?)" when it cannot make one. gpgv is installed
  # and runs; the message names the wrong thing.
  mkdir -p "$TREE/tmp"
  chmod 1777 "$TREE/tmp" 2>/dev/null || true

  # The guest resolves names with this, and every tree ships either nothing or a
  # placeholder. Copied from the host, which is the only name server this machine
  # is known to be able to reach.
  if [ -f /etc/resolv.conf ]; then
    mkdir -p "$TREE/etc"
    grep -E '^nameserver' /etc/resolv.conf > "$TREE/etc/resolv.conf" || true
  fi

  # And `localhost`, which glibc looks up through the resolver when /etc/hosts
  # does not answer -- and the resolver above is the host's, which maps every name
  # it does not know into 198.18.0.0/15. PostgreSQL's postmaster then tried to
  # bind 198.18.6.29 for "localhost" and refused to start with "could not create
  # any TCP/IP sockets". musl answers localhost itself, which is why alpine was
  # unaffected and this took a database to find. Ubuntu's base image ships no
  # /etc/hosts at all.
  mkdir -p "$TREE/etc"
  if [ ! -s "$TREE/etc/hosts" ]; then
    printf '127.0.0.1\tlocalhost\n::1\t\tlocalhost ip6-localhost ip6-loopback\n' > "$TREE/etc/hosts"
  fi
}

if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$SHA" ]; then
  # The tarball is the one that is pinned; the fixups may still be newer than
  # this tree. See the comment on `fixups` above.
  if [ "$(cat "$TREE/.rootfs-fixups" 2>/dev/null)" != "$FIXUPS" ]; then
    fixups
    printf '%s\n' "$FIXUPS" > "$TREE/.rootfs-fixups"
  fi
  absolute "$TREE"
  exit 0
fi

if [ ! -f "$TARBALL" ] || [ "$(shasum -a 256 "$TARBALL" | cut -d' ' -f1)" != "$SHA" ]; then
  echo "fetching $NAME" >&2
  curl -fsSL --retry 3 -o "$TARBALL.part" "$URL"
  got="$(shasum -a 256 "$TARBALL.part" | cut -d' ' -f1)"
  if [ "$got" != "$SHA" ]; then
    rm -f "$TARBALL.part"
    echo "error: $NAME digest mismatch" >&2
    echo "       expected $SHA" >&2
    echo "       got      $got" >&2
    echo "       If upstream published a new build, update the pin in $0." >&2
    exit 1
  fi
  mv "$TARBALL.part" "$TARBALL"
fi

# chmod first: a rootfs ships directories at 555, and rm cannot unlink from a
# directory it cannot write. Without this the re-unpack after a digest change
# fails halfway and leaves a tree that is neither the old one nor the new one.
[ -d "$TREE" ] && chmod -R u+w "$TREE" 2>/dev/null
rm -rf "$TREE"
mkdir -p "$TREE"

case "$LAYOUT" in
  plain)
    # Device nodes are skipped without root, which is what is wanted: the guest
    # builds its own /dev.
    tar xf "$TARBALL" -C "$TREE" 2>/dev/null || true
    ;;
  oci)
    # An OCI image layout rather than a filesystem: index.json names a manifest,
    # the manifest names layers, and the layers are the tree. Applied in order,
    # because a multi-layer image is only correct that way even when today's
    # base image has one.
    echo "unpacking the OCI layout" >&2
    OCI="$CACHE/$NAME.oci"
    rm -rf "$OCI"; mkdir -p "$OCI"
    tar xf "$TARBALL" -C "$OCI"
    python3 - "$OCI" "$TREE" <<'PY'
import json, os, subprocess, sys
oci, tree = sys.argv[1], sys.argv[2]

def blob(digest):
    return os.path.join(oci, "blobs", *digest.split(":"))

index = json.load(open(os.path.join(oci, "index.json")))
manifest = json.load(open(blob(index["manifests"][0]["digest"])))
layers = manifest["layers"]
print("%d layer(s)" % len(layers), file=sys.stderr)
for layer in layers:
    # tar rather than tarfile: whiteouts and hardlinks in a real image are the
    # kind of thing a hand-rolled extractor gets subtly wrong, and GNU/bsdtar
    # already knows. Device nodes fail without root and are skipped.
    subprocess.run(["tar", "xf", blob(layer["digest"]), "-C", tree],
                   stderr=subprocess.DEVNULL, check=False)
PY
    rm -rf "$OCI"
    ;;
esac

if [ ! -x "$TREE/bin/sh" ] && [ ! -L "$TREE/bin/sh" ]; then
  echo "error: $NAME unpacked without a /bin/sh" >&2
  exit 1
fi

fixups
printf '%s\n' "$FIXUPS" > "$TREE/.rootfs-fixups"
printf '%s\n' "$SHA" > "$STAMP"
absolute "$TREE"
