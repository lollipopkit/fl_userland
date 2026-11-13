#!/usr/bin/env python3
"""A dependency that points the wrong way up the tree.

`crates/` has six directories and they are a **layering**, not a filing system:

    util        no guest, no kernel state: locks, logging, string helpers
    emu         the CPU state and the software TLB
    asbestos    the interpreter -- the block cache, the compiler, dispatch
    kernel      syscalls and the objects they operate on
    fs          the VFS and the mount types, which is `kernel`'s own layer
    tools       binaries: the CLI, fakefsify, the interpose library

Cargo refuses a *cycle*, which is what caught nine of these on 2026-09-05 when
the C ABI calls became Rust ones. It says nothing about an edge that merely
points upward -- `util-locks` reaching into `kernel-taskcalls` is a perfectly
acyclic mistake, and until this file there was nothing to notice it.

The rule is: **a crate may depend on its own layer or a lower one.** `kernel`
and `fs` are one layer, because a filesystem reads the calling task's ids and a
syscall reaches the VFS, and 165 edges run each way.

`crates/kernel/abi` is exempt everywhere and is the reason this check needs an
exemption at all: it is the shared types — the guest's wire formats, `struct
cpu_state`, `struct fd`, `struct mount` and `struct task` — which every layer
depends on by design.

**The exemption was `kernel-taskview` until 2026-09-09**, and that crate was two
things: 3,500 lines of types and 760 of accessors over `current`. Exempting the
whole of it exempted the accessors too, which is a gate covering nothing for 81
crates' worth of edges. The types are `crates/kernel/abi` now and `taskview` is
an ordinary crate this rule applies to.

Every other exception is named below with a reason, and an entry that stops
applying fails the run -- the same rule every allowlist in this tree has,
because an entry that suppresses nothing has stopped recording a decision and
started waiting to cover something else.

Run by hand, or as `tools/checks.sh crate_layers`.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

LAYER = {
    "util": 0,
    "emu": 1,
    "asbestos": 2,
    "kernel": 3,
    "fs": 3,
    # `crates/iul` is not in a group: it is the staticlib that names every
    # kernel and filesystem crate, and `crates/tools/iul` links it as an *rlib*
    # to get the Rust half without a second copy of the standard library. So it
    # sits between the two -- above `fs` and `kernel`, below `tools`.
    #
    # It sat outside this check entirely until 2026-09-09, because the glob was
    # `crates/*/*/Cargo.toml` and this one is `crates/iul/Cargo.toml`. A
    # one-crate blind spot, found by this file's own count disagreeing with
    # `tools/crate-graph.py`'s by one.
    "iul": 4,
    "tools": 5,
}

# **Empty since 2026-09-09**, and that is the point of the entry rather than
# a leftover.
#
# It held `crates/kernel/taskview` when this check landed -- 81 crates depended
# on that one for the shared C types, so exempting it exempted its 760 lines of
# accessors too, and `util-locks` reaching into the *kernel* layer for a pid was
# invisible to a gate written to catch exactly that. Splitting the types out
# into `crates/kernel/abi` narrowed it to a crate that only holds types, and
# then the question was what the low layers actually took from it:
#
#   util/locks, util/waitfor, util/guestlock   lock_t, cond_t, wrlock_t
#   asbestos/diag                              c_int, c_void, CStr -- all `std`
#   emu/tlb, asbestos/{dispatch,gen,blockcache}  cpu_state, tlb, mmu, fiber_block
#
# None of it is a kernel type. `crates/util/synctypes` and `crates/emu/abi` own
# them now and `kernel-abi` re-exports both, so every consumer still writes
# `taskview::ffi::lock_t` and nothing was exempt from anything.
#
# **Leave it empty.** A name here suppresses every upward edge into that crate
# at once, which is what made the first version of this check answer nothing;
# `ALLOWED` below names the *edge* and fails when it stops existing.
FOUNDATION: set[str] = set()

# (from, to) -> why. An entry whose edge no longer exists fails the run.
ALLOWED = {
    ("asbestos-dispatch", "kernel-pagetable"): (
        "the dispatch loop reads and writes page flags -- P_CODE for W^X, and "
        "the mapping generation the TLB's coherence check compares against. "
        "The page table is guest memory rather than kernel policy, so this is "
        "the interpreter reaching sideways for the thing it executes out of."
    ),
}


def crates():
    """name -> (layer, directory), for every workspace crate."""
    out = {}
    for manifest in manifests():
        name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', manifest.read_text())
        if not name:
            continue
        group = group_of(manifest)
        assert group in LAYER, f"{manifest}: unknown group {group!r}"
        out[name.group(1)] = (LAYER[group], group)
    return out


def manifests():
    """Every crate manifest, at either depth.

    `crates/<group>/<crate>/Cargo.toml` for all but one, and
    `crates/iul/Cargo.toml` for the staticlib.
    """
    return sorted(ROOT.glob("crates/*/*/Cargo.toml")) + sorted(ROOT.glob("crates/*/Cargo.toml"))


def group_of(manifest):
    """The directory that names the layer."""
    rel = manifest.relative_to(ROOT / "crates").parts
    return rel[0] if len(rel) == 2 else rel[0]


def deps(manifest):
    """The `[dependencies]` names, without dev- or build-dependencies.

    Only the normal ones: a dev-dependency is allowed to point anywhere, which
    is what lets a leaf crate's test link `iul` for the gadgets.
    """
    text = manifest.read_text()
    if "[dependencies]" not in text:
        return []
    section = text.split("[dependencies]", 1)[1]
    for stop in ("[dev-dependencies]", "[build-dependencies]", "\n[features]", "\n[target"):
        section = section.split(stop, 1)[0]
    return [m.group(1) for m in re.finditer(r"(?m)^([\w-]+)\s*=", section)]


def main():
    known = crates()
    upward = []
    seen = set()
    edges = 0

    for manifest in manifests():
        name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', manifest.read_text())
        if not name:
            continue
        name = name.group(1)
        here, _ = known[name]
        for dep in deps(manifest):
            if dep not in known:
                continue
            edges += 1
            there, group = known[dep]
            if there <= here or dep in FOUNDATION:
                continue
            seen.add((name, dep))
            if (name, dep) not in ALLOWED:
                upward.append((name, here, dep, group, there))

    stale = sorted(set(ALLOWED) - seen)

    print(f"{len(known)} crates, {edges} dependency edges between them")
    print(f"{len(FOUNDATION)} foundation crate(s), exempt everywhere")
    print(f"{len(ALLOWED)} allowed upward edge(s), {len(stale)} of them stale")

    if stale:
        print("\nAllowed edges that no longer exist:")
        for a, b in stale:
            print(f"  {a} -> {b}")
        print(
            "\nAn entry that suppresses nothing has stopped recording a\n"
            "decision. Delete it, or find out why the edge went away."
        )

    if upward:
        print("\nDependencies that point up the tree:")
        for name, here, dep, group, there in upward:
            print(f"  {name} (layer {here}) -> {dep} (layer {there}, {group}/)")
        print(
            "\nA lower layer reaching into a higher one is a layering mistake\n"
            "cargo cannot see, because it is not a cycle. The three answers, in\n"
            "the order to try them, are in CLAUDE.md: move the code to where it\n"
            "belongs, install a hook in the leaf crate, or return the decision\n"
            "instead of acting on it. If it is none of those, add it to ALLOWED\n"
            "with the reason."
        )

    if upward or stale:
        return 1
    print("\nEvery dependency points down the tree or across it.")
    return 0



if __name__ == "__main__":
    sys.exit(main())
