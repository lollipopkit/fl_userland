#!/usr/bin/env python3
"""An opaque placeholder whose owning crate the layering already allows naming.

A handful of types in `crates/kernel/abi` and `crates/kernel/taskview` are
field-less `#[repr(C)]` structs:

    pub struct epoll_state { _unused: [u8; 0] }

They stand in for a Rust object some *other* crate owns, so every reader of the
field writes a `.cast()` to get the real type back -- and a `.cast()` between
two raw pointers is accepted whatever is on either end of it. Nothing in a
build, a test or clippy can tell a correct one from a wrong one.

What keeps a placeholder is **layering**, and only layering: a type
`struct task` or `struct fd` names has to sit below the crate that holds the
definition, or cargo refuses the cycle. So the question is one query --

    is the crate that *holds* the placeholder in the owning crate's
    transitive closure?

-- and if the answer is no, the placeholder can become
`pub use owning_crate::Real as name;` today and every cast on that field
becomes a conversion the compiler checks.

**The criterion is the closure and not the name of the first dependency.**
`ctty` was kept opaque for a month by "it depends on `fs-tty`", which is true
and does not imply a cycle; `kernel-taskview` was not in that closure at all.
`kernel-epoll` reads the same way and reaches exactly one crate of the
descriptor layer. Both were found by asking `cargo metadata` instead of reading
the manifest.

The other half of what this catches is a **dead dependency edge**, because the
closure is what it reads: `kernel-sighand` kept `kernel-abi` for three days
after the last `iul_abi::` path in it went, and that edge was the whole of the
reported blocker for three placeholders until somebody grepped.

Reported names are a failure, not a note: unlike `dead-exports.py` there is no
fact outside this repository needed to act on one.

Run by hand, or as `tools/checks.sh placeholder_owners`.
"""

import json
import re
import subprocess
import sys
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The files that hold a placeholder list. A file that stops having one fails the
# run: this check reads source rather than a name list, so an empty subject is
# exactly the "gate covering nothing" the suite is built to make visible.
SOURCES = [
    "crates/kernel/taskview/src/task_types.rs",
    "crates/kernel/abi/src/fd_types.rs",
    "crates/kernel/abi/src/mount_types.rs",
    "crates/kernel/abi/src/memory_types.rs",
    "crates/emu/abi/src/types.rs",
]

# placeholder -> the crate whose Rust object it stands for.
#
# This mapping cannot be derived: a placeholder is field-less by construction,
# so there is nothing in it pointing at the type it erases. It is the doc
# comment above each entry, restated where a machine can read it -- and an entry
# naming a placeholder that no longer exists fails the run, which is the rule
# every allowlist in this tree has.
OWNERS = {
    # `crates/kernel/taskview/src/task_types.rs` has none since 2026-09-29, when
    # `posix_timers_state` became `kernel_posixtimers::Timers`. Still read, so
    # that one added there is reported rather than unseen.
    # `crates/kernel/abi/src/fd_types.rs` has none since 2026-09-29, when
    # `union fd_state` became `driver_state`, an owned `Box<dyn Any>` that
    # names no driver's type -- which is what took `pidfd_state` and
    # `socket_state`, both blocked by a real cycle, without breaking one.
    # `crates/kernel/abi/src/mount_types.rs` has none since 2026-09-29, when
    # `fakedb` became `fakedb::Db`.
    # `crates/kernel/abi/src/memory_types.rs`. The real type is
    # `kernel_pagetable::L0` -- three `.cast::<L0>()` in that crate -- and the
    # entry is the crate rather than the type because that is what the closure
    # question is about.
    "pt_node": "kernel-pagetable",
    # `crates/emu/abi/src/types.rs`: `struct mmu` names the JIT, which is
    # `asbestos_blockcache::Asbestos` since 2026-10-17, one `.cast()` in
    # `Asbestos::of`.
    "asbestos": "asbestos-blockcache",
}

# A placeholder with no owning crate in this workspace, and why.
#
# `docs/object-model-arc.md` listed three names here on 2026-09-12 and **two of
# them were wrong**: `pt_node` is `kernel_pagetable::L0` behind an erased
# pointer with three casts, and `fakedb` is `fakedb::Db` with four. Both are
# ordinary blocked entries above. A name only belongs here when there is no
# second rendering anywhere -- which is what "no owner to compare against"
# has to mean for the exclusion to be safe.
# Empty since 2026-09-29: `DIR` was the one entry, and it is
# `util_hostdir::HostDir` now -- an owned stream rather than a placeholder.
# Still read, so that a name added here is checked like the others.
NO_OWNER = {}


def placeholders():
    """(name, holding crate, file) for every field-less struct in SOURCES.

    Two spellings: an entry in a `handle! { ... }` macro, and a `pub struct X`
    written out with a `_unused: [u8; 0]` body. Both produce the same type.
    """
    found = []
    for rel in SOURCES:
        path = ROOT / rel
        assert path.exists(), f"{rel} is gone; this check has lost its subject"
        text = path.read_text()
        crate = crate_of(path)
        # `handle! { ... }` -- one `name,` per line, doc comments between.
        for block in re.findall(r"(?ms)^handle!\s*\{(.*?)^\}", text):
            for line in block.splitlines():
                line = line.strip()
                if re.fullmatch(r"[A-Za-z_]\w*,", line):
                    found.append((line[:-1], crate, rel))
        # A placeholder written out. `[^{]*` so that a struct with fields, whose
        # body happens to mention the marker later, is not matched.
        for name in re.findall(
            r"(?ms)^pub struct (\w+)\s*\{[^{}]*?_unused:\s*\[u8;\s*0\][^{}]*?\}", text
        ):
            found.append((name, crate, rel))
    return found


def crate_of(path):
    """The package name of the crate a source file belongs to."""
    for parent in path.parents:
        manifest = parent / "Cargo.toml"
        if manifest.exists():
            name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', manifest.read_text())
            if name:
                return name.group(1)
    raise AssertionError(f"no crate owns {path}")


def closures():
    """package name -> the set of package names it can reach, itself included."""
    meta = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1"], cwd=ROOT
        )
    )
    name = {p["id"]: p["name"] for p in meta["packages"]}
    edges = {n["id"]: [d["pkg"] for d in n["deps"]] for n in meta["resolve"]["nodes"]}
    # Two packages may share a name across versions; the workspace's own never
    # do, and a third-party duplicate cannot be an answer here either way.
    ident = {}
    for pid, pname in name.items():
        ident.setdefault(pname, pid)

    out = {}
    for pname, pid in ident.items():
        seen, queue = {pid}, deque([pid])
        while queue:
            cur = queue.popleft()
            for nxt in edges.get(cur, ()):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        out[pname] = {name[i] for i in seen}
    return out


def main():
    found = placeholders()
    reach = closures()

    free, blocked, excluded, unmapped = [], [], [], []
    for name, holder, rel in found:
        if name in NO_OWNER:
            excluded.append((name, rel))
            continue
        owner = OWNERS.get(name)
        if owner is None:
            unmapped.append((name, rel))
            continue
        if owner not in reach:
            unmapped.append((name, rel))
            continue
        if holder in reach[owner]:
            blocked.append((name, owner, holder, len(reach[owner])))
        else:
            free.append((name, owner, holder, sorted(reach[owner])))

    stale = sorted((set(OWNERS) | set(NO_OWNER)) - {n for n, _, _ in found})

    print(f"{len(found)} opaque placeholders across {len(SOURCES)} files")
    print(f"{len(blocked)} blocked by the layering, {len(excluded)} with no owner here")

    # A gate covering nothing is worse than no gate. Both halves have to be
    # non-empty: no placeholders means the regexes stopped matching, and no
    # *blocked* ones means the tool has nothing it is refusing and would pass on
    # a tree where the question had changed shape.
    # Four on 2026-09-29, when `eventfd_state`, `pipe_end`, `tty`, `fakedb` and
    # `timerfd_desc` became real types; three later that day, when `DIR` did;
    # one the day after, when the descriptor union went. Lower it when one
    # goes -- that is the point of it being a number.
    assert len(found) >= 1, f"only found {len(found)} placeholders; the source moved"
    assert blocked, "nothing is blocked, so a clean run asserts nothing"

    status = 0
    if stale:
        print("\nNames in OWNERS or NO_OWNER that are not placeholders any more:")
        for name in stale:
            print(f"  {name}")
        print(
            "\nAn entry that suppresses nothing has stopped recording a\n"
            "decision. Delete it -- and if the placeholder became the real\n"
            "type, the casts on that field can go with it."
        )
        status = 1

    if unmapped:
        print("\nPlaceholders with no entry in OWNERS or NO_OWNER:")
        for name, rel in unmapped:
            print(f"  {name}  ({rel})")
        print(
            "\nSay which crate owns the object it stands for, or say in\n"
            "NO_OWNER that nothing does. This check cannot derive it: a\n"
            "field-less struct has nothing in it naming what it erases."
        )
        status = 1

    if free:
        print("\nPlaceholders the layering already allows naming:")
        for name, owner, holder, closure in free:
            print(f"  {name}: {owner} does not reach {holder}")
            print(f"    closure ({len(closure)}): {' '.join(closure)}")
        print(
            "\nReplace the placeholder with\n"
            "  pub use <owning crate>::<Real> as <name>;\n"
            "add the crate to the holder's [dependencies], and remove the\n"
            "`.cast()` on every reader of that field -- each is a conversion\n"
            "the compiler will check for the first time."
        )
        status = 1

    if status == 0:
        print("\nEvery placeholder has a dependency edge that keeps it opaque.")
    return status


if __name__ == "__main__":
    sys.exit(main())
