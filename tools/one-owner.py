#!/usr/bin/env python3
"""A rule this tree deliberately consolidated, defined in more than one crate.

Not "find every duplicate". A search for every free function name defined in
more than one crate answers **151** here, and about 140 of them are ordinary
verbs -- `new`, `default`, `decode`, `retain` -- whose meaning is the receiver's.
A check that reports those is read exactly as often as one that reports
nothing.

What this guards is narrower and is the thing that actually went wrong:
**a consolidation growing a second copy back.**

`crates/fs/devices` carries this comment, written on 2026-09-01:

    One definition because there were four, each a hand-copy of a `static
    inline` bindgen cannot emit, and *one of them was the wrong encoding*:
    `/proc/<pid>/stat` reported a terminal number `ps` attributes to nothing.

By 2026-09-15 there were four again, and one again disagreed -- a
`#[cfg(test)]` copy in `crates/fs/generic` with no `& 0xfff` on the major, used
to test *that crate's own* second copy of the decoders. Nothing could see it:
the test cases stop at `0xfff`, so the difference is never reached.

So the list below is hand-maintained and small, and each entry names a rule
somebody decided has one owner. Adding one costs a line; the thing it buys is
that the next copy fails a run instead of surviving a fortnight.

# What counts as a definition

A free function only. A trait *method* of the same name is not a second
rendering -- `fn read(&self, ...)` in eighteen places is one trait with
eighteen implementors, which is the shape this tree wants. So a signature whose
first parameter is `self` is skipped, and that is most of the 151.

A **delegating wrapper is allowed and is not a copy**: `crates/fs/devpts` and
`crates/kernel/boot` both define a local `dev_make` that calls
`fs_devices::dev_make` and adapts the integer width. What makes them fine is
that the encoding is in one place; what makes a copy a copy is that the
arithmetic is written out again. This check tells them apart by asking whether
the body mentions the owning crate.

# Assert the subject, like every analysis here

A name that no longer exists anywhere makes its entry vacuous, and an entry
that guards nothing reads exactly like one that guards something -- which is
`crates/kernel/abi`'s `NOT_REPR_C` lesson, where an exemption naming a type
that had become an enum was still in the list. So a name in `OWNED` that is
defined **nowhere** is a failure too, and says to delete the entry or fix the
rename.

Run by hand, or as `tools/checks.sh one_owner`.
"""

import pathlib
import re
import sys

# name -> (owning crate as `dir/dir`, one-line why it has one owner)
#
# Add an entry when you consolidate something. The cost is this line; the
# alternative is the fortnight `dev_make` spent with four copies.
OWNED = {
    "dev_make": (
        "fs/devices",
        "the guest dev_t packing. Had four copies and one was wrong: "
        "docs/changelog/2026-09-01-proc-stat-packed-its-terminal-number-wrong.md",
    ),
    "dev_major": ("fs/devices", "the inverse of dev_make, and wrong the same way"),
    "dev_minor": ("fs/devices", "as dev_major"),
    "sigset_size_valid": (
        "kernel/signaldeliver",
        "Linux refuses any sigsetsize but 8. Was defined twice, split by "
        "syscall group: ppoll/pselect6/epoll_pwait reached one and "
        "rt_sigprocmask/rt_sigaction the other",
    ),
    "monotonic_ns": (
        "util/timeabi",
        "CLOCK_MONOTONIC in nanoseconds. Five crates hand-rolled it and three "
        "multiplied plainly, where the shared conversion saturates",
    ),
    "host_timespec_to_ns": (
        "util/timeabi",
        "the saturating timespec conversion monotonic_ns is built on",
    ),
    "fill_path": (
        "kernel/abi",
        "the MAX_PATH buffer rule. Was six hand-written copies, two of which "
        "wrote the terminator one byte past the end",
    ),
    "path_bytes": ("kernel/abi", "the other half of fill_path's rule"),
}

# A name whose second definition is deliberate, with the reason. An entry here
# is read, not skipped: the run prints it.
# Ships **empty**, and that is a measurement rather than an omission: every
# second definition found so far was either a copy (fixed) or a wrapper that
# calls the owner (allowed by the body test above, no entry needed).
#
# The near miss is worth recording. `crates/fs/fakechange` has a `now_ns` that
# deliberately asks a different clock -- CLOCK_UPTIME_RAW, which excludes time
# the device spent asleep -- and it does *not* belong here, because the rule
# this tree owns is called `monotonic_ns`. Two functions answering different
# questions are not a duplicate however similar the names; the note explaining
# that lives on the function, which is where a reader of it will be.
ALLOWED: dict[tuple[str, str], str] = {}

ROOT = pathlib.Path(__file__).resolve().parent.parent
CRATES = ROOT / "crates"

# A free function definition. `self` as the first parameter is a method and is
# skipped -- see the module comment.
DEF = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:unsafe\s+)?"
    r'(?:extern\s+"C"\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(\s*(&?\s*mut\s+self|&?\s*self|[^)]*)'
)


def crate_of(path: pathlib.Path) -> str:
    rel = path.relative_to(CRATES).parts
    return "/".join(rel[:2]) if len(rel) > 2 else rel[0]


def body_after(lines, start):
    """The function's body, roughly: to the first line that closes it."""
    depth = 0
    out = []
    for line in lines[start:]:
        out.append(line)
        depth += line.count("{") - line.count("}")
        if depth <= 0 and "{" in "".join(out):
            break
        if len(out) > 60:
            break
    return "\n".join(out)


def main() -> int:
    found: dict[str, list[tuple[str, str, str]]] = {n: [] for n in OWNED}
    for path in CRATES.rglob("*.rs"):
        lines = path.read_text(errors="replace").split("\n")
        for i, line in enumerate(lines):
            m = DEF.match(line)
            if not m:
                continue
            name, first = m.group(1), m.group(2).strip()
            if first.replace(" ", "").endswith("self"):
                continue
            if name in found:
                found[name].append(
                    (crate_of(path), str(path.relative_to(ROOT)), body_after(lines, i))
                )

    status = 0

    missing = [n for n, defs in found.items() if not defs]
    if missing:
        print("A name in OWNED that is defined nowhere:")
        for n in missing:
            print(f"  {n}  (owner was {OWNED[n][0]})")
        print(
            "\nRenamed, or removed. Delete the entry or fix the name: an entry\n"
            "that guards nothing reads exactly like one that guards something."
        )
        status = 1

    copies = []
    allowed_seen = []
    for name, defs in found.items():
        owner_dir, why = OWNED[name]
        owner_lib = owner_dir.split("/")[1].replace("-", "_")
        for crate, rel, body in defs:
            if crate == owner_dir:
                continue
            if (name, crate) in ALLOWED:
                allowed_seen.append((name, crate, ALLOWED[(name, crate)]))
                continue
            # A wrapper that calls the owner is not a copy -- the encoding is
            # still in one place. A body that names the owning crate is one.
            if owner_lib in body or f"{owner_dir.split('/')[1]}::" in body:
                continue
            copies.append((name, crate, rel, why))

    if copies:
        print("A consolidated rule with a second definition:")
        for name, crate, rel, why in copies:
            print(f"  {name}  in {crate}  ({rel})")
            print(f"    owner: {OWNED[name][0]} -- {why}")
        print(
            "\nCall the owner, or add the crate to ALLOWED with the reason it is\n"
            "a different question rather than a second answer. A body that\n"
            "merely *agrees* today is what the dev_make copies were."
        )
        status = 1

    stale = [
        (name, crate)
        for (name, crate) in ALLOWED
        if not any(c == crate for c, _, _ in found.get(name, []))
    ]
    if stale:
        print("\nAn ALLOWED entry whose definition is gone:")
        for name, crate in stale:
            print(f"  {name} in {crate}")
        status = 1

    if allowed_seen:
        print("Deliberate second definitions:")
        for name, crate, why in allowed_seen:
            print(f"  {name} in {crate}: {why}")

    if status == 0:
        print(
            f"\n{len(OWNED)} consolidated rules, each with one definition"
            f" ({sum(len(d) for d in found.values())} definitions seen)."
        )
    return status


if __name__ == "__main__":
    sys.exit(main())
