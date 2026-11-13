#!/usr/bin/env python3
"""Every struct this tree allocates by hand must have no field that owns.

`libc::malloc` and `libc::calloc` hand back bytes, and the `libc::free` that
pairs with one **runs no destructor**. So a struct allocated that way is sound
only while every one of its fields is a scalar, a pointer, or an array of
those: the day a field becomes an `Arc`, a `Box`, a `String` or a `Vec`, the
free leaks it and nothing says so. That is not a hypothetical -- the object
model's remaining steps replace this tree's hand-rolled refcounts with `Arc`,
and `Arc` has a destructor.

The answer for four of them was to stop allocating by hand: `struct task`,
`struct tgroup`, `struct tlb` and `struct task_cleanup` are `Box`es since
2026-09-12, so the compiler runs whatever their fields need and there is
nothing here to check. What is left are the **flexible-array** structs -- a
header followed by a run of words whose length is not in the type -- and the
handful beside them, which `Box` cannot express.

So each of those carries

    const _: () = assert!(!std::mem::needs_drop::<T>(), "...");

which is the compiler answering the question exactly, recursively, at compile
time. This script's whole job is that **nobody can add a fifth hand-allocated
struct without one**: it finds every `libc::malloc`/`libc::calloc` in
`crates/`, reads the type off it, and asks whether that crate asserts.

It fails when it finds no allocation at all, and when it finds one whose type
it cannot read -- because a check that quietly skips what it does not
understand is the shape this repository has been caught by four times.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CRATES = ROOT / "crates"

# `realloc` is deliberately not here: it resizes something a `malloc` above it
# already allocated, so the type is asserted at that site and a second reading
# would only be a second place to keep in step.
ALLOC = re.compile(r"libc::(?:malloc|calloc)\s*\(")

# The three ways a site in this tree names what it is allocating. Every one of
# them is checked by the compiler at the site, which is why reading any of them
# is enough -- this script is looking for the *name*, not deciding it.
NAMES = (
    re.compile(r"size_of::<\s*([\w:]+)\s*>"),
    re.compile(r"\.cast::<\s*([\w:]+)\s*>"),
    re.compile(r":\s*\*mut\s+([\w:]+)\s*="),
)

ASSERTION = re.compile(r"needs_drop::<\s*([\w:]+)\s*>")

LINE_COMMENT = re.compile(r"//.*")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def code(text: str) -> str:
    """The source with its comments blanked.

    A `libc::calloc` written in a *sentence* is not an allocation, and this
    tree writes a lot of sentences about the calls it used to make. Three of
    `crates/fs/proc`'s would have been reported without this.
    """
    text = BLOCK_COMMENT.sub("", text)
    return "\n".join(LINE_COMMENT.sub("", line) for line in text.splitlines())


def crate_of(path: pathlib.Path) -> pathlib.Path:
    """The crate directory a source file belongs to: the one with a Cargo.toml."""
    for parent in path.parents:
        if (parent / "Cargo.toml").exists():
            return parent
    raise SystemExit(f"{path} is in no crate")


def main() -> int:
    sites: list[tuple[pathlib.Path, int, str, str]] = []
    unreadable: list[str] = []

    for path in sorted(CRATES.rglob("*.rs")):
        lines = code(path.read_text(encoding="utf-8")).splitlines()
        for i, line in enumerate(lines):
            if not ALLOC.search(line):
                continue
            # The statement, which in this tree is the line and at most the one
            # after it -- a `let x: *mut T = unsafe { libc::calloc(...) };`
            # wraps that way and nothing here wraps further.
            window = " ".join(lines[max(0, i - 1) : i + 2])
            found = None
            for pattern in NAMES:
                m = pattern.search(window)
                if m:
                    found = m.group(1)
                    break
            rel = path.relative_to(ROOT)
            if found is None:
                unreadable.append(f"{rel}:{i + 1}: {line.strip()}")
                continue
            sites.append((path, i + 1, found, line.strip()))

    if not sites:
        print(
            "hand-allocated-drop: found no libc::malloc or libc::calloc in crates/.\n"
            "\n"
            "That is either the end of hand allocation in this tree -- in which\n"
            "case delete this check and its entry in tools/checks.sh -- or this\n"
            "script has lost its subject, which is the same clean run either\n"
            "way. It fails rather than passing, for the reason\n"
            "tools/lock-order.py's header gives.",
            file=sys.stderr,
        )
        return 1

    if unreadable:
        print(
            "hand-allocated-drop: an allocation whose type this cannot read.\n"
            "\n"
            "A site that is skipped is a site that is not checked, so this\n"
            "fails rather than passing over it. Either name the type at the\n"
            "call -- `size_of::<T>()`, `.cast::<T>()` or a `*mut T`\n"
            "annotation, each of which the compiler already checks -- or teach\n"
            "NAMES the third spelling:\n",
            file=sys.stderr,
        )
        for line in unreadable:
            print(f"  {line}", file=sys.stderr)
        return 1

    # The last path component of a type name: `ffi::fd` and `fd` are the same
    # type reached two ways, and an assertion writes whichever the crate uses.
    def short(name: str) -> str:
        return name.rsplit("::", 1)[-1]

    asserted: dict[pathlib.Path, set[str]] = {}
    for path in sorted(CRATES.rglob("*.rs")):
        crate = crate_of(path)
        for m in ASSERTION.finditer(code(path.read_text(encoding="utf-8"))):
            asserted.setdefault(crate, set()).add(short(m.group(1)))

    missing = []
    for path, line, name, text in sites:
        crate = crate_of(path)
        if short(name) not in asserted.get(crate, set()):
            missing.append(
                f"  {path.relative_to(ROOT)}:{line}\n"
                f"    allocates `{name}` and no assertion in "
                f"{crate.relative_to(ROOT)} says it owns nothing\n"
                f"    {text}"
            )

    if missing:
        print(
            "hand-allocated-drop: a struct is `libc::calloc`ed and freed with\n"
            "`libc::free`, which runs no destructor, and nothing says its\n"
            "fields cannot need one.\n"
            "\n"
            "Add, beside the allocation:\n"
            "\n"
            "    const _: () = assert!(\n"
            "        !std::mem::needs_drop::<T>(),\n"
            "        \"<T> is libc::calloc'd and libc::free'd, and free runs no\n"
            "         destructor -- a field that owns something would leak. Give\n"
            "         it a Box, as struct task got on 2026-09-12, or say here why\n"
            "         it cannot have one.\",\n"
            "    );\n"
            "\n"
            "or -- better, and what the four in kernel/ did -- allocate it with\n"
            "a `Box` so the question does not arise.\n",
            file=sys.stderr,
        )
        print("\n".join(missing), file=sys.stderr)
        return 1

    kinds = sorted({short(n) for _, _, n, _ in sites})
    print(
        f"hand-allocated-drop: {len(sites)} hand allocations over "
        f"{len(kinds)} struct(s) -- {', '.join(kinds)} -- "
        f"and each crate asserts its fields own nothing"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
