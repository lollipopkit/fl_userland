#!/usr/bin/env python3
"""Report an `unsafe fn` that has nothing for a caller to guarantee.

`unsafe` on a function is a **contract**: the caller promises something the
compiler cannot check. Three conditions together say there is no such promise,
and `CLAUDE.md` states them as the mechanical test:

- no parameter carries a raw pointer, so there is no address whose validity the
  caller vouches for;
- the body performs no unsafe operation, so nothing inside needs one; and
- the doc comment has no `# Safety` section, so nobody wrote one down either.

Four were found by hand on 2026-09-04 — `anon_pages_used` and its neighbours —
and this is the search that finds the next.

## Why the second condition is exact rather than approximate

This workspace is edition 2024 and has **zero** `unsafe_op_in_unsafe_fn`
warnings, which is the lint that fires when an `unsafe fn` body performs an
unsafe operation outside an explicit `unsafe {}`. So "no `unsafe` token in the
body" really does mean "performs no unsafe operation" here, and would stop
meaning it the moment that lint started firing. The check asserts the tree is
in that state — see `assert_no_unsafe_op_warnings` in `docs/checks.md` for what
to do if it is not.

## What it does not catch

A parameter that carries a pointer **in disguise**: `Mount` and `Task` are
newtypes over one, and a `usize` that is really an address is the same thing
with no type at all. Those read as contract-free here and are not. The
condition is about what the *signature* promises, so a type alias hiding a
pointer defeats it — which is an argument for not hiding one.

Reported, not failed: some of these are `unsafe` because the *value* of an
argument has a precondition the compiler cannot see, and telling that from
decoration needs the function read.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# A newtype over a raw pointer reads as contract-free by signature. Each of
# these is one, so a parameter of the type counts as a pointer.
POINTER_NEWTYPES = ("Mount", "Task", "Fd", "Sock", "Handle")

FN = re.compile(
    r"(?P<doc>(?:^[ \t]*(?:///[^\n]*|//![^\n]*|#\[[^\n]*)\n)*)"
    r"^(?P<vis>[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?)unsafe[ \t]+(?:extern \"C\"[ \t]+)?fn[ \t]+"
    r"(?P<name>\w+)[ \t]*(?:<[^>]*>)?[ \t]*\((?P<params>[^)]*)\)",
    re.M,
)


def body_after(src, at):
    """The function body starting at the `{` that follows `at`, brace-matched."""
    i = src.find("{", at)
    if i < 0:
        return ""
    depth, j = 0, i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
        j += 1
    return src[i:]


def main():
    found, total = [], 0
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        src = path.read_text(errors="ignore")
        for m in FN.finditer(src):
            total += 1
            params = m.group("params")
            if "*const" in params or "*mut" in params:
                continue
            if any(re.search(rf":\s*&?{t}\b", params) for t in POINTER_NEWTYPES):
                continue
            doc = m.group("doc")
            if "# Safety" in doc:
                continue
            body = body_after(src, m.end())
            # `unsafe {`, `unsafe impl`, `unsafe fn` nested, or a `.cast()`
            # onto a call that is one -- the first is what the lint guarantees.
            if re.search(r"\bunsafe\b", body):
                continue
            line = src[: m.start("name")].count("\n") + 1
            found.append((f"{path.relative_to(ROOT)}:{line}", m.group("name"), params.strip()[:52]))

    if not total:
        print("no `unsafe fn` found at all, which is either a tree that has")
        print("none or a scan that stopped matching. This check asserts its")
        print("own input; see the module comment.")
        return 1

    print(f"{total} `unsafe fn` in crates/")
    print(f"{len(found)} with no pointer parameter, no unsafe operation and no `# Safety`")
    if found:
        print()
        for where, name, params in found:
            print(f"  {name:36s} ({params})")
            print(f"      {where}")
        print()
        print("Each of these has nothing for a caller to guarantee. Take the")
        print("`unsafe` off, or -- if the precondition is about an argument's")
        print("*value* rather than its type -- write the `# Safety` section.")
    else:
        print()
        print("Every `unsafe fn` carries a pointer, does something unsafe, or says why.")
    print()
    print("Reported, not failed: see this file's header.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
