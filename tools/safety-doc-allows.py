#!/usr/bin/env python3
"""Fail on any suppression of `clippy::missing_safety_doc` under `crates/`.

`CLAUDE.md` says the lint's count is zero, and on 2026-09-30 that was true only
because **59 crates** carried `#![allow(clippy::missing_safety_doc)]`. Removing
them all measured what they covered: 25 places with no `# Safety` section --
24 `unsafe fn` definitions, two of them macros that make one per invocation,
and an `unsafe trait`. Several needed no section at all --
`fs_fdobj::fd_create` asked nothing of its caller, `inotify_notify_path` had no
caller, `FdLocks` had no implementor promise -- and the rest were obligations
nobody had written down. See
`docs/changelog/2026-09-30-fifty-nine-crates-switched-off-the-safety-doc-lint.md`.

The lint is what enforces the rule, and it does: CI's iOS clippy step runs with
`-D warnings` over every crate the product links. What it cannot stop is being
switched off, and a crate-level `allow` switches it off for every function a
crate will ever have. That is this check's whole subject.

**Fails**: the answer to a finding is always in this repository -- write the
section, or take the `unsafe` off.

It asserts its own input, as every analysis here does: a tree with no
`unsafe fn` at all means the scan stopped matching.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# An attribute, inner or outer, that allows or expects the lint. Comments are
# blanked first, so a note recording where one used to be does not count.
SUPPRESSION = re.compile(
    r"#!?\[\s*(?:allow|expect)\s*\([^\]]*\bclippy::missing_safety_doc\b"
)
UNSAFE_FN = re.compile(r"\bunsafe\s+(?:extern\s+\"C\"\s+)?fn\b")


def blank_comments(src):
    """Replace `//` and `/* */` comments with spaces, keeping line numbers."""
    out, i, n = [], 0, len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(c if c == "\n" else " " for c in src[i:j]))
            i = j
        elif src[i] == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(src[i : j + 1])
            i = j + 1
        else:
            out.append(src[i])
            i += 1
    return "".join(out)


def main():
    unsafe_fns, found = 0, []
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        src = blank_comments(path.read_text(errors="ignore"))
        unsafe_fns += len(UNSAFE_FN.findall(src))
        for m in SUPPRESSION.finditer(src):
            line = src[: m.start()].count("\n") + 1
            found.append(f"{path.relative_to(ROOT)}:{line}")

    if unsafe_fns == 0:
        print("no `unsafe fn` found under crates/, which is a scan that stopped")
        print("matching rather than a tree with none. See the module comment.")
        return 1

    print(f"{unsafe_fns} `unsafe fn` definitions scanned")
    print(f"{len(found)} suppressions of clippy::missing_safety_doc")
    if found:
        print()
        for place in found:
            print(f"  {place}")
        print()
        print("Write the `# Safety` section, or take the `unsafe` off the")
        print("function. A suppression hides every future contract in its scope.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
