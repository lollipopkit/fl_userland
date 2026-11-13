#!/usr/bin/env python3
"""What each crate still reads a C header for, and why that is not nothing.

The migration this reports on is "make the headers Rust's". A crate that runs
bindgen does it for one of three reasons, and they are different amounts of
work:

- **A type.** Move it to the crate that owns it, or -- if several crates need
  it -- to `crates/kernel/taskview`, which owns the shared Rust definitions.
  `struct task`, `fd`, `mount`, `cpu_state` and `iul_env` went that way.
- **A `#define`.** Move it to Rust and let `tools/guessed-constants.py` be the
  gate: it reports a Rust constant that restates a C `#define` and disagrees
  with it.
- **A function declaration.** These are the C-ABI calls the 2026-09-05
  conversion was about, seen from the declaring end. Some are *dead* -- the
  crate declares a function it never calls -- and `groupcalls`' `task_self` and
  `waitcalls`' `wait_for` both were.

**Reported, not failed.** How many crates should still run bindgen is not a
number this repository can assert: the answer is "none, eventually", and the
work is one header at a time with a different check for each. What this prints
is the size of what is left, so that a claim about it can be checked rather
than remembered.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def allowlist(src: str, kind: str) -> set[str]:
    """The names one `allowlist_*` call asks for.

    Two shapes have to survive: a `concat!` of several string literals, and a
    literal split across lines with a trailing backslash — which continues the
    string *and* strips the next line's leading whitespace. Missing the second
    made `crates/fs/ttydev` read as "needs nothing" twice, and it needs four
    types; the compiler said so both times.
    """
    m = re.search(kind + r'\(\s*(?:concat!\()?\s*((?:"(?:[^"\\]|\\.)*"\s*,?\s*)+)', src, re.S)
    if not m:
        return set()
    joined = "|".join(re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1)))
    joined = re.sub(r"\\\s*\n\s*", "", joined)
    return {x.strip() for x in joined.split("|") if x.strip()}


def main() -> int:
    rows = []
    for b in sorted(ROOT.glob("crates/**/build.rs")):
        src = b.read_text()
        if "bindgen::Builder" not in src:
            continue
        d = str(b.parent.relative_to(ROOT))
        own = allowlist(src, "allowlist_type")
        rows.append((d, own, allowlist(src, "allowlist_var"), allowlist(src, "allowlist_function")))

    total = sum(1 for _ in ROOT.glob("crates/**/Cargo.toml"))
    if not rows:
        print(f"No crate runs bindgen. All {total} read Rust.")
        return 0

    types = sorted({t for _, o, _, _ in rows for t in o})
    print(f"{len(rows)} of {total} crates run bindgen")
    print(f"  {sum(1 for r in rows if r[1])} need a type not owned by that crate: "
          f"{len(types)} distinct")
    print(f"  {sum(1 for r in rows if r[2])} need a #define")
    print(f"  {sum(1 for r in rows if r[3])} need a function declaration")
    print()
    print("The nearest ones -- smallest remaining surface first:")
    rows.sort(key=lambda r: len(r[1]) + len(r[2]) + len(r[3]))
    for d, o, v, f in rows[:12]:
        bits = []
        if o:
            bits.append("types=" + ",".join(sorted(o)))
        if v:
            bits.append("vars=" + ",".join(sorted(v)))
        if f:
            bits.append("fns=" + ",".join(sorted(f)))
        print(f"  {d:38} {'  '.join(bits) or '(nothing -- droppable now)'}")
    print()
    print("Reported, not failed: see this file's header.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
