#!/usr/bin/env python3
"""The workspace's shape: four rules CLAUDE.md states and nothing checked.

Each of the four has already been broken once, and three of the four broke
*silently* — which is why this exists rather than the prose alone:

1. **Two lib targets may not share a name.** `crates/fs/locks` and
   `crates/util/locks` both had lib name `locks`, rustdoc could not resolve
   the ambiguity, and so `cargo test --workspace` had **never completed** —
   the doc-test step died before running and the 1823 unit tests below it were
   never reported. Nothing said so; the suite just ended. See
   `docs/changelog/2026-09-06-a-test-double-that-replaced-the-real-function-everywhere.md`.

2. **Every crate directory is a workspace member, and every member is a
   directory.** A crate with a `Cargo.toml` that no `members` entry names is
   not built, not tested and not linted, and it looks exactly like one that
   is. Adding a crate is two edits and the second is easy to forget.

3. **There is one `staticlib` in the product.** A Rust staticlib bundles the
   standard library, and the release profile's LTO makes std's symbols strong
   globals — so two of them in one link is a duplicate-symbol error. Sixteen
   made `libiul.a` 206 MB and made a release build impossible to link. The
   one exception, `crates/tools/fakefsredirect`, is a `DYLD_INSERT_LIBRARIES`
   library that links nothing of this tree, and it is named below rather than
   discovered, so a second exception has to be argued for.

4. **Every crate is reachable from something that ships.** A crate no product
   binary and no tool depends on still compiles in `cargo test --workspace`,
   so nothing about the build says it is stranded.

Each count is printed and each is asserted to be non-zero, because a rule
checked over an empty set passes — the shape this repository has been caught
by four times.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The one staticlib that is not `crates/iul`, and why. See rule 3.
STATICLIB_ALLOWED = {
    "crates/tools/fakefsredirect": (
        "injected into another process with DYLD_INSERT_LIBRARIES and links "
        "nothing of this tree, so its standard library meets no other"
    ),
}

# What a crate must be reachable from to be shipping something.
def is_root(d: str) -> bool:
    return d == "crates/iul" or d.startswith("crates/tools/")


def manifests():
    """Every crate directory under `crates/`, one or two levels deep."""
    out = {}
    for m in sorted(ROOT.glob("crates/*/Cargo.toml")) + sorted(ROOT.glob("crates/*/*/Cargo.toml")):
        text = m.read_text()
        name = re.search(r'^name = "([^"]+)"', text, re.M)
        if not name:
            continue
        lib = re.search(r"^\[lib\][^\[]*?^name = \"([^\"]+)\"", text, re.M | re.S)
        deps = []
        for _, p in re.findall(
            r'^([a-zA-Z0-9_-]+)\s*=\s*\{[^}]*path\s*=\s*"([^"]+)"', text, re.M
        ):
            deps.append(str((m.parent / p).resolve().relative_to(ROOT)))
        out[str(m.parent.relative_to(ROOT))] = {
            "package": name.group(1),
            "lib": lib.group(1) if lib else name.group(1).replace("-", "_"),
            "deps": deps,
            "crate_type": re.search(r"^crate-type = \[([^\]]*)\]", text, re.M),
        }
    return out


def main() -> int:
    crates = manifests()
    if not crates:
        print("crate-graph: no crates found -- the glob is wrong", file=sys.stderr)
        return 2
    bad = []

    # 1 -- lib names
    by_lib: dict[str, list[str]] = {}
    for d, c in crates.items():
        by_lib.setdefault(c["lib"], []).append(d)
    for lib, dirs in sorted(by_lib.items()):
        if len(dirs) > 1:
            bad.append(f"two lib targets named `{lib}`: {', '.join(dirs)}")

    # 2 -- membership
    ws = (ROOT / "Cargo.toml").read_text()
    block = re.search(r"members = \[(.*?)\]", ws, re.S)
    if not block:
        print("crate-graph: the workspace has no members list", file=sys.stderr)
        return 2
    members = set(re.findall(r'"(crates/[^"]+)"', block.group(1)))
    if not members:
        print("crate-graph: the members list is empty", file=sys.stderr)
        return 2
    for d in sorted(members - set(crates)):
        bad.append(f"`{d}` is a workspace member with no Cargo.toml")
    for d in sorted(set(crates) - members):
        bad.append(f"`{d}` has a Cargo.toml and is not a workspace member")

    # 3 -- staticlibs
    staticlibs = [d for d, c in crates.items() if c["crate_type"] and "staticlib" in c["crate_type"].group(1)]
    if not staticlibs:
        print("crate-graph: no staticlib at all, which cannot be right", file=sys.stderr)
        return 2
    for d in sorted(staticlibs):
        if d != "crates/iul" and d not in STATICLIB_ALLOWED:
            bad.append(
                f"`{d}` is a second staticlib in the product. Two put two "
                "standard libraries in one link; add it to crates/iul's "
                "dependencies as an rlib, or name it in STATICLIB_ALLOWED "
                "with the reason its std meets no other"
            )
    for d in sorted(STATICLIB_ALLOWED):
        if d not in staticlibs:
            bad.append(f"`{d}` is in STATICLIB_ALLOWED and is not a staticlib -- stale")

    # 4 -- reachability
    roots = [d for d in crates if is_root(d)]
    if not roots:
        print("crate-graph: nothing ships, so reachability is vacuous", file=sys.stderr)
        return 2
    seen: set[str] = set()
    stack = list(roots)
    while stack:
        d = stack.pop()
        if d in seen or d not in crates:
            continue
        seen.add(d)
        stack += crates[d]["deps"]
    for d in sorted(set(crates) - seen):
        bad.append(
            f"`{crates[d]['package']}` ({d}) is reachable from nothing that "
            "ships: no product binary and no tool depends on it"
        )

    print(f"{len(crates)} crates, {len(by_lib)} distinct lib names")
    print(f"{len(members)} workspace members, {len(set(crates) - members)} directories outside the list")
    print(f"{len(staticlibs)} staticlib(s), {len(STATICLIB_ALLOWED)} allowed besides crates/iul")
    print(f"{len(roots)} shipping roots, {len(seen)} crates reachable from them")

    if bad:
        print()
        for b in bad:
            print(f"  {b}")
        print(f"\n{len(bad)} problem(s) with the workspace's shape.")
        return 1
    print("\nThe workspace's shape holds: unique lib names, every crate a member,")
    print("one staticlib, nothing stranded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
