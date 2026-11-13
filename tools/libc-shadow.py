#!/usr/bin/env python3
"""No `#[no_mangle]` in this tree may take a name the host libc exports.

A `#[no_mangle]` item defines a **strong global**. The static archive this
repository ships is linked into a process that also links libSystem, and on
macOS the linker resolves a duplicate by picking one -- with a warning at most.
So a Rust function called `mkdirat` does not merely sit beside libc's: it
*replaces* it, for every caller in the image, including this tree's own
`libc::mkdirat`.

**That happened on 2026-09-16.** Splitting `generic_mkdirat` into an `iul.h`
shim and a Rust half left the `#[unsafe(no_mangle)]` attached to the Rust half,
which was named `mkdirat`. `crates/fs/realfs`'s `realfs_mkdir` calls
`libc::mkdirat(mount.root_fd, ...)` -- a host syscall with a host descriptor
number -- and it reached `fs_generic::mkdirat` instead, which took that integer
as a `struct fd *`. Every `mkdir` at boot recursed into the path walk and the
emulator died before `main`. `tools/checks.sh` was **28/28** while that was
true, and `cargo build` was clean: nothing in the tree looks at this.

**`DELIBERATE` ships empty, and that is a measurement.**
`crates/tools/fakefsredirect` interposes a dozen libc calls, which is a
deliberate shadow -- but DYLD's mechanism is a `__DATA,__interpose` table of
*pairs*, so its functions are called `my_stat` and `my_unlink` and collide with
nothing by name. Nothing else in the tree wants a libc name. The table is there
for the day something does, and an entry naming an export that is gone fails
the run.

Reported as a **failure**, because acting on a finding needs no fact from
outside this repository: either the name is a deliberate interpose, in which
case it goes in the table with its reason, or the function should not be
`#[no_mangle]` at all.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Names this tree exports on purpose, knowing libc has them, with the reason.
# An entry whose symbol is no longer exported fails the run: an allowlist that
# suppresses nothing is a finding, which is `probe_diff.sh`'s exit code 3.
DELIBERATE: dict[str, str] = {}

# `#[no_mangle]` in any of its spellings, and the item's name on a nearby line.
NO_MANGLE = re.compile(r"#\[(?:unsafe\()?no_mangle\)?\]")
ITEM = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:extern\s+\"C\"\s+)?"
    r"(?:fn|static(?:\s+mut)?)\s+([A-Za-z_][A-Za-z0-9_]*)"
)


def exported_names() -> dict[str, list[str]]:
    """Every `#[no_mangle]` name under `crates/`, and where it is."""
    found: dict[str, list[str]] = {}
    for path in (ROOT / "crates").rglob("*.rs"):
        lines = path.read_text(encoding="utf-8", errors="ignore").split("\n")
        for i, line in enumerate(lines):
            if not NO_MANGLE.search(line):
                continue
            # The item is on one of the next few lines; doc comments and other
            # attributes can sit between.
            for follow in lines[i + 1 : i + 8]:
                m = ITEM.match(follow)
                if m:
                    found.setdefault(m.group(1), []).append(
                        f"{path.relative_to(ROOT)}:{i + 1}"
                    )
                    break
    return found


def libc_symbols() -> set[str]:
    """What the host's C library exports.

    **The SDK's `.tbd` stubs, not `nm` on a dylib.** There is no
    `/usr/lib/libSystem.B.dylib` on disk to read on a current macOS -- it lives
    in the dyld shared cache and `nm` answers nothing, which the first version
    of this did and would have passed vacuously. The `.tbd` files are what the
    linker actually resolves against, so they are also the right answer to
    "what would win a duplicate".

    A run that finds too few symbols is a failure rather than a pass, for the
    reason `CLAUDE.md` gives about `tools/lock-order.py`: a check covering
    nothing reads exactly like a clean one.
    """
    sdk = subprocess.run(
        ["xcrun", "--show-sdk-path"], capture_output=True, text=True, check=False
    ).stdout.strip()
    if not sdk:
        return set()
    names: set[str] = set()
    root = Path(sdk) / "usr" / "lib"
    for tbd in list(root.glob("*.tbd")) + list((root / "system").glob("*.tbd")):
        try:
            text = tbd.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # `symbols: [ _open, _openat, ... ]`, wrapped across lines.
        for sym in re.findall(r"\b_([A-Za-z][A-Za-z0-9_]*)\b", text):
            names.add(sym)
    return names


def main() -> int:
    ours = exported_names()
    if not ours:
        print("libc_shadow: found no #[no_mangle] items at all, which cannot be right")
        return 1

    libc = libc_symbols()
    if len(libc) < 100:
        print(f"libc_shadow: the host libc reported {len(libc)} symbols, which")
        print("  cannot be right -- this check would pass vacuously. Is the SDK here?")
        return 1

    stale = [n for n in DELIBERATE if n not in ours]
    if stale:
        print("libc_shadow: the DELIBERATE table names exports that are gone:")
        for n in sorted(stale):
            print(f"    {n}")
        return 1

    clashes = {n: w for n, w in ours.items() if n in libc and n not in DELIBERATE}
    if clashes:
        for name in sorted(clashes):
            print(f"libc_shadow: `{name}` is exported here and by the host libc:")
            for where in sorted(set(clashes[name])):
                print(f"    {where}")
        print(
            f"\n{len(clashes)} shadowed libc symbol(s). A #[no_mangle] is a strong\n"
            "global and the linker picks one definition, so this replaces libc's\n"
            "for every caller in the image -- including this tree's own. Drop the\n"
            "attribute, or add the name to DELIBERATE with why it is an interpose."
        )
        return 1

    print(
        f"{len(ours)} #[no_mangle] names against {len(libc)} the host libc "
        f"exports; 0 shadowed, {len(DELIBERATE)} deliberate"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
