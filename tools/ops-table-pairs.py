#!/usr/bin/env python3
"""An operation a table sets whose companion field it does not.

Some entries of `struct fd_ops` only work in pairs, and setting one without the
other leaves the first **unreachable** rather than broken — no compiler warns,
no test fails, and the handler sits there reading as working code.

`ioctl` is the case. `fd_ioctl` in `kernel/fs.c` asks the driver how large the
argument is before it calls anything:

    ssize_t size = -1;
    if (fd->ops->ioctl_size)
        size = fd->ops->ioctl_size(cmd);
    if (size < 0)
        return _ENOTTY;

so a table with `.ioctl` and no `.ioctl_size` answers `ENOTTY` for every
command. `random_dev` in `fs/mem.c` was that from the beginning: `RNDGETENTCNT`
on `/dev/random` never ran, while the handler, its `case` and a comment
explaining the value it returns all sat there. A real kernel answers a count,
and programs read it to decide whether they must wait for entropy. See
`docs/changelog/2026-08-31-rndgetentcnt-on-dev-random-was-dead-code.md`.

**It is a designated-initialiser problem.** `.field = value` has no ordering to
notice and no arity to get wrong, so a missing entry is invisible — which is
also why it survives a migration: a Rust `ops.ioctl = Some(f)` beside no
`ops.ioctl_size` reads exactly as well.

## What it checks

Every place that builds an `fd_ops` — a C designated initialiser, or a Rust
function that assigns `ops.<field> = Some(...)` — is one table. For each, if it
sets a field on the left of a pair below, it must set the right one too.

Only `fd_ops` today, and only one pair. The list is meant to grow: the rule for
adding one is that the *absence* of the second field must make the first
unreachable or wrong, not merely incomplete.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# left field -> (right field, why the left one needs it)
PAIRS = {
    "ioctl": (
        "ioctl_size",
        "fd_ioctl answers ENOTTY for a negative size before calling ioctl, "
        "and a missing ioctl_size leaves it at -1",
    ),
}

# A driver that legitimately has one without the other, with the reason.
ALLOWED: dict[tuple[str, str], str] = {}

# How many descriptor drivers there should be at least. Sixteen `impl FdOps`
# today; the floor is there so that a rename of the trait, or a move of the
# drivers, fails loudly instead of reporting a clean run over nothing.
MIN_CHECKED = 12


def c_tables(path: Path) -> list[tuple[str, int, set[str]]]:
    """`(name, line, fields)` for each `struct fd_ops` initialiser in `path`."""
    text = path.read_text(errors="replace")
    out = []
    # `struct fd_ops name = { ... };` and `struct dev_ops name = { ... };`,
    # whose `.fd.foo = ` entries are an fd_ops written a field at a time.
    for m in re.finditer(
        r"struct\s+(fd_ops|dev_ops)\s+(\w+)\s*=\s*\{", text
    ):
        depth, i = 0, m.end() - 1
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = text[m.end() : i]
        prefix = r"\.fd\." if m.group(1) == "dev_ops" else r"\."
        fields = set(re.findall(prefix + r"(\w+)\s*=", body))
        line = text[: m.start()].count("\n") + 1
        out.append((m.group(2), line, fields))
    return out


def rust_tables(path: Path) -> list[tuple[str, int, set[str]]]:
    """`(name, line, fields)` for each Rust builder of an `fd_ops`.

    Two shapes, because crates use both. A **mutable builder** zeroes an
    `fd_ops` (or a `dev_ops`, whose entries are written `d.fd.foo`) and assigns
    the entries it wants; a **struct literal** names every field, and there the
    interesting thing is which are `None` rather than which are absent.
    """
    text = path.read_text(errors="replace")
    out = []

    # let mut d: ffi::fd_ops = ...;  /  let mut d = ...; d.read = Some(f);
    for m in re.finditer(r"let mut (\w+)\s*(?::\s*ffi::(?:fd_ops|dev_ops))?\s*=", text):
        var = m.group(1)
        fields = set()
        # From the next line: the rest of this one is the initialiser.
        rest = text[m.end():]
        rest = rest[rest.index("\n") + 1 :] if "\n" in rest else ""
        for line in rest.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            a = re.match(rf"{re.escape(var)}\.(?:fd\.)?(\w+)\s*=", stripped)
            if a:
                fields.add(a.group(1))
                continue
            break
        # Only a table: a builder that never sets an operation is something
        # else with the same shape.
        if fields & {"read", "write", "poll", "close", "ioctl", "lseek", "open"}:
            out.append((var, text[: m.start()].count("\n") + 1, fields))

    # ffi::fd_ops { read: Some(f), ioctl_size: None, .. }
    for m in re.finditer(r"(?:ffi::)?fd_ops\s*\{", text):
        depth, i = 0, m.end() - 1
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = text[m.end() : i]
        # A field written `None` is present and empty, which is the same as
        # absent for this question -- so it does not count as set.
        fields = {
            f for f, v in re.findall(r"(\w+)\s*:\s*([A-Za-z_][\w:]*)", body)
            if v != "None"
        }
        if fields & {"read", "write", "poll", "close", "ioctl", "lseek"}:
            out.append(("<literal>", text[: m.start()].count("\n") + 1, fields))

    return out


def rust_impls(path: Path) -> list[tuple[str, int, set[str]]]:
    """`(type, line, methods)` for each `impl FdOps for T` block in `path`.

    The shape since 2026-09-11, when `fd_ops` stopped being fifteen
    `Option<fn>` and became a trait. **The property did not go with the
    struct**: `ioctl` and `ioctl_size` are two methods with defaults, the
    default `ioctl_size` refuses every command, and a driver that overrides
    `ioctl` alone still leaves its handler unreachable. Only the spelling of
    "sets one and not the other" changed, from a field to an override.

    Teaching it this is what stopped it reporting `0 fd_ops tables` and
    passing, which is the shape CLAUDE.md calls worse than no gate: a clean run
    reads as "nothing is wrong" rather than as "nothing was looked at".
    """
    text = path.read_text(errors="replace")
    out = []
    for m in re.finditer(r"impl\s+(?:\w+::)*FdOps\s+for\s+(\w+)\s*\{", text):
        depth, i = 0, m.end() - 1
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = text[m.end() : i]
        methods = set(re.findall(r"\bfn\s+(\w+)\s*\(", body))
        out.append((m.group(1), text[: m.start()].count("\n") + 1, methods))
    return out


def tracked(pattern: str) -> list[Path]:
    """Source files, from `rg --files`, which honours `.gitignore`.

    Not `Path.glob("**/*.c")`: that walks `target/` and every `build*/`, which
    is tens of thousands of files and was **21 seconds** against this test's
    30-second timeout — so it passed alone and timed out whenever the machine
    was doing anything else. A gate that fails under load teaches its reader to
    re-run it.

    It was also reading the wrong thing. `build/` holds *generated* C, and the
    only reason it was not judged is a `"build" in path.parts` filter that
    names one directory out of however many a reader has made.
    """
    out = subprocess.run(
        ["rg", "--files", "-g", pattern],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()
    return sorted(ROOT / p for p in out)


def main() -> int:
    findings = []
    checked = 0

    for path in tracked("*.c"):
        if "offload_tests" in path.parts:
            continue
        for name, line, fields in c_tables(path):
            checked += 1
            findings += judge(path, name, line, fields)

    for path in tracked("crates/**/*.rs"):
        for name, line, fields in rust_tables(path):
            checked += 1
            findings += judge(path, name, line, fields)
        for name, line, methods in rust_impls(path):
            checked += 1
            findings += judge(path, name, line, methods)

    print(f"{checked} descriptor operation sets")
    print(f"{len(findings)} with an operation whose companion is missing")
    # A gate whose subject has gone reads exactly like a gate that found
    # nothing. Every source analysis here asserts it had something to look at.
    if checked < MIN_CHECKED:
        print()
        print(f"Only {checked} were found and there should be at least")
        print(f"{MIN_CHECKED}. Either the drivers have gone or this no longer")
        print("recognises how one is written; a clean run would mean nothing.")
        return 1
    if not findings:
        return 0
    print()
    for where, name, left, right, why in findings:
        print(f"  {where}: {name} sets .{left} and not .{right}")
        print(f"      {why}")
    print()
    print("The first operation is unreachable without the second. Add it, or --")
    print("if this table is reached some way this does not model -- add it to")
    print("ALLOWED with the reason.")
    return 1


def judge(path: Path, name: str, line: int, fields: set[str]):
    rel = path.relative_to(ROOT)
    out = []
    for left, (right, why) in PAIRS.items():
        if left in fields and right not in fields:
            if (str(rel), name) in ALLOWED:
                continue
            out.append((f"{rel}:{line}", name, left, right, why))
    return out


if __name__ == "__main__":
    sys.exit(main())
