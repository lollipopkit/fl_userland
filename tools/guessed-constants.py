#!/usr/bin/env python3
"""A Rust constant that restates a C `#define`, and disagrees with it.

**This is the shape the migration creates.** Rust that replaces C which *used*
a `#define` has to obtain the same number some other way, and copying it across
is the obvious thing to do. It is silent when wrong: both compilers are happy,
the syscall still returns 0, and the only evidence is behaviour.

Three were written wrong in one sitting on 2026-08-31 -- see
`docs/changelog/2026-08-31-three-constants-guessed-in-one-sitting.md`. The
sharpest was `P_NOACCESS` as `1 << 5` where it is `1 << 9`: `mprotect(PROT_NONE)`
then set a bit nothing reads and revoked nothing, so a guard page was not a
guard. Two were caught by tests that happened to exist and one by reading the
header, which is luck rather than a process.

## What it compares

Every `const NAME: T = <integer expression>;` in `crates/` against every
`#define NAME <integer expression>` in the C, by **name**. Both sides are
evaluated as Python integer expressions after the obvious rewrites (`1 << 9`
is already valid, a `U`/`u32` suffix is dropped, `0o755` and `0755` are the
same number). A pair that does not agree is reported.

A name that exists on only one side is not a finding: most Rust constants have
no C counterpart and vice versa.

## What it cannot see

An expression neither side can evaluate -- a `#define` over `sizeof`, or one
built from another macro this does not resolve -- is skipped and counted. The
count is in the output so that "0 unevaluated" is a claim rather than an
assumption.

**Generating is better than checking.** A crate that runs bindgen over the
header cannot have this defect at all, which is what `crates/kernel/mmapcalls`
does. This tool is for the ones that have not, and for the constants that have
no header to come from -- it finds the disagreement, it does not remove the
possibility.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# A Rust constant that deliberately differs from the C name it shares. One
# entry per constant, **with the reason**.
ALLOWED = {
    # (rust file stem, constant name): reason
    ("lib", "PAGE_SIZE"): (
        "emu/mmu.h defines PAGE_SIZE as (1 << PAGE_BITS) over its own macro; "
        "the Rust computes the same thing from the generated PAGE_BITS"
    ),
}


def run(*args: str) -> str:
    return subprocess.run(
        args, cwd=ROOT, capture_output=True, text=True, check=False
    ).stdout


def value_of(text: str):
    """The integer an expression denotes, or None if this cannot tell."""
    e = text.strip()
    # A trailing comment, then a trailing semicolon.
    e = re.sub(r"(//|/\*).*$", "", e).strip().rstrip(";").strip()
    if not e:
        return None
    # Rust and C integer suffixes and separators.
    e = re.sub(r"\b(0[xXoObB][0-9a-fA-F_]+|\d[\d_]*)(u8|u16|u32|u64|usize|i8|i16|i32|i64|isize|[uUlL]+)\b", r"\1", e)
    e = e.replace("_", "")
    # A C octal literal is 0NNN; Python needs 0oNNN. Not 0, and not 0x/0b.
    e = re.sub(r"\b0(?=[0-7]+\b)", "0o", e)
    # Casts, on either side.
    e = re.sub(r"\(\s*(unsigned\s+)?(int|long|short|char|u?int\d+_t)\s*\)", "", e)
    e = re.sub(r"\bas\s+\w+\b", "", e)
    if not re.fullmatch(r"[0-9a-fA-FxXoObB_()<>|&^~+*/\-\s]+", e):
        return None
    try:
        v = eval(e, {"__builtins__": {}}, {})  # noqa: S307 - arithmetic only
    except Exception:
        return None
    return v if isinstance(v, int) else None


def c_defines() -> dict[str, int]:
    """Every `#define NAME <arithmetic>` in the C, by name.

    **Two files disagreeing about a name is a defect and is reported.** It used
    to drop the name, with the reason "not this tool's business: it cannot say
    which one a crate meant" — which was true when many headers were compiled
    into different translation units and a `#if` could pick between them. No
    crate reads a header, `iul.h` is the interface and the rest are a record, so
    there is no arrangement in which two files may answer differently.

    That gap cost a defect the day this was changed: `iul.h` was written by hand
    on 2026-09-08 with `DEV_CHAR 0` and `DEV_BLOCK 1`, which is the opposite of
    `fs/dev.h`, and the disagreement made both names *invisible* here instead of
    reported. `tools/unread-flags.py` noticed, from one file over.

    Two definitions in the **same** file are a conditional — `debug.h`'s
    `TRACE_<channel>` is `TRACE__` or `TRACE__NOP` depending on a `-D`, and
    `util/sync.h`'s `LOCK_INITIALIZER` has a third field under `LOCK_DEBUG`.
    Those are kept out of the comparison, as before.
    """
    out = run(
        "rg", "--with-filename", "--no-line-number",
        r"^\s*#define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(\S.*)$",
        "--glob", "*.c", "--glob", "*.h",
        "--glob", "!kernel/offload_tests/**",
        ".",
    )
    found: dict[str, int] = {}
    origin: dict[str, str] = {}
    conditional: set[str] = set()
    disagree: dict[str, tuple[str, int, str, int]] = {}
    for line in out.splitlines():
        path, _, rest = line.partition(":")
        m = re.match(r"^\s*#define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(\S.*)$", rest)
        if not m:
            continue
        name, body = m.group(1), m.group(2)
        v = value_of(body)
        if v is None:
            continue
        if name in found and found[name] != v:
            if origin[name] == path:
                conditional.add(name)
            else:
                disagree[name] = (origin[name], found[name], path, v)
            continue
        found.setdefault(name, v)
        origin.setdefault(name, path)
    for name in conditional:
        found.pop(name, None)
    if disagree:
        for name, (a, va, b, vb) in sorted(disagree.items()):
            print(f"DISAGREE {name}: {va} in {a}, {vb} in {b}")
        raise SystemExit(
            f"guessed-constants: {len(disagree)} name(s) are defined differently "
            "in two files. Nothing compiles these headers, so there is no `#if` "
            "that picks between them -- one of the two is simply wrong."
        )
    return found


def rust_constants() -> list[tuple[str, str, str, int]]:
    """(path, line, name, value) for every evaluable `const NAME = ...`."""
    out = run(
        "rg", "--with-filename", "--line-number",
        r"^\s*(?:pub\s+)?const\s+([A-Z][A-Z0-9_]*)\s*:\s*[^=]+=\s*([^;]+);",
        "--glob", "*.rs", "crates",
    )
    found = []
    for line in out.splitlines():
        try:
            path, lineno, text = line.split(":", 2)
        except ValueError:
            continue
        m = re.search(
            r"const\s+([A-Z][A-Z0-9_]*)\s*:\s*[^=]+=\s*([^;]+);", text
        )
        if not m:
            continue
        v = value_of(m.group(2))
        if v is None:
            continue
        found.append((path, lineno, m.group(1), v))
    return found


def main() -> int:
    defines = c_defines()
    consts = rust_constants()

    compared = 0
    findings = []
    for path, lineno, name, value in consts:
        # `P_NOACCESS` in Rust against `P_NOACCESS` in C, and the trailing-
        # underscore spelling the guest constants use (`O_RDONLY_`).
        for candidate in (name, name + "_"):
            if candidate not in defines:
                continue
            compared += 1
            if defines[candidate] == value:
                break
            stem = Path(path).stem
            if (stem, name) in ALLOWED:
                break
            findings.append((path, lineno, name, value, candidate, defines[candidate]))
            break

    print(f"{len(consts)} evaluable Rust constants, {len(defines)} C defines")
    print(f"{compared} share a name and were compared")

    if not findings:
        print()
        print("Every one agrees with the C it shares a name with.")
        return 0

    print()
    print("Disagreeing:")
    for path, lineno, name, value, cname, cvalue in findings:
        print(f"  {name} = {value} ({value:#x})")
        print(f"      {path}:{lineno}")
        print(f"      #define {cname} is {cvalue} ({cvalue:#x})")
    print()
    print("Each is a number that has a definition and was written out again.")
    print("Generate it with bindgen -- see crates/kernel/mmapcalls/build.rs --")
    print("or, if the difference is deliberate, add it to ALLOWED with the reason.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
