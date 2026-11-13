#!/usr/bin/env python3
"""A Rust `extern "C"` declaration that disagrees with the C it names.

A crate that needs a C function declares it by hand:

    unsafe extern "C" {
        fn rusage_get_thread() -> Rusage;
    }

and **nothing checks that against the C**. The Rust compiler believes the
declaration, the C compiler never sees it, and the linker matches on the name
alone. So when the C side changes shape the call still links and passes whatever
happens to be in the argument registers.

That is not hypothetical. `rusage_get_thread` went from returning a struct to
filling a caller's on 2026-08-31, and `crates/kernel/timecalls` kept the old
declaration: every `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` wrote through a
register that held nothing, and the emulator took `SIGSEGV` at `fault addr 0x1`.
The guest suite caught it; nothing before the guest suite did.

**Generating beats checking**, as everywhere else here: a crate whose `build.rs`
runs bindgen over the header cannot have this defect at all. This finds the ones
that declare by hand — there are a lot, because most of these are one or two
symbols and a whole bindgen pass is a heavy answer to that.

## What it compares

The **argument count**, and whether the return is a value or nothing. Types are
deliberately not compared: `c_int` against `int` and `*mut c_void` against
`struct mem *` are the same thing spelled differently, and a checker that
insisted would be noise. Arity is what goes wrong when a signature changes, and
it is what happened above.

A name it cannot find a prototype for is skipped, not reported. A missing one is
`dead_exports`' question rather than this one.

## The other side of it, since 2026-09-01

A declaration does not have to name *C*. As the migration proceeds, one crate
increasingly declares a function another **crate** exports — `signalcalls`
declares `signal_kill_task_for_rs`, which `signaldeliver` defines — and that
pair is checked by nothing at all: there is no header, so the C search above
finds nothing and the name was skipped.

So the definitions this compares against are C prototypes *and* Rust
`#[unsafe(no_mangle)] extern "C" fn` definitions. A name defined on both sides
is a C prototype, and the C wins: that is the case the tool was written for.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# A declaration whose C prototype this cannot read, with the reason.
ALLOWED: dict[str, str] = {}

SKIP_DIRS = {"build", "target", "offload_tests"}


def tracked(pattern: str) -> list[Path]:
    """Source files, from `rg --files`, which honours `.gitignore`.

    Not `Path.glob("**/*.c")`: the filter above runs *after* the walk, so the
    walk still descended into `target/` and every `build*/` — tens of thousands
    of files, and most of this test's runtime. `tools/ops-table-pairs.py` had
    the same shape and went from 21 seconds to 0.15 with the same change; it
    was timing out at 30 whenever the machine was doing anything else.

    `SKIP_DIRS` stays, because `offload_tests` is tracked and `.gitignore`
    would not exclude a build directory somebody made outside the pattern.
    """
    out = subprocess.run(
        ["rg", "--files", "-g", pattern],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()
    return sorted(ROOT / p for p in out)


def c_prototypes() -> dict[str, int]:
    """`name -> argument count` for every C prototype in the tree.

    A prototype is a declaration or a definition; both give the arity. `void` as
    the only parameter is zero arguments, and a variadic `...` counts as one
    more than the fixed ones — which is enough for the comparison, because a
    Rust declaration of a variadic spells it `...` too.
    """
    out: dict[str, int] = {}
    pattern = re.compile(
        r"^[A-Za-z_][\w \t*]*?[\s*]([A-Za-z_]\w*)\s*\(([^;{]*)\)\s*[;{]",
        re.MULTILINE,
    )
    for path in tracked("*.h") + tracked("*.c"):
        if SKIP_DIRS & set(path.parts):
            continue
        text = path.read_text(errors="replace")
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
        text = re.sub(r"//[^\n]*", " ", text)
        for m in pattern.finditer(text):
            name, args = m.group(1), m.group(2).strip()
            if name in ("if", "for", "while", "switch", "return", "sizeof"):
                continue
            n = 0 if args in ("", "void") else top_level_commas(args) + 1
            # A name defined twice with different arity is a macro or a
            # platform split; the first one wins and a disagreement between
            # them is not this tool's question.
            out.setdefault(name, n)
    return out


def top_level_commas(s: str) -> int:
    """Commas outside parentheses, so a function-pointer parameter counts once."""
    depth, n = 0, 0
    for c in s:
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "," and depth == 0:
            n += 1
    return n


def rust_externs(path: Path):
    """`(name, argument count, line)` for each fn in an `extern "C"` block."""
    text = path.read_text(errors="replace")
    out = []
    for m in re.finditer(r'(?:unsafe\s+)?extern\s+"C"\s*\{', text):
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
        for fn in re.finditer(r"\bfn\s+(\w+)\s*\(", body):
            args, depth2, j = "", 0, fn.end() - 1
            while j < len(body):
                if body[j] == "(":
                    depth2 += 1
                elif body[j] == ")":
                    depth2 -= 1
                    if depth2 == 0:
                        break
                args += body[j]
                j += 1
            # Rust allows a trailing comma in a multi-line argument list and C
            # does not, so counting commas without stripping it reports every
            # multi-line declaration as one argument too many. The first
            # version of this tool did, and its seven findings were all that.
            args = args[1:].strip().rstrip(",").strip()
            n = 0 if args == "" else top_level_commas(args) + 1
            line = text[: m.end() + fn.start()].count("\n") + 1
            out.append((fn.group(1), n, line))
    return out


def cfg_test_spans(text: str) -> list[tuple[int, int]]:
    """Where each `#[cfg(test)] mod ... { ... }` starts and ends.

    A definition inside one is **not an interface**: it cannot be linked into
    `libiul.a`, and its only job is to give a test binary a symbol so that the
    crate can be tested at all. `crates/kernel/syscalltable` is the case that
    made this necessary — its 204 stubs are deliberately zero-argument, because
    giving each its real signature would be a second hand-written copy of what
    `build.rs` generates precisely so that there is only one.
    """
    spans = []
    for m in re.finditer(r"#\[cfg\(test\)\]", text):
        brace = text.find("{", m.end())
        if brace < 0:
            continue
        # Only a module: a `#[cfg(test)]` on a function has no definitions
        # under it that this would otherwise read.
        head = text[m.end() : brace]
        if "mod " not in head:
            continue
        depth, i = 0, brace
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        spans.append((m.start(), i))
    return spans


def rust_definitions() -> dict[str, tuple[int, str]]:
    """`name -> (argument count, where)` for each `#[no_mangle] extern "C" fn`.

    These are the exports one crate offers another. Their arity is as
    load-bearing as a C prototype's and nothing else compares it.

    A definition inside a `#[cfg(test)]` module is skipped; see
    [`cfg_test_spans`].
    """
    out: dict[str, tuple[int, str]] = {}
    pattern = re.compile(
        r'#\[(?:unsafe\()?no_mangle\)?\]\s*'
        r'(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)\s*\(',
        re.MULTILINE,
    )
    for path in sorted(ROOT.glob("crates/**/*.rs")):
        if SKIP_DIRS & set(path.parts):
            continue
        text = path.read_text(errors="replace")
        skip = cfg_test_spans(text)
        for m in pattern.finditer(text):
            if any(lo <= m.start() <= hi for lo, hi in skip):
                continue
            args, depth, j = "", 0, m.end() - 1
            while j < len(text):
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                args += text[j]
                j += 1
            args = args[1:].strip().rstrip(",").strip()
            n = 0 if args == "" else top_level_commas(args) + 1
            line = text[: m.start()].count("\n") + 1
            out.setdefault(m.group(1), (n, f"{path.relative_to(ROOT)}:{line}"))
    return out


def main() -> int:
    protos = c_prototypes()
    rust_defs = rust_definitions()
    findings = []
    checked = 0

    for path in sorted(ROOT.glob("crates/**/*.rs")):
        if SKIP_DIRS & set(path.parts):
            continue
        for name, n, line in rust_externs(path):
            if name in ALLOWED:
                continue
            # A C prototype wins over a Rust definition of the same name: that
            # is the case this was written for, and a Rust `extern "C"` shim
            # beside a C one is the same function.
            if name in protos:
                want, where = protos[name], "C"
            elif name in rust_defs:
                want, where = rust_defs[name][0], rust_defs[name][1]
                # A crate does not declare its own exports.
                if rust_defs[name][1].startswith(str(path.relative_to(ROOT))):
                    continue
            else:
                continue
            checked += 1
            if want != n:
                findings.append(
                    (f"{path.relative_to(ROOT)}:{line}", name, n, want, where)
                )

    # The other direction, and the one this tree now has most of: a C prototype
    # whose *definition* is a Rust `#[no_mangle] extern "C" fn`. Nothing else
    # compares those either -- the syscall table casts every entry to
    # `syscall_t`, so even a `sys_*` gets no check from the compiler -- and
    # `fs/real.h` had been declaring `realfs_rename` with three parameters since
    # the fourth was added. No C called it; a C caller would have compiled the
    # three-argument call and left `flags` to whatever was in the register.
    for name, (n, where) in sorted(rust_defs.items()):
        if name in ALLOWED or name not in protos:
            continue
        checked += 1
        if protos[name] != n:
            findings.append((where, name, n, protos[name], "C"))

    print(f"{checked} hand-written extern declarations with a definition to compare")
    print(f"{len(findings)} that disagree about how many arguments there are")
    if not findings:
        return 0
    print()
    for at, name, rust, want, where in findings:
        print(f"  {at}: {name} takes {rust} here and {want} in {where}")
    print()
    print("The linker matches on the name alone, so the call compiles and")
    print("passes whatever is in the argument registers. Fix the declaration,")
    print("or generate it -- a build.rs running bindgen over the header cannot")
    print("have this defect at all.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
