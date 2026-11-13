#!/usr/bin/env python3
"""A Rust crate calling another Rust crate through the C ABI.

`CLAUDE.md` records what that costs and why the count went from **691 sites
over 311 functions to 7** on 2026-09-05:

- A `#[no_mangle]` export is an **optimisation barrier**. The symbol stays
  externally visible, so LTO must emit the function as written and cannot
  specialise the call. `poll_bench` went 1.9 -> 1.4 us/fd when four such calls
  in `fs/poll` stopped being exports.
- A C ABI call needs **no dependency edge**, so the graph that would report a
  layering mistake never looks. Converting the last 38 owners made cargo look
  and it refused nine cycles, seven of which were a dependency pointing the
  wrong way and had been for as long as the code had.

It was a command in `CLAUDE.md` to be re-run by hand after adding a crate. That
is why this file exists: on 2026-09-06 the count went **7 -> 34** in a day and
nobody ran it. Moving C into Rust produces exactly this shape, because the
callers keep reaching the function the way they always had — so the day that
creates the most of them is the day nobody thinks to look.

## What is allowed

A site may stay on the C ABI if the comment above it says `keep-c-abi` and why.

**A macro-generated export is invisible here.** `crates/asbestos/diag` defines
its fifteen counters with a `counters!` macro that expands to
`#[unsafe(no_mangle)] pub static`, and this reads source rather than expansions
-- so `crates/asbestos/dispatch` declaring eleven of them in an `extern "C"`
block went unreported until somebody read it, on 2026-09-09. The name of the
shape is in `CLAUDE.md`: a gate whose filter is a proxy will one day be a proxy
for the wrong thing.
`crates/fs/mount` has three: the table reads the object's `mount_point_of` and
its refcount pair six times, so a direct call would be a cycle. Genuinely
mutual, and the direction with fewer sites gives way.

The marker exists because the conversion tooling reads code, not comments, and
undid one of those decisions twice.

## Two ways a crate reaches another one

`ffi::name(` is one: bindgen generated the declaration from a header. The other
is a **hand-written `extern "C"` block**, and it was invisible here until
2026-09-06 — twenty declarations across twelve crate pairs, doing exactly the
same thing with the same cost. A block is reported at its declaration rather
than at each call, because the declaration is the thing to delete.

## What this still does not see

A call through a function pointer. Real, and not common here.

Run as `tools/checks.sh rust_c_abi`, and by hand:

    python3 tools/rust-c-abi.py
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: How far above a call site to look for the marker. Three lines covers a
#: `// keep-c-abi: ...` sentence wrapped by rustfmt.
MARKER_LOOKBACK = 6

EXPORT = re.compile(
    r'#\[unsafe\(no_mangle\)\]\s*(?:pub\s+)?(?:unsafe\s+)?extern "C" fn (\w+)'
)
#: A `#[no_mangle] pub static`, which the linker resolves by name exactly as it
#: resolves a function. Added 2026-09-09: `crates/asbestos/dispatch` declared
#: eleven of `crates/asbestos/diag`'s counters in an `extern "C"` block while
#: depending on that crate, and `crates/kernel/boot` did the same with
#: `crates/fs/fdobj`'s `fdtable_ops`. Both were invisible here, because this
#: read `fn` and nothing else.
EXPORT_STATIC = re.compile(
    r'#\[unsafe\(no_mangle\)\]\s*(?:pub\s+)?static (?:mut )?(\w+)'
)
CALL = re.compile(r"\bffi::(\w+)\s*\(")
#: The opening of a hand-written `extern "C"` block, and a `fn` or a `static`
#: inside one.
EXTERN_BLOCK = re.compile(r'(?:unsafe\s+)?extern\s+"C"\s*\{')
EXTERN_FN = re.compile(r"\bfn\s+(\w+)\s*[(<]")
#: A `static` in an extern block, and the `#[link_name]` above one when it has
#: one -- which is what the linker actually matches on. `crates/kernel/boot`
#: declared `static FDTABLE_OPS` with `#[link_name = "fdtable_ops"]`, so reading
#: the Rust name would have missed it.
EXTERN_STATIC = re.compile(
    r'(?m)^\s*(?:#\[link_name\s*=\s*"(?P<link>\w+)"\]\s*\n\s*)?static (?:mut )?(?P<name>\w+)\s*:'
)


#: `#[cfg(test)] mod name;` — a test module in a *file of its own*.
TEST_MOD = re.compile(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+(\w+)\s*;")


def test_only_files(files: list[pathlib.Path]) -> set[pathlib.Path]:
    """Files that exist only for tests, because a `#[cfg(test)] mod` names them.

    The third hole in this gate's idea of what test code is, and the one that
    matters most: `crates/kernel/signalcalls/src/tests.rs` defines
    `#[no_mangle]` test symbols in a file that is included through a
    `#[cfg(test)] mod tests;` declaration in `lib.rs`. The scanner therefore
    treats such files as test-only when attributing C ABI symbols.
    """
    out: set[pathlib.Path] = set()
    for path in files:
        text = path.read_text(errors="replace")
        for m in TEST_MOD.finditer(text):
            name = m.group(1)
            out.add(path.parent / f"{name}.rs")
            out.add(path.parent / name / "mod.rs")
    return out


def rust_files() -> list[pathlib.Path]:
    out = subprocess.run(
        ["rg", "--files", "-g", "*.rs", "crates"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()
    return [ROOT / p for p in out]


def crate_of(path: pathlib.Path) -> str:
    """`crates/kernel/pids/src/lib.rs` -> `kernel/pids`."""
    parts = path.relative_to(ROOT).parts
    return "/".join(parts[1:3])


def test_spans(text: str) -> list[tuple[int, int]]:
    """The `[start, end)` byte ranges of every `#[cfg(test)]` item.

    Found by matching braces from the attribute, **not** by cutting the file at
    the first one. That cut is what this used to do, and it was wrong in the
    only way that matters: it assumes a test module is the last thing in its
    file. `crates/kernel/pids/src/lib.rs` has one at line 308 followed by nine
    hundred lines of production code, so thirteen of its exports —
    `pids_lock_acquire` and every `pidreg_*` — were invisible here, and four
    crates reached them through the C ABI with the gate reporting zero.

    Strings and comments are not parsed. A brace inside either would throw the
    match off; there is none in a `#[cfg(test)]` module's opening lines, and
    the failure mode is a span that ends early, which reports *more* rather
    than fewer.
    """
    spans = []
    at = 0
    while True:
        i = text.find("#[cfg(test)]", at)
        if i < 0:
            return spans
        j = text.find("{", i)
        if j < 0:
            return spans
        depth, k = 0, j
        while k < len(text):
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        spans.append((i, k))
        at = k + 1


def exports(files: list[pathlib.Path]) -> dict[str, str]:
    """Every C-ABI export, keyed by name, valued by the crate that owns it.

    Definitions inside a `#[cfg(test)]` item are skipped: a test stub is not
    the owner, and counting one makes an ordinary C call look like a Rust one.
    Test-only symbol definitions are excluded because they are link doubles,
    not production owners of an ABI.
    """
    out: dict[str, str] = {}
    test_only = test_only_files(files)
    for path in files:
        if "/examples/" in str(path) or path in test_only:
            continue
        text = path.read_text(errors="replace")
        spans = test_spans(text)
        for pattern in (EXPORT, EXPORT_STATIC):
            for m in pattern.finditer(text):
                if any(a <= m.start() <= b for a, b in spans):
                    continue
                out[m.group(1)] = crate_of(path)
    return out


def attached_comment(lines: list[str], at: int) -> str:
    """The contiguous run of comment lines directly above line index `at`.

    However many there are, rather than a fixed lookback: a `keep-c-abi`
    explanation is a paragraph, and `crates/kernel/usercopy`'s is nine lines
    over a four-function `extern` block. A window that stops short reports a
    decision that has already been written down and defended, which trains a
    reader to ignore the gate.
    """
    out = []
    i = at - 1
    while i >= 0:
        t = lines[i].strip()
        if t.startswith("//") or t.startswith("///"):
            out.append(t)
            i -= 1
        elif not t:
            # A blank line inside a comment paragraph ends it.
            break
        else:
            break
    return "\n".join(reversed(out))


def block_end(text: str, open_brace: int) -> int:
    """The index of the `}` closing the block whose `{` is at `open_brace`."""
    depth, k = 0, open_brace
    while k < len(text):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return k
        k += 1
    return len(text)


def offenders(files: list[pathlib.Path], owned: dict[str, str]) -> list[str]:
    bad = []
    for path in files:
        text = path.read_text(errors="replace")
        crate = crate_of(path)
        lines = text.splitlines()
        skip = test_spans(text)

        # A hand-written `extern "C"` block declaring another crate's export.
        for m in EXTERN_BLOCK.finditer(text):
            if any(a <= m.start() <= b for a, b in skip):
                continue
            # Not one written *inside a comment*. `crates/asbestos/gen` records
            # that a static "was an `extern "C" { static g_trace_highbits; }`
            # here until 2026-09-06", and reading that as a live declaration is
            # a check that punishes writing down what was removed.
            line_start = text.rfind("\n", 0, m.start()) + 1
            if text[line_start : m.start()].lstrip().startswith(("//", "*")):
                continue
            body = text[m.end() : block_end(text, m.end() - 1)]
            # The marker goes above the **block**, not above each `fn` in it:
            # one decision covers the whole interface, and a block's comment
            # can be much longer than MARKER_LOOKBACK. `crates/kernel/usercopy`
            # has a four-line one over a four-function block and was reported
            # anyway until 2026-09-06.
            block_line = text.count("\n", 0, m.start())
            if "keep-c-abi" in attached_comment(lines, block_line):
                continue
            found = [(fm, fm.group(1)) for fm in EXTERN_FN.finditer(body)]
            found += [
                (fm, fm.group("link") or fm.group("name"))
                for fm in EXTERN_STATIC.finditer(body)
            ]
            for fm, name in found:
                owner = owned.get(name)
                if owner is None or owner == crate:
                    continue
                at = m.end() + fm.start()
                line_no = text.count("\n", 0, at)
                if "keep-c-abi" in attached_comment(lines, line_no):
                    continue
                rel = path.relative_to(ROOT)
                bad.append(
                    f"{rel}:{line_no + 1}: {crate} declares {owner}'s {name} "
                    f"in an extern block"
                )

        for m in CALL.finditer(text):
            name = m.group(1)
            owner = owned.get(name)
            if owner is None or owner == crate:
                continue
            line_no = text.count("\n", 0, m.start())
            window = "\n".join(lines[max(0, line_no - MARKER_LOOKBACK):line_no])
            if "keep-c-abi" in window:
                continue
            rel = path.relative_to(ROOT)
            bad.append(f"{rel}:{line_no + 1}: {crate} calls {owner}'s {name}")
    return bad


def main() -> int:
    files = rust_files()
    owned = exports(files)
    if not owned:
        print(
            "rust-c-abi: found no C-ABI exports at all, which cannot be right "
            "-- the pattern this greps for has changed and the check is "
            "reading nothing",
            file=sys.stderr,
        )
        return 1

    bad = offenders(files, owned)
    print(f"{len(owned)} C-ABI exports in crates/")
    print(f"{len(bad)} calls to one from another crate, without a keep-c-abi marker")
    if not bad:
        print("\nNo Rust crate reaches another through the C ABI unremarked.")
        return 0

    print("\nThrough the C ABI:")
    for b in bad:
        print(f"  {b}")
    print(
        "\nA C ABI call is an optimisation barrier and a dependency edge cargo\n"
        "cannot check. Three ways out, in the order to try them:\n"
        "  1. Move the code to where it belongs, and add the dependency.\n"
        "  2. A hook in the leaf crate, for a notification.\n"
        "  3. Return the decision instead of acting on it.\n"
        "If the pair is genuinely mutual, say `keep-c-abi:` above the call and\n"
        "why -- the direction with fewer sites gives way."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
