#!/usr/bin/env python3
"""Which `iul.h` calls answer an `ERR_PTR`, and do they say so.

`iul.h` defines `ERR_PTR`/`PTR_ERR`/`IS_ERR`: a negative guest errno smuggled
through a pointer. Three exported functions answer one, and **none of them ever
answers NULL** -- so an embedder that writes the ordinary `if (!p)` gets a
pointer at an address like -2 and dereferences it. The convention is therefore
part of each declaration, not a remark near the macros.

**It was a remark near the macros until 2026-09-16.** `iul.h` said "several
calls answer one" and named none of them, and two of the three Rust sites each
carried a comment saying it was "one of the **two** places the `ERR_PTR`
encoding is left". They were wrong about the count: `crates/fs/ttydev`'s
`pty_open_fake` wrote the same expression out by hand -- `e as isize as *mut
ffi::tty` rather than `ffi::err_ptr(e)` -- so a grep for the helper found the
two that agreed with each other, three times over.

That is this tree's commonest defect shape, in its documentation form: a count
in a comment that nothing recomputes. This recomputes it.

Reported as a **failure**, because acting on a finding needs no fact from
outside this repository: either a declaration answers an `ERR_PTR` and says so,
or it does not and must not.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The sentence a pointer-returning declaration in `iul.h` must carry when it can
# answer an errno. Matched case-insensitively on the line above or the same one.
SAYS_SO = re.compile(r"answers an ERR_PTR", re.I)

# How the encoding is written in Rust. `err_ptr(...)` is the helper in
# `crates/kernel/abi`; the second arm is the hand-written form that hid the
# third site, and it is here so that writing it again is found rather than
# forbidden.
ENCODES = re.compile(r"\berr_ptr\s*\(|as\s+isize\s+as\s+\*(?:mut|const)\s")


def iul_h_pointer_decls() -> dict[str, bool]:
    """Every `iul.h` declaration returning a pointer, and whether it says so.

    The comment may be the block above the declaration or a trailing one, so the
    two preceding lines and the declaration itself are searched.
    """
    lines = (ROOT / "iul.h").read_text(encoding="utf-8").split("\n")
    out: dict[str, bool] = {}
    for i, line in enumerate(lines):
        m = re.match(r"^[A-Za-z_][\w ]*\*\s*(\w+)\s*\(", line)
        if not m:
            continue
        context = "\n".join(lines[max(0, i - 3) : i + 1])
        out[m.group(1)] = bool(SAYS_SO.search(context))
    return out


def rust_encoders() -> dict[str, list[str]]:
    """Every `#[no_mangle]` Rust function whose body encodes an `ERR_PTR`."""
    found: dict[str, list[str]] = {}
    for path in (ROOT / "crates").rglob("*.rs"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        # Comments first: this file's own prose names the helper repeatedly, and
        # so do the three sites' doc comments.
        text = re.sub(r"//[^\n]*", "", text)
        lines = text.split("\n")
        for i, line in enumerate(lines):
            m = re.match(
                r"^\s*pub (?:unsafe )?extern \"C\" fn (\w+)", line
            )
            if not m or not any(
                "no_mangle" in x for x in lines[max(0, i - 4) : i]
            ):
                continue
            # The body, to its closing brace at column 0.
            body = []
            for l in lines[i:]:
                body.append(l)
                if l.startswith("}"):
                    break
            if ENCODES.search("\n".join(body)):
                found.setdefault(m.group(1), []).append(
                    f"{path.relative_to(ROOT)}:{i + 1}"
                )
    return found


def main() -> int:
    decls = iul_h_pointer_decls()
    if len(decls) < 4:
        print(f"err_ptr: found {len(decls)} pointer-returning declarations in")
        print("  iul.h, which cannot be right -- this would pass vacuously.")
        return 1

    encoders = rust_encoders()
    if not encoders:
        print("err_ptr: no Rust function encodes an ERR_PTR, which cannot be")
        print("  right: iul.h defines the macros and three calls answer one.")
        return 1

    bad = False
    for name, says in sorted(decls.items()):
        encodes = name in encoders
        if encodes and not says:
            bad = True
            print(f"err_ptr: `{name}` answers an ERR_PTR and iul.h does not say so:")
            for w in encoders[name]:
                print(f"    {w}")
        if says and not encodes:
            bad = True
            print(f"err_ptr: iul.h says `{name}` answers an ERR_PTR, and no")
            print("    #[no_mangle] function of that name encodes one.")
    if bad:
        print(
            "\nA pointer-returning call that answers an errno never answers\n"
            "NULL, so an embedder testing `if (!p)` dereferences an address\n"
            "like -2. Say so above the declaration, or stop encoding one."
        )
        return 1

    n = sum(1 for v in decls.values() if v)
    print(
        f"{len(decls)} pointer-returning declarations in iul.h; "
        f"{n} answer an ERR_PTR and say so"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
