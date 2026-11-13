#!/usr/bin/env python3
"""Report a name `iul.h` declares that nothing in the tree defines.

`iul.h` is the whole of the embedder interface: a consumer links `libiul.a` and
includes this one file. It is **written by hand**, so every name in it is a
second rendering of something whose first rendering is a `#[no_mangle]` in
`crates/` -- and two renderings of one thing can disagree.

`tools/extern-signatures.py` already asks whether a declaration and a definition
agree about their *argument count*. This asks the question one step earlier:
**is there a definition at all?**

That is not hypothetical. On 2026-09-11 `iul.h` declared

    extern void (*exit_hook)(struct task *task, int code);

and the Rust that had defined it -- a `#[no_mangle] pub static mut` -- had become
a `OnceLock` behind `set_exit_hook` with no `#[no_mangle]` anywhere. So the
header named a symbol nothing defined, `tests/integration/sbm_api_test.c` did
not link, and `ninja -C build` was red on a tree whose `cargo build`,
`cargo test` and `cargo clippy` were all green. It had been that way for a
commit and the three cargo lines are what got read.

`extern-signatures.py` cannot see it, and correctly: there is no definition to
compare the declaration against, and a **variable** with no symbol is a
different question from a function whose signature disagrees.

Where a definition may live, in the order this looks:

* a `#[unsafe(no_mangle)]` or `#[no_mangle]` item in `crates/` -- `pub static`,
  `pub static mut`, or a function;
* a `.globl` in one of the gadget `.S` files, because five of those are the
  only non-Rust code that ships.

Usage:  tools/header-symbols.py [--quiet]
Exit:   0 if every name `iul.h` declares is defined, 1 otherwise. Finding no
        declarations, or no definitions, is also 1 -- a check that reads
        nothing reports nothing, and this file exists because a green line was
        read as "fine" rather than as "nothing was looked at".
"""

import pathlib
import re
import sys

# Two forms, and they are two regexes on purpose.
#
# Written as one alternation with a non-greedy type prefix, `extern void
# (*exit_hook)(struct task *, int);` matches the *plain* branch with the name
# `oid` -- the engine stops the prefix after `v`, takes `oid` as the
# identifier, and finds the `(` it needs right after. The back-out that put
# that declaration back therefore reported a name nobody had ever written, and
# "the tool went red" would have been the wrong thing to check: it has to go
# red *naming the symbol*.
#
# So: the function-pointer form is matched by the parenthesised `(*name)`, and
# the plain form ends at a `;` with a greedy type, which backtracks to leave
# the last identifier as the name.
EXTERN_FNPTR = re.compile(r"^extern\s+[^;]*?\(\s*\*\s*(\w+)\s*\)\s*\(", re.MULTILINE)
# The `(?<!\w)` is the whole of it, and both regexes without it were wrong in a
# way that still produced output:
#
# * greedy, the type class backtracks one **character** rather than one word,
#   so `extern const struct fs_ops realfs;` reports the name `s`;
# * requiring whitespace before the name drops `extern struct tty_driver
#   *tty_drivers[256];`, where the star is adjacent -- and the only sign is a
#   count going from 6 to 5.
#
# With the lookbehind the name can only start where a word does, so the
# non-greedy class is forced out to the last `*` or space.
EXTERN_PLAIN = re.compile(
    r"^extern\s+[A-Za-z_][\w \t*]*?(?<!\w)(\w+)\s*(?:\[[^\]]*\])?\s*;", re.MULTILINE
)

# A function declaration: a return type, a name, a parameter list, a semicolon.
# Anchored at the start of a line, which is how every one in this header is
# written, so a call inside a comment or a continuation line is not one.
#
# `typedef` is excluded and the exclusion is load-bearing: without it
# `typedef void (*prebuilt_fn)(struct cpu_state *, struct tlb *);` reports the
# *return type* as an undefined function, and this header has nine of them --
# so the first run of this file reported `void`, `int`, `bool` and
# `nsym_result` as missing symbols.
FUNC = re.compile(
    r"^(?!extern\b)(?!typedef\b)(?!return\b)[A-Za-z_][\w \t*]*?\**\s*(\w+)\s*\([^;{]*\)\s*;",
    re.MULTILINE,
)

COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)

NO_MANGLE = re.compile(
    r"#\[\s*(?:unsafe\s*\(\s*)?no_mangle\s*\)?\s*\]\s*"
    r"(?:#\[[^\]]*\]\s*)*"                      # any attributes in between
    r"(?:pub\s+)?(?:unsafe\s+)?(?:extern\s+\"C\"\s+)?"
    r"(?:fn\s+(\w+)|static\s+(?:mut\s+)?(\w+))",
    re.S,
)

# Not anchored to the start of a line, because half of these are inside a Rust
# `global_asm!` and the line begins with a quote. `iul_printk` and `die` are
# defined that way -- they are variadic, which Rust cannot express, so they are
# hand-written assembly that tail-calls a `va_list` form. Scanning only
# `asbestos/**/*.S` reported both as undefined on the first run.
GLOBL = re.compile(r"\.globl\s+_?(\w+)")

# Declared here and defined by the platform rather than by this tree. A name
# needs the reason it is not this tree's, like every other allowlist here.
NOT_OURS: set[str] = set()


def declared(header):
    """Every name `iul.h` declares, with comments blanked first."""
    text = COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), header)
    variables = set(EXTERN_FNPTR.findall(text)) | set(EXTERN_PLAIN.findall(text))
    names = set(variables)
    for m in FUNC.finditer(text):
        names.add(m.group(1))
    return names - NOT_OURS, variables - NOT_OURS


def defined(root):
    """Every symbol this tree exports, from Rust and from the gadgets."""
    out = set()
    for path in root.glob("crates/**/*.rs"):
        if "/target/" in str(path):
            continue
        text = path.read_text(errors="ignore")
        for m in NO_MANGLE.finditer(text):
            out.add(m.group(1) or m.group(2))
        out.update(GLOBL.findall(text))
    for path in root.glob("asbestos/**/*.S"):
        out.update(GLOBL.findall(path.read_text(errors="ignore")))
    return out


def main():
    quiet = "--quiet" in sys.argv
    root = pathlib.Path(__file__).resolve().parent.parent

    names, variables = declared((root / "iul.h").read_text())
    exported = defined(root)

    # The assertions. Either of these empty makes every comparison below
    # vacuous, and a vacuous run of this file reads exactly like a clean one.
    if not names:
        print("FAIL     no declarations parsed out of iul.h -- this check reads "
              "nothing. The header's shape changed, or it moved.")
        return 1
    if not exported:
        print("FAIL     no #[no_mangle] items found in crates/ -- every name "
              "below would be reported as missing, or none would.")
        return 1

    missing = sorted(names - exported)
    for name in missing:
        kind = "variable" if name in variables else "function"
        print(f"MISSING  iul.h declares {kind} `{name}` and nothing in crates/ "
              f"or asbestos/ defines it")

    if not quiet:
        print(f"{len(names)} names declared in iul.h ({len(variables)} of them "
              f"variables), {len(exported)} exported by the tree, "
              f"{len(missing)} declared and not defined")
    if missing:
        print("A consumer that uses one gets a link error naming it, and this "
              "repository's own embedder example is such a consumer. If the "
              "interface moved, the header has to move with it; if the name "
              "went, delete the declaration.")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
