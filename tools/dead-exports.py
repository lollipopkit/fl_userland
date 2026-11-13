#!/usr/bin/env python3
"""A function nothing can reach: a Rust `extern "C"` export, or a C definition.

Every `#[unsafe(no_mangle)] pub extern "C" fn` in `crates/` exists for one
reason: so that C can call it. When the C that called it moves to Rust, the
export does not go with it — it keeps compiling, keeps taking space in the
archive, and keeps being a second interface somebody has to keep in step with
the first.

**This is the shape the migration creates**, and it is the mirror image of
`unread-flags.py`: that one finds a request the callee stopped honouring, this
one finds an answer nobody asks for any more. On 2026-08-30 there were 34 of
them, 31 genuinely dead — the whole C ABI of `crates/fs/ldisc` (sixteen
functions) and of `crates/fs/ttyreg` (fourteen), left behind when
`crates/fs/tty` took the terminal over and started using the Rust API.

CLAUDE.md's step 5 is where these get deleted rather than added to. This counts
them.

## What counts as reachable

- **Named in C.** Any `.c` or `.h` file in the tree mentioning the identifier,
  which covers a call, a declaration and a function-pointer assignment.

  Two mentions do not count, and both were found by deleting one and watching an
  export become unreachable that instant with nothing about the code changed. A
  **comment** naming the function, since 2026-09-03: this tree records what moved
  to Rust in long comments that name what moved, so a migrated export stayed
  reachable as long as somebody had written down that it had gone, and nine were
  dead behind that. And a **prototype in a `.c` file** whose name appears nowhere
  else in that file, since the same day: a declaration in a `.c` file is not an
  interface, so it exists to call the function from that file, and if the file
  does not call it the declaration is what the caller left behind when it moved.
  Six were dead behind *that* — `bindpath_normalize` and `bindpath_relative`
  declared in `fs/fake.c`, the three JIT diagnostic recorders declared in
  `asbestos/asbestos.c` for a dispatch loop that is Rust now, and
  `timeabi_absolute_deadline` declared in `util/sync.c` for a `wait_for` that is.
  A prototype in a **header** does count: `fs/fake.h` is what an embedder
  compiles against, and ServerBox calls things this tree never does.
- **Stored in a table by Rust.** `crates/fs/realfs` builds its own `fs_ops`
  with `pread: Some(realfs_pread)`, and C reaches it through the pointer — so
  an export that appears inside a `Some(...)` in Rust is live even though no C
  names it.
- **Called from Rust through the C ABI**, which is `extern` block plus a call.
  Those are worth looking at — a Rust-to-Rust call does not need the C ABI —
  but they are not dead, so they go in ALLOWED with a reason.
- **Called by the gadgets**, which is a `bl NAME(...)` in a `.S`. That was not
  modelled until 2026-09-02, when `emu/tlb.c`'s operations became Rust and four
  of them — `c_stxr_cas`, `c_ic_ivau` and the two interleaved SIMD ones — were
  reported dead while the assembly called every one.

## And the same question asked of C

A non-`static` C function that nothing names is the same defect wearing the
other hat, and until 2026-09-02 nothing asked. `emu/tlb.c` had **fifteen**:
every one of the thirteen `c_load`/`c_store` gadget fallbacks, plus `c_stp64`
and `c_stp32` — the "reliable C-based" path the gadgets were meant to fall back
to, while the gadgets grew their own inline fast paths instead. `c_ldp64` and
`c_ldp32` beside them are called, which is what made the set hard to see by
reading.

Two of the fifteen would have been wrong if anything had called them:
`c_load32` and `c_load16` read a whole word through one `__tlb_read_ptr`, which
answers a pointer into *one* page, so a four-byte load at offset `0xffe` would
have read two bytes out of whatever follows that host page. Only the 64-bit
pair had the byte-at-a-time path that handles it.

The C half is deliberately narrower than the Rust half. It looks only at
definitions in `emu/`, `kernel/`, `fs/` and `util/`, and it skips anything the
assembly could reach by a name it constructs, anything `static` (the compiler
already warns), and anything a header declares — a declared function is an
interface, and whether an interface has a caller is a different question from
whether a definition does. What is left is a function that is neither `static`,
nor declared, nor named anywhere.

`kernel/offload_tests/` is excluded: it is 340,000 lines of generated fixtures
that compile only with `-Doffload_test_prebuilt=true`, and scanning it costs
more than everything else together.

## And of variables, since 2026-09-11

`#[no_mangle]` on a `static` is the same export wearing a third hat, and this
file read `extern "C" fn` only — so **43 symbols had never been asked the
question at all**. Six of them are the embedder contract (`realfs`, `fakefs`,
`procfs`, `devptsfs`, `tty_drivers`, `real_tty_driver`, all declared in
`iul.h`); the rest are reported with the same test the function half uses and,
like it, **reported rather than failed**.

Found while removing `extern "C"` from 200 Rust-only functions, by asking the
question by hand and noticing that nothing in `tools/` already did.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# An export that no C names and no Rust table holds, but which is still
# reachable. One entry per export, **with the reason**.
# It held four entries until 2026-09-04, and all four were one thing: an export
# another *crate* declares in a hand-written `extern` block and calls. That is
# now a reachability rule -- `rust_extern_declared` -- because it is an
# interface with somebody on the other side, and `extern-signatures.py` is what
# checks the two halves agree. The remaining entries are the watchpoint/page-
# table cycle and the two halves of the fakefs archive boundary.
ALLOWED: dict[str, str] = {}


# A dead C definition that has been read and is being kept, **with the reason**.
# The same rule as ALLOWED above: an entry that stops applying fails the run,
# because it would otherwise cover whatever lands on that name next.
C_ALLOWED: dict[str, str] = {}
# It held 25 entries until 2026-09-02, every one a reference implementation in
# asbestos/guest-arm64/crypto_helpers.c whose gadget ran the host's own
# instruction instead -- the whole of AES, SHA-1, SHA-256, SHA-512 and the six
# permutes. The entry said the choice between deleting them and routing the
# gadgets through them was step 6's; step 6 deleted them, and one of them
# (sha1su1_helper) had been *wrong* for as long as it existed, which is what a
# reference implementation nothing runs turns into. The fifteen that a gadget
# does call are crates/asbestos/crypto now.


def run(*args: str) -> str:
    return subprocess.run(
        args, cwd=ROOT, capture_output=True, text=True, check=False
    ).stdout


# `#[unsafe(no_mangle)]` or the old spelling, and the `extern "C" fn` under it.
#
# **The attribute is what makes it an export**, not the calling convention.
# This matched `pub extern "C" fn` alone until 2026-09-03 and reported four
# functions that had just *lost* their `#[no_mangle]` because their last C
# caller went away -- which is the fix, not the finding. Without the attribute
# the symbol is mangled and no C can name it: what is left is a Rust function
# with a C calling convention, which is what you write when something takes its
# address (an `fd_ops` entry, an `atexit` handler) and is not an interface to C.
NO_MANGLE = re.compile(
    r'#\[(?:unsafe\(\s*)?no_mangle(?:\s*\))?\]'
    r'(?:\s*(?:#\[[^\]]*\]|///[^\n]*))*'
    r'\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)'
)

# The same attribute on a **variable**, which this file did not look at until
# 2026-09-11 and which is 43 symbols.
#
# `iul.h` declares six of them -- `realfs`, `fakefs`, `procfs`, `devptsfs`,
# `tty_drivers` and `real_tty_driver` -- so the class is part of the embedder
# contract rather than an oversight. What had never been asked is the question
# the function half asks: how many of the rest can anything outside Rust reach.
# That number is printed and **not failed**, for the reason
# `outside_the_embedder_surface` gives -- which of them an out-of-tree consumer
# links is a fact this repository does not hold.
#
# `pub(crate)` and `pub(super)` are in the alternation deliberately. A
# visibility narrower than `pub` does nothing to a `#[no_mangle]` symbol: it is
# still a strong global in `libiul.a`, and matching only `pub` would make the
# count quietly low, which is the shape this file's own history calls a gate
# covering nothing.
NO_MANGLE_STATIC = re.compile(
    r'#\[(?:unsafe\(\s*)?no_mangle(?:\s*\))?\]'
    r'(?:\s*(?:#\[[^\]]*\]|///[^\n]*))*'
    r'\s*(?:pub(?:\s*\([^)]*\))?\s+)?static\s+(?:mut\s+)?(\w+)'
)


def cfg_test_spans(text: str) -> list[tuple[int, int]]:
    """Where each `#[cfg(test)] mod ... { ... }` starts and ends.

    A definition inside one is **not an export**: it cannot be linked into
    `libiul.a`, and its only job is to give a test binary a symbol so that the
    crate can be tested at all. `tools/extern-signatures.py` has had this rule
    since 2026-09-03; this file did not, and got away with it because every
    stub anybody had written happened to be for a name C also mentions. The
    first that was not -- a stub in `crates/kernel/fdattr` for a symbol nothing
    references, which was a mistake of its own -- was reported here as a dead
    export, which is the wrong finding: the right one is that the stub is
    unnecessary, and a tool that reads test stubs as interfaces cannot say so.
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


def test_only_files() -> set[Path]:
    """Files a `#[cfg(test)] mod name;` names, which contain no `#[cfg(test)]`.

    `cfg_test_spans` finds a test module written *inline*. A test module in a
    file of its own has the attribute on the `mod` line in its parent, so
    nothing inside it is marked and every `#[no_mangle]` stub in it counts as a
    real export. `crates/fs/tty/src/tests.rs` defines
    `guest_lock_wait_ignoring_signals` that way, and it was reported as an
    export outside the embedder surface — a suggestion to demote a symbol that
    does not exist in a real build.

    `tools/rust-c-abi.py` had the identical hole, found the same day and for
    the same reason: the two tools were written from the same idea of what test
    code looks like, and that idea covers one of the two ways to write it.
    """
    out: set[Path] = set()
    pattern = re.compile(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+(\w+)\s*;")
    for path in sorted(Path("crates").glob("**/*.rs")):
        if "target" in path.parts:
            continue
        for m in pattern.finditer(path.read_text(errors="replace")):
            out.add(path.parent / f"{m.group(1)}.rs")
            out.add(path.parent / m.group(1) / "mod.rs")
    return out


ANY_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)


def blank_comments(text: str) -> str:
    """Comments replaced by spaces, keeping every offset and newline.

    Offsets matter because [`cfg_test_spans`] indexes into the same string and
    the line number is counted from it.

    This exists because a **doc example** is not an export. On 2026-09-11
    `crates/kernel/taskview/src/task_types.rs` grew a ```ignore block
    demonstrating which of the two `improper_ctypes` lints recurses through a
    raw pointer, and the demonstration contains

        #[unsafe(no_mangle)] pub extern "C" fn defn(_t: *mut Task) {}   // clean

    -- so this file reported `defn` as an unreachable C-ABI export and the gate
    went red on a comment. A doc comment is the one place in this tree where
    code that is deliberately *not* compiled is written out in full, and this
    tree's convention is long doc comments, so it will happen again.
    """
    return ANY_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def exports() -> dict[str, str]:
    """Every C-ABI export, mapped to the file that defines it.

    A definition inside a `#[cfg(test)]` module is skipped, and so is one in a
    file that a `#[cfg(test)] mod` names; see [`cfg_test_spans`] and
    [`test_only_files`].
    """
    return _no_mangle(NO_MANGLE)


def exported_statics() -> dict[str, str]:
    """Every `#[no_mangle]` static, mapped to the file that defines it.

    `blank_comments` first, and that is not a detail: the first version of this
    scan was written without it and reported a static called `mut`, because
    `crates/kernel/exitcalls` has the words `#[no_mangle] static mut` inside a
    doc comment recording what `set_exit_hook` replaced. A count with a
    sentence in it is a count nobody can act on.
    """
    return _no_mangle(NO_MANGLE_STATIC)


def _no_mangle(pattern: re.Pattern) -> dict[str, str]:
    found: dict[str, str] = {}
    test_only = test_only_files()
    for path in sorted(Path("crates").glob("**/*.rs")):
        if "target" in path.parts or path in test_only:
            continue
        text = blank_comments(path.read_text(errors="replace"))
        skip = cfg_test_spans(text)
        for m in pattern.finditer(text):
            if any(start <= m.start() < end for start, end in skip):
                continue
            line = text[: m.start()].count("\n") + 1
            found[m.group(1)] = f"{path}:{line}"
    return found


COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
STRING = re.compile(r'"(?:\\.|[^"\\])*"')


def strip_comments(text: str) -> str:
    """Blank out comments and string literals.

    This is not cosmetic. Every identifier in a C or H file used to count as a
    C reference, comments included -- and this tree records what moved to Rust
    in long comments that *name the function*, so a migrated export stayed
    "reachable" as long as anybody had written down that it had gone. It was
    found on 2026-09-03 by deleting such a comment: `cpu_step_to_interrupt`
    became unreachable that instant, and nothing about the code had changed.

    String literals go for the same reason one step removed: a `TRACE("...")`
    naming a function is not a call either.
    """
    return STRING.sub('""', COMMENT.sub(" ", text))


# A function prototype: a name, a parameter list, a semicolon, and no body.
PROTOTYPE = re.compile(
    r"\b([a-z_][a-z0-9_]*)\s*\([^;{)]*\)\s*;",
)


def c_identifiers() -> set[str]:
    """Every identifier a C or H file *uses*.

    Two things do not count as a use, and both were found the same way -- by
    deleting one and watching an export become unreachable that instant, with
    nothing about the code having changed.

    A **comment** naming the function, since 2026-09-03. This tree records what
    moved to Rust in long comments that name what moved, so a migrated export
    stayed reachable as long as somebody had written down that it had gone; nine
    were dead behind that.

    A **prototype in a `.c` file** whose name appears nowhere else in the same
    file, since the same day. A declaration in a `.c` file is not an interface --
    nobody outside the file can see it -- so it exists for one purpose, which is
    to call the function from that file. If the file does not, the declaration is
    what is left over from the caller that moved. `fs/fake.c` was declaring
    `bindpath_normalize` and `bindpath_relative` months after the last call to
    either became Rust, and the two exports read as reachable the whole time.

    A prototype in a **header** does count, and deliberately: `fs/fake.h` is the
    interface an embedder compiles against, and ServerBox calls things this tree
    never does.
    """
    out = run(
        "rg", "--files",
        "--glob", "*.c", "--glob", "*.h",
        "--glob", "!kernel/offload_tests/**",
        ".",
    )
    names: set[str] = set()
    word = re.compile(r"\b[a-z_][a-z0-9_]*\b")
    for path in out.split():
        try:
            text = (ROOT / path).read_text(errors="replace")
        except OSError:
            continue
        text = strip_comments(text)
        here = word.findall(text)
        if path.endswith(".c"):
            counts: dict[str, int] = {}
            for name in here:
                counts[name] = counts.get(name, 0) + 1
            for name in PROTOTYPE.findall(text):
                # The prototype mentions the name once. If that is the only
                # mention in the file, nothing here calls it.
                if counts.get(name, 0) == 1:
                    counts.pop(name, None)
            names.update(counts)
        else:
            names.update(here)
    return names


# A C source directory whose definitions are checked. `main.c` and
# `platform/` are an application rather than the library, and `tools/` is host
# programs.
C_DIRS = ["emu", "kernel", "fs", "util", "asbestos"]


def c_definitions() -> dict[str, str]:
    """Every non-static C function definition, mapped to where it is.

    A definition is a line that begins in column zero, has a name followed by
    `(`, and ends the parameter list with `) {`. That is the shape this tree
    writes them in; a K&R declaration or a definition indented inside `#if`
    is missed, which makes the check quiet rather than wrong.
    """
    out = run(
        "rg", "--with-filename", "--line-number", "--no-heading",
        r"^(?!static\b)[A-Za-z_][\w \*]*\b(\w+)\([^;]*\)\s*\{",
        "--pcre2", "--glob", "*.c",
        "--glob", "!kernel/offload_tests/**",
        *C_DIRS,
    )
    found: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        path, lineno, text = parts
        m = re.search(r"(\w+)\s*\([^;]*\)\s*\{", text)
        if m and m.group(1) not in ("if", "for", "while", "switch", "return", "sizeof"):
            found.setdefault(m.group(1), f"{path}:{lineno}")
    return found


def c_declared() -> set[str]:
    """Names a header declares. A declared function is an interface."""
    out = run(
        "rg", "-o", "--no-filename", r"\b(\w+)\s*\([^;]*\)\s*;", "-r", "$1",
        "--glob", "*.h", "--glob", "!kernel/offload_tests/**", ".",
    )
    return set(out.split())


def assembly_identifiers() -> set[str]:
    """Anything the gadgets name, including through the NAME() macro."""
    out = run(
        "rg", "-o", "--no-filename", r"\b[a-z_][a-z0-9_]*\b",
        "--glob", "*.S", ".",
    )
    return set(out.split())


def rust_table_entries() -> set[str]:
    """Names inside `Some(...)`, which is how a Rust-built ops table holds one."""
    out = run(
        "rg", "-o", "--no-filename", r"Some\((\w+)\)", "-r", "$1",
        "--glob", "*.rs", "crates",
    )
    return set(out.split())


def rust_extern_declared() -> set[str]:
    """Names another crate declares in an `unsafe extern "C" {}` block.

    A Rust-to-Rust C ABI: one crate exports the symbol and another writes the
    declaration by hand and calls it. That *is* an interface with somebody on
    the other side, so it is reachable — `tools/extern-signatures.py` is what
    checks the two agree about the arguments, and it has found a real defect in
    exactly that shape.

    It is not the answer this tree wants, though. The right one is a Rust
    dependency and a path call, which is what `crates/fs/fake` does with
    `bindmount::bindmount_register` — and then the `#[unsafe(no_mangle)]` can go
    too, because nothing names the symbol.

    Why this rule had to be added: fifteen headers that no C included were
    deleted on 2026-09-04, and **79 exports became unreachable that instant**
    with nothing about the code changed. Sixty-four of them really were dead —
    the header declaration was the only thing naming them — and the rest are
    this: a hand-written declaration in another crate, which the header had
    been standing in for.
    """
    out = run(
        "rg", "-U", "--no-filename", "-o",
        r'unsafe extern "C" \{[^}]*\}',
        "--glob", "*.rs", "crates",
    )
    return set(re.findall(r"\bfn\s+(\w+)", out))


#: Exports that only a C header declares and that stay anyway, each with the
#: reason. An entry that stops applying fails the run, like every other
#: allowlist here -- it would otherwise cover whatever lands on that name next.
HEADER_ONLY_ALLOWED: dict[str, str] = {
    # Four setters an *embedder* calls. Nothing in this tree installs one --
    # that is the point of a hook -- so the only mention is the declaration
    # ServerBox compiles against.
    "iul_set_fork_guard":
        "an embedder refuses a fork its own runtime cannot survive",
    "iul_set_timer_tick_hook":
        "an embedder drives its own periodic work off the guest's tick",
    "native_offload_set_abort_handler":
        "an embedder decides what a failed native offload does",
    "fakefs_set_rootfs_data_path":
        "an embedder points the fakefs at a directory it chose at runtime",
    "iul_set_socket_prefix":
        "an embedder puts the host sockets behind guest unix sockets in its own directory",
}


def c_source_identifiers() -> set[str]:
    """Every identifier in a `.c` file, which is three files now."""
    return set(run(
        "rg", "-o", "--no-filename", r"\b[a-z_][a-z0-9_]*\b",
        "--glob", "*.c", "--glob", "!crates/**", "--glob", "!tests/guest/**",
        "--glob", "!kernel/offload_tests/**", ".",
    ).split())


def declared_in_headers() -> set[str]:
    """Every identifier in a `.h` file."""
    return set(run(
        "rg", "-o", "--no-filename", r"\b[a-z_][a-z0-9_]*\b",
        "--glob", "*.h", "--glob", "!crates/**", "--glob", "!tests/guest/**",
        "--glob", "!kernel/offload_tests/**", ".",
    ).split())


def embedder_headers() -> set[str]:
    """Every header reachable from the in-repo embedder example.

    `tests/integration/sbm_api_test.c` is the nearest thing here to ServerBox's
    own C, and what it includes — transitively — is what an out-of-tree
    consumer compiles against. 42 of the tree's 59 headers, because
    `kernel/calls.h` pulls in most of them.

    **It is a proxy and it is incomplete.** The example does not exercise every
    embedder API: `kernel/native_offload.h` is outside it, and
    `HEADER_ONLY_ALLOWED` above records `native_offload_set_abort_handler` as a
    setter an embedder calls. So the headers named there are added by hand, and
    an entry that stops being needed makes this over-report rather than
    under-report — which is the direction that is safe.
    """
    extra = {"kernel/native_offload.h"}
    seen: set[str] = set()
    stack = list(re.findall(
        r'#\s*include\s+"([^"]+)"',
        (ROOT / "tests/integration/sbm_api_test.c").read_text(errors="replace"),
    )) + list(extra)
    while stack:
        h = stack.pop()
        if h in seen:
            continue
        p = ROOT / h
        if not p.exists():
            continue
        seen.add(h)
        stack += re.findall(r'#\s*include\s+"([^"]+)"', p.read_text(errors="replace"))
    return seen


def outside_the_embedder_surface(defined: dict[str, str]) -> dict[str, str]:
    """Exports that no C can reach and no embedder header declares.

    Reported rather than failed. **An export no C can reach is an optimisation
    barrier** — LTO must emit an externally visible function as written and
    cannot specialise the call — so this number is a standing invitation to
    take `#[no_mangle]` off something. 37 went that way on 2026-09-06.

    It is not a gate because acting on it needs a fact this repository does not
    hold: which of these an out-of-tree consumer links. Removing a symbol
    ServerBox calls breaks its build, and no measurement here can rule that
    out. What the number *is* good for is telling somebody who has ServerBox in
    front of them how much is on the table.
    """
    surface_ids: set[str] = set()
    for h in embedder_headers():
        p = ROOT / h
        if p.exists():
            surface_ids |= set(re.findall(r"\b[a-z_][a-z0-9_]*\b",
                                          p.read_text(errors="replace")))
    # `c_source_identifiers`, **not** `c_identifiers`: the latter reads `.h`
    # as well, which makes this whole filter vacuous — every export is
    # declared in a header, so "no C names it" would always be false. The
    # first version did exactly that and reported 0 with a `#[no_mangle]`
    # deliberately put back, which is the check that caught it.
    reachable = c_source_identifiers() | assembly_identifiers()
    ffi_used = set(run(
        "rg", "-o", "--no-filename", r"ffi::(\w+)", "-r", "$1",
        "--glob", "*.rs", "crates",
    ).split())
    return {
        n: w for n, w in defined.items()
        if n not in reachable and n not in ffi_used and n not in surface_ids
    }


def main() -> int:
    defined = exports()
    rust_names = set(run(
        "rg", "-o", "--no-filename", r"\b[a-z_][a-z0-9_]*\b",
        "--glob", "*.rs", "crates", "tests",
    ).split())
    c_named = c_identifiers()
    asm = assembly_identifiers()
    reachable = c_named | rust_table_entries() | asm | rust_extern_declared()

    dead = {n: where for n, where in defined.items() if n not in reachable}
    unjustified = {n: w for n, w in dead.items() if n not in ALLOWED}
    stale = [n for n in ALLOWED if n not in dead]

    # The C half. A definition that is neither static, nor declared in a
    # header, nor named by any C, Rust or assembly other than itself.
    c_defs = c_definitions()
    declared = c_declared()
    c_dead: dict[str, str] = {}
    for name, where in c_defs.items():
        if name in declared or name in asm or name in rust_names:
            continue
        # Named by C somewhere other than its own definition: `rg -o` counts
        # the definition itself, so one occurrence is not a caller.
        uses = run(
            "rg", "-c", "--no-filename", rf"\b{re.escape(name)}\b",
            "--glob", "*.c", "--glob", "*.h",
            "--glob", "!kernel/offload_tests/**", ".",
        )
        total = sum(int(n) for n in uses.split() if n.isdigit())
        if total <= 1:
            c_dead[name] = where

    # An export whose *only* mention outside its own definition is a C header
    # declaration. That header is read by bindgen and by nothing else now --
    # the C is three files -- so the declaration keeps the export alive in this
    # check while nothing calls it.
    #
    # This found 30 of them on 2026-09-06, twenty-six being syscalls AArch64
    # Linux does not have: `sys_open`, `sys_fork`, `sys_pipe`, `sys_waitpid`
    # and the rest of the pre-`*at` forms, carried across from the i386 backend
    # by a line-by-line translation and unreachable since. `dead-exports` had
    # never reported one, because `kernel/calls.h` declares them all.
    c_sources = c_source_identifiers()
    in_headers = declared_in_headers()
    tables = rust_table_entries()
    header_only: dict[str, str] = {}
    for name, where in defined.items():
        if name in tables or name in asm or name in c_sources:
            continue
        if name not in in_headers:
            continue
        # **Not `build.rs`.** A name inside a bindgen `allowlist_function`
        # string is not a use: it asks for a *declaration*, and a declaration
        # nothing calls is exactly what this check is looking for. Counting it
        # made every allowlisted export look reachable, and `grouprusage_children`
        # -- dead since its two readers became a `times_of` Rust call -- hid
        # behind `crates/kernel/taskcalls/build.rs` until 2026-09-08, when 482
        # allowlist patterns that bought nothing were removed and it appeared.
        uses = run(
            "rg", "-c", "--no-filename", rf"\b{re.escape(name)}\b",
            "--glob", "*.rs", "--glob", "!build.rs", "crates", "tests",
        )
        if sum(int(n) for n in uses.split() if n.isdigit()) <= 1:
            header_only[name] = where
    header_unjustified = {n: w for n, w in header_only.items()
                          if n not in HEADER_ONLY_ALLOWED}
    header_stale = [n for n in HEADER_ONLY_ALLOWED if n not in header_only]

    outside = outside_the_embedder_surface(defined)
    statics = exported_statics()
    statics_outside = outside_the_embedder_surface(statics)

    print(f"{len(defined)} C-ABI exports in crates/")
    print(
        f"{len(outside)} of them outside the embedder surface: no C source or "
        f"assembly names them,"
    )
    print(
        "    no `ffi::` reaches them, and no header the embedder example "
        "compiles against declares them"
    )
    print(f"{len(dead)} that no C names and no Rust table holds")
    print(f"{len(header_only)} that only a C header declares, with no caller at all")
    # **Asserted, because a filter can make a count vacuous.** Breaking the
    # pattern deliberately makes this fire; without it a regex that stopped
    # matching would print `0 statics ... 0 outside`, which reads as a clean
    # result and is the shape CLAUDE.md calls a gate covering nothing.
    assert statics, "no `#[no_mangle]` statics found: the pattern stopped matching"
    print(f"{len(statics)} `#[no_mangle]` statics, which are exports too")
    print(
        f"{len(statics_outside)} of those are outside the embedder surface, by "
        f"the same test"
    )
    print(f"{len(c_defs)} non-static C definitions in {'/, '.join(C_DIRS)}/")
    print(f"{len(c_dead)} that nothing names, declares or assembles against")

    c_unjustified = {n: w for n, w in c_dead.items() if n not in C_ALLOWED}
    c_stale = [n for n in C_ALLOWED if n not in c_dead]
    print(f"{len(C_ALLOWED)} of those are in C_ALLOWED with a reason")

    if c_stale:
        print()
        print("C_ALLOWED entries that are no longer dead:")
        for n in sorted(c_stale):
            print(f"  {n} — delete this entry, or the reason it records is untested")
        return 1

    if c_unjustified:
        print()
        print("Unreachable C:")
        for name, where in sorted(c_unjustified.items()):
            print(f"  {name}\n      {where}")
        print()
        print("A non-static function nothing names is a definition with no")
        print("interface. Delete it, or declare it if it is meant to be one.")
        return 1

    if stale:
        # The same rule probe_diff.sh has: an allowlist entry that stops
        # applying is covering whatever lands on that name next.
        print()
        print("ALLOWED entries that are no longer dead:")
        for n in stale:
            print(f"  {n} — delete this entry, or the reason it records is untested")
        return 1

    if header_stale:
        print()
        print("HEADER_ONLY_ALLOWED entries that are no longer header-only:")
        for n in sorted(header_stale):
            print(f"  {n} — delete this entry, or the reason it records is untested")
        return 1
    if header_unjustified:
        print()
        print("Only a C header declares these, and nothing calls them:")
        for n, where in sorted(header_unjustified.items()):
            print(f"  {n}\n      {where}")
        print()
        print("The declaration is what keeps each reachable, and the headers are")
        print("read by bindgen now -- the C is three files. Delete the function")
        print("and its declaration, or add it to HEADER_ONLY_ALLOWED with the")
        print("reason it is an interface rather than a leftover.")
        return 1

    if not unjustified:
        print()
        print("Every export is reachable, or is in ALLOWED with a reason.")
        return 0

    print()
    print("Unreachable:")
    for name, where in sorted(unjustified.items()):
        print(f"  {name}\n      {where}")
    print()
    print("Each of these is a second interface with nobody on the other side.")
    print("Delete it, or -- if it is reached some way this does not model --")
    print("add it to ALLOWED with the reason.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
