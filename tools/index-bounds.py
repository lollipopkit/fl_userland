#!/usr/bin/env python3
"""Report array indexing by a syscall parameter whose bound check is not tight.

An index that comes from the guest is guest-controlled, and every fixed-size
array indexed by one needs a check that is exactly right. Two were not, and
both crashed the emulator from an unprivileged guest calling one syscall:

* `sys_timer_settime` bounded its id with `> TIMERS_MAX` where the array has
  `TIMERS_MAX` elements and its three sibling syscalls all said `>=`. Id 16
  indexed one element past `posix_timers[16]` and called `timer_set` on a
  pointer read out of the bytes after it. Signal 11 in `timer_set`.
* `do_sigaction` took the signal number as `int` -- it arrives as a `dword_t` --
  and checked only `sig > MAX_SIG`. `rt_sigaction(0x80000000, ...)` converted
  to a large negative number, compared *below* the bound, and indexed
  `sighand->action` at a wild negative offset, for a read and a write. Signal 11
  in `sys_rt_sigaction`.

They are the same mistake twice: a guard that is approximately right. `999` is
refused by any check; `65` and `16` are refused only by an exact one, and a
test that probes far outside a bound proves the bound is approximately
somewhere.

So this checks the guards mechanically. For every `array[param]` where `param`
is a parameter of the enclosing function, it asks two questions:

  1. Is the guard `param > N` where the array has `N` elements? That is one
     too many. It wants `>=`.
  2. Can `param` be negative -- is it a signed type -- and is there no lower
     bound? Then the upper bound does not bound it at all.
  3. Is there no comparison of `param` to anything at all? Then whatever bounds
     it is somewhere else, and this asks where.

The third was added after a third crash of the same shape, and it is the one
the first two would not have caught: `dev_open` indexed `char_devs[256]` with a
major taken straight out of a `dev_t`, which holds twelve bits of it. There was
no guard to be loose -- reading past the array gave a `struct dev_ops *` that
was not null, so the null check passed, and the function pointer at its first
field was called. See
docs/changelog/2026-08-23-a-device-node-was-an-indirect-call-to-anywhere.md.

**It is a heuristic, and it is one-sided.** It reads text rather than following
control flow, so a bound checked in a caller, or through a helper, or by an
early `return`, looks like no bound at all. A clean run is not a proof and a
report is a question. `CHECKED` below is for the ones that have been read, each
with its reason, because an allowlist without one is a way to stop looking.

Usage:  tools/index-bounds.py [--quiet]
Exit:   0 if every report is accounted for, 1 otherwise.
"""

import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Sources to read. The offload tests are generated and index nothing from a
# guest; asbestos and emu are the interpreter, whose indices come from decoded
# instructions rather than from syscall arguments.
DIRS = ["kernel", "fs", "util"]
SKIP = ("offload_tests/",)

# Directories with no source of ours in them. Pruned during the walk rather
# than filtered after it: `target/` alone holds hundreds of thousands of files,
# and a `**` glob visits every one before anything gets to reject it.
PRUNE = {"build", "target", ".git", ".claude", "node_modules"}


def source_files(root, suffix):
    """Every `*<suffix>` under `root`, skipping PRUNE, sorted by full path.

    Sorted because the callers used to be `sorted(root.glob(...))` and these
    analyses follow source order -- the order files arrive in is part of what
    they report.
    """
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in PRUNE and not d.startswith(".")]
        for name in filenames:
            if name.endswith(suffix):
                found.append(pathlib.Path(dirpath) / name)
    return sorted(found)

# Types a guest value arrives in that can hold a negative number. `fd_t` and
# `pid_t_` are `int`; `int_t` is `int32_t`.
SIGNED = {"int", "int_t", "long", "fd_t", "pid_t_", "sfd_t", "off_t_", "ssize_t"}

# Indexing sites that have been read and are not defects. The reason is the
# point of the entry.
#
# Keyed by **function**, not just by file and array. It used to be
# `(file, array)`, and that is how `fs/dyndev.c`'s `dyn_open` got away with
# indexing `devs[minor]` with nothing checking `minor` at all: the entry's
# reason is about `dyn_dev_register`, which does check it, and the coarser key
# silenced every other site in the file. `mknod /dev/x c 240 1048575` then read
# eight megabytes past a 256-pointer array and called the function pointer it
# found.
#
# An allowlist entry whose reason names one place must not speak for another.
CHECKED = {
}

# Rule 3's allowlist, kept apart because it answers a different question: not
# "is the guard tight" but "where is the guard". Each entry names the place.
UNCHECKED_OK = {
}


# Path joins that discard whether they fit. The reason is the point of the
# entry, as with every other allowlist here.
#
# A truncated path is not a shorter answer, it is a *different* one -- and one
# that usually exists, because the prefix of a path names a directory. Four
# defects of this shape were found in one pass on 2026-08-28, and two of them
# were the kind that destroys data: a bind-mount stash name that truncated back
# to the mount point, so `renameat(fd, x, fd, x)` reported that the guest's
# tree had been moved aside; and a fakefs created at a long path, where
# `mkdir` at a truncated name creates something nothing will look for again.
#
# The check is narrow deliberately: the destination has to be a buffer declared
# `char x[PATH_MAX]` or `[MAX_PATH]`, and the call's result has to be discarded.
# It catches half of that pass's findings -- the other two wrote through a
# `char *` parameter and a struct field -- and half of a class this expensive is
# worth gating.
# Keyed by the enclosing function as well as the buffer: `fs/fake.c` was 1600
# lines when this was written and more than one of them could declare
# `char path[PATH_MAX]`, so an entry keyed by the name alone would speak for a
# site its reason never read. CHECKED above had that defect and let an
# arbitrary indirect call through.
#
# Empty since 2026-09-04: the last entry named `fs/fake.c`, which is gone, and
# an entry naming a file that no longer exists is a stale entry waiting to
# cover whatever lands on that name next.
TRUNCATION_OK = {}


def truncating_joins(root):
    """Path joins whose result is discarded, into a PATH_MAX-sized buffer."""
    call = re.compile(r"(?<![\w.>])(snprintf|strlcpy|strlcat)\s*\(\s*(\w+)\s*,")
    # The enclosing function, so an allowlist entry names one site rather than
    # every buffer in the file that happens to share a name.
    # A definition starts at column 0 -- which is what excludes the indented
    # `if (` and `snprintf(` inside a body -- and has no `;` or `=`, which
    # excludes declarations and initialisers. The `(` may close on a later line.
    fndef = re.compile(r"^(?:static\s+|inline\s+)*[A-Za-z_]\w*[\w \t*]*?\b(\w+)\s*\([^;=]*$|"
                       r"^(?:static\s+|inline\s+)*[A-Za-z_]\w*[\w \t*]*?\b(\w+)\s*\([^;{)=]*\)\s*\{")
    decl = re.compile(r"char\s+(\w+)\s*\[\s*(PATH_MAX|MAX_PATH)\s*\]")
    used = re.compile(r"(=|if\s*\(|return|>=|<|\bassert)")
    found = []
    for path in sorted(source_files(root, ".c")) + sorted(source_files(root, ".h")):
        rel = str(path.relative_to(root))
        if rel.startswith(("build", "tests/")) or "/target/" in rel or "/.claude/" in rel:
            continue
        text = path.read_text(errors="ignore")
        sizes = dict(decl.findall(text))
        if not sizes:
            continue
        enclosing = "?"
        for i, line in enumerate(text.split("\n"), 1):
            d = fndef.match(line)
            if d is not None:
                enclosing = d.group(1) or d.group(2)
            m = call.search(line)
            if m is None:
                continue
            fn, dst = m.group(1), m.group(2)
            if dst not in sizes:
                continue
            if used.search(line.split(fn)[0]):
                continue
            found.append((rel, i, fn, dst, sizes[dst], enclosing))
    return found


def arrays_with_sizes(text):
    """Map an array's name to the expression that gives its element count.

    `NAME` and `NAME + 1` both count. The second is not a nicety: `fs/dyndev.c`
    declares `struct dev_ops *devs[MAX_MINOR+1]`, and without it this tool did
    not know the array's size, so rule 3 skipped it -- and `dyn_open` indexed it
    with a guest-supplied minor that nothing compared to anything. `mknod
    /dev/x c 240 1048575` then read eight megabytes past the array and called
    the function pointer it found there.

    The sibling bug, in `dev_open` one file over, was found by hand and is what
    this tool was written for. The two differ only in how the array's size
    happened to be spelled.
    """
    out = {}
    for m in re.finditer(
        r"\b\w+\s+\**(\w+)\s*\[\s*([A-Z_][A-Z0-9_]*(?:\s*\+\s*\d+)?)\s*\]", text
    ):
        out[m.group(1)] = re.sub(r"\s+", "", m.group(2))
    return out


def functions(text):
    """Yield (name, params, body) for each function definition."""
    for m in re.finditer(
        r"^(?:static\s+)?[\w \t*]+?\b(\w+)\s*\(([^;{)]*)\)\s*\{", text, re.M
    ):
        start = m.end() - 1
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    yield m.group(1), m.group(2), text[start : i + 1]
                    break


def index_sites(body, sizes):
    """Yield (array, index) for each `arr[idx]` in `body`.

    Two forms, because the second is how the bug that motivated rule 3 was
    written and a regex for a bare identifier does not see it:

        char_devs[major]
        (type == DEV_BLOCK ? block_devs : char_devs)[major]

    For the parenthesised form every known array named inside the parentheses
    is a candidate -- a conditional picks one of them at runtime and the index
    has to be right for both.
    """
    for m in re.finditer(r"\b(\w+)\s*\[\s*(\w+)\s*\]", body):
        yield m.group(1), m.group(2)
    for m in re.finditer(r"\)\s*\[\s*(\w+)\s*\]", body):
        idx = m.group(1)
        # Walk back to the matching open paren.
        depth = 0
        start = None
        for i in range(m.start(), -1, -1):
            if body[i] == ")":
                depth += 1
            elif body[i] == "(":
                depth -= 1
                if depth == 0:
                    start = i
                    break
        if start is None:
            continue
        for name in set(re.findall(r"\b\w+\b", body[start : m.start()])):
            if name in sizes:
                yield name, idx


def params_of(decl):
    """Map a parameter name to its declared type text."""
    out = {}
    for part in decl.split(","):
        part = part.strip()
        if not part or part == "void":
            continue
        m = re.match(r"^(.*?)\b(\w+)\s*$", part)
        if m:
            out[m.group(2)] = m.group(1).strip()
    return out


def header_sizes():
    """Every array size declared in a header, read once.

    It used to be read inside the per-source-file loop -- so the whole
    repository was walked, and every header re-read and re-parsed, once for
    each of the seventy C files. That is what made this analysis take 25
    seconds against a 30-second meson timeout, and it timed out for real the
    first time the machine had anything else running.

    The answer does not depend on which C file is being examined, which is why
    it can be hoisted at all.
    """
    sizes = {}
    for hdr in sorted(source_files(ROOT, ".h")):
        try:
            sizes.update(arrays_with_sizes(hdr.read_text(errors="replace")))
        except OSError:
            pass
    return sizes


def stale_allowlist(entries, label):
    """Allowlist keys naming a file that is not there any more.

    An entry records a site somebody read and justified. Once that site is gone
    the entry stops suppressing anything and starts *waiting* -- it will cover
    whatever lands on the same name next, silently. `probe_diff.sh` fails a run
    for the same reason; this is the same rule for a tool's own list.

    Three were found stale on 2026-08-31, all naming C files that had become
    Rust crates.

    Every key names a file, so every key is checked. Until 2026-09-04 only a
    name with a slash in it was, and `xX_main_Xx.h` -- a file at the root of
    the tree, deleted on 2026-09-03 when the CLI became Rust -- sat in
    TRUNCATION_OK for a day with the run passing.
    """
    stale = []
    for key in entries:
        path = key[0] if isinstance(key, tuple) else key
        if not (ROOT / str(path)).exists():
            stale.append(f"{label}: {key} names {path}, which does not exist")
    return stale


def report(quiet):
    findings = []
    scanned = 0
    from_headers = header_sizes()
    for d in DIRS:
        for path in sorted(source_files(ROOT / d, ".c")):
            rel = str(path.relative_to(ROOT))
            if any(s in rel for s in SKIP):
                continue
            scanned += 1
            text = path.read_text(errors="replace")
            # Array sizes come from the headers as well as the file itself.
            sizes = dict(from_headers)
            sizes.update(arrays_with_sizes(text))

            for fname, decl, body in functions(text):
                params = params_of(decl)
                if not params:
                    continue
                for arr, idx in index_sites(body, sizes):
                    if idx not in params or (rel, arr, fname) in CHECKED:
                        continue
                    size = sizes.get(arr)
                    ptype = params[idx]

                    # 1. `idx > SIZE` where the array has SIZE elements.
                    if size and re.search(
                        rf"\b{re.escape(idx)}\s*>\s*{re.escape(size)}\b(?!\s*[-+])", body
                    ) and not re.search(
                        rf"\b{re.escape(idx)}\s*>=\s*{re.escape(size)}\b", body
                    ):
                        findings.append(
                            f"{rel}: {fname}() bounds `{idx}` with `> {size}`, but "
                            f"`{arr}` has {size} elements -- `>=` is the tight check"
                        )

                    # 3. No comparison of the index to anything at all.
                    compared = re.search(
                        rf"\b{re.escape(idx)}\s*(?:[<>]=?|==|!=)", body)
                    if size and not compared and (rel, arr, fname) not in UNCHECKED_OK:
                        findings.append(
                            f"{rel}: {fname}() indexes `{arr}`, which has {size} "
                            f"elements, with the parameter `{idx}` and never compares "
                            f"it to anything -- whatever bounds it is elsewhere"
                        )

                    # 2. A signed index with no lower bound.
                    signed = any(t == ptype or ptype.endswith(t) for t in SIGNED)
                    has_upper = re.search(rf"\b{re.escape(idx)}\s*>=?\s*\w+", body)
                    has_lower = re.search(
                        rf"\b{re.escape(idx)}\s*<=?\s*-?\d|\b{re.escape(idx)}\s*<\s*0", body
                    )
                    if signed and has_upper and not has_lower:
                        findings.append(
                            f"{rel}: {fname}() indexes `{arr}` with `{idx}`, declared "
                            f"`{ptype}`, and bounds it above but not below -- a negative "
                            f"value passes the upper bound"
                        )

    for f in sorted(set(findings)):
        print(f"index-bounds: {f}")

    stray = list(stale_allowlist(CHECKED, "CHECKED")) \
        + list(stale_allowlist(UNCHECKED_OK, "UNCHECKED_OK")) \
        + list(stale_allowlist(TRUNCATION_OK, "TRUNCATION_OK"))
    for f in stray:
        print(f"stale: {f}")
    for rel, line, fn, dst, size, where in truncating_joins(ROOT):
        why = TRUNCATION_OK.get((rel, where, dst))
        if why is not None:
            if not quiet:
                print(f"known    {rel}:{line} {where}() {fn} -> {dst}[{size}]\n         {why}\n")
            continue
        stray.append(f"{rel}:{line}: {where}() {fn} into `{dst}`[{size}] and nothing looks at "
                     f"whether it fit -- a truncated path names a different file")
    for f in stray:
        print(f"truncation: {f}")

    if not findings and not stray and not quiet:
        # The count is not decoration. This reads C, and by 2026-09-03 the C
        # was eleven files with no syscall body among them -- so a clean run
        # says "the C that is left has none of this", which is a much smaller
        # claim than it reads as. `tools/lock-order.py` and
        # `tools/init-destroy.py` had emptied out the same way and printed
        # nothing to say so.
        #
        # It is not blind the way those two were: what this finds is an array
        # indexed out of bounds, and Rust checks that itself. What Rust turns
        # it into is a panic, which inside an `extern "C"` function is an
        # abort -- a smaller defect than a corrupted array, and a different
        # tool's job.
        print(f"index-bounds: {scanned} C files scanned; no guest-indexed array "
              "has a loose bound, and no path join discards whether it fit")
    return 1 if findings or stray else 0


if __name__ == "__main__":
    sys.exit(report("--quiet" in sys.argv))
