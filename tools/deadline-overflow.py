#!/usr/bin/env python3
"""Report a time-scale multiplication that can overflow.

A guest names a timeout as a `timespec` or a `timeval`, and this kernel turns it
into one number. `timespec_valid` is Linux's rule and puts **no upper bound on
`tv_sec`** — Linux saturates — so `LLONG_MAX` is a request a real kernel accepts,
and

    sec * 1_000_000_000 + nsec

in an `i64` does not have that number.

## Why it is worth a tool

Because the fix for one is not the fix for the others. `poll_probe` found the
first in `ppoll` on 2026-09-03 and it was fixed where `ppoll` reads its timeout;
the same line was still written out by hand in **five** other places, and
`deadline_probe` found them the same day:

    rt_sigtimedwait   sec * 1_000_000_000 + nsec
    futex(WAIT)       the same
    recvmmsg          now_ns() + sec as u64 * 1_000_000_000 + nsec
    clock_nanosleep   now_sec + req_sec
    SO_RCVTIMEO       tv_sec * 1000, in the socket wait

What the overflow costs depends on the build and both answers are bad. With
overflow checks on — the default build — it is a panic inside an `extern "C"`
function, which cannot unwind, so the **whole emulator aborts**: one syscall,
one argument, from any guest. Without them it wraps, and a wait meant to last
for ever ends at whatever time the wrapped number names.

The `SO_RCVTIMEO` one is the argument for a tool rather than a rule somebody
remembers. Its input arrives from `getsockopt`, which reads as a bounded host
value; it is not, because the guest put it there — and the fatal call is a later
`recv` rather than the one that named the number.

## What it looks for

A multiplication by 1000, 1_000_000 or 1_000_000_000 that is not
`saturating_mul`, `checked_mul` or `wrapping_mul`. That is narrow on purpose:
every member of the family above is one, and a narrow check with a short
allowlist is one people keep.

Three shapes are exempt without an entry, because they are bounded by
construction: a **literal** left operand, a **`% <the same scale>`**
remainder, which is what a millisecond-to-timespec conversion is made of, and
an **`i128::from(..)`** widening -- `From` into `i128` exists only for types of
64 bits or fewer, and 2^64 times a billion is far below 2^127.

It does not model addition, which `clock_nanosleep`'s was. There is no way to
tell `now + guest` from `a + b` by reading, and the answer for that one is that
the arithmetic belongs in `crates/util/timeabi` — where `absolute_deadline`
already saturates — rather than written out at the call site.

Usage:  tools/deadline-overflow.py [--quiet]
Exit:   0 if every unchecked multiplication is exempt or in ALLOWED, 1 otherwise.
"""

import os
import pathlib
import re
import sys

# Bounded for a reason that is not visible in the expression. The reason is the
# point of the entry.
_MONOTONIC = (
    "A CLOCK_MONOTONIC reading, whose seconds field is the machine's uptime. "
    "Overflowing an i64 of nanoseconds would take 292 years of it."
)
ALLOWED = {
    ("crates/kernel/waitcalls/src/wait.rs", "now_ns"): _MONOTONIC,
    ("crates/kernel/epollcalls/src/lib.rs", "now_ns"): _MONOTONIC,
    ("crates/fs/poll/src/lib.rs", "now_ns"): _MONOTONIC,
    ("crates/fs/sock/src/lib.rs", "now_ns"): _MONOTONIC,
    ("crates/kernel/tgroup/src/lib.rs", "now_ns"): _MONOTONIC,
    ("crates/fs/sock/src/wait.rs", "monotonic_ms"): _MONOTONIC,
    ("crates/kernel/syscalldispatch/src/lib.rs", "after_syscall"): _MONOTONIC,
    ("crates/kernel/hostrusage/src/lib.rs", "rusage_get_thread"): (
        "A host rusage, which counts CPU time actually spent. The seconds field "
        "is bounded by how long the process has run."
    ),
    ("crates/kernel/rescalls/src/lib.rs", "add"): (
        "A sum of host rusage seconds -- CPU time actually spent by this "
        "process and its reaped children. Reaching the overflow would take "
        "292,000 years of it."
    ),
    ("crates/kernel/epollcalls/src/lib.rs", "epoll_wait"): (
        "`timeout` is `epoll_pwait`'s `int` milliseconds and the multiply is "
        "guarded by `timeout >= 0`, so the product is at most 2^31 * 10^6, "
        "about 2.1e15 -- three orders of magnitude below where a u64 stops "
        "counting. The bound is the argument's *type*, which is why this is not "
        "one of the family: a `timespec`'s `tv_sec` is 64 bits and has no bound "
        "at all."
    ),
    ("crates/kernel/futexcalls/src/lib.rs", "futex_wait"): (
        "IUL_FUTEX_DBG's seconds, parsed from an environment variable this "
        "kernel's own operator sets, not from a guest."
    ),
}

PRUNE = {"build", "target", ".git", ".claude", "node_modules"}
SCALES = ("1_000_000_000", "1000000000", "1_000_000", "1000000", "1_000", "1000")

# `<something> * <scale>`, capturing what is on the left of the star.
MUL = re.compile(
    r"([\w\.\(\)\[\]]+(?:\s+as\s+\w+)?)\s*\*\s*(" + "|".join(SCALES) + r")\b"
)
SAFE_CALL = re.compile(r"(saturating|checked|wrapping)_mul")
FN = re.compile(
    r"^\s*(?:pub(?:\([\w:]+\))?\s+)?(?:const\s+)?(?:unsafe\s+)?"
    r"(?:extern\s+\"C\"\s+)?fn\s+(\w+)")
CFG_TEST = re.compile(r"#\[cfg\(test\)\]")
COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
LITERAL = re.compile(r"^\d[\d_]*$")


def walk(root):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in PRUNE and not d.startswith(".")]
        for name in filenames:
            if name.endswith(".rs"):
                found.append(pathlib.Path(dirpath) / name)
    return sorted(found)


def blank_comments(text):
    """Comments blanked, keeping offsets: this file's own prose is full of the
    expressions it looks for, and so are the comments beside every fix."""
    return COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


MODULUS = re.compile(r"%\s*(\d[\d_]*)\s*\)?\s*(?:as\s+\w+\s*)?$")


def bounded_by_modulus(before, scale):
    """Whether the left operand is a remainder small enough to multiply.

    `(ms % 1000) * 1_000_000` is a `timespec`'s nanosecond field: the remainder
    is below 1000 whatever `ms` was, so the product is below a billion. The
    check is the arithmetic rather than the spelling, because the modulus and
    the scale are different numbers -- milliseconds in, nanoseconds out.
    """
    m = MODULUS.search(before)
    if not m:
        return False
    return int(m.group(1).replace("_", "")) * scale < 2**62


def widened_to_i128(before, left):
    """Whether the left operand is `i128::from(..)`. The pattern captures
    `from(sec)` -- it stops at `::` -- so the type is what precedes it."""
    return left.startswith("from(") and before.endswith("i128::")


def stale_allowlist(root):
    """An entry naming a file that no longer exists suppresses nothing and is
    waiting to cover whatever lands on the same name. The rule every allowlist
    in this tree has."""
    return [f"ALLOWED: {k} names {k[0]}, which does not exist"
            for k in ALLOWED if not (root / k[0]).exists()]


def main():
    quiet = "--quiet" in sys.argv
    root = pathlib.Path(__file__).resolve().parent.parent

    findings, examined, exempt = [], 0, 0
    for path in walk(root / "crates"):
        rel = str(path.relative_to(root))
        if rel.endswith("tests.rs") or "/tests/" in rel or rel.endswith("build.rs"):
            continue
        text = blank_comments(path.read_text(errors="ignore"))
        lines = text.split("\n")
        fn, depth, test_depth, pending = "?", 0, None, False
        for i, line in enumerate(lines, 1):
            if CFG_TEST.search(line):
                pending = True
            m = FN.match(line)
            if m:
                fn = m.group(1)
            if test_depth is None and pending and "{" in line:
                test_depth, pending = depth, False

            if test_depth is None:
                for m in MUL.finditer(line):
                    left, scale = m.group(1), m.group(2)
                    examined += 1
                    # Bounded by construction: a literal, or a remainder by any
                    # literal small enough that the product fits. That is what a
                    # millisecond-to-`timespec` conversion is made of --
                    # `(ms % 1000) * 1_000_000` is a nanosecond field and cannot
                    # reach a billion however large `ms` was.
                    if LITERAL.match(left) or widened_to_i128(
                        line[:m.start(1)], left
                    ) or bounded_by_modulus(
                        line[:m.end(1)], int(scale.replace("_", ""))
                    ):
                        exempt += 1
                        continue
                    if SAFE_CALL.search(line):
                        exempt += 1
                        continue
                    key = (rel, fn)
                    if key in ALLOWED:
                        if not quiet:
                            print(f"known    {rel}:{i} {fn}(): `{left} * {scale}`\n"
                                  f"         {ALLOWED[key]}\n")
                        exempt += 1
                        continue
                    findings.append((rel, i, fn, left, scale))

            opened = line.count("{") - line.count("}")
            depth += opened
            if opened < 0 and test_depth is not None and depth <= test_depth:
                test_depth = None

    for rel, i, fn, left, scale in findings:
        print(f"OVERFLOW {rel}:{i} {fn}(): `{left} * {scale}` is not saturating")

    stale = stale_allowlist(root)
    for s in stale:
        print(f"stale: {s}")

    if not quiet:
        print(f"{examined} multiplications by a time scale, {exempt} bounded or "
              f"allowed, {len(findings)} unchecked")
    if findings:
        print("A guest chooses `tv_sec` and Linux puts no upper bound on it, so "
              "this can be `LLONG_MAX`. Saturate -- a deadline past the end of "
              "time is one that never arrives, which is what the caller asked "
              "for. If the value cannot come from a guest, say why in ALLOWED.")
    return 1 if findings or stale else 0


if __name__ == "__main__":
    sys.exit(main())
