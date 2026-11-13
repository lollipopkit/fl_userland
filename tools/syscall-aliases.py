#!/usr/bin/env python3
"""One implementation registered at two syscall numbers, without a reason.

The dispatcher hands every implementation **six registers**, whatever the
syscall's arity is — it cannot do otherwise, because the arity is not something
the table records. So an implementation registered at a second number reads
exactly as many arguments as it declares, and if Linux gives that number fewer,
the extra ones are whatever the guest happened to leave in `x3`, `x4`, `x5`.

Two of the three aliases in this table were wrong on 2026-09-03:

- `sys_faccessat` at 48 as well as 439. `faccessat(2)` is three arguments and
  `faccessat2(2)` is four, so `flags` was a leftover register — and a bit
  outside `AT_EACCESS|AT_SYMLINK_NOFOLLOW` is `EINVAL`, so a plain `access()`
  could fail for no reason a caller could see. Reproduced against a real kernel,
  which ignores the register.
- `sys_execve` at 221 as well as 281. `execveat(2)` is `execve`'s arguments
  shifted by one behind a directory descriptor, so the path was read from the
  address in `dirfd` — `AT_FDCWD` is `-100` — and every `execveat` in every
  revision answered `EFAULT`.

The third, `sys_fsync` at 82 and 83, is right: `fdatasync` is a weaker `fsync`
and both take one argument. That is the difference an entry in `ALLOWED` has to
state.

This cannot check the arities themselves: Linux's arity for a number is not
anything in this tree. What it can do is make the *choice* explicit, which is
enough — two of three were a mistake nobody had been asked to justify.

Run by hand, or as `tools/checks.sh syscall_aliases`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TABLE = ROOT / "crates/kernel/syscalltable/src/table.rs"

# An implementation deliberately registered at more than one number, **with the
# reason**. The same rule as every other allowlist here: an entry that stops
# applying fails the run, because it would otherwise cover whatever lands on
# that name next.
ALLOWED = {
    "sys_fsync": (
        "82 fsync and 83 fdatasync. Both take one descriptor and nothing else, "
        "and fdatasync is fsync without the metadata guarantee -- so answering "
        "it with the stronger call is correct, just slower than it has to be"
    ),
}

# The stubs are not implementations: several numbers share each by design.
STUBS = {"syscall_stub", "syscall_success_stub", "syscall_silent_stub", "not_configured"}


def arity(name: str) -> int | None:
    """How many arguments the Rust **definition** declares.

    It read `kernel/calls.h`'s prototype until 2026-09-08, when that header was
    deleted -- and reading the definition is better anyway: a declaration is a
    second rendering that can disagree with the thing it describes, which is
    what removing the 165 prototypes in that header was about.

    `extern "C"` is optional because a `sys_*` that answers `Result<T, Errno>`
    is a plain `fn`: the table wraps it in a shim of the right arity rather than
    transmuting it, so the calling convention is the shim's business.
    """
    import subprocess
    out = subprocess.run(
        ["rg", "--no-filename", "--multiline", "-o",
         r'(?:extern "C" )?fn %s\s*\(([^)]*)\)' % re.escape(name),
         "--glob", "*.rs", str(ROOT / "crates")],
        capture_output=True, text=True,
    ).stdout
    if not out.strip():
        return None
    body = out.split("(", 1)[1].rsplit(")", 1)[0]
    return len([a for a in body.split(",") if a.strip()])


def main() -> int:
    table = TABLE.read_text()
    where: dict[str, list[int]] = {}
    # `at!(t, 17, sys_getcwd);`, `at_res!(t, 57, sys_close, 1);` and
    # `at_val!(t, 172, sys_getpid, 0);` -- the second being an implementation
    # that answers `Result<T, Errno>` and the third one that cannot fail, with
    # the trailing number the arity in both. A range --
    # `at!(t, 5..=16, sys_xattr_stub)` -- is deliberately not matched: a range
    # is one implementation answering a block of numbers on purpose, which is
    # the thing this asks about only when somebody wrote the same name twice.
    for num, fn in re.findall(r"at(?:_res|_val)?!\(t,\s*(\d+),\s*(\w+)\s*[,)]", table):
        if fn in STUBS:
            continue
        where.setdefault(fn, []).append(int(num))

    # **Every line that registers a number must have been read.**
    #
    # This used to match `at!` alone and said nothing about the rest. Six
    # syscalls moving to `at_res!` on 2026-09-11 dropped the count from 229 to
    # 223 with no other change to the output, and this file is *reported* rather
    # than failed -- so a number going down is the only signal there is, and
    # nobody reads a number they are not told to compare. An alias introduced
    # among the six would have been invisible.
    #
    # **And the fix for that missed `at_val!`, in the same commit, for the same
    # length of time.** Seventeen entries -- `getpid`, `brk`, `umask`,
    # `sched_yield`, `exit`, `exit_group` and the rest of the calls that cannot
    # fail -- were neither read nor counted, *and the guard below could not say
    # so*, because it only inspects lines that start with one of the two
    # spellings it already knew. A filter that decides what to check from the
    # same list it checks against reports nothing about what it does not know:
    # this is `CLAUDE.md`'s "a gate whose filter is a proxy" twice in one file.
    # Fixed 2026-09-12; the entry count went 275 -> 292 and the implementation
    # count 212 -> 229, which is the number that says the seventeen are now in.
    #
    # The lesson for the next spelling: add it to `PREFIXES` **and** to the
    # regex, and check that both counts move.
    PREFIXES = ("at!(t,", "at_res!(t,", "at_val!(t,")
    entry = re.compile(r"at(?:_res|_val)?!\(t,\s*[\d]+(?:\.\.=\d+)?,\s*(\w+)\s*[,)]")
    unread = [
        line.strip()
        for line in table.splitlines()
        if line.strip().startswith(PREFIXES) and not entry.match(line.strip())
    ]
    entries = sum(1 for line in table.splitlines() if line.strip().startswith(PREFIXES))
    if unread:
        print(
            f"\n{len(unread)} of {entries} entries are in a form this file "
            "cannot parse:",
            file=sys.stderr,
        )
        for line in unread:
            print(f"  {line}", file=sys.stderr)
        return 1

    aliased = {fn: sorted(n) for fn, n in where.items() if len(n) > 1}
    print(f"{entries} entries in the syscall table, all of them read")
    print(f"{len(where)} implementations in it, stubs excluded")
    print(f"{len(aliased)} of them registered at more than one number")

    stale = [fn for fn in ALLOWED if fn not in aliased]
    if stale:
        print("\nALLOWED entries that suppress nothing:", file=sys.stderr)
        for fn in stale:
            print(f"  {fn}: {ALLOWED[fn]}", file=sys.stderr)
        print(
            "\nAn entry records a choice somebody read and justified. Once the "
            "alias is gone the entry covers whatever lands on that name next.",
            file=sys.stderr,
        )
        return 1

    bad = [fn for fn in aliased if fn not in ALLOWED]
    if bad:
        print("\nRegistered at more than one number with no reason:", file=sys.stderr)
        for fn in sorted(bad):
            n = arity(fn)
            takes = f"{n} arguments" if n is not None else "an unknown number of arguments"
            print(f"  {fn} at {aliased[fn]}, and takes {takes}", file=sys.stderr)
        print(
            "\nThe dispatcher passes six registers whatever the syscall's arity "
            "is, so an implementation at a number Linux gives fewer arguments "
            "reads whatever the guest left behind. Give each number its own "
            "entry point, or add the name to ALLOWED with the reason the two "
            "really are the same call.",
            file=sys.stderr,
        )
        return 1

    print("\nEvery alias is in ALLOWED with a reason.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
