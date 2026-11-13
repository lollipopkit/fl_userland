#!/usr/bin/env python3
"""Report a flag a caller passes that the function it is passed to never tests.

A call site writing `f(x, FLAG_A | FLAG_B)` is asking for behaviour. If `f` — or
the one function it forwards the argument to — never looks at `FLAG_B`, the
request is silently dropped, and the call site, which usually carries a comment
explaining what the flag is for, reads as though it works.

`N_PARENT_DIR_WRITE` was exactly that. Defined in 2019, passed to
`path_normalize` at nine call sites in `fs/generic.c` — every create, unlink,
rename, rmdir, symlink and link — and never read, in any revision. One of the
call sites said

    /* Include N_PARENT_DIR_WRITE so path_normalize checks write permission

and `fs/fake.h` documented `fakefs_bind_mount(read_only = true)` as working by
letting that check reject the writes. So an unprivileged guest could unlink
anything in any directory it could search, and an embedder-facing read-only
guarantee rested on nothing. See
`docs/changelog/2026-08-29-a-directory-could-be-changed-without-write-permission.md`.

**This is the shape the migration creates.** A flag handled in C, whose handling
the Rust rewrite does not carry across, leaves every caller asking for something
that no longer happens — and nothing in either language warns, because the
constant is still there and still passed.

# What it does, and why not something simpler

It follows the *argument*: which parameter of the callee received the flag
expression, and which bits that parameter is tested against in the callee's
body — plus one level of forwarding, for the very common `int f(int flags) {
return g(..., flags); }`. The callee may be C or Rust; a constant crossing
through bindgen is read as `ffi::FLAG`, and half of this tree's flag consumers
are crates now.

The obvious simpler check — "a flag constant that appears nowhere in a test
position" — was written first and does not work. It reports 73 constants, of
which at most two are interesting, because it cannot tell a dropped request from
a bitmask argument the callee ANDs against a variable it was given: `AC_W` in
`access_check(&stat, AC_W)`, every `IN_*` in `inotify_notify_path`, the `POLL_*`
set that a translation table converts wholesale. Grouping by flag family and
looking for the odd one out brings it to 40, which is no better a gate. The
distinguishing fact is not "nothing tests this bit" but "the code that was
*given* it does not".

**It is a heuristic and it is one-sided.** A callee that stores its flags for
later, or dispatches on the whole word, is invisible to it, so a clean run is
not a proof. `TESTED_ELSEWHERE` is for the ones that have been read, with the
reason.

Usage:  tools/unread-flags.py [--quiet]
Exit:   0 if every passed flag is tested or accounted for, 1 otherwise.
"""

import os
import pathlib
import re
import sys

# A `#define` whose value is a single bit. A mask of several bits is tested
# against a field rather than asked for, and a zero is the absence of the rest.
FLAG_DEFINE = re.compile(
    r"^[ \t]*#define[ \t]+([A-Z][A-Z0-9_]*)[ \t]+"
    r"(0x0*(?:1|2|4|8|10|20|40|80|100|200|400|800|1000|2000|4000|8000|10000|20000|"
    r"40000|80000|100000|200000|400000|800000)|"
    r"\(?1[ \t]*<<[ \t]*\d+\)?|"
    r"(?:1|2|4|8|16|32|64|128|256|512|1024|2048|4096|8192|16384|32768))"
    r"[ \t]*(?:$|//|/\*)",
    re.M,
)

# A call whose last argument is one or more flag constants OR'd together. The
# flags have to be the *whole* argument -- `f(a, FLAG | x)` says nothing about
# whether the callee reads FLAG, because `x` is a variable.
CALL = re.compile(
    r"\b([a-z_]\w{2,})\s*\(([^();]*?)\)",
)

SKIP_DIRS = ("build", "docs", ".git", "target", "offload_tests",
             "asbestos/guest-arm64/gadgets-aarch64")

COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)

# Read, and not a dropped request. Keyed "callee:FLAG"; the reason is the point
# of the entry.
#
# Six of the seven are the same two shapes, and both are things the heuristic
# cannot see rather than things anybody got wrong: a parameter that carries a
# *number* which happens to be a single bit, and a bitmask the callee stores for
# something else to read later.
TESTED_ELSEWHERE = {
    # pt_map_nothing moved to crates/kernel/pagetable on 2026-09-01, and this
    # tool reads only C -- so the call in kernel/memory.c's stack-growth path
    # is a caller whose callee it cannot see. The flag *is* tested there:
    # `flags & (P_READ | P_WRITE | P_EXEC)` decides whether the host mapping is
    # PROT_NONE, and the whole word is then stored in the page table entry.
    #
    # This is the same blindness CLAUDE.md records for lock_order, arriving in
    # a second tool. Teaching them to read Rust is the eventual answer.
    "pt_map_nothing:P_WRITE":
        "The callee is Rust. crates/kernel/pagetable's pt_map_nothing tests "
        "P_READ|P_WRITE|P_EXEC to choose the host protection, and stores the "
        "whole word in the entry.",
    "deliver_signal:SIGILL_":
        "A signal *number*, dispatched through sighand->action[sig]. The "
        "parameter compares against a few particular signals, which is what "
        "makes it look like a bitmask here.",
    "dev_open:DEV_CHAR":
        "A device *type*, compared against DEV_BLOCK rather than masked.",
    "tty_device_open:DEV_PTMX_MINOR":
        "A minor *number*.",
    "pt_map_nothing:P_GROWSDOWN":
        "Stored into the page table entry, and read back out of it in "
        "kernel/memory.c's stack-growth path as `pt_flags(...) & P_GROWSDOWN`. "
        "The flag survives the call rather than being consumed by it.",
    "syslog_read:FIFO_PEEK":
        "Decomposed into the `peek` bool that crates/util/fifo's Fifo::read "
        "takes, which breaks the argument chain this follows.",
    "fd_setflags:O_NONBLOCK_":
        "Forwarded to the mount's own `setflags`, which is a function pointer "
        "-- there is no single callee to follow. What each mount does with it "
        "is tests/guest/src/bin/dup_semantics.rs.",
    "path_normalize:N_SYMLINK_NOFOLLOW":
        "True, and harmless: the walk tests N_SYMLINK_FOLLOW and treats its "
        "absence as nofollow, so the constant is documentation at the call "
        "site rather than a request. Listed rather than removed because a call "
        "site that says which of the two it means is worth more than the bit.",
}



# Directories with no source of ours in them. Pruned during the walk rather
# than filtered after it: `target/` alone holds hundreds of thousands of files,
# and a `**` glob visits every one before anything gets to reject it. That cost
# `tools/index-bounds.py` 25 of its 25.1 seconds.
PRUNE = {"build", "target", ".git", ".claude", "node_modules"}


def walk_sources(root, suffixes):
    """Every file under `root` with one of `suffixes`, skipping PRUNE.

    Sorted by full path, which is what `sorted(root.glob("**/*.c"))` gave and
    is not cosmetic: `tools/lock-order.py` follows *source order*, so the order
    files arrive in changes what it reports. os.walk's own order is the
    directory's, and swapping to it silently moved two entries.
    """
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in PRUNE and not d.startswith(".")]
        for name in filenames:
            if name.endswith(suffixes):
                found.append(pathlib.Path(dirpath) / name)
    return sorted(found)


def blank_comments(text):
    """Comments blanked, keeping offsets. A flag named in a comment is not a use
    of it -- and the comment beside a dropped flag is usually the one claiming
    it works."""
    return COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def sources(root):
    for path in walk_sources(root, (".c", ".h", ".rs")):
        rel = str(path.relative_to(root))
        if any(rel.startswith(d) or f"/{d}/" in f"/{rel}" for d in SKIP_DIRS):
            continue
        yield rel, path


def function_bodies(texts):
    """name -> (parameter names in order, body). C and Rust both.

    A name defined more than once keeps the longest body, which is the
    definition rather than a prototype or a `#[cfg(test)]` stub.
    """
    c_def = re.compile(
        r"^(?:static\s+|inline\s+)*[A-Za-z_]\w*[\w \t*]*?\b(\w+)\s*\(([^;{)=]*)\)\s*\{",
        re.M,
    )
    rust_def = re.compile(
        r'^\s*pub (?:unsafe )?extern "C" fn (\w+)\s*\(([^)]*)\)[^{]*\{', re.M
    )
    out = {}
    for rel, text in texts.items():
        for pattern, is_rust in ((c_def, False), (rust_def, True)):
            for m in pattern.finditer(text):
                depth, start = 0, text.index("{", m.end() - 1)
                body = None
                for i in range(start, len(text)):
                    if text[i] == "{":
                        depth += 1
                    elif text[i] == "}":
                        depth -= 1
                        if depth == 0:
                            body = text[start:i + 1]
                            break
                if body is None:
                    continue
                params = []
                for part in m.group(2).split(","):
                    part = part.strip()
                    if not part or part == "void":
                        continue
                    if is_rust:
                        params.append(part.split(":")[0].strip())
                    else:
                        names = re.findall(r"\b(\w+)\b", part)
                        params.append(names[-1] if names else "")
                name = m.group(1)
                if name not in out or len(body) > len(out[name][1]):
                    out[name] = (params, body)
    return out


def bits_tested(body, param, bodies, depth=0):
    """Flag names the body tests `param` against, following one forward.

    A forward is `g(..., param, ...)` with the parameter passed on unchanged,
    which is how `path_normalize` reaches the walk and how half the C in this
    tree is shaped.
    """
    p = re.escape(param)
    names = set()
    for m in re.finditer(
        rf"{p}\s*&\s*~?\(?\s*(?:ffi::)?([A-Z][A-Z0-9_]*)|"
        rf"~?\(?\s*(?:ffi::)?([A-Z][A-Z0-9_]*)\s*\)?\s*&\s*{p}\b|"
        rf"{p}\s*[=!]=\s*(?:ffi::)?([A-Z][A-Z0-9_]*)|"
        rf"(?:ffi::)?([A-Z][A-Z0-9_]*)\s*[=!]=\s*{p}\b",
        body,
    ):
        names.update(g for g in m.groups() if g)
    # `switch (param)` reads every case in it.
    for m in re.finditer(rf"switch\s*\(\s*{p}\s*\)", body):
        tail = body[m.end():]
        names.update(re.findall(r"\bcase\s+([A-Z][A-Z0-9_]*)", tail[:tail.find("}")]))
    if depth >= 2:
        return names
    for m in CALL.finditer(body):
        callee, args = m.group(1), m.group(2)
        if callee not in bodies:
            continue
        for i, a in enumerate(args.split(",")):
            if a.strip() != param:
                continue
            cparams, cbody = bodies[callee]
            if i < len(cparams):
                names |= bits_tested(cbody, cparams[i], bodies, depth + 1)
    return names


def main():
    quiet = "--quiet" in sys.argv
    root = pathlib.Path(__file__).resolve().parent.parent

    texts = {}
    for rel, path in sources(root):
        texts[rel] = blank_comments(path.read_text(errors="ignore"))

    flags = set()
    for rel, text in texts.items():
        if rel.endswith(".h"):
            flags.update(m.group(1) for m in FLAG_DEFINE.finditer(text))

    bodies = function_bodies(texts)

    # (callee, flag) -> a call site, so each is reported once with a place.
    dropped = {}
    for rel, text in texts.items():
        if rel.startswith("tests/"):
            continue
        for m in CALL.finditer(text):
            callee, args = m.group(1), m.group(2)
            if callee not in bodies:
                continue
            params, body = bodies[callee]
            for i, arg in enumerate(args.split(",")):
                arg = arg.strip()
                if not arg or i >= len(params):
                    continue
                # The argument has to be flag constants and nothing else.
                parts = [p.strip().strip("()") for p in arg.split("|")]
                if not parts or not all(p in flags for p in parts):
                    continue
                tested = bits_tested(body, params[i], bodies)
                # Only a parameter the callee treats as a *bitmask* at all.
                # Without this the report is full of values that happen to be a
                # single bit -- `pidreg_alloc(MAX_PID)`, `send_process_signal
                # (SIGHUP_)`, `tty_device_open(DEV_PTMX_MINOR)` -- and of masks
                # the callee stores rather than tests, which is every
                # `inotify_notify_path(path, IN_CREATE_, 0)`. Neither is a
                # dropped request. What the real one looked like is a parameter
                # whose *other* bits are tested and whose this one is not:
                # `path_normalize` reads N_SYMLINK_FOLLOW out of the same word
                # it ignored N_PARENT_DIR_WRITE in.
                if not tested:
                    continue
                for p in parts:
                    if p not in tested:
                        line = text.count("\n", 0, m.start()) + 1
                        dropped.setdefault((callee, p), f"{rel}:{line}")

    findings = []
    for (callee, flag), where in sorted(dropped.items()):
        key = f"{callee}:{flag}"
        if key in TESTED_ELSEWHERE:
            if not quiet:
                print(f"known    {key}\n         {TESTED_ELSEWHERE[key]}\n")
            continue
        findings.append((callee, flag, where))

    for callee, flag, where in findings:
        print(f"DROPPED  {where}: {callee}() is passed {flag} and never tests it")
    if not quiet:
        print(f"{len(flags)} flag constants, {len(bodies)} functions, "
              f"{len(findings)} passed and never tested")
    if findings:
        print("Each one is a question: does the callee dispatch on the whole "
              "word, or store the flags for later? If so, add it to "
              "TESTED_ELSEWHERE with the reason. If not, every caller asking "
              "for it is being ignored.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
