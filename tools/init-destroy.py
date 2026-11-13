#!/usr/bin/env python3
"""Report a synchronisation object that is initialised and never destroyed.

`lock_init`, `cond_init` and `wrlock_init` each have a matching destroy, and a
struct field given one of them wants the other before the struct is freed.
Four fields did not have it on 2026-08-29, all found by reading:

* `tgroup.stopped_cond` — created beside `child_exit` in all three places a
  thread group is built, and destroyed in neither of the two teardowns. The
  teardown was two verbatim copies of nine calls, and the copies had drifted.
* `tgroup.lock`, `inode.lock`, `fd.lock` — no `lock_destroy` existed at all, so
  nothing in this tree had ever destroyed a `lock_t`.
* `task.pause` and `task.ptrace.cond` — `task_destroy` memsets the struct, which
  is not destroying a pthread object, it is making it invalid.

**Why it is worth a tool rather than a rule.** The destroy is where a *waiter*
is detected: `pthread_cond_destroy` and `pthread_mutex_destroy` answer EBUSY
when a thread is still parked, and every one of these sits immediately before a
`free()`. Skipping it does not lose a check, it converts a diagnosable EBUSY
into a use-after-free on another thread with the evidence already freed. The
tree's `cond_destroy`, `lock_destroy` and `wrlock_destroy` all trap on failure
for that reason.

**How the pairing is judged.** Per *struct field*, not per call: a field
initialised somewhere and destroyed nowhere is the finding. Which function does
either is not checked, because a group is built in three places and torn down in
three others, and matching those up is not something a regex can do.

The struct half of that key is not decoration. Keying on the field name alone
made `asbestos->lock` invisible — `lock` is a field of five different structs
here and the other four are destroyed, so the name looked paired while that one
was not. The receiver's type comes from its declaration in the enclosing
function, which is how `&asbestos->lock` becomes `(asbestos, lock)`.

A bare global (`&pids_lock`, no receiver) is skipped: it is initialised once and
lives as long as the process, so there is nothing it could outlive.

**It read only C until 2026-09-03, by which point it examined nothing.** The run
printed "0 struct fields, 0 initialised and never destroyed" and passed: every
object that embeds a `lock_t` or a `cond_t` had moved to a crate, leaving one
`lock_init` in C against fourteen init/destroy calls in `crates/`. A gate that
covers nothing still prints a clean run — the same thing `tools/lock-order.py`
was found doing the same hour, and for the same reason.

The Rust half is keyed on `(crate, field)` rather than on the receiver's
declared type, which Rust does not spell at the call site: one crate owns one of
these objects, and the receiver is `(*a)` on one line and `a` on the next —
`crates/asbestos/blockcache` does exactly that — so keying on the receiver would
report a field as unpaired because it was spelled twice. Two structs in one
crate sharing a field name collide, which hides a finding rather than inventing
one.

**It is a heuristic and it is one-sided.** A field destroyed through a pointer
alias, or by a Rust drop across the boundary, is invisible to it, so
`DESTROYED_ELSEWHERE` carries those with a reason. A clean run is not a proof.

Usage:  tools/init-destroy.py [--quiet]
Exit:   0 if every initialised field is destroyed or accounted for, 1 otherwise.
"""

import os
import pathlib
import re
import sys

# init -> destroy. Every pair the tree has.
PAIRS = {
    "lock_init": "lock_destroy",
    "cond_init": "cond_destroy",
    "wrlock_init": "wrlock_destroy",
}

# Initialised and not destroyed, on purpose, keyed the way findings are.
# The reason is the point of the entry.
DESTROYED_ELSEWHERE = {}

SKIP_DIRS = ("build", "docs", ".git", "target")
COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)

# `&recv->field` or `&recv.field`, and nothing else. A subscript (`&l->cond[i]`)
# is deliberately not matched: an array of them is not a field, and the loop
# that destroys one is not something this can pair up.
CALL = r"\b{}\s*\(\s*&(\w+)\s*(?:->|\.)\s*(?:\w+\s*\.\s*)*(\w+)\s*\)"

# The same pairs as written from Rust, which is where all but one of them are.
#
# **This tool examined zero fields on 2026-09-03**, and printed "0 struct
# fields, 0 initialised and never destroyed" while passing. Every object that
# embeds a `lock_t` or a `cond_t` had moved to a crate, and there are fourteen
# init/destroy calls in `crates/` against one left in C. A gate that covers
# nothing still prints a clean run, which is the same thing that had happened to
# `tools/lock-order.py` and was found the same hour.
#
# Rust reaches these through the `sync_*` shims, because `lock_init` and
# `cond_init` are macros and bindgen emits nothing for a macro. The address is
# always `&raw mut` of a field, in one of three spellings: `(*p).field`,
# `p.field` or `self.field`.
RUST_PAIRS = {
    "sync_lock_init": "sync_lock_destroy",
    "cond_init": "cond_destroy",
}
RUST_CALL = (r"\b{}\s*\(\s*&raw\s+mut\s+\(?\*?\(?[\w\.]*?(\w+)\)?\)?"
             r"\s*\.\s*(?:\w+\s*\.\s*)*(\w+)\s*\)")



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


def receiver_type(text, at, name):
    """The struct `name` was declared as, looking back from `at`.

    A local (`struct tgroup *group = ...`) or a parameter (`struct fd *fd`);
    both read the same. Nearest declaration wins, so an inner scope's shadow is
    the one found. None if it is not a struct -- which is what a bare global is,
    and those are skipped by the caller.
    """
    # The `\b` after the type is load-bearing: without it `sizeof(struct
    # tgroup)` parses as a declaration of `group` with type `struct t`, and
    # every tgroup field was reported under that name instead of its own.
    decl = re.compile(rf"\bstruct\s+(\w+)\b\s*\**\s*{re.escape(name)}\b\s*[=,;)]")
    last = None
    for m in decl.finditer(text, 0, at):
        last = m.group(1)
    return last


def blank_comments(text):
    """Comments blanked, keeping offsets. This file's own prose names every
    function it looks for, and so do several of the comments it reads."""
    return COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def sources(root):
    for path in walk_sources(root, (".c", ".h")):
        rel = str(path.relative_to(root))
        if any(rel.startswith(d) or f"/{d}/" in f"/{rel}" for d in SKIP_DIRS):
            continue
        yield rel, path


def main():
    quiet = "--quiet" in sys.argv
    root = pathlib.Path(__file__).resolve().parent.parent

    # (struct, field) -> {"init": [(file, line)], "destroy": [(file, line)]}
    seen = {}
    skipped_global = 0
    unknown_type = []
    for rel, path in sources(root):
        text = blank_comments(path.read_text(errors="ignore"))
        for init, destroy in PAIRS.items():
            for kind, fn in (("init", init), ("destroy", destroy)):
                for m in re.finditer(CALL.format(fn), text):
                    recv, field = m.group(1), m.group(2)
                    struct = receiver_type(text, m.start(), recv)
                    line = text[:m.start()].count("\n") + 1
                    if struct is None:
                        unknown_type.append((rel, line, recv, field))
                        continue
                    key = (f"struct {struct}", field)
                    seen.setdefault(key, {"init": [], "destroy": []})
                    seen[key][kind].append((rel, line))
        # A bare `&name` with no receiver is a global; counted, not reported.
        for fn in PAIRS:
            for m in re.finditer(rf"\b{fn}\s*\(\s*&(\w+)\s*\)", text):
                skipped_global += 1

    # The Rust half. Keyed on `(crate, field)` rather than on the receiver's
    # declared type, which Rust does not spell at the call site: one crate owns
    # one object here, and the receiver is `(*a)` in one line and `a` in the
    # next -- `crates/asbestos/blockcache` does exactly that -- so keying on the
    # receiver would report a field as unpaired because it was spelled twice.
    # Two structs in one crate sharing a field name would collide, which hides a
    # finding rather than inventing one.
    for path in walk_sources(root / "crates", (".rs",)):
        rel = str(path.relative_to(root))
        if rel.endswith("build.rs") or "teststub" in rel:
            continue
        text = blank_comments(path.read_text(errors="ignore"))
        crate = rel.split("/src/")[0].split("/")[-1]
        for init, destroy in RUST_PAIRS.items():
            for kind, fn in (("init", init), ("destroy", destroy)):
                for m in re.finditer(RUST_CALL.format(fn), text):
                    field = m.group(2)
                    line = text[:m.start()].count("\n") + 1
                    key = (f"crate {crate}", field)
                    seen.setdefault(key, {"init": [], "destroy": []})
                    seen[key][kind].append((rel, line))

    findings = []
    for (owner, field), where in sorted(seen.items()):
        if not where["init"] or where["destroy"]:
            continue
        if (owner, field) in DESTROYED_ELSEWHERE:
            if not quiet:
                print(f"known    {owner}: `{field}`\n         "
                      f"{DESTROYED_ELSEWHERE[(owner, field)]}\n")
            continue
        findings.append((owner, field, where["init"]))

    for owner, field, inits in findings:
        at = ", ".join(f"{f}:{n}" for f, n in inits[:3])
        print(f"UNPAIRED {owner}: `{field}` is initialised at {at} "
              f"and destroyed nowhere")
    if not quiet:
        print(f"{len(seen)} struct fields, {len(findings)} initialised and "
              f"never destroyed; {skipped_global} globals skipped")
        # A receiver whose type could not be read is a blind spot, not a pass.
        # Reported so a run that finds nothing is not mistaken for a clean one.
        for rel, line, recv, field in unknown_type:
            print(f"unread   {rel}:{line}: `{recv}` is not a struct this could "
                  f"resolve, so `{field}` was not checked")
    if findings:
        print("Each one is a question: is it destroyed through an alias this "
              "cannot see? If so, add it to DESTROYED_ELSEWHERE with the "
              "reason. If not, the free that follows is what a still-parked "
              "waiter finds -- and the EBUSY that would have named it was "
              "never asked for.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
