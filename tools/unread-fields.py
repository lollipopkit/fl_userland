#!/usr/bin/env python3
"""Report a `struct task` or `struct tgroup` field that is written and never read.

A per-task field is written on a path a guest reaches. If nothing ever reads it
back, that store is work done on every syscall, every fork or every signal for
an answer nobody asks — and, worse, it *reads* as though something does. The
field sits in the struct with a name that describes a decision, and a reader
looking for where that decision is made finds the store and stops.

Two were found by hand on 2026-08-29, both while migrating the group they were
in:

* `syscall_restart_num` — stored on **every syscall**, alongside the two values
  the `SA_RESTART` rewind really uses. The decision it looks like it is for,
  which syscalls may restart, is made from the local variable in
  `handle_interrupt` one line away.
* `waiting_lock` — the mutex a condition variable goes with, set and cleared
  around every interruptible wait. The signal path that wakes the task says in
  a comment that it deliberately does *not* take that mutex.

Neither was a defect. Both were a field whose presence answered a question the
code does not ask, which is the kind of thing that survives precisely because
nothing fails.

**How a field counts as read.** It appears somewhere other than the left of an
assignment to it, or than `&field` handed to something that only writes.
Struct-wide copies do not count — `*task = *parent` reads every field, which
would make this report nothing at all — and neither does the declaration.

That second clause is not a nicety. `atomic_fetch_add(&group->syscall_count, 1)`
looks exactly like a read: the field is not on the left of an `=`. It is a store
on every syscall for a counter nothing ever loads, and the first version of this
tool reported it as read for that reason.

**It is a heuristic and it is one-sided.** A field read only through a struct
copy, or by the assembly through `cpu-offsets.h`, is invisible to it, so
`READ_ELSEWHERE` carries those with a reason. A clean run is not a proof.

Usage:  tools/unread-fields.py [--quiet]
Exit:   0 if every written field is read or accounted for, 1 otherwise.
"""

import os
import pathlib
import re
import sys

# The structs this reads: the fields a guest's syscalls write, and whether
# anything reads them back.
STRUCTS = ["task", "tgroup"]

# Read, and not a dropped store. The reason is the point of the entry.
READ_ELSEWHERE = {
    ("task", "cpu"):
        "struct cpu_state, whose layout is a contract with the gadgets through "
        "cpu-offsets.h. The assembly reads it; no C has to.",
}

SKIP_DIRS = ("build", "docs", ".git", "target", "offload_tests")
COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)



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
    """Comments blanked, keeping offsets. A field named in a comment is not a
    use of it -- and the comment beside a dead field is usually the one that
    makes it look alive."""
    return COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def sources(root):
    for path in walk_sources(root, (".c", ".h", ".rs")):
        rel = str(path.relative_to(root))
        if any(rel.startswith(d) or f"/{d}/" in f"/{rel}" for d in SKIP_DIRS):
            continue
        yield rel, path


def struct_fields(text, name):
    """Field names of `struct name`, in declaration order.

    The struct is Rust's since 2026-09-05 -- see
    `crates/kernel/taskview/src/task_types.rs` and its layout modules -- so this
    reads `pub name: type,`.
    There are no anonymous members to skip any more, which is what the C
    version's brace counting was for.
    """
    m = re.search(rf"\npub struct {name} \{{(.*?)\n\}}", text, re.S)
    if not m:
        return []
    out = []
    for line in m.group(1).split("\n"):
        line = line.strip()
        if not line or line.startswith(("//", "#")):
            continue
        decl = re.match(r"^pub (\w+): ", line)
        if decl:
            out.append(decl.group(1))
    return out


# `&x->field` handed to one of these is a store, however much it looks like a
# read. `atomic_load*` is the one that is not, which is why the list is of the
# writers rather than of all of them.
ATOMIC_WRITE = re.compile(
    r"(?:atomic_store\w*|atomic_fetch_\w+|atomic_exchange\w*|"
    r"atomic_compare_exchange\w*|atomic_init)\s*\(\s*&$"
)


def atomic_write(text, at):
    """Whether the use starting at `at` is `&x->field` inside an atomic store.

    The receiver is whatever is between the `&` and the `->`, so this looks back
    from the arrow for `atomic_..._(&`.
    """
    start = max(0, at - 96)
    before = text[start:at]
    # Trim the receiver: `&current->group` for `->syscall_count`.
    trimmed = re.sub(r"[\w\[\]\.\->]*$", "", before)
    return ATOMIC_WRITE.search(trimmed) is not None


def main():
    quiet = "--quiet" in sys.argv
    root = pathlib.Path(__file__).resolve().parent.parent

    texts = {rel: blank_comments(p.read_text(errors="ignore")) for rel, p in sources(root)}
    layout_sources = [
        root / "crates/kernel/taskview/src/task_types.rs",
        root / "crates/kernel/taskview/src/group.rs",
        root / "crates/kernel/taskview/src/cleanup.rs",
        root / "crates/kernel/taskview/src/task.rs",
    ]
    header = "\n".join(path.read_text(errors="ignore") for path in layout_sources)

    findings = []
    total = 0
    for struct in STRUCTS:
        fields = struct_fields(header, struct)
        if not fields:
            findings.append((struct, "?", "no fields found -- has taskview layout sources moved?", 0))
            continue
        for field in fields:
            total += 1
            writes = 0
            reads = 0
            # `x->field` and `x.field`, but not `->fieldname` of a longer name.
            #
            # **A struct literal is invisible to this**, and that is a known
            # gap rather than an oversight: `tgroup_new` writes
            # `personality: 0,` and no `.personality =` exists anywhere, so
            # that field counts zero writes and is skipped by the `writes == 0`
            # rule below -- while being written once and read never, which is
            # what this tool is for. The C built a tgroup with `calloc` and a
            # run of assignments, so every initial write used to be a `->field
            # =`; the constructor is a Rust literal now.
            #
            # Matching `field:` as well would be worse: `ThreadAttr` has its
            # own `personality` and its own literal, so a name-only match
            # counts *that* as a write here and hides the finding. A fix has to
            # know which struct a literal constructs. See
            # `docs/changelog/2026-09-15-a-gate-that-cannot-see-a-struct-literal.md`,
            # which names `tgroup.personality` as the positive to test against.
            use = re.compile(rf"(?:->|\.)\s*{re.escape(field)}\b")
            for rel, text in texts.items():
                for m in use.finditer(text):
                    tail = text[m.end():m.end() + 3]
                    # `= ` but not `==`: an assignment to it is a write.
                    if re.match(r"\s*=[^=]", tail):
                        writes += 1
                    elif atomic_write(text, m.start()):
                        writes += 1
                    else:
                        reads += 1
            if reads > 0 or writes == 0:
                continue
            if (struct, field) in READ_ELSEWHERE:
                if not quiet:
                    print(f"known    {struct}.{field}\n         "
                          f"{READ_ELSEWHERE[(struct, field)]}\n")
                continue
            findings.append((struct, field, "written and never read", writes))

    for struct, field, why, writes in findings:
        print(f"UNREAD   struct {struct}: `{field}` is {why}"
              + (f" ({writes} store(s))" if writes else ""))
    if not quiet:
        print(f"{total} fields, {len(findings)} written and never read")
    if findings:
        print("Each one is a question: is it read through a struct copy, or by "
              "the assembly? If so, add it to READ_ELSEWHERE with the reason. "
              "If not, the store is work done for an answer nobody asks -- and "
              "the field's name is describing a decision the code does not make.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
