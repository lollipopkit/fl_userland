#!/usr/bin/env python3
"""Every `struct task` field the group-exit valve takes must be an atomic.

`crates/kernel/exitcalls`' `abandon_stuck_threads` is the only place in the
tree that writes another task's fields while that task is still running. A
thread it gives up on is, by construction, one that would not stop -- so it may
be anywhere, including in the middle of a syscall reading the very field this
loop is nulling. Every field it touches is therefore raced on by the owning
thread unless that thread holds a lock the valve also holds, and on the syscall
fast path it holds none.

**That argument has been got wrong three times in four days**, each time by a
comment naming `pids_lock`:

  - `task.mm`      2026-09-11, five lockless readers
  - `task.sighand` 2026-09-12, eight
  - `task.files`, `task.fs`, `task.syscall_refs` 2026-09-12, one each, and the
    `syscall_refs` one was a null dereference rather than a stale word

`pids_lock` is what stops `/proc/<pid>/fd` *resurrecting* a dying task's
object -- reading the pointer and then retaining it. It says nothing about
whether the word is raced on, and each of those comments ran the two together.

The gate that used to cover the class was `atomic_fields`, removed 2026-09-08
because "the fields are `std::sync::atomic` types, so a plain read does not
compile". True of a field that is *already* atomic, and silent about which ones
should be -- which is the gap all three fell into.

So this asks the question from the writer's end instead: find every field of
`(*t)` that `abandon_stuck_threads` assigns to or hands over, and require each
one's declaration in `crates/kernel/taskview/src/task.rs` to be an
`Atomic*` or an `Option<Arc<...>>`. A plain `*mut T` there is the defect.

It fails when it finds no valve, no fields, or a field it cannot find a
declaration for -- because a check that quietly covers nothing is worse than no
check, which is the shape this repository has been caught by four times.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VALVE = ROOT / "crates" / "kernel" / "exitcalls" / "src" / "group.rs"
TASK = ROOT / "crates" / "kernel" / "taskview" / "src" / "task.rs"

LINE_COMMENT = re.compile(r"//.*")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)

# `(*t).exiting = true` and the like: a plain assignment through the task
# pointer the loop is iterating over.
ASSIGN = re.compile(r"\(\*\s*(?:t|task)\s*\)\.(\w+)\s*=[^=]")
# `task.files.move_to(&(*cleanup).files)`, through the task borrowed or the
# raw pointer: the receiver is the task's side.
# `hand_over_atomic` and `hand_over_arc` were this shape's two spellings until
# 2026-10-16, when every handed-over field became an `ArcSlot`.
HANDOVER = re.compile(r"(?:\(\*\s*(?:t|task)\s*\)|\b(?:t|task))\.(\w+)\s*\.\s*move_to\s*\(")

# A field declaration in `struct task`. `pub name: type,` on one line, which is
# how every one of them is written.
FIELD = re.compile(r"^\s*pub\s+(\w+)\s*:\s*(.+?),\s*$", re.MULTILINE)

# Fields the valve writes that are *not* a resource handed to another owner.
# `exiting` is the flag the loop sets to claim the thread, read by `do_exit`'s
# early bail; it is a `bool` and making it atomic is a separate question this
# check deliberately does not decide. Named rather than inferred, so that a
# second one has to be added here on purpose.
NOT_A_HANDLE = {"exiting"}


def code(text: str) -> str:
    """The source with comments blanked.

    `group.rs` is more comment than code and several of its sentences quote
    the assignments this looks for.
    """
    text = BLOCK_COMMENT.sub("", text)
    return "\n".join(LINE_COMMENT.sub("", line) for line in text.splitlines())


def is_synchronised(ty: str) -> bool:
    """Does this field type make a concurrent read defined?

    `AtomicPtr<T>` and friends, or an `ArcSlot<T>`, which is an `AtomicPtr`
    owning one count. An `Option<Arc<T>>` was accepted until 2026-10-16 for
    `sighand`, whose readers held their own reference; the word itself was
    still a plain one another thread wrote, and it is a slot now.
    """
    return "Atomic" in ty or "ArcSlot<" in ty


def main() -> int:
    if not VALVE.exists() or not TASK.exists():
        print(f"valve_fields: {VALVE} or {TASK} is missing", file=sys.stderr)
        return 1

    body = code(VALVE.read_text())
    written = {m.group(1) for m in ASSIGN.finditer(body)}
    written |= {m.group(1) for m in HANDOVER.finditer(body)}
    handles = sorted(written - NOT_A_HANDLE)

    if not handles:
        print(
            "valve_fields: found no field the group-exit valve writes. Either "
            f"{VALVE.name} no longer has one, or this script has stopped "
            "recognising the shape -- both mean it is checking nothing.",
            file=sys.stderr,
        )
        return 1

    types = {m.group(1): m.group(2).strip() for m in FIELD.finditer(TASK.read_text())}

    bad = []
    unknown = []
    for name in handles:
        ty = types.get(name)
        if ty is None:
            unknown.append(name)
        elif not is_synchronised(ty):
            bad.append((name, ty))

    for name in unknown:
        print(
            f"valve_fields: the valve writes `{name}` and `struct task` has no "
            "such field -- this script cannot say whether it is synchronised",
            file=sys.stderr,
        )
    for name, ty in bad:
        print(
            f"valve_fields: `task.{name}: {ty}` is written by "
            "`abandon_stuck_threads` from another thread and read by the "
            "task's own. It must be an `AtomicPtr` or an `ArcSlot`.",
            file=sys.stderr,
        )

    print(
        f"valve_fields: {len(handles)} fields handed over by the group-exit "
        f"valve, {len(handles) - len(bad) - len(unknown)} synchronised"
    )
    return 1 if bad or unknown else 0


if __name__ == "__main__":
    sys.exit(main())
