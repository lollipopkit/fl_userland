#!/usr/bin/env python3
"""Report lock-order cycles.

A deadlock between two mutexes is findable by reading: enumerate every place one
lock is held while another is taken, and look for a cycle in the resulting
order. This does that mechanically over the sources.

It found `docs/changelog/2026-08-22-inotify-read-and-notify-deadlocked.md`, which
had been hiding behind a comment asserting the invariant it broke.

**It read only C until 2026-09-03, and by then the C had no nesting left.** The
run printed "0 locks with nesting, 0 cycles" and passed — a gate covering
nothing, which is worse than no gate, because a clean run reads as "no cycles"
rather than as "nothing was looked at". Every lock in the tree had moved to Rust
underneath it: 507 acquisitions across 79 files. It reads those too now, and the
count in the output is what says so.

**It is approximate, and the approximation is one-sided in the useful
direction.** It follows source order rather than control flow, so a lock taken
in one branch and released in another can look nested when it is not — false
*positives*, which cost a read. It does not follow calls, so a nesting that
happens across a function boundary is invisible — false *negatives*, which is
why a clean run is not a proof.

A third limitation is worth naming because it produced a whole family of
phantom cycles once: locks held in a *caller* are invisible here. Every path
through `fs/proc/pid.c` holds `pids_lock`, taken in `proc_get_task`, and this
sees none of it — so a cycle reported against that file may already be
serialised by a lock the analysis cannot see. Check the callers before believing
a cycle, not just the lines it names.

Every reported cycle has to be read before it is believed. `ALLOWED` below is
for the ones that have been, and each entry carries the reason.

The Rust half is more accurate than the C half rather than less, and for one
reason: a Rust guard is released by a **brace**, so there is no "taken in one
branch and released in another" to approximate. What it needs instead is the
three ways a hold ends — the block closing, an explicit `drop(g)`, and the
narrower scope of a temporary in a `match` or `if let` scrutinee — and all three
are modelled. Missing `drop(g)` alone would report `receive_signals` taking
`pids_lock` while holding sighand's, which is the inversion of what every other
path does and which the code explicitly avoids two lines earlier.

`--calls` additionally treats "held A, called g(), g() directly takes B" as an
A-to-B edge. **C only**: following a Rust call means resolving a method to an
impl, which this does not do. That is what found both real deadlocks so far, and it is **not**
part of the gate: two of the three cycles it reports today are false for reasons
a refactor could quietly change (see CALL_MODE_KNOWN), and a gate that needs
three subtle non-bugs understood before it passes is a gate that gets disabled.
Run it by hand when hunting.

It also reports a second, unrelated thing, because the parser already has what
it needs: **a function whose first lock-related event is an *unlock***. That is
either a helper the caller hands a held lock to, or a bug. Two of the eleven in
the tree on 2026-08-28 were bugs, one of them reachable from any guest with one
syscall -- see UNLOCK_FIRST_OK.

Usage:  tools/lock-order.py [--quiet] [--calls]
Exit:   0 if every cycle is in ALLOWED and every unlock-first function is in
        UNLOCK_FIRST_OK, 1 otherwise. `--calls` never fails; it prints and
        returns 0.
"""

import collections
import os
import pathlib
import re
import sys

# Cycles that have been read and are not deadlocks. The reason is the point of
# the entry: an allowlist without one is a way to stop looking.
_PIDS_LOCK_SERIALISED = (
    "Both paths hold pids_lock across the inner locks and are serialised by it. "
    "proc_get_task returns with pids_lock *held* (it unlocks only on failure) "
    "and proc_put_task releases it; do_exit_group takes pids_lock before "
    "group->lock. So the inner order cannot matter."
)

# Keyed on the *edges*, not on the set of lock names -- the same correction
# CALL_MODE_KNOWN below already carries, and for the same reason. Keyed on the
# set, a cycle among the same locks in a different direction, or through
# different functions, matched an entry written about neither and printed
# "known": the gate would have waved through a deadlock that had just been
# introduced.
#
# This list is the *gated* one and had the coarse key while the list that gates
# nothing had the precise one. An allowlist entry whose reason names one place
# must not speak for another; `tools/index-bounds.py`'s CHECKED had the
# identical defect and let an arbitrary indirect call through, on 2026-08-29.
#
# An edge is (holder, acquired, function), from cycle_key below.
ALLOWED = {
    frozenset({
        ("group->lock", "task->general_lock", "do_exit_group"),
        ("task->general_lock", "group->lock", "proc_pid_stat_snapshot"),
    }): _PIDS_LOCK_SERIALISED,
    # The same two functions, appearing as a three-cycle since
    # proc_pid_stat_snapshot was reordered to take sighand->lock above
    # group->lock -- which it had to be, to agree with the signal path. Same
    # pair, same reason.
    frozenset({
        ("sighand->lock", "group->lock", "proc_pid_stat_snapshot"),
        ("group->lock", "task->general_lock", "do_exit_group"),
        ("task->general_lock", "sighand->lock", "proc_pid_stat_snapshot"),
    }): _PIDS_LOCK_SERIALISED,
}

# What `--calls` finds today. Not an allowlist -- it gates nothing -- but the
# reading, so that a new entry stands out against these.
#
# Keyed on the *edges*, not on the set of locks. Keyed on the set, reverting
# proc_pid_stat_snapshot to the order that actually deadlocked still matched the
# safe sighand/group entry and printed "known" -- the tool would have waved
# through a bug that had just been reintroduced. An edge is (holder, acquired,
# function), and the direction is what tells the two apart.
CALL_MODE_KNOWN = {
    frozenset({
        ("sighand->lock", "group->lock", "proc_pid_stat_snapshot"),
        ("group->lock", "sighand->lock", "deliver_signal"),
    }):
        "proc_pid_stat_snapshot against do_exit_group's deliver_signal. Both "
        "hold pids_lock: the first through proc_get_task, which this analysis "
        "cannot see, the second explicitly.",
    frozenset({
        ("group->lock", "task->general_lock", "do_exit_group"),
        ("task->general_lock", "group->lock", "proc_pid_stat_snapshot"),
    }):
        "The same pair as the gated ALLOWED entry.",
    frozenset({
        ("sighand->lock", "group->lock", "proc_pid_stat_snapshot"),
        ("group->lock", "task->general_lock", "do_exit_group"),
        ("task->general_lock", "sighand->lock", "proc_pid_stat_snapshot"),
    }):
        "The same pair again, as a three-cycle.",
    frozenset({
        ("current->ptrace.lock", "sighand->lock", "signal_delivery_stop"),
        ("sighand->lock", "current->ptrace.lock", "signal_delivery_stop"),
    }):
        "signal_delivery_stop *unlocks* sighand->lock before taking "
        "ptrace.lock and retakes it at the end, so the two are never held "
        "together. This analysis sees the call, not the release.",
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


def cycle_key(cyc, edges):
    """A cycle as its edges: (holder, acquired, function) for each hop."""
    key = set()
    for a, b in zip(cyc, cyc[1:] + cyc[:1]):
        where = edges[a][b]
        # "path:line fn" or "path:line fn -> callee()". For a call edge this
        # takes the *callee*, which is where the lock is actually taken, and
        # unlike a line number it survives an edit above it.
        fn = where.split()[-1].removesuffix("()") if "->" in where else where.split()[-1]
        key.add((a, b, fn))
    return frozenset(key)

CALL = re.compile(r"(?<![\w>.])([a-z_][a-z0-9_]{2,})\s*\(")
NOT_CALLS = {"if", "while", "for", "switch", "return", "sizeof",
             "lock", "unlock", "read_wrlock", "read_wrunlock",
             "write_wrlock", "write_wrunlock"}

LOCK = re.compile(r"(?<!\w)(lock|read_wrlock|write_wrlock)\s*\(\s*&([A-Za-z_][\w\->\.\[\]]*)")
UNLOCK = re.compile(r"(?<!\w)(unlock|read_wrunlock|write_wrunlock)\s*\(\s*&([A-Za-z_][\w\->\.\[\]]*)")
FUNC = re.compile(r"^[A-Za-z_][\w \*]*\s+\**(\w+)\s*\([^;]*\)\s*\{?\s*$")

# ------------------------------------------------------------------- Rust
#
# The C half above reads what is left of the C, and on 2026-09-03 that became
# **nothing**: it reported "0 locks with nesting, 0 cycles" and passed, because
# every lock in the tree had moved to Rust. A gate that covers nothing still
# prints a clean run, which is worse than not having it.
#
# What Rust changes is that a lock is released by *scope* rather than by an
# explicit call, and that is easier to read rather than harder -- there is no
# "released in one branch and taken in another" to approximate, only a brace.
# So the model here is: a guard bound by `let` lives until the block it is
# written in closes, and a guard *temporary* in a `match` or `if let` scrutinee
# lives until the block that line opens closes. The second is a Rust footgun in
# its own right -- `if let Ok(g) = m.lock() { ... }` holds the lock across the
# whole body -- and getting it wrong is what made the first version of this
# report `Db::lookup_path` taking a write lock while holding a read lock on the
# same `RwLock`, which is a deadlock and which the code does not do.
#
# What it does not model, in the same one-sided spirit as the C half:
#
#   - Calls. `--calls` is C-only.
#   - Types. A lock is named by the *expression* that takes it, so the same
#     lock reached through two variable names is two nodes (a missed cycle) and
#     two different locks reached through the same name in one crate are one
#     (a phantom edge). `RUST_ALIASES` fixes the names that matter.
#   - `drop(guard)`, which ends a hold early. Modelled -- it is one line and it
#     is how a Rust caller says what the C said with `unlock`.
RUST_DOT_LOCK = re.compile(r"([A-Za-z_][\w:\.\(\)\[\]]*?)\s*\.\s*(lock|write|read)\s*\(\s*\)")
RUST_GUARD = re.compile(r"\b([A-Z]\w*Guard)\s*::\s*(?:new|take|acquire)\s*\(")
RUST_SYNC = re.compile(
    r"\bsync_(?:lock|read_wrlock|write_wrlock)\s*\(\s*&raw mut\s*\(?\*?\(?([\w\.]+)\)?\)?\.(\w+)")
RUST_FN = re.compile(
    r"^\s*(?:pub(?:\([\w:]+\))?\s+)?(?:const\s+)?(?:unsafe\s+)?(?:extern\s+\"C\"\s+)?fn\s+(\w+)")
RUST_IMPL = re.compile(r"^\s*impl(?:\s*<[^>]*>)?\s+(?:\w+\s+for\s+)?([\w:]+)")
RUST_LET = re.compile(r"\blet\s+(?:mut\s+)?[\w\(\), ]+\s*=")
RUST_BINDING = re.compile(r"\blet\s+(?:mut\s+)?(\w+)\s*=")
RUST_IF_LET = re.compile(r"\b(?:if|while)\s+let\b")
RUST_DROP = re.compile(r"\bdrop\s*\(\s*(\w+)\s*\)")
CFG_TEST = re.compile(r"#\[cfg\(test\)\]")

# The guard types that name a lock the C half also knows, so the two halves
# share a vocabulary and a cycle that crosses the boundary can be seen at all.
RUST_ALIASES = {
    "PidsGuard": "pids_lock",
    "InodeGuard": "inode->lock",
    "SigHandGuard": "sighand->lock",
}

# Struct names that say nothing about which lock this is: `fd->lock` and
# `sock->lock` are the same field, and collapsing them is what makes the
# analysis see through the variable a caller happened to use.
ANONYMOUS_OWNERS = {"current", "task", "sock", "fd", "mount", "poll_", "tty", "group"}


def normalise(name):
    name = re.sub(r"\[[^\]]*\]", "", name)
    parts = name.split("->")
    if len(parts) == 1:
        return parts[0]
    if parts[0] in ANONYMOUS_OWNERS and len(parts) > 2:
        parts = parts[1:]
    return "->".join(parts[-2:])


def strip_comments(text):
    """Blank out comments, keeping line numbers.

    Without this, prose creates edges: `kernel/exit.c` explains a deferred
    release in a comment that names `do_exit()`, and that was read as a call
    made while three locks were held. It produced a family of cycles that do not
    exist. A `lock(&x)` written in a comment would do the same.
    """
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out.append("".join("\n" if c == "\n" else " " for c in text[i:end]))
            i = end
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append(" " * (end - i))
            i = end
        elif text[i] in "\"'":
            quote, j = text[i], i + 1
            while j < n and text[j] != quote:
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:min(j + 1, n)])
            i = min(j + 1, n)
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def build_graph(root, follow_calls=False):
    """The lock-order edges.

    With `follow_calls`, a call made while holding a lock also contributes edges
    to whatever that callee takes *directly* -- one level, not transitively.
    Transitively is useless: `may_acquire(mem_ptr)` closes over most of the tree
    and every lock reaches every other, which reported 2457 cycles.
    """
    bodies = collections.defaultdict(list)
    edges = collections.defaultdict(dict)
    for path in walk_sources(root, (".c",)):
        p = str(path)
        if "/build" in p or "/tests/" in p or "/.claude/worktrees/" in p:
            continue
        fn, held = "?", []
        for i, line in enumerate(strip_comments(path.read_text(errors="ignore")).split("\n"), 1):
            m = FUNC.match(line.strip())
            if m and "=" not in line:
                fn, held = m.group(1), []
            for m in LOCK.finditer(line):
                n = normalise(m.group(2))
                for h in held:
                    if h != n:
                        edges[h].setdefault(n, f"{p}:{i} {fn}")
                held.append(n)
            for m in UNLOCK.finditer(line):
                n = normalise(m.group(2))
                if n in held:
                    held.remove(n)
            if follow_calls:
                for m in LOCK.finditer(line):
                    bodies[fn].append(("L", normalise(m.group(2)), f"{p}:{i} {fn}"))
                for m in UNLOCK.finditer(line):
                    bodies[fn].append(("U", normalise(m.group(2)), None))
                for m in CALL.finditer(line):
                    if m.group(1) not in NOT_CALLS:
                        bodies[fn].append(("C", m.group(1), f"{p}:{i} {fn}"))

    add_rust_edges(root, edges)

    if follow_calls:
        direct = {f: {e[1] for e in evs if e[0] == "L"} for f, evs in bodies.items()}
        for f, evs in bodies.items():
            held = []
            for kind, name, where in evs:
                if kind == "L":
                    held.append(name)
                elif kind == "U":
                    if name in held:
                        held.remove(name)
                elif kind == "C" and held and name in direct:
                    for h in held:
                        for target in direct[name]:
                            if h != target:
                                edges[h].setdefault(target, f"{where} -> {name}()")
    return edges


def rust_lock_name(receiver, kind, crate, impl_ty):
    """What to call the lock this expression takes.

    Three shapes, and the third is the approximate one:

    - `self.field.lock()` inside `impl Tty` is `Tty.field.lock`, which is the
      same lock however a caller spells the receiver.
    - `A_STATIC.lock()` is `crate::A_STATIC.lock`. A static is one object.
    - anything else is `crate::<last segment>.lock`, which is the variable's
      name and not the lock's. Two names for one lock are two nodes here.
    """
    if receiver == "self" or receiver.startswith("self."):
        base = f"{impl_ty}.{receiver[5:] or 'self'}"
    elif receiver.replace("_", "").isupper():
        base = f"{crate}::{receiver}"
    else:
        base = f"{crate}::{receiver.split('.')[-1].split('(')[0]}"
    return f"{base}.{kind}"


def add_rust_edges(root, edges):
    """Nested lock acquisitions in `crates/`, added to the same graph.

    Test modules are skipped: a `setup()` that takes five registry locks in a
    row is not a lock order the product has, and reading one is a cycle nobody
    can act on. Both spellings -- an inline `#[cfg(test)] mod tests {` and a
    whole `tests.rs` reached by one -- because the tree uses both.
    """
    for path in walk_sources(root / "crates", (".rs",)):
        p = str(path)
        if p.endswith("tests.rs") or "/tests/" in p:
            continue
        crate = p.split("/src/")[0].split("/")[-1]
        fn, impl_ty, depth = "?", "", 0
        held = []           # (name, the depth it is released at, binding)
        test_depth, pending_test = None, False
        for i, line in enumerate(strip_comments(path.read_text(errors="ignore")).split("\n"), 1):
            if CFG_TEST.search(line):
                pending_test = True
            m = RUST_IMPL.match(line)
            if m:
                impl_ty = m.group(1).split("::")[-1]
            m = RUST_FN.match(line)
            if m:
                fn, held = m.group(1), []
            if test_depth is None and pending_test and "{" in line:
                test_depth, pending_test = depth, False

            opened = line.count("{") - line.count("}")
            if test_depth is None:
                names = []
                for m in RUST_DOT_LOCK.finditer(line):
                    names.append(rust_lock_name(m.group(1), m.group(2), crate, impl_ty))
                for m in RUST_GUARD.finditer(line):
                    names.append(RUST_ALIASES.get(m.group(1), m.group(1)))
                for m in RUST_SYNC.finditer(line):
                    names.append(normalise(f"{m.group(1)}->{m.group(2)}"))

                bound = RUST_BINDING.search(line)
                bound = bound.group(1) if bound else None
                for name in names:
                    for h, _, _ in held:
                        if h != name:
                            edges[h].setdefault(name, f"{p}:{i} {fn}")
                    if RUST_LET.search(line) and not RUST_IF_LET.search(line):
                        held.append((name, depth, bound))
                    elif line.rstrip().endswith("{"):
                        # A temporary in a `match`/`if let` scrutinee: held for
                        # the block that line opens.
                        held.append((name, depth + opened, None))
                for m in RUST_DROP.finditer(line):
                    held = [h for h in held if h[2] != m.group(1)]

            depth += opened
            if opened < 0:
                held = [h for h in held if h[1] <= depth]
                if test_depth is not None and depth <= test_depth:
                    test_depth = None


def find_cycles(edges, limit=6):
    cycles, seen = [], set()

    def walk(node, path, onpath):
        for nxt in edges.get(node, {}):
            if nxt in onpath:
                cyc = path[path.index(nxt):]
                if len(cyc) > 1:
                    key = frozenset(cyc)
                    if key not in seen:
                        seen.add(key)
                        cycles.append(cyc)
            elif len(path) < limit:
                walk(nxt, path + [nxt], onpath | {nxt})

    for n in sorted(edges):
        walk(n, [n], {n})
    return cycles


# Functions whose first lock-related event is an unlock, which have been read
# and are not defects. The reason is the point of the entry.
#
# The shape is worth gating on because a function that releases a lock it did
# not take is either documented as taking one from its caller, or wrong -- and
# when it is wrong the caller usually releases the same lock again, which a
# pthread mutex does not refuse. `kill(-<empty group>, sig)` was that, from any
# guest, on the global process-table lock; futex_get_unlocked was that on
# every one of its five callers. See the changelogs of 2026-08-28.
UNLOCK_FIRST_OK = {
    # `fs/proc/pid.c`'s proc_put_task was here. The pair is Rust now
    # (crates/fs/proc's pidsnap), and this tool reads only C -- so the entry
    # stopped suppressing anything and started waiting to cover whatever landed
    # on the same name next, which is why a stale one fails the run.
    # `kernel/memory.c`'s mem_ptr was here and went on 2026-09-06 with the
    # file: taking `struct mem`'s lock is crates/kernel/pagetable's, over
    # crates/util/wrlock. The staleness check is what reported it, which is the
    # property this dict is written to have -- an entry naming a file that no
    # longer exists fails the run rather than silently covering whatever lands
    # on the same name next.
    # `util/guestlock.c`'s guest_lock_release went the same way on 2026-09-03,
    # and `fs/proc/pid.c`'s proc_put_task before it.
}


def find_unlock_first(root):
    """Functions whose first lock-related event is an unlock.

    Deliberately narrower than "unlocks something it never locked": that catches
    every function with a lock taken in one branch and released in two, which is
    most of them, and a gate nobody can read is a gate nobody keeps.
    """
    found = []
    for path in walk_sources(root, (".c",)):
        p = str(path.relative_to(root))
        if p.startswith(("build", "tests/", ".claude/")) or "/target/" in p:
            continue
        fn, first = "?", None
        for i, line in enumerate(strip_comments(path.read_text(errors="ignore")).split("\n"), 1):
            m = FUNC.match(line.strip())
            if m and "=" not in line:
                fn, first = m.group(1), None
            for m in LOCK.finditer(line):
                if first is None:
                    first = "L"
            for m in UNLOCK.finditer(line):
                if first is None:
                    first = "U"
                    found.append((p, i, fn, normalise(m.group(2))))
    return found


def stale_allowlist(entries, label):
    """Allowlist keys naming a file that is not there any more.

    An entry records a site somebody read and justified. Once that site is gone
    the entry stops suppressing anything and starts *waiting*: it will cover
    whatever lands on the same name next, silently. `probe_diff.sh` fails a run
    for the same reason, and this is the same rule for a tool's own list.

    Two of these were stale on 2026-08-31, both naming C files that had become
    Rust crates.
    """
    stale = []
    for key in entries:
        path = key[0] if isinstance(key, tuple) else key
        root = pathlib.Path(__file__).resolve().parent.parent
        if "/" in str(path) and not (root / str(path)).exists():
            stale.append(f"{label}: {key} names {path}, which does not exist")
    return stale


def main():
    quiet = "--quiet" in sys.argv
    calls = "--calls" in sys.argv
    root = pathlib.Path(__file__).resolve().parent.parent
    edges = build_graph(root, follow_calls=calls)
    cycles = find_cycles(edges)

    if calls:
        print(f"--calls: {len(cycles)} cycles. This gates nothing; read them.\n")
        for cyc in cycles:
            known = CALL_MODE_KNOWN.get(cycle_key(cyc, edges))
            print(f"{'known' if known else 'NEW  '}    {' -> '.join(cyc)}")
            if known:
                print(f"         {known}")
            else:
                for a, b in zip(cyc, cyc[1:] + cyc[:1]):
                    print(f"    {a} then {b}: {edges[a][b]}")
            print()
        return 0

    unexplained = []
    for cyc in cycles:
        key = cycle_key(cyc, edges)
        if key in ALLOWED:
            if not quiet:
                print(f"known    {' -> '.join(cyc)}\n         {ALLOWED[key]}\n")
            continue
        unexplained.append(cyc)
        print(f"CYCLE    {' -> '.join(cyc)} -> {cyc[0]}")
        for a, b in zip(cyc, cyc[1:] + cyc[:1]):
            print(f"    {a} then {b}: {edges[a][b]}")
        print()

    unlock_first = find_unlock_first(root)
    stray = []
    for p, i, fn, name in unlock_first:
        why = UNLOCK_FIRST_OK.get((p, fn))
        if why is not None:
            if not quiet:
                print(f"known    {p}:{i} {fn}() unlocks {name} first\n         {why}\n")
            continue
        stray.append((p, i, fn, name))
        print(f"UNLOCK   {p}:{i} {fn}() releases {name} before it takes anything")

    for f in stale_allowlist(UNLOCK_FIRST_OK, "UNLOCK_FIRST_OK") + stale_allowlist(ALLOWED, "ALLOWED"):
        print(f"stale: {f}")
        stray.append(f)

    if not quiet:
        print(f"{len(edges)} locks with nesting, {len(cycles)} cycles, "
              f"{len(unexplained)} unexplained; "
              f"{len(unlock_first)} unlock-first functions, {len(stray)} unexplained")
    if unexplained:
        print("Read each one before believing it: this follows source order, "
              "not control flow. If it is not a deadlock, add it to ALLOWED "
              "with the reason.")
    if stray:
        print("A function that releases a lock it did not take is either given "
              "one by its caller -- add it to UNLOCK_FIRST_OK with the reason "
              "-- or its caller releases the same lock again, which a pthread "
              "mutex does not refuse.")
    return 1 if unexplained or stray else 0


if __name__ == "__main__":
    sys.exit(main())
