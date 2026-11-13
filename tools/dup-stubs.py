#!/usr/bin/env python3
"""Report `#[cfg(test)]` stubs that duplicate a symbol a real dependency defines.

A crate whose code reached another crate through the C ABI needed a `#[no_mangle]`
stub in its test build to stand in for the other end. Converting those calls to
Rust made the other crate a real dependency — so its `#[no_mangle]` definition is
now *in the same link* as the stub, and there are two definitions of one symbol.

**The linker does not stop.** On macOS this is a warning, surfaced by rustc's
`linker_messages` lint and otherwise invisible: `ld` picks one definition and the
test binary runs. Which one it picks is not something the source says. So a test
can be exercising a stub that answers `Default::default()` where it means to
exercise the implementation, or the reverse — and it passes either way, which is
the failure mode `CLAUDE.md` calls "a test that passes against nothing".

Fifty-five of them across twelve crates on 2026-09-06, found by reading a link
log while chasing something else. Nothing had ever looked.

## What this does not decide

Not every duplicate should be deleted. Three shapes, and the tool reports rather
than fails because telling them apart needs the test read:

- **Link filler.** The stub exists so the binary links and nothing calls it.
  Delete it; the real definition was going to be linked anyway.
- **A driven double.** The test calls the stub itself and asserts on what it
  recorded — `crates/kernel/fsinfo`'s `fd_retain` counts references against fake
  pointers 1, 2 and 3, which the real one would dereference. Deleting it breaks
  the test, and *keeping* it is only right if the code under test actually
  reaches it.
- **A stub whose removal pulls in more graph than the test wants.**
  `crates/fs/tty`'s `guest_lock_*` set is this: the real `util-guestlock` needs
  `sighand_interrupts_a_wait`, which nothing in that test link provides.

Run it after converting a C ABI call to a Rust call, which is when a duplicate
appears:

    cargo test --workspace --no-run 2>&1 | python3 tools/dup-stubs.py
"""

import json
import re
import subprocess
import sys

# `ld: duplicate symbol '_foo' in:` then two object-file paths, one per line.
DUPLICATE = re.compile(r"duplicate symbol '_(\w+)' in:\n\s+(\S+)\n\s+(\S+)")
# `.../deps/libfs_mount-2ab88f5ee770f8dc.rlib[19](...)` or `.../deps/proc-<hash>.<...>.o`
MEMBER = re.compile(r"deps/(?:lib)?(\w+?)-[0-9a-f]{16}")


def crate_dirs():
    """Library target name -> the directory its sources are in."""
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True, text=True, check=True,
    ).stdout
    dirs = {}
    for pkg in json.loads(out)["packages"]:
        for target in pkg["targets"]:
            if {"lib", "rlib"} & set(target["kind"]):
                dirs[target["name"]] = target["src_path"].rsplit("/", 1)[0]
    return dirs


def main():
    log = sys.stdin.read()
    if not log.strip():
        print("nothing on stdin: pipe `cargo test --workspace --no-run 2>&1` in")
        return 2

    # The first object file is the one being linked -- the test binary's own
    # crate; the second is the rlib that also defines it.
    found = {}
    for symbol, mine, theirs in DUPLICATE.findall(log):
        who = MEMBER.search(mine)
        them = MEMBER.search(theirs)
        found.setdefault(who.group(1) if who else mine, {})[symbol] = (
            them.group(1) if them else theirs
        )

    if not found:
        # Say what was looked at. A clean run that examined nothing reads the
        # same as a clean run that examined everything, which is the shape
        # `CLAUDE.md` records three of.
        links = len(re.findall(r'"-o" "[^"]*deps/', log)) or log.count("Compiling")
        print(f"no duplicate symbols across {links} link steps")
        return 0

    dirs = crate_dirs()
    total = sum(len(v) for v in found.values())
    print(f"{total} duplicate symbols in {len(found)} test binaries\n")
    for crate in sorted(found):
        where = dirs.get(crate, "?")
        print(f"{crate}  ({where})")
        for symbol, owner in sorted(found[crate].items()):
            print(f"    {symbol:38} also defined by {owner}")
        print()
    print("Reported, not failed: see this file's header for the three shapes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
