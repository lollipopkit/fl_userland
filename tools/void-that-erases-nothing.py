#!/usr/bin/env python3
"""Report a `*mut c_void` parameter the body casts back on its first use.

A `c_void` in a signature says "this crate does not know what this points at".
When the body's next line is `p.cast::<T>()` for one concrete `T`, that is not
true: the erasure happens at the boundary and is undone immediately, and what it
costs is a `.cast()` at every call site — a conversion the compiler cannot check
standing in for one it can.

**31 on 2026-09-09, of which ten were fixable that day** — the descriptor
passed to `poll_wakeup`, `poll_cleanup_fd`, `fd_poll_types`, `fd_is_pipe`,
`fd_shared_mapping_gone`, `readiness_is_constant` and the four
`sockrestart_*_listen`. `crates/fs/mounttable`'s `type Mount = *mut c_void` was
the case that prompted it. Its comment said the type was opaque "because this crate reads its `point`
and its refcount through the two accessors below and nothing else", which was
true while those accessors lived in a crate it could not depend on. They moved,
and nobody revisited the alias.

## What is *not* this shape

- **A byte buffer.** `read(buf: *mut c_void, len: usize)` casting to `u8` is
  the C ABI for "some bytes", and there is no type to name. Excluded by the
  target being a primitive.
- **A table entry.** A function stored in a `#[repr(C)]` table of
  `extern "C" fn` pointers has the table's signature and cannot choose. Those
  are reported, because the *table* may be the thing to fix — three became
  traits on 2026-09-09 for exactly that reason — but they are marked.
- **A payload a container really does not know.** `crates/fs/fdtable` stores
  `*mut c_void` and calls back through an `Ops` vtable to retain and release
  it; `crates/fs/fd` is a refcount over one; `crates/fs/pollset`'s callback
  takes a context it never inspects. Those casts are in the *caller*, not here,
  so this scan does not see them — which is right.
- **A signature pinned by a struct field.** `blockcache_free` matches
  `asbestos.cache`, an opaque placeholder because `crates/kernel/abi` cannot
  name the cache. It reads as this shape and is not: typing the function
  without typing the field just moves the cast. Found by doing it and watching
  the build refuse. (`file_locks_destroy` was the other until 2026-10-01.)

Reported, not failed: telling the second and third apart from the first needs
the function read.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FN = re.compile(
    r"(?:pub(?:\([^)]*\))? )?(?:unsafe )?(?:(extern \"C\") )?fn (\w+)\s*\(([^)]*)\)",
    re.M,
)
# A cast target that is a primitive is a buffer or a scalar, not an object.
PRIMITIVE = re.compile(r"^(u8|i8|u16|i16|u32|i32|u64|i64|usize|isize|c_\w+|f32|f64)$")


def body_of(src, at):
    i = src.find("{", at)
    if i < 0:
        return ""
    depth, j = 0, i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
        j += 1
    return src[i:]


def main():
    found, buffers, total = [], 0, 0
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        src = path.read_text(errors="ignore")
        for m in FN.finditer(src):
            params = m.group(3)
            voids = re.findall(
                r"(\w+)\s*:\s*\*(?:mut|const) (?:std::ffi::)?c_void", params
            )
            if not voids:
                continue
            body = body_of(src, m.end())
            for v in voids:
                casts = set(re.findall(rf"\b{re.escape(v)}\.cast::<([\w:]+)>\(\)", body))
                if len(casts) != 1:
                    continue
                total += 1
                target = next(iter(casts))
                if PRIMITIVE.match(target.rsplit("::", 1)[-1]):
                    buffers += 1
                    continue
                found.append(
                    (
                        f"{path.relative_to(ROOT)}:{src[: m.start(2)].count(chr(10)) + 1}",
                        m.group(2),
                        v,
                        target,
                        bool(m.group(1)),
                    )
                )

    if not total:
        print("no `*mut c_void` parameter is cast to a single type anywhere, which")
        print("is either a tree that has none or a scan that stopped matching.")
        print("This check asserts its own input; see the module comment.")
        return 1

    print(f"{total} `*mut c_void` parameters cast to exactly one type in the body")
    print(f"{buffers} of those are a primitive — a byte buffer or a scalar, which is")
    print("    what `c_void` is for, and not this shape")
    print(f"{len(found)} name an object the signature could have said")
    if found:
        print()
        for where, fn, v, target, is_extern in sorted(found):
            mark = "  [extern \"C\" — may be pinned by a table]" if is_extern else ""
            print(f"  {fn}({v}: *mut c_void) -> {target}{mark}")
            print(f"      {where}")
        print()
        print("Each costs a `.cast()` at every call site. Say the type, or -- if a")
        print("`#[repr(C)]` table pins the signature -- consider whether the table")
        print("should be a trait; three became one on 2026-09-09.")
    print()
    print("Reported, not failed: see this file's header.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
