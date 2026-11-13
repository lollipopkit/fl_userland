#!/usr/bin/env python3
"""Report syscall parameters that are narrower than the aarch64 ABI passes.

Every argument of an aarch64 syscall arrives in a 64-bit register. A `sys_*`
function that declares one `dword_t` (`uint32_t`) silently drops the top half,
and nothing warns: the syscall table casts every entry to `syscall_t`, so the
compiler never compares the declaration against the call.

That has been wrong three times, and the third was destructive:

* `sys_mmap2`'s offset overflowed at 4 GiB, so a mapping came back pointing at
  the wrong part of the file.
* `sys_mremap` took `dword_t old_len, dword_t new_len`. Two lengths whose low
  32 bits are in the opposite order to their true order turn a grow into a
  shrink, and the shrink branch unmaps the difference -- a guest asking to grow
  a five-page mapping lost two of its pages, with success reported.
* `sys_pread`/`sys_pwrite` computed `malloc(size + 1)` in 32-bit arithmetic,
  which wraps to `malloc(0)` at `0xFFFFFFFF`, and then read a file into it.

So this checks the declarations mechanically. That is **rule 1**.

**Rule 2** is the same mistake one step further in: a parameter that is declared
64 bits wide and then cast down *inside the body*, before whatever bounds it.
`prctl` had two of these on 2026-08-29 --

    int_t sig = (int_t) arg2;
    if (sig != 0 && (sig < 1 || sig > MAX_SIG)) return _EINVAL;

-- so `prctl(PR_SET_PDEATHSIG, 0x1_0000_0009)` set SIGKILL, which Linux refuses,
and `prctl(PR_SET_DUMPABLE, 0x1_0000_0001)` set SUID_DUMP_USER. The bound was
there and was correct; the cast walked around it. Rule 1 saw neither, because
both parameters are `addr_t` and right.

A cast whose statement is a trace call is skipped: formatting a value narrow is
not a bound, and two of the three sites rule 2 first reported were that.

**It is a heuristic, and it is one-sided.** It works from parameter *names*:
anything called a length, size, count or offset should be 64 bits unless it is
on the list of ones that genuinely are not. It cannot know that
`sys_getgroups(dword_t size, ...)` is right because Linux declares that one
`int` -- that has to be written down. So a clean run is not a proof, and a
report is a question, not a verdict.

`NARROW_IS_CORRECT` below is for the ones that have been checked. Each entry
carries the reason, because an allowlist without one is a way to stop looking.

**It read C until 2026-09-11, and by then it was reading nothing.** Two
independent failures, each of which left it printing a clean line and exiting 0:

* Both parameter scans globbed `kernel/**/*.[ch]` and `fs/**/*.[ch]`. Those
  directories went with the C on 2026-09-06, so rule 1 and rule 2 had no input
  for five days.
* `wired_syscalls` read `crates/kernel/syscalltable/src/lib.rs` **by path**, and
  the table moved to `table.rs` in the module split. 292 entries became 0, and
  the output went from "229 wired syscalls" to "0 wired syscalls" with nothing
  else changing.

Either one alone makes every loop below iterate over an empty set. So this now
reads Rust, and — the part that matters more than the port — **it asserts that
it found its subject**: no wired syscalls, no `sys_*` bodies, or an allowlist
key naming a parameter that does not exist is a hard failure, not a clean run.
The last of those is how the port was checked: renaming a parameter in the Rust
(`sockaddr_len` became `len`, `hostname_len` became `len`) silently orphaned
nine allowlist entries, and an orphaned entry is a suppression with nothing
under it.

Usage:  tools/syscall-abi.py [--quiet]
Exit:   0 if every narrow parameter and every in-body narrowing is
        accounted for, 1 otherwise. A failure to read the subject at all is
        also 1, with a message saying which half went silent.
"""

import pathlib
import re
import sys

# Parameter names that name a quantity of bytes, a file offset or an element
# count -- the things that are `size_t`, `off_t` or `ssize_t` in the kernel's
# own prototypes, and therefore 64-bit on aarch64.
SUSPECT = re.compile(
    r"(?:^|_)(?:len|length|size|count|offset|off|nbytes|bufsize|buflen|n)$"
)

# Types that are 32 bits wide. The first row is this tree's own guest-ABI
# aliases, which are what the C declared and what the Rust still calls them; the
# second is Rust's own spellings, which is what a migrated `sys_*` writes.
NARROW = {"dword_t", "sdword_t", "int_t", "uint_t", "fd_t", "pid_t_", "mode_t_",
          "uid_t_", "gid_t_",
          "c_int", "c_uint", "i32", "u32", "c_short", "c_ushort", "i16", "u16"}

# The ones that are narrow on purpose. Key is "function:parameter".
NARROW_IS_CORRECT = {
    # Linux declares these `int` or `unsigned int`, not size_t.
    "sys_getgroups:size": "getgroups takes an int count of gid_t, not a size.",
    "sys_setgroups:size": "setgroups likewise.",
    # `iovec_count` in the C, `count` in the Rust. The rename orphaned all six
    # of these at once and nothing said so until the orphan check existed.
    "sys_readv:count": "iovcnt is an int in Linux's prototype.",
    "sys_writev:count": "iovcnt is an int.",
    "sys_preadv:count": "iovcnt is an int.",
    "sys_pwritev:count": "iovcnt is an int.",
    "sys_preadv2:count": "iovcnt is an int.",
    "sys_pwritev2:count": "iovcnt is an int.",
    "sys_getdents64:count": "Linux takes an unsigned int here.",
    # Every sigsetsize is `addr_t` now: sigset_size_valid requires exactly
    # sizeof(sigset_t_), and a 32-bit parameter would let 0x100000008 truncate
    # into passing it.
    "sys_clone3:size": "clone_args size, checked against the struct's own size.",
    "sys_sched_getaffinity:cpusetsize": "Refused unless it covers the reported "
                                        "cpu count, which is capped at 64.",
    "sys_sched_setaffinity:cpusetsize": "Same cap.",
    "sys_lseek64:whence": "`whence` matches the name pattern by accident: it is "
                          "an int, and is not an offset.",
    # `sys_lseek` and `sys__llseek` were the i386 table's; the aarch64 table
    # wires 62 to `sys_lseek64` and neither of the other two exists. Their four
    # entries were deleted rather than renamed.
    "sys_preadv:pos_l": "The arm64 5-argument form splits loff_t across "
                        "pos_l/pos_h; the callee recombines them.",
    "sys_preadv:pos_h": "The other half.",
    "sys_pwritev:pos_l": "Same split.",
    "sys_pwritev:pos_h": "Same split.",
    "sys_preadv2:pos_l": "Same split.",
    "sys_preadv2:pos_h": "Same split.",
    "sys_pwritev2:pos_l": "Same split.",
    "sys_pwritev2:pos_h": "Same split.",
    "sys_getrandom:len": "Linux caps getrandom at INT_MAX and returns a short "
                         "read above it; a 32-bit count cannot ask for more "
                         "than that cap.",
    "sys_setsockopt:value_len": "optlen is a socklen_t, which is 32 bits.",
    "sys_bind:len": "socklen_t.",
    "sys_connect:len": "socklen_t.",
    "sys_sendto:sockaddr_len": "socklen_t.",
    "sys_recvmmsg:vec_len": "vlen is an unsigned int in Linux's prototype.",
    "sys_sendmmsg:vec_len": "vlen is an unsigned int.",
    "sys_readlinkat:bufsize": "Linux declares bufsiz `int` for this one, "
                              "unlike most buffer sizes.",
    "sys_sethostname:len": "Linux declares len `int` -- `SYSCALL_DEFINE2("
                           "sethostname, char __user *, name, int, len)`. The "
                           "`size_t` in the man page is glibc's wrapper, not "
                           "the syscall.",
    "sys_setdomainname:len": "Linux declares len `int`, as sethostname's.",
    "sys_syslog:len": "Linux declares len `int`.",
    "sys_sched_getattr:size": "Linux declares usize `unsigned int`.",
    "sys_lsm_set_self_attr:size": "Linux declares size `u32`.",
    "sys_mq_timedsend:prio": "Linux declares msg_prio `unsigned int`; "
                             "mqueue_probe measured a priority of 1 << 32 "
                             "accepted as 0.",
}

# ---------------------------------------------------------------- rule 2
#
# The declaration being 64 bits wide is not the end of it: a body can narrow the
# argument itself, and then the bound check is against a value the guest did not
# pass. Both of these were live on 2026-08-29, in one file, and both were
# reachable by any guest:
#
#   int_t sig = (int_t) arg2;               // prctl(PR_SET_PDEATHSIG)
#   if (sig != 0 && (sig < 1 || sig > MAX_SIG)) return _EINVAL;
#
# `prctl(PR_SET_PDEATHSIG, 0x1_0000_0009)` is SIGKILL after that cast, and Linux
# refuses it. The stored number is then handed to send_signal, which indexes
# sighand->action[sig] -- so the cast walked around a bound that existed and was
# correct. PR_SET_DUMPABLE had the identical shape.
#
# Rule 1 above could not see either, because `arg2` is `addr_t` and right.
#
# **It found two more the first time it was run against Rust**, on 2026-09-11,
# and they are the other half of the shape: not a bound walked around, but a
# *quantity* silently divided. `sys_copy_file_range` and `sys_splice` take a
# `size_t` length -- 64 bits on aarch64 -- and handed it to a transfer loop
# that counts in `u32`:
#
#     let total = copy_between(&in_fd, ..., len as u32);
#
# A length of exactly 2^32 is zero after that, so the call reported that it had
# moved **nothing**, which is the end-of-file answer: a caller draining a file
# in a loop stops on its first pass, with success. Measured against an arm64
# container, which copies the whole file for the same call. Both are clamped on
# the 64-bit value now (`rwabi::copy_file_range_len`, `rwabi::splice_count`),
# and neither is in NARROWING_OK, because the cast they were reported for is
# gone.

# Casts that drop the top half. `long` is 64 bits on every target here and is
# not one of them.
NARROWING_CAST = NARROW | {
    "int", "unsigned", "unsigned int", "signed int", "int32_t", "uint32_t",
    "short", "unsigned short", "int16_t", "uint16_t", "char", "signed char",
    "unsigned char", "int8_t", "uint8_t", "float",
    # Rust's own, for `x as u32`. `usize` and `isize` are 64 bits on every
    # target this builds for and are not narrowings.
    "i8", "u8", "c_char", "c_uchar", "c_schar", "f32",
}

# A cast that only reaches a format string is not a bound, and two of the three
# this rule first reported were exactly that. Excluded rather than allowlisted:
# an entry per printf is a way to stop reading the output.
#
# The `_?` is load-bearing and the ordering would be: written as
# `STRACE|TRACE|TRACE_`, Python takes the first alternative that matches, so
# `TRACE` wins against `TRACE_(sock, ...)` and then `\s*\(` fails against the
# underscore -- and every TRACE_ call in fs/sock.c was reported.
PRINTING = re.compile(
    r"^(?:STRACE|TRACE_?|printk|fprintf|printf|snprintf"
    r"|strace!|trace!|format!|write!|writeln!|println!|eprintln!)\s*\("
)

# Read, and not a defect. Key is "function:parameter".
#
# There are two shapes here and they are not the same claim:
#
# * **Linux narrows it too.** The kernel's own prototype takes 32 bits, so the
#   top half of the register was never part of the value and a cast loses
#   nothing a guest could have meant. Quote the `SYSCALL_DEFINE*` or the
#   function it hands the argument to -- not the man page, which describes
#   glibc's wrapper: `sethostname` is `int` in the syscall and `size_t` in the
#   page, and that trap is why NARROW_IS_CORRECT says so above.
# * **The bound is above the cast.** The argument is judged at its full width
#   first, so by the time it is narrowed the top half is known to be zero.
#   `sys_ptrace:data` is the clean example and `sys_sendfile64:count` is the
#   other.
#
# Every entry here was checked against an arm64 container on 2026-09-11 as well
# as read, and the probe line is named so the next reader can re-run one. The
# reading alone would have been enough for those five and was **not** enough
# for the two that are missing: `copy_file_range` and `splice` read exactly
# like `sendfile`, one clamp looked like the answer for all three, and a real
# kernel gave three different ones -- the third refuses nothing at all.
NARROWING_OK = {
    # The clamp is on the line above the cast: `if (count > MAX_RW_COUNT_)
    # count = MAX_RW_COUNT_;`, which is what Linux does to every read and write
    # length, and MAX_RW_COUNT_ is well inside 32 bits. So the cast cannot lose
    # anything by the time it happens.
    "sys_sendfile64:count": "Clamped to MAX_RW_COUNT_ before the cast.",
    # `SYSCALL_DEFINE4(vmsplice, ..., unsigned long, nr_segs, ...)` hands it to
    # `import_iovec(..., unsigned nr_segs, ...)`. Measured by rarecalls_probe:
    # `1 << 32 | 1` segments is one segment on a real arm64 kernel.
    "sys_vmsplice:nr_segs": "Linux's `import_iovec` takes the count as an "
                            "`unsigned int`; `1 << 32 | 1` is one segment there.",
    # `sys_copy_file_range:len` and `sys_splice:count` were reported here on
    # 2026-09-11 and are **not** in this list: they were defects, the cast is
    # gone, and an entry for a cast that no longer exists would suppress
    # whatever lands on that parameter next. The rule-2 docstring above records
    # what they were.
    #
    # `do_fcntl` opens with `int argi = (int)arg;` and gives *that* to every
    # command that wants a number -- `f_dupfd(argi, ...)`, `setfl(fd, filp,
    # argi)`, `f_setown(filp, argi, 1)`, `valid_signal(argi)`,
    # `pipe_fcntl(filp, cmd, argi)`, `memfd_fcntl(filp, cmd, argi)` and
    # `f_dupfd_query(argi, filp)`, which is the one this rule reports. Only the
    # commands whose argument is a *pointer* see the whole word, and those take
    # no cast here. Measured: fcntl_probe's four `(1 << 32) | x` cases answer
    # exactly as the plain `x` ones on a real arm64 kernel.
    "sys_fcntl:arg": "Linux's `do_fcntl` truncates the whole argument once -- "
                     "`int argi = (int) arg;` -- and every numeric command "
                     "reads argi.",
    # For the WAIT operations this argument is a pointer and is used whole; for
    # REQUEUE, CMP_REQUEUE and WAKE_OP it is a count, and the syscall hands it
    # to `do_futex(u32 __user *uaddr, int op, u32 val, ktime_t *timeout, u32
    # __user *uaddr2, u32 val2, u32 val3)` -- `val2` is a u32, so Linux drops
    # the top half before anything looks at it. Measured: futex_probe's
    # `count=0x8000_0000` and `count=0x1_8000_0000` are both EINVAL on a real
    # kernel, which is the same answer and so is the narrowing itself.
    #
    # What the narrowing does *not* excuse is what happens after it:
    # `futex_requeue` reads both counts as `int` and refuses a negative one,
    # and this kernel did not. Fixed separately --
    # docs/changelog/2026-09-11-a-requeue-count-that-was-never-signed.md.
    "sys_futex:timeout_or_val2": "Linux's `do_futex` declares val2 `u32`, so "
                                 "the count operations never see more than 32 "
                                 "bits either.",
    # `ptrace_request` hands `addr` to `ptrace_regset(struct task_struct *task,
    # int req, unsigned int type, struct iovec *kiov)`, so the note type is 32
    # bits there too. Signed here and unsigned there makes no difference: the
    # only values that match are NT_PRSTATUS and NT_FPREGSET, 1 and 2.
    # Measured: `GETREGSET((1 << 32) | NT_PRSTATUS)` succeeds on a real kernel,
    # where a note type nobody has is EINVAL.
    "sys_ptrace:addr": "Linux's ptrace_regset takes the note type as an "
                       "`unsigned int`.",
    # The other shape: the bound is *above* the cast. `PTRACE_SETOPTIONS` is
    # the only arm that narrows `data`, and `options_valid` judges the whole
    # 64-bit word first -- which is exactly what `ptrace_setoptions` does, `if
    # (data & ~(unsigned long)PTRACE_O_MASK) return -EINVAL;`. So a bit above
    # 32 is refused rather than dropped, and the cast that follows cannot lose
    # one. Measured: `SETOPTIONS((1 << 32) | TRACESYSGOOD)` is EINVAL on both
    # sides. Every other arm uses `data` whole, as an address or a signal
    # number bounded at 64.
    "sys_ptrace:data": "options_valid refuses any bit outside the honoured set "
                       "at full width, before the cast -- Linux's "
                       "ptrace_setoptions has the same line.",
    # The fourth argument of semctl is a `union semun`, whose `val` member is
    # an `int`; `ksys_semctl` spells that `int val = (int) arg;` and only
    # SETVAL reads it as a number at all. Every other command treats it as a
    # pointer and takes no cast here. Measured: `SETVAL (1 << 32) | 7` sets 7
    # on a real arm64 kernel and `(1 << 32) | 0xffff_ffff` is the same ERANGE
    # as a plain -1.
    "sys_semctl:arg": "Linux's `ksys_semctl` reads SETVAL's argument as "
                      "`int val = (int) arg;` -- the semun union's member is "
                      "an int.",
}

BODY = re.compile(r"\bfn\s+(sys_\w+)\s*\(([^)]*)\)[^{;]*\{", re.S)


COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def strip_comments(text):
    """Comments blanked, keeping every offset and newline.

    Needed by both halves of rule 2: a cast written in a comment is not a cast,
    and -- the one that actually bit -- the statement a cast belongs to is found
    by walking back to the previous `;`, `{` or `}`, which lands in the comment
    block above it. Every TRACE_ call in fs/sock.c has such a block, so the
    trace exclusion silently did nothing for all of them. Rust makes that worse
    rather than better: this tree's convention is a long `//` block above the
    function and above most statements inside it.
    """
    return COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def function_bodies(text):
    """sys_* name -> (params text, body text)."""
    text = strip_comments(text)
    out = {}
    for m in BODY.finditer(text):
        depth, start = 0, m.end() - 1
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    out[m.group(1)] = (m.group(2), text[start:i + 1])
                    break
    return out


def narrowed_in_body(name, params, body):
    """Parameters declared 64-bit and cast down to 32 or fewer inside.

    The cast is `x as u32` here, where the C was `(uint32_t) x`. Same rule, and
    the same exclusion for a cast that only reaches a format string.
    """
    wide = [n for t, n in params if t not in NARROW]
    found = []
    for pname in wide:
        for cm in re.finditer(
            rf"\b{re.escape(pname)}\s+as\s+([A-Za-z_]\w*)\b",
            body,
        ):
            if cm.group(1) not in NARROWING_CAST:
                continue
            # The statement this cast is in. A cast whose statement is a trace
            # call is a formatting decision, not a bound.
            head = max(body.rfind(c, 0, cm.start()) for c in ";{}")
            if PRINTING.match(body[head + 1:].lstrip()):
                continue
            found.append((pname, cm.group(1)))
            break
    return found


DECL = re.compile(r"\bfn\s+(sys_\w+)\s*\(([^)]*)\)", re.S)


def split_params(plist):
    """`a: T, b: U` -> [(T, a), (U, b)], pointers and references dropped.

    A pointer parameter is an address and is 64 bits whatever it points at, so
    it is not this check's subject; the C version dropped them by looking for a
    `*` and this drops `*const`, `*mut` and `&`.
    """
    got = []
    for part in plist.split(","):
        if ":" not in part:
            continue
        pname, ptype = part.split(":", 1)
        ptype = ptype.strip()
        if ptype.startswith(("*", "&")):
            continue
        # `std::ffi::c_int` and `ffi::dword_t` name the same types their last
        # segment does, and a generic's parameters are not its width.
        ptype = ptype.split("<")[0].strip().rsplit("::", 1)[-1]
        got.append((ptype, pname.strip().lstrip("_")))
    return got


def parse_params(text):
    """Function name -> [(type, name)], from Rust `fn sys_*` signatures."""
    out = {}
    for m in DECL.finditer(text):
        name, got = m.group(1), split_params(m.group(2))
        # A crate defines the function and others may re-export it; keep
        # whichever signature parsed the most parameters.
        if name not in out or len(got) > len(out[name]):
            out[name] = got
    return out


def wired_syscalls(root):
    """The names the aarch64 table actually dispatches to.

    An unwired `sys_*` cannot be called by a guest, so a narrow parameter on one
    is dead code rather than a defect -- and this tree has had six of those.

    **Every file of the crate, not one named file.** Reading `lib.rs` by path is
    what made this return the empty set when the table moved to `table.rs`, and
    the caller could not tell that from a table with no entries.

    The entry macro is matched as `at` plus any suffix, because `at_res!` --
    the shim that turns a `Result`-answering implementation into the table's
    six-argument form -- is a second spelling of the same line.
    """
    src = root / "crates" / "kernel" / "syscalltable" / "src"
    table = "".join(p.read_text() for p in sorted(src.glob("*.rs")))
    return set(re.findall(r"\bat\w*!\(\s*t,\s*[\d.=]+,\s*(sys_\w+)", table))


def main():
    quiet = "--quiet" in sys.argv
    root = pathlib.Path(__file__).resolve().parent.parent
    wired = wired_syscalls(root)

    sources = [p for p in sorted(root.glob("crates/**/*.rs"))
               if "/target/" not in str(p)]

    params = {}
    bodies = {}
    for path in sources:
        text = path.read_text(errors="ignore")
        for name, got in parse_params(text).items():
            if name not in params or len(got) > len(params[name]):
                params[name] = got
        for name, pair in function_bodies(text).items():
            if name in wired and (name not in bodies
                                  or len(pair[1]) > len(bodies[name][1])):
                bodies[name] = pair

    # The assertion that makes a clean run mean something. Each of these was a
    # real state of this file: an empty table (the module split moved it), and
    # an empty source list (the glob named the deleted C directories).
    if not wired:
        print("FAIL     no wired syscalls found -- the table moved or the entry "
              "macro was renamed. Every check below would pass vacuously.")
        return 1
    if not params:
        print("FAIL     no `sys_*` signatures found in crates/ -- this check "
              "reads nothing and cannot report anything.")
        return 1
    if not bodies:
        print("FAIL     no `sys_*` bodies found in crates/ -- rule 2 reads "
              "nothing.")
        return 1

    # An allowlist key naming a parameter that no longer exists suppresses
    # nothing, and reads as a check that passed. Nine went stale at once when
    # the Rust renamed `sockaddr_len` to `len` and `iovec_count` to `count`.
    live = {f"{n}:{pn}" for n in wired for _, pn in params.get(n, [])}
    orphans = sorted((set(NARROW_IS_CORRECT) | set(NARROWING_OK)) - live)
    if orphans:
        for key in orphans:
            print(f"ORPHAN   {key} is allowlisted and no such parameter exists")
        print(f"{len(orphans)} allowlist entries name a parameter that is not "
              f"there. Each is a suppression with nothing under it: rename it "
              f"to match, or delete it if the syscall went.")
        return 1

    findings = []
    for name in sorted(wired):
        for ptype, pname in params.get(name, []):
            if ptype not in NARROW or not SUSPECT.search(pname):
                continue
            key = f"{name}:{pname}"
            if key in NARROW_IS_CORRECT:
                if not quiet:
                    print(f"known    {key} ({ptype})\n         {NARROW_IS_CORRECT[key]}\n")
                continue
            findings.append((key, ptype))

    # Rule 2: a wide parameter narrowed by a cast in the body.
    narrowings = []
    for name in sorted(bodies):
        ptext, body = bodies[name]
        for pname, cast in narrowed_in_body(name, split_params(ptext), body):
            key = f"{name}:{pname}"
            if key in NARROWING_OK:
                if not quiet:
                    print(f"known    {key} cast to {cast}\n         {NARROWING_OK[key]}\n")
                continue
            narrowings.append((key, cast))

    for key, ptype in findings:
        print(f"NARROW   {key} is {ptype}, but aarch64 passes 64 bits")
    for key, cast in narrowings:
        print(f"NARROWED {key} arrives 64-bit and is cast to {cast} inside "
              f"-- any bound checked after that is not the guest's value")
    if not quiet:
        print(f"{len(wired)} wired syscalls, {len(findings)} narrow parameters "
              f"and {len(narrowings)} in-body narrowings unexplained")
    if narrowings and not findings:
        print("Each one is a question: does Linux also treat this argument as "
              "32-bit? If it does, add it to NARROWING_OK with the reason. If "
              "it does not, a guest can pass a value that is refused on Linux "
              "and accepted here.")
    if findings:
        print("Each one is a question: is the kernel's own prototype 32-bit "
              "here? If it is, add it to NARROW_IS_CORRECT with the reason. If "
              "it is not, the top half of a guest argument is being dropped.")
    return 1 if (findings or narrowings) else 0


if __name__ == "__main__":
    sys.exit(main())
