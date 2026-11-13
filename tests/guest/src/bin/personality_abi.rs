//! `personality(2)`: what it accepts and what it returns.
//!
//! Linux's implementation is four lines and has no validation in it at all:
//!
//! ```c
//! SYSCALL_DEFINE1(personality, unsigned int, personality)
//! {
//!     unsigned int old = current->personality;
//!     if (personality != 0xffffffff)
//!         set_personality(personality);
//!     return old;
//! }
//! ```
//!
//! Two consequences a caller depends on, and both were wrong here:
//!
//! - **Almost any value is accepted.** `personality(0)` is `PER_LINUX`, which
//!   is what a program resets to and what `setarch` sets on the way in. This
//!   returned `EINVAL` for everything except `ADDR_NO_RANDOMIZE`.
//! - **The return is the *old* value**, not the new one. That is the whole
//!   protocol for a save-and-restore: read what you are given, set yours, put
//!   the old one back on the way out. Returning the new value makes the restore
//!   a no-op, so a process that dropped `ADDR_NO_RANDOMIZE` around a child
//!   could never get it back.
//!
//! What this emulator actually *does* with the bits is a separate question --
//! there is no address randomisation to disable, so `ADDR_NO_RANDOMIZE` is
//! always the effective state. That does not license refusing the call.
//!
//! # The one exception, and where it came from
//!
//! aarch64 does not use the generic entry point. `arch/arm64/kernel/sys.c`:
//!
//! ```c
//! SYSCALL_DEFINE1(arm64_personality, unsigned int, personality)
//! {
//!     if (personality(personality) == PER_LINUX32 &&
//!         !system_supports_32bit_el0())
//!         return -EINVAL;
//!     return ksys_personality(personality);
//! }
//! ```
//!
//! `personality(x)` there is `((x) & PER_MASK)`, the low byte. So a request
//! whose low byte is `PER_LINUX32` is refused on a CPU with no 32-bit EL0 --
//! which Apple Silicon is, and which this emulator is: there is no 32-bit guest
//! backend to switch to. The upper bits ride along, so `ADDR_NO_RANDOMIZE |
//! PER_LINUX32` is refused too.
//!
//! That was not written from the man page, which does not mention it. It came
//! out of `differential.sh`: the first version of this file asserted the
//! generic rule and a real arm64 kernel disagreed on exactly these two.
//!
//! Docker's seccomp profile allows `personality` for five argument values and
//! answers EPERM for the rest, so this test is in the sweep's `seccomp_off`
//! list -- otherwise it measures the profile's list rather than the kernel's.

use guest_tests::{Harness, check, sys};

const PER_LINUX: u32 = 0x0000;
const PER_LINUX32: u32 = 0x0008;
const ADDR_NO_RANDOMIZE: u32 = 0x0004_0000;
const ADDR_COMPAT_LAYOUT: u32 = 0x0020_0000;
const READ_IMPLIES_EXEC: u32 = 0x0040_0000;
const QUERY: u32 = 0xffff_ffff;

fn personality(persona: u32) -> i64 {
    sys::clear_errno();
    unsafe { libc::syscall(libc::SYS_personality, persona as libc::c_ulong) as i64 }
}

fn main() {
    let mut h = Harness::new();
    h.group("personality");

    // The query. Whatever it answers is this process's personality, and every
    // check below is relative to it rather than to a constant -- the value a
    // process starts with is the kernel's business.
    let start = personality(QUERY);
    check!(
        h,
        start >= 0,
        "the query is answered rather than refused: r={start} errno={}",
        sys::errno()
    );
    if start < 0 {
        std::process::exit(h.finish());
    }
    let start = start as u32;

    // A query does not change anything: two in a row agree.
    check!(
        h,
        personality(QUERY) == start as i64,
        "and asking twice gives the same answer"
    );

    h.group("every-value-is-accepted");
    // There is no validation beyond the PER_LINUX32 rule above: a bit nothing
    // implements is stored just the same. PER_LINUX is the one that matters --
    // it is what a program sets to reset.
    for (name, want) in [
        ("PER_LINUX", PER_LINUX),
        ("ADDR_NO_RANDOMIZE", ADDR_NO_RANDOMIZE),
        ("ADDR_COMPAT_LAYOUT", ADDR_COMPAT_LAYOUT),
        ("READ_IMPLIES_EXEC", READ_IMPLIES_EXEC),
        ("ADDR_NO_RANDOMIZE|ADDR_COMPAT_LAYOUT", ADDR_NO_RANDOMIZE | ADDR_COMPAT_LAYOUT),
        // A low byte that is neither 0 nor PER_LINUX32. PER_SVR4 is 0x01, and
        // nothing implements it anywhere; it is stored regardless.
        ("PER_SVR4", 0x0001),
    ] {
        let before = personality(QUERY);
        let r = personality(want);
        check!(
            h,
            r >= 0,
            "personality({name}) is accepted: r={r} errno={}",
            sys::errno()
        );
        if r < 0 {
            continue;
        }
        check!(
            h,
            r == before,
            "and returns the *old* value, which is the whole save/restore \
             protocol: got {r:#x}, was {before:#x}"
        );
        let now = personality(QUERY);
        check!(
            h,
            now == want as i64,
            "and the new one took: {now:#x} for {name} ({want:#x})"
        );
    }

    h.group("per-linux32-is-refused");
    // The architecture rule. It is about the *low byte*, so the upper bits do
    // not exempt a request from it -- and a low byte that merely contains bit
    // 3 without being equal to PER_LINUX32 is not covered by it either.
    for (name, want) in [
        ("PER_LINUX32", PER_LINUX32),
        ("ADDR_NO_RANDOMIZE|PER_LINUX32", ADDR_NO_RANDOMIZE | PER_LINUX32),
        ("READ_IMPLIES_EXEC|PER_LINUX32", READ_IMPLIES_EXEC | PER_LINUX32),
    ] {
        let before = personality(QUERY);
        let r = personality(want);
        check!(
            h,
            r == -1 && sys::errno() == libc::EINVAL,
            "personality({name}) is EINVAL on a CPU with no 32-bit EL0: \
             r={r} errno={}",
            sys::errno()
        );
        check!(
            h,
            personality(QUERY) == before,
            "and a refusal changes nothing: {:#x} vs {before:#x}",
            personality(QUERY)
        );
    }
    // The bound of that rule: PER_LINUX32_3GB has 0x08 in the low byte too and
    // is the same refusal, but 0x09 -- one above it -- is not PER_LINUX32 and
    // is accepted. A check that only tried 0x08 would pass against an
    // implementation that refused every low byte with bit 3 set.
    let before = personality(QUERY);
    let r = personality(0x0009);
    check!(
        h,
        r == before,
        "a low byte of 0x09 is not PER_LINUX32 and is accepted: r={r:#x} errno={}",
        sys::errno()
    );

    h.group("save-and-restore");
    // The pattern the return value exists for, end to end. The value flipped is
    // an upper bit, so this cannot collide with the PER_LINUX32 refusal.
    let saved = personality(QUERY) as u32;
    let old = personality(saved ^ ADDR_NO_RANDOMIZE);
    check!(h, old == saved as i64, "the set hands back what was there: {old:#x} vs {saved:#x}");
    let restored = personality(old as u32);
    check!(
        h,
        personality(QUERY) == saved as i64,
        "and putting it back restores it: {:#x} vs {saved:#x} (restore returned {restored:#x})",
        personality(QUERY)
    );

    h.group("the-high-bits");
    // personality is `unsigned int`, and 0xffffffff is the query rather than a
    // value -- so the largest settable one is 0xfffffffe. Linux stores it
    // whole; nothing masks it down. Its low byte is 0xfe, so the PER_LINUX32
    // rule does not apply.
    let before = personality(QUERY);
    let r = personality(0xffff_fffe);
    check!(h, r == before, "0xfffffffe is a value, not a query: r={r:#x} vs {before:#x}");
    if r >= 0 {
        let now = personality(QUERY);
        check!(h, now == 0xffff_fffe, "and is stored whole: {now:#x}");
    }
    // Put it back so nothing downstream inherits a nonsense personality.
    personality(start);
    check!(h, personality(QUERY) == start as i64, "restored to what we started with");

    h.group("it-is-per-thread");
    // Linux keeps `personality` on `task_struct`, not on the signal struct: it
    // is per *thread*, so a CLONE_THREAD sibling changing its own does not
    // change this one. Here it lived on `struct tgroup`, which is the whole
    // thread group, so one thread's setarch reached every other thread.
    let mine = personality(QUERY) as u32;
    let theirs = mine ^ ADDR_COMPAT_LAYOUT;
    let t = std::thread::spawn(move || {
        let before = personality(QUERY);
        let set = personality(theirs);
        (before, set, personality(QUERY))
    });
    let (child_before, child_set, child_after) = t.join().unwrap();
    check!(
        h,
        child_before == mine as i64,
        "a new thread starts with its parent's personality: {child_before:#x} vs {mine:#x}"
    );
    check!(h, child_set >= 0, "and may set its own: r={child_set}");
    check!(
        h,
        child_after == theirs as i64,
        "which takes in that thread: {child_after:#x} vs {theirs:#x}"
    );
    check!(
        h,
        personality(QUERY) == mine as i64,
        "and leaves this thread's alone: {:#x} vs {mine:#x}",
        personality(QUERY)
    );

    std::process::exit(h.finish());
}
