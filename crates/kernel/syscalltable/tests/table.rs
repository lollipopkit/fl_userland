//! The three checks that read `SYSCALL_TABLE`'s own relocations.
//!
//! A `static` of function pointers is a set of relocations, so a test that only
//! counts entries still has to link all 232 of them -- and they pull in the
//! rest of the kernel. This crate carried 232 `#[no_mangle]` doubles instead
//! until 2026-09-08, because "a test binary links no C and no other crate".
//!
//! An **integration** test rather than a `#[cfg(test)] mod`, because
//! `cargo test --lib` compiles the crate under test a second time -- once with
//! `cfg(test)` and once as the product's dependency -- and every `#[no_mangle]`
//! in it is then a duplicate symbol that `ld` picks between. A `tests/` binary
//! links the plain rlib and cargo unifies it with the one its dependencies use.
//!
//! The two checks that need no link -- the name test the reported flag is built
//! from, and the seven wide returns -- are in the crate's own module.

// The product, so the relocations resolve and the assertions are about the real
// implementations. `_` because nothing here calls them: an `--extern` nothing
// mentions is not loaded, so a dev-dependency alone leaves the link as it was.
use asbestos_gadgets as _;
use iul as _;

use syscalltable::{REPORTED_STUB, SYSCALL_TABLE, SYSCALL_TABLE_SIZE};

/// The gap Linux leaves, and the two ends. A table whose numbering slipped
/// would still build — every `at!` names its own index — so what is worth
/// asserting is that a few known numbers land where they should.
#[test]
fn the_ends_and_the_gap() {
    assert!(SYSCALL_TABLE[0].is_some(), "io_setup is a stub, not absent");
    assert!(SYSCALL_TABLE[449].is_some(), "futex_waitv is the last one");
    for (n, entry) in SYSCALL_TABLE.iter().enumerate().skip(244).take(16) {
        assert!(entry.is_none(), "{n} is in Linux's gap");
    }
    assert_eq!(SYSCALL_TABLE.len(), SYSCALL_TABLE_SIZE);
}

/// Every number outside the gap has an implementation. The C left the same
/// entries null and the dispatcher answers `ENOSYS` for them, so this is a
/// statement about what the table *covers*, not about correctness — and it
/// is the assertion that a whole block accidentally deleted would fail.
#[test]
fn nothing_outside_the_gap_is_missing() {
    let missing: Vec<usize> = (0..SYSCALL_TABLE_SIZE)
        .filter(|n| !(244..=259).contains(n) && SYSCALL_TABLE[*n].is_none())
        .collect();
    assert!(missing.is_empty(), "no implementation at {missing:?}");
}

/// The `at_res!` boundary, end to end, through the table's own entry.
///
/// `crates/kernel/fdcalls` answers `Result<T, Errno>` and this is the only
/// place that turns one into a number. What is being checked is the whole of
/// that path -- the shim `at_res!` generated, the entry's coercion to
/// [`Syscall`], the six-register call and `answer` -- against the number
/// `close_range` answered before the conversion, which is `-EINVAL`.
///
/// Both cases refuse before touching the calling task, which is what makes
/// them callable from a test binary with no guest booted. Backed out by
/// changing `Errno::EINVAL` to `Errno::EPERM` in `sys_close_range`, which
/// turns this red and nothing else in the workspace.
#[test]
fn a_result_answering_syscall_reaches_the_guest_as_a_negative_number() {
    let close_range = SYSCALL_TABLE[436].expect("close_range is implemented");
    // first > last.
    let r = close_range(5, 1, 0, 0xdead, 0xbeef, 0xf00d);
    assert_eq!(r, -22, "close_range(5, 1, 0)");
    // A flag bit this kernel does not have. Passing the registers junk in the
    // three the implementation does not declare is deliberate: the shim
    // declares all six and hands on exactly its own arity, so the junk has to
    // go nowhere. Until 2026-09-12 the shim declared three and the entry was a
    // `transmute`, and what made the other three harmless was AArch64 rather
    // than the signature.
    let r = close_range(0, 1, 0x8, u64::MAX, u64::MAX, u64::MAX);
    assert_eq!(r, -22, "close_range(0, 1, CLOSE_RANGE_UNKNOWN)");
}

/// A stub entry is called with six registers too, and answers `-ENOSYS`.
///
/// `at!`'s targets take no argument at all, so before 2026-09-12 a stub entry
/// was the *most* erased thing in the table: a `fn() -> u32` transmuted to a
/// six-argument `Syscall` and called as one. What made that sound was AAPCS64.
/// The shim declares the six now and this checks the whole of it -- the
/// coercion, the six-register call, and the `u32` widening `SyscallValue`
/// performs -- through the number the dispatcher would hand a guest.
///
/// 449 is `futex_waitv` and is a `syscall_stub`; 293 is `rseq` and is a
/// `syscall_silent_stub`. Both answer `-ENOSYS`: which of the two a number gets
/// changes only whether the dispatcher reports it, which
/// [`the_reported_stubs_are_the_numbers_that_ask_to_be`] covers.
///
/// Backed out by dropping one `_` from `at!`'s shim, which stops the crate
/// compiling, or by making `syscall_stub` answer something other than `ENOSYS`,
/// which turns this red alone.
#[test]
fn a_stub_entry_answers_enosys_through_six_registers() {
    for n in [471usize, 293] {
        let stub = SYSCALL_TABLE[n].expect("a stub is an entry, not an absence");
        let r = stub(u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX);
        // `-ENOSYS` as the dispatcher reads it: `SyscallValue for u32`
        // zero-extends, so the 64 bits are what the narrowing arm then reads
        // back as -38.
        assert_eq!(r as i32, -38, "syscall {n}");
    }
    // And the one deliberate success stub, `sync`.
    let sync = SYSCALL_TABLE[81].expect("sync is a success stub");
    assert_eq!(
        sync(u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        0
    );
}

/// The flag is a fact about the *number*, and these are the numbers.
///
/// It used to be read off the entry's address, and a release link folded
/// `syscall_stub` and `syscall_silent_stub` into one — so every silent stub
/// reported. That cannot be tested by comparing the two functions here,
/// because a test binary is not the release link; what is testable is that
/// the table says the right thing about each number, which is what the
/// dispatcher now asks.
#[test]
fn the_reported_stubs_are_the_numbers_that_ask_to_be() {
    // `syscall_stub`: a call nothing here answers and nothing falls back
    // from, so a guest reaching one is worth a line.
    // 190 was here until 2026-09-08, when `semget` was implemented -- the
    // list has to be numbers that are *still* stubs, so it names ones with
    // no prospect of an implementation rather than the next family to be
    // written: 41 `pivot_root`, 471 `rseq_slice_yield`. (0 `io_setup`, 449
    // `futex_waitv`, 437 `openat2` and 277 `seccomp` were here until they were
    // implemented on 2026-11-11, and 58 `vhangup` until 2026-11-12; 219
    // `keyctl` became `not_configured`, and so did 104 `kexec_load` and 273
    // `finit_module` once rarecalls_probe measured what the reference is built
    // with.)
    for n in [471] {
        assert!(REPORTED_STUB[n], "{n} is a reported stub");
    }
    // `not_configured`: ENOSYS on purpose, a decision rather than a gap, and
    // so not reported -- 280 `bpf`,
    // 104 `kexec_load`, 273 `finit_module`, 89 `acct`, 18 `lookup_dcookie`.
    for n in [280, 104, 273, 89, 18] {
        assert!(!REPORTED_STUB[n], "{n} is not configured, not a stub");
    }
    // `syscall_silent_stub`: a libc probes and falls back. 293 is `rseq`,
    // which every glibc program calls at startup. (441, `epoll_pwait2`, was
    // here until it was implemented on 2026-11-11.)
    for n in [293, 440] {
        assert!(!REPORTED_STUB[n], "{n} is a silent stub");
    }
    // An implemented syscall is neither -- including the four families
    // written on 2026-09-07/08: 190 semget, 186 msgget, 270
    // process_vm_readv, 5 setxattr.
    for n in [63, 64, 172, 222, 190, 186, 270, 5, 41, 217, 219, 262, 263, 288, 289, 290, 425, 426, 427, 428, 429, 430, 431, 432, 433, 442, 444, 445, 446, 467] {
        assert!(!REPORTED_STUB[n], "{n} is implemented");
    }
    // And the gap Linux left: no entry, so nothing to report.
    assert!(!REPORTED_STUB[250]);
}
