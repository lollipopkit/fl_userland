//! What `mmap` accepts, and what it does with a hint.
//!
//! Every rule here was **measured** — `tests/guest/src/bin/mmap_probe.rs` prints
//! one line per case and the same binary runs in an arm64 container, so a
//! difference is a diff rather than an argument. Four of them were differences,
//! and none of the four is what a reading of the man page suggests:
//!
//! | | Linux | was |
//! | --- | --- | --- |
//! | `mmap(0x1001, …)` without `MAP_FIXED` | maps something | `EINVAL` |
//! | `mmap(…, prot = 0x1000, …)` | maps something | `EINVAL` |
//! | `mmap(…, MAP_ANONYMOUS)` alone | `EINVAL` | mapped something |
//! | `MAP_FIXED_NOREPLACE` over a mapping | `EEXIST` | replaced it |
//!
//! The asymmetry in the first two is the point. `mmap` does **not** validate
//! `prot` and does **not** require an aligned hint; `mprotect` validates `prot`
//! and `MAP_FIXED` requires alignment. Rejecting more than Linux does is not
//! the safe direction — it is a program that works everywhere else failing
//! here.

use std::ffi::c_int;

pub use guest_errno::c_int_::{EEXIST, EINVAL};

/// `mmap` flags, from `kernel/calls.h`.
pub mod flag {
    pub const SHARED: u32 = 0x1;
    pub const PRIVATE: u32 = 0x2;
    pub const FIXED: u32 = 0x10;
    pub const ANONYMOUS: u32 = 0x20;
    pub const NORESERVE: u32 = 0x4000;
    /// `MAP_FIXED_NOREPLACE`: place it exactly there, and **fail** rather than
    /// replace what is already there.
    ///
    /// A program uses it to reserve an address range safely — the whole point
    /// is that it cannot clobber a mapping it did not know about. Unimplemented
    /// here, the flag was ignored and the mapping *was* replaced, which is
    /// worse than not supporting it: a caller that checks for `EEXIST` and gets
    /// success has been told its range was free.
    pub const FIXED_NOREPLACE: u32 = 0x100000;
}

/// `PROT_READ | PROT_WRITE | PROT_EXEC`, which is what this kernel records.
pub const PROT_RWX: u32 = 0x7;

/// Exactly one of `MAP_SHARED` and `MAP_PRIVATE`.
///
/// Both is `EINVAL` — that one was already checked. **Neither** is `EINVAL`
/// too, and was not: `mmap(NULL, len, prot, MAP_ANONYMOUS, -1, 0)` mapped
/// something here and is `EINVAL` on Linux. A caller that reaches it has left
/// out a flag it meant to pass, and getting a mapping back hides that until
/// something else goes wrong.
pub fn sharing_ok(flags: u32) -> bool {
    let shared = flags & flag::SHARED != 0;
    let private = flags & flag::PRIVATE != 0;
    shared != private
}

/// Whether `mmap` validates `prot`. **It does not.**
///
/// Linux's `arch_validate_prot` — which on aarch64 refuses anything outside
/// `PROT_READ|WRITE|EXEC|SEM|BTI|MTE` — is called from `do_mprotect_pkey` and
/// **not** from `do_mmap`. So `mmap(…, prot = 0x1000, …)` succeeds and
/// `mprotect(…, 0x1000)` is `EINVAL`, which is asymmetric and is what a real
/// kernel does. Measured both ways.
///
/// The bits this kernel does not record are dropped rather than refused: it
/// tracks read, write and execute, and a `PROT_MTE` it cannot honour is closer
/// to "ignored" than to "no such call".
pub fn prot_for_mmap(prot: u32) -> u32 {
    prot & PROT_RWX
}

/// `mprotect` **does** validate, and `EINVAL` is the answer.
pub fn prot_ok_for_mprotect(prot: u32) -> bool {
    prot & !PROT_RWX == 0
}

/// What to do with the address argument.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Placement {
    /// Exactly there, replacing whatever is in the way.
    Fixed,
    /// Exactly there, or `EEXIST`.
    FixedNoReplace,
    /// A suggestion. An unaligned one is **rounded down**, not refused: Linux's
    /// `arch_get_unmapped_area` page-aligns a hint, and a caller that passes
    /// one is not making an error.
    Hint,
}

/// Whether `madvise` knows this advice.
///
/// **Swept, not written from a header.** Every number from 0 to 31 and the
/// three above 100 were asked of a real arm64 kernel, and the set below is
/// what it accepted. `sys_madvise` accepted *everything*, so a program probing
/// for a feature — which is what `MADV_COLD` and `MADV_POPULATE_READ` callers
/// do, because the list has grown with almost every release — was told it
/// works and then got nothing.
///
/// Three of the refusals are not about the number being undefined, and are
/// worth naming so that nobody "fixes" them:
///
/// - **9, `MADV_REMOVE`.** Defined, but only for shmem and tmpfs mappings; on
///   the private anonymous mapping the sweep used it is `EINVAL`. Refusing it
///   matches that and is what this kernel can honour, since it punches no
///   holes.
/// - **12 and 13, `MADV_MERGEABLE`/`MADV_UNMERGEABLE`.** `EINVAL` without
///   `CONFIG_KSM`, which the container does not have. There is no page merging
///   here either.
/// - **100 and 101, `MADV_HWPOISON`/`MADV_SOFT_OFFLINE`.** They need
///   `CONFIG_MEMORY_FAILURE` and mark real physical pages bad. Not something
///   an emulator has.
///
/// What each accepted one does is `crates/kernel/mmapcalls`' `advise`.
pub fn advice_known(advice: u32) -> bool {
    matches!(
        advice,
        // NORMAL, RANDOM, SEQUENTIAL, WILLNEED, DONTNEED
        0..=4
        // FREE
        | 8
        // DONTFORK, DOFORK
        | 10 | 11
        // HUGEPAGE, NOHUGEPAGE, DONTDUMP, DODUMP, WIPEONFORK, KEEPONFORK,
        // COLD, PAGEOUT, POPULATE_READ, POPULATE_WRITE, COLLAPSE
        | 14..=24
        // GUARD_INSTALL and GUARD_REMOVE, added in 6.13 and accepted by the
        // container. The sweep stopped at 102, so 103 was refused until
        // 2026-11-11 and a guard could be installed and never taken away.
        | 102 | 103
    )
}

pub fn placement(flags: u32) -> Placement {
    // NOREPLACE first: a caller passes it *with* FIXED, and its refusal is the
    // stronger of the two requests. Linux's MAP_FIXED_NOREPLACE is defined to
    // include MAP_FIXED's behaviour except for the replacing.
    if flags & flag::FIXED_NOREPLACE != 0 {
        Placement::FixedNoReplace
    } else if flags & flag::FIXED != 0 {
        Placement::Fixed
    } else {
        Placement::Hint
    }
}

/// The address to place at, or `Err` with the errno.
///
/// `page_size` is a power of two. A `Hint` is rounded **down** so the caller
/// keeps a page it named; `Fixed` and `FixedNoReplace` require alignment and
/// answer `EINVAL` without it, which is Linux's rule and was applied to hints
/// as well.
pub fn resolve_addr(addr: u64, flags: u32, page_size: u64) -> Result<u64, c_int> {
    let misaligned = addr & (page_size - 1) != 0;
    match placement(flags) {
        Placement::Fixed | Placement::FixedNoReplace if misaligned => Err(EINVAL),
        Placement::Hint if misaligned => Ok(addr & !(page_size - 1)),
        _ => Ok(addr),
    }
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

/// 0 fixed, 1 fixed-no-replace, 2 a hint.
pub fn mmapabi_placement(flags: u32) -> c_int {
    match placement(flags) {
        Placement::Fixed => 0,
        Placement::FixedNoReplace => 1,
        Placement::Hint => 2,
    }
}


#[cfg(test)]
/// Non-zero if exactly one of `MAP_SHARED` and `MAP_PRIVATE` is set.
pub(crate) fn mmapabi_sharing_ok(flags: u32) -> c_int {
    sharing_ok(flags) as c_int
}

#[cfg(test)]
/// The permission bits this kernel records, from what the caller asked for.
/// `mmap` does not refuse the others.
pub(crate) fn mmapabi_prot_for_mmap(prot: u32) -> u32 {
    prot_for_mmap(prot)
}

#[cfg(test)]
/// Non-zero if `mprotect` accepts these bits. It is stricter than `mmap`.
pub(crate) fn mmapabi_prot_ok_for_mprotect(prot: u32) -> c_int {
    prot_ok_for_mprotect(prot) as c_int
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every number the sweep asked a real arm64 kernel about, with the answer
    /// it gave. Written out rather than generated, so that a change to
    /// `advice_known` has to disagree with a measurement to fail.
    const MEASURED: [(u32, bool); 36] = [
        (0, true),
        (1, true),
        (2, true),
        (3, true),
        (4, true),
        (5, false),
        (6, false),
        (7, false),
        (8, true),
        (9, false),
        (10, true),
        (11, true),
        (12, false),
        (13, false),
        (14, true),
        (15, true),
        (16, true),
        (17, true),
        (18, true),
        (19, true),
        (20, true),
        (21, true),
        (22, true),
        (23, true),
        (24, true),
        (25, false),
        (26, false),
        (27, false),
        (28, false),
        (29, false),
        (30, false),
        (31, false),
        (100, false),
        (101, false),
        (102, true),
        // mm_modern_probe: GUARD_REMOVE answers 0 on the reference kernel.
        (103, true),
    ];

    #[test]
    fn the_advice_set_is_the_one_that_was_measured() {
        for (advice, ok) in MEASURED {
            assert_eq!(advice_known(advice), ok, "advice {advice}");
        }
    }

    #[test]
    fn nothing_far_out_is_accepted() {
        // sys_madvise accepted every number there is, including -1 as an
        // unsigned word.
        for advice in [9999u32, 0x8000_0000, u32::MAX] {
            assert!(!advice_known(advice), "advice {advice}");
        }
    }

    const PAGE: u64 = 4096;

    #[test]
    fn exactly_one_of_shared_and_private() {
        assert!(sharing_ok(flag::PRIVATE));
        assert!(sharing_ok(flag::SHARED));
        assert!(sharing_ok(flag::PRIVATE | flag::ANONYMOUS));
        assert!(!sharing_ok(flag::SHARED | flag::PRIVATE), "both");
        // The one that was missing. Measured: EINVAL on Linux, a mapping here.
        assert!(!sharing_ok(flag::ANONYMOUS), "neither");
        assert!(!sharing_ok(0));
    }

    /// The asymmetry, both halves measured.
    #[test]
    fn mmap_does_not_validate_prot_and_mprotect_does() {
        assert_eq!(prot_for_mmap(0x1000), 0, "an unknown bit is dropped");
        assert_eq!(prot_for_mmap(0x1007), 0x7, "and the known ones kept");
        assert_eq!(prot_for_mmap(u32::MAX), 0x7);

        assert!(prot_ok_for_mprotect(0));
        assert!(prot_ok_for_mprotect(0x7));
        assert!(!prot_ok_for_mprotect(0x1000));
        assert!(!prot_ok_for_mprotect(u32::MAX));
    }

    #[test]
    fn a_hint_is_rounded_down_and_a_fixed_address_is_not() {
        // Measured: mmap(0x1001, PAGE) succeeds on Linux and was EINVAL here.
        assert_eq!(resolve_addr(0x1001, flag::PRIVATE, PAGE), Ok(0x1000));
        assert_eq!(resolve_addr(0x1000, flag::PRIVATE, PAGE), Ok(0x1000));
        assert_eq!(resolve_addr(0, flag::PRIVATE, PAGE), Ok(0));

        assert_eq!(
            resolve_addr(0x1001, flag::PRIVATE | flag::FIXED, PAGE),
            Err(EINVAL)
        );
        assert_eq!(
            resolve_addr(0x1000, flag::PRIVATE | flag::FIXED, PAGE),
            Ok(0x1000)
        );
    }

    #[test]
    fn no_replace_is_fixed_that_refuses() {
        assert_eq!(placement(flag::FIXED_NOREPLACE), Placement::FixedNoReplace);
        // A caller passes both; the refusal is the stronger request.
        assert_eq!(
            placement(flag::FIXED | flag::FIXED_NOREPLACE),
            Placement::FixedNoReplace
        );
        assert_eq!(placement(flag::FIXED), Placement::Fixed);
        assert_eq!(placement(0), Placement::Hint);
        // And it wants an aligned address like FIXED does.
        assert_eq!(
            resolve_addr(0x1001, flag::FIXED_NOREPLACE, PAGE),
            Err(EINVAL)
        );
    }

    #[test]
    fn the_abi_agrees_with_the_functions() {
        assert_eq!(mmapabi_sharing_ok(flag::ANONYMOUS), 0);
        assert_eq!(mmapabi_prot_for_mmap(0x1007), 7);
        assert_eq!(mmapabi_prot_ok_for_mprotect(0x1000), 0);
        assert_eq!(mmapabi_placement(flag::FIXED_NOREPLACE), 1);
        assert_eq!(resolve_addr(0x1001, flag::PRIVATE, PAGE), Ok(0x1000));
        assert_eq!(resolve_addr(0x1001, flag::FIXED, PAGE), Err(EINVAL));
    }
}
