//! How many anonymous pages a guest may have mapped, and how many it has.
//!
//! A cap on host memory, so that a guest which maps until it stops gets
//! `ENOMEM` rather than the host being killed — on iOS by jetsam, which gives
//! no warning and produces no crash report an embedder can read.
//!
//! # Why it lives here and not with `mmap`
//!
//! It was `crates/kernel/mmapcalls`', because `sys_mmap` is what refuses. But
//! the *charge* is [`crate::pt_map_nothing`]'s and the refund is
//! [`crate::pt_unmap_always`]'s — this crate is the one place an anonymous page
//! is created and the one place it is destroyed, which is what keeps the two
//! from getting out of step. With the counter in `mmapcalls` the dependency
//! ran the wrong way: the page table called *up* into the syscall layer for
//! every page it mapped, and once that call was a Rust call rather than a C
//! one, cargo reported it as the cycle it had always been.
//!
//! `sysinfo`'s `freeram` and `/proc/meminfo`'s `MemFree` are derived from
//! [`anon_pages_used`], and neither can see the compile-time switch, which is
//! why it answers -1 rather than 0 when the accounting is off.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Zero when the accounting is not compiled in.
/// The cap on anonymous mmap pages across **all** processes, in 4 KiB pages.
///
/// It exists to keep an iOS app from being killed by jetsam, which is a
/// host-side limit rather than anything a guest can see. 1048576 pages is 4 GiB;
/// the number was 524288 (2 GiB) and the Go runtime alone needs about 1.1 GiB of
/// `PROT_NONE` page-summary reservations, so a Go program hit it. 0 would mean
/// no limit.
const LIMIT: i64 = crate::ffi::ANON_MMAP_LIMIT_PAGES as i64;

/// A counter and its cap.
///
/// Separate from the process-wide [`ANON`] so that a test can make one with a
/// small limit and drive the real functions. The test that used to cover this
/// re-implemented the comparison beside the code it was checking — it asserted
/// `used + want > limit` in its own arithmetic, so it would have passed against
/// an off-by-one in [`Budget::would_fit`], which is the whole question.
pub struct Budget {
    used: AtomicI64,
    limit: i64,
    /// How often [`Budget::would_fit`] has said no.
    ///
    /// A refusal is **silent from the guest's side**: `brk` answers the current
    /// break and `mmap` answers `ENOMEM`, which is what a guest that genuinely
    /// ran out of address space gets, so nothing distinguishes "this emulator's
    /// cap" from "the guest asked for too much". That mattered once --
    /// `rpmkeys` could not load `librpm.so.9` in a `full.sh` run and there was
    /// no way to tell which. `/proc/iul/objects` reports it.
    refused: AtomicU64,
}

impl Budget {
    pub const fn new(limit: i64) -> Self {
        Self {
            used: AtomicI64::new(0),
            limit,
            refused: AtomicU64::new(0),
        }
    }

    /// Would `pages` more fit?
    ///
    /// **A question, not a charge.** The charge is [`Budget::add`]'s, made by
    /// `pt_map_nothing` once the page exists. Asking here and charging there is
    /// what makes the two impossible to get out of step: it used to charge, and
    /// the callers that mapped without asking — the ELF loader's five — were
    /// refunded anyway.
    ///
    /// The window between the question and the map is not closed, and does not
    /// need to be: this is what stands between a guest and the host running
    /// out, not an allocator, so overshooting by one racing `mmap` costs
    /// nothing the next call does not refuse.
    pub fn would_fit(&self, pages: u64) -> bool {
        if self.limit <= 0 {
            return true;
        }
        let fits = self.used.load(Ordering::Relaxed) + pages as i64 <= self.limit;
        if !fits {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
        fits
    }

    /// How many requests this budget has refused. Zero on every healthy run.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// The unconditional half: a page that has *already* been mapped.
    pub fn add(&self, pages: u64) {
        if self.limit > 0 {
            self.used.fetch_add(pages as i64, Ordering::Relaxed);
        }
    }

    pub fn sub(&self, pages: u64) {
        if self.limit > 0 {
            self.used.fetch_sub(pages as i64, Ordering::Relaxed);
        }
    }

    /// How many are accounted, or -1 when the accounting is not compiled in.
    pub fn used(&self) -> i64 {
        if self.limit <= 0 {
            return -1;
        }
        self.used.load(Ordering::Relaxed)
    }
}

static ANON: Budget = Budget::new(LIMIT);

pub fn anon_pages_would_fit(pages: u64) -> bool {
    ANON.would_fit(pages)
}

pub(crate) fn anon_pages_add(pages: u64) {
    ANON.add(pages)
}

pub(crate) fn anon_pages_sub(pages: u64) {
    ANON.sub(pages)
}

pub fn anon_pages_used() -> i64 {
    ANON.used()
}

pub fn anon_pages_refused() -> u64 {
    ANON.refused()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_refuses_at_the_limit_and_not_before() {
        let b = Budget::new(10);
        assert!(b.would_fit(10));
        assert!(!b.would_fit(11));
        assert_eq!(b.refused(), 1, "the 11 was counted, the 10 was not");
        b.add(9);
        assert_eq!(b.used(), 9);
        assert!(b.would_fit(1));
        assert!(!b.would_fit(2));
        assert_eq!(b.refused(), 2);
        b.sub(9);
        assert!(b.would_fit(10));
    }

    #[test]
    fn a_budget_of_zero_accounts_nothing() {
        // What a build without the accounting gets. `used` answers -1 rather
        // than 0 so that `/proc/meminfo` can tell "none mapped" from "not
        // counted"; nothing else tests the switch.
        let b = Budget::new(0);
        assert!(b.would_fit(u64::MAX));
        b.add(5);
        assert_eq!(b.used(), -1);
    }

    #[test]
    fn the_limit_is_the_headers() {
        // 1048576 pages is 4 GiB, and it counts readable pages only -- the Go
        // runtime alone reserves about 1.1 GB of PROT_NONE.
        assert_eq!(LIMIT, 1048576);
    }
}
