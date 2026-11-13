//! The anonymous-page budget balances: every page charged is given back.
//!
//! Not comparable to a real kernel and in its own binary for that reason. The
//! budget is this emulator's own — a cap on how much host memory a guest may
//! have mapped, so that a guest which maps until it stops gets `ENOMEM` rather
//! than the host being killed by jetsam with no crash report. Linux has no
//! equivalent number to compare against.
//!
//! # Why a leak here is worse than a leak
//!
//! The budget is one process-wide counter shared by every guest process, and it
//! is never reset. So a charge that is never refunded is **permanent for the
//! life of the emulator**: it does not go away when the process that caused it
//! exits, and it accumulates across every process a long run starts.
//!
//! What the guest sees when the counter reaches the cap is a plain `ENOMEM`
//! from `mmap` and, from `brk`, the current break unchanged — exactly what a
//! guest that has genuinely run out of address space gets. glibc's loader turns
//! the second into
//!
//! ```text
//! cannot create shared object descriptor: Cannot allocate memory
//! ```
//!
//! because `_dl_new_object`'s `calloc` failed, which reads as a corrupt library
//! rather than as an emulator limit. That is how it presented in a `full.sh`
//! run: `rpmkeys` could not load `librpm.so.9`, once, late in the longest
//! subject, and nothing anywhere said the budget had refused.
//!
//! # The shape being checked
//!
//! `PROT_NONE` anonymous memory is address space and nothing else — Linux maps
//! it `VM_NORESERVE` and does not charge it either — so the rule is
//! *accessibility*, and it has to be the same rule at every place that changes
//! it: the map, the unmap, the move, `mprotect`, and **fork**. Four of those
//! five asked `charged()`; the fifth asked `P_ANONYMOUS`, which is a different
//! question, and so a fork charged for pages the matching unmap would not
//! refund.
//!
//! glibc reserves 64 MB of `PROT_NONE` per malloc arena and Go's runtime about
//! 1.1 GB for page summaries, so the leak was in units of sixteen thousand
//! pages per fork against a cap of a million.

use guest_tests::{Harness, check};

const PAGE: usize = 4096;
/// 64 MB, which is what glibc reserves per per-thread malloc arena — the size
/// the real case leaked in.
const RESERVE: usize = 64 * 1024 * 1024;

/// A counter from `/proc/iul/objects`.
fn counter(name: &str) -> Option<i64> {
    let s = std::fs::read_to_string("/proc/iul/objects").ok()?;
    let prefix = format!("{name} ");
    s.lines().find_map(|l| l.strip_prefix(prefix.as_str()))?.trim().parse().ok()
}

fn map(prot: i32) -> *mut libc::c_void {
    unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            RESERVE,
            prot,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            -1,
            0,
        )
    }
}

/// Fork, have the child exit at once, and wait for it. The child inherits the
/// parent's mappings, which is the charge under test.
fn fork_and_reap(h: &mut Harness) {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::_exit(0);
        }
        check!(h, pid > 0, "fork succeeded");
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
    }
}

/// How much drift the measurement itself is allowed. The signal is 16384 pages
/// per fork, so 64 is more than two orders of magnitude below it -- a tolerance
/// this far from the effect cannot accept the defect it exists to catch.
const DRIFT: i64 = 64;

fn main() {
    let mut h = Harness::new();

    // Reading `/proc/iul/objects` allocates in the guest -- a `String`, a
    // `read_to_string` buffer -- and an allocation that grows the break is
    // itself charged, so the act of measuring moves the number. Warm the
    // allocator first, and compare against a tolerance below.
    for _ in 0..4 {
        let _ = counter("anon_pages");
    }

    h.group("the-budget-is-reported");
    let Some(start) = counter("anon_pages") else {
        check!(h, false, "/proc/iul/objects reports anon_pages");
        std::process::exit(h.finish());
    };
    // -1 is what a build without the accounting compiled in answers, and there
    // is nothing to check in one.
    if start < 0 {
        check!(h, true, "the accounting is not compiled in; nothing to check");
        std::process::exit(h.finish());
    }
    check!(h, counter("anon_refused") == Some(0), "nothing has been refused yet");

    // A PROT_NONE reservation is not charged, and a fork of one must not be
    // either. Without the fix the reservation itself is still free -- the map
    // side always asked the right question -- and the *fork* is what charges.
    h.group("prot-none-is-not-charged");
    let none = map(libc::PROT_NONE);
    check!(h, none != libc::MAP_FAILED, "the PROT_NONE reservation succeeded");
    let after_map = counter("anon_pages").unwrap_or(-1);
    check!(
        h,
        (after_map - start).abs() <= DRIFT,
        "64 MB PROT_NONE charged nothing (was {start}, now {after_map})"
    );

    h.group("forking-a-reservation-charges-nothing");
    fork_and_reap(&mut h);
    let after_fork = counter("anon_pages").unwrap_or(-1);
    // The load-bearing check. Before the fix this was `start + 16384`, and the
    // 16384 stayed for the life of the emulator.
    check!(
        h,
        (after_fork - start).abs() <= DRIFT,
        "fork of a PROT_NONE reservation charged nothing \
             (was {start}, now {after_fork}, leaked {})",
            after_fork - start
    );

    // Three more, because one fork of 16384 pages is under 2% of the cap and a
    // leak that only shows up after a hundred forks is the case that was
    // actually hit.
    for _ in 0..3 {
        fork_and_reap(&mut h);
    }
    let after_four = counter("anon_pages").unwrap_or(-1);
    check!(
        h,
        (after_four - start).abs() <= DRIFT,
        "four forks charged nothing (was {start}, now {after_four})"
    );

    unsafe { libc::munmap(none, RESERVE) };
    let after_unmap = counter("anon_pages").unwrap_or(-1);
    check!(
        h,
        (after_unmap - start).abs() <= DRIFT,
        "unmapping the reservation refunded nothing either (now {after_unmap})"
    );

    // The other half of the balance, and what says the counter is live rather
    // than stuck: a readable mapping *is* charged, and giving it back returns
    // the counter exactly.
    h.group("a-readable-mapping-balances");
    let rw = map(libc::PROT_READ | libc::PROT_WRITE);
    check!(h, rw != libc::MAP_FAILED, "the readable mapping succeeded");
    let charged = counter("anon_pages").unwrap_or(-1);
    check!(
        h,
        (charged - start - (RESERVE / PAGE) as i64).abs() <= DRIFT,
        "64 MB PROT_READ|PROT_WRITE charged 16384 pages (now {charged})"
    );

    fork_and_reap(&mut h);
    let forked = counter("anon_pages").unwrap_or(-1);
    check!(
        h,
        (forked - charged).abs() <= DRIFT,
        "the child's copy was charged and refunded when it exited \
             (was {charged}, now {forked})"
    );

    unsafe { libc::munmap(rw, RESERVE) };
    let back = counter("anon_pages").unwrap_or(-1);
    check!(h, (back - start).abs() <= DRIFT, "unmapping refunded all of it (now {back})");

    check!(h, counter("anon_refused") == Some(0), "the budget refused nothing");

    std::process::exit(h.finish());
}
