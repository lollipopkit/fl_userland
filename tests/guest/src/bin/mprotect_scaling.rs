//! What a guest `mprotect` costs per page of the range it covers.
//!
//! A deadline rather than a comparison. The numbers are about this emulator:
//! it applies a guest `mprotect` to the host mapping underneath, and a real
//! kernel has no such second mapping to update.
//!
//! It used to make **one host `mprotect` per 4 KB guest page**, which is a flat
//! ~318 ns each however large the range:
//!
//! | pages | before | after | arm64 Linux |
//! | --- | --- | --- | --- |
//! | 16 | 6.9 µs | 3.5 µs | 1.1 µs |
//! | 256 | 81 µs | 3.6 µs | 3.3 µs |
//! | 4096 | 1 351 µs | 10 µs | 36 µs |
//! | 32768 | **10 422 µs** | 55 µs | 343 µs |
//!
//! 32768 pages is V8's 128 MB heap cage, which it mprotects in one call. The
//! fix coalesces runs of host-contiguous pages, which `pt_set_flags`'s
//! reservation branch already did for its own mappings — with a comment saying
//! why — while the branch below it did not.
//!
//! `tests/guest/src/bin/mprotect_runs.rs` is the correctness half, and it is
//! compared against a real kernel. It passes with or without the coalescing;
//! this is the file that fails without it.
//!
//! # What it measures is the **slope**, since 2026-09-02
//!
//! It used to assert ns/page at each of three sizes against one deadline of
//! 100. At 256 pages the cost of making the call at all is most of the
//! measurement — 3.1 µs of 3.5 — so that check was really a deadline on the
//! fixed cost, and it was the only one with any margin: at 4096 and 32768 the
//! real numbers are 2 ns/page against a deadline of 100.
//!
//! It therefore passed while `pt_set_flags` got **twice as slow**. The page
//! table moved to `crates/kernel/pagetable` and the Rust release profile is
//! `opt-level = "z"`, which is chosen for the archive and costs about 2x on a
//! loop that runs once per guest page; the C it replaced was `-O3`. 32768
//! pages went 55 → 120 µs and nothing failed. The crate has an `opt-level = 3`
//! override in the root `Cargo.toml` now, and this file asks the question that
//! would have caught it: the marginal cost of a page, which is the difference
//! between two sizes divided by the difference in pages, with the fixed cost
//! subtracted out by the arithmetic rather than swamped by it.
//!
//! Measured 1.6 ns/page before the move, 3.2 during it, 1.9 after the
//! override — reported in **picoseconds**, because integer division by 28672
//! turns all three of those into "2" or "3" and a check cannot see a
//! difference its own units have rounded away.
//!
//! And it is a **ratio against a control measured in the same run**, not a
//! wall-clock deadline. A debug build is twenty times slower than a release
//! one and the guest suite runs whichever binary it is given, so any absolute
//! number is calibrated for one of them and meaningless for the other — the
//! deadline this replaces was 100 ns/page, which was three times the debug
//! measurement and *fifty* times the release one. The control is what one
//! `mprotect` costs when there is nothing to batch, which moves with the build
//! and the machine exactly as the per-page cost does. Measured:
//!
//! | | ps/page | one call, ns | ratio, pcm |
//! | --- | --- | --- | --- |
//! | release, before the move | 1801 | 3060 | 59 |
//! | release, `opt-level = "z"` | 3177 | 2975 | 107 |
//! | release, with the override | 1894 | 2980 | 63 |
//! | debug | 43651 | 12935 | 337 |
//! | one host call per page | ~318000 | ~3000 | ~10600 |
//!
//! The ratio is in **pcm**, thousandths of a percent: picoseconds over
//! nanoseconds, times 100. It was printed as "%" until 2026-11-11, which read
//! as a page costing more than the whole call. The deadline is 1000 pcm (a
//! page at the margin costs under 1% of a call): ten times below the shape it
//! guards and three times above the slowest healthy build.
//!
//! **It still does not catch that 2x** — 63 against 107 is inside it, and a
//! wall-clock number on a shared machine cannot be set tighter without failing
//! for reasons that are nobody's bug. What found that one is the practice this
//! test cannot replace: build a worktree at the previous commit, run the same
//! guest binary against both, and compare, with a control that should not move.
//! This file's job is to make that comparison cheap and to catch the shape
//! change; the A/B is what catches the factor.
//!
//! # 2026-11-11: four walks of the page table per page
//!
//! It failed on every build: 1400-1600 pcm release, 1850-2000 debug. The
//! slope was 7 ns/page release and 22 debug, and the control had fallen to
//! 450 ns and 1150 (why it fell from 3000 was not established). Profiled with
//! `sample`, the time was all in the page table: `mprotect` asked it about
//! every page of the range four times -- the seal, the memfd write seal, the
//! holes, then the change -- each a lookup from the root. The checks are one
//! walk over extents now, the walks go a leaf at a time, and the change is the
//! second walk:
//!
//! | | ps/page | one call, ns | ratio, pcm |
//! | --- | --- | --- | --- |
//! | release, before | 6700-8000 | 435-545 | 1467-1602 |
//! | release, after | 1195-1654 | 420-510 | 271-357 |
//! | debug, before | 21463-22945 | 1150 | 1866-1995 |
//! | debug, after | 1807-2444 | 1150-1320 | 152-185 |

use guest_tests::{Harness, check};
use std::time::Instant;

const PAGE: usize = 4096;

/// Nanoseconds for one `mprotect` that *raises* protection over `pages`.
fn raise_ns(pages: usize, rounds: usize) -> u128 {
    let len = pages * PAGE;
    let m = unsafe {
        libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE,
                   libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    };
    if m == libc::MAP_FAILED {
        return u128::MAX;
    }
    unsafe { libc::memset(m, 1, len) };
    // The lowering half costs nothing on the host -- protection is not
    // increasing, so no host call is made -- and is measured to be subtracted.
    let t0 = Instant::now();
    for _ in 0..rounds {
        unsafe { libc::mprotect(m, len, libc::PROT_READ) };
    }
    let down = t0.elapsed().as_nanos() / rounds as u128;
    let t0 = Instant::now();
    for _ in 0..rounds {
        unsafe { libc::mprotect(m, len, libc::PROT_READ) };
        unsafe { libc::mprotect(m, len, libc::PROT_READ | libc::PROT_WRITE) };
    }
    let both = t0.elapsed().as_nanos() / rounds as u128;
    unsafe { libc::munmap(m, len) };
    both.saturating_sub(down)
}

fn main() {
    let mut h = Harness::new();

    // Printed at every size, because the shape is the finding and a count is
    // not: 318 ns/page and 2 ns/page look the same in a pass/fail line.
    let mut at: Vec<(usize, u128)> = Vec::new();
    for pages in [256usize, 4096, 32768] {
        let ns = raise_ns(pages, if pages > 4096 { 20 } else { 50 });
        println!("  {pages:>6} pages: {ns:>9} ns   {:>5} ns/page", ns / pages as u128);
        at.push((pages, ns));
    }

    // The control: what one call costs when there is nothing to batch. It is
    // both the denominator below and a check of its own -- coalescing must not
    // have made the common case worse, and the slope cannot see that at all.
    let one = raise_ns(1, 200);
    println!("  {:>6} page : {one:>9} ns   (control)", 1);

    h.group("mprotect-does-not-cost-per-page");
    // The marginal cost of a page, in picoseconds because this is single-digit
    // nanoseconds and dividing by 28672 would round a 2x difference away.
    // Taken between the two large sizes, so the cost of making the call at all
    // cancels instead of hiding a regression behind itself: the absolute form
    // of this check passed through one. Then divided by the control, so the
    // answer is about this kernel rather than about the build.
    // In pcm, thousandths of a percent: a healthy page is a few thousandths of
    // the call, and a coarser unit rounds the finding away.
    const RATIO_PCM: u128 = 1000;
    let (small_pages, small_ns) = at[1];
    let (large_pages, large_ns) = at[2];
    let slope = large_ns.saturating_sub(small_ns) * 1000 / (large_pages - small_pages) as u128;
    let ratio = slope * 100 / one.max(1);
    println!(
        "  marginal: {slope} ps/page ({small_pages} -> {large_pages}), {ratio} pcm of the control"
    );
    check!(
        h,
        ratio < RATIO_PCM,
        "a page costs {slope} ps at the margin against a {one} ns call -- {ratio} pcm, over the \
         {RATIO_PCM} pcm deadline ({small_ns} ns for {small_pages} pages, {large_ns} for {large_pages})"
    );

    h.group("and-a-single-page-is-not-slower-for-it");
    check!(h, one < 20_000, "a one-page mprotect takes {one} ns");

    std::process::exit(h.finish());
}
