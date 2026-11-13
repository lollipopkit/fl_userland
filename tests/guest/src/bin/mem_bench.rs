//! Guest memory access, at strides that miss the software TLB.
//!
//! A measurement, not a check.
//!
//! # Why this exists
//!
//! Every guest load and store goes through `emu/tlb.h`'s inline lookup, and a
//! miss calls `tlb_handle_miss` -> `mem_ptr` -> the page table in
//! `kernel/memory.c`. Nothing in the tree measured that path, so a change to
//! the page table could halve it and every test would still pass — the guest
//! suite checks *answers*, and a slow right answer is still right.
//!
//! The three cases separate the two costs. `sequential` touches one byte per
//! guest page in order, which is the miss path with a warm host cache;
//! `strided` walks the same pages in an order the host prefetcher cannot
//! follow, so it pays the host miss too; `resident` touches one page over and
//! over and should never miss at all, which makes it the control **inside**
//! this benchmark — if it moves, the change was not to the miss path.
//!
//! `compute_bench` is the control outside it: no memory traffic, so a page
//! table change must leave it alone.
//!
//! Report ns per access, because the page count is what varies between runs.
//!
//! # The baseline, 2026-08-31
//!
//! `./build/iul -r <rootfs> /tmp/mem_bench 64`, median of three on an M-series
//! Mac, before any of `kernel/memory.c` moved:
//!
//! ```text
//!   read  sequential   76 ns/access   (first pass ~100)
//!   read  strided      67 ns/access
//!   read  resident      8 ns/access   (control)
//!   write sequential   57 ns/access
//! ```
//!
//! The first pass over a freshly written buffer costs about a third more than
//! the steady state, which is why both are printed: measuring only the first
//! would have reported sequential reads as *slower than scattered* ones, which
//! is backwards and is an artefact.

use std::time::Instant;

/// One guest page. The TLB is indexed by page, so a byte per page is one entry
/// each and the stride is what decides whether it is already there.
const PAGE: usize = 4096;

fn ns_per(elapsed: std::time::Duration, n: usize) -> f64 {
    elapsed.as_secs_f64() * 1e9 / n as f64
}

fn main() {
    // 64 MB by default: enough pages that the TLB cannot hold them, small
    // enough to map on a phone.
    let mb: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let bytes = mb * 1024 * 1024;
    let pages = bytes / PAGE;

    let mut buf = vec![0u8; bytes];
    // Touch every page once so the measurement is of the *steady* state rather
    // than of first-touch allocation, which is a different path.
    for p in 0..pages {
        buf[p * PAGE] = 1;
    }

    let mut sink: u64 = 0;

    // In order: one miss per page, host prefetcher helping. Measured twice,
    // because the first pass over a freshly written buffer can be paying for
    // something the steady state does not -- and telling those apart is the
    // whole reason this reports both.
    let start = Instant::now();
    for p in 0..pages {
        sink = sink.wrapping_add(buf[p * PAGE] as u64);
    }
    let sequential1 = ns_per(start.elapsed(), pages);
    let start = Instant::now();
    for p in 0..pages {
        sink = sink.wrapping_add(buf[p * PAGE] as u64);
    }
    let sequential = ns_per(start.elapsed(), pages);

    // A stride that is coprime with the page count, so the walk visits every
    // page exactly once in an order neither the TLB nor the host prefetcher
    // can anticipate. 1021 is prime and well below any plausible page count.
    let stride = 1021.min(pages.saturating_sub(1)).max(1);
    let start = Instant::now();
    let mut p = 0usize;
    for _ in 0..pages {
        sink = sink.wrapping_add(buf[p * PAGE] as u64);
        p = (p + stride) % pages;
    }
    let strided = ns_per(start.elapsed(), pages);

    // The same page every time: a TLB hit on every access after the first, so
    // this is the inline lookup alone. The control inside the benchmark.
    let start = Instant::now();
    for _ in 0..pages {
        sink = sink.wrapping_add(buf[0] as u64);
    }
    let resident = ns_per(start.elapsed(), pages);

    // Stores, which take the *write* miss path -- a separate branch in
    // mem_ptr that also has to invalidate compiled blocks for the page.
    let start = Instant::now();
    for p in 0..pages {
        buf[p * PAGE] = p as u8;
    }
    let write_seq = ns_per(start.elapsed(), pages);

    println!("{pages} pages of {mb} MB");
    println!("  read  sequential  {sequential:7.1} ns/access   (first pass {sequential1:.1})");
    println!("  read  strided     {strided:7.1} ns/access");
    println!("  read  resident    {resident:7.1} ns/access   (control: TLB hit)");
    println!("  write sequential  {write_seq:7.1} ns/access");
    println!("(sink={sink})");
}
