//! `/proc/<pid>/smaps` and `/proc/<pid>/smaps_rollup`.
//!
//! `maps` says where a mapping is; this says how much of it is really there and
//! who else has it. Everything that reports a process's memory honestly reads
//! one of these two — `smem`, `ps_mem` and every container memory accounting
//! tool want `Pss`, because summing `Rss` across processes counts a shared page
//! once per process.
//!
//! # Why it exists: Redis will not start without it
//!
//! `checkLinuxMadvFreeForkBug` in Redis's `syscheck.c` is compiled on arm64 and
//! run before anything else. It maps three pages, writes the middle one,
//! `madvise(MADV_FREE)`s it, writes it again, forks — and in the **child**
//! reads `/proc/self/smaps` for the mapping holding that page and looks at
//! `Shared_Dirty:`. A zero means the kernel has the bug that corrupts a
//! background save; a missing file means the test could not be run. Either way
//! Redis prints a warning and calls `exit(1)`.
//!
//! This kernel had no `smaps`, so `redis-server` exited with
//! "Failed to test the kernel for a bug that could lead to data corruption
//! during background save" before opening a socket. The answer it needs is the
//! one this kernel has: after a `fork` the page is `P_COW` and has no file
//! behind it, which is shared and dirty.
//!
//! # The format is Linux's, field for field
//!
//! `show_smap` in `fs/proc/task_mmu.c` writes each line as a 16-character name
//! and an 8-wide right-aligned number followed by ` kB`, and readers index by
//! column. `Private_Hugetlb:` is the one exception — its name is 17 characters
//! and its number is 7 wide — which is in the kernel as a `seq_put_decimal_ull_width`
//! call of its own beside a macro that does the rest.
//!
//! Fields this kernel has nothing behind report zero, and that is not a guess:
//! there is no swap, no transparent huge page, no KSM and no hugetlb here, so
//! zero is the true count rather than a placeholder. `Referenced` is `Rss`,
//! because nothing clears the reference bit, so every resident page has been
//! referenced.

use std::fmt::Write as _;
use std::os::raw::c_int;

use crate::ffi;
use crate::maps::{P_EXEC, P_READ, P_SHARED, P_WRITE, write_region};
use crate::pidmem::{Counts, Region};

/// `/proc/<pid>/smaps`.
///
/// `extern "C"` because the table holds its address, and **not** exported: no C
/// names it, so a `#[no_mangle]` would be a second interface with nobody on the
/// other side. That is the distinction `tools/dead-exports.py` reports, and it
/// reported these two on the run that added them.
pub(crate) fn proc_pid_smaps_show(
    entry: &mut ffi::proc_entry,
    buf: &mut ffi::proc_data,
) -> c_int {
    let regions = crate::pidmem::collect(entry);
    let text = format(&regions);
    buf.append(text.as_bytes());
    0
}

/// `/proc/<pid>/smaps_rollup`: the same counts, added up, under one header line.
pub(crate) fn proc_pid_smaps_rollup_show(
    entry: &mut ffi::proc_entry,
    buf: &mut ffi::proc_data,
) -> c_int {
    let regions = crate::pidmem::collect(entry);
    let text = format_rollup(&regions);
    buf.append(text.as_bytes());
    0
}

/// One line: a 16-character name, the number right-aligned in eight, ` kB`.
fn kb(text: &mut String, name: &str, bytes: u64) {
    let _ = writeln!(text, "{name:<16}{:>8} kB", bytes >> 10);
}

/// The whole of `smaps`.
fn format(regions: &[Region]) -> String {
    let mut text = String::with_capacity(regions.len() * 640);
    for r in regions {
        write_region(&mut text, r);
        kb(&mut text, "Size:", r.end - r.start);
        kb(&mut text, "KernelPageSize:", ffi::PAGE_SIZE.into());
        kb(&mut text, "MMUPageSize:", ffi::PAGE_SIZE.into());
        counts(&mut text, &r.counts, false);
        // No transparent huge pages, so no mapping is eligible for one.
        let _ = writeln!(text, "THPeligible:    {:>8}", 0);
        let _ = writeln!(text, "VmFlags: {}", vm_flags(r.flags, &r.counts));
    }
    text
}

/// The whole of `smaps_rollup`.
///
/// The header is Linux's: the first mapping's start, the last one's end, and
/// `---p`, which is not any mapping's protection — the line is there so that a
/// parser written for `smaps` finds the shape it expects before the fields.
fn format_rollup(regions: &[Region]) -> String {
    let mut total = Counts::default();
    for r in regions {
        total.add(&r.counts);
    }
    let start = regions.first().map_or(0, |r| r.start);
    let end = regions.last().map_or(0, |r| r.end);
    let mut text = String::with_capacity(512);
    let header = Region { start, end, file_offset: 0, flags: 0, dev: 0, inode: 0, path: "[rollup]".into(), counts: Counts::default() };
    write_region(&mut text, &header);
    counts(&mut text, &total, true);
    text
}

/// The block both files share, `__show_smap` in the kernel.
///
/// `rollup` is what decides whether the three `Pss_` splits are printed:
/// `smaps` prints them only for a shared mapping and `smaps_rollup` always, so
/// printing them always in the per-mapping file would be a field a parser does
/// not expect there.
fn counts(text: &mut String, c: &Counts, rollup: bool) {
    let page = u64::from(ffi::PAGE_SIZE);
    kb(text, "Rss:", c.rss * page);
    kb(text, "Pss:", c.pss);
    kb(text, "Pss_Dirty:", c.pss_dirty);
    if rollup {
        kb(text, "Pss_Anon:", c.pss_anon);
        kb(text, "Pss_File:", c.pss_file);
        kb(text, "Pss_Shmem:", c.pss_shmem);
    }
    kb(text, "Shared_Clean:", c.shared_clean * page);
    kb(text, "Shared_Dirty:", c.shared_dirty * page);
    kb(text, "Private_Clean:", c.private_clean * page);
    kb(text, "Private_Dirty:", c.private_dirty * page);
    // Nothing clears the reference bit here, so every resident page has been
    // referenced since the last clear, which never happened.
    kb(text, "Referenced:", c.rss * page);
    kb(text, "Anonymous:", c.anonymous() * page);
    // No KSM, no MADV_FREE accounting, no transparent huge pages, no hugetlb,
    // no swap, and mlock is not enforced -- so each of these is a true zero
    // rather than a field left blank.
    for name in [
        "KSM:",
        "LazyFree:",
        "AnonHugePages:",
        "ShmemPmdMapped:",
        "FilePmdMapped:",
        "Shared_Hugetlb:",
    ] {
        kb(text, name, 0);
    }
    // The one field whose name is 17 characters, so its number is 7 wide. The
    // kernel writes this one call by hand for the same reason.
    let _ = writeln!(text, "{:<17}{:>7} kB", "Private_Hugetlb:", 0);
    for name in ["Swap:", "SwapPss:", "Locked:"] {
        kb(text, name, 0);
    }
}

/// The `VmFlags:` line, which `pmap -XX` and `procps` read.
///
/// Only what this kernel can answer. Linux has twenty-odd codes for properties
/// that come from `vm_flags`, and this kernel keeps page flags rather than a
/// VMA — so the ones that would need a per-mapping record it does not have
/// (`de`, `nr`, `sf`, `dd`) are absent, which is what a mapping without them
/// looks like. In Linux's order (`show_smap_vma_flags`).
fn vm_flags(flags: u32, c: &Counts) -> String {
    let mut out: Vec<&str> = Vec::with_capacity(8);
    if flags & P_READ != 0 {
        out.push("rd");
    }
    if flags & P_WRITE != 0 {
        out.push("wr");
    }
    if flags & P_EXEC != 0 {
        out.push("ex");
    }
    if flags & P_SHARED != 0 {
        out.push("sh");
    }
    // The MAY bits: what mprotect would be allowed to turn back on. Every
    // mapping here may become anything, because this kernel applies no
    // per-mapping ceiling -- so all three, always, which is also what Linux
    // reports for an ordinary mmap.
    out.push("mr");
    out.push("mw");
    out.push("me");
    if flags & ffi::P_GROWSDOWN != 0 {
        out.push("gd");
    }
    if flags & ffi::P_LOCKED != 0 {
        out.push("lo");
    }
    if flags & ffi::P_DONTFORK != 0 {
        out.push("dc");
    }
    // Charged against the anonymous page budget, which is what this kernel
    // has in place of overcommit accounting.
    if c.anonymous() > 0 {
        out.push("ac");
    }
    if flags & ffi::P_WIPEONFORK != 0 {
        out.push("wf");
    }
    // `mseal`. Last, as Linux prints it.
    if flags & ffi::P_SEALED != 0 {
        out.push("sl");
    }
    out.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(start: u64, end: u64, flags: u32, counts: Counts) -> Region {
        Region {
            start,
            end,
            file_offset: 0,
            flags,
            dev: 0,
            inode: 0,
            path: String::new(),
            counts,
        }
    }

    /// A page is 4 kB, so a count of one is a line reading `4 kB`, and the
    /// columns are where a reader indexing by them expects.
    #[test]
    fn the_columns_are_linuxs() {
        let mut s = String::new();
        kb(&mut s, "Size:", 4096);
        assert_eq!(s, "Size:                  4 kB\n");
        // 16 + 8 = 24 characters before the space and `kB`.
        assert_eq!(s.find(" kB").unwrap(), 24);
        let mut s = String::new();
        kb(&mut s, "Private_Clean:", 12288);
        assert_eq!(s, "Private_Clean:        12 kB\n");
        assert_eq!(s.find(" kB").unwrap(), 24);
    }

    /// The one field whose name does not fit the width the rest share still
    /// lines its `kB` up with them.
    #[test]
    fn private_hugetlb_lines_up_with_the_rest() {
        let mut s = String::new();
        counts(&mut s, &Counts::default(), false);
        for line in s.lines() {
            assert_eq!(line.find(" kB"), Some(24), "{line}");
        }
    }

    /// What Redis asks: after a fork the middle page is `P_COW` with no file
    /// behind it, so the mapping holding it reports a non-zero `Shared_Dirty`.
    /// A zero there is what tells Redis the kernel corrupts background saves.
    #[test]
    fn a_forked_anonymous_page_is_shared_and_dirty() {
        let c = Counts {
            rss: 1,
            shared_dirty: 1,
            pss: 2048,
            pss_dirty: 2048,
            pss_anon: 2048,
            ..Default::default()
        };
        let text = format(&[region(0x1000, 0x2000, P_READ | P_WRITE, c)]);
        let line = text
            .lines()
            .find(|l| l.starts_with("Shared_Dirty:"))
            .unwrap();
        assert_eq!(line, "Shared_Dirty:          4 kB");
        // And the halves add up: one page shared with one other space is 2 kB
        // of proportional set size.
        assert!(text.contains("Pss:                   2 kB"));
    }

    /// Every field a reader looks for is there, once, in the kernel's order.
    #[test]
    fn the_field_order_is_the_kernels() {
        let text = format(&[region(0, 0x1000, P_READ, Counts::default())]);
        let names: Vec<&str> = text
            .lines()
            .skip(1)
            .map(|l| l.split(':').next().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "Size",
                "KernelPageSize",
                "MMUPageSize",
                "Rss",
                "Pss",
                "Pss_Dirty",
                "Shared_Clean",
                "Shared_Dirty",
                "Private_Clean",
                "Private_Dirty",
                "Referenced",
                "Anonymous",
                "KSM",
                "LazyFree",
                "AnonHugePages",
                "ShmemPmdMapped",
                "FilePmdMapped",
                "Shared_Hugetlb",
                "Private_Hugetlb",
                "Swap",
                "SwapPss",
                "Locked",
                "THPeligible",
                "VmFlags",
            ]
        );
    }

    /// The rollup adds the regions up and says which kind each byte was, which
    /// the per-mapping file does not.
    #[test]
    fn the_rollup_adds_up_and_splits_the_pss() {
        let a = Counts {
            rss: 2,
            private_dirty: 2,
            pss: 8192,
            pss_dirty: 8192,
            pss_anon: 8192,
            ..Default::default()
        };
        let b = Counts {
            rss: 1,
            private_clean: 1,
            pss: 4096,
            pss_file: 4096,
            ..Default::default()
        };
        let text = format_rollup(&[
            region(0x1000, 0x3000, P_READ, a),
            region(0x8000, 0x9000, P_READ, b),
        ]);
        // `---p`: the header is a span rather than a mapping, so it carries no
        // protection of its own, which is what Linux writes there too.
        assert!(text.starts_with("00001000-00009000 ---p"), "{text}");
        assert!(text.contains("[rollup]"));
        assert!(text.contains("Rss:                  12 kB"));
        assert!(text.contains("Pss_Anon:              8 kB"));
        assert!(text.contains("Pss_File:              4 kB"));
        assert!(text.contains("Pss_Shmem:             0 kB"));
        // The rollup has no per-mapping fields.
        assert!(!text.contains("Size:"));
        assert!(!text.contains("VmFlags:"));
    }

    /// An address space with nothing in it is an empty file, not a header with
    /// zeroes under it -- which is what a zombie reads as, the same answer
    /// `maps` gives.
    #[test]
    fn no_regions_is_no_output() {
        assert_eq!(format(&[]), "");
    }

    /// The codes come from the flags, and `ac` from there being anonymous
    /// memory to charge.
    #[test]
    fn the_vm_flags_are_the_pages_flags() {
        let none = Counts::default();
        assert_eq!(vm_flags(P_READ | P_EXEC, &none), "rd ex mr mw me");
        assert_eq!(
            vm_flags(P_READ | P_WRITE | P_SHARED, &none),
            "rd wr sh mr mw me"
        );
        let anon = Counts {
            rss: 1,
            private_dirty: 1,
            ..Default::default()
        };
        assert_eq!(vm_flags(P_READ | P_WRITE, &anon), "rd wr mr mw me ac");
        assert_eq!(
            vm_flags(P_READ | P_WRITE | ffi::P_GROWSDOWN, &anon),
            "rd wr mr mw me gd ac"
        );
    }
}
