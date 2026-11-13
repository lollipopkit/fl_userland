//! Address-space mapping walks and proc pid maps regions.

use std::sync::Arc;

use crate::ffi;

use super::Space;
use pagetable::memlock::Held;

// -------------------------------------------------------------------- maps

/// A region as the walk found it, before its path is known.
///
/// The name or the descriptor is carried out of the locked walk so the path can
/// be resolved once the lock is gone. The descriptor is **retained under the
/// lock**, which is what keeps the description alive until the `getpath`.
struct Raw {
    start: u64,
    end: u64,
    file_offset: u64,
    flags: u32,
    /// `'static`, so it outlives the walk's lock; see `Data::name`.
    name: Option<&'static std::ffi::CStr>,
    /// **Owning**, since 2026-09-12. The walk below collects these under
    /// `mem->lock` and `resolve` uses them after it is gone, so every one has to
    /// be released -- and `resolve` has an early `continue` in it. An
    /// [`fs_fdobj::Owned`] releases on every path out of the loop including
    /// the ones nobody wrote down; object model step 9.7.
    fd: Option<fs_fdobj::Owned>,
    stack: bool,
    counts: Counts,
}

/// What `smaps` reports about a region, counted page by page during the walk.
///
/// It is counted here rather than derived from `end - start` because the two
/// differ: `mem_next_page` skips an empty *subtree*, so a region can span a
/// hole of at least 512 pages and still read as one mapping. `Size` is the
/// span; `rss` is what is actually there.
///
/// Two questions per page, from the flags this kernel has:
///
/// - **shared** is `P_SHARED`, a `MAP_SHARED` mapping, or `P_COW` held by
///   more than one address space -- a fork's pages, until one side writes.
///   A private file page is `P_COW` from the start, and one process alone
///   holding it is `Private_Clean` on Linux.
/// - **dirty** is *not backed by a file*. A page with no file behind it exists
///   only in memory and cannot be dropped and read back, which is what dirty
///   means to a reader of this file. A written `MAP_PRIVATE` file page is a
///   copy with no file of its own, and so dirty, as on Linux.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Counts {
    pub rss: u64,
    pub shared_clean: u64,
    pub shared_dirty: u64,
    pub private_clean: u64,
    pub private_dirty: u64,
    /// Proportional set size in **bytes**: one page divided by the number of
    /// address spaces sharing it, summed.
    pub pss: u64,
    /// The same sum restricted to dirty pages, and split three ways by what
    /// backs the page — the split `smaps_rollup` reports and `maps` does not.
    pub pss_dirty: u64,
    pub pss_anon: u64,
    pub pss_file: u64,
    pub pss_shmem: u64,
}

impl Counts {
    /// Add another region's, for `smaps_rollup`.
    pub fn add(&mut self, o: &Counts) {
        self.rss += o.rss;
        self.shared_clean += o.shared_clean;
        self.shared_dirty += o.shared_dirty;
        self.private_clean += o.private_clean;
        self.private_dirty += o.private_dirty;
        self.pss += o.pss;
        self.pss_dirty += o.pss_dirty;
        self.pss_anon += o.pss_anon;
        self.pss_file += o.pss_file;
        self.pss_shmem += o.pss_shmem;
    }

    /// Pages this kernel calls anonymous: everything with nothing to read back
    /// from. `smaps`' `Anonymous:` line.
    pub fn anonymous(&self) -> u64 {
        self.shared_dirty + self.private_dirty
    }
}

/// One region, with a path. What the formatter takes.
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub flags: u32,
    /// `st_dev` and `st_ino` of the mapped file, as `fstat` on it answers in
    /// the guest; zero for a region with no file.
    pub dev: u64,
    pub inode: u64,
    pub path: String,
    pub counts: Counts,
}

/// The mapping a page belongs to: a private copy of a file page belongs to
/// the file's, as Linux keeps it in the file's VMA.
fn mapping(pt: &pagetable::PtEntry) -> Option<&Arc<pagetable::Data>> {
    pt.file_page().map(|(d, _)| d).or(pt.data())
}

/// Walk one address space and record its regions. `mem->lock` is held for the
/// walk and nothing else.
fn walk(held: &pagetable::memlock::ReadGuard<'_>) -> Vec<Raw> {
    let mut regions: Vec<Raw> = Vec::new();
    let mut page: u64 = 0;
    while page < ffi::MEM_PAGES {
        // Find a region.
        while page < ffi::MEM_PAGES && held.pt(page).is_none() {
            held.next_page(&mut page);
        }
        if page >= ffi::MEM_PAGES {
            break;
        }
        let start = page;
        let start_pt = held.pt(start).expect("the loop above stopped on a mapped page");
        let start_flags = start_pt.flags();
        let data = mapping(start_pt);
        let mut counts = Counts::default();

        // Find the end of it.
        while page < ffi::MEM_PAGES {
            let Some(pt) = held.pt(page) else {
                break;
            };
            let f = pt.flags();
            // The bits Linux keeps on the vma: a change in any of them is a
            // vma boundary there, so a line boundary here. Not P_GUARD, which
            // Linux keeps in the page tables and does not split a vma for.
            const VMA: u32 = ffi::P_RWX | ffi::P_SEALED | ffi::P_LOCKED | ffi::P_DONTFORK | ffi::P_WIPEONFORK;
            if f & VMA != start_flags & VMA {
                break;
            }
            // The region continues if the data is the same, or both are
            // anonymous.
            let same = match (mapping(pt), data) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            } || (f & ffi::P_ANONYMOUS != 0 && start_flags & ffi::P_ANONYMOUS != 0);
            if !same {
                break;
            }
            count_page(&mut counts, f, pt.data());
            held.next_page(&mut page);
        }
        let end = page;

        // Report what was collected rather than nothing, if this cannot grow.
        if regions.try_reserve(1).is_err() {
            break;
        }
        regions.push(Raw {
            start: start << ffi::PAGE_BITS,
            end: end << ffi::PAGE_BITS,
            // The offset of the region's first page, not of the mapping it
            // belongs to: the two differ once its front is unmapped or
            // remapped. Linux prints 0 for a mapping with no file.
            file_offset: start_pt.file_page().map_or(0, |(d, offset)| d.file_offset() + offset) as u64,
            flags: start_flags,
            name: data.and_then(|d| d.name()),
            // Retained, because `resolve` runs with no lock held and the
            // mapping can go in between.
            fd: data.and_then(|d| d.fd()).cloned(),
            stack: start_flags & ffi::P_GROWSDOWN != 0,
            counts,
        });
    }
    regions
}

/// Add one present page to a region's counts.
///
/// A reservation — an entry with no `data` behind it — is mapped but not
/// resident, so it counts towards `Size` and towards nothing else. That is the
/// same rule `vm_counts` applies for `statm`'s resident column.
fn count_page(counts: &mut Counts, flags: u32, data: Option<&Arc<pagetable::Data>>) {
    let Some(data) = data else {
        return;
    };
    counts.rss += 1;
    let shared = flags & ffi::P_SHARED != 0 || (flags & ffi::P_COW != 0 && sharers(true, data) > 1);
    let dirty = data.fd().is_none();
    match (shared, dirty) {
        (true, true) => counts.shared_dirty += 1,
        (true, false) => counts.shared_clean += 1,
        (false, true) => counts.private_dirty += 1,
        (false, false) => counts.private_clean += 1,
    }
    let share = u64::from(ffi::PAGE_SIZE) / sharers(shared, data);
    counts.pss += share;
    if dirty {
        counts.pss_dirty += share;
    }
    // The same three-way split `vm_counts` uses for `status`'s RssAnon,
    // RssFile and RssShmem, so the two files cannot disagree about a page:
    // shared first, because a shared file mapping is shmem to a reader and
    // counting it as file as well would make the three overshoot.
    if flags & ffi::P_SHARED != 0 {
        counts.pss_shmem += share;
    } else if dirty {
        counts.pss_anon += share;
    } else {
        counts.pss_file += share;
    }
}

/// How many address spaces have this page, for `Pss`.
///
/// **The kernel's own number, not an invented one**, and the arithmetic is why
/// it needs a comment. A `Data` is one host allocation that several page
/// table entries point into, and its strong count counts *entries* rather than
/// processes — so a mapping of `n` pages held by `k` address spaces has a
/// refcount of `n * k`. Dividing by the pages the allocation covers gives `k`.
///
/// It is exact while every page of the allocation is mapped in every sharer,
/// which is what a `fork` produces and what the number is asked for. A partial
/// `munmap` in one of them makes it an underestimate of the divisor, so `Pss`
/// comes out high; the clamp is what keeps that bounded, and one is the answer
/// for a page nothing shares.
fn sharers(shared: bool, data: &Arc<pagetable::Data>) -> u64 {
    if !shared {
        return 1;
    }
    // `Arc::strong_count` is the count the hand-rolled `refcount` field was
    // until 2026-09-12, and means the same thing: one per page-table entry.
    let count = Arc::strong_count(data) as u64;
    let pages = (data.size() as u64 / u64::from(ffi::PAGE_SIZE)).max(1);
    (count / pages).clamp(1, 64)
}

/// Turn the raw regions into ones that carry a path. Runs with no lock held.
fn resolve(raw: Vec<Raw>) -> Vec<Region> {
    let mut out = Vec::with_capacity(raw.len());
    // `MAX_PATH + 1`, not `MAX_PATH`: a path answer is the path *and* its
    // terminator, and this buffer was one byte short of the contract eight
    // implementations of `getpath` were written against. It is the slice's own
    // length that decides now -- an answer that does not fit is
    // `_ENAMETOOLONG` rather than a byte past the end of this array.
    let mut path = [0u8; ffi::MAX_PATH as usize + 1];
    for r in raw {
        let name = if r.stack {
            "[stack]".to_string()
        } else if let Some(name) = r.name {
            name.to_string_lossy().into_owned()
        } else if let Some(fd) = &r.fd {
            path[0] = 0;
            if fs_generic::generic_getpath(fd, &mut path) == 0 {
                String::from_utf8_lossy(ffi::path_bytes(&path)).into_owned()
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        // The same door `fstat` goes through, so the columns name what `stat`
        // on the file says, whichever filesystem it is on.
        let st = r.fd.as_deref().and_then(|fd| fs_fdobj::fd_fstat(fd).ok()).unwrap_or_default();
        out.push(Region {
            start: r.start,
            end: r.end,
            file_offset: r.file_offset,
            flags: r.flags,
            dev: st.dev,
            inode: st.inode,
            path: name,
            counts: r.counts,
        });
    }
    out
}

/// Every region of the address space `entry` names, with paths resolved.
pub fn collect(entry: &mut ffi::proc_entry) -> Vec<Region> {
    // Empty for a task that is gone and for a zombie alike: Linux's `maps` of
    // a zombie reads as nothing.
    let Ok(space) = Space::take(entry) else {
        return Vec::new();
    };
    let raw = walk(&space.read());
    // May be the last reference, in which case dropping `space` tears the
    // address space down -- which is exactly the work that must not happen
    // under pids_lock, and does not, because the pid table was given back in
    // `Space::take`.
    drop(space);
    resolve(raw)
}

/// Every region a file is mapped into, with the file: what
/// `/proc/<pid>/map_files` lists. Empty for a task with no address space.
pub(crate) fn file_regions(entry: &mut ffi::proc_entry) -> Vec<(u64, u64, fs_fdobj::Owned)> {
    let Ok(space) = Space::take(entry) else {
        return Vec::new();
    };
    let raw = walk(&space.read());
    drop(space);
    raw.into_iter().filter(|r| !r.stack).filter_map(|r| Some((r.start, r.end, r.fd?))).collect()
}

/// The emulator's own "print where everything is mapped" on a fatal fault.
///
/// This used to carry its own copy of the line format. The copies disagreed —
/// this one read the right `P_SHARED` bit and the other read `P_COW` — and
/// neither was the Linux layout. There is one formatter, in [`super::maps`].
/// The calling task's; nothing for a task with no address space.
pub fn proc_maps_dump(buf: &mut ffi::proc_data) {
    let Some(regions) =
        taskview::with_current_mm(|mm| resolve(walk(&pagetable::memlock::ReadGuard::of(&mm.mem))))
    else {
        return;
    };
    crate::maps::format(&regions, buf);
}
