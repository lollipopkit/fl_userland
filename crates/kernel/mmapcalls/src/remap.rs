//! What `mremap` may read of a range, and what backs the pages it adds.
//!
//! Two decisions, both pure, and both were wrong until 2026-09-04:
//!
//! - **Which of a page's flags describe the mapping and which describe the
//!   page.** Linux keeps protection, sharing and the file on the vma and keeps
//!   copy-on-write in the page tables; `mremap` refuses a range that spans two
//!   vmas (`EFAULT`) and does not care what the page tables say about any page
//!   in it. This kernel has one flags word per page and compared all of it, so
//!   a private mapping whose pages had been half copied after a fork was "not
//!   uniform" — which is apt, exactly: it forks its fetch methods, then builds
//!   its 24 MB package cache one page at a time, and its first growth answered
//!   `EFAULT` with 975 MB of address space free. `apt-get update` printed
//!   "Dynamic MMap ran out of room" and no Ubuntu package could be installed.
//! - **What backs the pages a growth adds.** For a file mapping they are the
//!   file's *next* pages — the vma keeps its file and its offset runs on. The
//!   comment here said Linux hands out anonymous memory there, and it does
//!   not: a grown file mapping read zeroes where the file had bytes, and a
//!   write through it never reached the file.
//!
//! Both are functions of numbers, so both are tested without an address space.

use crate::ffi;

const PAGE_SIZE: u64 = 1 << ffi::PAGE_BITS;

/// The bits that describe the mapping rather than the page. `P_COW` is what a
/// fork leaves on a private page until it is written, `P_CODE` what the JIT
/// leaves on a page it has compiled; neither is a boundary.
pub const MAPPING_FLAGS: u32 = ffi::P_READ
    | ffi::P_WRITE
    | ffi::P_EXEC
    | ffi::P_GROWSDOWN
    | ffi::P_ANONYMOUS
    | ffi::P_SHARED
    | ffi::P_NOACCESS
    // vma flags on Linux, so a boundary and inherited by a growth: an
    // mlocked mapping grows locked.
    | ffi::P_LOCKED
    | ffi::P_DONTFORK
    | ffi::P_WIPEONFORK;

pub(crate) fn mapping_flags(flags: u32) -> u32 {
    flags & MAPPING_FLAGS
}

/// Whether every page of a range describes the same mapping, and which.
///
/// `None` for a hole (`None` in the input) or a boundary, both of which
/// `mremap` answers `EFAULT` for. The mapping flags come back with the
/// per-page bits already dropped, which is what a growth is mapped with.
pub fn uniform(flags: impl IntoIterator<Item = Option<u32>>) -> Option<u32> {
    let mut pages = flags.into_iter();
    let first = mapping_flags(pages.next()??);
    for page in pages {
        if mapping_flags(page?) != first {
            return None;
        }
    }
    Some(first)
}

/// What backs the pages a growth adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backing {
    /// Fresh zero pages, charged to the anonymous budget.
    Anonymous,
    /// The file's next pages: `offset` is where the page after the range's
    /// last one starts in the file.
    File { offset: u64 },
}

/// From the range's last page: the mapping's flags, the file offset its
/// `struct data` was mapped from, and the page's own offset inside that data.
pub fn backing(flags: u32, data_file_offset: u64, offset_in_data: u64) -> Backing {
    if flags & ffi::P_ANONYMOUS != 0 {
        Backing::Anonymous
    } else {
        Backing::File {
            offset: data_file_offset + offset_in_data + PAGE_SIZE,
        }
    }
}

/// The `mmap` flags a file extension is mapped with: the sharing of the range
/// it extends, and nothing else.
pub(crate) fn mmap_flags_for(flags: u32) -> u32 {
    if flags & ffi::P_SHARED != 0 {
        ffi::MMAP_SHARED
    } else {
        ffi::MMAP_PRIVATE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RW: u32 = ffi::P_READ | ffi::P_WRITE;

    #[test]
    fn copy_on_write_and_code_are_not_boundaries() {
        // apt after a fork: some pages copied, some not.
        let pages = [
            Some(RW | ffi::P_ANONYMOUS),
            Some(RW | ffi::P_ANONYMOUS | ffi::P_COW),
            Some(RW | ffi::P_ANONYMOUS | ffi::P_CODE),
            Some(RW | ffi::P_ANONYMOUS | ffi::P_COW | ffi::P_CODE),
        ];
        assert_eq!(uniform(pages), Some(RW | ffi::P_ANONYMOUS));
    }

    #[test]
    fn a_change_of_protection_or_sharing_is() {
        let base = RW | ffi::P_ANONYMOUS;
        assert_eq!(uniform([Some(base), Some(base & !ffi::P_WRITE)]), None);
        assert_eq!(uniform([Some(base), Some(base | ffi::P_SHARED)]), None);
        assert_eq!(uniform([Some(base), Some(base & !ffi::P_ANONYMOUS)]), None);
        assert_eq!(uniform([Some(base), Some(base | ffi::P_NOACCESS)]), None);
    }

    #[test]
    fn a_hole_is_not_a_range() {
        assert_eq!(uniform([Some(RW), None, Some(RW)]), None);
        assert_eq!(uniform([None]), None);
        assert_eq!(uniform([]), None);
    }

    #[test]
    fn a_growth_is_the_files_next_page() {
        // A mapping made from file offset 0x10000 whose last page is 0x3000
        // into it continues at 0x14000.
        assert_eq!(
            backing(RW | ffi::P_SHARED, 0x10000, 0x3000),
            Backing::File { offset: 0x14000 }
        );
        assert_eq!(
            backing(RW | ffi::P_ANONYMOUS, 0x10000, 0x3000),
            Backing::Anonymous
        );
    }

    #[test]
    fn a_file_extension_keeps_the_ranges_sharing() {
        assert_eq!(mmap_flags_for(RW | ffi::P_SHARED), ffi::MMAP_SHARED);
        assert_eq!(mmap_flags_for(RW), ffi::MMAP_PRIVATE);
    }
}
