//! `remap_file_pages(2)`, as Linux has had it since 4.0: not the nonlinear
//! mapping it once was, but an `mmap(MAP_SHARED | MAP_FIXED)` of the same file
//! at the new page offset over the named range (`mm/mmap.c`).
//!
//! The rules, as `rarecalls_probe` measured them on a 7.2 arm64 kernel:
//!
//! - `prot` must be 0, and the start and size are rounded *down* to pages, so
//!   a size below a page is `EINVAL` and an unaligned start is accepted;
//! - the first page must be a shared mapping; anything else, a hole included,
//!   is `EINVAL`;
//! - a range past that mapping may run on only into mappings of the same open
//!   file description with the same flags and no hole; two descriptors of one
//!   file, or a different protection, is `EINVAL`;
//! - the new pages keep the old mapping's protection and lock, and `flags` is
//!   ignored apart from `MAP_NONBLOCK`, which is a no-op here;
//! - a page offset past the end of the file is accepted, and touching it is
//!   `SIGBUS`, as for any mapping past the end of its file.
//!
//! A shared anonymous mapping is a shmem file on Linux and is remapped the
//! same way; here it is one host object with no descriptor, so its pages are
//! pointed at other offsets inside that object instead.

use std::sync::Arc;

use super::*;

pub fn sys_remap_file_pages(start: u64, size: u64, prot: u64, pgoff: u64, _flags: u64) -> Result<(), Errno> {
    strace!("remap_file_pages({start:#x}, {size:#x}, {prot:#x}, {pgoff:#x})");
    if prot != 0 {
        return Err(Errno::EINVAL);
    }
    let (start, size) = (start & !(PAGE_SIZE - 1), size & !(PAGE_SIZE - 1));
    let pages = size >> PAGE_BITS;
    if start.wrapping_add(size) <= start || pgoff.wrapping_add(pages) < pgoff {
        return Err(Errno::EINVAL);
    }
    let first = page_of(start);
    let mut guard = mem_write();
    let target = target(&guard, first, pages).ok_or(Errno::EINVAL)?;
    advise::refuse_sealed(&guard, first, pages)?;
    // Not what a fork or a `madvise` left on the old pages: the new mapping
    // is a fresh one, with only the lock carried over.
    let flags = target.flags & !(ffi::P_DONTFORK | ffi::P_WIPEONFORK);
    match target.object {
        Object::File(fd) => {
            let offset = pgoff.checked_mul(PAGE_SIZE).and_then(|o| i64::try_from(o).ok()).ok_or(Errno::EOVERFLOW)?;
            let err = map_file_pages(&mut guard, &fd, first, pages, offset, flags, ffi::MMAP_SHARED);
            if err < 0 { Err(Errno::from_negative_or_eio(err)) } else { Ok(()) }
        }
        Object::Anonymous(data) => {
            // The object is the size the mapping was made with, and Linux's
            // shmem file is too; pages past it are SIGBUS there, which a page
            // here cannot point at.
            let offset = pgoff.checked_mul(PAGE_SIZE).ok_or(Errno::EINVAL)? as usize;
            if offset.checked_add(size as usize).is_none_or(|end| end > data.size()) {
                return Err(Errno::EINVAL);
            }
            guard.repoint(first, pages, &data, offset, flags);
            Ok(())
        }
    }
}

/// What the range is a mapping of.
enum Object {
    /// A shared file mapping: the open file description every page records.
    File(fs_fdobj::Owned),
    /// A shared anonymous mapping: the one host object every page points into.
    Anonymous(Arc<pagetable::Data>),
}

struct Target {
    object: Object,
    /// The mapping flags every page shares.
    flags: u32,
}

/// Whether `pages` pages from `first` are one shared mapping in Linux's sense
/// -- one object, one set of mapping flags, no hole -- and of what.
fn target(held: &impl Held, first: u64, pages: u64) -> Option<Target> {
    let entry = held.pt(first)?;
    let flags = remap::mapping_flags(entry.flags());
    if flags & ffi::P_SHARED == 0 {
        return None;
    }
    let data = entry.data()?;
    let object = match data.fd() {
        Some(fd) => Object::File(fd.clone()),
        None if flags & ffi::P_ANONYMOUS != 0 => Object::Anonymous(Arc::clone(data)),
        None => return None,
    };
    for page in first + 1..first + pages {
        let entry = held.pt(page)?;
        if remap::mapping_flags(entry.flags()) != flags {
            return None;
        }
        let data = entry.data()?;
        let same = match &object {
            Object::File(fd) => data.fd().is_some_and(|other| std::ptr::eq(other.as_ptr(), fd.as_ptr())),
            Object::Anonymous(object) => Arc::ptr_eq(data, object),
        };
        if !same {
            return None;
        }
    }
    Some(Target { object, flags })
}
