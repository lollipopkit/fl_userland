//! Page-table mapping, unmapping, protection, and copy-on-write operations.

use std::ffi::{c_int, c_uint, c_void};
use std::sync::Arc;

use guest_errno::Errno;
use taskview::ffi;

use crate::memlock::{self, NotMapped};
use crate::space::SpaceMut;
use crate::{Data, P_META, anonbudget, note_host_map_failure, tree, vdso_data};

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

impl SpaceMut<'_> {
    /// Point `pages` guest pages at `memory`, which the caller has already mapped.
    ///
    /// # Safety
    /// `memory` is a host mapping of at least `pages * PAGE_SIZE + offset` bytes,
    /// which the page table then owns.
    pub unsafe fn map(
        &mut self,
        start: u64,
        pages: u64,
        memory: *mut c_void,
        offset: usize,
        flags: c_uint,
    ) -> Result<(), Errno> {
        if memory == libc::MAP_FAILED {
            return Err(Errno::from_negative_or_eio(kernel_errno::errno_map()));
        }
        // If this fails, the munmap in pt_unmap would probably fail too.
        debug_assert!(
            (memory as usize).is_multiple_of(memlock::host_page_size()) || memory == vdso_data()
        );

        // A `Box`, not `libc::calloc`, since 2026-09-12. The zeroes `calloc`
        // produced were the null `fd`, the null `name` and `shared: false`, and
        // [`Data::new`] names all three -- so a field added to `Data` now has to be
        // given a value here rather than silently being zero.
        //
        // The `ENOMEM` that stood here is gone with it: `Box::new` of 48 bytes
        // aborts rather than answering null, which is what `crates/fs/inode` and
        // `crates/fs/mount` already do for their own small fixed allocations. The
        // guest-visible `ENOMEM` for an `mmap` comes from the host `mmap` above,
        // which still answers `errno_map()`.
        let data = Data::new(memory, pages as usize * ffi::PAGE_SIZE as usize + offset);

        for page in start..start + pages {
            if self.space().pt(page).is_some() {
                self.unmap_always(page, 1);
            }
            let pt = self.entry_new(page);
            pt.set_data(&data);
            pt.offset = (((page - start) << ffi::PAGE_BITS) + offset as u64) as usize;
            pt.set_flags(flags);
        }
        // The loop holds every reference there is. Dropping the last local one
        // here with `pages == 0` frees the mapping immediately, which is what the
        // C's refcount reaching zero did.
        Ok(())
    }

    /// Point the mapped `page` at its copy-on-write copy in `slot`.
    ///
    /// Not an unmap and a map: nothing is given back to the address space,
    /// so neither the anonymous-page budget nor the hole search's hint moves.
    /// Through `map` it moved the hint to every copied page, and an `execve`'s
    /// relocations, which are copies since private file mappings became
    /// copy-on-write, moved where its later `mmap`s were placed.
    pub(crate) fn map_copy(&mut self, page: u64, slot: crate::copies::Slot, flags: c_uint) {
        let data = Data::in_slot(slot);
        self.invalidate(page);
        let pt = self.entry_new(page);
        let original = pt.take_data();
        pt.set_data(&data);
        pt.offset = 0;
        pt.set_flags(flags);
        drop(original);
        self.changed();
    }

    /// Unmap a range, or nothing if any page in it is not mapped.
    pub fn unmap(&mut self, start: u64, pages: u64) -> Result<(), NotMapped> {
        if (start..start + pages).any(|page| self.space().pt(page).is_none()) {
            return Err(NotMapped);
        }
        self.unmap_always(start, pages);
        Ok(())
    }
}

/// Whether a page counts against the anonymous-page budget: anonymous **and**
/// accessible.
///
/// The two halves are not the same question, and treating them as one drove the
/// count negative. `sys_mmap` charges an anonymous mapping only when its
/// protection is not `PROT_NONE`, but `pt_map_nothing` marks every page it maps
/// `P_ANONYMOUS` and the unmap subtracted for all of them -- so a
/// `mmap(64 MB, PROT_NONE)`, which is what glibc reserves for each per-thread
/// malloc arena, subtracted 16384 pages it had never added. Two of those and
/// `anon_pages_used()` is negative, which makes `sysinfo` and `/proc/meminfo`
/// fall back to reporting half the machine and, worse, *raises* the budget:
/// `anon_pages_try_add` compares against a total that has gone below zero, so
/// the thing standing between a guest and the host running out stops standing.
///
/// `PROT_NONE` anonymous memory is address space and nothing else, and Linux
/// does not charge it either -- `mmap` maps it `VM_NORESERVE`. So the rule is
/// accessibility, applied at every place that changes it: the map, the unmap,
/// the move, and `mprotect`.
pub(crate) fn charged(flags: u32) -> bool {
    flags & ffi::P_ANONYMOUS != 0 && flags & ffi::P_NOACCESS == 0
}

impl SpaceMut<'_> {
    /// Unmap whatever of the range is mapped. Cannot fail.
    pub fn unmap_always(&mut self, start: u64, pages: u64) {
        // The hint tells the hole search where to start looking. Reset it when the
        // freed region is above it, so the next mmap(addr=0) can reuse the space.
        if start + pages - 1 > *self.mmap_hint {
            *self.mmap_hint = start + pages - 1;
        }
        self.remove_reservations(start, pages);

        let mut page = start;
        while page < start + pages {
            let Some(pt) = self.space().pt(page) else {
                self.space().next_page(&mut page);
                continue;
            };
            let flags = pt.flags();
            self.invalidate(page);
            // Per page, for an anonymous mapping. That is what makes a partial
            // unmap right: the mapping's reference count does not reach zero, but
            // the guest page is gone.
            if charged(flags) {
                anonbudget::anon_pages_sub(1);
            }
            // The entry's reference, taken out and dropped here. When it is the
            // last one this is where `Data::drop` runs -- `munmap`, the
            // shared-mapping-gone notification and the descriptor's whole
            // teardown, with `mem->lock` held for writing. See that destructor's
            // comment, which is the only record of the order.
            drop(tree::entry_del(self.root, page));
            self.space().next_page(&mut page);
        }
        self.changed();
    }

    /// Map anonymous memory over a range.
    ///
    /// **Host `PROT_NONE` for a guest `PROT_NONE` mapping.** Go's runtime reserves
    /// about 1.1 GB of it for page summaries, and giving that real memory wastes
    /// physical RAM and gets an iOS app killed by jetsam.
    ///
    pub fn map_nothing(&mut self, start: u64, pages: u64, flags: c_uint) -> Result<(), Errno> {
        if pages == 0 {
            return Ok(());
        }
        let readable = flags & (ffi::P_READ | ffi::P_WRITE | ffi::P_EXEC) != 0;
        let host_prot = if readable {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_NONE
        };
        let size = pages as usize * ffi::PAGE_SIZE as usize;
        // SAFETY: a fresh anonymous mapping, which aliases nothing.
        let memory = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                host_prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if memory == libc::MAP_FAILED {
            note_host_map_failure(size);
            return Err(Errno::ENOMEM);
        }
        let flags = flags | ffi::P_ANONYMOUS;
        // **The one place an anonymous page is charged**, against the one place it
        // is given back, which is `unmap_always`. It used to be the callers',
        // and they did not all remember: `sys_mmap` charged, the ELF loader's five
        // calls -- the bss, the vvar and vdso pages, the stack and its guard -- did
        // not, and the unmap refunded for all of them. Every `execve` therefore
        // took the total down, and a `mmap(64 MB, PROT_NONE)` took it down by
        // 16384 more, which is what glibc reserves for each per-thread malloc
        // arena. The total went negative, `sysinfo` and `/proc/meminfo` fell back
        // to reporting half the machine, and the budget *rose*, because
        // `anon_pages_try_add` compares against a number below zero.
        if charged(flags) {
            anonbudget::anon_pages_add(pages);
        }
        // SAFETY: `memory` is the `size` bytes just mapped, handed over whole.
        unsafe { self.map(start, pages, memory, 0, flags) }
    }
}

/// One host `mprotect` for a run of guest pages contiguous in host memory.
///
/// The host page can be larger than the guest's — 16 KB on Apple silicon
/// against the guest's 4 KB — so the start rounds down and the end rounds up.
fn protect_host_run(start: usize, len: usize, prot: c_int) -> c_int {
    // This crate's own static, read through its own accessor. It was
    // `ffi::real_page_size` -- a bindgen-generated `extern` declaration of a
    // symbol defined forty lines away in src/memlock.rs, which is an `unsafe`
    // for a plain load and a header read for a fact the crate already has.
    let page = memlock::host_page_size();
    let begin = start & !(page - 1);
    let end = (start + len + page - 1) & !(page - 1);
    // SAFETY: the range is guest pages the caller holds mapped, rounded out to
    // host pages that belong to the same mappings; `prot` only widens access
    // to memory the page table owns.
    unsafe { libc::mprotect(begin as *mut c_void, end - begin, prot) }
}

/// A run of guest pages being made more permissive, batched into one host
/// `mprotect`.
///
/// One call per *guest* page measured at 318 ns and flat, so V8's 128 MB heap
/// cage — 32768 pages, which it mprotects in one call — took 10.4 ms where a
/// real kernel takes 0.34 ms.
#[derive(Default)]
struct Run {
    at: Option<(usize, usize, c_int)>,
}

impl Run {
    /// Apply and forget whatever has accumulated.
    fn flush(&mut self) -> c_int {
        match self.at.take() {
            Some((start, len, prot)) => protect_host_run(start, len, prot),
            None => 0,
        }
    }

    /// Add one page, or start a new run.
    fn push(&mut self, host: *mut u8, prot: c_int) -> c_int {
        let size = ffi::PAGE_SIZE as usize;
        let host = host as usize;
        if let Some((start, len, run_prot)) = self.at
            && host == start + len
            && prot == run_prot
        {
            self.at = Some((start, len + size, prot));
            return 0;
        }
        let err = self.flush();
        self.at = Some((host, size, prot));
        err
    }
}

impl SpaceMut<'_> {
    /// `mprotect`'s change to a range.
    ///
    /// **Linux's order at a hole**: the pages before the first page that is
    /// neither mapped nor reserved are changed, and the answer is `ENOMEM`. A
    /// caller that wants all or nothing asks [`Space::covered`] first; this
    /// does not, because that is a second walk of the whole range and the
    /// walk is what an `mprotect` of V8's 32768-page cage costs.
    pub fn set_flags(&mut self, start: u64, pages: u64, flags: c_int) -> Result<(), Errno> {
        let mut charge: i64 = 0;
        let result = self.change_protection(start, pages, flags as u32, &mut charge);
        // Whatever was changed before a refusal stays changed, so the budget
        // and the TLB hear about it on every exit. A host failure returned
        // before both until 2026-11-11, leaving other threads' TLBs with the
        // permissions the pages had before.
        if charge > 0 {
            anonbudget::anon_pages_add(charge as u64);
        } else if charge < 0 {
            anonbudget::anon_pages_sub(-charge as u64);
        }
        self.changed();
        result
    }

    /// [`SpaceMut::set_flags`]'s walk. `charge` is the signed change to the
    /// anonymous-page budget, batched because this runs per guest page.
    fn change_protection(&mut self, start: u64, pages: u64, flags: u32, charge: &mut i64) -> Result<(), Errno> {
        let host_error = || Err(Errno::from_negative_or_eio(kernel_errno::errno_map()));
        let end = start + pages;
        let mut run = Run::default();
        let mut page = start;
        while page < end {
            // The mapped pages from `page` up to the first hole.
            let mut hole_end = end;
            for (at, entry) in self.space().mapped(page, end - page) {
                if at != page {
                    hole_end = at;
                    break;
                }
                page += 1;

                let old = entry.flags();
                let new = flags | (old & P_META);
                entry.set_flags(new);
                // An mprotect that makes an anonymous page reachable charges for it and
                // one that takes it away gives it back. Without this a page mapped
                // PROT_NONE and then made writable was never charged, and one made
                // PROT_NONE after being writable was charged for ever.
                *charge += i64::from(charged(new)) - i64::from(charged(old));

                // Only a page whose protection is *increasing* joins a run. A page
                // that needs nothing must not be swept into one: `prot` below has no
                // PROT_EXEC, and may lack PROT_WRITE, so applying it to a page that
                // already had write could take it away.
                //
                // A copy-on-write page is never written where it is: a store
                // breaks the copy first. Asking the host for write there is
                // refused outright for a private file page, which is a shared
                // read-only host mapping of the file (realfs's `map`).
                //
                // And a copy's host page is never changed at all: it holds
                // other mappings' copies too (`crate::copies`).
                //
                // Otherwise the host is asked for write whenever the memory can
                // take it, and not only when this page is to be writable: the
                // host page is 16 KB and holds the guest pages beside this one,
                // which keep whatever protection they had, enforced by their
                // flags. Raising one page of four from PROT_NONE to PROT_READ
                // asked the host for read alone until 2026-11-12, and the next
                // store to a neighbour killed the emulator with SIGSEGV.
                let data = entry.data();
                let in_shared_host_page = data.is_some_and(|d| d.in_shared_host_page());
                let err = if (flags & !old) & (ffi::P_READ | ffi::P_WRITE) != 0 && !in_shared_host_page {
                    let host = entry.host().unwrap();
                    let file_writable = data
                        .and_then(|d| d.fd())
                        .is_some_and(|fd| fd.flags() & ffi::O_ACCMODE_ != ffi::O_RDONLY_);
                    let mut prot = libc::PROT_READ;
                    if new & ffi::P_COW == 0
                        && (flags & ffi::P_WRITE != 0 || new & ffi::P_ANONYMOUS != 0 || file_writable)
                    {
                        prot |= libc::PROT_WRITE;
                    }
                    run.push(host, prot)
                } else {
                    run.flush()
                };
                if err < 0 {
                    return host_error();
                }
            }
            if run.flush() < 0 {
                return host_error();
            }
            if page == end {
                break;
            }
            if !self.space().reserved(page, hole_end) {
                return Err(Errno::ENOMEM);
            }
            // Reservation-only: V8 reserved this chunk of its heap cage
            // PROT_NONE and the guest is now mprotecting it RW. Materialise it
            // -- treat mprotect as "commit this page with the new protection".
            //
            // Coalesced, so the host mmap allocates one VM region rather than
            // one per page: V8 mprotects a whole 128 MB cage in one syscall,
            // and per-page mmap exhausts the iOS vm_map entry limit (about
            // 64k) and answers ENOMEM well before physical memory is tight.
            // That was the primary npm segfault on iPhone 8.
            if flags & (ffi::P_READ | ffi::P_WRITE | ffi::P_EXEC) != 0 {
                // `map_nothing` charges what it maps. A refusal leaves the
                // pages reserved-only, which is what they were.
                let _ = self.map_nothing(page, hole_end - page, flags | ffi::P_ANONYMOUS);
            }
            page = hole_end;
        }
        Ok(())
    }

    /// Set `set` and clear `clear` on every mapped page of a range, leaving the
    /// protection alone: `mseal`, `mlock` and the `madvise` dispositions.
    ///
    /// Only bits of [`P_META`]: a protection bit changed here would bypass the
    /// host `mprotect` that [`SpaceMut::set_flags`] keeps in step, and the
    /// anonymous-page budget with it. A reserved page with no entry has
    /// nowhere to keep a bit and is left as it is.
    pub fn change_meta(&mut self, start: u64, pages: u64, set: u32, clear: u32) {
        debug_assert_eq!((set | clear) & !P_META, 0, "change_meta of a protection bit");
        // `mapped` skips a whole absent subtree, which is what makes
        // `mlockall`'s sweep of the entire address space cheap.
        for (_, entry) in self.space().mapped(start, pages) {
            entry.set_flags((entry.flags() | set) & !clear);
        }
        // A guard changes what an access may do, so every cached translation
        // of these pages has to go.
        self.changed();
    }

    /// Relocate `pages` entries from `src` to `dst` within one address space.
    ///
    /// **Nothing is copied.** A `struct pt_entry` is a pointer to a `struct data`
    /// and an offset into it, so moving a mapping is moving those — which is why
    /// this works for a file-backed mapping as well as an anonymous one, and why
    /// `mremap` no longer has to refuse the first.
    ///
    /// The reference is taken on the way in and released by the unmap on the way
    /// out, rather than transferred by hand. That is one atomic more than strictly
    /// necessary and it keeps every invariant `pt_unmap_always` relies on — the
    /// anonymous-page count included, which is decremented per page there and would
    /// otherwise drift down by the size of every `mremap`.
    ///
    /// The caller has checked that the destination is a hole. **The two ranges
    /// must not overlap**, which is asserted: this walks forwards, so an
    /// overlapping move would read entries it had already written.
    pub fn move_pages(&mut self, src: u64, dst: u64, pages: u64) {
        self.duplicate_pages(src, dst, pages);
        self.unmap_always(src, pages);
    }

    /// [`SpaceMut::move_pages`] without the unmap: `dst` names the same
    /// backing as `src`, and both stay mapped. `MREMAP_DONTUNMAP` of a shared
    /// mapping, where the old range keeps reaching the same pages.
    ///
    /// Not for a private page a store could reach through both: neither entry
    /// is marked copy-on-write here, so the caller is the one that knows the
    /// pages are shared or that it marks them.
    pub fn duplicate_pages(&mut self, src: u64, dst: u64, pages: u64) {
        assert!(
            src + pages <= dst || dst + pages <= src,
            "move_pages of overlapping ranges"
        );
        for i in 0..pages {
            let Some(from) = self.space().pt(src + i) else {
                continue; // a hole inside the range stays a hole
            };
            // Everything read out of `from` before `entry_new` takes the tree
            // mutably -- which the borrow checker insists on: the two entries are
            // in one address space and may share a leaf.
            let data = Arc::clone(from.data().expect("a mapped page has a mapping"));
            let (offset, flags) = (from.offset, from.flags());
            let to = self.entry_new(dst + i);
            to.set_data(&data);
            to.offset = offset;
            // P_CODE is not inherited: the destination pages have no compiled
            // blocks yet and asbestos re-marks on the first compile. Copying it
            // would leave pages marked as code that nothing has translated.
            to.set_flags(flags & !ffi::P_CODE);
            if charged(flags) {
                anonbudget::anon_pages_add(1);
            }
        }
        self.changed();
    }

    /// Point `pages` pages from `start` at `data`, the first `offset` bytes into
    /// it and each after that a page further, with `flags`: `remap_file_pages`
    /// over shared anonymous memory, which rearranges pages inside one object.
    ///
    /// `data` covers `offset + pages` pages; the caller holds a reference, so
    /// unmapping what was there cannot free it.
    pub fn repoint(&mut self, start: u64, pages: u64, data: &Arc<Data>, offset: usize, flags: u32) {
        assert!(offset + (pages << ffi::PAGE_BITS) as usize <= data.size(), "repoint past its object");
        self.unmap_always(start, pages);
        for i in 0..pages {
            let to = self.entry_new(start + i);
            to.set_data(data);
            to.offset = offset + (i << ffi::PAGE_BITS) as usize;
            to.set_flags(flags & !ffi::P_CODE);
            if charged(flags) {
                anonbudget::anon_pages_add(1);
            }
        }
        self.changed();
    }

    /// Drop the private copy at `page` and show the file's page it was
    /// copied from again, copy-on-write: what `MADV_DONTNEED` and a
    /// truncation do to a copy on Linux. Answers whether `page` was one.
    pub fn revert_copy(&mut self, page: u64) -> bool {
        let Some(entry) = self.space().pt(page) else {
            return false;
        };
        let Some((data, offset)) = entry.data().and_then(|d| d.origin()).map(|o| o.page()) else {
            return false;
        };
        let data = Arc::clone(data);
        // Not P_CODE: the copy's compiled blocks go with it.
        let flags = (entry.flags() | ffi::P_COW) & !ffi::P_CODE;
        self.invalidate(page);
        let pt = self.entry_new(page);
        let copy = pt.take_data();
        pt.set_data(&data);
        pt.offset = offset;
        pt.set_flags(flags);
        drop(copy);
        self.changed();
        true
    }

    /// Give `dst` the same mappings as this address space, marked
    /// copy-on-write -- `fork`. Two views, so two write locks: this one's entries
    /// gain `P_COW`.
    pub fn copy_on_write_into(&mut self, dst: &mut SpaceMut<'_>, start: u64, pages: u64) {
        let src = self.space();
        let mut anon_copied: u64 = 0;
        let mut page = start;
        while page < start + pages {
            let Some(entry) = src.pt(page) else {
                src.next_page(&mut page);
                continue;
            };
            dst.unmap_always(page, 1);
            let flags = entry.flags();
            // MADV_DONTFORK: the child has nothing here at all.
            if flags & ffi::P_DONTFORK != 0 {
                src.next_page(&mut page);
                continue;
            }
            // MADV_WIPEONFORK: the child has the mapping, zero-filled, and
            // keeps the disposition; `map_nothing` charges the page. A refusal
            // leaves the child a hole there, which is what it would see of a
            // DONTFORK page -- better than the parent's bytes, which are what
            // the advice exists to keep from it.
            if flags & ffi::P_WIPEONFORK != 0 {
                let keep = flags & !(ffi::P_CODE | ffi::P_COW | ffi::P_LOCKED);
                let _ = dst.map_nothing(page, 1, keep);
                src.next_page(&mut page);
                continue;
            }
            // A shared mapping is not copied on write, which is what MAP_SHARED
            // means: both processes see each other's stores.
            if entry.flags() & ffi::P_SHARED == 0 {
                entry.add_flags(ffi::P_COW);
            }
            let dst_entry = dst.entry_new(page);
            dst_entry.set_data(entry.data().expect("a mapped page has a mapping"));
            dst_entry.offset = entry.offset;
            // Not P_CODE: the child's asbestos has no blocks for this page yet
            // and re-marks on its own first compile. Not P_LOCKED: a lock is
            // the process's, and Linux clears VM_LOCKED in the child.
            dst_entry.set_flags(entry.flags() & !(ffi::P_CODE | ffi::P_LOCKED));
            // `charged()`, not `P_ANONYMOUS`. They are different questions -- the
            // budget counts *accessible* anonymous pages, because a PROT_NONE one
            // is address space and nothing else -- and this was the one of the
            // five places that changes the count which asked the wrong one. The
            // refund in `unmap_always` asks `charged()`, so every fork of a
            // PROT_NONE reservation charged pages nothing would ever give back:
            // 16384 per glibc malloc arena, permanent for the life of the
            // emulator, against a cap of 1048576.
            if charged(entry.flags()) {
                anon_copied += 1;
            }
            src.next_page(&mut page);
        }
        // The child now has its own set of anonymous pages; they are decremented
        // per page when its mm is freed.
        anonbudget::anon_pages_add(anon_copied);

        // All or none: a child missing some of its parent's reservations would
        // fault where the parent does not, and one missing all of them is the same
        // as a refused `malloc` per node was before, only consistent.
        if dst.reservations.try_reserve(src.reservations.len()).is_ok() {
            dst.reservations.extend_from_slice(src.reservations);
        }
        self.changed();
        dst.changed();
    }
}
