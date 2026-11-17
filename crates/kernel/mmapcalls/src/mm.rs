//! An address space's lifetime, the anonymous-page budget, and the page-table
//! questions the syscalls ask.
//!
//! The page table itself — `pt_map`, `pt_unmap`, the copy-on-write fault, the
//! TLB — is the ABI-backed page-table layer: its layout is a contract with
//! `emu/tlb.h`'s inline lookup and with the gadgets through `cpu-offsets.h`,
//! which is step 6. What is here is everything that *asks* it something.
//!
//! # `struct mem`'s lock stays an ABI-backed primitive
//!
//! It is a `wrlock_t` — a reader/writer lock with owner tracking — and a crate
//! cannot take one without either mirroring the layout or calling in. Calling in
//! is the half that does not have to be unpicked when `struct mem` moves, so
//! `pagetable::memlock` keeps the lock operations behind one Rust-owned
//! boundary and the existing ABI-backed lock primitive.
//!
//! # The anonymous-page budget counts readable pages only
//!
//! A guest that maps more than the budget gets `ENOMEM` rather than the host
//! running out. It counts only pages that are readable because the Go runtime
//! alone reserves about 1.1 GB of `PROT_NONE`, and charging for that would
//! refuse every Go program.

use std::ffi::{c_int, c_uint};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::ffi;
use crate::mmflags;
use crate::remap;
use pagetable::memlock::{Held, WriteGuard};

// `struct mem`'s lock is `crates/kernel/pagetable`'s `memlock` as of
// 2026-09-06, called as ordinary Rust.

use guest_errno::c_int_::{EACCES, EBADF, EINVAL, ENODEV};

// ------------------------------------------------------ the address space

/// An address space ready for [`mem_init`].
///
/// **`mm_new_from` used `libc::malloc` and set six of the sixteen fields**
/// until 2026-09-12, so `vdso`, the argv, environment and auxv ranges,
/// `stack_start`, `exe_bias` and `exe_entry` were whatever the heap held.
/// `execve` publishes the new space with the `swap` in
/// `crates/kernel/execcalls`' `load.rs` and *then* runs
/// `place_image`/`finish_stack`, so those were readable through
/// `/proc/<pid>/stat`, `/cmdline`, `/environ` and `/auxv` in between. They are
/// `mem.image` now, whose `Default` is zero for each, and zero is what each of
/// them *means*: nothing mapped there yet.
pub(crate) fn blank_mm(prctl_flags: u32) -> ffi::mm {
    ffi::mm {
        // Filled in by `mem_init`, which is the only thing that may build
        // one -- it makes a page-table root and a block cache.
        mem: ffi::mem::default(),
        prctl_flags: AtomicU32::new(prctl_flags),
        futex_hash: AtomicU32::new(0),
    }
}

/// A fresh address space. `from` is the space it replaces -- an `execve`'s --
/// or `None` for the first process; what carries over is the `prctl` flags, by
/// [`mmflags::inherit`], which is Linux's `mm_init` reading
/// `current->mm->flags`.
///
/// **Never null, since 2026-10-01**, and an `Arc` since 2026-10-16. It was `std::alloc::alloc`
/// with a null test so that `execve` and `fork` could answer `ENOMEM` -- for
/// the `struct mm` alone. `mem_init` then built the page table and the block
/// cache with allocations that abort like every other in Rust, so the error
/// the callers reported was one allocation out of several, and the three null
/// tests and their unwinds were the cost of it.
pub fn mm_new_from(from: Option<&ffi::mm>) -> Arc<ffi::mm> {
    let inherited = from.map_or(0, |mm| mmflags::inherit(mm.prctl_flags.load(Ordering::Relaxed)));
    fresh(blank_mm(inherited))
}

/// An `mm` in its `Arc`, with its address space initialised in place -- the
/// page table and block cache keep pointers into it, so it is built where it
/// will live -- and the teardown its last reference runs installed.
fn fresh(mm: ffi::mm) -> Arc<ffi::mm> {
    ffi::set_mm_teardown(teardown);
    let mut mm = Arc::new(mm);
    let only = Arc::get_mut(&mut mm).expect("a new Arc is unique");
    // SAFETY: just made, and nothing else can see it.
    unsafe { pagetable::mem_init(&raw mut only.mem) };
    mm
}

/// What the last reference to an address space does: tear down the page
/// table and block cache. The executable is a field that releases itself. It
/// was the body of `mm_release`'s `fetch_sub(1) == 1` until 2026-10-16.
fn teardown(mm: &mut ffi::mm) {
    // SAFETY: the last reference, so nothing holds its lock.
    unsafe { pagetable::mem_destroy(&raw mut mm.mem) };
}

/// The calling process's `mm->flags`, or 0 for a task with no address space.
/// `prctl` writes them from one thread while `mmap` on another reads them
/// under a lock the writer does not hold, which is why they are atomic.
pub(crate) fn current_flags() -> u32 {
    taskview::with_current_mm(|mm| mm.prctl_flags.load(Ordering::Relaxed)).unwrap_or(0)
}

/// Replace the calling process's `mm->flags` with what `change` makes of
/// them, or answer the errno `change` refused with.
///
/// Not a compare-exchange: Linux's `prctl_set_mdwe` reads the flags and
/// `set_bit`s them in two steps too, so two threads racing a `prctl` end with
/// whichever wrote last, there as here.
fn change_current_flags(change: impl FnOnce(u32) -> Result<u32, c_int>) -> c_int {
    taskview::with_current_mm(|mm| {
        let f = &mm.prctl_flags;
        match change(f.load(Ordering::Relaxed)) {
            Ok(new) => {
                f.store(new, Ordering::Relaxed);
                0
            }
            Err(e) => e,
        }
    })
    .unwrap_or(EINVAL)
}

/// The `prctl` options that read or write `mm->flags`, for
/// `crates/kernel/misccalls`. The rules are [`mmflags`]'s; this is the
/// calling process's copy of them.
pub mod prctl {
    use super::*;

    fn answer(r: Result<c_int, c_int>) -> c_int {
        r.unwrap_or_else(|e| e)
    }

    pub fn thp_disable_get(a2: u64, a3: u64, a4: u64, a5: u64) -> c_int {
        answer(mmflags::thp_get(current_flags(), a2, a3, a4, a5))
    }

    pub fn thp_disable_set(a2: u64, a3: u64, a4: u64, a5: u64) -> c_int {
        change_current_flags(|f| mmflags::thp_set(f, a2, a3, a4, a5))
    }

    pub fn mdwe_get(a2: u64, a3: u64, a4: u64, a5: u64) -> c_int {
        answer(mmflags::mdwe_get(current_flags(), a2, a3, a4, a5))
    }

    pub fn mdwe_set(a2: u64, a3: u64, a4: u64, a5: u64) -> c_int {
        change_current_flags(|f| mmflags::mdwe_set(f, a2, a3, a4, a5))
    }
}

/// Does any mapped page of the range have flags `pred` is true of? An
/// unmapped page is not asked: whether the range has one is a different
/// answer (`ENOMEM`) that the operation itself gives.
pub(crate) fn any_mapped_page(held: &impl Held, page: u64, pages: u64, pred: impl Fn(u32) -> bool) -> bool {
    held.extents(page, pages).any(|x| pred(x.flags))
}

/// A copy for `fork`: the same mappings, copy-on-write.
///
/// It was `copy_nonoverlapping` of the whole struct followed by undoing the
/// three things that must not be shared -- the refcount, the `prctl` flags,
/// and `mem.lock`, which had to be zeroed because `wrlock_init` refuses to
/// reinitialise the same address. Now the child is a fresh space, and what it
/// inherits is the image, cloned under the parent's lock (a reference to the
/// executable of its own included), the flags by [`mmflags::inherit`], and
/// the mappings.
///
/// Takes both write locks, so this thread holds neither: holding one deadlocks.
pub fn mm_copy(parent: &ffi::mm) -> Arc<ffi::mm> {
    let new = fresh(blank_mm(mmflags::inherit(parent.prctl_flags.load(Ordering::Relaxed))));
    {
        // The child's lock too, though no other thread can reach it yet: it
        // costs one uncontended acquisition, and it is what lets the copy be
        // a method that asks for both.
        let mut from = WriteGuard::of(&parent.mem);
        let mut child = WriteGuard::of(&new.mem);
        *child.image_mut() = from.image().clone();
        from.copy_on_write_into(&mut child, 0, ffi::MEM_PAGES);
    }
    new
}

/// One counted reference to an address space, released when it is dropped.
///
/// Three readers of *another* task's address space -- `/proc/<pid>/mem` and
/// friends, `/proc/<pid>/stat`, and `process_vm_readv`/`writev` -- each
/// wrote `mm_retain` under `general_lock` and an `mm_release` somewhere later,
/// two of them in a guard of their own holding the pointer as a `usize`. The
/// retain has to happen under that lock and nothing else about it varies, so
/// it is one type, over the `Arc` the task's slot holds.
pub struct MmRef(Arc<ffi::mm>);

/// A `&mm` is sound: what other threads write in it is atomic or under
/// `mem.lock`, inside `mem.locked`'s cell.
impl std::ops::Deref for MmRef {
    type Target = ffi::mm;
    fn deref(&self) -> &ffi::mm {
        &self.0
    }
}

impl MmRef {
    /// Another reference to the space in `slot`, or `None` for an empty one --
    /// a task mid-exit, or a kernel task, has no address space.
    ///
    /// # Safety
    /// Nothing can take the slot's reference during this call: in practice, the caller holds the owning task's
    /// `general_lock`, which is what `execve` and `do_exit` hold while they
    /// swap `task->mm` and release the old one.
    unsafe fn retain(slot: &taskview::ArcSlot<ffi::mm>) -> Option<MmRef> {
        // SAFETY: the caller's contract -- every taker of the slot holds that
        // lock.
        unsafe { slot.clone_arc() }.map(MmRef)
    }

    pub fn as_ptr(&self) -> *mut ffi::mm {
        Arc::as_ptr(&self.0).cast_mut()
    }

    /// The `struct mem` embedded in it, which is what the page-table layer
    /// takes.
    pub fn mem(&self) -> *mut ffi::mem {
        std::ptr::from_ref(&self.0.mem).cast_mut()
    }

    /// The address space locked for reading, for no longer than this
    /// reference keeps it live.
    pub fn read(&self) -> pagetable::memlock::ReadGuard<'_> {
        pagetable::memlock::ReadGuard::of(&self.0.mem)
    }

    /// As [`MmRef::read`], for writing.
    pub fn write(&self) -> WriteGuard<'_> {
        WriteGuard::of(&self.0.mem)
    }
}

/// `task->general_lock`, which guards `task->mm` across the swap `execve` does,
/// held for a scope.
///
/// Holding it is what stops a `/proc/<pid>` reader retaining an `mm` that is
/// about to be freed — and neither `execve` nor `do_exit` holds `pids_lock`
/// while swapping, which is why this lock is not redundant with that one.
///
/// Here rather than beside each caller because the rule it enforces is one
/// rule and was written out twice: **read `task->mm` under this and retain it
/// before releasing, or the refcount may already have reached zero and the
/// retain is a resurrection**. `crates/fs/proc` had the only copy and
/// `crates/kernel/procvmcalls` was written without it -- the pair `pids_lock`
/// then this is what the two `mm` readers in the tree have in common, and a
/// guard is how it stops being something each new one has to be told.
///
/// Taken *after* `pids_lock`, which is the order `tools/lock-order.py` knows.
///
/// **Every writer of a published task's `mm` slot holds it**: `execve`'s
/// swap, `do_exit`'s take, the group-exit valve's hand-over, and the failed
/// clone's unwind. That is what makes [`GeneralGuard::mm`] safe, and the four
/// `unsafe` retains it replaced each said so separately.
#[must_use = "dropping it releases the lock"]
pub struct GeneralGuard<'a> {
    task: &'a ffi::task,
    _held: locks::mutex::Guard<'a>,
}

impl<'a> GeneralGuard<'a> {
    /// The lock of a task the caller has borrowed, which is the proof it is
    /// live for `'a`. Taking it twice on one thread deadlocks, which
    /// `-DLOCK_DEBUG=1` names.
    pub fn of(task: &'a ffi::task) -> GeneralGuard<'a> {
        GeneralGuard { task, _held: locks::guard!(&task.general_lock) }
    }

    /// A reference to the task's address space, or `None` for a task mid-exit
    /// or one that never had one.
    pub fn mm(&self) -> Option<MmRef> {
        // SAFETY: every taker of the slot holds this lock; see the type.
        unsafe { MmRef::retain(&self.task.mm) }
    }
}

/// Where a new image's stack put its strings and auxiliary vector, as
/// [`record_stack_ranges`] stores them.
#[derive(Clone, Copy, Debug)]
pub struct StackRanges {
    pub argv: (u64, u64),
    pub env: (u64, u64),
    pub auxv: (u64, u64),
    pub stack_start: u64,
}

/// Store the calling task's stack ranges, under the write lock that
/// `/proc`'s readers of `mem.image` hold, all in one hold.
///
/// `execve`'s `finish_stack` wrote these six words one or three at a time
/// with `mem->lock` released -- it has to be, to copy the strings onto the
/// guest stack -- while `/proc/<pid>/cmdline`, `environ` and `auxv` read them
/// under the read lock, and the comment there said their writers held the
/// write lock. Nothing was shared, so a reader could pair one image's start
/// with another's end. Found by reading on 2026-10-16; it needs a procfs read
/// during an `execve` and has no test.
pub fn record_stack_ranges(r: StackRanges) {
    let mut held = crate::mem_write();
    let image = held.image_mut();
    image.argv = r.argv;
    image.env = r.env;
    image.auxv = r.auxv;
    image.stack_start = r.stack_start;
}

/// `IUL_NO_DONTNEED=1` treats `MADV_DONTNEED` as a no-op, to test whether the
/// in-place zeroing loses concurrent writes.
pub(crate) fn mmap_no_dontneed() -> bool {
    util_iulenv::env().no_dontneed
}

// ------------------------------------------------ what the syscalls ask a page

/// The file half of an `mmap`: find the descriptor, ask its filesystem to map
/// it, and record which file and offset the pages came from.
///
/// One call because it is one operation. The reference `f_get` takes is
/// released when the syscall returns; the `fd_retain` here is the mapping's own.
pub(crate) fn mmap_map_file(
    guard: &mut WriteGuard,
    fd_no: c_int,
    page: u64,
    pages: u64,
    offset: i64,
    prot: c_uint,
    flags: c_uint,
) -> c_int {
    let Some(fd) = fs_fdobj::f_get(fd_no) else {
        return EBADF;
    };
    if file_access_refused(&fd, prot, flags) {
        return EACCES;
    }
    map_file_pages(guard, &fd.retain(), page, pages, offset, prot, flags)
}

/// Whether a shared mapping of `fd` may ever be writable: Linux's
/// `VM_MAYWRITE`, which `do_mmap` clears for a descriptor not open for writing
/// and `memfd`'s seal check clears under `F_SEAL_WRITE`.
pub(crate) fn shared_may_write(fd: &ffi::fd) -> bool {
    fd.flags() & ffi::O_ACCMODE_ != 0 && !memfdcalls::shared_write_sealed(fd)
}

/// `do_mmap`'s refusals for the descriptor itself, before anything is
/// mapped: a file not open for reading cannot be mapped at all, and one not
/// open for writing cannot be mapped shared and writable. The host refused
/// both instead, which answered `ENOMEM`.
pub(crate) fn file_access_refused(fd: &ffi::fd, prot: c_uint, flags: c_uint) -> bool {
    let mode = fd.flags() & ffi::O_ACCMODE_;
    let shared_write = flags & ffi::MMAP_SHARED != 0 && prot & ffi::P_WRITE != 0;
    mode == ffi::O_WRONLY_ || (shared_write && mode == 0)
}

/// The part of [`mmap_map_file`] that `mremap` shares: ask the file's
/// filesystem to map `pages` of it from `offset` at `page`, and record which
/// file and offset the pages came from. The mapping keeps a reference of its
/// own to `fd`.
pub(crate) fn map_file_pages(
    guard: &mut WriteGuard,
    fd: &fs_fdobj::Owned,
    page: u64,
    pages: u64,
    offset: i64,
    prot: c_uint,
    flags: c_uint,
) -> c_int {
    // `ENODEV` for a driver that cannot be mapped, which is Linux's
    // `if (!file->f_op->mmap) return -ENODEV` in `do_mmap`.
    let Some(ops) = fd.ops else {
        return ENODEV;
    };
    let Some(err) = (unsafe {
        ops.mmap(
            fd,
            guard.mem(),
            page,
            pages,
            offset,
            prot as c_int,
            flags as c_int,
        )
    }) else {
        return ENODEV;
    };
    if err < 0 {
        return err;
    }
    // `set_file_backing` takes the descriptor's reference and `Data`'s
    // destructor gives it back, so the retain and the close are one type's
    // rather than one here and one in the page table's unmap. `shared` is
    // recorded so the page table can say when the mapping is gone; see
    // `crates/kernel/memfdcalls`' `shared_mapping_gone`.
    guard.set_file_backing(page, fd.clone(), offset as usize, flags & ffi::MMAP_SHARED != 0);
    0
}

/// The mapping a range describes, if it describes one. `mremap` needs both
/// halves of that: `None` is a hole or a boundary, which it answers `EFAULT`
/// for, and the flags are what a growth is mapped with.
///
/// The decision is `crate::remap::uniform`, which compares the *mapping* bits
/// and not the per-page ones; comparing every bit made a private mapping that
/// had been half copied after a fork "not uniform", which is what stopped apt.
/// The C had `&&` here once, so the flags were compared only when there was no
/// entry to read them from — a guaranteed null dereference on a range with a
/// hole, and no uniformity check at all otherwise.
///
pub(crate) fn uniform_flags(held: &impl Held, start: u64, pages: u64) -> Option<u32> {
    remap::uniform((start..start + pages).map(|page| held.pt(page).map(|entry| entry.flags())))
}

/// What a growth of a range is made of: the decision from
/// [`remap::backing`], and the descriptor to make a file extension from.
pub(crate) struct Extension {
    backing: remap::Backing,
    /// `None` for an anonymous range. A reference of its own since
    /// 2026-10-17: it borrowed the mapping's, which made "the mapping is still
    /// mapped" part of [`extend`]'s contract.
    fd: Option<fs_fdobj::Owned>,
}

/// Read what backs the range that ends at `last`.
///
/// `None` for a file range this kernel cannot extend: one whose data records
/// no descriptor. Nothing maps one today — the ELF loader reads segments into
/// anonymous pages — so this is the case that says so rather than the one
/// that hands out zeroes.
///
/// `last` is a mapped page of a uniform range with `flags`.
pub(crate) fn extension_of(held: &impl Held, last: u64, flags: u32) -> Option<Extension> {
    let entry = held.pt(last).expect("`last` is a mapped page");
    // A private copy grows the file mapping it was copied from.
    let (data, offset_in_data) = entry
        .file_page()
        .unwrap_or_else(|| (entry.data().expect("a mapped page has a mapping"), entry.offset));
    let (file_offset, offset_in_data, fd) = (data.file_offset() as u64, offset_in_data as u64, data.fd().cloned());
    let backing = remap::backing(flags, file_offset, offset_in_data);
    if matches!(backing, remap::Backing::File { .. }) && fd.is_none() {
        return None;
    }
    Some(Extension { backing, fd })
}

/// Map `pages` fresh pages at `at` as the continuation of the range `ext` was
/// read from, with nothing mapped on failure.
///
/// `at..at + pages` is a hole: what `mremap` checked before calling. A
/// correctness rule rather than a safety one -- mapping over occupied pages
/// replaces them, which is wrong and not unsound -- so this is not `unsafe`
/// since 2026-10-17, when the descriptor half of its contract went.
pub(crate) fn extend(
    guard: &mut WriteGuard,
    at: u64,
    pages: u64,
    flags: u32,
    ext: &Extension,
) -> Result<(), guest_errno::Errno> {
    match ext.backing {
        remap::Backing::Anonymous => {
            // Asked first, as `mmap` asks: the budget is what stands between a
            // guest and the host running out. Only for pages it counts --
            // `PROT_NONE` anonymous memory is address space and nothing else.
            // The charge itself is `pt_map_nothing`'s.
            if flags & ffi::P_NOACCESS == 0 && !pagetable::anonbudget::anon_pages_would_fit(pages) {
                return Err(guest_errno::Errno::ENOMEM);
            }
            guard.map_nothing(at, pages, flags)
        }
        remap::Backing::File { offset } => {
            let fd = ext.fd.as_ref().expect("`extension_of` refuses a file range with no descriptor");
            let err = map_file_pages(
                guard,
                fd,
                at,
                pages,
                offset as i64,
                flags & !ffi::P_ANONYMOUS,
                remap::mmap_flags_for(flags),
            );
            if err < 0 { Err(guest_errno::Errno::from_negative_or_eio(err)) } else { Ok(()) }
        }
    }
}

/// What `msync` should do with one page.
pub(crate) enum MsyncPage {
    /// Not mapped at all: Linux reports a range that is not entirely mapped
    /// and flushes **none** of it, so the caller stops there.
    Unmapped,
    /// Mapped, and a shared file mapping: flush the host page at this address.
    Flush(*mut u8),
    /// Mapped with nothing to flush -- a private or anonymous mapping has no
    /// file behind it, exactly as on Linux.
    Nothing,
}

/// Classify one page for `msync`. It was -1/0/1 with the address through an
/// out-pointer until 2026-09-30.
///
pub(crate) fn mmap_msync_page(held: &impl Held, page: u64) -> MsyncPage {
    let Some(entry) = held.pt(page) else {
        return MsyncPage::Unmapped;
    };
    let flushable = entry.flags() & ffi::P_SHARED != 0 && entry.data().is_some_and(|d| d.fd().is_some());
    match entry.host() {
        Some(host) if flushable => MsyncPage::Flush(host),
        _ => MsyncPage::Nothing,
    }
}

/// Is this page part of a mapping at all? A lazy reservation counts: natively it
/// would be a `PROT_NONE` VMA.
///
/// This is what `madvise` and the `mlock` family ask, and answering it wrongly
/// is load-bearing.
pub(crate) fn mmap_page_mapped(held: &impl Held, page: u64) -> bool {
    held.pt(page).is_some() || held.find_reservation(page).is_some()
}

/// What `MADV_DONTNEED` does to one page.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Discard {
    /// Nothing: a page that is not in the table -- a demand-faulted page is
    /// already zero -- a shared page, whose bytes live in the object every
    /// mapping of it reaches (Linux drops this process's page table entries
    /// and the next access finds the same bytes; this zeroed shared anonymous
    /// memory until 2026-11-11, which wiped it for every process that shared
    /// it), and a private file page nobody has written, which is the file's
    /// already.
    Nothing,
    /// Zero it in place: private anonymous memory.
    Zero,
    /// A private copy of a file page: drop it, and the file's page shows
    /// again. Zeroing one **must not** happen: bun `MADV_DONTNEED`s its 164 MB
    /// embedded bytecode cache expecting the bytes to page back in from the
    /// file, and zeroing them corrupted the cache mid-decode.
    Revert,
}

pub(crate) fn mmap_discard(held: &impl Held, page: u64) -> Discard {
    let Some(pt) = held.pt(page) else {
        return Discard::Nothing;
    };
    if pt.flags() & ffi::P_SHARED != 0 {
        return Discard::Nothing;
    }
    match pt.file_page() {
        Some((data, _)) if pt.data().is_some_and(|own| std::sync::Arc::ptr_eq(own, data)) => Discard::Nothing,
        Some(_) => Discard::Revert,
        None => Discard::Zero,
    }
}

// ------------------------------------------------------------ diagnostics

use logline::printk;

/// `IUL_EXEC_TRACE`: log an `mmap` of two megabytes or more.
///
/// Safe: `taskview::current_pid` answers -1 when there is no task, so there is
/// nothing here for a caller to guarantee.
pub(crate) fn mmap_exec_trace(addr: u64, len: u64, prot: c_uint, flags: c_uint, fd_no: c_int) {
    if !util_iulenv::env().exec_trace || len < 0x20_0000 {
        return;
    }
    printk(&format!(
        "MMAP: pid={} addr={addr:#x} len={len:#x} prot={prot:#x} flags={flags:#x} fd={fd_no}",
        taskview::current_pid()
    ));
}

/// `IUL_VMA_TRACE`: does this range touch a file-backed mapping?
///
/// Used to track how guest runtimes reclaim file-backed regions — bun
/// `MADV_DONTNEED`ing its embedded bytecode cache is the case it was written
/// for.
fn hits_file(addr: u64, len: u64) -> bool {
    if !util_iulenv::env().vma_trace {
        return false;
    }
    let Some(guard) = pagetable::memlock::ReadGuard::current() else {
        return false;
    };
    let mut found = false;
    let mut p = addr;
    while p < addr + len && !found {
        if let Some(pt) = guard.pt(p >> ffi::PAGE_BITS)
            && pt.flags() & ffi::P_ANONYMOUS == 0
        {
            found = pt.data().is_some_and(|data| data.fd().is_some());
        }
        p += ffi::PAGE_SIZE as u64;
    }
    found
}

/// The `IUL_VMA_TRACE` and `IUL_PROT_TRACE` diagnostics. `op` is 0 for
/// `munmap`, 1 for `mprotect` and 2 for `madvise`.
///
/// Called unconditionally: the environment flags are plain bools and the check
/// is cheaper than a branch at every call site would be.
///
/// **Must not be called with `mem->lock` held**: `hits_file` takes it for
/// reading. That was an `unsafe` contract until 2026-09-09 and should not have
/// been — a deadlock is not undefined behaviour, and `unsafe` that does not
/// mark a memory-safety obligation trains a reader to skip the ones that do.
pub(crate) fn mmap_trace(op: c_int, addr: u64, len: u64, prot: c_int) {
    // Only MADV_DONTNEED is traced.
    if op == 2 && prot != 4 {
        return;
    }
    if hits_file(addr, len) {
        let pid = taskview::current_pid();
        printk(&match op {
            1 => format!(
                "[vma] mprotect({addr:#x}, {len:#x}, prot={prot:#x}) [file-backed] pid={pid}"
            ),
            2 => format!("[vma] madvise({addr:#x}, {len:#x}, DONTNEED) [file-backed] pid={pid}"),
            _ => format!("[vma] munmap({addr:#x}, {len:#x}) [file-backed] pid={pid}"),
        });
    }
    if util_iulenv::env().prot_trace && op != 2 {
        // The window the trace is about: where a JIT puts its code cage.
        let end = addr + len;
        if end > 0xed00_0000 && addr < 0xf000_0000 {
            printk(&if op == 1 {
                format!("[PROT_TRACE] mprotect({addr:#x}, {len:#x}, prot={prot:#x})")
            } else {
                format!("[PROT_TRACE] munmap({addr:#x}, {len:#x})")
            });
        }
    }
}
