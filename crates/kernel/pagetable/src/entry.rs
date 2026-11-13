//! What a mapped guest page is: a page-table entry, and the host mapping
//! several of them share.
//!
//! Both types were `crates/kernel/abi`'s until 2026-09-12, which is to say
//! they were in the list of names every crate agrees on — and neither is one.
//! `iul.h` does not declare them, no assembly indexes them, no `extern "C"`
//! signature names them, and the four crates that read a field of either
//! (`crates/kernel/mmapcalls`, `crates/kernel/execcalls`, `crates/fs/proc` and
//! this one) all already depend on this crate. That is `CLAUDE.md`'s test for
//! a definition nothing in C reads: it is a Rust definition, and it belongs to
//! its owner.
//!
//! # The host mapping is an `Arc`, and what that took
//!
//! `Data` carried a hand-rolled `AtomicU32 refcount` until 2026-09-12: `pt_map`
//! added one per page, `pt_unmap_always` subtracted one, and a `fetch_sub`
//! answering 1 ran the teardown. It is `Arc<Data>` now and the teardown is
//! `Drop`, which is object model step 9.1.
//!
//! What made that more than a rename is that **four of the seven fields were
//! written after the object was reachable, from two other crates** — a raw
//! `(*(*entry).data).fd = …` through a pointer nobody owned. An `Arc` hands out
//! `&Data`, so each of those had to become either a constructor argument or an
//! atomic, and deciding which is the useful half of this change:
//!
//! | field | when it is written |
//! | --- | --- |
//! | `host`, `size` | at construction, and never again |
//! | `fd`, `file_offset`, `shared` | once, by `crates/kernel/mmapcalls`' `mmap_map_file` or `crates/kernel/execcalls`' segment loader, immediately after the filesystem's `mmap` op returns — the write lock is held across both, so this is construction spread over two crates |
//! | `name` | genuinely later: `PR_SET_VMA_ANON_NAME`, and `[vdso]`/`[vvar]` |
//!
//! They are `Relaxed` atomics behind setters. Relaxed is enough because
//! `mem->lock` is what orders them — a reader holds it for reading and every
//! writer holds it for writing — and the atomic is there for Rust's aliasing
//! rules rather than for the hardware. Nobody had written that distinction
//! down.
//!
//! **`fd` is owned.** `set_file_backing` takes the reference and `Drop` gives
//! it back, so the `fd_retain` and the `fd_close` are in one type instead of
//! one in `mmapcalls` and one in this crate's `pt_unmap_always`.

use std::ffi::{CStr, c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering::Relaxed};
use std::sync::Arc;

use crate::ffi;


/// How many host mappings are alive.
///
/// **This is the only thing in the tree that can see a leaked mapping**, and a
/// leak is the failure mode of turning a hand-rolled refcount into an `Arc`: a
/// count one too high keeps a host `mmap` and a `struct fd` for ever, and every
/// assertion in the guest suite still passes. Nothing else counts them — the
/// anonymous-page budget is charged and refunded per *page* in
/// `pt_unmap_always`, independently of this object, so it balances either way.
///
/// `Relaxed`: it is a diagnostic, and a reader that wants it to mean anything
/// has to be the only thread mapping. `crates/kernel/pagetable/tests/` is that
/// reader, in a binary of its own for the reason
/// `crates/kernel/eventfd/tests/live_count.rs` gives about its own counter.
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// See [`LIVE`].
pub fn mapping_live_count() -> usize {
    LIVE.load(Relaxed)
}

/// A host mapping that one or more guest pages point at.
///
/// Held as `Arc<Data>`: the strong count is how many page-table entries point
/// here, across every address space that has forked since it was made. **It
/// has to be atomic**, because the parent unmapping under its `mem->lock` and
/// the child under the child's are two threads on one counter with nothing
/// between them. The first version of this crate wrote `-= 1`, and `task_race`
/// — concurrent fork, exec and `/proc` — lost enough updates in one run to
/// reach zero early and take the emulator down on the `0 - 1` at exit, which
/// in a release build would have been a double `munmap` instead.
#[derive(Debug)]
pub struct Data {
    /// The host address. **Not `munmap`ed when it is the vDSO**, which is in
    /// this binary's own data segment rather than a mapping.
    host: *mut c_void,
    size: usize,
    /// The file this is a mapping of, with a reference held. Set once, after
    /// the mapping is reachable -- see the module comment's table -- which is
    /// what a `OnceLock` is: it was an `AtomicPtr` the reference was erased
    /// into with `into_raw` and taken back out of in `Drop`, until 2026-10-17.
    fd: std::sync::OnceLock<fs_fdobj::Owned>,
    /// The file offset of `host`'s first byte; a page's is this plus its
    /// entry's offset. See `WriteGuard::set_file_backing`.
    file_offset: AtomicUsize,
    /// A `MAP_SHARED` file mapping. The page table tells the descriptor when
    /// the last page of one goes, which is what lets a memfd refuse
    /// `F_SEAL_WRITE` with `EBUSY` while one exists.
    shared: AtomicBool,
    /// `[heap]`, `[vdso]` or `[vvar]`, which `/proc/<pid>/maps` prints. Null,
    /// or a `&'static CStr` -- [`Data::set_name`] takes nothing else, which
    /// is what lets [`Data::name`] hand one back safely.
    name: AtomicPtr<c_char>,
    /// The file whose size bounds these pages, for a file mapping. See
    /// `crate::eof`.
    eof: std::sync::OnceLock<crate::eof::Eof>,
    /// For a private copy of a file page, the page it was copied from.
    origin: std::sync::OnceLock<Origin>,
    /// For a copy-on-write copy, the host page its slot is in, which `host`
    /// points into and which is not this mapping's to unmap. See
    /// `crate::copies`.
    chunk: Option<Arc<crate::copies::Chunk>>,
}

/// The file page a private copy was made from.
///
/// Kept because Linux can drop a private copy and show the file's page again:
/// `MADV_DONTNEED` does, and so does a truncation that cuts the page off.
/// It also bounds the copy by the file's end, names the file in
/// `/proc/<pid>/maps`, and says where `mremap` grows the mapping from. The
/// copy keeps the file's mapping alive for as long as it exists.
#[derive(Debug)]
pub(crate) struct Origin {
    data: Arc<Data>,
    /// The page's offset into `data`.
    offset: usize,
    /// Set when a truncation has cut the page off; `None` for a file the
    /// page table cannot ask about, which is never past its end.
    zap: Option<Arc<crate::eof::Zap>>,
}

impl Origin {
    pub(crate) fn new(data: Arc<Data>, offset: usize) -> Origin {
        let zap = data.eof().map(|eof| eof.copy(offset));
        Origin { data, offset, zap }
    }

    pub(crate) fn page(&self) -> (&Arc<Data>, usize) {
        (&self.data, self.offset)
    }
}

// SAFETY: a `Data` is shared between address spaces the moment one of them
// forks, so it crosses threads by construction — the parent unmapping under its
// own `mem->lock` and the child under the child's are two threads on one
// object. `clippy::arc_with_non_send_sync` is what asked the question, and it
// could not be asked while the field was a `*mut data`: the raw pointer made
// the claim implicitly and nothing checked it.
//
// What makes it hold is that **every field is either immutable after
// construction or an atomic**, which the module comment's table is the record
// of, and that the two pointees have synchronisation of their own — `host` is a
// host mapping whose guest-visible contents are guarded by `mem->lock`, and
// `fd` is a `struct fd`, which every syscall already reaches from an arbitrary
// thread. There is no `&mut Data` anywhere: `Arc` hands out shared references
// and the setters take `&self`.
unsafe impl Send for Data {}
// SAFETY: as `Send`. `Sync` is the one actually needed — `Arc<Data>` requires
// both — because the sharing is concurrent rather than a handover.
unsafe impl Sync for Data {}

impl Data {
    /// A mapping with no backing file and no name. [`crate::pt_map`] points
    /// the pages at it.
    pub(crate) fn new(host: *mut c_void, size: usize) -> Arc<Self> {
        Self::with_chunk(host, size, None)
    }

    /// One guest page in a slot of `crate::copies`.
    pub(crate) fn in_slot(slot: crate::copies::Slot) -> Arc<Self> {
        Self::with_chunk(slot.host.cast(), ffi::PAGE_SIZE as usize, Some(slot.chunk))
    }

    fn with_chunk(host: *mut c_void, size: usize, chunk: Option<Arc<crate::copies::Chunk>>) -> Arc<Self> {
        LIVE.fetch_add(1, Relaxed);
        Arc::new(Data {
            host,
            size,
            fd: std::sync::OnceLock::new(),
            file_offset: AtomicUsize::new(0),
            shared: AtomicBool::new(false),
            name: AtomicPtr::new(std::ptr::null_mut()),
            eof: std::sync::OnceLock::new(),
            origin: std::sync::OnceLock::new(),
            chunk,
        })
    }

    /// In a slot of a host page that other mappings share, whose host
    /// protection must not change.
    pub(crate) fn in_shared_host_page(&self) -> bool {
        self.chunk.is_some()
    }

    pub fn host(&self) -> *mut c_void {
        self.host
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// The file the pages came from, borrowed from the mapping's reference.
    pub fn fd(&self) -> Option<&fs_fdobj::Owned> {
        self.fd.get()
    }

    pub fn file_offset(&self) -> usize {
        self.file_offset.load(Relaxed)
    }

    pub fn shared(&self) -> bool {
        self.shared.load(Relaxed)
    }

    /// The region's name, if it has one.
    ///
    /// `'static`, and that is load-bearing: the maps walk carries the name out
    /// of the locked walk and prints it after the lock is gone, when the
    /// mapping may already be unmapped. It was a `*const c_char` until
    /// 2026-09-30 with a comment there saying it was "valid while `fd` is
    /// held" -- which says nothing for the heap, which has no `fd`. What made
    /// it hold was that every name was a literal, and the type says so now.
    pub fn name(&self) -> Option<&'static CStr> {
        let name = self.name.load(Relaxed);
        // SAFETY: the field is only ever null or a `&'static CStr`'s pointer.
        (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) })
    }

    /// Name the region for `/proc/<pid>/maps`.
    pub fn set_name(&self, name: &'static CStr) {
        self.name.store(name.as_ptr().cast_mut(), Relaxed);
    }

    /// Record which file the pages came from, **keeping `fd`**, the caller's
    /// reference. [`Data::drop`] gives it back. Once: the callers hold
    /// `mem->lock` for writing across the filesystem's `mmap` and this, which
    /// is construction spread over two crates.
    ///
    /// Safe since 2026-10-17. It took a `*mut fd` and retained it, on a
    /// promise that the descriptor was live and the backing unset.
    pub fn set_file_backing(&self, fd: fs_fdobj::Owned, file_offset: usize, shared: bool) {
        self.file_offset.store(file_offset, Relaxed);
        self.shared.store(shared, Relaxed);
        if let Some(eof) = crate::eof::Eof::new(fd.clone(), file_offset) {
            let _ = self.eof.set(eof);
        }
        let set = self.fd.set(fd);
        debug_assert!(set.is_ok(), "backing set twice");
    }

    pub(crate) fn eof(&self) -> Option<&crate::eof::Eof> {
        self.eof.get()
    }

    /// Record the file page this private copy was made from.
    pub(crate) fn set_origin(&self, origin: Origin) {
        let set = self.origin.set(origin);
        debug_assert!(set.is_ok(), "origin set twice");
    }

    pub(crate) fn origin(&self) -> Option<&Origin> {
        self.origin.get()
    }
}

impl Drop for Data {
    /// The last page pointing here has gone.
    ///
    /// **This runs with `mem->lock` held for writing**, at every one of the
    /// sites that can hold the last reference — `pt_unmap_always`, which is
    /// also what `mem_destroy` sweeps the whole address space with. That is
    /// today's behaviour and not something the `Arc` introduced: the explicit
    /// teardown this replaces sat at the same place. What is new is that
    /// `tools/lock-order.py --calls` cannot see it, because a destructor is one
    /// level below any call it follows — so the order
    /// `mem->lock → (a driver's close)` is recorded here and nowhere else.
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Relaxed);
        if self.host != crate::vdso_data() && self.chunk.is_none() {
            unsafe { libc::munmap(self.host, self.size) };
        }
        if let Some(fd) = self.fd.take() {
            // A shared mapping's last page: the descriptor may be counting
            // them (a memfd does, for `F_SEAL_WRITE`'s `EBUSY`), and is told
            // **before** its reference goes -- which is why the notification is
            // here rather than after the handle falls out of scope.
            if self.shared.load(Relaxed) {
                crate::shared_mapping_gone(&fd);
            }
        }
    }
}

/// One page's mapping: the host memory behind it, an offset into that, and the
/// flags.
///
/// **`flags` is read *and written* by threads holding only the read lock**, so
/// every access to it has to be atomic. The JIT sets `P_CODE` from `mem_ptr`
/// and `mmu_mark_code_page`, and the ptrace write path adds `P_WRITE|P_COW`,
/// all with the read lock — which excludes neither each other nor the plain
/// readers. A non-atomic read-modify-write there loses the other side's bits,
/// and the bit that matters is `P_CODE`: lose a clear and the page stays marked
/// as holding compiled code after a store has changed it, which is the W^X
/// guarantee gone and stale blocks left runnable.
///
/// Relaxed, because nothing here orders anything. What ordering there is comes
/// from the acquire/release pair on `P_CODE` in `mmu_mark_code_page` and
/// `mmu_code_page_intact`, and every other bit changes only under the write
/// lock. On arm64 a relaxed load of an aligned word is the instruction a plain
/// read compiles to, so this costs nothing on the TLB fill path.
///
/// Not `Copy`: `data` owns a reference and `flags` is an atomic. The leaf array
/// is built with `from_fn` rather than by repeating a `Default`, which is the
/// only place that mattered.
#[derive(Debug, Default)]
pub struct PtEntry {
    /// `None` is an unmapped page, which is what the C's null pointer was.
    data: Option<Arc<Data>>,
    pub offset: usize,
    pub(crate) flags: AtomicU32,
}

impl PtEntry {
    /// The mapping this page points at, or `None` when nothing is mapped.
    ///
    /// A borrow, not a clone: a caller that holds `mem->lock` cannot have the
    /// mapping torn down under it, and taking a reference of one's own would
    /// move the teardown to wherever the caller happened to drop it.
    pub fn data(&self) -> Option<&Arc<Data>> {
        self.data.as_ref()
    }

    /// Points this page at `data`, taking a reference.
    pub(crate) fn set_data(&mut self, data: &Arc<Data>) {
        self.data = Some(Arc::clone(data));
    }

    /// Unmaps this page. The returned handle is the reference the entry held;
    /// dropping it is what can run [`Data::drop`].
    pub(crate) fn take_data(&mut self) -> Option<Arc<Data>> {
        self.data.take()
    }

    /// The host address of this page: the mapping's base plus the entry's
    /// offset into it. `None` when nothing is mapped.
    ///
    /// `wrapping_add` because this only computes an address; whoever
    /// dereferences it holds the lock that keeps the mapping alive.
    pub fn host(&self) -> Option<*mut u8> {
        self.data.as_ref().map(|d| d.host().cast::<u8>().wrapping_add(self.offset))
    }

    /// The file page this entry shows, or for a private copy the one it was
    /// copied from: the file mapping and the page's offset into it. `None`
    /// for anonymous memory.
    pub fn file_page(&self) -> Option<(&Arc<Data>, usize)> {
        let data = self.data.as_ref()?;
        match data.origin() {
            Some(origin) => Some(origin.page()),
            None => data.fd().is_some().then_some((data, self.offset)),
        }
    }

    /// A page of a file mapping wholly past the end of its file.
    pub(crate) fn past_eof(&self) -> bool {
        self.file_page().is_some_and(|(data, offset)| data.eof().is_some_and(|eof| eof.past(offset)))
    }

    /// [`PtEntry::past_eof`], or [`PtEntry::zapped`]: the one question the
    /// miss path asks of a file page.
    pub(crate) fn past_eof_or_zapped(&self) -> bool {
        self.zapped() || self.past_eof()
    }

    /// A private copy that a truncation has cut off since it was made.
    pub(crate) fn zapped(&self) -> bool {
        self.data
            .as_ref()
            .and_then(|d| d.origin())
            .and_then(|o| o.zap.as_ref())
            .is_some_and(|zap| zap.zapped())
    }

    /// The `P_*` flags. Relaxed: they are read by threads holding only the
    /// read lock, and see the type comment for where ordering comes from.
    ///
    /// These three were `unsafe fn`s over a `*mut PtEntry` until 2026-09-30 --
    /// one crate-private copy here and a private copy each in
    /// `crates/kernel/mmapcalls` and `crates/fs/proc`. A `&PtEntry` is the
    /// proof they asked their callers for.
    pub fn flags(&self) -> u32 {
        self.flags.load(Relaxed)
    }

    pub(crate) fn set_flags(&self, flags: u32) {
        self.flags.store(flags, Relaxed);
    }

    pub(crate) fn add_flags(&self, bits: u32) {
        self.flags.fetch_or(bits, std::sync::atomic::Ordering::AcqRel);
    }
}
