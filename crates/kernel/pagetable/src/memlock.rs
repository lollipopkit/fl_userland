//! Taking `struct mem`'s reader-writer lock.
//!
//! The lock's *lifetime* was this crate's from 2026-09-03 to 2026-10-16, an
//! init and a destroy; `wrlock_t` is ready from `Default` and destroyed by
//! `Drop` now. Taking it stayed in
//! `kernel/memory.c` behind:
//!
//! > `read_wrlock` and its siblings carry the writer-preference spin, the bound
//! > on how long a reader stands aside for a waiting writer, and the
//! > `LOCK_DEBUG` bookkeeping. Reimplementing them in Rust would opt this lock
//! > out of the tree's deadlock diagnostics and put a **second copy of the
//! > fairness rule** in the tree.
//!
//! The second copy was the real half, and it was conditional on the C's
//! staying: `util/sync.h`'s four `static inline`s had exactly one caller, the
//! four wrappers in `kernel/memory.c`, which had no C caller of their own. They
//! are deleted, so this is the only copy and there is nothing to drift against.
//!
//! The fairness rule itself is `crates/util/wrlock`, because there are two
//! locks in this shape — this one and `struct asbestos`'s jetsam lock — and
//! one copy is the whole point.

use crate::space::{Space, SpaceMut};
use crate::{PtEntry, ffi};
use guest_errno::Errno;
use std::ffi::{c_int, c_uint, c_void};
use std::marker::PhantomData;
use std::ptr::NonNull;

/// Take the address space's read lock.
///
/// **Private to this module since 2026-09-16**, along with its three
/// neighbours. They were `pub` for a caller that no longer existed: inside this
/// tree the only takers are the guards below, and the only thing naming them
/// from outside was `tests/live_mappings.rs`, which held the write lock by hand
/// across two address spaces. That test uses [`WriteGuard`] now, so a release
/// it forgets is a compile error rather than a hang.
///
/// Not `#[unsafe(no_mangle)]`: every caller is Rust and names this directly
/// since 2026-09-06. An export no C reaches is a dependency edge cargo cannot
/// check and an optimisation barrier -- and this one is on the path the JIT
/// takes at every quantum boundary.
///
/// # Safety
/// `mem` is live and this thread does not already hold the lock.
unsafe fn mem_read_lock(mem: *mut ffi::mem) {
    // SAFETY: the caller's contract.
    unsafe { locks::wrlock::read_lock(&(*mem).lock) };
}

/// Give the read lock back.
///
/// # Safety
/// This thread holds it for reading.
unsafe fn mem_read_unlock(mem: *mut ffi::mem) {
    // SAFETY: the caller's contract.
    unsafe { locks::wrlock::read_unlock(&(*mem).lock) };
}

/// Take the address space's write lock.
///
/// # Safety
/// `mem` is live and this thread holds neither side.
unsafe fn mem_write_lock(mem: *mut ffi::mem) {
    // SAFETY: the caller's contract.
    unsafe { locks::write_wrlock!(&(*mem).lock) };
}

/// Give the write lock back.
///
/// # Safety
/// This thread holds it for writing.
unsafe fn mem_write_unlock(mem: *mut ffi::mem) {
    // SAFETY: the caller's contract.
    unsafe { locks::wrlock::write_unlock(&(*mem).lock) };
}

/// The host page size, which may be larger than the guest's -- 16 KB on Apple
/// silicon against the guest's 4 KB.
///
/// Read on first use. It was a `__mod_init_func` constructor filling an
/// `AtomicUsize` until 2026-09-29, and `become_first_process` asserted it had
/// run, because a constructor only runs if the linker keeps the object that
/// holds it -- and a zero page size makes every `mprotect` and `msync` compute
/// a zero-length range, silently. Reading on first use has no such failure to
/// check for. `crates/fs/realfs` kept a second, lazy copy for exactly that
/// ordering reason, and reads this one now.
pub fn host_page_size() -> usize {
    static SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SIZE.get_or_init(rustix::param::page_size)
}

/// The read lock, held for a scope.
///
/// Two crates had a private copy of this type until 2026-09-06 —
/// `crates/kernel/usercopy`'s `Held` and `crates/kernel/mmapcalls`' `MemRead`,
/// identical but for the name. A lock guard duplicated is a place the release
/// can drift from the acquire, and neither copy could see the other to drift
/// visibly against it. The lock is this crate's, so the guard is too.
///
/// One acquisition wide on purpose: nothing holds this across two operations,
/// which is what keeps it the shape that does not have to be unpicked when the
/// lock moves.
///
/// # The four guards held a `usize`
///
/// `ReadGuard(usize)`, `WriteGuard(usize)` and the two internal ones each
/// stored the address space as an integer and wrote `self.0 as *mut ffi::mem`
/// to get it back — **eleven integer-to-pointer casts** for a field that is a
/// pointer. `NonNull` says the same thing, makes the null unrepresentable
/// rather than checked nowhere, and costs the same eight bytes.
///
/// A `usize` would be the answer if these had to be `Send`, which is the usual
/// reason to write one. They do not: a guard is a stack local in every one of
/// its twenty call sites, and a lock guard that crosses threads would be a
/// defect rather than a feature — this lock is released by the thread that
/// took it.
///
/// # The lifetime
///
/// `'a` is how long the address space is known to be live. It was absent
/// until 2026-10-02, so every constructor was `unsafe` and a guard could
/// outlive what it locked; `mmapcalls`' `MmRef::read` now ties it to the
/// reference that keeps the space alive, and is safe.
pub struct ReadGuard<'a>(NonNull<ffi::mem>, PhantomData<&'a ffi::mem>);

impl<'a> ReadGuard<'a> {
    /// Take the read lock over a space the caller has borrowed, which is the
    /// liveness [`ReadGuard::new`] asks for; a `&mem` is sound since
    /// 2026-10-17. Taking it twice on one thread deadlocks, which is a bug
    /// and not unsound.
    pub fn of(mem: &'a ffi::mem) -> ReadGuard<'a> {
        // SAFETY: borrowed, so live for `'a`.
        unsafe { ReadGuard::new(std::ptr::from_ref(mem).cast_mut()) }
    }

    /// Take the read lock over `mem`.
    ///
    /// # Safety
    /// `mem` is live — so, non-null — for `'a`. A thread that already holds
    /// either side of its lock deadlocks, which is a bug and not unsound.
    pub unsafe fn new(mem: *mut ffi::mem) -> ReadGuard<'a> {
        // SAFETY: the caller's contract.
        unsafe {
            mem_read_lock(mem);
            ReadGuard(NonNull::new_unchecked(mem), PhantomData)
        }
    }

    /// The address space this guard holds, for the operation that needs it.
    pub fn mem(&self) -> *mut ffi::mem {
        self.0.as_ptr()
    }

    /// The calling task's address space, locked for reading; `None` on a
    /// thread with no task, or for a task whose address space has gone.
    ///
    /// **Safe**, where [`ReadGuard::new`] is not, because both halves of that
    /// contract are answered here or are not memory safety. The address space
    /// is the calling task's own, which the task holds a reference to for as
    /// long as it runs -- only its own `execve` swaps it, and `mem_destroy`
    /// takes the write lock, so it waits for this guard. And a thread that
    /// already holds the lock deadlocks rather than corrupting anything.
    ///
    /// `'static` for the same reason: the space can only go by this thread's
    /// own `execve` or exit, and either one waits for the write lock this
    /// guard keeps it from getting.
    pub fn current() -> Option<ReadGuard<'static>> {
        let mem = std::ptr::NonNull::new(taskview::current_mem())?;
        // SAFETY: as above.
        Some(unsafe { ReadGuard::new(mem.as_ptr()) })
    }

    /// The host address a guest access at `addr` should use, resolving the
    /// fault if there is one -- a stack to grow, a reservation to commit, a
    /// copy-on-write to break. Null if the guest may not have it.
    ///
    /// **`&mut self`**: resolving can drop the read lock for the write lock
    /// and take it back, so no entry borrowed from this guard may be alive
    /// across the call. Called on a guest thread; the stack-growth limit reads
    /// the calling task's, and panics on a thread with none.
    pub fn resolve(&mut self, addr: u64, kind: c_int) -> *mut u8 {
        // SAFETY: this guard holds the read lock and nothing borrows it.
        unsafe { crate::fault::mem_ptr(self.mem(), addr, kind) }
    }
}

impl Drop for ReadGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: this guard is what holds it.
        unsafe { mem_read_unlock(self.0.as_ptr()) };
    }
}

/// Swap the read lock this thread holds for the write lock, run `f`, and take
/// the read lock back — on the way out **and** on an unwind.
///
/// The page-fault path is what this is for: `mem_ptr` is called with the read
/// lock held and has to *map* something, so it drops the read lock, takes the
/// write lock, and puts it back the way it was. That was four hand-written
/// pairs of `mem_read_unlock` / `mem_write_lock` … `mem_write_unlock` /
/// `mem_read_lock`, each four lines apart, and each of them leaving the
/// address-space lock in the wrong state if anything between them unwound.
///
/// The counterpart of [`WriteGuard::without`], which goes the other way for
/// the same reason.
///
/// **The window is real and is not this function's to close**: another thread
/// may map the same page while the lock is down, which is why every caller
/// re-reads the entry after it. Linux's `handle_mm_fault` does the same thing
/// with `mmap_lock` and the same re-read.
///
/// Reached through [`crate::space::ReadHeld::upgraded`], which carries the
/// contract below in a type: the fault path has no guard to borrow, because
/// the lock was taken several frames up on the interpreter's hot path.
///
/// # Safety
/// This thread holds `mem`'s read lock and no other side of it.
pub(crate) unsafe fn upgraded<T>(mem: *mut ffi::mem, f: impl FnOnce() -> T) -> T {
    // SAFETY: the caller's contract.
    unsafe { mem_read_unlock(mem) };
    // SAFETY: as above -- `mem` is live, so it is not null.
    let back = Downgrade(unsafe { NonNull::new_unchecked(mem) });
    // SAFETY: the read lock is down, so this thread holds neither side.
    unsafe { mem_write_lock(mem) };
    let out = f();
    drop(back);
    out
}

/// Puts the read lock back, whether `f` returned or unwound.
struct Downgrade(NonNull<ffi::mem>);

impl Drop for Downgrade {
    fn drop(&mut self) {
        // SAFETY: `upgraded` took the write lock and released the read one.
        unsafe {
            mem_write_unlock(self.0.as_ptr());
            mem_read_lock(self.0.as_ptr());
        }
    }
}

/// The write lock, held for a scope. As [`ReadGuard`].
pub struct WriteGuard<'a>(NonNull<ffi::mem>, PhantomData<&'a ffi::mem>);

impl<'a> WriteGuard<'a> {
    /// As [`ReadGuard::current`], for writing.
    pub fn current() -> Option<WriteGuard<'static>> {
        let mem = std::ptr::NonNull::new(taskview::current_mem())?;
        // SAFETY: as `ReadGuard::current`.
        Some(unsafe { WriteGuard::new(mem.as_ptr()) })
    }

    /// As [`ReadGuard::of`], for writing.
    pub fn of(mem: &'a ffi::mem) -> WriteGuard<'a> {
        // SAFETY: borrowed, so live for `'a`.
        unsafe { WriteGuard::new(std::ptr::from_ref(mem).cast_mut()) }
    }

    /// # Safety
    /// As [`ReadGuard::new`].
    pub unsafe fn new(mem: *mut ffi::mem) -> WriteGuard<'a> {
        // SAFETY: the caller's contract.
        unsafe {
            mem_write_lock(mem);
            WriteGuard(NonNull::new_unchecked(mem), PhantomData)
        }
    }

    pub fn mem(&self) -> *mut ffi::mem {
        self.0.as_ptr()
    }

    /// Run `f` with the write lock released, then acquire it again.
    ///
    /// Guest-memory helpers must not be called while the address-space lock is
    /// held. The guard remains the owner of the lock across the callback, so
    /// the lock is reacquired before the caller continues or the guard drops.
    ///
    /// **`&mut self`**, not `&self`, since 2026-09-16: while `f` runs the lock
    /// is *down*, and the shared form let a caller hand `f` a `&WriteGuard`
    /// whose `mem()` it would then read unlocked. There is nothing to fix at a
    /// call site — all of them own the guard — and the signature is what says
    /// so.
    pub fn without<T>(&mut self, f: impl FnOnce() -> T) -> T {
        // SAFETY: this guard holds the write lock, and `Reacquire` puts it
        // back on both paths out of `f`.
        unsafe { mem_write_unlock(self.0.as_ptr()) };
        let reacquire = Reacquire(self.0);
        let out = f();
        drop(reacquire);
        out
    }
}

/// Reacquire a temporarily released write lock during normal return or panic
/// unwinding, before the owning `WriteGuard` is dropped.
struct Reacquire(NonNull<ffi::mem>);

impl Drop for Reacquire {
    fn drop(&mut self) {
        // SAFETY: `WriteGuard::without` released this lock immediately before
        // creating the guard, and no code in the callback owns it.
        unsafe { mem_write_lock(self.0.as_ptr()) };
    }
}

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: this guard is what holds it.
        unsafe { mem_write_unlock(self.0.as_ptr()) };
    }
}

/// A lock on an address space that this thread holds, for reading or
/// writing -- and so the proof every read of the page table asks for.
///
/// A guard *is* that proof, so through one these are safe calls, and what they
/// answer borrows the guard: an entry cannot outlive the lock, and cannot be
/// held across [`WriteGuard::without`] or a change to the tree, both of which
/// take `&mut self`.
///
/// **Not an `unsafe trait` since 2026-09-30.** It was one because an
/// implementor supplied a raw `*mut ffi::mem` the methods then trusted; an
/// implementor supplies a [`Space`] now, and the only way to make one is the
/// `unsafe` constructor a guard calls while it holds the lock.
pub trait Held {
    fn space(&self) -> Space<'_>;

    /// The entry for `page`, or `None` when nothing is mapped.
    fn pt(&self, page: u64) -> Option<&PtEntry> {
        self.space().pt(page)
    }

    /// Step to the next page that could hold a mapping.
    fn next_page(&self, page: &mut u64) {
        self.space().next_page(page)
    }

    /// Is every page of the range mapped or reserved?
    fn covered(&self, start: u64, pages: u64) -> bool {
        self.space().covered(start, pages)
    }

    /// The extents of a range, in order; see [`Space::extents`].
    fn extents(&self, start: u64, pages: u64) -> crate::Extents<'_> {
        self.space().extents(start, pages)
    }

    /// The lazy reservation covering `page`, as a copy.
    fn find_reservation(&self, page: u64) -> Option<ffi::Reservation> {
        self.space().find_reservation(page)
    }

    /// Is every page in the range unmapped and unreserved?
    fn is_hole(&self, start: u64, pages: u64) -> bool {
        self.space().is_hole(start, pages)
    }

    /// `mincore`'s answer for one page; -1 if it is not mapped.
    fn page_resident(&self, page: u64) -> c_int {
        self.space().page_resident(page)
    }

    /// `SEGV_ACCERR` or `SEGV_MAPERR` for a fault at `addr`.
    fn segv_reason(&self, addr: u64) -> c_int {
        self.space().segv_reason(addr)
    }

    /// Where `execve` put the running image.
    fn image(&self) -> &ffi::Image {
        self.space().image
    }
}

impl Held for ReadGuard<'_> {
    fn space(&self) -> Space<'_> {
        // SAFETY: this guard holds the read lock until it drops.
        unsafe { Space::from_raw(self.mem()) }
    }
}

impl Held for WriteGuard<'_> {
    fn space(&self) -> Space<'_> {
        // SAFETY: this guard holds the write lock until it drops, and
        // `without` releases it only inside a `&mut self` borrow, so nothing
        // borrowing the guard through this is alive then.
        unsafe { Space::from_raw(self.mem()) }
    }
}

/// A range [`WriteGuard::unmap`] was asked to unmap had a page that was not
/// mapped, so nothing was unmapped.
#[derive(Debug, PartialEq, Eq)]
pub struct NotMapped;

/// The changes, which need the write lock and `&mut self`: an entry borrowed
/// through [`Held::pt`] cannot be alive across one.
///
/// **`Result`s since 2026-09-30.** They answered the page table's `c_int` --
/// 0, a negative errno, or for `unmap` a bare -1 -- and `unmap_always` and
/// `copy_on_write_into` answered 0 whatever happened, so the `err < 0` tests
/// their callers wrote were branches nothing could take. `mremap` in
/// `crates/kernel/mmapcalls` said it kept its one-`i64` convention because
/// these did; see it for what that bought.
impl WriteGuard<'_> {
    /// Where `execve` put the running image, to change.
    pub fn image_mut(&mut self) -> &mut ffi::Image {
        self.space_mut().image
    }

    /// The address space, for changing. Borrows the guard mutably, so no
    /// [`Held`] answer can be alive across a change.
    pub fn space_mut(&mut self) -> SpaceMut<'_> {
        // SAFETY: this guard holds the write lock, and the address space it
        // was built over is initialised -- `mem_init` ran before anything
        // could lock it.
        unsafe { SpaceMut::from_raw(self.mem()) }
    }

    /// Unmap a range, or nothing if any page in it is not mapped.
    pub fn unmap(&mut self, start: u64, pages: u64) -> Result<(), NotMapped> {
        self.space_mut().unmap(start, pages)
    }

    /// Unmap whatever of the range is mapped. Cannot fail.
    pub fn unmap_always(&mut self, start: u64, pages: u64) {
        self.space_mut().unmap_always(start, pages)
    }

    /// Map anonymous memory over a range.
    pub fn map_nothing(&mut self, start: u64, pages: u64, flags: c_uint) -> Result<(), Errno> {
        self.space_mut().map_nothing(start, pages, flags)
    }

    /// Reserve a range lazily: no nodes, committed a page at a time.
    pub fn map_lazy(&mut self, start: u64, pages: u64, flags: c_uint) -> Result<(), Errno> {
        self.space_mut().map_lazy(start, pages, flags)
    }

    /// `mprotect`'s change to a range.
    pub fn set_flags(&mut self, start: u64, pages: u64, flags: c_int) -> Result<(), Errno> {
        self.space_mut().set_flags(start, pages, flags)
    }

    /// Set and clear meta bits over a range; see [`SpaceMut::change_meta`].
    pub fn change_meta(&mut self, start: u64, pages: u64, set: u32, clear: u32) {
        self.space_mut().change_meta(start, pages, set, clear)
    }

    /// Relocate `pages` entries from `src` to `dst`. The two ranges must not
    /// overlap, and the destination must be a hole.
    pub fn move_pages(&mut self, src: u64, dst: u64, pages: u64) {
        self.space_mut().move_pages(src, dst, pages)
    }

    /// Point `dst` at what `src` maps as well, leaving `src` mapped; see
    /// [`SpaceMut::duplicate_pages`].
    pub fn duplicate_pages(&mut self, src: u64, dst: u64, pages: u64) {
        self.space_mut().duplicate_pages(src, dst, pages)
    }

    /// Show the file's page again in place of a private copy; see
    /// [`SpaceMut::revert_copy`].
    pub fn revert_copy(&mut self, page: u64) -> bool {
        self.space_mut().revert_copy(page)
    }

    /// Point a range at other pages of one object; see [`SpaceMut::repoint`].
    pub fn repoint(&mut self, start: u64, pages: u64, data: &std::sync::Arc<crate::Data>, offset: usize, flags: u32) {
        self.space_mut().repoint(start, pages, data, offset, flags)
    }

    /// Somewhere to put `size` pages, or `BAD_PAGE`. Moves `mmap_hint`, which
    /// is why it needs the write lock.
    pub fn find_hole(&mut self, size: u64) -> u64 {
        self.space_mut().find_hole(size)
    }

    /// As [`WriteGuard::find_hole`], for a lazy reservation.
    pub fn find_hole_for_reservation(&mut self, size: u64) -> u64 {
        self.space_mut().find_hole_for_reservation(size)
    }

    /// Name the region whose page is `page` for `/proc/<pid>/maps`; nothing if
    /// the page is not mapped.
    pub fn name_region(&mut self, page: u64, name: &'static std::ffi::CStr) {
        if let Some(data) = self.pt(page).and_then(|entry| entry.data()) {
            data.set_name(name);
        }
    }

    /// Record which file the mapping at `page` came from, keeping the
    /// reference `fd` is. The page must be mapped -- a filesystem's `mmap` has
    /// just mapped it -- and have no backing yet. `file_offset` is the offset
    /// `page` maps.
    ///
    /// What is stored is the offset of the host mapping's first byte, which is
    /// `page`'s minus the entry's offset into it: realfs maps from a host-page
    /// boundary and points the first guest page `offset % 16K` bytes in. Every
    /// reader adds a page's own entry offset to it. Until 2026-11-11 the
    /// requested offset was stored as it came, so a mapping at 4096 grown by
    /// `mremap` read its new page from 12288, and `/proc/<pid>/maps` printed
    /// the first page's offset for a mapping whose front had been unmapped
    /// (found by `rarecalls_probe`'s `remap_file_pages` cases).
    pub fn set_file_backing(
        &mut self,
        page: u64,
        fd: fs_fdobj::Owned,
        file_offset: usize,
        shared: bool,
    ) {
        let entry = self.pt(page).expect("the filesystem's mmap just mapped this page");
        let data = entry.data().expect("a mapped page has a mapping");
        debug_assert!(entry.offset <= file_offset, "a mapping starts after the file offset it maps");
        data.set_file_backing(fd, file_offset.saturating_sub(entry.offset), shared);
    }

    /// Give `child` the same mappings as this address space, marked
    /// copy-on-write -- `fork`. Both guards, because both tables change: this
    /// one's entries gain `P_COW`.
    pub fn copy_on_write_into(&mut self, child: &mut WriteGuard, start: u64, pages: u64) {
        assert_ne!(self.0, child.0, "a fork copies into another address space");
        self.space_mut()
            .copy_on_write_into(&mut child.space_mut(), start, pages)
    }

    /// Point `pages` guest pages at host `memory`.
    ///
    /// # Safety
    /// `memory` is a host mapping of at least `pages * PAGE_SIZE + offset`
    /// bytes, which the page table then owns.
    pub unsafe fn map(
        &mut self,
        start: u64,
        pages: u64,
        memory: *mut c_void,
        offset: usize,
        flags: c_uint,
    ) -> Result<(), Errno> {
        // SAFETY: `memory` is the caller's.
        unsafe { self.space_mut().map(start, pages, memory, offset, flags) }
    }
}
