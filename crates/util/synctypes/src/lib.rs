//! `util/sync.h`'s four types: a mutex, a condition variable, a read-write
//! lock, and the bookkeeping `-DLOCK_DEBUG=1` adds to the first.
//!
//! **A crate of its own since 2026-09-09, and the reason is layering.** They
//! lived in `crates/kernel/abi` with everything else the headers used to
//! define, and `struct task` embeds three of them — so `crates/util/locks`,
//! `crates/util/waitfor` and `crates/util/guestlock`, all layer 0, named a
//! `kernel` crate for a mutex. That is one of the reasons
//! `tools/crate-layers.py` exempts `kernel-abi` everywhere, and an exemption
//! is a gate covering nothing.
//!
//! Nothing here does anything: `crates/util/locks` is the behaviour and this is
//! the shape. Depends on `libc` and nothing else, which is what lets any layer
//! name it.
//!
//! # `lock_t` has two layouts
//!
//! `-DLOCK_DEBUG=1` adds the `debug` field, and that is the **only thing in
//! this tree that exercises a second layout** — `CLAUDE.md` asks for the guest
//! suite under it after a migration and not only after a lock change, and this
//! field is why. The numbers in the assertions below were measured from
//! `util/sync.h` under both settings rather than worked out: 96 and 72, with
//! `debug` at 72 and `initialized` at 16.
//!
//! # Every one of them is interior-mutable, and that is load-bearing
//!
//! A lock is *taken through a shared reference* — that is what a lock is for,
//! and it is the only way a `&fd`, a `&Primitive` or a `&inode_data` can be
//! locked at all. Rust spells that permission `UnsafeCell`, and until
//! 2026-09-16 these four types did not: the pthread objects were plain fields,
//! so the whole of each type was `Freeze` and a `&` to one carried LLVM's
//! `noalias readonly`. `crates/util/guestlock` said so in a comment —
//!
//! > the object is behind an `UnsafeCell`-shaped boundary **in practice**
//!
//! — and "in practice" is exactly the part the compiler does not read. See
//! `docs/changelog/2026-09-16-a-mutex-that-was-unsafecell-shaped-in-practice.md`
//! for the emitted attribute.
//!
//! So the bytes a pthread call writes are `UnsafeCell`, and the words *this*
//! tree writes beside them — the owner, the wrlock's reader count and its
//! holder record — are atomics, which is what they always were in the C
//! (`_Atomic int`) and what makes them readable without the lock. The fields
//! are private and the accessors below are the whole interface, so a caller
//! cannot go back to writing the bytes through a `&raw const` cast.
//!
//! Wrapping costs nothing and the assertions in this file are what say so:
//! `UnsafeCell` and every `Atomic*` are `#[repr(transparent)]` over the value,
//! so all four sizes and every offset are unchanged.

#![allow(non_camel_case_types)]

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicUsize, Ordering};

pub use libc::{pthread_cond_t, pthread_mutex_t, pthread_t};

/// The relaxed load and store these accessors use.
///
/// Each of these words is a single value that nothing else is ordered against:
/// the owner is written by the thread that just took the lock and read by a
/// thread asking about *itself*, and the wrlock's holder record is a report.
/// (The wrlock's own state is ordered by `crates/util/locks`, which reaches it
/// through [`wrlock_t::val`] and chooses its orderings there.) Where two of
/// them would have to agree, the answer is
/// the lock, not a stronger ordering — the same reasoning `crates/kernel/abi`'s
/// `struct fd` records for its seven.
const RELAXED: Ordering = Ordering::Relaxed;

#[repr(C)]
pub struct lock_t {
    /// The pthread object. `UnsafeCell` because `pthread_mutex_lock` writes it
    /// and every caller holds only a `&lock_t`; see the module comment.
    m: UnsafeCell<pthread_mutex_t>,
    /// Which thread holds it, as a `pthread_t` widened to a word.
    ///
    /// Atomic, and that is a fix rather than a wrapping: it is written by the
    /// thread that takes the lock and read by [`lock_t::owner`] **without** the
    /// lock, which as a plain field was a data race on every call to
    /// `held_by_this_thread`.
    owner: AtomicUsize,
    /// Only in a `-DLOCK_DEBUG=1` build, which is the one thing in this tree
    /// that exercises a **second layout** -- CLAUDE.md asks for the guest suite
    /// under it after a migration, not only after a lock change, and this field
    /// is why.
    #[cfg(iul_lock_debug)]
    debug: UnsafeCell<lock_t_lock_debug>,
}

// SAFETY: a `lock_t` is shared between threads by definition -- it is the thing
// that makes sharing safe. The `UnsafeCell` bytes are touched only by pthread,
// which is what synchronises them, and the owner word is atomic.
unsafe impl Sync for lock_t {}
// SAFETY: as `Sync`. A `lock_t` may be moved until it is first taken, which is
// when Darwin initialises a statically initialised pthread object in place.
unsafe impl Send for lock_t {}

impl lock_t {
    /// A lock ready to take: `PTHREAD_MUTEX_INITIALIZER`, which Darwin
    /// initialises in place on the first lock, so the value may be moved until
    /// then.
    ///
    /// It was `zero()` until 2026-10-16, an all-zero value that a separate
    /// `unsafe fn init` had to turn into a mutex before use and an `unsafe fn
    /// destroy` had to undo before a free, at eleven sites in seven crates --
    /// and `pids_lock` needed a `__mod_init_func` constructor because a zeroed
    /// static is not a mutex on Darwin. `Drop` is the destroy now.
    ///
    /// A `const fn` and not a `const`: a `const` of a type with interior
    /// mutability is **copied at every use**, so `lock!(&lock_t::NEW)` would
    /// take a lock nobody else can see. `clippy::declare_interior_mutable_const`
    /// is what says so.
    ///
    /// ```
    /// let l = util_synctypes::lock_t::new();
    /// assert_eq!(l.owner(), 0, "a new lock is held by nobody");
    /// ```
    pub const fn new() -> lock_t {
        lock_t {
            m: UnsafeCell::new(libc::PTHREAD_MUTEX_INITIALIZER),
            owner: AtomicUsize::new(0),
            #[cfg(iul_lock_debug)]
            debug: UnsafeCell::new(lock_t_lock_debug {
                file: std::ptr::null(),
                line: 0,
                pid: 0,
                initialized: true,
            }),
        }
    }

    /// The pthread object, for the one crate that calls pthread on it.
    ///
    /// `crates/util/locks` and `crates/util/waitfor` are the only callers; a
    /// `*mut` out of a `&self` is sound here and nowhere else in this tree,
    /// because the field is an `UnsafeCell`.
    pub fn mutex(&self) -> *mut pthread_mutex_t {
        self.m.get()
    }

    /// The thread holding it, or 0. A `pthread_t` as a word, so that this
    /// compiles on both platforms — Darwin's is a pointer and Linux's is a
    /// `c_ulong`.
    pub fn owner(&self) -> usize {
        self.owner.load(RELAXED)
    }

    /// Record the holder. Called by the thread that has just taken the lock,
    /// and with 0 by the one about to release it.
    pub fn set_owner(&self, thread: usize) {
        self.owner.store(thread, RELAXED);
    }

    /// The `-DLOCK_DEBUG=1` bookkeeping.
    ///
    /// # Safety
    /// The caller holds this lock: every read and write of these fields happens
    /// between the acquire and the release.
    #[cfg(iul_lock_debug)]
    pub unsafe fn debug(&self) -> *mut lock_t_lock_debug {
        self.debug.get()
    }
}

/// The owner, which is the only part of a mutex worth printing.
///
/// Hand-written because `#[derive(Debug)]` cannot see through an `UnsafeCell` —
/// and what it used to print was `pthread_mutex_t`'s 56 opaque bytes, which
/// told a reader nothing. Every struct in this tree that embeds a lock and
/// derives `Debug` gets this instead.
impl std::fmt::Debug for lock_t {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.owner() {
            0 => f.write_str("lock_t(free)"),
            t => write!(f, "lock_t(held by {t:#x})"),
        }
    }
}
const _: () = {
    assert!(std::mem::align_of::<lock_t>() == 8, "Alignment of lock_t");
    assert!(
        std::mem::offset_of!(lock_t, m) == 0,
        "Offset of field: lock_t::m"
    );
    assert!(
        std::mem::offset_of!(lock_t, owner) == 64,
        "Offset of field: lock_t::owner"
    );
};
#[cfg(not(iul_lock_debug))]
const _: () = {
    assert!(std::mem::size_of::<lock_t>() == 72, "Size of lock_t");
};
#[cfg(iul_lock_debug)]
const _: () = {
    assert!(
        std::mem::size_of::<lock_t>() == 96,
        "Size of lock_t under LOCK_DEBUG"
    );
    assert!(
        std::mem::offset_of!(lock_t, debug) == 72,
        "Offset of field: lock_t::debug"
    );
};

/// The bookkeeping `-DLOCK_DEBUG=1` adds to every lock: who took it and where,
/// which is what catches recursive locking and unlock-without-lock.
///
/// The name is bindgen's -- a nested `struct lock_debug` is named after its
/// parent -- and `crates/util/locks` and `crates/util/waitfor` import it by it.
/// `file` doubles as "locked": null means nobody holds this.
///
/// The numbers below were measured from `util/sync.h` under both settings
/// rather than worked out: 96 and 72, with `debug` at 72 and `initialized` at
/// 16. There is no generator left to disagree with them, so the check is the
/// `-DLOCK_DEBUG=1` build itself -- a wrong offset makes the first `lock()`
/// read `initialized` out of padding and abort.
#[cfg(iul_lock_debug)]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct lock_t_lock_debug {
    pub file: *const std::ffi::c_char,
    pub line: std::ffi::c_int,
    pub pid: std::ffi::c_int,
    pub initialized: bool,
}
#[cfg(iul_lock_debug)]
const _: () = {
    assert!(
        std::mem::size_of::<lock_t_lock_debug>() == 24,
        "Size of lock_t_lock_debug"
    );
    assert!(std::mem::offset_of!(lock_t_lock_debug, file) == 0);
    assert!(std::mem::offset_of!(lock_t_lock_debug, line) == 8);
    assert!(std::mem::offset_of!(lock_t_lock_debug, pid) == 12);
    assert!(std::mem::offset_of!(lock_t_lock_debug, initialized) == 16);
};
impl Default for lock_t {
    fn default() -> Self {
        lock_t::new()
    }
}

/// **Checked**: pthread answers `EBUSY` for an object somebody holds or is
/// parked on, and the free that follows would turn that into a crash on another
/// thread with nothing left to read. Abort here instead.
impl Drop for lock_t {
    fn drop(&mut self) {
        // SAFETY: `&mut self` -- nobody else can reach it.
        if unsafe { libc::pthread_mutex_destroy(self.m.get()) } != 0 {
            std::process::abort();
        }
    }
}
#[repr(C)]
pub struct cond_t {
    /// As [`lock_t::m`]: `pthread_cond_wait` and `pthread_cond_broadcast` both
    /// write it, and both are reached through a shared reference.
    cond: UnsafeCell<pthread_cond_t>,
}

// SAFETY: as `lock_t`. A condition variable is shared by definition and pthread
// is what synchronises the bytes.
unsafe impl Sync for cond_t {}
// SAFETY: as `Sync`.
unsafe impl Send for cond_t {}

impl cond_t {
    /// The pthread object, for `crates/util/waitfor`.
    pub fn cond(&self) -> *mut pthread_cond_t {
        self.cond.get()
    }
}

/// A condition variable has nothing a reader can use. See [`lock_t`]'s.
impl std::fmt::Debug for cond_t {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cond_t")
    }
}
const _: () = {
    assert!(std::mem::size_of::<cond_t>() == 48, "Size of cond_t");
    assert!(std::mem::align_of::<cond_t>() == 8, "Alignment of cond_t");
    assert!(
        std::mem::offset_of!(cond_t, cond) == 0,
        "Offset of field: cond_t::cond"
    );
};
impl cond_t {
    /// `PTHREAD_COND_INITIALIZER`. As [`lock_t::new`]; Darwin's conditions take
    /// relative timeouts, so no clock attribute is needed.
    pub const fn new() -> cond_t {
        cond_t { cond: UnsafeCell::new(libc::PTHREAD_COND_INITIALIZER) }
    }
}

impl Default for cond_t {
    fn default() -> Self {
        cond_t::new()
    }
}

/// **Checked**: pthread answers `EBUSY` for an object somebody holds or is
/// parked on, and the free that follows would turn that into a crash on another
/// thread with nothing left to read. Abort here instead.
impl Drop for cond_t {
    fn drop(&mut self) {
        // SAFETY: as `lock_t`'s.
        if unsafe { libc::pthread_cond_destroy(self.cond.get()) } != 0 {
            std::process::abort();
        }
    }
}
/// The address-space reader-writer lock: the state is [`wrlock_t::val`] and
/// nothing else, and `crates/util/locks` is the protocol over it.
///
/// **Not a `pthread_rwlock_t` since 2026-11-13.** Darwin's rwlock wedges when
/// the threads waiting in `__psynch_rw_rdlock` are sent signals: from then on
/// every `trywrlock` fails with no thread inside (this type's own count reads
/// 0), some readers stay parked in the kernel, and the rest still get in. Why
/// libpthread gets there was not established. This emulator
/// sends `SIGUSR1` to guest threads constantly (it is how a blocking host call
/// is interrupted), so `tests/guest/src/bin/thread_start_signal.rs` hung 3 runs
/// in 40: one thread parked in `rdlock`, one in `mprotect` spinning on
/// `trywrlock`, and no thread holding either side. A twenty-line C program --
/// four readers, one `trywrlock` writer, one thread sending `SIGUSR1` -- wedges
/// the same way within a second, and runs clean without the signals; the Rust
/// version is `crates/util/locks`' `a_signal_storm_does_not_wedge_the_lock`.
///
/// What a reader parks on while a writer holds it is a mutex and a condition
/// variable, which tolerate the same storm (a spurious wake-up is a recheck).
#[repr(C)]
pub struct wrlock_t {
    /// The lock: the reader count, -1 while a writer holds it, 0 when free.
    ///
    /// `_Atomic int` in `util/sync.h`, where it shadowed the pthread object's
    /// own count; it is the only count now.
    val: AtomicI32,
    /// How many writers are waiting, which is what gives a writer preference
    /// over an arriving reader. `_Atomic int`, as [`wrlock_t::val`].
    writers_waiting: AtomicI32,
    /// How many readers are parked on [`wrlock_t::wake`], so a writer that
    /// releases with none skips the wake-up.
    sleepers: AtomicI32,
    /// Who holds it as a writer, for a hang report. Written under the write
    /// lock and read by a thread that does not hold it, which is why these
    /// three are atomic rather than `UnsafeCell`.
    line: AtomicI32,
    /// See [`wrlock_t::line`].
    file: AtomicPtr<std::ffi::c_char>,
    /// See [`wrlock_t::line`].
    pid: AtomicI32,
    /// What a parked reader holds while it checks [`wrlock_t::val`].
    park: std::sync::Mutex<()>,
    /// What a releasing writer wakes parked readers with.
    wake: std::sync::Condvar,
}

impl wrlock_t {
    /// The lock's state: the reader count, or -1 for a writer.
    pub fn val(&self) -> &AtomicI32 {
        &self.val
    }

    /// How many readers are parked.
    pub fn sleepers(&self) -> &AtomicI32 {
        &self.sleepers
    }

    /// What a reader parks on while a writer holds it: the mutex it checks
    /// under and the condition a releasing writer signals.
    pub fn parking(&self) -> (&std::sync::Mutex<()>, &std::sync::Condvar) {
        (&self.park, &self.wake)
    }

    /// How many writers are waiting.
    pub fn writers_waiting(&self) -> &AtomicI32 {
        &self.writers_waiting
    }

    /// Who holds it as a writer: the call site and the guest pid, or `None`
    /// for nobody.
    ///
    /// **Read without the lock, on purpose**, because the caller is a thread
    /// that is waiting for it and wants to name the holder. The three words
    /// are separate atomics, so a report taken while the holder is changing can
    /// pair one acquisition's file with another's line. That is acceptable in a
    /// hang report and is the reason they are atomics rather than an
    /// `UnsafeCell`: a torn read is a wrong line number, not undefined
    /// behaviour.
    pub fn writer(&self) -> Option<(*const std::ffi::c_char, i32, i32)> {
        let file = self.file.load(RELAXED);
        if file.is_null() {
            return None;
        }
        Some((file, self.line.load(RELAXED), self.pid.load(RELAXED)))
    }

    /// Record the writer holding it. `None` clears the record.
    pub fn set_writer(&self, site: Option<(*const std::ffi::c_char, i32, i32)>) {
        let (file, line, pid) = site.unwrap_or((std::ptr::null(), 0, 0));
        self.file.store(file.cast_mut(), RELAXED);
        self.line.store(line, RELAXED);
        self.pid.store(pid, RELAXED);
    }
}

/// **The bytes pthread writes are inside an `UnsafeCell`** — the property this
/// whole file exists for, as three field projections the compiler checks.
///
/// Each one type-checks only while the field really is an `UnsafeCell`: take
/// the wrapper off any of the three and the *build* fails here, which is a
/// stronger gate than a test and is why it is written this way. The weaker
/// spelling — asserting the type is not `Freeze` — is green with the fix backed
/// out: `lock_t::owner` is an `AtomicUsize`, an `UnsafeCell` inside, so the type
/// is non-`Freeze` whatever `m` is.
///
/// Why it matters is `docs/changelog/2026-09-16-a-mutex-that-was-unsafecell-shaped-in-practice.md`:
/// a lock is taken through a **shared reference**, so the write pthread does
/// has to be one `&` permits, and `UnsafeCell` is the only thing in the
/// language that says so.
const _: () = {
    const fn mutex(l: &lock_t) -> &UnsafeCell<pthread_mutex_t> {
        &l.m
    }
    const fn cond(c: &cond_t) -> &UnsafeCell<pthread_cond_t> {
        &c.cond
    }
    let _ = (mutex, cond);
};

/// The reader count and the waiting writers. See [`lock_t`]'s.
impl std::fmt::Debug for wrlock_t {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "wrlock_t(val {}, {} writers waiting)",
            self.val.load(RELAXED),
            self.writers_waiting.load(RELAXED)
        )
    }
}
// No size: `park` and `wake` are `std`'s, and nothing outside Rust reads this
// layout -- no header names `wrlock_t`. The words a hang report reads are
// first, where a debugger finds them.
const _: () = {
    assert!(std::mem::offset_of!(wrlock_t, val) == 0);
    assert!(std::mem::offset_of!(wrlock_t, writers_waiting) == 4);
    assert!(std::mem::offset_of!(wrlock_t, sleepers) == 8);
    assert!(std::mem::offset_of!(wrlock_t, line) == 12);
    assert!(std::mem::offset_of!(wrlock_t, file) == 16);
    assert!(std::mem::offset_of!(wrlock_t, pid) == 24);
};
impl wrlock_t {
    /// Nobody inside and nobody waiting.
    pub const fn new() -> wrlock_t {
        wrlock_t {
            val: AtomicI32::new(0),
            writers_waiting: AtomicI32::new(0),
            sleepers: AtomicI32::new(0),
            line: AtomicI32::new(0),
            file: AtomicPtr::new(std::ptr::null_mut()),
            pid: AtomicI32::new(0),
            park: std::sync::Mutex::new(()),
            wake: std::sync::Condvar::new(),
        }
    }
}

impl Default for wrlock_t {
    fn default() -> Self {
        wrlock_t::new()
    }
}

/// **Checked**, as `pthread_rwlock_destroy`'s `EBUSY` was: a lock freed while
/// somebody holds it turns into a crash on another thread with nothing left to
/// read. Abort here instead.
impl Drop for wrlock_t {
    fn drop(&mut self) {
        if *self.val.get_mut() != 0 || *self.sleepers.get_mut() != 0 {
            std::process::abort();
        }
    }
}
