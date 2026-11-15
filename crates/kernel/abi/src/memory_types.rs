//! Guest virtual memory and address translation layouts.

use crate::{addr_t, mmu, page_t, pages_t, wrlock_t};

/// An address range promised to the guest but not yet backed -- V8's heap
/// cage, reserved `PROT_NONE` and committed a chunk at a time.
///
/// A `malloc`ed node of an intrusive singly-linked list until 2026-09-29, with
/// a `next` pointer, a clone-and-relink on every split and a `free` on every
/// unlink, and a `!needs_drop` assertion standing where a destructor could not.
/// A value in a `Vec` on [`mem`] now, which the address space owns.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct Reservation {
    pub start: page_t,
    pub pages: pages_t,
    pub flags: std::ffi::c_uint,
}

impl Reservation {
    /// Whether any of `pages` pages from `start` falls in this range.
    pub fn overlaps(&self, start: page_t, pages: pages_t) -> bool {
        self.start < start + pages && self.start + self.pages > start
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pt_node {
    _unused: [u8; 0],
}
/// **Not `Copy` and not `Clone`**, for the reason `struct asbestos` is not:
/// `lock` is a `wrlock_t`, and a copied lock excludes nobody from the original.
/// An address space is not a value anyway — two `mem` with one `pgdir` is a
/// double free — so the derives were wrong twice over. They came from bindgen,
/// nothing used them, and `wrlock_t` losing its own is what said so.
#[repr(C)]
#[derive(Debug, Default)]
pub struct mem {
    /// Everything `lock` protects, in one cell: a `&mem` -- and so a `&mm` --
    /// is sound while another thread holds the write lock and changes it,
    /// because the bytes it changes are behind an `UnsafeCell`. Plain fields
    /// until 2026-10-17, reached only through raw pointers for that reason.
    /// `crates/kernel/pagetable`'s guards are what open it.
    pub locked: std::cell::UnsafeCell<Locked>,
    /// What the gadgets reach through `cpu.mmu`. Its words are atomics, or
    /// written by `mem_init`/`mem_destroy` alone.
    pub mmu: mmu,
    pub lock: wrlock_t,
}

/// The part of an address space under `mem.lock`.
#[repr(C)]
#[derive(Debug, Default)]
pub struct Locked {
    pub pgdir: *mut pt_node,
    pub pgdir_used: std::ffi::c_int,
    pub mmap_hint: page_t,
    pub reservations: Vec<Reservation>,
    /// Where `execve` put the running image.
    pub image: Image,
}

/// Where `execve` put the pieces of the running image, and the executable.
///
/// Fields of `struct mm` until 2026-10-16, each read and written through a raw
/// pointer with a comment naming the lock; a field of [`mem`] now, beside the
/// lock, so a `pagetable` guard hands out `&Image` for reading and `&mut
/// Image` for writing and nothing else can. `Clone` is `fork`'s copy, which
/// takes a reference to the executable of its own.
#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct Image {
    pub vdso: addr_t,
    pub start_brk: addr_t,
    pub brk: addr_t,
    pub argv: (addr_t, addr_t),
    pub env: (addr_t, addr_t),
    pub auxv: (addr_t, addr_t),
    pub stack_start: addr_t,
    /// `[start, end)` of the executable's code and of its data, as Linux's
    /// `load_elf_binary` computes them: the lowest executable `PT_LOAD` to the
    /// end of the highest one's file bytes, and the highest `PT_LOAD`'s start to
    /// the end of its file bytes. `/proc/<pid>/stat` fields 26, 27, 45 and 46.
    pub code: (addr_t, addr_t),
    pub data: (addr_t, addr_t),
    /// The executable's description: a counted reference, released with the
    /// space.
    pub exefile: Option<crate::FdOwned>,
    pub exe_bias: addr_t,
    pub exe_entry: addr_t,
}
const _: () = {
    // 288 until 2026-09-29: `reservations` is a `Vec`, 24 bytes where the
    // list head was 8. `mmu`, which the gadgets reach, is ahead of it. 304
    // until 2026-10-16, when `mmu` lost its `ops` table.
    assert!(std::mem::align_of::<mem>() == 8, "Alignment of mem");
    // Nothing indexes `mem` from assembly: the gadgets reach `mmu` through
    // `cpu.mmu`, and `pagetable`'s `mem_of` computes its offset.
    assert!(std::mem::offset_of!(mem, locked) == 0, "Offset of field: mem::locked");
};
/// Not `Copy`: two of its fields are atomics, and copying an atomic by value is
/// a read with no ordering.
///
/// **Held in an `Arc` since 2026-10-16** -- a task's `mm` is a
/// `taskview::ArcSlot` -- where it was a `Box` with a hand-rolled `refcount`
/// field, `mm_retain` and `mm_release`. That was declined on 2026-09-12 because
/// `Arc::new` cannot fail and `mm_new_from` answered null for `execve` to
/// report `ENOMEM`; the allocation became an aborting `Box` on 2026-10-01, and
/// the `AtomicPtr` boundary that would have stayed raw is what `ArcSlot` is,
/// so both halves of that trade had reversed. Dropping the last reference
/// tears the space down through [`set_mm_teardown`]'s hook.
#[repr(C)]
#[derive(Debug, Default)]
pub struct mm {
    pub mem: mem,
    /// Linux's `mm->flags`, the part a guest can set: `MMF_DISABLE_THP` and
    /// `MMF_HAS_MDWE`, from `prctl`. The bits and every rule about them are
    /// `crates/kernel/mmapcalls`'s `mmflags`; this is only where they live.
    ///
    /// **Atomic** because `prctl` writes it from one thread while `mmap` reads
    /// it from another, with no lock they share. Not named `flags`, because
    /// `tools/atomic-fields.py` attributes a field by name and `flags` is what
    /// half the structs in this tree call something else.
    ///
    /// An `AtomicU32` and not a `c_uint` since 2026-09-08: `kernel/mm.h` said
    /// `_Atomic` and bindgen rendered that as a plain word, so `|= 1` on it
    /// compiled -- which is what that gate exists to catch, and it caught the
    /// header going.
    pub prctl_flags: std::sync::atomic::AtomicU32,
    /// `PR_FUTEX_HASH`'s state for this address space, which is where Linux
    /// keeps it (`mm->futex_phash`). The encoding and every rule about it are
    /// `crates/kernel/futexcalls`'s `hash`; this is only where it lives.
    /// Atomic for the reason `prctl_flags` is. Zero in a new space, which is
    /// what a fork child and an `execve` start with.
    pub futex_hash: std::sync::atomic::AtomicU32,
    /// Per-address-space MPK protection key allocation bitmask (`mm->context.pkey_allocation_map`
    /// on Linux). Bit 0 is reserved for the default key 0. Preserved across `fork` (`mm_copy`)
    /// and reset on `execve` (`mm_new_from`).
    pub pkey_alloc_mask: std::sync::atomic::AtomicU16,
}
// SAFETY: an address space is shared by every thread of a `CLONE_VM` group by
// construction. The page table and the image are under `mem.lock`, reached
// only through `crates/kernel/pagetable`'s guards; `prctl_flags` is an atomic.
// The raw pointers are `mem`'s tree, which the teardown hook frees.
unsafe impl Send for mm {}
// SAFETY: as `Send`.
unsafe impl Sync for mm {}
const _: () = {
    assert!(std::mem::align_of::<mm>() == 8, "Alignment of mm");
    assert!(
        std::mem::offset_of!(mm, mem) == 0,
        "Offset of field: mm::mem"
    );
};

/// What the last reference to an `mm` does: give back the executable and tear
/// down the page table and block cache. `crates/kernel/mmapcalls`'s, which is
/// above this crate, so it is a hook installed before the first `mm` is made.
static MM_TEARDOWN: std::sync::OnceLock<fn(&mut mm)> = std::sync::OnceLock::new();

/// Install the teardown. The first call wins.
pub fn set_mm_teardown(f: fn(&mut mm)) {
    let _ = MM_TEARDOWN.set(f);
}

/// Whether the teardown is installed, for the wiring test.
pub fn mm_teardown_installed() -> bool {
    MM_TEARDOWN.get().is_some()
}

impl Drop for mm {
    fn drop(&mut self) {
        // An `mm` that never had `mem_init` -- a test's `Default` -- owns no
        // page table and has nothing to tear down.
        if self.mem.locked.get_mut().pgdir.is_null() {
            return;
        }
        let teardown = MM_TEARDOWN
            .get()
            .expect("an initialised mm is dropped without crates/kernel/mmapcalls' teardown installed");
        teardown(self);
    }
}
