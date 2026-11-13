//! Copying between a guest address space and the kernel's own — the half that
//! needs a *task*.
//!
//! `crates/kernel/usercopy` owns the copy: the range rule, the page chunking
//! and the terminator rule, which is where all three defects this boundary has
//! had lived, and which can be tested against a `BTreeMap` instead of an
//! address space. What is here is what that crate cannot know — which address
//! space, and the lock over it — and the page lookup, which walks the page
//! table.
//!
//! It was `kernel/user.c`, which is gone. The two crates used to meet through
//! a C ABI with a `static mut` function pointer on the Rust side: `user_init`
//! called `usercopy_bind(usercopy_map, USER_ADDR_MAX_PAGE)` at boot, and every
//! copy went out through `usercopy_read` and back in through the bound
//! callback. Both statics and all four `extern "C"` entry points are gone with
//! it — `Pages` is implemented here, and the bound is a constant this crate
//! generates.
//!
//! # The address-space snapshot is one acquire load
//!
//! The group-exit safety valve can take a stuck sibling's address space away
//! while another thread is copying. Read twice — once to test for null and once
//! to lock — it is a use-after-free, and the symptom is a fault at address
//! 0x38, which is `offsetof(struct mem, lock)`. Snapshotted once here, and the
//! valve leaks the `mm` rather than freeing it, so a non-null snapshot stays
//! valid for the copy.
//!
//! The field read is `task.mm` since 2026-09-11 and was a `task.mem` that
//! cached the interior pointer to it. Same one acquire load; `taskview::mem_of`
//! adds a constant, because `struct mm` embeds its `struct mem` by value.

use std::ffi::c_int;

use pagetable::memlock::ReadGuard;

use crate::{Access, Pages};

use crate::ffi;

const EFAULT: c_int = crate::EFAULT;

/// One address space, for the duration of one copy, with its lock held.
///
/// The guard is `crates/kernel/pagetable`'s -- it owns the lock, so it owns the
/// protocol -- and is released when it drops, so a path that returns early
/// cannot leave it held. It is *one call* wide on purpose: nothing here holds
/// it across two copies. What is left here is the `Pages` impl, which is this
/// crate's subject. There was a `Held` wrapper around it until 2026-10-02,
/// whose safe `new` took a raw `mem` and trusted it.
impl Pages for ReadGuard<'_> {
    fn map(&mut self, addr: u64, len: usize, access: Access) -> Option<*mut u8> {
        let _ = len; // never crosses a page, so one lookup answers it
        let p = self.resolve(addr, access as c_int);
        (!p.is_null()).then_some(p)
    }
}

/// The bound the guest's page numbers put on an address.
///
/// Above it an address does not fault, it **aliases**: the page table masks
/// each level's index, so `p + (1 << 48)` selects the same entry as `p` and a
/// write through one changes the guest's memory somewhere else. Generated, not
/// written down.
const MAX_PAGE: u64 = ffi::USER_ADDR_MAX_PAGE;

/// The calling thread's address space, locked for reading, or `None` for a
/// thread that has no task.
///
/// `None` is answered as `EFAULT` by every entry point below, which is what
/// makes `crate::GuestMem` safe to use from anywhere: a copy from a host
/// thread cannot reach the page table. It is still a defect — nothing but a
/// guest thread has a reason to copy guest memory — so it is said once, on
/// stderr, rather than answered silently.
fn current_held() -> Option<ReadGuard<'static>> {
    if taskview::current().is_null() {
        eprintln!("user copy from a thread with no task; answering EFAULT");
        return None;
    }
    ReadGuard::current()
}

// ---------------------------------------------------------------------------
// The entry points
// ---------------------------------------------------------------------------

// The entry points take slices since 2026-10-01. Each took a `*mut u8` and a
// count and rebuilt the slice inside, so every caller -- which had a slice or
// an array -- took it apart into a pointer and a length to be put back
// together, and the length half of the contract was the caller's to get right
// in an `unsafe` block. What is still `unsafe` is a `mem` or `task` named by
// pointer: whose address space it is, and that it stays live, is the caller's.

/// From an address space whose read lock `held` is, which is what a caller
/// holding a *pinned* one has -- `process_vm_readv` and `/proc/<pid>/mem`
/// retain the target's `mm` and lock it through that reference.
///
/// It took a raw `mem` and was `unsafe` until 2026-10-02; the guard's lifetime
/// is now what says the space is live.
pub fn read_held(held: &mut ReadGuard<'_>, addr: u64, out: &mut [u8]) -> c_int {
    if out.is_empty() {
        return 0;
    }
    crate::read(held, addr, out, MAX_PAGE)
}

/// From the calling thread's address space.
pub fn read_current(addr: u64, out: &mut [u8]) -> c_int {
    if out.is_empty() {
        return 0;
    }
    match current_held() {
        Some(mut held) => crate::read(&mut held, addr, out, MAX_PAGE),
        None => EFAULT,
    }
}

/// Into the calling thread's address space.
pub fn write_current(addr: u64, src: &[u8]) -> c_int {
    if src.is_empty() {
        return 0;
    }
    match current_held() {
        Some(mut held) => crate::write(&mut held, addr, src, Access::Write, MAX_PAGE),
        None => EFAULT,
    }
}

/// The mirror of [`read_held`]. `Access::Write`, not `WritePtrace` --
/// `process_vm_writev` is not a debugger and does not write through a
/// read-only mapping.
pub fn write_held(held: &mut ReadGuard<'_>, addr: u64, src: &[u8]) -> c_int {
    if src.is_empty() {
        return 0;
    }
    crate::write(held, addr, src, Access::Write, MAX_PAGE)
}

/// A debugger's write, which is allowed through a mapping the process itself
/// could not write: `PTRACE_POKEDATA` and `/proc/<pid>/mem`.
///
/// These and [`read_held`] replaced `read_current_task`,
/// `write_current_task` and `write_current_task_ptrace` on 2026-10-17, which
/// took a task by pointer and locked the `mem` inside its `mm` without
/// retaining the `mm` -- so a `/proc/<pid>/mem` read racing the target's
/// `execve` could lock a space being freed. The callers retain it now.
pub fn write_held_ptrace(held: &mut ReadGuard<'_>, addr: u64, src: &[u8]) -> c_int {
    if src.is_empty() {
        return 0;
    }
    crate::write(held, addr, src, Access::WritePtrace, MAX_PAGE)
}

/// How many of `count` bytes at `addr` the calling thread could write, writing
/// none of them — or `EFAULT` if the range is not one a guest could name at all.
///
/// What a read that **consumes** clamps its request to; see
/// `crate::writable_prefix` for why it has to and why the answer is a length
/// rather than a yes or no. The lock is taken and dropped here as it is for a
/// copy, so the answer is a snapshot — another thread can `munmap` the page
/// immediately afterwards, exactly as it can between Linux's `access_ok` and its
/// `copy_to_user`.
///
/// **A range failure and an unmapped page are different answers**, which is why
/// this is signed. Linux checks the range with `access_ok` *before* it waits for
/// data and finds the mapping missing *during* the copy, so a read of an empty
/// non-blocking pipe is `EFAULT` for an address above the address space and
/// `EAGAIN` for a merely unmapped one. Rolling the two together made the second
/// answer the first. `tests/guest/src/bin/faultread_probe.rs` measures both.
///
/// # Safety
/// Called on a guest thread.
pub(crate) fn user_writable(addr: u64, count: usize) -> isize {
    if count == 0 {
        return 0;
    }
    if !crate::range_ok(addr, count, MAX_PAGE) {
        return EFAULT as isize;
    }
    let Some(mut held) = current_held() else {
        return EFAULT as isize;
    };
    crate::writable_prefix(&mut held, addr, count, Access::Write, MAX_PAGE) as isize
}

/// A NUL-terminated string out of guest memory. 0, or a negative errno.
///
/// `ENAMETOOLONG` when there is no terminator in `out`, which used to be
/// *success* with the buffer full and unterminated — and every caller passes
/// the result to something that reads a C string, so a `char[PATH_MAX]` on the
/// stack and 4096 non-NUL bytes from the guest was a stack overread from one
/// syscall. It is also the right answer for a path that is genuinely too long.
///
/// From the calling thread's address space, into `out`.
pub fn read_current_string(addr: u64, out: &mut [u8]) -> c_int {
    if addr == 0 || out.is_empty() {
        return EFAULT;
    }
    let Some(mut held) = current_held() else {
        return EFAULT;
    };
    match crate::read_string(&mut held, addr, out, MAX_PAGE) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bound_is_the_guests_page_numbers_and_not_a_pointers() {
        // 36-bit page numbers over 4 KiB pages: a 48-bit address space. Above
        // it an address aliases rather than faulting, which is why the bound
        // exists at all -- and it is generated from kernel/memory.h rather than
        // written here, because a copy of a number is checked by nothing.
        assert_eq!(MAX_PAGE, 0xF_FFFF_FFFF);
        assert!(!crate::range_ok((MAX_PAGE + 1) << 12, 1, MAX_PAGE));
        assert!(crate::range_ok(MAX_PAGE << 12, 1, MAX_PAGE));
    }

    // `a_null_address_space_is_a_fault_rather_than_a_dereference` and
    // `a_zero_length_copy_touches_nothing_and_succeeds` were here until
    // 2026-10-17, over `read_from`/`write_to`, which took a space by pointer.
    // Nothing does now: a cross-task copy retains the space first, and a task
    // with none is `GeneralGuard::mm` answering `None`.
}
