//! Resolving a fault: what happens when the software TLB misses and the page
//! it wanted is not simply there.
//!
//! [`mem_ptr`] is the whole of it. Every guest load and store that misses the
//! TLB arrives here, as does every syscall that touches guest memory, so it is
//! the hottest path in the kernel after the dispatch itself — and it is the
//! only place that *changes* the address space while a guest thread is running
//! inside it.
//!
//! It was the last of `kernel/memory.c`, left there because it upgrades
//! `mem->lock` from read to write and that lock is a C `wrlock_t`. The layout
//! stays C and bindgen generates it; the four operations were already exported;
//! what was actually needed was to stop treating "a C type is in the struct" as
//! a reason the code around it cannot move.
//!
//! # Three ways a missing page is not a fault
//!
//! - **The stack grows down.** A page below a `P_GROWSDOWN` mapping is one the
//!   guest is entitled to, up to `RLIMIT_STACK`.
//! - **A reservation is committed.** A `MAP_NORESERVE` range — V8's heap cage,
//!   JSC's gigacage — has no page-table entries until something touches it.
//! - **A copy-on-write is broken.** The page is there and readable; the write
//!   is what needs a private copy.
//!
//! # The lock is upgraded, and returning `NULL` instead is not an option
//!
//! Each of the three drops the read lock, takes the write lock, does the work,
//! and takes the read lock back — because the caller holds the read lock on
//! entry and expects it held on return.
//!
//! It must not give up and answer `NULL` on contention. `NULL` becomes
//! `INT_GPF`, which retries the whole JIT block from its start, and a block
//! whose prologue is `sub sp, sp, #N` decrements the guest's stack pointer
//! **again** on every retry. Observed in musl's `printf_core`: `sub sp, sp,
//! #0x1dd0` three times over left the caller's saved `x29`/`x30` three frames
//! too low, the epilogue's `ldp` read zeroes out of a freshly grown page, and
//! `ret` jumped to pc 0. `write_wrlock` spins on `trylock` with a bounded
//! budget and falls back to blocking, so it always acquires.
//!
//! # And the window it opens has to be closed again
//!
//! While the lock is down, another thread's `fork` can mark this page
//! copy-on-write *again*: `pt_copy_on_write` adds `P_COW` to every one of the
//! parent's entries, and a `P_COW` page is not writable. The final lookup would
//! then answer `NULL` and the caller would report `EFAULT` for a perfectly good
//! address. A guest store survives that — `INT_GPF` retries — but a kernel-side
//! write does not: `user_put` has no retry, and `wait4` writes the status
//! *after* reaping, so `tests/guest/src/bin/task_race.rs` saw `LOST:
//! waitpid(...) errno 14` whenever a fork landed in the window. So the copy is
//! resolved again, up to sixteen times: each pass costs one page copy, and a
//! sixteenth consecutive fork into the same window is not worth spinning for.

use std::ffi::{c_int, c_void};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::entry::Origin;
use crate::ffi;
use crate::PtEntry;
use crate::mmu::mem_of;
use crate::space::{ReadHeld, Space};

/// How many stores have hit a `P_CODE` page and unprotected it, for
/// `IUL_WX_STATS=1`'s line.
///
/// `crates/asbestos/diag` prints it and cannot depend on this crate — this one
/// depends on *it*, for the store watchpoint on the host-write path — so it was
/// a `#[no_mangle]` that crate declared `extern`. It is handed the address once
/// instead, by `crates/kernel/boot`'s `install_run_hooks` — the `fetch_add`
/// below is unchanged, which is what makes that free.
///
/// **Not installed at the first clear**, which was the first attempt: a run
/// with no self-modifying code then reports `clears=0` whether the install
/// happened or not, so deleting it would be silent. From `install_run_hooks` it
/// is covered by the test that asserts the rest of that function's wiring.
pub static ST_WX_CLEARS: AtomicU64 = AtomicU64::new(0);

const PAGE_SIZE: u64 = ffi::PAGE_SIZE as u64;
const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// Can a guest with these flags write the page? A copy-on-write page cannot be
/// written until it has been copied, which is what makes the write path below
/// reachable at all.
fn writable(flags: u32) -> bool {
    flags & ffi::P_WRITE != 0 && flags & ffi::P_COW == 0
}

/// The host address for `addr`, or null — **without** changing anything.
///
/// The fast half, and what the JIT's TLB fill uses when it must not fault.
fn nofault(space: Space<'_>, addr: u64, kind: c_int) -> *mut u8 {
    let Some(entry) = space.pt(addr >> ffi::PAGE_BITS) else {
        return std::ptr::null_mut();
    };
    if kind == ffi::MEM_WRITE as c_int && !writable(entry.flags()) {
        return std::ptr::null_mut();
    }
    entry
        .host()
        .unwrap()
        .wrapping_add((addr & PAGE_MASK) as usize)
}

/// Is a fault at `page` the stack growing down, and is it within `RLIMIT_STACK`?
///
/// Answers the first already-mapped page above it, which is where the growth
/// stops.
///
/// The limit gets 128 KB of slack, because userspace derives its own stack
/// bound as `SP_at_entry - RLIMIT_STACK` while this counts from the stack VMA's
/// top — the guard page, which sits an argv/envp/auxv-sized distance above that
/// `SP` — and Linux grants the initial stack VMA that much expansion headroom
/// anyway (`setup_arg_pages`'s `stack_expand`). Without it, JS recursion that
/// runs right up to JSC's believed bound faults one page below the enforced
/// bottom before JSC can raise `RangeError`: a deterministic `SIGSEGV` at
/// `stack_top - RLIMIT_STACK` in bun.
///
/// Called on a guest thread -- `rlimit` reads `current`.
fn growsdown_to(space: Space<'_>, page: u64) -> Option<u64> {
    let above = space.next_mapped(page)?;
    let above_flags = space
        .pt(above)
        .expect("next_mapped answers a mapped page")
        .flags();
    if above_flags & ffi::P_GROWSDOWN == 0 {
        return None;
    }
    const SLACK: u64 = 131072;
    let limit = kernel_rlimit::current_soft(ffi::RLIMIT_STACK_);
    // `RLIM_INFINITY_` is `(rlim_t_) -1`, which bindgen cannot evaluate and
    // which is not worth writing out again -- `checked_add` says what the
    // sentinel *means*. It is also stricter than the C: that compared against
    // the sentinel by name and then added, so any limit within `SLACK` of the
    // top wrapped and let every stack through.
    if let Some(bound) = limit.checked_add(SLACK) {
        let pages = (ffi::STACK_TOP_PAGE as u64).saturating_sub(page);
        if pages.saturating_mul(PAGE_SIZE) > bound {
            return None;
        }
    }
    Some(above)
}

/// How far above the faulting page to map when a stack grows: one megabyte.
///
/// The whole run down to the fault page is mapped, not one page, because a
/// large `sub sp, sp, #N` followed by stores anywhere in the new frame works
/// on Linux without faulting on every intermediate page — musl's deeper `fs`
/// helpers use two-page frames, and growing one page at a time left the pages
/// *above* the fault unmapped for later stores to fault on, with the `SIGSEGV`
/// handler running on the same shallow stack and faulting recursively.
///
/// The cap is on how far **above** the fault page to go, never on the fault
/// page itself. Capping the other way round — moving the start up towards the
/// stack — left the faulting page unmapped for a fault more than `MAX_GROW`
/// pages below the stack, such as one `sub sp, sp, #0x30000`, and the store
/// then landed on unmapped memory and silently corrupted the frame.
const MAX_GROW: u64 = 256;

/// Give the guest the page at `page`, if it is entitled to one.
///
/// Answers whether the caller should carry on with the entry now there. The
/// read lock is held on entry and on return; in between it is given up for the
/// write lock, and the page is re-checked after, because another thread may
/// have resolved the same fault.
///
/// As [`growsdown_to`], on a guest thread.
fn resolve_absent(held: &mut ReadHeld, page: u64) -> bool {
    // Under the read lock: decide what kind of absence this is.
    let grow_to = growsdown_to(held.space(), page);
    let reservation_flags = if grow_to.is_none() {
        let Some(res) = held.space().find_reservation(page) else {
            return false; // not the guest's page, and never was
        };
        // A copy, so the lock being dropped below takes nothing from under it.
        Some(res.flags & !ffi::P_GROWSDOWN)
    } else {
        None
    };

    held.upgraded(|space| {
        // Another thread may have mapped it while the lock was down. A
        // host refusal leaves the page absent, which the caller's lookup
        // then reports.
        if space.space().pt(page).is_none() {
            let _ = match grow_to {
                // Both charge what they map, inside `map_nothing`.
                Some(above) => {
                    let end = above.min(page + MAX_GROW);
                    let count = end - page;
                    // `P_READ` too, and the *same* flags the initial stack page
                    // has -- `crates/kernel/execcalls` maps that one
                    // `P_READ | P_WRITE | P_GROWSDOWN`.
                    //
                    // Two things went wrong without it, and the second is why
                    // it was worth finding. A grown stack page read as `-w-p`
                    // in `/proc/<pid>/maps`, which is a combination no kernel
                    // produces on the one region every program reads from
                    // constantly -- the same defect `brk` had. And because the
                    // flags differed from the top page's, the maps walk
                    // **split the stack in two**: glibc's
                    // `pthread_getattr_np` finds the mapping holding
                    // `__libc_stack_end`, takes the previous mapping's end as
                    // the floor, and so computed a stack of exactly one page.
                    // Python 3.14 asks it at startup and aborts with
                    // "Unrecoverable stack overflow (used 4 kB)" before
                    // running a line, which is every `python3` on Ubuntu and
                    // every `apt install` that pulls one in.
                    space.map_nothing(page, count, ffi::P_READ | ffi::P_WRITE | ffi::P_GROWSDOWN)
                }
                None => space.map_nothing(page, 1, reservation_flags.unwrap_or(0)),
            };
        }
    });
    true
}

/// Break a copy-on-write page.
///
/// Answers whether the caller should look again — true when the page came back
/// still copy-on-write, which a concurrent `fork` can do while the lock is
/// down. See the module comment.
///
/// The read lock is held on entry and on return.
fn break_cow(held: &mut ReadHeld, page: u64) -> bool {
    // Allocated before the lock is dropped, so the window is as short as it
    // can be and the failure is reported before anything is changed. A
    // refusal is counted, so a copy-on-write fault the host refused is
    // distinguishable from one the guest's own state refused. See
    // `crate::host_map_failures`.
    let Some(copy) = crate::copies::alloc() else {
        return false;
    };

    held.upgraded(|space| {
        if let Some(entry) = space.space().pt(page)
            && entry.flags() & ffi::P_COW != 0
        {
            let flags = entry.flags();
            // SAFETY: the source is one mapped guest page, which the write
            // lock keeps mapped; the destination is the slot just allocated.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    entry.host().unwrap(),
                    copy.host,
                    PAGE_SIZE as usize,
                )
            };
            // No charge: the copy takes the page's place in the budget, and
            // `map_copy` gives nothing back for the page it replaces.
            // A private copy of a file page remembers the page: it is bounded
            // by the file's end, and a truncation or `MADV_DONTNEED` gives the
            // file's page back. See `crate::entry::Origin`.
            let origin = entry.file_page().map(|(data, offset)| Origin::new(Arc::clone(data), offset));
            // `entry` is not used past here, and the borrow checker agrees:
            // this replaces it.
            space.map_copy(page, copy, flags & !ffi::P_COW);
            if let Some(origin) = origin
                && let Some(data) = space.space().pt(page).and_then(|e| e.data())
            {
                data.set_origin(origin);
            }
        }
        // Otherwise the slot goes unused, and with its host page.
    });

    held.space()
        .pt(page)
        .is_some_and(|entry| entry.flags() & ffi::P_COW != 0)
}

/// A page of a file mapping past the end of its file, or a private copy a
/// truncation cut off.
///
/// The copy is dropped, as Linux drops it at the truncation, and the page is
/// the file's again: past the end it raises `SIGBUS`, and grown back it reads
/// the file, so the access is resolved again from the start. A page past the
/// end is simply refused.
///
/// Out of line and cold: it is reached only by a page the guest may not have
/// or a copy a truncation cut off, and the miss path of every other page
/// keeps the shape it had.
///
/// # Safety
/// As [`mem_ptr`], whose read lock `held` is.
#[cold]
#[inline(never)]
unsafe fn past_eof_or_zapped(mut held: ReadHeld, mem: *mut ffi::mem, addr: u64, kind: c_int) -> *mut u8 {
    let page = addr >> ffi::PAGE_BITS;
    if !held.space().pt(page).is_some_and(PtEntry::zapped) {
        return std::ptr::null_mut();
    }
    held.upgraded(|space| {
        if space.space().pt(page).is_some_and(PtEntry::zapped) {
            space.revert_copy(page);
        }
    });
    // SAFETY: the caller's contract.
    unsafe { mem_ptr(mem, addr, kind) }
}

/// The host address a guest access should use, resolving the fault if there is
/// one. Null if the guest may not have it.
///
/// The caller holds `mem->lock` for reading, and holds it on return.
///
/// # Safety
/// `mem` is live, the read lock is held, and this is a guest thread.
pub(crate) unsafe fn mem_ptr(mem: *mut ffi::mem, addr: u64, kind: c_int) -> *mut u8 {
    // SAFETY: the caller's contract.
    let mut held = unsafe { ReadHeld::assume(mem) };
    let page = addr >> ffi::PAGE_BITS;
    let write = kind == ffi::MEM_WRITE as c_int || kind == ffi::MEM_WRITE_PTRACE as c_int;
    let ptrace = kind == ffi::MEM_WRITE_PTRACE as c_int;

    if held.space().pt(page).is_none() && !resolve_absent(&mut held, page) {
        return std::ptr::null_mut();
    }

    // Host-side writes -- user_write, madvise's zeroing, the copy above --
    // bypass the guest store gadgets, so the watchpoint records them here.
    let watched = asbestos_diag::watch_pages();
    if write && watched[0] != 0 {
        let at = addr & !PAGE_MASK;
        if at == watched[0] || at == watched[1] {
            // The ring's field read walks a page table, which is this
            // crate's; installed here because this is the one place a
            // host-side write reaches the ring at all.
            asbestos_diag::set_peek32_hook(mem_watch_peek32);
            asbestos_diag::watch_record_memptr(addr);
        }
    }

    let mut cow_retries = 0;
    while let Some(entry) = held.space().pt(page) {
        let flags = entry.flags();

        // A PROT_NONE page must fault on every access. Writes were already
        // refused for want of P_WRITE; reads were refused by nothing, so
        // mem_ptr handed back a pointer into a host mapping with no read
        // permission either and the memcpy that followed took SIGBUS --
        // killing the *emulator*, where Linux gives the guest EFAULT. A
        // `write(fd, buf, 65536)` with a 16 KB buffer did it: the copy walks
        // page by page off the end of the buffer and into the guard page musl
        // leaves there.
        //
        // Keyed on P_NOACCESS rather than on the absence of P_READ, because
        // P_READ is not maintained -- the stack-growth path above maps P_WRITE
        // alone, and so does brk, and both are read constantly. Testing for
        // "no permission bits" rejected the stack and took the smoke suite
        // from 20 passed to 20 failed.
        //
        // A ptrace write is exempt: a debugger may write a page the process
        // itself cannot, which is what the branch below exists for.
        if !ptrace && flags & ffi::P_NOACCESS != 0 {
            return std::ptr::null_mut();
        }
        // A guard page (`MADV_GUARD_INSTALL`) refuses every access, a
        // debugger's included: Linux's guard marker faults for
        // `access_remote_vm` too, which is why `process_vm_readv` of one is
        // EFAULT there.
        if flags & ffi::P_GUARD != 0 {
            return std::ptr::null_mut();
        }
        // After the protection, which is Linux's order: a store to a
        // read-only page past the end is SIGSEGV. See `crate::eof`. The flag
        // first, so an anonymous page never reads its mapping here: asking
        // the mapping cost a write miss 1.5 ns in `mem_bench`.
        if flags & ffi::P_ANONYMOUS == 0 && entry.past_eof_or_zapped() {
            // SAFETY: the caller's contract, still held.
            return unsafe { past_eof_or_zapped(held, mem, addr, kind) };
        }
        if !write {
            break;
        }
        // A ptrace write goes through whatever the page's protection is,
        // which is `FOLL_FORCE`: a debugger sets a breakpoint in text the
        // process cannot write. It does **not** change the protection. This
        // used to add P_WRITE to the entry -- and P_COW, to force a private
        // copy below -- so every page a tracer had poked was writable to the
        // tracee from then on, and `/proc/<pid>/maps` said so. The copy still
        // happens for a page that is P_COW, which is what Linux's
        // `access_remote_vm` does for a private mapping: the tracee gets its
        // own page, at the protection it had.
        if !ptrace && flags & ffi::P_WRITE == 0 {
            return std::ptr::null_mut();
        }

        // Any compiled blocks for this page are about to be wrong.
        held.invalidate(page);

        // W^X: the page holds compiled guest code. Unprotect it and bump the
        // change generation, so every thread's cached writable TLB entry for
        // it goes stale -- stores keep coming back through here while blocks
        // exist. The invalidate happened first, so a compile racing with this
        // store either finished inserting (and its block was just
        // invalidated) or is still reading bytes (and will see the bump, or
        // the cleared flag, and discard its possibly-torn block).
        if entry.flags() & ffi::P_CODE != 0 {
            entry.flags.fetch_and(!ffi::P_CODE, Ordering::AcqRel);
            ST_WX_CLEARS.fetch_add(1, Ordering::Relaxed);
            held.changed();
            // Order the bump before the caller's store: a compiling thread that
            // observes the torn bytes must also observe the bump when it
            // verifies.
            std::sync::atomic::fence(Ordering::SeqCst);
        }

        if entry.flags() & ffi::P_COW == 0 {
            break;
        }
        cow_retries += 1;
        if !break_cow(&mut held, page) || cow_retries >= 16 {
            break;
        }
    }

    nofault(held.space(), addr, kind)
}

// ---------------------------------------------------------------------------
// What emu_tlb dispatches through
// ---------------------------------------------------------------------------

/// A TLB miss: resolve it properly, because a miss can be a stack to grow or a
/// copy-on-write to break. The TLB calls this from a guest thread, which holds
/// the read lock for its quantum.
unsafe fn translate(mmu: *mut ffi::mmu, addr: u64, kind: c_int) -> *mut c_void {
    unsafe { mem_ptr(mem_of(mmu), addr, kind).cast() }
}

/// A TLB fill for a *store*, which must not fault and must not change anything.
///
/// W^X: never stamp a writable entry for a page holding compiled code. Stores
/// have to take the miss path above, which invalidates the page's blocks and
/// clears `P_CODE` before the store is allowed to land.
unsafe fn translate_write_nofault(mmu: *mut ffi::mmu, addr: u64) -> *mut c_void {
    // SAFETY: as `translate`.
    let held = unsafe { ReadHeld::assume(mem_of(mmu)) };
    let space = held.space();
    if space
        .pt(addr >> ffi::PAGE_BITS)
        .is_some_and(|entry| entry.flags.load(Ordering::Acquire) & ffi::P_CODE != 0)
    {
        return std::ptr::null_mut();
    }
    nofault(space, addr, ffi::MEM_WRITE as c_int).cast()
}

/// What `emu_tlb` dispatches a miss through, installed by `mem_init`.
pub(crate) const TRANSLATOR: emu_tlb::Translator = emu_tlb::Translator {
    translate,
    translate_write_nofault,
};

// ---------------------------------------------------------------------------
// The write watchpoint's peek
// ---------------------------------------------------------------------------

/// A racy, unlocked read of a guest `u32`, for the store watchpoint's ring.
///
/// The sentinels say *why* there is no value rather than answering zero, which
/// is a plausible guest word: `0xdead0001` for no address space, `0xdead0002`
/// for an unmapped page.
///
/// # Safety
/// `mem` is live or null. Deliberately takes no lock — it runs from the store
/// gadget's diagnostic path, where taking one would change what is being
/// measured.
pub unsafe fn mem_watch_peek32_mem(mem: *mut ffi::mem, addr: u64) -> u32 {
    if mem.is_null() {
        return 0xdead_0001;
    }
    // SAFETY: **not** the contract `Space` asks for -- no lock is held, so a
    // concurrent unmap can free what this reads. Accepted for a diagnostic
    // that exists to observe a race without perturbing it; it is reachable
    // only with the watchpoint armed.
    let space = unsafe { Space::from_raw(mem) };
    let Some(host) = space
        .pt(addr >> ffi::PAGE_BITS)
        .and_then(|entry| entry.host())
    else {
        return 0xdead_0002;
    };
    // SAFETY: the caller's contract; the page is mapped, and an unaligned
    // read of four bytes may run off it only as far as the guest's own store
    // being watched did.
    unsafe {
        host.wrapping_add((addr & PAGE_MASK) as usize)
            .cast::<u32>()
            .read_unaligned()
    }
}

/// The same, for the calling thread's address space.
///
pub fn mem_watch_peek32(addr: u64) -> u32 {
    let Some(mem) = taskview::with_current_task(taskview::mem_of) else {
        return 0xdead_0001;
    };
    // SAFETY: this thread's own address space or null, which the helper
    // handles without dereferencing.
    unsafe { mem_watch_peek32_mem(mem, addr) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_on_write_page_is_not_writable() {
        // Which is what makes the write path reach break_cow at all: P_WRITE
        // alone is not enough while P_COW is set, and the two together are how
        // a forked page says "readable now, private on the first store".
        assert!(writable(ffi::P_WRITE));
        assert!(!writable(ffi::P_WRITE | ffi::P_COW));
        assert!(!writable(ffi::P_READ));
        assert!(!writable(0));
    }

    #[test]
    fn the_growth_window_caps_above_the_fault_and_never_below_it() {
        // The fault page is always mapped; the cap bounds how far *above* it
        // to pre-map. Capping the other way -- moving the start up towards the
        // stack -- left the faulting page itself unmapped for a fault more
        // than MAX_GROW pages below the stack, and the store then landed on
        // nothing.
        let page = 0x1000u64;
        for above in [
            page + 1,
            page + MAX_GROW,
            page + MAX_GROW + 1,
            page + 100_000,
        ] {
            let end = above.min(page + MAX_GROW);
            assert!(end > page, "the fault page is always in the run");
            assert!(end - page <= MAX_GROW, "and the run is bounded");
            assert!(end <= above, "and never past what is already mapped");
        }
    }

    #[test]
    fn the_watchpoint_peek_says_why_it_has_no_value() {
        // Rather than answering 0, which is a word a guest could really hold.
        assert_eq!(
            unsafe { mem_watch_peek32_mem(std::ptr::null_mut(), 0) },
            0xdead_0001
        );
    }
}
