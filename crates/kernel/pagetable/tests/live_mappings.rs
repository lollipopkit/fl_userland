//! Every host mapping this page table makes is given back.
//!
//! **This is the only check in the tree that can see a leaked mapping.** The
//! failure mode of object model step 9.1 — turning `struct data`'s hand-rolled
//! `AtomicU32` into an `Arc` — is a strong count one too high, which keeps a
//! host `mmap` and a `struct fd` for ever and breaks nothing a test asserts.
//! In particular:
//!
//! - `tests/guest/src/bin/anon_budget_leak.rs` cannot see it. The
//!   anonymous-page budget is charged and refunded **per page** in
//!   `pt_unmap_always`, independently of the object, so it balances whether or
//!   not the mapping is freed.
//! - `/proc/<pid>/maps` cannot see it: the entry is cleared either way, so the
//!   guest's view of its own address space is identical.
//! - The host's own resident size moves by a page or two on a leak this size,
//!   which is inside the noise of anything that could measure it from a test.
//!
//! So the observable is a counter. Two things about where it lives, and the
//! second was got wrong first:
//!
//! - It is an integration test rather than a `#[cfg(test)] mod` for the reason
//!   `crates/kernel/eventfd/tests/live_count.rs` gives about its own counter:
//!   cargo runs a crate's unit tests as threads of **one** process, so an
//!   assertion about a process-wide counter is only true where nothing else is
//!   mapping.
//! - **A separate binary is not enough — it has to be one `#[test]`.** The
//!   first version of this file was three, and cargo runs the test functions
//!   *within* a binary in parallel too, so each read a `before` that another
//!   case had already moved: `left: 1, right: 2` on the first assertion. That
//!   is the same mistake one level down, and it is why the three cases below
//!   are three blocks of one function.
//!
//! Backed out to check it bites: making `PtEntry::take_data` forget the handle
//! and answer `None` — a mapping that is unmapped from the guest's point of
//! view and never freed — turns it red at "the last page going is what frees
//! it", `left: 1, right: 0`.

use std::ffi::c_void;

use pagetable::{mapping_live_count as live, memlock};
use memlock::Held;
use taskview::ffi;

/// A fresh address space.
fn fresh_mem() -> *mut ffi::mem {
    // `Default`, where it was `mem::zeroed`: `reservations` is a `Vec`, and
    // an all-zero `Vec` is not a valid one.
    let mem: *mut ffi::mem = Box::into_raw(Box::new(ffi::mem::default()));
    unsafe { pagetable::mem_init(mem) };
    mem
}

/// `pages` pages of real host memory, which is what `pt_map` records and
/// `Data::drop` gives back with `munmap`. A real mapping, not a fake address:
/// the destructor calls `munmap` on it and an invented pointer would either
/// fail silently or unmap something else.
fn host_pages(pages: usize) -> *mut c_void {
    let len = pages * 4096;
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    assert_ne!(p, libc::MAP_FAILED, "the test's own mmap failed");
    p
}

#[test]
fn every_host_mapping_is_freed_by_the_last_page_that_points_at_it() {
    assert_eq!(live(), 0, "something mapped before this test started");

    // ---- One mapping, four pages, and a partial unmap.
    //
    // The partial unmap is the case the *per-page* anonymous refund exists
    // for: three of the four guest pages are gone and the host mapping is not.
    let mem = fresh_mem();
    // The guard, not `mem_write_lock`: this test held two write locks by hand
    // across sixty lines and released them at the bottom, so a panic anywhere
    // between left the address space locked and the next test hanging on it.
    // SAFETY: `fresh_mem` just made it and this thread holds neither side.
    let mut mem_lock = unsafe { memlock::WriteGuard::new(mem) };
    assert_eq!(unsafe { mem_lock.map(0x1000, 4, host_pages(4), 0, 0) }, Ok(()));
    assert_eq!(
        live(),
        1,
        "pt_map makes one host mapping however many pages point at it"
    );
    assert_eq!(mem_lock.unmap(0x1000, 3), Ok(()));
    assert_eq!(live(), 1, "three of four pages unmapped frees nothing");
    assert_eq!(mem_lock.unmap(0x1003, 1), Ok(()));
    assert_eq!(live(), 0, "the last page going is what frees it");

    // ---- A move is the same mapping at another address.
    //
    // `pt_move` takes a reference per page on the way in and the unmap on the
    // way out gives the old ones back -- one atomic more than strictly
    // necessary, and what keeps every invariant `pt_unmap_always` relies on.
    // The count must not move at all.
    assert_eq!(unsafe { mem_lock.map(0x2000, 2, host_pages(2), 0, 0) }, Ok(()));
    mem_lock.move_pages(0x2000, 0x4000, 2);
    assert_eq!(live(), 1, "a move does not make a second mapping");
    assert_eq!(mem_lock.unmap(0x4000, 2), Ok(()));
    assert_eq!(live(), 0, "and the move left nothing behind at the source");

    // ---- A fork: the mapping outlives the address space that made it.
    //
    // Freeing when the parent lets go would be a use-after-free the child
    // reaches through the TLB, which is the whole reason this object is
    // counted rather than owned by one address space.
    let child = fresh_mem();
    assert_eq!(unsafe { mem_lock.map(0x8000, 2, host_pages(2), 0, 0) }, Ok(()));
    // SAFETY: as above, for the second address space.
    let mut child_lock = unsafe { memlock::WriteGuard::new(child) };
    mem_lock.copy_on_write_into(&mut child_lock, 0x8000, 2);
    assert_eq!(live(), 1, "a fork shares the mapping, it does not copy it");
    assert_eq!(mem_lock.unmap(0x8000, 2), Ok(()));
    assert_eq!(live(), 1, "the child still points at it");

    // ---- A repoint (`remap_file_pages` of shared anonymous memory) moves
    // pages inside one mapping: no second one, the right host page, and the
    // caller's reference is what keeps the object alive across the unmap of
    // what was there.
    assert_eq!(unsafe { mem_lock.map(0x9000, 4, host_pages(4), 0, ffi::P_SHARED) }, Ok(()));
    let data = std::sync::Arc::clone(mem_lock.pt(0x9000).unwrap().data().unwrap());
    mem_lock.repoint(0x9000, 2, &data, 2 * 4096, ffi::P_SHARED);
    assert_eq!(live(), 2, "a repoint does not make a mapping (the child's is the other)");
    let host = |page| mem_lock.pt(page).unwrap().host().unwrap() as usize;
    assert_eq!(host(0x9000), data.host() as usize + 2 * 4096, "page 0 is the object's page 2");
    assert_eq!(host(0x9001), data.host() as usize + 3 * 4096, "page 1 is the object's page 3");
    assert_eq!(host(0x9002), data.host() as usize + 2 * 4096, "page 2 is untouched");
    drop(data);
    assert_eq!(mem_lock.unmap(0x9000, 4), Ok(()));
    assert_eq!(live(), 1, "and unmapping every page frees it");
    drop(mem_lock);
    drop(child_lock);

    // ---- And tearing the address space down is the same question asked of
    // every page at once, which is the path `do_exit` takes.
    unsafe { pagetable::mem_destroy(child) };
    assert_eq!(live(), 0, "mem_destroy left a mapping behind");
    unsafe { pagetable::mem_destroy(mem) };
    assert_eq!(live(), 0);
}
