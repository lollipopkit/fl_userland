//! A host `mprotect` that refuses partway through `set_flags` still settles
//! what the pages before it changed: the anonymous-page budget and the
//! address space's change count.
//!
//! The refusal is a real one, not a stub: a host `MAP_SHARED` mapping of a
//! descriptor open read-only, which the host will not make writable. The
//! syscall layer refuses such a page itself before it gets here (`mprotect`'s
//! `EACCES` for a VMA without `VM_MAYWRITE`), so this calls the page table
//! directly. One `#[test]` in a binary of its own, because the budget is
//! process-wide; see `live_mappings.rs`.
//!
//! Backed out to check it bites: returning the host error before the charge
//! and the change count are applied, which is what `set_flags` did until
//! 2026-11-11, turns it red at "the anonymous page made writable is charged".

use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;

use pagetable::anonbudget::anon_pages_used;
use pagetable::memlock::{self, Held};
use taskview::ffi;

#[test]
fn a_host_refusal_partway_still_settles_the_budget_and_the_tlbs() {
    let mem: *mut ffi::mem = Box::into_raw(Box::new(ffi::mem::default()));
    unsafe { pagetable::mem_init(mem) };
    let path = std::env::temp_dir().join(format!("pagetable-protect-failure-{}", std::process::id()));
    std::fs::write(&path, vec![b'f'; 65536]).unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let host_page = pagetable::memlock::host_page_size();
    // SAFETY: a fresh mapping, handed to the page table below.
    let shared = unsafe {
        libc::mmap(std::ptr::null_mut(), host_page, libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd(), 0)
    };
    assert_ne!(shared, libc::MAP_FAILED);

    let before = anon_pages_used();
    // SAFETY: just made, and this thread holds neither side of its lock.
    let mut held = unsafe { memlock::WriteGuard::new(mem) };
    // An anonymous PROT_NONE page, which is not charged, then the file page.
    held.map_nothing(0x1000, 1, ffi::P_NOACCESS).unwrap();
    // SAFETY: `shared` is a host mapping of `host_page` bytes, owned from here.
    unsafe { held.map(0x1001, 1, shared, 0, ffi::P_READ | ffi::P_SHARED) }.unwrap();
    assert_eq!(anon_pages_used(), before, "a PROT_NONE page is not charged");

    let changes = unsafe { (*mem).mmu.changes.load(Ordering::Acquire) };
    let r = held.set_flags(0x1000, 2, (ffi::P_READ | ffi::P_WRITE) as i32);
    assert!(r.is_err(), "the host refused to make a read-only descriptor's shared page writable");
    assert_ne!(held.pt(0x1000).unwrap().flags() & ffi::P_WRITE, 0, "the page before it changed");
    assert_eq!(anon_pages_used(), before + 1, "the anonymous page made writable is charged");
    assert!(
        unsafe { (*mem).mmu.changes.load(Ordering::Acquire) } > changes,
        "every thread's cached translations of the changed page are dropped"
    );

    held.unmap_always(0x1000, 2);
    assert_eq!(anon_pages_used(), before, "and unmapping it gives the charge back");
    drop(held);
    unsafe { pagetable::mem_destroy(mem) };
    let _ = std::fs::remove_file(&path);
}
