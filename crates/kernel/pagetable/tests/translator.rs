//! `mem_init` installs the TLB's translator.
//!
//! A missing translator and a working one look the same until the first TLB
//! miss, which then panics far from the cause; this is the check that the
//! wiring exists. Its own binary, so nothing has installed it before.

use taskview::ffi;

#[test]
fn the_first_address_space_installs_the_translator() {
    assert!(!emu_tlb::translator_installed());
    let mem: *mut ffi::mem = Box::into_raw(Box::new(ffi::mem::default()));
    unsafe { pagetable::mem_init(mem) };
    assert!(emu_tlb::translator_installed());
}
