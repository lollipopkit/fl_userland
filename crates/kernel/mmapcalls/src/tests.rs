//! Unit tests for address-space calls that do not place mappings.

use super::*;


/// The range rule, which is arithmetic and needs no address space.
///
/// Page numbers are 36 bits and the table masks each level, so an address
/// above that **aliases** onto a lower page rather than falling out. That is
/// what made `munmap(p + (1 << 48), 4096)` unmap the mapping at `p` and
/// report success.
#[test]
fn an_address_above_the_guest_space_is_refused() {
    assert!(user_range_ok(0x1000, PAGE_SIZE));
    assert!(!user_range_ok(1 << 48, PAGE_SIZE));
    // The last page is inside, and one past it is not.
    assert!(user_range_ok(USER_ADDR_MAX_PAGE << PAGE_BITS, PAGE_SIZE));
    assert!(!user_range_ok(
        (USER_ADDR_MAX_PAGE + 1) << PAGE_BITS,
        PAGE_SIZE
    ));
}

/// A length that rounds up past 2^64 is not "no pages".
///
/// `PAGE_ROUND_UP` overflows to zero, so the C read a length near 2^64 as
/// an empty range and reported success where Linux gives `EINVAL`.
#[test]
fn a_length_that_overflows_is_refused() {
    assert!(!user_range_ok(0x1000, u64::MAX));
    assert_eq!(page_round_up(u64::MAX), u64::MAX >> PAGE_BITS, "saturating");
    // And a range that merely runs off the end of the space is refused too,
    // rather than wrapping.
    assert!(!user_range_ok(
        USER_ADDR_MAX_PAGE << PAGE_BITS,
        PAGE_SIZE * 2
    ));
}

/// The generated constants are the header's, which is the whole point of
/// generating them.
///
/// `P_NOACCESS` was written by hand as `1 << 5` and is `1 << 9`; nothing
/// reads bit 5, so `mprotect(PROT_NONE)` revoked nothing and two guest
/// tests caught it only after it ran. Asserting the shape here means a
/// header change that moves one shows up as a failing test rather than as
/// a permission that silently does not apply.
#[test]
fn the_page_flags_come_from_the_header() {
    assert_eq!(P_RWX, 7, "read | write | exec");
    assert_eq!(P_NOACCESS, 1 << 9);
    // And it is not one of the three it has to be distinguishable from.
    assert_eq!(P_NOACCESS & P_RWX, 0);
    assert_eq!(PAGE_BITS, 12);
    assert_eq!(USER_ADDR_MAX_PAGE, 0xF_FFFF_FFFF, "36-bit page numbers");
}

/// Zero length is legal for the range check itself; the callers decide.
#[test]
fn zero_length_is_a_range() {
    assert!(user_range_ok(0x1000, 0));
    assert_eq!(page_round_up(0), 0);
    assert_eq!(page_round_up(1), 1);
    assert_eq!(page_round_up(PAGE_SIZE), 1);
    assert_eq!(page_round_up(PAGE_SIZE + 1), 2);
}

#[test]
fn mlockall_refuses_what_linux_refuses() {
    assert_eq!(sys_mlockall(0), Err(Errno::EINVAL), "locking nothing");
    assert_eq!(
        sys_mlockall(MCL_ONFAULT),
        Err(Errno::EINVAL),
        "ONFAULT qualifies the others"
    );
    // The accepted ones lock the address space, which a unit test has none
    // of; the rule is asked on its own.
    assert_eq!(mlockall_flags_ok(MCL_CURRENT), Ok(()));
    assert_eq!(mlockall_flags_ok(MCL_CURRENT | MCL_ONFAULT), Ok(()));
    assert_eq!(
        sys_mlockall(0x8000),
        Err(Errno::EINVAL),
        "a flag it does not know"
    );
}

#[test]
fn membarrier_refuses_a_flag_and_an_unknown_command() {
    assert_eq!(sys_membarrier(MEMBARRIER_CMD_QUERY, 1, 0), Err(Errno::EINVAL));
    assert_eq!(sys_membarrier(99, 0, 0), Err(Errno::EINVAL));
    // QUERY advertises exactly the seven it handles.
    let mask = sys_membarrier(MEMBARRIER_CMD_QUERY, 0, 0).expect("QUERY answers");
    for cmd in [
        MEMBARRIER_CMD_GLOBAL,
        MEMBARRIER_CMD_GLOBAL_EXPEDITED,
        MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED,
        MEMBARRIER_CMD_PRIVATE_EXPEDITED,
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED,
        MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
    ] {
        assert_ne!(mask & cmd as i64, 0, "QUERY omits {cmd}");
        assert_eq!(sys_membarrier(cmd, 0, 0), Ok(0), "but {cmd} works");
    }
}

/// A forked address space carries its parent's image and what `inherit`
/// keeps of its flags. Run on the real `mm_copy`: the image is one `Clone`
/// now, so what is under test is that the copy happens, under the locks.
#[test]
fn a_forked_address_space_inherits_the_image_and_the_flag_rule() {
    use pagetable::memlock::{Held, WriteGuard};
    use std::sync::atomic::Ordering;

    let parent = super::mm::mm_new_from(None);
    {
        let mut held = WriteGuard::of(&parent.mem);
        // Distinct non-zero values, so a field copied from the wrong place
        // shows up as the wrong number rather than as a coincidence.
        *held.image_mut() = ffi::Image {
            vdso: 0x1000,
            start_brk: 0x2000,
            brk: 0x3000,
            argv: (0x4000, 0x5000),
            env: (0x6000, 0x7000),
            auxv: (0x8000, 0x9000),
            stack_start: 0xa000,
            code: (0xe000, 0xf000),
            data: (0x10000, 0x11000),
            exefile: None,
            exe_bias: 0xc000,
            exe_entry: 0xd000,
        };
    }
    parent.prctl_flags.store(u32::MAX, Ordering::Relaxed);

    let child = super::mm::mm_copy(&parent);
    let held = pagetable::memlock::ReadGuard::of(&child.mem);
    let image = held.image();
    assert_eq!(
        (image.vdso, image.start_brk, image.brk, image.stack_start, image.exe_bias, image.exe_entry),
        (0x1000, 0x2000, 0x3000, 0xa000, 0xc000, 0xd000)
    );
    assert_eq!((image.argv, image.env, image.auxv), ((0x4000, 0x5000), (0x6000, 0x7000), (0x8000, 0x9000)));
    drop(held);
    assert_eq!(
        child.prctl_flags.load(Ordering::Relaxed),
        mmflags::inherit(u32::MAX),
        "what a child keeps of the flags is a rule, not a copy"
    );
    assert_ne!(mmflags::inherit(u32::MAX), u32::MAX, "if inherit() keeps everything this checks nothing");
}

/// Dropping the last `Arc` of an initialised space runs `teardown` through
/// `crates/kernel/abi`'s hook, which `mm_new_from` installs. A missing hook
/// and a space nobody dropped look the same from outside, so ask.
#[test]
fn a_new_address_space_installs_its_teardown() {
    let mm = super::mm::mm_new_from(None);
    assert!(ffi::mm_teardown_installed());
    assert!(!mm.mem.mmu.asbestos.is_null(), "mem_init ran in place");
    drop(mm);
}
