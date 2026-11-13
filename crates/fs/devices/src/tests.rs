//! Tests for device registry bounds and dynamic registration rules.

use super::*;

/// Every number a `dev_t` can carry, against a table of 256. The majors
/// that exist answer, and everything else — including the twelve-bit range
/// above the table — answers null rather than reading past it.
#[test]
fn a_major_outside_the_table_finds_nothing() {
    for m in [
        major::MEM,
        major::TTY_CONSOLE,
        major::TTY_ALTERNATE,
        major::TTY_PSEUDO_MASTER,
        major::TTY_PSEUDO_SLAVE,
        major::DYN_DEV,
    ] {
        assert!(char_dev_at(m as c_int).is_some(), "major {m}");
    }
    // Inside the table and unclaimed.
    for m in [0, 2, 3, 6, 100, 255] {
        assert!(char_dev_at(m).is_none(), "major {m}");
    }
    // Past it, which is what `mknod c 300 0` asked for. A dev_t's major is
    // twelve bits, so 4095 is the largest a guest can name.
    for m in [256, 300, 1000, 4095, c_int::MAX, -1, c_int::MIN] {
        assert!(char_dev_at(m).is_none(), "major {m}");
    }
}

/// The same for `MEM_MAJOR`'s minors, whose table is 256 long and whose
/// index a `dev_t` carries twenty bits of.
#[test]
fn a_mem_minor_outside_the_table_finds_nothing() {
    for m in [
        mem_minor::NULL,
        mem_minor::ZERO,
        mem_minor::FULL,
        mem_minor::RANDOM,
        mem_minor::URANDOM,
    ] {
        assert!(mem_dev_at(m as c_int).is_some(), "minor {m}");
    }
    for m in [0, 1, 2, 4, 6, 10, 255, 256, 1_048_575, -1] {
        assert!(mem_dev_at(m).is_none(), "minor {m}");
    }
}

/// `/dev/random` and `/dev/urandom` are the same device. Linux
/// distinguishes them by whether they block before the pool is seeded, and
/// the host's generator never does.
#[test]
fn random_and_urandom_are_one_device() {
    // The same `dev_ops`, by address: `dev_ops` has no `PartialEq` and the
    // question is identity rather than equality — two devices that merely
    // looked alike would not be one device.
    let (r, u) = (
        mem_dev_at(mem_minor::RANDOM as c_int).expect("/dev/random"),
        mem_dev_at(mem_minor::URANDOM as c_int).expect("/dev/urandom"),
    );
    assert!(std::ptr::eq(r, u));
}

/// The `ioctl_size` that made `RNDGETENTCNT` reachable. Without it
/// `fd_ioctl` answers `ENOTTY` for a negative size before calling anything,
/// so the handler was dead code and the command answered `ENOTTY` where a
/// real kernel answers a count.
#[test]
fn rndgetentcnt_has_a_size_or_it_never_runs() {
    assert_eq!(random_ioctl_size(RNDGETENTCNT), 4);
    assert_eq!(random_ioctl_size(0), -1);
    assert_eq!(random_ioctl_size(0x5401), -1); // TCGETS
}

/// What `dyn_dev_register` refuses. Every one is an argument an embedder
/// could get wrong, and the minor is also the index into a fixed table.
#[test]
fn the_dynamic_table_refuses_what_it_cannot_hold() {
    let mut ops = empty_ops();
    let p = &mut ops as *mut ffi::dev_ops;
    for minor in [-1, 256, 1000, c_int::MAX] {
        assert_eq!(
            unsafe { dyn_dev_register(p, DEV_CHAR, major::DYN_DEV as c_int, minor) },
            errno::EINVAL,
            "minor {minor}"
        );
    }
    assert_eq!(
        unsafe { dyn_dev_register(std::ptr::null_mut(), DEV_CHAR, major::DYN_DEV as c_int, 0) },
        errno::EINVAL,
        "a null ops table"
    );
    assert_eq!(
        unsafe { dyn_dev_register(p, DEV_BLOCK, major::DYN_DEV as c_int, 0) },
        errno::EINVAL,
        "a block device, which is not supported"
    );
    assert_eq!(
        unsafe { dyn_dev_register(p, DEV_CHAR, 1, 0) },
        errno::EINVAL,
        "a major that is not DYN_DEV"
    );
}

/// A minor can be claimed once. The second registration is `EEXIST` rather
/// than replacing what is there, because an embedder replacing another
/// embedder's device silently is worse than being told.
#[test]
fn a_minor_is_claimed_once() {
    let mut a = empty_ops();
    let mut b = empty_ops();
    // A minor no other test uses, since the table is process-wide.
    let minor = 200;
    assert_eq!(
        unsafe { dyn_dev_register(&mut a, DEV_CHAR, major::DYN_DEV as c_int, minor) },
        0
    );
    assert_eq!(
        unsafe { dyn_dev_register(&mut b, DEV_CHAR, major::DYN_DEV as c_int, minor) },
        errno::EEXIST
    );
}

/// The packing `fs/dev.h` uses, round-tripped **against the definitions in
/// this file**.
///
/// Moved here from `crates/fs/generic` on 2026-09-15. It was testing that
/// crate's own second copy of the encoder against its own second copy of the
/// decoders — a test agreeing with itself, and the two copies did not even
/// agree with these (no `& 0xfff` on the major), which the cases below cannot
/// see because they stop at `0xfff`.
///
/// Not a formality: the first version of `dev_major` here was written from
/// a guess -- major in the top sixteen bits -- which is the encoding a
/// modern Linux `dev_t` uses and *not* the one this guest ABI does. It
/// compiled, and it would have opened whatever device node happened to sit
/// at the number it computed.
#[test]
fn the_device_number_splits_where_the_header_says() {
    for (major, minor) in [
        (0u32, 0u32),
        (1, 3),        // /dev/null
        (5, 0),        // /dev/tty
        (136, 0),      // the first pty slave
        (0xfff, 0xff), // the widest each field is on its own
        (0xfff, 0xfffff),
    ] {
        let dev = dev_make(major, minor);
        assert_eq!(dev_major(dev), major, "major of {dev:#x}");
        assert_eq!(dev_minor(dev), minor, "minor of {dev:#x}");
    }
}

/// And the shape a naive reader would assume is *not* it, which is what
/// makes the assertions above worth having rather than incidental.
#[test]
fn it_is_not_a_sixteen_sixteen_split() {
    let dev = dev_make(136, 5);
    assert_ne!(
        dev >> 16,
        136,
        "a 16/16 read would have found the major here"
    );
    assert_eq!(dev_major(dev), 136);
    assert_eq!(dev_minor(dev), 5);
}
