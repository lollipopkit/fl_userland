//! Tests for generic file-descriptor flag and offset behavior.

use super::*;
/* The two `dev_t` packing tests moved to `crates/fs/devices` on 2026-09-15,
 * to the crate that defines the format. They were testing this crate's own
 * second copy of the encoder against this crate's own second copy of the
 * decoders, which is a test agreeing with itself. */

// ------------------------------------------ the guest's open(2) flag bits
//
// `tests/unit/openflags_test.c` until 2026-09-08.
//
// The guest is AArch64, and AArch64 overrides the asm-generic values for
// three flags (`arch/arm64/include/uapi/asm/fcntl.h`, for AArch32 compat).
// This tree carried x86's instead, so `O_DIRECTORY_` was `1<<16` -- which
// no aarch64 guest ever sets for `O_DIRECTORY` and *is* `O_DIRECT` there.
// An `O_DIRECT` open was read as an `O_DIRECTORY` one and failed on any
// non-directory: GNU `cp` over an existing file died with "cannot create
// regular file: Not a directory". `O_NOFOLLOW_` had no value at all.
//
// A wrong constant is only visible against something that does not move
// with it, so the values are literals rather than expressions over each
// other.

/// From `arch/arm64/include/uapi/asm/fcntl.h` and `asm-generic/fcntl.h`.
#[test]
fn the_flag_values_are_the_aarch64_ones() {
    assert_eq!(ffi::O_DIRECTORY_, 0x4000);
    assert_eq!(ffi::O_NOFOLLOW_, 0x8000);
    assert_eq!(ffi::O_DIRECT_, 0x10000);
    assert_eq!(ffi::O_LARGEFILE_, 0x20000);
    assert_eq!(ffi::O_NOATIME_, 0x40000);
    assert_eq!(ffi::O_CLOEXEC_, 0x80000);
    assert_eq!(ffi::O_PATH_, 0x200000);

    // The asm-generic ones AArch64 does not override, so a future edit
    // cannot quietly shift the whole block.
    assert_eq!(ffi::O_CREAT_, 0x40);
    assert_eq!(ffi::O_TRUNC_, 0x200);
    assert_eq!(ffi::O_APPEND_, 0x400);
    assert_eq!(ffi::O_NONBLOCK_, 0x800);
}

/// The *shape* of the original bug: two flags sharing a bit. Nothing above
/// would catch a **new** flag colliding with an existing one, which is the
/// same mistake in a different place.
#[test]
fn no_two_open_flags_share_a_bit() {
    let flags = [
        ("O_WRONLY_", ffi::O_WRONLY_),
        ("O_RDWR_", ffi::O_RDWR_),
        ("O_CREAT_", ffi::O_CREAT_),
        ("O_EXCL_", ffi::O_EXCL_),
        ("O_NOCTTY_", ffi::O_NOCTTY_),
        ("O_TRUNC_", ffi::O_TRUNC_),
        ("O_APPEND_", ffi::O_APPEND_),
        ("O_NONBLOCK_", ffi::O_NONBLOCK_),
        ("O_DIRECTORY_", ffi::O_DIRECTORY_),
        ("O_NOFOLLOW_", ffi::O_NOFOLLOW_),
        ("O_DIRECT_", ffi::O_DIRECT_),
        ("O_LARGEFILE_", ffi::O_LARGEFILE_),
        ("O_NOATIME_", ffi::O_NOATIME_),
        ("O_CLOEXEC_", ffi::O_CLOEXEC_),
        ("O_PATH_", ffi::O_PATH_),
    ];
    // `O_RDONLY_` is zero and is left out: an access mode is not a bit.
    assert_eq!(ffi::O_RDONLY_, 0);
    for (i, (na, a)) in flags.iter().enumerate() {
        for (nb, b) in &flags[i + 1..] {
            assert_eq!(a & b, 0, "{na} ({a:#x}) and {nb} ({b:#x}) share a bit");
        }
    }
}
