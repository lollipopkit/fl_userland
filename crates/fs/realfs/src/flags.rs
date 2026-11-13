//! Open flags, guest to host.
//!
//! The C wrote these as a run of `if (flags & O_RDONLY_)` tests and needed a
//! `#pragma clang diagnostic ignored "-Wunreachable-code"` around them,
//! because `O_RDONLY_` is 0 and that test can never fire. The access mode is
//! not a set of bits — it is a two-bit field — so it is translated as one
//! here, and the rest of the flags, which really are bits, as a table.
//!
//! One direction only, since 2026-09-04. There was a `from_host` for
//! `F_GETFL`, which re-derived a description's flags from the host descriptor
//! and so could never report `O_LARGEFILE`, `O_DIRECTORY`, `O_PATH` or
//! `O_NOATIME` -- the host has no such bits. `F_GETFL` is the description's own
//! `flags` now, for every kind of descriptor, and the host is only ever told.

use libc::c_int;

use crate::ffi;

/// Flags that mean the same thing on both sides, paired guest-to-host.
///
/// Deliberately not here:
///
/// * `O_DIRECTORY_` — `generic_openat` already enforces ENOTDIR against the
///   guest's view of the type, and Darwin's `open` has no `O_DIRECTORY`.
/// * `O_PATH_`, `O_DIRECT_`, `O_LARGEFILE_`, `O_NOATIME_` — no Darwin
///   equivalent; they stay guest-side.
/// * `O_CLOEXEC_` — the guest's own descriptor table carries the close-on-exec
///   bit and applies it at `execve`, so forwarding it would be redundant for
///   the guest and wrong for the host descriptor, which outlives the guest's.
const SHARED: &[(u32, c_int)] = &[
    (ffi::O_CREAT_, libc::O_CREAT),
    (ffi::O_EXCL_, libc::O_EXCL),
    (ffi::O_TRUNC_, libc::O_TRUNC),
    (ffi::O_APPEND_, libc::O_APPEND),
    (ffi::O_NONBLOCK_, libc::O_NONBLOCK),
    (ffi::O_NOFOLLOW_, libc::O_NOFOLLOW),
];

/// The access mode is a field, not a flag: 0, 1, 2 for read, write, both. The
/// fourth value is `O_ACCMODE` itself, which Linux gives to `O_PATH` opens and
/// which no host open should be asked for.
fn accmode_to_host(flags: u32) -> c_int {
    match flags & ffi::O_ACCMODE_ {
        ffi::O_WRONLY_ => libc::O_WRONLY,
        ffi::O_RDWR_ => libc::O_RDWR,
        _ => libc::O_RDONLY,
    }
}

pub fn to_host(flags: u32) -> c_int {
    SHARED.iter().fold(accmode_to_host(flags), |acc, &(g, h)| {
        if flags & g != 0 { acc | h } else { acc }
    })
}

/// The subset `F_SETFL` is allowed to change.
///
/// `fcntl` ignores everything else, but passing the creation flags through
/// invited the reader to think otherwise, and passing the access mode through
/// invited the worse belief that a descriptor's access mode can be changed
/// after the fact. It cannot, on either kernel.
pub(crate) fn to_host_settable(flags: u32) -> c_int {
    let mut host = 0;
    if flags & ffi::O_APPEND_ != 0 {
        host |= libc::O_APPEND;
    }
    if flags & ffi::O_NONBLOCK_ != 0 {
        host |= libc::O_NONBLOCK;
    }
    host
}

/// True when opening with these flags may modify the file, which is what the
/// bind-mount change tracker reports on.
pub(crate) fn may_modify(flags: u32) -> bool {
    flags & (ffi::O_CREAT_ | ffi::O_TRUNC_ | ffi::O_APPEND_) != 0
        || matches!(flags & ffi::O_ACCMODE_, ffi::O_WRONLY_ | ffi::O_RDWR_)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_mode_is_a_field_not_a_set_of_bits() {
        assert_eq!(to_host(ffi::O_RDONLY_) & libc::O_ACCMODE, libc::O_RDONLY);
        assert_eq!(to_host(ffi::O_WRONLY_) & libc::O_ACCMODE, libc::O_WRONLY);
        assert_eq!(to_host(ffi::O_RDWR_) & libc::O_ACCMODE, libc::O_RDWR);
    }

    #[test]
    fn each_shared_flag_reaches_the_host_as_its_own_bit() {
        for &(guest, host) in SHARED {
            assert_eq!(
                to_host(guest) & !libc::O_ACCMODE,
                host,
                "guest flag {guest:#x}"
            );
        }
        let guest = ffi::O_CREAT_ | ffi::O_EXCL_ | ffi::O_APPEND_ | ffi::O_NONBLOCK_ | ffi::O_RDWR_;
        assert_eq!(
            to_host(guest),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_APPEND | libc::O_NONBLOCK
        );
    }

    #[test]
    fn guest_only_flags_are_not_forwarded() {
        // Asking Darwin's open() for these produces either an error or, worse,
        // whatever the bit happens to mean there.
        for flag in [
            ffi::O_DIRECTORY_,
            ffi::O_PATH_,
            ffi::O_DIRECT_,
            ffi::O_LARGEFILE_,
            ffi::O_NOATIME_,
            ffi::O_CLOEXEC_,
        ] {
            assert_eq!(
                to_host(flag),
                libc::O_RDONLY,
                "guest-only flag {flag:#x} reached the host"
            );
        }
    }

    #[test]
    fn setflags_carries_only_what_fcntl_can_change() {
        let everything = ffi::O_CREAT_ | ffi::O_TRUNC_ | ffi::O_EXCL_ | ffi::O_RDWR_;
        assert_eq!(to_host_settable(everything), 0);
        assert_eq!(to_host_settable(ffi::O_APPEND_), libc::O_APPEND);
        assert_eq!(to_host_settable(ffi::O_NONBLOCK_), libc::O_NONBLOCK);
    }

    #[test]
    fn may_modify_covers_every_writable_open() {
        assert!(may_modify(ffi::O_WRONLY_));
        assert!(may_modify(ffi::O_RDWR_));
        assert!(may_modify(ffi::O_CREAT_));
        assert!(may_modify(ffi::O_TRUNC_));
        assert!(may_modify(ffi::O_APPEND_));
        assert!(!may_modify(ffi::O_RDONLY_));
        assert!(!may_modify(ffi::O_RDONLY_ | ffi::O_NONBLOCK_));
    }
}
