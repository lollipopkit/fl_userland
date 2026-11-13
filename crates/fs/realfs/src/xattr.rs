//! Extended attributes, forwarded to the host's.
//!
//! Darwin has all four operations and this mount is a host directory, so the
//! guest's attributes are the host file's — a guest that writes `user.a` and a
//! host tool that reads it see the same thing, which is what a passthrough
//! mount is for.
//!
//! Three things are not a straight forward, and each was measured on the host
//! rather than read:
//!
//! - **The host has attributes of its own.** `listxattr` on a file this program
//!   just created answers `com.apple.provenance user.a` — so the list is
//!   filtered to the four namespaces Linux defines, and the guest never sees
//!   the rest. Without that, every `listxattr` in a guest reports a name no
//!   Linux kernel would produce and a round trip does not round trip.
//! - **`XATTR_CREATE` and `XATTR_REPLACE` are not the same numbers.** Linux has
//!   1 and 2; Darwin has 2 and 4, with 1 being `XATTR_NOFOLLOW`. Passing the
//!   guest's word through unmapped would turn a `XATTR_CREATE` into a
//!   "do not follow the symlink" and lose the exclusivity the caller asked for.
//! - **A name may be 127 bytes here and 255 on Linux.** 128 answers
//!   `ENAMETOOLONG`, which is not in `setxattr(2)`'s list at all. It is passed
//!   through rather than translated: inventing a Linux errno for a host limit
//!   would say the name was wrong when it was the disk. `crates/fs/tmpfs` has
//!   no such limit, so `fs_conformance` checks Linux's 255 there.
//!
//! There is no `*xattrat`, so a path operation opens a descriptor relative to
//! the mount root and uses the `f*` form. `O_SYMLINK` is what Darwin has for
//! naming a link rather than its target, the same flag `realfs_open` uses for
//! `O_PATH|O_NOFOLLOW`.

use crate::errno::{Result, rx};
use crate::{at_path, ffi, host, root};
use rustix::fs::{self as host_fs, Mode, OFlags, XattrFlags};
use std::ffi::{CStr, c_int};
use std::os::fd::{AsFd, BorrowedFd};

// Darwin's `XATTR_NOFOLLOW` is 1, which is Linux's `XATTR_CREATE`. Not used: a
// path operation names the link with `O_SYMLINK` on the open instead. The test
// below says the flag mapping never produces it by accident, which is the
// mistake passing the guest's word through unmapped would make.
//
// The four calls are `rustix`'s since 2026-09-29, and `libc`'s the same day
// before that; they were a hand-written `extern` block and three hand-copied
// numbers until then, which is a second rendering of an interface the linker
// matches by name alone.

/// The guest's `XATTR_CREATE`/`XATTR_REPLACE` as Darwin's, which is what
/// `rustix`'s names hold on this host.
fn host_flags(guest: c_int) -> XattrFlags {
    let mut out = XattrFlags::empty();
    if guest & 1 != 0 {
        out |= XattrFlags::CREATE;
    }
    if guest & 2 != 0 {
        out |= XattrFlags::REPLACE;
    }
    out
}

/// Whether a name is one Linux would produce, which is what a guest may see.
///
/// The host's own `com.apple.*` are not; nor is anything else without one of
/// the four prefixes, because a guest could not have written it through this
/// interface and reporting it would be reporting the host.
fn guest_visible(name: &[u8]) -> bool {
    name.starts_with(b"user.")
        || name.starts_with(b"trusted.")
        || name.starts_with(b"security.")
        || name.starts_with(b"system.")
}

/// The filtered, NUL-terminated list, from what the host answered.
fn filter_list(host: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(host.len());
    for name in host.split(|b| *b == 0) {
        if !name.is_empty() && guest_visible(name) {
            out.extend_from_slice(name);
            out.push(0);
        }
    }
    out
}

/// One operation on an already-open host descriptor.
pub(crate) fn on_fd(fd: BorrowedFd<'_>, call: ffi::XattrCall<'_>) -> isize {
    let answer = match call {
            ffi::XattrCall::Get { name, out } => {
                // One call, not two: the second would answer a second time and
                // a value the guest changed in between would come back split.
                // The host's rule for an empty buffer is the guest's -- report
                // the length, write nothing -- so it passes straight through.
                rx(host_fs::fgetxattr(fd, name, &mut *out)).map(|n| n as isize)
            }
            ffi::XattrCall::Set { name, value, flags } => {
                // **Both flags at once is Darwin's `EINVAL` and Linux's
                // `EEXIST`-or-`ENODATA`.** Linux does not compare the two: it
                // applies `XATTR_CREATE` and then `XATTR_REPLACE`, and whichever
                // fails first is the answer -- so the pair is a request that
                // cannot succeed and the errno says *why*, which a caller
                // reading it to decide whether to retry needs. Answered here,
                // from whether the name is there, and the host is not asked.
                //
                // Only for the pair. A single flag goes down untouched, because
                // `XATTR_CREATE` on its own is an atomic test-and-set and
                // deciding it here would make it two calls with a window.
                if flags & (xattrabi::XATTR_CREATE | xattrabi::XATTR_REPLACE)
                    == (xattrabi::XATTR_CREATE | xattrabi::XATTR_REPLACE)
                {
                    let exists = host_fs::fgetxattr(fd, name, &mut [0u8; 0][..]).is_ok();
                    xattrabi::check_exists(flags, exists).map(|()| 0)
                } else {
                    rx(host_fs::fsetxattr(fd, name, value, host_flags(flags))).map(|()| 0)
                }
            }
            ffi::XattrCall::List { out } => {
                // Asked for in full first, because the filter changes the
                // length: a caller's buffer is measured against what it will
                // actually receive, not against what the host holds.
                host_list(fd).and_then(|host| {
                    let list = filter_list(&host);
                    if out.is_empty() {
                        Ok(list.len() as isize)
                    } else if list.len() > out.len() {
                        Err(xattrabi::ERANGE)
                    } else {
                        out[..list.len()].copy_from_slice(&list);
                        Ok(list.len() as isize)
                    }
                })
            }
            ffi::XattrCall::Remove { name } => {
                rx(host_fs::fremovexattr(fd, name)).map(|()| 0)
            }
    };
    answer.unwrap_or_else(|e| e as isize)
}

/// Every attribute name the host holds for `fd`.
///
/// A buffer that grows until the answer fits, rather than a size query and a
/// second call: a name added in between made the second call `ERANGE`, and
/// asking the size by passing an empty buffer is not portable to Darwin,
/// which answers `ERANGE` for a non-null one of length zero.
fn host_list(fd: BorrowedFd<'_>) -> Result<Vec<u8>> {
    let mut list = Vec::with_capacity(256);
    loop {
        match host_fs::flistxattr(fd, rustix::buffer::spare_capacity(&mut list)) {
            Ok(_) => return Ok(list),
            Err(rustix::io::Errno::RANGE) => list.reserve(list.capacity() * 2),
            Err(e) => return rx(Err(e)),
        }
    }
}


/// `fs_ops.xattr`: by path, relative to the mount root.
///
/// Neither `#[unsafe(no_mangle)]` nor `extern "C"`: a guest reaches this
/// through [`crate::ffi::FsOps`], which is a trait object rather than a name,
/// and no C calls it. The convention came off on 2026-09-11 and taking it off
/// is what allowed [`crate::ffi::XattrCall`] to exist — an `extern "C" fn`
/// may not take a type that is not FFI-safe, so the six pointers stayed six
/// pointers for as long as the C ABI was on this signature.
pub fn realfs_xattr(mount: &ffi::mount,
    path: &CStr,
    call: ffi::XattrCall,
    follow_links: bool,
) -> isize {
    {
        // O_RDONLY: none of the four writes the file's contents, and asking for
        // write would refuse a `getxattr` on a read-only file that Linux
        // answers.
        //
        // **O_NONBLOCK, or a fifo hangs the guest thread for ever.** Opening one
        // for reading waits for a writer, and `getxattr` on a fifo is a call
        // Linux answers -- the namespace rules refuse a *write* to `user.*` on
        // one and allow the read, so this is reachable by an ordinary caller.
        // Found by backing the namespace check out and watching
        // `fs_conformance` stop for thirty-four minutes, which is what that
        // discipline is for.
        //
        // O_NOCTTY for the same class of reason one step further out: a device
        // node in a passthrough mount would otherwise become the guest's
        // controlling terminal because somebody asked it for an attribute.
        let mut open_flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY;
        if !follow_links {
            // Darwin's `O_SYMLINK`, which `rustix` does not name.
            open_flags |= OFlags::from_bits_retain(libc::O_SYMLINK as _);
        }
        let opened = root(mount)
            .and_then(|root| rx(host_fs::openat(root, at_path(path), open_flags, Mode::empty())));
        match opened {
            Ok(fd) => on_fd(fd.as_fd(), call),
            Err(e) => e as isize,
        }
    }
}

/// `fs_ops.fxattr`: on an open descriptor.
pub fn realfs_fxattr(fd: &ffi::fd, call: ffi::XattrCall) -> isize {
    match host(fd) {
        Ok(host) => on_fd(host, call),
        Err(e) => e as isize,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hosts_own_attributes_are_not_the_guests() {
        // Measured: `listxattr` on a file this program had just created
        // answered `com.apple.provenance user.a`. A guest that saw the first
        // would be reading the host.
        let host = b"com.apple.provenance\0user.a\0com.apple.quarantine\0user.b\0";
        assert_eq!(filter_list(host), b"user.a\0user.b\0");
    }

    #[test]
    fn every_linux_namespace_survives_the_filter() {
        let host = b"user.a\0trusted.b\0security.c\0system.d\0com.apple.e\0";
        assert_eq!(
            filter_list(host),
            b"user.a\0trusted.b\0security.c\0system.d\0"
        );
    }

    #[test]
    fn an_empty_list_stays_empty_rather_than_becoming_one_nul() {
        assert_eq!(filter_list(b""), b"");
        assert_eq!(filter_list(b"com.apple.provenance\0"), b"");
    }

    #[test]
    fn the_two_flag_words_are_not_the_same_numbers() {
        // Linux 1 and 2, Darwin 2 and 4 -- and Darwin's 1 is NOFOLLOW, so
        // passing the guest's word through would turn a XATTR_CREATE into
        // "do not follow the symlink" and lose the exclusivity entirely.
        let bits = |g| host_flags(g).bits() as c_int;
        assert_eq!(bits(0), 0);
        assert_eq!(bits(1), libc::XATTR_CREATE);
        assert_eq!(bits(2), libc::XATTR_REPLACE);
        assert_eq!(bits(3), libc::XATTR_CREATE | libc::XATTR_REPLACE);
        assert_eq!(bits(1) & libc::XATTR_NOFOLLOW, 0, "never NOFOLLOW by accident");
    }
}
