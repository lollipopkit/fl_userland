//! Guest errno definitions and host-to-guest mapping.

use std::ffi::c_int;

/// What the table made of a host errno.
#[repr(C)]
pub struct Mapped {
    /// The guest errno, negative, always in `[-4095, -1]`.
    pub guest: c_int,
    /// Zero when the host errno was not in the table and `guest` is the
    /// fallback. The caller logs it; it is not an error in itself, because a
    /// host may define an errno this table has never heard of.
    pub known: c_int,
}

/// Where an unrecognised host errno lands.
///
/// It has to be a real errno rather than a sentinel, because whatever comes out
/// of here is what the guest program sees. `EIO` is the generic "the operation
/// failed for a reason not otherwise described", which is exactly the
/// situation, and unlike the old fallback it cannot be mistaken for success.
const FALLBACK: c_int = guest::EIO;

/// The guest's errno numbers, from asm-generic/errno.h. Negative, as the
/// syscall return convention wants them.
///
/// They were written out here until 2026-09-11 and are `crates/util/errno`'s
/// now, for the reason that crate's module comment gives: three crates in
/// `util/` answer an errno and cannot depend on a `kernel` one. This is a
/// re-export rather than a move of the name, so `guest::EIO` still resolves in
/// the crates that reach the numbers through this one.
pub use guest_errno::c_int_ as guest;

/// Host errnos the `libc` crate does not export for this target.
///
/// Darwin-only, from `sys/errno.h`. Written out rather than read from a header,
/// and checked by `host_only_errnos_are_in_range` below — these are the numbers
/// whose whole purpose is to be recognised rather than fall through, so a wrong
/// one would silently reinstate the bug this table exists to fix.
pub(crate) mod darwin {
    use std::ffi::c_int;
    pub const EPROCLIM: c_int = 67;
    pub const EBADRPC: c_int = 72;
    pub const ERPCMISMATCH: c_int = 73;
    pub const EPROGUNAVAIL: c_int = 74;
    pub const EPROGMISMATCH: c_int = 75;
    pub const EPROCUNAVAIL: c_int = 76;
    pub const EFTYPE: c_int = 79;
    pub const EAUTH: c_int = 80;
    pub const ENEEDAUTH: c_int = 81;
    pub const EPWROFF: c_int = 82;
    pub const EDEVERR: c_int = 83;
    pub const EBADEXEC: c_int = 85;
    pub const EBADARCH: c_int = 86;
    pub const ESHLIBVERS: c_int = 87;
    pub const EBADMACHO: c_int = 88;
    /// Darwin's `getxattr` answers this where Linux answers `ENODATA`.
    pub const ENOATTR: c_int = 93;
    pub const ENOPOLICY: c_int = 103;
    pub const EQFULL: c_int = 106;
    /// Capsicum's, which Darwin adopted. Linux has no capability errno of
    /// its own and refuses this kind of thing with EPERM.
    pub const ENOTCAPABLE: c_int = 107;
}

fn known(guest: c_int) -> Mapped {
    Mapped { guest, known: 1 }
}

/// The POSIX errnos, which both sides have under the same name.
fn posix(host: c_int) -> Option<c_int> {
    // Written as a chain rather than a `match`, because `libc::E*` are not
    // constant patterns on every target and two of them collide on some
    // (EOPNOTSUPP and ENOTSUP are the same number on Darwin, EAGAIN and
    // EWOULDBLOCK everywhere).
    let pairs: &[(c_int, c_int)] = &[
        (libc::EPERM, guest::EPERM),
        (libc::ENOENT, guest::ENOENT),
        (libc::ESRCH, guest::ESRCH),
        (libc::EINTR, guest::EINTR),
        (libc::EIO, guest::EIO),
        (libc::ENXIO, guest::ENXIO),
        (libc::E2BIG, guest::E2BIG),
        (libc::ENOEXEC, guest::ENOEXEC),
        (libc::EBADF, guest::EBADF),
        (libc::ECHILD, guest::ECHILD),
        (libc::EAGAIN, guest::EAGAIN),
        (libc::ENOMEM, guest::ENOMEM),
        (libc::EACCES, guest::EACCES),
        (libc::EFAULT, guest::EFAULT),
        (libc::ENOTBLK, guest::ENOTBLK),
        (libc::EBUSY, guest::EBUSY),
        (libc::EEXIST, guest::EEXIST),
        (libc::EXDEV, guest::EXDEV),
        (libc::ENODEV, guest::ENODEV),
        (libc::ENOTDIR, guest::ENOTDIR),
        (libc::EISDIR, guest::EISDIR),
        (libc::EINVAL, guest::EINVAL),
        (libc::ENFILE, guest::ENFILE),
        (libc::EMFILE, guest::EMFILE),
        (libc::ENOTTY, guest::ENOTTY),
        (libc::ETXTBSY, guest::ETXTBSY),
        (libc::EFBIG, guest::EFBIG),
        (libc::ENOSPC, guest::ENOSPC),
        (libc::ESPIPE, guest::ESPIPE),
        (libc::EROFS, guest::EROFS),
        (libc::EMLINK, guest::EMLINK),
        (libc::EPIPE, guest::EPIPE),
        (libc::EDOM, guest::EDOM),
        (libc::ERANGE, guest::ERANGE),
        (libc::EDEADLK, guest::EDEADLK),
        (libc::ENAMETOOLONG, guest::ENAMETOOLONG),
        (libc::ENOLCK, guest::ENOLCK),
        (libc::ENOSYS, guest::ENOSYS),
        (libc::ENOTEMPTY, guest::ENOTEMPTY),
        (libc::ELOOP, guest::ELOOP),
        (libc::ENOMSG, guest::ENOMSG),
        (libc::EIDRM, guest::EIDRM),
        (libc::ENOSTR, guest::ENOSTR),
        (libc::ENODATA, guest::ENODATA),
        (libc::ETIME, guest::ETIME),
        (libc::ENOSR, guest::ENOSR),
        (libc::EREMOTE, guest::EREMOTE),
        (libc::ENOLINK, guest::ENOLINK),
        (libc::EPROTO, guest::EPROTO),
        (libc::EMULTIHOP, guest::EMULTIHOP),
        (libc::EBADMSG, guest::EBADMSG),
        (libc::EOVERFLOW, guest::EOVERFLOW),
        (libc::EILSEQ, guest::EILSEQ),
        (libc::EUSERS, guest::EUSERS),
        (libc::ENOTSOCK, guest::ENOTSOCK),
        (libc::EDESTADDRREQ, guest::EDESTADDRREQ),
        (libc::EMSGSIZE, guest::EMSGSIZE),
        (libc::EPROTOTYPE, guest::EPROTOTYPE),
        (libc::ENOPROTOOPT, guest::ENOPROTOOPT),
        (libc::EPROTONOSUPPORT, guest::EPROTONOSUPPORT),
        (libc::ESOCKTNOSUPPORT, guest::ESOCKTNOSUPPORT),
        (libc::EOPNOTSUPP, guest::EOPNOTSUPP),
        (libc::ENOTSUP, guest::EOPNOTSUPP),
        (libc::EPFNOSUPPORT, guest::EPFNOSUPPORT),
        (libc::EAFNOSUPPORT, guest::EAFNOSUPPORT),
        (libc::EADDRINUSE, guest::EADDRINUSE),
        (libc::EADDRNOTAVAIL, guest::EADDRNOTAVAIL),
        (libc::ENETDOWN, guest::ENETDOWN),
        (libc::ENETUNREACH, guest::ENETUNREACH),
        (libc::ENETRESET, guest::ENETRESET),
        (libc::ECONNABORTED, guest::ECONNABORTED),
        (libc::ECONNRESET, guest::ECONNRESET),
        (libc::ENOBUFS, guest::ENOBUFS),
        (libc::EISCONN, guest::EISCONN),
        (libc::ENOTCONN, guest::ENOTCONN),
        (libc::ESHUTDOWN, guest::ESHUTDOWN),
        (libc::ETOOMANYREFS, guest::ETOOMANYREFS),
        (libc::ETIMEDOUT, guest::ETIMEDOUT),
        (libc::ECONNREFUSED, guest::ECONNREFUSED),
        (libc::EHOSTDOWN, guest::EHOSTDOWN),
        (libc::EHOSTUNREACH, guest::EHOSTUNREACH),
        (libc::EALREADY, guest::EALREADY),
        (libc::EINPROGRESS, guest::EINPROGRESS),
        (libc::ESTALE, guest::ESTALE),
        (libc::EDQUOT, guest::EDQUOT),
        (libc::ECANCELED, guest::ECANCELED),
        (libc::EOWNERDEAD, guest::EOWNERDEAD),
        (libc::ENOTRECOVERABLE, guest::ENOTRECOVERABLE),
    ];
    pairs.iter().find(|(h, _)| *h == host).map(|(_, g)| *g)
}

/// Errnos only Darwin has, and the nearest thing Linux would have said.
///
/// Most describe a failure Linux has no name for, and become `EINVAL` — a
/// defined refusal the caller can act on, where the alternative is a value it
/// reads as success.
fn host_only(host: c_int) -> Option<c_int> {
    Some(match host {
        // Linux reports a hit process limit as EAGAIN, from fork.
        darwin::EPROCLIM => guest::EAGAIN,
        // "Attribute not found" is Linux's ENODATA, which is what a guest's
        // getxattr expects. Nothing here implements xattr yet, so this is
        // ahead of its caller rather than fixing an observed failure.
        darwin::ENOATTR => guest::ENODATA,
        // The interface output queue is full: a send that could not be
        // buffered, which is ENOBUFS on Linux.
        darwin::EQFULL => guest::ENOBUFS,
        // Mach-O and dyld failures, reached through execve of a host binary in
        // the native-offload path. Linux's nearest is "not a valid executable".
        darwin::EBADEXEC | darwin::EBADARCH | darwin::ESHLIBVERS | darwin::EBADMACHO => {
            guest::ENOEXEC
        }
        // Authentication, RPC and device errors with no Linux counterpart.
        darwin::EAUTH
        | darwin::ENEEDAUTH
        | darwin::EBADRPC
        | darwin::ERPCMISMATCH
        | darwin::EPROGUNAVAIL
        | darwin::EPROGMISMATCH
        | darwin::EPROCUNAVAIL
        | darwin::EFTYPE
        | darwin::ENOPOLICY => guest::EINVAL,
        darwin::EPWROFF | darwin::EDEVERR => guest::EIO,
        darwin::ENOTCAPABLE => guest::EPERM,
        _ => return None,
    })
}

pub fn map(host: c_int) -> Mapped {
    if let Some(g) = posix(host) {
        return known(g);
    }
    if let Some(g) = host_only(host) {
        return known(g);
    }
    Mapped {
        guest: FALLBACK,
        known: 0,
    }
}
