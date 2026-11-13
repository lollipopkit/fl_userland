//! How long a socket address has to be, and what shape a unix one is.
//!
//! A guest `struct sockaddr` is a 16-bit family at offset 0 and the rest is the
//! family's business. What the kernel checks before looking at the rest is a
//! *minimum length per family*, and those minima are not `sizeof` — which is
//! the defect this crate was written for.
//!
//! The family translation is `crates/fs/sockabi`; the names are
//! `crates/fs/unixname` and `crates/fs/unixpeer`. What is here is the length
//! and shape rules, which were three `if`s and a `switch` in `fs/sock.c` with
//! no test of their own.

use std::ffi::c_int;

pub use guest_errno::c_int_::{EINVAL, ENOENT};

/// `offsetof(struct sockaddr_un, sun_path)`, and the family's own size. Every
/// length below is measured from the start of the address, so this is the
/// shortest address there is.
pub const FAMILY_LEN: usize = 2;

/// `sizeof(struct sockaddr_un) - offsetof(sun_path)`. The most name there can
/// be, in either unix namespace.
///
/// **Not `NAME_MAX`**, which is a *filename*'s limit and is 255: two different
/// numbers under one name in one tree, which `tools/guessed-constants.py`
/// reported as a disagreement and which is what the name was.
pub const UNIX_NAME_MAX: usize = 108;

/// The whole of the largest address: the family and `sun_path`.
pub const ADDR_MAX: usize = FAMILY_LEN + UNIX_NAME_MAX;

/// `sizeof(struct sockaddr_in)`. Linux's `inet_bind` refuses anything below it.
pub const INET_MIN: usize = 16;

/// `SIN6_LEN_RFC2133`, which is **24** and not `sizeof(struct sockaddr_in6)`.
///
/// It is the size the original IPv6 socket API had, before `sin6_scope_id` was
/// added, and `inet6_bind` still accepts it: an address without a scope id is a
/// whole address for anything that is not link-local. This kernel required 28
/// — `sizeof` — so a program built against the older shape was refused with
/// `EINVAL` where a real kernel binds it.
pub const INET6_MIN: usize = 24;

/// The length the *host* wants, for a family whose address is fixed-size.
///
/// Linux checks a minimum and ignores the rest; Darwin's `in_pcbbind` and
/// `in6_pcbbind` check `nam->sa_len != sizeof(...)` and refuse anything else,
/// and XNU's `sockargs` sets `sa_len` from the length the syscall was given.
/// So an address a guest may legally pass — 24 bytes of IPv6 with no scope id,
/// or 20 bytes of IPv4 with trailing junk Linux discards — has to be
/// normalised to exactly `sizeof` on the way out, with anything added zeroed.
///
/// `None` for a unix address, whose length is the name's and which the caller
/// rewrites anyway.
pub fn host_len(family: Family) -> Option<usize> {
    match family {
        Family::Unix => None,
        Family::Inet => Some(INET_MIN),
        // 28. The *minimum* is 24; the size is not.
        Family::Inet6 => Some(28),
    }
}

/// Which family's rules to apply. The caller has already translated the guest
/// family to its host one, which is `crates/fs/sockabi`'s job and is a
/// different question from this one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum Family {
    Unix = 0,
    Inet = 1,
    Inet6 = 2,
}

/// What a unix address names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unix<'a> {
    /// A path in the filesystem. The bytes are the path; there may be no
    /// terminator, so the length carries.
    Path(&'a [u8]),
    /// A name in the abstract namespace: the bytes *after* the leading NUL,
    /// which may contain NULs of their own.
    Abstract(&'a [u8]),
    /// The family and nothing else. `bind` reads this as an autobind — Linux
    /// picks a name — and every other call as `EINVAL`.
    Unnamed,
}

/// Is this address long enough for its family?
///
/// The upper bound is shared: nothing here is longer than a `sockaddr_un`, and
/// a caller claiming more is describing something this cannot hold.
pub fn check_len(family: Family, len: usize) -> Result<(), c_int> {
    if !(FAMILY_LEN..=ADDR_MAX).contains(&len) {
        return Err(EINVAL);
    }
    let min = match family {
        Family::Unix => FAMILY_LEN,
        Family::Inet => INET_MIN,
        Family::Inet6 => INET6_MIN,
    };
    if len < min { Err(EINVAL) } else { Ok(()) }
}

/// What the `sun_path` of a unix address names.
///
/// `path` is the address's bytes after the family — exactly `len - 2` of them,
/// however many the caller passed, with no terminator implied.
pub fn unix_name(path: &[u8]) -> Unix<'_> {
    match path.first() {
        None => Unix::Unnamed,
        // The leading NUL is the marker and is not part of the name.
        Some(0) => Unix::Abstract(&path[1..]),
        Some(_) => Unix::Path(path),
    }
}

/// The length `getsockname` reports for a bound name, measured from the start
/// of the address.
///
/// Linux records the length of the **name**, not the length the caller passed:
/// `unix_bind_bsd` uses `strlen(sun_path) + offsetof(sun_path) + 1`. Almost
/// everything passes `sizeof(struct sockaddr_un)`, so recording that made
/// `getsockname` report 110 for a socket bound to `/tmp/x.sock` where Linux
/// reports 16 — and the C idiom `path[len - offsetof] = '\0'` then writes one
/// byte past a 108-byte `sun_path` in the *guest*.
///
/// An abstract name is the exception and keeps the caller's length: it may
/// contain NULs and has no terminator, so trimming would lose part of it.
pub fn recorded_name_len(path: &[u8]) -> usize {
    match unix_name(path) {
        Unix::Unnamed | Unix::Abstract(_) => path.len(),
        Unix::Path(bytes) => {
            let n = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            // The terminator counts, as it does on Linux -- unless the name
            // fills the buffer and there is none.
            if n < bytes.len() { n + 1 } else { n }
        }
    }
}

/* `sockaddr_check_len` and `sockaddr_unix_name` were here, `#[cfg(test)]`,
 * until 2026-10-01: a C-shaped binding -- a family as an integer, a pointer
 * and a length, two out-parameters -- that no C has called since the socket
 * layer became Rust. Its one test asked whether it agreed with the functions
 * it wrapped; the test asks those directly now. */

/* `sockaddr_recorded_name_len` was here, `#[cfg(test)]`, until 2026-09-15: a
 * `(*const u8, usize)` wrapper over `recorded_name_len`, whose two callers are
 * tests that already hold a slice and were writing `name.as_ptr(),
 * name.len()`. A function whose whole body reassembles what its caller took
 * apart has nothing to do; the tests call `recorded_name_len` directly. */

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect. `SIN6_LEN_RFC2133` is 24 and `sizeof(struct sockaddr_in6)`
    /// is 28; `inet6_bind` uses the first. An arm64 Linux container binds a
    /// 24-byte address and this kernel answered EINVAL.
    #[test]
    fn an_ipv6_address_may_omit_its_scope_id() {
        assert_eq!(check_len(Family::Inet6, 24), Ok(()));
        assert_eq!(check_len(Family::Inet6, 28), Ok(()));
        assert_eq!(check_len(Family::Inet6, 23), Err(EINVAL));
        assert_ne!(INET6_MIN, 28, "not sizeof");
    }

    /// What a guest may pass and what the host wants are different questions,
    /// and conflating them is why 24 bytes of IPv6 did not work: Linux checks
    /// a minimum and Darwin checks `sa_len == sizeof`.
    #[test]
    fn the_host_length_is_the_size_and_the_check_is_the_minimum() {
        assert_eq!(host_len(Family::Inet6), Some(28));
        assert_eq!(check_len(Family::Inet6, 24), Ok(()));
        assert_eq!(host_len(Family::Inet), Some(16));
        assert_eq!(host_len(Family::Unix), None);
        for f in [Family::Inet, Family::Inet6] {
            assert!(check_len(f, host_len(f).unwrap()).is_ok());
        }
    }

    #[test]
    fn an_ipv4_address_is_the_whole_struct() {
        assert_eq!(check_len(Family::Inet, 16), Ok(()));
        assert_eq!(check_len(Family::Inet, 15), Err(EINVAL));
    }

    /// A unix address may be the family alone, which `bind` reads as an
    /// autobind. Every family refuses less than that, and every family refuses
    /// more than a `sockaddr_un`.
    #[test]
    fn the_family_alone_is_the_shortest_and_a_sockaddr_un_the_longest() {
        assert_eq!(check_len(Family::Unix, 2), Ok(()));
        for f in [Family::Unix, Family::Inet, Family::Inet6] {
            assert_eq!(check_len(f, 1), Err(EINVAL), "{f:?}");
            assert_eq!(check_len(f, 0), Err(EINVAL), "{f:?}");
            assert_eq!(check_len(f, ADDR_MAX + 1), Err(EINVAL), "{f:?}");
        }
        assert_eq!(check_len(Family::Unix, ADDR_MAX), Ok(()));
        assert_eq!(ADDR_MAX, 110);
    }

    #[test]
    fn a_unix_name_is_a_path_a_namespace_entry_or_nothing() {
        assert_eq!(unix_name(b"/tmp/s.sock"), Unix::Path(b"/tmp/s.sock"));
        assert_eq!(unix_name(b"\0log"), Unix::Abstract(b"log"));
        assert_eq!(unix_name(b""), Unix::Unnamed);
        assert_eq!(unix_name(b"\0"), Unix::Abstract(b""));
        assert_eq!(unix_name(b"\0a\0b"), Unix::Abstract(b"a\0b"));
    }

    /// A pathname's recorded length is `strlen + 1`, so `getsockname` reports
    /// 16 for `/tmp/x.sock` where the caller passed 110. The `+1` is the
    /// terminator, and it is dropped only when the name fills the buffer and
    /// there is none.
    #[test]
    fn a_pathname_records_its_length_and_its_terminator() {
        assert_eq!(recorded_name_len(b"/tmp/x.sock\0\0\0"), 12);
        assert_eq!(recorded_name_len(b"/a\0"), 3);
        let full = vec![b'a'; UNIX_NAME_MAX];
        assert_eq!(
            recorded_name_len(&full),
            UNIX_NAME_MAX,
            "no terminator to count"
        );
    }

    /// An abstract name keeps the caller's length, because it has no
    /// terminator and may contain NULs -- trimming would lose part of it.
    #[test]
    fn an_abstract_name_records_what_the_caller_passed() {
        assert_eq!(recorded_name_len(b"\0log\0v1"), 7);
        assert_eq!(recorded_name_len(b"\0"), 1);
        assert_eq!(recorded_name_len(b""), 0);
    }

    /// The two together are what a `getsockname` answers, and the sum has to
    /// be an address length a caller can hand back to `bind`.
    #[test]
    fn a_recorded_length_is_one_a_caller_could_pass() {
        for name in [&b"/tmp/x\0"[..], b"\0abstract", b"\0", b"/a"] {
            let reported = FAMILY_LEN + recorded_name_len(name);
            assert_eq!(check_len(Family::Unix, reported), Ok(()), "{name:?}");
        }
    }
}
