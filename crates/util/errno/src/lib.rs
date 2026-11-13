//! The guest's errno numbers, in one place.
//!
//! A `sys_*` here reports failure by returning a small negative number, and
//! those numbers are **asm-generic's** — what aarch64 Linux uses — not the
//! host's. Until 2026-09-11 every crate that needed one wrote it out:
//!
//! ```text
//! const EINVAL: i64 = -22;
//! ```
//!
//! 431 of those, across 119 files in 93 crates, for 53 distinct names. No two
//! disagreed, but nothing said they could not. This tree has already had the
//! same class of defect once: 55 crates each ran bindgen over the same
//! `#define`s, and `POLL_ERR` in one of them picked up a *system* header's
//! macro of the same name, whose value was another flag in the set. One owner
//! removes the class; a check over 93 copies only reports it.
//!
//! # Why `util/` and not `kernel/`
//!
//! `crates/util/waitfor` answers `EINTR` and `ETIMEDOUT`, `crates/util/guestlock`
//! three more, and `crates/util/timeabi` one. Those are layer 0, so an owner in
//! the `kernel` layer would be an upward edge and `tools/crate-layers.py`
//! refuses one. Errno numbers are a guest ABI constant and need no kernel state
//! to state, so the lowest layer is where they belong — the same argument that
//! moved `lock_t` into `crates/util/synctypes` and `cpu_state` into
//! `crates/emu/abi`.
//!
//! # The other errno crate
//!
//! `crates/kernel/errno` is the **host to guest** mapping: it reads the host's
//! `errno` and answers one of these. It is not a second copy of the numbers —
//! it re-exports this crate's as its `guest` module, which is where they lived
//! until this crate existed. Its `errno_map` also raises `SIGPIPE` for `EPIPE`,
//! so it is not a pure table and must not be reimplemented.
//!
//! # What a caller uses
//!
//! [`Errno`] is the type. The three modules below are the same numbers as plain
//! integers, one per width the tree's own definitions used, and exist so that
//! replacing a local `const` is type-exact rather than a judgement call:
//!
//! | module | type | who |
//! | --- | --- | --- |
//! | [`c_int_`] | `c_int` | most of the tree, and every `i32` site — `c_int` *is* `i32` on every target this builds for |
//! | [`i64_`] | `i64` | the width most `sys_*` return |
//! | [`isize_`] | `isize` | the read/write paths, where the success case is a byte count |
//!
//! New code should prefer `Errno` and a `Result`; the integer views are for the
//! functions that still return a negative number directly.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_int;
use std::fmt;

/// A guest errno, stored **negative** — the way a syscall returns it.
///
/// Negative rather than positive because that is what every caller in this tree
/// wants: the syscall table returns `-22` and nothing ever wants `22`. Storing
/// it the other way round would put a negation on every conversion and leave
/// the sign as something each call site could get wrong.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Errno(c_int);

/// The range a guest libc reads as an error.
///
/// musl's `__syscall_ret` treats an unsigned return above `-4096` as `-errno`
/// and anything else as a successful result, so a number outside this is not a
/// failure the guest can see — it is a huge length, descriptor or pointer. See
/// `docs/changelog/2026-08-22-unmapped-errno-arrived-as-success.md`, which is
/// the bug that property is stated for.
const GUEST_VISIBLE: std::ops::RangeInclusive<c_int> = -4095..=-1;

impl Errno {
    /// The number, as the syscall table's `c_int`.
    pub const fn as_c_int(self) -> c_int {
        self.0
    }

    /// The number, as the `i64` most `sys_*` return.
    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    /// The number, as the `isize` the read and write paths return.
    pub const fn as_isize(self) -> isize {
        self.0 as isize
    }

    /// Wrap a number that is already a negative guest errno, or `None`.
    ///
    /// The check is the range above and not membership of the list, because a
    /// guest kernel may answer an errno this file has never heard of and the
    /// property that matters is the one the guest's libc tests.
    pub const fn from_negative(v: c_int) -> Option<Self> {
        if v >= -4095 && v <= -1 {
            Some(Errno(v))
        } else {
            None
        }
    }

    /// The same, for a caller with nothing to do about a value out of range.
    ///
    /// Falls back to `EIO` for the reason `crates/kernel/errno` gives for its
    /// own fallback: whatever comes out of here is what the guest program sees,
    /// so it has to be a real errno, and `EIO` is the generic "failed for a
    /// reason not otherwise described". The `debug_assert` is what says a
    /// caller handing this an out-of-range number has a bug — the mapping that
    /// feeds it guarantees the range for every input.
    pub fn from_negative_or_eio(v: c_int) -> Self {
        debug_assert!(
            GUEST_VISIBLE.contains(&v),
            "{v} is not a guest-visible errno; a guest libc would read it as success"
        );
        match Self::from_negative(v) {
            Some(e) => e,
            None => Errno::EIO,
        }
    }

    /// Split a callee's "negative errno, or a value" return into a `Result`.
    ///
    /// **Transitional, and it changes nothing about what a guest sees.** A
    /// converted `sys_*` still calls functions that have not been converted and
    /// report failure the old way; this is the one place that reads that
    /// convention, so a caller does not open-code `if v < 0`.
    ///
    /// It is bit-identical to leaving the number alone: every value in
    /// `[-4095, -1]` comes back out of [`Errno::as_i64`] unchanged, and
    /// everything else is `Ok` of itself. The test below is that property over
    /// the whole range.
    ///
    /// **The range is the test, not membership of the list**, and not `v < 0`.
    /// A syscall may legitimately answer a large negative number — `lseek` past
    /// 2^63, and `fcntl(F_GETOWN)` answering a process group as a *small*
    /// negative one. The second is why `sys_fcntl` writes `Ok` there by hand
    /// rather than calling this: the answer is not an error, even though the
    /// two are the same 64 bits.
    pub fn split(v: i64) -> Result<i64, Self> {
        match c_int::try_from(v).ok().and_then(Self::from_negative) {
            Some(e) => Err(e),
            None => Ok(v),
        }
    }

    /// The name, for a log line or a failing assertion. `None` for a number in
    /// range that this file does not name.
    pub fn name(self) -> Option<&'static str> {
        NAMES.iter().find(|(_, e)| *e == self).map(|(n, _)| *n)
    }
}

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(n) => f.write_str(n),
            None => write!(f, "Errno({})", self.0),
        }
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl From<Errno> for c_int {
    fn from(e: Errno) -> c_int {
        e.as_c_int()
    }
}

impl From<Errno> for i64 {
    fn from(e: Errno) -> i64 {
        e.as_i64()
    }
}

impl From<Errno> for isize {
    fn from(e: Errno) -> isize {
        e.as_isize()
    }
}

/// The list, once.
///
/// Written positive here and negated by the macro, because that is how
/// `asm-generic/errno-base.h` and `asm-generic/errno.h` write them and the
/// point of this table is to be checkable against those two files by reading.
///
/// It is the **whole** of asm-generic rather than the names this tree happens
/// to use, because it is a wire format: a guest asks for the number, not for
/// the ones a syscall here currently answers. Adding one later, name by name,
/// is how a list acquires a gap nobody can explain.
///
/// The three aliases asm-generic defines — `EWOULDBLOCK` for `EAGAIN`,
/// `EDEADLOCK` for `EDEADLK`, `ENOTSUP` for `EOPNOTSUPP` — are deliberately
/// absent: nothing in this tree writes those spellings, and a second name for
/// the same number would make [`Errno::name`] answer whichever came first.
macro_rules! errnos {
    ($($name:ident = $value:literal;)*) => {
        impl Errno {
            $(pub const $name: Errno = Errno(-$value);)*
        }

        const NAMES: &[(&str, Errno)] = &[$((stringify!($name), Errno::$name),)*];

        /// The numbers as `c_int`, which is what most of this tree's own
        /// definitions said. `c_int` is `i32` on every target this builds for,
        /// so an `i32` site imports from here too.
        pub mod c_int_ {
            use std::ffi::c_int;
            $(pub const $name: c_int = super::Errno::$name.as_c_int();)*
        }

        /// The numbers as `i64`, the width the syscall table returns.
        pub mod i64_ {
            $(pub const $name: i64 = super::Errno::$name.as_i64();)*
        }

        /// The numbers as `isize`, for the paths whose success case is a byte
        /// count.
        pub mod isize_ {
            $(pub const $name: isize = super::Errno::$name.as_isize();)*
        }
    };
}

errnos! {
    // asm-generic/errno-base.h
    EPERM = 1; ENOENT = 2; ESRCH = 3; EINTR = 4; EIO = 5;
    ENXIO = 6; E2BIG = 7; ENOEXEC = 8; EBADF = 9; ECHILD = 10;
    EAGAIN = 11; ENOMEM = 12; EACCES = 13; EFAULT = 14; ENOTBLK = 15;
    EBUSY = 16; EEXIST = 17; EXDEV = 18; ENODEV = 19; ENOTDIR = 20;
    EISDIR = 21; EINVAL = 22; ENFILE = 23; EMFILE = 24; ENOTTY = 25;
    ETXTBSY = 26; EFBIG = 27; ENOSPC = 28; ESPIPE = 29; EROFS = 30;
    EMLINK = 31; EPIPE = 32; EDOM = 33; ERANGE = 34;

    // asm-generic/errno.h
    EDEADLK = 35; ENAMETOOLONG = 36; ENOLCK = 37; ENOSYS = 38;
    ENOTEMPTY = 39; ELOOP = 40; ENOMSG = 42; EIDRM = 43; ECHRNG = 44;
    EL2NSYNC = 45; EL3HLT = 46; EL3RST = 47; ELNRNG = 48; EUNATCH = 49;
    ENOCSI = 50; EL2HLT = 51; EBADE = 52; EBADR = 53; EXFULL = 54;
    ENOANO = 55; EBADRQC = 56; EBADSLT = 57; EBFONT = 59; ENOSTR = 60;
    ENODATA = 61; ETIME = 62; ENOSR = 63; ENONET = 64; ENOPKG = 65;
    EREMOTE = 66; ENOLINK = 67; EADV = 68; ESRMNT = 69; ECOMM = 70;
    EPROTO = 71; EMULTIHOP = 72; EDOTDOT = 73; EBADMSG = 74;
    EOVERFLOW = 75; ENOTUNIQ = 76; EBADFD = 77; EREMCHG = 78;
    ELIBACC = 79; ELIBBAD = 80; ELIBSCN = 81; ELIBMAX = 82;
    ELIBEXEC = 83; EILSEQ = 84; ERESTART = 85; ESTRPIPE = 86;
    EUSERS = 87; ENOTSOCK = 88; EDESTADDRREQ = 89; EMSGSIZE = 90;
    EPROTOTYPE = 91; ENOPROTOOPT = 92; EPROTONOSUPPORT = 93;
    ESOCKTNOSUPPORT = 94; EOPNOTSUPP = 95; EPFNOSUPPORT = 96;
    EAFNOSUPPORT = 97; EADDRINUSE = 98; EADDRNOTAVAIL = 99;
    ENETDOWN = 100; ENETUNREACH = 101; ENETRESET = 102;
    ECONNABORTED = 103; ECONNRESET = 104; ENOBUFS = 105; EISCONN = 106;
    ENOTCONN = 107; ESHUTDOWN = 108; ETOOMANYREFS = 109; ETIMEDOUT = 110;
    ECONNREFUSED = 111; EHOSTDOWN = 112; EHOSTUNREACH = 113;
    EALREADY = 114; EINPROGRESS = 115; ESTALE = 116; EUCLEAN = 117;
    ENOTNAM = 118; ENAVAIL = 119; EISNAM = 120; EREMOTEIO = 121;
    EDQUOT = 122; ENOMEDIUM = 123; EMEDIUMTYPE = 124; ECANCELED = 125;
    ENOKEY = 126; EKEYEXPIRED = 127; EKEYREVOKED = 128; EKEYREJECTED = 129;
    EOWNERDEAD = 130; ENOTRECOVERABLE = 131; ERFKILL = 132; EHWPOISON = 133;
    // Linux 7.x: `openat2`'s `OPENAT2_REGULAR` on anything but a regular file.
    EFTYPE = 134;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole file exists for, over every entry rather than a
    /// sample: a number outside this range is not an error a guest can see.
    #[test]
    fn every_errno_is_one_a_guest_libc_reads_as_an_error() {
        for (name, e) in NAMES {
            assert!(
                GUEST_VISIBLE.contains(&e.as_c_int()),
                "{name} is {}, which a guest libc reads as success",
                e.as_c_int()
            );
        }
    }

    /// Two names for one number would make `name()` answer whichever came
    /// first, and would mean a copy-paste slip in the list above is invisible.
    #[test]
    fn no_two_names_share_a_number() {
        let mut seen: Vec<c_int> = NAMES.iter().map(|(_, e)| e.as_c_int()).collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(before, seen.len(), "two entries have the same number");
    }

    /// asm-generic numbers every errno from 1 to 134 except 41 and 58, which
    /// are `EWOULDBLOCK` and `EDEADLOCK` — aliases, so the header gives them no
    /// number of their own. A gap anywhere else is a name left out of the list.
    #[test]
    fn the_list_is_the_whole_of_asm_generic() {
        let mut present: Vec<c_int> = NAMES.iter().map(|(_, e)| -e.as_c_int()).collect();
        present.sort_unstable();
        let expected: Vec<c_int> = (1..=134).filter(|n| *n != 41 && *n != 58).collect();
        assert_eq!(present, expected);
    }

    /// The three views are the one list, not three.
    #[test]
    fn the_integer_views_agree_with_the_type() {
        assert_eq!(c_int_::EINVAL, Errno::EINVAL.as_c_int());
        assert_eq!(i64_::EINVAL, Errno::EINVAL.as_i64());
        assert_eq!(isize_::EINVAL, Errno::EINVAL.as_isize());
        assert_eq!(i64_::EPERM, -1);
        assert_eq!(c_int_::ETIMEDOUT, -110);
        assert_eq!(isize_::EAGAIN, -11);
    }

    #[test]
    fn a_number_outside_the_range_is_not_an_errno() {
        assert_eq!(Errno::from_negative(-22), Some(Errno::EINVAL));
        assert_eq!(Errno::from_negative(0), None);
        assert_eq!(Errno::from_negative(1), None);
        assert_eq!(Errno::from_negative(-4096), None);
        assert_eq!(Errno::from_negative(-4095), Errno::from_negative(-4095));
    }

    /// The one check here whose other side is not this file.
    ///
    /// Every other test above compares the list with itself, and that is the
    /// limit of what a list can check: swapping `ELIBACC` and `ELIBBAD` leaves
    /// the set 1..=133 intact and turns nothing red — measured on 2026-09-11,
    /// with the whole workspace suite green against the swap.
    ///
    /// `libc` is a separate copy of the numbers, maintained by somebody else,
    /// and below 35 the BSDs number the same errnos as Linux — with exactly two
    /// exceptions, which the test below pins. That covers 33 names, including
    /// every one this tree used to write out except `ETIMEDOUT`, `ELOOP`,
    /// `ENAMETOOLONG` and the socket errnos.
    ///
    /// **What is still unchecked here is 35 to 133.** Those are Linux's
    /// numbering and the host has a different one, so nothing on this machine
    /// can confirm them; `tests/integration/differential.sh` is what does, for
    /// the ones a guest test exercises.
    #[test]
    fn the_errnos_below_35_are_the_hosts_too() {
        let same: &[(&str, Errno, c_int)] = &[
            ("EPERM", Errno::EPERM, libc::EPERM),
            ("ENOENT", Errno::ENOENT, libc::ENOENT),
            ("ESRCH", Errno::ESRCH, libc::ESRCH),
            ("EINTR", Errno::EINTR, libc::EINTR),
            ("EIO", Errno::EIO, libc::EIO),
            ("ENXIO", Errno::ENXIO, libc::ENXIO),
            ("E2BIG", Errno::E2BIG, libc::E2BIG),
            ("ENOEXEC", Errno::ENOEXEC, libc::ENOEXEC),
            ("EBADF", Errno::EBADF, libc::EBADF),
            ("ECHILD", Errno::ECHILD, libc::ECHILD),
            ("ENOMEM", Errno::ENOMEM, libc::ENOMEM),
            ("EACCES", Errno::EACCES, libc::EACCES),
            ("EFAULT", Errno::EFAULT, libc::EFAULT),
            ("ENOTBLK", Errno::ENOTBLK, libc::ENOTBLK),
            ("EBUSY", Errno::EBUSY, libc::EBUSY),
            ("EEXIST", Errno::EEXIST, libc::EEXIST),
            ("EXDEV", Errno::EXDEV, libc::EXDEV),
            ("ENODEV", Errno::ENODEV, libc::ENODEV),
            ("ENOTDIR", Errno::ENOTDIR, libc::ENOTDIR),
            ("EISDIR", Errno::EISDIR, libc::EISDIR),
            ("EINVAL", Errno::EINVAL, libc::EINVAL),
            ("ENFILE", Errno::ENFILE, libc::ENFILE),
            ("EMFILE", Errno::EMFILE, libc::EMFILE),
            ("ENOTTY", Errno::ENOTTY, libc::ENOTTY),
            ("ETXTBSY", Errno::ETXTBSY, libc::ETXTBSY),
            ("EFBIG", Errno::EFBIG, libc::EFBIG),
            ("ENOSPC", Errno::ENOSPC, libc::ENOSPC),
            ("ESPIPE", Errno::ESPIPE, libc::ESPIPE),
            ("EROFS", Errno::EROFS, libc::EROFS),
            ("EMLINK", Errno::EMLINK, libc::EMLINK),
            ("EPIPE", Errno::EPIPE, libc::EPIPE),
            ("EDOM", Errno::EDOM, libc::EDOM),
            ("ERANGE", Errno::ERANGE, libc::ERANGE),
        ];
        for (name, ours, host) in same {
            assert_eq!(ours.as_c_int(), -host, "{name}");
        }
        assert_eq!(same.len(), 33, "one of the names was dropped from the list");
    }

    /// The two the host numbers differently, asserted as a *disagreement*.
    ///
    /// Darwin has `EDEADLK` at 11 and `EAGAIN` at 35; Linux has them the other
    /// way round. Writing that down as a check rather than a comment is what
    /// stops somebody "fixing" the list to match the header it was tested
    /// against — which is the whole reason `crates/kernel/errno` exists.
    #[test]
    fn eagain_and_edeadlk_are_where_linux_puts_them_and_not_the_host() {
        assert_eq!(Errno::EAGAIN.as_c_int(), -11);
        assert_eq!(Errno::EDEADLK.as_c_int(), -35);
        assert_eq!(libc::EAGAIN, 35);
        assert_eq!(libc::EDEADLK, 11);
    }

    /// `split` may not change the number a guest sees, for any input.
    ///
    /// This is what makes converting a family to `Result` a re-labelling rather
    /// than a behaviour change: whatever the unconverted callee answered, the
    /// converted caller passes on. The sweep is the whole errno range plus both
    /// sides of it, and a few values no syscall produces.
    #[test]
    fn splitting_a_return_never_changes_it() {
        let mut checked = 0;
        for v in (-5000..=5000).chain([
            i64::MIN,
            i64::MIN + 1,
            i64::MAX,
            c_int::MIN as i64,
            c_int::MIN as i64 - 1,
            0x0000_0000_ffff_ffff,
        ]) {
            let back = match Errno::split(v) {
                Ok(x) => x,
                Err(e) => e.as_i64(),
            };
            assert_eq!(back, v, "split({v})");
            checked += 1;
        }
        assert_eq!(checked, 10_007);
    }

    #[test]
    fn split_calls_an_errno_an_error_and_nothing_else() {
        assert_eq!(Errno::split(-22), Err(Errno::EINVAL));
        assert_eq!(Errno::split(0), Ok(0));
        assert_eq!(Errno::split(7), Ok(7));
        // Below the errno range: a huge negative is a *value*, which is what
        // lseek answers and what a guest libc reads as success.
        assert_eq!(Errno::split(-4096), Ok(-4096));
        assert_eq!(Errno::split(i64::MIN), Ok(i64::MIN));
    }

    #[test]
    fn the_name_is_what_a_log_line_wants() {
        assert_eq!(Errno::EINVAL.name(), Some("EINVAL"));
        assert_eq!(format!("{:?}", Errno::ENOSYS), "ENOSYS");
        assert_eq!(format!("{}", Errno::EPERM), "EPERM");
        assert_eq!(Errno::from_negative(-4000).unwrap().name(), None);
    }
}
