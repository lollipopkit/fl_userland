//! Translation between the guest's socket ABI and the host's.
//!
//! The guest is aarch64 Linux; the host is Darwin, or Linux for a development
//! build. Families, socket types, message flags and socket options are numbered
//! differently on the two sides, and a few of the guest's options have no host
//! equivalent at all.
//!
//! This was `static inline` functions in `fs/sock.h`, where nothing could reach
//! them but a build of the whole kernel. Four bugs came out of that table --
//! an i386 `cmsghdr`, `SO_RCVTIMEO` known only at its post-2038 number,
//! `MSG_NOSIGNAL` missing, `MSG_CMSG_CLOEXEC` missing -- and each was a wrong
//! constant that a unit test would have caught in a second. Here they are data,
//! and the tests at the bottom of this file are that second.
//!
//! Everything stateful about a socket stays in `fs/sock.c`. This crate holds no
//! state, takes no locks and touches no descriptors.

use std::ffi::c_int;

pub mod guest;

mod mapping;
pub use mapping::{
    family_from_real, family_to_real, flags_from_real, flags_to_real, level_known, level_to_real,
    opt_to_real, type_flags_ok, type_to_real_for,
};

/// Host constants the `libc` crate does not export for this target.
///
/// Written out rather than taken from a header, which is the duplication this
/// tree normally refuses. The mitigation is that `host_constants_are_real`
/// below asks the running kernel whether each number names an option at all,
/// so a wrong one fails a `cargo test` rather than silently configuring
/// something else.
mod host {
    use std::ffi::c_int;

    /// `netinet/in.h`. Darwin numbers this 8 and Linux numbers it 7, so it is
    /// exactly the sort of constant that cannot be guessed from the guest's.
    pub const IP_RETOPTS: c_int = 8;
}

/// Not a valid option, family or type on the host.
pub const NONE: c_int = -1;

/// What `flags_to_real` made of a guest flag word.
///
/// `unknown` is the bits that mean nothing here, reported separately so the
/// caller can trace *which* bits were dropped. The C this replaced traced the
/// whole word, which named the flags that had been understood as well.
#[repr(C)]
pub struct Flags {
    pub real: c_int,
    pub unknown: c_int,
}

/// How a guest socket option maps.
///
/// The C returned one `int` with two sentinels in it -- negative for "no such
/// option" and zero for "accepted and dropped" -- which relied on no host
/// option ever being numbered zero, and which `sys_getsockopt` got wrong: it
/// handled the negative case and passed the zero straight to the host as an
/// option number.
#[repr(C)]
pub struct OptMap {
    /// One of the `OPT_*` values below.
    pub kind: c_int,
    /// The host option number, meaningful only when `kind` is `OPT_REAL`.
    pub real: c_int,
}

/// No such option at this level: the caller answers `ENOPROTOOPT`.
pub const OPT_UNKNOWN: c_int = 0;
/// Pass `real` to the host.
pub const OPT_REAL: c_int = 1;
/// The host has no equivalent, and the option is advisory: a set is accepted
/// and dropped, and a get answers zero. Refusing instead would fail a program
/// at setup over a hint it is not depending on.
pub const OPT_IGNORE: c_int = 2;
/// The host has no equivalent, and Linux **stores** the value: a set is kept
/// on the socket and a get reads it back, which is what a program that
/// compares the two expects. `real` is the slot, one of `STORE_*`. Measured
/// by `sock_probe`: `SO_PRIORITY`, `TCP_USER_TIMEOUT` and `TCP_DEFER_ACCEPT`
/// read back as set on a real kernel, where `TCP_QUICKACK` is derived.
pub const OPT_STORE: c_int = 3;

/// The stored options' slots in `struct fd`'s `socket.stored_opts`.
pub const STORE_PRIORITY: c_int = 0;
pub const STORE_USER_TIMEOUT: c_int = 1;
pub const STORE_DEFER_ACCEPT: c_int = 2;
/// How many slots there are; the array in `fs/fd.h` is this long.
pub const STORE_SLOTS: usize = 3;

impl OptMap {
    fn unknown() -> Self {
        OptMap {
            kind: OPT_UNKNOWN,
            real: 0,
        }
    }
    fn real(real: c_int) -> Self {
        OptMap {
            kind: OPT_REAL,
            real,
        }
    }
    fn ignore() -> Self {
        OptMap {
            kind: OPT_IGNORE,
            real: 0,
        }
    }
    fn store(slot: c_int) -> Self {
        OptMap {
            kind: OPT_STORE,
            real: slot,
        }
    }
}

// --------------------------------------------------------------- C binding

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::{protocol_ok, type_to_real};

    #[test]
    fn families_round_trip() {
        for f in [guest::PF_LOCAL, guest::PF_INET, guest::PF_INET6] {
            assert_eq!(family_from_real(family_to_real(f)), f, "family {f}");
        }
        // AF_NETLINK, which the guest may ask for and this kernel does not
        // have. It must be refused, not mapped to whatever the host numbers 16.
        assert_eq!(family_to_real(16), NONE);
        assert_eq!(family_to_real(0), NONE);
    }

    #[test]
    fn type_flags_are_not_part_of_the_type() {
        // SOCK_NONBLOCK (0x800) and SOCK_CLOEXEC (0x80000) ride in the type
        // argument and belong to the descriptor. They must not change what
        // kind of socket is created.
        let plain = type_to_real(guest::SOCK_STREAM, 0);
        assert_eq!(type_to_real(guest::SOCK_STREAM | 0x800, 0), plain);
        assert_eq!(type_to_real(guest::SOCK_STREAM | 0x80000, 0), plain);
        assert_eq!(type_to_real(guest::SOCK_STREAM | 0x80800, 0), plain);
    }

    #[test]
    fn type_rejects_a_protocol_the_type_cannot_carry() {
        assert_eq!(type_to_real(guest::SOCK_STREAM, guest::IPPROTO_UDP), NONE);
        assert_eq!(type_to_real(guest::SOCK_DGRAM, guest::IPPROTO_TCP), NONE);
        assert_eq!(
            type_to_real(guest::SOCK_STREAM, guest::IPPROTO_TCP),
            libc::SOCK_STREAM
        );
        assert_eq!(
            type_to_real(guest::SOCK_DGRAM, guest::IPPROTO_UDP),
            libc::SOCK_DGRAM
        );
        assert_eq!(type_to_real(99, 0), NONE);
    }

    #[test]
    fn known_flags_are_never_reported_unknown() {
        // The regression that started this crate: a flag missing from the table
        // is silently dropped, and the only sign is a trace nobody reads.
        for f in [
            guest::MSG_OOB,
            guest::MSG_PEEK,
            guest::MSG_CTRUNC,
            guest::MSG_TRUNC,
            guest::MSG_DONTWAIT,
            guest::MSG_EOR,
            guest::MSG_WAITALL,
            guest::MSG_NOSIGNAL,
            guest::MSG_CMSG_CLOEXEC,
        ] {
            assert_eq!(flags_to_real(f).unknown, 0, "flag {f:#x} reported unknown");
        }
        assert_eq!(flags_to_real(0).unknown, 0);
        // And one that really is unknown still is, or the check above proves
        // nothing.
        assert_eq!(flags_to_real(0x2000).unknown, 0x2000);
    }

    #[test]
    fn nosignal_and_cloexec_do_not_reach_a_darwin_host() {
        // 0x4000 is MSG_RCVMORE on Darwin and 0x40000000 is not a send flag
        // anywhere: passing either through would ask for something else.
        // `sock.c` reads both from the guest word instead.
        let f = flags_to_real(guest::MSG_NOSIGNAL | guest::MSG_CMSG_CLOEXEC);
        assert_eq!(f.unknown, 0);
        assert_eq!(f.real, 0);
    }

    #[test]
    fn flags_round_trip_through_the_host() {
        for f in [
            guest::MSG_OOB,
            guest::MSG_PEEK,
            guest::MSG_CTRUNC,
            guest::MSG_TRUNC,
            guest::MSG_DONTWAIT,
            guest::MSG_EOR,
            guest::MSG_WAITALL,
        ] {
            let there = flags_to_real(f);
            assert_ne!(there.real, 0, "flag {f:#x} maps to nothing");
            assert_eq!(flags_from_real(there.real).real, f, "flag {f:#x}");
        }
    }

    #[test]
    fn both_timeout_numberings_reach_one_option() {
        // musl on aarch64 sends the _OLD numbers. Knowing only the _NEW ones
        // meant no program could set a socket timeout at all.
        for (old, new, want) in [
            (
                guest::SO_RCVTIMEO_OLD,
                guest::SO_RCVTIMEO_NEW,
                libc::SO_RCVTIMEO,
            ),
            (
                guest::SO_SNDTIMEO_OLD,
                guest::SO_SNDTIMEO_NEW,
                libc::SO_SNDTIMEO,
            ),
        ] {
            for opt in [old, new] {
                let m = opt_to_real(opt, guest::SOL_SOCKET);
                assert_eq!(m.kind, OPT_REAL, "option {opt} is not mapped");
                assert_eq!(m.real, want, "option {opt}");
            }
        }
    }

    #[test]
    fn an_unknown_option_is_distinguishable_from_an_ignored_one() {
        // The C packed both into one int, negative and zero, and relied on no
        // host option ever being numbered zero. `sys_getsockopt` then handled
        // the negative case and passed the zero to the host as an option
        // number.
        assert_eq!(opt_to_real(9999, guest::SOL_SOCKET).kind, OPT_UNKNOWN);
        assert_eq!(
            opt_to_real(guest::TCP_QUICKACK, guest::IPPROTO_TCP).kind,
            OPT_IGNORE
        );
        // Stored rather than dropped: Linux reads these back as set, and a
        // program comparing what it set with what it reads would otherwise
        // conclude the option is broken. Each has a slot the array in
        // fs/fd.h is long enough for.
        for (opt, level, slot) in [
            (guest::SO_PRIORITY, guest::SOL_SOCKET, STORE_PRIORITY),
            (
                guest::TCP_USER_TIMEOUT,
                guest::IPPROTO_TCP,
                STORE_USER_TIMEOUT,
            ),
            (
                guest::TCP_DEFER_ACCEPT,
                guest::IPPROTO_TCP,
                STORE_DEFER_ACCEPT,
            ),
        ] {
            let m = opt_to_real(opt, level);
            assert_eq!(m.kind, OPT_STORE, "option {opt}");
            assert_eq!(m.real, slot, "option {opt}");
            assert!(
                (slot as usize) < STORE_SLOTS,
                "slot {slot} has nowhere to go"
            );
        }
        assert_eq!(
            opt_to_real(guest::SO_REUSEADDR, guest::SOL_SOCKET).kind,
            OPT_REAL
        );
    }

    #[test]
    fn an_option_is_only_valid_at_its_own_level() {
        // SO_TYPE is 3 and IP_HDRINCL is 3. Looking one up at the other's level
        // must not find it.
        assert_eq!(
            opt_to_real(guest::SO_TYPE, guest::IPPROTO_IP).real,
            opt_to_real(guest::IP_HDRINCL, guest::IPPROTO_IP).real
        );
        assert_eq!(
            opt_to_real(guest::SO_PEERCRED, guest::IPPROTO_TCP).kind,
            OPT_UNKNOWN
        );
        assert_eq!(opt_to_real(guest::TCP_NODELAY, 12345).kind, OPT_UNKNOWN);
    }

    #[test]
    fn options_sock_c_answers_itself_are_not_claimed_here() {
        // SO_DOMAIN, SO_TYPE, SO_PROTOCOL and SO_PEERCRED are answered from
        // this kernel's own record of the socket, because the host either has
        // no such option or would answer about the host's socket. They must not
        // also appear here, or a future edit could route them to the host.
        for opt in [guest::SO_DOMAIN, guest::SO_PROTOCOL, guest::SO_PEERCRED] {
            assert_eq!(
                opt_to_real(opt, guest::SOL_SOCKET).kind,
                OPT_UNKNOWN,
                "option {opt} is claimed by the table as well"
            );
        }
    }
    // `guest_constants_match_the_c_header` was here until 2026-09-08. It read
    // every `#define NAME_ <number>` out of `fs/sock.h` and compared it with
    // this crate's, because "`fs/sock.c` matches on the guest numbers directly,
    // so a handful of them exist in both places. Two copies of an ABI is how
    // the original went wrong."
    //
    // `fs/sock.c` went on 2026-09-03 and `fs/sock.h` on 2026-09-08, and no
    // other file in the tree names one of these numbers. **There is one copy**,
    // so there is nothing left to compare it with -- which is a better ending
    // than the check, and the same one `docs/checks.md` records for
    // `bindgen_shadowed`.
    //
    // What still asks a question is `host_constants_are_real` below, and it
    // asks the *running kernel* rather than a second rendering.

    #[test]
    fn host_constants_are_real() {
        // host::IP_RETOPTS is a number this crate wrote down instead of
        // reading from a header. Ask the kernel: an option a level does not
        // know answers ENOPROTOOPT.
        let probe = |opt: c_int| -> Option<i32> {
            let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            assert!(s >= 0, "socket");
            let mut buf = [0u8; 64];
            let mut len = buf.len() as libc::socklen_t;
            let r = unsafe {
                libc::getsockopt(s, libc::IPPROTO_IP, opt, buf.as_mut_ptr().cast(), &mut len)
            };
            let e = if r == 0 {
                None
            } else {
                std::io::Error::last_os_error().raw_os_error()
            };
            unsafe { libc::close(s) };
            e
        };
        assert_ne!(
            probe(host::IP_RETOPTS),
            Some(libc::ENOPROTOOPT),
            "IP_RETOPTS = {} does not name an option on this host",
            host::IP_RETOPTS
        );
        // The control: a number that is not an option must answer the thing
        // the check above is looking for the absence of.
        assert_eq!(
            probe(9999),
            Some(libc::ENOPROTOOPT),
            "the probe cannot tell"
        );
    }

    #[test]
    fn protocol_levels_pass_through_unchanged() {
        assert_eq!(level_to_real(guest::SOL_SOCKET), libc::SOL_SOCKET);
        for l in [guest::IPPROTO_IP, guest::IPPROTO_TCP, guest::IPPROTO_IPV6] {
            assert_eq!(level_to_real(l), l, "level {l}");
        }
    }

    // --------------------------------------------- what a real kernel answers

    /// Measured, by running the same probe here and in an arm64 container.
    #[test]
    fn af_unix_takes_protocol_one() {
        // PF_UNIX is 1, and `unix_create` is
        // `if (protocol && protocol != PF_UNIX) return -EPROTONOSUPPORT;`.
        assert!(protocol_ok(guest::PF_LOCAL, 0));
        assert!(protocol_ok(guest::PF_LOCAL, 1));
        assert!(!protocol_ok(guest::PF_LOCAL, 2));
        assert!(!protocol_ok(guest::PF_LOCAL, 6), "not even TCP's number");

        assert_ne!(
            type_to_real_for(guest::PF_LOCAL, guest::SOCK_STREAM, 1),
            NONE,
            "socket(AF_UNIX, SOCK_STREAM, 1) works on Linux and was EINVAL here"
        );
    }

    #[test]
    fn af_unix_takes_sock_raw_as_a_datagram() {
        // Linux: `case SOCK_RAW: sock->type = SOCK_DGRAM; fallthrough;`
        assert_eq!(
            type_to_real_for(guest::PF_LOCAL, guest::SOCK_RAW, 0),
            libc::SOCK_DGRAM
        );
    }

    #[test]
    fn af_unix_takes_every_type_it_has() {
        for ty in [
            guest::SOCK_STREAM,
            guest::SOCK_DGRAM,
            guest::SOCK_SEQPACKET,
            guest::SOCK_RAW,
        ] {
            assert_ne!(type_to_real_for(guest::PF_LOCAL, ty, 0), NONE, "type {ty}");
        }
        assert_eq!(type_to_real_for(guest::PF_LOCAL, 99, 0), NONE);
    }

    /// The flags are checked and the type is not: `SOCK_STREAM | 0x1000000`
    /// was a plain stream socket here and is `EINVAL` on Linux.
    #[test]
    fn only_nonblock_and_cloexec_may_ride_along() {
        assert!(type_flags_ok(guest::SOCK_STREAM));
        assert!(type_flags_ok(guest::SOCK_STREAM | guest::SOCK_NONBLOCK));
        assert!(type_flags_ok(
            guest::SOCK_STREAM | guest::SOCK_NONBLOCK | guest::SOCK_CLOEXEC
        ));
        assert!(!type_flags_ok(guest::SOCK_STREAM | 0x1000000));
        assert!(!type_flags_ok(guest::SOCK_STREAM | 0x100));
        assert!(!type_flags_ok(-1));
    }

    #[test]
    fn the_flag_values_are_the_guests() {
        // Not the host's: Darwin has no SOCK_NONBLOCK at all, and these are
        // what an aarch64 Linux guest passes.
        assert_eq!(guest::SOCK_NONBLOCK, 0o4000);
        assert_eq!(guest::SOCK_CLOEXEC, 0o2000000);
    }

    #[test]
    fn a_level_that_is_not_a_level() {
        assert!(level_known(guest::SOL_SOCKET));
        assert!(level_known(guest::IPPROTO_IP));
        assert!(level_known(guest::IPPROTO_TCP));
        assert!(level_known(guest::IPPROTO_IPV6));
        // Measured: EOPNOTSUPP on a real kernel, where an unknown option of a
        // known level is ENOPROTOOPT. Both were the latter here.
        assert!(!level_known(99));
        assert!(!level_known(-1));
    }
}
