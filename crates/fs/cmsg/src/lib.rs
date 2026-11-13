//! The control-message wire format: `struct cmsghdr` as an aarch64 Linux guest
//! writes and reads it.
//!
//! ```text
//! offset  0   cmsg_len    u64   (__kernel_size_t)
//!         8   cmsg_level  i32
//!        12   cmsg_type   i32
//!        16   payload, then padding to a multiple of 8
//! ```
//!
//! The C this replaces had the i386 layout — a 4-byte length, `cmsg_level` at
//! 4, `cmsg_type` at 8, the payload at 12, and 4-byte alignment. Every field
//! after the first was read from the wrong offset, so `sendmsg` looked at the
//! guest's padding where the level should be, decided the message was not
//! `SOL_SOCKET`, and skipped it. Passing a descriptor over a unix socket
//! reported success and passed nothing; the receiver got `MSG_CTRUNC` and an
//! empty control buffer. `struct flock_` had been wrong the same way.
//!
//! A wire format is exactly what a `static_assert` and a round-trip test are
//! for, and there are both below.

/// Bytes before the payload. Linux's `CMSG_LEN(0)`.
const HDR: usize = 16;
/// `CMSG_ALIGN` rounds to `sizeof(long)`, which is 8 on this ABI. The C used 4.
const ALIGN: usize = 8;

const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;

use guest_errno::c_int_::EINVAL;

const fn align(n: usize) -> usize {
    (n + ALIGN - 1) & !(ALIGN - 1)
}

/// `CMSG_LEN`: the value that goes in `cmsg_len`, unaligned.
const fn cmsg_len(payload: usize) -> usize {
    HDR + payload
}

/// `CMSG_SPACE`: the bytes one message occupies, padding included.
const fn cmsg_space(payload: usize) -> usize {
    align(HDR + payload)
}

#[path = "build.rs"]
mod build;
#[path = "parse.rs"]
mod parse;
pub use build::{build, build_rights};
pub use parse::{parse_rights, rights_capacity};

// ---- the C ABI ----------------------------------------------------------
//
// fs/sock.c keeps everything that is not the format: the descriptor table, the
// reference counting, the peer locks, the SCM queue.

#[cfg(test)]
mod tests {
    use std::ffi::c_int;

    use super::*;

    /// The offsets a guest reads by. These are the numbers the C had wrong.
    #[test]
    fn the_header_is_the_aarch64_one() {
        assert_eq!(HDR, 16, "cmsg_len is 8 bytes on LP64, not 4");
        assert_eq!(ALIGN, 8, "CMSG_ALIGN rounds to sizeof(long)");
        assert_eq!(cmsg_len(0), 16);
        assert_eq!(cmsg_len(4), 20);
        assert_eq!(cmsg_space(4), 24);
        assert_eq!(cmsg_space(0), 16);
    }

    #[test]
    fn one_descriptor_round_trips() {
        let msg = build_rights(&[7]);
        assert_eq!(msg.len(), 24, "CMSG_SPACE(4)");
        assert_eq!(u64::from_le_bytes(msg[0..8].try_into().unwrap()), 20);
        assert_eq!(
            i32::from_le_bytes(msg[8..12].try_into().unwrap()),
            SOL_SOCKET
        );
        assert_eq!(
            i32::from_le_bytes(msg[12..16].try_into().unwrap()),
            SCM_RIGHTS
        );
        assert_eq!(parse_rights(&msg).unwrap(), vec![7]);
    }

    #[test]
    fn several_descriptors_keep_their_order() {
        let msg = build_rights(&[3, 1, 4, 1, 5]);
        assert_eq!(parse_rights(&msg).unwrap(), vec![3, 1, 4, 1, 5]);
    }

    #[test]
    fn no_descriptors_is_a_bare_header() {
        let msg = build_rights(&[]);
        assert_eq!(msg.len(), 16);
        assert_eq!(parse_rights(&msg).unwrap(), Vec::<c_int>::new());
    }

    #[test]
    fn two_messages_in_one_buffer_are_both_read() {
        let mut buf = build_rights(&[1, 2]);
        buf.extend_from_slice(&build_rights(&[3]));
        assert_eq!(parse_rights(&buf).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn another_level_is_skipped() {
        let mut buf = build_rights(&[9]);
        // Rewrite the level to something else: the message is not ours.
        buf[8..12].copy_from_slice(&99i32.to_le_bytes());
        assert_eq!(parse_rights(&buf).unwrap(), Vec::<c_int>::new());
    }

    #[test]
    fn another_socket_level_type_is_refused() {
        let mut buf = build_rights(&[9]);
        buf[12..16].copy_from_slice(&2i32.to_le_bytes()); // SCM_CREDENTIALS
        assert_eq!(parse_rights(&buf), Err(EINVAL));
    }

    /// The guest picks these lengths, so every malformed one has to be an
    /// error and not a walk off the end or a loop that never advances.
    #[test]
    fn a_length_shorter_than_the_header_is_refused() {
        let mut buf = build_rights(&[1]);
        buf[0..8].copy_from_slice(&8u64.to_le_bytes());
        assert_eq!(parse_rights(&buf), Err(EINVAL));
    }

    #[test]
    fn a_length_past_the_end_is_refused() {
        let mut buf = build_rights(&[1]);
        buf[0..8].copy_from_slice(&4096u64.to_le_bytes());
        assert_eq!(parse_rights(&buf), Err(EINVAL));
    }

    #[test]
    fn a_huge_length_does_not_wrap_the_walk() {
        let mut buf = build_rights(&[1]);
        buf[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
        // Refused rather than accepted with a step of zero, which is what the
        // C's 32-bit rounding produced.
        assert_eq!(parse_rights(&buf), Err(EINVAL));
    }

    #[test]
    fn a_trailing_partial_header_is_ignored() {
        let mut buf = build_rights(&[1]);
        buf.extend_from_slice(&[0u8; 7]); // less than a header
        assert_eq!(parse_rights(&buf).unwrap(), vec![1]);
    }

    #[test]
    fn capacity_matches_what_a_message_costs() {
        assert_eq!(rights_capacity(0), 0);
        assert_eq!(rights_capacity(15), 0, "not even a header");
        assert_eq!(
            rights_capacity(16),
            0,
            "a header and no room for a descriptor"
        );
        assert_eq!(rights_capacity(20), 1);
        assert_eq!(rights_capacity(24), 2);
        // Whatever the capacity says fits, must fit.
        for len in 0..64usize {
            let n = rights_capacity(len);
            if n > 0 {
                assert!(
                    cmsg_len(n * 4) <= len,
                    "capacity said {n} fit in {len} bytes, but the message needs {}",
                    cmsg_len(n * 4)
                );
            }
        }
    }
}
