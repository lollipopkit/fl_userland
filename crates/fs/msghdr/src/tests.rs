//! Tests for guest message header layout and validation rules.

use super::*;
use core::mem::size_of;

/// Every expectation below is a line of `msg_probe`'s output from an
/// arm64 container, not a reading of a manual page.
fn send(raw: &Raw) -> Result<Checked, i32> {
    check(raw, Direction::Send)
}
fn recv(raw: &Raw) -> Result<Checked, i32> {
    check(raw, Direction::Recv)
}

fn with_iov(iovlen: u64) -> Raw {
    Raw {
        iov: 0x1000,
        iovlen,
        ..Default::default()
    }
}

// ---------------------------------------------------------- the layout

#[test]
fn the_offsets_are_the_ones_the_guest_writes() {
    assert_eq!(SIZE, 56);
    assert_eq!(IOVEC_SIZE, 16);
    assert_eq!(MMSG_SIZE, 64);
    assert_eq!(MMSG_LEN_OFFSET, 56);
    // Written field by field into the exact bytes, so a decode that reads
    // the wrong offset cannot agree with all seven at once.
    let mut b = [0u8; SIZE];
    b[0..8].copy_from_slice(&0x1111_1111_1111_1111u64.to_le_bytes());
    b[8..12].copy_from_slice(&0x2222_2222u32.to_le_bytes());
    b[16..24].copy_from_slice(&0x3333_3333_3333_3333u64.to_le_bytes());
    b[24..32].copy_from_slice(&0x4444_4444_4444_4444u64.to_le_bytes());
    b[32..40].copy_from_slice(&0x5555_5555_5555_5555u64.to_le_bytes());
    b[40..48].copy_from_slice(&0x6666_6666_6666_6666u64.to_le_bytes());
    b[48..52].copy_from_slice(&0x7777_7777u32.to_le_bytes());
    let r = Raw::decode(&b).unwrap();
    assert_eq!(r.name, 0x1111_1111_1111_1111);
    assert_eq!(r.namelen, 0x2222_2222);
    assert_eq!(r.iov, 0x3333_3333_3333_3333);
    assert_eq!(r.iovlen, 0x4444_4444_4444_4444);
    assert_eq!(r.control, 0x5555_5555_5555_5555);
    assert_eq!(r.controllen, 0x6666_6666_6666_6666);
    assert_eq!(r.flags, 0x7777_7777);
}

#[test]
fn a_short_buffer_is_not_a_header() {
    assert!(Raw::decode(&[0u8; SIZE - 1]).is_none());
    assert!(Raw::decode(&[0u8; SIZE]).is_some());
}

// --------------------------------------------------------- msg_iovlen

#[test]
fn no_vectors_is_a_message_of_no_bytes() {
    // Measured: 0 on Linux, both directions. This kernel answered
    // EMSGSIZE, which came from the *host* -- Darwin refuses iovlen 0.
    assert_eq!(send(&with_iov(0)).unwrap().iovlen, 0);
    assert_eq!(recv(&with_iov(0)).unwrap().iovlen, 0);
}

#[test]
fn the_vector_count_is_bounded_at_uio_maxiov() {
    assert_eq!(send(&with_iov(1024)).unwrap().iovlen, 1024);
    assert_eq!(send(&with_iov(1025)), Err(EMSGSIZE));
}

#[test]
fn the_vector_count_is_compared_before_it_is_narrowed() {
    // The whole point. Each of these has a low half that any check would
    // accept, and the C compared the low half.
    for n in [
        0x1_0000_0001u64,
        0x1_0000_0000,
        0xffff_ffff_0000_0001,
        u64::MAX,
    ] {
        assert_eq!(send(&with_iov(n)), Err(EMSGSIZE), "iovlen {n:#x}");
        assert_eq!(recv(&with_iov(n)), Err(EMSGSIZE), "iovlen {n:#x}");
    }
}

// -------------------------------------------------------- msg_namelen

#[test]
fn a_null_name_has_no_length_whatever_the_guest_wrote() {
    for n in [0i32, 16, 128, 129, i32::MAX] {
        let raw = Raw {
            name: 0,
            namelen: n,
            ..with_iov(1)
        };
        assert_eq!(send(&raw).unwrap().namelen, 0, "namelen {n}");
        assert_eq!(recv(&raw).unwrap().namelen, 0, "namelen {n}");
    }
}

#[test]
fn a_negative_name_length_is_refused() {
    // 0xffffffff written into an int. Measured: EINVAL on recv, where
    // this kernel read it as unsigned, clamped, and accepted it -- and
    // where the answer it gave depended on uninitialised stack.
    let raw = Raw {
        name: 0x1000,
        namelen: -1,
        ..with_iov(1)
    };
    assert_eq!(send(&raw), Err(EINVAL));
    assert_eq!(recv(&raw), Err(EINVAL));
}

#[test]
fn zero_is_a_legal_name_length() {
    // Measured: `sendmsg(name=set, namelen=0)` sends. This kernel refused
    // it, because the address reader would not take a zero-length one.
    let raw = Raw {
        name: 0x1000,
        namelen: 0,
        ..with_iov(1)
    };
    assert_eq!(send(&raw).unwrap().namelen, 0);
    assert_eq!(recv(&raw).unwrap().namelen, 0);
}

#[test]
fn a_name_length_of_sockaddr_storage_fits() {
    // 128, not 110. A caller passing sizeof(struct sockaddr_storage) --
    // which is what every portable program passes -- was told EINVAL.
    let raw = Raw {
        name: 0x1000,
        namelen: 128,
        ..with_iov(1)
    };
    assert_eq!(send(&raw).unwrap().namelen, 128);
    assert_eq!(recv(&raw).unwrap().namelen, 128);
}

#[test]
fn past_sockaddr_storage_the_two_directions_differ() {
    let raw = Raw {
        name: 0x1000,
        namelen: 129,
        ..with_iov(1)
    };
    assert_eq!(send(&raw), Err(EINVAL));
    assert_eq!(recv(&raw).unwrap().namelen, 128, "clamped, not refused");
}

// ----------------------------------------------------- msg_controllen

#[test]
fn control_data_is_bounded_before_it_is_narrowed() {
    // Truncates to zero in 32 bits, which read as "no control data" and
    // sent the message. Measured: ENOBUFS.
    let raw = Raw {
        control: 0x1000,
        controllen: 0x1_0000_0000,
        ..with_iov(1)
    };
    assert_eq!(send(&raw), Err(ENOBUFS));
    let raw = Raw {
        control: 0x1000,
        controllen: u64::MAX,
        ..with_iov(1)
    };
    assert_eq!(send(&raw), Err(ENOBUFS));
}

#[test]
fn a_large_control_length_is_enobufs_not_einval() {
    // Above INT_MAX, which is where Linux refuses outright.
    for n in [0x8000_0000u64, 0x1_0000_0000, u64::MAX] {
        let raw = Raw {
            control: 0x1000,
            controllen: n,
            ..with_iov(1)
        };
        assert_eq!(send(&raw), Err(ENOBUFS), "controllen {n:#x}");
    }
    // ...and below INT_MAX but above what will be allocated, which is
    // where Linux's own sock_kmalloc gives up.
    for n in [CONTROL_ALLOC_MAX + 1, 0x7fff_ffff] {
        let raw = Raw {
            control: 0x1000,
            controllen: n,
            ..with_iov(1)
        };
        assert_eq!(send(&raw), Err(ENOBUFS), "controllen {n:#x}");
    }
    // A length past the stack buffer but inside the allocation is not an
    // error at all: `controllen = 2049` is EINVAL on Linux, from the
    // malformed message inside it, and was ENOBUFS here from a buffer the
    // guest has no way to know about. These also check that a length which
    // fits in 32 bits survives the narrowing intact.
    for n in [CONTROL_STACK, CONTROL_STACK + 1, CONTROL_ALLOC_MAX] {
        let raw = Raw {
            control: 0x1000,
            controllen: n,
            ..with_iov(1)
        };
        assert_eq!(
            send(&raw).unwrap().controllen,
            n as u32,
            "controllen {n:#x}"
        );
    }
}

#[test]
fn control_data_with_no_buffer_is_a_fault() {
    let raw = Raw {
        control: 0,
        controllen: 64,
        ..with_iov(1)
    };
    assert_eq!(send(&raw), Err(EFAULT));
    // ...but a length of zero with no buffer is just no control data.
    let raw = Raw {
        control: 0,
        controllen: 0,
        ..with_iov(1)
    };
    assert_eq!(send(&raw).unwrap().controllen, 0);
}

#[test]
fn on_a_receive_the_control_length_is_only_a_capacity() {
    // Measured: a real kernel accepts every one of these on recvmsg,
    // including ~0, and reports back what it actually wrote.
    for n in [2049u64, 0x7fff_ffff, 0x1_0000_0000, u64::MAX] {
        let raw = Raw {
            control: 0x1000,
            controllen: n,
            ..with_iov(1)
        };
        assert!(recv(&raw).is_ok(), "controllen {n:#x}");
    }
}

// ------------------------------------------------------------- iovecs

#[test]
fn a_negative_vector_length_is_einval() {
    let mut total = 0;
    assert_eq!(iov_entry(u64::MAX, &mut total), Err(EINVAL));
    assert_eq!(iov_entry(0x8000_0000_0000_0000, &mut total), Err(EINVAL));
    assert_eq!(total, 0, "nothing accumulates from a refused entry");
}

#[test]
fn a_vector_too_large_to_copy_is_a_fault() {
    // Measured: EFAULT on Linux, because it goes ahead and the copy
    // fails. This kernel said EINVAL.
    let mut total = 0;
    assert_eq!(iov_entry(0x7fff_ffff_ffff_ffff, &mut total), Err(EFAULT));
    let mut total = 0;
    assert_eq!(iov_entry(IOV_TOTAL_MAX + 1, &mut total), Err(EFAULT));
}

#[test]
fn the_total_is_what_is_bounded_not_each_entry() {
    let mut total = 0;
    assert_eq!(iov_entry(IOV_TOTAL_MAX, &mut total), Ok(()));
    assert_eq!(total, IOV_TOTAL_MAX);
    assert_eq!(iov_entry(1, &mut total), Err(EFAULT));
    assert_eq!(total, IOV_TOTAL_MAX, "a refused entry leaves the sum alone");
}

#[test]
fn the_sum_itself_cannot_overflow() {
    // The subtraction is on the cap, which is a constant, rather than on
    // the operands -- so two lengths that would wrap cannot both pass.
    let mut total = 0;
    assert_eq!(iov_entry(IOV_TOTAL_MAX - 1, &mut total), Ok(()));
    assert_eq!(iov_entry(IOV_TOTAL_MAX - 1, &mut total), Err(EFAULT));
}

// -------------------------------------------------------------- mmsg

#[test]
fn an_over_large_message_count_is_clamped() {
    assert_eq!(mmsg_vlen(0), 0);
    assert_eq!(mmsg_vlen(1), 1);
    assert_eq!(mmsg_vlen(1024), 1024);
    assert_eq!(mmsg_vlen(1025), 1024);
    assert_eq!(mmsg_vlen(u32::MAX), 1024);
}

// ---------------------------------------------------------- msg_flags

#[test]
fn only_the_reporting_flags_come_back() {
    assert_eq!(recv_flags(MSG_TRUNC), MSG_TRUNC);
    assert_eq!(recv_flags(MSG_CTRUNC | MSG_TRUNC), MSG_CTRUNC | MSG_TRUNC);
    // 0x40 is MSG_DONTWAIT, which is what Darwin echoed back and what a
    // guest then read as "something happened to this message".
    assert_eq!(recv_flags(0x40), 0);
    assert_eq!(recv_flags(0x40 | MSG_TRUNC), MSG_TRUNC);
    assert_eq!(recv_flags(-1), RECV_REPORTED);
    assert_eq!(recv_flags(0), 0);
}

// ----------------------------------------------------------- the ABI

#[test]
fn the_abi_struct_is_the_size_its_fields_are() {
    assert_eq!(size_of::<CheckedAbi>(), 8 * 3 + 4 * 4);
}
