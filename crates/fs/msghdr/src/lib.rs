//! The `msghdr` a guest hands `sendmsg` and `recvmsg`, and the bounds on the
//! three lengths inside it.
//!
//! This is the same split as [`cmsg`](../cmsg) and `crates/fs/dirent`: a wire
//! format is a table of offsets, and it belongs somewhere the offsets can be
//! asserted. Here the format is 56 bytes with seven fields, three of which are
//! lengths the guest chooses — and **every one of those three was wrong**.
//!
//! What `msg_probe` measured against a real arm64 kernel, before this crate:
//!
//! | The guest wrote | Linux | This kernel |
//! | --- | --- | --- |
//! | `msg_iovlen = 0` | sends nothing, returns 0 | `EMSGSIZE` |
//! | `msg_iovlen = 0x1_0000_0001` | `EMSGSIZE` | sent one vector |
//! | `msg_controllen = 0x1_0000_0000` | `ENOBUFS` | sent, with no control data |
//! | `msg_controllen = INT_MAX` | `ENOBUFS` | `EINVAL` |
//! | `msg_control = NULL`, `controllen = 64` | `EFAULT` | sent |
//! | `msg_namelen = 0` with a name | accepted | `EINVAL` |
//! | `msg_namelen = 0xffffffff` on recv | `EINVAL` | accepted |
//! | `vlen = 1025` on `sendmmsg` | clamped to 1024 | `EINVAL` |
//!
//! Two of those are the same mistake: `msg_iovlen` and `msg_controllen` are
//! 64-bit fields, and the C read them into 32-bit locals **before** the
//! comparison that bounds them. `0x1_0000_0001` truncates to 1, which is a
//! count any check would accept, and `0x1_0000_0000` truncates to 0, which
//! reads as "no control data" rather than as a refusal. This is the shape
//! `tools/syscall-abi.py` rule 2 exists to find — a value declared 64 bits wide
//! and cast down before whatever bounds it — and the tool did not see it,
//! because these are struct fields rather than syscall parameters.
//!
//! So every length here stays `u64` until it has been compared, and the type
//! that comes out the other end is the narrow one. A caller cannot get at an
//! unchecked length: [`Checked`] is the only way to read the fields, and
//! [`check`] is the only way to build one.

#![no_std]

// ---------------------------------------------------------------- the layout

/// The guest's `struct msghdr`. `msg_iov` at 16, `msg_control` at 32,
/// `msg_flags` at 48 — asserted by the tests, not by a struct definition.
pub const SIZE: usize = 56;

/// The guest's `struct iovec`: a pointer and a length.
pub const IOVEC_SIZE: usize = 16;

/// The guest's `struct mmsghdr`: a header and the length it reports back.
pub const MMSG_SIZE: usize = 64;

/// Where `msg_len` sits inside an `mmsghdr`.
pub const MMSG_LEN_OFFSET: usize = SIZE;

// ----------------------------------------------------------------- the rules

/// Linux's `UIO_MAXIOV`: the most vectors one call may name.
pub const UIO_MAXIOV: u64 = 1024;

/// `sizeof(struct sockaddr_storage)`. Linux measures `msg_namelen` against
/// this, not against the largest address any family actually uses — a `sockaddr_un`
/// is 110 bytes and this kernel used to refuse anything above it, so a caller
/// passing the ordinary `sizeof(struct sockaddr_storage)` was told `EINVAL`.
pub const SOCKADDR_STORAGE: i64 = 128;

/// The most control bytes a `sendmsg` may name: `____sys_sendmsg` has
/// `if (msg_sys->msg_controllen > INT_MAX) goto out_freeiov;` with `err =
/// -ENOBUFS`. Below it the answer comes from the allocation, which is the
/// caller's — see [`CONTROL_STACK`].
pub const CONTROL_MAX: u64 = i32::MAX as u64;

/// The most control bytes a `sendmsg` will actually be given a buffer for.
///
/// Linux's own bound here is not [`CONTROL_MAX`] but `sock_kmalloc`, which
/// refuses above `net.core.optmem_max` — twenty kilobytes by default. So a
/// large `msg_controllen` is `ENOBUFS` there too, just from an allocation
/// rather than a rule, and the exact threshold is a sysctl rather than
/// something a guest can rely on.
///
/// What matters is that the threshold is far above any real control message —
/// 253 descriptors is about a kilobyte — and that crossing it is `ENOBUFS`.
/// Bounding it at the size of a stack buffer instead was visible:
/// `msg_controllen = 2049` was `ENOBUFS` where Linux allocates and then
/// answers `EINVAL` for the malformed message inside.
pub const CONTROL_ALLOC_MAX: u64 = 64 * 1024;

/// The control buffer a `sendmsg` gets without allocating at all.
pub const CONTROL_STACK: u64 = 2048;

/// The most bytes one call may name across all its vectors.
///
/// Linux has no such cap for `sendmsg` — it hands the user's pages to the
/// protocol. This kernel copies every vector into an allocation of the guest's
/// chosen size, so an uncapped total is 1024 unbounded allocations for one
/// syscall. What differs is only the *errno*: see [`iov_entry`].
pub const IOV_TOTAL_MAX: u64 = i32::MAX as u64;

use guest_errno::c_int_::{EFAULT, EINVAL, EMSGSIZE, ENOBUFS};

/// Which call is reading the header. The two differ in three places, and each
/// difference was measured rather than read from a manual page.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    /// `msg_namelen` above [`SOCKADDR_STORAGE`] is `EINVAL`, `msg_control`
    /// is a buffer to be read, and its length is bounded.
    Send,
    /// `msg_namelen` above [`SOCKADDR_STORAGE`] is *clamped*, and
    /// `msg_controllen` is a capacity rather than a payload — a real kernel
    /// accepts any value for it, including `~0`.
    Recv,
}

/// A header as it was written, with nothing checked. Every length is still the
/// width the guest wrote it at.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Raw {
    pub name: u64,
    /// Signed. Linux reads it as an `int` and refuses a negative one, so
    /// `0xffffffff` is `-1` and not a very large buffer.
    pub namelen: i32,
    pub iov: u64,
    pub iovlen: u64,
    pub control: u64,
    pub controllen: u64,
    pub flags: i32,
}

/// Where each field a `recvmsg` writes back lives in the 56 bytes.
///
/// A receive owns three of them and puts each back at its offset, rather than
/// reading the header again and writing it whole -- which would undo anything
/// the guest changed in between, and would write the four fields it does not
/// own.
pub const NAMELEN_OFFSET: u64 = 8;
pub const CONTROLLEN_OFFSET: u64 = 40;
pub const FLAGS_OFFSET: u64 = 48;

impl Raw {
    /// Decodes the 56 bytes. `None` if there are not that many.
    pub fn decode(b: &[u8]) -> Option<Raw> {
        if b.len() < SIZE {
            return None;
        }
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let i32_at = |o: usize| i32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Some(Raw {
            name: u64_at(0),
            namelen: i32_at(8),
            iov: u64_at(16),
            iovlen: u64_at(24),
            control: u64_at(32),
            controllen: u64_at(40),
            flags: i32_at(48),
        })
    }
}

/// A header whose lengths have been compared against their bounds. The narrow
/// types are the point: nothing here can still be `0x1_0000_0001`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Checked {
    pub name: u64,
    /// Zero when there is no name buffer, whatever the guest wrote — which is
    /// what Linux's `__copy_msghdr` does before anything else looks at it.
    pub namelen: u32,
    pub iov: u64,
    /// At most [`UIO_MAXIOV`]. May be zero: a message with no vectors sends no
    /// bytes and succeeds. That case reached the host here, and Darwin refuses
    /// it — `sendmsg` with `msg_iovlen == 0` is `EMSGSIZE` there — so a guest
    /// doing something legal got an error from a kernel it is not running on.
    pub iovlen: u32,
    pub control: u64,
    pub controllen: u32,
    pub flags: i32,
}

/// Applies every rule to a header. `Err` is a negative guest errno.
pub fn check(raw: &Raw, dir: Direction) -> Result<Checked, i32> {
    // The 64-bit comparison, before anything narrows it.
    if raw.iovlen > UIO_MAXIOV {
        return Err(EMSGSIZE);
    }

    // A negative length is a length the guest wrote as an `int`. Both
    // directions refuse it; only the upper bound differs.
    if raw.namelen < 0 {
        return Err(EINVAL);
    }
    let namelen = if raw.name == 0 {
        // No buffer, so no length -- checked before the upper bound, because a
        // null name with a huge length is legal and this kernel used to walk
        // into the bound and refuse it.
        0
    } else if raw.namelen as i64 > SOCKADDR_STORAGE {
        match dir {
            Direction::Send => return Err(EINVAL),
            // Clamped rather than refused: `__copy_msghdr` does
            // `if (kmsg->msg_namelen > sizeof(struct sockaddr_storage))
            //      kmsg->msg_namelen = sizeof(struct sockaddr_storage);`
            Direction::Recv => SOCKADDR_STORAGE as u32,
        }
    } else {
        raw.namelen as u32
    };

    let controllen = match dir {
        Direction::Send => {
            if raw.controllen > CONTROL_MAX {
                return Err(ENOBUFS);
            }
            if raw.controllen > 0 {
                if raw.control == 0 {
                    // Linux does not look at the pointer; it copies, and the
                    // copy faults. The answer is the same and the reason is
                    // worth writing down, because this kernel treated a null
                    // pointer as "no control data" and sent the message.
                    return Err(EFAULT);
                }
                if raw.controllen > CONTROL_ALLOC_MAX {
                    return Err(ENOBUFS);
                }
            }
            raw.controllen as u32
        }
        // A capacity. A real kernel accepts anything here and reports back how
        // much it wrote, so the only thing to do is not overflow: what the
        // receiver can be told about is bounded by the buffer this kernel
        // builds, not by what the guest claims to have room for.
        Direction::Recv => raw.controllen.min(u32::MAX as u64) as u32,
    };

    Ok(Checked {
        name: raw.name,
        namelen,
        iov: raw.iov,
        iovlen: raw.iovlen as u32,
        control: raw.control,
        controllen,
        flags: raw.flags,
    })
}

/// One vector's length, accumulated into `total`. `Ok(())`, or a negative
/// guest errno.
///
/// The two errnos are not interchangeable, and which one applies is the
/// difference between "you asked for something impossible" and "the memory you
/// named is not there":
///
/// - A length that is negative as a signed 64-bit value is `EINVAL`. Linux's
///   `iovec_from_user` does `if (unlikely(len < 0)) return -EINVAL;` on an
///   `ssize_t`, so `~0` and `0x8000_0000_0000_0000` are refused outright.
/// - A positive length past what this kernel will allocate is `EFAULT`, which
///   is what Linux answers because it goes ahead and the copy fails. A guest
///   with a two-gigabyte buffer would be told `EFAULT` where Linux succeeds;
///   that is the price of copying rather than mapping, and it is a resource
///   limit rather than a rule.
pub fn iov_entry(len: u64, total: &mut u64) -> Result<(), i32> {
    if (len as i64) < 0 {
        return Err(EINVAL);
    }
    if len > IOV_TOTAL_MAX || *total > IOV_TOTAL_MAX - len {
        return Err(EFAULT);
    }
    *total += len;
    Ok(())
}

/// How many messages a `sendmmsg`/`recvmmsg` should actually walk.
///
/// **Clamped, not refused.** `if (vlen > UIO_MAXIOV) vlen = UIO_MAXIOV;` is
/// what Linux does, and this kernel answered `EINVAL` — so a caller passing a
/// count it had not bounded got an error where Linux would have sent the first
/// thousand. Measured: `sendmmsg(vlen = 0xffff_ffff)` sends, `recvmmsg` of an
/// empty socket answers `EAGAIN`.
pub fn mmsg_vlen(vlen: u32) -> u32 {
    if vlen as u64 > UIO_MAXIOV {
        UIO_MAXIOV as u32
    } else {
        vlen
    }
}

/// The `msg_flags` bits `recvmsg` is allowed to report back.
///
/// Everything else the host says is not a report about the message. This
/// kernel passed the host's whole `msg_flags` through, and Darwin echoes the
/// *input* flags there — so a `recvmsg(MSG_DONTWAIT)` came back with
/// `msg_flags == MSG_DONTWAIT`, and a guest testing `msg_flags != 0` for an
/// error found one on every ordinary receive.
///
/// The values are the guest's, which is why they are written out rather than
/// taken from `libc`.
pub const MSG_OOB: i32 = 0x01;
pub const MSG_EOR: i32 = 0x80;
pub const MSG_TRUNC: i32 = 0x20;
pub const MSG_CTRUNC: i32 = 0x08;
pub const MSG_ERRQUEUE: i32 = 0x2000;

/// The mask of the above.
pub const RECV_REPORTED: i32 = MSG_OOB | MSG_EOR | MSG_TRUNC | MSG_CTRUNC | MSG_ERRQUEUE;

/// What to write into the guest's `msg_flags` after a receive.
pub fn recv_flags(from_host: i32) -> i32 {
    from_host & RECV_REPORTED
}

// ------------------------------------------------------------------ the ABI

/// [`Checked`], laid out for C. Padded explicitly so that neither compiler is
/// choosing the offsets.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CheckedAbi {
    pub name: u64,
    pub iov: u64,
    pub control: u64,
    pub namelen: u32,
    pub iovlen: u32,
    pub controllen: u32,
    pub flags: i32,
}

#[cfg(test)]
mod tests;
