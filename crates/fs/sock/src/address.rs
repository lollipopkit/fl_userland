//! Conversion and bounded writes for guest socket addresses.
//!
//! This module owns the guest `sockaddr_` size policy. Descriptor lookup and
//! host syscalls remain in the parent module.


use sockabi::guest;
use usercopy::GuestMem;

use super::{Errno, put_u32};

/// The guest's `struct sockaddr_`: a 16-bit family and the bytes after it.
///
/// `SOCKADDR_DATA_MAX` is 108 — `sun_path`'s length, the longest of the three
/// families. A buffer this size is what every call fills, **sized by what an
/// address can be rather than by what the guest asked for**: the guest length
/// is not a promise of anything, and as a C VLA it was a guest-chosen stack
/// allocation with no upper bound, so a length of `0xffffffff` was four
/// gigabytes on the thread stack.
pub(super) const SOCKADDR_DATA_MAX: usize = 108;
pub(super) const SOCKADDR_MAX: usize = 2 + SOCKADDR_DATA_MAX;

/// A host address as the guest's `struct sockaddr_`, and the length to report.
///
/// Pure, and separate from the write for one reason: the family is **not** the
/// first two bytes. A `sockaddr` is `{ sa_family_t sa_family; ... }` on Linux
/// and `{ u8 sa_len; u8 sa_family; ... }` on Darwin, so reading a
/// little-endian `u16` gives the family on one host and `sa_len | family << 8`
/// on the other -- 16 for every address here, which is no family at all. It
/// made `getsockname` on an inet socket answer `EINVAL`, so a program that
/// bound to port 0 could not find out which port it got.
///
/// The reported length is the untruncated one, as Linux reports it: a caller
/// whose buffer was too small is told how much there was, and the address is
/// truncated rather than refused.
pub(super) fn host_addr_to_guest(host: &[u8]) -> Result<(Vec<u8>, usize), Errno> {
    let real_family = super::host::family(host).ok_or(Errno::EINVAL)?;
    let family = sockabi::family_from_real(real_family);
    let (body, report): (&[u8], usize) = match family {
        guest::PF_LOCAL => {
            // Most callers use this to return a peer name, and a host unix
            // address carries none that means anything here -- the host path is
            // /tmp/iulsock<pid>.<id>, not what the guest bound. The family and
            // nothing else, which is what Linux reports for an unnamed one.
            //
            // Linux reports offsetof(sun_path) -- 2. This reported
            // sizeof(struct sockaddr_), 16, which claims fourteen bytes of name
            // that are not there, so a caller testing `len > 2` to decide
            // whether there is one was told yes.
            (&[], 2)
        }
        // The payload starts at offset 2 on both hosts: one `sa_family_t`, or
        // `sa_len` and `sa_family`.
        guest::PF_INET | guest::PF_INET6 => (&host[2..], host.len()),
        _ => return Err(Errno::EINVAL),
    };

    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&(family as u16).to_le_bytes());
    out.extend_from_slice(&body[..body.len().min(SOCKADDR_DATA_MAX)]);
    Ok((out, report))
}

/// Writes a *host* address to the guest, translated and truncated.
pub(super) fn write_host_addr(
    addr: u64,
    host: &[u8],
    buffer_len: u32,
) -> Result<u32, Errno> {
    let (bytes, report) = host_addr_to_guest(host)?;
    let copy = (buffer_len as usize).min(report).min(bytes.len());
    if GuestMem.write(addr, &bytes[..copy]) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(report as u32)
}

/// The guest-facing address of one end of a unix socket.
///
/// Returns the bytes and the length to *report*, which is the family plus the
/// whole recorded name — a caller's buffer truncates the copy, not the answer.
pub(super) fn unix_addr(handle: u64, peers: bool) -> (Vec<u8>, u32) {
    let name = unixpeer::with_table(|t| {
        let n = if peers {
            t.peer_name(handle)
        } else {
            t.name(handle)
        };
        n.to_vec()
    });
    let mut out = Vec::with_capacity(2 + name.len());
    out.extend_from_slice(&(guest::PF_LOCAL as u16).to_le_bytes());
    out.extend_from_slice(&name);
    let len = out.len() as u32;
    (out, len)
}

/// Writes a guest-side address and its length back, truncating the copy only.
pub(super) fn put_addr(
    addr: u64,
    len_addr: u64,
    bytes: &[u8],
    report: u32,
    buffer_len: u32,
) -> Result<(), Errno> {
    let copy = (buffer_len as usize).min(bytes.len());
    if GuestMem.write(addr, &bytes[..copy]) != 0 {
        return Err(Errno::EFAULT);
    }
    put_u32(len_addr, report)
}
