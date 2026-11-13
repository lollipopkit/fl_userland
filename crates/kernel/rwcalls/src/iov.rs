//! Guest iovec parsing and scatter/gather operations.

use std::os::raw::c_uint;

use usercopy::GuestMem;

use guest_errno::Errno;

use crate::bounce;

/// One entry of a guest `iovec` array: where and how much.
#[derive(Clone, Copy)]
pub(crate) struct Vector {
    pub(crate) base: u64,
    pub(crate) len: usize,
}

// ---------------------------------------------------------------------------
// The vectored forms
// ---------------------------------------------------------------------------

/// Reads the guest's iovec array and the number of bytes it names.
///
/// Both bounds matter and neither used to be here:
///
/// - the count arrives as an unsigned 32-bit word, so `writev(fd, v, -1)` asked
///   for `0xffffffff` vectors, and the 68-gigabyte allocation that followed
///   failed with `EFAULT` instead of the `EINVAL` Linux answers;
/// - `iov_len` is 64 bits on this ABI and was assigned into a `uint_t`, so a
///   length of `0x1_0000_0000` became a length of zero and the call moved no
///   data while reporting success.
///
/// The per-entry length is **clamped, not refused**. Linux shortens a vector
/// that would push the total past `MAX_RW_COUNT` and carries on, so the errno
/// for an over-large length comes from the copy that follows — `EFAULT`,
/// because a buffer that big is not mapped — and not from a rule here. This
/// answered `EINVAL`, for both a single huge vector and a total that added up
/// to one.
pub(crate) fn read_iovec(addr: u64, count: c_uint) -> Result<(Vec<Vector>, usize), Errno> {
    if count > rwabi::UIO_MAXIOV {
        return Err(Errno::EINVAL);
    }
    let count = count as usize;
    let mut raw = bounce(count * 16)?;
    if count > 0 && GuestMem.read(addr, &mut raw) != 0 {
        return Err(Errno::EFAULT);
    }
    let mut out = Vec::with_capacity(count);
    let mut total = 0u64;
    for i in 0..count {
        let at = i * 16;
        let base = u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
        let len = u64::from_le_bytes(raw[at + 8..at + 16].try_into().unwrap());
        let use_ = rwabi::iov_entry(len, &mut total).map_err(Errno::from_negative_or_eio)?;
        out.push(Vector {
            base,
            len: use_ as usize,
        });
    }
    Ok((out, total as usize))
}

/// Scatters the first `count` bytes of `buf` across the vectors, which is as
/// many as the read actually returned.
///
/// Writing each vector's full length instead — which is what this used to do —
/// hands the guest whatever was in the rest of the bounce buffer, and overwrites
/// bytes past the return value that belong to the caller. A three-byte read into
/// three 64-byte vectors destroyed 192.
pub(crate) fn scatter(vectors: &[Vector], buf: &[u8], count: usize) -> Result<(), Errno> {
    let mut at = 0usize;
    for v in vectors {
        if at >= count {
            break;
        }
        let chunk = (count - at).min(v.len);
        if GuestMem.write(v.base, &buf[at..at + chunk]) != 0 {
            return Err(Errno::EFAULT);
        }
        at += chunk;
    }
    Ok(())
}

/// Fills `buf` from the start of the vectors and stops at the first page that
/// cannot be read, answering how many bytes it placed.
///
/// [`gather`] refuses the whole call for one bad vector, which is `writev`'s
/// rule; `vmsplice` pins the user pages one at a time and moves what it pinned,
/// so a good vector followed by an unmapped one is a short count there
/// (`rarecalls_probe`).
pub(crate) fn gather_prefix(vectors: &[Vector], buf: &mut [u8]) -> usize {
    const PAGE: u64 = 4096;
    let mut got = 0usize;
    for v in vectors {
        let mut at = v.base;
        let mut left = v.len.min(buf.len() - got);
        while left > 0 {
            let chunk = left.min((PAGE - at % PAGE) as usize);
            if GuestMem.read(at, &mut buf[got..got + chunk]) != 0 {
                return got;
            }
            got += chunk;
            at += chunk as u64;
            left -= chunk;
        }
        if got == buf.len() {
            break;
        }
    }
    got
}

/// Fills `buf` with up to `buf.len()` bytes of the vectors, starting `skip`
/// bytes into the logical stream they make up.
///
/// The window is what lets a total larger than the bounce buffer be *chunked*
/// rather than refused. It used to gather the whole array in one go, so a
/// `writev` whose vectors summed past the cap answered `EINVAL` — and that is
/// not an edge case, it is any program writing a sixteen-megabyte buffer.
pub(crate) fn gather(
    vectors: &[Vector],
    buf: &mut [u8],
    mut skip: usize,
) -> Result<(), Errno> {
    let max = buf.len();
    let mut got = 0usize;
    for v in vectors {
        if got >= max {
            break;
        }
        if skip >= v.len {
            skip -= v.len;
            continue;
        }
        let chunk = (v.len - skip).min(max - got);
        if GuestMem.read(v.base + skip as u64, &mut buf[got..got + chunk]) != 0 {
            return Err(Errno::EFAULT);
        }
        skip = 0;
        got += chunk;
    }
    Ok(())
}
