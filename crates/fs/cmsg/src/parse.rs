//! Parse `SCM_RIGHTS` control messages.

use std::ffi::c_int;

use super::{EINVAL, HDR, SCM_RIGHTS, SOL_SOCKET, align};

/// How many descriptors a receiver with `controllen` bytes has room for.
///
/// Linux works this out before installing anything, so that a descriptor the
/// receiver will never be told the number of is not installed in its table at
/// all. The C installed every descriptor and then truncated the buffer, which
/// left the guest holding descriptors it had no way to name or close.
pub fn rights_capacity(controllen: usize) -> usize {
    controllen.saturating_sub(HDR) / 4
}

/// The descriptors named by the `SCM_RIGHTS` messages in a control buffer.
///
/// A message for another level is skipped, as Linux does. A `SOL_SOCKET`
/// message of another type is `EINVAL`: this implements `SCM_RIGHTS` and
/// nothing else, and a guest asking for `SCM_CREDENTIALS` should be told so
/// rather than have it ignored.
pub fn parse_rights(buf: &[u8]) -> Result<Vec<c_int>, c_int> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + HDR <= buf.len() {
        let len = u64::from_le_bytes(buf[at..at + 8].try_into().unwrap()) as usize;
        let level = i32::from_le_bytes(buf[at + 8..at + 12].try_into().unwrap());
        let kind = i32::from_le_bytes(buf[at + 12..at + 16].try_into().unwrap());

        // A length that does not cover its own header, or runs off the end of
        // the buffer, is a message the guest built wrong.
        if len < HDR || len > buf.len() - at {
            return Err(EINVAL);
        }
        if level == SOL_SOCKET {
            if kind != SCM_RIGHTS {
                return Err(EINVAL);
            }
            let payload = &buf[at + HDR..at + len];
            for &fd in payload.as_chunks::<4>().0 {
                out.push(i32::from_le_bytes(fd));
            }
        }

        // Every step has to move, or a guest can spin the walk forever with a
        // crafted length. align() of a value that is at least HDR is at least
        // HDR, so this is always positive -- unlike the C, where rounding a
        // 32-bit length up in 32 bits wrapped to zero near UINT32_MAX.
        let step = align(len);
        debug_assert!(step > 0);
        at += step;
    }
    Ok(out)
}
