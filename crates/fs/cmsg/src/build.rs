//! Build control messages in the guest's layout.

use std::ffi::c_int;

use super::{HDR, SCM_RIGHTS, SOL_SOCKET, cmsg_len, cmsg_space};

/// One control message, `level`/`ty` carrying `payload`, padded to the space
/// it occupies.
///
/// `cmsg_len` names the meaningful bytes and the buffer is `CMSG_SPACE` long,
/// which is what Linux's `put_cmsg` produces: the caller copies out as much as
/// the receiver had room for and reports that as `msg_controllen`.
pub fn build(level: c_int, ty: c_int, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; cmsg_space(payload.len())];
    out[0..8].copy_from_slice(&(cmsg_len(payload.len()) as u64).to_le_bytes());
    out[8..12].copy_from_slice(&level.to_le_bytes());
    out[12..16].copy_from_slice(&ty.to_le_bytes());
    out[HDR..HDR + payload.len()].copy_from_slice(payload);
    out
}

/// An `SCM_RIGHTS` message carrying `fds`.
pub fn build_rights(fds: &[c_int]) -> Vec<u8> {
    let payload: Vec<u8> = fds.iter().flat_map(|fd| fd.to_le_bytes()).collect();
    build(SOL_SOCKET, SCM_RIGHTS, &payload)
}
