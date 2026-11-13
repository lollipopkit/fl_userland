//! System V semaphore control structure encoders.

use super::{SetState, plan};

/// `struct semid_ds`: `ipc_perm` followed by two times and the count.
pub(super) const SEMID_DS_LEN: usize = 88;

/// Encode the bytes returned by `IPC_STAT` and `SEM_STAT`.
pub(super) fn semid_ds(s: &SetState) -> [u8; SEMID_DS_LEN] {
    let mut buf = [0u8; SEMID_DS_LEN];
    sysvipc::write_perm(&mut buf, &s.perm);
    buf[48..56].copy_from_slice(&s.otime.to_le_bytes());
    buf[56..64].copy_from_slice(&s.ctime.to_le_bytes());
    buf[64..72].copy_from_slice(&(s.sems.len() as u64).to_le_bytes());
    buf
}

/// `struct seminfo`: ten 32-bit integers.
pub(super) fn seminfo(used_sets: usize, used_sems: usize, counts: bool) -> [u8; 40] {
    let mut b = [0u8; 40];
    let fields = [
        0i32,
        plan::SEMMNI as i32,
        1_024_000_000,
        32_000,
        plan::SEMMSL,
        plan::SEMOPM as i32,
        32_000,
        if counts { used_sets as i32 } else { 20 },
        plan::SEMVMX,
        if counts { used_sems as i32 } else { 32_767 },
    ];
    for (i, v) in fields.iter().enumerate() {
        b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    b
}
