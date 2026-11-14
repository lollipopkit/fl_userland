//! SysV shared memory control operations and wire-format encoding.

use super::*;

/// `struct shmid64_ds`, 112 bytes on aarch64.
const SHMID_DS_SIZE: usize = 112;

/// What `IPC_STAT` answers: the guest's `struct shmid_ds`.
///
/// **The wire format, separately from the registry entry.** `encode_shmid_ds`
/// took a `&Segment` until 2026-09-16 and read eight of its thirteen fields —
/// never `fd`, `pages` or `marked` — so the test for the *layout* had to build
/// a registry entry, including a memfd it made up as `fd: 0`. When `fd` became
/// an owning handle there was no zero to write, which is what made the coupling
/// visible: a wire format should not need a live descriptor to be encoded.
///
/// `CLAUDE.md`'s rule for this crate's neighbours — "put a wire format where
/// its offsets can be asserted" — one step further: and nothing else with it.
pub(super) struct ShmidDs {
    pub(super) key: i32,
    pub(super) perm: Perm,
    pub(super) seq: u16,
    pub(super) size: u64,
    pub(super) atime: i64,
    pub(super) dtime: i64,
    pub(super) ctime: i64,
    pub(super) cpid: i32,
    pub(super) lpid: i32,
    pub(super) nattch: u64,
}

impl Segment {
    /// This segment as `IPC_STAT` reports it.
    pub(super) fn shmid_ds(&self, key: i32, seq: u16, nattch: u64) -> ShmidDs {
        ShmidDs {
            key,
            perm: self.perm,
            seq,
            size: self.size,
            atime: self.atime,
            dtime: self.dtime,
            ctime: self.ctime,
            cpid: self.cpid,
            lpid: self.lpid,
            nattch,
        }
    }
}

pub(super) fn encode_shmid_ds(ds: &ShmidDs) -> [u8; SHMID_DS_SIZE] {
    let (key, seq, nattch, seg) = (ds.key, ds.seq, ds.nattch, ds);
    let mut out = [0u8; SHMID_DS_SIZE];
    let mut at = 0usize;
    let mut put = |bytes: &[u8]| {
        out[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };
    // struct ipc64_perm: key, uid, gid, cuid, cgid, mode (u32 on arm64), seq,
    // pad, two unused longs.
    put(&key.to_le_bytes());
    put(&seg.perm.uid.to_le_bytes());
    put(&seg.perm.gid.to_le_bytes());
    put(&seg.perm.cuid.to_le_bytes());
    put(&seg.perm.cgid.to_le_bytes());
    put(&seg.perm.mode.to_le_bytes());
    put(&seq.to_le_bytes());
    put(&0u16.to_le_bytes());
    // Four bytes of alignment before the two unused longs, which is what puts
    // shm_segsz at 48 and not 44 -- the first version had it at 44.
    put(&[0u8; 4]);
    put(&0u64.to_le_bytes());
    put(&0u64.to_le_bytes());
    put(&seg.size.to_le_bytes());
    put(&seg.atime.to_le_bytes());
    put(&seg.dtime.to_le_bytes());
    put(&seg.ctime.to_le_bytes());
    put(&seg.cpid.to_le_bytes());
    put(&seg.lpid.to_le_bytes());
    put(&nattch.to_le_bytes());
    // two unused longs
    out
}

pub(super) fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
}

pub fn sys_shmctl(id: c_int, cmd: c_int, buf_addr: u64) -> Result<c_int, Errno> {
    strace!("shmctl({id}, {cmd}, {buf_addr:#x})");
    let mem = GuestMem::current();
    let me = who_am_i();
    let who = me.who();
    match cmd {
        ipc::INFO => {
            // struct shminfo64: shmmax, shmmin, shmmni, shmseg, shmall, and
            // four unused longs.
            let mut out = [0u8; 72];
            for (i, v) in [
                ipc::SHMMAX,
                ipc::SHMMIN,
                ipc::SHMMNI as u64,
                ipc::SHMMNI as u64,
                ipc::SHMALL,
            ]
            .iter()
            .enumerate()
            {
                out[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
            }
            if mem.write(buf_addr, &out) != 0 {
                return Err(Errno::EFAULT);
            }
            Ok(registry()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .max_index() as c_int)
        }
        ipc::SHM_INFO => {
            // struct shm_info: int used_ids, then five unsigned longs.
            let (used, total, max) = {
                let reg = registry();
                let r = reg.lock().unwrap_or_else(|e| e.into_inner());
                (r.used(), r.total_pages, r.max_index())
            };
            let mut out = [0u8; 48];
            out[..4].copy_from_slice(&(used as i32).to_le_bytes());
            out[8..16].copy_from_slice(&total.to_le_bytes());
            out[16..24].copy_from_slice(&total.to_le_bytes()); // shm_rss
            if mem.write(buf_addr, &out) != 0 {
                return Err(Errno::EFAULT);
            }
            Ok(max as c_int)
        }
        ipc::STAT | ipc::SHM_STAT | ipc::SHM_STAT_ANY => {
            let (bytes, answer) = {
                let reg = registry();
                let r = reg.lock().unwrap_or_else(|e| e.into_inner());
                // IPC_STAT names an id; the SHM_STATs name a slot and answer
                // the id, which is how `ipcs` walks the table.
                let index = if cmd == ipc::STAT {
                    r.lookup(id)
                } else if id >= 0 && r.slots.get(id as usize).is_some_and(|s| s.is_some()) {
                    Some(id as usize)
                } else {
                    None
                };
                let Some(i) = index else {
                    return Err(Errno::EINVAL);
                };
                let seg = r.slots[i].as_ref().expect("found");
                if cmd != ipc::SHM_STAT_ANY && !permitted(&seg.perm, &who, 0o444) {
                    return Err(Errno::EACCES);
                }
                let nattch = memfdcalls::shared_mappings(&seg.fd).unwrap_or(0) as u64;
                let answer = if cmd == ipc::STAT {
                    0
                } else {
                    id_of(i, seg.seq)
                };
                (encode_shmid_ds(&seg.shmid_ds(seg.key, seg.seq, nattch)), answer)
            };
            if mem.write(buf_addr, &bytes) != 0 {
                return Err(Errno::EFAULT);
            }
            Ok(answer)
        }
        ipc::SET => {
            let mut bytes = [0u8; SHMID_DS_SIZE];
            if mem.read(buf_addr, &mut bytes) != 0 {
                return Err(Errno::EFAULT);
            }
            let reg = registry();
            let mut r = reg.lock().unwrap_or_else(|e| e.into_inner());
            let Some(i) = r.lookup(id) else {
                return Err(Errno::EINVAL);
            };
            let seg = r.slots[i].as_mut().expect("looked up");
            if !owner(&seg.perm, &who) {
                return Err(Errno::EPERM);
            }
            seg.perm.uid = u32_at(&bytes, 4);
            seg.perm.gid = u32_at(&bytes, 8);
            seg.perm.mode = (seg.perm.mode & !0o777) | (u32_at(&bytes, 20) & 0o777);
            seg.ctime = now();
            Ok(0)
        }
        ipc::RMID => {
            let gone = {
                let reg = registry();
                let mut r = reg.lock().unwrap_or_else(|e| e.into_inner());
                let Some(i) = r.lookup(id) else {
                    return Err(Errno::EINVAL);
                };
                let seg = r.slots[i].as_mut().expect("looked up");
                if !owner(&seg.perm, &who) {
                    return Err(Errno::EPERM);
                }
                if memfdcalls::shared_mappings(&seg.fd).unwrap_or(0) > 0 {
                    // Still attached: marked, and its key given up, so a new
                    // shmget of the key makes a new segment while this one
                    // lives on for whoever holds it.
                    seg.marked = true;
                    seg.perm.mode |= ipc::SHM_DEST;
                    let key = std::mem::replace(&mut seg.key, ipc::PRIVATE);
                    if key != ipc::PRIVATE {
                        r.by_key.remove(&key);
                    }
                    None
                } else {
                    r.remove(i)
                }
            };
            // Dropped with the registry lock released; see `segment_unmapped`.
            drop(gone);
            Ok(0)
        }
        ipc::SHM_LOCK | ipc::SHM_UNLOCK => {
            let reg = registry();
            let mut r = reg.lock().unwrap_or_else(|e| e.into_inner());
            let Some(i) = r.lookup(id) else {
                return Err(Errno::EINVAL);
            };
            let seg = r.slots[i].as_mut().expect("looked up");
            // `shmctl_do_lock`: the owner or creator, or `CAP_IPC_LOCK`;
            // `CAP_SYS_ADMIN` is not asked here.
            if !who.ipc_lock && who.euid != seg.perm.uid && who.euid != seg.perm.cuid {
                return Err(Errno::EPERM);
            }
            if cmd == ipc::SHM_LOCK {
                seg.perm.mode |= ipc::SHM_LOCKED;
            } else {
                seg.perm.mode &= !ipc::SHM_LOCKED;
            }
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}
