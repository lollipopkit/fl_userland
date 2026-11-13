//! System V shared memory: `shmget`, `shmat`, `shmdt`, `shmctl`.
//!
//! All four were `syscall_stub`. PostgreSQL creates one segment on every start
//! -- a few dozen bytes, whatever `shared_memory_type` says, because the
//! segment is the postmaster's interlock: `shmctl(IPC_STAT)` on the id a stale
//! `postmaster.pid` names, and `shm_nattch` says whether anyone still runs
//! there. Without `shmget` it does not start.
//!
//! # A segment is a memfd
//!
//! `crates/kernel/memfdcalls` makes anonymous shared files -- a host file with
//! no name, one set of pages for every guest process -- and that is what a
//! segment is. The registry here holds one descriptor per segment; `shmat` is
//! a shared mapping of it through `crates/kernel/mmapcalls`, and `nattch` is
//! the count of those mappings the memfd already keeps for its seals. When the
//! page table drops the last page of one, the memfd tells this crate, which is
//! how a segment that `IPC_RMID` marked while attached is destroyed once the
//! last process detaches or exits -- Linux's `SHM_DEST`.
//!
//! One thing that count is not: Linux's `nattch` is per attach and per
//! process, so a `fork` doubles it, where a forked child here shares the
//! parent's mapping record and it stays at one until both have detached. It
//! reaches zero at the same moment either way, which is what `SHM_DEST` and a
//! stale-segment check care about.
//!
//! # Locks
//!
//! The registry's mutex is never held across a call into the page table: the
//! detach notification arrives *from* the page table with its lock held and
//! takes the registry's, so the other order would be an inversion. `shmat`
//! looks the segment up, takes a reference on its file, lets go, and maps.
//!
//! # What is not here
//!
//! `SHM_HUGETLB` (`EINVAL`, as a kernel without huge pages), `SHM_LOCK`'s
//! effect (the bit is kept; nothing is pinned), and per-user limits.


use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::Mutex;

use strace::strace;
use usercopy::GuestMem;

pub(crate) use guest_errno::Errno;

/// The `IPC_*` and `SHM_*` numbers, from `include/uapi/linux/ipc.h` and
/// `shm.h`.
mod rules;
pub use rules::{attach, index_of, owner, permitted};
use rules::{existing_ok, id_of, size_ok};

#[path = "registry.rs"]
mod registry;
use registry::{REGISTRY, Segment, now, segment_unmapped, tgid, who_am_i};

#[path = "control.rs"]
mod control;
pub use control::sys_shmctl;

pub mod ipc {
    pub const PRIVATE: i32 = 0;
    pub const CREAT: i32 = 0o1000;
    pub const EXCL: i32 = 0o2000;
    pub const RMID: i32 = 0;
    pub const SET: i32 = 1;
    pub const STAT: i32 = 2;
    pub const INFO: i32 = 3;
    pub const SHM_LOCK: i32 = 11;
    pub const SHM_UNLOCK: i32 = 12;
    pub const SHM_STAT: i32 = 13;
    pub const SHM_INFO: i32 = 14;
    pub const SHM_STAT_ANY: i32 = 15;

    pub const SHM_RDONLY: i32 = 0o10000;
    pub const SHM_RND: i32 = 0o20000;
    pub const SHM_REMAP: i32 = 0o40000;
    pub const SHM_EXEC: i32 = 0o100000;
    pub const SHM_HUGETLB: i32 = 0o4000;

    /// Mode bits Linux keeps beside the permissions: marked for destruction,
    /// and locked.
    pub const SHM_DEST: u32 = 0o1000;
    pub const SHM_LOCKED: u32 = 0o2000;

    /// The limits: `SHMMNI` segments, at least `SHMMIN` bytes each, at most
    /// `SHMMAX`, `SHMALL` pages in all. The last two are Linux's defaults,
    /// which are "no limit" spelled as a number.
    pub const SHMMNI: usize = 4096;
    pub const SHMMIN: u64 = 1;
    pub const SHMMAX: u64 = u64::MAX - (1 << 24);
    pub const SHMALL: u64 = u64::MAX - (1 << 24);

    /// `SEQ_MULTIPLIER`: an id is `seq * 32768 + index`, so an index reused
    /// for a new segment gets a new id and an old id names nothing.
    pub const SEQ_MULTIPLIER: i32 = 32768;
    /// `IPCMNI_SEQ_MAX`: the sequence wraps here.
    pub const SEQ_MAX: u16 = 0x7fff;
}

const PAGE_SIZE: u64 = 4096;

/// The owner and mode of a segment: `struct ipc64_perm`, less the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Perm {
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    /// Nine permission bits, plus `SHM_DEST` and `SHM_LOCKED`.
    pub mode: u32,
}

/// Who is asking, for [`permitted`] and [`owner`].
#[derive(Clone, Copy, Debug)]
pub struct Who<'a> {
    pub euid: u32,
    pub egid: u32,
    pub groups: &'a [u32],
    /// `CAP_IPC_OWNER`, which passes [`permitted`].
    pub ipc_owner: bool,
    /// `CAP_SYS_ADMIN`, which passes [`owner`].
    pub sys_admin: bool,
    /// `CAP_IPC_LOCK`, which passes `SHM_LOCK`'s ownership test.
    pub ipc_lock: bool,
}

// ------------------------------------------------------------ the registry

// ------------------------------------------------------------ the syscalls

pub fn sys_shmget(key: c_int, size: u64, flags: c_int) -> Result<c_int, Errno> {
    strace!("shmget({key}, {size}, {flags:#o})");
    if flags & ipc::SHM_HUGETLB != 0 {
        return Err(Errno::EINVAL);
    }
    let mode = (flags & 0o777) as u32;
    let me = who_am_i();
    let who = me.who();
    let mut r = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());

    if key != ipc::PRIVATE {
        if let Some(&i) = r.by_key.get(&key) {
            let seg = r.slots[i].as_ref().expect("a keyed slot is filled");
            existing_ok(flags, seg.size, size)?;
            if !permitted(&seg.perm, &who, mode) {
                return Err(Errno::EACCES);
            }
            return Ok(id_of(i, seg.seq));
        }
        if flags & ipc::CREAT == 0 {
            return Err(Errno::ENOENT);
        }
    }

    let pages = size_ok(size, r.total_pages)?;
    let index = match r.slots.iter().position(|s| s.is_none()) {
        Some(i) => i,
        None if r.slots.len() < ipc::SHMMNI => {
            r.slots.push(None);
            r.slots.len() - 1
        }
        None => return Err(Errno::ENOSPC),
    };
    // The registry's one reference. A `*mut ffi::fd` stored as a `usize`
    // until 2026-09-16.
    let fd = memfdcalls::create_internal(&file_name(key), size, mode, Some(segment_unmapped))
        .map_err(|_| Errno::ENOMEM)?;
    let seq = r.seq;
    r.seq = if seq >= ipc::SEQ_MAX { 0 } else { seq + 1 };
    let t = now();
    r.slots[index] = Some(Segment {
        key,
        perm: Perm {
            uid: who.euid,
            gid: who.egid,
            cuid: who.euid,
            cgid: who.egid,
            mode,
        },
        seq,
        size,
        pages,
        fd,
        cpid: tgid(),
        lpid: 0,
        atime: 0,
        dtime: 0,
        ctime: t,
        marked: false,
    });
    if key != ipc::PRIVATE {
        r.by_key.insert(key, index);
    }
    r.total_pages += pages;
    Ok(id_of(index, seq))
}

/// The name of the file behind a segment, as `/proc/<pid>/maps` shows it
/// before ` (deleted)`: `newseg`'s `sprintf(name, "SYSV%08x", key)`, the key
/// as unsigned hex, `IPC_PRIVATE` included. It does not change when
/// `IPC_RMID` frees the key (`shm_probe`).
///
/// Was `/memfd:SYSV` for every segment until 2026-11-11, which no Linux prints
/// and which told a reader of `maps` neither that it was System V memory nor
/// which segment.
fn file_name(key: c_int) -> Vec<u8> {
    format!("/SYSV{:08x}", key as u32).into_bytes()
}

mod attach;
pub use attach::{sys_shmat, sys_shmdt};

#[cfg(test)]
mod tests {
    use super::*;

    /// The three lines `shm_probe` records from a real kernel.
    #[test]
    fn a_segment_file_is_named_by_its_key() {
        assert_eq!(file_name(0x5348_0001), b"/SYSV53480001");
        assert_eq!(file_name(ipc::PRIVATE), b"/SYSV00000000");
        assert_eq!(file_name(0x8765_4321u32 as c_int), b"/SYSV87654321");
    }

    const ROOT: Who<'static> = Who {
        euid: 0,
        egid: 0,
        groups: &[],
        ipc_owner: true,
        sys_admin: true,
        ipc_lock: true,
    };
    const ALICE: Who<'static> = Who {
        euid: 1000,
        egid: 1000,
        groups: &[1000, 2000],
        ipc_owner: false,
        sys_admin: false,
        ipc_lock: false,
    };
    const BOB: Who<'static> = Who {
        euid: 1001,
        egid: 1001,
        groups: &[1001],
        ipc_owner: false,
        sys_admin: false,
        ipc_lock: false,
    };

    fn perm(uid: u32, gid: u32, mode: u32) -> Perm {
        Perm {
            uid,
            gid,
            cuid: uid,
            cgid: gid,
            mode,
        }
    }

    #[test]
    fn permission_is_judged_by_the_class_the_caller_falls_in() {
        let p = perm(1000, 1000, 0o640);
        assert!(
            permitted(&p, &ALICE, 0o444 | 0o222),
            "the owner may read and write"
        );
        assert!(!permitted(&p, &BOB, 0o444), "a stranger may not read");
        let member = Who {
            euid: 1001,
            egid: 1001,
            groups: &[1000],
            ipc_owner: false,
            sys_admin: false,
            ipc_lock: false,
        };
        assert!(permitted(&p, &member, 0o444), "a group member may read");
        assert!(!permitted(&p, &member, 0o222), "and not write");
        assert!(
            permitted(&p, &ROOT, 0o444 | 0o222 | 0o111),
            "root may anything"
        );
        assert!(
            permitted(&perm(1000, 1000, 0o004), &BOB, 0o444),
            "the other bits are everyone's"
        );
    }

    #[test]
    fn the_creator_keeps_owner_class_after_a_chown() {
        let p = Perm {
            uid: 1001,
            gid: 1001,
            cuid: 1000,
            cgid: 1000,
            mode: 0o600,
        };
        assert!(permitted(&p, &ALICE, 0o444), "the creator");
        assert!(permitted(&p, &BOB, 0o444), "and the owner");
        assert!(owner(&p, &ALICE));
        assert!(owner(&p, &BOB));
        assert!(!owner(
            &p,
            &Who {
                euid: 5,
                egid: 5,
                groups: &[],
                ipc_owner: false,
                sys_admin: false,
                ipc_lock: false
            }
        ));
    }

    #[test]
    fn the_size_rules() {
        assert_eq!(size_ok(0, 0), Err(Errno::EINVAL));
        assert_eq!(size_ok(1, 0), Ok(1));
        assert_eq!(size_ok(4096, 0), Ok(1));
        assert_eq!(size_ok(4097, 0), Ok(2));
        assert_eq!(size_ok(ipc::SHMMAX + 1, 0), Err(Errno::EINVAL));
        assert_eq!(
            size_ok(ipc::SHMMAX, 0),
            Err(Errno::EINVAL),
            "past what a file may hold"
        );
        assert_eq!(
            size_ok(1 << 62, 0),
            Ok(1 << 50),
            "a sparse file that large is fine"
        );
        assert_eq!(size_ok(4096, ipc::SHMALL), Err(Errno::ENOSPC));
    }

    #[test]
    fn an_existing_key() {
        assert_eq!(
            existing_ok(ipc::CREAT | ipc::EXCL, 100, 10),
            Err(Errno::EEXIST)
        );
        assert_eq!(existing_ok(ipc::CREAT, 100, 101), Err(Errno::EINVAL));
        assert_eq!(existing_ok(0, 100, 100), Ok(()));
        assert_eq!(
            existing_ok(0, 100, 0),
            Ok(()),
            "asking for nothing of an existing segment is fine"
        );
    }

    #[test]
    fn attach_addresses() {
        assert_eq!(
            attach(0, 0).map(|a| (a.addr, a.prot, a.acc, a.replace)),
            Ok((0, 3, 0o666, false))
        );
        assert_eq!(
            attach(0, ipc::SHM_RDONLY).map(|a| (a.prot, a.acc)),
            Ok((1, 0o444))
        );
        assert_eq!(
            attach(0, ipc::SHM_EXEC).map(|a| (a.prot, a.acc)),
            Ok((7, 0o777))
        );
        assert_eq!(attach(0x1000, 0).map(|a| a.addr), Ok(0x1000));
        assert_eq!(
            attach(0x1001, 0),
            Err(Errno::EINVAL),
            "unaligned without SHM_RND"
        );
        assert_eq!(
            attach(0x1001, ipc::SHM_RND).map(|a| a.addr),
            Ok(0x1000),
            "rounded down with it"
        );
        assert_eq!(
            attach(0x1, ipc::SHM_RND | ipc::SHM_REMAP),
            Err(Errno::EINVAL),
            "rounded to zero with REMAP"
        );
        assert_eq!(
            attach(0x1, ipc::SHM_RND).map(|a| a.addr),
            Ok(0),
            "rounded to zero without is anywhere"
        );
        assert_eq!(
            attach(0, ipc::SHM_REMAP),
            Err(Errno::EINVAL),
            "REMAP needs an address"
        );
        assert_eq!(attach(0x2000, ipc::SHM_REMAP).map(|a| a.replace), Ok(true));
    }

    #[test]
    fn ids_carry_a_sequence() {
        assert_eq!(id_of(0, 0), 0);
        assert_eq!(id_of(3, 2), 2 * 32768 + 3);
        let seqs = |i: usize| if i == 3 { Some(2u16) } else { None };
        assert_eq!(index_of(id_of(3, 2), seqs), Some(3));
        assert_eq!(
            index_of(id_of(3, 1), seqs),
            None,
            "an old sequence names nothing"
        );
        assert_eq!(index_of(-1, seqs), None);
        assert_eq!(index_of(id_of(4, 2), seqs), None);
    }

    #[test]
    fn shmid_ds_is_112_bytes_with_the_fields_where_linux_puts_them() {
        // The wire record, not a registry entry: this test is about where
        // Linux puts each field, and it used to build a whole `Segment` --
        // memfd included, as `fd: 0` -- to reach an encoder that reads eight
        // of its thirteen fields. See `control::ShmidDs`.
        let ds = control::ShmidDs {
            key: 0x1234,
            perm: Perm {
                uid: 1,
                gid: 2,
                cuid: 3,
                cgid: 4,
                mode: 0o640,
            },
            seq: 7,
            size: 8192,
            atime: 11,
            dtime: 22,
            ctime: 33,
            cpid: 100,
            lpid: 200,
            nattch: 5,
        };
        let b = control::encode_shmid_ds(&ds);
        assert_eq!(b.len(), 112);
        assert_eq!(control::u32_at(&b, 0), 0x1234);
        assert_eq!(control::u32_at(&b, 4), 1);
        assert_eq!(control::u32_at(&b, 8), 2);
        assert_eq!(control::u32_at(&b, 12), 3);
        assert_eq!(control::u32_at(&b, 16), 4);
        assert_eq!(control::u32_at(&b, 20), 0o640);
        assert_eq!(u16::from_le_bytes(b[24..26].try_into().unwrap()), 7);
        assert_eq!(
            u64::from_le_bytes(b[48..56].try_into().unwrap()),
            8192,
            "shm_segsz"
        );
        assert_eq!(
            i64::from_le_bytes(b[56..64].try_into().unwrap()),
            11,
            "shm_atime"
        );
        assert_eq!(
            i64::from_le_bytes(b[64..72].try_into().unwrap()),
            22,
            "shm_dtime"
        );
        assert_eq!(
            i64::from_le_bytes(b[72..80].try_into().unwrap()),
            33,
            "shm_ctime"
        );
        assert_eq!(control::u32_at(&b, 80), 100, "shm_cpid");
        assert_eq!(control::u32_at(&b, 84), 200, "shm_lpid");
        assert_eq!(
            u64::from_le_bytes(b[88..96].try_into().unwrap()),
            5,
            "shm_nattch"
        );
    }
}
