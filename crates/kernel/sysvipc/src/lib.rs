//! What System V semaphores, message queues and shared memory have in common:
//! a key space, an id space, an owner and a mode.
//!
//! Here rather than in each of the three because it is one rule written once —
//! the shape `crates/util/buildcfg` and `crates/kernel/taskview` are, and the
//! shape `crates/kernel/taskcalls`' `GeneralGuard` became on 2026-09-08 after a
//! second caller was written without the rule it enforced.
//!
//! # The parts that are only *nearly* obvious
//!
//! - **`IPC_PRIVATE` is 0 and is not a key.** It always creates, and the object
//!   has no key anyone can look up — so it is reachable only through the id,
//!   which is what `fork` passes to a child.
//! - **A lookup may ask for fewer than the object has, and not more.**
//!   `semget(key, 3, 0)` against a set of two is `EINVAL`; `semget(key, 1, 0)`
//!   and `semget(key, 0, 0)` both answer the id. `semget(2)` states the rule
//!   for the create case and is silent about the lookup; measured against an
//!   arm64 kernel by `tests/guest/src/bin/sysvsem_probe.rs`.
//! - **An id is gone the moment `IPC_RMID` runs**, and every later use of it is
//!   `EINVAL` — not `EIDRM`. `EIDRM` is for a caller that was already *blocked*
//!   on the object when it was removed, which is the one case where "it existed
//!   when you asked" is true. Both measured.
//!
//! # The wire structs are here too, because their offsets are the contract
//!
//! `struct ipc_perm` is 48 bytes with `mode` at 20 and `seq` at 24 — measured
//! from musl's own headers in an arm64 container rather than derived, which is
//! what `CLAUDE.md` asks of a wire format. A `mode` written at 24 is read by
//! `ipcs` as a sequence number and the permissions column comes out empty.

use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::Arc;

/// `IPC_PRIVATE`. Not a key: an object made with it has none.
pub const IPC_PRIVATE: i32 = 0;

pub const IPC_CREAT: i32 = 0o1000;
pub const IPC_EXCL: i32 = 0o2000;
pub const IPC_NOWAIT: i32 = 0o4000;

/// `ipcctl` commands, of the three every family has.
pub const IPC_RMID: c_int = 0;
pub const IPC_SET: c_int = 1;
pub const IPC_STAT: c_int = 2;
pub const IPC_INFO: c_int = 3;

pub use guest_errno::Errno;

/// `MAY_READ` / `MAY_WRITE`, as the mode bits are laid out: the same 4 and 2 a
/// file's permissions use, because an IPC object's mode *is* a file mode with
/// the execute bit unused.
pub const READ: u16 = 4;
pub const WRITE: u16 = 2;

/// Who made an object and who may reach it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Perm {
    /// The key it was created under, or [`IPC_PRIVATE`].
    pub key: i32,
    /// The current owner, which `IPC_SET` may change.
    pub uid: u32,
    pub gid: u32,
    /// The creator, which nothing changes.
    pub cuid: u32,
    pub cgid: u32,
    /// The low nine bits are the permissions; the rest are the `IPC_*` flags
    /// the creating call carried and are not kept.
    pub mode: u16,
    /// Bumped when an id is reused, so a stale id from before a removal cannot
    /// name the object that took its place. Linux folds it into the id itself;
    /// this reports it and allocates ids that are not reused within a run,
    /// which answers the same question more directly.
    pub seq: u16,
}

impl Perm {
    pub fn new(key: i32, uid: u32, gid: u32, mode: u16) -> Perm {
        Perm {
            key,
            uid,
            gid,
            cuid: uid,
            cgid: gid,
            mode: mode & 0o777,
            seq: 0,
        }
    }
}

/// Whether a caller may reach an object.
///
/// Linux's `ipcperms`: `CAP_IPC_OWNER` always may; the owner or creator is asked
/// about the user bits; a member of the group about the group bits; anyone else
/// about the other bits. Note that it is **not** the file rule of falling
/// through — a uid match uses the user bits and stops, so an object with mode
/// 0o077 refuses its own owner, which is a real thing to be able to express.
pub fn may(
    perm: &Perm,
    ipc_owner: bool,
    euid: u32,
    egid: u32,
    want: u16,
) -> Result<(), Errno> {
    if ipc_owner {
        return Ok(());
    }
    let granted = if euid == perm.uid || euid == perm.cuid {
        (perm.mode >> 6) & 7
    } else if egid == perm.gid || egid == perm.cgid {
        (perm.mode >> 3) & 7
    } else {
        perm.mode & 7
    };
    if granted & want == want {
        Ok(())
    } else {
        Err(Errno::EACCES)
    }
}

/// What a `*get` call was asked for, once the flags are taken apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetFlags {
    pub create: bool,
    pub exclusive: bool,
    pub mode: u16,
}

pub fn get_flags(flags: i32) -> GetFlags {
    GetFlags {
        create: flags & IPC_CREAT != 0,
        exclusive: flags & IPC_EXCL != 0,
        mode: (flags & 0o777) as u16,
    }
}

/// The objects of one family, by id and by key.
///
/// `Arc<T>` so a blocked caller can hold the object across a wait without
/// holding this table -- which it must not, since the thing it is waiting for
/// is another process reaching the same object through the same table.
pub struct Registry<T> {
    by_id: HashMap<i32, Arc<T>>,
    by_key: HashMap<i32, i32>,
    next: i32,
}

impl<T> Default for Registry<T> {
    fn default() -> Self {
        Registry::new()
    }
}

impl<T> Registry<T> {
    pub fn new() -> Registry<T> {
        Registry {
            by_id: HashMap::new(),
            by_key: HashMap::new(),
            next: 0,
        }
    }

    /// The object at `id`, or `None` for one that never existed or has been
    /// removed. Both are `EINVAL` to a caller; see the module comment.
    pub fn get(&self, id: i32) -> Option<Arc<T>> {
        self.by_id.get(&id).cloned()
    }

    pub fn by_key(&self, key: i32) -> Option<(i32, Arc<T>)> {
        let id = *self.by_key.get(&key)?;
        Some((id, self.by_id.get(&id)?.clone()))
    }

    /// Add an object, answering the id it got.
    ///
    /// Ids are **not reused within a run**: `next` only goes up. Linux packs a
    /// sequence number into the id for the same reason, and this is the same
    /// guarantee by a simpler means -- a stale id cannot name a later object.
    pub fn insert(&mut self, key: i32, obj: T) -> i32 {
        let id = self.next;
        self.next += 1;
        self.by_id.insert(id, Arc::new(obj));
        if key != IPC_PRIVATE {
            self.by_key.insert(key, id);
        }
        id
    }

    /// Take an object out. The `Arc` a blocked caller holds keeps it alive
    /// until that caller has looked at it once more and seen it removed --
    /// which is how a waiter learns to answer `EIDRM`.
    pub fn remove(&mut self, id: i32, key: i32) -> Option<Arc<T>> {
        if key != IPC_PRIVATE {
            // Only if it still names this id: a key freed by an earlier
            // removal may already have been taken by a newer object.
            if self.by_key.get(&key) == Some(&id) {
                self.by_key.remove(&key);
            }
        }
        self.by_id.remove(&id)
    }

    /// Every live id, ascending. `ipcs` walks the space; this is the walk.
    pub fn ids(&self) -> Vec<i32> {
        let mut v: Vec<i32> = self.by_id.keys().copied().collect();
        v.sort_unstable();
        v
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

// ------------------------------------------------------------------- the wire

/// `struct ipc_perm` as the guest lays it out: 48 bytes.
///
/// Measured from musl's headers in an arm64 container:
/// `key@0 uid@4 gid@8 cuid@12 cgid@16 mode@20 seq@24`, size 48. The tail is
/// two unused longs, which stay zero.
pub const IPC_PERM_LEN: usize = 48;

pub fn write_perm(out: &mut [u8], perm: &Perm) {
    out[0..4].copy_from_slice(&perm.key.to_le_bytes());
    out[4..8].copy_from_slice(&perm.uid.to_le_bytes());
    out[8..12].copy_from_slice(&perm.gid.to_le_bytes());
    out[12..16].copy_from_slice(&perm.cuid.to_le_bytes());
    out[16..20].copy_from_slice(&perm.cgid.to_le_bytes());
    out[20..24].copy_from_slice(&(perm.mode as u32).to_le_bytes());
    out[24..26].copy_from_slice(&perm.seq.to_le_bytes());
}

/// The three fields `IPC_SET` may change, out of a guest's `ipc_perm`.
///
/// Only `uid`, `gid` and the low nine bits of `mode`: Linux's `ipc_update_perm`
/// ignores the rest, and a caller that writes a key or a creator there is not
/// refused, it is simply not obeyed.
pub fn read_perm_update(buf: &[u8]) -> Option<(u32, u32, u16)> {
    Some((
        u32::from_le_bytes(buf.get(4..8)?.try_into().ok()?),
        u32::from_le_bytes(buf.get(8..12)?.try_into().ok()?),
        (u32::from_le_bytes(buf.get(20..24)?.try_into().ok()?) & 0o777) as u16,
    ))
}

/// Whether a caller may `IPC_SET` or `IPC_RMID` an object: the owner, the
/// creator, or `CAP_SYS_ADMIN`. **Not** the mode bits -- write permission on an
/// object does not let a caller give it away or destroy it.
pub fn may_control(perm: &Perm, sys_admin: bool, euid: u32) -> Result<(), Errno> {
    if sys_admin || euid == perm.uid || euid == perm.cuid {
        Ok(())
    } else {
        Err(Errno::EPERM)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perm() -> Perm {
        Perm {
            key: 42,
            uid: 1000,
            gid: 100,
            cuid: 1000,
            cgid: 100,
            mode: 0o640,
            seq: 0,
        }
    }

    #[test]
    fn the_mode_check_stops_at_the_first_class_that_matches() {
        let p = perm();
        // The owner is asked about the user bits and *only* those.
        assert_eq!(may(&p, false, 1000, 100, READ), Ok(()));
        assert_eq!(may(&p, false, 1000, 100, WRITE), Ok(()));
        // A group member about the group bits: 0o640 gives read, not write.
        assert_eq!(may(&p, false, 2000, 100, READ), Ok(()));
        assert_eq!(may(&p, false, 2000, 100, WRITE), Err(Errno::EACCES));
        // Anyone else about the other bits, which here are none.
        assert_eq!(may(&p, false, 2000, 200, READ), Err(Errno::EACCES));
        assert_eq!(may(&p, false, 2000, 200, WRITE), Err(Errno::EACCES));
        // And CAP_IPC_OWNER always.
        assert_eq!(may(&p, true, 2000, 200, WRITE), Ok(()));
    }

    #[test]
    fn an_owner_can_be_refused_by_a_mode_that_grants_only_others() {
        // 0o077: the owner gets nothing and everyone else gets everything.
        // A file-style fall-through would grant the owner the other bits;
        // Linux's ipcperms does not, and this is a real thing to express.
        let p = Perm {
            mode: 0o077,
            ..perm()
        };
        assert_eq!(may(&p, false, 1000, 100, READ), Err(Errno::EACCES));
        assert_eq!(may(&p, false, 2000, 200, READ), Ok(()));
    }

    #[test]
    fn control_is_ownership_and_not_the_mode_bits() {
        // Write permission does not let a caller destroy an object or give it
        // away, which is the distinction between `may` and `may_control`.
        let p = Perm {
            mode: 0o666,
            ..perm()
        };
        assert_eq!(may(&p, false, 2000, 200, WRITE), Ok(()));
        assert_eq!(may_control(&p, false, 2000), Err(Errno::EPERM));
        assert_eq!(may_control(&p, false, 1000), Ok(()));
        assert_eq!(may_control(&p, true, 2000), Ok(()));
    }

    #[test]
    fn an_id_is_never_reused_within_a_run() {
        // A stale id from before a removal must not name the object that took
        // its place, which is what Linux's sequence number in the id is for.
        let mut r: Registry<u32> = Registry::new();
        let a = r.insert(IPC_PRIVATE, 1);
        r.remove(a, IPC_PRIVATE);
        let b = r.insert(IPC_PRIVATE, 2);
        assert_ne!(a, b);
        assert!(r.get(a).is_none(), "the removed id names nothing");
        assert_eq!(*r.get(b).unwrap(), 2);
    }

    #[test]
    fn a_private_object_has_no_key_to_look_up() {
        let mut r: Registry<u32> = Registry::new();
        let id = r.insert(IPC_PRIVATE, 7);
        assert!(r.by_key(IPC_PRIVATE).is_none(), "IPC_PRIVATE is not a key");
        assert_eq!(*r.get(id).unwrap(), 7);
    }

    #[test]
    fn removing_by_a_key_another_object_now_holds_leaves_that_one_alone() {
        // The sequence that gets this wrong: create under a key, remove, create
        // again under the same key, then remove the *first* id. A `by_key`
        // removal that does not check which id it names unregisters the second
        // object's key and leaves it reachable only by id.
        let mut r: Registry<u32> = Registry::new();
        let a = r.insert(5, 1);
        r.remove(a, 5);
        let b = r.insert(5, 2);
        r.remove(a, 5);
        assert_eq!(
            r.by_key(5).map(|(id, _)| id),
            Some(b),
            "the second is still there"
        );
    }

    #[test]
    fn the_perm_wire_format_puts_mode_at_twenty() {
        // Measured from musl's own headers. A mode at 24 is read by `ipcs` as
        // the sequence number and the permissions column comes out empty.
        let mut buf = [0u8; IPC_PERM_LEN];
        let p = Perm {
            key: 0x1234,
            uid: 1000,
            gid: 100,
            cuid: 7,
            cgid: 8,
            mode: 0o640,
            seq: 3,
        };
        write_perm(&mut buf, &p);
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 0x1234);
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 1000);
        assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), 100);
        assert_eq!(u32::from_le_bytes(buf[12..16].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(buf[20..24].try_into().unwrap()), 0o640);
        assert_eq!(u16::from_le_bytes(buf[24..26].try_into().unwrap()), 3);
        // And the round trip an IPC_SET makes.
        assert_eq!(read_perm_update(&buf), Some((1000, 100, 0o640)));
    }

    #[test]
    fn ipc_set_takes_three_fields_and_ignores_the_rest() {
        // A caller that writes a key or a creator is not refused; it is simply
        // not obeyed, which is Linux's ipc_update_perm.
        let mut buf = [0u8; IPC_PERM_LEN];
        write_perm(
            &mut buf,
            &Perm {
                key: 9,
                uid: 5,
                gid: 6,
                cuid: 1,
                cgid: 2,
                mode: 0o7777,
                seq: 1,
            },
        );
        let (uid, gid, mode) = read_perm_update(&buf).unwrap();
        assert_eq!((uid, gid), (5, 6));
        assert_eq!(
            mode, 0o777,
            "the flag bits above the permissions are dropped"
        );
        assert!(
            read_perm_update(&buf[..10]).is_none(),
            "a short buffer is not read past"
        );
    }

    #[test]
    fn the_get_flags_are_the_three_a_caller_can_ask_for() {
        assert_eq!(
            get_flags(0),
            GetFlags {
                create: false,
                exclusive: false,
                mode: 0
            }
        );
        assert_eq!(
            get_flags(IPC_CREAT | IPC_EXCL | 0o640),
            GetFlags {
                create: true,
                exclusive: true,
                mode: 0o640
            }
        );
        // A mode with bits above the permissions: they are the IPC_* flags and
        // are not part of the mode.
        assert_eq!(get_flags(IPC_CREAT | 0o1777).mode, 0o777);
    }
}
