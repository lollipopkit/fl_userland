//! Capability sets and securebits, and the rules that change them.
//!
//! Linux's `security/commoncap.c` and the `capget`/`capset`/`prctl` halves of
//! `kernel/capability.c` and `kernel/sys.c`. Every answer below was measured
//! against a 7.2 arm64 kernel by `tests/guest/src/bin/caps_probe.rs`.
//!
//! Until 2026-11-13 privilege here was derived from the uids: the effective
//! set was full when the effective uid was 0, the permitted set when any uid
//! was, and the bounding set and securebits sat on the thread's attributes
//! with nothing reading them. A root process that dropped one capability kept
//! all of them, `capset` stored nothing, and no execve could gain one.

use std::ffi::c_int;

use guest_errno::c_int_::{EINVAL, EPERM};

/// `CAP_LAST_CAP`, which is `CAP_CHECKPOINT_RESTORE` in Linux 7.0.
pub const CAP_LAST_CAP: u32 = 40;
/// `CAP_VALID_MASK`: every capability, which is what init's sets hold.
pub const CAP_FULL: u64 = (1 << (CAP_LAST_CAP + 1)) - 1;

pub const CAP_CHOWN: u32 = 0;
pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_DAC_READ_SEARCH: u32 = 2;
pub const CAP_FOWNER: u32 = 3;
pub const CAP_FSETID: u32 = 4;
pub const CAP_KILL: u32 = 5;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_SETPCAP: u32 = 8;
pub const CAP_LINUX_IMMUTABLE: u32 = 9;
pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_IPC_LOCK: u32 = 14;
pub const CAP_IPC_OWNER: u32 = 15;
pub const CAP_SYS_CHROOT: u32 = 18;
pub const CAP_SYS_PTRACE: u32 = 19;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYS_BOOT: u32 = 22;
pub const CAP_SYS_NICE: u32 = 23;
pub const CAP_SYS_RESOURCE: u32 = 24;
pub const CAP_SYS_TIME: u32 = 25;
pub const CAP_SYS_TTY_CONFIG: u32 = 26;
pub const CAP_MKNOD: u32 = 27;
pub const CAP_SETFCAP: u32 = 31;
pub const CAP_MAC_OVERRIDE: u32 = 32;
pub const CAP_SYSLOG: u32 = 34;
pub const CAP_CHECKPOINT_RESTORE: u32 = 40;

const fn bit(cap: u32) -> u64 {
    1 << cap
}

/// `CAP_FS_SET`: what moving the fsuid away from 0 takes out of the effective
/// set and moving it back restores from the permitted one. Measured: root's
/// `setfsuid(1000)` leaves `0x1fef7fffde0`, bits 0-4, 9, 27 and 32 gone.
pub const CAP_FS_SET: u64 = bit(CAP_CHOWN)
    | bit(CAP_DAC_OVERRIDE)
    | bit(CAP_DAC_READ_SEARCH)
    | bit(CAP_FOWNER)
    | bit(CAP_FSETID)
    | bit(CAP_LINUX_IMMUTABLE)
    | bit(CAP_MKNOD)
    | bit(CAP_MAC_OVERRIDE);

/// `cap_valid`: a number that names a capability.
pub fn cap_valid(cap: u64) -> bool {
    cap <= CAP_LAST_CAP as u64
}

/// The securebits, from `include/uapi/linux/securebits.h`. Each bit has a
/// **lock** one place above it; a locked bit cannot change, and a lock cannot
/// be cleared.
pub mod secure {
    pub const NOROOT: u32 = 0;
    pub const NO_SETUID_FIXUP: u32 = 2;
    pub const KEEP_CAPS: u32 = 4;
    pub const NO_CAP_AMBIENT_RAISE: u32 = 6;
    /// The two 6.14 additions, measured rather than read: `0x100` is accepted
    /// by the reference kernel, and a list of four would have refused it.
    pub const EXEC_RESTRICT_FILE: u32 = 8;
    pub const EXEC_DENY_INTERACTIVE: u32 = 10;

    pub const fn mask(bit: u32) -> u32 {
        1 << bit
    }
    pub const fn locked(bit: u32) -> u32 {
        1 << (bit + 1)
    }

    /// `SECURE_ALL_BITS`: the six settable bits.
    pub const ALL_BITS: u32 = mask(NOROOT)
        | mask(NO_SETUID_FIXUP)
        | mask(KEEP_CAPS)
        | mask(NO_CAP_AMBIENT_RAISE)
        | mask(EXEC_RESTRICT_FILE)
        | mask(EXEC_DENY_INTERACTIVE);
    /// `SECURE_ALL_LOCKS`: their six locks.
    pub const ALL_LOCKS: u32 = ALL_BITS << 1;
    /// `SECURE_ALL_UNPRIVILEGED`: what a process without `CAP_SETPCAP` may
    /// change, with its locks. The two exec bits, measured: without the
    /// capability `0x100` is accepted and `0x40` (`NO_CAP_AMBIENT_RAISE`) is
    /// `EPERM`. It said `NO_CAP_AMBIENT_RAISE` here until 2026-11-13.
    pub const ALL_UNPRIVILEGED: u32 = mask(EXEC_RESTRICT_FILE) | mask(EXEC_DENY_INTERACTIVE);
}

/// `PR_CAP_AMBIENT`'s four operations.
pub mod ambient {
    pub const IS_SET: u64 = 1;
    pub const RAISE: u64 = 2;
    pub const LOWER: u64 = 3;
    pub const CLEAR_ALL: u64 = 4;
}

/// A task's five capability sets.
///
/// The invariant Linux asserts at every change, `cap_ambient_invariant_ok`, is
/// `ambient ⊆ permitted ∩ inheritable`; every method below that can shrink
/// either of those trims the ambient set with it.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    pub permitted: u64,
    pub effective: u64,
    pub inheritable: u64,
    pub bounding: u64,
    pub ambient: u64,
}

impl Caps {
    /// `init_cred`'s: what a root login has. Inheritable and ambient empty.
    pub const ROOT: Caps = Caps {
        permitted: CAP_FULL,
        effective: CAP_FULL,
        inheritable: 0,
        bounding: CAP_FULL,
        ambient: 0,
    };
}

/// `cap_capset`. `setpcap` is whether the caller's effective set holds
/// `CAP_SETPCAP` (`cap_inh_is_capped`). Bits past `CAP_LAST_CAP` are dropped
/// before the rules see them, as `mk_kernel_cap` does: setting them is a
/// success, measured.
pub(crate) fn capset(old: &Caps, effective: u64, permitted: u64, inheritable: u64) -> Result<Caps, c_int> {
    let (e, p, i) = (effective & CAP_FULL, permitted & CAP_FULL, inheritable & CAP_FULL);
    let setpcap = old.effective & bit(CAP_SETPCAP) != 0;
    if !setpcap && i & !(old.inheritable | old.permitted) != 0 {
        return Err(EPERM);
    }
    if i & !(old.inheritable | old.bounding) != 0 {
        return Err(EPERM);
    }
    if p & !old.permitted != 0 || e & !p != 0 {
        return Err(EPERM);
    }
    Ok(Caps {
        permitted: p,
        effective: e,
        inheritable: i,
        bounding: old.bounding,
        ambient: old.ambient & p & i,
    })
}

/// `PR_SET_SECUREBITS`, `cap_task_prctl`'s refusals, all `EPERM`: a locked bit
/// may not change, a lock may not be cleared, an unknown bit may not be set;
/// and without `CAP_SETPCAP` the request must change something and only the
/// unprivileged bits and their locks.
pub(crate) fn securebits_change(old: u32, new: u64, setpcap: bool) -> Result<u32, c_int> {
    let Ok(new) = u32::try_from(new) else {
        return Err(EPERM);
    };
    let changed = old ^ new;
    if ((old & secure::ALL_LOCKS) >> 1) & changed != 0
        || old & secure::ALL_LOCKS & !new != 0
        || new & !(secure::ALL_LOCKS | secure::ALL_BITS) != 0
    {
        return Err(EPERM);
    }
    if !setpcap {
        let unpriv_and_locks = secure::ALL_UNPRIVILEGED | secure::ALL_UNPRIVILEGED << 1;
        if changed == 0 || changed & !unpriv_and_locks != 0 {
            return Err(EPERM);
        }
    }
    Ok(new)
}

/// The ids `cap_task_fix_setuid` compares.
#[derive(Clone, Copy)]
pub(crate) struct Uids {
    pub real: u32,
    pub eff: u32,
    pub saved: u32,
}

impl Uids {
    fn any_root(&self) -> bool {
        self.real == 0 || self.eff == 0 || self.saved == 0
    }
}

/// `cap_emulate_setxuid`, after a `setuid`, `setreuid` or `setresuid` that
/// succeeded. Not under `SECBIT_NO_SETUID_FIXUP`.
///
/// Leaving 0 with all three ids empties permitted and effective, unless
/// `SECBIT_KEEP_CAPS`, and always the ambient set; an effective uid leaving 0
/// empties effective, and one arriving at 0 gets the permitted set.
pub(crate) fn fix_setuid(caps: &mut Caps, securebits: u32, old: Uids, new: Uids) {
    if securebits & secure::mask(secure::NO_SETUID_FIXUP) != 0 {
        return;
    }
    if old.any_root() && !new.any_root() {
        if securebits & secure::mask(secure::KEEP_CAPS) == 0 {
            caps.permitted = 0;
            caps.effective = 0;
        }
        caps.ambient = 0;
    }
    if old.eff == 0 && new.eff != 0 {
        caps.effective = 0;
    }
    if old.eff != 0 && new.eff == 0 {
        caps.effective = caps.permitted;
    }
}

/// `cap_task_fix_setuid`'s `LSM_SETID_FS` arm, after a `setfsuid`.
pub(crate) fn fix_setfsuid(caps: &mut Caps, securebits: u32, old_fs: u32, new_fs: u32) {
    if securebits & secure::mask(secure::NO_SETUID_FIXUP) != 0 {
        return;
    }
    if old_fs == 0 && new_fs != 0 {
        caps.effective &= !CAP_FS_SET;
    }
    if old_fs != 0 && new_fs == 0 {
        caps.effective |= caps.permitted & CAP_FS_SET;
    }
}

// ------------------------------------------------------- file capabilities

/// The `security.capability` attribute's name.
pub const XATTR_NAME_CAPS: &[u8] = b"security.capability";

const VFS_CAP_REVISION_MASK: u32 = 0xff00_0000;
const VFS_CAP_REVISION_1: u32 = 0x0100_0000;
const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
const VFS_CAP_REVISION_3: u32 = 0x0300_0000;
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x0000_0001;
/// `XATTR_CAPS_SZ_1`, `_2`, `_3`.
const SZ_1: usize = 12;
const SZ_2: usize = 20;
const SZ_3: usize = 24;

/// A file's capabilities, decoded: `struct cpu_vfs_cap_data`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileCaps {
    pub permitted: u64,
    pub inheritable: u64,
    pub effective: bool,
}

fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// `get_vfs_caps_from_disk`: `Ok(None)` for an attribute that does not apply
/// (a v3 whose root is not this namespace's 0, which in the only namespace
/// here is any rootid but 0), `EINVAL` for one that is malformed, which fails
/// the exec.
pub fn file_caps_from_xattr(b: &[u8]) -> Result<Option<FileCaps>, c_int> {
    if b.len() < 4 {
        return Err(EINVAL);
    }
    let magic = word(b, 0);
    let size = match magic & VFS_CAP_REVISION_MASK {
        VFS_CAP_REVISION_1 => SZ_1,
        VFS_CAP_REVISION_2 => SZ_2,
        VFS_CAP_REVISION_3 => SZ_3,
        _ => return Err(EINVAL),
    };
    if b.len() != size {
        return Err(EINVAL);
    }
    if size == SZ_3 && word(b, 20) != 0 {
        return Ok(None);
    }
    let mut permitted = word(b, 4) as u64;
    let mut inheritable = word(b, 8) as u64;
    if size != SZ_1 {
        permitted |= (word(b, 12) as u64) << 32;
        inheritable |= (word(b, 16) as u64) << 32;
    }
    Ok(Some(FileCaps {
        permitted: permitted & CAP_FULL,
        inheritable: inheritable & CAP_FULL,
        effective: magic & VFS_CAP_FLAGS_EFFECTIVE != 0,
    }))
}

/// `cap_convert_nscap`'s validation of a value being written:
/// `validheader`, a v2 or a v3 of exactly its size. A v1 is refused, measured.
pub fn xattr_caps_valid(b: &[u8]) -> bool {
    if b.len() < 4 {
        return false;
    }
    match word(b, 0) & VFS_CAP_REVISION_MASK {
        VFS_CAP_REVISION_2 => b.len() == SZ_2,
        VFS_CAP_REVISION_3 => b.len() == SZ_3,
        _ => false,
    }
}

/// `cap_inode_getsecurity`: a v3 whose rootid is 0 is this namespace's own
/// and reads back as a v2, 20 bytes. Measured; any other value is answered as
/// stored. `None` when nothing changes.
pub fn xattr_caps_for_reader(b: &[u8]) -> Option<[u8; SZ_2]> {
    if b.len() != SZ_3 || word(b, 0) & VFS_CAP_REVISION_MASK != VFS_CAP_REVISION_3 || word(b, 20) != 0 {
        return None;
    }
    let mut out = [0u8; SZ_2];
    out.copy_from_slice(&b[..SZ_2]);
    let magic = VFS_CAP_REVISION_2 | (word(b, 0) & VFS_CAP_FLAGS_EFFECTIVE);
    out[..4].copy_from_slice(&magic.to_le_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: Caps = Caps::ROOT;
    const X: u64 = bit(CAP_NET_BIND_SERVICE);

    /// The `capset` rows of `caps_probe`.
    #[test]
    fn capset_is_bounded_by_the_old_sets() {
        let e = FULL.effective;
        assert_eq!(capset(&FULL, e, e & !X, 0), Err(EPERM), "E beyond P");
        let dropped = capset(&FULL, e & !X, e & !X, 0).unwrap();
        assert_eq!(capset(&dropped, e, e, 0), Err(EPERM), "P back after a drop");
        assert!(capset(&dropped, e & !X, e & !X, X).is_ok(), "I outside P with SETPCAP");
        let no_setpcap = capset(&FULL, e & !X & !bit(CAP_SETPCAP), e & !X, 0).unwrap();
        assert_eq!(capset(&no_setpcap, 0, e & !X, X), Err(EPERM), "I outside P without SETPCAP");
        assert!(capset(&no_setpcap, 0, e & !X, bit(CAP_CHOWN)).is_ok());
        let unbounded = Caps { bounding: CAP_FULL & !X, ..FULL };
        assert_eq!(capset(&unbounded, e, e, X), Err(EPERM), "I outside the bounding set");
        let past = capset(&FULL, u64::MAX, u64::MAX, 0).unwrap();
        assert_eq!(past.permitted, CAP_FULL, "bits past the last are dropped, not refused");
    }

    #[test]
    fn capset_trims_the_ambient_set() {
        let with = Caps { inheritable: X, ambient: X, ..FULL };
        assert_eq!(capset(&with, CAP_FULL, CAP_FULL, 0).unwrap().ambient, 0, "I dropped");
        assert_eq!(capset(&with, CAP_FULL & !X, CAP_FULL & !X, X).unwrap().ambient, 0, "P dropped");
        assert_eq!(capset(&with, CAP_FULL, CAP_FULL, X).unwrap().ambient, X);
    }

    #[test]
    fn securebits_without_setpcap_are_the_exec_bits() {
        let exec = secure::mask(secure::EXEC_RESTRICT_FILE) as u64;
        assert_eq!(securebits_change(0, 0x40, false), Err(EPERM));
        assert_eq!(securebits_change(0, exec, false), Ok(exec as u32));
        assert_eq!(securebits_change(exec as u32, exec, false), Err(EPERM), "no change");
        assert_eq!(securebits_change(exec as u32, exec | 0x10, false), Err(EPERM));
        assert_eq!(securebits_change(0x3, 0x2, true), Err(EPERM), "a locked bit");
        assert_eq!(securebits_change(0x3, 0x1, true), Err(EPERM), "a lock");
        assert_eq!(securebits_change(0x3, 0x1003, true), Err(EPERM), "an unknown bit");
        assert_eq!(securebits_change(0x3, 0x3, true), Ok(0x3), "the same, with SETPCAP");
    }

    fn uids(real: u32, eff: u32, saved: u32) -> Uids {
        Uids { real, eff, saved }
    }

    #[test]
    fn leaving_root_with_every_uid_empties_permitted() {
        let mut c = Caps { inheritable: X, ambient: X, ..FULL };
        fix_setuid(&mut c, 0, uids(0, 0, 0), uids(1000, 1000, 1000));
        assert_eq!((c.permitted, c.effective, c.ambient), (0, 0, 0));
        assert_eq!(c.inheritable, X);
        let mut kept = Caps { inheritable: X, ambient: X, ..FULL };
        fix_setuid(&mut kept, secure::mask(secure::KEEP_CAPS), uids(0, 0, 0), uids(1000, 1000, 1000));
        assert_eq!((kept.permitted, kept.effective, kept.ambient), (CAP_FULL, 0, 0));
        let mut fixed = FULL;
        fix_setuid(&mut fixed, secure::mask(secure::NO_SETUID_FIXUP), uids(0, 0, 0), uids(1000, 1000, 1000));
        assert_eq!(fixed, FULL);
    }

    #[test]
    fn the_effective_uid_moves_the_effective_set() {
        let mut c = Caps { inheritable: X, ambient: X, ..FULL };
        fix_setuid(&mut c, 0, uids(0, 0, 0), uids(0, 1000, 0));
        assert_eq!((c.permitted, c.effective, c.ambient), (CAP_FULL, 0, X), "a saved 0 keeps P and A");
        fix_setuid(&mut c, 0, uids(0, 1000, 0), uids(0, 0, 0));
        assert_eq!(c.effective, CAP_FULL);
        let mut partial = Caps { effective: CAP_FULL & !1, ..FULL };
        fix_setuid(&mut partial, 0, uids(0, 0, 0), uids(0, 1000, 0));
        fix_setuid(&mut partial, 0, uids(0, 1000, 0), uids(0, 0, 0));
        assert_eq!(partial.effective, CAP_FULL, "back to the whole permitted set");
    }

    #[test]
    fn the_fsuid_moves_the_fs_set() {
        let mut c = FULL;
        fix_setfsuid(&mut c, 0, 0, 1000);
        assert_eq!(c.effective, 0x1fef7fffde0, "measured");
        fix_setfsuid(&mut c, 0, 1000, 0);
        assert_eq!(c.effective, CAP_FULL);
    }

    #[test]
    fn file_caps_decode_and_reject() {
        let v2 = [0x01, 0, 0, 0x02, 0x00, 0x04, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            file_caps_from_xattr(&v2),
            Ok(Some(FileCaps { permitted: X, inheritable: bit(CAP_NET_RAW), effective: true }))
        );
        assert_eq!(file_caps_from_xattr(&v2[..19]), Err(EINVAL));
        let mut v3 = [0u8; 24];
        v3[..20].copy_from_slice(&v2);
        v3[3] = 0x03;
        assert!(file_caps_from_xattr(&v3).unwrap().is_some());
        v3[20] = 0xe8;
        v3[21] = 0x03;
        assert_eq!(file_caps_from_xattr(&v3), Ok(None), "another namespace's root");
        assert!(xattr_caps_for_reader(&v3).is_none());
        let v1 = [0, 0, 0, 0x01, 0, 0x04, 0, 0, 0, 0, 0, 0];
        assert_eq!(file_caps_from_xattr(&v1).unwrap().unwrap().permitted, X);
        assert!(!xattr_caps_valid(&v1), "a v1 may be read and not written");
        assert!(xattr_caps_valid(&v2) && !xattr_caps_valid(&v2[..19]));
    }

    #[test]
    fn a_v3_of_root_reads_back_as_a_v2() {
        let mut v3 = [0u8; 24];
        v3[0] = 1;
        v3[3] = 3;
        v3[5] = 4;
        let v2 = xattr_caps_for_reader(&v3).unwrap();
        assert_eq!(&v2[..8], &[1, 0, 0, 2, 0, 4, 0, 0]);
    }
}
