//! Credential state and its invariants.

use std::ffi::c_int;

use crate::Change;
use crate::caps::{self, CAP_FOWNER, CAP_SETGID, CAP_SETPCAP, CAP_SETUID, Caps, Uids, cap_valid, secure};

use super::{
    EINVAL, EPERM, MAX_GROUPS, access as access_check, may_link, set_fsid, set_id, set_reid,
    set_resid, setattr,
};

/// A task's ids for one of the two kinds. `saved` is the saved set-user-ID (or
/// set-group-ID), the field that makes a privilege drop permanent.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Ids {
    pub real: u32,
    pub eff: u32,
    pub saved: u32,
}

impl Ids {
    /// Whether `id` is one this task already holds. An unprivileged change may
    /// only name one of these — which is the whole of the permission model.
    pub(super) fn holds(&self, id: u32) -> bool {
        id == self.real || id == self.eff || id == self.saved
    }
}

/// A task's supplementary groups.
///
/// It was `unsigned ngroups` and `uid_t_ groups[MAX_GROUPS]` on `struct task`,
/// with the bound checked at the one call site that wrote them —
/// `tools/index-bounds.py` carried an entry for it saying so. A count and an
/// array that have to agree is the shape three defects in this tree have had;
/// here the count cannot exceed what is stored because nothing can write one.
///
/// Plain data, and embedded in `struct task` rather than allocated: a child
/// inherits its parent's groups, so being copied by the struct assignment that
/// makes one is exactly right.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Groups {
    list: [u32; MAX_GROUPS],
    n: u32,
}

impl Default for Groups {
    fn default() -> Groups {
        Groups {
            list: [0; MAX_GROUPS],
            n: 0,
        }
    }
}

impl Groups {
    pub fn new() -> Groups {
        Groups::default()
    }

    pub fn len(&self) -> u32 {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn as_slice(&self) -> &[u32] {
        &self.list[..self.n as usize]
    }

    /// `setgroups`. `EINVAL` for more than the kernel holds, which is the only
    /// rule about the *values* — who may call it at all is a permission
    /// question and stays with the caller.
    pub fn set(&mut self, groups: &[u32]) -> Result<(), c_int> {
        if groups.len() > MAX_GROUPS {
            return Err(EINVAL);
        }
        self.list = [0; MAX_GROUPS];
        self.list[..groups.len()].copy_from_slice(groups);
        self.n = groups.len() as u32;
        Ok(())
    }

    /// `getgroups`. A size of 0 is a question about the count and does not
    /// write anything; a size below the count is `EINVAL`, because a short
    /// answer would look like a complete one.
    ///
    /// **`size` is signed**, and a negative one is `EINVAL`: Linux's
    /// `gidsetsize` is an `int` and the first thing `getgroups` does is
    /// `if (gidsetsize < 0) return -EINVAL;`. Read as unsigned, `-1` is
    /// 4294967295 — larger than any count, so it looked like a caller with
    /// plenty of room and the call succeeded. Measured against a real arm64
    /// kernel, which refuses it.
    pub fn get(&self, size: i32) -> Result<&[u32], c_int> {
        if size < 0 {
            return Err(EINVAL);
        }
        if size == 0 {
            return Ok(&[]);
        }
        if (size as u32) < self.n {
            return Err(EINVAL);
        }
        Ok(self.as_slice())
    }

    pub fn contains(&self, gid: u32) -> bool {
        self.as_slice().contains(&gid)
    }
}

/// Everything about who a task is, and what it may do: Linux's `struct cred`.
///
/// Plain data: a child inherits it by the struct assignment that makes one,
/// which is what fork does. The default is `init_cred`, root with every
/// capability, which is what the first process starts as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Creds {
    pub(crate) uid: Ids,
    pub(crate) gid: Ids,
    pub(crate) fsuid: u32,
    pub(crate) fsgid: u32,
    /// The user this task was counted against for `RLIMIT_NPROC`, recorded
    /// because `uid` can change afterwards and the count has to go back to
    /// whoever it was taken from.
    pub(crate) nproc_uid: u32,
    /// `SECBIT_*`, which Linux keeps on the credentials: `PR_SET_KEEPCAPS`
    /// and `PR_SET_SECUREBITS` are two views of one word.
    pub(crate) securebits: u32,
    pub(crate) groups: Groups,
    pub(crate) caps: Caps,
}

impl Default for Creds {
    fn default() -> Creds {
        Creds {
            uid: Ids::default(),
            gid: Ids::default(),
            fsuid: 0,
            fsgid: 0,
            nproc_uid: 0,
            securebits: 0,
            groups: Groups::default(),
            caps: Caps::ROOT,
        }
    }
}

/// What [`Creds::override_fsids_with_real`] replaced, for
/// [`Creds::restore_fsids`] to put back.
#[derive(Clone, Copy, Debug)]
pub struct Overridden {
    fsuid: u32,
    fsgid: u32,
    effective: u64,
}

impl Creds {
    pub fn uid(&self) -> u32 {
        self.uid.real
    }
    pub fn euid(&self) -> u32 {
        self.uid.eff
    }
    pub fn suid(&self) -> u32 {
        self.uid.saved
    }
    pub fn gid(&self) -> u32 {
        self.gid.real
    }
    pub fn egid(&self) -> u32 {
        self.gid.eff
    }
    pub fn sgid(&self) -> u32 {
        self.gid.saved
    }
    pub fn fsuid(&self) -> u32 {
        self.fsuid
    }
    pub fn fsgid(&self) -> u32 {
        self.fsgid
    }
    pub fn nproc_uid(&self) -> u32 {
        self.nproc_uid
    }
    pub fn set_nproc_uid(&mut self, uid: u32) {
        self.nproc_uid = uid;
    }
    pub fn groups(&self) -> &Groups {
        &self.groups
    }
    pub fn groups_mut(&mut self) -> &mut Groups {
        &mut self.groups
    }

    /// May this task send a signal to one with `target`'s credentials?
    ///
    /// Linux's `kill_ok_by_cred`, four comparisons and a capability:
    ///
    /// ```c
    /// return uid_eq(cred->euid, tcred->suid) ||
    ///        uid_eq(cred->euid, tcred->uid) ||
    ///        uid_eq(cred->uid,  tcred->suid) ||
    ///        uid_eq(cred->uid,  tcred->uid) ||
    ///        ns_capable(tcred->user_ns, CAP_KILL);
    /// ```
    ///
    /// Both of the sender's ids against both of the target's, which is what
    /// lets a setuid program signal the process that started it and lets a
    /// process signal a child that has since changed its effective id. The
    /// target's *effective* id is deliberately not one of them: a process that
    /// has temporarily assumed another identity has not put itself out of reach
    /// of the user it belongs to.
    ///
    /// The signal number is not part of this. `SIGCONT` within a session is the
    /// one exception Linux makes and this kernel does not implement, so a shell
    /// continuing a job of a different user is refused here and allowed there —
    /// which needs sessions to be checkable and is a separate question.
    pub fn may_signal(&self, target: &Creds) -> bool {
        self.capable(caps::CAP_KILL)
            || self.euid() == target.suid()
            || self.euid() == target.uid()
            || self.uid() == target.suid()
            || self.uid() == target.uid()
    }

    /// `capable(cap)`: whether the effective set holds `cap`. Every
    /// permission decision asks this, path permission checks included, so it
    /// is one load and a test.
    #[inline]
    pub fn capable(&self, cap: u32) -> bool {
        self.caps.effective & (1 << cap) != 0
    }

    pub fn caps(&self) -> &Caps {
        &self.caps
    }

    pub fn securebits(&self) -> u32 {
        self.securebits
    }

    /// The ids `cap_task_fix_setuid` compares.
    fn uids(&self) -> Uids {
        Uids {
            real: self.uid.real,
            eff: self.uid.eff,
            saved: self.uid.saved,
        }
    }

    /// The one way the user ids change. **`fsuid` follows the effective uid**,
    /// here and therefore everywhere, and the capability sets follow the uids
    /// (`cap_emulate_setxuid`).
    fn take_uid(&mut self, ids: Ids) {
        let old = self.uids();
        self.uid = ids;
        self.fsuid = ids.eff;
        let new = self.uids();
        caps::fix_setuid(&mut self.caps, self.securebits, old, new);
    }

    fn take_gid(&mut self, ids: Ids) {
        self.gid = ids;
        self.fsgid = ids.eff;
    }

    /// `setuid`. Each of the uid calls asks `CAP_SETUID` and each of the gid
    /// calls `CAP_SETGID`, measured: root without `CAP_SETUID` may still
    /// `setresgid`, and without `CAP_SETGID` still `setresuid`.
    pub fn setuid(&mut self, id: u32) -> Result<(), c_int> {
        let out = set_id(self.capable(CAP_SETUID), self.uid, id)?;
        self.take_uid(out);
        Ok(())
    }

    pub fn setgid(&mut self, id: u32) -> Result<(), c_int> {
        let out = set_id(self.capable(CAP_SETGID), self.gid, id)?;
        self.take_gid(out);
        Ok(())
    }

    pub fn setreuid(&mut self, r: u32, e: u32) -> Result<(), c_int> {
        let out = set_reid(self.capable(CAP_SETUID), self.uid, r, e)?;
        self.take_uid(out);
        Ok(())
    }

    pub fn setregid(&mut self, r: u32, e: u32) -> Result<(), c_int> {
        let out = set_reid(self.capable(CAP_SETGID), self.gid, r, e)?;
        self.take_gid(out);
        Ok(())
    }

    pub fn setresuid(&mut self, r: u32, e: u32, sv: u32) -> Result<(), c_int> {
        let out = set_resid(self.capable(CAP_SETUID), self.uid, r, e, sv)?;
        self.take_uid(out);
        Ok(())
    }

    pub fn setresgid(&mut self, r: u32, e: u32, sv: u32) -> Result<(), c_int> {
        let out = set_resid(self.capable(CAP_SETGID), self.gid, r, e, sv)?;
        self.take_gid(out);
        Ok(())
    }

    /// `setfsuid`, which answers the *previous* value and cannot fail. A move
    /// away from 0 takes `CAP_FS_SET` out of the effective set and a move back
    /// restores what the permitted set has of it.
    pub fn setfsuid(&mut self, want: u32) -> u32 {
        let old = self.fsuid;
        self.fsuid = set_fsid(self.capable(CAP_SETUID), self.uid, old, want);
        caps::fix_setfsuid(&mut self.caps, self.securebits, old, self.fsuid);
        old
    }

    pub fn setfsgid(&mut self, want: u32) -> u32 {
        let old = self.fsgid;
        self.fsgid = set_fsid(self.capable(CAP_SETGID), self.gid, old, want);
        old
    }

    /// `setgroups`, which needs `CAP_SETGID`.
    pub fn setgroups(&mut self, groups: &[u32]) -> Result<(), c_int> {
        if !self.capable(CAP_SETGID) {
            return Err(EPERM);
        }
        self.groups.set(groups)
    }

    /// Make the fs ids the **real** ids for the duration of one call, and
    /// answer what to give back: Linux's `access_override_creds`.
    ///
    /// `access(2)` without `AT_EACCESS` is deliberately about the real uid, so
    /// that a set-id program can ask whether the user who invoked it may do
    /// something — and that has to hold for the whole path resolution, the
    /// search permission on every directory along the way and not only the
    /// final check. Threading a second pair of ids through the walk would mean
    /// every mount's lookup carrying them, so they are overridden instead, as
    /// Linux did with `override_creds()` until `faccessat2` gave it a better
    /// way.
    ///
    /// The effective set goes with them, unless `SECBIT_NO_SETUID_FIXUP`: a
    /// real uid of 0 checks with the whole permitted set, any other with none.
    /// Measured: root without `CAP_DAC_OVERRIDE` in its effective set is still
    /// told `R_OK` on another user's file by `CAP_DAC_READ_SEARCH`.
    ///
    /// Not `setfsuid`: this is a kernel-internal override and is not subject to
    /// the permission rule.
    pub fn override_fsids_with_real(&mut self) -> Overridden {
        let old = Overridden {
            fsuid: self.fsuid,
            fsgid: self.fsgid,
            effective: self.caps.effective,
        };
        self.fsuid = self.uid.real;
        self.fsgid = self.gid.real;
        if self.securebits & secure::mask(secure::NO_SETUID_FIXUP) == 0 {
            self.caps.effective = if self.uid.real == 0 { self.caps.permitted } else { 0 };
        }
        old
    }

    /// Give back what [`Creds::override_fsids_with_real`] returned.
    pub fn restore_fsids(&mut self, old: Overridden) {
        self.fsuid = old.fsuid;
        self.fsgid = old.fsgid;
        self.caps.effective = old.effective;
    }

    /// Whether going from `before` to this set is a change of identity in
    /// `commit_creds`' sense, which leaves the process undumpable:
    ///
    /// ```c
    /// if (!uid_eq(old->euid, new->euid) || !gid_eq(old->egid, new->egid) ||
    ///     !uid_eq(old->fsuid, new->fsuid) || !gid_eq(old->fsgid, new->fsgid) ||
    ///     !cred_cap_issubset(old, new))
    /// ```
    ///
    /// The real and saved ids and the groups are not part of it; the
    /// permitted set growing is.
    pub fn changes_identity(&self, before: &Creds) -> bool {
        self.uid.eff != before.uid.eff
            || self.gid.eff != before.gid.eff
            || self.fsuid != before.fsuid
            || self.fsgid != before.fsgid
            || self.caps.permitted & !before.caps.permitted != 0
    }

    /// `begin_new_exec`'s test, asked of the ids the exec **starts** with:
    /// the new image is dumpable when the effective ids are the real ones and
    /// the caller may read the file (`would_dump`). Otherwise a process that
    /// cannot read a program could read its memory once it runs, and a
    /// set-id process's next program would inherit what it was hiding.
    pub fn exec_keeps_dumpable(&self, file_uid: u32, file_gid: u32, file_mode: u32) -> bool {
        self.uid.eff == self.uid.real && self.gid.eff == self.gid.real && self.may_read(file_uid, file_gid, file_mode)
    }

    /// `would_dump`'s question of one file: may these credentials read it.
    pub fn may_read(&self, file_uid: u32, file_gid: u32, file_mode: u32) -> bool {
        self.access(file_uid, file_gid, file_mode, crate::AC_R).is_ok()
    }

    /// `in_group_p`: the fs gid or a supplementary group.
    pub fn in_group(&self, gid: u32) -> bool {
        crate::in_group(self.fsgid, self.groups.as_slice(), gid)
    }

    /// Discretionary access to a node, with the **fs** ids and the effective
    /// set's `CAP_DAC_OVERRIDE` and `CAP_DAC_READ_SEARCH`.
    #[inline]
    pub fn access(&self, uid: u32, gid: u32, mode: u32, want: u32) -> Result<(), c_int> {
        access_check(
            self.caps.effective,
            self.fsuid,
            self.fsgid,
            self.groups.as_slice(),
            uid,
            gid,
            mode,
            want,
        )
    }

    /// `inode_owner_or_capable`: the fsuid owns it, or `CAP_FOWNER`.
    pub fn owner_or_capable(&self, uid: u32) -> bool {
        self.fsuid == uid || self.capable(CAP_FOWNER)
    }

    /// `protected_hardlinks`, likewise.
    pub fn may_link(&self, uid: u32, gid: u32, mode: u32) -> Result<(), c_int> {
        may_link(
            self.capable(CAP_FOWNER),
            self.fsuid,
            self.fsgid,
            self.groups.as_slice(),
            uid,
            gid,
            mode,
        )
    }

    /// May this caller make this change to this node?
    pub fn setattr(
        &self,
        node_uid: u32,
        node_gid: u32,
        node_mode: u32,
        change: Change,
    ) -> Result<(), c_int> {
        setattr(
            self.caps.effective,
            self.fsuid,
            self.fsgid,
            self.groups.as_slice(),
            node_uid,
            node_gid,
            node_mode,
            change,
        )
    }

    /// The mode a permitted `chmod` stores: `setattr_prepare` takes `S_ISGID`
    /// off unless the caller is in the file's group or has `CAP_FSETID`.
    /// Measured: root without `CAP_FSETID`, `chmod 2755` on a file of group
    /// 1000, stores `0755`.
    pub fn chmod_mode(&self, node_gid: u32, mode: u32) -> u32 {
        const S_ISGID: u32 = 0o2000;
        if mode & S_ISGID != 0 && !self.in_group(node_gid) && !self.capable(caps::CAP_FSETID) {
            mode & !S_ISGID
        } else {
            mode
        }
    }

    /// `utimensat`'s rule (`setattr_prepare` and `notify_change`): explicit
    /// times need the owner or `CAP_FOWNER` (`EPERM`); "now" also lets a
    /// caller who may write the file (`EACCES`).
    pub fn may_set_times(&self, uid: u32, gid: u32, mode: u32, touch: bool) -> Result<(), c_int> {
        if self.owner_or_capable(uid) {
            return Ok(());
        }
        if touch {
            return self.access(uid, gid, mode, crate::AC_W);
        }
        Err(EPERM)
    }

    // ---------------------------------------------------- capability calls

    /// `capset` on the caller's own sets.
    pub fn capset(&mut self, effective: u64, permitted: u64, inheritable: u64) -> Result<(), c_int> {
        self.caps = caps::capset(&self.caps, effective, permitted, inheritable)?;
        Ok(())
    }

    /// `PR_CAPBSET_READ`.
    pub fn cap_bset_has(&self, cap: u64) -> Result<bool, c_int> {
        if !cap_valid(cap) {
            return Err(EINVAL);
        }
        Ok(self.caps.bounding & (1 << cap) != 0)
    }

    /// `PR_CAPBSET_DROP`. `CAP_SETPCAP` is asked for **before** the number is
    /// looked at — `cap_prctl_drop` — so without it capability 41 is `EPERM`
    /// and with it `EINVAL`, measured.
    pub fn cap_bset_drop(&mut self, cap: u64) -> Result<(), c_int> {
        if !self.capable(CAP_SETPCAP) {
            return Err(EPERM);
        }
        if !cap_valid(cap) {
            return Err(EINVAL);
        }
        self.caps.bounding &= !(1 << cap);
        Ok(())
    }

    /// `PR_CAP_AMBIENT`. `RAISE` needs the capability in both the permitted
    /// and the inheritable set and no `SECBIT_NO_CAP_AMBIENT_RAISE`; the
    /// bounding set is not asked, measured.
    pub fn cap_ambient(&mut self, op: u64, a3: u64, a4: u64, a5: u64) -> Result<c_int, c_int> {
        use caps::ambient;
        if op == ambient::CLEAR_ALL {
            if a3 | a4 | a5 != 0 {
                return Err(EINVAL);
            }
            self.caps.ambient = 0;
            return Ok(0);
        }
        if !cap_valid(a3) || a4 | a5 != 0 {
            return Err(EINVAL);
        }
        let b = 1u64 << a3;
        match op {
            ambient::IS_SET => Ok((self.caps.ambient & b != 0) as c_int),
            ambient::RAISE => {
                if self.caps.permitted & self.caps.inheritable & b == 0
                    || self.securebits & secure::mask(secure::NO_CAP_AMBIENT_RAISE) != 0
                {
                    return Err(EPERM);
                }
                self.caps.ambient |= b;
                Ok(0)
            }
            ambient::LOWER => {
                self.caps.ambient &= !b;
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    }

    pub fn keepcaps(&self) -> bool {
        self.securebits & secure::mask(secure::KEEP_CAPS) != 0
    }

    /// `PR_SET_KEEPCAPS`: 0 or 1, `EPERM` once `SECBIT_KEEP_CAPS_LOCKED`.
    /// The other arguments are not looked at, measured.
    pub fn set_keepcaps(&mut self, v: u64) -> Result<(), c_int> {
        if v > 1 {
            return Err(EINVAL);
        }
        if self.securebits & secure::locked(secure::KEEP_CAPS) != 0 {
            return Err(EPERM);
        }
        if v == 1 {
            self.securebits |= secure::mask(secure::KEEP_CAPS);
        } else {
            self.securebits &= !secure::mask(secure::KEEP_CAPS);
        }
        Ok(())
    }

    /// `PR_SET_SECUREBITS`; the rule is `caps::securebits_change`.
    pub fn set_securebits(&mut self, bits: u64) -> Result<(), c_int> {
        self.securebits = caps::securebits_change(self.securebits, bits, self.capable(CAP_SETPCAP))?;
        Ok(())
    }
}
