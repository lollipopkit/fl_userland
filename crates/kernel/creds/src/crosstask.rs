//! What one task may do to another: the credential halves of Linux's
//! cross-process checks, each measured by `tests/guest/src/bin/crossperm_probe.rs`.
//!
//! Linux has five rules, and the calls do not share one:
//!
//! | rule | calls |
//! | --- | --- |
//! | [`Creds::may_ptrace`] | `/proc/<pid>`, `process_vm_*`, `kcmp`, `pidfd_getfd`, `get_robust_list`, `process_madvise` |
//! | [`Creds::may_signal`] | `kill`, `pidfd_send_signal` |
//! | [`Creds::may_set_sched`] | `sched_setaffinity`, `sched_set{scheduler,param,attr}`, `setpriority` |
//! | [`Creds::may_set_ioprio`] | `ioprio_set` |
//! | [`Creds::may_prlimit`] | `prlimit64` on another task |
//!
//! Until 2026-11-13 each caller wrote its own: procfs had the ptrace rule
//! with the fs ids, and the syscalls compared effective uids and asked
//! neither the gids, nor the real ids, nor the target's dumpable flag; the
//! affinity, scheduler and ioprio calls asked nothing, and `get_robust_list`
//! refused every other task.
//!
//! The capability halves compare real sets: `CAP_SYS_PTRACE`, `CAP_KILL`,
//! `CAP_SYS_NICE` and `CAP_SYS_RESOURCE` in the caller's effective set, and
//! the target's permitted set against the caller's (`cap_ptrace_access_check`,
//! `cap_safe_nice`) -- which is what makes a process that dropped to uid 1000
//! but kept a saved uid of 0, and with it its permitted set, untouchable by
//! uid 1000. Until 2026-11-13 the sets were derived from the uids.

use super::Creds;
use crate::caps::{CAP_SYS_NICE, CAP_SYS_PTRACE, CAP_SYS_RESOURCE};

/// `PTRACE_MODE_*`: which of the caller's ids [`Creds::may_ptrace`] compares,
/// and whether it is asked for reading or for attaching.
///
/// Read and attach differ only under Yama, which this kernel does not have:
/// `kernel.yama.ptrace_scope` is 0 on the reference kernel, where no
/// relationship between the two processes is asked either. The mode is still
/// named at every call site, as Linux names it, so that adding Yama is one
/// match arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PtraceMode {
    /// `PTRACE_MODE_READ_FSCREDS`: `/proc/<pid>` and `process_madvise`.
    ReadFs,
    /// `PTRACE_MODE_READ_REALCREDS`: `kcmp`, `get_robust_list`.
    ReadReal,
    /// `PTRACE_MODE_ATTACH_FSCREDS`: `/proc/<pid>/mem`, `syscall`,
    /// `personality`, `stack`.
    AttachFs,
    /// `PTRACE_MODE_ATTACH_REALCREDS`: `process_vm_*`, `pidfd_getfd`.
    AttachReal,
}

impl PtraceMode {
    fn fs_creds(self) -> bool {
        matches!(self, PtraceMode::ReadFs | PtraceMode::AttachFs)
    }
}

impl Creds {
    /// `__ptrace_may_access` for a target outside the caller's thread group
    /// (that one is always allowed, and is the caller's to ask first).
    ///
    /// Three tests, each passed by `CAP_SYS_PTRACE` as well:
    /// - the caller's fs ids (`*Fs`) or real ids (`*Real`) equal all three of
    ///   the target's uids and all three of its gids;
    /// - the target is dumpable, `SUID_DUMP_USER` exactly (`dumpable` is
    ///   `true` for a target without an address space, which Linux does not
    ///   ask about);
    /// - `cap_ptrace_access_check`: the target's permitted capabilities are a
    ///   subset of the caller's effective set (`*Fs`) or permitted set
    ///   (`*Real`).
    pub fn may_ptrace(&self, target: &Creds, dumpable: bool, mode: PtraceMode) -> bool {
        if self.capable(CAP_SYS_PTRACE) {
            return true;
        }
        let (uid, gid, caps) = if mode.fs_creds() {
            (self.fsuid(), self.fsgid(), self.caps.effective)
        } else {
            (self.uid(), self.gid(), self.caps.permitted)
        };
        let ids = [target.uid(), target.euid(), target.suid()].iter().all(|&u| u == uid)
            && [target.gid(), target.egid(), target.sgid()].iter().all(|&g| g == gid);
        ids && dumpable && target.caps.permitted & !caps == 0
    }

    /// `cap_safe_nice`: the target's permitted capabilities are a subset of
    /// the caller's, or the caller has `CAP_SYS_NICE`. Asked after each of
    /// the scheduling calls' own id test.
    fn may_nice(&self, target: &Creds) -> bool {
        self.capable(CAP_SYS_NICE) || target.caps.permitted & !self.caps.permitted == 0
    }

    /// `sched_setaffinity`, `sched_setscheduler`, `sched_setparam`,
    /// `sched_setattr` and `setpriority` on another task: `check_same_owner`
    /// (the caller's effective uid is the target's real or effective one) or
    /// `CAP_SYS_NICE`, and then [`Creds::may_nice`]. `EPERM` otherwise.
    ///
    /// Lowering a nice value is a further test, the caller's.
    pub fn may_set_sched(&self, target: &Creds) -> bool {
        let owner = self.euid() == target.euid() || self.euid() == target.uid();
        (owner || self.capable(CAP_SYS_NICE)) && self.may_nice(target)
    }

    /// `set_task_ioprio`: the target's **real** uid is the caller's real or
    /// effective one, or `CAP_SYS_NICE`; then [`Creds::may_nice`].
    pub fn may_set_ioprio(&self, target: &Creds) -> bool {
        let owner = target.uid() == self.euid() || target.uid() == self.uid();
        (owner || self.capable(CAP_SYS_NICE)) && self.may_nice(target)
    }

    /// `check_prlimit_permission`: the caller's real uid and gid are all
    /// three of the target's, or `CAP_SYS_RESOURCE`. The ptrace ids without
    /// dumpable or the capability subset.
    pub fn may_prlimit(&self, target: &Creds) -> bool {
        self.capable(CAP_SYS_RESOURCE)
            || ([target.uid(), target.euid(), target.suid()].iter().all(|&u| u == self.uid())
                && [target.gid(), target.egid(), target.sgid()].iter().all(|&g| g == self.gid()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(uid: [u32; 3], gid: [u32; 3]) -> Creds {
        let mut c = Creds::default();
        c.setresgid(gid[0], gid[1], gid[2]).unwrap();
        c.setresuid(uid[0], uid[1], uid[2]).unwrap();
        c
    }

    const ROOT: [u32; 3] = [0; 3];
    const U: [u32; 3] = [1000; 3];

    /// The rows of `crossperm_probe` the rule decides, as the reference
    /// kernel answered them.
    #[test]
    fn ptrace_asks_six_ids_dumpable_and_the_permitted_set() {
        use PtraceMode::*;
        let user = creds(U, U);
        let root = creds(ROOT, ROOT);
        assert!(root.may_ptrace(&user, false, AttachReal), "CAP_SYS_PTRACE");
        assert!(!user.may_ptrace(&root, true, ReadFs));
        assert!(user.may_ptrace(&user, true, ReadFs));
        assert!(!user.may_ptrace(&user, false, ReadFs), "not dumpable");
        assert!(!user.may_ptrace(&creds(U, [1001; 3]), true, ReadFs), "another gid");
        assert!(!user.may_ptrace(&creds([1000, 1000, 0], U), true, ReadReal), "a saved uid of 0");
        let fs_only = creds([2000, 1000, 2000], [2000, 1000, 2000]);
        assert!(fs_only.may_ptrace(&user, true, ReadFs));
        assert!(!fs_only.may_ptrace(&user, true, AttachReal));
        let real_only = creds([1000, 2000, 1000], [1000, 2000, 1000]);
        assert!(!real_only.may_ptrace(&user, true, AttachFs));
        assert!(real_only.may_ptrace(&user, true, ReadReal));
    }

    #[test]
    fn the_scheduling_calls_ask_the_owner_and_the_permitted_set() {
        let user = creds(U, U);
        assert!(user.may_set_sched(&creds([2000, 1000, 2000], ROOT)), "the effective uid");
        assert!(!user.may_set_sched(&creds(ROOT, ROOT)));
        assert!(!user.may_set_sched(&creds([1000, 1000, 0], U)), "cap_safe_nice");
        let mut kept = Creds::default();
        kept.set_keepcaps(1).unwrap();
        kept.setresuid(1000, 1000, 1000).unwrap();
        assert!(!user.may_set_sched(&kept), "a kept permitted set, all uids 1000");
        assert!(!user.may_ptrace(&kept, true, PtraceMode::ReadReal));
        assert!(!creds([1000, 2000, 1000], U).may_set_sched(&user), "the caller's effective uid");
        assert!(user.may_set_sched(&creds(U, [1001; 3])), "no gid");
    }

    #[test]
    fn ioprio_asks_the_targets_real_uid() {
        let user = creds(U, U);
        assert!(!user.may_set_ioprio(&creds([2000, 1000, 2000], U)));
        assert!(creds([1000, 2000, 1000], U).may_set_ioprio(&user), "the caller's real uid");
        assert!(creds([2000, 1000, 2000], U).may_set_ioprio(&creds([2000, 1000, 2000], U)));
    }

    #[test]
    fn prlimit_asks_the_real_ids_and_not_dumpable() {
        let user = creds(U, U);
        assert!(user.may_prlimit(&user));
        assert!(!user.may_prlimit(&creds([1000, 1000, 0], U)));
        assert!(!user.may_prlimit(&creds(U, [1001; 3])));
        assert!(!creds([2000, 1000, 2000], [2000, 1000, 2000]).may_prlimit(&user));
        assert!(creds([1000, 2000, 1000], [1000, 2000, 1000]).may_prlimit(&user));
    }
}
