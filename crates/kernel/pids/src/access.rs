//! `ptrace_may_access`, for every caller that asks it about a task found
//! under `pids_lock`: `/proc/<pid>` and the syscalls `kernel_creds::PtraceMode`
//! lists. The credential half is `kernel_creds::Creds::may_ptrace`; this adds
//! what only a task has, its thread group and its dumpable flag.

use kernel_creds::PtraceMode;
use taskview::ffi::TgroupId;

use crate::Task;

/// `SUID_DUMP_USER`, the one value that lets another user in.
/// `SUID_DUMP_ROOT` (2) keeps everyone but `CAP_SYS_PTRACE` out, as 0 does.
const SUID_DUMP_USER: std::ffi::c_int = 1;

impl Task<'_> {
    /// Whether this task is in the calling task's thread group: Linux's
    /// `same_thread_group(task, current)`.
    pub fn is_in_callers_group(&self) -> bool {
        let Some(group) = self.group() else { return false };
        taskview::with_current_group(|g| TgroupId::of(g) == group.id()).unwrap_or(false)
    }

    /// `ptrace_may_access(task, mode)` for the calling task: its own thread
    /// group always, anyone else by [`kernel_creds::Creds::may_ptrace`].
    ///
    /// Dumpable is the process's; a zombie has no address space to be
    /// dumpable about, and Linux does not ask (`task->mm` is NULL).
    pub fn may_ptrace(&self, mode: PtraceMode) -> bool {
        if self.is_in_callers_group() {
            return true;
        }
        let dumpable = self.is_zombie()
            || self.group().is_none_or(|g| g.tgroup().attr.dumpable() == SUID_DUMP_USER);
        taskview::with_current_creds(|mine| mine.may_ptrace(self.creds(), dumpable, mode)).unwrap_or(false)
    }
}
