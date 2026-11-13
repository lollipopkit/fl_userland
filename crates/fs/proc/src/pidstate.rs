//! `/proc/<pid>/{io,personality,syscall,timerslack_ns}`: four entries that
//! report one value of the task each, measured by `procstate_probe`, with
//! who may read them measured by `procaccess_probe`.
//!
//! None of the four asks at `open`. Linux checks ptrace access when the file
//! is read -- `io` answers `EACCES` (`do_io_accounting`), `personality` and
//! `syscall` `EPERM` (`lock_trace`, which asks for attach) -- and
//! `timerslack_ns` asks `CAP_SYS_NICE` of anyone but the task itself, for
//! reading and for writing.

use std::ffi::c_int;
use std::fmt::Write as _;

use kernel_creds::PtraceMode;

use crate::ffi;
use crate::pidsnap::Found;

use guest_errno::c_int_::{EACCES, EINVAL, EPERM, ESRCH};

/// `/proc/<pid>/io`: the thread group's counters in the process's
/// directory, the thread's own in `task/<tid>`.
///
/// `read_bytes`, `write_bytes` and `cancelled_write_bytes` are block I/O,
/// which the host does and does not attribute to a guest task: 0, as Linux
/// answers for a task whose reads all hit the page cache.
pub(crate) fn io_show(entry: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    let Some(found) = Found::get(entry) else {
        return ESRCH;
    };
    let task = found.task();
    if !task.may_ptrace(PtraceMode::ReadFs) {
        return EACCES;
    }
    let io = if entry.meta.is_some_and(|m| m.in_thread_dir) {
        task.task().io.own()
    } else {
        // The departed threads', and every thread still in the group. A
        // zombie leader has left the list and is added on its own.
        let mut sum = task.task().io.gone();
        let mut leader_listed = false;
        for t in found.group().threads() {
            leader_listed |= t.pid() == task.pid();
            sum += t.task().io.own();
        }
        if !leader_listed {
            sum += task.task().io.own();
        }
        sum
    };
    drop(found);
    let text = format!(
        "rchar: {}\nwchar: {}\nsyscr: {}\nsyscw: {}\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n",
        io.rchar, io.wchar, io.syscr, io.syscw
    );
    buf.append(text.as_bytes());
    0
}

/// `/proc/<pid>/personality`: what `personality(0xffffffff)` answers there.
pub(crate) fn personality_show(entry: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    let Some(found) = Found::get(entry) else {
        return ESRCH;
    };
    let task = found.task();
    if !task.may_ptrace(PtraceMode::AttachFs) {
        return EPERM;
    }
    let persona = task.attr().personality();
    drop(found);
    buf.append(format!("{persona:08x}\n").as_bytes());
    0
}

/// `/proc/<pid>/syscall`: `task_current_syscall`'s answer.
///
/// - in a call: its number, the six argument registers, the stack pointer and
///   the pc after the `svc`, as the task published them on the way in
///   (`kernel_observe::SyscallState`);
/// - sitting out a group stop outside one: `-1`, the stack pointer and the pc;
/// - a zombie: `-1 0x0 0x0`, which is what a task with no stack answers;
/// - otherwise `running`.
///
/// One difference from Linux: a task that is computing inside a call it has
/// not slept in is `running` there and shows the call here. Nothing here
/// knows whether a host thread is on a processor.
pub(crate) fn syscall_show(entry: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    let Some(found) = Found::get(entry) else {
        return ESRCH;
    };
    let task = found.task();
    if !task.may_ptrace(PtraceMode::AttachFs) {
        return EPERM;
    }
    let zombie = task.is_zombie();
    let now = task.task().syscall.get();
    drop(found);
    let mut text = String::new();
    match now {
        _ if zombie => text.push_str("-1 0x0 0x0\n"),
        None => text.push_str("running\n"),
        Some(s) => {
            match s.nr {
                Some(nr) => {
                    let _ = write!(text, "{nr}");
                    for a in s.args {
                        let _ = write!(text, " {a:#x}");
                    }
                }
                None => text.push_str("-1"),
            }
            let _ = writeln!(text, " {:#x} {:#x}", s.sp, s.pc);
        }
    }
    buf.append(text.as_bytes());
    0
}

/// Linux's `timerslack_ns_{show,write}` test: the task itself, or
/// `CAP_SYS_NICE`. *Task*, not thread group: another
/// thread of the process asks the capability too.
fn may_slack(found: &Found) -> bool {
    found.task().pid() == taskview::current_pid() || taskview::capable(taskview::caps::CAP_SYS_NICE)
}

/// `/proc/<pid>/timerslack_ns`: `PR_GET_TIMERSLACK` of the task.
pub(crate) fn timerslack_show(entry: &mut ffi::proc_entry, buf: &mut ffi::proc_data) -> c_int {
    let Some(found) = Found::get(entry) else {
        return ESRCH;
    };
    if !may_slack(&found) {
        return EPERM;
    }
    let ns = found.task().attr().timer_slack();
    drop(found);
    buf.append(format!("{ns}\n").as_bytes());
    0
}

/// `PR_SET_TIMERSLACK` of the task, from a decimal number (`kstrtoull`, so a
/// sign, a non-digit or an empty write is `EINVAL`); 0 is the task's
/// default, the slack its parent had at the fork.
pub(crate) fn timerslack_update(entry: &mut ffi::proc_entry, data: &mut ffi::proc_data) -> c_int {
    let text = data.as_slice();
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    let Some(ns) = std::str::from_utf8(text).ok().filter(|t| !t.starts_with('-')).and_then(|t| t.parse::<u64>().ok())
    else {
        return EINVAL;
    };
    let Some(found) = Found::get(entry) else {
        return ESRCH;
    };
    if !may_slack(&found) {
        return EPERM;
    }
    found.task().with_attr_mut(|a| a.set_timer_slack(ns));
    0
}
