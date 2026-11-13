//! Scheduling, affinity, priority, and processor queries.

use super::*;
use kernel_pids::{Group, Task};

/// The task a scheduling or affinity call names, with the lock held.
///
/// `0` is the caller. Anything else has to be *found*: every one of these calls
/// used to ignore the argument, so `sched_getscheduler(99999)` answered
/// `SCHED_OTHER` for a process that does not exist and `sched_getparam(-1, p)`
/// wrote a priority into it. A syscall that reports success for a target that
/// is not there is the silent kind of wrong answer.
fn target(guard: &PidsGuard, pid: c_int) -> Result<Task<'_>, Errno> {
    if pid < 0 {
        return Err(Errno::EINVAL);
    }
    let found = if pid == 0 { guard.me() } else { guard.find_live(pid) };
    found.ok_or(Errno::ESRCH)
}

/// `check_same_owner` and `cap_safe_nice`: whether the caller may change how
/// `task` is scheduled. `EPERM` otherwise. Always true of the caller itself.
fn may_set_sched(task: &Task<'_>) -> Result<(), Errno> {
    if taskview::with_current_creds(|mine| mine.may_set_sched(task.creds())).unwrap_or(false) {
        Ok(())
    } else {
        Err(Errno::EPERM)
    }
}

/// The largest `cpu_set_t` this reports through, in bytes.
const CPU_MASK_BYTES: usize = (schedabi::MASK_BITS / 8) as usize;

pub fn sys_sched_getaffinity(
    pid: c_int,
    cpusetsize: c_uint,
    cpuset_addr: u64,
) -> Result<i64, Errno> {
    strace!("sched_getaffinity({pid}, {cpusetsize}, {cpuset_addr:#x})");
    let cpus = sched_online_cpus();
    // The size and the two length rules are crates/kernel/schedabi -- a wire
    // format with a length rule, which is the combination this tree keeps
    // finding defects in, and both of the ones here were length rules.
    if !schedabi::getaffinity_len_ok(cpusetsize as u64, cpus) {
        return Err(Errno::EINVAL);
    }
    let bytes = (schedabi::mask_bytes(cpus) as usize).min(cpusetsize as usize);

    let mask = target(&PidsGuard::take(), pid)?.cpu_affinity();
    // A task that has never asked is allowed everything. Set lazily rather than
    // at creation so a task copied from another inherits its parent's, which is
    // what Linux does.
    let mask = if mask == 0 {
        sched_all_cpus_mask()
    } else {
        mask
    };

    let mut cpuset = [0u8; CPU_MASK_BYTES];
    schedabi::encode(mask, cpus, &mut cpuset);
    if GuestMem.write(cpuset_addr, &cpuset[..bytes]) != 0 {
        return Err(Errno::EFAULT);
    }
    // The number of bytes written, as Linux returns.
    Ok(bytes as i64)
}

pub fn sys_sched_setaffinity(
    pid: c_int,
    cpusetsize: c_uint,
    cpuset_addr: u64,
) -> Result<(), Errno> {
    strace!("sched_setaffinity({pid}, {cpusetsize}, {cpuset_addr:#x})");
    if cpusetsize == 0 {
        return Err(Errno::EINVAL);
    }
    // Only the first eight bytes can name a processor this reports, and a
    // caller's cpu_set_t is usually 128 bytes of which the rest is zero. Read
    // what fits and ignore the rest, which is what Linux does for bits above
    // the ones it has.
    let mut cpuset = [0u8; CPU_MASK_BYTES];
    let to_read = (cpusetsize as usize).min(CPU_MASK_BYTES);
    if GuestMem.read(cpuset_addr, &mut cpuset[..to_read]) != 0 {
        return Err(Errno::EFAULT);
    }
    // A mask naming no processor this kernel has is EINVAL rather than a thread
    // that may run nowhere.
    let requested = schedabi::decode(&cpuset[..to_read]);
    let mask = schedabi::setaffinity_mask(requested, sched_all_cpus_mask())
        .map_err(Errno::from_negative_or_eio)?;

    let guard = PidsGuard::take();
    let task = target(&guard, pid)?;
    may_set_sched(&task)?;
    task.set_cpu_affinity(mask);
    // Stored and reported, not enforced: the host does the scheduling and is
    // not told. A program that pins itself and reads the mask back is no longer
    // contradicted, which is what it can actually observe.
    Ok(())
}

const PRIO_PROCESS: c_int = 0;
const PRIO_PGRP: c_int = 1;
const PRIO_USER: c_int = 2;

/// The group `which`/`who` names, with the lock held.
///
/// `who` of 0 means the caller's own, which is the only form anything uses in
/// practice. `PRIO_USER` is not distinguished from the calling process: it
/// would mean walking every task in the system to find the ones with a matching
/// uid, and there is one uid here.
///
/// TODO: revisit if the emulator ever grows real users.
///
/// `ESRCH` for a task with no group as well as for no task. That arm answered
/// a null group until 2026-09-30, which both callers dereferenced; a task
/// `find_live` returns has one, so it was not reached.
fn priority_target(guard: &PidsGuard, which: c_int, who: c_int) -> Result<Group<'_>, Errno> {
    if which != PRIO_PROCESS && which != PRIO_PGRP && which != PRIO_USER {
        return Err(Errno::EINVAL);
    }
    let task = if who == 0 || which == PRIO_USER {
        guard.me()
    } else {
        guard.find_live(who)
    };
    task.and_then(|t| t.group()).ok_or(Errno::ESRCH)
}

pub fn sys_getpriority(which: c_int, who: c_int) -> Result<i64, Errno> {
    strace!("getpriority({which}, {who})");
    let nice = priority_target(&PidsGuard::take(), which, who)?.nice();
    Ok(rlimit::to_getpriority(nice) as i64)
}

pub fn sys_setpriority(which: c_int, who: c_int, prio: c_int) -> Result<(), Errno> {
    strace!("setpriority({which}, {who}, {prio})");
    let prio = rlimit::clamp_nice(prio);
    let privileged = taskview::capable(taskview::caps::CAP_SYS_NICE);
    let caller_euid = taskview::with_current_creds(kernel_creds::Creds::euid).unwrap_or(0);

    let guard = PidsGuard::take();
    let group = priority_target(&guard, which, who)?;
    // The leader's ids, or `None` when every thread has exited and the leader
    // has been reaped -- which the rule treats as "no owner to compare
    // against" rather than as a refusal.
    let leader = group.leader_task();
    let ids = leader.map(|t| (t.creds().uid(), t.creds().euid()));
    rlimit::may_set_priority(privileged, caller_euid, ids, prio, group.nice())
        .map_err(Errno::from_negative_or_eio)?;
    // `security_task_setnice`, after the two above.
    if let Some(t) = leader {
        may_set_sched(&t)?;
    }
    group.set_nice(prio);
    Ok(())
}

/// The only scheduling policy this implements. A guest asking to *be* run under
/// any other is told so rather than quietly run under this one.
///
/// The policies Linux knows, and the priority range each one has.
///
/// A guest cannot be *scheduled* under any of these but `SCHED_OTHER`, and
/// [`sys_sched_setscheduler`] says so. Asking what a policy's range *is* is a
/// different question, and it is one a program asks before it decides whether
/// to try: `pthread_attr_setschedparam` validates against these, and musl's
/// `sched_get_priority_max` is a straight syscall. Answering `EINVAL` for
/// `SCHED_FIFO` tells a caller the policy does not exist, which is not what
/// this kernel means and not what Linux answers.
///
/// The numbers are Linux's and are not a choice: 1..99 for the two real-time
/// policies and 0..0 for everything else. `tests/guest/src/bin/atcall_probe.rs`
/// is what compares them against a real kernel.
const SCHED_RANGES: &[(c_int, i64, i64)] = &[
    (0, 0, 0),  // SCHED_OTHER
    (1, 99, 1), // SCHED_FIFO
    (2, 99, 1), // SCHED_RR
    (3, 0, 0),  // SCHED_BATCH
    (5, 0, 0),  // SCHED_IDLE
    (6, 0, 0),  // SCHED_DEADLINE
];

/// Whether the pid a scheduling call names exists. See [`target`].
fn sched_check_pid(pid: c_int) -> Result<(), Errno> {
    let guard = PidsGuard::take();
    target(&guard, pid).map(|_| ())
}

pub fn sys_sched_getparam(pid: c_int, param_addr: u64) -> Result<(), Errno> {
    strace!("sched_getparam({pid}, {param_addr:#x})");
    // A null param is EINVAL and comes before the lookup, as in the setter.
    if param_addr == 0 || pid < 0 {
        return Err(Errno::EINVAL);
    }
    sched_check_pid(pid)?;
    if GuestMem.write(param_addr, &0i32.to_le_bytes()) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

pub fn sys_sched_getscheduler(pid: c_int) -> Result<i64, Errno> {
    strace!("sched_getscheduler({pid})");
    let attr = target(&PidsGuard::take(), pid)?.attr();
    let reset = if attr.sched_reset_on_fork() { SCHED_RESET_ON_FORK } else { 0 };
    Ok(i64::from(attr.sched_policy() | reset))
}

/// `SCHED_RESET_ON_FORK`, the bit `sched_setscheduler` takes in `policy` and
/// `sched_getscheduler` reports there.
const SCHED_RESET_ON_FORK: c_int = 0x4000_0000;

/// The priority a `SCHED_OTHER` thread may be given, which is one value.
///
/// Shared by `sched_setscheduler` and `sched_setparam`, because Linux's
/// `do_sched_setscheduler` is one function that the second calls with the
/// policy left alone.
///
/// **The order is Linux's and is observable**: a null param is `EINVAL` rather
/// than `EFAULT`, checked before anything is copied or looked up, and the task
/// is found before the priority is judged — so a bad priority at a pid that
/// does not exist is `ESRCH`. A real kernel answered `EINVAL` where this said
/// `EFAULT`, which is how the order came to be written down.
fn sched_set_priority(pid: c_int, param_addr: u64) -> Result<(), Errno> {
    if param_addr == 0 || pid < 0 {
        return Err(Errno::EINVAL);
    }
    let mut b = [0u8; 4];
    if GuestMem.read(param_addr, &mut b) != 0 {
        return Err(Errno::EFAULT);
    }
    let guard = PidsGuard::take();
    let task = target(&guard, pid)?;
    if i32::from_le_bytes(b) != 0 {
        return Err(Errno::EINVAL);
    }
    may_set_sched(&task)
}

/// The three non-realtime policies are accepted and remembered; the realtime
/// ones are refused.
///
/// `SCHED_BATCH` and `SCHED_IDLE` need no privilege, their only legal
/// `sched_priority` is 0, and what they change is how the scheduler weights a
/// runnable task — nothing a guest can observe directly, which is why
/// remembering and reporting is the whole of the contract. Refusing them was
/// also inconsistent with [`sys_sched_get_priority_max`] two functions down,
/// which has known both since it was written.
///
/// `SCHED_FIFO`, `SCHED_RR` and `SCHED_DEADLINE` stay `EINVAL`, and the
/// difference is not arbitrary: they promise *preemption*, which a guest thread
/// running as an ordinary host thread cannot be given, and a program told it
/// has `SCHED_FIFO` would build on a guarantee that is not there. Linux with
/// no `CAP_SYS_NICE` answers `EPERM` for those; this answers `EINVAL`, because
/// here it is the policy that is missing rather than the privilege.
pub fn sys_sched_setscheduler(
    pid: c_int,
    policy: c_int,
    param_addr: u64,
) -> Result<(), Errno> {
    strace!("sched_setscheduler({pid}, {policy}, {param_addr:#x})");
    // The flag rides in the policy word here and in `sched_flags` for
    // `sched_setattr`; Linux takes it off before it looks at the policy.
    let reset = policy & SCHED_RESET_ON_FORK != 0;
    let policy = policy & !SCHED_RESET_ON_FORK;
    if !kernel_procattr::sched_policy_supported(policy) {
        return Err(Errno::EINVAL);
    }
    // The priority and the target, in Linux's order -- see `sched_set_priority`.
    sched_set_priority(pid, param_addr)?;
    let guard = PidsGuard::take();
    let task = target(&guard, pid)?;
    task.with_attr_mut(|a| {
        a.set_sched_policy(policy);
        a.set_sched_reset_on_fork(reset);
    });
    Ok(())
}

/// `struct sched_attr`, which is versioned by its first word.
mod attr {
    /// Through `sched_period`: the struct 3.14 shipped with.
    pub const SIZE_VER0: usize = 48;
    /// Through `sched_util_max`, and this kernel's size.
    pub const SIZE_VER1: usize = 56;
    /// `PAGE_SIZE`, the most `sched_copy_attr` will read.
    pub const SIZE_MAX: usize = 4096;

    pub const FLAG_RESET_ON_FORK: u64 = 0x01;
    pub const FLAG_KEEP_POLICY: u64 = 0x08;
    pub const FLAG_KEEP_PARAMS: u64 = 0x10;
    pub const FLAG_UTIL_CLAMP: u64 = 0x20 | 0x40;
    /// `SCHED_FLAG_ALL`.
    pub const FLAG_ALL: u64 = 0x7f;

    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct SchedAttr {
        pub policy: u32,
        pub flags: u64,
        pub nice: i32,
        pub priority: u32,
    }

    impl SchedAttr {
        /// From the caller's bytes, at least `SIZE_VER0` of them.
        pub fn decode(b: &[u8]) -> SchedAttr {
            let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
            SchedAttr {
                policy: u32_at(4),
                flags: u64::from_le_bytes(b[8..16].try_into().unwrap()),
                nice: u32_at(16) as i32,
                priority: u32_at(20),
            }
        }

        /// The kernel's struct, `SIZE_VER1` bytes, with `size` in its first
        /// word. `sched_util_min`/`_max` are 0: there is no utilisation
        /// clamping here, and a 7.2 kernel without `CONFIG_UCLAMP_TASK`
        /// reports 0 for both, measured.
        pub fn encode(&self, size: u32) -> [u8; SIZE_VER1] {
            let mut b = [0u8; SIZE_VER1];
            b[0..4].copy_from_slice(&size.to_le_bytes());
            b[4..8].copy_from_slice(&self.policy.to_le_bytes());
            b[8..16].copy_from_slice(&self.flags.to_le_bytes());
            b[16..20].copy_from_slice(&self.nice.to_le_bytes());
            b[20..24].copy_from_slice(&self.priority.to_le_bytes());
            b
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_struct_round_trips_through_linuxs_offsets() {
            let a = SchedAttr { policy: 3, flags: FLAG_RESET_ON_FORK, nice: -3, priority: 0 };
            let b = a.encode(SIZE_VER1 as u32);
            assert_eq!(&b[0..4], &56u32.to_le_bytes());
            assert_eq!(SchedAttr::decode(&b), a);
        }
    }
}

/// `sched_getattr(2)`: the policy, its flags and the nice value, in a struct
/// the caller says the size of.
///
/// Measured on 7.2: a size below 48 or above a page, a non-zero `flags`, a
/// null pointer and a negative pid are all `EINVAL`; the `size` written back
/// is the smaller of the caller's and the kernel's 56, and a longer struct's
/// tail is zeroed.
pub fn sys_sched_getattr(pid: c_int, attr_addr: u64, size: c_uint, flags: c_uint) -> Result<(), Errno> {
    strace!("sched_getattr({pid}, {attr_addr:#x}, {size}, {flags:#x})");
    let size = size as usize;
    if attr_addr == 0 || pid < 0 || !(attr::SIZE_VER0..=attr::SIZE_MAX).contains(&size) || flags != 0 {
        return Err(Errno::EINVAL);
    }
    let (thread, nice) = {
        let guard = PidsGuard::take();
        let task = target(&guard, pid)?;
        let nice = task.group().map_or(0, Group::nice);
        (task.attr(), nice)
    };
    let a = attr::SchedAttr {
        policy: thread.sched_policy() as u32,
        flags: if thread.sched_reset_on_fork() { attr::FLAG_RESET_ON_FORK } else { 0 },
        nice,
        priority: 0,
    };
    // `copy_struct_to_user`: this kernel's struct, and zeroes for the part of
    // a newer caller's that it does not know. Measured: 7.2 clears the tail
    // of a 72-byte struct, which a program allocating the size it named has
    // room for.
    let n = size.min(attr::SIZE_VER1);
    let mut out = vec![0u8; size];
    out[..n].copy_from_slice(&a.encode(n as u32)[..n]);
    if GuestMem.write(attr_addr, &out) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// `sched_setattr(2)`: `sched_setscheduler` and `setpriority` in one call,
/// with the flags 3.14 added.
///
/// The policies are `sched_setscheduler`'s -- the three non-realtime ones;
/// see `kernel_procattr::ThreadAttr::sched_policy` for why the realtime ones
/// are refused -- and the nice value is `setpriority`'s, with its privilege
/// rule and its clamp. `SCHED_FLAG_UTIL_CLAMP_*` is `EOPNOTSUPP`, which a 7.2
/// kernel without `CONFIG_UCLAMP_TASK` answers, measured.
///
/// The size rules are `sched_copy_attr`'s: 0 means the first published
/// struct; below that or past a page is `E2BIG` with this kernel's size
/// written back, and so is a struct longer than this kernel's whose tail is
/// not zero.
pub fn sys_sched_setattr(pid: c_int, attr_addr: u64, flags: c_uint) -> Result<(), Errno> {
    strace!("sched_setattr({pid}, {attr_addr:#x}, {flags:#x})");
    if attr_addr == 0 || pid < 0 || flags != 0 {
        return Err(Errno::EINVAL);
    }
    let mut word = [0u8; 4];
    if GuestMem.read(attr_addr, &mut word) != 0 {
        return Err(Errno::EFAULT);
    }
    let too_big = || {
        if GuestMem.write(attr_addr, &(attr::SIZE_VER1 as u32).to_le_bytes()) != 0 {
            return Errno::EFAULT;
        }
        Errno::E2BIG
    };
    let size = match u32::from_le_bytes(word) as usize {
        0 => attr::SIZE_VER0,
        s if !(attr::SIZE_VER0..=attr::SIZE_MAX).contains(&s) => return Err(too_big()),
        s => s,
    };
    let mut bytes = vec![0u8; size.max(attr::SIZE_VER1)];
    if GuestMem.read(attr_addr, &mut bytes[..size]) != 0 {
        return Err(Errno::EFAULT);
    }
    if bytes[attr::SIZE_VER1..].iter().any(|&b| b != 0) {
        return Err(too_big());
    }
    let a = attr::SchedAttr::decode(&bytes);
    if (a.policy as i32) < 0 || a.flags & !attr::FLAG_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    if a.flags & attr::FLAG_UTIL_CLAMP != 0 {
        if size < attr::SIZE_VER1 {
            return Err(Errno::EINVAL);
        }
        return Err(Errno::EOPNOTSUPP);
    }
    let keep_policy = a.flags & attr::FLAG_KEEP_POLICY != 0;
    let keep_params = a.flags & attr::FLAG_KEEP_PARAMS != 0;

    let privileged = taskview::capable(taskview::caps::CAP_SYS_NICE);
    let caller_euid = taskview::with_current_creds(kernel_creds::Creds::euid).unwrap_or(0);
    let guard = PidsGuard::take();
    let task = target(&guard, pid)?;
    let policy = if keep_policy { task.attr().sched_policy() } else { a.policy as c_int };
    if !kernel_procattr::sched_policy_supported(policy) {
        return Err(Errno::EINVAL);
    }
    // A non-realtime policy has no priority, and 0 is the only one.
    if !keep_params && a.priority != 0 {
        return Err(Errno::EINVAL);
    }
    may_set_sched(&task)?;
    if !keep_params {
        let group = task.group().ok_or(Errno::ESRCH)?;
        let nice = rlimit::clamp_nice(a.nice);
        let leader = group.leader_task().map(|t| (t.creds().uid(), t.creds().euid()));
        rlimit::may_set_priority(privileged, caller_euid, leader, nice, group.nice())
            .map_err(Errno::from_negative_or_eio)?;
        group.set_nice(nice);
    }
    // With KEEP_POLICY the policy *and* its reset-on-fork flag are the
    // thread's own: Linux's `SETPARAM_POLICY` path reads both back from the
    // task. Measured: RESET_ON_FORK, then KEEP_POLICY without it, still
    // reports the flag.
    task.with_attr_mut(|t| {
        t.set_sched_policy(policy);
        if !keep_policy {
            t.set_sched_reset_on_fork(a.flags & attr::FLAG_RESET_ON_FORK != 0);
        }
    });
    Ok(())
}

/// `sched_setparam`: the policy is whatever the thread already has, which here
/// is always `SCHED_OTHER`.
///
/// It was a stub, so a program that set a priority without changing the policy
/// — which is what every `SCHED_OTHER` user does — got `ENOSYS` from a call
/// that cannot fail on Linux for a valid argument.
pub fn sys_sched_setparam(pid: c_int, param_addr: u64) -> Result<(), Errno> {
    strace!("sched_setparam({pid}, {param_addr:#x})");
    sched_set_priority(pid, param_addr)
}

/// The highest priority a policy allows. See [`SCHED_RANGES`].
pub fn sys_sched_get_priority_max(policy: c_int) -> Result<i64, Errno> {
    strace!("sched_get_priority_max({policy})");
    match SCHED_RANGES.iter().find(|(p, _, _)| *p == policy) {
        Some((_, max, _)) => Ok(*max),
        None => Err(Errno::EINVAL),
    }
}

/// The lowest, likewise.
pub fn sys_sched_get_priority_min(policy: c_int) -> Result<i64, Errno> {
    strace!("sched_get_priority_min({policy})");
    match SCHED_RANGES.iter().find(|(p, _, _)| *p == policy) {
        Some((_, _, min)) => Ok(*min),
        None => Err(Errno::EINVAL),
    }
}

/// The round-robin quantum, which a `SCHED_OTHER` thread does not have:
/// Linux's `get_rr_interval_fair` answers zero for any policy but `SCHED_RR`,
/// and the call still succeeds. It was a stub, and a caller reading `ENOSYS`
/// cannot tell that from "there is no such process".
pub fn sys_sched_rr_get_interval(pid: c_int, interval_addr: u64) -> Result<(), Errno> {
    strace!("sched_rr_get_interval({pid}, {interval_addr:#x})");
    sched_check_pid(pid)?;
    // A `struct timespec`: two 64-bit zeroes.
    if GuestMem.write(interval_addr, &[0u8; 16]) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// Which processor this thread is on, for a guest that shards by it.
///
/// **There is no honest answer**: a guest thread is a host thread and the host
/// schedules it, and macOS will not even say where. What callers use this for
/// is picking a per-cpu shard — glibc's malloc arena, jemalloc's tcache, a
/// per-cpu counter — and for that what matters is that different threads get
/// different answers and one thread's answer does not move about. So it is
/// derived from the thread id and restricted to the processors the thread's
/// affinity mask allows.
///
/// A caller using it to *verify* an affinity would be misled, and nothing does:
/// `sched_getaffinity` is that question.
///
/// It was a stub, so glibc's `sched_getcpu()` failed and every thread picked
/// shard zero.
pub fn sys_getcpu(cpu_addr: u64, node_addr: u64, _tcache: u64) -> Result<(), Errno> {
    strace!("getcpu({cpu_addr:#x}, {node_addr:#x})");
    let mask = PidsGuard::take().me().map_or(0, |t| t.cpu_affinity());
    let pid = taskview::current_pid();
    let mask = if mask == 0 {
        sched_all_cpus_mask()
    } else {
        mask
    };

    let cpus = sched_online_cpus();
    // The nth allowed processor, counting from the thread id.
    let allowed = (0..cpus).filter(|i| mask & (1u64 << i) != 0).count() as u32;
    let want = if allowed == 0 {
        0
    } else {
        (pid as u32) % allowed
    };
    let cpu = (0..cpus)
        .filter(|i| mask & (1u64 << i) != 0)
        .nth(want as usize)
        .unwrap_or(0);

    if cpu_addr != 0 && GuestMem.write(cpu_addr, &cpu.to_le_bytes()) != 0 {
        return Err(Errno::EFAULT);
    }
    // One NUMA node, which is what a machine with one memory system has.
    if node_addr != 0 && GuestMem.write(node_addr, &0u32.to_le_bytes()) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}
