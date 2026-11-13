//! Resource limits and scheduling priority: the rules, separated from the state.
//!
//! `kernel/resource.c` keeps the locks, the task lookup and the host calls.
//! What is here is everything that is a decision about values — which resource
//! numbers exist, when a `setrlimit` is refused and with which errno, how a
//! nice value is clamped and encoded, and who may lower one. Each is a pure
//! function over integers, which is the whole reason to move it: these are the
//! parts a test can pin exactly, and they were the parts with no test at all.
//!
//! The errno values are guest errnos (`crates/util/errno`), negative, and are
//! returned as `Err(-EINVAL)` rather than as a sentinel in the value.

/// Guest errnos, negated as the syscall layer returns them.
pub use guest_errno::c_int_::{EACCES, EINVAL, EPERM};

pub use kernel_rlimitstate::{
    CORE, MEMLOCK, MSGQUEUE, NICE, NOFILE, NPROC, RTPRIO, SIGPENDING, STACK,
};
pub use kernel_rlimitstate::{INFINITY, Limits, NLIMITS, Rlimit};

pub const CPU: u32 = 0;
pub const FSIZE: u32 = 1;
pub const DATA: u32 = 2;
pub const RSS: u32 = 5;
pub const AS: u32 = 9;
pub const LOCKS: u32 = 10;
pub const RTTIME: u32 = 15;

/// Is `resource` one this kernel has?
pub fn resource_valid(resource: u32) -> bool {
    resource < NLIMITS
}

/// May `new` replace `old`?
///
/// Two independent refusals, and Linux reports them differently:
///
/// * A soft limit above the hard one is not a permission question — it is an
///   incoherent rlimit, and the answer is `EINVAL` **even for root**. Nothing
///   checked it, so a guest could store one and every later `rlimit()` read it
///   back.
/// * Raising the hard limit needs `CAP_SYS_RESOURCE`: `EPERM`. Lowering it is always
///   allowed, and is irreversible for an unprivileged caller — that is the
///   point of a hard limit.
pub fn check_set(sys_resource: bool, new: Rlimit, old: Rlimit) -> Result<(), i32> {
    if new.cur > new.max {
        return Err(EINVAL);
    }
    if !sys_resource && new.max > old.max {
        return Err(EPERM);
    }
    Ok(())
}

// ------------------------------------------------------------- priority

/// The nice range Linux accepts. Outside it, `setpriority` clamps rather than
/// refusing — an out-of-range nice is not an error.
pub const NICE_MIN: i32 = -20;
pub const NICE_MAX: i32 = 19;

pub fn clamp_nice(prio: i32) -> i32 {
    prio.clamp(NICE_MIN, NICE_MAX)
}

/// What `getpriority` returns for a given nice value.
///
/// `20 - nice`, so that every success is non-negative and cannot be mistaken
/// for an error return; the libc subtracts it back out. A nice of 19 — the
/// lowest priority — is therefore 1, and never 0, which would be ambiguous
/// with the errno the raw syscall reports.
pub fn to_getpriority(nice: i32) -> i32 {
    20 - nice
}

/// May the caller set the target group's nice to `prio`?
///
/// Linux's `set_one_prio` splits this into two refusals and reports them
/// differently, and a caller may well want to tell them apart:
///
/// * The target's real or effective uid must equal the caller's effective uid,
///   or the caller needs `CAP_SYS_NICE`. Otherwise `EPERM` — "not your
///   process".
/// * Separately, lowering the nice value below what the target already has
///   needs `CAP_SYS_NICE` too, and that one is `EACCES` — "not allowed to go
///   faster". Raising it, giving away priority, is always allowed.
///
/// Neither was checked. The comment that stood there said it did not matter
/// because "there are no capabilities here and the guest is root" — true when
/// it was written, and false once a guest could hold a real unprivileged uid.
///
/// `target_uid`/`target_euid` are `None` when the group has no leader left, in
/// which case there is nobody to compare against and only the nice check runs.
pub fn may_set_priority(
    sys_nice: bool,
    caller_euid: u32,
    target: Option<(u32, u32)>,
    prio: i32,
    target_nice: i32,
) -> Result<(), i32> {
    if sys_nice {
        return Ok(());
    }
    if let Some((uid, euid)) = target
        && caller_euid != uid
        && caller_euid != euid
    {
        return Err(EPERM);
    }
    if prio < target_nice {
        return Err(EACCES);
    }
    Ok(())
}

/// The calling task's **soft** limit for `resource`.
///
/// Here rather than in `crates/kernel/rescalls`, where it was: it is one field
/// read of the calling task and a call to [`rlimits_get`] just below, and
/// having it in the syscall crate made the descriptor table and the boot path
/// depend on the resource *syscalls* to ask how many descriptors they may
/// open -- `fs-fdobj` -> `kernel-rescalls` -> `kernel-taskcalls` ->
/// `fs-fdobj` was the cycle that came out of it.
///
/// Every caller passes a literal, so the only way this fails is a resource
/// number that does not exist, which is a bug in the caller rather than
/// something a guest can provoke.
///
/// **Asked on a guest thread**, and a panic on any other. It was `&*` of
/// `current_limits()`, which answers null with no task -- a null dereference
/// in a safe function, reachable by nothing today but a safe signature away
/// from anything that calls it. Four lines of an orphaned doc comment for a
/// function removed on 2026-09-16 sat on top of this one, with a `# Safety`
/// heading `clippy::unnecessary_safety_doc` found.
pub fn current_soft(resource: u32) -> u64 {
    taskview::with_current_group(|g| g.limits.soft(resource))
        .expect("current_soft is asked on a guest thread")
        .unwrap_or_else(|| panic!("invalid resource {resource}"))
}

/* `rlimits_get` and `rlimits_set` were here until 2026-09-16.
 *
 * `rlimits_get(t: *mut Limits, resource, out: *mut Rlimit) -> i32` wrapped
 * `Limits::get(resource) -> Option<Rlimit>`: an **out parameter** for the
 * value, an errno for the `None`, and a null check on a table every caller
 * reached as `&mut (*group).limits` -- the address of a field. All five
 * callers then rebuilt the option, three of them differently: `< 0` and fall
 * back, `== 0` and read, and one that ignored the answer and pushed whatever
 * default it had initialised the out-parameter with.
 *
 * `rlimits_set` was the same over `Limits::set(..) -> bool`.
 *
 * See `docs/changelog/2026-09-16-the-same-c-binding-one-crate-over.md` for the
 * class. */

#[cfg(test)]
mod tests;
