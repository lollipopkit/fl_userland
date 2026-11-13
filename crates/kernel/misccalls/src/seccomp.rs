//! `seccomp(2)`, and `PR_SET_SECCOMP`/`PR_GET_SECCOMP`, its older spelling.
//!
//! The filter engine and the per-task state are `crates/kernel/seccomp`; the
//! check on every syscall is `crates/kernel/syscalldispatch`'s. What is here is
//! installing one: reading the program out of the guest, the privilege rule,
//! and `SECCOMP_FILTER_FLAG_TSYNC`.
//!
//! Every answer below was measured on 7.2 by `tests/guest` `procsec_probe`.

use std::ffi::c_uint;
use std::sync::Arc;

use kernel_pids::PidsGuard;
use kernel_seccomp as sc;
use strace::strace;
use usercopy::GuestMem;

use guest_errno::Errno;

const SET_MODE_STRICT: c_uint = 0;
const SET_MODE_FILTER: c_uint = 1;
const GET_ACTION_AVAIL: c_uint = 2;
const GET_NOTIF_SIZES: c_uint = 3;

mod flag {
    pub const TSYNC: u32 = 1 << 0;
    pub const LOG: u32 = 1 << 1;
    pub const SPEC_ALLOW: u32 = 1 << 2;
    pub const TSYNC_ESRCH: u32 = 1 << 4;
    /// What this kernel takes. `NEW_LISTENER` (1 << 3) is not among them: there is no
    /// user-space notification here, and a listener descriptor that never
    /// delivered a notification would leave the filtered thread waiting for
    /// an answer nobody can give. It is `EINVAL`, which is what a kernel
    /// before 5.0 said, and `WAIT_KILLABLE_RECV` (1 << 5), which only qualifies it,
    /// is refused for the reason Linux refuses it alone.
    pub const SUPPORTED: u32 = TSYNC | LOG | SPEC_ALLOW | TSYNC_ESRCH;
}

/// `struct seccomp_notif_sizes`: what a supervisor allocates. Linux reports
/// them whether or not it could ever deliver a notification.
const NOTIF_SIZES: [u16; 3] = [80, 24, sc::DATA_SIZE as u16];

pub fn sys_seccomp(op: c_uint, flags: c_uint, args: u64) -> Result<i64, Errno> {
    strace!("seccomp({op}, {flags:#x}, {args:#x})");
    match op {
        SET_MODE_STRICT => {
            if flags != 0 || args != 0 {
                return Err(Errno::EINVAL);
            }
            set_strict().map(|()| 0)
        }
        SET_MODE_FILTER => set_filter(flags, args),
        GET_ACTION_AVAIL => {
            if flags != 0 {
                return Err(Errno::EINVAL);
            }
            let mut b = [0u8; 4];
            if GuestMem.read(args, &mut b) != 0 {
                return Err(Errno::EFAULT);
            }
            if sc::action_available(u32::from_le_bytes(b)) { Ok(0) } else { Err(Errno::EOPNOTSUPP) }
        }
        GET_NOTIF_SIZES => {
            if flags != 0 {
                return Err(Errno::EINVAL);
            }
            let b: Vec<u8> = NOTIF_SIZES.iter().flat_map(|s| s.to_le_bytes()).collect();
            if GuestMem.write(args, &b) != 0 {
                return Err(Errno::EFAULT);
            }
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// `PR_GET_SECCOMP`: the mode. A task in strict mode never gets here -- the
/// call is not one of its four.
pub fn prctl_get() -> Result<i64, Errno> {
    taskview::with_current_task(|t| t.seccomp.mode() as i64).ok_or(Errno::EINVAL)
}

/// `PR_SET_SECCOMP(mode, filter)`.
pub fn prctl_set(mode: u64, filter: u64) -> Result<i64, Errno> {
    match mode {
        1 => set_strict().map(|()| 0),
        2 => set_filter(0, filter),
        _ => Err(Errno::EINVAL),
    }
}

fn set_strict() -> Result<(), Errno> {
    taskview::with_current_task(|t| t.seccomp.set_strict()).ok_or(Errno::EINVAL)?
}

/// `seccomp_prepare_user_filter`: the program, out of the guest, validated.
fn read_program(addr: u64) -> Result<sc::Program, Errno> {
    // `struct sock_fprog`: a u16 length, padding, and a pointer.
    let mut head = [0u8; 16];
    if GuestMem.read(addr, &mut head) != 0 {
        return Err(Errno::EFAULT);
    }
    let len = u16::from_le_bytes([head[0], head[1]]) as usize;
    let ptr = u64::from_le_bytes(head[8..16].try_into().unwrap());
    if len == 0 || len > sc::MAX_INSNS {
        return Err(Errno::EINVAL);
    }
    // The privilege rule sits between the length check and the copy in
    // Linux's `seccomp_prepare_filter`, so it is here too: without
    // `no_new_privs`, only a caller that could have given itself the
    // privilege anyway may install a filter that changes what a setuid
    // program it then runs is allowed to do.
    let nnp = taskview::with_current_attr(|a| a.no_new_privs()).unwrap_or(false);
    if !nnp && !taskview::capable(taskview::caps::CAP_SYS_ADMIN) {
        return Err(Errno::EACCES);
    }
    let mut raw = vec![0u8; len * 8];
    if GuestMem.read(ptr, &mut raw) != 0 {
        return Err(Errno::EFAULT);
    }
    let insns: Vec<sc::Insn> = raw.as_chunks::<8>().0.iter().map(sc::Insn::decode).collect();
    sc::validate(&insns)
}

/// `seccomp_set_mode_filter`: 0, or with `TSYNC` the tid of a thread that
/// could not be synchronised.
fn set_filter(flags: c_uint, prog_addr: u64) -> Result<i64, Errno> {
    if flags & !flag::SUPPORTED != 0 {
        return Err(Errno::EINVAL);
    }
    let prog = read_program(prog_addr)?;
    let log = flags & flag::LOG != 0;

    // Under `pids_lock` from here: it is what `TSYNC` writes other threads'
    // slots under, and what keeps the threads it walks alive.
    let pids = PidsGuard::take();
    let me = pids.me().ok_or(Errno::ESRCH)?;
    let mine = &me.task().seccomp;
    if mine.mode() == sc::MODE_STRICT {
        return Err(Errno::EINVAL);
    }
    // SAFETY: `pids_lock` is held.
    let current = unsafe { mine.chain() };
    let filter = sc::Filter::new(prog, log, current.clone())?;

    if flags & flag::TSYNC != 0 {
        // Every other thread must be running this thread's filters or an
        // ancestor of them, so that replacing its chain only adds to it --
        // Linux's `seccomp_can_sync_threads`. The first that is not is the
        // answer, or `ESRCH` when the caller asked for that instead.
        let group = me.group().ok_or(Errno::ESRCH)?;
        for t in group.threads() {
            if t.raw() == me.raw() {
                continue;
            }
            let theirs = &t.task().seccomp;
            // SAFETY: `pids_lock` is held.
            let theirs_chain = unsafe { theirs.chain() };
            let ok = theirs.mode() != sc::MODE_STRICT
                && match (&theirs_chain, &current) {
                    (None, _) => true,
                    (Some(t), Some(c)) => c.descends_from(t),
                    (Some(_), None) => false,
                };
            if !ok {
                return if flags & flag::TSYNC_ESRCH != 0 { Err(Errno::ESRCH) } else { Ok(t.pid() as i64) };
            }
        }
        for t in group.threads() {
            if t.raw() != me.raw() {
                t.task().seccomp.install(Arc::clone(&filter))?;
            }
        }
    }
    mine.install(filter)?;
    Ok(0)
}
