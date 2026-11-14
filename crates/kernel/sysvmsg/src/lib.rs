//! System V message queues: `msgget`, `msgsnd`, `msgrcv`, `msgctl`.
//!
//! All four were `syscall_stub`, so `ipcs -q` said "kernel not configured for
//! message queues". The other half of what that one report named; the
//! semaphores are `crates/kernel/sysvsem` and what the two share is
//! `crates/kernel/sysvipc`.
//!
//! # The selector is in [`plan`] and the waiting is here
//!
//! Which message a `msgrcv` takes is a pure function of the types in the queue,
//! so it is testable without a queue -- and it is the one part of this family
//! that a reasonable reading gets wrong. See [`plan`].
//!
//! # A woken receiver rechecks rather than takes
//!
//! Every send wakes every parked receiver, because a send cannot know which of
//! them was waiting for that type. Each then looks again and parks if the
//! message is not for it. The alternative -- handing the message to whoever was
//! woken -- gives a receiver waiting for type 7 a message of type 3, and
//! `sysvmsg_probe` checks exactly that: a send of the wrong type leaves the
//! receiver parked *and* leaves the message in the queue.
//!
//! # `E2BIG` leaves the message and `MSG_NOERROR` removes it
//!
//! A receiver whose buffer is too small gets `E2BIG` and the queue is
//! unchanged, so it can ask again with a bigger one. With `MSG_NOERROR` it gets
//! the truncated message and the rest is **gone** -- measured, and the
//! asymmetry is the point: one is a retryable error and the other is a choice.

#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::VecDeque;
use std::ffi::c_int;
use std::sync::{Arc, Mutex};

use strace::strace;
use sysvipc::{Errno, may, may_control};
use usercopy::GuestMem;
use util_guestlock::GuestLock;

pub mod plan;

/// The one condition: the queue changed.
const CHANGED: u32 = 0;

struct Msg {
    mtype: i64,
    text: Vec<u8>,
}

struct QueueState {
    perm: sysvipc::Perm,
    msgs: VecDeque<Msg>,
    /// Bytes held, which is the sum of the texts and is what `IPC_STAT`
    /// reports as `msg_cbytes`.
    cbytes: usize,
    /// The limit, which `IPC_SET` may raise with `CAP_SYS_RESOURCE` and lower for
    /// anyone who may control the queue.
    qbytes: usize,
    stime: i64,
    rtime: i64,
    ctime: i64,
    lspid: i32,
    lrpid: i32,
    removed: bool,
}

struct Queue {
    state: GuestLock<QueueState>,
}

/// The calling task's IPC namespace's table.
fn table() -> Arc<Mutex<sysvipc::Registry<Queue>>> {
    taskview::current_ipc().part()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn creds() -> (Caller, u32, u32) {
    // With no task this dereferenced null; it answers what `capable` and
    // `current_fsids` answer for one now.
    let (euid, egid) = taskview::with_current_creds(|c| (c.euid(), c.egid())).unwrap_or((0, 0));
    let caller = Caller {
        ipc_owner: taskview::capable(taskview::caps::CAP_IPC_OWNER),
        sys_admin: taskview::capable(taskview::caps::CAP_SYS_ADMIN),
        sys_resource: taskview::capable(taskview::caps::CAP_SYS_RESOURCE),
    };
    (caller, euid, egid)
}

/// The capabilities the rules ask: `CAP_IPC_OWNER` for access, `CAP_SYS_ADMIN`
/// for `IPC_SET` and `IPC_RMID`, `CAP_SYS_RESOURCE` past a limit.
#[derive(Clone, Copy)]
struct Caller {
    ipc_owner: bool,
    sys_admin: bool,
    sys_resource: bool,
}

fn find(id: i32, want: u16) -> Result<Arc<Queue>, Errno> {
    let q = table()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(id)
        .ok_or(Errno::EINVAL)?;
    let (caller, euid, egid) = creds();
    let s = q.state.lock();
    if s.removed {
        return Err(Errno::EIDRM);
    }
    let perm = s.perm;
    drop(s);
    may(&perm, caller.ipc_owner, euid, egid, want)?;
    Ok(q)
}

// ------------------------------------------------------------------- msgget

pub fn sys_msgget(key: i32, flags: c_int) -> Result<i64, Errno> {
    strace!("msgget({key:#x}, {flags:#o})");
    let f = sysvipc::get_flags(flags);
    let (caller, euid, egid) = creds();
    let table = table();
    let mut t = table.lock().unwrap_or_else(|e| e.into_inner());

    if key != sysvipc::IPC_PRIVATE {
        if let Some((id, q)) = t.by_key(key) {
            if f.create && f.exclusive {
                return Err(Errno::EEXIST);
            }
            let perm = q.state.lock().perm;
            may(&perm, caller.ipc_owner, euid, egid, f.mode >> 6)?;
            return Ok(id as i64);
        }
        if !f.create {
            return Err(Errno::ENOENT);
        }
    }
    if t.len() >= plan::MSGMNI {
        return Err(Errno::ENOSPC);
    }
    let state = QueueState {
        perm: sysvipc::Perm::new(key, euid, egid, f.mode),
        msgs: VecDeque::new(),
        cbytes: 0,
        qbytes: plan::MSGMNB,
        stime: 0,
        rtime: 0,
        ctime: now(),
        lspid: 0,
        lrpid: 0,
        removed: false,
    };
    Ok(t.insert(key, Queue { state: GuestLock::new(state, 1) }) as i64)
}

mod operations;
pub use operations::{sys_msgrcv, sys_msgsnd};

// ------------------------------------------------------------------- msgctl

/// `struct msqid_ds`: 120 bytes. Measured from musl's headers in an arm64
/// container -- `perm@0 stime@48 rtime@56 ctime@64 cbytes@72 qnum@80
/// qbytes@88 lspid@96 lrpid@100`.
const MSQID_DS_LEN: usize = 120;

/// `struct msginfo`: seven ints and a short.
const MSGINFO_LEN: usize = 32;

const MSG_STAT: c_int = 11;
const MSG_INFO: c_int = 12;
const MSG_STAT_ANY: c_int = 13;

fn msqid_ds(s: &QueueState) -> [u8; MSQID_DS_LEN] {
    let mut b = [0u8; MSQID_DS_LEN];
    sysvipc::write_perm(&mut b, &s.perm);
    b[48..56].copy_from_slice(&s.stime.to_le_bytes());
    b[56..64].copy_from_slice(&s.rtime.to_le_bytes());
    b[64..72].copy_from_slice(&s.ctime.to_le_bytes());
    b[72..80].copy_from_slice(&(s.cbytes as u64).to_le_bytes());
    b[80..88].copy_from_slice(&(s.msgs.len() as u64).to_le_bytes());
    b[88..96].copy_from_slice(&(s.qbytes as u64).to_le_bytes());
    b[96..100].copy_from_slice(&s.lspid.to_le_bytes());
    b[100..104].copy_from_slice(&s.lrpid.to_le_bytes());
    b
}

fn msginfo(used_queues: usize, used_bytes: usize, counts: bool) -> [u8; MSGINFO_LEN] {
    let mut b = [0u8; MSGINFO_LEN];
    let fields = [
        if counts { used_bytes as i32 } else { 0 },  // msgpool
        if counts { used_queues as i32 } else { 0 }, // msgmap
        plan::MSGMAX as i32,
        plan::MSGMNB as i32,
        plan::MSGMNI as i32,
        16,                  // msgssz
        plan::MSGMNI as i32, // msgtql
    ];
    for (i, v) in fields.iter().enumerate() {
        b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    b[28..30].copy_from_slice(&0u16.to_le_bytes()); // msgseg
    b
}

pub fn sys_msgctl(id: i32, cmd: c_int, buf: u64) -> Result<i64, Errno> {
    strace!("msgctl({id}, {cmd}, {buf:#x})");

    // The three that do not take an id: `IPC_INFO` and `MSG_INFO` take none,
    // and `MSG_STAT` takes an **index** into the live queues. `ipcs -q` uses
    // the last two and nothing else, so a crate that answers the other five
    // perfectly still reports "not configured" without them -- which is what
    // happened to the semaphores beside this one.
    match cmd {
        sysvipc::IPC_INFO | MSG_INFO => {
            let table = table();
            let t = table.lock().unwrap_or_else(|e| e.into_inner());
            let ids = t.ids();
            let bytes: usize = ids
                .iter()
                .filter_map(|i| t.get(*i))
                .map(|q| q.state.lock().cbytes)
                .sum();
            let info = msginfo(ids.len(), bytes, cmd == MSG_INFO);
            drop(t);
            if GuestMem.write(buf, &info) != 0 {
                return Err(Errno::EFAULT);
            }
            return Ok(ids.len().saturating_sub(1) as i64);
        }
        MSG_STAT | MSG_STAT_ANY => {
            let ids = table().lock().unwrap_or_else(|e| e.into_inner()).ids();
            let Some(real) = ids.get(id as usize).copied() else {
                return Err(Errno::EINVAL);
            };
            let q = find(real, if cmd == MSG_STAT { sysvipc::READ } else { 0 })?;
            let bytes = msqid_ds(&q.state.lock());
            if GuestMem.write(buf, &bytes) != 0 {
                return Err(Errno::EFAULT);
            }
            return Ok(real as i64);
        }
        _ => {}
    }

    let want = match cmd {
        sysvipc::IPC_STAT => sysvipc::READ,
        sysvipc::IPC_SET | sysvipc::IPC_RMID => 0,
        _ => return Err(Errno::EINVAL),
    };
    let q = find(id, want)?;
    let (caller, euid, _) = creds();
    let mut s = q.state.lock();

    match cmd {
        sysvipc::IPC_STAT => {
            let bytes = msqid_ds(&s);
            if GuestMem.write(buf, &bytes) != 0 {
                Err(Errno::EFAULT)
            } else {
                Ok(0)
            }
        }
        sysvipc::IPC_SET => {
            may_control(&s.perm, caller.sys_admin, euid)?;
            let mut b = [0u8; MSQID_DS_LEN];
            if GuestMem.read(buf, &mut b) != 0 {
                return Err(Errno::EFAULT);
            }
            let Some((uid, gid, mode)) = sysvipc::read_perm_update(&b) else {
                return Err(Errno::EFAULT);
            };
            let qbytes = u64::from_le_bytes(b[88..96].try_into().unwrap()) as usize;
            // Raising the limit past the default is CAP_SYS_RESOURCE's; lowering
            // it is anyone's who may control the queue. Linux's check, and the
            // reason it is here rather than in `plan` is that it needs the
            // caller's privilege as well as the number.
            if qbytes > plan::MSGMNB && !caller.sys_resource {
                return Err(Errno::EPERM);
            }
            s.perm.uid = uid;
            s.perm.gid = gid;
            s.perm.mode = mode;
            s.qbytes = qbytes;
            s.ctime = now();
            drop(s);
            // A raised limit may be room a parked sender was waiting for.
            q.state.notify(CHANGED);
            Ok(0)
        }
        sysvipc::IPC_RMID => {
            may_control(&s.perm, caller.sys_admin, euid)?;
            let key = s.perm.key;
            s.removed = true;
            drop(s);
            table()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(id, key);
            q.state.notify(CHANGED);
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

#[cfg(test)]
mod tests {
    /// The wire sizes, which are the contract with a guest's headers.
    #[test]
    fn the_struct_sizes_are_musls() {
        assert_eq!(super::MSQID_DS_LEN, 120);
        assert_eq!(sysvipc::IPC_PERM_LEN, 48);
        // qbytes is where IPC_SET reads a new limit from and where IPC_STAT
        // writes the old one: 88, not 80, which is qnum.
        assert_eq!(88 + 8, 96);
    }
}
