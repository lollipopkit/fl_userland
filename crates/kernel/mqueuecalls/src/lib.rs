//! POSIX message queues: `mq_open`, `mq_unlink`, `mq_timedsend`,
//! `mq_timedreceive`, `mq_notify`, `mq_getsetattr`, and the descriptor they
//! hand out.
//!
//! All six were `syscall_stub`, so musl's `mq_open` answered `ENOSYS` and
//! every program built on them -- a POSIX-portable work queue, a test suite
//! probing for `_POSIX_MESSAGE_PASSING` -- took its fallback or stopped. The
//! queue and the numbers it is judged by are `crates/kernel/mqueue`; what is
//! here needs a task: the name space, the caller's credentials and umask, the
//! descriptor, and delivering a notification.
//!
//! Every errno and every ordering between two of them was measured against an
//! arm64 Linux 7.2 kernel by `tests/guest/src/bin/mqueue_probe.rs`; the
//! behaviour that needs two processes or a blocked thread is checked by
//! `mqueue_abi` on both.
//!
//! # The name space has no mount
//!
//! Linux keeps the queues on an internal `mqueue` mount per IPC namespace and
//! a guest may mount that filesystem anywhere -- a container runtime puts one
//! at `/dev/mqueue`. The name space is here, one per IPC namespace
//! (`crates/kernel/nsproxy`), but not the mount: `mount(2)` does not know the
//! type, and `/proc/filesystems` does not list it. That is the
//! shape of a kernel whose `mqueue` filesystem is not mountable rather than an
//! answer that is wrong: `/dev/mqueue` does not exist, which is what a bare
//! kernel's `/dev` has, and nothing a program does through the six syscalls
//! depends on it. Listing a queue with `ls /dev/mqueue` is what is lost.
//!
//! The descriptor still lives on a filesystem of its own, so `fstatfs` reports
//! `MQUEUE_MAGIC`, `fstat` a regular file whose mode, owner and size belong to
//! the queue (an `fchmod` through one descriptor is what the next `mq_open`
//! is checked against), and `/proc/<pid>/fd` reads `/<name>`, with
//! ` (deleted)` after an unlink.
//!
//! # Privilege
//!
//! `CAP_SYS_RESOURCE` (past `msg_max`, `msgsize_max` and `queues_max`) and
//! `CAP_FOWNER`/`CAP_DAC_OVERRIDE` (the sticky name space, the mode check) are
//! read as this kernel reads every capability: the effective uid for the
//! first, the fs uid for the other two. A container's root has no
//! `CAP_SYS_RESOURCE` and is limited where this one is not; the probe's limit
//! cases run as uid 65534 for that reason.
//!
//! # A registration goes with the owner's close
//!
//! Linux drops an `mq_notify` registration when the owning process closes
//! *any* descriptor of the queue -- a duplicate included -- because that is
//! `f_op->flush`, called by `filp_close` on every close and at exit. This is
//! [`ffi::FdOps::flush`], which exists for it. Without it a registration
//! outlived its owner: any other process got `EBUSY` for good.
//!
//! # What is not here
//!
//! - The exec check: Linux does not signal an owner that has exec'd since it
//!   registered. An exec closes every queue descriptor (they are always
//!   close-on-exec), which drops the registration first; one whose `FD_CLOEXEC`
//!   was cleared by hand keeps it across the exec here.
//! - `EMFILE` for a full descriptor table is reported after the name checks
//!   rather than before them; the queue a refused create made is removed again,
//!   so nothing is left behind.

#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use guest_errno::Errno;
use kernel_mqueue::abi::{self, Attr, Sigevent};
use kernel_mqueue::{Deadline, How, Inode, Queue, Registration};
use strace::strace;
use usercopy::GuestMem;

pub use taskview::ffi;

mod deliver;
mod descriptor;

use descriptor::Desc;

const O_ACCMODE: u32 = 3;
const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;
const O_NOCTTY: u32 = 0o400;
const O_TRUNC: u32 = 0o1000;
const O_NONBLOCK: u32 = 0o4000;
const S_IFREG: u32 = 0o100000;

/// The queue behind a name, and the bytes it is charged.
pub(crate) struct Mq {
    pub(crate) queue: Queue<fs_fdobj::Owned>,
    pub(crate) name: Vec<u8>,
    _charge: Charge,
}

// --------------------------------------------------------------- accounting

/// Live queues in one IPC namespace, an unlinked one still open included:
/// what `queues_max` counts -- Linux's `mq_queues_count`, per namespace.
#[derive(Default)]
struct Live(AtomicUsize);

fn live() -> Arc<Live> {
    taskview::current_ipc().part()
}

/// `RLIMIT_MSGQUEUE` bytes charged, per real uid -- Linux's `ucounts`, which
/// is per user and not per process: a fork's queues count against the same
/// total as its parent's.
static CHARGED: LazyLock<Mutex<HashMap<u32, u64>>> = LazyLock::new(Mutex::default);

/// One queue's share of its namespace's [`Live`] and of [`CHARGED`], given
/// back when the queue goes -- which is when it is unlinked and the last
/// descriptor closes.
struct Charge {
    live: Arc<Live>,
    uid: u32,
    bytes: u64,
}

impl Charge {
    fn take(live: Arc<Live>, uid: u32, bytes: u64, limit: u64) -> Result<Charge, Errno> {
        let mut charged = CHARGED.lock().unwrap_or_else(|e| e.into_inner());
        let used = charged.get(&uid).copied().unwrap_or(0);
        match used.checked_add(bytes) {
            Some(total) if total <= limit => charged.insert(uid, total),
            _ => return Err(Errno::EMFILE),
        };
        live.0.fetch_add(1, Ordering::Relaxed);
        Ok(Charge { live, uid, bytes })
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.live.0.fetch_sub(1, Ordering::Relaxed);
        let mut charged = CHARGED.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(used) = charged.get_mut(&self.uid) {
            *used -= self.bytes;
            if *used == 0 {
                charged.remove(&self.uid);
            }
        }
    }
}

// ---------------------------------------------------------------- the names

/// Name to queue, in one IPC namespace: Linux's per-namespace `mqueue`
/// mount. A std `Mutex`: nothing waits under it, and the only locks taken
/// inside it are a queue's own (the mode check) and the descriptor table's
/// (installing).
#[derive(Default)]
struct Names(Mutex<HashMap<Vec<u8>, Arc<Mq>>>);

/// The calling task's namespace's names.
fn names() -> Arc<Names> {
    taskview::current_ipc().part()
}

impl Names {
    fn lock(&self) -> MutexGuard<'_, HashMap<Vec<u8>, Arc<Mq>>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

static NEXT_INO: AtomicU64 = AtomicU64::new(1);

fn now() -> (i64, i64) {
    util_timeabi::host_clock(libc::CLOCK_REALTIME).unwrap_or((0, 0))
}

/// The caller's ids as the name space asks for them.
struct Caller {
    /// Real uid: who is charged, and the `si_uid` of a notification.
    uid: u32,
    fsuid: u32,
    fsgid: u32,
    /// `CAP_FOWNER`.
    fowner: bool,
}

fn caller() -> Caller {
    taskview::with_current_creds(|c| Caller {
        uid: c.uid(),
        fsuid: c.fsuid(),
        fsgid: c.fsgid(),
        fowner: c.capable(taskview::caps::CAP_FOWNER),
    })
    .unwrap_or(Caller { uid: 0, fsuid: 0, fsgid: 0, fowner: false })
}

/// The name, read and judged. `getname` copies it before anything else is
/// looked at, so a bad pointer is `EFAULT` whatever else is wrong.
fn read_name(addr: u64) -> Result<Vec<u8>, Errno> {
    let mut buf = vec![0u8; abi::PATH_MAX];
    let len = GuestMem.read_string(addr, &mut buf).map_err(Errno::from_negative_or_eio)?;
    buf.truncate(len);
    abi::check_name(&buf)?;
    Ok(buf)
}

fn read_bytes<const N: usize>(addr: u64) -> Result<[u8; N], Errno> {
    let mut b = [0u8; N];
    if GuestMem.read(addr, &mut b) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(b)
}

/// `oflag`'s access mode as the permission it needs. `None` for 3, which is
/// `EINVAL` on an existing queue and creates one nobody can use.
fn wanted(oflag: u32) -> Option<u32> {
    match oflag & O_ACCMODE {
        O_RDONLY => Some(4),
        O_WRONLY => Some(2),
        O_RDWR => Some(6),
        _ => None,
    }
}

/// What an `mq_open(oflag)` leaves in the description's flags: Linux's
/// `do_dentry_open` takes four out. Not `O_CLOEXEC` -- `F_GETFL` shows it, on
/// a descriptor that is close-on-exec whether it was asked for or not.
fn description_flags(oflag: u32) -> u32 {
    oflag & !(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC)
}

pub fn sys_mq_open(name_addr: u64, oflag: c_int, mode: u32, attr_addr: u64) -> Result<i64, Errno> {
    strace!("mq_open({name_addr:#x}, {oflag:#o}, {mode:#o}, {attr_addr:#x})");
    let oflag = oflag as u32;
    // The attr is copied first, whether or not it will be used: an unmapped
    // one is `EFAULT` even when the queue exists.
    let attr = match attr_addr {
        0 => None,
        a => Some(Attr::decode(&read_bytes::<{ abi::ATTR_LEN }>(a)?)),
    };
    let name = read_name(name_addr)?;
    let who = caller();

    let names = names();
    let mut table = names.lock();
    let (mq, created) = match table.get(&name) {
        Some(mq) => {
            if oflag & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
                return Err(Errno::EEXIST);
            }
            let want = wanted(oflag).ok_or(Errno::EINVAL)?;
            let inode = mq.queue.lock().inode;
            may(&inode, want)?;
            (Arc::clone(mq), false)
        }
        None => {
            if oflag & O_CREAT == 0 {
                return Err(Errno::ENOENT);
            }
            let mq = Arc::new(create(&name, mode, attr, &who)?);
            table.insert(name.clone(), Arc::clone(&mq));
            (mq, true)
        }
    };
    let fd = descriptor::describe(mq, description_flags(oflag));
    // Close-on-exec always: Linux's `do_mq_open` asks for a descriptor with
    // `O_CLOEXEC` whatever `oflag` says, and `F_GETFD` reads 1 either way.
    let n = fs_fdobj::f_install_start(fd, 0, true);
    if n < 0 {
        // A refused create leaves nothing behind. The table is still held, so
        // nobody else has seen the queue.
        if created {
            table.remove(&name);
        }
        return Err(Errno::from_negative_or_eio(n));
    }
    Ok(n as i64)
}

/// A new queue, in Linux's order of refusals: `queues_max` (`ENOSPC`), the
/// attr (`EINVAL`), then `RLIMIT_MSGQUEUE` (`EMFILE`).
fn create(name: &[u8], mode: u32, attr: Option<Attr>, who: &Caller) -> Result<Mq, Errno> {
    let privileged = taskview::capable(taskview::caps::CAP_SYS_RESOURCE);
    let live = live();
    if live.0.load(Ordering::Relaxed) >= abi::QUEUES_MAX && !privileged {
        return Err(Errno::ENOSPC);
    }
    let (maxmsg, msgsize) = match attr {
        Some(a) => (a.maxmsg, a.msgsize),
        None => (abi::MSG_DEFAULT, abi::MSGSIZE_DEFAULT),
    };
    let bytes = abi::charge(maxmsg, msgsize, privileged)?;
    let limit = kernel_rlimit::current_soft(ffi::RLIMIT_MSGQUEUE_);
    let charge = Charge::take(live, who.uid, bytes, limit)?;
    let perm = taskview::with_current_fs(|fs| fs.apply_umask(mode & 0o7777)).unwrap_or(mode & 0o7777);
    let t = now();
    let inode = Inode {
        ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mode: S_IFREG | perm,
        uid: who.fsuid,
        gid: who.fsgid,
        size: abi::FILENT_SIZE,
        linked: true,
        atime: t,
        mtime: t,
        ctime: t,
    };
    Ok(Mq {
        // Both bounded by `charge`: at most 65536 and 16 MiB.
        queue: Queue::new(maxmsg as usize, msgsize as usize, inode),
        name: name.to_vec(),
        _charge: charge,
    })
}

/// The mode check an existing queue's open makes, against the inode as it is
/// now. `want` is a mask of 4, 2, 1.
fn may(inode: &Inode, want: u32) -> Result<(), Errno> {
    taskview::with_current_creds(|c| c.access(inode.uid, inode.gid, inode.mode, want))
        .unwrap_or(Err(guest_errno::c_int_::EACCES))
        .map_err(Errno::from_negative_or_eio)
}

pub fn sys_mq_unlink(name_addr: u64) -> Result<(), Errno> {
    strace!("mq_unlink({name_addr:#x})");
    let name = read_name(name_addr)?;
    let who = caller();
    let names = names();
    let mut table = names.lock();
    let Some(mq) = table.get(&name) else {
        return Err(Errno::ENOENT);
    };
    {
        let mut s = mq.queue.lock();
        // The name space is a sticky directory owned by root: only the queue's
        // owner, the directory's (an fsuid of 0), or `CAP_FOWNER` removes a
        // name from it (`check_sticky`). Measured: uid 65534 unlinking root's
        // 0666 queue is `EPERM`.
        if !who.fowner && who.fsuid != 0 && who.fsuid != s.inode.uid {
            return Err(Errno::EPERM);
        }
        s.inode.linked = false;
        s.inode.ctime = now();
    }
    // The queue lives on for whoever holds it; the name goes now.
    let gone = table.remove(&name);
    drop(table);
    drop(gone);
    Ok(())
}

/// An `mq_*` call's descriptor: one of this crate's, or `EBADF`.
fn queue_fd(fd_no: c_int) -> Result<fs_fdobj::FdRef, Errno> {
    let fd = fs_fdobj::f_get(fd_no).ok_or(Errno::EBADF)?;
    if fd.driver_state::<Desc>().is_none() {
        return Err(Errno::EBADF);
    }
    Ok(fd)
}

fn desc(fd: &ffi::fd) -> &Desc {
    fd.driver_state::<Desc>().expect("checked by queue_fd")
}

/// An `O_PATH` description can do none of these, and access mode 3 neither.
fn readable(fd: &ffi::fd) -> bool {
    !fd.is_path_only() && matches!(fd.flags() & O_ACCMODE, O_RDONLY | O_RDWR)
}

fn writable(fd: &ffi::fd) -> bool {
    !fd.is_path_only() && matches!(fd.flags() & O_ACCMODE, O_WRONLY | O_RDWR)
}

/// The absolute deadline, read and validated before anything else: an
/// invalid one is `EINVAL` even on a call that would not have waited, and
/// even on a bad descriptor (`prepare_timeout` runs in the syscall wrapper).
fn read_deadline(addr: u64) -> Result<Option<Deadline>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let b = read_bytes::<16>(addr)?;
    let sec = i64::from_le_bytes(b[..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(b[8..].try_into().unwrap());
    if !util_timeabi::timespec_valid(sec, nsec) {
        return Err(Errno::EINVAL);
    }
    Ok(Some(Deadline { sec, nsec }))
}

/// `msg_prio` is an `unsigned int`: the register's high half is not looked
/// at (measured: a priority of `1 << 32` is accepted as 0).
pub fn sys_mq_timedsend(fd_no: c_int, msg_addr: u64, len: u64, prio: u32, ts_addr: u64) -> Result<(), Errno> {
    strace!("mq_timedsend({fd_no}, {msg_addr:#x}, {len}, {prio}, {ts_addr:#x})");
    let deadline = read_deadline(ts_addr)?;
    if prio >= abi::PRIO_MAX {
        return Err(Errno::EINVAL);
    }
    let fd = queue_fd(fd_no)?;
    if !writable(&fd) {
        return Err(Errno::EBADF);
    }
    let mq = &desc(&fd).mq;
    if len > mq.queue.msgsize as u64 {
        return Err(Errno::EMSGSIZE);
    }
    let mut msg = Vec::new();
    msg.try_reserve_exact(len as usize).map_err(|_| Errno::ENOMEM)?;
    msg.resize(len as usize, 0);
    if GuestMem.read(msg_addr, &mut msg) != 0 {
        return Err(Errno::EFAULT);
    }
    let nonblock = fd.flags() & O_NONBLOCK != 0;
    if let Some(d) = mq.queue.send(prio, msg, nonblock, deadline, now())? {
        deliver::deliver(d);
    }
    Ok(())
}

pub fn sys_mq_timedreceive(
    fd_no: c_int,
    buf_addr: u64,
    len: u64,
    prio_addr: u64,
    ts_addr: u64,
) -> Result<i64, Errno> {
    strace!("mq_timedreceive({fd_no}, {buf_addr:#x}, {len}, {prio_addr:#x}, {ts_addr:#x})");
    let deadline = read_deadline(ts_addr)?;
    let fd = queue_fd(fd_no)?;
    if !readable(&fd) {
        return Err(Errno::EBADF);
    }
    let mq = &desc(&fd).mq;
    // The buffer must hold the largest message the queue can have, not the
    // one at its head.
    if len < mq.queue.msgsize as u64 {
        return Err(Errno::EMSGSIZE);
    }
    let nonblock = fd.flags() & O_NONBLOCK != 0;
    let (prio, msg) = mq.queue.receive(nonblock, deadline, now())?;
    // The message is off the queue by now, and a fault on either copy loses
    // it. Linux does the same: measured, `curmsgs` drops by one.
    if prio_addr != 0 && GuestMem.write(prio_addr, &prio.to_le_bytes()) != 0 {
        return Err(Errno::EFAULT);
    }
    if GuestMem.write(buf_addr, &msg) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(msg.len() as i64)
}

/// `SIGEV_THREAD`'s half that comes before the descriptor is looked up: the
/// cookie (`EFAULT`), then the socket (`EBADF`, `ENOTSOCK`, `EINVAL`).
fn thread_registration(ev: &Sigevent) -> Result<How<fs_fdobj::Owned>, Errno> {
    let cookie = read_bytes::<{ abi::COOKIE_LEN }>(ev.value)?;
    let sock = fs_fdobj::f_get(ev.signo).ok_or(Errno::EBADF)?;
    fs_sock::netlink_of(&sock)?;
    Ok(How::Thread { sock: sock.retain(), cookie })
}

pub fn sys_mq_notify(fd_no: c_int, sev_addr: u64) -> Result<(), Errno> {
    strace!("mq_notify({fd_no}, {sev_addr:#x})");
    let how = match sev_addr {
        0 => None,
        a => {
            let ev = Sigevent::decode(&read_bytes::<{ abi::SIGEVENT_LEN }>(a)?);
            ev.check()?;
            Some(match ev.notify {
                abi::SIGEV_NONE => How::Nothing,
                abi::SIGEV_SIGNAL => How::Signal { signo: ev.signo, value: ev.value },
                _ => thread_registration(&ev)?,
            })
        }
    };
    // No access-mode check: a write-only descriptor registers, and so does
    // one opened with access mode 3.
    let fd = queue_fd(fd_no)?;
    let mq = &desc(&fd).mq;
    let tgid = taskview::current_tgid();
    let Some(how) = how else {
        if let Some(d) = mq.queue.unregister(tgid, Some(now())) {
            deliver::deliver(d);
        }
        return Ok(());
    };
    let owner = deliver::leader_ref().ok_or(Errno::ESRCH)?;
    match mq.queue.register(Registration { owner_tgid: tgid, owner, how }, now()) {
        Ok(()) => Ok(()),
        // The refused registration -- and a socket it holds -- drops here,
        // outside the queue's lock.
        Err((e, _refused)) => Err(e),
    }
}

pub fn sys_mq_getsetattr(fd_no: c_int, new_addr: u64, old_addr: u64) -> Result<(), Errno> {
    strace!("mq_getsetattr({fd_no}, {new_addr:#x}, {old_addr:#x})");
    let new = match new_addr {
        0 => None,
        a => Some(Attr::decode(&read_bytes::<{ abi::ATTR_LEN }>(a)?)),
    };
    // Only `O_NONBLOCK` is settable, and anything else is refused before the
    // descriptor is looked at.
    if new.is_some_and(|a| a.flags & !(O_NONBLOCK as i64) != 0) {
        return Err(Errno::EINVAL);
    }
    let fd = queue_fd(fd_no)?;
    let mq = &desc(&fd).mq;
    let mut old = mq.queue.attr();
    old.flags = (fd.flags() & O_NONBLOCK) as i64;
    if let Some(new) = new {
        // Through `F_SETFL`'s own path, so the two cannot disagree about what
        // the description's flags are.
        let current = fd.flags();
        let wanted = if new.flags != 0 { current | O_NONBLOCK } else { current & !O_NONBLOCK };
        let err = fs_fdobj::fd_setflags(&fd, wanted as c_int);
        if err < 0 {
            return Err(Errno::from_negative_or_eio(err));
        }
        let t = now();
        let mut s = mq.queue.lock();
        s.inode.atime = t;
        s.inode.ctime = t;
    }
    // Written after the change, so an unwritable `omqstat` is `EFAULT` with
    // the new flags already applied. Measured.
    if old_addr != 0 && GuestMem.write(old_addr, &old.encode()) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `F_GETFL` on `mq_open(O_RDWR | O_TRUNC | O_APPEND | O_NOCTTY)` reads
    /// `O_APPEND | O_RDWR`, and `O_CLOEXEC` stays (`mqueue_probe`).
    #[test]
    fn an_open_leaves_what_do_dentry_open_leaves() {
        assert_eq!(description_flags(O_RDWR | O_TRUNC | 0o2000 | O_NOCTTY), 0o2002);
        assert_eq!(description_flags(O_CREAT | O_EXCL | O_RDWR | 0o2000000), 0o2000002);
        assert_eq!(description_flags(O_NONBLOCK | O_RDONLY), O_NONBLOCK);
        assert_eq!(description_flags(3), 3);
    }

    #[test]
    fn access_mode_three_wants_something_nobody_can_have() {
        assert_eq!(wanted(O_RDONLY), Some(4));
        assert_eq!(wanted(O_WRONLY), Some(2));
        assert_eq!(wanted(O_RDWR), Some(6));
        assert_eq!(wanted(3), None);
        assert_eq!(wanted(O_CREAT | 3), None);
    }

    /// The charges go back: a queue dropped returns its bytes and its count.
    #[test]
    fn a_charge_is_given_back() {
        let live = Arc::new(Live::default());
        let a = Charge::take(Arc::clone(&live), 4242, 600, 1000).unwrap();
        assert_eq!(Charge::take(Arc::clone(&live), 4242, 401, 1000).err(), Some(Errno::EMFILE));
        let b = Charge::take(Arc::clone(&live), 4242, 400, 1000).unwrap();
        assert_eq!(live.0.load(Ordering::Relaxed), 2);
        drop(a);
        drop(b);
        assert_eq!(live.0.load(Ordering::Relaxed), 0);
        assert!(!CHARGED.lock().unwrap().contains_key(&4242));
        assert_eq!(Charge::take(Arc::clone(&live), 4242, 1001, 1000).err(), Some(Errno::EMFILE));
        assert!(!CHARGED.lock().unwrap().contains_key(&4242), "a refusal charges nothing");
        // A total that would wrap is a refusal, not a small number.
        let all = Charge::take(Arc::clone(&live), 4242, u64::MAX, u64::MAX).unwrap();
        assert_eq!(Charge::take(Arc::clone(&live), 4242, 1, u64::MAX).err(), Some(Errno::EMFILE));
        drop(all);
    }
}
