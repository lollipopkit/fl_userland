//! `fanotify_init(2)` and `fanotify_mark(2)`.

use std::collections::HashMap;
use std::ffi::{CStr, c_int};
use std::sync::Mutex;

use guest_errno::Errno;
use strace::strace;
use taskview::ffi;
use usercopy::GuestMem;

const FAN_CLOEXEC: u32 = 0x0000_0001;
const FAN_NONBLOCK: u32 = 0x0000_0002;
const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
const FAN_CLASS_CONTENT: u32 = 0x0000_0004;
const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
const FAN_CLASS_MASK: u32 = 0x0000_000c;
const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;
const FAN_UNLIMITED_MARKS: u32 = 0x0000_0020;
const FAN_ENABLE_AUDIT: u32 = 0x0000_0040;
const FAN_REPORT_PIDFD: u32 = 0x0000_0080;
const FAN_REPORT_TID: u32 = 0x0000_0100;
const FAN_REPORT_FID: u32 = 0x0000_0200;
const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;
const FAN_REPORT_NAME: u32 = 0x0000_0800;
const FAN_REPORT_TARGET_FID: u32 = 0x0000_1000;

const FAN_INIT_SUPPORTED: u32 = FAN_CLOEXEC
    | FAN_NONBLOCK
    | FAN_CLASS_MASK
    | FAN_UNLIMITED_QUEUE
    | FAN_UNLIMITED_MARKS
    | FAN_ENABLE_AUDIT
    | FAN_REPORT_PIDFD
    | FAN_REPORT_TID
    | FAN_REPORT_FID
    | FAN_REPORT_DIR_FID
    | FAN_REPORT_NAME
    | FAN_REPORT_TARGET_FID;

const FAN_MARK_ADD: u32 = 0x0000_0001;
const FAN_MARK_REMOVE: u32 = 0x0000_0002;
const FAN_MARK_FLUSH: u32 = 0x0000_0080;
const FAN_MARK_DONT_FOLLOW: u32 = 0x0000_0004;
const FAN_MARK_ONLYDIR: u32 = 0x0000_0008;
const FAN_MARK_MOUNT: u32 = 0x0000_0010;
const FAN_MARK_IGNORED_MASK: u32 = 0x0000_0020;
const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x0000_0040;
const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;
const FAN_MARK_IGNORE: u32 = 0x0000_0400;

const FAN_MARK_ALL_FLAGS: u32 = FAN_MARK_ADD
    | FAN_MARK_REMOVE
    | FAN_MARK_FLUSH
    | FAN_MARK_DONT_FOLLOW
    | FAN_MARK_ONLYDIR
    | FAN_MARK_MOUNT
    | FAN_MARK_IGNORED_MASK
    | FAN_MARK_IGNORED_SURV_MODIFY
    | FAN_MARK_FILESYSTEM
    | FAN_MARK_IGNORE;

const AT_FDCWD: c_int = -100;

struct FanotifyState {
    _flags: u32,
    _event_f_flags: u32,
    marks: Mutex<HashMap<Vec<u8>, u64>>,
}

struct FanotifyOps;

impl ffi::FdOps for FanotifyOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::STREAM
    }

    fn read(&self, _fd: &ffi::fd, _buf: &mut [u8]) -> isize {
        guest_errno::isize_::EAGAIN
    }

    fn poll(&self, _fd: &ffi::fd) -> Option<c_int> {
        Some(0)
    }

    fn close(&self, fd: &mut ffi::fd) -> c_int {
        drop(fd.take_driver_state::<FanotifyState>());
        0
    }
}

static FANOTIFY_OPS: FanotifyOps = FanotifyOps;

pub fn sys_fanotify_init(flags: u32, event_f_flags: u32) -> Result<i64, Errno> {
    strace!("fanotify_init({flags:#x}, {event_f_flags:#x})");
    if flags & !FAN_INIT_SUPPORTED != 0 {
        return Err(Errno::EINVAL);
    }
    let class = flags & FAN_CLASS_MASK;
    if !matches!(class, FAN_CLASS_NOTIF | FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT) {
        return Err(Errno::EINVAL);
    }
    let unpriv_fid = class == FAN_CLASS_NOTIF && (flags & (FAN_REPORT_FID | FAN_REPORT_DIR_FID)) != 0;
    if !unpriv_fid && !taskview::capable(taskview::caps::CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }

    let allowed_event_flags = ffi::O_ACCMODE_
        | ffi::O_CLOEXEC_
        | ffi::O_NONBLOCK_
        | ffi::O_APPEND_
        | 0o010000 // O_DSYNC
        | 0o100000 // O_LARGEFILE
        | 0o1000000 // O_NOATIME
        | 0o4010000; // O_SYNC
    if event_f_flags & !allowed_event_flags != 0
        || (event_f_flags & ffi::O_ACCMODE_) == ffi::O_ACCMODE_
    {
        return Err(Errno::EINVAL);
    }

    let mut fd = fs_adhoc::adhoc_anon(Some(&FANOTIFY_OPS), Some(c"[fanotify]"));
    fd.set_driver_state(Box::new(FanotifyState {
        _flags: flags,
        _event_f_flags: event_f_flags,
        marks: Mutex::new(HashMap::new()),
    }));

    let mut fd_flags = 0;
    if flags & FAN_CLOEXEC != 0 {
        fd_flags |= ffi::O_CLOEXEC_ as c_int;
    }
    if flags & FAN_NONBLOCK != 0 {
        fd_flags |= ffi::O_NONBLOCK_ as c_int;
    }
    Errno::split(fs_fdobj::f_install(fd.into_owned(), fd_flags) as i64)
}

pub fn sys_fanotify_mark(
    fanotify_fd: c_int,
    flags: u32,
    mask: u64,
    dirfd: c_int,
    pathname_addr: u64,
) -> Result<(), Errno> {
    strace!("fanotify_mark({fanotify_fd}, {flags:#x}, {mask:#x}, {dirfd}, {pathname_addr:#x})");
    if flags & !FAN_MARK_ALL_FLAGS != 0 {
        return Err(Errno::EINVAL);
    }
    let op = flags & (FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH);
    if op.count_ones() != 1 {
        return Err(Errno::EINVAL);
    }
    let fd = fs_fdobj::f_get(fanotify_fd).ok_or(Errno::EBADF)?;
    let state = fd.driver_state::<FanotifyState>().ok_or(Errno::EBADF)?;

    if op == FAN_MARK_FLUSH {
        state.marks.lock().unwrap_or_else(|e| e.into_inner()).clear();
        return Ok(());
    }
    if mask == 0 {
        return Err(Errno::EINVAL);
    }

    let resolved = if pathname_addr == 0 {
        if dirfd < 0 {
            return Err(Errno::EBADF);
        }
        let target_fd = fs_fdobj::f_get(dirfd).ok_or(Errno::EBADF)?;
        let mut buf = vec![0u8; ffi::MAX_PATH as usize + 1];
        let err = fs_generic::generic_getpath(&target_fd, &mut buf);
        if err < 0 {
            return Err(Errno::from_negative_or_eio(err));
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        buf.truncate(len);
        buf
    } else {
        let mut raw = [0u8; ffi::MAX_PATH as usize + 1];
        GuestMem
            .read_string(pathname_addr, &mut raw)
            .map_err(Errno::from_negative_or_eio)?;
        let cpath = CStr::from_bytes_until_nul(&raw).unwrap_or(c"");
        let dir_owned = if dirfd == AT_FDCWD || cpath.to_bytes().starts_with(b"/") {
            None
        } else {
            Some(fs_fdobj::f_get(dirfd).ok_or(Errno::EBADF)?)
        };
        let at = match dir_owned.as_deref() {
            Some(f) => ffi::At::Fd(f),
            None => ffi::At::Pwd,
        };
        let follow = flags & FAN_MARK_DONT_FOLLOW == 0;
        let mut st = ffi::statbuf::default();
        let err = fs_generic::generic_statat(at, cpath, &mut st, follow);
        if err < 0 {
            return Err(Errno::from_negative_or_eio(err));
        }
        if flags & FAN_MARK_ONLYDIR != 0 && (st.mode & ffi::S_IFMT) != ffi::S_IFDIR {
            return Err(Errno::ENOTDIR);
        }
        let walk = if follow {
            ffi::N_SYMLINK_FOLLOW
        } else {
            ffi::N_SYMLINK_NOFOLLOW
        };
        fs_generic::normalize::resolve(at, cpath.to_bytes(), walk as c_int)
            .map_err(Errno::from_negative_or_eio)?
            .path
    };

    let mut marks = state.marks.lock().unwrap_or_else(|e| e.into_inner());
    match op {
        FAN_MARK_ADD => {
            let entry = marks.entry(resolved).or_insert(0);
            *entry |= mask;
        }
        FAN_MARK_REMOVE => {
            if let Some(entry) = marks.get_mut(&resolved) {
                *entry &= !mask;
                if *entry == 0 {
                    marks.remove(&resolved);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fanotify_flag_masks_cover_standard_modes() {
        assert_ne!(FAN_INIT_SUPPORTED & FAN_CLOEXEC, 0);
        assert_ne!(FAN_INIT_SUPPORTED & FAN_REPORT_FID, 0);
        assert_ne!(FAN_MARK_ALL_FLAGS & FAN_MARK_ADD, 0);
    }
}
