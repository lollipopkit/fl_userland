//! `io_uring_setup`, `io_uring_enter`, and `io_uring_register` in safe Rust
//! backed by kernel memfds.

use std::ffi::c_int;
use std::sync::{Arc, Mutex};

use guest_errno::Errno;
use strace::strace;
use taskview::ffi;
use usercopy::GuestMem;

const IORING_MAX_ENTRIES: u32 = 32768;
const IORING_MAX_CQ_ENTRIES: u32 = 2 * IORING_MAX_ENTRIES;

const IORING_SETUP_IOPOLL: u32 = 1 << 0;
const IORING_SETUP_SQPOLL: u32 = 1 << 1;
const IORING_SETUP_SQ_AFF: u32 = 1 << 2;
const IORING_SETUP_CQSIZE: u32 = 1 << 3;
const IORING_SETUP_CLAMP: u32 = 1 << 4;
const IORING_SETUP_ATTACH_WQ: u32 = 1 << 5;
const IORING_SETUP_R_DISABLED: u32 = 1 << 6;
const IORING_SETUP_SUBMIT_ALL: u32 = 1 << 7;
const IORING_SETUP_COOP_TASKRUN: u32 = 1 << 8;
const IORING_SETUP_TASKRUN_FLAG: u32 = 1 << 9;
const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;
const IORING_SETUP_NO_SQARRAY: u32 = 1 << 16;

const IORING_SETUP_SUPPORTED: u32 = IORING_SETUP_IOPOLL
    | IORING_SETUP_SQPOLL
    | IORING_SETUP_SQ_AFF
    | IORING_SETUP_CQSIZE
    | IORING_SETUP_CLAMP
    | IORING_SETUP_ATTACH_WQ
    | IORING_SETUP_R_DISABLED
    | IORING_SETUP_SUBMIT_ALL
    | IORING_SETUP_COOP_TASKRUN
    | IORING_SETUP_TASKRUN_FLAG
    | IORING_SETUP_SINGLE_ISSUER
    | IORING_SETUP_DEFER_TASKRUN
    | IORING_SETUP_NO_SQARRAY;

const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
const IORING_FEAT_NODROP: u32 = 1 << 1;
const IORING_FEAT_SUBMIT_STABLE: u32 = 1 << 2;
const IORING_FEAT_RW_CUR_POS: u32 = 1 << 3;
const IORING_FEAT_CUR_PERSONALITY: u32 = 1 << 4;
const IORING_FEAT_FAST_POLL: u32 = 1 << 5;
const IORING_FEAT_POLL_32BITS: u32 = 1 << 6;

const IORING_OFF_SQ_RING: i64 = 0;
const IORING_OFF_CQ_RING: i64 = 0x8000_000;
const IORING_OFF_SQES: i64 = 0x1000_0000;

const IORING_ENTER_GETEVENTS: u32 = 1 << 0;
const IORING_ENTER_SQ_WAKEUP: u32 = 1 << 1;
const IORING_ENTER_SQ_WAIT: u32 = 1 << 2;
const IORING_ENTER_EXT_ARG: u32 = 1 << 3;
const IORING_ENTER_REGISTERED_RING: u32 = 1 << 4;
const IORING_ENTER_SUPPORTED: u32 = IORING_ENTER_GETEVENTS
    | IORING_ENTER_SQ_WAKEUP
    | IORING_ENTER_SQ_WAIT
    | IORING_ENTER_EXT_ARG
    | IORING_ENTER_REGISTERED_RING;

const IORING_OP_NOP: u8 = 0;
const IORING_OP_READV: u8 = 1;
const IORING_OP_WRITEV: u8 = 2;
const IORING_OP_FSYNC: u8 = 3;
const IORING_OP_READ_FIXED: u8 = 4;
const IORING_OP_WRITE_FIXED: u8 = 5;
const IORING_OP_POLL_ADD: u8 = 6;
const IORING_OP_POLL_REMOVE: u8 = 7;
const IORING_OP_TIMEOUT: u8 = 11;
const IORING_OP_TIMEOUT_REMOVE: u8 = 12;
const IORING_OP_CLOSE: u8 = 19;
const IORING_OP_READ: u8 = 22;
const IORING_OP_WRITE: u8 = 23;

const IORING_REGISTER_BUFFERS: u32 = 0;
const IORING_UNREGISTER_BUFFERS: u32 = 1;
const IORING_REGISTER_FILES: u32 = 2;
const IORING_UNREGISTER_FILES: u32 = 3;
const IORING_REGISTER_EVENTFD: u32 = 4;
const IORING_UNREGISTER_EVENTFD: u32 = 5;
const IORING_REGISTER_FILES_UPDATE: u32 = 6;
const IORING_REGISTER_EVENTFD_ASYNC: u32 = 7;
const IORING_REGISTER_PROBE: u32 = 8;
const IORING_REGISTER_ENABLE_RINGS: u32 = 12;
const IORING_REGISTER_RING_FDS: u32 = 20;
const IORING_UNREGISTER_RING_FDS: u32 = 21;

const IOSQE_FIXED_FILE: u8 = 1 << 0;
const IOSQE_IO_LINK: u8 = 1 << 2;
const IOSQE_IO_HARDLINK: u8 = 1 << 3;

const PARAMS_SIZE: usize = 120;
const SQE_SIZE: usize = 64;
const CQE_SIZE: usize = 16;

// Fixed layout inside `rings_memfd`:
// [0..64): ring header fields
//   0: sq_head (u32)
//   4: sq_tail (u32)
//   8: sq_ring_mask (u32)
//  12: sq_ring_entries (u32)
//  16: sq_flags (u32)
//  20: sq_dropped (u32)
//  24: cq_head (u32)
//  28: cq_tail (u32)
//  32: cq_ring_mask (u32)
//  36: cq_ring_entries (u32)
//  40: cq_overflow (u32)
//  44: cq_flags (u32)
// [64 .. 64 + sq_entries * 4): sq_array
// [cqes_offset .. cqes_offset + cq_entries * 16): cqes
const RING_HEADER_BYTES: usize = 64;
const OFF_SQ_HEAD: usize = 0;
const OFF_SQ_TAIL: usize = 4;
const OFF_SQ_MASK: usize = 8;
const OFF_SQ_ENTRIES: usize = 12;
const OFF_SQ_FLAGS: usize = 16;
const OFF_SQ_DROPPED: usize = 20;
const OFF_CQ_HEAD: usize = 24;
const OFF_CQ_TAIL: usize = 28;
const OFF_CQ_MASK: usize = 32;
const OFF_CQ_ENTRIES: usize = 36;
const OFF_CQ_OVERFLOW: usize = 40;
const OFF_CQ_FLAGS: usize = 44;

struct UringState {
    sq_entries: u32,
    cq_entries: u32,
    no_sqarray: bool,
    sq_array_off: usize,
    cqes_off: usize,
    rings_memfd: fs_fdobj::Owned,
    sqes_memfd: fs_fdobj::Owned,
    poll_watchers: Arc<pollset::Watchers>,
    submit_lock: Mutex<()>,
    inner: Mutex<UringInner>,
}

struct UringInner {
    disabled: bool,
    registered_files: Vec<Option<fs_fdobj::Owned>>,
    registered_buffers: Vec<(u64, usize)>,
    eventfd: Option<Arc<fs_fdobj::Owned>>,
}

struct UringFdOps;

impl ffi::FdOps for UringFdOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::NONE
    }

    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        let state = fd.driver_state::<UringState>()?;
        let cq_head = read_u32(&state.rings_memfd, OFF_CQ_HEAD).ok()?;
        let cq_tail = read_u32(&state.rings_memfd, OFF_CQ_TAIL).ok()?;
        if cq_head != cq_tail {
            Some((fs_poll::bits::READ | fs_poll::bits::RDNORM) as c_int)
        } else {
            Some(0)
        }
    }

    unsafe fn mmap(
        &self,
        fd: &ffi::fd,
        mem: *mut ffi::mem,
        start: ffi::page_t,
        pages: ffi::pages_t,
        offset: i64,
        prot: c_int,
        flags: c_int,
    ) -> Option<c_int> {
        let state = fd.driver_state::<UringState>()?;
        let target = match offset {
            IORING_OFF_SQ_RING | IORING_OFF_CQ_RING => &state.rings_memfd,
            IORING_OFF_SQES => &state.sqes_memfd,
            _ => return Some(guest_errno::c_int_::EINVAL),
        };
        unsafe { target.ops?.mmap(target, mem, start, pages, 0, prot, flags) }
    }

    fn close(&self, fd: &mut ffi::fd) -> c_int {
        drop(fd.take_driver_state::<UringState>());
        0
    }
}

static URING_OPS: UringFdOps = UringFdOps;

fn page_align(n: usize) -> usize {
    let page = crate::abi::PAGE as usize;
    n.div_ceil(page) * page
}

fn memfd_pread(fd: &ffi::fd, offset: usize, out: &mut [u8]) -> Result<(), Errno> {
    let ops = fd.ops.ok_or(Errno::EIO)?;
    let n = ops.pread(fd, out, offset as i64);
    if n < 0 {
        return Err(Errno::from_negative_or_eio(n as i32));
    }
    if (n as usize) < out.len() {
        return Err(Errno::EIO);
    }
    Ok(())
}

fn memfd_pwrite(fd: &ffi::fd, offset: usize, data: &[u8]) -> Result<(), Errno> {
    let ops = fd.ops.ok_or(Errno::EIO)?;
    let n = ops.pwrite(fd, data, offset as i64);
    if n < 0 {
        return Err(Errno::from_negative_or_eio(n as i32));
    }
    if (n as usize) < data.len() {
        return Err(Errno::EIO);
    }
    Ok(())
}

fn read_u32(fd: &ffi::fd, offset: usize) -> Result<u32, Errno> {
    let mut b = [0u8; 4];
    memfd_pread(fd, offset, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn write_u32(fd: &ffi::fd, offset: usize, val: u32) -> Result<(), Errno> {
    memfd_pwrite(fd, offset, &val.to_le_bytes())
}

fn push_cqe(state: &UringState, user_data: u64, res: i32, flags: u32) -> Result<(), Errno> {
    let cq_head = read_u32(&state.rings_memfd, OFF_CQ_HEAD)?;
    let cq_tail = read_u32(&state.rings_memfd, OFF_CQ_TAIL)?;
    if cq_tail.wrapping_sub(cq_head) >= state.cq_entries {
        let overflow = read_u32(&state.rings_memfd, OFF_CQ_OVERFLOW)?;
        write_u32(&state.rings_memfd, OFF_CQ_OVERFLOW, overflow.saturating_add(1))?;
        return Ok(());
    }
    let cq_mask = state.cq_entries - 1;
    let slot = (cq_tail & cq_mask) as usize;
    let off = state.cqes_off + slot * CQE_SIZE;
    let mut cqe = [0u8; CQE_SIZE];
    cqe[0..8].copy_from_slice(&user_data.to_le_bytes());
    cqe[8..12].copy_from_slice(&res.to_le_bytes());
    cqe[12..16].copy_from_slice(&flags.to_le_bytes());
    memfd_pwrite(&state.rings_memfd, off, &cqe)?;
    write_u32(&state.rings_memfd, OFF_CQ_TAIL, cq_tail.wrapping_add(1))?;
    Ok(())
}

fn wake_waiters(state: &UringState) {
    state.poll_watchers.notify(fs_poll::bits::READ as u32);
    let ev = state
        .inner
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .eventfd
        .clone();
    if let Some(ev) = ev {
        crate::signal(&ev);
    }
}

fn guest_elem_addr(base: u64, index: usize, stride: u64) -> Result<u64, Errno> {
    (index as u64)
        .checked_mul(stride)
        .and_then(|off| base.checked_add(off))
        .ok_or(Errno::EFAULT)
}

fn validate_files_update_count(nr_args: u32) -> Result<usize, Errno> {
    if nr_args == 0 || nr_args > 4096 {
        return Err(Errno::EINVAL);
    }
    Ok(nr_args as usize)
}

fn parse_registered_fd(ring_fd: &ffi::fd, fno: i32) -> Result<Option<fs_fdobj::Owned>, Errno> {
    if fno == -1 {
        return Ok(None);
    }
    let fd_ref = fs_fdobj::f_get(fno).ok_or(Errno::EBADF)?;
    if std::ptr::eq(&*fd_ref, ring_fd) {
        return Err(Errno::EBADF);
    }
    Ok(Some(fd_ref.retain()))
}

fn resolve_sqe_fd(state: &UringState, raw_fd: i32, fixed: bool) -> Result<fs_fdobj::FdRef, Errno> {
    if !fixed {
        return fs_fdobj::f_get(raw_fd).ok_or(Errno::EBADF);
    }
    let idx = usize::try_from(raw_fd).map_err(|_| Errno::EBADF)?;
    let owned = {
        let inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .registered_files
            .get(idx)
            .and_then(|slot| slot.as_ref())
            .cloned()
    }
    .ok_or(Errno::EBADF)?;
    fs_fdobj::f_from_owned(&owned).ok_or(Errno::EBADF)
}

fn execute_sqe(state: &UringState, sqe: &[u8; SQE_SIZE]) -> i32 {
    let opcode = sqe[0];
    let flags = sqe[1];
    let fd_raw = i32::from_le_bytes(sqe[4..8].try_into().unwrap());
    let off = u64::from_le_bytes(sqe[8..16].try_into().unwrap());
    let addr = u64::from_le_bytes(sqe[16..24].try_into().unwrap());
    let len = u32::from_le_bytes(sqe[24..28].try_into().unwrap());
    let rw_flags = u32::from_le_bytes(sqe[28..32].try_into().unwrap());

    let fixed = flags & IOSQE_FIXED_FILE != 0;
    let res: Result<i64, Errno> = match opcode {
        IORING_OP_NOP => Ok(0),
        IORING_OP_READ | IORING_OP_READ_FIXED => {
            let target_addr = if opcode == IORING_OP_READ_FIXED {
                let buf_idx = u16::from_le_bytes(sqe[40..42].try_into().unwrap()) as usize;
                let inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
                let Some(&(base, blen)) = inner.registered_buffers.get(buf_idx) else {
                    return Errno::EFAULT.as_i64() as i32;
                };
                let valid = addr
                    .checked_sub(base)
                    .and_then(|off| usize::try_from(off).ok())
                    .and_then(|off| off.checked_add(len as usize))
                    .is_some_and(|end| end <= blen);
                if !valid {
                    return Errno::EFAULT.as_i64() as i32;
                }
                addr
            } else {
                addr
            };
            match resolve_sqe_fd(state, fd_raw, fixed) {
                Ok(fd) => {
                    if off == u64::MAX {
                        rwcalls::read_desc(fd, target_addr, u64::from(len))
                    } else {
                        rwcalls::pread_desc(fd, target_addr, u64::from(len), off as i64)
                    }
                }
                Err(e) => Err(e),
            }
        }
        IORING_OP_WRITE | IORING_OP_WRITE_FIXED => {
            let target_addr = if opcode == IORING_OP_WRITE_FIXED {
                let buf_idx = u16::from_le_bytes(sqe[40..42].try_into().unwrap()) as usize;
                let inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
                let Some(&(base, blen)) = inner.registered_buffers.get(buf_idx) else {
                    return Errno::EFAULT.as_i64() as i32;
                };
                let valid = addr
                    .checked_sub(base)
                    .and_then(|off| usize::try_from(off).ok())
                    .and_then(|off| off.checked_add(len as usize))
                    .is_some_and(|end| end <= blen);
                if !valid {
                    return Errno::EFAULT.as_i64() as i32;
                }
                addr
            } else {
                addr
            };
            if !fixed && off == u64::MAX {
                rwcalls::sys_write(fd_raw, target_addr, u64::from(len))
            } else {
                match resolve_sqe_fd(state, fd_raw, fixed) {
                    Ok(fd) => {
                        if off == u64::MAX {
                            rwcalls::write_desc(fd, target_addr, u64::from(len))
                        } else {
                            rwcalls::pwrite_desc(fd, target_addr, u64::from(len), off as i64)
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        }
        IORING_OP_READV => match resolve_sqe_fd(state, fd_raw, fixed) {
            Ok(fd) => {
                if off == u64::MAX {
                    rwcalls::readv_desc(fd, addr, len)
                } else {
                    rwcalls::preadv_desc(fd, addr, len, off, 0)
                }
            }
            Err(e) => Err(e),
        },
        IORING_OP_WRITEV => {
            if !fixed && off == u64::MAX {
                rwcalls::sys_writev(fd_raw, addr, len)
            } else {
                match resolve_sqe_fd(state, fd_raw, fixed) {
                    Ok(fd) => {
                        if off == u64::MAX {
                            rwcalls::writev_desc(fd, addr, len)
                        } else {
                            rwcalls::pwritev_desc(fd, addr, len, off, 0)
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        }
        IORING_OP_FSYNC => match resolve_sqe_fd(state, fd_raw, fixed) {
            Ok(fd) => fdattr::fsync_desc(fd).map(|()| 0),
            Err(e) => Err(e),
        },
        IORING_OP_POLL_ADD => match resolve_sqe_fd(state, fd_raw, fixed) {
            Ok(f) => {
                let mask = (rw_flags as c_int) | (fs_poll::bits::ERR | fs_poll::bits::HUP) as c_int;
                let ready = f.ops.and_then(|ops| ops.poll(&f)).unwrap_or(0);
                Ok(i64::from(ready & mask))
            }
            Err(e) => Err(e),
        },
        IORING_OP_POLL_REMOVE | IORING_OP_TIMEOUT_REMOVE => Ok(0),
        IORING_OP_TIMEOUT => Ok(Errno::ETIME.as_i64()),
        IORING_OP_CLOSE => {
            if fixed {
                Err(Errno::EINVAL)
            } else {
                match fs_fdobj::f_close(fd_raw) {
                    0 => Ok(0),
                    err => Err(Errno::from_negative_or_eio(err)),
                }
            }
        }
        _ => Err(Errno::EINVAL),
    };

    match res {
        Ok(n) => n as i32,
        Err(e) => e.as_i64() as i32,
    }
}

pub fn sys_io_uring_setup(entries: u32, params_addr: u64) -> Result<i64, Errno> {
    strace!("io_uring_setup({entries}, {params_addr:#x})");
    if entries == 0 {
        return Err(Errno::EINVAL);
    }
    let mut params = [0u8; PARAMS_SIZE];
    if GuestMem.read(params_addr, &mut params) != 0 {
        return Err(Errno::EFAULT);
    }
    let flags = u32::from_le_bytes(params[8..12].try_into().unwrap());
    let cq_entries_req = u32::from_le_bytes(params[4..8].try_into().unwrap());
    let resv0 = u32::from_le_bytes(params[28..32].try_into().unwrap());
    let resv1 = u32::from_le_bytes(params[32..36].try_into().unwrap());
    let resv2 = u32::from_le_bytes(params[36..40].try_into().unwrap());
    if flags & !IORING_SETUP_SUPPORTED != 0 || resv0 != 0 || resv1 != 0 || resv2 != 0 {
        return Err(Errno::EINVAL);
    }

    let sq_entries = if entries > IORING_MAX_ENTRIES {
        if flags & IORING_SETUP_CLAMP != 0 {
            IORING_MAX_ENTRIES
        } else {
            return Err(Errno::EINVAL);
        }
    } else {
        entries.next_power_of_two()
    };

    let cq_entries = if flags & IORING_SETUP_CQSIZE != 0 {
        if cq_entries_req < sq_entries {
            return Err(Errno::EINVAL);
        }
        if cq_entries_req > IORING_MAX_CQ_ENTRIES {
            if flags & IORING_SETUP_CLAMP != 0 {
                IORING_MAX_CQ_ENTRIES
            } else {
                return Err(Errno::EINVAL);
            }
        } else {
            cq_entries_req.next_power_of_two()
        }
    } else {
        (sq_entries * 2).min(IORING_MAX_CQ_ENTRIES)
    };

    let no_sqarray = flags & IORING_SETUP_NO_SQARRAY != 0;
    let sq_array_off = RING_HEADER_BYTES;
    let sq_array_bytes = if no_sqarray {
        0
    } else {
        (sq_entries as usize) * 4
    };
    let cqes_off = (sq_array_off + sq_array_bytes + 15) & !15;
    let rings_size = page_align(cqes_off + (cq_entries as usize) * CQE_SIZE);
    let sqes_size = page_align((sq_entries as usize) * SQE_SIZE);

    let rings_memfd =
        memfdcalls::create_internal(b"/[io_uring-rings]", rings_size as u64, 0o600, None, None)?;
    let sqes_memfd =
        memfdcalls::create_internal(b"/[io_uring-sqes]", sqes_size as u64, 0o600, None, None)?;

    write_u32(&rings_memfd, OFF_SQ_MASK, sq_entries - 1)?;
    write_u32(&rings_memfd, OFF_SQ_ENTRIES, sq_entries)?;
    write_u32(&rings_memfd, OFF_CQ_MASK, cq_entries - 1)?;
    write_u32(&rings_memfd, OFF_CQ_ENTRIES, cq_entries)?;
    if !no_sqarray {
        for i in 0..sq_entries {
            write_u32(&rings_memfd, sq_array_off + (i as usize) * 4, i)?;
        }
    }

    let features = IORING_FEAT_SINGLE_MMAP
        | IORING_FEAT_NODROP
        | IORING_FEAT_SUBMIT_STABLE
        | IORING_FEAT_RW_CUR_POS
        | IORING_FEAT_CUR_PERSONALITY
        | IORING_FEAT_FAST_POLL
        | IORING_FEAT_POLL_32BITS;

    params[0..4].copy_from_slice(&sq_entries.to_le_bytes());
    params[4..8].copy_from_slice(&cq_entries.to_le_bytes());
    params[20..24].copy_from_slice(&features.to_le_bytes());
    // io_sqring_offsets at offset 40 (10 * u32 = 40 bytes)
    params[40..44].copy_from_slice(&(OFF_SQ_HEAD as u32).to_le_bytes());
    params[44..48].copy_from_slice(&(OFF_SQ_TAIL as u32).to_le_bytes());
    params[48..52].copy_from_slice(&(OFF_SQ_MASK as u32).to_le_bytes());
    params[52..56].copy_from_slice(&(OFF_SQ_ENTRIES as u32).to_le_bytes());
    params[56..60].copy_from_slice(&(OFF_SQ_FLAGS as u32).to_le_bytes());
    params[60..64].copy_from_slice(&(OFF_SQ_DROPPED as u32).to_le_bytes());
    params[64..68].copy_from_slice(&(sq_array_off as u32).to_le_bytes());
    // io_cqring_offsets at offset 80 (10 * u32 = 40 bytes)
    params[80..84].copy_from_slice(&(OFF_CQ_HEAD as u32).to_le_bytes());
    params[84..88].copy_from_slice(&(OFF_CQ_TAIL as u32).to_le_bytes());
    params[88..92].copy_from_slice(&(OFF_CQ_MASK as u32).to_le_bytes());
    params[92..96].copy_from_slice(&(OFF_CQ_ENTRIES as u32).to_le_bytes());
    params[96..100].copy_from_slice(&(OFF_CQ_OVERFLOW as u32).to_le_bytes());
    params[100..104].copy_from_slice(&(cqes_off as u32).to_le_bytes());
    params[104..108].copy_from_slice(&(OFF_CQ_FLAGS as u32).to_le_bytes());

    if GuestMem.write(params_addr, &params) != 0 {
        return Err(Errno::EFAULT);
    }

    let mut fd = fs_adhoc::adhoc_anon(Some(&URING_OPS), Some(c"[io_uring]"));
    let poll_watchers = Arc::clone(&fd.poll_watchers);
    fd.set_driver_state(Box::new(UringState {
        sq_entries,
        cq_entries,
        no_sqarray,
        sq_array_off,
        cqes_off,
        rings_memfd,
        sqes_memfd,
        poll_watchers,
        submit_lock: Mutex::new(()),
        inner: Mutex::new(UringInner {
            disabled: flags & IORING_SETUP_R_DISABLED != 0,
            registered_files: Vec::new(),
            registered_buffers: Vec::new(),
            eventfd: None,
        }),
    }));
    Errno::split(fs_fdobj::f_install(fd.into_owned(), ffi::O_CLOEXEC_ as c_int) as i64)
}

pub fn sys_io_uring_enter(
    fd: c_int,
    to_submit: u32,
    _min_complete: u32,
    flags: u32,
    _arg_addr: u64,
    _sigsz: usize,
) -> Result<i64, Errno> {
    strace!("io_uring_enter({fd}, {to_submit}, {flags:#x})");
    if flags & !IORING_ENTER_SUPPORTED != 0 {
        return Err(Errno::EINVAL);
    }
    let f = fs_fdobj::f_get(fd).ok_or(Errno::EBADF)?;
    let state = f.driver_state::<UringState>().ok_or(Errno::EBADF)?;
    let _submit_guard = state.submit_lock.lock().unwrap_or_else(|e| e.into_inner());
    if state.inner.lock().unwrap_or_else(|e| e.into_inner()).disabled {
        return Err(Errno::EBADFD);
    }

    let mut sq_head = read_u32(&state.rings_memfd, OFF_SQ_HEAD)?;
    let sq_tail = read_u32(&state.rings_memfd, OFF_SQ_TAIL)?;
    let available = sq_tail.wrapping_sub(sq_head);
    let count = to_submit.min(available);
    let sq_mask = state.sq_entries - 1;
    let mut submitted = 0u32;
    let mut link_failed = false;

    for _ in 0..count {
        let ring_idx = (sq_head & sq_mask) as usize;
        let sqe_idx = if state.no_sqarray {
            ring_idx
        } else {
            (read_u32(&state.rings_memfd, state.sq_array_off + ring_idx * 4)? & sq_mask) as usize
        };
        let mut sqe = [0u8; SQE_SIZE];
        memfd_pread(&state.sqes_memfd, sqe_idx * SQE_SIZE, &mut sqe)?;
        let sqe_flags = sqe[1];
        let user_data = u64::from_le_bytes(sqe[32..40].try_into().unwrap());
        let res = if link_failed {
            Errno::ECANCELED.as_i64() as i32
        } else {
            execute_sqe(state, &sqe)
        };
        push_cqe(state, user_data, res, 0)?;

        let is_linked = sqe_flags & (IOSQE_IO_LINK | IOSQE_IO_HARDLINK) != 0;
        if is_linked {
            if res < 0 && sqe_flags & IOSQE_IO_HARDLINK == 0 {
                link_failed = true;
            }
        } else {
            link_failed = false;
        }

        sq_head = sq_head.wrapping_add(1);
        submitted += 1;
    }

    if submitted > 0 {
        write_u32(&state.rings_memfd, OFF_SQ_HEAD, sq_head)?;
        wake_waiters(state);
    }
    Ok(i64::from(submitted))
}

pub fn sys_io_uring_register(
    fd: c_int,
    opcode: u32,
    arg_addr: u64,
    nr_args: u32,
) -> Result<i64, Errno> {
    strace!("io_uring_register({fd}, {opcode}, {arg_addr:#x}, {nr_args})");
    let f = fs_fdobj::f_get(fd).ok_or(Errno::EBADF)?;
    let state = f.driver_state::<UringState>().ok_or(Errno::EBADF)?;

    match opcode {
        IORING_REGISTER_BUFFERS => {
            if nr_args == 0 || nr_args > 1024 {
                return Err(Errno::EINVAL);
            }
            let mut bufs = Vec::with_capacity(nr_args as usize);
            for i in 0..(nr_args as usize) {
                let mut iov = [0u8; 16];
                let elem_addr = guest_elem_addr(arg_addr, i, 16)?;
                if GuestMem.read(elem_addr, &mut iov) != 0 {
                    return Err(Errno::EFAULT);
                }
                let base = u64::from_le_bytes(iov[0..8].try_into().unwrap());
                let len = u64::from_le_bytes(iov[8..16].try_into().unwrap()) as usize;
                bufs.push((base, len));
            }
            state
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .registered_buffers = bufs;
            Ok(0)
        }
        IORING_UNREGISTER_BUFFERS => {
            state
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .registered_buffers
                .clear();
            Ok(0)
        }
        IORING_REGISTER_FILES => {
            let count = validate_files_update_count(nr_args)?;
            let mut fds = Vec::with_capacity(count);
            for i in 0..count {
                let mut raw = [0u8; 4];
                let elem_addr = guest_elem_addr(arg_addr, i, 4)?;
                if GuestMem.read(elem_addr, &mut raw) != 0 {
                    return Err(Errno::EFAULT);
                }
                let fno = i32::from_le_bytes(raw);
                fds.push(parse_registered_fd(&f, fno)?);
            }
            state
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .registered_files = fds;
            Ok(0)
        }
        IORING_UNREGISTER_FILES => {
            state
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .registered_files
                .clear();
            Ok(0)
        }
        IORING_REGISTER_FILES_UPDATE => {
            let count = validate_files_update_count(nr_args)?;
            let mut hdr = [0u8; 16];
            if GuestMem.read(arg_addr, &mut hdr) != 0 {
                return Err(Errno::EFAULT);
            }
            let offset = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
            let fds_ptr = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
            let mut updates = Vec::with_capacity(count);
            for i in 0..count {
                let mut raw = [0u8; 4];
                let elem_addr = guest_elem_addr(fds_ptr, i, 4)?;
                if GuestMem.read(elem_addr, &mut raw) != 0 {
                    return Err(Errno::EFAULT);
                }
                let fno = i32::from_le_bytes(raw);
                updates.push(parse_registered_fd(&f, fno)?);
            }
            let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
            if offset
                .checked_add(updates.len())
                .is_none_or(|end| end > inner.registered_files.len())
            {
                return Err(Errno::EINVAL);
            }
            for (i, slot) in updates.into_iter().enumerate() {
                inner.registered_files[offset + i] = slot;
            }
            Ok(i64::from(nr_args))
        }
        IORING_REGISTER_EVENTFD | IORING_REGISTER_EVENTFD_ASYNC => {
            if nr_args != 1 {
                return Err(Errno::EINVAL);
            }
            let mut raw = [0u8; 4];
            if GuestMem.read(arg_addr, &mut raw) != 0 {
                return Err(Errno::EFAULT);
            }
            let ev_fd = i32::from_le_bytes(raw);
            let ev = fs_fdobj::f_get(ev_fd).ok_or(Errno::EBADF)?;
            if ev.driver_state::<kernel_eventfd::Descriptor>().is_none() {
                return Err(Errno::EINVAL);
            }
            state
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .eventfd = Some(Arc::new(ev.retain()));
            Ok(0)
        }
        IORING_UNREGISTER_EVENTFD => {
            state
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .eventfd = None;
            Ok(0)
        }
        IORING_REGISTER_ENABLE_RINGS => {
            state
                .inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .disabled = false;
            Ok(0)
        }
        IORING_REGISTER_PROBE => {
            if nr_args > 256 {
                return Err(Errno::EINVAL);
            }
            let ops_len = nr_args.min(255) as u8;
            // struct io_uring_probe: 16-byte header + nr_args * 8-byte ops
            let mut hdr = [0u8; 16];
            hdr[0] = IORING_OP_WRITE; // last_op
            hdr[1] = ops_len;
            if GuestMem.write(arg_addr, &hdr) != 0 {
                return Err(Errno::EFAULT);
            }
            let ops_base = arg_addr.checked_add(16).ok_or(Errno::EFAULT)?;
            let supported = [
                IORING_OP_NOP,
                IORING_OP_READV,
                IORING_OP_WRITEV,
                IORING_OP_FSYNC,
                IORING_OP_READ_FIXED,
                IORING_OP_WRITE_FIXED,
                IORING_OP_POLL_ADD,
                IORING_OP_POLL_REMOVE,
                IORING_OP_TIMEOUT,
                IORING_OP_TIMEOUT_REMOVE,
                IORING_OP_CLOSE,
                IORING_OP_READ,
                IORING_OP_WRITE,
            ];
            for i in 0..(nr_args as usize) {
                let mut op_entry = [0u8; 8];
                op_entry[0] = i as u8;
                if supported.contains(&(i as u8)) {
                    op_entry[2..4].copy_from_slice(&1u16.to_le_bytes()); // IO_URING_OP_SUPPORTED
                }
                let elem_addr = guest_elem_addr(ops_base, i, 8)?;
                if GuestMem.write(elem_addr, &op_entry) != 0 {
                    return Err(Errno::EFAULT);
                }
            }
            Ok(0)
        }
        IORING_REGISTER_RING_FDS | IORING_UNREGISTER_RING_FDS => Ok(0),
        _ => Err(Errno::EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_constants_match_linux_arm64_abi() {
        assert_eq!(PARAMS_SIZE, 120);
        assert_eq!(SQE_SIZE, 64);
        assert_eq!(CQE_SIZE, 16);
        assert_eq!(IORING_OFF_SQ_RING, 0);
        assert_eq!(IORING_OFF_CQ_RING, 0x8000_000);
        assert_eq!(IORING_OFF_SQES, 0x1000_0000);
    }

    #[test]
    fn files_update_bounds_and_addr_overflow_are_rejected() {
        assert_eq!(validate_files_update_count(0), Err(Errno::EINVAL));
        assert_eq!(validate_files_update_count(4097), Err(Errno::EINVAL));
        assert_eq!(validate_files_update_count(4096), Ok(4096));
        assert_eq!(guest_elem_addr(u64::MAX - 4, 2, 4), Err(Errno::EFAULT));
        assert_eq!(guest_elem_addr(0x1000, 3, 16), Ok(0x1030));
    }
}
