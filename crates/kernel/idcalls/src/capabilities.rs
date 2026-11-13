//! `capget` and `capset`: the capability sets through Linux's
//! `__user_cap_header_struct` and `__user_cap_data_struct`.
//!
//! The sets and their rules are `crates/kernel/creds`' `caps`; this is the
//! wire format and the order of the refusals, measured by `caps_probe`:
//!
//! - an unknown version writes the preferred one back and is `EINVAL` -- and
//!   0 for `capget` with a null data pointer, which is how libcap probes;
//! - `capget` with a null data pointer answers 0 before it reads the pid, so a
//!   pid of -1 or one that does not exist is not refused there;
//! - a v1 header carries one 32-bit word per set and a v2 or v3 two; `capset`
//!   v1 clears the upper half (measured: `0xffffffff` after it).

use std::ffi::c_int;

use kernel_pids::PidsGuard;
use strace::strace;
use usercopy::GuestMem;

use guest_errno::Errno;

const CAP_VERSION_1: u32 = 0x1998_0330; // one data element
const CAP_VERSION_2: u32 = 0x2007_1026; // two, and deprecated on Linux
const CAP_VERSION_3: u32 = 0x2008_0522; // two; what a modern libcap asks for

/// `cap_validate_magic`: how many data elements the header's version has.
/// An unknown one has the preferred version written over it -- the version
/// alone, the pid is left -- and is `EINVAL`.
fn validate_magic(addr: u64) -> Result<usize, Errno> {
    let mut b = [0u8; 4];
    if GuestMem.read(addr, &mut b) != 0 {
        return Err(Errno::EFAULT);
    }
    match u32::from_le_bytes(b) {
        CAP_VERSION_1 => Ok(1),
        CAP_VERSION_2 | CAP_VERSION_3 => Ok(2),
        _ => {
            if GuestMem.write(addr, &CAP_VERSION_3.to_le_bytes()) != 0 {
                return Err(Errno::EFAULT);
            }
            Err(Errno::EINVAL)
        }
    }
}

fn read_pid(header_addr: u64) -> Result<c_int, Errno> {
    let mut b = [0u8; 4];
    if GuestMem.read(header_addr + 4, &mut b) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(i32::from_le_bytes(b))
}

pub fn sys_capget(header_addr: u64, data_addr: u64) -> Result<(), Errno> {
    strace!("capget({header_addr:#x}, {data_addr:#x})");
    let elements = match validate_magic(header_addr) {
        Err(Errno::EINVAL) if data_addr == 0 => return Ok(()),
        r => r?,
    };
    if data_addr == 0 {
        return Ok(());
    }
    let pid = read_pid(header_addr)?;
    if pid < 0 {
        return Err(Errno::EINVAL);
    }

    // pid 0 means the caller, and any process may read any other's -- the
    // **target's** sets, read under the lock: the task can be reaped the
    // moment it is dropped. Reading the caller's own for another pid is the
    // defect `cap_cross` records.
    let sets = |c: &kernel_creds::Creds| {
        let caps = c.caps();
        (caps.effective, caps.permitted, caps.inheritable)
    };
    let me = taskview::current_pid();
    let (e, p, i) = if pid != 0 && pid != me {
        let guard = PidsGuard::take();
        let Some(task) = guard.find_live(pid) else {
            return Err(Errno::ESRCH);
        };
        sets(task.creds())
    } else {
        taskview::with_current_creds(sets).unwrap_or_default()
    };

    // Two `struct __user_cap_data_struct`: effective, permitted, inheritable,
    // the low words and then the high ones.
    let data = [e as u32, p as u32, i as u32, (e >> 32) as u32, (p >> 32) as u32, (i >> 32) as u32];
    if GuestMem.write(data_addr, &plain::slice_bytes(&data)[..elements * 12]) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

pub fn sys_capset(header_addr: u64, data_addr: u64) -> Result<(), Errno> {
    strace!("capset({header_addr:#x}, {data_addr:#x})");
    let elements = validate_magic(header_addr)?;
    let pid = read_pid(header_addr)?;
    // Only a process's own, since 2.6.
    if pid != 0 && pid != taskview::current_pid() {
        return Err(Errno::EPERM);
    }
    let mut data = [0u32; 6];
    if GuestMem.read(data_addr, &mut plain::slice_bytes_mut(&mut data)[..elements * 12]) != 0 {
        return Err(Errno::EFAULT);
    }
    let set = |n: usize| data[n] as u64 | (data[n + 3] as u64) << 32;
    let (e, p, i) = (set(0), set(1), set(2));
    // Under `pids_lock`, which is also what takes `dumpable` away should the
    // permitted set grow -- it cannot here, and the rule says so.
    PidsGuard::take()
        .commit_current_creds(|c| c.capset(e, p, i))
        .expect("a syscall runs in a task")
        .map_err(Errno::from_negative_or_eio)
}
