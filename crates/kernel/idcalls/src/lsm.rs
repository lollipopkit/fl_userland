//! The LSM syscalls of 6.8: `lsm_list_modules`, `lsm_get_self_attr` and
//! `lsm_set_self_attr`.
//!
//! The one security module here is the capability one, which every Linux
//! kernel has and which keeps no per-task attributes -- so the list has one
//! entry, and asking for or setting an attribute is `EOPNOTSUPP`, which is
//! `security_getselfattr`'s answer when no module provides the attribute.
//! Measured on 7.2, whose list is longer and whose answers for an attribute
//! no module there provides are the same.

use std::ffi::c_uint;

use strace::strace;
use usercopy::GuestMem;

use guest_errno::Errno;

/// `LSM_ID_CAPABILITY`.
const LSM_ID_CAPABILITY: u64 = 100;
/// `LSM_FLAG_SINGLE`, the one flag `lsm_get_self_attr` takes.
const LSM_FLAG_SINGLE: u32 = 1;
/// `struct lsm_ctx` without its payload: id, flags, len, ctx_len.
const LSM_CTX_HEADER: usize = 32;
/// `PAGE_SIZE`, the most `lsm_set_self_attr` copies in.
const LSM_CTX_MAX: usize = 4096;

/// The active modules, in the order `/sys/kernel/security/lsm` would list
/// them.
const ACTIVE: &[u64] = &[LSM_ID_CAPABILITY];

fn read_u32(addr: u64) -> Result<u32, Errno> {
    let mut b = [0u8; 4];
    if GuestMem.read(addr, &mut b) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(u32::from_le_bytes(b))
}

fn write_u32(addr: u64, v: u32) -> Result<(), Errno> {
    if GuestMem.write(addr, &v.to_le_bytes()) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// `lsm_list_modules(ids, size, flags)`: the ids, and how many there are.
///
/// A buffer too small for them is `E2BIG` with the size it needed written
/// back, which is how a caller learns what to allocate.
pub fn sys_lsm_list_modules(ids_addr: u64, size_addr: u64, flags: c_uint) -> Result<i64, Errno> {
    strace!("lsm_list_modules({ids_addr:#x}, {size_addr:#x}, {flags:#x})");
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let have = read_u32(size_addr)? as usize;
    let need = ACTIVE.len() * 8;
    if have < need {
        write_u32(size_addr, need as u32)?;
        return Err(Errno::E2BIG);
    }
    let bytes: Vec<u8> = ACTIVE.iter().flat_map(|id| id.to_le_bytes()).collect();
    if GuestMem.write(ids_addr, &bytes) != 0 {
        return Err(Errno::EFAULT);
    }
    write_u32(size_addr, need as u32)?;
    Ok(ACTIVE.len() as i64)
}

/// `lsm_get_self_attr(attr, ctx, size, flags)`: no module here has an
/// attribute to report.
pub fn sys_lsm_get_self_attr(attr: c_uint, ctx_addr: u64, size_addr: u64, flags: c_uint) -> Result<i64, Errno> {
    strace!("lsm_get_self_attr({attr}, {ctx_addr:#x}, {size_addr:#x}, {flags:#x})");
    // `security_getselfattr`'s order: the flags, a null size pointer, then
    // reading it -- `table_probe` measured `EINVAL` for all-zero arguments.
    if flags & !LSM_FLAG_SINGLE != 0 || size_addr == 0 {
        return Err(Errno::EINVAL);
    }
    read_u32(size_addr)?;
    Err(Errno::EOPNOTSUPP)
}

/// `lsm_set_self_attr(attr, ctx, size, flags)`: the struct is checked as
/// Linux checks it, and then no module takes it.
pub fn sys_lsm_set_self_attr(attr: c_uint, ctx_addr: u64, size: c_uint, flags: c_uint) -> Result<(), Errno> {
    strace!("lsm_set_self_attr({attr}, {ctx_addr:#x}, {size}, {flags:#x})");
    let size = size as usize;
    if flags != 0 || size < LSM_CTX_HEADER {
        return Err(Errno::EINVAL);
    }
    if size > LSM_CTX_MAX {
        return Err(Errno::E2BIG);
    }
    let mut ctx = vec![0u8; size];
    if GuestMem.read(ctx_addr, &mut ctx) != 0 {
        return Err(Errno::EFAULT);
    }
    let word = |i: usize| u64::from_le_bytes(ctx[i * 8..i * 8 + 8].try_into().unwrap());
    let (len, ctx_len) = (word(2), word(3));
    let header = LSM_CTX_HEADER as u64;
    if (size as u64) < len || (size as u64) < ctx_len.saturating_add(header) || len < ctx_len.saturating_add(header) {
        return Err(Errno::EINVAL);
    }
    Err(Errno::EOPNOTSUPP)
}
