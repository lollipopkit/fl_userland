//! Ioctl argument handling and interface queries.

use super::*;

// ---------------------------------------------------------------------------
// ioctl
// ---------------------------------------------------------------------------

/// What fits without touching the heap.
///
/// `ioctl_size` answers per *command*: four bytes for `FIONREAD` and the pgrp
/// ioctls, a `struct winsize_`, a `struct termios_`. The largest this kernel has
/// is under a hundred bytes, so nothing in the tree today takes the second
/// branch — and a fixed array of `IOCTL_ARG_MAX` would memset four kilobytes on
/// every `isatty`.
const IOCTL_INLINE: usize = 128;

/// The buffer an ioctl's argument is copied through.
///
/// A driver's own table decides the size, not the guest. The C used a VLA and a
/// comment reading "praying that this won't break"; the bound is
/// [`ffi::IOCTL_ARG_MAX`] and it is checked, because an operation that one day
/// answered with a length it took from the guest would blow the thread's stack
/// silently.
enum ArgBuf {
    Inline([u8; IOCTL_INLINE], usize),
    Heap(Vec<u8>),
}

impl ArgBuf {
    fn new(size: usize) -> Option<ArgBuf> {
        if size <= IOCTL_INLINE {
            return Some(ArgBuf::Inline([0; IOCTL_INLINE], size));
        }
        let mut v = Vec::new();
        v.try_reserve(size).ok()?;
        v.resize(size, 0);
        Some(ArgBuf::Heap(v))
    }

    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            ArgBuf::Inline(b, n) => &mut b[..*n],
            ArgBuf::Heap(v) => v.as_mut_slice(),
        }
    }
}

/// The `int` a `FIO*` command points at.
///
/// Three of the commands below take one and each read it out for itself: a
/// `[0u8; 4]`, a `read` compared against zero, and a `from_ne_bytes`. The
/// interesting difference between them is what they do with the value, which
/// is one line each and is now all that is written at each.
fn arg_word(addr: u64) -> Result<i32, Errno> {
    let mut word = [0u8; 4];
    if GuestMem::current().read(addr, &mut word) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(i32::from_ne_bytes(word))
}

/// The driver's own ioctl, with its argument copied in and out.
///
/// `ENOTTY` rather than a truncation for a command whose argument does not fit:
/// one this kernel cannot hold is one it does not implement correctly, and
/// saying so is better than copying part of it. It is also the answer for a
/// driver with no `ioctl_size` at all — see `tools/ops-table-pairs.py`, which
/// exists because `/dev/random` was that and its handler never ran.
fn fd_ioctl(fd: &ffi::fd, cmd: c_int, arg: u64) -> Ret {
    // Both halves of this function changed on 2026-09-11 and the merge keeps
    // both: `fd_ops` became a trait, so there is one `Option` at the table
    // rather than one per operation, and this family answers a `Result`, so
    // every errno below is an `Err` instead of a negative number.
    let Some(ops) = fd.ops else {
        return Err(Errno::ENOTTY);
    };
    let size = ops.ioctl_size(cmd);
    if size < 0 {
        return Err(Errno::ENOTTY);
    }
    // Size zero means the argument *is* the value, not a pointer to one.
    if size == 0 {
        return Errno::split(ops.ioctl(fd, cmd, ffi::IoctlArg::Value(arg as usize)) as i64);
    }
    let size = size as usize;
    if size > ffi::IOCTL_ARG_MAX as usize {
        return Err(Errno::ENOTTY);
    }
    let Some(mut buf) = ArgBuf::new(size) else {
        return Err(Errno::ENOMEM);
    };
    let mem = GuestMem::current();
    if mem.read(arg, buf.as_mut()) != 0 {
        return Err(Errno::EFAULT);
    }
    let res = Errno::split(ops.ioctl(fd, cmd, ffi::IoctlArg::Buf(buf.as_mut())) as i64)?;
    if mem.write(arg, buf.as_mut()) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(res)
}

/// `FIOASYNC`: set or clear `O_ASYNC` from a word in guest memory.
///
/// The same request as `fcntl(F_SETFL, O_ASYNC)`, and answered the same way --
/// the two spellings differ only in which API defined them. `crates/fs/fdobj`'s
/// `status::setfl` is the rule: the flag sticks on a description that could
/// raise `SIGIO` and is dropped on one that could not.
///
/// **Linux does not ask the driver when nothing changes.** `ioctl_fioasync`
/// compares the requested state against `f_flags` first and returns 0 if they
/// agree, so `FIOASYNC` with `off` on a regular file -- which has no `fasync`
/// and would otherwise be `ENOTTY` -- succeeds. That is a rule a program can
/// see, and it is why this is a comparison rather than a store.
fn set_async(fd: &ffi::fd, on_addr: u64) -> Result<(), Errno> {
    let want = arg_word(on_addr)? != 0;
    let flags = fd.flags();
    if (flags & ffi::O_ASYNC_ != 0) == want {
        return Ok(());
    }
    let new = if want {
        flags | ffi::O_ASYNC_
    } else {
        flags & !ffi::O_ASYNC_
    };
    Errno::split(fs_fdobj::fd_setflags(fd, new as c_int) as i64)?;
    // A description that cannot raise the signal drops the flag rather than
    // keeping it, and Linux answers ENOTTY for that case -- the driver it
    // would have asked has no `fasync`.
    if (fd.flags() & ffi::O_ASYNC_ != 0) != want {
        return Err(Errno::ENOTTY);
    }
    Ok(())
}

/// `FIONBIO`: set or clear `O_NONBLOCK` from a word in guest memory.
fn set_nonblock(fd: &ffi::fd, nb_addr: u64) -> Ret {
    let on = arg_word(nb_addr)? != 0;
    let mut flags = fd.flags() as c_int;
    if on {
        flags |= ffi::O_NONBLOCK_ as c_int;
    } else {
        flags &= !(ffi::O_NONBLOCK_ as c_int);
    }
    Errno::split(fs_fdobj::fd_setflags(fd, flags) as i64)
}

/// Called on a guest thread, from the syscall table.
///
/// Not an `unsafe fn`: it was one with a `# Safety` section reading "called on
/// a guest thread", which is the precondition every `sys_*` in this crate has
/// and none of the others declared. A contract nothing distinguishes is not a
/// contract; the raw-pointer work inside is in `unsafe` blocks, where the
/// obligation actually is.
pub fn sys_ioctl(f: c_int, cmd: u32, arg: u64) -> Ret {
    strace!("ioctl({f}, {cmd:#x}, {arg:#x})");
    let Some(fd) = fs_fdobj::f_get(f) else {
        return Err(Errno::EBADF);
    };
    let fd = &*fd;
    // An O_PATH descriptor names a file and cannot be operated on.
    if fd.is_path_only() {
        return Err(Errno::EBADF);
    }

    // Three the descriptor table answers rather than the driver. They are
    // ioctls only for history: FIOCLEX and FIONCLEX are fcntl(F_SETFD) written
    // another way, and FIONBIO is fcntl(F_SETFL).
    match cmd {
        c if c == ffi::FIONBIO_ => return set_nonblock(fd, arg),
        c if c == ffi::FIOASYNC_ => return set_async(fd, arg).map(|()| 0),
        c if c == ffi::FIOCLEX_ => {
            return with_table(|table| Errno::split(table.set_cloexec(f, true) as i64));
        }
        c if c == ffi::FIONCLEX_ => {
            return with_table(|table| Errno::split(table.set_cloexec(f, false) as i64));
        }
        // fcntl(F_SETOWN)/F_GETOWN written another way. Two spellings each,
        // from the two socket APIs that defined them; Linux answers all four
        // out of the same `f_owner`.
        c if c == ffi::FIOSETOWN_ || c == ffi::SIOCSPGRP_ => {
            fd.set_owner_pid(arg_word(arg)?);
            return Ok(0);
        }
        c if c == ffi::FIOGETOWN_ || c == ffi::SIOCGPGRP_ => {
            let owner = fd.owner_pid();
            if GuestMem::current().write(arg, &owner.to_ne_bytes()) != 0 {
                return Err(Errno::EFAULT);
            }
            return Ok(0);
        }
        _ => {}
    }
    // The `SIOCGIF*` family, answered here rather than by the driver.
    //
    // Here for two reasons. `SIOCGIFCONF`'s argument holds a **guest pointer**
    // to the buffer it fills, and `fd_ioctl` below hands a driver a kernel copy
    // of the argument -- so a driver could not reach the buffer at all. And the
    // family is not a property of the socket: any socket answers for any
    // interface, which is why `SIOCSPGRP` and `SIOCGPGRP` are already here.
    //
    // Only for a socket, as on Linux: on anything else these fall through and
    // become `ENOTTY`.
    if fd.type_ as u32 == libc::S_IFSOCK as u32
        && let Some(r) = siocgif(cmd, arg)
    {
        return r;
    }
    fd_ioctl(fd, cmd as c_int, arg)
}

/// The `SIOCGIF*` family. `None` for a command that is not one of them.
fn siocgif(cmd: u32, arg: u64) -> Option<Ret> {
    use netlink::{IFCONF_LEN, IFREQ_LEN, SIOCGIFCONF};
    let mem = GuestMem::current();
    if cmd == SIOCGIFCONF {
        // `struct ifconf`: an `int` length, four bytes of padding, and a
        // pointer. A **null** buffer is the sizing call -- the caller asks how
        // much room it needs and gets the length with nothing written, which is
        // what `ifconfig` does first.
        let mut hdr = [0u8; IFCONF_LEN];
        if mem.read(arg, &mut hdr) != 0 {
            return Some(Err(Errno::EFAULT));
        }
        let len = i32::from_le_bytes(hdr[0..4].try_into().unwrap()).max(0) as usize;
        let buf = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
        let entries = netlink::ifconf_entries(&netlink::host_ifaces());
        let n = if buf == 0 {
            entries.len()
        } else {
            entries.len().min(len)
        };
        if buf != 0 && n > 0 && mem.write(buf, &entries[..n]) != 0 {
            return Some(Err(Errno::EFAULT));
        }
        // The length written back is what *fitted*, which is how a caller knows
        // to grow its buffer and try again -- reporting the full length would
        // make it read past what was written.
        hdr[0..4].copy_from_slice(&(n as i32).to_le_bytes());
        if mem.write(arg, &hdr) != 0 {
            return Some(Err(Errno::EFAULT));
        }
        return Some(Ok(0));
    }
    if !matches!(
        cmd,
        netlink::SIOCGIFNAME
            | netlink::SIOCGIFFLAGS
            | netlink::SIOCGIFADDR
            | netlink::SIOCGIFNETMASK
            | netlink::SIOCGIFMTU
            | netlink::SIOCGIFHWADDR
            | netlink::SIOCGIFINDEX
            | netlink::SIOCGIFTXQLEN
    ) {
        return None;
    }
    let mut req = [0u8; IFREQ_LEN];
    if mem.read(arg, &mut req) != 0 {
        return Some(Err(Errno::EFAULT));
    }
    match netlink::ifreq_ioctl(cmd, &mut req, &netlink::host_ifaces()) {
        Err(e) => Some(Errno::split(e as i64)),
        Ok(()) => {
            if mem.write(arg, &req) != 0 {
                Some(Err(Errno::EFAULT))
            } else {
                Some(Ok(0))
            }
        }
    }
}
