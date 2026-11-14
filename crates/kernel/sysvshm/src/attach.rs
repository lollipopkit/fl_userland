//! Shared-memory attach and detach syscalls.

use std::ffi::c_int;

use strace::strace;

use super::{
    Errno, PAGE_SIZE, attach, registry, registry_of, id_of, now, permitted, tgid, who_am_i,
};

pub fn sys_shmat(id: c_int, addr: u64, flags: c_int) -> Result<i64, Errno> {
    strace!("shmat({id}, {addr:#x}, {flags:#o})");
    if id < 0 {
        return Err(Errno::EINVAL);
    }
    let want = attach(addr, flags)?;
    let me = who_am_i();
    let who = me.who();

    // The segment's file, with a reference of this call's own, so the
    // registry's lock is not held while the page table's is taken.
    let reg = registry();
    let (fd, size) = {
        let r = reg.lock().unwrap_or_else(|e| e.into_inner());
        let Some(i) = r.lookup(id) else {
            return Err(Errno::EINVAL);
        };
        let seg = r.slots[i].as_ref().expect("looked up");
        if !permitted(&seg.perm, &who, want.acc) {
            return Err(Errno::EACCES);
        }
        // **The clone is the retain.** It was a `memfdcalls::retain` and a
        // `memfdcalls::release` eight lines apart with a fallible `map`
        // between them, and the comment above says why the reference exists:
        // so the registry's lock is not held while the page table's is taken.
        // An `Owned` says the same thing and releases on both paths out.
        (seg.fd.clone(), seg.size)
    };
    // The address, or a negative errno. `share::map` is the mapping layer's
    // convention and is shared with `mmap`; the release runs either way, which
    // is why the answer is read after it.
    let mapped = mmapcalls::share::map(&fd, want.addr, size, want.prot, want.replace);
    drop(fd);
    let mapped = Errno::split(mapped)?;
    let mut r = reg.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(i) = r.lookup(id) {
        let seg = r.slots[i].as_mut().expect("looked up");
        seg.atime = now();
        seg.lpid = tgid();
    }
    Ok(mapped)
}

pub fn sys_shmdt(addr: u64) -> Result<(), Errno> {
    strace!("shmdt({addr:#x})");
    if addr & (PAGE_SIZE - 1) != 0 {
        return Err(Errno::EINVAL);
    }
    // Linux's rule: the mapping at `addr` is a segment's and `addr` is where
    // it was attached -- the page there maps offset zero of the file.
    let Some((fd, first)) = mmapcalls::share::mapped_at(addr) else {
        return Err(Errno::EINVAL);
    };
    if first != 0 {
        return Err(Errno::EINVAL);
    }
    // The segment's own namespace's, which this task may have left. One
    // gone with its segments still detaches: Linux's attachment holds the
    // namespace, and the mapping is all that is left of it here.
    let Some(reg) = registry_of(&fd) else {
        let Some(owner) = memfdcalls::internal_owner::<super::Owner>(&fd) else {
            return Err(Errno::EINVAL);
        };
        mmapcalls::share::unmap(addr, owner.pages);
        return Ok(());
    };
    let (id, pages) = {
        let r = reg.lock().unwrap_or_else(|e| e.into_inner());
        let Some(i) = r.by_fd(&fd) else {
            return Err(Errno::EINVAL);
        };
        let seg = r.slots[i].as_ref().expect("found");
        (id_of(i, seg.seq), seg.pages)
    };
    mmapcalls::share::unmap(addr, pages);
    // The segment may have gone with the unmap, if it was marked.
    let mut r = reg.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(i) = r.lookup(id) {
        let seg = r.slots[i].as_mut().expect("looked up");
        seg.dtime = now();
        seg.lpid = tgid();
    }
    Ok(())
}
