//! Pure permission, size, attachment, and identifier rules for SysV SHM.

use super::*;

// ---------------------------------------------------------------- the rules
//
// Pure, and tested below. Each is a decision the C would have made inline.

/// Linux's `ipcperms`: may `who` access a segment with `perm` in the way
/// `acc` asks (`S_IRUGO`-style bits, 0o444 for read and 0o222 for write)?
/// The owner or creator is judged by the owner bits, a member of the group or
/// creator group by the group bits, everyone else by the other bits, and
/// `CAP_IPC_OWNER` by none.
pub fn permitted(perm: &Perm, who: &Who<'_>, acc: u32) -> bool {
    let requested = ((acc >> 6) | (acc >> 3) | acc) & 7;
    let granted = if who.euid == perm.cuid || who.euid == perm.uid {
        perm.mode >> 6
    } else if who.egid == perm.cgid
        || who.egid == perm.gid
        || who.groups.contains(&perm.gid)
        || who.groups.contains(&perm.cgid)
    {
        perm.mode >> 3
    } else {
        perm.mode
    };
    requested & !granted & 7 == 0 || who.ipc_owner
}

/// Linux's `ipcctl_obtain_check`: may `who` change or remove the segment?
/// The owner, the creator, or `CAP_SYS_ADMIN`.
pub fn owner(perm: &Perm, who: &Who<'_>) -> bool {
    who.euid == perm.cuid || who.euid == perm.uid || who.sys_admin
}

/// `newseg`'s size rules: `EINVAL` outside `[SHMMIN, SHMMAX]`, `ENOSPC` when
/// the page count overflows or the total would pass `SHMALL`, and `EINVAL`
/// again past `MAX_LFS_FILESIZE`, which is where the tmpfs file behind a
/// Linux segment refuses. The pages, on success.
pub(crate) fn size_ok(size: u64, total_pages: u64) -> Result<u64, Errno> {
    if !(ipc::SHMMIN..=ipc::SHMMAX).contains(&size) {
        return Err(Errno::EINVAL);
    }
    if size > i64::MAX as u64 {
        return Err(Errno::EINVAL);
    }
    let pages = size.div_ceil(PAGE_SIZE);
    if pages
        .checked_mul(PAGE_SIZE)
        .is_none_or(|bytes| bytes < size)
    {
        return Err(Errno::ENOSPC);
    }
    match total_pages.checked_add(pages) {
        Some(t) if t <= ipc::SHMALL => Ok(pages),
        _ => Err(Errno::ENOSPC),
    }
}

/// `shmget`'s decision for a key that already names a segment, given the
/// segment's size: `IPC_CREAT|IPC_EXCL` is `EEXIST`, asking for more than it
/// holds is `EINVAL`, and then the permission check.
pub(crate) fn existing_ok(
    flags: i32,
    existing_size: u64,
    wanted: u64,
) -> Result<(), Errno> {
    if flags & ipc::CREAT != 0 && flags & ipc::EXCL != 0 {
        return Err(Errno::EEXIST);
    }
    if existing_size < wanted {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// What `shmat` makes of its address and flags: the address to map at (0 for
/// anywhere), the `P_*` protection, the access the permission check needs,
/// and whether an occupied range is replaced. `EINVAL` for an address that is
/// not a multiple of `SHMLBA` without `SHM_RND`, for `SHM_REMAP` without an
/// address, and for a rounded address that comes out at zero with
/// `SHM_REMAP`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attach {
    pub addr: u64,
    pub prot: c_int,
    pub acc: u32,
    pub replace: bool,
}

pub fn attach(mut addr: u64, flags: i32) -> Result<Attach, Errno> {
    let shmlba = PAGE_SIZE;
    if addr != 0 {
        if addr & (shmlba - 1) != 0 {
            if flags & ipc::SHM_RND != 0 {
                addr &= !(shmlba - 1);
                if addr == 0 && flags & ipc::SHM_REMAP != 0 {
                    return Err(Errno::EINVAL);
                }
            } else {
                return Err(Errno::EINVAL);
            }
        }
    } else if flags & ipc::SHM_REMAP != 0 {
        return Err(Errno::EINVAL);
    }
    let (mut prot, mut acc) = if flags & ipc::SHM_RDONLY != 0 {
        (1, 0o444)
    } else {
        (1 | 2, 0o444 | 0o222)
    };
    if flags & ipc::SHM_EXEC != 0 {
        prot |= 4;
        acc |= 0o111;
    }
    Ok(Attach {
        addr,
        prot,
        acc,
        replace: addr != 0 && flags & ipc::SHM_REMAP != 0,
    })
}

/// An id from its slot and sequence, and the slot an id names if its
/// sequence still matches.
pub(crate) fn id_of(index: usize, seq: u16) -> i32 {
    seq as i32 * ipc::SEQ_MULTIPLIER + index as i32
}

pub fn index_of(id: i32, seq_of: impl Fn(usize) -> Option<u16>) -> Option<usize> {
    if id < 0 {
        return None;
    }
    let index = (id % ipc::SEQ_MULTIPLIER) as usize;
    let seq = (id / ipc::SEQ_MULTIPLIER) as u16;
    (seq_of(index) == Some(seq)).then_some(index)
}
