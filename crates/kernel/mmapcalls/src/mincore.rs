//! `mincore(2)`: report resident guest pages in bounded chunks.

use super::*;

// ---------------------------------------------------------------------------
// mincore
// ---------------------------------------------------------------------------

/// How many pages of the answer are collected before being copied out.
///
/// The vector is one byte per page and `length` is the guest's, so the whole
/// answer can be gigabytes: `mincore` over the entire address space asks for
/// 2^36 bytes. The C wrote one byte at a time with `user_put` **while holding
/// `mem->lock` for reading** — which takes the same lock again, a recursive
/// read acquisition that happens to work and is not a thing to keep. A chunk at
/// a time bounds the allocation and takes the lock once per chunk.
///
/// Nothing is lost by that: the C's answer was not atomic either, because
/// `user_put` released and retook the lock inside every iteration.
const MINCORE_CHUNK: usize = 512;

/// Which pages of a mapping are in RAM.
///
/// This used to write a 1 for every page and return 0 without looking at the
/// address at all, so two of `mincore`'s three answers were unreachable and the
/// one it gave was a guess. It matters because "is this address mapped?" is a
/// real use of the call: an allocator or a JIT probes with `mincore` rather than
/// installing a `SIGSEGV` handler, and reads `ENOMEM` as "no".
///
/// And **mapped is not resident**: `pt_map_nothing` maps a whole range up
/// front, so every mapped guest page looks backed from inside the emulator while
/// the host has not faulted in the ones nothing has touched. Measured — a page
/// that has never been written reports 0 on a real kernel and reported 1 here,
/// so an allocator asking which of its pages are worth returning was told "all
/// of them".
///
pub fn sys_mincore(addr: u64, length: u64, vec_addr: u64) -> Result<(), Errno> {
    strace!("mincore({addr:#x}, {length:#x}, {vec_addr:#x})");
    if !addr.is_multiple_of(PAGE_SIZE) {
        return Err(Errno::EINVAL);
    }
    if length == 0 {
        return Ok(());
    }
    let Some(end) = addr.checked_add(length) else {
        return Err(Errno::ENOMEM);
    };
    let pages = end.div_ceil(PAGE_SIZE) - page_of(addr);
    let start = page_of(addr);

    // The whole range has to be mapped, not just its first page.
    {
        let guard = mem_read();
        for i in 0..pages {
            if !mmap_page_mapped(&guard, start + i) {
                return Err(Errno::ENOMEM);
            }
        }
    }

    let mem = usercopy::GuestMem::current();
    let mut done = 0u64;
    let mut chunk = Vec::new();
    while done < pages {
        let n = (pages - done).min(MINCORE_CHUNK as u64) as usize;
        chunk.clear();
        if chunk.try_reserve(n).is_err() {
            return Err(Errno::ENOMEM);
        }
        {
            let guard = mem_read();
            for i in 0..n as u64 {
                let res =
                    guard.page_resident(start + done + i);
                chunk.push(u8::from(res > 0));
            }
        }
        if mem.write(vec_addr + done, &chunk) != 0 {
            return Err(Errno::EFAULT);
        }
        done += n as u64;
    }
    Ok(())
}
