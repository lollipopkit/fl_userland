//! Copying between a guest address space and the kernel's own.
//!
//! Every syscall argument that is not a scalar arrives here, so this is both
//! the hottest path in the kernel and the one place where a mistake reaches
//! every syscall at once. Three have been found in it, and each is a property
//! this crate can be asked about directly:
//!
//! - **A range that wraps was accepted and copied nothing.** `while (p < addr
//!   + count)` with an end that overflowed is a loop that never runs, so a
//!   read of four bytes at `0xFFFFFFFFFFFFFFFF` returned *success* with the
//!     destination untouched — and the syscall used it as the guest's argument.
//! - **An address above the guest's address space aliased onto a low page.**
//!   Page numbers are 36 bits and the page table masks each level's index, so
//!   `p + (1 << 48)` selects the same entry as `p`. A write through one
//!   changed the guest's own memory somewhere else.
//! - **A string was copied a character at a time**, each through a full
//!   page-table walk, and one with no terminator in the space given was
//!   reported as success with the buffer full and unterminated.
//!
//! What stays in C is the page table: [`Pages::map`] reaches `mem_ptr`, which
//! walks it, resolves copy-on-write and may grow the stack. This crate owns the
//! range rule, the chunking, and the terminator rule — the parts that had the
//! bugs and that can be tested against a `Vec` instead of an address space.
//!
//! The task side — which address space, and the lock over it — is
//! `crates/kernel/mmapcalls`'s `usermem`. The two used to meet through a C ABI
//! with a `static mut` function pointer here, bound once at boot by
//! `user_init`; that is a Rust `impl Pages` now, and `usercopy_bind`,
//! `usercopy_read`, `usercopy_write` and `usercopy_read_string` went with
//! `kernel/user.c`.


use std::ffi::c_int;

/// Pages are 4 KiB, here as everywhere else in this tree.
pub const PAGE_BITS: u32 = 12;
pub const PAGE_SIZE: u64 = 1 << PAGE_BITS;

pub use guest_errno::c_int_::{EFAULT, ENAMETOOLONG};

/// What the caller wants to do with the page. The numbering is `emu/mmu.h`'s,
/// because these go straight through to `mem_ptr`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum Access {
    Read = 0,
    Write = 1,
    /// A debugger's write, which is allowed through a read-only mapping.
    WritePtrace = 2,
}

/// One address space, as far as this crate needs to know one.
pub trait Pages {
    /// The host bytes backing `len` bytes at guest `addr`, or `None` if that
    /// is not mapped — or not writable, when `access` says write.
    ///
    /// `len` never crosses a page boundary, so an implementation has one page
    /// to find and never has to loop.
    fn map(&mut self, addr: u64, len: usize, access: Access) -> Option<*mut u8>;
}

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

/// The half that takes `mem->lock` and reads the calling task.
///
/// `crates/kernel/mmapcalls`' until 2026-09-06. The rest of this crate is the
/// pure copy -- the range rule, the page chunking, the terminator rule -- and
/// takes no lock; this is what binds it to a real address space.
pub mod usermem;

pub mod guest;
pub use guest::{GuestIo, GuestMem};

mod extensible;
pub use extensible::read_extensible;

/// Is `addr .. addr + count` a range a guest could name?
///
/// Two ways it is not. It can **wrap**, which made the copy loops vacuous. And
/// it can lie **above the address space**, which does not fault: the page
/// table masks each level's index, so a high address selects a low page and
/// the copy silently goes somewhere else.
pub fn range_ok(addr: u64, count: usize, max_page: u64) -> bool {
    if count == 0 {
        return true;
    }
    let Some(last) = addr.checked_add(count as u64 - 1) else {
        return false;
    };
    (last >> PAGE_BITS) <= max_page
}

/// The pieces `addr .. addr + count` breaks into, none crossing a page.
///
/// Written as an iterator so the arithmetic has one home and can be checked on
/// its own: the first piece is short by the offset into its page, the last is
/// short by whatever is left, and a range that fits inside one page is one
/// piece.
pub struct Chunks {
    addr: u64,
    left: usize,
}

pub fn chunks(addr: u64, count: usize) -> Chunks {
    Chunks { addr, left: count }
}

impl Iterator for Chunks {
    type Item = (u64, usize);

    fn next(&mut self) -> Option<(u64, usize)> {
        if self.left == 0 {
            return None;
        }
        let to_page_end = (PAGE_SIZE - (self.addr & (PAGE_SIZE - 1))) as usize;
        let len = to_page_end.min(self.left);
        let at = self.addr;
        self.addr += len as u64;
        self.left -= len;
        Some((at, len))
    }
}

/// Guest memory into `buf`. 0, or `EFAULT`.
pub fn read(mem: &mut impl Pages, addr: u64, buf: &mut [u8], max_page: u64) -> c_int {
    if !range_ok(addr, buf.len(), max_page) {
        return EFAULT;
    }
    let mut done = 0usize;
    for (at, len) in chunks(addr, buf.len()) {
        let Some(src) = mem.map(at, len, Access::Read) else {
            return EFAULT;
        };
        // SAFETY: map promised `len` readable bytes at `src`, and `buf` has
        // `len` free from `done` because the chunks sum to `buf.len()`.
        unsafe { std::ptr::copy_nonoverlapping(src, buf.as_mut_ptr().add(done), len) };
        done += len;
    }
    0
}

/// How many of `count` bytes at `addr` can be written, counting from `addr` and
/// stopping at the first page that cannot.
///
/// # Why a consuming read has to ask
///
/// A `read` here bounces: the driver fills a host buffer and the result is
/// copied to the guest **after**. So a driver that consumes has already given
/// the bytes up by the time the copy can fail, and answering `EFAULT` then
/// destroys them.
///
/// Linux does not have that problem, because its drivers copy to the caller
/// themselves and then **consume exactly what landed**. That is not a guess:
/// `tests/guest/src/bin/faultread_probe.rs` asks a real kernel, and a `read`
/// into an unmapped buffer leaves a pipe's bytes queued. They were lost here.
///
/// # Why a *prefix* and not a yes or no
///
/// Because the span a caller offers is not the amount that will be delivered. A
/// `read(fd, buf, 1 << 20)` from a pipe holding eight bytes is eight bytes on
/// Linux even when almost all of that span is unmapped — the copy stops when the
/// data does, not when the mapping does. The same probe measures it: a read
/// across a mapped/unmapped page boundary delivers into the mapped page and
/// answers the short count.
///
/// So a caller clamps its request to this and the two behaviours fall out
/// together: a prefix of zero is `EFAULT` before anything is consumed, and a
/// short prefix is a short read of exactly the bytes that fit.
///
/// It is deliberately **not** [`range_ok`], which is what Linux's `access_ok`
/// is: that is arithmetic and passes for any address inside the address space,
/// including every unmapped one this is about.
///
/// It costs a page-table walk per page, which is why only the reads that cannot
/// undo a consumption ask — `crates/kernel/rwcalls` says which and why.
pub fn writable_prefix(
    mem: &mut impl Pages,
    addr: u64,
    count: usize,
    access: Access,
    max_page: u64,
) -> usize {
    if count == 0 {
        return 0;
    }
    // The whole span has to be nameable before any of it is walked: above the
    // address space an address *aliases* rather than faulting, so a walk would
    // answer about some other page and report it writable.
    if !range_ok(addr, count, max_page) {
        return 0;
    }
    let mut ok = 0usize;
    for (at, len) in chunks(addr, count) {
        if mem.map(at, len, access).is_none() {
            break;
        }
        ok += len;
    }
    ok
}

/// `buf` into guest memory. 0, or `EFAULT`.
pub fn write(mem: &mut impl Pages, addr: u64, buf: &[u8], access: Access, max_page: u64) -> c_int {
    if !range_ok(addr, buf.len(), max_page) {
        return EFAULT;
    }
    let mut done = 0usize;
    for (at, len) in chunks(addr, buf.len()) {
        let Some(dst) = mem.map(at, len, access) else {
            return EFAULT;
        };
        // SAFETY: as above, in the other direction.
        unsafe { std::ptr::copy_nonoverlapping(buf.as_ptr().add(done), dst, len) };
        done += len;
    }
    0
}

/// A NUL-terminated string out of guest memory, into `buf`.
///
/// `Ok(len)` counts the bytes before the terminator. `Err(ENAMETOOLONG)` when
/// there is none in `buf`, which used to be reported as success with `buf`
/// full and unterminated — and the caller then read past it. `Err(EFAULT)` for
/// an address that is not there, including one reached only because the string
/// ran on: a chunk is bounded to its page, so a string that ends before a hole
/// never touches the page after it.
pub fn read_string(
    mem: &mut impl Pages,
    addr: u64,
    buf: &mut [u8],
    max_page: u64,
) -> Result<usize, c_int> {
    if buf.is_empty() {
        return Err(EFAULT);
    }
    let mut done = 0usize;
    while done < buf.len() {
        let at = addr.checked_add(done as u64).ok_or(EFAULT)?;
        if !range_ok(at, 1, max_page) {
            return Err(EFAULT);
        }
        let to_page_end = (PAGE_SIZE - (at & (PAGE_SIZE - 1))) as usize;
        let len = to_page_end.min(buf.len() - done);
        let Some(src) = mem.map(at, len, Access::Read) else {
            return Err(EFAULT);
        };
        // SAFETY: map promised `len` readable bytes; `buf[done..done + len]`
        // is in bounds because `len <= buf.len() - done`.
        unsafe { std::ptr::copy_nonoverlapping(src, buf.as_mut_ptr().add(done), len) };
        if let Some(i) = buf[done..done + len].iter().position(|&b| b == 0) {
            return Ok(done + i);
        }
        done += len;
    }
    Err(ENAMETOOLONG)
}

#[cfg(test)]
mod tests;
