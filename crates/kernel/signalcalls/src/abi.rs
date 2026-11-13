use std::ffi::c_int;

use kernel_sigdisp::Disposition;

use super::EINVAL;

/* `sigset_size_valid` was defined here until 2026-09-15, with the same rule,
 * the same quoted Linux snippet and the same note about the same fixed bug as
 * `crates/kernel/signaldeliver`'s. Two renderings of one rule, split by
 * syscall group rather than by meaning, with nothing comparing them. This
 * crate depends on that one, so the rule is imported rather than restated. */
pub use signaldeliver::sigset_size_valid;

/// The guest's `struct sigaction`, aarch64, as a table of offsets.
///
/// Deliberately not the same type as [`Disposition`], which is this kernel's own
/// representation: its `flags` is four bytes and it is packed, so reading it
/// straight out of guest memory would put `restorer` and `mask` in the wrong
/// places.
pub struct SigActionAbi;

impl SigActionAbi {
    pub const HANDLER: u64 = 0;
    pub const FLAGS: u64 = 8;
    pub const RESTORER: u64 = 16;
    pub const MASK: u64 = 24;
    pub const SIZE: u64 = 32;

    pub fn read<M: usercopy::GuestIo>(
        mem: &M,
        addr: u64,
        mask_size: u64,
    ) -> Result<Disposition, c_int> {
        if !sigset_size_valid(mask_size) {
            return Err(EINVAL);
        }
        let handler = mem.read_u64(addr + Self::HANDLER)?;
        let flags = mem.read_u64(addr + Self::FLAGS)?;
        let restorer = mem.read_u64(addr + Self::RESTORER)?;
        let mask = mem.read_u64(addr + Self::MASK)?;
        Ok(Disposition {
            handler,
            // Narrowed on purpose: the guest word is 64 bits wide and Linux's
            // `sa_flags` is an `int`. The high half has no meaning and is not
            // stored, which is what the C did by assigning to a `dword_t`.
            flags: flags as u32,
            restorer,
            mask,
        })
    }

    /// The write half of [`Self::read`], at the same offsets.
    pub fn write<M: usercopy::GuestIo>(
        mem: &M,
        addr: u64,
        mask_size: u64,
        d: &Disposition,
    ) -> Result<(), c_int> {
        if !sigset_size_valid(mask_size) {
            return Err(EINVAL);
        }
        // Copied out of the packed struct first: a reference to a field of it
        // is unaligned.
        let (handler, flags, restorer, mask) = (d.handler, d.flags, d.restorer, d.mask);
        for (off, word) in [
            (Self::HANDLER, handler),
            (Self::FLAGS, flags as u64),
            (Self::RESTORER, restorer),
            (Self::MASK, mask),
        ] {
            match mem.write_u64(addr + off, word) {
                0 => {}
                e => return Err(e),
            }
        }
        Ok(())
    }
}

/// The guest's `stack_t`, aarch64.
///
/// ```c
/// typedef struct { void *ss_sp; int ss_flags; size_t ss_size; } stack_t;
/// ```
///
/// `ss_flags` is four bytes with four of padding after it, which is why this is
/// a table of offsets rather than three consecutive words: the size is at 16,
/// not at 12.
pub struct StackTAbi;

impl StackTAbi {
    pub const SP: u64 = 0;
    pub const FLAGS: u64 = 8;
    pub const SIZE: u64 = 16;
    pub const BYTES: u64 = 24;
}

const _: () = {
    assert!(StackTAbi::SIZE == 16);
    assert!(StackTAbi::BYTES == 24);
};

/// A `sigset_t` out of guest memory.
pub fn read_sigset<M: usercopy::GuestIo>(mem: &M, addr: u64, size: u64) -> Result<u64, c_int> {
    if !sigset_size_valid(size) {
        return Err(EINVAL);
    }
    mem.read_u64(addr)
}

/// A `sigset_t` into guest memory.
pub fn write_sigset<M: usercopy::GuestIo>(
    mem: &M,
    addr: u64,
    size: u64,
    set: u64,
) -> Result<(), c_int> {
    if !sigset_size_valid(size) {
        return Err(EINVAL);
    }
    match mem.write_u64(addr, set) {
        0 => Ok(()),
        e => Err(e),
    }
}
