//! The argument list `execve` carries, and the one rewrite that changes it.
//!
//! `struct exec_args` in `kernel/exec.c` is a count and a flat buffer: `count`
//! NUL-terminated strings one after another, and then one more NUL. That is
//! what `execve` hands to the loader and what a `#!` line has to be rewritten
//! into.
//!
//! # The count and the buffer have to agree, and twice they did not
//!
//! Both defects this file exists for were counting:
//!
//! - **An empty `argv` has no `argv[0]` to drop.** A script's path replaces
//!   `argv[0]`, so the rewrite passes on `count - 1` strings — and `count` is a
//!   `size_t`, so with nothing there that is about 2^64. `args_size` then
//!   walked that many NUL-terminated strings off the end of a 128 KB buffer.
//!   `execve(script, (char *[]){NULL}, (char *[]){NULL})` took the emulator
//!   down, and `argc` 0 is legal: Linux allows it and runs the script.
//! - **`args_size` trusted the buffer.** It walked `count` strings and then
//!   `assert`ed that the next byte was the terminator, which in a release build
//!   is not a check at all. A count that does not match its buffer walked off
//!   the end.
//!
//! Both are the same shape: a length that comes from somewhere other than the
//! bytes. Here the walk is bounded by the buffer and answers `None` rather than
//! asserting, so a count that disagrees with its buffer is a value the caller
//! has to handle.

use std::ffi::c_int;

mod rules;

pub use rules::{at, count, insert_arg, set_env, shebang, size};

/// `-E2BIG`: the arguments do not fit.
use guest_errno::c_int_::E2BIG;

/// Linux's `MAX_ARG_STRLEN`: the most one argument or environment entry may
/// be, terminator included -- 32 pages. The *total* is a separate, larger
/// bound that depends on the stack limit; see `crates/kernel/execcalls`.
pub const MAX_ARG_STRLEN: usize = 32 * 4096;
/// `-EINVAL`: the count and the buffer disagree.
use guest_errno::c_int_::EINVAL;
/// `-EFAULT`: the guest handed over an address that is not there.
use guest_errno::c_int_::EFAULT;
/// `-ENAMETOOLONG`, which a string that does not fit answers and which this
/// turns into `E2BIG`: the array is what is too big, not the name.
use guest_errno::c_int_::ENAMETOOLONG;
/// `-ENOMEM`: the buffer could not grow.
use guest_errno::c_int_::ENOMEM;
/// A guest pointer. `ELF_PTR_SIZE` in `kernel/elf.h`.
const PTR_SIZE: u64 = 8;

/// Reads a guest `char *argv[]` -- a NUL-terminated array of pointers -- into
/// the flat buffer this crate's other functions take, and answers how many
/// strings there were.
///
/// One page-table walk per page of each string rather than one per character.
/// The C copied `argv` and `envp` a byte at a time through `user_get`, and each
/// of those walks the page table, so an `execve` with a four-kilobyte
/// environment did four thousand walks for it.
///
/// `E2BIG` when the strings do not fit, including the terminator that ends the
/// list -- which is why the bound is checked again after the loop. A string
/// that does not fit in what is left is the *array* being too big, which is
/// what the caller of `execve` is told.
///
/// The address space is a parameter rather than `GuestMem` taken here, which
/// lets tests provide an in-memory implementation directly. Generic and not
/// `dyn`, so the product's call is direct.
///
/// The buffer grows with what is read, at most `max` bytes. It was a `max`-byte
/// buffer zeroed before the first string -- 128 KB for `argv` and again for
/// `envp` on every `execve`, against a few hundred bytes used -- and the most
/// sampled frame of a loop spawning `/bin/true`. Each string is read into a
/// window that starts at a page and doubles, rereading the string, until it
/// fits or the bound is reached.
pub fn read_array<M: usercopy::GuestIo>(mem: &M, addr: u64, max: usize) -> Result<(Vec<u8>, usize), c_int> {
    let mut buf = Vec::new();
    let mut count = 0usize;
    let mut at = 0usize;
    loop {
        let slot = addr
            .checked_add((count as u64).checked_mul(PTR_SIZE).ok_or(EFAULT)?)
            .ok_or(EFAULT)?;
        let str_addr = mem.read_u64(slot).map_err(|_| EFAULT)?;
        if str_addr == 0 {
            break;
        }
        if at >= max {
            return Err(E2BIG);
        }
        // One string is bounded on its own as well as by what is left:
        // Linux's `strnlen_user(str, MAX_ARG_STRLEN)` refuses a single
        // argument of 128 KB or more whatever the total limit is, and the
        // total limit is up to 6 MB.
        let room = (max - at).min(MAX_ARG_STRLEN);
        let mut window = room.min(FIRST_WINDOW);
        let n = loop {
            grow(&mut buf, at + window)?;
            match mem.read_string(str_addr, &mut buf[at..at + window]) {
                Ok(n) => break n,
                Err(e) if e == ENAMETOOLONG && window < room => window = (window * 2).min(room),
                Err(e) if e == ENAMETOOLONG => return Err(E2BIG),
                Err(e) => return Err(e),
            }
        };
        at += n + 1;
        count += 1;
    }
    // Room for the NUL that ends the list, which `size` counts and every
    // reader of the buffer walks to.
    if at >= max {
        return Err(E2BIG);
    }
    buf.truncate(at);
    buf.push(0);
    Ok((buf, count))
}

/// The first window a string is read into: a page, which nearly every
/// argument and environment entry fits.
const FIRST_WINDOW: usize = 4096;

/// Make `buf` at least `len` bytes, or `ENOMEM`: `len` is bounded by the
/// guest's argument limit, up to 6 MB, so the allocation may fail.
fn grow(buf: &mut Vec<u8>, len: usize) -> Result<(), c_int> {
    if let Some(more) = len.checked_sub(buf.len()).filter(|&n| n > 0) {
        buf.try_reserve(more).map_err(|_| ENOMEM)?;
        buf.resize(len, 0);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
