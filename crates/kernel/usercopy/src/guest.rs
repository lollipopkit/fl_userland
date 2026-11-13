//! Guest memory, through Rust entry points that take the address space's lock.
//!
//! The rest of this crate owns the *copy* — the range rule, the page chunking,
//! the terminator rule — and takes no lock, because it is asked about a
//! `Pages`. What is missing from it for a caller at syscall level is
//! `mem->lock`: `read_current_mem` in this crate is equivalent to
//!
//! ```c
//! read_wrlock(&mem->lock);
//! int res = usercopy_read(mem, addr, buf, count);
//! read_wrunlock(&mem->lock);
//! ```
//!
//! and a Rust syscall that called the copy primitive directly would copy out of
//! an address space another thread was `munmap`ing. The syscall-facing wrappers
//! therefore take the address-space lock first, preserving the lock *order* of
//! the C paths they replace.
//!
//! # Nothing here is `unsafe`
//!
//! Every method was an `unsafe fn` until 2026-09-04, with the precondition
//! "called on a guest thread": the entry points read `current` and dereferenced
//! its task, so a host thread — the timer service, a test binary — would have
//! crashed the emulator. That put an `unsafe` block at every one of 145 copies
//! and the precondition in none of them, and the handle was a public unit
//! struct anybody could write as `GuestMem`, so the contract was not one the
//! type could hold anyway.
//!
//! The entry points refuse the call instead: `crates/kernel/mmapcalls`'s
//! `read_current` and its siblings answer `EFAULT` for a thread with no task, and
//! say so on stderr, because such a call is a defect and a silent one would
//! hide it. With that, a copy is an ordinary function that may fail, and the
//! only `unsafe` left is the four FFI calls in this file.
//!
//! TODO(migration): `mem->lock` is a `wrlock_t` in C, and this is the shape that
//! ends when the address space itself moves. The unit is one call rather than a
//! guard for exactly that reason: nothing here can hold the lock across two
//! copies, so nothing here has to be unpicked when it does.

use std::ffi::c_int;

use plain::Plain;

// The four below were a hand-written `extern "C"` block into
// `crates/kernel/mmapcalls` until 2026-09-06, under a `keep-c-abi` marker whose
// TODO said what to do about it: `usermem` belongs in *this* crate, because it
// needs nothing of the mmap syscalls -- `crates/kernel/pagetable` for the page
// lookup and the four `mem_*_lock` wrappers, both of which are below this one.
// The wrappers became `pagetable::memlock`'s the same day, which is what made
// the move possible; the file is `usermem.rs` here now and the edge runs the
// right way.
use crate::usermem::{read_current, read_current_string, user_writable, write_current};

/// What a crate needs of the calling thread's address space, as a trait.
///
/// Each dependent crate can provide a small in-memory implementation in its
/// tests without defining or overriding a linker symbol.
///
/// **Generic, not `dyn`**, and that is what makes it free: every caller
/// monomorphises to [`GuestMem`] and the call is direct, so the syscall path
/// pays nothing. `dyn` would have been one indirect call per guest copy, which
/// is the cost the note here rejected the trait for until somebody separated
/// the two.
///
/// Only the crates that *thread the memory through as a parameter* implement
/// against it. `signalcalls` already took a `&GuestMem` on ten functions and
/// `execargs` on one, so for those the change was the type and nothing else;
/// the other 37 files that name `GuestMem` still name the struct.
pub trait GuestIo {
    /// A `u64` at `addr`, little-endian as the guest is.
    fn read_u64(&self, addr: u64) -> Result<u64, c_int>;
    /// 0, or a negative guest errno.
    fn write_u64(&self, addr: u64, value: u64) -> c_int;
    /// 0, or a negative guest errno.
    fn write(&self, addr: u64, bytes: &[u8]) -> c_int;
    /// 0, or a negative guest errno.
    fn read(&self, addr: u64, bytes: &mut [u8]) -> c_int;
    /// The length, not counting the NUL. `ENAMETOOLONG` when `buf` fills first.
    fn read_string(&self, addr: u64, buf: &mut [u8]) -> Result<usize, c_int>;
}

impl GuestIo for GuestMem {
    fn read_u64(&self, addr: u64) -> Result<u64, c_int> {
        GuestMem::read_u64(self, addr)
    }
    fn write_u64(&self, addr: u64, value: u64) -> c_int {
        GuestMem::write_u64(self, addr, value)
    }
    fn write(&self, addr: u64, bytes: &[u8]) -> c_int {
        GuestMem::write(self, addr, bytes)
    }
    fn read(&self, addr: u64, bytes: &mut [u8]) -> c_int {
        GuestMem::read(self, addr, bytes)
    }
    fn read_string(&self, addr: u64, buf: &mut [u8]) -> Result<usize, c_int> {
        GuestMem::read_string(self, addr, buf)
    }
}

/// The calling thread's address space.
///
/// A unit type: `read_current` reads `current`, so there is nothing to carry. It
/// exists so that a function taking one says it touches guest memory.
///
/// Tests substitute guest memory through [`GuestIo`] implementations passed to
/// generic helpers. This keeps the test double local to the call and avoids
/// duplicate linker symbols.
///
/// The trait is generic rather than `dyn`, so each product call monomorphises
/// to [`GuestMem`] and remains direct.
///
#[derive(Clone, Copy, Default)]
pub struct GuestMem;

impl GuestMem {
    pub fn current() -> GuestMem {
        GuestMem
    }

    /// A `u64` at `addr`, little-endian as the guest is.
    pub fn read_u64(&self, addr: u64) -> Result<u64, c_int> {
        let mut word = [0u8; 8];
        match read_current(addr, &mut word) {
            0 => Ok(u64::from_le_bytes(word)),
            e => Err(e),
        }
    }

    /// 0, or a negative guest errno.
    pub fn write_u64(&self, addr: u64, value: u64) -> c_int {
        let word = value.to_le_bytes();
        // SAFETY: `word` is 8 readable bytes.
        write_current(addr, &word)
    }

    /// A block of bytes — a `siginfo_t`, which is 128 of them and opaque to
    /// everything here except its first word. 0, or a negative guest errno.
    pub fn write(&self, addr: u64, bytes: &[u8]) -> c_int {
        // SAFETY: `bytes` is `bytes.len()` readable bytes.
        write_current(addr, bytes)
    }

    /// 0, or a negative guest errno.
    pub fn read(&self, addr: u64, bytes: &mut [u8]) -> c_int {
        // SAFETY: `bytes` is `bytes.len()` writable bytes.
        read_current(addr, bytes)
    }

    /// A guest struct, as its bytes. 0, or a negative guest errno.
    ///
    /// Where nine syscalls each took the struct's address and
    /// `from_raw_parts` it, unchecked for padding; [`plain::plain!`] checks.
    pub fn write_value<T: Plain>(&self, addr: u64, value: &T) -> c_int {
        self.write(addr, plain::bytes_of(value))
    }

    /// A guest struct, from its bytes.
    pub fn read_value<T: Plain + Default>(&self, addr: u64) -> Result<T, c_int> {
        let mut value = T::default();
        match self.read(addr, plain::bytes_of_mut(&mut value)) {
            0 => Ok(value),
            e => Err(e),
        }
    }

    /// How many of `count` bytes at `addr` are writable, writing none of them,
    /// or `EFAULT` for a range no guest could name.
    ///
    /// What a **consuming** read clamps its request to before it consumes; see
    /// [`crate::writable_prefix`] for why it has to, and `user_writable` for why
    /// a range failure is a different answer from an unmapped page.
    pub fn writable_prefix(&self, addr: u64, count: usize) -> isize {
        // Safe since 2026-09-06: `user_writable` is a plain Rust `fn` in this
        // crate now, and it never was `unsafe` for a reason -- it writes
        // nothing and takes no pointer.
        user_writable(addr, count)
    }

    /// A NUL-terminated string into `buf`, answering its length without the
    /// terminator.
    ///
    /// `ENAMETOOLONG` when there is no terminator inside `buf`, which used to
    /// be reported as success with `buf` full and unterminated — and the caller
    /// then read past it. Four crates declared this symbol for themselves
    /// before it was here.
    pub fn read_string(&self, addr: u64, buf: &mut [u8]) -> Result<usize, c_int> {
        match read_current_string(addr, buf) {
            e if e < 0 => Err(e),
            _ => Ok(buf.iter().position(|&b| b == 0).unwrap_or(buf.len())),
        }
    }
}
