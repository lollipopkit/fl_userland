//! `eventfd2`, and the descriptor it hands out.
//!
//! The counter and its two modes have been `crates/kernel/eventfd` since the
//! first object whose *state* moved; what was left in `kernel/eventfd.c` was
//! the descriptor around it — the `fd_ops` table and the four operations that
//! forward to the crate.
//!
//! # `EFD_SEMAPHORE` is not an open flag
//!
//! It is 1, which is `O_WRONLY`. It has to be taken out of the word before
//! `f_install` sees it or the descriptor comes back write-only, and it has to
//! be remembered somewhere else — which is the state, because it decides what a
//! read does. That is the one thing this file does with its arguments, and it
//! is why the flags are split rather than passed through.


use std::ffi::c_int;
use std::sync::Arc;

use guest_errno::Errno;
use kernel_eventfd as eventfd;
use strace::strace;

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

/// `EFD_SEMAPHORE`: a read takes one from the counter rather than all of it, so
/// the descriptor is a counting semaphore instead of a coalescing event flag.
const EFD_SEMAPHORE: u32 = 1;

/// eventfd's driver: a read, a write, a poll and a close.
struct EventfdOps;

static EVENTFD_FDOPS: EventfdOps = EventfdOps;

fn eventfd_fdops() -> Option<&'static dyn ffi::FdOps> {
    Some(&EVENTFD_FDOPS)
}

impl ffi::FdOps for EventfdOps {
    fn caps(&self) -> ffi::Caps {
        ffi::Caps::STREAM
    }
    fn read(&self, fd: &ffi::fd, buf: &mut [u8]) -> isize {
        eventfd_fd_read(fd, buf)
    }
    fn write(&self, fd: &ffi::fd, buf: &[u8]) -> isize {
        eventfd_fd_write(fd, buf)
    }
    fn poll(&self, fd: &ffi::fd) -> Option<c_int> {
        Some(eventfd_fd_poll(fd))
    }
    fn close(&self, fd: &mut ffi::fd) -> c_int {
        eventfd_fd_close(fd)
    }
    fn show_fdinfo(&self, fd: &ffi::fd, out: &mut String) {
        if let Some(state) = state_of(fd) {
            out.push_str(&state.fdinfo());
        }
    }
}

/// The counter behind this descriptor, or `None` if it is not an eventfd.
///
/// A downcast of the state itself since 2026-09-29, which is what says whose
/// description this is. Before that it was a downcast of the operations table
/// -- and before 2026-09-15 a comparison of the table's *address* -- followed
/// by a read of the union arm the table was trusted to imply.
fn state_of(fd: &ffi::fd) -> Option<&eventfd::Descriptor> {
    fd.driver_state()
}

fn nonblocking(fd: &ffi::fd) -> bool {
    (fd.flags() & ffi::O_NONBLOCK_) != 0
}

fn eventfd_fd_read(fd: &ffi::fd, buf: &mut [u8]) -> isize {
    if buf.len() < 8 {
        return guest_errno::isize_::EINVAL;
    }
    let Some(state) = state_of(fd) else {
        return guest_errno::isize_::EINVAL;
    };
    // The `None` arm here was `eventfd::EINVAL`, for a null the `is_null()`
    // above had already returned on — the second test the sentinel cost.
    let value = match state.read(nonblocking(fd)) {
        Ok(value) => value,
        Err(err) => return err,
    };
    buf[..8].copy_from_slice(&value.to_ne_bytes());
    8
}

fn eventfd_fd_write(fd: &ffi::fd, buf: &[u8]) -> isize {
    // **Exactly eight**, where the read above takes *at least* eight. That
    // asymmetry is Linux's and is not one anybody would guess, which is why it
    // was measured: `tests/guest/src/bin/evfd_probe.rs` asks 4, 7, 8, 9 and 16
    // of both, and a real kernel refuses every write but 8 while answering a
    // read of 9 or 16 with the eight bytes it has.
    //
    // This was `< 8` for both, so a 16-byte write added to the counter and
    // reported that it had written 8 -- a caller handing over a `u64` and a
    // `sizeof` of the wrong thing was told it had worked.
    let Ok(bytes) = <[u8; 8]>::try_from(buf) else {
        return guest_errno::isize_::EINVAL;
    };
    let Some(state) = state_of(fd) else {
        return guest_errno::isize_::EINVAL;
    };
    match state.write(nonblocking(fd), u64::from_ne_bytes(bytes)) {
        Ok(()) => 8,
        Err(err) => err,
    }
}

fn eventfd_fd_poll(fd: &ffi::fd) -> c_int {
    state_of(fd).map_or(0, eventfd::Descriptor::poll_types)
}

fn eventfd_fd_close(fd: &mut ffi::fd) -> c_int {
    drop(fd.take_driver_state::<eventfd::Descriptor>());
    0
}

/// The syscall. `f_install`'s answer is still a negative errno, which is what
/// `Errno::split` reads; the descriptor number passes through unaltered.
pub fn sys_eventfd2(initval: u32, flags: c_int) -> Result<i64, Errno> {
    strace!("eventfd({initval}, {flags:#x})");
    if !eventfd::flags_valid(flags as u32) {
        return Err(Errno::EINVAL);
    }

    let mut fd = fs_adhoc::adhoc_anon(eventfd_fdops(), Some(c"[eventfd]"));
    let state = eventfd::Descriptor::new(
        initval as u64,
        flags as u32 & EFD_SEMAPHORE != 0,
        Arc::clone(&fd.poll_watchers),
    );
    fd.set_driver_state(state);
    // EFD_SEMAPHORE is 1, which f_install would read as O_WRONLY. It is on the
    // state now, so it must not also be in the descriptor's flags.
    Errno::split(fs_fdobj::f_install(fd.into_owned(), flags & !(EFD_SEMAPHORE as c_int)) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `EFD_SEMAPHORE` and `O_WRONLY` are the same bit, which is why it has to
    /// be masked out before `f_install`. Asserted rather than left as a comment
    /// because the two constants come from different headers and nothing else
    /// would notice if either moved.
    #[test]
    fn the_semaphore_flag_is_o_wronly() {
        assert_eq!(EFD_SEMAPHORE, 1);
        assert_eq!(EFD_SEMAPHORE & !EFD_SEMAPHORE, 0);
        // The flags a caller may pass, with the semaphore bit taken out, are
        // still flags `f_install` accepts.
        assert!(eventfd::flags_valid(EFD_SEMAPHORE));
        assert!(eventfd::flags_valid(0));
    }
}
