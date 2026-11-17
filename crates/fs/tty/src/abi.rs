//! The C entry points.
//!
//! Every one takes the opaque `struct tty *` C holds and turns it back into
//! an `Arc` without consuming a count.
//!
//! **A pointer is a user and a strong count**, since 2026-09-29: a
//! [`tty::User`] across the boundary. `tty_open_external` is the one function
//! that hands one out, with `User::into_raw`, and `tty_release` takes it back.
//! Before that the pointer carried only the *user* (`Tty::users`, Linux's
//! `tty->count`): the strong count `into_raw` took was never returned, so no
//! terminal the ABI had handed out was ever freed.
//!
//! `tty_get`, `tty_open_ptmx`, `tty_retain` and `tty_slave_open_allowed` went
//! on 2026-09-30: their callers, `crates/fs/ttydev` and `crates/kernel/ctty`,
//! hold a `tty::User` and call `tty::User::get`, `pty::open_master` and
//! `pty::open_slave` directly.

use crate::pty;
use crate::tty::{self, Tty, Winsize};
use pollset::Watchers;
use std::ffi::c_int;
use std::mem::ManuallyDrop;
use std::sync::Arc;

/// # Safety
/// `raw` must be a terminal the caller holds a user of.
unsafe fn borrow(raw: *const Tty) -> ManuallyDrop<Arc<Tty>> {
    ManuallyDrop::new(unsafe { Arc::from_raw(raw) })
}

/// # Safety
/// `raw` must be a live reverse edge from `poll_watchers_new`.
unsafe fn borrow_watchers(raw: *const Watchers) -> ManuallyDrop<Arc<Watchers>> {
    ManuallyDrop::new(unsafe { Arc::from_raw(raw) })
}

/// # Safety
/// `raw` must be a terminal the caller holds a user of, and must not be used
/// afterwards.
pub unsafe fn tty_release(raw: *const Tty) {
    if !raw.is_null() {
        // SAFETY: the caller's user, which this takes over and drops.
        drop(unsafe { tty::User::from_raw(raw) });
    }
}

/// Hang up an embedder's terminal, waking any blocked [`tty_input`] and
/// closing the host side: its `/dev/pts` node goes and it cannot be opened
/// again. Separate from [`tty_release`], which only gives a reference back --
/// an embedder may release its handle and leave the session running.
///
/// # Safety
/// `raw` is null, or a terminal the caller holds a user of.
pub unsafe fn tty_hangup(raw: *const Tty) {
    if !raw.is_null() {
        tty::close_external(&*unsafe { borrow(raw) });
    }
}

/// # Safety
/// `raw` and `watchers` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tty_open(
    raw: *const Tty,
    watchers: *const Watchers,
    flags: c_int,
) -> c_int {
    if raw.is_null() || watchers.is_null() {
        return tty::EINVAL;
    }
    tty::attach(
        &*unsafe { borrow(raw) },
        &*unsafe { borrow_watchers(watchers) },
        flags,
    )
}

// `tty_close` was here until 2026-09-30: `Arc::from_raw` of a pointer its one
// caller, `crates/fs/ttydev`, had made with `Arc::into_raw` from the `Arc` it
// held, then `tty::close`. That caller calls `tty::close` itself now. So do
// `tty_read`, `tty_write`, `tty_poll`, `tty_claim` and `tty_disown`'s callers,
// which is why those five went the same day with no caller left.

/// Bytes arriving from the driver side: the console's reader thread, or the
/// other end of a pty.
///
/// # Safety
/// `raw` is null, or a live `Tty` the caller holds a reference to.
///
/// `buf` was a `(*const u8, usize)` pair until 2026-09-15, with a
/// `buf.is_null() && len != 0` arm; the one caller passes a single byte as
/// `&raw const ch, 1`, which is `std::slice::from_ref`.
pub unsafe fn tty_input(raw: *const Tty, buf: &[u8], blocking: bool) -> isize {
    if raw.is_null() {
        return tty::EINVAL as isize;
    }
    tty::input(&*unsafe { borrow(raw) }, buf, blocking)
}

/// # Safety
/// `raw` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tty_set_winsize(raw: *const Tty, winsize: Winsize) {
    if !raw.is_null() {
        tty::set_winsize(&*unsafe { borrow(raw) }, winsize);
    }
}

// `tty_console_init_state` was here until 2026-09-30, over a raw pointer and
// a nullable `*const Termios`; it is `tty::set_console_state`.

/// How many bytes `arg` points at, 0 when it is a value, -1 when the command
/// is not one of ours.
pub fn tty_ioctl_size(cmd: c_int) -> isize {
    crate::ioctl::arg_size(cmd)
}

/// Run `cmd` over the argument the kernel copied in, as whichever shape
/// [`tty_ioctl_size`] said the command has.
///
/// It took a raw `*const Tty` and a `*mut u8` until 2026-09-30, and made
/// each shape a `&mut` straight into the kernel's byte buffer -- whose
/// alignment is one. A copy in and out has no alignment to get wrong.
pub fn tty_ioctl(tty_: &tty::Open, cmd: c_int, mut arg: ioctlarg::IoctlArg<'_>) -> c_int {
    use crate::ioctl::{self, Arg};
    let size = ioctl::arg_size(cmd);
    if size < 0 {
        return tty::ENOTTY;
    }
    if let ioctlarg::IoctlArg::Value(value) = arg {
        return ioctl::ioctl(tty_, cmd, Arg::Value(value));
    }
    // By size, which is what `arg_size` above answered for this command: 4 is
    // a word, 8 a `winsize`, 44 a `termios2` and 36 a `termios`. The size is
    // decided by the command, so a command whose argument is four bytes
    // cannot be handed a termios here.
    let done = match size as usize {
        4 => arg.with(|w| ioctl::ioctl(tty_, cmd, Arg::Word(w))),
        8 => arg.with(|w| ioctl::ioctl(tty_, cmd, Arg::Winsize(w))),
        n if n == size_of::<ldisc::Termios2>() => {
            arg.with(|t| ioctl::ioctl(tty_, cmd, Arg::Termios2(t)))
        }
        _ => arg.with(|t| ioctl::ioctl(tty_, cmd, Arg::Termios(t))),
    };
    done.unwrap_or(tty::EINVAL)
}

// === What devpts needs from the pty table ===

pub fn pty_slave_exists(num: c_int) -> bool {
    pty::exists(num)
}

/// The slave's owner, group and permission bits, or `None` for a number with
/// no pty. It wrote them through three out-parameters until 2026-09-30.
pub fn pty_slave_info(num: c_int) -> Option<(u32, u32, u32)> {
    pty::attrs(num)
}

pub fn pty_slave_set(num: c_int, which: c_int, value: u32) -> bool {
    pty::set_attr(num, which, value)
}

pub fn pty_slave_next(from: c_int) -> c_int {
    pty::next(from).unwrap_or(-1)
}

/// An embedder's terminal: writes go to its `driver->ops->write`, and it is
/// published at `/dev/pts/<number>` so the guest can open it.
///
/// The reference is the caller's: `User::into_raw`, released by `tty_release`.
///
/// Safe since 2026-10-17: this calls `write` only as [`ExternalWrite`] says,
/// with a live terminal and buffer. That the embedder's callback behind it
/// stays callable is the embedder's undertaking, taken on in
/// `crates/fs/ttydev`'s `pty_open_fake`, not something this could check.
///
/// [`ExternalWrite`]: crate::tty::ExternalWrite
///
/// It answered a null with the errno through a `*mut c_int` out-parameter
/// until 2026-09-16, over a `pty::open_external` that already answered a
/// `Result`. The `# Safety` section named `driver`, which is not a parameter
/// of this function -- it is `pty_open_fake`'s, one frame up -- so the half of
/// the contract that was real was stated about the wrong signature and the
/// half about `error` is gone with the out-parameter.
///
/// The `Option<ExternalWrite>` went too: its one caller always passed `Some`,
/// and the `None` arm answered `EINVAL` for a state no caller could reach.
pub fn tty_open_external(write: crate::tty::ExternalWrite) -> Result<*const Tty, c_int> {
    pty::open_external(write).map(tty::User::into_raw)
}

/// # Safety
/// `raw` must be live and `out` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tty_get_termios(raw: *const Tty, out: *mut ldisc::Termios) {
    if let (false, Some(out)) = (raw.is_null(), unsafe { out.as_mut() }) {
        *out = tty::termios(&*unsafe { borrow(raw) });
    }
}

/// # Safety
/// `raw` must be live and `termios` readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tty_set_termios(raw: *const Tty, termios: *const ldisc::Termios) {
    if let (false, Some(termios)) = (raw.is_null(), unsafe { termios.as_ref() }) {
        tty::set_termios(&*unsafe { borrow(raw) }, *termios);
    }
}

/// The number of this terminal, which `/dev/pts` names a slave by.
///
/// # Safety
/// `raw` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tty_number(raw: *const Tty) -> c_int {
    if raw.is_null() {
        return -1;
    }
    unsafe { &*raw }.num
}

