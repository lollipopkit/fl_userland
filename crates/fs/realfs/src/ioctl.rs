//! The ioctls a passthrough descriptor answers.
//!
//! Only the terminal ones, and only because a guest's stdio may be a host pipe
//! that is itself connected to a real terminal. A program that asks whether it
//! is on a terminal, and then how big it is, gets a truthful answer about the
//! host's; anything else is not a terminal and is told so.

use std::os::fd::BorrowedFd;
use std::os::raw::c_int;

use rustix::termios::{
    self, ControlModes, InputModes, LocalModes, OptionalActions, OutputModes, Termios,
};

use crate::errno::{self, rx};
use crate::ffi;

/// How many bytes of `arg` the caller must make valid.
///
/// -1 means the command is not one of ours; 0 would mean the argument is not a
/// pointer, which none of these are.
pub fn realfs_ioctl_size(cmd: c_int) -> isize {
    match cmd as u32 {
        ffi::FIONREAD_ => size_of::<u32>() as isize,
        ffi::TCGETS_ | ffi::TCSETS_ | ffi::TCSETSW_ | ffi::TCSETSF_ => {
            size_of::<ffi::termios_>() as isize
        }
        ffi::TIOCGWINSZ_ => size_of::<ffi::winsize_>() as isize,
        _ => -1,
    }
}

/// `arg` is the buffer `realfs_ioctl_size` sized; a command whose handler
/// disagrees with that table answers `EINVAL` rather than writing past it.
pub fn realfs_ioctl(fd: &ffi::fd, cmd: c_int, mut arg: ffi::IoctlArg<'_>) -> c_int {
    let Some(host) = fd.host() else {
        return errno::ENOTTY;
    };
    match cmd as u32 {
        ffi::FIONREAD_ => match rx(rustix::io::ioctl_fionread(host)) {
            Ok(n) => written(arg.write(n as u32)),
            Err(e) => e,
        },

        ffi::TCGETS_ => {
            let Some(host) = host_termios(host) else {
                return errno::ENOTTY;
            };
            let out = ffi::termios_ {
                iflags: host.input_modes.bits() as u32,
                oflags: host.output_modes.bits() as u32,
                cflags: host.control_modes.bits() as u32,
                lflags: host.local_modes.bits() as u32,
                ..Default::default()
            };
            written(arg.write(out))
        }

        ffi::TCSETS_ | ffi::TCSETSW_ | ffi::TCSETSF_ => {
            // Node's ResetStdio calls tcsetattr on any descriptor it
            // previously saw as a terminal, and CHECK()s on any error other
            // than success or EPERM. For stdio backed by a host terminal the
            // settings are applied; for anything else there is nothing to
            // apply and nothing to complain about.
            if let Some(mut t) = host_termios(host) {
                let Some(want) = arg.read::<ffi::termios_>() else {
                    return errno::EINVAL;
                };
                t.input_modes = InputModes::from_bits_retain(want.iflags as _);
                t.output_modes = OutputModes::from_bits_retain(want.oflags as _);
                t.control_modes = ControlModes::from_bits_retain(want.cflags as _);
                t.local_modes = LocalModes::from_bits_retain(want.lflags as _);
                let when = match cmd as u32 {
                    ffi::TCSETSW_ => OptionalActions::Drain,
                    ffi::TCSETSF_ => OptionalActions::Flush,
                    _ => OptionalActions::Now,
                };
                let _ = termios::tcsetattr(host, when, &t);
            }
            0
        }

        ffi::TIOCGWINSZ_ => {
            // libuv asks during uv_tty_init.
            if !termios::isatty(host) {
                return errno::ENOTTY;
            }
            let Ok(size) = termios::tcgetwinsize(host) else {
                return errno::ENOTTY;
            };
            let out = ffi::winsize_ {
                row: size.ws_row,
                col: size.ws_col,
                xpixel: size.ws_xpixel,
                ypixel: size.ws_ypixel,
            };
            written(arg.write(out))
        }

        _ => errno::ENOTTY,
    }
}

/// 0 for a stored answer, `EINVAL` for a buffer the size table did not make.
fn written(ok: bool) -> c_int {
    if ok { 0 } else { errno::EINVAL }
}

/// The host terminal settings, if this descriptor is on a terminal at all.
fn host_termios(host: BorrowedFd<'_>) -> Option<Termios> {
    if !termios::isatty(host) {
        return None;
    }
    termios::tcgetattr(host).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_answered_has_a_size_and_the_rest_have_none() {
        for cmd in [
            ffi::FIONREAD_,
            ffi::TCGETS_,
            ffi::TCSETS_,
            ffi::TCSETSW_,
            ffi::TCSETSF_,
            ffi::TIOCGWINSZ_,
        ] {
            assert!(
                realfs_ioctl_size(cmd as c_int) > 0,
                "{cmd:#x} is answered but has no size"
            );
        }
        // The size is what the caller uses to make `arg` valid, so a command
        // with the wrong one is a buffer overrun waiting for a guest to ask.
        assert_eq!(realfs_ioctl_size(ffi::FIONREAD_ as c_int), 4);
        assert_eq!(realfs_ioctl_size(0x1234), -1);
        assert_eq!(realfs_ioctl_size(0), -1);
    }
}
