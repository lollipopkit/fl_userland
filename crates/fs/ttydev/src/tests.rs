//! Tests for terminal device operation table and console defaults.

use super::*;

/// A terminal's `ioctl` is **reachable**.
///
/// The pair `tools/ops-table-pairs.py` exists for: `fd_ioctl` asks the driver
/// how large the argument is and answers `ENOTTY` for a negative, *before* it
/// calls the handler at all. `/dev/random` shipped that way in every revision.
///
/// It used to assert that both `Option<fn>` fields were `Some`, which a trait
/// has nothing to say — there is no field to be `None`. So it asks the
/// question instead: the size for a command every terminal implements. Leaving
/// `ioctl_size` to [`ffi::FdOps`]'s default, which refuses every command, is
/// the mistake this catches, and that default is exactly what a missing field
/// used to be.
#[test]
fn a_terminals_ioctl_is_reachable() {
    use ffi::FdOps as _;
    /// `TCGETS`, which is what `isatty` asks.
    const TCGETS: c_int = 0x5401;
    assert!(
        TTY_FDOPS.ioctl_size(TCGETS) > 0,
        "fd_ioctl would answer ENOTTY without calling the handler"
    );
}

#[test]
fn the_console_defaults_to_tty1() {
    assert_eq!(console_device(), (ffi::TTY_CONSOLE_MAJOR as c_int, 1));
}
