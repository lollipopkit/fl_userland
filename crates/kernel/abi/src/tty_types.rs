//! Guest terminal callback and device ABI layouts.

use crate::tty;

pub type tty_external_write_t = Option<
    unsafe extern "C" fn(
        tty: *const tty,
        buf: *const std::ffi::c_void,
        len: usize,
        blocking: bool,
    ) -> std::ffi::c_int,
>;
/// `struct winsize_` and `struct termios_` are the terminal's, re-exported
/// under their C names. This file had its own `#[repr(C)]` copy of each until
/// 2026-09-30, beside `fs_tty::tty::Winsize` and `ldisc::Termios` with the
/// same fields -- a second rendering, which `crates/fs/realfs`'s ioctls wrote
/// through while the terminal's wrote through the first.
pub use fs_tty::tty::Winsize as winsize_;
pub use ldisc::Termios as termios_;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct tty_driver_ops {
    pub init: Option<unsafe extern "C" fn(tty: *mut tty) -> std::ffi::c_int>,
    pub open: Option<unsafe extern "C" fn(tty: *mut tty) -> std::ffi::c_int>,
    pub close: Option<unsafe extern "C" fn(tty: *mut tty) -> std::ffi::c_int>,
    pub write: Option<
        unsafe extern "C" fn(
            tty: *mut tty,
            buf: *const std::ffi::c_void,
            len: usize,
            blocking: bool,
        ) -> std::ffi::c_int,
    >,
    pub ioctl: Option<
        unsafe extern "C" fn(
            tty: *mut tty,
            cmd: std::ffi::c_int,
            arg: *mut std::ffi::c_void,
        ) -> std::ffi::c_int,
    >,
    pub cleanup: Option<unsafe extern "C" fn(tty: *mut tty)>,
}
const _: () = {
    assert!(
        std::mem::size_of::<tty_driver_ops>() == 48,
        "Size of tty_driver_ops"
    );
    assert!(
        std::mem::align_of::<tty_driver_ops>() == 8,
        "Alignment of tty_driver_ops"
    );
    assert!(
        std::mem::offset_of!(tty_driver_ops, init) == 0,
        "Offset of field: tty_driver_ops::init"
    );
    assert!(
        std::mem::offset_of!(tty_driver_ops, open) == 8,
        "Offset of field: tty_driver_ops::open"
    );
    assert!(
        std::mem::offset_of!(tty_driver_ops, close) == 16,
        "Offset of field: tty_driver_ops::close"
    );
    assert!(
        std::mem::offset_of!(tty_driver_ops, write) == 24,
        "Offset of field: tty_driver_ops::write"
    );
    assert!(
        std::mem::offset_of!(tty_driver_ops, ioctl) == 32,
        "Offset of field: tty_driver_ops::ioctl"
    );
    assert!(
        std::mem::offset_of!(tty_driver_ops, cleanup) == 40,
        "Offset of field: tty_driver_ops::cleanup"
    );
};
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct tty_driver {
    pub ops: *const tty_driver_ops,
    pub major: std::ffi::c_int,
    pub limit: std::ffi::c_uint,
}
const _: () = {
    assert!(
        std::mem::size_of::<tty_driver>() == 16,
        "Size of tty_driver"
    );
    assert!(
        std::mem::align_of::<tty_driver>() == 8,
        "Alignment of tty_driver"
    );
    assert!(
        std::mem::offset_of!(tty_driver, ops) == 0,
        "Offset of field: tty_driver::ops"
    );
    assert!(
        std::mem::offset_of!(tty_driver, major) == 8,
        "Offset of field: tty_driver::major"
    );
    assert!(
        std::mem::offset_of!(tty_driver, limit) == 12,
        "Offset of field: tty_driver::limit"
    );
};
