//! Host errno to guest errno.
//!
//! Everything in this crate is a host call, so unlike tmpfs — which invents
//! its own errors and never sees a host one — the errors here all arrive as
//! `errno` and have to be translated. The translation lives in the kernel
//! (`kernel/errno.c`) and is not duplicated here, because it is not a pure
//! table: `errno_map` sends SIGPIPE to the current task when the error is
//! EPIPE, and a second implementation would silently drop that.
//!
//! The rule that makes calling it safe is that it reads the thread's `errno`,
//! so it has to be called immediately after the call that failed. `ck` exists
//! so that there is nowhere to put anything in between.
//!
//! It is a Rust call into `crates/kernel/errno` since 2026-09-04; it used to
//! go out through this crate's bindgen and back in, which is one `unsafe`
//! block per call for a function that has no unsafe in it.

use libc::c_int;

pub type Result<T> = std::result::Result<T, c_int>;

/// A host return value where negative means failure.
pub trait Failable: Copy {
    fn failed(self) -> bool;
}

macro_rules! failable_signed {
    ($($t:ty),*) => {$(
        impl Failable for $t {
            fn failed(self) -> bool {
                self < 0
            }
        }
    )*};
}
failable_signed!(i32, i64, isize);

/// Translate a host call's return value, reading `errno` only if it failed.
///
/// Must be applied to the call itself — `ck(libc::unlink(p))` — and not to a
/// value stored in a local first, or an intervening call can overwrite the
/// `errno` this reads.
pub fn ck<T: Failable>(res: T) -> Result<T> {
    if res.failed() {
        Err(kernel_errno::errno_map())
    } else {
        Ok(res)
    }
}

/// A `rustix` call's result, translated. `rustix` hands back the errno it
/// read, so unlike [`ck`] there is no window for anything to overwrite it.
pub fn rx<T>(res: rustix::io::Result<T>) -> Result<T> {
    res.map_err(|e| kernel_errno::raised(e.raw_os_error()))
}

/// The same for `std::io`.
pub fn io<T>(res: std::io::Result<T>) -> Result<T> {
    res.map_err(io_err)
}

/// One `std::io` error, translated. An error `std` made up itself rather than
/// read from the host carries no errno, and is `EIO`.
pub fn io_err(e: std::io::Error) -> c_int {
    kernel_errno::raised(e.raw_os_error().unwrap_or(libc::EIO))
}

/// A guest errno as a C ABI return, 0 on success.
pub fn status(res: Result<()>) -> c_int {
    res.err().unwrap_or(0)
}

/// A type that can carry a negative guest errno in place of a value, which is
/// how every function in this crate reports failure across the C ABI.
pub trait FromErrno: Copy {
    fn from_errno(err: c_int) -> Self;
}

macro_rules! from_errno {
    ($($t:ty),*) => {$(
        impl FromErrno for $t {
            fn from_errno(err: c_int) -> Self {
                err as $t
            }
        }
    )*};
}
from_errno!(i32, i64, isize);

/// A `Result` flattened the way the C ABI wants it.
pub fn flat<T: FromErrno>(res: Result<T>) -> T {
    match res {
        Ok(v) => v,
        Err(e) => T::from_errno(e),
    }
}

/// Guest errno constants used where this crate answers without asking the
/// host — the values are Linux's, negated, as everywhere else in the tree.
pub use guest_errno::c_int_::{
    EBADF, EINTR, EINVAL, EIO, EISDIR, ENAMETOOLONG, ENOMEM, ENOTTY, EPERM,
};
