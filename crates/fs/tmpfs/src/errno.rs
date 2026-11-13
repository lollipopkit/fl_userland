//! Guest errno values, from `crates/util/errno`.
//!
//! The C spelled a guest errno with a leading underscore to tell it from the
//! host's; there is no host errno in this crate, so the names are plain.

use libc::c_int;

pub use guest_errno::c_int_::{
    EBADF, EEXIST, EINVAL, EISDIR, ENAMETOOLONG, ENOENT, ENOMEM, ENOTDIR, ENOTEMPTY, EPERM,
};

pub type Result<T> = std::result::Result<T, c_int>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_values_are_the_ones_a_guest_expects() {
        // These cross the FFI boundary as plain ints; a wrong one is reported
        // to the guest as an unrelated failure. Written out rather than read
        // from the owner, which would make this a copy compared with itself.
        assert_eq!((EPERM, ENOENT, EBADF, ENOMEM), (-1, -2, -9, -12));
        assert_eq!((EEXIST, ENOTDIR, EISDIR, EINVAL), (-17, -20, -21, -22));
        assert_eq!((ENAMETOOLONG, ENOTEMPTY), (-36, -39));
    }
}
