//! A pointer-shaped negative errno: [`err_ptr`], [`ptr_err`], [`is_err`].
//!
//! # Why this exists rather than a `Result`
//!
//! It is the **embedder interface**. `iul.h` states the convention and three
//! of its declarations answer one:
//!
//! ```c
//! #define ERR_PTR(err) (void *) (intptr_t) (err)
//! #define PTR_ERR(ptr) (intptr_t) (ptr)
//! #define IS_ERR(ptr) ((uintptr_t) (ptr) > (uintptr_t) -0xfff)
//!
//! struct fd *generic_open(const char *path, int flags, int mode);
//! struct fd *realfs_open(struct mount *, const char *, int, int);
//! ```
//!
//! So the convention cannot leave the tree, the way `realfs_write`'s pointer
//! and length could not. What it can do is stop being spelled ten times.
//!
//! # It was ten renderings in four spellings, and two of them disagreed
//!
//! Measured 2026-09-14, before this module existed:
//!
//! | spelling | where | the range it calls an error |
//! | --- | --- | --- |
//! | `(p as usize) > usize::MAX - 0xfff` | `kernel/pathcalls`, `kernel/execcalls`, `kernel/forkcalls`, `fs/generic`, and a test in `kernel/taskcalls` | `-4095..=-1` |
//! | `(p as usize) > (-0xfffisize) as usize` | `kernel/boot` ×2, `kernel/timecalls`, `tools/iul` | `-4094..=-1` |
//! | `(p as isize) < 0 && (p as isize) > -4096` | `fs/fake` | `-4095..=-1` |
//! | `(fd as usize) > usize::MAX - 0xfff`, inline | `fs/generic`'s `open` | `-4095..=-1` |
//!
//! **`-0xfff` is itself not an error**, which is the second row and is what
//! `iul.h` says; six of the ten said it was. Nothing observes the difference,
//! because the largest errno this kernel has is 133 — so this is the shape
//! that is wrong without being a bug, and it is the third of its kind in this
//! crate after `siginfo_` and `timeval_`. One definition, matching the header
//! that states the contract, and a test that asserts the boundary from both
//! sides.
//!
//! Six `err_ptr` and three `ptr_err` went the same way, for the same reason:
//! a conversion written per crate is a conversion that can differ per crate.

use std::ffi::c_int;

/// The largest errno the convention can carry, as `iul.h` writes it.
///
/// The bound is exclusive: a pointer **equal** to `-ERR_MAX` is a pointer.
const ERR_MAX: isize = 0xfff;

/// A negative errno as a pointer.
pub fn err_ptr<T>(e: c_int) -> *mut T {
    e as isize as *mut T
}

/// The errno back out of one. Meaningless unless [`is_err`] says so.
pub fn ptr_err<T>(p: *const T) -> c_int {
    p as isize as c_int
}

/// Whether this is an errno rather than an address.
pub fn is_err<T>(p: *const T) -> bool {
    is_err_value(p as usize)
}

/// The same question about a value that is not a pointer.
///
/// `crates/kernel/timecalls` puts a `timer_id_t` through this convention, and
/// a timer id is an integer — so the predicate is the integer one and
/// [`is_err`] is the pointer's spelling of it, rather than the other way
/// round.
pub fn is_err_value(v: usize) -> bool {
    v > (-ERR_MAX) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The boundary, from both sides, because six of the ten renderings had it
    /// one value out.
    #[test]
    fn the_error_range_is_the_top_4094_addresses() {
        assert!(is_err(err_ptr::<u8>(-1)));
        assert!(is_err(err_ptr::<u8>(-12)));
        assert!(is_err((-0xffeisize) as *const u8), "-4094 is an errno");
        assert!(
            !is_err((-ERR_MAX) as *const u8),
            "-4095 is not: `IS_ERR` in iul.h is a strict `>`"
        );
        assert!(!is_err(std::ptr::null::<u8>()));
        assert!(!is_err(0x1000 as *const u8));
        // The high half of the address space is not an error either, which is
        // what makes the bound exclusive rather than "negative".
        assert!(!is_err((isize::MIN) as *const u8));
    }

    #[test]
    fn a_round_trip_answers_the_errno_it_was_given() {
        for e in [-1, -12, -133] {
            let p = err_ptr::<u8>(e);
            assert!(is_err(p));
            assert_eq!(ptr_err(p), e);
        }
    }

    /// The integer form and the pointer form are one predicate.
    #[test]
    fn the_value_form_agrees_with_the_pointer_form() {
        for v in [0usize, 1, 0x1000, (-0xffeisize) as usize, (-ERR_MAX) as usize] {
            assert_eq!(is_err_value(v), is_err(v as *const u8));
        }
    }
}
