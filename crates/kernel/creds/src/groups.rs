//! What was a second copy of the raw-pointer adapter layer.
//!
//! Five `pub unsafe fn` over a `*const Groups` or a `*mut Groups` — `len`,
//! `as_slice().as_ptr()`, `get`, `set`, `contains` — each dereferencing the
//! pointer and calling the method of the same name, with `Result<_, c_int>`
//! flattened into an errno on the way out. Removed 2026-09-16 with the larger
//! one in `abi.rs`; see `crate`'s module comment.
//!
//! The header said "`struct groups` in kernel/creds.h is a byte array of the
//! same size, so C can embed one in `struct task` without knowing the shape",
//! and there is no `kernel/creds.h` — the headers went on 2026-09-09. The size
//! assertion below is kept, because `Groups` is still embedded by value in a
//! `#[repr(C)]` `Creds` and growing it is still a layout change; what it is
//! asserted *against* is this tree's own `struct task` now.

#[cfg(test)]
mod groups_tests {
    use crate::{EINVAL, Groups, MAX_GROUPS};

    /// `struct groups` in kernel/creds.h reserves this many bytes so C can
    /// embed one. Growing past it would be C writing off the end of a field.
    #[test]
    fn the_c_side_reserves_enough() {
        assert!(
            std::mem::size_of::<Groups>() <= 136,
            "struct groups in kernel/creds.h reserves 136 bytes, this needs {}",
            std::mem::size_of::<Groups>()
        );
        assert!(std::mem::align_of::<Groups>() <= 4);
    }

    #[test]
    fn a_zeroed_list_is_an_empty_one() {
        // There is no initialiser on the C side and there does not need to be:
        // `struct task` is zeroed when it is made, and a zeroed Groups has to
        // *be* the empty list rather than merely look like one. If a field is
        // ever added whose zero is not its empty value, this fails.
        let zeroed: Groups = unsafe { std::mem::zeroed() };
        assert_eq!(zeroed, Groups::new());
        assert_eq!(zeroed.len(), 0);
        assert_eq!(zeroed.as_slice(), &[] as &[u32]);
    }

    #[test]
    fn a_new_list_is_empty() {
        let g = Groups::new();
        assert_eq!(g.len(), 0);
        assert!(g.is_empty());
        assert_eq!(g.as_slice(), &[] as &[u32]);
        assert!(!g.contains(0));
    }

    #[test]
    fn what_is_set_is_what_is_read() {
        let mut g = Groups::new();
        assert_eq!(g.set(&[4, 8, 15]), Ok(()));
        assert_eq!(g.as_slice(), &[4, 8, 15]);
        assert_eq!(g.len(), 3);
        assert!(g.contains(8));
        assert!(!g.contains(9));
    }

    #[test]
    fn the_whole_list_fits_and_one_more_does_not() {
        let full: Vec<u32> = (0..MAX_GROUPS as u32).collect();
        let mut g = Groups::new();
        assert_eq!(g.set(&full), Ok(()));
        assert_eq!(g.len(), MAX_GROUPS as u32);
        let over: Vec<u32> = (0..MAX_GROUPS as u32 + 1).collect();
        assert_eq!(g.set(&over), Err(EINVAL));
        assert_eq!(g.len(), MAX_GROUPS as u32, "and a refusal changes nothing");
    }

    #[test]
    fn setting_a_shorter_list_forgets_the_rest() {
        // The count and the array used to be two fields, and a short setgroups
        // over a long one left the tail in place. Nothing read past the count,
        // but the two disagreed.
        let mut g = Groups::new();
        g.set(&[1, 2, 3, 4, 5]).unwrap();
        g.set(&[9]).unwrap();
        assert_eq!(g.as_slice(), &[9]);
        assert!(!g.contains(5), "and the tail is gone");
    }

    #[test]
    fn getgroups_of_zero_asks_the_count() {
        let mut g = Groups::new();
        g.set(&[1, 2, 3]).unwrap();
        assert_eq!(g.get(0), Ok(&[] as &[u32]), "writes nothing");
        assert_eq!(g.len(), 3);
    }

    #[test]
    fn getgroups_refuses_a_buffer_that_is_too_small() {
        // A short answer would look like a complete one.
        let mut g = Groups::new();
        g.set(&[1, 2, 3]).unwrap();
        assert_eq!(g.get(2), Err(EINVAL));
        assert_eq!(g.get(3), Ok(&[1, 2, 3][..]));
        assert_eq!(g.get(100), Ok(&[1, 2, 3][..]), "and a larger one is fine");
    }

    #[test]
    fn an_empty_list_answers_zero_for_any_size() {
        let g = Groups::new();
        assert_eq!(g.get(0), Ok(&[] as &[u32]));
        assert_eq!(g.get(1), Ok(&[] as &[u32]));
    }

    /// The rules `the_c_abi_round_trips` checked, on the methods themselves.
    ///
    /// It drove them through five `unsafe fn` over a `*mut Groups` until
    /// 2026-09-16, which is what made a `from_raw_parts` necessary to read the
    /// list back. The rules are the same and every one of them is a real
    /// `getgroups`/`setgroups` answer; what went is the pointer.
    #[test]
    fn the_size_argument_is_signed_and_a_short_buffer_is_refused() {
        let mut g = Groups::new();
        assert_eq!(g.len(), 0);
        assert_eq!(g.set(&[4, 8, 15]), Ok(()));
        assert_eq!(g.len(), 3);
        // Signed: -1 read as unsigned is larger than any count, so it looked
        // like plenty of room. Measured as EINVAL.
        assert_eq!(g.get(-1), Err(EINVAL));
        assert_eq!(g.get(0), Ok(&[] as &[u32]), "a size of 0 is the count question");
        assert_eq!(g.get(2), Err(EINVAL), "a short buffer is refused, not truncated");
        assert_eq!(g.get(3), Ok(&[4u32, 8, 15][..]));
        assert_eq!(g.as_slice(), &[4, 8, 15]);
        assert!(g.contains(8));
        assert!(!g.contains(9));

        let over: Vec<u32> = (0..MAX_GROUPS as u32 + 1).collect();
        assert_eq!(g.set(&over), Err(EINVAL));
        assert_eq!(g.len(), 3, "and a refusal changes nothing");

        // The empty set, which was `(null, 0)` -- a pair the callee had an arm
        // for and no caller could produce.
        assert_eq!(g.set(&[]), Ok(()), "an empty list is fine");
        assert_eq!(g.len(), 0);
    }
}
