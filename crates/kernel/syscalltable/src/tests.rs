use super::table::is_reported;
use super::*;

/// The name test the flag is built from, in both directions.
#[test]
fn only_the_reporting_stubs_name_matches() {
    assert!(is_reported("syscall_stub"));
    assert!(!is_reported("syscall_silent_stub"));
    assert!(!is_reported("syscall_success_stub"));
    assert!(!is_reported("sys_read"));
    assert!(!is_reported("syscall_stu"));
    assert!(!is_reported("syscall_stubb"));
}

/// The widening rules, which are the part of `answer` a hand-written wrapper
/// gets wrong.
///
/// The dispatcher narrows a syscall that is not in [`returns_64bit`] back to 32
/// bits and decides there whether to sign- or zero-extend, so what matters here
/// is that the 64 bits `answer` produces carry the same *32* bits the C ABI
/// return did -- a `u32` must not arrive sign-extended, or `personality`'s
/// `0xfffffffe` becomes the errno -2.
#[test]
fn a_success_widens_the_way_its_own_type_does() {
    use guest_errno::Errno;

    assert_eq!(answer::<()>(Ok(())), 0);
    assert_eq!(answer(Ok(7u32)), 7);
    assert_eq!(answer(Ok(u32::MAX)), 0xffff_ffff, "a u32 zero-extends");
    assert_eq!(answer(Ok(-2i32)), -2, "an i32 sign-extends");
    assert_eq!(answer(Ok(u64::MAX)), -1i64, "a u64 keeps all 64 bits");
    assert_eq!(answer(Ok(1usize << 40)), 1 << 40);
    assert_eq!(answer(Ok(-1isize)), -1);
    assert_eq!(answer(Ok(true)), 1);
    assert_eq!(answer(Ok(false)), 0);

    // And the error side is the number the guest reads, unchanged.
    assert_eq!(answer::<()>(Err(Errno::EINVAL)), -22);
    assert_eq!(answer::<u32>(Err(Errno::EBADF)), -9);
    assert_eq!(answer::<i64>(Err(Errno::ETIMEDOUT)), -110);
}

/// The seven, and one that is deliberately not there.
#[test]
fn the_wide_returns_are_the_seven() {
    for n in [62, 92, 167, 196, 214, 216, 222] {
        assert!(returns_64bit(n), "{n}");
    }
    assert!(
        !returns_64bit(139),
        "rt_sigreturn's writeback is skipped entirely"
    );
    assert!(!returns_64bit(63), "read is a dword_t");
}
