use super::fatal::fatal_exit_status;
use super::*;

#[test]
fn the_exit_status_of_a_fatal_signal() {
    let (trap, abrt, segv, ill, bus, term) = (5, 6, 11, 4, 7, 15);
    // Ordinary: the signal number.
    for sig in [trap, abrt, segv, ill, bus, term] {
        assert_eq!(
            fatal_exit_status(sig, false, 0x40_0000, false),
            sig,
            "sig {sig}"
        );
    }
    // A process that has printed V8's fatal preamble exits 0 for the three
    // signals V8's own abort produces, and not for others.
    for sig in [trap, abrt, segv] {
        assert_eq!(fatal_exit_status(sig, true, 0x40_0000, false), 0);
    }
    assert_eq!(fatal_exit_status(term, true, 0x40_0000, false), term);
    // The pc-range rule is behind the switch, and applies to SIGILL and
    // SIGBUS in the range only.
    assert_eq!(
        fatal_exit_status(ill, false, 0xc000_0000, false),
        ill,
        "off by default"
    );
    assert_eq!(fatal_exit_status(ill, false, 0xc000_0000, true), 1 << 8);
    assert_eq!(fatal_exit_status(bus, false, 0xefff_0000, true), 1 << 8);
    assert_eq!(
        fatal_exit_status(ill, false, 0xf000_0000, true),
        ill,
        "just past the range"
    );
    assert_eq!(
        fatal_exit_status(segv, false, 0xc000_0000, true),
        segv,
        "not SIGSEGV"
    );
}

#[test]
fn kernel_info_says_si_kernel_and_nothing_else() {
    // Read as bytes rather than through `.code`, because what is being
    // checked is the *offset* a guest reads si_code at: naming the field
    // would assert the struct against itself.
    let info = kernel_info();
    let bytes = kernel_sigqueue::as_bytes(&info);
    assert_eq!(i32::from_ne_bytes(bytes[8..12].try_into().unwrap()), 128);
    assert!(bytes[..8].iter().all(|&b| b == 0));
    assert!(bytes[12..].iter().all(|&b| b == 0));
}

/// Bytes 12..16 are zero however dirty the stack was.
///
/// They were padding until 2026-09-30, and a struct literal built with
/// `..SigInfo::default()` left them as whatever the stack held: this failed
/// 1000 times in 1000, debug and release, and `kernel_info_says_si_kernel_and_nothing_else`
/// above failed once in a full `cargo test --workspace` for the same reason.
/// The stack is dirtied first so that the answer does not depend on what ran
/// before.
#[test]
fn the_bytes_after_si_code_are_zero_on_a_dirty_stack() {
    #[inline(never)]
    fn dirty() {
        let a = [0xa5u8; 8192];
        std::hint::black_box(&a);
    }
    #[inline(never)]
    fn after_code() -> [u8; 4] {
        let info = kernel_info();
        kernel_sigqueue::as_bytes(&info)[12..16].try_into().unwrap()
    }
    for _ in 0..1000 {
        dirty();
        assert_eq!(after_code(), [0; 4]);
    }
}
