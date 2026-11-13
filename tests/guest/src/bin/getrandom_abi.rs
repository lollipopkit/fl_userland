//! `getrandom(2)`: what it accepts, and how much it delivers at once.
//!
//! The two rules that had defects are both about a guest being told the wrong
//! thing rather than getting wrong bytes:
//!
//! - a request larger than a megabyte answered `EIO`, where Linux answers a
//!   **short count** up to 32 MB and every libc loops on that;
//! - a flag outside the three Linux defines was accepted, so a guest asking for
//!   behaviour this kernel does not have was told it got it.
//!
//! Comparable against a real kernel: `getrandom` needs no privilege and Docker's
//! seccomp profile allows it.

use guest_tests::{Harness, check, check_fails, sys};

/// The three Linux defines.
const GRND_NONBLOCK: u32 = 0x0001;
const GRND_RANDOM: u32 = 0x0002;
const GRND_INSECURE: u32 = 0x0004;

fn getrandom(buf: *mut u8, len: usize, flags: u32) -> isize {
    sys::clear_errno();
    unsafe { libc::syscall(libc::SYS_getrandom, buf, len, flags) as isize }
}

fn main() {
    let mut h = Harness::new();
    h.group("getrandom");

    // The three flags Linux defines are accepted. None of them changes what a
    // correct answer looks like here -- the host supplies the bytes and is
    // always ready -- so what is checked is that they are not refused.
    for (name, f) in [
        ("no flags", 0),
        ("GRND_NONBLOCK", GRND_NONBLOCK),
        ("GRND_RANDOM", GRND_RANDOM),
        ("GRND_INSECURE", GRND_INSECURE),
        ("GRND_NONBLOCK|GRND_RANDOM", GRND_NONBLOCK | GRND_RANDOM),
        ("GRND_NONBLOCK|GRND_INSECURE", GRND_NONBLOCK | GRND_INSECURE),
    ] {
        let mut buf = [0u8; 16];
        let r = getrandom(buf.as_mut_ptr(), buf.len(), f);
        check!(h, r == 16, "{name}: r={r} errno={}", sys::errno());
    }

    // GRND_INSECURE asks for whatever the pool has and GRND_RANDOM asks for the
    // pool that blocks, so together they are EINVAL -- which is not "an
    // undefined bit" and is not in the man page. A real arm64 kernel refuses
    // 0x6 and 0x7 and accepts the other six combinations.
    for f in [GRND_RANDOM | GRND_INSECURE, GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE] {
        let mut buf = [0u8; 16];
        check_fails!(
            h,
            getrandom(buf.as_mut_ptr(), buf.len(), f),
            libc::EINVAL,
            "GRND_RANDOM with GRND_INSECURE ({f:#x})"
        );
    }

    // And a flag outside the set is refused.
    for f in [0x0008u32, 0x0010, 0x8000_0000] {
        let mut buf = [0u8; 16];
        check_fails!(
            h,
            getrandom(buf.as_mut_ptr(), buf.len(), f),
            libc::EINVAL,
            "flag {f:#x}"
        );
    }

    // Zero bytes is a legal request.
    let r = getrandom(std::ptr::null_mut(), 0, 0);
    check!(h, r == 0, "a zero-length request: r={r} errno={}", sys::errno());

    // Two megabytes in one call. This answered EIO; Linux answers a count.
    //
    // The comparison is `> 0` rather than `== len` on purpose: Linux is allowed
    // to return a short count, and a test that demanded the whole thing would
    // be asserting more than the interface promises.
    let mut big = vec![0u8; 2 * 1024 * 1024];
    let r = getrandom(big.as_mut_ptr(), big.len(), 0);
    check!(
        h,
        r > 0,
        "two megabytes in one call: r={r} errno={}",
        sys::errno()
    );
    check!(
        h,
        r <= big.len() as isize,
        "and no more than was asked for: {r} of {}",
        big.len()
    );
    if r > 0 {
        // The bytes it says it wrote are not all zero. Without this the check
        // above passes against a kernel that returns a count and writes
        // nothing, which is exactly the shape of the bug next door in
        // `syslog`.
        let written = &big[..r as usize];
        check!(
            h,
            written.iter().any(|&b| b != 0),
            "and wrote something: {r} bytes, all zero"
        );
    }

    // Successive calls differ. 32 bytes matching would be a 1-in-2^256 event,
    // so this is a check on the source rather than a flake.
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    getrandom(a.as_mut_ptr(), a.len(), 0);
    getrandom(b.as_mut_ptr(), b.len(), 0);
    check!(h, a != b, "two calls give different bytes");

    // An unmapped destination faults.
    check_fails!(
        h,
        getrandom(0x7fff_0000_0000usize as *mut u8, 64, 0),
        libc::EFAULT,
        "an unmapped destination"
    );

    std::process::exit(h.finish());
}
