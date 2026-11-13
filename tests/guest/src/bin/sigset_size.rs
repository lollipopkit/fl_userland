//! `rt_sigprocmask` and friends take a `sigsetsize`, and Linux requires it to
//! be **exactly** `sizeof(sigset_t)` -- 8 on aarch64. Anything else is EINVAL.
//!
//! This kernel accepted any multiple of 8 that was at least 8.

use guest_tests::{Harness, check};

fn rt_sigprocmask(how: i32, size: usize) -> i32 {
    let set = [0u64; 16];
    let r = unsafe {
        libc::syscall(libc::SYS_rt_sigprocmask, how, set.as_ptr(), std::ptr::null_mut::<u64>(), size)
    };
    if r < 0 { -std::io::Error::last_os_error().raw_os_error().unwrap_or(0) } else { r as i32 }
}

fn main() {
    let mut h = Harness::new();
    h.group("sigsetsize-is-exact");

    // The control first: the size every libc actually passes must work.
    check!(h, rt_sigprocmask(libc::SIG_BLOCK, 8) == 0,
        "sigsetsize of 8 is accepted: {}", rt_sigprocmask(libc::SIG_BLOCK, 8));

    for bad in [16usize, 24, 128, 4, 0, 1] {
        let r = rt_sigprocmask(libc::SIG_BLOCK, bad);
        check!(h, r == -libc::EINVAL,
            "sigsetsize of {bad} is EINVAL: got {r}");
    }

    // `how` is the other argument with a fixed set of values, and the shape
    // worth checking is the same: a `match` whose `_` arm does something rather
    // than refusing. Linux's `do_sigprocmask` switches on `how` **inside**
    // `if (set)`, so an unknown `how` with a NULL `set` is not an error and one
    // with a real `set` is `EINVAL`. Both halves, because a blanket refusal and
    // a blanket accept each satisfy one of them.
    h.group("how-is-a-closed-set");

    for good in [libc::SIG_BLOCK, libc::SIG_UNBLOCK, libc::SIG_SETMASK] {
        let r = rt_sigprocmask(good, 8);
        check!(h, r == 0, "how={good} is accepted: got {r}");
    }
    for bad in [3i32, 4, -1, 99] {
        let r = rt_sigprocmask(bad, 8);
        check!(h, r == -libc::EINVAL, "how={bad} with a set is EINVAL: got {r}");
    }

    // The same `how` values with no set: nothing to change, so nothing to
    // refuse. This is the half a blanket `EINVAL` on `how` would fail.
    for bad in [3i32, 99] {
        let mut old = [0u64; 2];
        let r = unsafe {
            libc::syscall(libc::SYS_rt_sigprocmask, bad, std::ptr::null::<u64>(),
                          old.as_mut_ptr(), 8usize)
        };
        check!(h, r == 0, "how={bad} with a NULL set still reports the mask: got {r}");
    }

    // Unblock everything again so the harness is not left with a mask.
    let empty = [0u64; 16];
    unsafe {
        libc::syscall(libc::SYS_rt_sigprocmask, libc::SIG_SETMASK,
                      empty.as_ptr(), std::ptr::null_mut::<u64>(), 8usize);
    }
    std::process::exit(h.finish());
}
