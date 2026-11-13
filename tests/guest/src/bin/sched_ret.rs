//! `sched_setscheduler`'s return value never reached the guest.
//!
//! The syscall dispatcher skipped the x0 writeback for numbers 139 and 119,
//! commented "rt_sigreturn" and "sigreturn" -- those are the *i386* numbers.
//! On aarch64 there is no `sigreturn` syscall at all and 119 is
//! `sched_setscheduler`, so its result was dropped and the guest read back
//! whatever x0 held, which is the first argument: the pid.

use guest_tests::{Harness, check};

fn setscheduler(pid: i32, policy: i32, prio: i32) -> i64 {
    let param = prio;
    unsafe { libc::syscall(libc::SYS_sched_setscheduler, pid, policy, &raw const param) }
}

fn main() {
    let mut h = Harness::new();
    h.group("sched_setscheduler-returns-something");

    // This kernel implements SCHED_OTHER only, so a realtime policy is EINVAL.
    // With the writeback skipped the guest saw x0 unchanged -- the pid.
    let r = setscheduler(0, libc::SCHED_FIFO, 1);
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::EINVAL,
        "a realtime policy is refused: r={r} errno={e}");

    // A non-zero priority under SCHED_OTHER is EINVAL too.
    let r = setscheduler(0, libc::SCHED_OTHER, 1);
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::EINVAL,
        "a non-zero priority under SCHED_OTHER is refused: r={r} errno={e}");

    // The control: the one call this kernel accepts must still succeed, so the
    // checks above are not satisfied by a syscall that refuses everything.
    let r = setscheduler(0, libc::SCHED_OTHER, 0);
    check!(h, r == 0, "SCHED_OTHER with priority 0 succeeds: r={r}");

    // And with a real pid rather than 0, which is where the old behaviour was
    // most visible: x0 held the pid, so the call "returned" it.
    let pid = unsafe { libc::getpid() };
    let r = setscheduler(pid, libc::SCHED_FIFO, 1);
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r != pid as i64,
        "the return value is not just the pid read back: r={r} pid={pid}");
    check!(h, r == -1 && e == libc::EINVAL,
        "and is the errno: r={r} errno={e}");

    h.group("signals-still-return");
    // Removing the 119 case must not disturb 139. A handler that runs and
    // returns exercises rt_sigreturn, whose x0 is restored from the frame and
    // must still not be overwritten.
    static mut RAN: i32 = 0;
    extern "C" fn on_usr1(_: i32) {
        unsafe { RAN += 1 };
    }
    // Through a fn pointer, not a direct cast of the fn item: `on_usr1 as
    // usize` is a cast of a zero-sized item rather than of its address, which
    // rustc now warns about because it is not the thing it reads like.
    unsafe { libc::signal(libc::SIGUSR1, on_usr1 as extern "C" fn(i32) as usize) };
    let before = unsafe { libc::getpid() };
    unsafe { libc::raise(libc::SIGUSR1) };
    check!(h, unsafe { RAN } == 1, "the handler ran and returned");
    check!(h, unsafe { libc::getpid() } == before,
        "and the guest is intact afterwards");

    std::process::exit(h.finish());
}
