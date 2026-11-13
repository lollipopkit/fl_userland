//! `/proc/<pid>/status`'s four signal masks say which signal, not roughly which.
//!
//! `SigPnd`, `SigBlk`, `SigIgn` and `SigCgt` are 64-bit masks in which **bit
//! `n - 1` is signal `n`** — the convention every mask in a `sigset_t` uses. A
//! reader of this file is `ps`, `gdb`, or a supervisor deciding whether a
//! process will act on the signal it is about to send, so an answer that is
//! right to within one bit is wrong.
//!
//! This kernel built the two disposition masks with
//!
//! ```c
//! for (int i = 0; i < 32; i++) {
//!     uint64_t h = sigdisp_handler(task->sighand->disp, i);
//!     if (h == SIG_IGN_) out->ignored |= 1ul << i;
//! ```
//!
//! which is wrong three times over: it reads a signal 0 that does not exist,
//! reports every disposition one bit too high, and never looks at signals
//! 33..64 at all. `SigBlk` beside it came from the real mask and was right, so
//! the same file answered in two different conventions.
//!
//! Compared against a real kernel by `differential.sh`, which is the point:
//! every check here is one both sides can meet.

use guest_tests::{Harness, check};

extern "C" fn on_signal(_: libc::c_int) {}

/// One `Sig*:` line of `/proc/self/status`, as the number it spells.
fn status_mask(field: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("read status");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            let hex = rest.trim_start_matches(':').trim();
            return u64::from_str_radix(hex, 16).unwrap_or_else(|e| {
                panic!("{field} is {hex:?}, which is not hex: {e}");
            });
        }
    }
    panic!("no {field} line in /proc/self/status");
}

fn catch(sig: libc::c_int) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as *const () as usize;
        assert_eq!(libc::sigaction(sig, &sa, std::ptr::null_mut()), 0);
    }
}

fn ignore(sig: libc::c_int) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_IGN;
        assert_eq!(libc::sigaction(sig, &sa, std::ptr::null_mut()), 0);
    }
}

fn bit(sig: libc::c_int) -> u64 {
    1u64 << (sig - 1)
}

fn main() {
    let mut h = Harness::new();

    h.group("a-caught-signal-is-bit-n-minus-one");
    catch(libc::SIGINT); // 2
    let caught = status_mask("SigCgt");
    check!(
        h,
        caught & bit(libc::SIGINT) != 0,
        "SIGINT caught: SigCgt {caught:#x} has bit {}",
        libc::SIGINT - 1
    );
    check!(
        h,
        caught & bit(libc::SIGINT + 1) == 0,
        "and not the bit above it: SigCgt {caught:#x}"
    );

    h.group("an-ignored-signal-is-in-the-other-mask");
    ignore(libc::SIGHUP); // 1, so bit 0 -- the one a shift by the signal number
    // cannot produce at all
    let ignored = status_mask("SigIgn");
    let caught = status_mask("SigCgt");
    check!(
        h,
        ignored & bit(libc::SIGHUP) != 0,
        "SIGHUP ignored: SigIgn {ignored:#x} has bit 0"
    );
    check!(
        h,
        caught & bit(libc::SIGHUP) == 0,
        "and is not also reported as caught: SigCgt {caught:#x}"
    );

    h.group("the-two-masks-are-disjoint");
    check!(
        h,
        ignored & caught == 0,
        "SigIgn {ignored:#x} and SigCgt {caught:#x} share no bit"
    );

    h.group("a-realtime-signal-is-reported-at-all");
    // Signals 33..64 were outside the loop's range entirely, so a process that
    // caught one was reported as catching nothing. 35 rather than 34: musl
    // reserves the first two realtime signals for its own use, and installing a
    // handler for one of those is not a thing a program may do.
    const RT: libc::c_int = 35;
    catch(RT);
    let caught = status_mask("SigCgt");
    check!(
        h,
        caught & bit(RT) != 0,
        "signal {RT} caught: SigCgt {caught:#x} has bit {}",
        RT - 1
    );

    h.group("blocked-uses-the-same-convention");
    // SigBlk came from the real mask and was always right, which is what made
    // the other two hard to notice: one file, two conventions.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR2); // 12
        libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    let blocked = status_mask("SigBlk");
    check!(
        h,
        blocked & bit(libc::SIGUSR2) != 0,
        "SIGUSR2 blocked: SigBlk {blocked:#x} has bit {}",
        libc::SIGUSR2 - 1
    );

    h.group("a-signal-that-cannot-be-caught-is-in-neither-mask");
    // rt_sigaction refuses SIGKILL and SIGSTOP, so nothing can put them there.
    let ignored = status_mask("SigIgn");
    let caught = status_mask("SigCgt");
    for sig in [libc::SIGKILL, libc::SIGSTOP] {
        check!(
            h,
            (ignored | caught) & bit(sig) == 0,
            "signal {sig} is in neither mask"
        );
    }

    std::process::exit(h.finish());
}
