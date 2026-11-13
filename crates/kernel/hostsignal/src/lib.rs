//! Which host signal a guest signal forwards as.
//!
//! Only one thing asks: a guest process that `execve`d a name registered for
//! native offload is a **host** process, and a `kill` aimed at it has to be
//! turned into a host `kill`. `kernel/native_offload.c`.
//!
//! # The two numberings diverge, and passing a number through is wrong
//!
//! The C translated twelve signals with a `switch` and ended
//! `default: return guest_sig` — pass the number through. Linux and macOS agree
//! on 1..6, 8, 9, 11, 13..15, 21, 22 and 24..28, and **disagree everywhere
//! else**, so eight signals were forwarded as a different signal entirely:
//!
//! | guest | | arrived as | |
//! | --- | --- | --- | --- |
//! | 7 | `SIGBUS` | 7 | `SIGEMT` |
//! | 10 | `SIGUSR1` | 10 | **`SIGBUS`** |
//! | 12 | `SIGUSR2` | 12 | **`SIGSYS`** |
//! | 16 | `SIGSTKFLT` | 16 | `SIGURG` |
//! | 23 | `SIGURG` | 23 | `SIGIO` |
//! | 29 | `SIGIO` | 29 | `SIGINFO` |
//! | 30 | `SIGPWR` | 30 | **`SIGUSR1`** |
//! | 31 | `SIGSYS` | 31 | **`SIGUSR2`** |
//!
//! The sharpest is `SIGUSR1`: a guest sending one to a native-offloaded
//! `ffmpeg` delivered `SIGBUS`, whose default action is to dump core. The
//! program's own handler for the signal it was actually sent never ran.
//!
//! # A signal the host does not have is not forwarded
//!
//! `SIGSTKFLT` and `SIGPWR` are Linux's alone, and the real-time signals 32
//! upwards have no macOS equivalent at all. There is no number to send, so
//! nothing is sent — the previous behaviour was to send *some* signal, which is
//! worse than sending none.
//!
//! # Written out, not derived
//!
//! The host side is `libc`'s, which is per-platform and right by construction.
//! The guest side is a `#define` in `kernel/signal.h`, and the constants below
//! carry the same names so that `tools/guessed-constants.py` compares them.

/// The guest's signal numbers. `kernel/signal.h`.
pub const SIGHUP_: i32 = 1;
pub const SIGINT_: i32 = 2;
pub const SIGQUIT_: i32 = 3;
pub const SIGILL_: i32 = 4;
pub const SIGTRAP_: i32 = 5;
pub const SIGABRT_: i32 = 6;
pub const SIGBUS_: i32 = 7;
pub const SIGFPE_: i32 = 8;
pub const SIGKILL_: i32 = 9;
pub const SIGUSR1_: i32 = 10;
pub const SIGSEGV_: i32 = 11;
pub const SIGUSR2_: i32 = 12;
pub const SIGPIPE_: i32 = 13;
pub const SIGALRM_: i32 = 14;
pub const SIGTERM_: i32 = 15;
pub const SIGSTKFLT_: i32 = 16;
pub const SIGCHLD_: i32 = 17;
pub const SIGCONT_: i32 = 18;
pub const SIGSTOP_: i32 = 19;
pub const SIGTSTP_: i32 = 20;
pub const SIGTTIN_: i32 = 21;
pub const SIGTTOU_: i32 = 22;
pub const SIGURG_: i32 = 23;
pub const SIGXCPU_: i32 = 24;
pub const SIGXFSZ_: i32 = 25;
pub const SIGVTALRM_: i32 = 26;
pub const SIGPROF_: i32 = 27;
pub const SIGWINCH_: i32 = 28;
pub const SIGIO_: i32 = 29;
pub const SIGPWR_: i32 = 30;
pub const SIGSYS_: i32 = 31;

/// The host signal `guest` forwards as, or `None` when the host has no signal
/// that means the same thing.
///
/// Paired **by name**, which is the only correspondence there is: the numbers
/// are two unrelated conventions that happen to agree for most of the first
/// twenty.
pub fn to_host(guest: i32) -> Option<i32> {
    Some(match guest {
        SIGHUP_ => libc::SIGHUP,
        SIGINT_ => libc::SIGINT,
        SIGQUIT_ => libc::SIGQUIT,
        SIGILL_ => libc::SIGILL,
        SIGTRAP_ => libc::SIGTRAP,
        SIGABRT_ => libc::SIGABRT,
        SIGBUS_ => libc::SIGBUS,
        SIGFPE_ => libc::SIGFPE,
        SIGKILL_ => libc::SIGKILL,
        SIGUSR1_ => libc::SIGUSR1,
        SIGSEGV_ => libc::SIGSEGV,
        SIGUSR2_ => libc::SIGUSR2,
        SIGPIPE_ => libc::SIGPIPE,
        SIGALRM_ => libc::SIGALRM,
        SIGTERM_ => libc::SIGTERM,
        SIGCHLD_ => libc::SIGCHLD,
        SIGCONT_ => libc::SIGCONT,
        SIGSTOP_ => libc::SIGSTOP,
        SIGTSTP_ => libc::SIGTSTP,
        SIGTTIN_ => libc::SIGTTIN,
        SIGTTOU_ => libc::SIGTTOU,
        SIGURG_ => libc::SIGURG,
        SIGXCPU_ => libc::SIGXCPU,
        SIGXFSZ_ => libc::SIGXFSZ,
        SIGVTALRM_ => libc::SIGVTALRM,
        SIGPROF_ => libc::SIGPROF,
        SIGWINCH_ => libc::SIGWINCH,
        SIGIO_ => libc::SIGIO,
        SIGSYS_ => libc::SIGSYS,
        // SIGSTKFLT and SIGPWR are Linux's alone, and 32 upwards are the
        // real-time signals, which macOS does not have. Nothing to send.
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The eight the C got wrong, named on both sides.
    ///
    /// Each row is what a guest sent, what it used to arrive as, and what it
    /// arrives as now. The middle column is the guest number passed through
    /// unchanged, which is what `default: return guest_sig` did.
    #[test]
    fn the_eight_that_were_forwarded_as_a_different_signal() {
        for (guest, passed_through, want) in [
            (SIGBUS_, libc::SIGEMT, libc::SIGBUS),
            (SIGUSR1_, libc::SIGBUS, libc::SIGUSR1),
            (SIGUSR2_, libc::SIGSYS, libc::SIGUSR2),
            (SIGURG_, libc::SIGIO, libc::SIGURG),
            (SIGIO_, libc::SIGINFO, libc::SIGIO),
            (SIGSYS_, libc::SIGUSR2, libc::SIGSYS),
        ] {
            assert_eq!(guest, passed_through, "the number that was sent through");
            assert_eq!(to_host(guest), Some(want), "guest {guest}");
            assert_ne!(to_host(guest), Some(passed_through));
        }
        // And the two Linux has that macOS does not, which used to arrive as
        // whatever shared their number.
        assert_eq!(SIGSTKFLT_, libc::SIGURG);
        assert_eq!(to_host(SIGSTKFLT_), None);
        assert_eq!(SIGPWR_, libc::SIGUSR1);
        assert_eq!(to_host(SIGPWR_), None);
    }

    /// Every signal both sides have maps to the one with the same name, and no
    /// two guest signals share a host one.
    #[test]
    fn the_mapping_is_by_name_and_one_to_one() {
        let mut seen: Vec<(i32, i32)> = Vec::new();
        for guest in 1..=31 {
            if let Some(host) = to_host(guest) {
                assert!(
                    (1..=31).contains(&host),
                    "guest {guest} -> host {host}, which is not a signal"
                );
                if let Some((other, _)) = seen.iter().find(|(_, h)| *h == host) {
                    panic!("guest {guest} and {other} both forward as host {host}");
                }
                seen.push((guest, host));
            }
        }
        // 29 of the 31: everything but SIGSTKFLT and SIGPWR.
        assert_eq!(seen.len(), 29);
    }

    /// The twelve the C did translate, which have to keep translating the same
    /// way — those were right and a rewrite must not lose them.
    #[test]
    fn the_twelve_that_were_already_right_are_unchanged() {
        assert_eq!(to_host(SIGHUP_), Some(libc::SIGHUP));
        assert_eq!(to_host(SIGINT_), Some(libc::SIGINT));
        assert_eq!(to_host(SIGQUIT_), Some(libc::SIGQUIT));
        assert_eq!(to_host(SIGABRT_), Some(libc::SIGABRT));
        assert_eq!(to_host(SIGKILL_), Some(libc::SIGKILL));
        assert_eq!(to_host(SIGPIPE_), Some(libc::SIGPIPE));
        assert_eq!(to_host(SIGALRM_), Some(libc::SIGALRM));
        assert_eq!(to_host(SIGTERM_), Some(libc::SIGTERM));
        // The four the C translated because the numbers differ, and they do:
        // a guest SIGCHLD is 17 and a host one is 20.
        assert_eq!(to_host(SIGCHLD_), Some(libc::SIGCHLD));
        assert_eq!(to_host(SIGCONT_), Some(libc::SIGCONT));
        assert_eq!(to_host(SIGSTOP_), Some(libc::SIGSTOP));
        assert_eq!(to_host(SIGTSTP_), Some(libc::SIGTSTP));
        assert_ne!(SIGCHLD_, libc::SIGCHLD, "and they really do differ");
    }

    /// Nothing outside the guest's range forwards, including the real-time
    /// signals, which the host does not have.
    #[test]
    fn a_number_that_is_not_a_guest_signal_forwards_as_nothing() {
        for n in [0, 32, 34, 64, 65, -1, i32::MAX, i32::MIN] {
            assert_eq!(to_host(n), None, "{n}");
        }
    }
}
