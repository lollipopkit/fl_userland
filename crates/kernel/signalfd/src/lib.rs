//! `signalfd`: turning a pending signal into 128 bytes a poll loop can read.
//!
//! Two wire formats meet here, and the interesting part is the rule that joins
//! them.
//!
//! **`siginfo_t` is a union that does not describe itself.** Which of its
//! members carries meaning depends on `si_signo` and `si_code`, and reading the
//! wrong one returns whatever the right one left there. That decision was
//! fifteen lines of C with no test, in a file whose sibling layout has been
//! wrong twice — `siginfo_`'s union once ended at 48 of its 128 bytes, and
//! `si_utime`/`si_stime` once sat four bytes apart instead of eight.
//!
//! **`signalfd_siginfo` is flat.** 128 bytes, every field at a fixed offset,
//! and a reader indexes them by position. Nothing about it says which are
//! meaningful, so a kernel that fills the wrong ones reports a sender for a
//! fault or an exit status for a timer, and the reader believes it.
//!
//! So the offsets of both are stated here and tested, and `describe` — the
//! rule that reads one and writes the other — is a pure function.
//!
//! # What stays in C
//!
//! Everything about the *task*: `current->pending`, `signal_dequeue`, the
//! `sighand` lock and the wait. A signalfd reports the **reading** thread's
//! pending signals rather than the creating one's, so it has no state of its
//! own beyond the mask — and the mask is a `u64`. Step 4 of the order in
//! CLAUDE.md moves `struct task`, and the loop goes with it.

#![no_std]

// ---------------------------------------------------------------------------
#[path = "format.rs"]
mod format;
pub use format::{RECORD_BYTES, Record, SIGINFO_BYTES, describe, encode, flags_valid, usable_mask};

// The four `extern "C"` shims that used to be here -- `signalfd_describe`,
// `signalfd_usable_mask`, `signalfd_flags_valid`, `signalfd_record_size` --
// went with `kernel/signalfd.h` on 2026-09-04. Every caller was Rust and
// already used the safe functions above by path; the shims existed only
// because a header declared them.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::*;

    /// Measured from the C with `offsetof`, not derived. The union is
    /// 8-aligned so it starts at 16, and that gap is why `si_utime` is at 32
    /// rather than at 28 -- which it was once written as, so a guest reading
    /// one field got the other.
    #[test]
    fn the_siginfo_offsets_are_the_measured_ones() {
        assert_eq!(SIGINFO_BYTES, 128);
        assert_eq!(SI_CODE, 8);
        assert_eq!(SI_UNION, 16, "the union is 8-aligned, so it is not at 12");
        assert_eq!(KILL_PID, 16);
        assert_eq!(KILL_UID, 20);
        assert_eq!(CHLD_STATUS, 24);
        assert_eq!(CHLD_UTIME, 32);
        assert_eq!(CHLD_STIME, 40);
        assert_eq!(FAULT_ADDR, 16);
        assert_eq!(TIMER_VALUE, 24);
    }

    #[test]
    fn the_record_offsets_are_linuxs() {
        assert_eq!(RECORD_BYTES, 128);
        assert_eq!(SSI_PID, 12);
        assert_eq!(SSI_STATUS, 40);
        assert_eq!(SSI_PTR, 48);
        assert_eq!(SSI_UTIME, 56);
        assert_eq!(SSI_ADDR, 72);
    }

    fn info(signo: i32, code: i32) -> [u8; SIGINFO_BYTES] {
        let mut b = [0u8; SIGINFO_BYTES];
        b[SI_SIGNO..SI_SIGNO + 4].copy_from_slice(&signo.to_le_bytes());
        b[SI_CODE..SI_CODE + 4].copy_from_slice(&code.to_le_bytes());
        b
    }

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn a_child_exit_reports_the_child() {
        let mut b = info(SIGCHLD, 1);
        put32(&mut b, CHLD_PID, 4242);
        put32(&mut b, CHLD_UID, 1000);
        put32(&mut b, CHLD_STATUS, 7);
        put64(&mut b, CHLD_UTIME, 11);
        put64(&mut b, CHLD_STIME, 13);
        let r = describe(&b);
        assert_eq!(
            (r.pid, r.uid, r.status, r.utime, r.stime),
            (4242, 1000, 7, 11, 13)
        );
        assert_eq!(r.addr, 0, "a child exit has no fault address");
    }

    /// A fault describes an address only when the *kernel* raised it. The sign
    /// of si_code is the whole test: a `kill(pid, SIGSEGV)` carries a sender in
    /// the same bytes, and reporting it as an address would report the sender's
    /// pid as a memory address.
    #[test]
    fn a_fault_reports_an_address_only_when_the_kernel_raised_it() {
        let mut b = info(SIGSEGV, 1); // SEGV_MAPERR
        put64(&mut b, FAULT_ADDR, 0xdead_beef);
        let r = describe(&b);
        assert_eq!(r.addr, 0xdead_beef);
        assert_eq!(r.pid, 0, "and no sender");

        // The same signal, sent by a process: si_code is SI_USER (0).
        let mut b = info(SIGSEGV, 0);
        put32(&mut b, KILL_PID, 99);
        put32(&mut b, KILL_UID, 1000);
        let r = describe(&b);
        assert_eq!(r.addr, 0, "a kill(SIGSEGV) has no faulting address");
        assert_eq!((r.pid, r.uid), (99, 1000));
    }

    #[test]
    fn every_fault_signal_is_treated_the_same_way() {
        for signo in [SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP] {
            let mut b = info(signo, 2);
            put64(&mut b, FAULT_ADDR, 0x1000);
            assert_eq!(describe(&b).addr, 0x1000, "signal {signo}");
        }
    }

    #[test]
    fn a_timer_reports_its_id_and_value() {
        let mut b = info(14 /* SIGALRM */, SI_TIMER);
        put32(&mut b, TIMER_ID, 3);
        put32(&mut b, TIMER_OVERRUN, 5);
        put64(&mut b, TIMER_VALUE, 0xabcd);
        let r = describe(&b);
        assert_eq!((r.tid, r.overrun, r.ptr), (3, 5, 0xabcd));
        assert_eq!(r.int_, 0xabcd, "sigval is a union: the int is its low half");
        assert_eq!(r.pid, 0, "a timer has no sender");
    }

    #[test]
    fn anything_else_reports_a_sender() {
        let mut b = info(10 /* SIGUSR1 */, 0);
        put32(&mut b, KILL_PID, 1234);
        put32(&mut b, KILL_UID, 501);
        let r = describe(&b);
        assert_eq!((r.pid, r.uid), (1234, 501));
        assert_eq!((r.addr, r.status, r.tid), (0, 0, 0));
    }

    /// The whole 128 bytes are written. A reader that finds its own bytes in
    /// the tail reads them as fields.
    #[test]
    fn the_whole_record_is_written() {
        let mut out = [0xABu8; RECORD_BYTES];
        encode(&mut out, &describe(&info(10, 0)));
        assert!(!out.contains(&0xAB));
    }

    #[test]
    fn the_record_lands_where_a_reader_looks() {
        let mut b = info(SIGCHLD, 1);
        put32(&mut b, CHLD_PID, 7);
        put32(&mut b, CHLD_STATUS, 3);
        put64(&mut b, CHLD_UTIME, 100);
        let mut out = [0u8; RECORD_BYTES];
        encode(&mut out, &describe(&b));
        assert_eq!(u32_at(&out, SSI_SIGNO), SIGCHLD as u32);
        assert_eq!(u32_at(&out, SSI_PID), 7);
        assert_eq!(i32_at(&out, SSI_STATUS), 3);
        assert_eq!(u64_at(&out, SSI_UTIME), 100);
    }

    /// Neither may be consumed through a descriptor: that would let a process
    /// survive a signal it may not survive. Removed silently, because asking
    /// for everything with a full mask is not a mistake.
    #[test]
    fn kill_and_stop_are_removed_from_a_mask() {
        assert_eq!(usable_mask(u64::MAX) & (1 << (SIGKILL - 1)), 0);
        assert_eq!(usable_mask(u64::MAX) & (1 << (SIGSTOP - 1)), 0);
        // And nothing else is.
        let full = usable_mask(u64::MAX);
        for sig in 1..=64u32 {
            let bit = 1u64 << (sig - 1);
            if sig == SIGKILL || sig == SIGSTOP {
                continue;
            }
            assert_ne!(full & bit, 0, "signal {sig} was removed and should not be");
        }
        assert_eq!(usable_mask(0), 0);
    }

    #[test]
    fn the_flags_are_cloexec_and_nonblock() {
        assert!(flags_valid(0));
        assert!(flags_valid(0o2000000));
        assert!(flags_valid(0o4000));
        assert!(flags_valid(0o2004000));
        assert!(!flags_valid(1 << 20));
    }
}
