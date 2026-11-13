use super::*;

// The six `guest_lock_*` symbols, which the C provides in the product.
use kernel_sighand as _;

fn state() -> Ptrace {
    Ptrace::new()
}

#[test]
fn a_fresh_task_is_not_traced_and_has_nothing_to_report() {
    let p = state();
    assert!(!p.is_traced());
    assert_eq!(p.take_stop_report(false), None);
}

#[test]
fn a_stop_reports_the_signal_that_caused_it() {
    let p = state();
    p.enter_stop(19, &ffi::siginfo_::default());
    // SIGSTOP << 8 | 0x7f, which is the same packing an ordinary group stop
    // uses -- only the branch that produced it knows which kind it is,
    // which is why waitid's si_code is set beside this.
    assert_eq!(p.take_stop_report(false), Some(19 << 8 | 0x7f));
}

#[test]
fn a_stop_is_reported_once() {
    let p = state();
    p.enter_stop(5, &ffi::siginfo_::default());
    assert!(p.take_stop_report(false).is_some());
    assert_eq!(p.take_stop_report(false), None, "and not a second time");
}

#[test]
fn wnowait_leaves_the_stop_where_it_was() {
    let p = state();
    p.enter_stop(5, &ffi::siginfo_::default());
    assert!(p.take_stop_report(true).is_some());
    assert!(p.take_stop_report(true).is_some());
    assert!(p.take_stop_report(false).is_some());
    assert_eq!(p.take_stop_report(false), None);
}

#[test]
fn a_task_that_is_not_stopped_reports_nothing() {
    // The signal outlives the stop -- `resume` does not clear it -- so the
    // stopped flag has to be part of the test. Reading the signal alone
    // would report a stop for a tracee the tracer has already continued.
    let p = state();
    p.enter_stop(5, &ffi::siginfo_::default());
    p.resume();
    assert_eq!(p.take_stop_report(false), None);
}

#[test]
fn a_wait_that_is_not_stopped_does_not_park() {
    let p = state();
    assert!(!p.wait_while_stopped(|| panic!("nothing to wait for")));
}

#[test]
fn abandoning_leaves_the_stop_without_continuing_it() {
    // What a SIGKILL to a stopped tracee does: the signal does not end this
    // wait, so the exit path resumes it and the abandon test is what tells
    // the tracee to leave rather than loop.
    let p = state();
    p.enter_stop(9, &ffi::siginfo_::default());
    let p2 = std::thread::scope(|s| {
        let h = s.spawn(|| p.wait_while_stopped(|| true));
        // The wake has to come from somewhere; a resume is what the exit
        // path does.
        std::thread::sleep(std::time::Duration::from_millis(20));
        p.resume();
        h.join().unwrap()
    });
    assert!(
        p2,
        "it left because it was told to, not because it was continued"
    );
}

/// Every option with a stop behind it is honoured, and SUSPEND_SECCOMP is
/// refused: an accepted option whose event never comes leaves a tracer
/// waiting for ever.
#[test]
fn setoptions_takes_every_option_with_a_stop_behind_it() {
    assert!(options_valid(0), "the empty set, which strace asks for first");
    // strace -f's word: TRACESYSGOOD | TRACEEXEC | TRACEEXIT and the three
    // fork-family events.
    assert!(options_valid(0x5f));
    assert!(options_valid(0x20), "TRACEVFORKDONE");
    assert!(options_valid(0x10_0000), "EXITKILL");
    assert!(options_valid(0x80), "TRACESECCOMP");
    assert!(!options_valid(0x0020_0000), "SUSPEND_SECCOMP");
    assert!(!options_valid(u64::MAX));
}

/// The event stop is the ordinary stop with a different number: the tracer
/// reads `SIGTRAP | (PTRACE_EVENT_EXEC << 8)` where without the option it
/// reads a bare `SIGTRAP` and cannot tell an exec from a breakpoint.
#[test]
fn an_armed_exec_event_relabels_the_trap_and_only_that_trap() {
    let trap = ffi::SIGTRAP_ as c_int;
    let ev = ffi::PTRACE_EVENT_EXEC_ as c_int;

    // Without the option, arming does nothing and the stop is a SIGTRAP.
    let p = Ptrace::new();
    assert!(!p.arm_event(ev, ffi::PTRACE_O_TRACEEXEC_, 0), "not asked for");
    p.enter_stop(trap, &ffi::siginfo_::default());
    assert_eq!(p.take_stop_report(true), Some(((trap as u32) << 8) | 0x7f));

    let p = Ptrace::new();
    p.lock().options = ffi::PTRACE_O_TRACEEXEC_;
    assert!(p.arm_event(ev, ffi::PTRACE_O_TRACEEXEC_, 0));
    p.enter_stop(trap, &ffi::siginfo_::default());
    let want = ((trap | (ev << 8)) as u32) << 8 | 0x7f;
    assert_eq!(
        p.take_stop_report(true),
        Some(want),
        "0x40507f, what Linux reports"
    );
    p.resume();

    // And it is consumed: the next SIGTRAP is the program's own, which a
    // tracer must not read as a second exec.
    p.enter_stop(trap, &ffi::siginfo_::default());
    assert_eq!(p.take_stop_report(true), Some(((trap as u32) << 8) | 0x7f));
}

/// An armed event labels a `SIGTRAP` and nothing else. A tracee that takes
/// another signal between the arming and the stop -- a `SIGSTOP` from the
/// shell's job control is the ordinary case -- would otherwise have that
/// signal reported as an exec event.
#[test]
fn an_armed_event_does_not_relabel_another_signal() {
    let p = Ptrace::new();
    p.lock().options = ffi::PTRACE_O_TRACEEXEC_;
    assert!(p.arm_event(ffi::PTRACE_EVENT_EXEC_ as c_int, ffi::PTRACE_O_TRACEEXEC_, 0));
    p.enter_stop(ffi::SIGSTOP_ as c_int, &ffi::siginfo_::default());
    assert_eq!(p.take_stop_report(true), Some((ffi::SIGSTOP_ << 8) | 0x7f));
}

/// A syscall-stop reports `SIGTRAP`, or `SIGTRAP | 0x80` once the tracer
/// has asked for it -- and the two halves alternate, which is the whole of
/// how a tracer pairs an entry with its exit.
#[test]
fn a_syscall_stop_alternates_and_carries_the_option() {
    let p = Ptrace::new();
    assert!(p.enter_syscall_stop(), "the first is an entry");
    assert_eq!(p.take_stop_report(true), Some((ffi::SIGTRAP_ << 8) | 0x7f));
    p.resume();
    assert!(!p.enter_syscall_stop(), "and the next is its exit");
    p.resume();
    assert!(p.enter_syscall_stop(), "then the next call's entry");
    p.resume();

    // A stop that is not a syscall boundary breaks the pairing, so the
    // next PTRACE_SYSCALL reports an entry again.
    p.leave_syscall_pairing();
    assert!(p.enter_syscall_stop());
    p.resume();

    p.lock().options = ffi::PTRACE_O_TRACESYSGOOD_;
    p.leave_syscall_pairing();
    p.enter_syscall_stop();
    let want = ((ffi::SIGTRAP_ | 0x80) << 8) | 0x7f;
    assert_eq!(p.take_stop_report(true), Some(want));
}

/// The dispatcher's question, which it asks twice per syscall: both halves
/// have to be true, so an untraced task and a traced one running free both
/// answer no.
#[test]
fn only_a_tracee_told_to_stop_stops_at_syscalls() {
    let p = Ptrace::new();
    assert!(!p.stops_at_syscalls());
    p.set_stops_at_syscalls(true);
    assert!(!p.stops_at_syscalls(), "not traced");
    p.attach(false, 0);
    assert!(!p.stops_at_syscalls(), "an attach starts from no PTRACE_SYSCALL");
    p.set_stops_at_syscalls(true);
    assert!(p.stops_at_syscalls());
    p.set_stops_at_syscalls(false);
    assert!(!p.stops_at_syscalls(), "traced, but running free");
}

#[test]
fn the_request_numbers_are_the_headers() {
    // Generated, so this is checking that the generation happened rather
    // than that somebody typed them correctly.
    assert_eq!(ffi::PTRACE_TRACEME_, 0);
    assert_eq!(ffi::PTRACE_PEEKDATA_, 2);
    assert_eq!(ffi::PTRACE_GETREGSET_, 0x4204);
    assert_eq!(ffi::PTRACE_DETACH_, 17);
    assert_eq!(size_of::<ffi::siginfo_>(), 128);
}

/// `PTRACE_CONT`'s `data`: 0 suppresses, 1..=64 is a signal, anything
/// else is `EIO`. Linux's `ptrace_resume` is `if (!valid_signal(data))
/// return -EIO`, and `valid_signal` is `sig <= _NSIG`.
#[test]
fn the_resume_data_is_a_signal_or_nothing() {
    assert_eq!(resume_signal(0), Some(0));
    assert_eq!(resume_signal(15), Some(15));
    assert_eq!(resume_signal(64), Some(64));
    assert_eq!(resume_signal(65), None);
    assert_eq!(resume_signal(99), None);
    assert_eq!(resume_signal(u64::MAX), None);
}

/// What the tracer asked for is handed over once.
#[test]
fn the_resume_signal_is_consumed() {
    let p = Ptrace::new();
    assert_eq!(p.take_resume_signal(), 0, "nothing asked for");
    p.lock().resume_signal = 15;
    assert_eq!(p.take_resume_signal(), 15);
    assert_eq!(p.take_resume_signal(), 0, "and not twice");
}
