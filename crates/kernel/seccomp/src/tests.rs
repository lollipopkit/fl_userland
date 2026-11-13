use super::*;

fn i(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

const LD_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const RET_K: u16 = 0x06;

/// `nr == n ? ret : ALLOW`, the shape every probe case uses.
fn for_nr(n: u32, r: u32) -> Vec<Insn> {
    vec![i(LD_ABS, 0, 0, 0), i(JEQ_K, 0, 1, n), i(RET_K, 0, 0, r), i(RET_K, 0, 0, ret::ALLOW)]
}

fn data(nr: i32) -> Data {
    Data { nr, arch: AUDIT_ARCH_AARCH64, ..Default::default() }
}

/// Each refusal `procsec_probe` measured on 7.2 is `EINVAL`.
#[test]
fn the_validator_refuses_what_linux_refuses() {
    assert_eq!(validate(&[]), Err(Errno::EINVAL), "no instructions");
    assert_eq!(validate(&[i(0xffff, 0, 0, 0)]), Err(Errno::EINVAL), "no such opcode");
    assert_eq!(validate(&[i(LD_ABS, 0, 0, 0)]), Err(Errno::EINVAL), "no return at the end");
    assert_eq!(validate(&[i(LD_ABS, 0, 0, 64), i(RET_K, 0, 0, 0)]), Err(Errno::EINVAL), "past seccomp_data");
    assert_eq!(validate(&[i(LD_ABS, 0, 0, 2), i(RET_K, 0, 0, 0)]), Err(Errno::EINVAL), "unaligned");
    assert_eq!(validate(&[i(JEQ_K, 5, 0, 0), i(RET_K, 0, 0, 0)]), Err(Errno::EINVAL), "jumps out");
    let big = vec![i(RET_K, 0, 0, ret::ALLOW); MAX_INSNS + 1];
    assert_eq!(validate(&big), Err(Errno::EINVAL), "too long");
    // A packet load, BPF_LD|BPF_H|BPF_ABS, is not a seccomp instruction.
    assert_eq!(validate(&[i(0x28, 0, 0, 0), i(RET_K, 0, 0, 0)]), Err(Errno::EINVAL));
    // BPF_ALU|BPF_MOD|BPF_K, and BPF_RET|BPF_X.
    assert_eq!(validate(&[i(0x94, 0, 0, 3), i(RET_K, 0, 0, 0)]), Err(Errno::EINVAL));
    assert_eq!(validate(&[i(0x0e, 0, 0, 0)]), Err(Errno::EINVAL));
    // A scratch word read before anything wrote it.
    assert_eq!(validate(&[i(0x60, 0, 0, 0), i(RET_K, 0, 0, 0)]), Err(Errno::EINVAL));
    assert!(validate(&for_nr(173, ret::ERRNO | 1)).is_ok());
}

/// A word of an argument is its low half at the lower offset.
#[test]
fn a_filter_reads_seccomp_data_as_the_guest_lays_it_out() {
    let p = validate(&[i(LD_ABS, 0, 0, 20), i(0x16, 0, 0, 0)]).unwrap(); // RET A
    let mut d = data(23);
    d.args[0] = 0x1111_2222_3333_4444;
    assert_eq!(p.run(&d), 0x1111_2222);
    let p = validate(&[i(LD_ABS, 0, 0, 4), i(0x16, 0, 0, 0)]).unwrap();
    assert_eq!(p.run(&d), AUDIT_ARCH_AARCH64);
}

/// Across a chain, the action that sorts lowest as a signed number wins:
/// KILL_PROCESS over everything, ERRNO over ALLOW whichever was first.
#[test]
fn the_strictest_action_in_the_chain_wins() {
    let first = Filter::new(validate(&for_nr(173, ret::ERRNO | 1)).unwrap(), false, None).unwrap();
    let second = Filter::new(validate(&for_nr(178, ret::ERRNO | 13)).unwrap(), false, Some(first.clone())).unwrap();
    assert_eq!(Verdict::of(second.evaluate(&data(173)).0), Verdict::Errno(1));
    assert_eq!(Verdict::of(second.evaluate(&data(178)).0), Verdict::Errno(13));
    assert_eq!(Verdict::of(second.evaluate(&data(172)).0), Verdict::Allow);
    assert_eq!(second.count(), 2);
    assert!(second.descends_from(&first));
    assert!(!first.descends_from(&second));
    let kill = Filter::new(validate(&for_nr(173, ret::KILL_PROCESS)).unwrap(), false, Some(second)).unwrap();
    assert_eq!(Verdict::of(kill.evaluate(&data(173)).0), Verdict::KillProcess);
}

#[test]
fn errno_data_is_clamped_to_max_errno_and_zero_is_an_answer() {
    assert_eq!(Verdict::of(ret::ERRNO | 0xffff), Verdict::Errno(4095));
    assert_eq!(Verdict::of(ret::ERRNO), Verdict::Errno(0));
    assert_eq!(Verdict::of(ret::TRACE | 42), Verdict::Trace(42));
    assert_eq!(Verdict::of(ret::USER_NOTIF), Verdict::Enosys);
    assert_eq!(Verdict::of(0x1234_0000), Verdict::KillProcess, "an unknown action kills");
}

#[test]
fn a_division_by_a_zero_register_returns_kill_thread() {
    // A = 1; X = 0; A /= X; RET A
    let p = validate(&[i(0x00, 0, 0, 1), i(0x01, 0, 0, 0), i(0x3c, 0, 0, 0), i(0x16, 0, 0, 0)]).unwrap();
    assert_eq!(p.run(&data(0)), ret::KILL_THREAD);
}

#[test]
fn strict_mode_is_one_way_and_excludes_a_filter() {
    let s = State::new();
    assert_eq!(s.set_strict(), Ok(()));
    assert_eq!(s.set_strict(), Err(Errno::EINVAL));
    let f = Filter::new(validate(&for_nr(0, ret::ALLOW)).unwrap(), false, None).unwrap();
    assert_eq!(s.install(f), Err(Errno::EINVAL));
    assert!(strict_allows(63) && strict_allows(139) && !strict_allows(94));
}
