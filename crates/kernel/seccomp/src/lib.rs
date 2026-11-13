//! Seccomp: a task's syscall filter, and the classic-BPF machine it runs on.
//!
//! What is here is the part with no task in it -- the validator, the
//! interpreter, the chain a task carries and the decision it reaches. The
//! syscall that installs a filter is `crates/kernel/misccalls`' (beside
//! `prctl`, which is its other spelling), and the check on every syscall is
//! `crates/kernel/syscalldispatch`'s.
//!
//! # It was `CONFIG_SECCOMP=n`, inconsistently
//!
//! Until 2026-11-11 `seccomp(2)` was `ENOSYS`, `PR_SET_SECCOMP` was `EINVAL`
//! and `PR_GET_SECCOMP` answered 0 -- but a kernel built without seccomp
//! answers `EINVAL` to `PR_GET_SECCOMP` too, and prints no `Seccomp:` line in
//! `/proc/<pid>/status`, which this one did. A sandbox that probes for the
//! feature got two different stories. It is the real thing now: strict mode
//! and filter mode, every return action, filter inheritance across `fork` and
//! `exec`, and `SECCOMP_FILTER_FLAG_TSYNC`. Not here: `NEW_LISTENER` (no
//! user-space notification), which is refused rather than accepted.
//!
//! # Why the chain is safe to read without a lock
//!
//! A task's slot is written by the task itself when it installs a filter, and
//! by another thread of its group only for `TSYNC` -- which installs a chain
//! that *contains* the one it replaces (`prev`), so the filter a reader holds
//! a pointer into stays alive through the replacement. That is Linux's
//! argument too: filters only ever grow, and a task never sheds one.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use guest_errno::Errno;
use util_arcslot::ArcSlot;

/// `SECCOMP_MODE_*`.
pub const MODE_DISABLED: u8 = 0;
pub const MODE_STRICT: u8 = 1;
pub const MODE_FILTER: u8 = 2;

/// `AUDIT_ARCH_AARCH64`: `EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`.
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

/// `BPF_MAXINSNS`.
pub const MAX_INSNS: usize = 4096;
/// `MAX_INSNS_PER_PATH`: the instructions every filter on a task may add up
/// to, counted with a penalty of four per filter as Linux counts them.
const MAX_INSNS_PER_PATH: usize = (1 << 18) / 8;

/// `sizeof(struct seccomp_data)`: nr, arch, instruction_pointer, args[6].
pub const DATA_SIZE: u32 = 64;

/// The return actions, `SECCOMP_RET_*`.
pub mod ret {
    pub const KILL_PROCESS: u32 = 0x8000_0000;
    pub const KILL_THREAD: u32 = 0x0000_0000;
    pub const TRAP: u32 = 0x0003_0000;
    pub const ERRNO: u32 = 0x0005_0000;
    pub const USER_NOTIF: u32 = 0x7fc0_0000;
    pub const TRACE: u32 = 0x7ff0_0000;
    pub const LOG: u32 = 0x7ffc_0000;
    pub const ALLOW: u32 = 0x7fff_0000;
    pub const ACTION_FULL: u32 = 0xffff_0000;
    pub const DATA: u32 = 0x0000_ffff;
}

/// Whether `SECCOMP_GET_ACTION_AVAIL` says yes for `action`.
pub fn action_available(action: u32) -> bool {
    matches!(
        action,
        ret::KILL_PROCESS
            | ret::KILL_THREAD
            | ret::TRAP
            | ret::ERRNO
            | ret::USER_NOTIF
            | ret::TRACE
            | ret::LOG
            | ret::ALLOW
    )
}

/// `/proc/sys/kernel/seccomp/actions_avail`, in Linux's order.
pub const ACTIONS_AVAIL: &str = "kill_process kill_thread trap errno user_notif trace log allow";

/// The syscalls strict mode allows on arm64: `read`, `write`, `exit` and
/// `rt_sigreturn`. `exit_group` is not one of them, which is Linux's list.
pub fn strict_allows(nr: u32) -> bool {
    matches!(nr, 63 | 64 | 93 | 139)
}

/// One classic BPF instruction, `struct sock_filter`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl Insn {
    /// `struct sock_filter`'s eight little-endian bytes.
    pub fn decode(b: &[u8; 8]) -> Insn {
        Insn {
            code: u16::from_le_bytes([b[0], b[1]]),
            jt: b[2],
            jf: b[3],
            k: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        }
    }
}

/// The opcode fields.
mod op {
    pub const LD: u16 = 0x00;
    pub const LDX: u16 = 0x01;
    pub const ST: u16 = 0x02;
    pub const STX: u16 = 0x03;
    pub const ALU: u16 = 0x04;
    pub const JMP: u16 = 0x05;
    pub const RET: u16 = 0x06;
    pub const MISC: u16 = 0x07;

    pub const W: u16 = 0x00;
    pub const IMM: u16 = 0x00;
    pub const ABS: u16 = 0x20;
    pub const MEM: u16 = 0x60;
    pub const LEN: u16 = 0x80;

    pub const K: u16 = 0x00;
    pub const X: u16 = 0x08;
    /// `BPF_RET`'s third source: the accumulator.
    pub const A: u16 = 0x10;

    pub const ADD: u16 = 0x00;
    pub const SUB: u16 = 0x10;
    pub const MUL: u16 = 0x20;
    pub const DIV: u16 = 0x30;
    pub const OR: u16 = 0x40;
    pub const AND: u16 = 0x50;
    pub const LSH: u16 = 0x60;
    pub const RSH: u16 = 0x70;
    pub const NEG: u16 = 0x80;
    pub const XOR: u16 = 0xa0;

    pub const JA: u16 = 0x00;
    pub const JEQ: u16 = 0x10;
    pub const JGT: u16 = 0x20;
    pub const JGE: u16 = 0x30;
    pub const JSET: u16 = 0x40;

    pub const TAX: u16 = 0x00;
    pub const TXA: u16 = 0x80;

    /// `BPF_MEMWORDS`.
    pub const MEMWORDS: u32 = 16;
}

/// The instructions a seccomp filter may use, after the rewrite
/// `seccomp_check_filter` does: `LD|W|LEN` becomes a load of the constant 64.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    /// A = seccomp_data[k..k+4].
    LdAbs(u32),
    LdImm(u32),
    LdxImm(u32),
    LdMem(u32),
    LdxMem(u32),
    St(u32),
    Stx(u32),
    Alu { op: u16, x: bool, k: u32 },
    Neg,
    Ja(u32),
    Jmp { op: u16, x: bool, k: u32, jt: u8, jf: u8 },
    RetK(u32),
    RetA,
    Tax,
    Txa,
}

/// A validated program.
#[derive(Debug, PartialEq, Eq)]
pub struct Program(Box<[Op]>);

/// `bpf_check_classic` and `seccomp_check_filter` together: every rule a
/// filter must pass, `EINVAL` for any it does not.
///
/// - between 1 and 4096 instructions, the last a return;
/// - only the opcodes seccomp allows -- no packet loads, no `MOD`, no `RET|X`;
/// - a load from `seccomp_data` 32-bit aligned and inside it;
/// - a jump that stays inside the program (they only go forward);
/// - a shift by less than 32 and no division by a constant zero;
/// - a scratch word read only where every path to it has written it.
pub fn validate(insns: &[Insn]) -> Result<Program, Errno> {
    if insns.is_empty() || insns.len() > MAX_INSNS {
        return Err(Errno::EINVAL);
    }
    let len = insns.len();
    let mut prog = Vec::with_capacity(len);
    for (pc, i) in insns.iter().enumerate() {
        let class = i.code & 0x07;
        let k = i.k;
        let in_range = |off: u32| (pc as u64 + 1 + off as u64) < len as u64;
        let o = match class {
            op::LD | op::LDX => {
                let mode = i.code & 0xe0;
                let size = i.code & 0x18;
                match (class, mode, size) {
                    (op::LD, op::ABS, op::W) => {
                        if k >= DATA_SIZE || k & 3 != 0 {
                            return Err(Errno::EINVAL);
                        }
                        Op::LdAbs(k)
                    }
                    (op::LD, op::LEN, op::W) => Op::LdImm(DATA_SIZE),
                    (op::LDX, op::LEN, op::W) => Op::LdxImm(DATA_SIZE),
                    (op::LD, op::IMM, 0) => Op::LdImm(k),
                    (op::LDX, op::IMM, 0) => Op::LdxImm(k),
                    (op::LD, op::MEM, 0) if k < op::MEMWORDS => Op::LdMem(k),
                    (op::LDX, op::MEM, 0) if k < op::MEMWORDS => Op::LdxMem(k),
                    _ => return Err(Errno::EINVAL),
                }
            }
            op::ST if i.code == op::ST && k < op::MEMWORDS => Op::St(k),
            op::STX if i.code == op::STX && k < op::MEMWORDS => Op::Stx(k),
            op::ALU => {
                let aop = i.code & 0xf0;
                let x = i.code & op::X != 0;
                if i.code & !0xf8 != op::ALU {
                    return Err(Errno::EINVAL);
                }
                match aop {
                    op::NEG if !x => Op::Neg,
                    op::ADD | op::SUB | op::MUL | op::OR | op::AND | op::XOR => Op::Alu { op: aop, x, k },
                    op::DIV if x || k != 0 => Op::Alu { op: aop, x, k },
                    op::LSH | op::RSH if x || k < 32 => Op::Alu { op: aop, x, k },
                    _ => return Err(Errno::EINVAL),
                }
            }
            op::JMP => {
                let jop = i.code & 0xf0;
                let x = i.code & op::X != 0;
                if i.code & !0xf8 != op::JMP {
                    return Err(Errno::EINVAL);
                }
                match jop {
                    op::JA if !x => {
                        if !in_range(k) {
                            return Err(Errno::EINVAL);
                        }
                        Op::Ja(k)
                    }
                    op::JEQ | op::JGT | op::JGE | op::JSET => {
                        if !in_range(i.jt as u32) || !in_range(i.jf as u32) {
                            return Err(Errno::EINVAL);
                        }
                        Op::Jmp { op: jop, x, k, jt: i.jt, jf: i.jf }
                    }
                    _ => return Err(Errno::EINVAL),
                }
            }
            op::RET => match i.code & 0x18 {
                op::K if i.code == op::RET | op::K => Op::RetK(k),
                op::A if i.code == op::RET | op::A => Op::RetA,
                _ => return Err(Errno::EINVAL),
            },
            op::MISC => match i.code {
                c if c == op::MISC | op::TAX => Op::Tax,
                c if c == op::MISC | op::TXA => Op::Txa,
                _ => return Err(Errno::EINVAL),
            },
            _ => return Err(Errno::EINVAL),
        };
        prog.push(o);
    }
    if !matches!(prog[len - 1], Op::RetK(_) | Op::RetA) {
        return Err(Errno::EINVAL);
    }
    check_load_and_stores(&prog)?;
    Ok(Program(prog.into_boxed_slice()))
}

/// Linux's `check_load_and_stores`: a scratch word must be written on every
/// path that reads it. Jumps only go forward, so one pass in order suffices.
fn check_load_and_stores(prog: &[Op]) -> Result<(), Errno> {
    let mut masks = vec![u16::MAX; prog.len()];
    let mut valid: u16 = 0;
    for (pc, o) in prog.iter().enumerate() {
        valid &= masks[pc];
        match *o {
            Op::St(k) | Op::Stx(k) => valid |= 1 << k,
            Op::LdMem(k) | Op::LdxMem(k) if valid & (1 << k) == 0 => return Err(Errno::EINVAL),
            Op::Ja(k) => {
                masks[pc + 1 + k as usize] &= valid;
                valid = u16::MAX;
            }
            Op::Jmp { jt, jf, .. } => {
                masks[pc + 1 + jt as usize] &= valid;
                masks[pc + 1 + jf as usize] &= valid;
                valid = u16::MAX;
            }
            _ => {}
        }
    }
    Ok(())
}

/// `struct seccomp_data`, what a filter reads.
#[derive(Clone, Copy, Debug, Default)]
pub struct Data {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

impl Data {
    /// The 32-bit word at byte `k`, which `validate` has checked is aligned
    /// and inside the struct. Little-endian, as the guest lays it out.
    fn word(&self, k: u32) -> u32 {
        match k {
            0 => self.nr as u32,
            4 => self.arch,
            8 => self.instruction_pointer as u32,
            12 => (self.instruction_pointer >> 32) as u32,
            _ => {
                let a = self.args[((k - 16) / 8) as usize];
                if k.is_multiple_of(8) { a as u32 } else { (a >> 32) as u32 }
            }
        }
    }
}

impl Program {
    /// Run it. A division by a zero register ends the program with 0, which
    /// is `SECCOMP_RET_KILL_THREAD` -- classic BPF's rule.
    pub fn run(&self, d: &Data) -> u32 {
        let (mut a, mut x) = (0u32, 0u32);
        let mut mem = [0u32; op::MEMWORDS as usize];
        let mut pc = 0usize;
        while let Some(o) = self.0.get(pc) {
            pc += 1;
            match *o {
                Op::LdAbs(k) => a = d.word(k),
                Op::LdImm(k) => a = k,
                Op::LdxImm(k) => x = k,
                Op::LdMem(k) => a = mem[k as usize],
                Op::LdxMem(k) => x = mem[k as usize],
                Op::St(k) => mem[k as usize] = a,
                Op::Stx(k) => mem[k as usize] = x,
                Op::Neg => a = a.wrapping_neg(),
                Op::Alu { op: aop, x: use_x, k } => {
                    let v = if use_x { x } else { k };
                    a = match aop {
                        op::ADD => a.wrapping_add(v),
                        op::SUB => a.wrapping_sub(v),
                        op::MUL => a.wrapping_mul(v),
                        op::DIV => match a.checked_div(v) {
                            Some(q) => q,
                            None => return 0,
                        },
                        op::OR => a | v,
                        op::AND => a & v,
                        op::XOR => a ^ v,
                        op::LSH => a.checked_shl(v).unwrap_or(0),
                        op::RSH => a.checked_shr(v).unwrap_or(0),
                        _ => unreachable!("validate admits no other ALU op"),
                    };
                }
                Op::Ja(k) => pc += k as usize,
                Op::Jmp { op: jop, x: use_x, k, jt, jf } => {
                    let v = if use_x { x } else { k };
                    let taken = match jop {
                        op::JEQ => a == v,
                        op::JGT => a > v,
                        op::JGE => a >= v,
                        op::JSET => a & v != 0,
                        _ => unreachable!("validate admits no other jump"),
                    };
                    pc += if taken { jt } else { jf } as usize;
                }
                Op::RetK(k) => return k,
                Op::RetA => return a,
                Op::Tax => x = a,
                Op::Txa => a = x,
            }
        }
        unreachable!("validate requires the last instruction to return")
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One installed filter and the ones installed before it.
pub struct Filter {
    prog: Program,
    /// `SECCOMP_FILTER_FLAG_LOG`.
    log: bool,
    prev: Option<Arc<Filter>>,
    /// The instructions this and every earlier filter add up to, with
    /// Linux's penalty of four per filter.
    path_insns: usize,
}

impl Filter {
    /// `prog` on top of `prev`. `ENOMEM` past the total Linux allows a task.
    pub fn new(prog: Program, log: bool, prev: Option<Arc<Filter>>) -> Result<Arc<Filter>, Errno> {
        let path_insns = prog.len() + 4 + prev.as_ref().map_or(0, |p| p.path_insns);
        if path_insns > MAX_INSNS_PER_PATH {
            return Err(Errno::ENOMEM);
        }
        Ok(Arc::new(Filter { prog, log, prev, path_insns }))
    }

    /// How many filters the chain holds, for `Seccomp_filters:`.
    pub fn count(&self) -> usize {
        1 + self.prev.as_ref().map_or(0, |p| p.count())
    }

    /// Whether `other` is this filter or one installed before it: the rule
    /// `TSYNC` asks of every thread it synchronises.
    pub fn descends_from(&self, other: &Filter) -> bool {
        let mut f = Some(self);
        while let Some(cur) = f {
            if std::ptr::eq(cur, other) {
                return true;
            }
            f = cur.prev.as_deref();
        }
        false
    }

    /// Every filter's answer, and the one that wins: the action that sorts
    /// lowest as a signed number -- `KILL_PROCESS` first, `ALLOW` last -- with
    /// its data, and whether the filter that gave it asked for logging.
    pub fn evaluate(&self, d: &Data) -> (u32, bool) {
        let action = |r: u32| (r & ret::ACTION_FULL) as i32;
        let mut best = ret::ALLOW;
        let mut log = false;
        let mut f = Some(self);
        while let Some(cur) = f {
            let r = cur.prog.run(d);
            if action(r) < action(best) {
                best = r;
                log = cur.log;
            }
            f = cur.prev.as_deref();
        }
        (best, log)
    }
}

/// What a filter decided, in the terms the dispatcher acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Skip the call and answer `-errno` (0 is an answer too).
    Errno(u16),
    /// Skip the call and raise `SIGSYS` with this in `si_errno`.
    Trap(u16),
    /// Skip the call and answer `-ENOSYS`: `TRACE` with no tracer asking for
    /// seccomp stops, or `USER_NOTIF` with no listener. Neither can exist
    /// here.
    Enosys,
    KillThread,
    KillProcess,
}

impl Verdict {
    /// From a filter's return value. An action no kernel defines is treated
    /// as `KILL_PROCESS`, which is Linux's `default:` arm.
    pub fn of(r: u32) -> Verdict {
        let data = (r & ret::DATA) as u16;
        match r & ret::ACTION_FULL {
            ret::ALLOW | ret::LOG => Verdict::Allow,
            ret::ERRNO => Verdict::Errno(data.min(4095)),
            ret::TRAP => Verdict::Trap(data),
            ret::TRACE | ret::USER_NOTIF => Verdict::Enosys,
            ret::KILL_THREAD => Verdict::KillThread,
            _ => Verdict::KillProcess,
        }
    }
}

/// A task's seccomp state: its mode and its filter chain.
#[derive(Default)]
pub struct State {
    mode: AtomicU8,
    filter: ArcSlot<Filter>,
}

impl State {
    pub const fn new() -> State {
        State { mode: AtomicU8::new(MODE_DISABLED), filter: ArcSlot::empty() }
    }

    /// The mode, read on every syscall.
    #[inline]
    pub fn mode(&self) -> u8 {
        self.mode.load(Ordering::Acquire)
    }

    /// What a child of this task starts with: the same mode and chain, which
    /// is `fork`'s and `clone`'s rule and survives `execve`.
    ///
    /// # Safety
    /// Called under whatever keeps this task's slot from being replaced
    /// meanwhile -- the task's own thread, or `pids_lock` against `TSYNC`.
    pub unsafe fn for_child(&self) -> State {
        // SAFETY: the caller's contract.
        let f = unsafe { self.filter.clone_arc() };
        State { mode: AtomicU8::new(self.mode()), filter: ArcSlot::new(f) }
    }

    /// The chain, to evaluate or to build on.
    ///
    /// # Safety
    /// As [`State::for_child`].
    pub unsafe fn chain(&self) -> Option<Arc<Filter>> {
        // SAFETY: the caller's contract.
        unsafe { self.filter.clone_arc() }
    }

    /// Run the chain over one syscall. Lock-free; see the module comment for
    /// why the borrow is sound against a concurrent `TSYNC`.
    pub fn evaluate(&self, d: &Data) -> Verdict {
        let p = self.filter.as_ptr();
        if p.is_null() {
            return Verdict::Allow;
        }
        // SAFETY: the slot holds a count on `p`, and the only writer other
        // than this task's own thread is `TSYNC`, which replaces it with a
        // chain that holds `p` alive as an ancestor.
        let (r, _log) = unsafe { &*p }.evaluate(d);
        Verdict::of(r)
    }

    /// Strict mode, which can only be entered from no mode at all.
    pub fn set_strict(&self) -> Result<(), Errno> {
        self.mode
            .compare_exchange(MODE_DISABLED, MODE_STRICT, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| Errno::EINVAL)
    }

    /// Install `f`, which was built on this task's current chain (or on one
    /// it descends from, for `TSYNC`). Strict mode cannot be left for a
    /// filter: `EINVAL`.
    pub fn install(&self, f: Arc<Filter>) -> Result<(), Errno> {
        if self.mode() == MODE_STRICT {
            return Err(Errno::EINVAL);
        }
        drop(self.filter.swap(Some(f)));
        self.mode.store(MODE_FILTER, Ordering::Release);
        Ok(())
    }

    /// How many filters are installed, for `/proc/<pid>/status`.
    ///
    /// # Safety
    /// As [`State::for_child`].
    pub unsafe fn filter_count(&self) -> usize {
        // SAFETY: the caller's contract.
        unsafe { self.filter.clone_arc() }.map_or(0, |f| f.count())
    }
}

#[cfg(test)]
mod tests;
