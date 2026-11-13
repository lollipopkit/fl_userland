//! What another task may read about a task while it runs: its I/O counters
//! (`/proc/<pid>/io`) and the system call it is in (`/proc/<pid>/syscall`).
//!
//! Both are written on every read, write or system call by the task's own
//! thread and read rarely by any other, so each is a set of atomics that only
//! the owner stores to: a load and a plain store each, no read-modify-write
//! and no lock on the path the owner pays for. A reader takes what is there.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering, fence};

/// `struct task_io_accounting`'s four counters this kernel can keep; Linux's
/// `read_bytes`, `write_bytes` and `cancelled_write_bytes` count block I/O,
/// which is the host's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Io {
    pub rchar: u64,
    pub wchar: u64,
    pub syscr: u64,
    pub syscw: u64,
}

impl std::ops::AddAssign for Io {
    fn add_assign(&mut self, o: Io) {
        self.rchar += o.rchar;
        self.wchar += o.wchar;
        self.syscr += o.syscr;
        self.syscw += o.syscw;
    }
}

#[derive(Default, Debug)]
struct Counters {
    rchar: AtomicU64,
    wchar: AtomicU64,
    syscr: AtomicU64,
    syscw: AtomicU64,
}

impl Counters {
    fn get(&self) -> Io {
        Io {
            rchar: self.rchar.load(Ordering::Relaxed),
            wchar: self.wchar.load(Ordering::Relaxed),
            syscr: self.syscr.load(Ordering::Relaxed),
            syscw: self.syscw.load(Ordering::Relaxed),
        }
    }
}

/// A single writer's increment: the owning thread is the only one that
/// stores, so a load and a store say what a `fetch_add` would without the
/// exclusive access.
fn bump(c: &AtomicU64, n: u64) {
    c.store(c.load(Ordering::Relaxed).wrapping_add(n), Ordering::Relaxed);
}

/// One task's counters, and the ones its thread group's departed threads
/// left behind: Linux's `task->ioac` and `signal->ioac`.
///
/// The second is shared by every thread of a group and added to as each
/// thread's task is freed ([`Drop`]), which happens under `pids_lock` in the
/// same hold that takes it off the group's thread list -- so a reader under
/// that lock counts a thread's I/O exactly once, in the list or in the sum.
#[derive(Debug)]
pub struct IoAccounting {
    own: Counters,
    gone: Arc<Counters>,
}

impl IoAccounting {
    /// A task in a new thread group: nothing read, nothing written.
    pub fn new_process() -> IoAccounting {
        IoAccounting { own: Counters::default(), gone: Arc::default() }
    }

    /// A new thread of the group `self` is in. Linux starts every task at 0.
    pub fn new_thread(&self) -> IoAccounting {
        IoAccounting { own: Counters::default(), gone: Arc::clone(&self.gone) }
    }

    /// A read-side call: `syscr`, and `rchar` by what it returned. The
    /// owning thread only.
    pub fn read(&self, bytes: u64) {
        bump(&self.own.syscr, 1);
        bump(&self.own.rchar, bytes);
    }

    /// The write side, likewise.
    pub fn wrote(&self, bytes: u64) {
        bump(&self.own.syscw, 1);
        bump(&self.own.wchar, bytes);
    }

    /// This task's own, for `/proc/<pid>/task/<tid>/io`.
    pub fn own(&self) -> Io {
        self.own.get()
    }

    /// The group's threads that have been freed.
    pub fn gone(&self) -> Io {
        self.gone.get()
    }
}

impl Drop for IoAccounting {
    fn drop(&mut self) {
        let own = self.own.get();
        let gone = &self.gone;
        gone.rchar.fetch_add(own.rchar, Ordering::Relaxed);
        gone.wchar.fetch_add(own.wchar, Ordering::Relaxed);
        gone.syscr.fetch_add(own.syscr, Ordering::Relaxed);
        gone.syscw.fetch_add(own.syscw, Ordering::Relaxed);
    }
}

/// What `/proc/<pid>/syscall` reports for a task that is not running: the
/// call it is in (`nr`, with its six argument registers), or none -- `-1`,
/// a task sitting out a group stop -- and the stack pointer and the pc after
/// the `svc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InSyscall {
    pub nr: Option<u64>,
    pub args: [u64; 6],
    pub sp: u64,
    pub pc: u64,
}

/// [`InSyscall`] published by the task's thread, for others to read.
///
/// A sequence lock over atomics: a publish makes `seq` odd, writes, and makes
/// it even again; a reader that sees the same even value on both sides of its
/// reads has one publish's words. `leave` is a single store into `state`,
/// which a reader sees or does not -- either answer is one a reader racing the
/// return could have had.
#[derive(Debug, Default)]
pub struct SyscallState {
    seq: AtomicU64,
    /// [`OUTSIDE`], [`STOPPED`], or the call's number plus [`FIRST_NR`].
    state: AtomicU64,
    words: [AtomicU64; 8],
}

/// Running, or never made a call: the state a new task starts in.
const OUTSIDE: u64 = 0;
const STOPPED: u64 = 1;
const FIRST_NR: u64 = 2;

impl SyscallState {
    fn publish(&self, state: u64, args: &[u64; 6], sp: u64, pc: u64) {
        let s = self.seq.load(Ordering::Relaxed);
        self.seq.store(s.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        self.state.store(state, Ordering::Relaxed);
        for (w, v) in self.words.iter().zip(args.iter().chain([sp, pc].iter())) {
            w.store(*v, Ordering::Relaxed);
        }
        self.seq.store(s.wrapping_add(2), Ordering::Release);
    }

    /// The owning thread, on its way into call `nr`.
    pub fn enter(&self, nr: u64, args: &[u64; 6], sp: u64, pc: u64) {
        self.publish(nr + FIRST_NR, args, sp, pc);
    }

    /// The owning thread, about to sit out a stop outside any call.
    pub fn stopped(&self, sp: u64, pc: u64) {
        self.publish(STOPPED, &[0; 6], sp, pc);
    }

    /// The owning thread, on its way out of either.
    pub fn leave(&self) {
        self.state.store(OUTSIDE, Ordering::Relaxed);
    }

    /// What the task is in, or `None` when it is running -- outside both, or
    /// moving between them as this reads.
    pub fn get(&self) -> Option<InSyscall> {
        let s1 = self.seq.load(Ordering::Acquire);
        if s1 % 2 == 1 {
            return None;
        }
        let state = self.state.load(Ordering::Relaxed);
        let w: [u64; 8] = std::array::from_fn(|i| self.words[i].load(Ordering::Relaxed));
        fence(Ordering::Acquire);
        if self.seq.load(Ordering::Relaxed) != s1 || state == OUTSIDE {
            return None;
        }
        Some(InSyscall {
            nr: state.checked_sub(FIRST_NR),
            args: [w[0], w[1], w[2], w[3], w[4], w[5]],
            sp: w[6],
            pc: w[7],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_departed_thread_is_counted_once_in_its_group() {
        let leader = IoAccounting::new_process();
        let thread = leader.new_thread();
        thread.read(10);
        thread.wrote(3);
        leader.read(1);
        assert_eq!(leader.gone(), Io::default());
        drop(thread);
        assert_eq!(leader.gone(), Io { rchar: 10, wchar: 3, syscr: 1, syscw: 1 });
        assert_eq!(leader.own(), Io { rchar: 1, wchar: 0, syscr: 1, syscw: 0 });
        let other = IoAccounting::new_process();
        assert_eq!(other.gone(), Io::default(), "another process does not share it");
    }

    #[test]
    fn a_syscall_is_reported_between_enter_and_leave() {
        let s = SyscallState::default();
        assert_eq!(s.get(), None, "no call yet");
        s.enter(0, &[1, 2, 3, 4, 5, 6], 0x10, 0x20);
        assert_eq!(s.get(), Some(InSyscall { nr: Some(0), args: [1, 2, 3, 4, 5, 6], sp: 0x10, pc: 0x20 }));
        s.leave();
        assert_eq!(s.get(), None);
        s.stopped(0x30, 0x40);
        assert_eq!(s.get(), Some(InSyscall { nr: None, args: [0; 6], sp: 0x30, pc: 0x40 }));
    }
}
