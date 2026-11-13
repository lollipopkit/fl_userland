//! `futex(2)`, `set_robust_list(2)`, `get_robust_list(2)`, and the robust list
//! a dying thread has to disown.
//!
//! The wait queue is `crates/kernel/futex` and the list walk is
//! `crates/kernel/robustlist`. This is the syscall layer joining them: what
//! each operation number means, the timeout rules, the `FUTEX_WAKE_OP`
//! encoding, and where a thread's robust-list head lives.
//!
//! The guest word itself is `guestmem`'s: reading it needs `mem->lock` held
//! across the dereference *and* an atomic load, and the same for
//! `FUTEX_WAKE_OP`'s read-modify-write and the PI operations' compare-and-swap.
//! `guestmem` also has the `IUL_FUTEX_DBG` stall dump, which reads every
//! thread's `struct cpu_state`.
//!
//! The futex2 syscalls -- `futex_wait`, `futex_wake`, `futex_waitv` and
//! `futex_requeue` -- are `futex2`, over the same queue; `PR_FUTEX_HASH` is
//! `hash`.
//!
//! # The robust-list head is a field of `struct task`
//!
//! Written only by the owning thread, and zero in every new task -- a child
//! does not inherit its parent's (`copy_process` does `p->robust_list =
//! NULL`). It was a `thread_local!` from 2026-09 until 2026-11-13, when
//! nothing but the owner read it and `get_robust_list` for another pid was
//! `EPERM`; Linux answers any task the caller may ptrace, which needs the
//! head where another thread can read it.


use std::sync::atomic::Ordering;
use std::ffi::c_int;

/// The operation numbers a guest passes.
///
/// `CMD_MASK` strips the two flags, and `CLOCK_REALTIME` has to be read from
/// the **unmasked** word — which is why `FUTEX_WAIT_BITSET` measured an
/// absolute timeout against the wrong clock for as long as it existed.
///
/// Rust rather than a `#define`, since 2026-09-04: `kernel/futex.h` declared
/// these and no C read it.
mod cmd {
    pub const WAIT: u32 = 0;
    pub const WAKE: u32 = 1;
    pub const REQUEUE: u32 = 3;
    pub const CMP_REQUEUE: u32 = 4;
    pub const WAKE_OP: u32 = 5;
    pub const LOCK_PI: u32 = 6;
    pub const UNLOCK_PI: u32 = 7;
    pub const TRYLOCK_PI: u32 = 8;
    pub const WAIT_BITSET: u32 = 9;
    pub const WAKE_BITSET: u32 = 10;
    pub const WAIT_REQUEUE_PI: u32 = 11;
    pub const CMP_REQUEUE_PI: u32 = 12;
    pub const LOCK_PI2: u32 = 13;
}

/// The two flags a command carries, spelled as Linux spells them.
///
/// **Not `FUTEX_CLOCK_REALTIME`**: `tools/guessed-constants.py` compares a Rust
/// constant against a `#define` of the same name, and the C's
/// `CLOCK_REALTIME` is the clock id 0 rather than this flag. A name that is
/// ambiguous to a reader is ambiguous to the tool.
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_REALTIME: u32 = 256;
/// What is left of the operation word once the two flags are stripped.
pub const FUTEX_CMD_MASK: u32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

use kernel_futex::Word;
use kernel_robustlist as robustlist;
use strace::strace;
use usercopy::GuestMem;

mod rules;
#[cfg(test)]
use rules::WakeOp;
#[cfg(test)]
use rules::relative_to;
use rules::{decode_wake_op, wake_op_compare};

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

pub mod guestmem;

mod deadline;
mod futex2;
pub mod hash;
mod syscall;
pub use futex2::{sys_futex_requeue, sys_futex_wait, sys_futex_wake, sys_futex_waitv};
pub use syscall::sys_futex;

use guestmem::{
    CurrentSpace, futex_atomic_op, futex_dbg_enter_wait, futex_dbg_leave_wait, futex_dbg_secs,
    futex_dump_stall, futex_report_unsupported,
};

use guest_errno::Errno;
use pagetable::memlock::ReadGuard;
use guest_errno::i64_::{EFAULT, EINVAL, ENOSYS, ETIMEDOUT};

/// Every bit set: what `FUTEX_WAIT` and `FUTEX_WAKE` use where the `_BITSET`
/// forms take a mask.
const BITSET_MATCH_ANY: u32 = 0xffff_ffff;

/// How many a wake count wakes. Linux counts with `if (++ret >= nr_wake)
/// break`, after the first wake, on a signed `int`: so 0 and every negative
/// count wake **one**. `futex2_probe` measured it on a real kernel, with three
/// waiters parked -- `FUTEX_WAKE` 0 and -1 woke 1 there, and 0 and all three
/// here until 2026-11-11.
fn wake_count(nr: i32) -> u32 {
    nr.max(1) as u32
}

/// `Result<u32, c_int>` from the queue, as the `i64` the dispatch below reads.
fn counted(r: Result<u32, c_int>) -> i64 {
    match r {
        Ok(n) => n as i64,
        Err(e) => e as i64,
    }
}

// ---------------------------------------------------------------------------
// The wait
// ---------------------------------------------------------------------------

/// Every futex wait, legacy and futex2: park on `w` until woken, `deadline`,
/// or a signal. 0 or a negative errno.
fn futex_wait(w: Word, val: u32, bitset: u32, deadline: Option<std::time::Instant>) -> i64 {
    futex_dbg_enter_wait(w.addr, val);
    // `blocking` is what the futex-stall diagnostic reads to say this thread is
    // parked rather than running. Set around the wait and not inside it,
    // because the queue has no task.
    taskview::set_blocking(true);

    let dbg_secs = futex_dbg_secs();
    // IUL_FUTEX_DBG=<seconds> turns an untimed wait into a timed one, so that a
    // stall can be *reported* rather than merely waited out. Kept apart from
    // `deadline` because what the caller asked for is what decides whether the
    // expiry is an answer or a cue to dump.
    let wait = match deadline {
        None if dbg_secs > 0 => deadline::after(std::time::Duration::from_secs(dbg_secs as u64)),
        asked => asked,
    };

    let space = CurrentSpace::new();
    let mut err = kernel_futex::wait(&space, w, val, bitset, wait) as i64;
    if err == ETIMEDOUT && deadline.is_none() {
        // The caller asked to wait for ever, so this expiry was the
        // diagnostic's. Dump and go back to waiting without a deadline.
        //
        // Re-entering re-reads the word, so a value that changed while the dump
        // ran answers EAGAIN rather than 0 -- which a futex caller handles,
        // because it has to recheck either way, and which happens only with the
        // diagnostic turned on.
        futex_dump_stall(w.addr, val, dbg_secs);
        err = kernel_futex::wait(&space, w, val, bitset, None) as i64;
    }

    taskview::set_blocking(false);
    futex_dbg_leave_wait();
    err
}

/// Wakes up to `wake_max` waiters on one address. For `kernel/exit.c`, which
/// wakes a `clear_tid` futex as a thread dies.
pub fn futex_wake(uaddr: u64, wake_max: u32) -> c_int {
    // **Shared**, which is what Linux's `mm_release` and `handle_futex_death`
    // use: a `PTHREAD_PROCESS_SHARED` robust mutex on a `MAP_SHARED` page is
    // waited on by another *process*, keyed on the page. On a private page
    // the shared key falls back to the private one, so a thread of this
    // process waiting with `FUTEX_PRIVATE_FLAG` is still found. This was
    // private until 2026-11-11, and the other process slept for ever.
    let w = Word { addr: uaddr, private: false };
    kernel_futex::wake(&CurrentSpace::new(), w, wake_max, BITSET_MATCH_ANY).map_or(0, |n| n as c_int)
}

/// `FUTEX_CMP_REQUEUE`: like `FUTEX_REQUEUE`, but first check `*uaddr` against
/// `expected`.
///
/// The comparison is made **under the queue's lock**, with the wake and the
/// move, so that a waiter that arrives with the new value cannot be moved by a
/// requeue that read the old one. It was made before the lock until
/// 2026-11-11.
fn cmp_requeue(from: Word, wake_max: u32, requeue_max: u32, to: Word, expected: Option<u32>) -> i64 {
    // The counts, before anything else -- including the comparison, which is
    // what `futex_probe` measured rather than assumed: `CMP_REQUEUE` with a
    // count of 0x8000_0000 and a value that does not match is `EINVAL` on a
    // real arm64 kernel and not `EAGAIN`. See `rules::requeue_counts_ok` for
    // why a count is signed at all when it arrives as a `u32`.
    if !rules::requeue_counts_ok(wake_max, requeue_max) {
        return EINVAL;
    }
    // The second address is a futex word too, so the same alignment rule
    // applies to it. See `sys_futex`.
    if !to.addr.is_multiple_of(4) {
        return EINVAL;
    }
    counted(kernel_futex::requeue(&CurrentSpace::new(), from, to, wake_max, requeue_max, expected))
}

/// `FUTEX_WAKE_OP`: an atomic read-modify-write on `*uaddr2`, then wake up to
/// `wake_max1` waiters on `uaddr`, and — if the *old* value of `*uaddr2`
/// satisfies the comparison — up to `wake_max2` on `uaddr2`.
fn wake_op(w1: Word, wake_max1: u32, w2: Word, wake_max2: u32, val3: u32) -> i64 {
    // As for requeue: `uaddr2` is the word the read-modify-write lands on.
    if !w2.addr.is_multiple_of(4) {
        return EINVAL;
    }
    let decoded = match decode_wake_op(val3) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // mem->lock has to be held across the lookup and the atomic, or the
    // mapping can vanish between them. A task with no address space --
    // mid-exit -- is answered EFAULT, where it reached the lock with a null
    // pointer until 2026-10-02.
    let Some(mut held) = ReadGuard::current() else {
        return EFAULT;
    };
    let old = futex_atomic_op(&mut held, w2.addr, decoded.op as c_int, decoded.oparg);
    drop(held);
    let old = match old {
        Ok(old) => old,
        Err(e) => return e as i64,
    };
    let space = CurrentSpace::new();

    let woke = match wake_op_compare(decoded.cmp, old as i32, decoded.cmparg) {
        Ok(w) => w,
        Err(e) => return e,
    };

    // Two calls rather than one operation: they are separate queues and a
    // waiter on one is not affected by the other, so there is nothing for a
    // combined acquisition to make atomic.
    let mut total = match kernel_futex::wake(&space, w1, wake_max1, BITSET_MATCH_ANY) {
        Ok(n) => n,
        Err(e) => return e as i64,
    };
    if woke {
        match kernel_futex::wake(&space, w2, wake_max2, BITSET_MATCH_ANY) {
            Ok(n) => total += n,
            Err(e) => return e as i64,
        }
    }
    total as i64
}

// ---------------------------------------------------------------------------
// Priority inheritance
// ---------------------------------------------------------------------------

/// The calling thread's tid, as a PI futex word holds it.
fn current_tid() -> u32 {
    taskview::current_pid() as u32 & kernel_futex::FUTEX_TID_MASK
}

/// Whether `tid` is a live thread that has not started exiting, which is what
/// a PI owner has to be.
///
/// `exiting` and not only "findable": a thread is still in the table between
/// the point it is marked exiting and its removal, and [`futex_exit_pi`] runs
/// after the mark. A waiter that found it alive *before* the mark is covered by
/// the queue's epoch; one that finds it after has to see it as gone.
fn pi_owner_alive(tid: u32) -> bool {
    let pids = kernel_pids::PidsGuard::take();
    pids.find_live(tid as c_int).is_some_and(|t| !t.task().exiting.get())
}

/// A thread has finished exiting: hand any PI futex it held to the thread
/// parked behind it. `crates/kernel/exitcalls` calls this after the thread is
/// marked exiting, which [`pi_owner_alive`] depends on.
pub fn futex_exit_pi(tid: c_int) {
    kernel_futex::owner_exited(tid as u32 & kernel_futex::FUTEX_TID_MASK);
}

// ---------------------------------------------------------------------------
// The robust list
// ---------------------------------------------------------------------------

/// Where this thread's robust futex list starts, or 0: `task.robust_list`,
/// which only the owning thread writes.
fn robust_head() -> u64 {
    taskview::with_current_task(|t| t.robust_list.load(Ordering::Relaxed)).unwrap_or(0)
}

fn set_robust_head(head: u64) {
    taskview::with_current_task(|t| t.robust_list.store(head, Ordering::Relaxed));
}

/// `struct robust_list_head`'s layout is `crates/kernel/robustlist`.
///
/// It was declared in `kernel/futex.c` as `{ addr_t list; dword_t offset;
/// addr_t list_op_pending; }`, which came to 24 bytes by accident — the padding
/// after a 4-byte field made up the difference — while getting the middle field
/// wrong twice over. Linux's `futex_offset` is a *signed long*: 64 bits, and
/// glibc's is negative, because the futex sits before the list node. Read as an
/// unsigned 32-bit quantity it names an address four gigabytes away.
pub fn sys_set_robust_list(robust_list: u64, len: u64) -> Result<(), Errno> {
    strace!("set_robust_list({robust_list:#x}, {len})");
    if len != robustlist::robustlist_head_size() as u64 {
        return Err(Errno::EINVAL);
    }
    set_robust_head(robust_list);
    Ok(())
}

pub fn sys_get_robust_list(
    pid: c_int,
    robust_list_ptr: u64,
    len_ptr: u64,
) -> Result<(), Errno> {
    strace!("get_robust_list({pid}, {robust_list_ptr:#x}, {len_ptr:#x})");
    // Any task the caller may ptrace (`PTRACE_MODE_READ_REALCREDS`), by its
    // thread id; it was EPERM for every one but the caller until 2026-11-13.
    let head = if pid == 0 {
        robust_head()
    } else {
        let pids = kernel_pids::PidsGuard::take();
        let task = pids.find(pid).ok_or(Errno::ESRCH)?;
        if !task.may_ptrace(kernel_creds::PtraceMode::ReadReal) {
            return Err(Errno::EPERM);
        }
        task.task().robust_list.load(Ordering::Relaxed)
    };
    if GuestMem.write(robust_list_ptr, &head.to_le_bytes()) != 0 {
        return Err(Errno::EFAULT);
    }
    // size_t, which is eight bytes. This wrote four, leaving whatever the
    // caller had in the top half of a variable it was about to read.
    let len = robustlist::robustlist_head_size() as u64;
    if GuestMem.write(len_ptr, &len.to_le_bytes()) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// Guest memory for the list walk.
///
/// It runs on the exiting thread itself and before its mm is released, so the
/// ordinary accessors apply and the address space is the right one.
struct ExitingThreadMem;

impl robustlist::GuestMem for ExitingThreadMem {
    fn read_u64(&mut self, addr: u64) -> Option<u64> {
        let mut raw = [0u8; 8];
        (GuestMem.read(addr, &mut raw) == 0).then(|| u64::from_le_bytes(raw))
    }

    fn read_u32(&mut self, addr: u64) -> Option<u32> {
        let mut raw = [0u8; 4];
        (GuestMem.read(addr, &mut raw) == 0).then(|| u32::from_le_bytes(raw))
    }

    fn cmpxchg_u32(&mut self, addr: u64, old: u32, new: u32) -> Option<Result<(), u32>> {
        // An unaligned word cannot be a futex and cannot be swapped atomically;
        // Linux's `handle_futex_death` refuses it the same way.
        if !addr.is_multiple_of(4) {
            return None;
        }
        guestmem::futex_cmpxchg(&mut ReadGuard::current()?, addr, old, new)
    }
}

/// Disowns every robust futex this thread still holds.
///
/// Called from `do_exit` while the mm is still there. Without it a thread that
/// died holding a robust mutex left it locked for the life of the process and
/// every waiter blocked for ever — libc's own unwinding only runs on the
/// orderly path, which is the one where nothing went wrong.
pub fn futex_exit_robust_list() {
    let head = robust_head();
    if head == 0 {
        return;
    }
    let tid = taskview::current_pid() as u32;
    let woken = robustlist::exit_robust_list(&mut ExitingThreadMem, head, tid);
    set_robust_head(0);
    for addr in woken {
        futex_wake(addr, 1);
    }
}

/// `execve`'s half of the same, Linux's `futex_exec_release`: the robust list
/// is walked and forgotten, and the PI futexes this thread held are handed on
/// -- the old image's locks do not survive into the new one, whose memory the
/// list would otherwise be walked through at exit.
///
/// `pi_owner` is the tid the thread held them under. An exec from a thread
/// that is not the leader has taken the leader's pid by now, so the robust
/// walk asks with the *new* tid and leaves a lock word holding the old one
/// alone -- which is what Linux does, measured (`execthreads_probe`) -- while
/// the PI futexes, which Linux tracks by task rather than by number, are
/// found under the old.
///
/// The `set_tid_address` word is forgotten too, as `mm_release` forgets it:
/// it is an address in the image that is going, and the new program's exit
/// would otherwise write a zero into whatever its own image has there. Written
/// first only if another process shares the address space -- `mm_users > 1`,
/// a `vfork` parent; `mm_shared` says so -- since nobody else could be
/// waiting on it.
pub fn futex_exec_release(pi_owner: i32, mm_shared: bool) {
    futex_exit_robust_list();
    futex_exit_pi(pi_owner);
    let clear_tid = taskview::with_current_task(|t| t.clear_tid.swap(0, std::sync::atomic::Ordering::Relaxed)).unwrap_or(0);
    if clear_tid != 0 && mm_shared && usercopy::GuestMem.write(clear_tid, &0i32.to_le_bytes()) == 0 {
        futex_wake(clear_tid, 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `FUTEX_WAKE_OP`'s two arguments are twelve bits **signed**, which is the
    /// part that is easy to get wrong and impossible to notice: a positive
    /// argument reads the same either way, and glibc's are positive.
    #[test]
    fn wake_op_arguments_are_twelve_bit_signed() {
        // op=ADD(1), cmp=EQ(0), oparg=+1, cmparg=+0
        let d = decode_wake_op((1 << 28) | (1 << 12)).unwrap();
        assert_eq!(
            d,
            WakeOp {
                op: guestmem::op::ADD,
                cmp: guestmem::op::CMP_EQ,
                oparg: 1,
                cmparg: 0
            }
        );

        // The most negative twelve-bit value in both fields: 0x800 is -2048.
        let d = decode_wake_op((0x800 << 12) | 0x800).unwrap();
        assert_eq!(d.oparg, -2048);
        assert_eq!(d.cmparg, -2048);
        // And -1, which is all twelve bits set.
        let d = decode_wake_op((0xfff << 12) | 0xfff).unwrap();
        assert_eq!(d.oparg, -1);
        assert_eq!(d.cmparg, -1);
        // The largest positive is 2047, not 4095.
        let d = decode_wake_op((0x7ff << 12) | 0x7ff).unwrap();
        assert_eq!(d.oparg, 2047);
        assert_eq!(d.cmparg, 2047);
        // Nothing above bit 23 leaks into oparg. The opcode here is SET
        // rather than every bit, because every bit includes OPARG_SHIFT and
        // that is a different question -- see the next test.
        let d = decode_wake_op(0x0fff_ffff).unwrap();
        assert_eq!(d.oparg, -1);
        assert_eq!(d.cmparg, -1);
        assert_eq!(d.op, guestmem::op::SET);
    }

    /// `FUTEX_OP_OPARG_SHIFT` turns the argument into a shift count, and a
    /// count an int cannot take is `EINVAL` rather than undefined behaviour.
    /// **Masked, not refused.** This asserted `EINVAL` above 31 until
    /// 2026-09-03, on the reasoning that a shift an `int` cannot take is not a
    /// shift. `tests/guest/src/bin/futex_probe.rs` asked a real kernel for 31,
    /// 32, 33, 63 and 4095 and got 0 for every one: Linux does `oparg &= 31`,
    /// which it arrived at as a security fix for what used to be undefined
    /// behaviour rather than as a design.
    #[test]
    fn an_oparg_shift_is_masked_to_five_bits() {
        let shifted = |arg: i32| {
            let bits = (arg as u32 & 0xfff) << 12;
            decode_wake_op(((guestmem::op::OPARG_SHIFT | guestmem::op::ADD) << 28) | bits)
                .unwrap()
                .oparg
        };
        assert_eq!(shifted(0), 1);
        assert_eq!(shifted(31), 1 << 31i64 as i32);
        assert_eq!(shifted(32), 1, "32 & 31 is 0");
        assert_eq!(shifted(33), 2);
        assert_eq!(shifted(63), 1 << 31i64 as i32);
        assert_eq!(
            shifted(-1),
            1 << 31i64 as i32,
            "the low five bits of -1 are 31"
        );
        // And the shift flag is not left in the opcode.
        assert_eq!(
            decode_wake_op((guestmem::op::OPARG_SHIFT | guestmem::op::ADD) << 28)
                .unwrap()
                .op,
            guestmem::op::ADD
        );
    }

    /// A requeue count arrives as a `u32` and is read as an `int`, so the top
    /// half of the range is a refusal rather than a very large request.
    ///
    /// Measured, not read: `FUTEX_CMP_REQUEUE` with `0x8000_0000` is `EINVAL`
    /// on a real arm64 kernel and was 0 here — which a caller reads as "no
    /// waiter matched" and does not retry. `FUTEX_WAKE` and `FUTEX_WAKE_OP`
    /// with the same count are 0 there, which is what says the rule belongs to
    /// `futex_requeue` and not to counts in general.
    #[test]
    fn a_requeue_count_is_signed() {
        assert!(rules::requeue_counts_ok(0, 0));
        assert!(rules::requeue_counts_ok(1, 1));
        assert!(rules::requeue_counts_ok(i32::MAX as u32, i32::MAX as u32));
        assert!(!rules::requeue_counts_ok(0x8000_0000, 0));
        assert!(!rules::requeue_counts_ok(0, 0x8000_0000));
        assert!(!rules::requeue_counts_ok(u32::MAX, u32::MAX));
        // The boundary, both sides of it: one below is the largest count a
        // caller can actually ask for.
        assert!(rules::requeue_counts_ok(0, 0x7fff_ffff));
        assert!(!rules::requeue_counts_ok(0, 0x8000_0000));
        // That `0x1_8000_0000` is the *same* request is not asserted here: the
        // narrowing happens in `sys_futex`, above this function, so a cast
        // written in this test would only be restating Rust's own semantics.
        // `tests/guest/src/bin/futex_timeout.rs` asks it through the syscall,
        // which is where the claim lives.
    }

    /// Every comparison Linux defines, and nothing else.
    #[test]
    fn the_comparisons_are_signed_and_bounded() {
        assert_eq!(wake_op_compare(guestmem::op::CMP_EQ, 1, 1), Ok(true));
        assert_eq!(wake_op_compare(guestmem::op::CMP_NE, 1, 1), Ok(false));
        // Signed: -1 is below 0, where an unsigned comparison would put it
        // above. The old value comes out of an atomic as a u32.
        assert_eq!(wake_op_compare(guestmem::op::CMP_LT, -1, 0), Ok(true));
        assert_eq!(wake_op_compare(guestmem::op::CMP_GT, -1, 0), Ok(false));
        assert_eq!(wake_op_compare(guestmem::op::CMP_LE, 5, 5), Ok(true));
        assert_eq!(wake_op_compare(guestmem::op::CMP_GE, 5, 5), Ok(true));
        assert_eq!(wake_op_compare(6, 0, 0), Err(ENOSYS));
        assert_eq!(wake_op_compare(15, 0, 0), Err(ENOSYS));
    }

    /// An absolute deadline turned into a wait from now, which is what
    /// `FUTEX_WAIT_BITSET` needs and what measured against the wrong clock
    /// returned `ETIMEDOUT` at once.
    #[test]
    fn an_absolute_deadline_becomes_a_relative_wait() {
        let t = relative_to(100, 0, 90, 0);
        assert_eq!((t.tv_sec, t.tv_nsec), (10, 0));
        // A borrow across the second boundary.
        let t = relative_to(100, 0, 99, 500_000_000);
        assert_eq!((t.tv_sec, t.tv_nsec), (0, 500_000_000));
        // A deadline that has passed is a wait of zero, never a negative one --
        // which the queue would read as "no timeout" and wait for ever on.
        let t = relative_to(90, 0, 100, 0);
        assert_eq!((t.tv_sec, t.tv_nsec), (0, 0));
        let t = relative_to(100, 0, 100, 1);
        assert_eq!((t.tv_sec, t.tv_nsec), (0, 0));
        // Exactly now.
        let t = relative_to(100, 5, 100, 5);
        assert_eq!((t.tv_sec, t.tv_nsec), (0, 0));
    }

    /// `FUTEX_CMD_MASK` strips the two flags, so a command must be read from
    /// the masked word and `FUTEX_CLOCK_REALTIME` from the unmasked one.
    ///
    /// Reading the clock flag after masking is what made `FUTEX_WAIT_BITSET`
    /// use `CLOCK_REALTIME` unconditionally: the bit was never there to test.
    #[test]
    fn the_command_mask_strips_the_flags_and_only_the_flags() {
        let op = cmd::WAIT_BITSET | FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME;
        assert_eq!(op & FUTEX_CMD_MASK, cmd::WAIT_BITSET);
        assert_ne!(op & FUTEX_CLOCK_REALTIME, 0);
        assert_eq!(
            op & FUTEX_CMD_MASK & FUTEX_CLOCK_REALTIME,
            0,
            "the clock flag is gone after masking, which is why it is read before"
        );
    }
}
