//! Reading and writing the guest word a futex is about, and the diagnostics
//! that say who is parked on it.
//!
//! # Both halves of a read matter, and both were missing in places
//!
//! `mem->lock` has to be held across the **dereference**, not only across
//! `mem_ptr`: it is what stops an `munmap` or `mremap` on another thread
//! unmapping the page in between. And the read has to be **atomic**, because a
//! futex word is the one word in a program other threads are certainly CAS-ing
//! — ThreadSanitizer reports it against the guest's own `stxr` gadget.
//!
//! [`futex_read_word`] is called by `crates/kernel/futex` **with the wait
//! queue's lock held**: the comparison and the enqueue have to happen together,
//! or a waker can change the word and wake between them, finding nobody and
//! leaving the thread asleep on a value that has already moved.
//!
//! # A host address identifies a *shared* page and nothing else
//!
//! [`futex_backing`] answers where a guest address is, as a number two
//! address spaces can compare — and only for a page that is genuinely shared.
//! The `P_SHARED` test is not a shortcut, it is the rule: Linux's
//! `get_futex_key` falls back to the mm-based key when the mapping is not
//! `VM_MAYSHARE` whatever the flag said, and so must this. **A host address is
//! not stable for a private page**: a private mapping is copy-on-write, so
//! `mem_ptr` answers the original before the first write and the copy after it,
//! and a futex whose word is being written is exactly the case where that
//! happens. Keying on it made every ping-pong wake miss — the waiter enqueued
//! under one address and the waker looked up another —
//! `tests/guest/src/bin/futex_pingpong.rs` is what hung.
//!
//! `MEM_READ`, not `MEM_WRITE`: a write would copy a private page that has not
//! been written yet, which is a side effect a futex must not have.

use std::ffi::c_int;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

/// The `FUTEX_WAKE_OP` encoding, which this file decodes and executes. Linux's
/// `futex.h` numbering.
///
/// Rust rather than a `#define`, since 2026-09-04: `kernel/futex.h` declared
/// these and no C read it, so the header was a second place to get them wrong.
pub(crate) mod op {
    pub const SET: u32 = 0;
    pub const ADD: u32 = 1;
    pub const OR: u32 = 2;
    pub const ANDN: u32 = 3;
    pub const XOR: u32 = 4;
    pub const OPARG_SHIFT: u32 = 8;

    pub const CMP_EQ: u32 = 0;
    pub const CMP_NE: u32 = 1;
    pub const CMP_LT: u32 = 2;
    pub const CMP_LE: u32 = 3;
    pub const CMP_GT: u32 = 4;
    pub const CMP_GE: u32 = 5;
}

use crate::ffi;
use pagetable::memlock::{Held, ReadGuard};

use guest_errno::c_int_::{EFAULT, ENOSYS};

/// The guest word at `addr`, under the address-space lock `held` and
/// atomically. `None` when the address is not mapped.
///
/// The three functions here took a raw `mem` and were `unsafe` until
/// 2026-10-02; the guard's lifetime is what says the space is live now.
pub(crate) fn futex_read_word(held: &mut ReadGuard<'_>, addr: u64) -> Option<u32> {
    let ptr = held.resolve(addr, ffi::MEM_READ as c_int);
    if ptr.is_null() {
        return None;
    }
    // Relaxed: the ordering a futex needs comes from the queue's lock, which
    // the caller holds. What matters here is that the load is atomic at all.
    // SAFETY: a mapped guest word under the lock `held`; every caller checks
    // the alignment a futex word has.
    Some(unsafe { AtomicU32::from_ptr(ptr.cast()).load(Ordering::Relaxed) })
}

/// What backs this guest address, for a futex key. A host address only for a
/// shared page; see the module comment.
pub(crate) fn futex_backing(held: &mut ReadGuard<'_>, addr: u64) -> kernel_futex::Backing {
    let Some(entry) = held.pt(addr >> ffi::PAGE_BITS) else {
        return kernel_futex::Backing::Unmapped;
    };
    if entry.flags() & ffi::P_SHARED == 0 {
        return kernel_futex::Backing::Private;
    }
    match held.resolve(addr, ffi::MEM_READ as c_int) {
        p if p.is_null() => kernel_futex::Backing::Unmapped,
        p => kernel_futex::Backing::Shared(p as u64),
    }
}

/// The PI operations' compare-and-swap on the guest word, under `held`.
///
/// `MEM_WRITE`, which is what breaks a copy-on-write page: the swap is a
/// write, and Linux faults the page in for writing the same way
/// (`futex_cmpxchg_value_locked`). `None` for an address not mapped for
/// writing.
pub(crate) fn futex_cmpxchg(held: &mut ReadGuard<'_>, addr: u64, old: u32, new: u32) -> Option<Result<(), u32>> {
    let ptr = held.resolve(addr, ffi::MEM_WRITE as c_int);
    if ptr.is_null() {
        return None;
    }
    // SAFETY: as in `futex_read_word`; the caller checks the alignment.
    let word = unsafe { AtomicU32::from_ptr(ptr.cast()) };
    Some(word.compare_exchange(old, new, Ordering::SeqCst, Ordering::SeqCst).map(|_| ()))
}

/// `FUTEX_WAKE_OP`'s read-modify-write.
///
/// The lock has to be held across `mem_ptr` and the atomic, or the mapping can
/// vanish between them. What the operation *means* is decoded by the caller;
/// this takes the opcode and argument and answers the old value.
///
/// The word's old value, or a negative guest errno: `EFAULT` for an address
/// that is not mapped for writing, `ENOSYS` for an opcode Linux does not
/// define. It wrote the old value through an out-pointer until 2026-10-02.
pub(crate) fn futex_atomic_op(
    held: &mut ReadGuard<'_>,
    uaddr: u64,
    op_code: c_int,
    oparg: i32,
) -> Result<u32, c_int> {
    let ptr = held.resolve(uaddr, ffi::MEM_WRITE as c_int);
    if ptr.is_null() {
        return Err(EFAULT);
    }
    // SAFETY: as in `futex_read_word`; the caller checks the alignment.
    let word = unsafe { AtomicU32::from_ptr(ptr.cast()) };
    let arg = oparg as u32;
    let old = match op_code as u32 {
        op::SET => word.swap(arg, Ordering::SeqCst),
        op::ADD => word.fetch_add(arg, Ordering::SeqCst),
        op::OR => word.fetch_or(arg, Ordering::SeqCst),
        // ANDN is "and with the complement", which is what the name says and
        // what Linux does; the argument is inverted, not the result.
        op::ANDN => word.fetch_and(!arg, Ordering::SeqCst),
        op::XOR => word.fetch_xor(arg, Ordering::SeqCst),
        _ => return Err(ENOSYS),
    };
    Ok(old)
}

// ------------------------------------------------------------ diagnostics

/// Whether `IUL_FUTEX_DBG` is set at all.
///
/// Read once. Without the gate, every `futex_wait` would run a linear scan on
/// entry *and* exit for no reason, and JSC and Go hammer futex — so this stays
/// off the hot path unless the diagnostic was asked for. It is a separate
/// question from `iul_env.futex_dbg_secs`, which is zero for a value that is
/// not a number.
fn dbg_on() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("IUL_FUTEX_DBG").is_some())
}

/// Per-thread record of the futex address currently being waited on. 0 when the
/// thread is not in a wait.
///
/// A fixed table rather than a map: it is written on every wait and read once,
/// by a diagnostic that has already decided something is wrong. The C had no
/// lock on it at all.
const DBG_MAX: usize = 64;

/// The C also stored the value the thread was waiting *for*, and nothing read
/// it: the dump prints the word's value read fresh, which is the question.
#[derive(Clone, Copy, Default)]
struct Parked {
    pid: c_int,
    uaddr: u64,
}

fn parked() -> &'static Mutex<[Parked; DBG_MAX]> {
    static P: OnceLock<Mutex<[Parked; DBG_MAX]>> = OnceLock::new();
    P.get_or_init(|| Mutex::new([Parked::default(); DBG_MAX]))
}

fn dbg_set(pid: c_int, uaddr: u64) {
    if !dbg_on() {
        return;
    }
    let mut table = parked().lock().unwrap();
    for e in table.iter_mut() {
        if e.pid == pid || e.pid == 0 {
            *e = Parked { pid, uaddr };
            return;
        }
    }
}

/// What `pid` is parked on, or 0.
fn dbg_get(pid: c_int) -> u64 {
    let table = parked().lock().unwrap();
    table.iter().find(|e| e.pid == pid).map_or(0, |e| e.uaddr)
}

/// `IUL_FUTEX_DBG=<seconds>`: how long an untimed wait runs before the stall is
/// *reported* rather than merely waited out. 0 when the diagnostic is off.
pub fn futex_dbg_secs() -> c_int {
    util_iulenv::env().futex_dbg_secs
}

use logline::printk;


/// The word at `addr` in `mem`, for a diagnostic line; `None` for a null
/// space -- a thread whose `mm` the group-exit valve has taken, which the stall
/// dump walks past. That null went to the lock until 2026-10-02.
fn peek(mem: &ffi::mem, addr: u64) -> Option<u32> {
    futex_read_word(&mut ReadGuard::of(mem), addr)
}

/// [`peek`] at the calling task's own address space; `None` without one.
fn peek_current(addr: u64) -> Option<u32> {
    taskview::with_current_mm(|mm| peek(&mm.mem, addr)).flatten()
}

pub(crate) fn futex_dbg_enter_wait(uaddr: u64, val: u32) {
    let task = taskview::current();
    if task.is_null() {
        return;
    }
    dbg_set(taskview::current_pid(), uaddr);
    if uaddr != util_iulenv::env().futex_watch {
        return;
    }
    let mem = taskview::current_mem();
    let seen = peek_current(uaddr);
    // `space` is the private futex's key half, and it is printed because "the
    // wake found nobody" has two causes that look identical without it: nobody
    // was there, or the waiter is in another address space and the two keys
    // never matched.
    printk(&format!(
        "[fw] pid={} WAIT uaddr={uaddr:#x} space={:#x} expect_val={val:#x} actual_mem={} {}",
        taskview::current_pid(),
        mem as usize,
        seen.map_or("unmapped".to_string(), |v| format!("{v:#x}")),
        if seen != Some(val) {
            "(MISMATCH->EAGAIN)"
        } else {
            "(match->sleep)"
        }
    ));
}

/// `IUL_FUTEX_WATCH`'s wake half: what a wake on the watched address did, and
/// under which key.
///
/// The watch traced only the wait side, which answers "who is asleep here" and
/// not "did anybody try to wake them". A lost wakeup looks identical either way
/// without this.
///
pub(crate) fn futex_dbg_wake(uaddr: u64, n: c_int, private: c_int, space: u64) {
    if uaddr != util_iulenv::env().futex_watch {
        return;
    }
    let task = taskview::current();
    if task.is_null() {
        return;
    }
    let seen = peek_current(uaddr);
    printk(&format!(
        "[fw] pid={} WAKE uaddr={uaddr:#x} woke={n} private={private} space={space:#x} val={}",
        taskview::current_pid(),
        seen.map_or("unmapped".to_string(), |v| format!("{v:#x}"))
    ));
}

/// Safe: `current_pid` answers -1 with no task.
pub(crate) fn futex_dbg_leave_wait() {
    dbg_set(taskview::current_pid(), 0);
}

/// Every thread of this group, and what it is parked on. `IUL_FUTEX_DBG=<n>`.
///
/// This is what `struct task`'s `blocking` field exists for, and its only
/// reader: when a multithreaded guest stops making progress, the question is
/// which thread holds the word the others are waiting on, and the answer is a
/// list of who is parked where with the current value of each.
///
/// Once per process. A second stall is the same stall.
///
pub(crate) fn futex_dump_stall(uaddr: u64, val: u32, secs: c_int) {
    static DUMPED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if DUMPED.swap(true, Ordering::SeqCst) {
        return;
    }
    if taskview::current().is_null() {
        return;
    }
    // Two reads of the calling task through the accessors. This was a `&*task`
    // held across the walk below, which is a shared reference to a struct the
    // other threads of the group write -- `cpu_poke` among them -- the shape
    // `CLAUDE.md`'s "borrowing once" section says not to write.
    let pid = taskview::current_pid();
    let seen = peek_current(uaddr);
    printk(&format!(
        "FUTEX-DBG: pid={pid} stalled {secs}s on uaddr={uaddr:#x} (curval={}, waited-for val={val})",
        seen.map_or("unmapped".to_string(), |v| format!("{v:#x}"))
    ));

    let pids = kernel_pids::PidsGuard::take();
    let threads = kernel_pids::Group::current(pids.held())
        .into_iter()
        .flat_map(kernel_pids::Group::threads);
    for t in threads {
        let t_pid = t.pid();
        let task = t.task();
        let t_mem = taskview::mem_in(task.mm.as_ptr().cast_mut());
        let waddr = dbg_get(t_pid);
        // The group's threads share one address space, the caller's: the
        // word every one of them waits on is read there.
        let wv = if waddr != 0 { peek_current(waddr) } else { None };
        let waiters = if waddr != 0 {
            kernel_futex::waiters(t_mem as usize, waddr)
        } else {
            0
        };
        // A torn read of a running thread's registers is what this diagnostic
        // is for: it prints where every thread is when nothing is moving.
        // SAFETY: a racing read of plain words, which is what is asked for;
        // the registers are in a cell, so the `&task` asserts nothing of them.
        let (regs, pc) = unsafe { ((*task.cpu.get()).regs, (*task.cpu.get()).pc) };
        let blocking = task.blocking.load(Ordering::Relaxed);
        printk(&format!(
            "  thread pid={} blocking={} x8={} futex_uaddr={waddr:#x} curval={} waiters={waiters} \
             pc={:#x} lr={:#x} x0={:#x} x1={:#x}",
            t_pid,
            blocking as c_int,
            regs[8],
            wv.map_or("unmapped".to_string(), |v| format!("{v:#x}")),
            pc,
            regs[30],
            regs[0],
            regs[1],
        ));
    }
    // Every guest store to the watched window, when IUL_WATCH_PAGE is armed.
    //
    // The ring is otherwise dumped only on a fatal fault and at exit, and a
    // hang reaches neither -- which is why three occurrences of the task_race
    // deadlock produced no answer to "did the unlock's store happen". It is
    // the measurement that closed that one: the hung process had never written
    // the word at all.
    // The write-watchpoint ring, armed with `IUL_WATCH_PAGE`, and **only
    // recording jit stores in a build with `ENABLE_WRITE_WATCHPOINT`** -- which
    // is commented out by default, so an empty ring means nothing without it.
    if asbestos_diag::watch_pages()[0] != 0 {
        let (lo, hi) = asbestos_diag::watch_window();
        asbestos_diag::dump_watch_hits(lo, hi);
    }
}

/// An op nobody implements, reported with the process that asked.
///
pub(crate) fn futex_report_unsupported(
    op: u32,
    cmd: u32,
    uaddr: u64,
    val: u32,
    uaddr2: u64,
    val3: u32,
) {
    printk(&format!(
        "SYS_FUTEX: unsupported op={op} (cmd={cmd}) uaddr={uaddr:#x} val={val} \
         uaddr2={uaddr2:#x} val3={val3:#x} pid={} comm={}",
        taskview::current_pid(),
        taskview::current_comm()
    ));
}

// ------------------------------------------------ what the futex table asks

/// The calling task's address space, as `crates/kernel/futex` asks about one.
///
/// The pointer is kept as the space's identity, the key half a private futex
/// is filed under, and is never dereferenced: each question locks the calling
/// task's own space through `ReadGuard::current`, and a task with none answers
/// "unmapped".
pub(crate) struct CurrentSpace(*mut ffi::mem);

impl CurrentSpace {
    pub(crate) fn new() -> CurrentSpace {
        CurrentSpace(taskview::current_mem())
    }
}

impl kernel_futex::Space for CurrentSpace {
    fn id(&self) -> usize {
        self.0 as usize
    }

    fn read_word(&self, addr: u64) -> Option<u32> {
        futex_read_word(&mut ReadGuard::current()?, addr)
    }

    fn cmpxchg_word(&self, addr: u64, old: u32, new: u32) -> Option<Result<(), u32>> {
        futex_cmpxchg(&mut ReadGuard::current()?, addr, old, new)
    }

    fn backing(&self, addr: u64) -> kernel_futex::Backing {
        ReadGuard::current().map_or(kernel_futex::Backing::Unmapped, |mut held| futex_backing(&mut held, addr))
    }

    fn woke(&self, addr: u64, n: c_int, private: bool, space: u64) {
        futex_dbg_wake(addr, n, private as c_int, space);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_parked_table_is_the_size_the_c_had() {
        // A fixed table because it is written on every wait when the
        // diagnostic is on. 64 threads is more than any guest here runs.
        assert_eq!(DBG_MAX, 64);
        assert_eq!(Parked::default().pid, 0, "an empty slot is pid 0");
    }

    #[test]
    fn andn_inverts_the_argument_and_not_the_result() {
        // Linux's FUTEX_OP_ANDN is "and with the complement of oparg". Getting
        // it the other way round is a value that looks plausible.
        let arg: u32 = 0x0f;
        assert_eq!(0xff_u32 & !arg, 0xf0);
        assert_ne!(!(0xff_u32 & arg), 0xf0);
    }
}
