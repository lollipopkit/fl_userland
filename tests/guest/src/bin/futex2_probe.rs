//! What the futex2 syscalls (`futex_waitv`, `futex_wake`, `futex_wait`,
//! `futex_requeue`), the priority-inheritance `futex(2)` operations and
//! `PR_FUTEX_HASH` do with their arguments.
//!
//! One line per case, nothing asserted: `probe_diff.sh` compares the lines
//! against a real kernel. Nothing here parks without a timeout; the cases that
//! need a second thread to wake them spawn one that wakes after a few
//! milliseconds.
//!
//! # A fresh word per case
//!
//! `futex_probe` learned this: the PI operations write the caller's tid into the
//! word, so reusing a word makes a later case depend on an earlier one.

use std::io::Write;
use std::sync::atomic::{AtomicU32, Ordering};

unsafe fn sys(n: i64, a: i64, b: i64, c: i64, d: i64, e: i64, f: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a => ret,
            in("x1") b, in("x2") c, in("x3") d, in("x4") e, in("x5") f,
            options(nostack)
        );
    }
    ret
}

fn errname(e: i32) -> String {
    let n = match e {
        1 => "EPERM", 3 => "ESRCH", 4 => "EINTR", 9 => "EBADF", 11 => "EAGAIN",
        12 => "ENOMEM", 14 => "EFAULT", 16 => "EBUSY", 22 => "EINVAL",
        35 => "EDEADLK", 38 => "ENOSYS", 95 => "EOPNOTSUPP", 110 => "ETIMEDOUT",
        _ => return format!("errno {e}"),
    };
    n.into()
}

fn r(v: i64) -> String {
    if v < 0 && v > -4096 { format!("-{}", errname(-v as i32)) } else { v.to_string() }
}

fn say(what: &str, v: i64) {
    println!("  {what:<58} {}", r(v));
    let _ = std::io::stdout().flush();
}

fn show(what: &str, v: String) {
    println!("  {what:<58} {v}");
    let _ = std::io::stdout().flush();
}

const NR_FUTEX: i64 = 98;
const NR_PRCTL: i64 = 167;
const NR_FUTEX_WAITV: i64 = 449;
const NR_FUTEX_WAKE: i64 = 454;
const NR_FUTEX_WAIT: i64 = 455;
const NR_FUTEX_REQUEUE: i64 = 456;

const U8: i64 = 0;
const U16: i64 = 1;
const U32: i64 = 2;
const U64: i64 = 3;
const NUMA: i64 = 4;
const MPOL: i64 = 8;
const PRIV: i64 = 128;

const ANY: i64 = 0xffff_ffff;

const CLOCK_REALTIME: i64 = 0;
const CLOCK_MONOTONIC: i64 = 1;
const CLOCK_BOOTTIME: i64 = 7;

/// Words nothing else has touched, at a stable address for the whole run.
fn word() -> &'static AtomicU32 {
    Box::leak(Box::new(AtomicU32::new(0)))
}

fn addr(w: &AtomicU32) -> i64 {
    w as *const AtomicU32 as i64
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Waitv {
    val: u64,
    uaddr: u64,
    flags: u32,
    reserved: u32,
}

fn wv(w: &AtomicU32, val: u64, flags: i64) -> Waitv {
    Waitv { val, uaddr: addr(w) as u64, flags: flags as u32, reserved: 0 }
}

fn now(clock: i64) -> [i64; 2] {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(clock as libc::clockid_t, &mut ts) };
    [ts.tv_sec, ts.tv_nsec]
}

fn plus_ms(mut t: [i64; 2], ms: i64) -> [i64; 2] {
    t[1] += ms * 1_000_000;
    while t[1] >= 1_000_000_000 {
        t[1] -= 1_000_000_000;
        t[0] += 1;
    }
    while t[1] < 0 {
        t[1] += 1_000_000_000;
        t[0] -= 1;
    }
    t
}

fn gettid() -> i64 {
    unsafe { sys(178, 0, 0, 0, 0, 0, 0) }
}

/// Waker thread: sleeps `ms`, then runs `f`.
fn later(ms: u64, f: impl FnOnce() + Send + 'static) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(ms));
        f();
    })
}

fn main() {
    println!("## futex2 and PI futexes");
    // First, in a child that has never had a second thread: the private hash
    // is only allocated with the first one.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        hash_cases("single-threaded");
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
    futex_wake_cases();
    numa_cases();
    wake_count_cases();
    futex_wait_cases();
    futex_waitv_cases();
    futex_requeue_cases();
    pi_cases();
    hash_cases("after threads");
}

fn futex_wake_cases() {
    println!("## futex_wake");
    let w = word();
    for (name, flags) in [
        ("U32 | PRIVATE", U32 | PRIV),
        ("U32, shared", U32),
        ("U8", U8 | PRIV),
        ("U16", U16 | PRIV),
        ("U64", U64 | PRIV),
        ("U32 | NUMA", U32 | NUMA | PRIV),
        ("U32 | MPOL", U32 | MPOL | PRIV),
        ("U32 | unknown bit 0x10", U32 | 0x10 | PRIV),
        ("U32 | bit 31", U32 | (1 << 31) | PRIV),
    ] {
        say(&format!("wake 1, {name}"), unsafe { sys(NR_FUTEX_WAKE, addr(w), ANY, 1, flags, 0, 0) });
    }
    say("wake, mask 0", unsafe { sys(NR_FUTEX_WAKE, addr(w), 0, 1, U32 | PRIV, 0, 0) });
    say("wake, mask 0x1_0000_0000", unsafe { sys(NR_FUTEX_WAKE, addr(w), 1 << 32, 1, U32 | PRIV, 0, 0) });
    say("wake, mask u64::MAX", unsafe { sys(NR_FUTEX_WAKE, addr(w), -1, 1, U32 | PRIV, 0, 0) });
    say("wake 0", unsafe { sys(NR_FUTEX_WAKE, addr(w), ANY, 0, U32 | PRIV, 0, 0) });
    say("wake -1", unsafe { sys(NR_FUTEX_WAKE, addr(w), ANY, -1, U32 | PRIV, 0, 0) });
    say("wake, unaligned", unsafe { sys(NR_FUTEX_WAKE, addr(w) + 1, ANY, 1, U32 | PRIV, 0, 0) });
    say("wake, U16 aligned to 2", unsafe { sys(NR_FUTEX_WAKE, addr(w) + 2, ANY, 1, U16 | PRIV, 0, 0) });
    say("wake, null", unsafe { sys(NR_FUTEX_WAKE, 0, ANY, 1, U32 | PRIV, 0, 0) });
    say("wake, unmapped", unsafe { sys(NR_FUTEX_WAKE, 0x10, ANY, 1, U32 | PRIV, 0, 0) });
    say("wake, unmapped, shared", unsafe { sys(NR_FUTEX_WAKE, 0x10, ANY, 1, U32, 0, 0) });

    // A real waiter, woken through futex_wake.
    let w = word();
    let a = addr(w);
    let t = std::thread::spawn(move || unsafe {
        let ts = [5i64, 0];
        sys(NR_FUTEX, a, 128, 0, ts.as_ptr() as i64, 0, 0)
    });
    let mut woke = 0;
    for _ in 0..500 {
        woke = unsafe { sys(NR_FUTEX_WAKE, a, ANY, 1, U32 | PRIV, 0, 0) };
        if woke != 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    say("futex_wake wakes a FUTEX_WAIT waiter", woke);
    say("  and the waiter answers", t.join().unwrap());

    // futex_wake's mask against FUTEX_WAIT_BITSET's.
    let w = word();
    let a = addr(w);
    let t = std::thread::spawn(move || unsafe {
        let ts = plus_ms(now(CLOCK_MONOTONIC), 300);
        sys(NR_FUTEX, a, 9 | 128, 0, ts.as_ptr() as i64, 0, 0b0100)
    });
    std::thread::sleep(std::time::Duration::from_millis(50));
    say("wake, disjoint mask, against a bitset waiter", unsafe { sys(NR_FUTEX_WAKE, a, 0b0011, 1, U32 | PRIV, 0, 0) });
    say("wake, overlapping mask", unsafe { sys(NR_FUTEX_WAKE, a, 0b0110, 1, U32 | PRIV, 0, 0) });
    say("  and the waiter answers", t.join().unwrap());
}

/// `FUTEX2_NUMA`: the futex is two words, the value and a node, and a node of
/// -1 is filled in by the kernel.
fn numa_cases() {
    println!("## FUTEX2_NUMA");
    #[repr(C, align(8))]
    struct Pair([AtomicU32; 2]);
    let pair = || -> &'static Pair { Box::leak(Box::new(Pair([AtomicU32::new(0), AtomicU32::new(0)]))) };
    for (name, node) in [("node 0", 0u32), ("node -1", u32::MAX), ("node 1", 1), ("node 1000", 1000), ("node -2", u32::MAX - 1)] {
        let p = pair();
        p.0[1].store(node, Ordering::SeqCst);
        let a = p as *const Pair as i64;
        say(&format!("wake, {name}"), unsafe { sys(NR_FUTEX_WAKE, a, ANY, 1, U32 | NUMA | PRIV, 0, 0) });
        show("  node word after", format!("{:#x}", p.0[1].load(Ordering::SeqCst)));
        p.0[1].store(node, Ordering::SeqCst);
        say(&format!("wait mismatch, {name}"), unsafe { sys(NR_FUTEX_WAIT, a, 1, ANY, U32 | NUMA | PRIV, 0, 0) });
        show("  node word after", format!("{:#x}", p.0[1].load(Ordering::SeqCst)));
        p.0[1].store(node, Ordering::SeqCst);
        say(&format!("wait mismatch, shared, {name}"), unsafe { sys(NR_FUTEX_WAIT, a, 1, ANY, U32 | NUMA, 0, 0) });
        show("  node word after", format!("{:#x}", p.0[1].load(Ordering::SeqCst)));
    }
    let p = pair();
    let a = p as *const Pair as i64;
    say("wake, NUMA at a 4-byte offset", unsafe { sys(NR_FUTEX_WAKE, a + 4, ANY, 1, U32 | NUMA | PRIV, 0, 0) });
    say("wake, MPOL without NUMA", unsafe { sys(NR_FUTEX_WAKE, a, ANY, 1, U32 | MPOL | PRIV, 0, 0) });
    show("  node word after", format!("{:#x}", p.0[1].load(Ordering::SeqCst)));
    p.0[1].store(u32::MAX, Ordering::SeqCst);
    say("wake, NUMA | MPOL, node -1", unsafe { sys(NR_FUTEX_WAKE, a, ANY, 1, U32 | NUMA | MPOL | PRIV, 0, 0) });
    show("  node word after", format!("{:#x}", p.0[1].load(Ordering::SeqCst)));
    // The NUMA node word unmapped: the value at the end of a page.
    let page = unsafe {
        libc::mmap(std::ptr::null_mut(), 8192, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    } as i64;
    unsafe { libc::munmap((page + 4096) as *mut libc::c_void, 4096) };
    say("wake, NUMA, value at the end of the last page", unsafe { sys(NR_FUTEX_WAKE, page + 4088, ANY, 1, U32 | NUMA | PRIV, 0, 0) });
    say("wake, NUMA, unmapped", unsafe { sys(NR_FUTEX_WAKE, 0x10, ANY, 1, U32 | NUMA | PRIV, 0, 0) });
    say("wake, NUMA, null", unsafe { sys(NR_FUTEX_WAKE, 0, ANY, 1, U32 | NUMA | PRIV, 0, 0) });
    say("wake, NUMA, unmapped, shared", unsafe { sys(NR_FUTEX_WAKE, 0x10, ANY, 1, U32 | NUMA, 0, 0) });
    say("wake, U32, word at the end of the last page", unsafe { sys(NR_FUTEX_WAKE, page + 4092, ANY, 1, U32 | PRIV, 0, 0) });
    let w = word();
    say("futex_requeue, NUMA entry", {
        let v = [wv(w, 0, U32 | NUMA | PRIV), wv(word(), 0, U32 | PRIV)];
        unsafe { sys(NR_FUTEX_REQUEUE, v.as_ptr() as i64, 0, 1, 1, 0, 0) }
    });
}

/// How many a wake count of 0 or less wakes, with three parked.
fn wake_count_cases() {
    println!("## wake counts with waiters parked");
    for (name, legacy, nr) in [
        ("FUTEX_WAKE 0", true, 0i64),
        ("FUTEX_WAKE -1", true, -1),
        ("FUTEX_WAKE 2", true, 2),
        ("futex_wake 0", false, 0),
        ("futex_wake -1", false, -1),
    ] {
        let w = word();
        let a = addr(w);
        let ts: Vec<_> = (0..3)
            .map(|_| std::thread::spawn(move || unsafe {
                let t = [1i64, 0];
                sys(NR_FUTEX, a, 128, 0, t.as_ptr() as i64, 0, 0)
            }))
            .collect();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let n = if legacy {
            unsafe { sys(NR_FUTEX, a, 1 | 128, nr, 0, 0, 0) }
        } else {
            unsafe { sys(NR_FUTEX_WAKE, a, ANY, nr, U32 | PRIV, 0, 0) }
        };
        say(name, n);
        let _ = unsafe { sys(NR_FUTEX, a, 1 | 128, 9, 0, 0, 0) };
        for t in ts {
            t.join().unwrap();
        }
    }
    say("unknown op 14, unaligned", unsafe { sys(NR_FUTEX, addr(word()) + 1, 14 | 128, 0, 0, 0, 0) });
    say("WAIT, unaligned, bad timeout pointer", unsafe { sys(NR_FUTEX, addr(word()) + 1, 128, 0, 0x10, 0, 0) });
    say("WAKE | CLOCK_REALTIME, unaligned", unsafe { sys(NR_FUTEX, addr(word()) + 1, 1 | 128 | 256, 0, 0, 0, 0) });
}

fn futex_wait_cases() {
    println!("## futex_wait");
    let w = word();
    let a = addr(w);
    let soon = || plus_ms(now(CLOCK_MONOTONIC), 2);
    say("mismatch, no timeout", unsafe { sys(NR_FUTEX_WAIT, a, 1, ANY, U32 | PRIV, 0, 0) });
    say("match, past monotonic deadline", unsafe {
        let t = plus_ms(now(CLOCK_MONOTONIC), -1000);
        sys(NR_FUTEX_WAIT, a, 0, ANY, U32 | PRIV, t.as_ptr() as i64, CLOCK_MONOTONIC)
    });
    say("match, 2ms monotonic deadline", unsafe {
        let t = soon();
        sys(NR_FUTEX_WAIT, a, 0, ANY, U32 | PRIV, t.as_ptr() as i64, CLOCK_MONOTONIC)
    });
    say("match, 2ms realtime deadline", unsafe {
        let t = plus_ms(now(CLOCK_REALTIME), 2);
        sys(NR_FUTEX_WAIT, a, 0, ANY, U32 | PRIV, t.as_ptr() as i64, CLOCK_REALTIME)
    });
    say("match, monotonic time on the realtime clock", unsafe {
        let t = soon();
        sys(NR_FUTEX_WAIT, a, 0, ANY, U32 | PRIV, t.as_ptr() as i64, CLOCK_REALTIME)
    });
    say("clock BOOTTIME", unsafe {
        let t = soon();
        sys(NR_FUTEX_WAIT, a, 0, ANY, U32 | PRIV, t.as_ptr() as i64, CLOCK_BOOTTIME)
    });
    say("clock 99", unsafe {
        let t = soon();
        sys(NR_FUTEX_WAIT, a, 0, ANY, U32 | PRIV, t.as_ptr() as i64, 99)
    });
    say("clock 99, no timeout, mismatch", unsafe { sys(NR_FUTEX_WAIT, a, 1, ANY, U32 | PRIV, 0, 99) });
    say("tv_nsec 1e9", unsafe {
        let t = [0i64, 1_000_000_000];
        sys(NR_FUTEX_WAIT, a, 0, ANY, U32 | PRIV, t.as_ptr() as i64, CLOCK_MONOTONIC)
    });
    say("negative tv_sec", unsafe {
        let t = [-1i64, 0];
        sys(NR_FUTEX_WAIT, a, 0, ANY, U32 | PRIV, t.as_ptr() as i64, CLOCK_MONOTONIC)
    });
    say("unreadable timeout", unsafe { sys(NR_FUTEX_WAIT, a, 0, ANY, U32 | PRIV, 0x10, CLOCK_MONOTONIC) });
    say("mask 0", unsafe { sys(NR_FUTEX_WAIT, a, 1, 0, U32 | PRIV, 0, 0) });
    say("mask 0x1_0000_0000", unsafe { sys(NR_FUTEX_WAIT, a, 1, 1 << 32, U32 | PRIV, 0, 0) });
    say("val 0x1_0000_0000", unsafe { sys(NR_FUTEX_WAIT, a, 1 << 32, ANY, U32 | PRIV, 0, 0) });
    say("val 0xffff_ffff, mismatch", unsafe { sys(NR_FUTEX_WAIT, a, 0xffff_ffff, ANY, U32 | PRIV, 0, 0) });
    say("U8", unsafe { sys(NR_FUTEX_WAIT, a, 1, ANY, U8 | PRIV, 0, 0) });
    say("U64", unsafe { sys(NR_FUTEX_WAIT, a, 1, ANY, U64 | PRIV, 0, 0) });
    say("NUMA", unsafe { sys(NR_FUTEX_WAIT, a, 1, ANY, U32 | NUMA | PRIV, 0, 0) });
    say("unknown flag 0x10", unsafe { sys(NR_FUTEX_WAIT, a, 1, ANY, U32 | 0x10 | PRIV, 0, 0) });
    say("unaligned", unsafe { sys(NR_FUTEX_WAIT, a + 1, 1, ANY, U32 | PRIV, 0, 0) });
    say("null", unsafe { sys(NR_FUTEX_WAIT, 0, 1, ANY, U32 | PRIV, 0, 0) });
    say("unmapped", unsafe { sys(NR_FUTEX_WAIT, 0x10, 1, ANY, U32 | PRIV, 0, 0) });
    say("shared, mismatch", unsafe { sys(NR_FUTEX_WAIT, a, 1, ANY, U32, 0, 0) });

    // Woken by FUTEX_WAKE through the old interface.
    let w = word();
    let a = addr(w);
    let t = later(20, move || {
        for _ in 0..200 {
            if unsafe { sys(NR_FUTEX, a, 1 | 128, 1, 0, 0, 0) } > 0 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    });
    say("woken by FUTEX_WAKE", unsafe {
        let d = plus_ms(now(CLOCK_MONOTONIC), 3000);
        sys(NR_FUTEX_WAIT, a, 0, ANY, U32 | PRIV, d.as_ptr() as i64, CLOCK_MONOTONIC)
    });
    t.join().unwrap();
}

fn futex_waitv_cases() {
    println!("## futex_waitv");
    let (w0, w1) = (word(), word());
    let soon = || plus_ms(now(CLOCK_MONOTONIC), 2);
    let call = |v: &[Waitv], n: i64, flags: i64, t: Option<[i64; 2]>, clock: i64| unsafe {
        let tp = t.as_ref().map_or(0, |t| t.as_ptr() as i64);
        sys(NR_FUTEX_WAITV, v.as_ptr() as i64, n, flags, tp, clock, 0)
    };
    let both = [wv(w0, 0, U32 | PRIV), wv(w1, 0, U32 | PRIV)];
    say("two, both match, 2ms deadline", call(&both, 2, 0, Some(soon()), CLOCK_MONOTONIC));
    say("two, realtime deadline", call(&both, 2, 0, Some(plus_ms(now(CLOCK_REALTIME), 2)), CLOCK_REALTIME));
    say("two, past deadline", call(&both, 2, 0, Some(plus_ms(now(CLOCK_MONOTONIC), -5)), CLOCK_MONOTONIC));
    let second = [wv(w0, 0, U32 | PRIV), wv(w1, 1, U32 | PRIV)];
    say("second does not match", call(&second, 2, 0, None, 0));
    let first = [wv(w0, 1, U32 | PRIV), wv(w1, 0, U32 | PRIV)];
    say("first does not match", call(&first, 2, 0, None, 0));
    say("nr 0", call(&both, 0, 0, None, 0));
    let many = vec![wv(w0, 1, U32 | PRIV); 129];
    say("nr 128, all mismatch", call(&many, 128, 0, None, 0));
    say("nr 129", call(&many, 129, 0, None, 0));
    say("nr -1", call(&both, -1, 0, None, 0));
    say("flags 1", call(&both, 2, 1, Some(soon()), CLOCK_MONOTONIC));
    say("clock BOOTTIME", call(&both, 2, 0, Some(soon()), CLOCK_BOOTTIME));
    say("clock 99", call(&both, 2, 0, Some(soon()), 99));
    say("clock 99, no timeout, mismatch", call(&second, 2, 0, None, 99));
    say("tv_nsec -1", call(&both, 2, 0, Some([0, -1]), CLOCK_MONOTONIC));
    say("unreadable timeout", unsafe { sys(NR_FUTEX_WAITV, both.as_ptr() as i64, 2, 0, 0x10, CLOCK_MONOTONIC, 0) });
    say("null waiters", unsafe { sys(NR_FUTEX_WAITV, 0, 2, 0, 0, 0, 0) });
    say("unmapped waiters", unsafe { sys(NR_FUTEX_WAITV, 0x10, 2, 0, 0, 0, 0) });
    for (name, flags) in [
        ("entry U8", U8 | PRIV),
        ("entry U64", U64 | PRIV),
        ("entry NUMA", U32 | NUMA | PRIV),
        ("entry unknown flag 0x10", U32 | 0x10 | PRIV),
        ("entry shared", U32),
    ] {
        let v = [wv(w0, 1, flags), wv(w1, 0, U32 | PRIV)];
        say(&format!("{name}, mismatch"), call(&v, 2, 0, None, 0));
    }
    let mut v = second;
    v[1].reserved = 1;
    say("entry reserved != 0", call(&v, 2, 0, None, 0));
    let mut v = second;
    v[1].val = 1 << 32;
    say("entry val 0x1_0000_0000", call(&v, 2, 0, None, 0));
    let mut v = second;
    v[1].uaddr += 1;
    say("entry unaligned", call(&v, 2, 0, None, 0));
    let mut v = second;
    v[1].uaddr = 0x10;
    say("entry unmapped", call(&v, 2, 0, None, 0));
    let mut v = second;
    v[1].uaddr = 0;
    say("entry null", call(&v, 2, 0, None, 0));
    let dup = [wv(w0, 0, U32 | PRIV), wv(w0, 1, U32 | PRIV)];
    say("one word twice, second mismatch", call(&dup, 2, 0, None, 0));

    // Which index is woken.
    for idx in 0..3usize {
        let ws = [word(), word(), word()];
        let target = addr(ws[idx]);
        let t = later(20, move || {
            for _ in 0..200 {
                if unsafe { sys(NR_FUTEX, target, 1 | 128, 1, 0, 0, 0) } > 0 {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        });
        let v = [wv(ws[0], 0, U32 | PRIV), wv(ws[1], 0, U32 | PRIV), wv(ws[2], 0, U32 | PRIV)];
        say(
            &format!("three, woken on index {idx}"),
            call(&v, 3, 0, Some(plus_ms(now(CLOCK_MONOTONIC), 3000)), CLOCK_MONOTONIC),
        );
        t.join().unwrap();
    }
    // A shared entry woken by a shared FUTEX_WAKE.
    let ws = [word(), word()];
    let target = addr(ws[1]);
    let t = later(20, move || {
        for _ in 0..200 {
            if unsafe { sys(NR_FUTEX, target, 1, 1, 0, 0, 0) } > 0 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    });
    let v = [wv(ws[0], 0, U32 | PRIV), wv(ws[1], 0, U32)];
    say("private + shared, shared woken", call(&v, 2, 0, Some(plus_ms(now(CLOCK_MONOTONIC), 3000)), CLOCK_MONOTONIC));
    t.join().unwrap();
}

fn futex_requeue_cases() {
    println!("## futex_requeue");
    let (w0, w1) = (word(), word());
    let call = |v: &[Waitv], flags: i64, nw: i64, nr: i64| unsafe {
        sys(NR_FUTEX_REQUEUE, v.as_ptr() as i64, flags, nw, nr, 0, 0)
    };
    let ok = [wv(w0, 0, U32 | PRIV), wv(w1, 0, U32 | PRIV)];
    say("nobody waiting, value matches", call(&ok, 0, 1, 1));
    let bad = [wv(w0, 1, U32 | PRIV), wv(w1, 0, U32 | PRIV)];
    say("first value does not match", call(&bad, 0, 1, 1));
    let bad2 = [wv(w0, 0, U32 | PRIV), wv(w1, 1, U32 | PRIV)];
    say("second value does not match", call(&bad2, 0, 1, 1));
    say("flags 1", call(&ok, 1, 1, 1));
    say("nr_wake -1", call(&ok, 0, -1, 1));
    say("nr_requeue -1", call(&ok, 0, 1, -1));
    say("nr_wake 0, nr_requeue 0", call(&ok, 0, 0, 0));
    let mixed = [wv(w0, 0, U32 | PRIV), wv(w1, 0, U32)];
    say("private onto shared", call(&mixed, 0, 1, 1));
    let u8s = [wv(w0, 0, U8 | PRIV), wv(w1, 0, U32 | PRIV)];
    say("first U8", call(&u8s, 0, 1, 1));
    let mut res = ok;
    res[0].reserved = 1;
    say("reserved != 0", call(&res, 0, 1, 1));
    let same = [wv(w0, 0, U32 | PRIV), wv(w0, 0, U32 | PRIV)];
    say("same address twice", call(&same, 0, 1, 1));
    say("null waiters", unsafe { sys(NR_FUTEX_REQUEUE, 0, 0, 1, 1, 0, 0) });
    let mut un = ok;
    un[1].uaddr = 0x10;
    say("second unmapped", call(&un, 0, 1, 1));

    // Two waiters on w0: wake one, requeue one onto w1, then wake w1.
    let (a, b) = (word(), word());
    let (aa, ba) = (addr(a), addr(b));
    let ts: Vec<_> = (0..2)
        .map(|_| {
            std::thread::spawn(move || unsafe {
                let t = [3i64, 0];
                sys(NR_FUTEX, aa, 128, 0, t.as_ptr() as i64, 0, 0)
            })
        })
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let v = [wv(a, 0, U32 | PRIV), wv(b, 0, U32 | PRIV)];
    say("two waiters: wake 1, requeue 1", call(&v, 0, 1, 1));
    say("  wake on the second word", unsafe { sys(NR_FUTEX_WAKE, ba, ANY, 5, U32 | PRIV, 0, 0) });
    let mut answers: Vec<i64> = ts.into_iter().map(|t| t.join().unwrap()).collect();
    answers.sort();
    show("  the waiters answer", format!("{answers:?}"));
}

fn pi_cases() {
    println!("## PI futexes");
    const LOCK_PI: i64 = 6;
    const UNLOCK_PI: i64 = 7;
    const TRYLOCK_PI: i64 = 8;
    const WAIT_REQUEUE_PI: i64 = 11;
    const CMP_REQUEUE_PI: i64 = 12;
    const LOCK_PI2: i64 = 13;
    const P: i64 = 128;
    const RT: i64 = 256;
    let tid = gettid() as u32;
    let fx = |w: &AtomicU32, op: i64, val: i64, t: i64, a2: i64, v3: i64| unsafe {
        sys(NR_FUTEX, addr(w), op, val, t, a2, v3)
    };
    let state = |w: &AtomicU32| {
        let v = w.load(Ordering::SeqCst);
        if v == 0 {
            "0".to_string()
        } else {
            let mut s = String::new();
            if v & 0x3fff_ffff == tid {
                s.push_str("tid");
            } else {
                s.push_str(&format!("{:#x}", v & 0x3fff_ffff));
            }
            if v & 0x8000_0000 != 0 {
                s.push_str("|WAITERS");
            }
            if v & 0x4000_0000 != 0 {
                s.push_str("|OWNER_DIED");
            }
            s
        }
    };

    for (name, op) in [("LOCK_PI", LOCK_PI), ("LOCK_PI2", LOCK_PI2)] {
        let w = word();
        say(&format!("{name} on 0"), fx(w, op | P, 0, 0, 0, 0));
        show("  word", state(w));
        say(&format!("  {name} again, own lock"), fx(w, op | P, 0, 0, 0, 0));
        say("  TRYLOCK_PI, own lock", fx(w, TRYLOCK_PI | P, 0, 0, 0, 0));
        say("  UNLOCK_PI", fx(w, UNLOCK_PI | P, 0, 0, 0, 0));
        show("  word", state(w));
        say("  UNLOCK_PI, not held", fx(w, UNLOCK_PI | P, 0, 0, 0, 0));
    }
    let w = word();
    say("TRYLOCK_PI on 0", fx(w, TRYLOCK_PI | P, 0, 0, 0, 0));
    show("  word", state(w));
    say("  UNLOCK_PI", fx(w, UNLOCK_PI | P, 0, 0, 0, 0));
    say("LOCK_PI | CLOCK_REALTIME", fx(word(), LOCK_PI | P | RT, 0, 0, 0, 0));
    say("LOCK_PI2 | CLOCK_REALTIME on 0", fx(word(), LOCK_PI2 | P | RT, 0, 0, 0, 0));
    say("TRYLOCK_PI | CLOCK_REALTIME", fx(word(), TRYLOCK_PI | P | RT, 0, 0, 0, 0));
    say("UNLOCK_PI | CLOCK_REALTIME", fx(word(), UNLOCK_PI | P | RT, 0, 0, 0, 0));
    say("LOCK_PI, unaligned", unsafe { sys(NR_FUTEX, addr(word()) + 1, LOCK_PI | P, 0, 0, 0, 0) });
    say("LOCK_PI, unmapped", unsafe { sys(NR_FUTEX, 0x10, LOCK_PI | P, 0, 0, 0, 0) });
    say("UNLOCK_PI, unmapped", unsafe { sys(NR_FUTEX, 0x10, UNLOCK_PI | P, 0, 0, 0, 0) });
    say("TRYLOCK_PI, unmapped", unsafe { sys(NR_FUTEX, 0x10, TRYLOCK_PI | P, 0, 0, 0, 0) });

    // A word owned by a tid that does not exist.
    let w = word();
    w.store(0x3fff_0000, Ordering::SeqCst);
    say("LOCK_PI, owner tid does not exist", fx(w, LOCK_PI | P, 0, 0, 0, 0));
    show("  word", state(w));
    let w = word();
    w.store(0x3fff_0000, Ordering::SeqCst);
    say("TRYLOCK_PI, owner tid does not exist", fx(w, TRYLOCK_PI | P, 0, 0, 0, 0));
    show("  word", state(w));
    let w = word();
    w.store(0x3fff_0000, Ordering::SeqCst);
    say("UNLOCK_PI, owner is someone else", fx(w, UNLOCK_PI | P, 0, 0, 0, 0));
    show("  word", state(w));
    let w = word();
    w.store(0x4000_0000, Ordering::SeqCst);
    say("LOCK_PI, OWNER_DIED and no owner", fx(w, LOCK_PI | P, 0, 0, 0, 0));
    show("  word", state(w));
    let _ = fx(w, UNLOCK_PI | P, 0, 0, 0, 0);
    let w = word();
    w.store(tid | 0x8000_0000, Ordering::SeqCst);
    say("UNLOCK_PI, own tid with WAITERS and no waiter", fx(w, UNLOCK_PI | P, 0, 0, 0, 0));
    show("  word", state(w));

    // Contention with a live owner: another thread holds it.
    let w = word();
    let wa = addr(w) as usize;
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let owner = std::thread::spawn(move || unsafe {
        let r = sys(NR_FUTEX, wa as i64, LOCK_PI | P, 0, 0, 0, 0);
        locked_tx.send(r).unwrap();
        go_rx.recv().unwrap();
        sys(NR_FUTEX, wa as i64, UNLOCK_PI | P, 0, 0, 0, 0)
    });
    say("owner thread LOCK_PI", locked_rx.recv().unwrap());
    say("TRYLOCK_PI, held by a live thread", fx(w, TRYLOCK_PI | P, 0, 0, 0, 0));
    say("UNLOCK_PI, held by a live thread", fx(w, UNLOCK_PI | P, 0, 0, 0, 0));
    let past = plus_ms(now(CLOCK_REALTIME), 20);
    say("LOCK_PI, 20ms realtime deadline", fx(w, LOCK_PI | P, 0, past.as_ptr() as i64, 0, 0));
    show("  word after the timeout", if w.load(Ordering::SeqCst) & 0x8000_0000 != 0 { "WAITERS set" } else { "WAITERS clear" }.into());
    let mono = plus_ms(now(CLOCK_MONOTONIC), 20);
    say("LOCK_PI2, 20ms monotonic deadline", fx(w, LOCK_PI2 | P, 0, mono.as_ptr() as i64, 0, 0));
    let rt = plus_ms(now(CLOCK_REALTIME), 20);
    say("LOCK_PI2 | CLOCK_REALTIME, 20ms deadline", fx(w, LOCK_PI2 | P | RT, 0, rt.as_ptr() as i64, 0, 0));
    say("LOCK_PI, bad timespec", fx(w, LOCK_PI | P, 0, [0i64, -1].as_ptr() as i64, 0, 0));
    // Now block for real and let the owner hand over.
    let g = later(30, move || go_tx.send(()).unwrap());
    say("LOCK_PI, handed over by UNLOCK_PI", fx(w, LOCK_PI | P, 0, 0, 0, 0));
    show("  word", state(w));
    say("  the owner's UNLOCK_PI", owner.join().unwrap());
    g.join().unwrap();
    say("  UNLOCK_PI", fx(w, UNLOCK_PI | P, 0, 0, 0, 0));
    show("  word", state(w));

    // Requeue-PI argument rules.
    let (c, m) = (word(), word());
    say("WAIT_REQUEUE_PI, same address twice", fx(c, WAIT_REQUEUE_PI | P, 0, 0, addr(c), 0));
    say("WAIT_REQUEUE_PI, mismatch", fx(c, WAIT_REQUEUE_PI | P, 1, 0, addr(m), 0));
    let t = plus_ms(now(CLOCK_MONOTONIC), 5);
    say("WAIT_REQUEUE_PI, 5ms monotonic deadline", fx(c, WAIT_REQUEUE_PI | P, 0, t.as_ptr() as i64, addr(m), 0));
    let t = plus_ms(now(CLOCK_REALTIME), 5);
    say("WAIT_REQUEUE_PI | REALTIME, 5ms deadline", fx(c, WAIT_REQUEUE_PI | P | RT, 0, t.as_ptr() as i64, addr(m), 0));
    say("CMP_REQUEUE_PI, nr_wake 2", fx(c, CMP_REQUEUE_PI | P, 2, 1, addr(m), 0));
    say("CMP_REQUEUE_PI, nr_wake 0", fx(c, CMP_REQUEUE_PI | P, 0, 1, addr(m), 0));
    say("CMP_REQUEUE_PI, nobody, match", fx(c, CMP_REQUEUE_PI | P, 1, 1, addr(m), 0));
    say("CMP_REQUEUE_PI, mismatch", fx(c, CMP_REQUEUE_PI | P, 1, 1, addr(m), 7));
    say("CMP_REQUEUE_PI, same address", fx(c, CMP_REQUEUE_PI | P, 1, 1, addr(c), 0));
    say("CMP_REQUEUE_PI, nr_requeue -1", fx(c, CMP_REQUEUE_PI | P, 1, -1, addr(m), 0));

    // The condvar pattern glibc uses for PI mutexes.
    let (c, m) = (word(), word());
    let (ca, ma) = (addr(c), addr(m));
    let waiter = std::thread::spawn(move || unsafe {
        let r = sys(NR_FUTEX, ca, WAIT_REQUEUE_PI | P, 0, 0, ma, 0);
        let mine = (*(ma as *const AtomicU32)).load(Ordering::SeqCst) & 0x3fff_ffff == gettid() as u32;
        let u = sys(NR_FUTEX, ma, UNLOCK_PI | P, 0, 0, 0, 0);
        (r, mine, u)
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    let mut moved = 0;
    for _ in 0..100 {
        moved = fx(c, CMP_REQUEUE_PI | P, 1, 0, ma, 0);
        if moved != 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    say("CMP_REQUEUE_PI wakes the WAIT_REQUEUE_PI waiter", moved);
    let (r, mine, u) = waiter.join().unwrap();
    say("  the waiter answers", r);
    show("  and owns the mutex", mine.to_string());
    say("  and unlocks it", u);
    show("  mutex word", state(m));

    // Requeued rather than woken, because the mutex is held.
    let (c, m) = (word(), word());
    let (ca, ma) = (addr(c), addr(m));
    say("main LOCK_PI on the mutex", fx(m, LOCK_PI | P, 0, 0, 0, 0));
    let waiter = std::thread::spawn(move || unsafe {
        let r = sys(NR_FUTEX, ca, WAIT_REQUEUE_PI | P, 0, 0, ma, 0);
        let mine = (*(ma as *const AtomicU32)).load(Ordering::SeqCst) & 0x3fff_ffff == gettid() as u32;
        let u = sys(NR_FUTEX, ma, UNLOCK_PI | P, 0, 0, 0, 0);
        (r, mine, u)
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    let mut moved = 0;
    for _ in 0..100 {
        moved = fx(c, CMP_REQUEUE_PI | P, 1, 1, ma, 0);
        if moved != 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    say("CMP_REQUEUE_PI onto a held mutex", moved);
    show("  mutex word", state(m));
    say("  main UNLOCK_PI", fx(m, UNLOCK_PI | P, 0, 0, 0, 0));
    let (r, mine, u) = waiter.join().unwrap();
    say("  the waiter answers", r);
    show("  and owns the mutex", mine.to_string());
    say("  and unlocks it", u);
    show("  mutex word", state(m));
}

fn hash_cases(when: &str) {
    println!("## PR_FUTEX_HASH, {when}");
    const PR_FUTEX_HASH: i64 = 78;
    let pr = |a: i64, b: i64, c: i64, d: i64| unsafe { sys(NR_PRCTL, PR_FUTEX_HASH, a, b, c, d, 0) };
    say("GET_SLOTS, before any change", pr(2, 0, 0, 0));
    let t = std::thread::spawn(|| ());
    t.join().unwrap();
    say("GET_SLOTS, after a thread", pr(2, 0, 0, 0));
    say("op 0", pr(0, 0, 0, 0));
    say("op 3", pr(3, 0, 0, 0));
    say("GET_SLOTS with arg 1", pr(2, 1, 0, 0));
    say("GET_SLOTS with arg4 1", pr(2, 0, 1, 0));
    say("GET_SLOTS with arg5 1", pr(2, 0, 0, 1));
    say("SET_SLOTS 32, arg5 1", pr(1, 32, 0, 1));
    say("GET_SLOTS", pr(2, 0, 0, 0));
    say("SET_SLOTS 3", pr(1, 3, 0, 0));
    say("SET_SLOTS 16", pr(1, 16, 0, 0));
    say("GET_SLOTS", pr(2, 0, 0, 0));
    say("SET_SLOTS 16, flags 1", pr(1, 16, 1, 0));
    say("SET_SLOTS 16, flags 2", pr(1, 16, 2, 0));
    say("SET_SLOTS 2", pr(1, 2, 0, 0));
    say("GET_SLOTS", pr(2, 0, 0, 0));
    say("SET_SLOTS 1", pr(1, 1, 0, 0));
    say("SET_SLOTS 6", pr(1, 6, 0, 0));
    say("SET_SLOTS 1 << 20", pr(1, 1 << 20, 0, 0));
    say("GET_SLOTS", pr(2, 0, 0, 0));
    say("SET_SLOTS 1 << 31", pr(1, 1 << 31, 0, 0));
    say("SET_SLOTS 8", pr(1, 8, 0, 0));
    say("SET_SLOTS -1", pr(1, -1, 0, 0));
    say("GET_SLOTS", pr(2, 0, 0, 0));
    say("SET_SLOTS 1 << 40", pr(1, 1 << 40, 0, 0));
    say("GET_SLOTS", pr(2, 0, 0, 0));
    say("SET_SLOTS 0", pr(1, 0, 0, 0));
    say("GET_SLOTS", pr(2, 0, 0, 0));
    say("SET_SLOTS 16, unused arg 5", pr(1, 16, 0, 1));
    say("GET_SLOTS", pr(2, 0, 0, 0));
    let t = std::thread::spawn(|| ());
    t.join().unwrap();
    say("GET_SLOTS after a thread", pr(2, 0, 0, 0));
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        say("GET_SLOTS in a forked child", pr(2, 0, 0, 0));
        let t = std::thread::spawn(|| ());
        t.join().unwrap();
        say("  and after its first thread", pr(2, 0, 0, 0));
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
}
