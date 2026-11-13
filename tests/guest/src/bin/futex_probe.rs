//! What `futex(2)` does with its arguments.
//!
//! # Why this exists
//!
//! Every mutex, condition variable, semaphore and thread join in every guest is
//! a futex underneath. It was the most depended-on syscall in the tree with no
//! probe, and the crate's own history says why that matters: `futex_wait` did
//! not wait at all until 2026-08-31 — it opened a pipe per thread and polled it
//! with a 100 ms timeout, so every blocked thread woke ten times a second for
//! ever, and nothing failed.
//!
//! Its arguments are the hard part. `futex` is several syscalls behind one
//! number: `uaddr2`, `val2` and `val3` mean different things per operation, two
//! flag bits are stripped before the operation is looked at and one of them has
//! to be read *first*, and an operation a modern kernel has withdrawn answers
//! `ENOSYS` rather than `EINVAL`. Getting any of it wrong is silent, because a
//! libc turns an unexpected errno into a hang or a spin rather than a message.
//!
//! # Nothing here parks for long
//!
//! A probe that blocks for ever is a hung suite. Every case either returns at
//! once — a value that does not match is `EAGAIN`, a wake with no waiter is 0 —
//! or names a millisecond and expects `ETIMEDOUT`. The one case that really
//! parks runs in a child with an alarm, which is `deadline_probe`'s shape.
//!
//! # A fresh pair of words per case
//!
//! This is the rule `fs_probe` learned about files, and it bites harder here.
//! The PI operations write **the caller's TID** into the word, a container's
//! first process has TID 1, and a later `WAIT` for the value 1 therefore
//! matched and parked for ever — on the *Linux* side, for a reason that was
//! nothing to do with either kernel. The emulator's first process has a
//! different tid, so the two sides would have disagreed about a case the probe
//! had broken itself.

use std::io::Write;

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

const NR_FUTEX: i64 = 98;

fn errname(e: i32) -> String {
    let n = match e {
        1 => "EPERM", 2 => "ENOENT", 3 => "ESRCH", 4 => "EINTR", 9 => "EBADF",
        11 => "EAGAIN", 12 => "ENOMEM", 13 => "EACCES", 14 => "EFAULT",
        16 => "EBUSY", 22 => "EINVAL", 35 => "EDEADLK", 38 => "ENOSYS",
        62 => "ETIME", 75 => "EOVERFLOW", 110 => "ETIMEDOUT",
        _ => return format!("errno {e}"),
    };
    n.into()
}

fn r(v: i64) -> String {
    if v < 0 && v > -4096 {
        format!("-{}", errname(-v as i32))
    } else {
        v.to_string()
    }
}

fn say(what: &str, v: i64) {
    println!("  {what:<50} {}", r(v));
    let _ = std::io::stdout().flush();
}

/// Words nothing else has touched, handed out two at a time.
///
/// The arena is allocated once and never grown, so the pointers stay valid for
/// the life of the run.
struct Words {
    arena: Vec<u32>,
    next: usize,
}

impl Words {
    fn new() -> Words {
        Words { arena: vec![0u32; 512], next: 0 }
    }

    /// A `uaddr` and a `uaddr2`, both zero and untouched by any earlier case.
    fn pair(&mut self) -> (i64, i64) {
        let base = self.arena.as_mut_ptr();
        let (a, b) = (self.next, self.next + 1);
        self.next += 2;
        assert!(self.next <= self.arena.len(), "more words than the probe reserved");
        unsafe { (base.add(a) as i64, base.add(b) as i64) }
    }
}

// The operations, as `futex(2)` numbers them.
const WAIT: i64 = 0;
const WAKE: i64 = 1;
const FD: i64 = 2;
const REQUEUE: i64 = 3;
const CMP_REQUEUE: i64 = 4;
const WAKE_OP: i64 = 5;
const LOCK_PI: i64 = 6;
const UNLOCK_PI: i64 = 7;
const TRYLOCK_PI: i64 = 8;
const WAIT_BITSET: i64 = 9;
const WAKE_BITSET: i64 = 10;
const WAIT_REQUEUE_PI: i64 = 11;
const CMP_REQUEUE_PI: i64 = 12;
const LOCK_PI2: i64 = 13;

const PRIVATE: i64 = 128;
const CLOCK_REALTIME: i64 = 256;

/// A millisecond, for the cases meant to expire rather than park.
const SHORT: [i64; 2] = [0, 1_000_000];

fn main() {
    println!("## futex operations and their arguments");
    let mut words = Words::new();

    println!("## the operation numbers");
    for (op, name) in [
        (WAIT, "WAIT"),
        (WAKE, "WAKE"),
        (FD, "FD"),
        (REQUEUE, "REQUEUE"),
        (CMP_REQUEUE, "CMP_REQUEUE"),
        (WAKE_OP, "WAKE_OP"),
        (LOCK_PI, "LOCK_PI"),
        (UNLOCK_PI, "UNLOCK_PI"),
        (TRYLOCK_PI, "TRYLOCK_PI"),
        (WAIT_BITSET, "WAIT_BITSET"),
        (WAKE_BITSET, "WAKE_BITSET"),
        (WAIT_REQUEUE_PI, "WAIT_REQUEUE_PI"),
        (CMP_REQUEUE_PI, "CMP_REQUEUE_PI"),
        (LOCK_PI2, "LOCK_PI2"),
        (14, "an unallocated operation"),
        (99, "operation 99"),
    ] {
        // `val` = 1 against a word of 0, so a working WAIT answers EAGAIN
        // rather than parking, and a millisecond timeout for the ones that
        // take one. What each operation does with the arguments it does *not*
        // take is part of what this is asking.
        let (w, w2) = words.pair();
        say(
            &format!("{name} | PRIVATE"),
            unsafe { sys(NR_FUTEX, w, op | PRIVATE, 1, SHORT.as_ptr() as i64, w2, 1) },
        );
    }

    println!("## WAIT");
    let (w, _) = words.pair();
    say("value does not match", unsafe {
        sys(NR_FUTEX, w, WAIT | PRIVATE, 1, 0, 0, 0)
    });
    let (w, _) = words.pair();
    say("value matches, 1ms timeout", unsafe {
        sys(NR_FUTEX, w, WAIT | PRIVATE, 0, SHORT.as_ptr() as i64, 0, 0)
    });
    let (w, _) = words.pair();
    say("negative tv_sec", unsafe {
        let t = [-1i64, 0];
        sys(NR_FUTEX, w, WAIT | PRIVATE, 0, t.as_ptr() as i64, 0, 0)
    });
    let (w, _) = words.pair();
    say("tv_nsec = 1_000_000_000", unsafe {
        let t = [0i64, 1_000_000_000];
        sys(NR_FUTEX, w, WAIT | PRIVATE, 0, t.as_ptr() as i64, 0, 0)
    });
    let (w, _) = words.pair();
    say("unreadable timeout", unsafe {
        sys(NR_FUTEX, w, WAIT | PRIVATE, 0, 0x10, 0, 0)
    });
    let (w, _) = words.pair();
    say("unaligned uaddr", unsafe {
        sys(NR_FUTEX, w + 1, WAIT | PRIVATE, 0, SHORT.as_ptr() as i64, 0, 0)
    });
    say("null uaddr", unsafe {
        sys(NR_FUTEX, 0, WAIT | PRIVATE, 0, SHORT.as_ptr() as i64, 0, 0)
    });
    say("unmapped uaddr", unsafe {
        sys(NR_FUTEX, 0x10, WAIT | PRIVATE, 0, SHORT.as_ptr() as i64, 0, 0)
    });
    // `CLOCK_REALTIME` is allowed on the waits and on nothing else, and the bit
    // has to be read *before* `FUTEX_CMD_MASK` strips it -- which is a rule
    // `crates/kernel/futexcalls` calls out as easy to get backwards.
    let (w, _) = words.pair();
    say("WAIT | CLOCK_REALTIME, value mismatch", unsafe {
        sys(NR_FUTEX, w, WAIT | PRIVATE | CLOCK_REALTIME, 1, 0, 0, 0)
    });
    let (w, _) = words.pair();
    say("WAKE | CLOCK_REALTIME", unsafe {
        sys(NR_FUTEX, w, WAKE | PRIVATE | CLOCK_REALTIME, 1, 0, 0, 0)
    });
    // Which operations the flag *is* allowed on is the other half of the rule,
    // and asking only the refusals would leave it a guess.
    let (w, _) = words.pair();
    say("WAIT_BITSET | CLOCK_REALTIME, mismatch", unsafe {
        sys(NR_FUTEX, w, WAIT_BITSET | PRIVATE | CLOCK_REALTIME, 1, 0, 0, -1)
    });
    let (w, w2) = words.pair();
    say("WAIT_REQUEUE_PI | CLOCK_REALTIME", unsafe {
        sys(NR_FUTEX, w, WAIT_REQUEUE_PI | PRIVATE | CLOCK_REALTIME, 1, 0, w2, 0)
    });
    let (w, _) = words.pair();
    say("LOCK_PI | CLOCK_REALTIME", unsafe {
        sys(NR_FUTEX, w, LOCK_PI | PRIVATE | CLOCK_REALTIME, 0, 0, 0, 0)
    });
    let (w, _) = words.pair();
    say("CMP_REQUEUE | CLOCK_REALTIME", unsafe {
        sys(NR_FUTEX, w, CMP_REQUEUE | PRIVATE | CLOCK_REALTIME, 0, 1, w, 0)
    });

    println!("## WAKE");
    let (w, _) = words.pair();
    say("wake 1, nobody waiting", unsafe {
        sys(NR_FUTEX, w, WAKE | PRIVATE, 1, 0, 0, 0)
    });
    say("wake 0", unsafe { sys(NR_FUTEX, w, WAKE | PRIVATE, 0, 0, 0, 0) });
    say("wake -1", unsafe { sys(NR_FUTEX, w, WAKE | PRIVATE, -1, 0, 0, 0) });
    say("unaligned uaddr", unsafe {
        sys(NR_FUTEX, w + 2, WAKE | PRIVATE, 1, 0, 0, 0)
    });
    say("unmapped uaddr", unsafe {
        sys(NR_FUTEX, 0x10, WAKE | PRIVATE, 1, 0, 0, 0)
    });

    println!("## WAIT_BITSET and WAKE_BITSET");
    // A bitset of zero matches nothing, so a wait on one could never end and a
    // wake with one could never reach anybody. Linux refuses both.
    let (w, _) = words.pair();
    say("WAIT_BITSET, bitset 0", unsafe {
        sys(NR_FUTEX, w, WAIT_BITSET | PRIVATE, 1, 0, 0, 0)
    });
    say("WAKE_BITSET, bitset 0", unsafe {
        sys(NR_FUTEX, w, WAKE_BITSET | PRIVATE, 1, 0, 0, 0)
    });
    let (w, _) = words.pair();
    say("WAIT_BITSET, all bits, value mismatch", unsafe {
        sys(NR_FUTEX, w, WAIT_BITSET | PRIVATE, 1, 0, 0, -1)
    });
    say("WAKE_BITSET, all bits", unsafe {
        sys(NR_FUTEX, w, WAKE_BITSET | PRIVATE, 1, 0, 0, -1)
    });
    // **Its timeout is absolute where WAIT's is relative.** A deadline in 1970
    // has already passed, so this must expire at once; read as relative it is a
    // wait of a second.
    let (w, _) = words.pair();
    say("WAIT_BITSET, unaligned uaddr", unsafe {
        sys(NR_FUTEX, w + 1, WAIT_BITSET | PRIVATE, 0, SHORT.as_ptr() as i64, 0, -1)
    });
    let (w, _) = words.pair();
    say("WAKE_BITSET, unaligned uaddr", unsafe {
        sys(NR_FUTEX, w + 3, WAKE_BITSET | PRIVATE, 1, 0, 0, -1)
    });
    let (w, _) = words.pair();
    say("WAIT_BITSET, deadline in 1970", unsafe {
        let t = [1i64, 0];
        sys(NR_FUTEX, w, WAIT_BITSET | PRIVATE, 0, t.as_ptr() as i64, 0, -1)
    });

    println!("## REQUEUE and CMP_REQUEUE");
    let (w, w2) = words.pair();
    say("REQUEUE, nobody waiting", unsafe {
        sys(NR_FUTEX, w, REQUEUE | PRIVATE, 0, 1, w2, 0)
    });
    let (w, w2) = words.pair();
    say("CMP_REQUEUE, value matches", unsafe {
        sys(NR_FUTEX, w, CMP_REQUEUE | PRIVATE, 0, 1, w2, 0)
    });
    let (w, w2) = words.pair();
    say("CMP_REQUEUE, value does not match", unsafe {
        sys(NR_FUTEX, w, CMP_REQUEUE | PRIVATE, 0, 1, w2, 1)
    });
    let (w, _) = words.pair();
    say("CMP_REQUEUE onto the same address", unsafe {
        sys(NR_FUTEX, w, CMP_REQUEUE | PRIVATE, 0, 1, w, 0)
    });
    let (w, w2) = words.pair();
    say("CMP_REQUEUE, unaligned uaddr2", unsafe {
        sys(NR_FUTEX, w, CMP_REQUEUE | PRIVATE, 0, 1, w2 + 1, 0)
    });
    let (w, _) = words.pair();
    say("CMP_REQUEUE, unmapped uaddr2", unsafe {
        sys(NR_FUTEX, w, CMP_REQUEUE | PRIVATE, 0, 1, 0x10, 0)
    });

    // The fourth argument is a *timeout pointer* for the WAIT operations and a
    // *count* for these three, and the count's width is what these ask. Linux
    // declares `do_futex(..., u32 val2, u32 val3)` and the syscall hands it
    // `(unsigned long)utime`, so the top half is dropped before the count is
    // looked at. `futex_requeue` then refuses a negative one:
    //
    //     if (nr_wake < 0 || nr_requeue < 0)
    //         return -EINVAL;
    //
    // -- so 0x8000_0000 is EINVAL there and a kernel that kept all 64 bits
    // would see a large positive number and requeue instead. The pair is the
    // measurement: 0x8000_0000 and 0x1_8000_0000 must answer alike.
    let (w, w2) = words.pair();
    say("CMP_REQUEUE, count=0x8000_0000", unsafe {
        sys(NR_FUTEX, w, CMP_REQUEUE | PRIVATE, 0, 0x8000_0000, w2, 0)
    });
    let (w, w2) = words.pair();
    say("CMP_REQUEUE, count=0x1_8000_0000", unsafe {
        sys(NR_FUTEX, w, CMP_REQUEUE | PRIVATE, 0, 0x1_8000_0000, w2, 0)
    });
    let (w, w2) = words.pair();
    say("CMP_REQUEUE, count=0x1_0000_0001", unsafe {
        sys(NR_FUTEX, w, CMP_REQUEUE | PRIVATE, 0, 0x1_0000_0001, w2, 0)
    });
    // `futex_requeue` judges *both* of its counts, so `val` is asked the same
    // question -- and `futex_wake`, which has no such check, is the control
    // that says the refusal belongs to requeue rather than to every operation.
    let (w, w2) = words.pair();
    say("CMP_REQUEUE, val=0x8000_0000", unsafe {
        sys(NR_FUTEX, w, CMP_REQUEUE | PRIVATE, 0x8000_0000, 1, w2, 0)
    });
    let (w, _) = words.pair();
    say("WAKE, val=0x8000_0000", unsafe {
        sys(NR_FUTEX, w, WAKE | PRIVATE, 0x8000_0000, 0, 0, 0)
    });
    // Which of the two refusals comes first. `futex_requeue` reads as though
    // the counts are judged above the `cmpval` comparison, and every case
    // above answers EINVAL whichever order it is -- this one does not.
    let (w, w2) = words.pair();
    say("CMP_REQUEUE, count=0x8000_0000 and a value mismatch", unsafe {
        sys(NR_FUTEX, w, CMP_REQUEUE | PRIVATE, 0, 0x8000_0000, w2, 1)
    });
    // The same question of WAKE_OP's `nr_wake2`, which is the same argument.
    let (w, w2) = words.pair();
    say("WAKE_OP, count=0x8000_0000", unsafe {
        sys(NR_FUTEX, w, WAKE_OP | PRIVATE, 1, 0x8000_0000, w2, 0)
    });
    let (w, w2) = words.pair();
    say("WAKE_OP, count=0x1_8000_0000", unsafe {
        sys(NR_FUTEX, w, WAKE_OP | PRIVATE, 1, 0x1_8000_0000, w2, 0)
    });

    println!("## WAKE_OP");
    // `val3` packs an operation, a comparison and two twelve-bit signed
    // arguments: `(op << 28) | (cmp << 24) | (oparg << 12) | cmparg`, where bit
    // 3 of `op` means the argument is a shift count rather than a value.
    for (val3, name) in [
        (0i64, "SET 0, EQ 0"),
        ((1 << 28) | 5, "ADD, EQ 5"),
        ((2 << 28) | (1 << 24), "OR, NE"),
        ((3 << 28) | (2 << 24), "ANDN, LT"),
        ((4 << 28) | (3 << 24), "XOR, LE"),
        ((8 << 28) | (1 << 12), "SET with the shift bit, oparg 1"),
        ((8 << 28) | (31 << 12), "shift by 31"),
        ((8 << 28) | (32 << 12), "shift by 32"),
        ((8 << 28) | (33 << 12), "shift by 33"),
        ((8 << 28) | (63 << 12), "shift by 63"),
        ((8 << 28) | (0xfff << 12), "shift by 4095, the widest oparg"),
        ((1 << 28) | (0xfff << 12), "ADD with oparg 4095"),
        ((1 << 28) | (0x800 << 12), "ADD with oparg 0x800, the sign bit"),
        (5 << 28, "operation 5, unallocated"),
        (5 << 24, "comparison 5, unallocated"),
    ] {
        let (w, w2) = words.pair();
        say(&format!("WAKE_OP {name}"), unsafe {
            sys(NR_FUTEX, w, WAKE_OP | PRIVATE, 1, 1, w2, val3)
        });
    }
    let (w, _) = words.pair();
    say("WAKE_OP, unmapped uaddr2", unsafe {
        sys(NR_FUTEX, w, WAKE_OP | PRIVATE, 1, 1, 0x10, 0)
    });

    println!("## without the private flag");
    // The key is the page rather than the address space, which is a different
    // lookup and has to answer the same way for a private mapping.
    let (w, _) = words.pair();
    say("WAKE", unsafe { sys(NR_FUTEX, w, WAKE, 1, 0, 0, 0) });
    say("WAIT, value mismatch", unsafe { sys(NR_FUTEX, w, WAIT, 1, 0, 0, 0) });

    println!("## a wait that really parks");
    // In a child with an alarm: a matching value and no timeout at all.
    // `blocked (alarmed)` is the right answer and anything else means the wait
    // did not wait, which is the defect this crate actually had.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::alarm(1);
            let mut w3: u32 = 0;
            let r = sys(NR_FUTEX, &raw mut w3 as i64, WAIT | PRIVATE, 0, 0, 0, 0);
            libc::_exit(if r < 0 { (-r).min(120) as i32 } else { 100 });
        }
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let how = if libc::WIFSIGNALED(status) {
        if libc::WTERMSIG(status) == libc::SIGALRM {
            "blocked (alarmed)".to_string()
        } else {
            format!("signal {}", libc::WTERMSIG(status))
        }
    } else {
        format!("returned {}", libc::WEXITSTATUS(status))
    };
    println!("  {:<50} {how}", "WAIT, no timeout, value matches");
}
