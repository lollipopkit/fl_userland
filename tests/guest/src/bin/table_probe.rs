//! Every syscall number, issued with zero arguments, compared against Linux.
//!
//! # Why this exists
//!
//! The syscall table decides which implementation number `N` reaches, and
//! **nothing checks that against Linux**. It cannot: which implementation
//! belongs at which number is not a fact anywhere in this tree.
//!
//! It had one check and lost it. The table was `kernel/arch/arm64/calls.c`
//! until 2026-09-03, and moving it to `crates/kernel/syscalltable` was verified
//! by parsing both files and comparing 434 entries — a check that stopped
//! existing the moment the C was deleted. `tools/syscall-aliases.py` asks a
//! different question (is one implementation at two numbers), and the `at!`
//! macro refuses a duplicate number at compile time. Neither can tell you that
//! 62 is `lseek`.
//!
//! A real kernel can. This is `decode_probe`'s method applied to syscalls:
//! sweep the space, issue each one identically on both sides, and the
//! differences are the finding. Two of today's defects would have shown up here
//! — `execveat` dispatched to `execve` answered `EFAULT` where Linux answers
//! `ENOENT`, and syscall 48 read a fourth register the guest never set.
//!
//! Its first run found **nineteen**, and none of them was a wrong table entry.
//! They were all one shape: *which argument a syscall objects to first*. A
//! caller gets one errno, and it names the thing the kernel looked at first, so
//! `flock(-1, 0)` saying `EBADF` where Linux says `EINVAL` sends a program
//! looking at its descriptor instead of its operation. Nine were an order, six
//! were a missing check on the file's *kind* — `fchdir` to `/dev/null` reported
//! success and left the working directory pointing at a character device — and
//! four were a shortcut taken too early, `splice` with a zero length answering
//! `EBADF` for descriptors Linux never looks at.
//!
//! # All-zero arguments
//!
//! Not because zero is interesting but because it is *the same on both sides*.
//! Most syscalls answer a characteristic errno for it — `EFAULT` for a null
//! pointer, `EBADF` for a descriptor, `EINVAL` for a flag word — and that
//! answer is a fingerprint of which implementation ran. A number pointing at
//! the wrong one usually gives a different letter.
//!
//! It is deliberately *not* a test of behaviour. `read` answering `0` here says
//! nothing about `read`; what it says is that number 63 reaches something that
//! behaves like `read` on both sides.
//!
//! # Only the numbers this kernel implements
//!
//! The set comes from `crates/kernel/syscalltable` through `build.rs`, because
//! a number this kernel does not implement answers `ENOSYS` here whatever Linux
//! does — 240 lines saying "not implemented", which is a coverage fact and is
//! already knowable from the table. Sweeping all 450 buried the 40 lines that
//! mean something under 233 that do not.
//!
//! What that cannot see is a number Linux implements and the table leaves out,
//! which is the same coverage fact from the other side. What it *can* see is
//! the thing this exists for: a number in the table whose implementation
//! behaves like a different syscall.
//!
//! # A blocking syscall is an answer, not a hang
//!
//! `pselect6(0, NULL, NULL, NULL, NULL, NULL)` waits for ever, and correctly:
//! a null timeout is "no deadline" on both sides. So the child arms an alarm
//! before it issues anything, and a case that does not come back shows up as
//! `signal 14` — which is comparable, and says the thing worth saying.
//!
//! Two seconds rather than one. A case that takes longer than that under a
//! loaded differential run would otherwise be reported as blocking when it is
//! only slow, which is a difference in the *probe*.
//!
//! # Each case runs in a forked child, with its stdio on /dev/null
//!
//! Some of these succeed and have effects — `close(0)`, `setuid(0)`,
//! `personality(0)`, `chdir` — and some crash, which `rt_sigreturn` on a
//! garbage frame certainly does. A child contains all of it. The stdio
//! redirect is what makes `ftruncate(0, 0)` harmless whatever the harness
//! attached to descriptor 0.
//!
//! # What is skipped, and why each one
//!
//! Six numbers, and every one of them reaches *outside* the child:
//!
//! | | |
//! | --- | --- |
//! | 93 `exit`, 94 `exit_group` | the child leaves before it can report |
//! | 117 `ptrace` | request 0 is `PTRACE_TRACEME` — the child becomes traced by this process, and every later `waitpid` then reports its stops |
//! | 129 `kill` | `kill(0, 0)` is **the whole process group**, which includes this process |
//! | 142 `reboot` | the arguments are magic numbers and zero is not one of them, so it should be `EINVAL` — but "should" is not a reason to ask a machine to halt |
//! | 220 `clone` | flags 0 is `fork`, inside a fork, for 450 cases |
//!
//! `435 clone3` is not skipped: its first argument is a pointer, so zero is
//! `EFAULT` before anything is created.

use std::io::Write;

include!(concat!(env!("OUT_DIR"), "/syscall_table.rs"));

/// See the module comment. Sorted, because it is read as a list.
const SKIP: &[i64] = &[93, 94, 117, 129, 142, 220];

/// A raw syscall with six zero arguments.
///
/// `x8` is the number and `x0`–`x5` the arguments, which is the aarch64
/// convention the dispatcher hands six registers for.
unsafe fn sys0(n: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") 0i64 => ret,
            in("x1") 0i64,
            in("x2") 0i64,
            in("x3") 0i64,
            in("x4") 0i64,
            in("x5") 0i64,
            options(nostack)
        );
    }
    ret
}

fn errname(e: i32) -> String {
    let n = match e {
        1 => "EPERM", 2 => "ENOENT", 3 => "ESRCH", 4 => "EINTR", 5 => "EIO",
        7 => "E2BIG", 9 => "EBADF", 11 => "EAGAIN", 12 => "ENOMEM",
        13 => "EACCES", 14 => "EFAULT", 15 => "ENOTBLK", 16 => "EBUSY",
        17 => "EEXIST", 18 => "EXDEV", 19 => "ENODEV", 20 => "ENOTDIR",
        21 => "EISDIR", 22 => "EINVAL", 23 => "ENFILE", 24 => "EMFILE",
        25 => "ENOTTY", 27 => "EFBIG", 28 => "ENOSPC", 29 => "ESPIPE",
        32 => "EPIPE", 34 => "ERANGE", 36 => "ENAMETOOLONG", 38 => "ENOSYS",
        39 => "ENOTEMPTY", 40 => "ELOOP", 61 => "ENODATA", 62 => "ETIME",
        75 => "EOVERFLOW", 84 => "EILSEQ", 88 => "ENOTSOCK", 89 => "EDESTADDRREQ",
        91 => "EPROTOTYPE", 92 => "ENOPROTOOPT", 93 => "EPROTONOSUPPORT",
        95 => "EOPNOTSUPP", 97 => "EAFNOSUPPORT", 107 => "ENOTCONN",
        110 => "ETIMEDOUT", 111 => "ECONNREFUSED", 114 => "EALREADY",
        115 => "EINPROGRESS",
        _ => return format!("errno {e}"),
    };
    n.into()
}

/// What the child reports: how it ended, and with what.
///
/// A signal is as much an answer as an errno — an implementation that faults
/// where Linux refuses is exactly the kind of difference this is for.
#[derive(Clone, Copy)]
#[repr(C)]
struct Outcome {
    ran: i32,
    value: i64,
}

fn main() {
    // One shared page, reused by every child. `MAP_SHARED` because the point is
    // that the parent reads what the child wrote.
    let slot = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    }
    .cast::<Outcome>();
    assert!(!slot.is_null() && slot != libc::MAP_FAILED.cast());

    println!(
        "## {} implemented syscall numbers, zero arguments",
        IMPLEMENTED.len()
    );
    let out = std::io::stdout();
    let mut out = out.lock();
    for &n in IMPLEMENTED {
        if SKIP.contains(&n) {
            let _ = writeln!(out, "  {n:3} -> skipped");
            continue;
        }
        let _ = out.flush();
        let answer = one(n, slot);
        let _ = writeln!(out, "  {n:3} -> {answer}");
    }
}

/// Issue `n` in a child and say what happened to it.
fn one(n: i64, slot: *mut Outcome) -> String {
    unsafe {
        (*slot).ran = 0;
        (*slot).value = 0;
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Nothing this child does may reach the harness: a syscall that
        // succeeds on descriptor 0, 1 or 2 would otherwise reach whatever the
        // parent had there, and `ftruncate` is the one that would be noticed.
        unsafe {
            let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
            if null >= 0 {
                libc::dup2(null, 0);
                libc::dup2(null, 1);
                libc::dup2(null, 2);
                if null > 2 {
                    libc::close(null);
                }
            }
            // See the module comment: this is what turns "waits for ever" into
            // an answer. `alarm` is `setitimer(ITIMER_REAL)` under musl, and
            // SIGALRM's default action ends the process.
            libc::alarm(2);
            let v = sys0(n);
            (*slot).value = v;
            (*slot).ran = 1;
            libc::_exit(0);
        }
    }
    if pid < 0 {
        return "the probe could not fork".into();
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    if libc::WIFSIGNALED(status) {
        return format!("signal {}", libc::WTERMSIG(status));
    }
    if unsafe { (*slot).ran } == 0 {
        // It exited without writing: the syscall did not return to it.
        return "did not return".into();
    }
    let v = unsafe { (*slot).value };
    if v < 0 && v > -4096 {
        format!("-{}", errname(-v as i32))
    } else if v == 0 {
        "0".into()
    } else {
        // A positive answer is a descriptor, a count or an address, and none of
        // those is comparable between two kernels — what is comparable is that
        // it *succeeded*.
        "ok".into()
    }
}
