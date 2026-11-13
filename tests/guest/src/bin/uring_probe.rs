//! What `io_uring_setup`, `io_uring_enter` and `io_uring_register` answer, and
//! what `rseq` and `rseq_slice_yield` answer.
//!
//! This kernel implements neither io_uring nor rseq (see the table lines at
//! 293, 425-427 and 471 in `crates/kernel/syscalltable/src/table.rs`), so the
//! comparison this probe exists for is with a kernel that has them
//! *unavailable*: `CONFIG_IO_URING=n` answers `ENOSYS` to all three, and
//! `kernel.io_uring_disabled=2` answers `EPERM` to `io_uring_setup` and goes on
//! checking the descriptor of the other two (`EBADF`, and `EINVAL` for a
//! blind register). Docker's default seccomp profile answers `EPERM` to all
//! three, which is what the recorded baseline holds; `probe_diff.sh` tags the
//! io_uring and rseq lines as the deliberate difference they are.
//!
//! A registration with a real area is not asked: the answer depends on the
//! stack's alignment (32 bytes is required), which differs from run to run.

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

fn r(v: i64) -> String {
    let n = match -v {
        1 => "EPERM", 9 => "EBADF", 14 => "EFAULT", 22 => "EINVAL", 38 => "ENOSYS",
        _ if v >= 0 => return "fd or count".into(),
        e => return format!("errno {e}"),
    };
    format!("-{n}")
}

fn say(what: &str, v: i64) {
    println!("  {what:<44} {}", r(v));
    let _ = std::io::stdout().flush();
}

fn main() {
    println!("## io_uring and rseq");
    // struct io_uring_params is 120 bytes, zeroed: a valid request.
    let params = [0u8; 120];
    say("io_uring_setup(8, zeroed params)", unsafe { sys(425, 8, params.as_ptr() as i64, 0, 0, 0, 0) });
    say("io_uring_setup(0, zeroed params)", unsafe { sys(425, 0, params.as_ptr() as i64, 0, 0, 0, 0) });
    say("io_uring_setup(8, NULL)", unsafe { sys(425, 8, 0, 0, 0, 0, 0) });
    say("io_uring_enter(-1, 0, 0, 0, NULL, 0)", unsafe { sys(426, -1, 0, 0, 0, 0, 0) });
    say("io_uring_register(-1, 0, NULL, 0)", unsafe { sys(427, -1, 0, 0, 0, 0, 0) });
    // rseq(NULL, 32, 0, sig): EFAULT on a kernel with rseq, which reads the area.
    say("rseq(NULL, 32, 0, 0)", unsafe { sys(293, 0, 32, 0, 0, 0, 0) });
    say("rseq_slice_yield()", unsafe { sys(471, 0, 0, 0, 0, 0, 0) });
}
