//! `process_vm_readv` and `process_vm_writev`: what each argument shape
//! answers.
//!
//! A probe rather than a test, because the interesting values are the ones the
//! man page does not name: a zero-length iovec, a count of zero, a remote
//! address that is unmapped in the middle of a list, mismatched totals, a
//! length above `SSIZE_MAX`. Every line is `case -> result`, and the diff
//! against a real kernel is the finding.
//!
//! `strace` calls it to read a tracee's memory and falls back to
//! `PTRACE_PEEKDATA`, which is why it is worth having.

use std::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct Iov {
    base: *mut c_void,
    len: usize,
}

const NR_READV: libc::c_long = 270;
const NR_WRITEV: libc::c_long = 271;

fn call(nr: libc::c_long, pid: i32, l: &[Iov], r: &[Iov], flags: u64) -> (isize, i32) {
    unsafe {
        *libc::__errno_location() = 0;
        let n = libc::syscall(
            nr,
            pid,
            l.as_ptr(),
            l.len() as u64,
            r.as_ptr(),
            r.len() as u64,
            flags,
        ) as isize;
        (n, if n < 0 { *libc::__errno_location() } else { 0 })
    }
}

fn say(name: &str, (n, e): (isize, i32)) {
    if n < 0 {
        println!("{name} -> -1 {}", errname(e));
    } else {
        println!("{name} -> {n}");
    }
}

fn errname(e: i32) -> String {
    let s = match e {
        libc::EPERM => "EPERM",
        libc::ESRCH => "ESRCH",
        libc::EFAULT => "EFAULT",
        libc::EINVAL => "EINVAL",
        libc::ENOSYS => "ENOSYS",
        libc::ENOMEM => "ENOMEM",
        _ => return format!("errno {e}"),
    };
    s.to_string()
}

/// An iovec array at an address nothing maps, for the cases about *when* it is
/// read rather than about what is in it.
fn nowhere_early() -> &'static [Iov] {
    // SAFETY: never dereferenced here -- the kernel is the one asked to read
    // it, and answering EFAULT is the point.
    unsafe { std::slice::from_raw_parts(0x10 as *const Iov, 1) }
}

fn iov(buf: &mut [u8]) -> Iov {
    Iov { base: buf.as_mut_ptr().cast(), len: buf.len() }
}

fn main() {
    let me = unsafe { libc::getpid() };

    // The subject: a buffer in this process, read through the syscall into
    // another buffer in this process. Same-process is legal and is the
    // simplest thing that can work.
    let mut src = *b"the quick brown fox jumps";
    let mut dst = [0u8; 25];

    println!("== the ordinary case ==");
    let r = call(NR_READV, me, &[iov(&mut dst)], &[iov(&mut src)], 0);
    say("read 25 from self", r);
    println!("content matches -> {}", dst == *b"the quick brown fox jumps");

    println!("== counts and lengths ==");
    say("liovcnt 0, riovcnt 0", call(NR_READV, me, &[], &[], 0));
    let mut empty = [0u8; 0];
    say(
        "one iovec of length 0",
        call(NR_READV, me, &[iov(&mut empty)], &[iov(&mut empty)], 0),
    );
    // Local shorter than remote: the transfer is what fits.
    let mut small = [0u8; 4];
    say(
        "local 4, remote 25",
        call(NR_READV, me, &[iov(&mut small)], &[iov(&mut src)], 0),
    );
    // Local longer than remote: likewise.
    let mut big = [0u8; 64];
    say(
        "local 64, remote 25",
        call(NR_READV, me, &[iov(&mut big)], &[iov(&mut src)], 0),
    );
    // Two remote pieces into one local buffer.
    let mut two = [0u8; 8];
    let halves = [
        Iov { base: src.as_mut_ptr().cast(), len: 4 },
        Iov { base: unsafe { src.as_mut_ptr().add(10) }.cast(), len: 4 },
    ];
    say("2 remote iovecs into 1 local", call(NR_READV, me, &[iov(&mut two)], &halves, 0));
    println!("gathered -> {:?}", String::from_utf8_lossy(&two));

    println!("== an empty transfer, and where the pid is checked ==");
    // Linux imports the *local* vector first and returns 0 the moment it is
    // empty -- before it looks at the pid at all. So an empty transfer to a pid
    // that does not exist is 0 and not ESRCH, which is the order and not a
    // special case. `table_probe`'s sweep calls this with every argument zero
    // and found it.
    say("everything zero, pid 0", call(NR_READV, 0, &[], &[], 0));
    say("everything zero, pid -1", call(NR_READV, -1, &[], &[], 0));
    say("empty local, bad pid, real remote",
        call(NR_READV, 0x7ff_ffff, &[], &[iov(&mut src)], 0));
    // The other way round: a *local* that is not empty and a remote that is.
    // Now the pid is reached, so a bad one is ESRCH.
    say("real local, empty remote, bad pid",
        call(NR_READV, 0x7ff_ffff, &[iov(&mut dst)], &[], 0));
    say("real local, empty remote, pid 0",
        call(NR_READV, 0, &[iov(&mut dst)], &[], 0));
    // And an empty local with an unreadable *remote* array: returned before the
    // remote is imported, so not EFAULT.
    say("empty local, unmapped remote array",
        call(NR_READV, me, &[], nowhere_early(), 0));
    // Flags are checked before any of that.
    say("flags 1 with everything else empty", call(NR_READV, 0, &[], &[], 1));

    println!("== the refusals ==");
    say("flags 1", call(NR_READV, me, &[iov(&mut dst)], &[iov(&mut src)], 1));
    say("pid -1", call(NR_READV, -1, &[iov(&mut dst)], &[iov(&mut src)], 0));
    say("pid 0", call(NR_READV, 0, &[iov(&mut dst)], &[iov(&mut src)], 0));
    // A pid that cannot exist.
    say("pid 0x7ffffff", call(NR_READV, 0x7ff_ffff, &[iov(&mut dst)], &[iov(&mut src)], 0));

    let unmapped = Iov { base: 0x10 as *mut c_void, len: 8 };
    say("remote unmapped", call(NR_READV, me, &[iov(&mut dst)], &[unmapped], 0));
    say("local unmapped", call(NR_READV, me, &[unmapped], &[iov(&mut src)], 0));
    // The second remote piece is bad: Linux transfers what it could.
    let part = [Iov { base: src.as_mut_ptr().cast(), len: 8 }, unmapped];
    say("remote good then bad", call(NR_READV, me, &[iov(&mut big)], &part, 0));

    let huge = Iov { base: src.as_mut_ptr().cast(), len: usize::MAX };
    say("remote len SIZE_MAX", call(NR_READV, me, &[iov(&mut dst)], &[huge], 0));
    say("local len SIZE_MAX", call(NR_READV, me, &[huge], &[iov(&mut src)], 0));

    // UIO_MAXIOV is 1024. One past it is EINVAL on both sides.
    let many: Vec<Iov> = (0..1025).map(|_| Iov { base: src.as_mut_ptr().cast(), len: 1 }).collect();
    say("liovcnt 1025", call(NR_READV, me, &many, &[iov(&mut src)], 0));
    say("riovcnt 1025", call(NR_READV, me, &[iov(&mut dst)], &many, 0));
    let exactly: Vec<Iov> =
        (0..1024).map(|_| Iov { base: src.as_mut_ptr().cast(), len: 1 }).collect();
    say("riovcnt 1024", call(NR_READV, me, &[iov(&mut big)], &exactly, 0));

    // A null iovec array, which is the caller's own memory being unreadable.
    let nowhere: &[Iov] = nowhere_early();
    say("local iovec array unmapped", call(NR_READV, me, nowhere, &[iov(&mut src)], 0));
    say("remote iovec array unmapped", call(NR_READV, me, &[iov(&mut dst)], nowhere, 0));

    println!("== writev ==");
    let mut target = [0u8; 25];
    let r = call(NR_WRITEV, me, &[iov(&mut src)], &[iov(&mut target)], 0);
    say("write 25 to self", r);
    println!("content matches -> {}", target == *b"the quick brown fox jumps");
    say("flags 1", call(NR_WRITEV, me, &[iov(&mut src)], &[iov(&mut target)], 1));
    say("remote unmapped", call(NR_WRITEV, me, &[iov(&mut src)], &[unmapped], 0));

    println!("== another process ==");
    // A child, so the target is a real second address space. The child holds a
    // known pattern at an address the parent knows, because it is the same
    // image and the same page after a fork.
    let mut shared = *b"CHILD-SIDE-PATTERN-000000";
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Diverge from the parent's copy, so a read that answers with the
        // *parent's* page rather than the child's is visible.
        shared[19..].copy_from_slice(b"111111");
        unsafe {
            libc::sleep(3);
            libc::_exit(0)
        }
    }
    unsafe { libc::usleep(300_000) };
    let mut got = [0u8; 25];
    let remote = Iov { base: shared.as_mut_ptr().cast(), len: 25 };
    say("read 25 from a child", call(NR_READV, pid, &[iov(&mut got)], &[remote], 0));
    println!("child's copy -> {:?}", String::from_utf8_lossy(&got));

    let mut poke = *b"PARENT-WROTE-THIS--------";
    say("write 25 to a child", call(NR_WRITEV, pid, &[iov(&mut poke)], &[remote], 0));
    let mut back = [0u8; 25];
    call(NR_READV, pid, &[iov(&mut back)], &[remote], 0);
    println!("after the write -> {:?}", String::from_utf8_lossy(&back));

    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
    }

    // A pid that exists and is not ours would be EPERM; there is no reliable
    // one in a container, so it is left to the differential run's allowlist.
}
