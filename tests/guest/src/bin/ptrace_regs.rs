//! `ptrace` register access on aarch64.
//!
//! `PTRACE_GETREGS` and friends are the **x86** requests; arm64's `arch_ptrace`
//! answers `EIO` and a debugger uses `PTRACE_GETREGSET` with a note type. This
//! kernel implemented the x86 ones against the i386 `struct user_regs_struct`
//! -- 68 bytes of `ebx`/`ecx`/`eip` where aarch64's is 272 -- through accessors
//! that memset their output to zero and reported success. `GETREGSET` did not
//! exist at all, so there was no way to read a register.

use guest_tests::{Harness, check};

const PTRACE_TRACEME: i32 = 0;
const PTRACE_PEEKUSER: i32 = 3;
const PTRACE_CONT: i32 = 7;
const PTRACE_KILL: i32 = 8;
const PTRACE_GETREGS: i32 = 12;
const PTRACE_GETSIGINFO: i32 = 0x4202;
const PTRACE_GETREGSET: i32 = 0x4204;
const PTRACE_SETREGSET: i32 = 0x4205;
const NT_PRSTATUS: i32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct UserRegs {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

#[repr(C)]
struct Iovec {
    base: *mut u8,
    len: usize,
}

fn ptrace(req: i32, pid: i32, addr: usize, data: usize) -> i64 {
    unsafe { libc::ptrace(req as _, pid, addr, data) as i64 }
}

fn main() {
    let mut h = Harness::new();
    h.group("getregset");

    // A watchdog: every wait below is bounded, but a kernel that never reports
    // the stop would otherwise hang the whole suite.
    unsafe { libc::alarm(20) };

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::ptrace(PTRACE_TRACEME as _, 0, 0, 0);
            libc::raise(libc::SIGSTOP);
            // Spin so the parent has something live to look at; the parent
            // kills us.
            loop {
                std::hint::black_box(0u64);
            }
        }
    }

    let mut st = 0;
    let w = unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, w == pid && libc::WIFSTOPPED(st),
        "the child stopped for the tracer: w={w} stopped={}", libc::WIFSTOPPED(st));
    if !(w == pid && libc::WIFSTOPPED(st)) {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        std::process::exit(h.finish());
    }

    let mut regs: UserRegs = unsafe { std::mem::zeroed() };
    let mut iov = Iovec {
        base: (&raw mut regs).cast::<u8>(),
        len: std::mem::size_of::<UserRegs>(),
    };
    let r = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS as usize, (&raw mut iov) as usize);
    check!(h, r == 0, "PTRACE_GETREGSET(NT_PRSTATUS) succeeds: r={r} errno={}",
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    check!(h, iov.len == 272, "and reports the aarch64 regset size: {}", iov.len);

    // The old accessors zeroed everything, so "not all zero" is the check that
    // separates a real read from the stub.
    let any_set = regs.pc != 0 || regs.sp != 0 || regs.regs.iter().any(|&r| r != 0);
    check!(h, any_set, "the registers are not all zero: pc={:#x} sp={:#x}", regs.pc, regs.sp);
    check!(h, regs.pc != 0, "pc is set: {:#x}", regs.pc);
    check!(h, regs.sp != 0, "sp is set: {:#x}", regs.sp);

    h.group("setregset");
    // Write a register back and read it again. x9 is caller-saved and the
    // child is spinning, so nothing else here depends on it.
    let mut modified = regs;
    modified.regs[9] = 0x0123_4567_89ab_cdef;
    let mut iov2 = Iovec {
        base: (&raw mut modified).cast::<u8>(),
        len: std::mem::size_of::<UserRegs>(),
    };
    let r = ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS as usize, (&raw mut iov2) as usize);
    check!(h, r == 0, "PTRACE_SETREGSET succeeds: r={r}");

    let mut back: UserRegs = unsafe { std::mem::zeroed() };
    let mut iov3 = Iovec {
        base: (&raw mut back).cast::<u8>(),
        len: std::mem::size_of::<UserRegs>(),
    };
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS as usize, (&raw mut iov3) as usize);
    check!(h, back.regs[9] == 0x0123_4567_89ab_cdef,
        "and the value is there on the next read: {:#x}", back.regs[9]);

    h.group("x86-requests-are-eio");
    // These are not aarch64 requests. Answering them at all meant handing a
    // tracer a structure of the wrong shape.
    for (name, req) in [("PTRACE_GETREGS", PTRACE_GETREGS), ("PTRACE_PEEKUSER", PTRACE_PEEKUSER)] {
        let r = ptrace(req, pid, 0, (&raw mut regs) as usize);
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        check!(h, r == -1 && e == libc::EIO, "{name} is EIO: r={r} errno={e}");
    }

    // An unknown note type is EINVAL, not success.
    let mut iov4 = Iovec { base: (&raw mut regs).cast::<u8>(), len: 272 };
    let r = ptrace(PTRACE_GETREGSET, pid, 0x999, (&raw mut iov4) as usize);
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::EINVAL, "an unknown regset is EINVAL: r={r} errno={e}");

    // And the lock is not left held: a second GETREGSET must still work. The
    // PEEKUSER above used to return without unlocking find_child's ptrace lock.
    let mut iov5 = Iovec {
        base: (&raw mut back).cast::<u8>(),
        len: std::mem::size_of::<UserRegs>(),
    };
    let r = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS as usize, (&raw mut iov5) as usize);
    check!(h, r == 0, "the ptrace lock was released: a later GETREGSET works: r={r}");

    h.group("a-failed-request-releases-the-lock");
    // PTRACE_GETSIGINFO with an address the child cannot be written to. Its
    // EFAULT path returned without releasing find_child's ptrace lock -- the
    // same defect as PEEKUSER's above, in the same file, surviving the fix
    // that named it. A held ptrace lock is permanent: every later ptrace on
    // the child blocks, and so does the child's own signal_delivery_stop.
    //
    // The errno is the ABI check. The check after it is the one that matters,
    // and it is why this group exists rather than a line in the last one.
    let r = ptrace(PTRACE_GETSIGINFO, pid, 0, 1);
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::EFAULT,
        "GETSIGINFO with an unwritable address is EFAULT: r={r} errno={e}");

    let mut iov6 = Iovec {
        base: (&raw mut back).cast::<u8>(),
        len: std::mem::size_of::<UserRegs>(),
    };
    let r = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS as usize, (&raw mut iov6) as usize);
    check!(h, r == 0, "and the child is still usable afterwards: r={r}");

    // The successful form, so the failing one above is not the only coverage.
    let mut info = [0u8; 128];
    let r = ptrace(PTRACE_GETSIGINFO, pid, 0, info.as_mut_ptr() as usize);
    check!(h, r == 0, "GETSIGINFO into a real buffer: r={r} errno={}",
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0));

    ptrace(PTRACE_KILL, pid, 0, 0);
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut s2 = 0;
        libc::waitpid(pid, &mut s2, 0);
        libc::alarm(0);
    }
    let _ = PTRACE_CONT;
    std::process::exit(h.finish());
}
