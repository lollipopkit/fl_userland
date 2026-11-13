//! The syscall return convention, where it is easy to get wrong.
//!
//! aarch64 Linux returns in x0, and errors are the range -4095..-1. The
//! emulator's syscall table casts every implementation to one function pointer
//! type, which erases whether the C function returned 32 or 64 bits — and on
//! this ABI a 32-bit return only sets w0, so a `dword_t` syscall returning
//! -EFAULT and a `qword_t` syscall returning 0x00000000fffffff2 leave x0
//! holding the same bits. These checks pin the cases where telling them apart
//! matters.

use guest_tests::{Harness, check, check_fails, cpath, sys};
use std::sync::atomic::{AtomicU32, Ordering};

/// Offsets around the window where a 64-bit return looks like a 32-bit errno:
/// 0xfffff001 through 0xffffffff, the last 4 KB below 4 GB.
fn t_lseek_across_the_boundary(h: &mut Harness, dir: &str) {
    h.group("lseek-64bit");
    let path = format!("{dir}/seek");
    check!(h, sys::write_file(&path, b"x"), "creating a file");
    let fd = sys::open(&path, libc::O_RDWR, 0);
    if fd < 0 {
        check!(h, false, "opening it");
        return;
    }

    for off in [
        0x0000_0000_FFFF_F000u64, // just below the window
        0x0000_0000_FFFF_F001,    // first offset that looks like an errno
        0x0000_0000_FFFF_F500,
        0x0000_0000_FFFF_FFFE,
        0x0000_0000_FFFF_FFFF, // last one: looks like -1
        0x0000_0001_0000_0000, // above: the top half is no longer zero
        0x0000_0002_0000_0000,
    ] {
        let got = sys::lseek(fd, off as i64, libc::SEEK_SET);
        check!(
            h,
            got as u64 == off,
            "lseek to {off:#x} returned {got:#x} ({got})"
        );
    }

    // Seeking past the end is legal and does not make the file that big, so
    // the checks above cost nothing on disk. Writing there does.
    check!(
        h,
        sys::lseek(fd, 0, libc::SEEK_END) == 1,
        "the file is still one byte long"
    );
    sys::close(fd);
}

/// A 64-bit-returning syscall must still be able to report an error. Those
/// arrive with the whole of x0 set, so they are not ambiguous — but exempting
/// the syscall from the 32-bit repair must not exempt it from working.
fn t_errors_from_64bit_syscalls(h: &mut Harness, dir: &str) {
    h.group("errno-64bit");
    check_fails!(
        h,
        sys::lseek(-1, 0, libc::SEEK_SET),
        libc::EBADF,
        "lseek on a closed descriptor"
    );

    let path = format!("{dir}/seek");
    let fd = sys::open(&path, libc::O_RDONLY, 0);
    if fd >= 0 {
        check_fails!(
            h,
            sys::lseek(fd, 0, 999),
            libc::EINVAL,
            "lseek with a nonsense whence"
        );
        // mmap of a length it cannot possibly satisfy.
        let r = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                usize::MAX / 2,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                fd,
                0,
            )
        };
        check!(
            h,
            r == libc::MAP_FAILED,
            "an impossible mmap reports failure rather than an address"
        );
        sys::close(fd);
    }
}

/// `rt_sigqueueinfo` and `rt_tgsigqueueinfo`: a signal carrying a `siginfo_t`
/// the caller supplies, which is what `sigqueue(3)` is built on.
///
/// Slot 240 was wired to `sys_rt_sigreturn`, which restores a whole CPU state
/// from a signal frame that is not there — reaching it outside a handler
/// loaded registers and a PC out of whatever happened to be on the guest
/// stack. It became `syscall_stub` and then, once a differential run showed
/// Linux implementing it, the real thing.
///
/// The permission rule is the interesting part and is not obvious: a caller
/// may only claim a non-negative `si_code`, or `SI_TKILL`, when the target is
/// itself. Otherwise a process could forge a signal that looks like the
/// kernel's or like another process's `kill`.
const SI_QUEUE: i32 = -1;

fn queued_value(info: *mut libc::siginfo_t) -> i32 {
    // si_value.sival_int, at offset 20 in the 64-bit siginfo_t: three ints,
    // padded to 16, then the pid/uid pair, then the value.
    unsafe { info.cast::<u8>().add(20).cast::<i32>().read() }
}

static QUEUED: AtomicU32 = AtomicU32::new(u32::MAX);
static QUEUED_CODE: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_queued(_: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    QUEUED.store(queued_value(info) as u32, Ordering::SeqCst);
    QUEUED_CODE.store(unsafe { (*info).si_code } as u32, Ordering::SeqCst);
}

fn t_signal_slots(h: &mut Harness) {
    h.group("signal-slots");

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_queued as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut());
    }

    // The value arrives.
    let me = unsafe { libc::getpid() };
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    unsafe {
        info.si_code = SI_QUEUE;
        (&raw mut info).cast::<u8>().add(20).cast::<i32>().write(0x5eed);
    }
    let r = unsafe { libc::syscall(138, me, libc::SIGUSR2, &raw const info) };
    check!(h, r == 0, "rt_sigqueueinfo to self, got {r} errno {}", sys::errno());
    check!(
        h,
        QUEUED.load(Ordering::SeqCst) == 0x5eed,
        "the caller's sigval reaches the handler: got {:#x}",
        QUEUED.load(Ordering::SeqCst)
    );
    check!(
        h,
        QUEUED_CODE.load(Ordering::SeqCst) as i32 == SI_QUEUE,
        "and so does its si_code: got {}",
        QUEUED_CODE.load(Ordering::SeqCst) as i32
    );

    // The thread-directed form, at the slot that used to be a sigreturn.
    QUEUED.store(u32::MAX, Ordering::SeqCst);
    let tid = unsafe { libc::syscall(178) } as libc::pid_t; // gettid
    unsafe {
        (&raw mut info).cast::<u8>().add(20).cast::<i32>().write(0x1234);
    }
    let r = unsafe { libc::syscall(240, me, tid, libc::SIGUSR2, &raw const info) };
    check!(h, r == 0, "rt_tgsigqueueinfo to self, got {r} errno {}", sys::errno());
    check!(
        h,
        QUEUED.load(Ordering::SeqCst) == 0x1234,
        "the thread-directed form delivers too: got {:#x}",
        QUEUED.load(Ordering::SeqCst)
    );
    // Still alive, which the old wiring was not: a stray sigreturn would have
    // reloaded the PC from the stack.
    check!(h, unsafe { libc::getpid() } > 0, "the task survived it");

    // Argument rules.
    unsafe {
        info.si_code = SI_QUEUE;
        check_fails!(
            h,
            libc::syscall(240, 0, tid, libc::SIGUSR2, &raw const info),
            libc::EINVAL,
            "rt_tgsigqueueinfo with a tgid of zero"
        );
        check_fails!(
            h,
            libc::syscall(240, me, 0, libc::SIGUSR2, &raw const info),
            libc::EINVAL,
            "rt_tgsigqueueinfo with a tid of zero"
        );
        check_fails!(
            h,
            libc::syscall(138, me, 65, &raw const info),
            libc::EINVAL,
            "a signal number above the last one"
        );
        check_fails!(
            h,
            libc::syscall(138, me, libc::SIGUSR2, std::ptr::null::<libc::siginfo_t>()),
            libc::EFAULT,
            "a siginfo pointer that is not there"
        );
    }

    // Forging the kernel's own si_code at somebody else is refused. The child
    // exists only to be a target that is not us.
    unsafe {
        let child = libc::fork();
        if child == 0 {
            libc::pause();
            libc::_exit(0);
        }
        let mut forged: libc::siginfo_t = std::mem::zeroed();
        forged.si_code = 128; // SI_KERNEL
        check_fails!(
            h,
            libc::syscall(138, child, libc::SIGUSR2, &raw const forged),
            libc::EPERM,
            "forging a kernel-sourced signal at another process"
        );
        // And with a negative code that is not SI_TKILL it is allowed, which
        // is what makes the check above about the code and not about the
        // target.
        let mut honest: libc::siginfo_t = std::mem::zeroed();
        honest.si_code = SI_QUEUE;
        let r = libc::syscall(138, child, libc::SIGKILL, &raw const honest);
        check!(h, r == 0, "queuing an SI_QUEUE signal at another process, got {r} errno {}", sys::errno());
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);
    }
}

/// A PT_INTERP segment whose contents are not a C string.
///
/// `kernel/exec.c` mallocs the segment's `p_filesz` bytes, reads the segment
/// into it, and hands the result to the path walker as a C string. With no
/// bound and no terminator check, an ELF whose PT_INTERP ran to the end of the
/// segment made `strlen` read off the end of the allocation.
///
/// These checks do NOT catch that, and were kept anyway because they catch the
/// opposite regression. Removing the bounds from `exec.c` leaves all four
/// passing: the garbage the overread produces is not a path that opens, so
/// `execve` fails either way and the child exits the same. What changed was a
/// read past the allocation, which only AddressSanitizer sees —
///
///     RUSTFLAGS='-Z sanitizer=address' cargo +nightly build -p iul-cli \
///         --target aarch64-apple-darwin
///     target/aarch64-apple-darwin/debug/iul -r <rootfs> /bin/sh -c '/tmp/interp-nonul'
///     ==> heap-buffer-overflow, READ of size 27 ... in strlen
///
/// — and that is the verification. What is pinned here is that a malformed
/// PT_INTERP is refused rather than accepted, and that a well-formed one still
/// runs, so a bound that is too strict fails the last check.
fn t_elf_interp(h: &mut Harness, dir: &str) {
    h.group("elf-interp");
    let Ok(elf) = std::fs::read("/bin/busybox") else {
        println!("  SKIP  [elf-interp] no /bin/busybox to derive a test ELF from");
        return;
    };
    // Locate PT_INTERP in the program headers.
    let u16at = |o: usize| u16::from_le_bytes(elf[o..o + 2].try_into().unwrap()) as usize;
    let u32at = |o: usize| u32::from_le_bytes(elf[o..o + 4].try_into().unwrap());
    let u64at = |o: usize| u64::from_le_bytes(elf[o..o + 8].try_into().unwrap()) as usize;
    if elf.len() < 64 || &elf[..4] != b"\x7fELF" {
        check!(h, false, "/bin/busybox is not an ELF");
        return;
    }
    let (phoff, phentsize, phnum) = (u64at(0x20), u16at(0x36), u16at(0x38));
    let Some(ph) = (0..phnum)
        .map(|i| phoff + i * phentsize)
        .find(|&o| u32at(o) == 3)
    else {
        println!("  SKIP  [elf-interp] /bin/busybox has no PT_INTERP");
        return;
    };
    let (p_offset, p_filesz) = (u64at(ph + 0x08), u64at(ph + 0x20));

    let run = |name: &str, bytes: Vec<u8>| -> i32 {
        let path = format!("{dir}/{name}");
        if std::fs::write(&path, &bytes).is_err() {
            return -1;
        }
        let _ = sys::chmod(&path, 0o755);
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                let c = cpath(&path);
                libc::execl(c.as_ptr(), c.as_ptr(), std::ptr::null::<libc::c_char>());
                // execve refused it, which is the point.
                libc::_exit(99);
            }
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
            (status >> 8) & 0xff
        }
    };

    // Unterminated: the whole segment overwritten with non-NUL bytes.
    let mut bad = elf.clone();
    for b in &mut bad[p_offset..p_offset + p_filesz] {
        *b = b'A';
    }
    check!(h, run("interp-nonul", bad) == 99, "an unterminated PT_INTERP is refused");

    // Zero length: nothing to read, nothing to terminate.
    let mut zero = elf.clone();
    zero[ph + 0x20..ph + 0x28].copy_from_slice(&0u64.to_le_bytes());
    check!(h, run("interp-zero", zero) == 99, "a zero-length PT_INTERP is refused");

    // Absurd length, which used to be an unbounded malloc.
    let mut huge = elf.clone();
    huge[ph + 0x20..ph + 0x28].copy_from_slice(&(1u64 << 40).to_le_bytes());
    check!(h, run("interp-huge", huge) == 99, "an overlong PT_INTERP is refused");

    // And the unmodified one still runs, so the bounds did not reject
    // everything.
    check!(h, run("interp-ok", elf) != 99, "an unmodified binary still runs");
}

/// Syscalls whose partner was implemented while they were not.
///
/// A sweep of the aarch64 table found 88 stubs out of 277. The defensible ones
/// are the asymmetries: a program that can lock memory but not unlock it, or
/// arm an interval timer but not read it, or open a pidfd but not signal
/// through it, is looking at a gap rather than at a design.
fn t_syscall_pairs(h: &mut Harness) {
    h.group("syscall-pairs");

    // mlock had always claimed success; its partners answered ENOSYS.
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if page != libc::MAP_FAILED {
        check!(h, unsafe { libc::mlock(page, 4096) } == 0, "mlock");
        check!(h, unsafe { libc::munlock(page, 4096) } == 0, "munlock");
        unsafe { libc::munmap(page, 4096) };
    }
    check!(h, unsafe { libc::mlockall(libc::MCL_CURRENT) } == 0, "mlockall");
    check!(h, unsafe { libc::munlockall() } == 0, "munlockall");

    // setitimer armed a timer nothing could read back.
    let want = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: 100, tv_usec: 0 },
    };
    let mut got: libc::itimerval = unsafe { std::mem::zeroed() };
    check!(
        h,
        unsafe { libc::setitimer(libc::ITIMER_REAL, &want, std::ptr::null_mut()) } == 0,
        "setitimer"
    );
    check!(
        h,
        unsafe { libc::getitimer(libc::ITIMER_REAL, &mut got) } == 0,
        "getitimer"
    );
    // It counts down, so what comes back is at most what went in and more than
    // nothing — an unimplemented one would report zero.
    check!(
        h,
        got.it_value.tv_sec > 90 && got.it_value.tv_sec <= 100,
        "getitimer reports the time left: {}s {}us",
        got.it_value.tv_sec,
        got.it_value.tv_usec
    );
    // Disarm, and check that reads back too.
    let off = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: 0, tv_usec: 0 },
    };
    unsafe { libc::setitimer(libc::ITIMER_REAL, &off, std::ptr::null_mut()) };
    unsafe { libc::getitimer(libc::ITIMER_REAL, &mut got) };
    check!(
        h,
        got.it_value.tv_sec == 0 && got.it_value.tv_usec == 0,
        "a disarmed timer reports zero, not a negative remainder: {}s {}us",
        got.it_value.tv_sec,
        got.it_value.tv_usec
    );

    // pidfd_open worked; signalling through one, which is what it is for,
    // did not.
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            // Wait to be killed.
            loop {
                libc::pause();
            }
        }
        if pid > 0 {
            let pidfd = libc::syscall(434 /* pidfd_open */, pid, 0) as i32;
            check!(h, pidfd >= 0, "pidfd_open");
            if pidfd >= 0 {
                let r = libc::syscall(424 /* pidfd_send_signal */, pidfd, libc::SIGKILL, 0, 0);
                check!(h, r == 0, "pidfd_send_signal returned {r} errno {}", sys::errno());
                let mut status = 0;
                let got = libc::waitpid(pid, &mut status, 0);
                check!(
                    h,
                    got == pid && libc::WIFSIGNALED(status),
                    "the child was killed through the pidfd"
                );
                libc::close(pidfd);
            } else {
                libc::kill(pid, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(pid, &mut status, 0);
            }
        }
    }
}

/// How a syscall reads the string arguments it was given.
///
/// `user_read_string` copied a character at a time through the full page-table
/// walk -- about 24ns each, so a 210-byte path cost 4.6us more than a 20-byte
/// one through the same file. It reads a page at a time now, which is what
/// `strncpy_from_user` does. The checks here are the properties that chunking
/// has to keep: a string that spans a page boundary is joined, one that runs
/// off the end of a mapping faults, and one with no terminator in the space
/// given is `ENAMETOOLONG` rather than a full unterminated buffer.
///
/// The last of those was *success* before, which left the caller holding an
/// unterminated `char path[4096]` on the stack and reading past it. That is a
/// kernel-side overread and a guest cannot see it directly -- what it can see
/// is the errno, and both the old and the new code answer `ENAMETOOLONG` for
/// a long path, the old one by accident further down. The check below is
/// therefore an ABI check and not a regression test for that fix; the fix is
/// by construction. `prctl-name` underneath it *is* a regression test, for the
/// one caller that must not be given the new error.
fn t_string_arguments(h: &mut Harness, dir: &str) {
    h.group("path-argument");
    const PAGE: usize = 4096;

    // Two pages, so a path can straddle the boundary between them.
    let region = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            2 * PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if region == libc::MAP_FAILED {
        check!(h, false, "mapping two pages");
        return;
    }
    let base = region.cast::<u8>();

    // A real path written across the page boundary: the copy reads it in two
    // chunks and has to join them.
    let target = format!("{dir}/straddle");
    let _ = std::fs::write(&target, b"x");
    let bytes = target.as_bytes();
    let start = PAGE - bytes.len() / 2;
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(start), bytes.len());
        base.add(start + bytes.len()).write(0);
        let mut st: libc::stat = std::mem::zeroed();
        let r = libc::syscall(
            libc::SYS_newfstatat,
            libc::AT_FDCWD,
            base.add(start),
            &raw mut st,
            0,
        );
        check!(
            h,
            r == 0,
            "a path spanning a page boundary is read whole, errno {}",
            sys::errno()
        );
    }

    // A string that runs off the end of what is mapped. The second page goes,
    // and what is left is a path with no terminator before the hole -- so the
    // copy has to fault at the boundary rather than reading into it.
    unsafe {
        libc::munmap(base.add(PAGE).cast(), PAGE);
        std::ptr::write_bytes(base.add(PAGE - 64), b'a', 64);
        let mut st: libc::stat = std::mem::zeroed();
        check_fails!(
            h,
            libc::syscall(
                libc::SYS_newfstatat,
                libc::AT_FDCWD,
                base.add(PAGE - 64),
                &raw mut st,
                0
            ),
            libc::EFAULT,
            "a path running off the end of a mapping"
        );
        libc::munmap(region, PAGE);
    }

    // A path that is simply too long. An ABI check: PATH_MAX is 4096 and a
    // name past it is ENAMETOOLONG, not a truncated lookup.
    let long = format!("{dir}/{}", "b".repeat(5000));
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        check_fails!(
            h,
            libc::syscall(
                libc::SYS_newfstatat,
                libc::AT_FDCWD,
                cpath(&long).as_ptr(),
                &raw mut st,
                0
            ),
            libc::ENAMETOOLONG,
            "a path longer than PATH_MAX"
        );
    }
    let _ = std::fs::remove_file(&target);

    // The one caller that truncates instead of refusing. Linux's PR_SET_NAME
    // does strncpy_from_user(comm, arg2, sizeof(comm) - 1) over a buffer whose
    // last byte it has already zeroed, and that returns the count rather than
    // an error -- so a long name is fifteen characters and success. Passing
    // ENAMETOOLONG on from user_read_string would break it, which is what this
    // catches.
    h.group("prctl-name");
    let long_name = "abcdefghijklmnopqrstuvwxyz";
    unsafe {
        let r = libc::prctl(libc::PR_SET_NAME, cpath(long_name).as_ptr());
        check!(h, r == 0, "a 26-character name is accepted, errno {}", sys::errno());
        let mut got = [0u8; 32];
        let r = libc::prctl(libc::PR_GET_NAME, got.as_mut_ptr());
        let n = got.iter().position(|&c| c == 0).unwrap_or(got.len());
        check!(
            h,
            r == 0 && &got[..n] == &long_name.as_bytes()[..15],
            "and comes back as its first fifteen characters: {:?}",
            std::str::from_utf8(&got[..n])
        );
        // A name that fits is unchanged.
        libc::prctl(libc::PR_SET_NAME, cpath("short").as_ptr());
        let mut got = [0u8; 32];
        libc::prctl(libc::PR_GET_NAME, got.as_mut_ptr());
        let n = got.iter().position(|&c| c == 0).unwrap_or(got.len());
        check!(h, &got[..n] == b"short", "a short name is kept whole");
    }
}

fn main() -> std::process::ExitCode {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: syscall_abi <scratch-directory>");
        return std::process::ExitCode::from(2);
    };
    if sys::mkdir(&dir, 0o755) != 0 && sys::errno() != libc::EEXIST {
        eprintln!("cannot create {dir}: {}", sys::strerror(sys::errno()));
        return std::process::ExitCode::from(2);
    }
    let _ = cpath(&dir);

    let mut h = Harness::new();
    t_lseek_across_the_boundary(&mut h, &dir);
    t_errors_from_64bit_syscalls(&mut h, &dir);
    t_signal_slots(&mut h);
    t_elf_interp(&mut h, &dir);
    t_syscall_pairs(&mut h);
    t_string_arguments(&mut h, &dir);
    std::process::ExitCode::from(h.finish() as u8)
}
