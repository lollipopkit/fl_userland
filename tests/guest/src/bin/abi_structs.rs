//! The structs the kernel writes into guest memory, checked by size.
//!
//! `struct flock` was still the i386 layout — packed, 24 bytes, `l_start` at
//! offset 4 instead of 8 — and nothing noticed, because a struct that is too
//! small does not fail: it writes the fields it knows about at the offsets it
//! believes in and leaves the rest of the caller's buffer as it found it. The
//! caller then reads plausible-looking rubbish.
//!
//! So the detector is generic: fill the buffer with a pattern, make the call,
//! and check that **every byte the guest's struct occupies** was written. A
//! kernel struct that is too short leaves a tail of poison; one whose fields
//! are the wrong width leaves poison in the holes. Then check the values that
//! can be checked, because a struct of the right size can still have its
//! fields in the wrong places.

use guest_tests::{Harness, check};

const POISON: u8 = 0xA5;

/// A buffer of `n` poison bytes, and where the poison still is afterwards.
struct Probe(Vec<u8>);

impl Probe {
    fn new(n: usize) -> Probe {
        Probe(vec![POISON; n])
    }
    fn ptr(&mut self) -> *mut libc::c_void {
        self.0.as_mut_ptr().cast()
    }
    /// The first offset at or after `from` that is still poison, if the whole
    /// tail from there is poison. Used to report where writing stopped.
    fn untouched_tail(&self) -> Option<usize> {
        let first_poison_of_tail = (0..self.0.len())
            .rev()
            .take_while(|&i| self.0[i] == POISON)
            .last()?;
        Some(first_poison_of_tail)
    }
    fn u16_at(&self, off: usize) -> u16 {
        u16::from_le_bytes([self.0[off], self.0[off + 1]])
    }
    fn u32_at(&self, off: usize) -> u32 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.0[off..off + 4]);
        u32::from_le_bytes(b)
    }
    fn u64_at(&self, off: usize) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.0[off..off + 8]);
        u64::from_le_bytes(b)
    }
}

/// Every byte written, or a report of where it stopped.
fn fully_written(h: &mut Harness, p: &Probe, size: usize, what: &str) {
    match p.untouched_tail() {
        None => check!(h, true, "{what}: all {size} bytes written"),
        Some(at) => check!(
            h,
            false,
            "{what}: writing stopped at offset {at} of {size} — the rest is untouched"
        ),
    }
}

/// `struct tms` on aarch64: four `clock_t`, and `clock_t` is `long`.
/// Four times eight is thirty-two.
fn t_times(h: &mut Harness) {
    h.group("times");
    const SIZE: usize = 32;
    let mut p = Probe::new(SIZE);
    let r = unsafe { libc::syscall(libc::SYS_times, p.ptr()) };
    check!(h, r >= 0, "times() returned {r}");
    fully_written(h, &p, SIZE, "struct tms");

    // The four fields are tick counts, so each is small. If they were written
    // as 32-bit values, the guest reads two of them as one and gets something
    // enormous.
    for (i, name) in ["tms_utime", "tms_stime", "tms_cutime", "tms_cstime"]
        .iter()
        .enumerate()
    {
        let v = p.u64_at(i * 8);
        check!(
            h,
            v < (1 << 32),
            "{name} is a plausible tick count, got {v:#x}"
        );
    }
}

/// `struct rusage` on aarch64: two `struct timeval` (16 bytes each) then
/// fourteen `__kernel_long_t`. Thirty-two plus a hundred and twelve.
fn t_getrusage(h: &mut Harness) {
    h.group("getrusage");
    const SIZE: usize = 144;
    let mut p = Probe::new(SIZE);
    let r = unsafe { libc::syscall(libc::SYS_getrusage, libc::RUSAGE_SELF, p.ptr()) };
    check!(h, r == 0, "getrusage() returned {r}");
    fully_written(h, &p, SIZE, "struct rusage");

    // ru_utime.tv_sec at 0, tv_usec at 8; ru_stime at 16 and 24. A process
    // that has just started has used less than an hour of either.
    check!(h, p.u64_at(0) < 3600, "ru_utime.tv_sec is plausible, got {}", p.u64_at(0));
    check!(h, p.u64_at(8) < 1_000_000, "ru_utime.tv_usec is in range, got {}", p.u64_at(8));
    check!(h, p.u64_at(16) < 3600, "ru_stime.tv_sec is plausible, got {}", p.u64_at(16));
    check!(h, p.u64_at(24) < 1_000_000, "ru_stime.tv_usec is in range, got {}", p.u64_at(24));
    // ru_maxrss at 32, in kilobytes.
    check!(
        h,
        p.u64_at(32) < (1u64 << 40),
        "ru_maxrss is a plausible size, got {:#x}",
        p.u64_at(32)
    );
}

/// wait4 fills the same struct.
fn t_wait4_rusage(h: &mut Harness) {
    h.group("wait4-rusage");
    const SIZE: usize = 144;
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::_exit(0) };
    }
    if pid < 0 {
        check!(h, false, "fork");
        return;
    }
    let mut p = Probe::new(SIZE);
    let mut status = 0;
    let got = unsafe {
        libc::syscall(libc::SYS_wait4, pid, &mut status, 0, p.ptr())
    };
    check!(h, got as i32 == pid, "wait4 reaped the child: {got}");
    fully_written(h, &p, SIZE, "wait4's struct rusage");
}

/// The ones that should already be right, so a failure here says the detector
/// found something rather than that it is miscalibrated.
fn t_known_good(h: &mut Harness) {
    h.group("known-good");

    // struct timespec: two 64-bit words.
    let mut p = Probe::new(16);
    let r = unsafe { libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_MONOTONIC, p.ptr()) };
    check!(h, r == 0, "clock_gettime returned {r}");
    fully_written(h, &p, 16, "struct timespec");

    // struct rlimit: two 64-bit words.
    let mut p = Probe::new(16);
    let r = unsafe {
        libc::syscall(libc::SYS_prlimit64, 0, libc::RLIMIT_NOFILE, std::ptr::null::<u8>(), p.ptr())
    };
    check!(h, r == 0, "prlimit64 returned {r}");
    fully_written(h, &p, 16, "struct rlimit");

    // struct sysinfo: 112 bytes on aarch64.
    let mut p = Probe::new(112);
    let r = unsafe { libc::syscall(libc::SYS_sysinfo, p.ptr()) };
    check!(h, r == 0, "sysinfo returned {r}");
    fully_written(h, &p, 112, "struct sysinfo");

    // struct stat: 128 bytes.
    let mut p = Probe::new(128);
    let r = unsafe {
        libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, c"/".as_ptr(), p.ptr(), 0)
    };
    check!(h, r == 0, "fstatat returned {r}");
    fully_written(h, &p, 128, "struct stat");

    // struct statfs: 120 bytes.
    let mut p = Probe::new(120);
    let r = unsafe { libc::syscall(libc::SYS_statfs, c"/".as_ptr(), p.ptr()) };
    check!(h, r == 0, "statfs returned {r}");
    fully_written(h, &p, 120, "struct statfs");
}

/// The rest of the structs a wired syscall fills completely.
///
/// "Completely" is the condition for the poison test to mean anything: Linux
/// writes every byte of each of these, so a byte left as 0xA5 is a byte the
/// emulator's struct does not know about. msghdr is deliberately absent —
/// recvmsg updates three of its fields and leaves the rest as the caller set
/// them, so the same check would report the caller's own doing.
fn t_more_structs(h: &mut Harness) {
    h.group("more-structs");

    // struct statx: 256 bytes, and the kernel writes all of it.
    let mut p = Probe::new(256);
    let r = unsafe {
        libc::syscall(libc::SYS_statx, libc::AT_FDCWD, c"/".as_ptr(), 0, 0xfffu32, p.ptr())
    };
    if r == 0 {
        fully_written(h, &p, 256, "struct statx");
        // Size alone cannot see a struct whose fields are in the wrong places,
        // so cross-check against fstatat: two independent paths to the same
        // answers have to agree.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, c"/".as_ptr(), &mut st, 0)
        } == 0;
        check!(h, ok, "fstatat for the cross-check");
        // Offsets from include/uapi/linux/stat.h.
        let mode = p.u16_at(28);
        let nlink = p.u32_at(16);
        let ino = p.u64_at(32);
        let size = p.u64_at(40);
        let blksize = p.u32_at(4);
        check!(
            h,
            u32::from(mode) & libc::S_IFMT == libc::S_IFDIR,
            "stx_mode says / is a directory, got {mode:#o}"
        );
        // Cross-checked against fstatat rather than asserted to be at least 2.
        //
        // "A directory has at least two links" is true of ordinary
        // filesystems and not of every mount: an overlayfs merged root reports
        // 1, which is what a container's `/` is, and Linux permits a
        // filesystem not to count its subdirectories. Asserting the number
        // made this test wrong about a real kernel; asserting that the two
        // syscalls agree is what the surrounding checks are for and holds
        // everywhere.
        check!(h, u64::from(nlink) == st.st_nlink as u64,
            "stx_nlink matches stat: {nlink} vs {}", st.st_nlink);
        check!(h, ino == st.st_ino, "stx_ino matches stat: {ino} vs {}", st.st_ino);
        check!(h, size == st.st_size as u64, "stx_size matches stat: {size} vs {}", st.st_size);
        check!(h, blksize > 0, "stx_blksize is set, got {blksize}");
        check!(
            h,
            u32::from(mode) == st.st_mode,
            "stx_mode matches stat: {mode:#o} vs {:#o}",
            st.st_mode
        );
    } else {
        check!(h, false, "statx returned {r} errno {}", guest_tests::sys::errno());
    }

    // struct sigaction as the kernel sees it: handler, flags, restorer, mask.
    let mut p = Probe::new(32);
    let mut act: [u64; 4] = [0; 4];
    act[0] = libc::SIG_DFL as u64;
    let r = unsafe {
        libc::syscall(libc::SYS_rt_sigaction, libc::SIGUSR2, act.as_ptr(), p.ptr(), 8usize)
    };
    check!(h, r == 0, "rt_sigaction returned {r}");
    fully_written(h, &p, 32, "struct sigaction");

    // stack_t: ss_sp, ss_flags with padding, ss_size.
    let mut p = Probe::new(24);
    let r = unsafe {
        libc::syscall(libc::SYS_sigaltstack, std::ptr::null::<u8>(), p.ptr())
    };
    check!(h, r == 0, "sigaltstack returned {r}");
    fully_written(h, &p, 24, "stack_t");

    // struct itimerval: two timevals.
    let mut p = Probe::new(32);
    let r = unsafe { libc::syscall(libc::SYS_getitimer, libc::ITIMER_REAL, p.ptr()) };
    check!(h, r == 0, "getitimer returned {r}");
    fully_written(h, &p, 32, "struct itimerval");

    // struct itimerspec, through timerfd_gettime.
    let tfd = unsafe { libc::syscall(libc::SYS_timerfd_create, libc::CLOCK_MONOTONIC, 0) as i32 };
    if tfd >= 0 {
        let mut p = Probe::new(32);
        let r = unsafe { libc::syscall(libc::SYS_timerfd_gettime, tfd, p.ptr()) };
        check!(h, r == 0, "timerfd_gettime returned {r}");
        fully_written(h, &p, 32, "struct itimerspec");
        unsafe { libc::close(tfd) };
    }

    // struct utsname: six NUL-terminated fields of 65 bytes.
    //
    // Not the poison test: Linux zero-fills each field past its string, but
    // the emulator is entitled to leave the tail of a field alone as long as
    // the string is terminated. What matters is that all six are there and
    // none is empty.
    let mut p = Probe::new(390);
    let r = unsafe { libc::syscall(libc::SYS_uname, p.ptr()) };
    check!(h, r == 0, "uname returned {r}");
    let fields = ["sysname", "nodename", "release", "version", "machine", "domainname"];
    for (i, name) in fields.iter().enumerate() {
        let f = &p.0[i * 65..(i + 1) * 65];
        let len = f.iter().position(|&b| b == 0).unwrap_or(65);
        check!(
            h,
            len > 0 && len < 65 && f[..len].iter().all(|&b| b != POISON),
            "utsname.{name} is a terminated string, got {len} bytes"
        );
    }

    // struct sched_param: one int.
    let mut p = Probe::new(4);
    let r = unsafe { libc::syscall(libc::SYS_sched_getparam, 0, p.ptr()) };
    check!(h, r == 0, "sched_getparam returned {r}");
    fully_written(h, &p, 4, "struct sched_param");
}

/// The structs whose layout `kernel/signal.h`, `kernel/time.h` and `fs/sock.h`
/// assert at compile time, checked here against what a guest actually receives.
///
/// The two checks are not the same check. A `static_assert` says the C struct
/// agrees with the numbers written beside it; this says the kernel filled the
/// buffer a *guest* laid out. A struct that is self-consistently wrong passes
/// the first and fails this one.
fn t_asserted_structs(h: &mut Harness) {
    h.group("asserted-structs");

    // struct sigaction as the kernel takes it: handler, flags, restorer, mask,
    // four 64-bit words. Not the libc `struct sigaction`, which is a different
    // shape -- so this goes through the raw syscall.
    //
    // This is the one that looked like the bug of the day while reading:
    // `struct sigaction_` in kernel/signal.h is packed with a 4-byte flags
    // field, which would put restorer and mask four and eight bytes early. It
    // is not what rt_sigaction reads; `struct sigaction_arm64_kernel` is.
    unsafe {
        let mut act = [0u64; 4];
        act[0] = libc::SIG_DFL as u64;
        let r = libc::syscall(libc::SYS_rt_sigaction, libc::SIGUSR2, act.as_ptr(), std::ptr::null_mut::<u8>(), 8usize);
        check!(h, r == 0, "installing a handler to read back: {r}");
        let mut p = Probe::new(32);
        let r = libc::syscall(libc::SYS_rt_sigaction, libc::SIGUSR2, std::ptr::null::<u8>(), p.ptr(), 8usize);
        check!(h, r == 0, "rt_sigaction oldact returned {r}");
        if r == 0 {
            fully_written(h, &p, 32, "kernel struct sigaction");
            check!(
                h,
                p.u64_at(0) == libc::SIG_DFL as u64,
                "the handler reads back from offset 0, got {:#x}",
                p.u64_at(0)
            );
        }
    }

    // stack_t: ss_sp, ss_flags with four bytes of padding, ss_size.
    //
    // Installed and read back rather than merely read: Rust's runtime installs
    // an alternate signal stack of its own at startup for stack-overflow
    // detection, so a fresh process does *not* report SS_DISABLE and a probe
    // expecting one is testing Rust, not this kernel. A round trip says where
    // each field lives without depending on what else ran first.
    unsafe {
        let mut stack = vec![0u8; 64 * 1024];
        let want_sp = stack.as_mut_ptr() as u64;
        let want_size = stack.len() as u64;
        let mut ss = [0u64; 3];
        ss[0] = want_sp;
        ss[1] = 0; // ss_flags, and the padding above it
        ss[2] = want_size;

        let mut p = Probe::new(24);
        let r = libc::syscall(libc::SYS_sigaltstack, ss.as_ptr(), p.ptr());
        check!(h, r == 0, "sigaltstack(new, old) returned {r}");
        if r == 0 {
            fully_written(h, &p, 24, "stack_t");
        }

        // And now read back what was just installed.
        let mut p = Probe::new(24);
        let r = libc::syscall(libc::SYS_sigaltstack, std::ptr::null::<u8>(), p.ptr());
        check!(h, r == 0, "sigaltstack oss returned {r}");
        if r == 0 {
            fully_written(h, &p, 24, "stack_t, read back");
            check!(h, p.u64_at(0) == want_sp, "ss_sp is at offset 0");
            check!(
                h,
                p.u32_at(8) == 0,
                "ss_flags is at offset 8 and is neither disabled nor on-stack, got {:#x}",
                p.u32_at(8)
            );
            check!(
                h,
                p.u64_at(16) == want_size,
                "ss_size is at offset 16, got {} wanted {want_size}",
                p.u64_at(16)
            );
        }

        // Put it back the way Rust's runtime had it, so nothing downstream
        // runs a signal handler on a stack this function is about to free.
        let mut off = [0u64; 3];
        off[1] = 0x2; // SS_DISABLE
        libc::syscall(libc::SYS_sigaltstack, off.as_ptr(), std::ptr::null_mut::<u8>());
    }

    // struct itimerval: two struct timeval, four 64-bit words.
    unsafe {
        let mut p = Probe::new(32);
        let r = libc::syscall(libc::SYS_getitimer, 0 /* ITIMER_REAL */, p.ptr());
        check!(h, r == 0, "getitimer returned {r}");
        if r == 0 {
            fully_written(h, &p, 32, "struct itimerval");
        }
    }

    // struct timeval, and the struct timezone beside it. Linux writes both.
    unsafe {
        let mut tv = Probe::new(16);
        let mut tz = Probe::new(8);
        let r = libc::syscall(libc::SYS_gettimeofday, tv.ptr(), tz.ptr());
        check!(h, r == 0, "gettimeofday returned {r}");
        if r == 0 {
            fully_written(h, &tv, 16, "struct timeval");
            fully_written(h, &tz, 8, "struct timezone");
            // tv_usec is a full 64-bit word here and is always under a million,
            // so its top half must be zero. A 32-bit tv_usec with padding the
            // kernel did not clear would show up as poison in the top half.
            check!(
                h,
                tv.u64_at(8) < 1_000_000,
                "tv_usec at offset 8 is a whole word, got {}",
                tv.u64_at(8)
            );
        }
    }

    // struct sockaddr_un, written by getsockname on a bound socket. The length
    // is an output too, and Linux reports the whole thing: family, then path.
    unsafe {
        let mut sv = [0i32; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) == 0 {
            let mut p = Probe::new(110);
            let mut len: libc::socklen_t = 110;
            let r = libc::getsockname(sv[0], p.ptr().cast(), &mut len);
            check!(h, r == 0, "getsockname returned {r}");
            if r == 0 {
                // An unbound socketpair has no name, so only the family is
                // written and the length says so -- which is the point: the
                // check is that `len` and the bytes agree, not that all 110
                // were touched.
                check!(
                    h,
                    len >= 2,
                    "the reported length covers at least the family, got {len}"
                );
                check!(
                    h,
                    p.u16_at(0) == libc::AF_UNIX as u16,
                    "sa_family is at offset 0 and is AF_UNIX, got {}",
                    p.u16_at(0)
                );
            }
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
    }
}

fn main() {
    let mut h = Harness::new();
    t_known_good(&mut h);
    t_times(&mut h);
    t_getrusage(&mut h);
    t_wait4_rusage(&mut h);
    t_more_structs(&mut h);
    t_asserted_structs(&mut h);
    std::process::exit(h.finish());
}
