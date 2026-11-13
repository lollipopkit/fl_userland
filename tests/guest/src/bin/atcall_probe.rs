//! The argument handling of the syscalls nothing in `tests/` names.
//!
//! # Why this exists
//!
//! Cross-referencing the syscall table against `tests/` on 2026-09-03 left 33
//! implemented syscalls that no test mentions. Most are aliases a libc reaches
//! through a sibling — `fstat64` for `fstat`, `getuid32` for `getuid` — but a
//! dozen are calls whose *whole observable behaviour* is what they do with
//! their arguments: `fadvise64` and `membarrier` change nothing a caller can
//! see, `sched_get_priority_max` answers a number, and the `*at` family's
//! flags decide whether a call is refused.
//!
//! That is exactly where this tree keeps finding defects. Two were found the
//! same day in the same place: syscall 48 read a fourth register the guest
//! never set, so `access()` could answer `EINVAL`; and `execveat` was
//! dispatched to `execve`, so it answered `EFAULT` for every argument it was
//! ever given.
//!
//! # What is checked
//!
//! Nothing is asserted. Each case prints one line, and the finding is the
//! difference against a real arm64 kernel through
//! `tests/integration/probe_diff.sh`.
//!
//! Every destructive case gets its own name under a scratch directory, because
//! a probe whose cases share a file reports one difference eight times.

use std::ffi::CString;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn r(v: i64) -> String {
    if v < 0 {
        format!("-{}", errname(-v as i32))
    } else {
        v.to_string()
    }
}

fn errname(e: i32) -> String {
    // The names, not the numbers: a probe that prints `-22` says less than one
    // that prints `EINVAL`, and the numbers agree between the two sides anyway.
    let n = match e {
        1 => "EPERM", 2 => "ENOENT", 4 => "EINTR", 9 => "EBADF", 11 => "EAGAIN",
        13 => "EACCES", 14 => "EFAULT", 16 => "EBUSY", 17 => "EEXIST",
        18 => "EXDEV", 20 => "ENOTDIR", 21 => "EISDIR", 22 => "EINVAL",
        28 => "ENOSPC", 34 => "ERANGE", 38 => "ENOSYS", 40 => "ELOOP",
        36 => "ENAMETOOLONG", 39 => "ENOTEMPTY", 95 => "EOPNOTSUPP",
        _ => return format!("errno {e}"),
    };
    n.into()
}

/// A raw syscall, so a case can pass an argument a libc would refuse to.
unsafe fn sys(n: i64, a: i64, b: i64, cc: i64, d: i64, e: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a => ret,
            in("x1") b,
            in("x2") cc,
            in("x3") d,
            in("x4") e,
            options(nostack)
        );
    }
    ret
}

const NR_FCHMODAT: i64 = 53;
const NR_FCHOWNAT: i64 = 54;
const NR_MKNODAT: i64 = 33;
const NR_MKDIRAT: i64 = 34;
const NR_LINKAT: i64 = 37;
/// `newfstatat`, which is what aarch64 calls `fstatat`.
const NR_NEWFSTATAT: i64 = 79;
const NR_SYMLINKAT: i64 = 36;
const NR_RENAMEAT: i64 = 38;
const NR_FADVISE64: i64 = 223;
const NR_MEMBARRIER: i64 = 283;
const NR_SCHED_GET_PRIORITY_MAX: i64 = 125;
const NR_SCHED_GET_PRIORITY_MIN: i64 = 126;
const NR_FDATASYNC: i64 = 83;
const NR_FSYNC: i64 = 82;
const NR_SYNC_FILE_RANGE: i64 = 84;
const NR_FTRUNCATE: i64 = 46;
const NR_LSEEK: i64 = 62;
const NR_SETHOSTNAME: i64 = 161;
const NR_SETDOMAINNAME: i64 = 162;
const NR_FCHDIR: i64 = 50;
const NR_TRUNCATE: i64 = 45;
const NR_SYNCFS: i64 = 267;

const AT_FDCWD: i64 = -100;

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/atprobe".into());
    // Cleared, not just created. The emulator's rootfs persists between runs
    // and a container's `/tmp` does not, so a case that creates a name would
    // answer `EEXIST` on one side and `0` on the other -- which is a difference
    // in the *probe*, and this suite has produced more of those than real ones.
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);

    membarrier();
    sched_priorities();
    fadvise(&dir);
    at_flags(&dir);
    descriptor_calls(&dir);
    hostname();
}

/// `membarrier`'s query mask and its one flag rule.
///
/// The mask is what a runtime branches on — Go, JSC and crossbeam all ask
/// before they use the expedited form — so claiming a command that is not
/// implemented is worse than claiming none.
fn membarrier() {
    println!("## membarrier");
    let mask = unsafe { sys(NR_MEMBARRIER, 0, 0, 0, 0, 0) };
    // Printed as a set of bits rather than one number: the two sides will
    // differ, and *which* commands differ is the answer, not how many.
    let names = [
        (1i64, "GLOBAL"),
        (2, "GLOBAL_EXPEDITED"),
        (4, "REGISTER_GLOBAL_EXPEDITED"),
        (8, "PRIVATE_EXPEDITED"),
        (16, "REGISTER_PRIVATE_EXPEDITED"),
        (32, "PRIVATE_EXPEDITED_SYNC_CORE"),
        (64, "REGISTER_PRIVATE_EXPEDITED_SYNC_CORE"),
        (128, "PRIVATE_EXPEDITED_RSEQ"),
        (256, "REGISTER_PRIVATE_EXPEDITED_RSEQ"),
        (512, "GET_REGISTRATIONS"),
    ];
    if mask < 0 {
        println!("  QUERY -> {}", r(mask));
    } else {
        for (bit, name) in names {
            println!("  QUERY {name} -> {}", i64::from(mask & bit != 0));
        }
        let extra = mask & !names.iter().map(|(b, _)| b).sum::<i64>();
        println!("  QUERY unnamed bits -> {extra:#x}");
    }
    // The registration commands, then the barrier, in the order a runtime
    // issues them.
    for (cmd, name) in [(16i64, "REGISTER_PRIVATE_EXPEDITED"), (8, "PRIVATE_EXPEDITED")] {
        println!("  {name} -> {}", r(unsafe { sys(NR_MEMBARRIER, cmd, 0, 0, 0, 0) }));
    }
    // A flag is only defined for the CPU-targeted forms, so every command here
    // must refuse one.
    println!("  PRIVATE_EXPEDITED with flags=1 -> {}", r(unsafe {
        sys(NR_MEMBARRIER, 8, 1, 0, 0, 0)
    }));
    println!("  an unallocated command -> {}", r(unsafe {
        sys(NR_MEMBARRIER, 9999, 0, 0, 0, 0)
    }));
}

/// What a thread may ask for. `pthread_attr_setschedparam` validates against
/// these, so a wrong pair makes every real-time attribute either impossible or
/// wrongly accepted.
fn sched_priorities() {
    println!("## sched priorities");
    for (policy, name) in [
        (0i64, "SCHED_OTHER"),
        (1, "SCHED_FIFO"),
        (2, "SCHED_RR"),
        (3, "SCHED_BATCH"),
        (5, "SCHED_IDLE"),
        (6, "SCHED_DEADLINE"),
        (99, "an unallocated policy"),
    ] {
        let max = unsafe { sys(NR_SCHED_GET_PRIORITY_MAX, policy, 0, 0, 0, 0) };
        let min = unsafe { sys(NR_SCHED_GET_PRIORITY_MIN, policy, 0, 0, 0, 0) };
        println!("  {name} -> max {} min {}", r(max), r(min));
    }
}

/// `fadvise64` does nothing at all, here and often on Linux too — so its
/// argument handling is the entire interface. An advice value Linux does not
/// know is `EINVAL`, and answering success tells a program probing its own
/// arguments that nothing is wrong with a number that means nothing.
fn fadvise(dir: &str) {
    println!("## fadvise64");
    let path = format!("{dir}/fadvise");
    let _ = std::fs::write(&path, b"0123456789");
    let fd = unsafe { libc::open(c(&path).as_ptr(), libc::O_RDONLY) } as i64;
    for advice in 0i64..8 {
        println!("  advice {advice} -> {}", r(unsafe {
            sys(NR_FADVISE64, fd, 0, 10, advice, 0)
        }));
    }
    println!("  advice 99 -> {}", r(unsafe { sys(NR_FADVISE64, fd, 0, 10, 99, 0) }));
    // Which of `offset` and `len` may be negative, and what the sum does. The
    // arguments are `loff_t`, so both are signed and both can overflow.
    for (off, len, what) in [
        (0i64, -1i64, "len = -1"),
        (-1, 0, "offset = -1"),
        (-1, -1, "both -1"),
        (0, i64::MAX, "len = LLONG_MAX"),
        (i64::MAX, 1, "offset = LLONG_MAX"),
        (i64::MAX, i64::MAX, "a sum that overflows"),
        (0, 0, "len = 0, which means the whole file"),
    ] {
        println!("  {what} -> {}", r(unsafe { sys(NR_FADVISE64, fd, off, len, 0, 0) }));
    }
    println!("  a closed descriptor -> {}", r(unsafe {
        sys(NR_FADVISE64, 9999, 0, 10, 0, 0)
    }));
    unsafe { libc::close(fd as i32) };
}

/// The `*at` family's flags. Each takes a different set, and a flag outside it
/// is `EINVAL` — which is the only thing several of these calls can be asked
/// about without changing the filesystem.
fn at_flags(dir: &str) {
    println!("## *at flags");
    let base = format!("{dir}/atflags");
    let _ = std::fs::create_dir_all(&base);
    let file = format!("{base}/f");
    let _ = std::fs::write(&file, b"x");
    let f = c(&file);
    let missing = c(&format!("{base}/missing"));

    // AT_SYMLINK_NOFOLLOW is 0x100 and AT_EMPTY_PATH 0x1000; anything else is
    // not a flag any of these takes.
    for (flag, name) in [(0i64, "0"), (0x100, "AT_SYMLINK_NOFOLLOW"), (0x1000, "AT_EMPTY_PATH"), (0x40, "an unallocated flag")] {
        println!("  fchmodat({name}) -> {}", r(unsafe {
            sys(NR_FCHMODAT, AT_FDCWD, f.as_ptr() as i64, 0o644, flag, 0)
        }));
        println!("  fchownat({name}) -> {}", r(unsafe {
            sys(NR_FCHOWNAT, AT_FDCWD, f.as_ptr() as i64, -1, -1, flag)
        }));
    }

    // `AT_EMPTY_PATH` with an **empty path**, which is the whole point of the
    // flag and is how systemd's `chase()` asks about every component it has
    // walked to: open `O_PATH|O_NOFOLLOW`, then
    // `fstatat(fd, "", AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)`. It was not
    // implemented for `fstatat` or `fchownat` — the flag was accepted and the
    // empty path went to the resolver, which answered `ENOENT` about a file
    // the caller had open. `systemd-machine-id-setup` reported exactly that
    // and failed the `systemd` package's postinst.
    {
        let empty = c("");
        let held = unsafe { libc::open(f.as_ptr(), libc::O_RDONLY) } as i64;
        let mut st = [0u8; 128];
        println!("  fstatat(fd, \"\", AT_EMPTY_PATH) -> {}", r(unsafe {
            sys(NR_NEWFSTATAT, held, empty.as_ptr() as i64, st.as_mut_ptr() as i64, 0x1000, 0)
        }));
        println!("  fstatat(fd, \"\", AT_EMPTY_PATH|NOFOLLOW) -> {}", r(unsafe {
            sys(NR_NEWFSTATAT, held, empty.as_ptr() as i64, st.as_mut_ptr() as i64, 0x1100, 0)
        }));
        // Without the flag an empty path is nothing, whatever the descriptor.
        println!("  fstatat(fd, \"\", 0) -> {}", r(unsafe {
            sys(NR_NEWFSTATAT, held, empty.as_ptr() as i64, st.as_mut_ptr() as i64, 0, 0)
        }));
        // AT_FDCWD is not a descriptor, so there is nothing to stat.
        println!("  fstatat(AT_FDCWD, \"\", AT_EMPTY_PATH) -> {}", r(unsafe {
            sys(NR_NEWFSTATAT, AT_FDCWD, empty.as_ptr() as i64, st.as_mut_ptr() as i64, 0x1000, 0)
        }));
        // **`statx` asks the same question and was a different function.**
        // `fstatat` above special-cases `AT_FDCWD` -- the line before this one
        // is what measured it -- and `statx` did not: it handed its resolved
        // base straight to the descriptor's `fstat`, and for `AT_FDCWD` that
        // base was `AT_PWD`, the sentinel `(struct fd *) -2`. So
        // `statx(AT_FDCWD, "", AT_EMPTY_PATH)` read a field off address -2 and
        // took the **host** down with SIGSEGV, three lines from any guest
        // program. Covered by nothing: the `fstatat` spelling was measured and
        // the `statx` one was not, which is the same shape as `FIONBIO`
        // against `F_SETFL` earlier today.
        const NR_STATX: i64 = 291;
        let mut sx = [0u8; 256];
        println!("  statx(AT_FDCWD, \"\", AT_EMPTY_PATH) -> {}", r(unsafe {
            sys(NR_STATX, AT_FDCWD, empty.as_ptr() as i64, 0x1000, 0, sx.as_mut_ptr() as i64)
        }));
        println!("  statx(fd, \"\", AT_EMPTY_PATH) -> {}", r(unsafe {
            sys(NR_STATX, held, empty.as_ptr() as i64, 0x1000, 0, sx.as_mut_ptr() as i64)
        }));
        println!("  statx(999, \"\", AT_EMPTY_PATH) -> {}", r(unsafe {
            sys(NR_STATX, 999, empty.as_ptr() as i64, 0x1000, 0, sx.as_mut_ptr() as i64)
        }));
        // A flag outside the three it takes.
        println!("  fstatat(fd, path, an unallocated flag) -> {}", r(unsafe {
            sys(NR_NEWFSTATAT, AT_FDCWD, f.as_ptr() as i64, st.as_mut_ptr() as i64, 0x40, 0)
        }));
        // AT_NO_AUTOMOUNT is accepted and does nothing.
        println!("  fstatat(fd, path, AT_NO_AUTOMOUNT) -> {}", r(unsafe {
            sys(NR_NEWFSTATAT, AT_FDCWD, f.as_ptr() as i64, st.as_mut_ptr() as i64, 0x800, 0)
        }));
        println!("  fchownat(fd, \"\", -1, -1, AT_EMPTY_PATH) -> {}", r(unsafe {
            sys(NR_FCHOWNAT, held, empty.as_ptr() as i64, -1, -1, 0x1000)
        }));
        // linkat's is a *different* operation -- linking the description
        // rather than the path -- and is refused here; the comment in
        // crates/kernel/pathcalls says why, and why the errno is this one.
        let link = c(&format!("{base}/empty-link"));
        println!("  linkat(fd, \"\", AT_EMPTY_PATH) -> {}", r(unsafe {
            sys(NR_LINKAT, held, empty.as_ptr() as i64, AT_FDCWD, link.as_ptr() as i64, 0x1000)
        }));
        unsafe { libc::close(held as i32) };
    }

    // A directory descriptor that is not a directory.
    let fd = unsafe { libc::open(f.as_ptr(), libc::O_RDONLY) } as i64;
    println!("  fchmodat with a file as the base -> {}", r(unsafe {
        sys(NR_FCHMODAT, fd, c("rel").as_ptr() as i64, 0o644, 0, 0)
    }));
    println!("  mkdirat with a file as the base -> {}", r(unsafe {
        sys(NR_MKDIRAT, fd, c("rel").as_ptr() as i64, 0o755, 0, 0)
    }));
    unsafe { libc::close(fd as i32) };

    // mknod's type bits: a regular file and a FIFO are allowed to an
    // unprivileged process and a device node is not -- except that a guest
    // here is root inside its own filesystem.
    for (mode, name) in [
        (0o100_644i64, "S_IFREG"),
        (0o010_644, "S_IFIFO"),
        (0o020_644, "S_IFCHR"),
        (0o060_644, "S_IFBLK"),
        (0o140_644, "S_IFSOCK"),
        (0o120_644, "S_IFLNK"),
    ] {
        let p = c(&format!("{base}/node-{name}"));
        println!("  mknodat({name}) -> {}", r(unsafe {
            sys(NR_MKNODAT, AT_FDCWD, p.as_ptr() as i64, mode, 0, 0)
        }));
    }

    // linkat's flags, and the two errnos its corners give.
    let l = c(&format!("{base}/link"));
    println!("  linkat(0) -> {}", r(unsafe {
        sys(NR_LINKAT, AT_FDCWD, f.as_ptr() as i64, AT_FDCWD, l.as_ptr() as i64, 0)
    }));
    println!("  linkat over an existing name -> {}", r(unsafe {
        sys(NR_LINKAT, AT_FDCWD, f.as_ptr() as i64, AT_FDCWD, l.as_ptr() as i64, 0)
    }));
    println!("  linkat(an unallocated flag) -> {}", r(unsafe {
        sys(NR_LINKAT, AT_FDCWD, f.as_ptr() as i64, AT_FDCWD, c(&format!("{base}/l2")).as_ptr() as i64, 0x40)
    }));
    println!("  linkat from a missing source -> {}", r(unsafe {
        sys(NR_LINKAT, AT_FDCWD, missing.as_ptr() as i64, AT_FDCWD, c(&format!("{base}/l3")).as_ptr() as i64, 0)
    }));

    // AT_SYMLINK_FOLLOW is the one *at flag whose absence is the special case:
    // without it a hard link is made to the symlink, with it to the target. The
    // difference is visible through the link count of the target.
    let target = c(&format!("{base}/lt"));
    let _ = std::fs::write(format!("{base}/lt"), b"x");
    let via = c(&format!("{base}/lt-sym"));
    unsafe { sys(NR_SYMLINKAT, target.as_ptr() as i64, AT_FDCWD, via.as_ptr() as i64, 0, 0) };
    for (flag, name) in [(0i64, "without AT_SYMLINK_FOLLOW"), (0x400, "with AT_SYMLINK_FOLLOW")] {
        let out = c(&format!("{base}/lt-link-{flag}"));
        let rc = unsafe {
            sys(NR_LINKAT, AT_FDCWD, via.as_ptr() as i64, AT_FDCWD, out.as_ptr() as i64, flag)
        };
        // Whether the new name is a symlink is the whole question.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let is_link = unsafe { libc::lstat(out.as_ptr(), &mut st) } == 0
            && st.st_mode & libc::S_IFMT == libc::S_IFLNK;
        println!("  linkat {name} -> {} and the new name is a symlink: {is_link}", r(rc));
    }

    // symlinkat and renameat, whose corners are about what already exists.
    let s = c(&format!("{base}/sym"));
    println!("  symlinkat -> {}", r(unsafe {
        sys(NR_SYMLINKAT, c("target").as_ptr() as i64, AT_FDCWD, s.as_ptr() as i64, 0, 0)
    }));
    println!("  symlinkat over an existing name -> {}", r(unsafe {
        sys(NR_SYMLINKAT, c("target").as_ptr() as i64, AT_FDCWD, s.as_ptr() as i64, 0, 0)
    }));
    println!("  symlinkat with an empty target -> {}", r(unsafe {
        sys(NR_SYMLINKAT, c("").as_ptr() as i64, AT_FDCWD, c(&format!("{base}/sym2")).as_ptr() as i64, 0, 0)
    }));
    let rn = c(&format!("{base}/renamed"));
    println!("  renameat -> {}", r(unsafe {
        sys(NR_RENAMEAT, AT_FDCWD, s.as_ptr() as i64, AT_FDCWD, rn.as_ptr() as i64, 0)
    }));
    println!("  renameat from a missing source -> {}", r(unsafe {
        sys(NR_RENAMEAT, AT_FDCWD, missing.as_ptr() as i64, AT_FDCWD, rn.as_ptr() as i64, 0)
    }));
}

/// The calls that take a descriptor and a number.
fn descriptor_calls(dir: &str) {
    println!("## descriptor calls");
    let path = format!("{dir}/desc");
    let _ = std::fs::write(&path, b"0123456789");
    let fd = unsafe { libc::open(c(&path).as_ptr(), libc::O_RDWR) } as i64;
    let ro = unsafe { libc::open(c(&path).as_ptr(), libc::O_RDONLY) } as i64;

    println!("  fsync -> {}", r(unsafe { sys(NR_FSYNC, fd, 0, 0, 0, 0) }));
    println!("  fdatasync -> {}", r(unsafe { sys(NR_FDATASYNC, fd, 0, 0, 0, 0) }));
    println!("  fsync on a closed descriptor -> {}", r(unsafe {
        sys(NR_FSYNC, 9999, 0, 0, 0, 0)
    }));

    // sync_file_range: dpkg's call on every file it unpacks, which was a stub
    // here. The descriptor is looked up before the flags and signs are judged
    // -- the first version of the implementation had that the other way
    // round, and the closed-descriptor line below is what said so -- and its
    // refusal for a pipe is ESPIPE where fsync's is EINVAL.
    let mut pp = [0i32; 2];
    unsafe { libc::pipe(pp.as_mut_ptr()) };
    for (what, f, off, len, flags) in [
        ("WRITE on a file", fd, 0, 0, 2),
        ("WAIT_BEFORE|WRITE|WAIT_AFTER on a file", fd, 0, 4096, 7),
        ("a flag outside the three", fd, 0, 0, 8),
        ("a flag outside the three, closed descriptor", 9999, 0, 0, 8),
        ("a closed descriptor", 9999, 0, 0, 2),
        ("a negative offset", fd, -1, 0, 2),
        ("a negative length", fd, 0, -1, 2),
        ("an offset and length that overflow", fd, i64::MAX, 1, 2),
        ("a pipe", pp[1] as i64, 0, 0, 2),
    ] {
        println!("  sync_file_range({what}) -> {}", r(unsafe {
            sys(NR_SYNC_FILE_RANGE, f, off, len, flags, 0)
        }));
    }
    unsafe {
        libc::close(pp[0]);
        libc::close(pp[1]);
    }

    println!("  ftruncate to 4 -> {}", r(unsafe { sys(NR_FTRUNCATE, fd, 4, 0, 0, 0) }));
    println!("  ftruncate to a negative length -> {}", r(unsafe {
        sys(NR_FTRUNCATE, fd, -1, 0, 0, 0)
    }));
    println!("  ftruncate a read-only descriptor -> {}", r(unsafe {
        sys(NR_FTRUNCATE, ro, 0, 0, 0, 0)
    }));

    // What each of these does with a descriptor that is not a regular file.
    // Every one used to answer **0** and do nothing: `fsync` on a socket said
    // the data was safe, `ftruncate` on `/dev/null` said it had been truncated,
    // and `fchdir` left the working directory pointing at a character device,
    // after which every relative path resolved against something that cannot be
    // walked. `chdir` cannot do that, because it resolves a path and the walk
    // refuses; `fchdir` skips the walk, which is the point of it.
    //
    // The directory pair is an asymmetry worth pinning: `ftruncate` on a
    // directory descriptor is `EINVAL` and `truncate` on the same path is
    // `EISDIR`. And `syncfs` is about the *filesystem*, so it succeeds on
    // exactly the descriptors `fsync` refuses.
    let null = unsafe { libc::open(c("/dev/null").as_ptr(), libc::O_RDWR) } as i64;
    let dirfd = unsafe {
        libc::open(c(dir).as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY)
    } as i64;
    let mut pipefd = [0i32; 2];
    unsafe { libc::pipe(pipefd.as_mut_ptr()) };
    let mut sockfd = [0i32; 2];
    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockfd.as_mut_ptr()) };

    for (name, d) in [
        ("/dev/null", null),
        ("a directory", dirfd),
        ("a pipe", pipefd[0] as i64),
        ("a unix socket", sockfd[0] as i64),
    ] {
        println!("  fsync on {name} -> {}", r(unsafe { sys(NR_FSYNC, d, 0, 0, 0, 0) }));
        println!("  syncfs on {name} -> {}", r(unsafe { sys(NR_SYNCFS, d, 0, 0, 0, 0) }));
        println!("  ftruncate on {name} -> {}", r(unsafe { sys(NR_FTRUNCATE, d, 0, 0, 0, 0) }));
        println!("  fchdir to {name} -> {}", r(unsafe { sys(NR_FCHDIR, d, 0, 0, 0, 0) }));
    }
    println!("  fchdir to a regular file -> {}", r(unsafe { sys(NR_FCHDIR, fd, 0, 0, 0, 0) }));
    println!("  truncate on a directory path -> {}", r(unsafe {
        sys(NR_TRUNCATE, c(dir).as_ptr() as i64, 0, 0, 0, 0)
    }));
    // And back, so that a `fchdir` that wrongly succeeded above cannot make
    // every later case in this program resolve somewhere else.
    println!("  fchdir back to the test directory -> {}", r(unsafe {
        sys(NR_FCHDIR, dirfd, 0, 0, 0, 0)
    }));

    unsafe {
        libc::close(null as i32);
        libc::close(dirfd as i32);
        libc::close(pipefd[0]);
        libc::close(pipefd[1]);
        libc::close(sockfd[0]);
        libc::close(sockfd[1]);
    }

    // lseek's whence values, including the two that need holes.
    for (whence, name) in [(0i64, "SEEK_SET"), (1, "SEEK_CUR"), (2, "SEEK_END"), (3, "SEEK_DATA"), (4, "SEEK_HOLE"), (9, "an unallocated whence")] {
        println!("  lseek({name}, 0) -> {}", r(unsafe { sys(NR_LSEEK, fd, 0, whence, 0, 0) }));
    }
    println!("  lseek to a negative offset -> {}", r(unsafe {
        sys(NR_LSEEK, fd, -1, 0, 0, 0)
    }));

    unsafe {
        libc::close(fd as i32);
        libc::close(ro as i32);
    }
}

/// `sethostname`'s length rule, which is the only thing about it an
/// unprivileged process can observe -- and `setdomainname`'s, which had
/// nothing at all.
///
/// The two share one helper in `crates/kernel/unamecalls` and differ by which
/// field of one struct they write, so a swap is invisible to a test that
/// exercises one of them. That is the shape `sched_get_priority_max` and
/// `_min` were in on 2026-09-06: one table, one differing index, one of the
/// pair covered.
fn hostname() {
    println!("## sethostname");
    let name = c("probe-host");
    let lens = [
        (-1i64, "a negative length"),
        (0, "zero"),
        (10, "the real length"),
        (1 << 20, "a length past any buffer"),
    ];
    for (len, what) in lens {
        println!("  sethostname, {what} -> {}", r(unsafe {
            sys(NR_SETHOSTNAME, name.as_ptr() as i64, len, 0, 0, 0)
        }));
    }

    println!("## setdomainname");
    let domain = c("probe-domain");
    for (len, what) in lens {
        println!("  setdomainname, {what} -> {}", r(unsafe {
            sys(NR_SETDOMAINNAME, domain.as_ptr() as i64, len, 0, 0, 0)
        }));
    }
}
