//! What `mmap`, `munmap` and `mprotect` answer at their edges.
//!
//! **A report, not a check.** It prints one line per case and never fails, so
//! that the same binary can be run here and in an arm64 container and the two
//! outputs diffed. Anything the two disagree about is a question worth asking;
//! anything they agree on can become an assertion somewhere that gates.
//!
//! This is the shape CLAUDE.md's "ask a real kernel" section describes, made
//! explicit: five of the first nine differences a sweep like this found were in
//! the *tests*, written from a man page that was silent on the point.

const PAGE: u64 = 4096;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn name(e: i32) -> &'static str {
    match e {
        libc::EINVAL => "EINVAL",
        libc::ENOMEM => "ENOMEM",
        libc::EACCES => "EACCES",
        libc::EBADF => "EBADF",
        libc::EPERM => "EPERM",
        libc::EOVERFLOW => "EOVERFLOW",
        libc::EEXIST => "EEXIST",
        libc::EAGAIN => "EAGAIN",
        0 => "-",
        _ => "?",
    }
}

fn report(what: &str, r: i64) {
    if r == -1 {
        println!("{what:<52} -> {} ({})", name(errno()), errno());
    } else if r == 0 {
        println!("{what:<52} -> ok");
    } else {
        // An address. Only its shape matters for a diff, not its value.
        let a = r as u64;
        println!(
            "{what:<52} -> addr aligned={} low4g={}",
            a % PAGE == 0,
            a < 0x1_0000_0000
        );
    }
}

fn mmap(addr: u64, len: u64, prot: i32, flags: i32) -> i64 {
    let p = unsafe { libc::mmap(addr as *mut libc::c_void, len as usize, prot, flags, -1, 0) };
    if p == libc::MAP_FAILED { -1 } else { p as i64 }
}

fn main() {
    let anon = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    let rw = libc::PROT_READ | libc::PROT_WRITE;

    println!("## length");
    report("mmap(NULL, 0)", mmap(0, 0, rw, anon));
    report("mmap(NULL, 1)", mmap(0, 1, rw, anon));
    report("mmap(NULL, PAGE+1)", mmap(0, PAGE + 1, rw, anon));
    // Rounds up to zero, which is the overflow case.
    report("mmap(NULL, ~0)", mmap(0, u64::MAX, rw, anon));
    report("mmap(NULL, ~0 & ~0xfff)", mmap(0, u64::MAX & !0xfff, rw, anon));
    report("mmap(NULL, 1<<47)", mmap(0, 1 << 47, rw, anon));

    println!("## a hint that is not page aligned");
    report("mmap(0x1001, PAGE)", mmap(0x1001, PAGE, rw, anon));
    report(
        "mmap(0x1001, PAGE, FIXED)",
        mmap(0x1001, PAGE, rw, anon | libc::MAP_FIXED),
    );

    println!("## prot bits");
    report("mmap(prot=0)", mmap(0, PAGE, 0, anon));
    // Bits no architecture defines. Linux's arch_validate_prot decides.
    report("mmap(prot=0x1000)", mmap(0, PAGE, 0x1000, anon));
    report("mmap(prot=-1)", mmap(0, PAGE, -1, anon));

    println!("## flags");
    // Neither SHARED nor PRIVATE.
    report(
        "mmap(anon, neither shared nor private)",
        mmap(0, PAGE, rw, libc::MAP_ANONYMOUS),
    );
    // Both.
    report(
        "mmap(anon, both)",
        mmap(0, PAGE, rw, libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_PRIVATE),
    );
    report("mmap(flags=0)", mmap(0, PAGE, rw, 0));

    println!("## munmap");
    let p = mmap(0, PAGE * 4, rw, anon);
    let base = if p > 0 { p as u64 } else { 0 };
    report("munmap(len=0)", unsafe {
        libc::munmap(base as *mut _, 0) as i64
    });
    report("munmap(unaligned addr)", unsafe {
        libc::munmap((base + 1) as *mut _, PAGE as usize) as i64
    });
    report("munmap(len rounds up past the end)", unsafe {
        libc::munmap(base as *mut _, (PAGE * 4 - 1) as usize) as i64
    });
    report("munmap(never mapped)", unsafe {
        libc::munmap(0x7000_0000_0000 as *mut _, PAGE as usize) as i64
    });
    report("munmap(len=~0)", unsafe {
        libc::munmap(base as *mut _, usize::MAX) as i64
    });

    println!("## mprotect");
    let p = mmap(0, PAGE * 2, rw, anon);
    let base = if p > 0 { p as u64 } else { 0 };
    report("mprotect(len=0)", unsafe {
        libc::mprotect(base as *mut _, 0, libc::PROT_READ) as i64
    });
    report("mprotect(unaligned addr)", unsafe {
        libc::mprotect((base + 1) as *mut _, PAGE as usize, libc::PROT_READ) as i64
    });
    report("mprotect(never mapped)", unsafe {
        libc::mprotect(0x7000_0000_0000 as *mut _, PAGE as usize, libc::PROT_READ) as i64
    });
    report("mprotect(prot=0x1000)", unsafe {
        libc::mprotect(base as *mut _, PAGE as usize, 0x1000) as i64
    });
    report("mprotect(half of a mapping)", unsafe {
        libc::mprotect(base as *mut _, PAGE as usize, libc::PROT_READ) as i64
    });

    println!("## a fixed mapping over an existing one");
    let p = mmap(0, PAGE * 4, rw, anon);
    if p > 0 {
        let base = p as u64;
        report(
            "mmap(FIXED over the middle)",
            mmap(base + PAGE, PAGE, rw, anon | libc::MAP_FIXED),
        );
        // MAP_FIXED_NOREPLACE refuses rather than replacing. 0x100000 is its
        // value; the constant is not in every libc.
        report(
            "mmap(FIXED_NOREPLACE over the middle)",
            mmap(base + PAGE, PAGE, rw, anon | 0x100000),
        );
    }

    println!("## brk");
    let cur = unsafe { libc::syscall(libc::SYS_brk, 0) };
    println!("{:<52} -> {}", "brk(0) is nonzero", cur != 0);
    // Shrinking below the start is refused; the answer is the *current* break,
    // not an error, which is brk's odd calling convention.
    let r = unsafe { libc::syscall(libc::SYS_brk, 1) };
    println!("{:<52} -> unchanged={}", "brk(1)", r == cur);
}
