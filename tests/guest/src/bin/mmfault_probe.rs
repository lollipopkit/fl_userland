//! Two places a memory call stops partway: `mprotect` over a range it cannot
//! finish, and a file mapping touched past the end of its file.
//!
//! **A report, not a check**: one line per case, diffed against an arm64
//! container by `tests/integration/probe_diff.sh`.
//!
//! - `mprotect` across a hole, a VMA whose file forbids the protection, or a
//!   sealed VMA: the answer, then the protection `/proc/self/maps` shows for
//!   each page, which says whether the pages before the refusal changed.
//! - A page of a file mapping wholly past the end of the file, at map time, after
//!   `ftruncate` shrinks the file and after it grows again, for a regular file
//!   and a memfd: what a touch raises, with `si_code` and `si_addr`.
//! - A private file mapping and the file under it: whether a page nobody has
//!   written follows a later `pwrite` when a neighbouring page has been
//!   written, what `MADV_DONTNEED` leaves in a written page, and what a fork's
//!   two sides see.
//! - Both sets again for a file on a tmpfs the probe mounts.

use std::io::Write;

const PAGE: usize = 4096;
const SYS_MSEAL: libc::c_long = 462;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<64} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EPERM => "EPERM",
        libc::EFAULT => "EFAULT",
        libc::EINVAL => "EINVAL",
        libc::ENOMEM => "ENOMEM",
        libc::EACCES => "EACCES",
        libc::ENOSYS => "ENOSYS",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn ok(v: i64) -> String {
    if v < 0 { named(errno()) } else { "ok".into() }
}

/// The permission field `/proc/self/maps` gives the page at `addr`.
fn perms(addr: *mut u8) -> String {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    let a = addr as usize;
    for l in maps.lines() {
        let mut f = l.split_whitespace();
        let (Some(range), Some(p)) = (f.next(), f.next()) else { continue };
        let mut r = range.split('-');
        let lo = usize::from_str_radix(r.next().unwrap_or("0"), 16).unwrap_or(0);
        let hi = usize::from_str_radix(r.next().unwrap_or("0"), 16).unwrap_or(0);
        if lo <= a && a < hi {
            return p.into();
        }
    }
    "unmapped".into()
}

fn row(base: *mut u8, pages: usize) -> String {
    (0..pages)
        .map(|i| perms(unsafe { base.add(i * PAGE) }))
        .collect::<Vec<_>>()
        .join(" ")
}

fn file_with(path: &std::ffi::CStr, len: usize) -> i32 {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644) };
    assert!(fd >= 0);
    let buf = vec![b'f'; len];
    assert_eq!(unsafe { libc::write(fd, buf.as_ptr().cast(), len) }, len as isize);
    fd
}

/// A read-only descriptor's `MAP_SHARED` page over `at`, which no mprotect may
/// make writable.
fn readonly_shared_over(at: *mut u8) {
    let path = c"/tmp/mmfault_probe.ro";
    let w = file_with(path, PAGE);
    unsafe { libc::close(w) };
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    let p = unsafe {
        libc::mmap(at.cast(), PAGE, libc::PROT_READ, libc::MAP_SHARED | libc::MAP_FIXED, fd, 0)
    };
    assert_eq!(p, at.cast());
    unsafe { libc::close(fd) };
}

fn hole(at: *mut u8) {
    unsafe { libc::munmap(at.cast(), PAGE) };
}

fn seal(at: *mut u8) -> String {
    ok(unsafe { libc::syscall(SYS_MSEAL, at, PAGE, 0) })
}

/// Four fresh pages far above everything else, so that no allocation the probe
/// makes on the way lands in one of its holes: both kernels place `mmap(NULL)`
/// well below 64 GB.
fn high(pages: usize, prot: i32) -> *mut u8 {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let at = 0x10_0000_0000 + NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) * 0x10_0000;
    const MAP_FIXED_NOREPLACE: i32 = 0x100000;
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE;
    let p = unsafe { libc::mmap(at as *mut _, pages * PAGE, prot, flags, -1, 0) };
    assert_eq!(p as usize, at, "{}", errno());
    p.cast()
}

/// Four pages laid out by `shape`, one letter a page: `a` anonymous `PROT_READ`,
/// `-` a hole, `f` a read-only shared file page, `s` a sealed anonymous page,
/// `g` a sealed read-only shared file page.
/// Then `mprotect(all four, prot)`.
fn mprotect_case(shape: &str, prot: i32, what: &str) {
    let base = high(4, libc::PROT_READ);
    let mut sealed = false;
    for (i, c) in shape.bytes().enumerate() {
        let at = unsafe { base.add(i * PAGE) };
        match c {
            b'-' => hole(at),
            b'f' => readonly_shared_over(at),
            b'g' => {
                readonly_shared_over(at);
                let r = seal(at);
                if r != "ok" {
                    line(&format!("  mseal for {shape}"), r);
                }
                sealed = true;
            }
            b's' => {
                // A page of its own, so the seal does not take its neighbours.
                unsafe { libc::mprotect(at.cast(), PAGE, libc::PROT_READ | libc::PROT_EXEC) };
                let r = seal(at);
                if r != "ok" {
                    line(&format!("  mseal for {shape}"), r);
                }
                sealed = true;
            }
            _ => {}
        }
    }
    let r = ok(unsafe { libc::mprotect(base.cast(), 4 * PAGE, prot) } as i64);
    line(&format!("mprotect([{shape}], {what})"), r);
    line(&format!("  [{shape}] afterwards"), row(base, 4));
    if !sealed {
        unsafe { libc::munmap(base.cast(), 4 * PAGE) };
    }
}

fn mprotect_cases() {
    println!("\n########## mprotect that stops partway ##########");
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    mprotect_case("aaaa", rw, "RW");
    mprotect_case("a-aa", rw, "RW");
    mprotect_case("-aaa", rw, "RW");
    mprotect_case("aaa-", rw, "RW");
    mprotect_case("aafa", rw, "RW");
    mprotect_case("faaa", rw, "RW");
    mprotect_case("aafa", libc::PROT_READ | libc::PROT_EXEC, "RX");
    mprotect_case("a-fa", rw, "RW");
    mprotect_case("af-a", rw, "RW");
    mprotect_case("asaa", rw, "RW");
    mprotect_case("a-sa", rw, "RW");
    mprotect_case("afsa", rw, "RW");
    mprotect_case("asfa", rw, "RW");
    mprotect_case("aaas", rw, "RW");
    mprotect_case("agaa", rw, "RW");
    mprotect_case("agaa", libc::PROT_READ | libc::PROT_EXEC, "RX");

    // What mmap itself refuses for the descriptor.
    let path = c"/tmp/mmfault_probe.ro";
    let w = file_with(path, PAGE);
    unsafe { libc::close(w) };
    for (mode, name) in [(libc::O_RDONLY, "O_RDONLY"), (libc::O_WRONLY, "O_WRONLY"), (libc::O_RDWR, "O_RDWR")] {
        let fd = unsafe { libc::open(path.as_ptr(), mode) };
        for (prot, flags, what) in [
            (libc::PROT_READ, libc::MAP_SHARED, "shared R"),
            (rw, libc::MAP_SHARED, "shared RW"),
            (rw, libc::MAP_PRIVATE, "private RW"),
        ] {
            let p = unsafe { libc::mmap(std::ptr::null_mut(), PAGE, prot, flags, fd, 0) };
            line(&format!("mmap({name} file, {what})"), if p == libc::MAP_FAILED { named(errno()) } else { "ok".into() });
            if p != libc::MAP_FAILED {
                unsafe { libc::munmap(p, PAGE) };
            }
        }
        unsafe { libc::close(fd) };
    }

    // A memfd under F_SEAL_WRITE, mapped shared read-only, in the middle.
    let base = high(3, libc::PROT_READ);
    let m = unsafe { libc::memfd_create(c"mmfault".as_ptr(), libc::MFD_ALLOW_SEALING) };
    unsafe { libc::ftruncate(m, PAGE as i64) };
    unsafe { libc::fcntl(m, libc::F_ADD_SEALS, libc::F_SEAL_WRITE) };
    let mid = unsafe { base.add(PAGE) };
    let p = unsafe { libc::mmap(mid.cast(), PAGE, libc::PROT_READ, libc::MAP_SHARED | libc::MAP_FIXED, m, 0) };
    line("mmap a write-sealed memfd shared read-only", if p == mid.cast() { "ok".into() } else { named(errno()) });
    line("mprotect([a m a], RW)", ok(unsafe { libc::mprotect(base.cast(), 3 * PAGE, rw) } as i64));
    line("  [a m a] afterwards", row(base, 3));
    unsafe { libc::munmap(base.cast(), 3 * PAGE) };
    unsafe { libc::close(m) };
}

/// Shared with the child that touches, so the handler's findings outlive it.
static mut REPORT: *mut u64 = std::ptr::null_mut();

extern "C" fn on_fault(sig: i32, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    unsafe {
        let r = REPORT;
        *r = sig as u64;
        *r.add(1) = (*info).si_code as u64;
        *r.add(2) = (*info).si_addr() as u64;
        libc::_exit(0);
    }
}

/// Touch `at` in a child: what it read, or the signal it took and whether
/// `si_addr` named `at`.
fn touch(at: *mut u8, write: bool) -> String {
    unsafe {
        if REPORT.is_null() {
            let p = libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            REPORT = p.cast();
        }
        let r = REPORT;
        std::ptr::write_bytes(r, 0, 4);
        let pid = libc::fork();
        if pid == 0 {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_fault as *const () as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
            if write {
                std::ptr::write_volatile(at, b'w');
                *r.add(3) = 0x100 | b'w' as u64;
            } else {
                *r.add(3) = 0x100 | std::ptr::read_volatile(at) as u64;
            }
            libc::_exit(0);
        }
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        if !libc::WIFEXITED(st) {
            return format!("child died, status {st:#x}");
        }
        if *r.add(3) != 0 {
            let b = (*r.add(3) & 0xff) as u8;
            return if b.is_ascii_graphic() { format!("ok {:?}", b as char) } else { format!("ok {b:#04x}") };
        }
        let sig = match *r as i32 {
            libc::SIGBUS => "SIGBUS",
            libc::SIGSEGV => "SIGSEGV",
            _ => "signal?",
        };
        let code = match (*r as i32, *r.add(1) as i32) {
            (libc::SIGBUS, 1) => "BUS_ADRALN".into(),
            (libc::SIGBUS, 2) => "BUS_ADRERR".into(),
            (libc::SIGBUS, 3) => "BUS_OBJERR".into(),
            (libc::SIGSEGV, 1) => "SEGV_MAPERR".into(),
            (libc::SIGSEGV, 2) => "SEGV_ACCERR".into(),
            (_, c) => format!("code {c}"),
        };
        let addr = if *r.add(2) == at as u64 { "si_addr exact".into() } else { format!("si_addr {:+#x}", *r.add(2) as i64 - at as i64) };
        format!("{sig} {code} {addr}")
    }
}

/// A syscall handed a pointer into the page: what it answers, in a child, so
/// that an emulator taking a host fault for it does not end the probe.
fn syscall_reads(at: *mut u8) -> String {
    unsafe {
        let mut fds = [0; 2];
        libc::pipe(fds.as_mut_ptr());
        let pid = libc::fork();
        if pid == 0 {
            let n = libc::write(fds[1], at.cast(), 16);
            let e = if n < 0 { errno() } else { 0 };
            libc::_exit(if n < 0 { 100 + e.min(100) } else { n as i32 });
        }
        libc::close(fds[0]);
        libc::close(fds[1]);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        if libc::WIFSIGNALED(st) {
            return format!("killed by signal {}", libc::WTERMSIG(st));
        }
        match libc::WEXITSTATUS(st) {
            n if n >= 100 => named(n - 100),
            n => format!("wrote {n}"),
        }
    }
}

fn map_file(fd: i32, pages: usize, prot: i32, flags: i32, off: i64) -> *mut u8 {
    let p = unsafe { libc::mmap(std::ptr::null_mut(), pages * PAGE, prot, flags, fd, off) };
    assert_ne!(p, libc::MAP_FAILED, "{}", errno());
    p.cast()
}

fn pg(p: *mut u8, i: usize) -> *mut u8 {
    unsafe { p.add(i * PAGE) }
}

fn eof_cases(kind: &str, make: &dyn Fn(usize) -> i32) {
    println!("\n########## {kind}: pages past the end of the file ##########");
    let rw = libc::PROT_READ | libc::PROT_WRITE;

    // 100 bytes, mapped as four pages.
    for (flags, name) in [(libc::MAP_SHARED, "shared"), (libc::MAP_PRIVATE, "private")] {
        let fd = make(100);
        let p = map_file(fd, 4, rw, flags, 0);
        line(&format!("{name}, 100-byte file: page 0 byte 50"), touch(unsafe { p.add(50) }, false));
        line(&format!("{name}, 100-byte file: page 0 byte 4000"), touch(unsafe { p.add(4000) }, false));
        line(&format!("{name}, 100-byte file: read page 1"), touch(pg(p, 1), false));
        line(&format!("{name}, 100-byte file: write page 1"), touch(pg(p, 1), true));
        line(&format!("{name}, 100-byte file: read page 3 byte 8"), touch(unsafe { pg(p, 3).add(8) }, false));
        line(&format!("{name}, 100-byte file: write(2) from page 1"), syscall_reads(pg(p, 1)));
        unsafe { libc::munmap(p.cast(), 4 * PAGE) };
        unsafe { libc::close(fd) };
    }

    // 5000 bytes: page 1 holds the tail, pages 2 and 3 are past it.
    let fd = make(5000);
    let p = map_file(fd, 4, libc::PROT_READ, libc::MAP_SHARED, 0);
    line("5000-byte file: page 1 byte 1000", touch(unsafe { pg(p, 1).add(1000) }, false));
    line("5000-byte file: page 1 byte 2000", touch(unsafe { pg(p, 1).add(2000) }, false));
    line("5000-byte file: page 2", touch(pg(p, 2), false));
    unsafe { libc::munmap(p.cast(), 4 * PAGE) };
    // At an offset: file pages 1..3 of a two-page file.
    let p = map_file(fd, 2, libc::PROT_READ, libc::MAP_PRIVATE, PAGE as i64);
    line("5000-byte file at offset 4096: page 0", touch(pg(p, 0), false));
    line("5000-byte file at offset 4096: page 1", touch(pg(p, 1), false));
    unsafe { libc::munmap(p.cast(), 2 * PAGE) };
    unsafe { libc::close(fd) };

    // Shrunk under the mapping, and grown back.
    for (flags, name) in [(libc::MAP_SHARED, "shared"), (libc::MAP_PRIVATE, "private")] {
        let fd = make(4 * PAGE);
        let p = map_file(fd, 4, rw, flags, 0);
        line(&format!("{name}, 4-page file: read page 3"), touch(pg(p, 3), false));
        // A private copy of page 2 before the file shrinks under it.
        unsafe { *pg(p, 2) = b'c' };
        unsafe { libc::ftruncate(fd, 100) };
        line(&format!("{name}, shrunk to 100: page 0 byte 50"), touch(unsafe { p.add(50) }, false));
        line(&format!("{name}, shrunk to 100: page 0 byte 200"), touch(unsafe { p.add(200) }, false));
        line(&format!("{name}, shrunk to 100: read page 1"), touch(pg(p, 1), false));
        line(&format!("{name}, shrunk to 100: read page 2, written before"), touch(pg(p, 2), false));
        line(&format!("{name}, shrunk to 100: read page 3"), touch(pg(p, 3), false));
        line(&format!("{name}, shrunk to 100: write(2) from page 3"), syscall_reads(pg(p, 3)));
        unsafe { libc::ftruncate(fd, 4 * PAGE as i64) };
        unsafe { libc::pwrite(fd, b"G".as_ptr().cast(), 1, 3 * PAGE as i64) };
        line(&format!("{name}, grown back: read page 2"), touch(pg(p, 2), false));
        line(&format!("{name}, grown back: read page 3 after pwrite 'G'"), touch(pg(p, 3), false));
        unsafe { libc::munmap(p.cast(), 4 * PAGE) };
        unsafe { libc::close(fd) };
    }

    // Grown after the mapping was made, never touched before.
    let fd = make(100);
    let p = map_file(fd, 2, rw, libc::MAP_SHARED, 0);
    unsafe { libc::ftruncate(fd, 2 * PAGE as i64) };
    unsafe { libc::pwrite(fd, b"X".as_ptr().cast(), 1, PAGE as i64) };
    line("shared, 100 bytes grown to 2 pages: read page 1", touch(pg(p, 1), false));
    unsafe { *pg(p, 1).add(1) = b'Y' };
    let mut back = [0u8; 1];
    unsafe { libc::pread(fd, back.as_mut_ptr().cast(), 1, PAGE as i64 + 1) };
    line("  a store to page 1 reaches the file", back[0] as char);
    unsafe { libc::munmap(p.cast(), 2 * PAGE) };
    unsafe { libc::close(fd) };
}

fn regular(len: usize) -> i32 {
    file_with(c"/tmp/mmfault_probe.f", len)
}

fn memfd(len: usize) -> i32 {
    let fd = unsafe { libc::memfd_create(c"mmfault".as_ptr(), 0) };
    let buf = vec![b'f'; len];
    unsafe { libc::write(fd, buf.as_ptr().cast(), len) };
    fd
}

/// One byte at `at`, read in this process: a fork would not show whether this
/// process's own page table still has the page.
fn byte(at: *mut u8) -> String {
    let b = unsafe { std::ptr::read_volatile(at) };
    if b.is_ascii_graphic() { format!("{:?}", b as char) } else { format!("{b:#04x}") }
}

fn pwrite1(fd: i32, b: u8, off: usize) {
    assert_eq!(unsafe { libc::pwrite(fd, [b].as_ptr().cast(), 1, off as i64) }, 1);
}

fn pread1(fd: i32, off: usize) -> String {
    let mut b = [0u8; 1];
    match unsafe { libc::pread(fd, b.as_mut_ptr().cast(), 1, off as i64) } {
        1 if b[0].is_ascii_graphic() => format!("{:?}", b[0] as char),
        1 => format!("{:#04x}", b[0]),
        n => format!("returned {n}"),
    }
}

fn follow_cases(kind: &str, make: &dyn Fn(usize) -> i32) {
    println!("\n########## {kind}: a private mapping and the file under it ##########");
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    let fd = make(4 * PAGE);
    let p = map_file(fd, 4, rw, libc::MAP_PRIVATE, 0);
    line("page 0 before anything", byte(pg(p, 0)));
    // A store to page 1 only: pages 0, 2 and 3 are nobody's but the file's.
    unsafe { *pg(p, 1) = b'w' };
    for i in 0..4 {
        pwrite1(fd, b'P', i * PAGE);
    }
    for i in 0..4 {
        line(&format!("page {i} after pwrite 'P' (page 1 written before)"), byte(pg(p, i)));
    }
    line("pread of page 1 after the store", pread1(fd, PAGE));
    let r = unsafe { libc::madvise(pg(p, 1).cast(), PAGE, libc::MADV_DONTNEED) };
    line("madvise(page 1, MADV_DONTNEED)", ok(r as i64));
    line("page 1 after MADV_DONTNEED", byte(pg(p, 1)));
    // Read-only, then writable, then a store: still the process's own copy.
    unsafe { libc::mprotect(pg(p, 3).cast(), PAGE, libc::PROT_READ) };
    line("page 3 read-only", byte(pg(p, 3)));
    let r = unsafe { libc::mprotect(pg(p, 3).cast(), PAGE, rw) };
    line("mprotect(page 3, RW) again", ok(r as i64));
    unsafe { *pg(p, 3) = b'm' };
    line("page 3 after a store", byte(pg(p, 3)));
    line("pread of page 3 after that store", pread1(fd, 3 * PAGE));

    // A fork: the child stores to page 0, the parent then pwrites pages 0
    // and 2, and each side says what it sees.
    unsafe {
        let mut go = [0; 2];
        let mut done = [0; 2];
        libc::pipe(go.as_mut_ptr());
        libc::pipe(done.as_mut_ptr());
        let pid = libc::fork();
        if pid == 0 {
            *pg(p, 0) = b'c';
            libc::write(done[1], b"x".as_ptr().cast(), 1);
            let mut b = [0u8; 1];
            libc::read(go[0], b.as_mut_ptr().cast(), 1);
            let seen = format!("{} {}", byte(pg(p, 0)), byte(pg(p, 2)));
            libc::write(done[1], seen.as_ptr().cast(), seen.len());
            libc::_exit(0);
        }
        let mut b = [0u8; 16];
        libc::read(done[0], b.as_mut_ptr().cast(), 1);
        pwrite1(fd, b'Q', 0);
        pwrite1(fd, b'Q', 2 * PAGE);
        libc::write(go[1], b"x".as_ptr().cast(), 1);
        let n = libc::read(done[0], b.as_mut_ptr().cast(), b.len());
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        line("fork: the child stored page 0, the parent pwrote 'Q' to 0 and 2", "");
        line("  the child's pages 0 and 2", String::from_utf8_lossy(&b[..n.max(0) as usize]));
        line("  the parent's pages 0 and 2", format!("{} {}", byte(pg(p, 0)), byte(pg(p, 2))));
        for f in [go[0], go[1], done[0], done[1]] {
            libc::close(f);
        }
    }
    unsafe { libc::munmap(p.cast(), 4 * PAGE) };
    unsafe { libc::close(fd) };
}

const TMPFS: &std::ffi::CStr = c"/tmp/mmfault_probe.tmpfs";

/// A tmpfs of the probe's own, or `None` where it may not mount one.
fn mount_tmpfs() -> bool {
    unsafe { libc::mkdir(TMPFS.as_ptr(), 0o755) };
    let r = unsafe { libc::mount(c"none".as_ptr(), TMPFS.as_ptr(), c"tmpfs".as_ptr(), 0, std::ptr::null()) };
    line("mount a tmpfs", if r == 0 { "ok".into() } else { named(errno()) });
    r == 0
}

fn tmpfs_file(len: usize) -> i32 {
    file_with(c"/tmp/mmfault_probe.tmpfs/f", len)
}

fn main() {
    mprotect_cases();
    eof_cases("regular file", &regular);
    eof_cases("memfd", &memfd);
    follow_cases("regular file", &regular);
    follow_cases("memfd", &memfd);
    if mount_tmpfs() {
        eof_cases("tmpfs file", &tmpfs_file);
        follow_cases("tmpfs file", &tmpfs_file);
        unsafe { libc::unlink(c"/tmp/mmfault_probe.tmpfs/f".as_ptr()) };
        unsafe { libc::umount(TMPFS.as_ptr()) };
    }
    unsafe { libc::rmdir(TMPFS.as_ptr()) };
    unsafe { libc::unlink(c"/tmp/mmfault_probe.f".as_ptr()) };
    unsafe { libc::unlink(c"/tmp/mmfault_probe.ro".as_ptr()) };
}
