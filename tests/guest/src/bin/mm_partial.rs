//! Where a memory call or a touch stops partway, asserted as a 7.2 arm64
//! kernel answers it (`mmfault_probe` is the measurement):
//!
//! - `mprotect` changes the VMAs before a hole, a VMA whose file forbids the
//!   protection, or a sealed VMA, and then answers `ENOMEM`, `EACCES` or
//!   `EPERM`; within one VMA `EACCES` is asked before the seal.
//! - `mmap` refuses a descriptor not open for reading, and a shared writable
//!   mapping of one not open for writing, with `EACCES`.
//! - Raising one page's protection leaves the pages beside it as they were.
//! - A page of a file mapping wholly past the end of the file raises
//!   `SIGBUS`/`BUS_ADRERR` at the exact address and is `EFAULT` to a syscall:
//!   at map time, after `ftruncate` shrinks the file (a private copy made
//!   after a fork included), and not once the file grows back.
//!
//! `mm_partial <dir>`: the files go in `<dir>`, so the same checks run on
//! realfs and fakefs; a memfd is checked as well.

use guest_tests::{Harness, check, check_fails};
use std::ffi::CString;

const PAGE: usize = 4096;
const SYS_MSEAL: libc::c_long = 462;
const RW: i32 = libc::PROT_READ | libc::PROT_WRITE;

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
    (0..pages).map(|i| perms(pg(base, i))).collect::<Vec<_>>().join(" ")
}

fn pg(p: *mut u8, i: usize) -> *mut u8 {
    unsafe { p.add(i * PAGE) }
}

/// Fresh pages far above everything both kernels place by themselves, so no
/// allocation lands in a hole made in them.
fn high(pages: usize, prot: i32) -> *mut u8 {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let at = 0x11_0000_0000 + NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) * 0x10_0000;
    const MAP_FIXED_NOREPLACE: i32 = 0x100000;
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE;
    let p = unsafe { libc::mmap(at as *mut _, pages * PAGE, prot, flags, -1, 0) };
    assert_eq!(p as usize, at);
    p.cast()
}

fn file_with(path: &CString, len: usize) -> i32 {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644) };
    assert!(fd >= 0, "open {path:?}");
    let buf = vec![b'f'; len];
    assert_eq!(unsafe { libc::write(fd, buf.as_ptr().cast(), len) }, len as isize);
    fd
}

/// Four pages laid out by `shape`: `a` anonymous `PROT_READ`, `-` a hole, `f`
/// a read-only shared file page, `s` a sealed page, `g` a sealed read-only
/// shared file page. Answers `mprotect(all four, prot)`'s errno (0 for
/// success) and the protections afterwards.
fn mprotect_over(ro: &CString, shape: &str, prot: i32) -> (i32, String) {
    let base = high(4, libc::PROT_READ);
    for (i, c) in shape.bytes().enumerate() {
        let at = pg(base, i);
        if c == b'-' {
            unsafe { libc::munmap(at.cast(), PAGE) };
        }
        if c == b'f' || c == b'g' {
            let fd = unsafe { libc::open(ro.as_ptr(), libc::O_RDONLY) };
            let p = unsafe { libc::mmap(at.cast(), PAGE, libc::PROT_READ, libc::MAP_SHARED | libc::MAP_FIXED, fd, 0) };
            assert_eq!(p, at.cast());
            unsafe { libc::close(fd) };
        }
        if c == b's' {
            unsafe { libc::mprotect(at.cast(), PAGE, libc::PROT_READ | libc::PROT_EXEC) };
        }
        if c == b's' || c == b'g' {
            assert_eq!(unsafe { libc::syscall(SYS_MSEAL, at, PAGE, 0) }, 0, "mseal");
        }
    }
    guest_tests::sys::clear_errno();
    let r = unsafe { libc::mprotect(base.cast(), 4 * PAGE, prot) };
    let e = if r < 0 { guest_tests::sys::errno() } else { 0 };
    (e, row(base, 4))
}

fn mprotect_checks(h: &mut Harness, dir: &str) {
    h.group("mprotect-stops-partway");
    let ro = guest_tests::cpath(&format!("{dir}/mm_partial.ro"));
    unsafe { libc::close(file_with(&ro, PAGE)) };
    let rx = libc::PROT_READ | libc::PROT_EXEC;
    for (shape, prot, errno, after) in [
        ("aaaa", RW, 0, "rw-p rw-p rw-p rw-p"),
        ("a-aa", RW, libc::ENOMEM, "rw-p unmapped r--p r--p"),
        ("-aaa", RW, libc::ENOMEM, "unmapped r--p r--p r--p"),
        ("aaa-", RW, libc::ENOMEM, "rw-p rw-p rw-p unmapped"),
        ("aafa", RW, libc::EACCES, "rw-p rw-p r--s r--p"),
        ("faaa", RW, libc::EACCES, "r--s r--p r--p r--p"),
        ("aafa", rx, 0, "r-xp r-xp r-xs r-xp"),
        ("af-a", RW, libc::EACCES, "rw-p r--s unmapped r--p"),
        ("a-fa", RW, libc::ENOMEM, "rw-p unmapped r--s r--p"),
        ("asaa", RW, libc::EPERM, "rw-p r-xp r--p r--p"),
        ("asfa", RW, libc::EPERM, "rw-p r-xp r--s r--p"),
        ("agaa", RW, libc::EACCES, "rw-p r--s r--p r--p"),
        ("agaa", rx, libc::EPERM, "r-xp r--s r--p r--p"),
    ] {
        let (e, got) = mprotect_over(&ro, shape, prot);
        check!(h, e == errno, "mprotect([{shape}], {prot:#x}): errno {e}, wanted {errno}");
        check!(h, got == after, "[{shape}] afterwards: {got}, wanted {after}");
    }

    h.group("mmap-refuses-the-descriptor");
    let mmap = |mode: i32, prot: i32, flags: i32| unsafe {
        let fd = libc::open(ro.as_ptr(), mode);
        let p = libc::mmap(std::ptr::null_mut(), PAGE, prot, flags, fd, 0);
        let r = if p == libc::MAP_FAILED { -1 } else { libc::munmap(p, PAGE) as i64 };
        libc::close(fd);
        r
    };
    check_fails!(h, mmap(libc::O_RDONLY, RW, libc::MAP_SHARED), libc::EACCES, "O_RDONLY, shared RW");
    check_fails!(h, mmap(libc::O_WRONLY, libc::PROT_READ, libc::MAP_PRIVATE), libc::EACCES, "O_WRONLY, private R");
    check!(h, mmap(libc::O_RDONLY, RW, libc::MAP_PRIVATE) == 0, "O_RDONLY, private RW maps");
    check!(h, mmap(libc::O_RDONLY, libc::PROT_READ, libc::MAP_SHARED) == 0, "O_RDONLY, shared R maps");
    unsafe { libc::unlink(ro.as_ptr()) };

    // One page of four taken to PROT_NONE and back up to PROT_READ: the other
    // three, which share a 16 KB host page with it here, stay writable.
    h.group("mprotect-one-page-keeps-its-neighbours");
    let rwf = guest_tests::cpath(&format!("{dir}/mm_partial.rw"));
    let fd = file_with(&rwf, 4 * PAGE);
    for (flags, fd, kind) in [
        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, "anonymous"),
        (libc::MAP_SHARED, fd, "shared file"),
        (libc::MAP_PRIVATE, fd, "private file"),
    ] {
        let p = unsafe { libc::mmap(std::ptr::null_mut(), 4 * PAGE, RW, flags, fd, 0) } as *mut u8;
        for i in 0..4 {
            unsafe { *pg(p, i) = b'1' };
        }
        let down = unsafe { libc::mprotect(p.cast(), PAGE, libc::PROT_NONE) };
        let up = unsafe { libc::mprotect(p.cast(), PAGE, libc::PROT_READ) };
        check!(h, down == 0 && up == 0, "{kind}: mprotect page 0 to none and back to read");
        unsafe {
            *pg(p, 1) = b'2';
            *pg(p, 3) = b'3';
        }
        check!(h, unsafe { *pg(p, 1) == b'2' && *pg(p, 3) == b'3' && *p == b'1' }, "{kind}: pages 1 and 3 still take stores");
        unsafe { libc::munmap(p.cast(), 4 * PAGE) };
    }
    unsafe { libc::close(fd) };
    unsafe { libc::unlink(rwf.as_ptr()) };
}

static mut REPORT: *mut u64 = std::ptr::null_mut();

extern "C" fn on_fault(sig: i32, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    unsafe {
        *REPORT = sig as u64;
        *REPORT.add(1) = (*info).si_code as u64;
        *REPORT.add(2) = (*info).si_addr() as u64;
        libc::_exit(0);
    }
}

#[derive(Debug, PartialEq)]
enum Touch {
    Read(u8),
    Wrote,
    /// `SIGBUS`/`BUS_ADRERR` with `si_addr` the address touched.
    Bus,
    Other(String),
}

/// Touch `at` in a child, so that a signal ends the child and not the test.
fn touch(at: *mut u8, write: bool) -> Touch {
    touch_in_child(at, write, None)
}

/// [`touch`], after the child has read `at` once and then run `between`: the
/// second access is one its own TLB has a translation for.
fn touch_after(at: *mut u8, write: bool, between: impl Fn()) -> Touch {
    touch_in_child(at, write, Some(&between))
}

fn touch_in_child(at: *mut u8, write: bool, between: Option<&dyn Fn()>) -> Touch {
    unsafe {
        if REPORT.is_null() {
            let p = libc::mmap(std::ptr::null_mut(), PAGE, RW, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1, 0);
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
            if let Some(between) = between {
                std::hint::black_box(std::ptr::read_volatile(at));
                between();
            }
            if write {
                std::ptr::write_volatile(at, b'w');
                *r.add(3) = 0x200;
            } else {
                *r.add(3) = 0x100 | std::ptr::read_volatile(at) as u64;
            }
            libc::_exit(0);
        }
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        match (*r.add(3), *r as i32, *r.add(1) as i32, *r.add(2)) {
            (0x200, ..) => Touch::Wrote,
            (v, ..) if v & 0x100 != 0 => Touch::Read(v as u8),
            (0, libc::SIGBUS, 2, a) if a == at as u64 => Touch::Bus,
            (_, sig, code, a) => Touch::Other(format!("signal {sig} code {code} at {:+#x}, status {st:#x}", a as i64 - at as i64)),
        }
    }
}

/// Another thread of a child reads `at` in a loop while the child shrinks the
/// file under it: the reader's translations are cached, and it makes no
/// syscall that could drop them.
fn touch_while_shrinking(at: *mut u8, fd: i32, to: i64) -> Touch {
    unsafe {
        let r = REPORT;
        std::ptr::write_bytes(r, 0, 4);
        let pid = libc::fork();
        if pid == 0 {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_fault as *const () as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
            let addr = at as usize;
            std::thread::spawn(move || {
                loop {
                    let v = std::ptr::read_volatile(addr as *const u8);
                    *REPORT.add(3) = 0x100 | v as u64;
                }
            });
            while std::ptr::read_volatile(r.add(3)) == 0 {
                std::hint::spin_loop();
            }
            libc::ftruncate(fd, to);
            libc::usleep(300_000);
            libc::_exit(0);
        }
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        match (*r as i32, *r.add(1) as i32, *r.add(2), *r.add(3)) {
            (libc::SIGBUS, 2, a, _) if a == at as u64 => Touch::Bus,
            (0, _, _, v) => Touch::Read(v as u8),
            (sig, code, a, _) => Touch::Other(format!("signal {sig} code {code} at {:+#x}", a as i64 - at as i64)),
        }
    }
}

/// `write(2)` from the page: what a syscall reaching it answers. The two
/// closes succeed and leave `errno` as the write set it.
fn write_from(at: *mut u8) -> i64 {
    let mut fds = [0; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let n = unsafe { libc::write(fds[1], at.cast(), 16) } as i64;
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    n
}

fn map(fd: i32, pages: usize, prot: i32, flags: i32, off: i64) -> *mut u8 {
    let p = unsafe { libc::mmap(std::ptr::null_mut(), pages * PAGE, prot, flags, fd, off) };
    assert_ne!(p, libc::MAP_FAILED);
    p.cast()
}

fn eof_checks(h: &mut Harness, make: &dyn Fn(usize) -> i32) {
    for (flags, kind) in [(libc::MAP_SHARED, "shared"), (libc::MAP_PRIVATE, "private")] {
        let fd = make(100);
        let p = map(fd, 4, RW, flags, 0);
        check!(h, touch(unsafe { p.add(50) }, false) == Touch::Read(b'f'), "{kind}: the file's bytes read");
        check!(h, touch(unsafe { p.add(4000) }, false) == Touch::Read(0), "{kind}: the rest of the last page reads zero");
        let t = touch(pg(p, 1), false);
        check!(h, t == Touch::Bus, "{kind}: a read of the page past the end: {t:?}");
        let t = touch(pg(p, 1), true);
        check!(h, t == Touch::Bus, "{kind}: a write to the page past the end: {t:?}");
        let t = touch(unsafe { pg(p, 3).add(8) }, false);
        check!(h, t == Touch::Bus, "{kind}: an address inside the last page: {t:?}");
        check_fails!(h, write_from(pg(p, 1)), libc::EFAULT, "{kind}: write(2) from the page past the end");
        unsafe { libc::munmap(p.cast(), 4 * PAGE) };
        unsafe { libc::close(fd) };
    }

    // Pages 2 and 3 sit in the 16 KB host page that holds the end, which
    // the host itself fills with zeroes.
    let fd = make(5000);
    let p = map(fd, 4, libc::PROT_READ, libc::MAP_SHARED, 0);
    check!(h, touch(unsafe { pg(p, 1).add(2000) }, false) == Touch::Read(0), "5000 bytes: the tail of page 1 reads zero");
    let t = touch(pg(p, 2), false);
    check!(h, t == Touch::Bus, "5000 bytes: page 2, in the host page that holds the end: {t:?}");
    unsafe { libc::munmap(p.cast(), 4 * PAGE) };
    let p = map(fd, 2, libc::PROT_READ, libc::MAP_PRIVATE, PAGE as i64);
    check!(h, touch(p, false) == Touch::Read(b'f'), "at offset 4096: page 0 is the file's");
    let t = touch(pg(p, 1), false);
    check!(h, t == Touch::Bus, "at offset 4096: page 1: {t:?}");
    unsafe { libc::munmap(p.cast(), 2 * PAGE) };
    unsafe { libc::close(fd) };

    for (flags, kind) in [(libc::MAP_SHARED, "shared"), (libc::MAP_PRIVATE, "private")] {
        let fd = make(4 * PAGE);
        let p = map(fd, 4, RW, flags, 0);
        check!(h, touch(pg(p, 3), false) == Touch::Read(b'f'), "{kind}: page 3 before the shrink");
        let t = touch_after(pg(p, 3), false, || unsafe {
            libc::ftruncate(fd, 2 * PAGE as i64);
        });
        check!(h, t == Touch::Bus, "{kind}: page 3, read, then the file shrunk under it: {t:?}");
        unsafe { libc::ftruncate(fd, 4 * PAGE as i64) };
        let t = touch_while_shrinking(pg(p, 3), fd, 2 * PAGE as i64);
        check!(h, t == Touch::Bus, "{kind}: page 3, read in a loop by a thread while the file shrinks: {t:?}");
        unsafe { libc::ftruncate(fd, 4 * PAGE as i64) };
        // Written after `touch` has forked, so a private page is this
        // kernel's own copy rather than the host's.
        unsafe { *pg(p, 2) = b'c' };
        unsafe { libc::ftruncate(fd, 100) };
        for i in 1..4 {
            let t = touch(pg(p, i), false);
            check!(h, t == Touch::Bus, "{kind}, shrunk to 100 bytes: page {i}: {t:?}");
        }
        check_fails!(h, write_from(pg(p, 3)), libc::EFAULT, "{kind}, shrunk: write(2) from page 3");
        unsafe { libc::ftruncate(fd, 4 * PAGE as i64) };
        let t = touch(pg(p, 3), false);
        check!(h, matches!(t, Touch::Read(_)), "{kind}, grown back: page 3 reads: {t:?}");
        unsafe { libc::munmap(p.cast(), 4 * PAGE) };
        unsafe { libc::close(fd) };
    }

    let fd = make(100);
    let p = map(fd, 2, libc::PROT_READ, libc::MAP_SHARED, 0);
    unsafe { libc::ftruncate(fd, 2 * PAGE as i64) };
    unsafe { libc::pwrite(fd, b"X".as_ptr().cast(), 1, PAGE as i64) };
    let t = touch(pg(p, 1), false);
    check!(h, t == Touch::Read(b'X'), "a read-only shared page past the end at mmap, after the file grew: {t:?}");
    unsafe { libc::munmap(p.cast(), 2 * PAGE) };
    unsafe { libc::close(fd) };
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp".into());
    let mut h = Harness::new();
    mprotect_checks(&mut h, &dir);

    h.group("past-the-end: file");
    let path = guest_tests::cpath(&format!("{dir}/mm_partial.f"));
    eof_checks(&mut h, &|len| file_with(&path, len));
    unsafe { libc::unlink(path.as_ptr()) };

    h.group("past-the-end: memfd");
    eof_checks(&mut h, &|len| {
        let fd = unsafe { libc::memfd_create(c"mm_partial".as_ptr(), 0) };
        let buf = vec![b'f'; len];
        unsafe { libc::write(fd, buf.as_ptr().cast(), len) };
        fd
    });
    std::process::exit(h.finish());
}
