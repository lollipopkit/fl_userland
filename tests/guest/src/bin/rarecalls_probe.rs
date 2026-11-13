//! The syscalls the table answered `ENOSYS` for without a measured reason:
//! `vmsplice`, `remap_file_pages`, the swap, quota, accounting, module, kexec
//! and hangup calls, `pivot_root`, and two numbers Linux has retired.
//!
//! **A report, not a check**: one line per case, run here and in a privileged
//! arm64 container (the guest is root with every capability) and diffed by
//! `tests/integration/probe_diff.sh`. Every case that reaches the real kernel
//! is an error path or an operation on the probe's own objects: nothing here
//! enables swap, loads a module or replaces a kernel. Protection keys,
//! `map_shadow_stack` and the NUMA calls are `mm_modern_probe`'s.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<56} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EINVAL => "EINVAL",
        libc::EBADF => "EBADF",
        libc::EFAULT => "EFAULT",
        libc::EAGAIN => "EAGAIN",
        libc::EPIPE => "EPIPE",
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ENOSYS => "ENOSYS",
        libc::EINTR => "EINTR",
        libc::EACCES => "EACCES",
        libc::EISDIR => "EISDIR",
        libc::ENOTDIR => "ENOTDIR",
        libc::ENOTBLK => "ENOTBLK",
        libc::ENODEV => "ENODEV",
        libc::EBUSY => "EBUSY",
        libc::ENOEXEC => "ENOEXEC",
        libc::ESRCH => "ESRCH",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::ENOMEM => "ENOMEM",
        libc::EIO => "EIO",
        libc::ENXIO => "ENXIO",
        libc::ELOOP => "ELOOP",
        libc::ETXTBSY => "ETXTBSY",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn r(v: i64) -> String {
    if v < 0 { named(errno()) } else { v.to_string() }
}

fn ok(v: i64) -> String {
    if v < 0 { named(errno()) } else { "ok".into() }
}

#[repr(C)]
struct Iovec {
    base: *mut u8,
    len: usize,
}

fn iov(buf: &mut [u8]) -> Iovec {
    Iovec { base: buf.as_mut_ptr(), len: buf.len() }
}

const PAGE: usize = 4096;
const SPLICE_F_NONBLOCK: i64 = 2;
const SPLICE_F_GIFT: i64 = 8;

fn vmsplice(fd: i32, v: *const Iovec, n: u64, flags: i64) -> i64 {
    unsafe { libc::syscall(libc::SYS_vmsplice, fd, v, n, flags) }
}

fn pipe(flags: i32) -> (i32, i32) {
    let mut p = [0i32; 2];
    unsafe { libc::pipe2(p.as_mut_ptr(), flags) };
    (p[0], p[1])
}

fn close(fd: i32) {
    unsafe { libc::close(fd) };
}

fn queued(fd: i32) -> i32 {
    let mut n = 0i32;
    unsafe { libc::ioctl(fd, libc::FIONREAD, &mut n) };
    n
}

fn read_all(fd: i32, n: usize) -> String {
    let mut buf = vec![0u8; n];
    let got = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), n) };
    if got < 0 {
        return named(errno());
    }
    String::from_utf8_lossy(&buf[..got as usize]).into_owned()
}

extern "C" fn on_alarm(_: i32) {}

/// Runs `f` with a one-second alarm whose handler does not restart, so a call
/// that blocks comes back `EINTR` and is reported as blocking.
fn bounded(f: impl FnOnce() -> i64) -> String {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_alarm as extern "C" fn(i32) as usize;
        libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
        libc::alarm(1);
    }
    let v = f();
    let e = errno();
    unsafe { libc::alarm(0) };
    if v < 0 && e == libc::EINTR { "blocked".into() } else if v < 0 { named(e) } else { v.to_string() }
}

fn vmsplice_cases() {
    println!("\n########## vmsplice ##########");
    let mut hello = *b"hello";
    let v = iov(&mut hello);
    line("vmsplice(-1, NULL, 0, 0)", r(vmsplice(-1, std::ptr::null(), 0, 0)));
    line("vmsplice(-1, NULL, 0, 0x10)", r(vmsplice(-1, std::ptr::null(), 0, 0x10)));
    line("vmsplice(-1, iov, 1, 0)", r(vmsplice(-1, &v, 1, 0)));

    let (rd, wr) = pipe(0);
    line("vmsplice(write end, hello)", r(vmsplice(wr, &v, 1, 0)));
    line("  read back", read_all(rd, 64));
    let mut a = *b"ab";
    let mut b = *b"cde";
    let two = [iov(&mut a), iov(&mut b)];
    line("vmsplice(write end, two iovecs)", r(vmsplice(wr, two.as_ptr(), 2, 0)));
    line("  read back", read_all(rd, 64));
    line("vmsplice(write end, SPLICE_F_GIFT)", r(vmsplice(wr, &v, 1, SPLICE_F_GIFT)));
    line("  read back", read_all(rd, 64));
    line("vmsplice(write end, flags 0xf)", r(vmsplice(wr, &v, 1, 0xf)));
    line("  read back", read_all(rd, 64));
    line("vmsplice(write end, flags 0x10)", r(vmsplice(wr, &v, 1, 0x10)));
    line("vmsplice(write end, no iovecs)", r(vmsplice(wr, &v, 0, 0)));
    line("vmsplice(write end, NULL, 1)", r(vmsplice(wr, std::ptr::null(), 1, 0)));
    let empty = Iovec { base: std::ptr::null_mut(), len: 0 };
    line("vmsplice(write end, one empty iovec)", r(vmsplice(wr, &empty, 1, 0)));
    let wild = Iovec { base: 8 as *mut u8, len: 4 };
    line("vmsplice(write end, unmapped base)", r(vmsplice(wr, &wild, 1, 0)));
    line("  queued after it", queued(rd));
    let one = [iov(&mut a), Iovec { base: 8 as *mut u8, len: 4 }];
    line("vmsplice(write end, good then unmapped)", r(vmsplice(wr, one.as_ptr(), 2, 0)));
    line("  queued after it", queued(rd));
    let _ = read_all(rd, 64);
    line("vmsplice(write end, 1025 iovecs)", r(vmsplice(wr, &v, 1025, 0)));
    line("vmsplice(write end, 1 << 32 | 1 iovecs)", r(vmsplice(wr, &v, (1 << 32) | 1, 0)));
    line("  read back", read_all(rd, 64));
    line("vmsplice(read end, NULL, 0)", r(vmsplice(rd, std::ptr::null(), 0, 0)));

    // The read side: into the caller's memory, consuming.
    let _ = unsafe { libc::write(wr, b"xyz".as_ptr().cast(), 3) };
    let mut into = [0u8; 8];
    let vi = iov(&mut into);
    line("vmsplice(read end, 8 bytes, 3 queued)", r(vmsplice(rd, &vi, 1, 0)));
    line("  the buffer", String::from_utf8_lossy(&into[..3]));
    line("  queued after it", queued(rd));
    let _ = unsafe { libc::write(wr, b"123456".as_ptr().cast(), 6) };
    let mut p1 = [0u8; 2];
    let mut p2 = [0u8; 2];
    let split = [iov(&mut p1), iov(&mut p2)];
    line("vmsplice(read end, 2+2, 6 queued)", r(vmsplice(rd, split.as_ptr(), 2, 0)));
    line("  the buffers", format!("{}{}", String::from_utf8_lossy(&p1), String::from_utf8_lossy(&p2)));
    line("  queued after it", queued(rd));
    let _ = read_all(rd, 64);
    line("vmsplice(read end, empty, SPLICE_F_NONBLOCK)", r(vmsplice(rd, &vi, 1, SPLICE_F_NONBLOCK)));
    line("vmsplice(read end, empty, blocking)", bounded(|| vmsplice(rd, &vi, 1, 0)));
    let ro = unsafe {
        libc::mmap(std::ptr::null_mut(), PAGE, libc::PROT_READ, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    } as *mut u8;
    let _ = unsafe { libc::write(wr, b"qq".as_ptr().cast(), 2) };
    let vro = Iovec { base: ro, len: 2 };
    line("vmsplice(read end, into read-only memory)", r(vmsplice(rd, &vro, 1, 0)));
    line("  queued after it", queued(rd));
    let _ = read_all(rd, 64);
    line("vmsplice(write end, from read-only memory)", r(vmsplice(wr, &vro, 1, 0)));
    let _ = read_all(rd, 64);

    // O_NONBLOCK on the description, without the flag.
    unsafe { libc::fcntl(rd, libc::F_SETFL, libc::O_NONBLOCK) };
    line("vmsplice(O_NONBLOCK read end, empty)", bounded(|| vmsplice(rd, &vi, 1, 0)));
    unsafe { libc::fcntl(rd, libc::F_SETFL, 0) };

    // A full pipe.
    let cap = unsafe { libc::fcntl(wr, libc::F_GETPIPE_SZ) } as usize;
    // Page-aligned, because Linux moves whole user pages into the pipe's
    // slots and an unaligned buffer fills sixteen slots with less than 64K.
    let big = unsafe {
        libc::mmap(std::ptr::null_mut(), cap * 2, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    } as *mut u8;
    let vbig = Iovec { base: big, len: cap * 2 };
    line("vmsplice(write end, twice the capacity)", bounded(|| vmsplice(wr, &vbig, 1, 0)));
    line("  queued after it", queued(rd));
    line("vmsplice(full write end, SPLICE_F_NONBLOCK)", r(vmsplice(wr, &v, 1, SPLICE_F_NONBLOCK)));
    line("vmsplice(full write end, blocking)", bounded(|| vmsplice(wr, &v, 1, 0)));
    unsafe { libc::fcntl(wr, libc::F_SETFL, libc::O_NONBLOCK) };
    line("vmsplice(full O_NONBLOCK write end)", bounded(|| vmsplice(wr, &v, 1, 0)));
    unsafe { libc::fcntl(wr, libc::F_SETFL, 0) };
    close(rd);
    close(wr);

    // The ends that have lost their other half.
    let (rd, wr) = pipe(0);
    close(wr);
    line("vmsplice(read end, no writers)", bounded(|| vmsplice(rd, &vi, 1, 0)));
    close(rd);
    let (rd, wr) = pipe(0);
    close(rd);
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    line("vmsplice(write end, no readers)", r(vmsplice(wr, &v, 1, 0)));
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    close(wr);
    let (rd, wr) = pipe(0);
    close(rd);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        vmsplice(wr, &v, 1, 0);
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    line(
        "  without SIG_IGN, the child",
        if libc::WIFSIGNALED(st) { format!("signal {}", libc::WTERMSIG(st)) } else { format!("exit {}", libc::WEXITSTATUS(st)) },
    );
    close(wr);

    // Packet mode: is a vmsplice one record?
    let (rd, wr) = pipe(libc::O_DIRECT);
    let _ = vmsplice(wr, two.as_ptr(), 2, 0);
    line("O_DIRECT pipe: vmsplice of two iovecs, then read(64)", read_all(rd, 64));
    close(rd);
    close(wr);

    // Descriptors that are not pipes.
    let path = c"/tmp/rarecalls_probe.file";
    let f = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644) };
    let _ = unsafe { libc::write(f, b"file".as_ptr().cast(), 4) };
    unsafe { libc::lseek(f, 0, libc::SEEK_SET) };
    line("vmsplice(regular file O_RDWR)", r(vmsplice(f, &v, 1, 0)));
    line("vmsplice(regular file, no iovecs)", r(vmsplice(f, &v, 0, 0)));
    close(f);
    let f = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    line("vmsplice(regular file O_RDONLY)", r(vmsplice(f, &vi, 1, 0)));
    close(f);
    let f = unsafe { libc::open(path.as_ptr(), libc::O_PATH) };
    line("vmsplice(O_PATH)", r(vmsplice(f, &v, 1, 0)));
    close(f);
    let f = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY) };
    line("vmsplice(/dev/null)", r(vmsplice(f, &v, 1, 0)));
    close(f);
    let mut sv = [0i32; 2];
    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    line("vmsplice(socket)", r(vmsplice(sv[0], &v, 1, 0)));
    close(sv[0]);
    close(sv[1]);

    // A pipe reached by name: /proc/self/fd, read-write, and a FIFO.
    let (rd, wr) = pipe(0);
    let name = std::ffi::CString::new(format!("/proc/self/fd/{rd}")).unwrap();
    let both = unsafe { libc::open(name.as_ptr(), libc::O_RDWR) };
    line("vmsplice(/proc/self/fd/<read end>, O_RDWR)", r(vmsplice(both, &v, 1, 0)));
    line("  queued on the read end", queued(rd));
    close(both);
    close(rd);
    close(wr);
    let fifo = c"/tmp/rarecalls_probe.fifo";
    unsafe { libc::unlink(fifo.as_ptr()) };
    unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) };
    let both = unsafe { libc::open(fifo.as_ptr(), libc::O_RDWR) };
    line("vmsplice(FIFO, O_RDWR)", r(vmsplice(both, &v, 1, 0)));
    line("  read back", read_all(both, 64));
    close(both);
    let rdonly = unsafe { libc::open(fifo.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    let wronly = unsafe { libc::open(fifo.as_ptr(), libc::O_WRONLY) };
    let _ = unsafe { libc::write(wronly, b"fifo".as_ptr().cast(), 4) };
    line("vmsplice(FIFO, O_RDONLY)", r(vmsplice(rdonly, &vi, 1, 0)));
    line("  the buffer", String::from_utf8_lossy(&into[..4]));
    line("vmsplice(FIFO O_RDONLY, empty, SPLICE_F_NONBLOCK)", r(vmsplice(rdonly, &vi, 1, SPLICE_F_NONBLOCK)));
    close(rdonly);
    close(wronly);
    unsafe { libc::unlink(fifo.as_ptr()) };
    unsafe { libc::unlink(path.as_ptr()) };
}

fn remap(start: *mut u8, size: usize, prot: i64, pgoff: i64, flags: i64) -> i64 {
    unsafe { libc::syscall(libc::SYS_remap_file_pages, start, size, prot, pgoff, flags) }
}

fn maps_line(addr: *mut u8) -> String {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    let want = format!("{:08x}-", addr as usize);
    for l in maps.lines() {
        if l.starts_with(&want) {
            let f: Vec<&str> = l.split_whitespace().collect();
            let len = usize::from_str_radix(f[0].split('-').nth(1).unwrap_or("0"), 16).unwrap_or(0) - addr as usize;
            return format!("{} pages {} off {}", len / PAGE, f[1], f[2]);
        }
    }
    "none".into()
}

fn remap_cases() {
    println!("\n########## remap_file_pages ##########");
    let path = c"/tmp/rarecalls_probe.map";
    let f = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644) };
    for i in 0..4u8 {
        let page = [b'a' + i; PAGE];
        unsafe { libc::write(f, page.as_ptr().cast(), PAGE) };
    }
    let map = |flags: i32, prot: i32| unsafe {
        libc::mmap(std::ptr::null_mut(), 4 * PAGE, prot, flags, f, 0) as *mut u8
    };
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    let p = map(libc::MAP_SHARED, rw);
    let at = |q: *mut u8, i: usize| unsafe { *q.add(i * PAGE) as char };
    line("remap_file_pages(page 0 -> file page 3)", ok(remap(p, PAGE, 0, 3, 0)));
    line("  the four pages read", format!("{}{}{}{}", at(p, 0), at(p, 1), at(p, 2), at(p, 3)));
    line("  maps at the start", maps_line(p));
    line("  maps at page 1", maps_line(unsafe { p.add(PAGE) }));
    unsafe { *p = b'Z' };
    let mut back = [0u8; 1];
    unsafe { libc::pread(f, back.as_mut_ptr().cast(), 1, 3 * PAGE as i64) };
    line("  a store there reaches file page 3", back[0] as char);
    line("remap_file_pages(pages 0-1 -> file page 1), across the split", ok(remap(p, 2 * PAGE, 0, 1, 0)));
    line("  the four pages read", format!("{}{}{}{}", at(p, 0), at(p, 1), at(p, 2), at(p, 3)));
    line("remap_file_pages(prot PROT_READ)", ok(remap(p, PAGE, libc::PROT_READ as i64, 0, 0)));
    line("remap_file_pages(size 0)", ok(remap(p, 0, 0, 0, 0)));
    line("remap_file_pages(size 1)", ok(remap(p, 1, 0, 0, 0)));
    line("remap_file_pages(unaligned start)", ok(remap(unsafe { p.add(5) }, PAGE, 0, 2, 0)));
    line("  page 0 reads", at(p, 0));
    line("remap_file_pages(flags 0xffff)", ok(remap(p, PAGE, 0, 0, 0xffff)));
    line("  page 0 reads", at(p, 0));
    line("remap_file_pages(past the mapping)", ok(remap(p, 5 * PAGE, 0, 0, 0)));
    line("remap_file_pages(pgoff wraps)", ok(remap(p, 2 * PAGE, 0, -1, 0)));
    line("remap_file_pages(pgoff past the file)", ok(remap(p, PAGE, 0, 100, 0)));
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let _ = unsafe { std::ptr::read_volatile(p) };
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    line("  touching the page past the end of the file", if libc::WIFSIGNALED(st) { format!("signal {}", libc::WTERMSIG(st)) } else { "survived".into() });
    unsafe { libc::munmap(p.cast(), 4 * PAGE) };

    let p = map(libc::MAP_SHARED, libc::PROT_READ);
    line("remap_file_pages(read-only shared)", ok(remap(p, PAGE, 0, 2, 0)));
    line("  page 0 reads", at(p, 0));
    line("  maps", maps_line(p));
    unsafe { libc::munmap(p.cast(), 4 * PAGE) };
    let p = map(libc::MAP_PRIVATE, rw);
    line("remap_file_pages(MAP_PRIVATE file)", ok(remap(p, PAGE, 0, 2, 0)));
    unsafe { libc::munmap(p.cast(), 4 * PAGE) };
    let p = map(libc::MAP_SHARED, rw);
    unsafe { libc::mlock(p.cast(), PAGE) };
    line("remap_file_pages(locked page)", ok(remap(p, PAGE, 0, 2, 0)));
    line("  maps", maps_line(p));
    unsafe { libc::munmap(p.cast(), 4 * PAGE) };
    // Two mappings of the same file, side by side.
    let p = map(libc::MAP_SHARED, rw);
    unsafe { libc::mmap(p.add(2 * PAGE).cast(), 2 * PAGE, rw, libc::MAP_SHARED | libc::MAP_FIXED, f, 0) };
    line("remap_file_pages(across two adjacent mappings of one file)", ok(remap(unsafe { p.add(PAGE) }, 2 * PAGE, 0, 0, 0)));
    line("  the four pages read", format!("{}{}{}{}", at(p, 0), at(p, 1), at(p, 2), at(p, 3)));
    let g = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    unsafe { libc::mmap(p.add(2 * PAGE).cast(), 2 * PAGE, rw, libc::MAP_SHARED | libc::MAP_FIXED, g, 0) };
    line("remap_file_pages(across two descriptors of one file)", ok(remap(unsafe { p.add(PAGE) }, 2 * PAGE, 0, 0, 0)));
    unsafe { libc::mprotect(p.add(2 * PAGE).cast(), 2 * PAGE, libc::PROT_READ) };
    line("remap_file_pages(across a protection change)", ok(remap(unsafe { p.add(PAGE) }, 2 * PAGE, 0, 0, 0)));
    unsafe { libc::munmap(p.add(2 * PAGE).cast(), PAGE) };
    line("remap_file_pages(across a hole)", ok(remap(unsafe { p.add(PAGE) }, 2 * PAGE, 0, 0, 0)));
    unsafe { libc::munmap(p.cast(), 4 * PAGE) };
    close(g);

    let anon = |flags: i32| unsafe {
        libc::mmap(std::ptr::null_mut(), 2 * PAGE, rw, flags | libc::MAP_ANONYMOUS, -1, 0) as *mut u8
    };
    let p = anon(libc::MAP_SHARED);
    unsafe { *p.add(PAGE) = b'S' };
    line("remap_file_pages(shared anon, page 0 -> 1)", ok(remap(p, PAGE, 0, 1, 0)));
    line("  page 0 reads", unsafe { *p } as char);
    unsafe { libc::munmap(p.cast(), 2 * PAGE) };
    let p = anon(libc::MAP_PRIVATE);
    line("remap_file_pages(private anon)", ok(remap(p, PAGE, 0, 1, 0)));
    unsafe { libc::munmap(p.cast(), 2 * PAGE) };
    line("remap_file_pages(unmapped)", ok(remap(p, PAGE, 0, 1, 0)));
    close(f);
    unsafe { libc::unlink(path.as_ptr()) };
}

fn sys(n: i64, a: &[i64]) -> i64 {
    let g = |i: usize| a.get(i).copied().unwrap_or(0);
    unsafe { libc::syscall(n, g(0), g(1), g(2), g(3), g(4), g(5)) }
}

fn ptr(s: &std::ffi::CStr) -> i64 {
    s.as_ptr() as i64
}

fn admin_cases() {
    let file = c"/tmp/rarecalls_probe.zeros";
    let f = unsafe { libc::open(file.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o600) };
    let zeros = vec![0u8; 16 * PAGE];
    unsafe { libc::write(f, zeros.as_ptr().cast(), zeros.len()) };
    close(f);
    let missing = c"/tmp/rarecalls_probe.missing";
    let notdir = c"/tmp/rarecalls_probe.zeros/x";

    println!("\n########## swapon / swapoff ##########");
    line("swapon(NULL, 0)", ok(sys(224, &[0, 0])));
    line("swapon(\"\", 0)", ok(sys(224, &[ptr(c""), 0])));
    line("swapon(missing, 0)", ok(sys(224, &[ptr(missing), 0])));
    line("swapon(through a file, 0)", ok(sys(224, &[ptr(notdir), 0])));
    line("swapon(/tmp, 0)", ok(sys(224, &[ptr(c"/tmp"), 0])));
    line("swapon(/dev/null, 0)", ok(sys(224, &[ptr(c"/dev/null"), 0])));
    line("swapon(a file of zeros, 0)", ok(sys(224, &[ptr(file), 0])));
    line("swapon(a file of zeros, SWAP_FLAG_PREFER|5)", ok(sys(224, &[ptr(file), 0x8005])));
    line("swapon(a file of zeros, DISCARD_ONCE)", ok(sys(224, &[ptr(file), 0x30000])));
    line("swapon(missing, 0x100000)", ok(sys(224, &[ptr(missing), 0x100000])));
    line("swapon(NULL, 0x100000)", ok(sys(224, &[0, 0x100000])));
    line("swapoff(NULL)", ok(sys(225, &[0])));
    line("swapoff(\"\")", ok(sys(225, &[ptr(c"")])));
    line("swapoff(missing)", ok(sys(225, &[ptr(missing)])));
    line("swapoff(a socket)", {
        let sock = c"/tmp/rarecalls_probe.sock";
        unsafe { libc::unlink(sock.as_ptr()) };
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as u16;
        for (d, s) in sa.sun_path.iter_mut().zip(sock.to_bytes()) {
            *d = *s as libc::c_char;
        }
        unsafe { libc::bind(fd, (&raw const sa).cast(), std::mem::size_of::<libc::sockaddr_un>() as u32) };
        let v = ok(sys(225, &[ptr(sock)]));
        close(fd);
        unsafe { libc::unlink(sock.as_ptr()) };
        v
    });
    line("swapoff(a FIFO)", {
        let fifo = c"/tmp/rarecalls_probe.swapfifo";
        unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) };
        let v = ok(sys(225, &[ptr(fifo)]));
        unsafe { libc::unlink(fifo.as_ptr()) };
        v
    });
    line("swapoff(through a file)", ok(sys(225, &[ptr(notdir)])));
    line("swapoff(/tmp)", ok(sys(225, &[ptr(c"/tmp")])));
    line("swapoff(/dev/null)", ok(sys(225, &[ptr(c"/dev/null")])));
    line("swapoff(a file of zeros)", ok(sys(225, &[ptr(file)])));
    line("swapoff(/proc/self/status)", ok(sys(225, &[ptr(c"/proc/self/status")])));
    let ro = c"/tmp/rarecalls_probe.ro";
    let f = unsafe { libc::open(ro.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o400) };
    close(f);
    line("swapoff(a mode 0400 file)", ok(sys(225, &[ptr(ro)])));
    unsafe { libc::unlink(ro.as_ptr()) };

    println!("\n########## quotactl / quotactl_fd ##########");
    let qcmd = |c: i64, t: i64| (c << 8) | (t & 0xff);
    const Q_SYNC: i64 = 0x800001;
    const Q_QUOTAON: i64 = 0x800002;
    const Q_GETFMT: i64 = 0x800004;
    const Q_GETINFO: i64 = 0x800005;
    const Q_GETQUOTA: i64 = 0x800007;
    const Q_SETQUOTA: i64 = 0x800008;
    let mut out = [0u8; 256];
    let o = out.as_mut_ptr() as i64;
    line("quotactl(Q_SYNC, NULL)", ok(sys(60, &[qcmd(Q_SYNC, 0), 0, 0, 0])));
    line("quotactl(Q_SYNC grpquota, NULL)", ok(sys(60, &[qcmd(Q_SYNC, 1), 0, 0, 0])));
    line("quotactl(Q_SYNC type 3, NULL)", ok(sys(60, &[qcmd(Q_SYNC, 3), 0, 0, 0])));
    line("quotactl(Q_GETFMT, NULL)", ok(sys(60, &[qcmd(Q_GETFMT, 0), 0, 0, o])));
    line("quotactl(Q_GETFMT type 3, NULL)", ok(sys(60, &[qcmd(Q_GETFMT, 3), 0, 0, o])));
    line("quotactl(cmd 0, NULL)", ok(sys(60, &[0, 0, 0, 0])));
    line("quotactl(Q_GETFMT, \"\")", ok(sys(60, &[qcmd(Q_GETFMT, 0), ptr(c""), 0, o])));
    line("quotactl(Q_GETFMT, missing)", ok(sys(60, &[qcmd(Q_GETFMT, 0), ptr(missing), 0, o])));
    line("quotactl(Q_GETFMT, through a file)", ok(sys(60, &[qcmd(Q_GETFMT, 0), ptr(notdir), 0, o])));
    line("quotactl(Q_GETFMT, /tmp)", ok(sys(60, &[qcmd(Q_GETFMT, 0), ptr(c"/tmp"), 0, o])));
    line("quotactl(Q_GETFMT, /dev/null)", ok(sys(60, &[qcmd(Q_GETFMT, 0), ptr(c"/dev/null"), 0, o])));
    line("quotactl(Q_GETFMT, a file)", ok(sys(60, &[qcmd(Q_GETFMT, 0), ptr(file), 0, o])));
    line("quotactl(Q_GETFMT, bad pointer)", ok(sys(60, &[qcmd(Q_GETFMT, 0), 8, 0, o])));
    line("quotactl(Q_GETFMT type 3, /dev/null)", ok(sys(60, &[qcmd(Q_GETFMT, 3), ptr(c"/dev/null"), 0, o])));
    line("quotactl(Q_QUOTAON, /dev/null, missing)", ok(sys(60, &[qcmd(Q_QUOTAON, 0), ptr(c"/dev/null"), 2, ptr(missing)])));
    line("quotactl(Q_SETQUOTA, /dev/null)", ok(sys(60, &[qcmd(Q_SETQUOTA, 0), ptr(c"/dev/null"), 0, o])));
    line("quotactl(0xff00, /dev/null)", ok(sys(60, &[0xff00, ptr(c"/dev/null"), 0, o])));
    let tmp = unsafe { libc::open(c"/tmp".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    let file_fd = unsafe { libc::open(file.as_ptr(), libc::O_RDONLY) };
    let proc_fd = unsafe { libc::open(c"/proc/self/status".as_ptr(), libc::O_RDONLY) };
    let path_fd = unsafe { libc::open(c"/tmp".as_ptr(), libc::O_PATH) };
    let qfd = |fd: i32, c: i64| ok(sys(443, &[fd as i64, c, 0, o]));
    line("quotactl_fd(-1, Q_GETFMT)", qfd(-1, qcmd(Q_GETFMT, 0)));
    line("quotactl_fd(-1, type 3)", qfd(-1, qcmd(Q_GETFMT, 3)));
    line("quotactl_fd(/tmp, type 3)", qfd(tmp, qcmd(Q_GETFMT, 3)));
    line("quotactl_fd(/tmp, Q_GETFMT)", qfd(tmp, qcmd(Q_GETFMT, 0)));
    line("quotactl_fd(/tmp, Q_GETINFO)", qfd(tmp, qcmd(Q_GETINFO, 0)));
    line("quotactl_fd(/tmp, Q_GETQUOTA)", qfd(tmp, qcmd(Q_GETQUOTA, 0)));
    line("quotactl_fd(/tmp, Q_SYNC)", qfd(tmp, qcmd(Q_SYNC, 0)));
    line("quotactl_fd(/tmp, Q_SETQUOTA)", qfd(tmp, qcmd(Q_SETQUOTA, 0)));
    line("quotactl_fd(/tmp, cmd 0)", qfd(tmp, 0));
    line("quotactl_fd(/tmp, 0xff00)", qfd(tmp, 0xff00));
    line("quotactl_fd(a file, Q_GETFMT)", qfd(file_fd, qcmd(Q_GETFMT, 0)));
    line("quotactl_fd(/proc file, Q_GETFMT)", qfd(proc_fd, qcmd(Q_GETFMT, 0)));
    line("quotactl_fd(O_PATH /tmp, Q_GETFMT)", qfd(path_fd, qcmd(Q_GETFMT, 0)));
    close(tmp);
    close(file_fd);
    close(proc_fd);
    close(path_fd);

    println!("\n########## acct ##########");
    line("acct(NULL)", ok(sys(89, &[0])));
    line("acct(missing)", ok(sys(89, &[ptr(missing)])));
    line("acct(/tmp)", ok(sys(89, &[ptr(c"/tmp")])));
    line("acct(/dev/null)", ok(sys(89, &[ptr(c"/dev/null")])));
    line("acct(bad pointer)", ok(sys(89, &[8])));
    line("acct(a file)", ok(sys(89, &[ptr(file)])));
    line("acct(NULL), off again", ok(sys(89, &[0])));

    println!("\n########## modules, kexec ##########");
    line("init_module(NULL, 0, \"\")", ok(sys(105, &[0, 0, ptr(c"")])));
    line("init_module(16 zero bytes, \"\")", ok(sys(105, &[zeros.as_ptr() as i64, 16, ptr(c"")])));
    line("delete_module(\"rarecalls_probe_none\", 0)", ok(sys(106, &[ptr(c"rarecalls_probe_none"), 0])));
    line("delete_module(\"rarecalls_probe_none\", O_NONBLOCK)", ok(sys(106, &[ptr(c"rarecalls_probe_none"), libc::O_NONBLOCK as i64])));
    line("delete_module(NULL, 0)", ok(sys(106, &[0, 0])));
    line("finit_module(-1, \"\", 0)", ok(sys(273, &[-1, ptr(c""), 0])));
    line("finit_module(-1, \"\", 0x100)", ok(sys(273, &[-1, ptr(c""), 0x100])));
    let zf = unsafe { libc::open(file.as_ptr(), libc::O_RDONLY) };
    line("finit_module(a file of zeros, \"\", 0)", ok(sys(273, &[zf as i64, ptr(c""), 0])));
    close(zf);
    line("kexec_load(0, 0, NULL, flags 0xdead0000)", ok(sys(104, &[0, 0, 0, 0xdead0000])));
    line("kexec_load(0, 17 segments, NULL, 0)", ok(sys(104, &[0, 17, 0, 0])));
    line("kexec_file_load(-1, -1, 0, \"\", flags 0x100)", ok(sys(294, &[-1, -1, 0, 0, 0x100])));

    println!("\n########## retired numbers ##########");
    line("lookup_dcookie(0, NULL, 0)", ok(sys(18, &[0, 0, 0])));
    line("nfsservctl(0, NULL, NULL)", ok(sys(42, &[0, 0, 0])));

    println!("\n########## pivot_root ##########");
    line("pivot_root(missing, /)", ok(sys(41, &[ptr(missing), ptr(c"/")])));
    line("pivot_root(a file, /)", ok(sys(41, &[ptr(file), ptr(c"/")])));
    line("pivot_root(/tmp/x, /tmp/x), not a mount", {
        let d = c"/tmp/rarecalls_probe.dir";
        unsafe { libc::mkdir(d.as_ptr(), 0o755) };
        let v = ok(sys(41, &[ptr(d), ptr(d)]));
        unsafe { libc::rmdir(d.as_ptr()) };
        v
    });
    line("pivot_root(NULL, /)", ok(sys(41, &[0, ptr(c"/")])));
    unsafe { libc::unlink(file.as_ptr()) };
}

fn vhangup_cases() {
    println!("\n########## vhangup ##########");
    // In a child, so the probe's own session is untouched: no controlling
    // terminal first, then a pty this child makes its own.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::setsid() };
        line("vhangup(), no controlling terminal", ok(sys(58, &[])));
        let m = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        unsafe {
            libc::grantpt(m);
            libc::unlockpt(m);
        }
        let name = unsafe { std::ffi::CStr::from_ptr(libc::ptsname(m)) }.to_owned();
        let s = unsafe { libc::open(name.as_ptr(), libc::O_RDWR) };
        unsafe { libc::ioctl(s, libc::TIOCSCTTY, 0) };
        let mut sid = 0;
        unsafe { libc::ioctl(s, libc::TIOCGSID, &mut sid) };
        line("  the pty is the controlling terminal", sid == unsafe { libc::getsid(0) });
        unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
        line("vhangup(), with one", ok(sys(58, &[])));
        let mut b = [0u8; 4];
        // Non-blocking, so a kernel that did not hang it up answers EAGAIN
        // rather than waiting for ever.
        unsafe { libc::fcntl(s, libc::F_SETFL, libc::O_NONBLOCK) };
        line("  read the old slave descriptor", r(unsafe { libc::read(s, b.as_mut_ptr().cast(), 4) } as i64));
        line("  write the old slave descriptor", r(unsafe { libc::write(s, b"x".as_ptr().cast(), 1) } as i64));
        let mut sid2 = 0;
        line("  TIOCGSID on it", r(unsafe { libc::ioctl(s, libc::TIOCGSID, &mut sid2) } as i64));
        let again = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        line("  reopen the slave", if again < 0 { named(errno()) } else { "ok".into() });
        line("  write the new descriptor", r(unsafe { libc::write(again, b"y".as_ptr().cast(), 1) } as i64));
        let tty = unsafe { libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR) };
        line("  open /dev/tty", if tty < 0 { named(errno()) } else { "ok".into() });
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
}

fn main() {
    vmsplice_cases();
    remap_cases();
    admin_cases();
    vhangup_cases();
}
