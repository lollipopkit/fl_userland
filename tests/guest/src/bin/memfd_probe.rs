//! What `memfd_create(2)` and its seals answer.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! A memfd is a file with no name that two processes can map shared and that
//! one of them can seal, and the seals are where a program's expectations are
//! precise: a compositor handed a sealed buffer relies on the producer being
//! unable to shrink it under it. The cases here are the flag and name rules,
//! what the file looks like, the seven seals and what each refuses, and that a
//! mapping is one set of pages for two processes.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<58} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EINVAL => "EINVAL",
        libc::EPERM => "EPERM",
        libc::EFAULT => "EFAULT",
        libc::ENOSYS => "ENOSYS",
        libc::EBUSY => "EBUSY",
        libc::EACCES => "EACCES",
        libc::ENOENT => "ENOENT",
        libc::EBADF => "EBADF",
        libc::EFBIG => "EFBIG",
        libc::ENOMEM => "ENOMEM",
        libc::ENODEV => "ENODEV",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

const MFD_CLOEXEC: u32 = 1;
const MFD_ALLOW_SEALING: u32 = 2;
const MFD_HUGETLB: u32 = 4;
const MFD_NOEXEC_SEAL: u32 = 8;
const MFD_EXEC: u32 = 0x10;

const F_SEAL_SEAL: i32 = 1;
const F_SEAL_SHRINK: i32 = 2;
const F_SEAL_GROW: i32 = 4;
const F_SEAL_WRITE: i32 = 8;
const F_SEAL_FUTURE_WRITE: i32 = 0x10;
const F_SEAL_EXEC: i32 = 0x20;
const F_ADD_SEALS: i32 = 1033;
const F_GET_SEALS: i32 = 1034;

fn memfd(name: &str, flags: u32) -> Result<i32, i32> {
    let c = std::ffi::CString::new(name).unwrap();
    let r = unsafe { libc::syscall(libc::SYS_memfd_create, c.as_ptr(), flags) };
    if r < 0 { Err(errno()) } else { Ok(r as i32) }
}

fn memfd_line(what: &str, name: &str, flags: u32) -> Option<i32> {
    match memfd(name, flags) {
        Ok(fd) => {
            line(what, "ok");
            Some(fd)
        }
        Err(e) => {
            line(what, named(e));
            None
        }
    }
}

fn result(r: i64) -> String {
    if r < 0 { named(errno()) } else if r == 0 { "ok".to_string() } else { r.to_string() }
}

fn seals(fd: i32) -> String {
    let r = unsafe { libc::fcntl(fd, F_GET_SEALS) };
    if r < 0 { named(errno()) } else { format!("{r:#x}") }
}

fn add_seals(fd: i32, s: i32) -> String {
    result(unsafe { libc::fcntl(fd, F_ADD_SEALS, s) } as i64)
}

fn write_at(fd: i32, off: i64, n: usize) -> String {
    let buf = vec![b'x'; n];
    let r = unsafe { libc::pwrite(fd, buf.as_ptr().cast(), n, off) };
    if r < 0 { named(errno()) } else { format!("wrote {r}") }
}

fn ftruncate(fd: i32, n: i64) -> String {
    result(unsafe { libc::ftruncate(fd, n) } as i64)
}

fn size(fd: i32) -> String {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, st.as_mut_ptr()) } < 0 {
        return named(errno());
    }
    unsafe { st.assume_init() }.st_size.to_string()
}

fn mmap_line(what: &str, fd: i32, prot: i32, flags: i32) -> Option<*mut u8> {
    let p = unsafe { libc::mmap(std::ptr::null_mut(), 4096, prot, flags, fd, 0) };
    if p == libc::MAP_FAILED {
        line(what, named(errno()));
        None
    } else {
        line(what, "ok");
        Some(p.cast())
    }
}

fn main() {
    println!("## the flags and the name");
    if let Some(fd) = memfd_line("memfd_create(\"probe\", 0)", "probe", 0) {
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = memfd_line("memfd_create(\"\", 0), an empty name", "", 0) {
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = memfd_line("MFD_CLOEXEC", "probe", MFD_CLOEXEC) {
        let r = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        line("  FD_CLOEXEC is set", (r & libc::FD_CLOEXEC != 0).to_string());
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = memfd_line("no MFD_CLOEXEC", "probe", 0) {
        let r = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        line("  FD_CLOEXEC is set", (r & libc::FD_CLOEXEC != 0).to_string());
        unsafe { libc::close(fd) };
    }
    line("flag 0x20", memfd("probe", 0x20).map(|_| "ok".to_string()).unwrap_or_else(named));
    line("flag 0x40000000, a huge page size alone", memfd("probe", 0x4000_0000).map(|_| "ok".to_string()).unwrap_or_else(named));
    line("MFD_EXEC | MFD_NOEXEC_SEAL", memfd("probe", MFD_EXEC | MFD_NOEXEC_SEAL).map(|_| "ok".to_string()).unwrap_or_else(named));
    line("MFD_HUGETLB", memfd("probe", MFD_HUGETLB).map(|_| "ok".to_string()).unwrap_or_else(named));
    line("a name of 249 bytes", memfd(&"n".repeat(249), 0).map(|_| "ok".to_string()).unwrap_or_else(named));
    line("a name of 250 bytes", memfd(&"n".repeat(250), 0).map(|_| "ok".to_string()).unwrap_or_else(named));
    line("a name of 1000 bytes", memfd(&"n".repeat(1000), 0).map(|_| "ok".to_string()).unwrap_or_else(named));
    line("a name at a bad address", {
        let r = unsafe { libc::syscall(libc::SYS_memfd_create, 1usize, 0u32) };
        result(r)
    });
    line("a NULL name", {
        let r = unsafe { libc::syscall(libc::SYS_memfd_create, 0usize, 0u32) };
        result(r)
    });

    println!("## what the file looks like");
    if let Some(fd) = memfd_line("a plain memfd", "look", 0) {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        unsafe { libc::fstat(fd, st.as_mut_ptr()) };
        let st = unsafe { st.assume_init() };
        line("  mode", format!("{:o}", st.st_mode & 0o177777));
        line("  nlink", st.st_nlink.to_string());
        line("  size", st.st_size.to_string());
        line("  uid is ours", (st.st_uid == unsafe { libc::getuid() }).to_string());
        let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).map(|p| p.to_string_lossy().into_owned());
        line("  /proc/self/fd", link.unwrap_or_else(|e| e.to_string()));
        line("  F_GET_SEALS", seals(fd));
        line("  F_ADD_SEALS(SHRINK) without MFD_ALLOW_SEALING", add_seals(fd, F_SEAL_SHRINK));
        line("  F_GETFL & O_ACCMODE", format!("{}", unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE));
        let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
        let r = unsafe { libc::fstatfs(fd, fs.as_mut_ptr()) };
        line("  fstatfs type", if r < 0 { named(errno()) } else { format!("{:#x}", unsafe { fs.assume_init() }.f_type) });
        line("  write 10 bytes", write_at(fd, 0, 10));
        line("  size after", size(fd));
        line("  lseek(SEEK_END)", result(unsafe { libc::lseek(fd, 0, libc::SEEK_END) } as i64));
        line("  ftruncate(100)", ftruncate(fd, 100));
        line("  size after", size(fd));
        line("  ftruncate(5)", ftruncate(fd, 5));
        line("  size after", size(fd));
        let mut buf = [0u8; 16];
        let r = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), 16, 0) };
        line("  pread at 0", if r < 0 { named(errno()) } else { format!("{r} bytes: {:?}", String::from_utf8_lossy(&buf[..r as usize])) });
        line("  fchmod(0600)", result(unsafe { libc::fchmod(fd, 0o600) } as i64));
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = memfd_line("MFD_NOEXEC_SEAL", "noexec", MFD_NOEXEC_SEAL) {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        unsafe { libc::fstat(fd, st.as_mut_ptr()) };
        line("  mode", format!("{:o}", unsafe { st.assume_init() }.st_mode & 0o7777));
        line("  F_GET_SEALS", seals(fd));
        line("  F_ADD_SEALS(SHRINK)", add_seals(fd, F_SEAL_SHRINK));
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = memfd_line("MFD_EXEC", "exec", MFD_EXEC) {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        unsafe { libc::fstat(fd, st.as_mut_ptr()) };
        line("  mode", format!("{:o}", unsafe { st.assume_init() }.st_mode & 0o7777));
        line("  F_GET_SEALS", seals(fd));
        unsafe { libc::close(fd) };
    }
    line("F_GET_SEALS on a pipe", {
        let mut p = [0i32; 2];
        unsafe { libc::pipe(p.as_mut_ptr()) };
        let s = seals(p[0]);
        unsafe { libc::close(p[0]); libc::close(p[1]) };
        s
    });
    line("F_ADD_SEALS on /dev/null", {
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
        let s = add_seals(fd, F_SEAL_SHRINK);
        unsafe { libc::close(fd) };
        s
    });

    println!("## the seals");
    if let Some(fd) = memfd_line("a sealable memfd", "seals", MFD_ALLOW_SEALING) {
        line("  F_GET_SEALS", seals(fd));
        line("  ftruncate(100)", ftruncate(fd, 100));
        line("  F_ADD_SEALS(0x40)", add_seals(fd, 0x40));
        line("  F_ADD_SEALS(0)", add_seals(fd, 0));
        line("  F_ADD_SEALS(SHRINK)", add_seals(fd, F_SEAL_SHRINK));
        line("  F_GET_SEALS", seals(fd));
        line("  ftruncate(50) under SHRINK", ftruncate(fd, 50));
        line("  ftruncate(100) under SHRINK, the same size", ftruncate(fd, 100));
        line("  ftruncate(200) under SHRINK", ftruncate(fd, 200));
        line("  F_ADD_SEALS(GROW)", add_seals(fd, F_SEAL_GROW));
        line("  ftruncate(300) under GROW", ftruncate(fd, 300));
        line("  ftruncate(200) under GROW, the same size", ftruncate(fd, 200));
        line("  pwrite 10 at 190 under GROW, up to the end", write_at(fd, 190, 10));
        line("  pwrite 10 at 195 under GROW, past it", write_at(fd, 195, 10));
        line("  pwrite 10 at 0 under GROW", write_at(fd, 0, 10));
        line("  F_ADD_SEALS(SHRINK) again", add_seals(fd, F_SEAL_SHRINK));
        let shared = mmap_line("  mmap(PROT_READ|PROT_WRITE, MAP_SHARED) before WRITE", fd, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED);
        line("  F_ADD_SEALS(WRITE) with a writable shared mapping", add_seals(fd, F_SEAL_WRITE));
        if let Some(p) = shared {
            unsafe { libc::munmap(p.cast(), 4096) };
        }
        line("  F_ADD_SEALS(WRITE) once it is unmapped", add_seals(fd, F_SEAL_WRITE));
        line("  F_GET_SEALS", seals(fd));
        line("  pwrite under WRITE", write_at(fd, 0, 10));
        line("  write under WRITE", {
            let r = unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
            if r < 0 { named(errno()) } else { format!("wrote {r}") }
        });
        line("  ftruncate(200) under WRITE, the same size", ftruncate(fd, 200));
        mmap_line("  mmap(PROT_READ|PROT_WRITE, MAP_SHARED) under WRITE", fd, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED);
        if let Some(p) = mmap_line("  mmap(PROT_READ, MAP_SHARED) under WRITE", fd, libc::PROT_READ, libc::MAP_SHARED) {
            // The seal's other half: a read-only shared mapping may not be
            // made writable afterwards.
            let r = unsafe { libc::mprotect(p.cast(), 4096, libc::PROT_READ | libc::PROT_WRITE) };
            line("    mprotect(PROT_READ|PROT_WRITE) on it", if r == 0 { "ok".to_string() } else { named(errno()) });
            let r = unsafe { libc::mprotect(p.cast(), 4096, libc::PROT_READ) };
            line("    mprotect(PROT_READ) on it", if r == 0 { "ok".to_string() } else { named(errno()) });
            unsafe { libc::munmap(p.cast(), 4096) };
        }
        if let Some(p) = mmap_line("  mmap(PROT_READ|PROT_WRITE, MAP_PRIVATE) under WRITE", fd, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE) {
            let r = unsafe { libc::mprotect(p.cast(), 4096, libc::PROT_READ | libc::PROT_WRITE) };
            line("    mprotect(PROT_READ|PROT_WRITE) on the private one", if r == 0 { "ok".to_string() } else { named(errno()) });
            unsafe { libc::munmap(p.cast(), 4096) };
        }
        line("  pread under WRITE", {
            let mut buf = [0u8; 4];
            let r = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), 4, 0) };
            if r < 0 { named(errno()) } else { format!("{r} bytes") }
        });
        line("  F_ADD_SEALS(SEAL)", add_seals(fd, F_SEAL_SEAL));
        line("  F_ADD_SEALS(EXEC) after SEAL", add_seals(fd, F_SEAL_EXEC));
        line("  F_GET_SEALS", seals(fd));
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = memfd_line("FUTURE_WRITE", "future", MFD_ALLOW_SEALING) {
        line("  ftruncate(4096)", ftruncate(fd, 4096));
        let before = mmap_line("  mmap(PROT_READ|PROT_WRITE, MAP_SHARED) before", fd, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED);
        line("  F_ADD_SEALS(FUTURE_WRITE) with a writable shared mapping", add_seals(fd, F_SEAL_FUTURE_WRITE));
        line("  F_GET_SEALS", seals(fd));
        if let Some(p) = before {
            unsafe { p.write_volatile(7) };
            line("  a store through the earlier mapping", "ok");
            unsafe { libc::munmap(p.cast(), 4096) };
        }
        line("  pwrite under FUTURE_WRITE", write_at(fd, 0, 1));
        mmap_line("  mmap(PROT_READ|PROT_WRITE, MAP_SHARED) under FUTURE_WRITE", fd, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED);
        mmap_line("  mmap(PROT_READ, MAP_SHARED) under FUTURE_WRITE", fd, libc::PROT_READ, libc::MAP_SHARED);
        line("  ftruncate(8192) under FUTURE_WRITE", ftruncate(fd, 8192));
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = memfd_line("EXEC on an executable memfd", "execseal", MFD_ALLOW_SEALING) {
        line("  F_ADD_SEALS(EXEC)", add_seals(fd, F_SEAL_EXEC));
        line("  F_GET_SEALS, the write seals come with it", seals(fd));
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        unsafe { libc::fstat(fd, st.as_mut_ptr()) };
        line("  mode after", format!("{:o}", unsafe { st.assume_init() }.st_mode & 0o7777));
        line("  fchmod(0777) under EXEC, the same bits", result(unsafe { libc::fchmod(fd, 0o777) } as i64));
        line("  fchmod(0755) under EXEC", result(unsafe { libc::fchmod(fd, 0o755) } as i64));
        line("  fchmod(0666) under EXEC", result(unsafe { libc::fchmod(fd, 0o666) } as i64));
        unsafe { libc::fstat(fd, st.as_mut_ptr()) };
        line("  mode after that", format!("{:o}", unsafe { st.assume_init() }.st_mode & 0o7777));
        line("  pwrite under EXEC", write_at(fd, 0, 1));
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = memfd_line("EXEC on a non-executable memfd", "execseal2", MFD_ALLOW_SEALING) {
        line("  fchmod(0666)", result(unsafe { libc::fchmod(fd, 0o666) } as i64));
        line("  F_ADD_SEALS(EXEC)", add_seals(fd, F_SEAL_EXEC));
        line("  F_GET_SEALS, EXEC alone", seals(fd));
        line("  fchmod(0777) under EXEC", result(unsafe { libc::fchmod(fd, 0o777) } as i64));
        line("  fchmod(0600) under EXEC", result(unsafe { libc::fchmod(fd, 0o600) } as i64));
        line("  pwrite under EXEC alone", write_at(fd, 0, 1));
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = memfd_line("a read-only shared mapping and F_SEAL_WRITE", "romap", MFD_ALLOW_SEALING) {
        line("  ftruncate(4096)", ftruncate(fd, 4096));
        let p = mmap_line("  mmap(PROT_READ, MAP_SHARED)", fd, libc::PROT_READ, libc::MAP_SHARED);
        line("  F_ADD_SEALS(WRITE) with it mapped", add_seals(fd, F_SEAL_WRITE));
        line("  F_ADD_SEALS(SHRINK) with it mapped", add_seals(fd, F_SEAL_SHRINK));
        if let Some(p) = p {
            unsafe { libc::munmap(p.cast(), 4096) };
        }
        line("  F_ADD_SEALS(WRITE) once unmapped", add_seals(fd, F_SEAL_WRITE));
        unsafe { libc::close(fd) };
    }
    if let Some(fd) = memfd_line("the owner", "owner", 0) {
        line("  fchown(1234, 5678)", result(unsafe { libc::fchown(fd, 1234, 5678) } as i64));
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        unsafe { libc::fstat(fd, st.as_mut_ptr()) };
        let st = unsafe { st.assume_init() };
        line("  uid:gid after", format!("{}:{}", st.st_uid, st.st_gid));
        unsafe { libc::close(fd) };
    }

    println!("## a mapping is one set of pages");
    if let Some(fd) = memfd_line("a memfd of one page", "share", 0) {
        line("  ftruncate(4096)", ftruncate(fd, 4096));
        if let Some(p) = mmap_line("  mmap(MAP_SHARED)", fd, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED) {
            let word = p.cast::<u32>();
            unsafe { word.write_volatile(1) };
            let _ = std::io::stdout().flush();
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // The child maps the same descriptor afresh and stores.
                let q = unsafe { libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0) };
                if q == libc::MAP_FAILED {
                    unsafe { libc::_exit(2) };
                }
                let seen = unsafe { q.cast::<u32>().read_volatile() };
                unsafe { q.cast::<u32>().write_volatile(0xBEEF) };
                unsafe { libc::_exit(if seen == 1 { 0 } else { 3 }) };
            }
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            line("  the child saw the parent's store", format!("exit {}", libc::WEXITSTATUS(status)));
            line("  and the parent sees the child's", format!("{:#x}", unsafe { word.read_volatile() }));
            let mut buf = [0u8; 4];
            unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), 4, 0) };
            line("  and a read of the file sees it", format!("{:#x}", u32::from_ne_bytes(buf)));
            unsafe { libc::munmap(p.cast(), 4096) };
        }
        line("  a dup shares the seals", {
            let d = unsafe { libc::dup(fd) };
            let s = seals(d);
            unsafe { libc::close(d) };
            s
        });
        unsafe { libc::close(fd) };
    }

    println!("## a memfd can be run");
    if let Some(fd) = memfd_line("a memfd holding busybox", "program", MFD_CLOEXEC) {
        let image = std::fs::read("/bin/busybox").unwrap();
        let n = unsafe { libc::write(fd, image.as_ptr().cast(), image.len()) };
        line("  written whole", (n as usize == image.len()).to_string());
        // fexecve: the child runs the memfd as `true` and exits 0; if the exec
        // fails the errno comes back through a pipe.
        let _ = std::io::stdout().flush();
        let mut fds = [0i32; 2];
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let argv0 = c"true";
            let argv = [argv0.as_ptr(), std::ptr::null()];
            let envp: [*const libc::c_char; 1] = [std::ptr::null()];
            unsafe {
                libc::syscall(libc::SYS_execveat, fd, c"".as_ptr(), argv.as_ptr(), envp.as_ptr(), 0x1000);
                let e = errno();
                libc::write(fds[1], (&e as *const i32).cast(), 4);
                libc::_exit(99);
            }
        }
        unsafe { libc::close(fds[1]) };
        let mut e = [0u8; 4];
        let got = unsafe { libc::read(fds[0], e.as_mut_ptr().cast(), 4) };
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        line(
            "  execveat(memfd, \"\", AT_EMPTY_PATH) as true",
            if got == 4 { named(i32::from_ne_bytes(e)) } else { format!("ran, exit {}", libc::WEXITSTATUS(status)) },
        );
        unsafe { libc::close(fd) };
    }
}
