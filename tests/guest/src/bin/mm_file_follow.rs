//! A file mapping and the file under it, asserted as a 7.2 arm64 kernel
//! answers (`mmfault_probe` is the measurement):
//!
//! - **Private**: a page nobody has written is the file's, so a `pwrite`
//!   shows through it even when the page beside it has been written, and a
//!   truncation zeroes the tail of the page holding the new end. A written
//!   page is the process's own: `read` does not see it, a truncation that cuts
//!   it off drops it (grown back, it reads the file's zeroes), and
//!   `MADV_DONTNEED` drops it too. After a fork, a page one side writes is
//!   that side's, and the pages neither wrote follow the file in both.
//!   `/proc/self/maps` still shows the mapping as one line of the file.
//! - **tmpfs**: a file there can be mapped, shared and private, with all of
//!   the above, a shared store reaching `read` and the other process, and the
//!   device and inode in `/proc/self/maps` being what `fstat` says.
//!
//! `mm_file_follow <dir>`: the files go in `<dir>`, and a tmpfs is mounted
//! under it.

use guest_tests::{Harness, check, cpath};
use std::ffi::CString;

const PAGE: usize = 4096;
const RW: i32 = libc::PROT_READ | libc::PROT_WRITE;

fn pg(p: *mut u8, i: usize) -> *mut u8 {
    unsafe { p.add(i * PAGE) }
}

fn at(p: *mut u8, i: usize) -> u8 {
    unsafe { std::ptr::read_volatile(pg(p, i)) }
}

fn file_with(path: &CString, len: usize) -> i32 {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644) };
    assert!(fd >= 0, "open {path:?}");
    let buf = vec![b'f'; len];
    assert_eq!(unsafe { libc::write(fd, buf.as_ptr().cast(), len) }, len as isize);
    fd
}

fn map(fd: i32, pages: usize, flags: i32) -> *mut u8 {
    let p = unsafe { libc::mmap(std::ptr::null_mut(), pages * PAGE, RW, flags, fd, 0) };
    assert_ne!(p, libc::MAP_FAILED, "mmap errno {}", guest_tests::sys::errno());
    p.cast()
}

fn pwrite1(fd: i32, b: u8, off: usize) {
    assert_eq!(unsafe { libc::pwrite(fd, [b].as_ptr().cast(), 1, off as i64) }, 1);
}

fn pread1(fd: i32, off: usize) -> u8 {
    let mut b = [0u8; 1];
    assert_eq!(unsafe { libc::pread(fd, b.as_mut_ptr().cast(), 1, off as i64) }, 1);
    b[0]
}

/// What a child reading `p`'s byte saw: the byte, or `None` for `SIGBUS`.
fn read_in_child(p: *mut u8) -> Option<u8> {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::signal(libc::SIGBUS, libc::SIG_DFL);
            let b = std::ptr::read_volatile(p);
            libc::_exit(i32::from(b));
        }
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        if libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGBUS {
            None
        } else {
            Some(libc::WEXITSTATUS(st) as u8)
        }
    }
}

/// The lines of `/proc/self/maps` that overlap `[p, p + len)`.
fn maps_lines(p: *mut u8, len: usize) -> Vec<String> {
    let (lo, hi) = (p as usize, p as usize + len);
    std::fs::read_to_string("/proc/self/maps")
        .unwrap_or_default()
        .lines()
        .filter(|l| {
            let mut r = l.split(' ').next().unwrap_or("").split('-');
            let a = usize::from_str_radix(r.next().unwrap_or("0"), 16).unwrap_or(0);
            let b = usize::from_str_radix(r.next().unwrap_or("0"), 16).unwrap_or(0);
            a < hi && lo < b
        })
        .map(str::to_string)
        .collect()
}

fn private_checks(h: &mut Harness, path: &CString) {
    let fd = file_with(path, 4 * PAGE);
    let p = map(fd, 4, libc::MAP_PRIVATE);
    unsafe { *pg(p, 1) = b'w' };
    for i in 0..4 {
        pwrite1(fd, b'P', i * PAGE);
    }
    check!(h, at(p, 0) == b'P', "a pwrite shows through page 0, beside a written page: {:?}", at(p, 0) as char);
    check!(h, at(p, 2) == b'P' && at(p, 3) == b'P', "and through pages 2 and 3");
    check!(h, at(p, 1) == b'w', "the written page keeps its store: {:?}", at(p, 1) as char);
    check!(h, pread1(fd, PAGE) == b'P', "read(2) does not see the store");
    let lines = maps_lines(p, 4 * PAGE);
    let name = path.to_str().unwrap();
    check!(h, lines.len() == 1 && lines[0].ends_with(name), "maps shows one line of the file: {lines:?}");

    check!(h, unsafe { libc::madvise(pg(p, 1).cast(), PAGE, libc::MADV_DONTNEED) } == 0, "MADV_DONTNEED");
    check!(h, at(p, 1) == b'P', "MADV_DONTNEED drops the written page for the file's: {:?}", at(p, 1) as char);

    // A fork: the child stores to page 0; the parent then pwrites 0 and 2.
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
            libc::write(done[1], [at(p, 0), at(p, 2)].as_ptr().cast(), 2);
            libc::_exit(0);
        }
        let mut b = [0u8; 2];
        libc::read(done[0], b.as_mut_ptr().cast(), 1);
        pwrite1(fd, b'Q', 0);
        pwrite1(fd, b'Q', 2 * PAGE);
        libc::write(go[1], b"x".as_ptr().cast(), 1);
        libc::read(done[0], b.as_mut_ptr().cast(), 2);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
        check!(h, b == [b'c', b'Q'], "the child: its own page 0, the file's page 2: {:?}", b.map(char::from));
        check!(h, at(p, 0) == b'Q' && at(p, 2) == b'Q', "the parent: the file's pages 0 and 2");
        for f in [go[0], go[1], done[0], done[1]] {
            libc::close(f);
        }
    }

    // Truncated under the mapping and grown back.
    unsafe { *pg(p, 2) = b'c' };
    check!(h, unsafe { libc::ftruncate(fd, 100) } == 0, "ftruncate to 100");
    check!(h, unsafe { *p.add(200) } == 0, "the tail of the page holding the end reads zero");
    check!(h, read_in_child(pg(p, 2)).is_none(), "a written page cut off is SIGBUS");
    check!(h, unsafe { libc::ftruncate(fd, 4 * PAGE as i64) } == 0, "ftruncate back to 4 pages");
    pwrite1(fd, b'G', 3 * PAGE);
    check!(h, at(p, 2) == 0, "grown back, the cut-off store is gone: {:#x}", at(p, 2));
    check!(h, at(p, 3) == b'G', "and a pwrite shows: {:?}", at(p, 3) as char);
    unsafe { libc::munmap(p.cast(), 4 * PAGE) };
    unsafe { libc::close(fd) };
}

fn shared_checks(h: &mut Harness, path: &CString) {
    let fd = file_with(path, 2 * PAGE);
    let p = map(fd, 2, libc::MAP_SHARED);
    unsafe { *pg(p, 0) = b's' };
    check!(h, pread1(fd, 0) == b's', "a shared store reaches read(2)");
    pwrite1(fd, b'P', PAGE);
    check!(h, at(p, 1) == b'P', "a pwrite reaches the shared mapping");
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            *pg(p, 1) = b'k';
            libc::_exit(0);
        }
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    check!(h, at(p, 1) == b'k', "a child's shared store reaches the parent");
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(fd, &mut st) };
    let lines = maps_lines(p, 2 * PAGE);
    let want = format!("{:02x}:{:02x} {}", libc::major(st.st_dev), libc::minor(st.st_dev), st.st_ino);
    check!(h, lines.len() == 1 && lines[0].contains(&want), "maps names fstat's device and inode {want}: {lines:?}");
    check!(h, unsafe { libc::ftruncate(fd, 100) } == 0, "ftruncate to 100");
    check!(h, read_in_child(pg(p, 1)).is_none(), "a shared page cut off is SIGBUS");
    check!(h, unsafe { *p } == b's' && unsafe { *p.add(200) } == 0, "the end page keeps its head and zeroes its tail");
    unsafe { libc::munmap(p.cast(), 2 * PAGE) };
    unsafe { libc::close(fd) };
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp".into());
    let mut h = Harness::new();
    let path = cpath(&format!("{dir}/mm_file_follow.f"));
    h.group("private: file");
    private_checks(&mut h, &path);
    unsafe { libc::unlink(path.as_ptr()) };

    let mnt = cpath(&format!("{dir}/mm_file_follow.tmpfs"));
    unsafe { libc::mkdir(mnt.as_ptr(), 0o755) };
    let mounted = unsafe { libc::mount(c"none".as_ptr(), mnt.as_ptr(), c"tmpfs".as_ptr(), 0, std::ptr::null()) } == 0;
    check!(h, mounted, "mount a tmpfs: errno {}", guest_tests::sys::errno());
    if mounted {
        let path = cpath(&format!("{dir}/mm_file_follow.tmpfs/f"));
        h.group("private: tmpfs");
        private_checks(&mut h, &path);
        h.group("shared: tmpfs");
        shared_checks(&mut h, &path);
        unsafe { libc::unlink(path.as_ptr()) };
        unsafe { libc::umount(mnt.as_ptr()) };
    }
    unsafe { libc::rmdir(mnt.as_ptr()) };
    std::process::exit(h.finish());
}
