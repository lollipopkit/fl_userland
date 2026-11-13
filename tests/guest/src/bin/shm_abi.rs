//! POSIX shared memory and named semaphores, which are files under `/dev/shm`.
//!
//! `shm_open` is `open` of `/dev/shm/<name>` in musl and glibc alike, and
//! `sem_open` is a file there too, so a guest without the directory has neither
//! -- Python's `multiprocessing` and PostgreSQL's dynamic shared memory fail at
//! once. The CLI mounts a realfs there since 2026-09-04, and the property that
//! matters is not that the file opens but that a `MAP_SHARED` mapping of it is
//! **one set of pages for every process**: a byte the child stores is the byte
//! the parent loads, with no `msync` between.

use guest_tests::{Harness, check, sys};
use std::ffi::CString;

const NAME: &str = "/iul-shm-abi";

fn main() {
    let mut h = Harness::new();
    h.group("the directory");

    let st = std::fs::metadata("/dev/shm");
    check!(h, st.is_ok(), "/dev/shm exists: {:?}", st.as_ref().err());
    if let Ok(st) = &st {
        check!(h, st.is_dir(), "and is a directory");
        let mode = std::os::unix::fs::PermissionsExt::mode(&st.permissions()) & 0o7777;
        check!(h, mode == 0o1777, "with mode 1777, sticky and world-writable: {mode:o}");
    }

    h.group("shared memory");
    let name = CString::new(NAME).unwrap();
    unsafe { libc::shm_unlink(name.as_ptr()) };
    let fd = unsafe { libc::shm_open(name.as_ptr(), libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o600) };
    check!(h, fd >= 0, "shm_open(O_CREAT|O_EXCL) works: {}", sys::errno());
    if fd >= 0 {
        let r = unsafe { libc::ftruncate(fd, 4096) };
        check!(h, r == 0, "ftruncate sizes it: {}", sys::errno());
        let again = unsafe { libc::shm_open(name.as_ptr(), libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o600) };
        check!(h, again < 0 && sys::errno() == libc::EEXIST, "a second O_EXCL create is EEXIST: {again} {}", sys::errno());

        let p = unsafe {
            libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0)
        };
        check!(h, p != libc::MAP_FAILED, "mmap(MAP_SHARED) of it works: {}", sys::errno());
        if p != libc::MAP_FAILED {
            let word = p.cast::<u32>();
            unsafe { word.write_volatile(1) };

            // A child that inherits the mapping stores through it.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                unsafe { word.write_volatile(0xC0FFEE) };
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            let seen = unsafe { word.read_volatile() };
            check!(h, seen == 0xC0FFEE, "the parent sees the child's store through the inherited mapping: {seen:#x}");

            // A child that opens the name afresh -- what an unrelated process
            // does -- maps the same pages.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                let fd2 = unsafe { libc::shm_open(name.as_ptr(), libc::O_RDWR, 0) };
                if fd2 < 0 {
                    unsafe { libc::_exit(2) };
                }
                let q = unsafe {
                    libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd2, 0)
                };
                if q == libc::MAP_FAILED {
                    unsafe { libc::_exit(3) };
                }
                let before = unsafe { q.cast::<u32>().read_volatile() };
                unsafe { q.cast::<u32>().write_volatile(0xBEEF) };
                unsafe { libc::_exit(if before == 0xC0FFEE { 0 } else { 4 }) };
            }
            unsafe { libc::waitpid(pid, &mut status, 0) };
            check!(
                h,
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "a fresh open in another process sees the same pages: exit {}",
                libc::WEXITSTATUS(status)
            );
            let seen = unsafe { word.read_volatile() };
            check!(h, seen == 0xBEEF, "and its store is visible here: {seen:#x}");
            unsafe { libc::munmap(p, 4096) };
        }
        unsafe { libc::close(fd) };
    }
    let r = unsafe { libc::shm_unlink(name.as_ptr()) };
    check!(h, r == 0, "shm_unlink removes it: {}", sys::errno());
    let gone = unsafe { libc::shm_open(name.as_ptr(), libc::O_RDWR, 0) };
    check!(h, gone < 0 && sys::errno() == libc::ENOENT, "and it is ENOENT afterwards: {gone} {}", sys::errno());

    h.group("as an ordinary user");
    // What PostgreSQL's `initdb` does: a process that is not root makes a
    // segment and sizes it. The first `/dev/shm` here was a realfs, which
    // reported the host's ownership, so the file belonged to someone else
    // the moment it was made and its own `ftruncate` was refused.
    {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            if unsafe { libc::setgid(1000) } != 0 || unsafe { libc::setuid(1000) } != 0 {
                unsafe { libc::_exit(10) };
            }
            let name = CString::new("/iul-shm-user").unwrap();
            unsafe { libc::shm_unlink(name.as_ptr()) };
            let fd = unsafe { libc::shm_open(name.as_ptr(), libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o600) };
            if fd < 0 {
                unsafe { libc::_exit(11) };
            }
            let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
            unsafe { libc::fstat(fd, st.as_mut_ptr()) };
            if unsafe { st.assume_init() }.st_uid != 1000 {
                unsafe { libc::_exit(12) };
            }
            if unsafe { libc::ftruncate(fd, 8192) } != 0 {
                unsafe { libc::_exit(13) };
            }
            // Reopened by name, as a second process would.
            let again = unsafe { libc::shm_open(name.as_ptr(), libc::O_RDWR, 0) };
            if again < 0 {
                unsafe { libc::_exit(14) };
            }
            let p = unsafe {
                libc::mmap(std::ptr::null_mut(), 8192, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, again, 0)
            };
            if p == libc::MAP_FAILED {
                unsafe { libc::_exit(15) };
            }
            unsafe { p.cast::<u32>().write_volatile(1) };
            if unsafe { libc::shm_unlink(name.as_ptr()) } != 0 {
                unsafe { libc::_exit(16) };
            }
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        check!(
            h,
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "uid 1000 can make, own, size, map and unlink a segment: exit {}",
            libc::WEXITSTATUS(status)
        );
    }

    h.group("named semaphores");
    let sname = CString::new("/iul-sem-abi").unwrap();
    unsafe { libc::sem_unlink(sname.as_ptr()) };
    let sem = unsafe { libc::sem_open(sname.as_ptr(), libc::O_CREAT | libc::O_EXCL, 0o600, 0u32) };
    check!(h, sem != libc::SEM_FAILED, "sem_open(O_CREAT) works: {}", sys::errno());
    if sem != libc::SEM_FAILED {
        // The child posts; the parent waits. A semaphore that was not shared
        // would leave the parent waiting for ever, which the alarm turns into
        // a failure rather than a hang.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let mine = unsafe { libc::sem_open(sname.as_ptr(), 0) };
            if mine == libc::SEM_FAILED {
                unsafe { libc::_exit(2) };
            }
            unsafe { libc::sem_post(mine) };
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::alarm(10) };
        let r = unsafe { libc::sem_wait(sem) };
        unsafe { libc::alarm(0) };
        check!(h, r == 0, "sem_wait returns once the child has posted: {r} {}", sys::errno());
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        check!(h, libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "the child opened it: exit {}", libc::WEXITSTATUS(status));
        let mut value = -1;
        unsafe { libc::sem_getvalue(sem, &mut value) };
        check!(h, value == 0, "and the count is back to zero: {value}");
        unsafe { libc::sem_close(sem) };
    }
    let r = unsafe { libc::sem_unlink(sname.as_ptr()) };
    check!(h, r == 0, "sem_unlink removes it: {}", sys::errno());

    std::process::exit(h.finish());
}
