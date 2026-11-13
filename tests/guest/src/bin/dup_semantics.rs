//! `dup`, `dup2` and `dup3`, and the case where the two numbers are the same.
//!
//! `dup2(f, f)` is defined to do nothing at all and return `f`. It is not
//! "close f and reinstall it", which is what it looks like and which has
//! observable side effects: closing a descriptor releases the process's record
//! locks on that file and clears its close-on-exec bit.
//!
//! `dup3(f, f, flags)` is the opposite -- `EINVAL`, always, whatever the flags
//! say and even when `f` is a perfectly good descriptor. That is the one
//! difference between `dup2` and `dup3` beyond the flags argument.

use guest_tests::{Harness, check, cpath};

fn cloexec(fd: i32) -> i32 {
    unsafe { libc::fcntl(fd, libc::F_GETFD) }
}

fn main() {
    let mut h = Harness::new();
    let path = "/tmp/dup_semantics_file";
    std::fs::write(path, b"0123456789").expect("write the fixture");

    h.group("dup");
    let fd = unsafe { libc::open(cpath(path).as_ptr(), libc::O_RDWR) };
    check!(h, fd >= 0, "opening the fixture: fd={fd}");
    if fd < 0 {
        std::process::exit(h.finish());
    }
    let d = unsafe { libc::dup(fd) };
    check!(h, d >= 0 && d != fd, "dup gives a new number: d={d}");
    check!(h, cloexec(d) == 0, "and the copy is not close-on-exec: {}", cloexec(d));
    // One description, so one offset.
    unsafe { libc::lseek(fd, 4, libc::SEEK_SET) };
    let at = unsafe { libc::lseek(d, 0, libc::SEEK_CUR) };
    check!(h, at == 4, "the copy shares the offset: {at}");
    unsafe { libc::close(d) };
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };

    h.group("dup2-onto-itself");
    // The close-on-exec bit is set first, because "close and reinstall" clears
    // it and returning the number is not enough to notice.
    check!(h, unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
        "setting close-on-exec");
    check!(h, cloexec(fd) == libc::FD_CLOEXEC, "which took: {}", cloexec(fd));
    let same = unsafe { libc::dup2(fd, fd) };
    check!(h, same == fd, "dup2(f, f) returns f: {same}");
    check!(h, cloexec(fd) == libc::FD_CLOEXEC,
        "and leaves close-on-exec alone: {}", cloexec(fd));
    // Still usable, which it would not be if the slot had been emptied.
    let mut buf = [0u8; 4];
    let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), 4, 0) };
    check!(h, n == 4 && &buf == b"0123", "and the descriptor still reads: n={n}");
    unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };

    h.group("dup2-onto-itself-keeps-locks");
    // A record lock belongs to the process and is dropped when *any* descriptor
    // for the file is closed. So a dup2 implemented as close-and-reinstall
    // silently unlocks the file, and nothing about the call reports it.
    //
    // The probe is a second descriptor for the same file: the lock is only
    // visible to F_GETLK through a description that does not own it.
    let mut lk = libc::flock {
        l_type: libc::F_WRLCK as i16,
        l_whence: libc::SEEK_SET as i16,
        l_start: 0,
        l_len: 4,
        l_pid: 0,
    };
    let locked = unsafe { libc::fcntl(fd, libc::F_SETLK, &lk) };
    check!(h, locked == 0, "taking a write lock: {locked}");

    let same2 = unsafe { libc::dup2(fd, fd) };
    check!(h, same2 == fd, "dup2(f, f) over a locked descriptor returns f: {same2}");

    // Whether the lock survived, asked from a different process: within one
    // process every lock looks grantable, so asking here would pass either way.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let child_fd = unsafe { libc::open(cpath(path).as_ptr(), libc::O_RDWR) };
        let probe = libc::flock {
            l_type: libc::F_WRLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: 4,
            l_pid: 0,
        };
        let got = unsafe { libc::fcntl(child_fd, libc::F_SETLK, &probe) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        // 0 means the parent's lock is gone.
        let held = got == -1 && (e == libc::EACCES || e == libc::EAGAIN);
        unsafe { libc::close(child_fd) };
        std::process::exit(if held { 0 } else { 1 });
    }
    check!(h, pid > 0, "forking a prober: pid={pid}");
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let held = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    check!(h, held, "and the record lock survived it: status={status}");

    lk.l_type = libc::F_UNLCK as i16;
    unsafe { libc::fcntl(fd, libc::F_SETLK, &lk) };

    h.group("dup3-onto-itself");
    // Not a no-op and not a success: dup3 refuses the same-number case
    // outright, which is how a caller distinguishes the two calls.
    for flags in [0, libc::O_CLOEXEC] {
        let r = unsafe { libc::syscall(libc::SYS_dup3, fd, fd, flags) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        check!(h, r == -1 && e == libc::EINVAL,
            "dup3(f, f, {flags:#x}) is EINVAL: r={r} errno={e}");
    }
    check!(h, cloexec(fd) == 0, "and changed nothing: {}", cloexec(fd));

    h.group("dup3-flags");
    let target = 200;
    let r = unsafe { libc::syscall(libc::SYS_dup3, fd, target, libc::O_CLOEXEC) };
    check!(h, r == target as i64, "dup3 with O_CLOEXEC: r={r}");
    check!(h, cloexec(target) == libc::FD_CLOEXEC,
        "sets close-on-exec on the copy: {}", cloexec(target));
    unsafe { libc::close(target) };

    let r = unsafe { libc::syscall(libc::SYS_dup3, fd, target, 0) };
    check!(h, r == target as i64, "dup3 without it: r={r}");
    check!(h, cloexec(target) == 0, "leaves the copy clear: {}", cloexec(target));
    unsafe { libc::close(target) };

    // Every flag that is not O_CLOEXEC. Linux takes O_CLOEXEC only; a flag word
    // it does not know is EINVAL rather than quietly ignored, which is how a
    // caller finds out the descriptor is not what it asked for.
    for bad in [libc::O_NONBLOCK, libc::O_APPEND, libc::O_DIRECT, 1 << 30] {
        let r = unsafe { libc::syscall(libc::SYS_dup3, fd, target, bad) };
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        check!(h, r == -1 && e == libc::EINVAL,
            "dup3 with {bad:#x} is EINVAL: r={r} errno={e}");
        if r >= 0 {
            unsafe { libc::close(target) };
        }
    }

    h.group("dup2-above-the-limit");
    // A number at or above RLIMIT_NOFILE. Reached through open() the same
    // condition is EMFILE -- "no more descriptors" -- but dup2 is asking for a
    // *particular* number and that number is not one this process may have, so
    // Linux answers EBADF. The two errnos come from one check in this kernel
    // and it reported the open() one for both.
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    check!(h, unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0, "the descriptor limit");
    let over = lim.rlim_cur as i32;
    let r = unsafe { libc::syscall(libc::SYS_dup3, fd, over, 0) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::EBADF,
        "dup3 to the limit itself is EBADF: r={r} errno={e} limit={over}");
    let r = unsafe { libc::dup2(fd, over + 16) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::EBADF,
        "and dup2 past it: r={r} errno={e}");

    h.group("dup2-bad-numbers");
    let r = unsafe { libc::dup2(fd, -1) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::EBADF, "dup2 to a negative number: r={r} errno={e}");
    let r = unsafe { libc::dup2(9999, 300) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::EBADF, "dup2 from a closed number: r={r} errno={e}");
    // The same-number case with a *bad* number is EBADF, not the no-op: the
    // descriptor is checked first.
    let r = unsafe { libc::dup2(9999, 9999) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    check!(h, r == -1 && e == libc::EBADF, "dup2(bad, bad) is EBADF: r={r} errno={e}");

    unsafe { libc::close(fd) };
    let _ = std::fs::remove_file(path);
    std::process::exit(h.finish());
}
