//! Every `fcntl` command this kernel answers, and what it answers for one it
//! does not.
//!
//! The command numbers *are* the interface — a wrong one is a request silently
//! answered by the wrong arm — and nothing checked them against a guest libc
//! until this. `crates/kernel/fdcalls` writes them out because there is nothing
//! to generate them from: `fs/fd.c` spelled them as `#define`s of its own, and
//! the host's `<fcntl.h>` disagrees (macOS `F_GETPATH` is 50, where Linux's 50
//! is nothing at all).
//!
//! Three of the checks here are for defects the C had:
//!
//! - `F_DUPFD` with a nonsense minimum answered `EMFILE` — "close something and
//!   retry", which a caller that passed -1 will do for ever. Linux's `f_dupfd`
//!   bounds `from` against `RLIMIT_NOFILE` and `from` is *unsigned*, so -1 is a
//!   very large number.
//! - `F_SETLKW` never blocked, because the two arms that implement it each
//!   tested the *other* one's command number.
//! - The OFD locks were `EINVAL`, and SQLite asks for them by preference.

use guest_tests::{Harness, check, cpath};

const F_OFD_GETLK: i32 = 36;
const F_OFD_SETLK: i32 = 37;
const F_SETPIPE_SZ: i32 = 1031;
const F_GETPIPE_SZ: i32 = 1032;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn main() {
    let mut h = Harness::new();
    let path = "/tmp/fcntl_abi_file";
    std::fs::write(path, b"0123456789abcdef").expect("write the fixture");
    let fd = unsafe { libc::open(cpath(path).as_ptr(), libc::O_RDWR) };
    check!(h, fd >= 0, "opening the fixture: fd={fd}");
    if fd < 0 {
        std::process::exit(h.finish());
    }

    h.group("dupfd");
    {
        let d = unsafe { libc::fcntl(fd, libc::F_DUPFD, 100) };
        check!(h, d >= 100, "F_DUPFD honours the minimum: {d}");
        check!(
            h,
            unsafe { libc::fcntl(d, libc::F_GETFD) } == 0,
            "and the copy is not close-on-exec"
        );
        unsafe { libc::close(d) };

        let c = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 100) };
        check!(h, c >= 100, "F_DUPFD_CLOEXEC honours the minimum: {c}");
        check!(
            h,
            unsafe { libc::fcntl(c, libc::F_GETFD) } == libc::FD_CLOEXEC,
            "and the copy is close-on-exec: {}",
            unsafe { libc::fcntl(c, libc::F_GETFD) }
        );
        unsafe { libc::close(c) };

        // The minimum is unsigned, so -1 is the top of the register.
        let bad = unsafe { libc::fcntl(fd, libc::F_DUPFD, -1) };
        check!(
            h,
            bad == -1 && errno() == libc::EINVAL,
            "F_DUPFD with -1 is EINVAL, not EMFILE: r={bad} errno={}",
            errno()
        );
        let huge = unsafe { libc::fcntl(fd, libc::F_DUPFD, 1 << 30) };
        check!(
            h,
            huge == -1 && errno() == libc::EINVAL,
            "F_DUPFD past the limit is EINVAL: r={huge} errno={}",
            errno()
        );
    }

    h.group("fd-flags");
    {
        check!(h, unsafe { libc::fcntl(fd, libc::F_GETFD) } == 0, "F_GETFD starts clear");
        check!(
            h,
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
            "F_SETFD accepts FD_CLOEXEC"
        );
        check!(
            h,
            unsafe { libc::fcntl(fd, libc::F_GETFD) } == libc::FD_CLOEXEC,
            "and F_GETFD reads it back"
        );
        check!(
            h,
            unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } == 0,
            "F_SETFD clears it again"
        );
        check!(h, unsafe { libc::fcntl(fd, libc::F_GETFD) } == 0, "and it is clear");
    }

    h.group("file-flags");
    {
        let before = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        check!(
            h,
            before & libc::O_ACCMODE == libc::O_RDWR,
            "F_GETFL reports the access mode: {before:#o}"
        );
        check!(
            h,
            before & libc::O_NONBLOCK == 0,
            "and the descriptor is blocking"
        );
        check!(
            h,
            unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } == 0,
            "F_SETFL sets O_NONBLOCK"
        );
        let after = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        check!(h, after & libc::O_NONBLOCK != 0, "and it reads back: {after:#o}");
        // The access mode is not settable, and F_SETFL must not have cleared
        // it: a descriptor that forgot it was writable fails every later write.
        check!(
            h,
            after & libc::O_ACCMODE == libc::O_RDWR,
            "and the access mode survives F_SETFL: {after:#o}"
        );
        unsafe { libc::fcntl(fd, libc::F_SETFL, 0) };
        check!(
            h,
            unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK == 0,
            "F_SETFL clears it again"
        );
    }

    h.group("record-locks");
    {
        let mut lock = libc::flock {
            l_type: libc::F_WRLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: 4,
            l_pid: 0,
        };
        check!(
            h,
            unsafe { libc::fcntl(fd, libc::F_SETLK, &lock) } == 0,
            "F_SETLK takes a write lock: errno={}",
            errno()
        );
        // The same process asking about its own lock is told the region is
        // free -- F_GETLK reports a *conflicting* lock, and a lock never
        // conflicts with its own owner.
        let mut query = libc::flock {
            l_type: libc::F_WRLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: 4,
            l_pid: 0,
        };
        check!(
            h,
            unsafe { libc::fcntl(fd, libc::F_GETLK, &mut query) } == 0,
            "F_GETLK answers: errno={}",
            errno()
        );
        check!(
            h,
            query.l_type == libc::F_UNLCK as i16,
            "and reports no conflict with the caller's own lock: {}",
            query.l_type
        );
        lock.l_type = libc::F_UNLCK as i16;
        check!(
            h,
            unsafe { libc::fcntl(fd, libc::F_SETLK, &lock) } == 0,
            "F_SETLK releases it"
        );
    }

    h.group("ofd-locks");
    {
        // The owner is the open file description, so a second open of the same
        // file contends with the first where a second descriptor for the same
        // description would not.
        let other = unsafe { libc::open(cpath(path).as_ptr(), libc::O_RDWR) };
        check!(h, other >= 0, "a second open: {other}");
        let lock = libc::flock {
            l_type: libc::F_WRLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: 4,
            l_pid: 0,
        };
        let set = unsafe { libc::fcntl(fd, F_OFD_SETLK, &lock) };
        check!(h, set == 0, "F_OFD_SETLK is answered: r={set} errno={}", errno());

        let mut query = libc::flock {
            l_type: libc::F_WRLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: 4,
            l_pid: 0,
        };
        let got = unsafe { libc::fcntl(other, F_OFD_GETLK, &mut query) };
        check!(h, got == 0, "F_OFD_GETLK is answered: r={got} errno={}", errno());
        check!(
            h,
            query.l_type == libc::F_WRLCK as i16,
            "and the other description sees the conflict: {}",
            query.l_type
        );

        let unlock = libc::flock {
            l_type: libc::F_UNLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: 4,
            l_pid: 0,
        };
        unsafe { libc::fcntl(fd, F_OFD_SETLK, &unlock) };
        unsafe { libc::close(other) };
    }

    h.group("pipe-size");
    {
        let mut p = [0i32; 2];
        check!(h, unsafe { libc::pipe(p.as_mut_ptr()) } == 0, "a pipe");
        let size = unsafe { libc::fcntl(p[0], F_GETPIPE_SZ) };
        check!(h, size > 0, "F_GETPIPE_SZ answers a size: {size}");
        let set = unsafe { libc::fcntl(p[0], F_SETPIPE_SZ, 1 << 16) };
        check!(h, set > 0, "F_SETPIPE_SZ answers the new size: {set}");
        check!(
            h,
            unsafe { libc::fcntl(p[0], F_GETPIPE_SZ) } == set,
            "and F_GETPIPE_SZ agrees"
        );
        // EBADF, not EINVAL, and the difference is the point: Linux routes
        // both commands into pipe_fcntl, which answers EBADF for a descriptor
        // that is not a pipe. It is a strange answer for a descriptor that is
        // open, which is why a program probing its pipe facilities reads it --
        // EINVAL would say "known command, bad argument". This answered EINVAL
        // and differential.sh is what said so.
        let on_file = unsafe { libc::fcntl(fd, F_GETPIPE_SZ) };
        check!(
            h,
            on_file == -1 && errno() == libc::EBADF,
            "F_GETPIPE_SZ on a regular file is EBADF: r={on_file} errno={}",
            errno()
        );
        let set_on_file = unsafe { libc::fcntl(fd, F_SETPIPE_SZ, 1 << 16) };
        check!(
            h,
            set_on_file == -1 && errno() == libc::EBADF,
            "and so is F_SETPIPE_SZ: r={set_on_file} errno={}",
            errno()
        );
        unsafe { libc::close(p[0]) };
        unsafe { libc::close(p[1]) };
    }

    h.group("refusals");
    {
        // A command nobody implements. 9999 is not any Linux fcntl.
        let unknown = unsafe { libc::fcntl(fd, 9999, 0) };
        check!(
            h,
            unknown == -1 && errno() == libc::EINVAL,
            "an unknown command is EINVAL: r={unknown} errno={}",
            errno()
        );
        // A bad descriptor is answered before the command is looked at, so a
        // bad descriptor *and* an unknown command is EBADF and not EINVAL.
        let bad = unsafe { libc::fcntl(4096, 9999, 0) };
        check!(
            h,
            bad == -1 && errno() == libc::EBADF,
            "a bad descriptor beats an unknown command: r={bad} errno={}",
            errno()
        );
        let bad_known = unsafe { libc::fcntl(4096, libc::F_GETFD) };
        check!(
            h,
            bad_known == -1 && errno() == libc::EBADF,
            "and a bad descriptor with a known command is EBADF: errno={}",
            errno()
        );
    }

    unsafe { libc::close(fd) };
    let _ = std::fs::remove_file(path);
    std::process::exit(h.finish());
}
