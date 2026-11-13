//! What inotify_add_watch and inotify_rm_watch accept and refuse.
//!
//! Nothing in this emulator generates inotify events, so a watch never fires.
//! That is a gap rather than a lie — but answering with a watch descriptor for
//! a path that does not exist, a pointer that cannot be read or a mask that
//! names no event is a lie, and it is what this used to do.

use guest_tests::{Harness, check, check_fails, cpath};

fn main() -> std::process::ExitCode {
    let mut h = Harness::new();
    h.group("inotify");

    let ifd = unsafe { libc::inotify_init1(0) };
    check!(h, ifd >= 0, "inotify_init1");
    if ifd < 0 {
        return std::process::ExitCode::from(h.finish() as u8);
    }

    let tmp = cpath("/tmp");
    let wd = unsafe { libc::inotify_add_watch(ifd, tmp.as_ptr(), libc::IN_MODIFY) };
    check!(h, wd >= 0, "a watch on a directory that exists: {wd}");

    let missing = cpath("/tmp/definitely-not-here-12345");
    check_fails!(
        h,
        unsafe { libc::inotify_add_watch(ifd, missing.as_ptr(), libc::IN_MODIFY) },
        libc::ENOENT,
        "a watch on a path that does not exist"
    );

    check_fails!(
        h,
        unsafe { libc::inotify_add_watch(ifd, 0x10 as *const libc::c_char, libc::IN_MODIFY) },
        libc::EFAULT,
        "a watch on an unreadable pointer"
    );

    check_fails!(
        h,
        unsafe { libc::inotify_add_watch(ifd, tmp.as_ptr(), 0) },
        libc::EINVAL,
        "a watch whose mask names no event"
    );

    check_fails!(
        h,
        unsafe { libc::inotify_rm_watch(ifd, wd + 1000) },
        libc::EINVAL,
        "removing a watch descriptor that was never handed out"
    );
    check!(
        h,
        unsafe { libc::inotify_rm_watch(ifd, wd) } == 0,
        "removing the one that was"
    );

    // Not an inotify descriptor at all.
    let f = unsafe { libc::open(tmp.as_ptr(), libc::O_RDONLY) };
    if f >= 0 {
        check_fails!(
            h,
            unsafe { libc::inotify_add_watch(f, tmp.as_ptr(), libc::IN_MODIFY) },
            libc::EINVAL,
            "a watch on a descriptor that is not an inotify"
        );
        unsafe { libc::close(f) };
    }

    // A non-blocking read has nothing to report and must say so rather than
    // block: no events are ever generated.
    let nb = unsafe { libc::inotify_init1(libc::IN_NONBLOCK) };
    if nb >= 0 {
        let mut buf = [0u8; 256];
        check_fails!(
            h,
            unsafe { libc::read(nb, buf.as_mut_ptr().cast(), buf.len()) },
            libc::EAGAIN,
            "a non-blocking read with no events pending"
        );
        unsafe { libc::close(nb) };
    }

    unsafe { libc::close(ifd) };
    std::process::ExitCode::from(h.finish() as u8)
}
