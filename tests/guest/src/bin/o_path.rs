//! `O_PATH`: a descriptor that names a file rather than opening it.
//!
//! > obtain a file descriptor that can be used for two purposes: to indicate a
//! > location in the filesystem tree and to perform operations that act purely
//! > at the file descriptor level.
//!
//! There is no permission to check on the object itself — only search
//! permission on the directories leading to it — and nothing is opened behind
//! it: a device node yields a reference to the *node*, not to the device. In
//! exchange, reading or writing through it is `EBADF`. That is not `EACCES`:
//! the descriptor is not one you can do this with, whatever your permissions.
//!
//! The flag was defined here and never looked at, so `open(x, O_PATH)` behaved
//! like an ordinary open and answered `EACCES` for a file the caller could not
//! read. That is the wrong way round for a caller that only wants to name the
//! file — systemd, container runtimes and Go's `os.Root` all do — and it is a
//! refusal a program cannot work around, because the point of the flag is that
//! it needs no permission.
//!
//! # `O_PATH | O_NOFOLLOW`
//!
//! It names the **symlink itself**, which is how Go's `os.Root`, systemd and
//! every container runtime walk a tree without following a link out of it. It
//! was `ELOOP` here until 2026-09-03, on the grounds that the mount's `open`
//! would have to open a symlink and `realfs` had no portable way to ask a host
//! for one — Darwin has `O_SYMLINK`, which is exactly that.
//!
//! The check below used to accept **either** answer, so that it would pass
//! whichever way the kernel behaved. That is a check about nothing: it asserts
//! the descriptor now, and that it still cannot be read through.

use guest_tests::{Harness, check, sys};

use std::ffi::CString;

const O_PATH: i32 = 0o10_000_000;

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn setfsuid(uid: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_setfsuid, uid as libc::c_long) as i64 }
}

const DIR: &str = "/tmp/o_path_scratch";

fn main() {
    let mut h = Harness::new();
    let start = setfsuid(u32::MAX) as u32;
    let _ = std::fs::remove_dir_all(DIR);
    unsafe {
        libc::mkdir(cs(DIR).as_ptr(), 0o777);
        libc::chmod(cs(DIR).as_ptr(), 0o777);
    }

    // A file with nothing granted to anyone else.
    let secret = format!("{DIR}/secret");
    unsafe {
        let f = libc::open(cs(&secret).as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600);
        if f >= 0 {
            libc::write(f, c"hunter2".as_ptr().cast(), 7);
            libc::close(f);
        }
        libc::symlink(cs(&secret).as_ptr(), cs(&format!("{DIR}/link")).as_ptr());
    }
    let mut sst: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::stat(cs(&secret).as_ptr(), &mut sst) };
    let stranger = sst.st_uid + 11;
    setfsuid(stranger);

    h.group("it-needs-no-permission-on-the-file");
    let r = unsafe { libc::open(cs(&secret).as_ptr(), libc::O_RDONLY) };
    check!(
        h,
        r < 0 && sys::errno() == libc::EACCES,
        "an ordinary open of it is refused: r={r} errno={}",
        sys::errno()
    );
    if r >= 0 {
        unsafe { libc::close(r) };
    }
    sys::clear_errno();
    let p = unsafe { libc::open(cs(&secret).as_ptr(), O_PATH) };
    check!(h, p >= 0, "O_PATH opens it anyway: p={p} errno={}", sys::errno());

    if p >= 0 {
        h.group("but-nothing-can-be-read-through-it");
        let mut buf = [0u8; 8];
        sys::clear_errno();
        let n = unsafe { libc::read(p, buf.as_mut_ptr().cast(), 8) };
        check!(
            h,
            n < 0 && sys::errno() == libc::EBADF,
            "read() is EBADF, not EACCES and not the contents: n={n} errno={} bytes={:?}",
            sys::errno(),
            &buf[..n.max(0) as usize]
        );
        sys::clear_errno();
        let n = unsafe { libc::write(p, c"x".as_ptr().cast(), 1) };
        check!(h, n < 0 && sys::errno() == libc::EBADF, "write() is EBADF: n={n}");
        sys::clear_errno();
        let n = unsafe { libc::pread(p, buf.as_mut_ptr().cast(), 8, 0) };
        check!(h, n < 0 && sys::errno() == libc::EBADF, "pread() is EBADF: n={n}");
        sys::clear_errno();
        let n = unsafe { libc::pwrite(p, c"x".as_ptr().cast(), 1, 0) };
        check!(h, n < 0 && sys::errno() == libc::EBADF, "pwrite() is EBADF: n={n}");

        h.group("what-it-is-for");
        // fstat works: this is how a caller learns about a file it may not read.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::fstat(p, &mut st) };
        check!(h, r == 0, "fstat() through it works: r={r}");
        check!(h, st.st_mode & 0o777 == 0o600, "and reports the mode: {:o}", st.st_mode & 0o777);
        check!(h, st.st_size == 7, "and the size: {}", st.st_size);
        // And it can be duplicated, which is a descriptor-level operation.
        let d = unsafe { libc::dup(p) };
        check!(h, d >= 0, "dup() works: d={d}");
        if d >= 0 {
            unsafe { libc::close(d) };
        }
        unsafe { libc::close(p) };
    }

    h.group("a-directory-held-open-as-a-base");
    // The other half of what it is for: an O_PATH descriptor for a directory,
    // used as the `dirfd` of an `*at` call.
    sys::clear_errno();
    let d = unsafe { libc::open(cs(DIR).as_ptr(), O_PATH | libc::O_DIRECTORY) };
    check!(h, d >= 0, "O_PATH|O_DIRECTORY on a directory: d={d} errno={}", sys::errno());
    if d >= 0 {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        sys::clear_errno();
        let r = unsafe { libc::fstatat(d, c"secret".as_ptr(), &mut st, 0) };
        check!(
            h,
            r == 0,
            "fstatat through it finds the file: r={r} errno={}",
            sys::errno()
        );
        check!(h, st.st_size == 7, "with the right size: {}", st.st_size);
        unsafe { libc::close(d) };
    }
    // O_PATH ignores the access mode, so a directory opened for writing is not
    // EISDIR -- there is nothing to write through.
    sys::clear_errno();
    let d = unsafe { libc::open(cs(DIR).as_ptr(), O_PATH | libc::O_RDWR) };
    check!(
        h,
        d >= 0,
        "O_PATH ignores the access mode, so a directory is not EISDIR: d={d} errno={}",
        sys::errno()
    );
    if d >= 0 {
        unsafe { libc::close(d) };
    }
    // And O_DIRECTORY still means what it says.
    sys::clear_errno();
    let r = unsafe { libc::open(cs(&secret).as_ptr(), O_PATH | libc::O_DIRECTORY) };
    check!(
        h,
        r < 0 && sys::errno() == libc::ENOTDIR,
        "O_PATH|O_DIRECTORY on a file is ENOTDIR: r={r} errno={}",
        sys::errno()
    );
    if r >= 0 {
        unsafe { libc::close(r) };
    }

    h.group("the-symlink-case");
    // A descriptor for the link itself. See this file's header for what it is
    // for and why the check no longer accepts a refusal as well.
    sys::clear_errno();
    let r = unsafe { libc::open(cs(&format!("{DIR}/link")).as_ptr(), O_PATH | libc::O_NOFOLLOW) };
    check!(h, r >= 0, "O_PATH|O_NOFOLLOW names the symlink: r={r} errno={}", sys::errno());
    if r >= 0 {
        // It must still not be readable: an O_PATH descriptor is a name and
        // not access, and a symlink's contents come from `readlink`.
        let mut buf = [0u8; 8];
        sys::clear_errno();
        let n = unsafe { libc::read(r, buf.as_mut_ptr().cast(), 8) };
        check!(h, n < 0, "a symlink named by O_PATH cannot be read through: n={n}");
        // And it is the *link*, not its target: `fstat` says so.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let ok = unsafe { libc::fstat(r, &mut st) };
        check!(
            h,
            ok == 0 && st.st_mode & libc::S_IFMT == libc::S_IFLNK,
            "the descriptor is the link: fstat={ok} mode={:#o}",
            st.st_mode
        );
        unsafe { libc::close(r) };
    }
    // Without O_PATH it is still ELOOP, which is Linux's rule: the two flags
    // only name a symlink together.
    sys::clear_errno();
    let r = unsafe { libc::open(cs(&format!("{DIR}/link")).as_ptr(), libc::O_NOFOLLOW) };
    check!(
        h,
        r < 0 && sys::errno() == libc::ELOOP,
        "O_NOFOLLOW alone still refuses a symlink: r={r} errno={}",
        sys::errno()
    );
    if r >= 0 {
        unsafe { libc::close(r) };
    }

    setfsuid(start);
    let _ = std::fs::remove_dir_all(DIR);
    std::process::exit(h.finish());
}
