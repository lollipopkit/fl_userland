//! `O_TMPFILE` on every mount type: what `tmpfile_probe` measured on a real
//! arm64 kernel, asserted. `tmpfile <dir> [realfs]` runs it in `dir`, which
//! it makes and removes; `tmpfile tmpfs` mounts a tmpfs to run it in.
//!
//! realfs cannot keep the inode when the file is named -- the name is a
//! copy, see `crates/fs/realfs`'s `unnamed` -- which is the one thing not
//! asserted there.

use std::ffi::CString;

use guest_tests::{Harness, check};

const AT_EMPTY_PATH: i32 = 0x1000;
const AT_SYMLINK_FOLLOW: i32 = 0x400;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn tmpfile(dir: &str, flags: i32, mode: u32) -> i32 {
    unsafe { libc::open(c(dir).as_ptr(), libc::O_TMPFILE | flags, mode) }
}

fn entries(dir: &str) -> usize {
    std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(usize::MAX)
}

fn fstat(fd: i32) -> libc::stat {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(fd, &mut st) };
    st
}

fn link_name(fd: i32) -> String {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
}

fn run(h: &mut Harness, dir: &str, keeps_inode: bool) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let empty = entries(dir);

    h.group("an unnamed file");
    let fd = tmpfile(dir, libc::O_RDWR, 0o640);
    check!(h, fd >= 0, "O_TMPFILE|O_RDWR: errno {}", errno());
    let st = fstat(fd);
    check!(h, st.st_mode == libc::S_IFREG | 0o640 && st.st_nlink == 0 && st.st_size == 0,
        "a regular file, mode 0640, no link, empty: {:o} {} {}", st.st_mode, st.st_nlink, st.st_size);
    check!(h, entries(dir) == empty, "no directory lists it");
    let name = link_name(fd);
    check!(h, name == format!("{dir}/#{} (deleted)", st.st_ino), "/proc/self/fd: {name}");
    let mut buf = [0u8; 8];
    let (w, r) = unsafe {
        (libc::write(fd, b"hello".as_ptr().cast(), 5), libc::pread(fd, buf.as_mut_ptr().cast(), 8, 0))
    };
    check!(h, w == 5 && r == 5 && &buf[..5] == b"hello", "write and pread back: {w} {r}");

    h.group("naming it");
    let named = format!("{dir}/named");
    let r = unsafe { libc::linkat(fd, c"".as_ptr(), libc::AT_FDCWD, c(&named).as_ptr(), AT_EMPTY_PATH) };
    check!(h, r == 0, "linkat(fd, \"\", AT_EMPTY_PATH): errno {}", errno());
    check!(h, fstat(fd).st_nlink == 1, "one link: {}", fstat(fd).st_nlink);
    check!(h, std::fs::read_to_string(&named).ok().as_deref() == Some("hello"), "the name reads what was written");
    unsafe { libc::pwrite(fd, b"!".as_ptr().cast(), 1, 5) };
    check!(h, std::fs::read_to_string(&named).ok().as_deref() == Some("hello!"), "a write after naming reaches the name");
    if keeps_inode {
        let by_name = std::fs::metadata(&named).map(|m| std::os::unix::fs::MetadataExt::ino(&m)).unwrap_or(0);
        check!(h, by_name == st.st_ino && fstat(fd).st_ino == st.st_ino, "the same inode");
    }
    let second = format!("{dir}/second");
    let r = unsafe { libc::linkat(fd, c"".as_ptr(), libc::AT_FDCWD, c(&second).as_ptr(), AT_EMPTY_PATH) };
    check!(h, r == 0 && std::path::Path::new(&second).exists(), "a second link: errno {}", errno());
    let r = unsafe { libc::linkat(fd, c"".as_ptr(), libc::AT_FDCWD, c(&second).as_ptr(), AT_EMPTY_PATH) };
    check!(h, r < 0 && errno() == libc::EEXIST, "onto a name that exists: EEXIST, got {}", errno());
    unsafe { libc::close(fd) };
    check!(h, entries(dir) == empty + 2, "two names after close: {}", entries(dir));
    check!(h, std::fs::metadata(&named).map(|m| std::os::unix::fs::MetadataExt::nlink(&m)).ok() == Some(2), "and two links");

    h.group("naming through /proc/self/fd");
    let fd = tmpfile(dir, libc::O_WRONLY, 0o600);
    unsafe { libc::write(fd, b"w".as_ptr().cast(), 1) };
    let via = format!("{dir}/via-proc");
    let r = unsafe {
        libc::linkat(libc::AT_FDCWD, c(&format!("/proc/self/fd/{fd}")).as_ptr(), libc::AT_FDCWD, c(&via).as_ptr(), AT_SYMLINK_FOLLOW)
    };
    check!(h, r == 0, "linkat(/proc/self/fd/N, AT_SYMLINK_FOLLOW) of a write-only one: errno {}", errno());
    check!(h, std::fs::read_to_string(&via).ok().as_deref() == Some("w"), "the name reads what was written");
    unsafe { libc::close(fd) };

    h.group("never to be named, or never named");
    let fd = tmpfile(dir, libc::O_RDWR | libc::O_EXCL, 0o600);
    let r = unsafe { libc::linkat(fd, c"".as_ptr(), libc::AT_FDCWD, c(&format!("{dir}/excl")).as_ptr(), AT_EMPTY_PATH) };
    check!(h, r < 0 && errno() == libc::ENOENT, "O_EXCL, then linkat: ENOENT, got {}", errno());
    unsafe { libc::close(fd) };
    let n = entries(dir);
    let fd = tmpfile(dir, libc::O_RDWR, 0o600);
    unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
    unsafe { libc::close(fd) };
    check!(h, entries(dir) == n, "closed unnamed: nothing left");

    h.group("creation rules");
    let old = unsafe { libc::umask(0o027) };
    let fd = tmpfile(dir, libc::O_RDWR, 0o666);
    check!(h, fstat(fd).st_mode & 0o777 == 0o640, "the umask applies: {:o}", fstat(fd).st_mode & 0o777);
    unsafe { libc::close(fd) };
    unsafe { libc::umask(old) };
    let fd = tmpfile(dir, libc::O_RDWR, 0o600);
    let r = unsafe { libc::ftruncate(fd, 4096) };
    check!(h, r == 0 && fstat(fd).st_size == 4096, "ftruncate");
    unsafe { libc::close(fd) };
    let refused = |flags: i32, path: &str, want: i32, what: &str, h: &mut Harness| {
        let r = unsafe { libc::open(c(path).as_ptr(), flags, 0o600) };
        check!(h, r < 0 && errno() == want, "{what}: want {want}, got {r} {}", errno());
    };
    refused(libc::O_TMPFILE | libc::O_RDONLY, dir, libc::EINVAL, "O_TMPFILE|O_RDONLY", h);
    refused(libc::O_TMPFILE | libc::O_RDWR, &named, libc::ENOTDIR, "on a file", h);
    refused(libc::O_TMPFILE | libc::O_RDWR, &format!("{dir}/nope"), libc::ENOENT, "on a missing path", h);
    refused(libc::O_TMPFILE | libc::O_RDWR | libc::O_CREAT, dir, libc::EINVAL, "O_TMPFILE|O_CREAT", h);

    let _ = std::fs::remove_dir_all(dir);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut h = Harness::new();
    match args.get(1).map(String::as_str) {
        Some("tmpfs") => {
            let dir = "/tmp/tmpfile-tmpfs";
            let _ = std::fs::create_dir_all(dir);
            let r = unsafe { libc::mount(c"none".as_ptr(), c(dir).as_ptr(), c"tmpfs".as_ptr(), 0, std::ptr::null()) };
            check!(h, r == 0, "mount -t tmpfs: errno {}", errno());
            run(&mut h, &format!("{dir}/t"), true);
            unsafe { libc::umount(c(dir).as_ptr()) };
        }
        Some(dir) => run(&mut h, dir, args.get(2).map(String::as_str) != Some("realfs")),
        None => run(&mut h, "/tmp/tmpfile-test", true),
    }
    std::process::exit(h.finish());
}
