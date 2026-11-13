//! Thin wrappers over the syscalls the tests exercise.
//!
//! Deliberately raw. These programs are testing what the emulator does with a
//! given syscall, so the layer between the test and the syscall should be as
//! thin as it can be — `std::fs` would decide for itself when to retry, when
//! to buffer and which call to make.

use std::ffi::{CStr, CString};

use libc::{c_char, c_int, c_void, mode_t, off_t, size_t};

pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn clear_errno() {
    // SAFETY: __errno_location is per-thread and always valid on musl.
    unsafe { *libc::__errno_location() = 0 };
}

pub fn strerror(err: i32) -> String {
    // SAFETY: strerror returns a pointer to a static string.
    let p = unsafe { libc::strerror(err) };
    if p.is_null() {
        return format!("errno {err}");
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn c(path: &str) -> CString {
    CString::new(path).expect("path with an interior NUL")
}

pub fn open(path: &str, flags: c_int, mode: mode_t) -> c_int {
    // SAFETY: `path` is NUL-terminated for the duration of the call.
    unsafe { libc::open(c(path).as_ptr(), flags, mode as c_int) }
}

pub fn close(fd: c_int) -> c_int {
    unsafe { libc::close(fd) }
}

pub fn read(fd: c_int, buf: &mut [u8]) -> isize {
    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len() as size_t) }
}

pub fn write(fd: c_int, buf: &[u8]) -> isize {
    unsafe { libc::write(fd, buf.as_ptr() as *const c_void, buf.len() as size_t) }
}

pub fn lseek(fd: c_int, off: off_t, whence: c_int) -> off_t {
    unsafe { libc::lseek(fd, off, whence) }
}

pub fn mkdir(path: &str, mode: mode_t) -> c_int {
    unsafe { libc::mkdir(c(path).as_ptr(), mode) }
}

pub fn rmdir(path: &str) -> c_int {
    unsafe { libc::rmdir(c(path).as_ptr()) }
}

pub fn unlink(path: &str) -> c_int {
    unsafe { libc::unlink(c(path).as_ptr()) }
}

pub fn rename(from: &str, to: &str) -> c_int {
    unsafe { libc::rename(c(from).as_ptr(), c(to).as_ptr()) }
}

pub fn link(from: &str, to: &str) -> c_int {
    unsafe { libc::link(c(from).as_ptr(), c(to).as_ptr()) }
}

pub fn symlink(target: &str, path: &str) -> c_int {
    unsafe { libc::symlink(c(target).as_ptr(), c(path).as_ptr()) }
}

pub fn readlink(path: &str, buf: &mut [u8]) -> isize {
    unsafe {
        libc::readlink(
            c(path).as_ptr(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len() as size_t,
        )
    }
}

pub fn truncate(path: &str, len: off_t) -> c_int {
    unsafe { libc::truncate(c(path).as_ptr(), len) }
}

pub fn ftruncate(fd: c_int, len: off_t) -> c_int {
    unsafe { libc::ftruncate(fd, len) }
}

pub fn chmod(path: &str, mode: mode_t) -> c_int {
    unsafe { libc::chmod(c(path).as_ptr(), mode) }
}

pub fn access(path: &str, mode: c_int) -> c_int {
    unsafe { libc::access(c(path).as_ptr(), mode) }
}

pub fn chdir(path: &str) -> c_int {
    unsafe { libc::chdir(c(path).as_ptr()) }
}

pub fn getcwd() -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let p = unsafe { libc::getcwd(buf.as_mut_ptr() as *mut c_char, buf.len() as size_t) };
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    Some(s)
}

pub fn stat(path: &str) -> Option<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::stat(c(path).as_ptr(), &mut st) };
    (r == 0).then_some(st)
}

pub fn lstat(path: &str) -> Option<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::lstat(c(path).as_ptr(), &mut st) };
    (r == 0).then_some(st)
}

pub fn fstat(fd: c_int) -> Option<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstat(fd, &mut st) };
    (r == 0).then_some(st)
}

/// `stat` as a bare result, for the cases that assert on the errno.
pub fn stat_raw(path: &str) -> c_int {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::stat(c(path).as_ptr(), &mut st) }
}

pub fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

pub fn is_reg(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFREG
}

pub fn is_lnk(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFLNK
}

/// Write a whole file, replacing it.
pub fn write_file(path: &str, contents: &[u8]) -> bool {
    let fd = open(path, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644);
    if fd < 0 {
        return false;
    }
    let ok = contents.is_empty() || write(fd, contents) == contents.len() as isize;
    close(fd);
    ok
}

/// Read a whole file. `None` if it could not be opened.
pub fn read_file(path: &str) -> Option<Vec<u8>> {
    let fd = open(path, libc::O_RDONLY, 0);
    if fd < 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = read(fd, &mut buf);
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    close(fd);
    Some(out)
}

pub fn flock(fd: c_int, operation: c_int) -> c_int {
    unsafe { libc::flock(fd, operation) }
}

pub fn chown(path: &str, uid: libc::uid_t, gid: libc::gid_t) -> c_int {
    unsafe { libc::chown(c(path).as_ptr(), uid, gid) }
}

pub fn fchown(fd: c_int, uid: libc::uid_t, gid: libc::gid_t) -> c_int {
    unsafe { libc::fchown(fd, uid, gid) }
}
