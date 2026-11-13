//! The `*at` filesystem calls Linux added after 5.6, and the `AT_EMPTY_PATH`
//! corners of the older ones.
//!
//! `faccessat2`, `fchmodat2`, the four `*xattrat`, `file_getattr` and
//! `file_setattr`, `cachestat`, `statmount` and `listmount`, and
//! `name_to_handle_at`. Each takes an extensible struct, a flag word or a
//! descriptor-or-path pair, and a caller probes for each by what it answers --
//! glibc's `fchmodat` falls back on `ENOSYS` from `fchmodat2`, systemd asks
//! `statmount` before it parses `/proc/self/mountinfo` -- so the errno a case
//! answers is the observable, and so is the *order* in which two bad arguments
//! are refused.
//!
//! Nothing is asserted; one line per case, compared against a real arm64
//! kernel by `tests/integration/probe_diff.sh`.

use std::ffi::CString;

const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: i64 = 0x100;
const AT_EACCESS: i64 = 0x200;
const AT_EMPTY_PATH: i64 = 0x1000;

const NR_FCHOWNAT: i64 = 54;
const NR_NEWFSTATAT: i64 = 79;
const NR_STATX: i64 = 291;
const NR_NAME_TO_HANDLE_AT: i64 = 264;
const NR_OPEN_BY_HANDLE_AT: i64 = 265;
const NR_FACCESSAT: i64 = 48;
const NR_FACCESSAT2: i64 = 439;
const NR_CACHESTAT: i64 = 451;
const NR_FCHMODAT2: i64 = 452;
const NR_STATMOUNT: i64 = 457;
const NR_LISTMOUNT: i64 = 458;
const NR_SETXATTRAT: i64 = 463;
const NR_GETXATTRAT: i64 = 464;
const NR_LISTXATTRAT: i64 = 465;
const NR_REMOVEXATTRAT: i64 = 466;
const NR_FILE_GETATTR: i64 = 468;
const NR_FILE_SETATTR: i64 = 469;

fn errname(e: i64) -> String {
    let n = match e {
        1 => "EPERM", 2 => "ENOENT", 3 => "ESRCH", 7 => "E2BIG", 9 => "EBADF",
        11 => "EAGAIN", 13 => "EACCES", 14 => "EFAULT", 17 => "EEXIST",
        18 => "EXDEV", 20 => "ENOTDIR", 21 => "EISDIR", 22 => "EINVAL",
        25 => "ENOTTY", 34 => "ERANGE", 38 => "ENOSYS", 40 => "ELOOP",
        61 => "ENODATA", 75 => "EOVERFLOW", 95 => "EOPNOTSUPP", 116 => "ESTALE",
        _ => return format!("errno {e}"),
    };
    n.into()
}

fn r(v: i64) -> String {
    if v < 0 { errname(-v) } else { v.to_string() }
}

unsafe fn sys(n: i64, a: [i64; 6]) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a[0] => ret,
            in("x1") a[1],
            in("x2") a[2],
            in("x3") a[3],
            in("x4") a[4],
            in("x5") a[5],
            options(nostack)
        );
    }
    ret
}

fn call(n: i64, a: &[i64]) -> i64 {
    let mut args = [0i64; 6];
    args[..a.len()].copy_from_slice(a);
    unsafe { sys(n, args) }
}

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<62} -> {value}");
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn p(s: &CString) -> i64 {
    s.as_ptr() as i64
}

fn open(path: &str, flags: i32) -> i64 {
    unsafe { libc::open(c(path).as_ptr(), flags, 0o644) as i64 }
}

fn mode_of(path: &str) -> String {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c(path).as_ptr(), &mut st) } != 0 {
        return "lstat failed".into();
    }
    format!("{:o}", st.st_mode & 0o7777)
}

/// Run `f` in a child that has dropped to an unprivileged uid, and print what
/// it printed. A credential change cannot be undone, hence the fork.
fn as_nobody(f: impl FnOnce()) {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::setgroups(0, std::ptr::null());
            libc::setgid(65534);
            libc::setuid(65534);
            f();
            libc::_exit(0);
        }
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
    }
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/fsatprobe".into());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(format!("{dir}/sub")).unwrap();
    std::fs::write(format!("{dir}/f"), b"hello").unwrap();
    std::fs::write(format!("{dir}/secret"), b"s").unwrap();
    unsafe { libc::chmod(c(&format!("{dir}/secret")).as_ptr(), 0o600) };
    std::os::unix::fs::symlink("f", format!("{dir}/lf")).unwrap();
    std::os::unix::fs::symlink("nothing", format!("{dir}/dangling")).unwrap();
    // The directory has to be searchable by the unprivileged child.
    unsafe { libc::chmod(c(&dir).as_ptr(), 0o755) };

    let dirfd = open(&dir, libc::O_RDONLY | libc::O_DIRECTORY);
    let ffd = open(&format!("{dir}/f"), libc::O_RDWR);
    let opath = open(&format!("{dir}/f"), libc::O_PATH);

    faccessat2(&dir, dirfd, ffd, opath);
    fchmodat2(&dir, dirfd, opath);
    empty_path_forms(&dir, dirfd, ffd, opath);
    xattrat(&dir, dirfd, opath);
    file_attr(&dir, dirfd);
    cachestat(&dir, ffd, opath);
    mounts(dirfd);
    handles(&dir, dirfd);
}

fn faccessat2(dir: &str, dirfd: i64, ffd: i64, opath: i64) {
    println!("########## faccessat2 ##########");
    let f = c("f");
    let empty = c("");
    let fa = |at: i64, path: i64, mode: i64, flags: i64| call(NR_FACCESSAT2, &[at, path, mode, flags]);
    line("F_OK", r(fa(dirfd, p(&f), 0, 0)));
    line("R_OK|W_OK, AT_EACCESS", r(fa(dirfd, p(&f), 6, AT_EACCESS)));
    line("AT_SYMLINK_NOFOLLOW on a dangling link", r(fa(dirfd, p(&c("dangling")), 0, AT_SYMLINK_NOFOLLOW)));
    line("a dangling link, followed", r(fa(dirfd, p(&c("dangling")), 0, 0)));
    line("AT_EMPTY_PATH on a descriptor", r(fa(ffd, p(&empty), 4, AT_EMPTY_PATH)));
    line("AT_EMPTY_PATH on an O_PATH descriptor", r(fa(opath, p(&empty), 4, AT_EMPTY_PATH)));
    line("AT_EMPTY_PATH on AT_FDCWD", r(fa(AT_FDCWD, p(&empty), 1, AT_EMPTY_PATH)));
    line("AT_EMPTY_PATH on a closed descriptor", r(fa(999, p(&empty), 0, AT_EMPTY_PATH)));
    line("AT_EMPTY_PATH with a NULL path", r(fa(ffd, 0, 0, AT_EMPTY_PATH)));
    line("AT_EMPTY_PATH with a name", r(fa(dirfd, p(&f), 0, AT_EMPTY_PATH)));
    line("an empty path without AT_EMPTY_PATH", r(fa(ffd, p(&empty), 0, 0)));
    line("every defined flag", r(fa(dirfd, p(&f), 0, AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)));
    line("flag 0x400", r(fa(dirfd, p(&f), 0, 0x400)));
    line("flag 0x8000", r(fa(dirfd, p(&f), 0, 0x8000)));
    line("mode 8", r(fa(dirfd, p(&f), 8, 0)));
    line("faccessat(48) ignores a fourth register", r(call(NR_FACCESSAT, &[dirfd, p(&f), 0, 0x400])));
    let secret = format!("{dir}/secret");
    let sfd = open(&secret, libc::O_RDONLY);
    as_nobody(|| {
        let s = c(&secret);
        line("as nobody: R_OK on a 0600 file", r(fa(AT_FDCWD, p(&s), 4, 0)));
        line("as nobody: R_OK on it by AT_EMPTY_PATH", r(fa(sfd, p(&c("")), 4, AT_EMPTY_PATH)));
        line("as nobody: F_OK on it by AT_EMPTY_PATH", r(fa(sfd, p(&c("")), 0, AT_EMPTY_PATH)));
    });
}

fn fchmodat2(dir: &str, dirfd: i64, opath: i64) {
    println!("########## fchmodat2 ##########");
    let fc = |at: i64, path: i64, mode: i64, flags: i64| call(NR_FCHMODAT2, &[at, path, mode, flags]);
    let f = c("f");
    line("flags 0", r(fc(dirfd, p(&f), 0o640, 0)));
    line("  the mode", mode_of(&format!("{dir}/f")));
    line("AT_SYMLINK_NOFOLLOW on a file", r(fc(dirfd, p(&f), 0o600, AT_SYMLINK_NOFOLLOW)));
    line("  the mode", mode_of(&format!("{dir}/f")));
    line("AT_SYMLINK_NOFOLLOW on a symlink", r(fc(dirfd, p(&c("lf")), 0o644, AT_SYMLINK_NOFOLLOW)));
    line("  the file's mode", mode_of(&format!("{dir}/f")));
    line("a symlink, followed", r(fc(dirfd, p(&c("lf")), 0o644, 0)));
    line("  the file's mode", mode_of(&format!("{dir}/f")));
    line("AT_SYMLINK_NOFOLLOW on a dangling symlink", r(fc(dirfd, p(&c("dangling")), 0o644, AT_SYMLINK_NOFOLLOW)));
    line("AT_EMPTY_PATH on an O_PATH descriptor", r(fc(opath, p(&c("")), 0o604, AT_EMPTY_PATH)));
    line("  the mode", mode_of(&format!("{dir}/f")));
    line("AT_EMPTY_PATH|NOFOLLOW on an O_PATH descriptor", r(fc(opath, p(&c("")), 0o644, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)));
    let lpath = open(&format!("{dir}/lf"), libc::O_PATH | libc::O_NOFOLLOW);
    line("AT_EMPTY_PATH on an O_PATH descriptor of a symlink", r(fc(lpath, p(&c("")), 0o644, AT_EMPTY_PATH)));
    line("AT_EMPTY_PATH with a NULL path", r(fc(opath, 0, 0o644, AT_EMPTY_PATH)));
    line("AT_EMPTY_PATH on a closed descriptor", r(fc(999, p(&c("")), 0o644, AT_EMPTY_PATH)));
    {
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(format!("{dir}/sub")).unwrap();
        line("AT_EMPTY_PATH on AT_FDCWD", r(fc(AT_FDCWD, p(&c("")), 0o750, AT_EMPTY_PATH)));
        line("  sub's mode", mode_of(&format!("{dir}/sub")));
        std::env::set_current_dir(cwd).unwrap();
    }
    line("an empty path without AT_EMPTY_PATH", r(fc(dirfd, p(&c("")), 0o644, 0)));
    line("flag 0x200", r(fc(dirfd, p(&f), 0o644, 0x200)));
    line("flag 0x400", r(fc(dirfd, p(&f), 0o644, 0x400)));
    line("mode with file-type bits", r(fc(dirfd, p(&f), 0o100755, 0)));
    line("  the mode", mode_of(&format!("{dir}/f")));
    // Every bit but setgid: on a passthrough mount the host clears that one
    // for a group the host user is not in, which is the host's rule and not
    // this call's.
    line("mode 0o5777", r(fc(dirfd, p(&f), 0o5777, 0)));
    line("  the mode", mode_of(&format!("{dir}/f")));
    line("a missing name", r(fc(dirfd, p(&c("missing")), 0o644, 0)));
    line("a bad flag and a missing name", r(fc(dirfd, p(&c("missing")), 0o644, 0x400)));
    line("a bad flag and a closed descriptor", r(fc(999, p(&f), 0o644, 0x400)));
    let _ = fc(dirfd, p(&f), 0o644, 0);
    let fp = format!("{dir}/f");
    as_nobody(|| {
        line("as nobody: on root's file", r(fc(AT_FDCWD, p(&c(&fp)), 0o777, 0)));
        line("as nobody: NOFOLLOW on root's symlink", r(fc(dirfd, p(&c("lf")), 0o777, AT_SYMLINK_NOFOLLOW)));
    });
}

fn empty_path_forms(dir: &str, dirfd: i64, ffd: i64, opath: i64) {
    println!("########## AT_EMPTY_PATH and a NULL path ##########");
    let mut buf = [0u8; 256];
    let b = buf.as_mut_ptr() as i64;
    line("statx(fd, NULL, AT_EMPTY_PATH)", r(call(NR_STATX, &[ffd, 0, AT_EMPTY_PATH, 0x7ff, b])));
    line("statx(AT_FDCWD, NULL, AT_EMPTY_PATH)", r(call(NR_STATX, &[AT_FDCWD, 0, AT_EMPTY_PATH, 0x7ff, b])));
    line("statx(fd, NULL, 0)", r(call(NR_STATX, &[ffd, 0, 0, 0x7ff, b])));
    line("statx(closed, NULL, AT_EMPTY_PATH)", r(call(NR_STATX, &[999, 0, AT_EMPTY_PATH, 0x7ff, b])));
    line("fstatat(fd, NULL, AT_EMPTY_PATH)", r(call(NR_NEWFSTATAT, &[ffd, 0, b, AT_EMPTY_PATH])));
    line("fstatat(AT_FDCWD, NULL, AT_EMPTY_PATH)", r(call(NR_NEWFSTATAT, &[AT_FDCWD, 0, b, AT_EMPTY_PATH])));
    line("fstatat(fd, NULL, 0)", r(call(NR_NEWFSTATAT, &[ffd, 0, b, 0])));
    line("fstatat(O_PATH fd, \"\", AT_EMPTY_PATH)", r(call(NR_NEWFSTATAT, &[opath, p(&c("")), b, AT_EMPTY_PATH])));
    let e = c("");
    line("fchownat(O_PATH fd, \"\", -1, -1, AT_EMPTY_PATH)", r(call(NR_FCHOWNAT, &[opath, p(&e), -1, -1, AT_EMPTY_PATH])));
    line("fchownat(AT_FDCWD, \"\", -1, -1, AT_EMPTY_PATH)", r(call(NR_FCHOWNAT, &[AT_FDCWD, p(&e), -1, -1, AT_EMPTY_PATH])));
    line("fchownat(fd, NULL, -1, -1, AT_EMPTY_PATH)", r(call(NR_FCHOWNAT, &[ffd, 0, -1, -1, AT_EMPTY_PATH])));
    // utimensat: AT_EMPTY_PATH since 5.8.
    let now = [0i64, (1 << 30) - 1, 0, (1 << 30) - 1];
    line("utimensat(fd, \"\", now, AT_EMPTY_PATH)", r(call(88, &[ffd, p(&e), now.as_ptr() as i64, AT_EMPTY_PATH])));
    line("utimensat(O_PATH fd, \"\", now, AT_EMPTY_PATH)", r(call(88, &[opath, p(&e), now.as_ptr() as i64, AT_EMPTY_PATH])));
    line("utimensat(AT_FDCWD, \"\", now, AT_EMPTY_PATH)", r(call(88, &[AT_FDCWD, p(&e), now.as_ptr() as i64, AT_EMPTY_PATH])));
    line("utimensat(fd, \"\", now, 0)", r(call(88, &[ffd, p(&e), now.as_ptr() as i64, 0])));
    line("utimensat(dirfd, \"f\", now, 0x200)", r(call(88, &[dirfd, p(&c("f")), now.as_ptr() as i64, 0x200])));
    // statx: STATX_ATTR_MOUNT_ROOT, which the VFS reports for every
    // filesystem, and its bit in stx_attributes_mask.
    for path in ["/proc", "/", "/proc/self"] {
        let mut sx = [0u8; 256];
        let n = call(NR_STATX, &[AT_FDCWD, p(&c(path)), 0, 0x7ff, sx.as_mut_ptr() as i64]);
        let attrs = u64::from_le_bytes(sx[8..16].try_into().unwrap());
        let amask = u64::from_le_bytes(sx[56..64].try_into().unwrap());
        line(&format!("statx({path}): MOUNT_ROOT in attributes, in the mask"), format!("{} {} {}", r(n), attrs & 0x2000 != 0, amask & 0x2000 != 0));
    }
    let mut sx = [0u8; 256];
    call(NR_STATX, &[dirfd, p(&c("f")), 0, 0x7ff, sx.as_mut_ptr() as i64]);
    line("statx(f): MOUNT_ROOT in attributes", u64::from_le_bytes(sx[8..16].try_into().unwrap()) & 0x2000 != 0);
    // close_range: the two flags and an undefined one.
    let d1 = unsafe { libc::dup(ffd as i32) } as i64;
    line("close_range(CLOSE_RANGE_CLOEXEC)", format!("{} {}", r(call(436, &[d1, d1, 4])), unsafe { libc::fcntl(d1 as i32, libc::F_GETFD) }));
    line("close_range(CLOSE_RANGE_UNSHARE)", r(call(436, &[d1, d1, 2])));
    line("close_range(flag 8)", r(call(436, &[d1, d1, 8])));
    // renameat2: the three flags and an undefined one.
    std::fs::write(format!("{dir}/ra"), b"a").unwrap();
    std::fs::write(format!("{dir}/rb"), b"b").unwrap();
    let ren = |flags: i64| call(276, &[dirfd, p(&c("ra")), dirfd, p(&c("rb")), flags]);
    line("renameat2(RENAME_NOREPLACE) over an existing name", r(ren(1)));
    line("renameat2(RENAME_EXCHANGE)", r(ren(2)));
    line("renameat2(NOREPLACE|EXCHANGE)", r(ren(3)));
    line("renameat2(RENAME_WHITEOUT)", r(ren(4)));
    line("renameat2(flag 8)", r(ren(8)));
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct XattrArgs {
    value: u64,
    size: u32,
    flags: u32,
}

fn xattrat(dir: &str, dirfd: i64, opath: i64) {
    println!("########## the *xattrat calls ##########");
    let f = c("f");
    let name = c("user.probe");
    let value = *b"abc";
    let args = |flags: u32| XattrArgs { value: value.as_ptr() as u64, size: 3, flags };
    let set = |at: i64, path: i64, atf: i64, name: i64, a: *const XattrArgs, size: i64| {
        call(NR_SETXATTRAT, &[at, path, atf, name, a as i64, size])
    };
    let a0 = args(0);
    line("setxattrat", r(set(dirfd, p(&f), 0, p(&name), &a0, 16)));
    line("setxattrat, usize 0", r(set(dirfd, p(&f), 0, p(&name), &a0, 0)));
    line("setxattrat, usize 15", r(set(dirfd, p(&f), 0, p(&name), &a0, 15)));
    line("setxattrat, usize 4097", r(set(dirfd, p(&f), 0, p(&name), &a0, 4097)));
    let big = [a0.value, 3u64, 0, 0];
    line("setxattrat, usize 32, zero tail", r(set(dirfd, p(&f), 0, p(&name), big.as_ptr().cast(), 32)));
    let bigbad = [a0.value, 3u64, 0, 1];
    line("setxattrat, usize 32, nonzero tail", r(set(dirfd, p(&f), 0, p(&name), bigbad.as_ptr().cast(), 32)));
    line("setxattrat, args NULL", r(set(dirfd, p(&f), 0, p(&name), std::ptr::null(), 16)));
    line("setxattrat, at_flags 0x200", r(set(dirfd, p(&f), 0x200, p(&name), &a0, 16)));
    line("setxattrat, at_flags 0x200 and a bad usize", r(set(dirfd, p(&f), 0x200, p(&name), &a0, 8)));
    line("setxattrat, XATTR_CREATE over an existing name", r(set(dirfd, p(&f), 0, p(&name), &args(1), 16)));
    line("setxattrat, XATTR_REPLACE", r(set(dirfd, p(&f), 0, p(&name), &args(2), 16)));
    line("setxattrat, flags 4", r(set(dirfd, p(&f), 0, p(&name), &args(4), 16)));
    line("setxattrat, flags 4 and a missing file", r(set(dirfd, p(&c("missing")), 0, p(&name), &args(4), 16)));
    line("setxattrat, a missing file", r(set(dirfd, p(&c("missing")), 0, p(&name), &a0, 16)));
    line("setxattrat, a bad name and a missing file", r(set(dirfd, p(&c("missing")), 0, p(&c("nonamespace")), &a0, 16)));
    line("setxattrat, a closed dirfd", r(set(999, p(&f), 0, p(&name), &a0, 16)));
    line("setxattrat, AT_EMPTY_PATH on an O_PATH fd", r(set(opath, p(&c("")), AT_EMPTY_PATH, p(&name), &a0, 16)));
    let rw = open(&format!("{dir}/f"), libc::O_RDONLY);
    line("setxattrat, AT_EMPTY_PATH on a descriptor", r(set(rw, p(&c("")), AT_EMPTY_PATH, p(&c("user.fd")), &a0, 16)));
    line("setxattrat, AT_EMPTY_PATH, NULL path", r(set(rw, 0, AT_EMPTY_PATH, p(&c("user.null")), &a0, 16)));
    line("setxattrat, NULL path without AT_EMPTY_PATH", r(set(rw, 0, 0, p(&name), &a0, 16)));
    line("setxattrat, \"\" without AT_EMPTY_PATH", r(set(rw, p(&c("")), 0, p(&name), &a0, 16)));
    {
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        line("setxattrat, AT_FDCWD and AT_EMPTY_PATH", r(set(AT_FDCWD, p(&c("")), AT_EMPTY_PATH, p(&c("user.cwd")), &a0, 16)));
        std::env::set_current_dir(cwd).unwrap();
    }
    line("setxattrat, NOFOLLOW on a symlink", r(set(dirfd, p(&c("lf")), AT_SYMLINK_NOFOLLOW, p(&name), &a0, 16)));
    line("setxattrat, through a symlink", r(set(dirfd, p(&c("lf")), 0, p(&c("user.via")), &a0, 16)));

    let get = |at: i64, path: i64, atf: i64, name: i64, a: *const XattrArgs, size: i64| {
        call(NR_GETXATTRAT, &[at, path, atf, name, a as i64, size])
    };
    // The kernel writes the value here, so the address is a mutable one.
    let mut out = [0u8; 16];
    let out_at = out.as_mut_ptr() as u64;
    let ga = |size: u32, flags: u32| XattrArgs { value: out_at, size, flags };
    let n = get(dirfd, p(&f), 0, p(&name), &ga(16, 0), 16);
    line("getxattrat", format!("{} {:?}", r(n), &out[..n.max(0) as usize]));
    line("getxattrat, size 0", r(get(dirfd, p(&f), 0, p(&name), &ga(0, 0), 16)));
    line("getxattrat, size 1", r(get(dirfd, p(&f), 0, p(&name), &ga(1, 0), 16)));
    line("getxattrat, args.flags 1", r(get(dirfd, p(&f), 0, p(&name), &ga(16, 1), 16)));
    line("getxattrat, a missing name", r(get(dirfd, p(&f), 0, p(&c("user.none")), &ga(16, 0), 16)));
    line("getxattrat, usize 8", r(get(dirfd, p(&f), 0, p(&name), &ga(16, 0), 8)));
    line("getxattrat, at_flags 0x400", r(get(dirfd, p(&f), 0x400, p(&name), &ga(16, 0), 16)));
    line("getxattrat, the one set through a descriptor", r(get(dirfd, p(&f), 0, p(&c("user.fd")), &ga(16, 0), 16)));
    line("getxattrat, the one set with a NULL path", r(get(dirfd, p(&f), 0, p(&c("user.null")), &ga(16, 0), 16)));
    line("getxattrat, the one set on the cwd", r(get(AT_FDCWD, p(&c(dir)), 0, p(&c("user.cwd")), &ga(16, 0), 16)));
    line("getxattrat, the one set through the symlink", r(get(dirfd, p(&f), 0, p(&c("user.via")), &ga(16, 0), 16)));
    line("getxattrat, AT_EMPTY_PATH on an O_PATH fd", r(get(opath, p(&c("")), AT_EMPTY_PATH, p(&name), &ga(16, 0), 16)));

    let list = |at: i64, path: i64, atf: i64, buf: i64, size: i64| call(NR_LISTXATTRAT, &[at, path, atf, buf, size]);
    let mut lbuf = [0u8; 256];
    let n = list(dirfd, p(&f), 0, lbuf.as_mut_ptr() as i64, 256);
    let mut names: Vec<String> = lbuf[..n.max(0) as usize]
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .filter(|s| s.starts_with("user."))
        .collect();
    names.sort();
    line("listxattrat, the user.* names", names.join(","));
    line("listxattrat, size 0 is not an error", (list(dirfd, p(&f), 0, 0, 0) > 0).to_string());
    line("listxattrat, size 1", r(list(dirfd, p(&f), 0, lbuf.as_mut_ptr() as i64, 1)));
    line("listxattrat, at_flags 0x200", r(list(dirfd, p(&f), 0x200, lbuf.as_mut_ptr() as i64, 256)));
    line("listxattrat, a missing file", r(list(dirfd, p(&c("missing")), 0, lbuf.as_mut_ptr() as i64, 256)));
    line("listxattrat, AT_EMPTY_PATH on a descriptor", (list(rw, p(&c("")), AT_EMPTY_PATH, lbuf.as_mut_ptr() as i64, 256) > 0).to_string());
    line("listxattrat, AT_EMPTY_PATH on an O_PATH fd", r(list(opath, p(&c("")), AT_EMPTY_PATH, lbuf.as_mut_ptr() as i64, 256)));

    let rm = |at: i64, path: i64, atf: i64, name: i64| call(NR_REMOVEXATTRAT, &[at, path, atf, name]);
    line("removexattrat", r(rm(dirfd, p(&f), 0, p(&name))));
    line("removexattrat, again", r(rm(dirfd, p(&f), 0, p(&name))));
    line("removexattrat, at_flags 0x200", r(rm(dirfd, p(&f), 0x200, p(&c("user.fd")))));
    line("removexattrat, a bad name", r(rm(dirfd, p(&f), 0, p(&c("nonamespace")))));
    line("removexattrat, a bad name and a missing file", r(rm(dirfd, p(&c("missing")), 0, p(&c("nonamespace")))));
    line("removexattrat, AT_EMPTY_PATH on a descriptor", r(rm(rw, p(&c("")), AT_EMPTY_PATH, p(&c("user.fd")))));
    line("removexattrat, AT_EMPTY_PATH on an O_PATH fd", r(rm(opath, p(&c("")), AT_EMPTY_PATH, p(&c("user.null")))));
}

fn file_attr(dir: &str, dirfd: i64) {
    println!("########## file_getattr and file_setattr ##########");
    let mut fa = [0u64; 8];
    let b = fa.as_mut_ptr() as i64;
    let get = |at: i64, path: i64, size: i64, atf: i64, b: i64| call(NR_FILE_GETATTR, &[at, path, b, size, atf]);
    let st = c("/proc/self/status");
    line("file_getattr, a procfs file", r(get(AT_FDCWD, p(&st), 24, 0, b)));
    line("file_getattr, usize 23", r(get(AT_FDCWD, p(&st), 23, 0, b)));
    line("file_getattr, usize 4097", r(get(AT_FDCWD, p(&st), 4097, 0, b)));
    line("file_getattr, usize 32", r(get(AT_FDCWD, p(&st), 32, 0, b)));
    line("file_getattr, at_flags 0x200", r(get(AT_FDCWD, p(&st), 24, 0x200, b)));
    line("file_getattr, at_flags 0x200 and usize 4097", r(get(AT_FDCWD, p(&st), 4097, 0x200, b)));
    line("file_getattr, a missing file", r(get(dirfd, p(&c("missing")), 24, 0, b)));
    line("file_getattr, usize 4097 and a missing file", r(get(dirfd, p(&c("missing")), 4097, 0, b)));
    line("file_getattr, a closed dirfd", r(get(999, p(&c("f")), 24, 0, b)));
    line("file_getattr, NULL path without AT_EMPTY_PATH", r(get(dirfd, 0, 24, 0, b)));
    let pfd = open("/proc/self/status", libc::O_RDONLY);
    line("file_getattr, AT_EMPTY_PATH on a procfs descriptor", r(get(pfd, p(&c("")), 24, AT_EMPTY_PATH, b)));
    line("file_getattr, AT_EMPTY_PATH, NULL path", r(get(pfd, 0, 24, AT_EMPTY_PATH, b)));
    line("file_getattr, AT_EMPTY_PATH on a closed descriptor", r(get(999, 0, 24, AT_EMPTY_PATH, b)));
    line("file_getattr, a bad buffer on procfs", r(get(AT_FDCWD, p(&st), 24, 0, 8)));
    let pipe = {
        let mut fds = [0i32; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };
        fds[0] as i64
    };
    line("file_getattr, AT_EMPTY_PATH on a pipe", r(get(pipe, p(&c("")), 24, AT_EMPTY_PATH, b)));
    let set = |at: i64, path: i64, size: i64, atf: i64, b: i64| call(NR_FILE_SETATTR, &[at, path, b, size, atf]);
    fa = [0; 8];
    let b = fa.as_mut_ptr() as i64;
    line("file_setattr, a procfs file", r(set(AT_FDCWD, p(&st), 24, 0, b)));
    line("file_setattr, usize 23", r(set(AT_FDCWD, p(&st), 23, 0, b)));
    line("file_setattr, usize 4097", r(set(AT_FDCWD, p(&st), 4097, 0, b)));
    line("file_setattr, at_flags 0x200", r(set(AT_FDCWD, p(&st), 24, 0x200, b)));
    line("file_setattr, a missing file", r(set(dirfd, p(&c("missing")), 24, 0, b)));
    line("file_setattr, a bad buffer", r(set(AT_FDCWD, p(&st), 24, 0, 8)));
    let mut bad = [0u64; 8];
    bad[0] = 1 << 40;
    line("file_setattr, an undefined xflag on procfs", r(set(AT_FDCWD, p(&st), 24, 0, bad.as_mut_ptr() as i64)));
    let refused: Vec<String> = (0..64)
        .filter(|bit| {
            let mut one = [0u64; 8];
            one[0] = 1 << bit;
            set(AT_FDCWD, p(&st), 24, 0, one.as_mut_ptr() as i64) == -22
        })
        .map(|b| b.to_string())
        .collect();
    line("file_setattr, the xflag bits refused on procfs", refused.join(","));
    bad[0] = 0;
    bad[3] = 1;
    line("file_setattr, usize 32 with a nonzero tail", r(set(AT_FDCWD, p(&st), 32, 0, bad.as_mut_ptr() as i64)));
    let _ = dir;
}

fn cachestat(dir: &str, ffd: i64, opath: i64) {
    println!("########## cachestat ##########");
    // On /dev/shm, which is tmpfs in a container and a host file here: a
    // container's /tmp is overlayfs, which answers for its own mapping and
    // not the file's, so every count there is 0.
    let path = if std::path::Path::new("/dev/shm").is_dir() {
        "/dev/shm/fsat-cachestat".to_string()
    } else {
        format!("{dir}/cs")
    };
    std::fs::write(&path, vec![7u8; 8192]).unwrap();
    let fd = open(&path, libc::O_RDONLY);
    let mut out = [0u64; 5];
    let o = out.as_mut_ptr() as i64;
    let range = |off: u64, len: u64| [off, len];
    let cs = |fd: i64, rng: *const [u64; 2], o: i64, flags: i64| call(NR_CACHESTAT, &[fd, rng as i64, o, flags]);
    let all = range(0, 0);
    let n = cs(fd, &all, o, 0);
    line("an 8192-byte file just written, the whole range", r(n));
    line("  nr_cache", out[0]);
    line("  nr_writeback, nr_evicted", format!("{} {}", out[2], out[3]));
    let n = cs(fd, &range(4096, 1), o, 0);
    line("one byte at 4096", format!("{} nr_cache {}", r(n), out[0]));
    let n = cs(fd, &range(8192, 4096), o, 0);
    line("a range past the end", format!("{} nr_cache {}", r(n), out[0]));
    let n = cs(fd, &range(0, u64::MAX), o, 0);
    line("len = u64::MAX", format!("{} nr_cache {}", r(n), out[0]));
    line("flags 1", r(cs(fd, &all, o, 1)));
    line("a closed descriptor", r(cs(999, &all, o, 0)));
    line("an O_PATH descriptor", r(cs(opath, &all, o, 0)));
    line("range NULL", r(cs(fd, std::ptr::null(), o, 0)));
    line("result NULL", r(cs(fd, &all, 0, 0)));
    line("flags 1 and range NULL", r(cs(fd, std::ptr::null(), o, 1)));
    line("a closed descriptor and range NULL", r(cs(999, std::ptr::null(), o, 0)));
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    unsafe { libc::write(fds[1], b"x".as_ptr().cast(), 1) };
    out = [9; 5];
    let o = out.as_mut_ptr() as i64;
    let n = cs(fds[0] as i64, &all, o, 0);
    line("a pipe", format!("{} {:?}", r(n), out));
    let d = open(dir, libc::O_RDONLY | libc::O_DIRECTORY);
    let n = cs(d, &all, o, 0);
    line("a directory", format!("{} nr_cache {}", r(n), out[0]));
    let m = unsafe { libc::memfd_create(c"cs".as_ptr(), 0) } as i64;
    unsafe { libc::write(m as i32, vec![1u8; 12288].as_ptr().cast(), 12288) };
    let n = cs(m, &all, o, 0);
    line("a memfd with 12288 bytes", format!("{} nr_cache {} nr_dirty {}", r(n), out[0], out[1]));
    let _ = ffd;
    let pathc = path.clone();
    as_nobody(|| {
        let fd = open(&pathc, libc::O_RDONLY);
        let mut out = [0u64; 5];
        line("as nobody: a root-owned 0644 file opened read-only", r(cs(fd, &range(0, 0), out.as_mut_ptr() as i64, 0)));
    });
    let _ = std::fs::remove_file(&path);
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct MntIdReq {
    size: u32,
    fd: u32,
    mnt_id: u64,
    param: u64,
    mnt_ns_id: u64,
}

fn unique_mnt_id(path: &str) -> u64 {
    let mut buf = [0u8; 256];
    let n = call(NR_STATX, &[AT_FDCWD, p(&c(path)), 0, 0x4000, buf.as_mut_ptr() as i64]);
    if n < 0 {
        return 0;
    }
    let mask = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if mask & 0x4000 == 0 {
        return 0;
    }
    u64::from_le_bytes(buf[144..152].try_into().unwrap())
}

struct Statmount {
    ret: i64,
    buf: Vec<u8>,
}

impl Statmount {
    fn u32_at(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.buf[off..off + 4].try_into().unwrap())
    }
    fn u64_at(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.buf[off..off + 8].try_into().unwrap())
    }
    fn str_at(&self, field_off: usize) -> String {
        let off = 512 + self.u32_at(field_off) as usize;
        let end = self.buf[off..].iter().position(|b| *b == 0).map_or(self.buf.len(), |e| off + e);
        String::from_utf8_lossy(&self.buf[off..end]).into_owned()
    }
}

fn statmount(id: u64, mask: u64, bufsize: usize, flags: i64) -> Statmount {
    let req = MntIdReq { size: 24, mnt_id: id, param: mask, ..Default::default() };
    let mut buf = vec![0u8; bufsize.max(1024)];
    let ret = call(NR_STATMOUNT, &[&req as *const _ as i64, buf.as_mut_ptr() as i64, bufsize as i64, flags]);
    Statmount { ret, buf }
}

fn mounts(dirfd: i64) {
    println!("########## statmount and listmount ##########");
    let root = unique_mnt_id("/");
    let proc_ = unique_mnt_id("/proc");
    line("statx's unique mount id of / is above 1<<31", root > (1 << 31));
    line("/proc's is different", proc_ != root && proc_ != 0);

    const SB_BASIC: u64 = 0x1;
    const MNT_BASIC: u64 = 0x2;
    const MNT_ROOT: u64 = 0x8;
    const MNT_POINT: u64 = 0x10;
    const FS_TYPE: u64 = 0x20;
    let s = statmount(proc_, SB_BASIC | MNT_BASIC | MNT_ROOT | MNT_POINT | FS_TYPE, 4096, 0);
    line("statmount(/proc, basic|root|point|type)", r(s.ret));
    if s.ret == 0 {
        line("  mask", format!("{:#x}", s.u64_at(8)));
        line("  size is the struct plus its strings", s.u32_at(0) > 512);
        line("  sb_magic", format!("{:#x}", s.u64_at(24)));
        line("  mnt_id is statx's", s.u64_at(40) == proc_);
        line("  mnt_parent_id is the root's", s.u64_at(48) == root);
        line("  mnt_id_old nonzero", s.u32_at(56) != 0);
        line("  fs_type", s.str_at(36));
        line("  mnt_root", s.str_at(104));
        line("  mnt_point", s.str_at(108));
    }
    let s = statmount(root, MNT_BASIC | MNT_POINT, 4096, 0);
    line("statmount(/, basic|point)", r(s.ret));
    if s.ret == 0 {
        line("  mnt_point", s.str_at(108));
        line("  the root's parent is itself", s.u64_at(48) == root);
    }
    let s = statmount(proc_, 0, 4096, 0);
    line("statmount, mask 0", r(s.ret));
    if s.ret == 0 {
        line("  size", s.u32_at(0));
        line("  mask", s.u64_at(8));
    }
    let s = statmount(proc_, 1 << 40, 4096, 0);
    line("statmount, an undefined mask bit", format!("{} mask {:#x}", r(s.ret), s.u64_at(8)));
    let s = statmount(proc_, MNT_POINT, 520, 0);
    line("statmount, a buffer too small for the strings", r(s.ret));
    let s = statmount(proc_, MNT_BASIC, 64, 0);
    line("statmount, a 64-byte buffer, no strings", format!("{} size {}", r(s.ret), s.u32_at(0)));
    let s = statmount(proc_, MNT_POINT, 64, 0);
    line("statmount, a 64-byte buffer, a string", r(s.ret));
    line("statmount, flags 2", r(statmount(proc_, 0, 4096, 2).ret));
    line("statmount, mnt_id 5", r(statmount(5, 0, 4096, 0).ret));
    line("statmount, mnt_id 0", r(statmount(0, 0, 4096, 0).ret));
    line("statmount, a mount that does not exist", r(statmount((1 << 32) + 123456, 0, 4096, 0).ret));
    {
        let req = MntIdReq { size: 24, fd: dirfd as u32, param: MNT_POINT, ..Default::default() };
        let mut buf = vec![0u8; 4096];
        let ret = call(NR_STATMOUNT, &[&req as *const _ as i64, buf.as_mut_ptr() as i64, 4096, 1]);
        let s = Statmount { ret, buf };
        line("statmount, STATMOUNT_BY_FD on the probe's directory", r(s.ret));
        if s.ret == 0 {
            line("  mnt_point", s.str_at(108));
        }
    }
    let sm = |req: &MntIdReq, flags: i64| {
        let mut buf = vec![0u8; 4096];
        call(NR_STATMOUNT, &[req as *const _ as i64, buf.as_mut_ptr() as i64, 4096, flags])
    };
    line("statmount, req.size 23", r(sm(&MntIdReq { size: 23, mnt_id: proc_, ..Default::default() }, 0)));
    line("statmount, req.size 32", r(sm(&MntIdReq { size: 32, mnt_id: proc_, ..Default::default() }, 0)));
    line("statmount, req.size 4097", r(sm(&MntIdReq { size: 4097, mnt_id: proc_, ..Default::default() }, 0)));
    line("statmount, req.fd nonzero", r(sm(&MntIdReq { size: 24, fd: 3, mnt_id: proc_, ..Default::default() }, 0)));
    line("statmount, req.mnt_ns_id nonzero", r(sm(&MntIdReq { size: 32, mnt_id: proc_, mnt_ns_id: 77, ..Default::default() }, 0)));
    line("statmount, req NULL", r(call(NR_STATMOUNT, &[0, 0, 0, 0])));
    {
        let req = MntIdReq { size: 24, mnt_id: proc_, ..Default::default() };
        line("statmount, buf NULL", r(call(NR_STATMOUNT, &[&req as *const _ as i64, 0, 4096, 0])));
    }

    const LSMT_ROOT: u64 = u64::MAX;
    let lm = |req: &MntIdReq, ids: &mut [u64], n: usize, flags: i64| {
        call(NR_LISTMOUNT, &[req as *const _ as i64, ids.as_mut_ptr() as i64, n as i64, flags])
    };
    let mut ids = vec![0u64; 512];
    let all = MntIdReq { size: 24, mnt_id: LSMT_ROOT, ..Default::default() };
    let n = lm(&all, &mut ids, 512, 0);
    line("listmount(LSMT_ROOT) answers some", n > 1);
    let listed = &ids[..n.max(0) as usize];
    line("  the root is listed", listed.contains(&root));
    line("  /proc is listed", listed.contains(&proc_));
    line("  in ascending order", listed.windows(2).all(|w| w[0] < w[1]));
    let mut rev = vec![0u64; 512];
    let nr = lm(&all, &mut rev, 512, 1);
    line("LISTMOUNT_REVERSE, the same set backwards", nr == n && rev[..nr.max(0) as usize].iter().rev().eq(listed.iter()));
    let n1 = lm(&all, &mut ids, 1, 0);
    let first = ids[0];
    line("one at a time", r(n1));
    let next = MntIdReq { size: 24, mnt_id: LSMT_ROOT, param: first, ..Default::default() };
    let n2 = lm(&next, &mut ids, 1, 0);
    line("  continuing from the first answers a later one", n2 == 1 && ids[0] > first);
    let under = MntIdReq { size: 24, mnt_id: root, ..Default::default() };
    let n = lm(&under, &mut ids, 512, 0);
    line("listmount(the root) does not list the root", n >= 0 && !ids[..n.max(0) as usize].contains(&root));
    let under = MntIdReq { size: 24, mnt_id: proc_, ..Default::default() };
    let n = lm(&under, &mut ids, 512, 0);
    line("listmount(/proc)'s children are not /proc", n >= 0 && !ids[..n.max(0) as usize].contains(&proc_));
    line("listmount, nr 0", r(lm(&all, &mut ids, 0, 0)));
    line("listmount, flags 2", r(lm(&all, &mut ids, 512, 2)));
    line("listmount, mnt_id 5", r(lm(&MntIdReq { size: 24, mnt_id: 5, ..Default::default() }, &mut ids, 512, 0)));
    line("listmount, a mount that does not exist", r(lm(&MntIdReq { size: 24, mnt_id: (1 << 32) + 123456, ..Default::default() }, &mut ids, 512, 0)));
    line("listmount, param 5", r(lm(&MntIdReq { size: 24, mnt_id: LSMT_ROOT, param: 5, ..Default::default() }, &mut ids, 512, 0)));
    line("listmount, req.size 23", r(lm(&MntIdReq { size: 23, mnt_id: LSMT_ROOT, ..Default::default() }, &mut ids, 512, 0)));
    line("listmount, req.size 4097", r(lm(&MntIdReq { size: 4097, mnt_id: LSMT_ROOT, ..Default::default() }, &mut ids, 512, 0)));
    line("listmount, req NULL", r(call(NR_LISTMOUNT, &[0, ids.as_mut_ptr() as i64, 512, 0])));
    line("listmount, ids NULL", r(call(NR_LISTMOUNT, &[&all as *const _ as i64, 0, 512, 0])));
    line("listmount, an enormous nr", r(call(NR_LISTMOUNT, &[&all as *const _ as i64, ids.as_mut_ptr() as i64, 1 << 40, 0])));
}

fn handles(dir: &str, dirfd: i64) {
    println!("########## name_to_handle_at and open_by_handle_at ##########");
    let mut h = vec![0u8; 8 + 128];
    let mut mnt: i32 = 0;
    let set_bytes = |h: &mut Vec<u8>, n: u32| h[0..4].copy_from_slice(&n.to_le_bytes());
    let nth = |at: i64, path: i64, h: &mut Vec<u8>, mnt: *mut i32, flags: i64| {
        call(NR_NAME_TO_HANDLE_AT, &[at, path, h.as_mut_ptr() as i64, mnt as i64, flags])
    };
    set_bytes(&mut h, 128);
    line("flags 0x10, undefined", r(nth(dirfd, p(&c("f")), &mut h, &mut mnt, 0x10)));
    set_bytes(&mut h, 129);
    line("handle_bytes 129", r(nth(dirfd, p(&c("f")), &mut h, &mut mnt, 0)));
    set_bytes(&mut h, 0);
    let n = nth(AT_FDCWD, p(&c("/proc/self/status")), &mut h, &mut mnt, 0x200);
    line("AT_HANDLE_FID, handle_bytes 0, on procfs", r(n));
    line("  handle_bytes is set to what it needs", u32::from_le_bytes(h[0..4].try_into().unwrap()) > 0);
    set_bytes(&mut h, 128);
    let n = nth(AT_FDCWD, p(&c("/proc/self/status")), &mut h, &mut mnt, 0);
    line("no FID, on procfs", r(n));
    set_bytes(&mut h, 128);
    line("a missing name", r(nth(dirfd, p(&c("missing")), &mut h, &mut mnt, 0x200)));
    line("handle NULL", r(call(NR_NAME_TO_HANDLE_AT, &[dirfd, p(&c("f")), 0, &mut mnt as *mut i32 as i64, 0x200])));
    line("open_by_handle_at, a closed mount fd", r(call(NR_OPEN_BY_HANDLE_AT, &[999, h.as_mut_ptr() as i64, 0])));
    as_nobody(|| {
        let mut h = vec![0u8; 136];
        h[0..4].copy_from_slice(&8u32.to_le_bytes());
        line("as nobody: open_by_handle_at", r(call(NR_OPEN_BY_HANDLE_AT, &[AT_FDCWD, h.as_mut_ptr() as i64, 0])));
    });
    let _ = dir;
}
