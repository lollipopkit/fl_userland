//! The filesystem calls Linux added after 5.6, asserted: `openat2`'s six
//! `RESOLVE_*` flags, `faccessat2`, `fchmodat2`, the `*xattrat` four,
//! `file_getattr`, `cachestat`, `statmount`, `listmount` and the file-handle
//! pair -- and the `openat` rules 6.4 and 7.x added that `openat2_probe` found
//! missing.
//!
//! Every expected answer here was first measured on an arm64 7.2 kernel by
//! `openat2_probe` and `fsat_probe`; this is the half that gates. It runs on
//! realfs and fakefs, because the walk's refusals ask each mount what a name
//! is and the two answer through different code.
//!
//! The containment cases are the point: each `RESOLVE_*` flag is tried against
//! the escape it exists to stop, and a refusal that opened the file outside
//! the root would be a descriptor a sandbox believes it cannot have.

use std::ffi::CString;

use guest_tests::{Harness, check, check_fails, cpath};

const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: i64 = 0x100;
const AT_EMPTY_PATH: i64 = 0x1000;

const NR_OPENAT: i64 = 56;
const NR_OPENAT2: i64 = 437;
const NR_FACCESSAT2: i64 = 439;
const NR_FCHMODAT2: i64 = 452;
const NR_SETXATTRAT: i64 = 463;
const NR_GETXATTRAT: i64 = 464;
const NR_REMOVEXATTRAT: i64 = 466;
const NR_FILE_GETATTR: i64 = 468;
const NR_CACHESTAT: i64 = 451;
const NR_STATMOUNT: i64 = 457;
const NR_LISTMOUNT: i64 = 458;
const NR_STATX: i64 = 291;
const NR_NAME_TO_HANDLE_AT: i64 = 264;
const NR_OPEN_BY_HANDLE_AT: i64 = 265;

const O_RDWR: u64 = 0o2;
const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;
const O_DIRECTORY: u64 = 0o40000;
const O_NOFOLLOW: u64 = 0o100000;
const O_PATH: u64 = 0o10000000;
const O_EMPTYPATH: u64 = 1 << 26;
const OPENAT2_REGULAR: u64 = 1 << 32;

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;

const EFTYPE: i32 = 134;

/// A raw syscall that sets errno the way libc's wrappers do, so
/// `check_fails!` can read it.
fn sys(n: i64, a: &[i64]) -> i64 {
    let mut args = [0i64; 6];
    args[..a.len()].copy_from_slice(a);
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") args[0] => ret,
            in("x1") args[1],
            in("x2") args[2],
            in("x3") args[3],
            in("x4") args[4],
            in("x5") args[5],
            options(nostack)
        );
    }
    if ret < 0 && ret > -4096 {
        unsafe { *libc::__errno_location() = -ret as i32 };
        return -1;
    }
    ret
}

fn p(s: &CString) -> i64 {
    s.as_ptr() as i64
}

fn openat2(dirfd: i64, path: &str, flags: u64, mode: u64, resolve: u64) -> i64 {
    let c = cpath(path);
    let how = [flags, mode, resolve];
    sys(NR_OPENAT2, &[dirfd, p(&c), how.as_ptr() as i64, 24])
}

fn identity_of_fd(fd: i64) -> (u64, u64) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(fd as i32, &mut st) };
    (st.st_dev, st.st_ino)
}

fn identity(path: &str) -> (u64, u64) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::lstat(cpath(path).as_ptr(), &mut st) };
    (st.st_dev, st.st_ino)
}

/// Whether `fd` is open on `path`, closing it either way.
fn opened(fd: i64, path: &str) -> bool {
    if fd < 0 {
        return false;
    }
    let same = identity_of_fd(fd) == identity(path);
    unsafe { libc::close(fd as i32) };
    same
}

fn as_nobody(h: &mut Harness, f: impl FnOnce() -> bool, what: &str) {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::setgroups(0, std::ptr::null());
            libc::setgid(65534);
            libc::setuid(65534);
            libc::_exit(if f() { 0 } else { 1 });
        }
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        check!(h, libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "{what}");
    }
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/fs-at-calls".into());
    let _ = std::fs::remove_dir_all(&dir);
    // What an escape would have made, from an earlier run of a broken build.
    let _ = std::fs::remove_file(format!("{dir}/../escape"));
    std::fs::create_dir_all(format!("{dir}/sub")).unwrap();
    std::fs::write(format!("{dir}/f"), b"hello").unwrap();
    std::fs::write(format!("{dir}/sub/g"), b"g").unwrap();
    let sl = |target: &str, name: &str| std::os::unix::fs::symlink(target, format!("{dir}/{name}")).unwrap();
    sl("/etc", "abs");
    sl("/sub/g", "abs_in_root");
    sl("sub", "rel");
    sl("..", "up");
    sl("nothing", "dangling");
    unsafe { libc::chmod(cpath(&dir).as_ptr(), 0o755) };

    let dirfd = unsafe { libc::open(cpath(&dir).as_ptr(), libc::O_PATH | libc::O_DIRECTORY) } as i64;
    let procfd = unsafe { libc::open(c"/proc".as_ptr(), libc::O_PATH | libc::O_DIRECTORY) } as i64;
    let rootfd = unsafe { libc::open(c"/".as_ptr(), libc::O_PATH | libc::O_DIRECTORY) } as i64;
    let ffd = unsafe { libc::open(cpath(&format!("{dir}/f")).as_ptr(), libc::O_RDONLY) } as i64;
    let f = format!("{dir}/f");
    let g = format!("{dir}/sub/g");

    let mut h = Harness::new();

    h.group("openat2 arguments");
    {
        let c = cpath("f");
        let mut how = vec![0u64; 512];
        check_fails!(h, sys(NR_OPENAT2, &[dirfd, p(&c), how.as_ptr() as i64, 23]), libc::EINVAL, "a size below VER0");
        check_fails!(h, sys(NR_OPENAT2, &[dirfd, p(&c), how.as_ptr() as i64, 4097]), libc::E2BIG, "a size above a page");
        check!(h, opened(sys(NR_OPENAT2, &[dirfd, p(&c), how.as_ptr() as i64, 4096]), &f), "a page with a zero tail");
        how[3] = 1;
        check_fails!(h, sys(NR_OPENAT2, &[dirfd, p(&c), how.as_ptr() as i64, 32]), libc::E2BIG, "a field this kernel does not know, set");
        check_fails!(h, sys(NR_OPENAT2, &[dirfd, p(&c), 0, 24]), libc::EFAULT, "a NULL how");
    }
    check_fails!(h, openat2(dirfd, "f", 1 << 2, 0, 0), libc::EINVAL, "an undefined flag openat ignores");
    check_fails!(h, openat2(dirfd, "f", 1 << 33, 0, 0), libc::EINVAL, "a flag above OPENAT2_REGULAR");
    check_fails!(h, openat2(dirfd, "f", 0, 0o644, 0), libc::EINVAL, "a mode without O_CREAT");
    check_fails!(h, openat2(dirfd, "m", O_CREAT, 0o10000, 0), libc::EINVAL, "a mode with a type bit");
    check_fails!(h, openat2(dirfd, "f", 0, 0, 0x40), libc::EINVAL, "an undefined resolve bit");
    check_fails!(h, openat2(dirfd, "f", 0, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT), libc::EINVAL, "BENEATH and IN_ROOT");
    check_fails!(h, openat2(dirfd, "f", O_PATH | O_RDWR, 0, 0), libc::EINVAL, "O_PATH with an access mode");
    check_fails!(h, openat2(dirfd, "", 0, 0, 0), libc::ENOENT, "an empty path");
    check_fails!(h, openat2(999, "", 0, 0, 0), libc::ENOENT, "an empty path beats a closed dirfd");
    check_fails!(h, openat2(999, "/f", 0, 0, RESOLVE_BENEATH), libc::EXDEV, "an absolute path under BENEATH, before the dirfd");
    check_fails!(h, openat2(999, "/f", 0, 0, RESOLVE_IN_ROOT), libc::EBADF, "an absolute path under IN_ROOT needs the dirfd");

    h.group("RESOLVE_BENEATH");
    let b = RESOLVE_BENEATH;
    check!(h, opened(openat2(dirfd, "sub/../f", 0, 0, b), &f), "sub/../f stays inside");
    check!(h, opened(openat2(dirfd, "rel/g", 0, 0, b), &g), "a relative symlink inside");
    check_fails!(h, openat2(dirfd, "..", O_PATH, 0, b), libc::EXDEV, "..");
    check_fails!(h, openat2(dirfd, &format!("../{}/f", dir.rsplit('/').next().unwrap()), 0, 0, b), libc::EXDEV, "out and back in");
    check_fails!(h, openat2(dirfd, &f, 0, 0, b), libc::EXDEV, "an absolute path");
    check_fails!(h, openat2(dirfd, "abs/passwd", 0, 0, b), libc::EXDEV, "an absolute symlink");
    check_fails!(h, openat2(dirfd, "up/f", 0, 0, b), libc::EXDEV, "a relative symlink that climbs");
    check_fails!(h, openat2(dirfd, "up/escape", O_CREAT | O_WRONLY, 0o644, b), libc::EXDEV, "a create through a climbing symlink");
    check!(h, !std::path::Path::new(&format!("{dir}/../escape")).exists(), "  and nothing was made outside");
    check_fails!(h, openat2(procfd, &format!("self/fd/{ffd}"), 0, 0, b), libc::EXDEV, "a magic link");
    let link = openat2(procfd, &format!("self/fd/{ffd}"), O_PATH | O_NOFOLLOW, 0, b);
    check!(h, link >= 0, "a magic link not followed");
    if link >= 0 {
        unsafe { libc::close(link as i32) };
    }
    check_fails!(h, openat2(dirfd, "missing/../f", 0, 0, b), libc::ENOENT, "a missing name before ..");
    check_fails!(h, openat2(rootfd, "..", O_PATH, 0, b), libc::EXDEV, ".. at the machine's root");

    h.group("RESOLVE_IN_ROOT");
    let ir = RESOLVE_IN_ROOT;
    check!(h, opened(openat2(dirfd, "/f", 0, 0, ir), &f), "/f is the root's f");
    check!(h, opened(openat2(dirfd, "../../f", 0, 0, ir), &f), ".. stops at the root");
    check!(h, opened(openat2(dirfd, "abs_in_root", 0, 0, ir), &g), "an absolute symlink restarts at the root");
    check!(h, opened(openat2(dirfd, "up/f", 0, 0, ir), &f), "a climbing symlink stops at the root");
    check_fails!(h, openat2(dirfd, "abs/passwd", 0, 0, ir), libc::ENOENT, "/etc is the root's /etc");
    check_fails!(h, openat2(procfd, &format!("self/fd/{ffd}"), 0, 0, ir), libc::EXDEV, "a magic link");
    let made = openat2(dirfd, "/../made", O_CREAT | O_WRONLY, 0o644, ir);
    check!(h, made >= 0 && std::path::Path::new(&format!("{dir}/made")).exists(), "a create of /../made is made inside");
    if made >= 0 {
        unsafe { libc::close(made as i32) };
    }

    h.group("RESOLVE_NO_SYMLINKS and NO_MAGICLINKS");
    check_fails!(h, openat2(dirfd, "rel/g", 0, 0, RESOLVE_NO_SYMLINKS), libc::ELOOP, "a symlink on the way");
    check_fails!(h, openat2(dirfd, "dangling", 0, 0, RESOLVE_NO_SYMLINKS), libc::ELOOP, "a dangling one");
    check!(h, opened(openat2(dirfd, "rel", O_PATH | O_NOFOLLOW, 0, RESOLVE_NO_SYMLINKS), &format!("{dir}/rel")), "the link itself, not followed");
    check_fails!(h, openat2(AT_FDCWD, "/proc/self/status", 0, 0, RESOLVE_NO_SYMLINKS), libc::ELOOP, "/proc/self is a symlink");
    let fdlink = format!("/proc/self/fd/{ffd}");
    check_fails!(h, openat2(AT_FDCWD, &fdlink, 0, 0, RESOLVE_NO_MAGICLINKS), libc::ELOOP, "/proc/self/fd/<n>");
    check_fails!(h, openat2(AT_FDCWD, "/proc/self/cwd", O_PATH, 0, RESOLVE_NO_MAGICLINKS), libc::ELOOP, "/proc/self/cwd");
    check!(h, opened(openat2(AT_FDCWD, &fdlink, 0, 0, 0), &f), "the same link without the flag");
    let st = openat2(AT_FDCWD, "/proc/self/status", 0, 0, RESOLVE_NO_MAGICLINKS);
    check!(h, st >= 0, "/proc/self is not a magic link");
    if st >= 0 {
        unsafe { libc::close(st as i32) };
    }

    h.group("RESOLVE_NO_XDEV");
    let nx = RESOLVE_NO_XDEV;
    check_fails!(h, openat2(rootfd, "proc", O_PATH, 0, nx), libc::EXDEV, "onto a mount point, not followed");
    check_fails!(h, openat2(procfd, "..", O_PATH, 0, nx), libc::EXDEV, "out of a mount's root");
    check_fails!(h, openat2(AT_FDCWD, "/proc/self/status", 0, 0, nx), libc::EXDEV, "an absolute path crossing");
    check!(h, opened(openat2(dirfd, "rel/g", 0, 0, nx), &g), "a symlink on the same mount");
    check_fails!(h, openat2(dirfd, "abs", O_PATH, 0, nx), libc::EXDEV, "an absolute symlink before the root is set");
    check!(h, opened(openat2(dirfd, "sub/../abs", O_PATH, 0, nx), "/etc"), "the same after a ..");

    h.group("RESOLVE_CACHED");
    check!(h, opened(openat2(dirfd, "f", 0, 0, RESOLVE_CACHED), &f), "a name looked up already");
    check_fails!(h, openat2(dirfd, "cc", O_CREAT | O_WRONLY, 0o644, RESOLVE_CACHED), libc::EAGAIN, "a create");
    check_fails!(h, openat2(AT_FDCWD, &fdlink, 0, 0, RESOLVE_CACHED), libc::EAGAIN, "a magic link");
    check_fails!(h, openat2(dirfd, "..", O_PATH, 0, RESOLVE_CACHED | b), libc::EAGAIN, "a refusal the cached walk cannot make");

    h.group("O_EMPTYPATH and OPENAT2_REGULAR");
    let opath = unsafe { libc::open(cpath(&f).as_ptr(), libc::O_PATH) } as i64;
    let re = openat2(opath, "", O_EMPTYPATH, 0, 0);
    let mut buf = [0u8; 8];
    let n = if re >= 0 { unsafe { libc::read(re as i32, buf.as_mut_ptr().cast(), 8) } } else { -1 };
    check!(h, n == 5 && &buf[..5] == b"hello", "an O_PATH descriptor reopened for reading");
    if re >= 0 {
        unsafe { libc::close(re as i32) };
    }
    let lpath = unsafe { libc::open(cpath(&format!("{dir}/rel")).as_ptr(), libc::O_PATH | libc::O_NOFOLLOW) } as i64;
    check_fails!(h, openat2(lpath, "", O_EMPTYPATH, 0, 0), libc::ELOOP, "a symlink's descriptor reopens the link");
    check_fails!(h, openat2(dirfd, "sub", OPENAT2_REGULAR, 0, 0), EFTYPE, "OPENAT2_REGULAR on a directory");
    check_fails!(h, openat2(AT_FDCWD, "/dev/null", OPENAT2_REGULAR, 0, 0), EFTYPE, "on a device");
    check_fails!(h, openat2(dirfd, "sub", OPENAT2_REGULAR | O_DIRECTORY, 0, 0), libc::EINVAL, "with O_DIRECTORY");
    check!(h, opened(openat2(dirfd, "f", OPENAT2_REGULAR, 0, 0), &f), "on a regular file");

    h.group("openat");
    let oa = |path: &str, flags: u64, mode: i64| {
        let c = cpath(path);
        sys(NR_OPENAT, &[dirfd, p(&c), flags as i64, mode])
    };
    check_fails!(h, oa("dc", O_DIRECTORY | O_CREAT, 0o644), libc::EINVAL, "O_DIRECTORY|O_CREAT");
    check_fails!(h, oa("sub", O_CREAT, 0o644), libc::EISDIR, "O_CREAT of a directory");
    check_fails!(h, oa("pathcreat", O_PATH | O_CREAT, 0o644), libc::ENOENT, "O_PATH drops O_CREAT");
    check!(h, !std::path::Path::new(&format!("{dir}/pathcreat")).exists(), "  and made nothing");
    check_fails!(h, oa("missing/../f", 0, 0), libc::ENOENT, "a missing name before ..");
    check_fails!(h, sys(NR_OPENAT, &[999, p(&cpath("")), 0, 0]), libc::ENOENT, "an empty path beats a closed dirfd");

    h.group("faccessat2");
    let e = cpath("");
    check!(h, sys(NR_FACCESSAT2, &[ffd, p(&e), 4, AT_EMPTY_PATH]) == 0, "AT_EMPTY_PATH on a descriptor");
    check!(h, sys(NR_FACCESSAT2, &[opath, p(&e), 4, AT_EMPTY_PATH]) == 0, "AT_EMPTY_PATH on an O_PATH descriptor");
    check!(h, sys(NR_FACCESSAT2, &[dirfd, p(&cpath("dangling")), 0, AT_SYMLINK_NOFOLLOW]) == 0, "NOFOLLOW asks about the link");
    check_fails!(h, sys(NR_FACCESSAT2, &[dirfd, p(&cpath("dangling")), 0, 0]), libc::ENOENT, "and following it does not");
    check_fails!(h, sys(NR_FACCESSAT2, &[dirfd, p(&cpath("f")), 0, 0x400]), libc::EINVAL, "an undefined flag");
    std::fs::write(format!("{dir}/secret"), b"s").unwrap();
    unsafe { libc::chmod(cpath(&format!("{dir}/secret")).as_ptr(), 0o600) };
    let sfd = unsafe { libc::open(cpath(&format!("{dir}/secret")).as_ptr(), libc::O_RDONLY) } as i64;
    as_nobody(
        &mut h,
        || {
            sys(NR_FACCESSAT2, &[sfd, p(&cpath("")), 4, AT_EMPTY_PATH]) == -1
                && unsafe { *libc::__errno_location() } == libc::EACCES
        },
        "as nobody, R_OK by descriptor on a 0600 file is EACCES",
    );

    h.group("fchmodat2");
    let fc = |path: &str, mode: i64, flags: i64| sys(NR_FCHMODAT2, &[dirfd, p(&cpath(path)), mode, flags]);
    check_fails!(h, fc("rel", 0o700, AT_SYMLINK_NOFOLLOW), libc::EOPNOTSUPP, "a symlink's mode");
    let mode = |path: &str| std::fs::metadata(path).map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o7777).unwrap_or(0);
    check!(h, mode(&format!("{dir}/sub")) == 0o755, "  and the directory it names is unchanged");
    check!(h, fc("f", 0o640, AT_SYMLINK_NOFOLLOW) == 0 && mode(&f) == 0o640, "NOFOLLOW on a file");
    check!(h, sys(NR_FCHMODAT2, &[opath, p(&e), 0o604, AT_EMPTY_PATH]) == 0 && mode(&f) == 0o604, "AT_EMPTY_PATH on an O_PATH descriptor");
    check_fails!(h, sys(NR_FCHMODAT2, &[lpath, p(&e), 0o604, AT_EMPTY_PATH]), libc::EOPNOTSUPP, "AT_EMPTY_PATH on a symlink's descriptor");
    check_fails!(h, fc("f", 0o644, 0x200), libc::EINVAL, "an undefined flag");
    let _ = fc("f", 0o644, 0);

    h.group("AT_EMPTY_PATH in the older calls");
    let mut sx = [0u8; 256];
    check!(h, sys(NR_STATX, &[ffd, 0, AT_EMPTY_PATH, 0x7ff, sx.as_mut_ptr() as i64]) == 0, "statx with a NULL path");
    check!(h, sys(79, &[ffd, 0, sx.as_mut_ptr() as i64, AT_EMPTY_PATH]) == 0, "fstatat with a NULL path");
    {
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        check!(h, sys(54, &[AT_FDCWD, p(&e), -1, -1, AT_EMPTY_PATH]) == 0, "fchownat(AT_FDCWD, \"\") is the working directory");
        std::env::set_current_dir(cwd).unwrap();
    }
    let times = [1_000_000i64, 0, 2_000_000, 0];
    check!(h, sys(88, &[opath, p(&e), times.as_ptr() as i64, AT_EMPTY_PATH]) == 0, "utimensat(O_PATH fd, \"\", AT_EMPTY_PATH)");
    let mtime = std::fs::metadata(&f).map(|m| std::os::unix::fs::MetadataExt::mtime(&m)).unwrap_or(0);
    check!(h, mtime == 2_000_000, "  set the file's mtime: {mtime}");
    let mount_root = |at: i64, path: &str, flags: i64| {
        let mut sx = [0u8; 256];
        sys(NR_STATX, &[at, p(&cpath(path)), flags, 0x7ff, sx.as_mut_ptr() as i64]);
        let attrs = u64::from_le_bytes(sx[8..16].try_into().unwrap());
        let mask = u64::from_le_bytes(sx[56..64].try_into().unwrap());
        (attrs & 0x2000 != 0, mask & 0x2000 != 0)
    };
    check!(h, mount_root(AT_FDCWD, "/proc", 0) == (true, true), "STATX_ATTR_MOUNT_ROOT on /proc");
    check!(h, mount_root(procfd, "", AT_EMPTY_PATH) == (true, true), "  and through a descriptor on it");
    check!(h, mount_root(dirfd, "f", 0) == (false, true), "  known about and clear on a file");
    std::fs::write(format!("{dir}/xa"), b"a").unwrap();
    std::fs::create_dir_all(format!("{dir}/xb")).unwrap();
    std::fs::write(format!("{dir}/xb/in"), b"in").unwrap();
    let swapped = sys(276, &[dirfd, p(&cpath("xa")), dirfd, p(&cpath("xb")), 2]);
    check!(
        h,
        swapped == 0
            && std::fs::read(format!("{dir}/xb")).ok().as_deref() == Some(b"a")
            && std::fs::read(format!("{dir}/xa/in")).ok().as_deref() == Some(b"in"),
        "renameat2(RENAME_EXCHANGE) swaps a file and a directory"
    );
    check_fails!(h, sys(276, &[dirfd, p(&cpath("xa")), dirfd, p(&cpath("xa/in")), 2]), libc::EINVAL, "  but not one with something under it");

    h.group("the *xattrat calls");
    let name = cpath("user.fsat");
    let val = *b"abc";
    let args = [val.as_ptr() as u64, 3];
    check!(h, sys(NR_SETXATTRAT, &[dirfd, p(&cpath("f")), 0, p(&name), args.as_ptr() as i64, 16]) == 0, "setxattrat");
    let mut out = [0u8; 8];
    let gargs = [out.as_mut_ptr() as u64, 8];
    let n = sys(NR_GETXATTRAT, &[dirfd, p(&cpath("f")), 0, p(&name), gargs.as_ptr() as i64, 16]);
    check!(h, n == 3 && &out[..3] == b"abc", "getxattrat reads it back: {n}");
    let rw = unsafe { libc::open(cpath(&f).as_ptr(), libc::O_RDONLY) } as i64;
    let n = sys(NR_GETXATTRAT, &[rw, 0, AT_EMPTY_PATH, p(&name), gargs.as_ptr() as i64, 16]);
    check!(h, n == 3, "by descriptor, with a NULL path: {n}");
    check_fails!(h, sys(NR_GETXATTRAT, &[opath, p(&e), AT_EMPTY_PATH, p(&name), gargs.as_ptr() as i64, 16]), libc::EBADF, "not by an O_PATH descriptor");
    check_fails!(h, sys(NR_SETXATTRAT, &[dirfd, p(&cpath("f")), 0, p(&name), args.as_ptr() as i64, 15]), libc::EINVAL, "a struct below VER0");
    let flagged = [out.as_mut_ptr() as u64, 8 | (1 << 32)];
    check_fails!(h, sys(NR_GETXATTRAT, &[dirfd, p(&cpath("f")), 0, p(&name), flagged.as_ptr() as i64, 16]), libc::EINVAL, "a get with flags");
    check_fails!(h, sys(NR_SETXATTRAT, &[dirfd, p(&cpath("missing")), 0, p(&name), [val.as_ptr() as u64, 3 | (4 << 32)].as_ptr() as i64, 16]), libc::EINVAL, "a bad set flag beats a missing file");
    check!(h, sys(NR_REMOVEXATTRAT, &[dirfd, p(&cpath("f")), 0, p(&name)]) == 0, "removexattrat");
    check_fails!(h, sys(NR_REMOVEXATTRAT, &[dirfd, p(&cpath("f")), 0, p(&name)]), libc::ENODATA, "  and it is gone");

    h.group("file_getattr");
    let mut fa = [0u64; 3];
    check_fails!(h, sys(NR_FILE_GETATTR, &[AT_FDCWD, p(&cpath("/proc/self/status")), fa.as_mut_ptr() as i64, 24, 0]), libc::EOPNOTSUPP, "procfs has no inode flags");
    check_fails!(h, sys(NR_FILE_GETATTR, &[AT_FDCWD, p(&cpath("/proc/self/status")), fa.as_mut_ptr() as i64, 23, 0]), libc::EINVAL, "a struct below VER0");
    check_fails!(h, sys(NR_FILE_GETATTR, &[dirfd, p(&cpath("missing")), fa.as_mut_ptr() as i64, 24, 0]), libc::ENOENT, "a missing file");

    h.group("cachestat");
    let range = [0u64, 0];
    let mut cs = [9u64; 5];
    let m = unsafe { libc::memfd_create(c"fsat".as_ptr(), 0) } as i64;
    unsafe { libc::write(m as i32, vec![1u8; 12288].as_ptr().cast(), 12288) };
    check!(h, sys(NR_CACHESTAT, &[m, range.as_ptr() as i64, cs.as_mut_ptr() as i64, 0]) == 0 && cs[0] == 3 && cs[1] == 0, "a memfd's three pages, none dirty: {cs:?}");
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    check!(h, sys(NR_CACHESTAT, &[fds[0] as i64, range.as_ptr() as i64, cs.as_mut_ptr() as i64, 0]) == 0 && cs == [0; 5], "a pipe has no pages");
    check_fails!(h, sys(NR_CACHESTAT, &[m, range.as_ptr() as i64, cs.as_mut_ptr() as i64, 1]), libc::EINVAL, "a flag");
    check_fails!(h, sys(NR_CACHESTAT, &[opath, range.as_ptr() as i64, cs.as_mut_ptr() as i64, 0]), libc::EBADF, "an O_PATH descriptor");

    h.group("statmount and listmount");
    let unique = |path: &str| {
        let mut buf = [0u8; 256];
        sys(NR_STATX, &[AT_FDCWD, p(&cpath(path)), 0, 0x4000, buf.as_mut_ptr() as i64]);
        u64::from_le_bytes(buf[144..152].try_into().unwrap())
    };
    let (root, proc_) = (unique("/"), unique("/proc"));
    check!(h, root > (1 << 31) && proc_ > (1 << 31) && root != proc_, "STATX_MNT_ID_UNIQUE is above 1<<31: {root:#x} {proc_:#x}");
    let req = [24u64, proc_, 0x2 | 0x10 | 0x20, 0];
    let mut sm = vec![0u8; 4096];
    let r = sys(NR_STATMOUNT, &[req.as_ptr() as i64, sm.as_mut_ptr() as i64, 4096, 0]);
    let s32 = |off: usize| u32::from_le_bytes(sm[off..off + 4].try_into().unwrap());
    let s64 = |off: usize| u64::from_le_bytes(sm[off..off + 8].try_into().unwrap());
    let string = |off: usize| {
        let at = 512 + s32(off) as usize;
        let end = sm[at..].iter().position(|b| *b == 0).unwrap() + at;
        String::from_utf8_lossy(&sm[at..end]).into_owned()
    };
    check!(h, r == 0 && s64(40) == proc_ && s64(48) == root, "statmount(/proc) names it and its parent");
    check!(h, r == 0 && string(36) == "proc" && string(108) == "/proc", "  its type and its point: {:?} {:?}", string(36), string(108));
    let bad = [24u64, 5, 0, 0];
    check_fails!(h, sys(NR_STATMOUNT, &[bad.as_ptr() as i64, sm.as_mut_ptr() as i64, 4096, 0]), libc::EINVAL, "an id below the unique range");
    let all = [24u64, u64::MAX, 0, 0];
    let mut ids = vec![0u64; 256];
    let n = sys(NR_LISTMOUNT, &[all.as_ptr() as i64, ids.as_mut_ptr() as i64, 256, 0]);
    let listed = &ids[..n.max(0) as usize];
    check!(h, listed.contains(&root) && listed.contains(&proc_), "listmount(LSMT_ROOT) lists / and /proc");
    check!(h, listed.windows(2).all(|w| w[0] < w[1]), "  in ascending order");

    h.group("file handles");
    let mut handle = vec![0u8; 8 + 128];
    handle[0..4].copy_from_slice(&128u32.to_le_bytes());
    let mut mnt: i32 = 0;
    let status = cpath("/proc/self/status");
    let r = sys(NR_NAME_TO_HANDLE_AT, &[AT_FDCWD, p(&status), handle.as_mut_ptr() as i64, &mut mnt as *mut i32 as i64, 0x200]);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::stat(status.as_ptr(), &mut st) };
    let bytes = u32::from_le_bytes(handle[0..4].try_into().unwrap());
    let kind = i32::from_le_bytes(handle[4..8].try_into().unwrap());
    let ino = u64::from_le_bytes(handle[8..16].try_into().unwrap());
    check!(h, r == 0 && bytes == 12 && kind == 0x81 && ino == st.st_ino, "AT_HANDLE_FID is the generic ino64 handle: {r} {bytes} {kind:#x}");
    handle[0..4].copy_from_slice(&128u32.to_le_bytes());
    check_fails!(h, sys(NR_NAME_TO_HANDLE_AT, &[AT_FDCWD, p(&status), handle.as_mut_ptr() as i64, &mut mnt as *mut i32 as i64, 0]), libc::EOPNOTSUPP, "a decodable handle from a filesystem that exports none");
    handle[0..4].copy_from_slice(&0u32.to_le_bytes());
    check_fails!(h, sys(NR_NAME_TO_HANDLE_AT, &[AT_FDCWD, p(&status), handle.as_mut_ptr() as i64, &mut mnt as *mut i32 as i64, 0x200]), libc::EOVERFLOW, "a buffer too small");
    check!(h, u32::from_le_bytes(handle[0..4].try_into().unwrap()) == 12, "  says how big it needs to be");
    check_fails!(h, sys(NR_OPEN_BY_HANDLE_AT, &[999, handle.as_mut_ptr() as i64, 0]), libc::EBADF, "open_by_handle_at, a closed mount fd");

    let _ = (O_WRONLY, O_RDWR);
    std::process::exit(h.finish());
}
