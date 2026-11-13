//! `openat2(2)`: the extensible argument struct and the six `RESOLVE_*` flags.
//!
//! # Why this exists
//!
//! `openat2` is what a caller uses when it wants *containment*: Go's
//! `os.Root`, runc, systemd's `chase()` and every container runtime keep a
//! path walk inside a subtree with `RESOLVE_BENEATH` or `RESOLVE_IN_ROOT`. An
//! implementation that hands back a descriptor without enforcing the flags is
//! worse than `ENOSYS`, which every one of those callers falls back from. So
//! each flag is probed for the escape it exists to stop -- `..`, an absolute
//! path, an absolute symlink, a relative symlink that climbs, a procfs magic
//! link, a mount crossing -- and for the ordinary path it must still allow.
//!
//! Nothing is asserted. One line per case; the difference against a real
//! arm64 kernel through `tests/integration/probe_diff.sh` is the finding.
//!
//! A descriptor that comes back is named by what it is open on, compared by
//! `(st_dev, st_ino)` against the files the probe made, so "it opened
//! something" and "it opened the file outside the root" read differently.

use std::ffi::CString;

const NR_OPENAT: i64 = 56;
const NR_OPENAT2: i64 = 437;
const AT_FDCWD: i64 = -100;

const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_NONBLOCK: u64 = 0o4000;
const O_DIRECTORY: u64 = 0o40000;
const O_NOFOLLOW: u64 = 0o100000;
const O_LARGEFILE: u64 = 0o400000;
const O_CLOEXEC: u64 = 0o2000000;
const O_PATH: u64 = 0o10000000;
const O_TMPFILE: u64 = 0o20000000 | O_DIRECTORY;
const O_EMPTYPATH: u64 = 1 << 26;
const OPENAT2_REGULAR: u64 = 1 << 32;

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;

fn errname(e: i64) -> String {
    let n = match e {
        1 => "EPERM", 2 => "ENOENT", 7 => "E2BIG", 9 => "EBADF", 11 => "EAGAIN",
        13 => "EACCES", 14 => "EFAULT", 17 => "EEXIST", 18 => "EXDEV",
        20 => "ENOTDIR", 21 => "EISDIR", 22 => "EINVAL", 38 => "ENOSYS",
        40 => "ELOOP", 95 => "EOPNOTSUPP", 6 => "ENXIO", 26 => "ETXTBSY",
        134 => "EFTYPE",
        _ => return format!("errno {e}"),
    };
    n.into()
}

unsafe fn sys(n: i64, a: i64, b: i64, c: i64, d: i64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") n,
            inlateout("x0") a => ret,
            in("x1") b,
            in("x2") c,
            in("x3") d,
            options(nostack)
        );
    }
    ret
}

/// The files the probe made, by identity, so an answer can say which one a
/// descriptor is open on.
struct Known(Vec<(String, u64, u64)>);

impl Known {
    fn name_of(&self, fd: i64) -> String {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd as i32, &mut st) } != 0 {
            return "fstat failed".into();
        }
        for (name, dev, ino) in &self.0 {
            if st.st_dev == *dev && st.st_ino == *ino {
                return name.clone();
            }
        }
        format!("something else (mode {:o})", st.st_mode & libc::S_IFMT)
    }
}

fn identity(path: &str) -> (u64, u64) {
    let c = CString::new(path).unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::lstat(c.as_ptr(), &mut st) };
    (st.st_dev, st.st_ino)
}

/// `struct open_how` with room for a tail, so a case can pass a size larger
/// than the three fields.
#[repr(C, align(8))]
struct How {
    words: [u64; 512],
}

impl How {
    fn new(flags: u64, mode: u64, resolve: u64) -> Box<How> {
        let mut h = Box::new(How { words: [0; 512] });
        h.words[0] = flags;
        h.words[1] = mode;
        h.words[2] = resolve;
        h
    }
}

fn openat2_raw(dirfd: i64, path: *const libc::c_char, how: *const How, size: usize) -> i64 {
    unsafe { sys(NR_OPENAT2, dirfd, path as i64, how as i64, size as i64) }
}

fn show(known: &Known, what: &str, r: i64) {
    let answer = if r < 0 {
        errname(-r)
    } else {
        let s = format!("ok: {}", known.name_of(r));
        unsafe { libc::close(r as i32) };
        s
    };
    println!("{what:<60} -> {answer}");
}

fn case(known: &Known, what: &str, dirfd: i64, path: &str, flags: u64, mode: u64, resolve: u64) {
    let c = CString::new(path).unwrap();
    let how = How::new(flags, mode, resolve);
    show(known, what, openat2_raw(dirfd, c.as_ptr(), &*how, 24));
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/openat2probe".into());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(format!("{dir}/sub/deep")).unwrap();
    std::fs::write(format!("{dir}/f"), b"hello").unwrap();
    std::fs::write(format!("{dir}/sub/g"), b"g").unwrap();
    let sl = |target: &str, name: &str| std::os::unix::fs::symlink(target, format!("{dir}/{name}")).unwrap();
    sl("/etc", "abs");
    sl("/sub/g", "abs_in_root");
    sl("sub", "rel");
    sl("..", "up");
    sl("../../", "sub/upup");
    sl("../f", "sub/back");
    sl("loop", "loop");
    sl("nothing", "dangling");

    let mut known = vec![("the root dir".to_string(), 0, 0)];
    known[0] = ("the root dir".into(), identity(&dir).0, identity(&dir).1);
    for (name, p) in [
        ("f", format!("{dir}/f")),
        ("sub", format!("{dir}/sub")),
        ("sub/g", format!("{dir}/sub/g")),
        ("the root's parent", format!("{dir}/..")),
        ("/etc", "/etc".into()),
        ("/etc/passwd", "/etc/passwd".into()),
        ("/proc", "/proc".into()),
        ("the symlink rel", format!("{dir}/rel")),
        ("the symlink abs", format!("{dir}/abs")),
    ] {
        let (d, i) = identity(&p);
        known.push((name.into(), d, i));
    }
    let known = Known(known);

    let dpath = CString::new(dir.clone()).unwrap();
    let dirfd = unsafe { libc::open(dpath.as_ptr(), libc::O_PATH | libc::O_DIRECTORY) } as i64;
    let procfd = unsafe { libc::open(c"/proc".as_ptr(), libc::O_PATH | libc::O_DIRECTORY) } as i64;
    let rootfd = unsafe { libc::open(c"/".as_ptr(), libc::O_PATH | libc::O_DIRECTORY) } as i64;
    let filefd = unsafe { libc::open(CString::new(format!("{dir}/f")).unwrap().as_ptr(), libc::O_RDONLY) } as i64;
    let fpath = format!("/proc/self/fd/{filefd}");

    println!("########## the size argument ##########");
    let f = CString::new("f").unwrap();
    for (what, size) in [
        ("size 0", 0usize),
        ("size 23, one short of VER0", 23),
        ("size 24, VER0", 24),
        ("size 32, zero tail", 32),
        ("size 4096, zero tail", 4096),
        ("size 4097, one past a page", 4097),
    ] {
        let how = How::new(0, 0, 0);
        show(&known, what, openat2_raw(dirfd, f.as_ptr(), &*how, size));
    }
    {
        let mut how = How::new(0, 0, 0);
        how.words[3] = 1;
        show(&known, "size 32, a nonzero byte in the tail", openat2_raw(dirfd, f.as_ptr(), &*how, 32));
        let mut how = How::new(0, 0, 0);
        how.words[511] = 1 << 56;
        show(&known, "size 4096, the last byte nonzero", openat2_raw(dirfd, f.as_ptr(), &*how, 4096));
    }
    show(&known, "how = NULL", openat2_raw(dirfd, f.as_ptr(), std::ptr::null(), 24));
    show(&known, "how = NULL, size 4097", openat2_raw(dirfd, f.as_ptr(), std::ptr::null(), 4097));
    show(&known, "how = NULL, size 0", openat2_raw(dirfd, f.as_ptr(), std::ptr::null(), 0));
    show(&known, "path = NULL", openat2_raw(dirfd, std::ptr::null(), &*How::new(0, 0, 0), 24));
    show(&known, "path = NULL and a bad flag", openat2_raw(dirfd, std::ptr::null(), &*How::new(1 << 40, 0, 0), 24));
    show(&known, "path = NULL and BENEATH|IN_ROOT", openat2_raw(dirfd, std::ptr::null(), &*How::new(0, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT), 24));
    case(&known, "empty path", dirfd, "", 0, 0, 0);
    case(&known, "a closed dirfd, relative", 999, "f", 0, 0, 0);
    case(&known, "a closed dirfd, absolute", 999, &format!("{dir}/f"), 0, 0, 0);
    case(&known, "a closed dirfd, absolute, IN_ROOT", 999, "/f", 0, 0, RESOLVE_IN_ROOT);
    case(&known, "a closed dirfd, absolute, BENEATH", 999, "/f", 0, 0, RESOLVE_BENEATH);
    case(&known, "a file as dirfd", filefd, "x", 0, 0, 0);

    println!("########## flags ##########");
    for bit in 0..32u32 {
        let fl = 1u64 << bit;
        let path = format!("bit{bit}");
        let what = format!("flags bit {bit} ({fl:#o}) on a new name");
        case(&known, &what, dirfd, &path, fl, 0, 0);
    }
    for bit in 0..32u32 {
        let fl = 1u64 << bit;
        let what = format!("flags bit {bit} ({fl:#o}) on f");
        case(&known, &what, dirfd, "f", fl, 0, 0);
    }
    case(&known, "flags bit 32", dirfd, "f", 1 << 32, 0, 0);
    case(&known, "flags bit 63", dirfd, "f", 1 << 63, 0, 0);
    case(&known, "O_WRONLY|O_RDWR", dirfd, "f", O_WRONLY | O_RDWR, 0, 0);
    case(&known, "O_DIRECTORY|O_CREAT on a new name", dirfd, "dc", O_DIRECTORY | O_CREAT, 0o644, 0);
    case(&known, "O_DIRECTORY|O_CREAT on sub", dirfd, "sub", O_DIRECTORY | O_CREAT, 0o644, 0);
    case(&known, "O_TMPFILE|O_RDWR in sub", dirfd, "sub", O_TMPFILE | O_RDWR, 0o600, 0);
    case(&known, "O_TMPFILE read-only in sub", dirfd, "sub", O_TMPFILE, 0o600, 0);
    case(&known, "O_PATH", dirfd, "f", O_PATH, 0, 0);
    case(&known, "O_PATH|O_CLOEXEC|O_NOFOLLOW", dirfd, "f", O_PATH | O_CLOEXEC | O_NOFOLLOW, 0, 0);
    case(&known, "O_PATH|O_DIRECTORY on sub", dirfd, "sub", O_PATH | O_DIRECTORY, 0, 0);
    case(&known, "O_PATH|O_RDWR", dirfd, "f", O_PATH | O_RDWR, 0, 0);
    case(&known, "O_PATH|O_LARGEFILE", dirfd, "f", O_PATH | O_LARGEFILE, 0, 0);
    case(&known, "O_PATH|O_NONBLOCK", dirfd, "f", O_PATH | O_NONBLOCK, 0, 0);
    case(&known, "O_PATH|O_CREAT", dirfd, "pc", O_PATH | O_CREAT, 0, 0);
    case(&known, "O_PATH|O_NOFOLLOW on the symlink rel", dirfd, "rel", O_PATH | O_NOFOLLOW, 0, 0);
    case(&known, "O_NOFOLLOW on the symlink rel", dirfd, "rel", O_NOFOLLOW, 0, 0);
    {
        let c = CString::new("f").unwrap();
        let how = How::new(O_CLOEXEC, 0, 0);
        let fd = openat2_raw(dirfd, c.as_ptr(), &*how, 24);
        let fdfl = if fd >= 0 { unsafe { libc::fcntl(fd as i32, libc::F_GETFD) } } else { -1 };
        println!("{:<60} -> {fdfl}", "O_CLOEXEC sets FD_CLOEXEC");
        if fd >= 0 { unsafe { libc::close(fd as i32) }; }
        let how = How::new(0, 0, 0);
        let fd = openat2_raw(dirfd, c.as_ptr(), &*how, 24);
        let fl = if fd >= 0 { unsafe { libc::fcntl(fd as i32, libc::F_GETFL) } } else { -1 };
        println!("{:<60} -> {fl:#o}", "F_GETFL of a plain open");
        if fd >= 0 { unsafe { libc::close(fd as i32) }; }
        let how = How::new(O_PATH, 0, 0);
        let fd = openat2_raw(dirfd, c.as_ptr(), &*how, 24);
        let fl = if fd >= 0 { unsafe { libc::fcntl(fd as i32, libc::F_GETFL) } } else { -1 };
        println!("{:<60} -> {fl:#o}", "F_GETFL of an O_PATH open");
        if fd >= 0 { unsafe { libc::close(fd as i32) }; }
    }
    // The same rule through plain openat, which has had it since 6.4.
    {
        let c = CString::new("dc2").unwrap();
        let r = unsafe { sys(NR_OPENAT, dirfd, c.as_ptr() as i64, (O_DIRECTORY | O_CREAT) as i64, 0o644) };
        show(&known, "openat(O_DIRECTORY|O_CREAT) on a new name", r);
        let c = CString::new("f").unwrap();
        let r = unsafe { sys(NR_OPENAT, dirfd, c.as_ptr() as i64, 1 << 40, 0) };
        show(&known, "openat with a bit above 31", r);
    }

    println!("########## mode ##########");
    case(&known, "mode without O_CREAT", dirfd, "f", 0, 0o644, 0);
    case(&known, "mode 07777 with O_CREAT", dirfd, "m1", O_CREAT, 0o7777, 0);
    case(&known, "mode 010000 with O_CREAT", dirfd, "m2", O_CREAT, 0o10000, 0);
    case(&known, "mode 1<<40 with O_CREAT", dirfd, "m3", O_CREAT, 1 << 40, 0);
    case(&known, "mode 010000 with O_TMPFILE", dirfd, "sub", O_TMPFILE | O_RDWR, 0o10000, 0);
    {
        let old = unsafe { libc::umask(0o022) };
        let c = CString::new("um").unwrap();
        let how = How::new(O_CREAT | O_WRONLY, 0o777, 0);
        let fd = openat2_raw(dirfd, c.as_ptr(), &*how, 24);
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if fd >= 0 {
            unsafe { libc::fstat(fd as i32, &mut st) };
            unsafe { libc::close(fd as i32) };
        }
        println!("{:<60} -> {:o}", "O_CREAT 0777 under umask 022", st.st_mode & 0o7777);
        unsafe { libc::umask(old) };
    }

    println!("########## resolve ##########");
    case(&known, "resolve 0x40, a bit nothing defines", dirfd, "f", 0, 0, 0x40);
    case(&known, "resolve 1<<63", dirfd, "f", 0, 0, 1 << 63);
    case(&known, "BENEATH|IN_ROOT", dirfd, "f", 0, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT);
    case(&known, "every defined flag but IN_ROOT", dirfd, "f", 0, 0, 0x2f);

    println!("########## RESOLVE_BENEATH ##########");
    let b = RESOLVE_BENEATH;
    case(&known, "f", dirfd, "f", 0, 0, b);
    case(&known, "sub/g", dirfd, "sub/g", 0, 0, b);
    case(&known, "sub/../f", dirfd, "sub/../f", 0, 0, b);
    case(&known, ".", dirfd, ".", 0, 0, b);
    case(&known, "sub/..", dirfd, "sub/..", 0, 0, b);
    case(&known, "..", dirfd, "..", 0, 0, b);
    case(&known, "sub/../..", dirfd, "sub/../..", 0, 0, b);
    case(&known, "../<dir>/f, out and back in", dirfd, &format!("../{}/f", dir.rsplit('/').next().unwrap()), 0, 0, b);
    case(&known, "an absolute path", dirfd, &format!("{dir}/f"), 0, 0, b);
    case(&known, "/", dirfd, "/", 0, 0, b);
    case(&known, "abs, an absolute symlink", dirfd, "abs", 0, 0, b);
    case(&known, "abs with O_PATH|O_NOFOLLOW", dirfd, "abs", O_PATH | O_NOFOLLOW, 0, b);
    case(&known, "abs/passwd", dirfd, "abs/passwd", 0, 0, b);
    case(&known, "rel/g, a relative symlink inside", dirfd, "rel/g", 0, 0, b);
    case(&known, "up/f, a relative symlink to ..", dirfd, "up/f", 0, 0, b);
    case(&known, "sub/upup/f, a symlink two levels up", dirfd, "sub/upup/f", 0, 0, b);
    case(&known, "sub/back, ../f from sub", dirfd, "sub/back", 0, 0, b);
    case(&known, "loop", dirfd, "loop", 0, 0, b);
    case(&known, "dangling", dirfd, "dangling", 0, 0, b);
    case(&known, "missing/..", dirfd, "missing/..", 0, 0, b);
    case(&known, "f/..", dirfd, "f/..", 0, 0, b);
    case(&known, "/proc's self/status", procfd, "self/status", 0, 0, b);
    case(&known, "/proc's self/fd/<n>, a magic link", procfd, &format!("self/fd/{filefd}"), 0, 0, b);
    case(&known, "/proc's self/fd/<n> with O_PATH|O_NOFOLLOW", procfd, &format!("self/fd/{filefd}"), O_PATH | O_NOFOLLOW, 0, b);
    case(&known, "/proc's self/cwd", procfd, "self/cwd", O_PATH, 0, b);
    case(&known, "/proc's self/root", procfd, "self/root", O_PATH, 0, b);
    case(&known, "/proc's self/exe", procfd, "self/exe", O_PATH, 0, b);
    case(&known, "O_CREAT of a new name", dirfd, "bn", O_CREAT | O_WRONLY, 0o644, b);
    case(&known, "O_CREAT of ../escape", dirfd, "../openat2-escape", O_CREAT | O_WRONLY, 0o644, b);
    case(&known, "O_CREAT through up/", dirfd, "up/openat2-escape2", O_CREAT | O_WRONLY, 0o644, b);
    {
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        case(&known, "AT_FDCWD, f", AT_FDCWD, "f", 0, 0, b);
        case(&known, "AT_FDCWD, ..", AT_FDCWD, "..", 0, 0, b);
        case(&known, "AT_FDCWD, up/f", AT_FDCWD, "up/f", 0, 0, b);
        std::env::set_current_dir(cwd).unwrap();
    }
    case(&known, "the root as dirfd, ..", rootfd, "..", 0, 0, b);
    case(&known, "the root as dirfd, etc/passwd", rootfd, "etc/passwd", 0, 0, b);

    println!("########## RESOLVE_IN_ROOT ##########");
    let ir = RESOLVE_IN_ROOT;
    case(&known, "f", dirfd, "f", 0, 0, ir);
    case(&known, "/f", dirfd, "/f", 0, 0, ir);
    case(&known, "/", dirfd, "/", 0, 0, ir);
    case(&known, "..", dirfd, "..", 0, 0, ir);
    case(&known, "../../f", dirfd, "../../f", 0, 0, ir);
    case(&known, "/../sub/g", dirfd, "/../sub/g", 0, 0, ir);
    case(&known, "abs, -> /etc", dirfd, "abs", 0, 0, ir);
    case(&known, "abs_in_root, -> /sub/g", dirfd, "abs_in_root", 0, 0, ir);
    case(&known, "up/f", dirfd, "up/f", 0, 0, ir);
    case(&known, "sub/upup/f", dirfd, "sub/upup/f", 0, 0, ir);
    case(&known, "/etc/passwd", dirfd, "/etc/passwd", 0, 0, ir);
    case(&known, "/proc's self/fd/<n>", procfd, &format!("self/fd/{filefd}"), 0, 0, ir);
    case(&known, "/proc's /self/status", procfd, "/self/status", 0, 0, ir);
    case(&known, "O_CREAT of /../made", dirfd, "/../made", O_CREAT | O_WRONLY, 0o644, ir);
    {
        let made = std::path::Path::new(&dir).join("made").exists();
        println!("{:<60} -> {made}", "  ... and it is inside the root");
    }

    println!("########## RESOLVE_NO_SYMLINKS ##########");
    let ns = RESOLVE_NO_SYMLINKS;
    case(&known, "f", dirfd, "f", 0, 0, ns);
    case(&known, "rel/g", dirfd, "rel/g", 0, 0, ns);
    case(&known, "rel", dirfd, "rel", 0, 0, ns);
    case(&known, "rel with O_PATH|O_NOFOLLOW", dirfd, "rel", O_PATH | O_NOFOLLOW, 0, ns);
    case(&known, "rel with O_NOFOLLOW", dirfd, "rel", O_NOFOLLOW, 0, ns);
    case(&known, "rel/ with O_PATH|O_NOFOLLOW", dirfd, "rel/", O_PATH | O_NOFOLLOW, 0, ns);
    case(&known, "abs", dirfd, "abs", 0, 0, ns);
    case(&known, "dangling", dirfd, "dangling", 0, 0, ns);
    case(&known, "dangling with O_CREAT", dirfd, "dangling", O_CREAT | O_WRONLY, 0o644, ns);
    case(&known, "/proc/self/status", AT_FDCWD, "/proc/self/status", 0, 0, ns);
    case(&known, "/proc/<fd>", AT_FDCWD, &fpath, 0, 0, ns);

    println!("########## RESOLVE_NO_MAGICLINKS ##########");
    let nm = RESOLVE_NO_MAGICLINKS;
    case(&known, "/proc/self/fd/<n>", AT_FDCWD, &fpath, 0, 0, nm);
    case(&known, "/proc/self/fd/<n> with O_PATH|O_NOFOLLOW", AT_FDCWD, &fpath, O_PATH | O_NOFOLLOW, 0, nm);
    case(&known, "/proc/self/status", AT_FDCWD, "/proc/self/status", 0, 0, nm);
    case(&known, "/proc/self/cwd", AT_FDCWD, "/proc/self/cwd", O_PATH, 0, nm);
    case(&known, "/proc/self/exe", AT_FDCWD, "/proc/self/exe", O_PATH, 0, nm);
    case(&known, "/proc/self/root", AT_FDCWD, "/proc/self/root", O_PATH, 0, nm);
    case(&known, "/proc/self/fd/0", AT_FDCWD, "/proc/self/fd/0", 0, 0, nm);
    case(&known, "/proc/self/fd/<n>/, through it", AT_FDCWD, &format!("{fpath}/"), 0, 0, nm);
    case(&known, "/proc/self/cwd/f, through a magic dir", AT_FDCWD, "/proc/self/cwd/f", 0, 0, nm);
    case(&known, "rel/g, an ordinary symlink", dirfd, "rel/g", 0, 0, nm);
    case(&known, "/proc/self/fd/<n>, no flag", AT_FDCWD, &fpath, 0, 0, 0);

    println!("########## RESOLVE_NO_XDEV ##########");
    let nx = RESOLVE_NO_XDEV;
    case(&known, "f", dirfd, "f", 0, 0, nx);
    case(&known, "the root as dirfd, proc", rootfd, "proc", O_PATH, 0, nx);
    case(&known, "the root as dirfd, proc/self/status", rootfd, "proc/self/status", 0, 0, nx);
    case(&known, "the root as dirfd, etc/passwd", rootfd, "etc/passwd", 0, 0, nx);
    case(&known, "the root as dirfd, .", rootfd, ".", O_PATH, 0, nx);
    case(&known, "/proc as dirfd, self/status", procfd, "self/status", 0, 0, nx);
    case(&known, "/proc as dirfd, .", procfd, ".", O_PATH, 0, nx);
    case(&known, "/proc as dirfd, ..", procfd, "..", O_PATH, 0, nx);
    case(&known, "/proc as dirfd, an absolute /etc/passwd", procfd, "/etc/passwd", 0, 0, nx);
    case(&known, "/proc as dirfd, an absolute /proc/self/status", procfd, "/proc/self/status", 0, 0, nx);
    case(&known, "/proc as dirfd, self/fd/<n>, a magic link out", procfd, &format!("self/fd/{filefd}"), 0, 0, nx);
    case(&known, "AT_FDCWD, /proc", AT_FDCWD, "/proc", O_PATH, 0, nx);
    case(&known, "AT_FDCWD, /", AT_FDCWD, "/", O_PATH, 0, nx);
    case(&known, "abs, a symlink staying on this mount", dirfd, "abs", O_PATH, 0, nx);
    case(&known, "rel/g", dirfd, "rel/g", 0, 0, nx);
    // Linux sets the walk's root lazily: an absolute path or a `..` sets it,
    // and an absolute symlink met before either is EXDEV under NO_XDEV.
    case(&known, "sub/../abs, a `..` first", dirfd, "sub/../abs", O_PATH, 0, nx);
    case(&known, "an absolute <dir>/abs", AT_FDCWD, &format!("{dir}/abs"), O_PATH, 0, nx);
    {
        // A symlink whose target is on another mount.
        let _ = std::os::unix::fs::symlink("/proc/self", format!("{dir}/toproc"));
        case(&known, "toproc, -> /proc/self", dirfd, "toproc", O_PATH, 0, nx);
        case(&known, "toproc with O_PATH|O_NOFOLLOW", dirfd, "toproc", O_PATH | O_NOFOLLOW, 0, nx);
    }

    println!("########## RESOLVE_CACHED ##########");
    let ca = RESOLVE_CACHED;
    case(&known, "f, just written", dirfd, "f", 0, 0, ca);
    case(&known, "O_CREAT", dirfd, "cc", O_CREAT | O_WRONLY, 0o644, ca);
    case(&known, "O_CREAT of an existing f", dirfd, "f", O_CREAT | O_WRONLY, 0o644, ca);
    case(&known, "O_TRUNC", dirfd, "f", O_TRUNC | O_WRONLY, 0, ca);
    case(&known, "O_TMPFILE", dirfd, "sub", O_TMPFILE | O_RDWR, 0o600, ca);
    case(&known, "rel/g, through a symlink", dirfd, "rel/g", 0, 0, ca);
    case(&known, "/proc/self/status", AT_FDCWD, "/proc/self/status", 0, 0, ca);
    case(&known, "/proc/self/fd/<n>", AT_FDCWD, &fpath, 0, 0, ca);
    case(&known, "missing", dirfd, "missing", 0, 0, ca);
    case(&known, "CACHED|BENEATH, ..", dirfd, "..", 0, 0, ca | b);

    println!("########## O_EMPTYPATH and OPENAT2_REGULAR ##########");
    {
        let opath_f = unsafe { libc::open(CString::new(format!("{dir}/f")).unwrap().as_ptr(), libc::O_PATH) } as i64;
        case(&known, "O_EMPTYPATH on an O_PATH fd of f", opath_f, "", O_EMPTYPATH, 0, 0);
        case(&known, "O_EMPTYPATH|O_RDWR on an O_PATH fd of f", opath_f, "", O_EMPTYPATH | O_RDWR, 0, 0);
        case(&known, "O_EMPTYPATH on the dirfd", dirfd, "", O_EMPTYPATH, 0, 0);
        case(&known, "O_EMPTYPATH|O_DIRECTORY on f", opath_f, "", O_EMPTYPATH | O_DIRECTORY, 0, 0);
        case(&known, "O_EMPTYPATH on AT_FDCWD", AT_FDCWD, "", O_EMPTYPATH | O_DIRECTORY, 0, 0);
        case(&known, "O_EMPTYPATH on a closed fd", 999, "", O_EMPTYPATH, 0, 0);
        case(&known, "O_EMPTYPATH with a name", dirfd, "f", O_EMPTYPATH, 0, 0);
        case(&known, "O_EMPTYPATH|O_CREAT", dirfd, "", O_EMPTYPATH | O_CREAT, 0o644, 0);
        case(&known, "O_EMPTYPATH|O_PATH", opath_f, "", O_EMPTYPATH | O_PATH, 0, 0);
        case(&known, "O_EMPTYPATH with BENEATH", opath_f, "", O_EMPTYPATH, 0, b);
        case(&known, "O_EMPTYPATH on the symlink rel's O_PATH fd", {
            unsafe { libc::open(CString::new(format!("{dir}/rel")).unwrap().as_ptr(), libc::O_PATH | libc::O_NOFOLLOW) as i64 }
        }, "", O_EMPTYPATH, 0, 0);
        let r = unsafe { sys(NR_OPENAT, opath_f, c"".as_ptr() as i64, O_EMPTYPATH as i64, 0) };
        show(&known, "openat: O_EMPTYPATH on an O_PATH fd of f", r);
        let r = unsafe { sys(NR_OPENAT, dirfd, c"".as_ptr() as i64, 0, 0) };
        show(&known, "openat: empty path without O_EMPTYPATH", r);
        let r = unsafe { sys(NR_OPENAT, 999, c"".as_ptr() as i64, 0, 0) };
        show(&known, "openat: empty path, a closed dirfd", r);
        case(&known, "empty path, a closed dirfd", 999, "", 0, 0, 0);
        let r = unsafe { sys(NR_OPENAT, opath_f, c"".as_ptr() as i64, O_EMPTYPATH as i64, 0) };
        let fl = if r >= 0 { unsafe { libc::fcntl(r as i32, libc::F_GETFL) } } else { -1 };
        println!("{:<60} -> {fl:#o}", "F_GETFL after an O_EMPTYPATH open");
        if r >= 0 { unsafe { libc::close(r as i32) }; }
        case(&known, "O_CREAT of the existing directory sub", dirfd, "sub", O_CREAT, 0o644, 0);
        let r = unsafe { sys(NR_OPENAT, dirfd, c"sub".as_ptr() as i64, O_CREAT as i64, 0o644) };
        show(&known, "openat: O_CREAT of the existing directory sub", r);
        let r = unsafe { sys(NR_OPENAT, dirfd, c"pathcreat".as_ptr() as i64, (O_PATH | O_CREAT) as i64, 0o644) };
        show(&known, "openat: O_PATH|O_CREAT of a new name", r);
        let r = unsafe { sys(NR_OPENAT, dirfd, c"f".as_ptr() as i64, (O_PATH | O_RDWR | O_WRONLY) as i64, 0) };
        show(&known, "openat: O_PATH|O_RDWR|O_WRONLY", r);
        case(&known, "OPENAT2_REGULAR on f", dirfd, "f", OPENAT2_REGULAR, 0, 0);
        case(&known, "OPENAT2_REGULAR on sub", dirfd, "sub", OPENAT2_REGULAR, 0, 0);
        case(&known, "OPENAT2_REGULAR|O_PATH on sub", dirfd, "sub", OPENAT2_REGULAR | O_PATH, 0, 0);
        case(&known, "OPENAT2_REGULAR|O_DIRECTORY on sub", dirfd, "sub", OPENAT2_REGULAR | O_DIRECTORY, 0, 0);
        case(&known, "OPENAT2_REGULAR on /dev/null", AT_FDCWD, "/dev/null", OPENAT2_REGULAR, 0, 0);
        case(&known, "OPENAT2_REGULAR|O_CREAT of a new name", dirfd, "reg", OPENAT2_REGULAR | O_CREAT | O_WRONLY, 0o644, 0);
        case(&known, "OPENAT2_REGULAR|O_PATH|O_NOFOLLOW on rel", dirfd, "rel", OPENAT2_REGULAR | O_PATH | O_NOFOLLOW, 0, 0);
        case(&known, "OPENAT2_REGULAR on rel/g", dirfd, "rel/g", OPENAT2_REGULAR, 0, 0);
        case(&known, "OPENAT2_REGULAR|O_TMPFILE", dirfd, "sub", OPENAT2_REGULAR | O_TMPFILE | O_RDWR, 0o600, 0);
        case(&known, "bit 33", dirfd, "f", 1 << 33, 0, 0);
        let r = unsafe { sys(NR_OPENAT, dirfd, c"f".as_ptr() as i64, OPENAT2_REGULAR as i64, 0) };
        show(&known, "openat: bit 32 is not OPENAT2_REGULAR there", r);
        let r = unsafe { sys(NR_OPENAT, dirfd, c"sub".as_ptr() as i64, OPENAT2_REGULAR as i64, 0) };
        show(&known, "openat: bit 32 on sub", r);
    }

    println!("########## combinations ##########");
    case(&known, "BENEATH|NO_SYMLINKS, rel/g", dirfd, "rel/g", 0, 0, b | ns);
    case(&known, "BENEATH|NO_SYMLINKS, abs", dirfd, "abs", 0, 0, b | ns);
    case(&known, "IN_ROOT|NO_SYMLINKS, abs_in_root", dirfd, "abs_in_root", 0, 0, ir | ns);
    case(&known, "IN_ROOT|NO_XDEV, /proc's /..", procfd, "/..", O_PATH, 0, ir | nx);
    case(&known, "BENEATH|NO_MAGICLINKS, /proc's self/fd/<n>", procfd, &format!("self/fd/{filefd}"), 0, 0, b | nm);
    case(&known, "NO_SYMLINKS|NO_MAGICLINKS, /proc/self/fd/<n>", AT_FDCWD, &fpath, 0, 0, ns | nm);
    case(&known, "BENEATH, a trailing slash on f", dirfd, "f/", 0, 0, b);
    case(&known, "BENEATH, sub/", dirfd, "sub/", O_PATH, 0, b);
    case(&known, "no flag, missing/../f", dirfd, "missing/../f", 0, 0, 0);
    case(&known, "no flag, f/../f", dirfd, "f/../f", 0, 0, 0);
    case(&known, "no flag, dangling/../f", dirfd, "dangling/../f", 0, 0, 0);
}
