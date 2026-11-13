//! What `statfs` says about a filesystem, and what `fstatfs` says about a
//! descriptor that has none.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! # Why this exists
//!
//! `f_type` is what a program branches on to decide what it is standing on —
//! systemd looks for `TMPFS_MAGIC` and `PROC_SUPER_MAGIC`, `git` looks for a
//! network filesystem, `du` and `df` print a name for it — and `f_flags` is
//! what tells a caller the mount is read-only *before* it tries to write. An
//! installer that checks `ST_RDONLY` and is told 0 goes on to fail halfway.
//!
//! # Nothing here prints a block count
//!
//! They are the host's and differ between two machines. What is reported is
//! the *shape*: whether a field is plausible, which flag bits are set, and
//! whether two mounts answer differently — which is the whole content of
//! `f_type`.

use std::ffi::CString;
use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<50} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::ENOENT => "ENOENT",
        libc::ENOTDIR => "ENOTDIR",
        libc::EFAULT => "EFAULT",
        libc::EBADF => "EBADF",
        libc::EACCES => "EACCES",
        libc::ELOOP => "ELOOP",
        libc::ENOSYS => "ENOSYS",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn c(p: &str) -> CString {
    CString::new(p).unwrap()
}

/// The `f_flags` bits `statfs` reports, by name. `ST_VALID` says the kernel
/// filled the field at all — a kernel that leaves it zero is indistinguishable
/// from one reporting a filesystem with no properties.
fn flag_names(f: u64) -> String {
    let mut out = Vec::new();
    for (bit, name) in [
        (1u64, "RDONLY"),
        (2, "NOSUID"),
        (4, "NODEV"),
        (8, "NOEXEC"),
        (16, "SYNCHRONOUS"),
        (32, "VALID"),
        (64, "MANDLOCK"),
        (512, "NOATIME"),
        (1024, "NODIRATIME"),
        (4096, "RELATIME"),
    ] {
        if f & bit != 0 {
            out.push(name);
        }
    }
    if out.is_empty() { "none".into() } else { out.join("|") }
}

struct Fs {
    ty: i64,
    bsize: i64,
    namelen: i64,
    flags: u64,
    blocks: u64,
}

fn statfs(path: &str) -> Result<Fs, i32> {
    let mut buf: libc::statfs64 = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs64(c(path).as_ptr(), &mut buf) } < 0 {
        return Err(errno());
    }
    Ok(Fs {
        ty: buf.f_type as i64,
        bsize: buf.f_bsize as i64,
        namelen: buf.f_namelen as i64,
        flags: buf.f_flags as u64,
        blocks: buf.f_blocks,
    })
}

fn fstatfs(fd: i32) -> Result<Fs, i32> {
    let mut buf: libc::statfs64 = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs64(fd, &mut buf) } < 0 {
        return Err(errno());
    }
    Ok(Fs {
        ty: buf.f_type as i64,
        bsize: buf.f_bsize as i64,
        namelen: buf.f_namelen as i64,
        flags: buf.f_flags as u64,
        blocks: buf.f_blocks,
    })
}

/// A filesystem's answer as a comparable shape. The type is reported as
/// *which known magic it is*, because the number itself is the filesystem's
/// and two machines do not have the same ones.
fn describe(fs: &Fs) -> String {
    let ty: String = match fs.ty {
        0x0102_1994 => "TMPFS".into(),
        0x9fa0 => "PROC".into(),
        0x1cd1 => "DEVPTS".into(),
        0xef53 => "EXT".into(),
        0x794c_7630 => "OVERLAYFS".into(),
        0x5846_5342 => "XFS".into(),
        0x6969 => "NFS".into(),
        0x0102_0000 => "?".into(),
        0 => "zero".into(),
        _ => "an unknown magic".into(),
    };
    format!(
        "{ty}, bsize {}, namelen {}, flags {}",
        if fs.bsize > 0 && fs.bsize <= 1 << 20 { "plausible" } else { "odd" },
        fs.namelen,
        flag_names(fs.flags)
    )
}

fn main() {
    let dir = "/tmp/statfs_probe.d";
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();

    mounts(dir);
    descriptors(dir);
    refusals(dir);

    let _ = std::fs::remove_dir_all(dir);
}

/// One line per mount a guest is likely to stand on.
fn mounts(dir: &str) {
    println!("## statfs of a mount");
    for (what, path) in [
        ("the root", "/"),
        ("the scratch directory", dir),
        ("/proc", "/proc"),
        ("/proc/self/stat, a file on it", "/proc/self/stat"),
        ("/dev", "/dev"),
    ] {
        match statfs(path) {
            Ok(fs) => line(&format!("  {what}"), describe(&fs)),
            Err(e) => line(&format!("  {what}"), named(e)),
        }
    }
    // Two mounts that are different filesystems must not answer the same
    // magic. That is the whole point of the field, and it is a comparison the
    // two sides can both make without agreeing on the numbers.
    let root = statfs("/").map(|f| f.ty).unwrap_or(0);
    let proc = statfs("/proc").map(|f| f.ty).unwrap_or(0);
    line("  /proc and / differ", (root != proc).to_string());
    // A file and its directory are on the same filesystem.
    let f = statfs(&format!("{dir}/.")).map(|f| f.ty).unwrap_or(0);
    line("  a directory and its parent agree", (f == statfs(dir).map(|f| f.ty).unwrap_or(1)).to_string());
    // Blocks: a real filesystem has some.
    line(
        "  the root has blocks",
        statfs("/").map(|f| f.blocks > 0).unwrap_or(false).to_string(),
    );
}

/// `fstatfs` through a descriptor, including the kinds that are on no mount at
/// all.
fn descriptors(dir: &str) {
    println!("## fstatfs of a descriptor");
    let path = format!("{dir}/f");
    unsafe {
        let fd = libc::open(c(&path).as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644);
        libc::close(fd);
    }
    let fd = unsafe { libc::open(c(&path).as_ptr(), libc::O_RDONLY) };
    match fstatfs(fd) {
        Ok(fs) => line("  a regular file", describe(&fs)),
        Err(e) => line("  a regular file", named(e)),
    }
    // The same file by path and by descriptor: the same filesystem.
    let by_path = statfs(&path).map(|f| f.ty).unwrap_or(0);
    let by_fd = fstatfs(fd).map(|f| f.ty).unwrap_or(1);
    line("  by path and by descriptor agree", (by_path == by_fd).to_string());
    unsafe { libc::close(fd) };

    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    match fstatfs(p[0]) {
        Ok(fs) => line("  a pipe", describe(&fs)),
        Err(e) => line("  a pipe", named(e)),
    }
    unsafe {
        libc::close(p[0]);
        libc::close(p[1]);
    }

    let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    match fstatfs(s) {
        Ok(fs) => line("  a socket", describe(&fs)),
        Err(e) => line("  a socket", named(e)),
    }
    unsafe { libc::close(s) };

    let e = unsafe { libc::eventfd(0, 0) };
    match fstatfs(e) {
        Ok(fs) => line("  an eventfd", describe(&fs)),
        Err(e) => line("  an eventfd", named(e)),
    }
    unsafe { libc::close(e) };

    // A pipe and a socket are different filesystems to Linux -- pipefs and
    // sockfs -- and reporting one magic for both is what the C did.
    let mut p2 = [0i32; 2];
    unsafe { libc::pipe(p2.as_mut_ptr()) };
    let s2 = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    let pt = fstatfs(p2[0]).map(|f| f.ty).unwrap_or(0);
    let st = fstatfs(s2).map(|f| f.ty).unwrap_or(0);
    line("  a pipe and a socket differ", (pt != st).to_string());
    unsafe {
        libc::close(p2[0]);
        libc::close(p2[1]);
        libc::close(s2);
    }
}

/// What is refused.
fn refusals(dir: &str) {
    println!("## refusals");
    line(
        "  statfs of a path that is not there",
        match statfs(&format!("{dir}/nope")) {
            Ok(_) => "answered".into(),
            Err(e) => named(e),
        },
    );
    line(
        "  statfs through a file",
        match statfs(&format!("{dir}/f/x")) {
            Ok(_) => "answered".into(),
            Err(e) => named(e),
        },
    );
    line(
        "  statfs of the empty path",
        match statfs("") {
            Ok(_) => "answered".into(),
            Err(e) => named(e),
        },
    );
    line(
        "  fstatfs of -1",
        match fstatfs(-1) {
            Ok(_) => "answered".into(),
            Err(e) => named(e),
        },
    );
    // A null buffer, which the libc wrapper will not do for us.
    let rc = unsafe { libc::syscall(43, c("/").as_ptr(), 0u64) };
    line("  statfs into a null buffer", if rc < 0 { named(errno()) } else { rc.to_string() });
    let rc = unsafe { libc::syscall(44, 0, 0u64) };
    line("  fstatfs(0) into a null buffer", if rc < 0 { named(errno()) } else { rc.to_string() });
}
