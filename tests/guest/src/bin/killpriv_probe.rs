//! What a write does to a file's set-id bits and `security.capability`:
//! Linux's `file_remove_privs`, reached from `write`, `truncate`,
//! `fallocate`, `copy_file_range` and an `open(O_TRUNC)`, and not from a
//! store through a shared mapping.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container (`--privileged`, for `security.capability` on the overlay) and
//! diffed by `tests/integration/probe_diff.sh`. Each case gets a fresh file
//! and a fresh child; the descriptor is opened by root before the child
//! takes the caller's credentials, so every caller can write through it.
//!
//! Run by `probe_diff.sh` on realfs, which cannot give a file to another
//! user: the cases whose owner is not root differ there for that reason and
//! are in its KNOWN list; `killpriv` asserts them on fakefs.

use std::ffi::CString;
use std::io::Write;

const DIR: &str = "/tmp/killprivprobe";
const FSETID: u32 = 4;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<44} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[repr(C)]
struct Header {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn drop_effective(cap: u32) {
    let mut h = Header { version: 0x2008_0522, pid: 0 };
    let mut d = [Data::default(); 2];
    unsafe {
        libc::syscall(libc::SYS_capget, &raw mut h, d.as_mut_ptr());
        d[0].effective &= !(1 << cap);
        libc::syscall(libc::SYS_capset, &raw mut h, d.as_ptr());
    }
}

/// A v2 `security.capability` granting `CAP_NET_RAW`, effective.
const VFS_CAP: [u8; 20] = [1, 0, 0, 2, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[derive(Clone, Copy)]
enum Caller {
    Root,
    RootNoFsetid,
    /// uid 1000, the owner, in the file's group.
    OwnerInGroup,
    /// uid 1000, the owner, not in the file's group (2000).
    OwnerNotInGroup,
}

impl Caller {
    fn name(self) -> &'static str {
        match self {
            Caller::Root => "root",
            Caller::RootNoFsetid => "root-fsetid",
            Caller::OwnerInGroup => "owner-ingrp",
            Caller::OwnerNotInGroup => "owner-nogrp",
        }
    }

    fn owner(self) -> (u32, u32) {
        match self {
            Caller::Root | Caller::RootNoFsetid => (0, 0),
            Caller::OwnerInGroup => (1000, 1000),
            Caller::OwnerNotInGroup => (1000, 2000),
        }
    }

    fn become_it(self) {
        unsafe {
            match self {
                Caller::Root => {}
                Caller::RootNoFsetid => drop_effective(FSETID),
                Caller::OwnerInGroup | Caller::OwnerNotInGroup => {
                    libc::setgroups(0, std::ptr::null());
                    libc::syscall(libc::SYS_setresgid, 1000, 1000, 1000);
                    libc::syscall(libc::SYS_setresuid, 1000, 1000, 1000);
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Op {
    Write,
    WriteEmpty,
    Pwrite,
    Ftruncate,
    FtruncateSame,
    Truncate,
    OpenTrunc,
    Fallocate,
    CopyFileRange,
    Sendfile,
    MmapStore,
}

const OPS: [Op; 11] = [
    Op::Write,
    Op::WriteEmpty,
    Op::Pwrite,
    Op::Ftruncate,
    Op::FtruncateSame,
    Op::Truncate,
    Op::OpenTrunc,
    Op::Fallocate,
    Op::CopyFileRange,
    Op::Sendfile,
    Op::MmapStore,
];

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::Write => "write",
            Op::WriteEmpty => "write 0",
            Op::Pwrite => "pwrite",
            Op::Ftruncate => "ftruncate",
            Op::FtruncateSame => "ftruncate same",
            Op::Truncate => "truncate",
            Op::OpenTrunc => "open O_TRUNC",
            Op::Fallocate => "fallocate",
            Op::CopyFileRange => "copy_file_range",
            Op::Sendfile => "sendfile",
            Op::MmapStore => "mmap store",
        }
    }

    /// Runs the operation; the return value, or the errno as a negative.
    fn run(self, fd: i32, path: &str, src: i32) -> i64 {
        let b = b"x";
        let r: i64 = unsafe {
            match self {
                Op::Write => libc::write(fd, b.as_ptr().cast(), 1) as i64,
                Op::WriteEmpty => libc::write(fd, b.as_ptr().cast(), 0) as i64,
                Op::Pwrite => libc::pwrite(fd, b.as_ptr().cast(), 1, 2) as i64,
                Op::Ftruncate => libc::ftruncate(fd, 1) as i64,
                Op::FtruncateSame => libc::ftruncate(fd, 4) as i64,
                Op::Truncate => libc::truncate(c(path).as_ptr(), 1) as i64,
                Op::OpenTrunc => {
                    let f = libc::open(c(path).as_ptr(), libc::O_WRONLY | libc::O_TRUNC);
                    if f >= 0 {
                        libc::close(f);
                    }
                    f.min(0) as i64
                }
                Op::Fallocate => libc::fallocate(fd, 0, 0, 8192) as i64,
                Op::CopyFileRange => {
                    let mut off = 0i64;
                    libc::copy_file_range(src, &mut off, fd, std::ptr::null_mut(), 2, 0) as i64
                }
                Op::Sendfile => {
                    let mut off = 0i64;
                    libc::sendfile(fd, src, &mut off, 2) as i64
                }
                Op::MmapStore => {
                    let p = libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0);
                    if p == libc::MAP_FAILED {
                        -1
                    } else {
                        *p.cast::<u8>() = b'y';
                        libc::msync(p, 4096, libc::MS_SYNC);
                        libc::munmap(p, 4096);
                        0
                    }
                }
            }
        };
        if r < 0 { -(errno() as i64) } else { r }
    }
}

fn mode_of(path: &str) -> String {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c(path).as_ptr(), &mut st) } != 0 {
        return format!("stat errno {}", errno());
    }
    format!("{:04o}", st.st_mode & 0o7777)
}

fn cap_of(path: &str) -> &'static str {
    let mut buf = [0u8; 64];
    let n = unsafe { libc::getxattr(c(path).as_ptr(), c"security.capability".as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    match n {
        n if n > 0 => "cap",
        _ if errno() == libc::ENODATA => "nocap",
        _ => "cap?",
    }
}

/// One file: `mode` and, if `with_cap`, a file capability, owned by the
/// caller's owner, four bytes long.
fn case(n: &mut u32, caller: Caller, op: Op, mode: u32, with_cap: bool, src: i32) {
    *n += 1;
    let path = format!("{DIR}/f{n}");
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, b"abcd").unwrap();
    let (uid, gid) = caller.owner();
    let setup = unsafe {
        let p = c(&path);
        let mut r = libc::chown(p.as_ptr(), uid, gid);
        if r == 0 && with_cap {
            r = libc::setxattr(p.as_ptr(), c"security.capability".as_ptr(), VFS_CAP.as_ptr().cast(), VFS_CAP.len(), 0);
        }
        // After the chown and the setxattr, both of which clear the bits.
        if r == 0 {
            r = libc::chmod(p.as_ptr(), mode);
        }
        r
    };
    let what = format!("{} {:04o}{} {}", caller.name(), mode, if with_cap { "+cap" } else { "" }, op.name());
    if setup != 0 {
        line(&what, format!("setup errno {}", errno()));
        return;
    }
    let before = format!("{} {}", mode_of(&path), cap_of(&path));
    let fd = unsafe { libc::open(c(&path).as_ptr(), libc::O_RDWR) };
    let _ = std::io::stdout().flush();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        caller.become_it();
        let r = op.run(fd, &path, src);
        unsafe { libc::_exit(if r < 0 { -r as i32 } else { 0 }) };
    }
    let mut st = 0;
    unsafe {
        libc::waitpid(pid, &mut st, 0);
        libc::close(fd);
    }
    let rc = match libc::WEXITSTATUS(st) {
        0 => "ok".to_string(),
        e => format!("errno {e}"),
    };
    line(&what, format!("{rc}: {before} => {} {}", mode_of(&path), cap_of(&path)));
}

fn main() {
    let _ = std::fs::remove_dir_all(DIR);
    std::fs::create_dir_all(DIR).unwrap();
    unsafe { libc::chmod(c(DIR).as_ptr(), 0o777) };
    let src_path = format!("{DIR}/src");
    std::fs::write(&src_path, b"zz").unwrap();
    let src = unsafe { libc::open(c(&src_path).as_ptr(), libc::O_RDONLY) };
    let mut n = 0;
    for caller in [Caller::Root, Caller::RootNoFsetid, Caller::OwnerInGroup, Caller::OwnerNotInGroup] {
        for op in OPS {
            // set-uid, set-gid with group execute; set-gid without it; a
            // file capability on a plain executable. `o+w` so a path
            // operation by uid 1000 is not refused for another reason.
            case(&mut n, caller, op, 0o6757, false, src);
            case(&mut n, caller, op, 0o2747, false, src);
            case(&mut n, caller, op, 0o0757, true, src);
        }
    }
    let _ = std::fs::remove_dir_all(DIR);
}
