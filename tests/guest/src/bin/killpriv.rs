//! A write takes a file's set-id bits and `security.capability` away:
//! `killpriv_probe`'s cases, asserted with what a real arm64 kernel answered,
//! and run on fakefs, since realfs cannot give a file to another user and
//! the host clears set-id bits on its own writes.
//!
//! Then the mark that lets a write skip the check: a privilege added after a
//! write has been through, by any route, is still removed by the next one.

use guest_tests::caps::*;
use guest_tests::{Harness, check};

const DIR: &str = "/tmp/killprivdir";
const FSETID: u32 = 4;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Caller {
    Root,
    RootNoFsetid,
    OwnerInGroup,
    OwnerNotInGroup,
}

#[derive(Clone, Copy, PartialEq, Debug)]
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

fn run(op: Op, fd: i32, path: &str, src: i32) -> i64 {
    let b = b"x";
    unsafe {
        r(match op {
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
                f as i64
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
        })
    }
}

/// What Linux left, as `killpriv_probe` recorded it: `(mode, capability
/// still there)`.
fn linux(caller: Caller, op: Op, mode: u32, cap: bool) -> (u32, bool) {
    if matches!(op, Op::WriteEmpty | Op::MmapStore) {
        return (mode, cap);
    }
    let kill = match caller {
        Caller::Root => 0,
        Caller::RootNoFsetid | Caller::OwnerInGroup => {
            if mode & 0o0010 != 0 {
                0o6000
            } else {
                0o4000
            }
        }
        Caller::OwnerNotInGroup => 0o6000,
    };
    (mode & !kill, false)
}

fn new_file(path: &str, (uid, gid): (u32, u32), mode: u32, cap: bool) {
    let _ = std::fs::remove_file(path);
    std::fs::write(path, b"abcd").unwrap();
    unsafe { libc::chown(c(path).as_ptr(), uid, gid) };
    if cap {
        setcap(path, &vfs_cap(true, 1 << 13, None));
    }
    unsafe { libc::chmod(c(path).as_ptr(), mode) };
}

fn has_cap(path: &str) -> bool {
    getcap_len(path) > 0
}

fn main() {
    unsafe { libc::setgroups(0, std::ptr::null()) };
    let _ = std::fs::remove_dir_all(DIR);
    std::fs::create_dir_all(DIR).unwrap();
    unsafe { libc::chmod(c(DIR).as_ptr(), 0o777) };
    let mut h = Harness::new();
    let src_path = format!("{DIR}/src");
    std::fs::write(&src_path, b"zz").unwrap();
    let src = unsafe { libc::open(c(&src_path).as_ptr(), libc::O_RDONLY) };

    let probe = format!("{DIR}/owned");
    new_file(&probe, (1000, 2000), 0o6757, true);
    check!(h, owner_of(&probe) == 1000 && mode_of(&probe) == 0o6757 && has_cap(&probe), "this mount records owner, set-id bits and capability");

    h.group("what a write removes");
    let mut n = 0;
    for caller in [Caller::Root, Caller::RootNoFsetid, Caller::OwnerInGroup, Caller::OwnerNotInGroup] {
        let owner = match caller {
            Caller::Root | Caller::RootNoFsetid => (0, 0),
            Caller::OwnerInGroup => (1000, 1000),
            Caller::OwnerNotInGroup => (1000, 2000),
        };
        for op in OPS {
            for (mode, cap) in [(0o6757, false), (0o2747, false), (0o0757, true)] {
                n += 1;
                let path = format!("{DIR}/f{n}");
                new_file(&path, owner, mode, cap);
                let fd = unsafe { libc::open(c(&path).as_ptr(), libc::O_RDWR) };
                let rc = one(|| {
                    match caller {
                        Caller::Root => {}
                        Caller::RootNoFsetid => without(&[FSETID]),
                        Caller::OwnerInGroup | Caller::OwnerNotInGroup => unsafe {
                            libc::syscall(libc::SYS_setresgid, 1000, 1000, 1000);
                            setresuid(1000);
                        },
                    }
                    run(op, fd, &path, src)
                });
                unsafe { libc::close(fd) };
                let got = (mode_of(&path), has_cap(&path));
                let want = linux(caller, op, mode, cap);
                check!(h, rc == 0 && got == want, "{caller:?} {op:?} on {mode:04o}{}: {rc} {got:?}, Linux {want:?}", if cap { "+cap" } else { "" });
            }
        }
    }

    h.group("a privilege added after a write is still removed");
    let path = format!("{DIR}/late");
    new_file(&path, (1000, 1000), 0o644, false);
    let fd = unsafe { libc::open(c(&path).as_ptr(), libc::O_RDWR) };
    let write_as_owner = |fd: i32| {
        one(|| unsafe {
            libc::syscall(libc::SYS_setresgid, 1000, 1000, 1000);
            setresuid(1000);
            r(libc::write(fd, b"x".as_ptr().cast(), 1) as i64)
        })
    };
    check!(h, write_as_owner(fd) == 0, "a first write, with nothing to remove");
    unsafe { libc::chmod(c(&path).as_ptr(), 0o4755) };
    check!(h, write_as_owner(fd) == 0 && mode_of(&path) == 0o755, "chmod u+s by path: {:o}", mode_of(&path));
    unsafe { libc::fchmod(fd, 0o4755) };
    check!(h, write_as_owner(fd) == 0 && mode_of(&path) == 0o755, "fchmod u+s: {:o}", mode_of(&path));
    setcap(&path, &vfs_cap(true, 1 << 13, None));
    check!(h, write_as_owner(fd) == 0 && !has_cap(&path), "setxattr by path: still has it {}", has_cap(&path));
    let value = vfs_cap(true, 1 << 13, None);
    unsafe { libc::fsetxattr(fd, c"security.capability".as_ptr(), value.as_ptr().cast(), value.len(), 0) };
    check!(h, write_as_owner(fd) == 0 && !has_cap(&path), "fsetxattr: still has it {}", has_cap(&path));
    unsafe { libc::close(fd) };

    let _ = std::fs::remove_dir_all(DIR);
    std::process::exit(h.finish());
}
