//! What the file syscalls answer at their edges.
//!
//! **A report, not a check** — the third in the shape `mmap_probe` established.
//! One line per case, never fails, run here and in an arm64 container and
//! diffed.
//!
//! **Every destructive case gets its own file.** The first version reused one,
//! and `unlinkat(flags = 0x1000)` — which this kernel accepted and Linux
//! refuses — deleted it, so eight later cases answered `ENOENT` here and
//! something else there. The diff looked like eight differences and was one.
//!
//! What is probed is deliberately **argument validation and errnos**, not
//! filesystem behaviour: the container's root is overlayfs and this kernel's is
//! a fakefs, so anything that depends on the filesystem would be measuring the
//! difference between those. A flag combination that is `EINVAL` is `EINVAL`
//! whatever is underneath.

use std::ffi::CString;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn name(e: i32) -> String {
    let s = match e {
        0 => "-",
        libc::EINVAL => "EINVAL",
        libc::ENOENT => "ENOENT",
        libc::EEXIST => "EEXIST",
        libc::ENOTDIR => "ENOTDIR",
        libc::EISDIR => "EISDIR",
        libc::ELOOP => "ELOOP",
        libc::EBADF => "EBADF",
        libc::EACCES => "EACCES",
        libc::EPERM => "EPERM",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EFAULT => "EFAULT",
        libc::EXDEV => "EXDEV",
        libc::EBUSY => "EBUSY",
        libc::ENOSYS => "ENOSYS",
        libc::EFBIG => "EFBIG",
        libc::ESPIPE => "ESPIPE",
        libc::EOVERFLOW => "EOVERFLOW",
        _ => return format!("errno {e}"),
    };
    s.into()
}

fn report(what: &str, r: i64) {
    if r < 0 {
        println!("{what:<52} -> {}", name(errno()));
    } else {
        println!("{what:<52} -> ok");
    }
}

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

const AT_FDCWD: i32 = -100;

fn openat(dirfd: i32, path: &str, flags: i32, mode: u32) -> i64 {
    let p = cs(path);
    unsafe { libc::openat(dirfd, p.as_ptr(), flags, mode) as i64 }
}

fn main() {
    let dir = "/tmp/fs_probe.d";
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).expect("mkdir");
    std::fs::write(format!("{dir}/f"), b"hello").expect("write");
    std::fs::create_dir(format!("{dir}/sub")).expect("mkdir sub");
    std::os::unix::fs::symlink("f", format!("{dir}/link")).expect("symlink");
    // A symlink that points at itself, for ELOOP.
    std::os::unix::fs::symlink("loop", format!("{dir}/loop")).expect("symlink loop");

    println!("## open flags");
    report("open(a file, O_DIRECTORY)", openat(AT_FDCWD, &format!("{dir}/f"), libc::O_DIRECTORY, 0));
    report("open(a dir, O_WRONLY)", openat(AT_FDCWD, dir, libc::O_WRONLY, 0));
    report("open(a dir, O_RDONLY)", openat(AT_FDCWD, dir, libc::O_RDONLY, 0));
    report("open(a symlink, O_NOFOLLOW)", openat(AT_FDCWD, &format!("{dir}/link"), libc::O_NOFOLLOW, 0));
    report(
        "open(a symlink, O_NOFOLLOW|O_PATH)",
        openat(AT_FDCWD, &format!("{dir}/link"), libc::O_NOFOLLOW | libc::O_PATH, 0),
    );
    report("open(a self-referencing symlink)", openat(AT_FDCWD, &format!("{dir}/loop"), 0, 0));
    report(
        "open(O_CREAT|O_EXCL on something that exists)",
        openat(AT_FDCWD, &format!("{dir}/f"), libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY, 0o644),
    );
    // O_TMPFILE is O_DIRECTORY|0o20000000 on aarch64; a kernel without it sees
    // a plain O_DIRECTORY and answers differently.
    const O_TMPFILE: i32 = 0o20000000 | libc::O_DIRECTORY;
    report("open(dir, O_TMPFILE|O_RDWR)", openat(AT_FDCWD, dir, O_TMPFILE | libc::O_RDWR, 0o600));
    report("open(dir, O_TMPFILE|O_RDONLY)", openat(AT_FDCWD, dir, O_TMPFILE | libc::O_RDONLY, 0o600));
    // A bit no flag defines.
    report("open(a file, 0x40000000)", openat(AT_FDCWD, &format!("{dir}/f"), 0x40000000, 0));

    println!("## O_PATH's restrictions");
    let pathfd = openat(AT_FDCWD, &format!("{dir}/f"), libc::O_PATH, 0) as i32;
    let mut buf = [0u8; 8];
    report("read(an O_PATH fd)", unsafe {
        libc::read(pathfd, buf.as_mut_ptr().cast(), 8) as i64
    });
    report("fchmod(an O_PATH fd)", unsafe {
        libc::fchmod(pathfd, 0o644) as i64
    });
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    report("fstat(an O_PATH fd)", unsafe {
        libc::fstat(pathfd, &mut st) as i64
    });
    report("lseek(an O_PATH fd)", unsafe {
        libc::lseek(pathfd, 0, libc::SEEK_SET) as i64
    });

    println!("## the *at family's dirfd");
    let filefd = openat(AT_FDCWD, &format!("{dir}/f"), libc::O_RDONLY, 0) as i32;
    report("openat(a regular file as dirfd, \"x\")", openat(filefd, "x", libc::O_RDONLY, 0));
    report("openat(a closed fd as dirfd)", openat(4096, "x", libc::O_RDONLY, 0));
    // An absolute path ignores the dirfd, even a nonsensical one.
    report("openat(a regular file as dirfd, absolute)", openat(filefd, &format!("{dir}/f"), libc::O_RDONLY, 0));
    report("openat(a closed fd as dirfd, absolute)", openat(4096, &format!("{dir}/f"), libc::O_RDONLY, 0));
    // An empty path.
    report("openat(AT_FDCWD, \"\")", openat(AT_FDCWD, "", libc::O_RDONLY, 0));

    // A file that nothing above has touched, made fresh for each case that
    // might remove it.
    let fresh = |n: &str| {
        let p = format!("{dir}/{n}");
        std::fs::write(&p, b"x").expect("write");
        p
    };
    let fresh_dir = |n: &str| {
        let p = format!("{dir}/{n}");
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir(&p).expect("mkdir");
        p
    };

    println!("## unlink and rmdir");
    let d = fresh_dir("u_dir");
    report("unlink(a directory)", unsafe {
        libc::unlink(cs(&d).as_ptr()) as i64
    });
    let f = fresh("u_file");
    report("rmdir(a regular file)", unsafe {
        libc::rmdir(cs(&f).as_ptr()) as i64
    });
    let d = fresh_dir("u_dot");
    report("rmdir(\".\")", unsafe {
        libc::rmdir(cs(&format!("{d}/.")).as_ptr()) as i64
    });
    let f = fresh("u_removedir");
    report("unlinkat(AT_REMOVEDIR on a file)", unsafe {
        libc::unlinkat(AT_FDCWD, cs(&f).as_ptr(), libc::AT_REMOVEDIR) as i64
    });
    let f = fresh("u_badflag");
    report("unlinkat(flags=0x1000)", unsafe {
        libc::unlinkat(AT_FDCWD, cs(&f).as_ptr(), 0x1000) as i64
    });
    println!("{:<52} -> {}", "  and the file is still there", std::path::Path::new(&f).exists());

    println!("## rename");
    let f = fresh("r_self");
    report("rename(a file onto itself)", unsafe {
        libc::rename(cs(&f).as_ptr(), cs(&f).as_ptr()) as i64
    });
    let d = fresh_dir("r_dir");
    let f = fresh("r_onto");
    report("rename(a directory onto a file)", unsafe {
        libc::rename(cs(&d).as_ptr(), cs(&f).as_ptr()) as i64
    });
    report("rename(a file onto a directory)", unsafe {
        libc::rename(cs(&f).as_ptr(), cs(&d).as_ptr()) as i64
    });
    // renameat2's flags. RENAME_NOREPLACE is 1, EXCHANGE 2, WHITEOUT 4.
    for (n, flag) in [("NOREPLACE", 1u32), ("EXCHANGE", 2), ("WHITEOUT", 4), ("both", 3), ("unknown8", 8)] {
        let from = fresh(&format!("r2_{n}_from"));
        let to = format!("{dir}/r2_{n}_to");
        let _ = std::fs::remove_file(&to);
        report(&format!("renameat2(from -> to, {n})"), unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                AT_FDCWD,
                cs(&from).as_ptr(),
                AT_FDCWD,
                cs(&to).as_ptr(),
                flag,
            )
        });
    }

    println!("## link and symlink");
    let f = fresh("l_exists");
    report("link(onto something that exists)", unsafe {
        libc::link(cs(&f).as_ptr(), cs(&f).as_ptr()) as i64
    });
    let d = fresh_dir("l_dir");
    report("link(a directory)", unsafe {
        libc::link(cs(&d).as_ptr(), cs(&format!("{dir}/l_hard")).as_ptr()) as i64
    });
    report("symlink(\"\", target)", unsafe {
        libc::symlink(cs("").as_ptr(), cs(&format!("{dir}/empty")).as_ptr()) as i64
    });
    let mut rbuf = [0u8; 64];
    report("readlink(a regular file)", unsafe {
        libc::readlink(
            cs(&format!("{dir}/f")).as_ptr(),
            rbuf.as_mut_ptr().cast(),
            rbuf.len(),
        ) as i64
    });
    report("readlink(size=0)", unsafe {
        libc::readlink(
            cs(&format!("{dir}/link")).as_ptr(),
            rbuf.as_mut_ptr().cast(),
            0,
        ) as i64
    });

    println!("## truncate and seek");
    report("truncate(a directory, 0)", unsafe {
        libc::truncate(cs(dir).as_ptr(), 0) as i64
    });
    let f = fresh("t_neg");
    report("truncate(a file, -1)", unsafe {
        libc::truncate(cs(&f).as_ptr(), -1) as i64
    });
    report("ftruncate(an O_RDONLY fd)", unsafe {
        libc::ftruncate(filefd, 0) as i64
    });
    report("lseek(whence=99)", unsafe {
        libc::lseek(filefd, 0, 99) as i64
    });
    report("lseek(SEEK_SET, -1)", unsafe {
        libc::lseek(filefd, -1, libc::SEEK_SET) as i64
    });

    println!("## fcntl");
    report("fcntl(F_GETFL)", unsafe {
        libc::fcntl(filefd, libc::F_GETFL) as i64
    });
    report("fcntl(cmd=9999)", unsafe {
        libc::fcntl(filefd, 9999) as i64
    });
    report("fcntl(F_DUPFD, -1)", unsafe {
        libc::fcntl(filefd, libc::F_DUPFD, -1) as i64
    });
    report("fcntl(F_DUPFD, huge)", unsafe {
        libc::fcntl(filefd, libc::F_DUPFD, 1 << 30) as i64
    });
    report("fcntl(F_SETFL, O_APPEND)", unsafe {
        libc::fcntl(filefd, libc::F_SETFL, libc::O_APPEND) as i64
    });

    println!("## a path that is too long");
    let long = "a".repeat(300);
    report("open(a 300-byte name)", openat(AT_FDCWD, &format!("{dir}/{long}"), libc::O_RDONLY, 0));
    let deep = (0..200).map(|_| "a").collect::<Vec<_>>().join("/");
    report("open(a 200-component path)", openat(AT_FDCWD, &format!("{dir}/{deep}"), libc::O_RDONLY, 0));

    let _ = std::fs::remove_dir_all(dir);
}
