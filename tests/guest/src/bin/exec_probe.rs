//! What `execve(2)` and `execveat(2)` answer for a file that cannot be run,
//! and which file they run when one can.
//!
//! **A report, not a check** — one line per case, never fails, run here and in
//! an arm64 container and diffed by `tests/integration/probe_diff.sh`.
//!
//! A shell reads the errno: `ENOEXEC` means "run it as a script", `EACCES` is
//! "Permission denied", `ENOENT` is "not found" and sends a `PATH` search on to
//! the next directory. A loader's `E2BIG`, `ELOOP` and `ETXTBSY` are what a
//! build system or a package manager sees. `exec_semantics` checks that a
//! program runs; this asks what a program that cannot run is told.
//!
//! Every case forks: the child execs, and if the exec returns it writes the
//! errno into a pipe and exits. A child that does not write ran something, and
//! its exit status says what -- `/bin/true` exits 0, and each script here
//! exits a number of its own.

use std::ffi::CString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;

const DIR: &str = "/tmp/exec_probe.d";

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<58} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::ENOENT => "ENOENT",
        libc::EACCES => "EACCES",
        libc::ENOEXEC => "ENOEXEC",
        libc::ELOOP => "ELOOP",
        libc::E2BIG => "E2BIG",
        libc::EFAULT => "EFAULT",
        libc::EINVAL => "EINVAL",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ETXTBSY => "ETXTBSY",
        libc::ENOTDIR => "ENOTDIR",
        libc::EBADF => "EBADF",
        libc::EISDIR => "EISDIR",
        libc::ELIBBAD => "ELIBBAD",
        libc::EIO => "EIO",
        libc::EPERM => "EPERM",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Write `body` at `DIR/name` with `mode`, and answer the path.
fn file(name: &str, body: &[u8], mode: u32) -> String {
    let path = format!("{DIR}/{name}");
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, body).unwrap();
    std::os::unix::fs::PermissionsExt::set_mode(&mut std::fs::metadata(&path).unwrap().permissions(), mode);
    let perms = std::os::unix::fs::PermissionsExt::from_mode(mode);
    std::fs::set_permissions(&path, perms).unwrap();
    path
}

fn script(name: &str, body: &str) -> String {
    file(name, body.as_bytes(), 0o755)
}

/// What one exec attempt came to.
enum Outcome {
    Failed(i32),
    Exited(i32),
    Signalled(i32),
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Failed(e) => write!(f, "{}", named(*e)),
            Outcome::Exited(n) => write!(f, "ran, exit {n}"),
            Outcome::Signalled(s) => write!(f, "ran, signal {s}"),
        }
    }
}

/// Fork, and in the child do `exec` -- which returns only on failure -- then
/// report the errno through a pipe. `Exited`/`Signalled` mean it ran.
fn attempt(exec: impl FnOnce() -> i64) -> Outcome {
    let _ = std::io::stdout().flush();
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(fds[0]) };
        let r = exec();
        let e = if r < 0 { errno() } else { 0 };
        let bytes = e.to_ne_bytes();
        unsafe {
            libc::write(fds[1], bytes.as_ptr().cast(), 4);
            libc::_exit(99);
        }
    }
    unsafe { libc::close(fds[1]) };
    let mut buf = [0u8; 4];
    let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), 4) };
    unsafe { libc::close(fds[0]) };
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if n == 4 {
        return Outcome::Failed(i32::from_ne_bytes(buf));
    }
    if libc::WIFEXITED(status) {
        Outcome::Exited(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Outcome::Signalled(libc::WTERMSIG(status))
    } else {
        Outcome::Exited(-1)
    }
}

fn execve(path: &str) -> Outcome {
    let path = c(path);
    let argv0 = path.clone();
    attempt(|| {
        let argv = [argv0.as_ptr(), std::ptr::null()];
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];
        unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) as i64 }
    })
}

fn execve_raw(path: *const libc::c_char, argv: *const *const libc::c_char, envp: *const *const libc::c_char) -> Outcome {
    attempt(|| unsafe { libc::syscall(libc::SYS_execve, path, argv, envp) })
}

fn execveat(dirfd: i32, path: &str, flags: i32) -> Outcome {
    let path = c(path);
    let argv0 = c("x");
    attempt(|| {
        let argv = [argv0.as_ptr(), std::ptr::null()];
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];
        unsafe { libc::syscall(libc::SYS_execveat, dirfd, path.as_ptr(), argv.as_ptr(), envp.as_ptr(), flags) }
    })
}

fn main() {
    let _ = std::fs::remove_dir_all(DIR);
    std::fs::create_dir_all(DIR).unwrap();
    line("setup", "ok");

    println!("## what cannot be run");
    line("a path that does not exist", execve(&format!("{DIR}/nothing")));
    line("a path under a file", execve("/bin/true/x"));
    line("a directory", execve(DIR));
    line("a directory with no execute bit", {
        let d = format!("{DIR}/noexec");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
        execve(&d)
    });
    line("/dev/null", execve("/dev/null"));
    line("a fifo with the execute bit", {
        let p = c(&format!("{DIR}/fifo"));
        unsafe { libc::mkfifo(p.as_ptr(), 0o755) };
        execve(&format!("{DIR}/fifo"))
    });
    line("a regular file with no execute bit", execve(&file("noexec.sh", b"#!/bin/sh\nexit 3\n", 0o644)));
    line("an empty file with the execute bit", execve(&file("empty", b"", 0o755)));
    line("four bytes of nothing in particular", execve(&file("junk", b"junk", 0o755)));
    line("a text file with no #!", execve(&file("text", b"echo hello\n", 0o755)));
    line("a path of 5000 bytes", execve(&format!("{DIR}/{}", "a".repeat(5000))));
    line("a component of 300 bytes", execve(&format!("{DIR}/{}", "a".repeat(300))));
    line("a symlink loop", {
        let a = format!("{DIR}/loop-a");
        let b = format!("{DIR}/loop-b");
        let _ = std::os::unix::fs::symlink(&b, &a);
        let _ = std::os::unix::fs::symlink(&a, &b);
        execve(&a)
    });
    line("a dangling symlink", {
        let p = format!("{DIR}/dangling");
        let _ = std::os::unix::fs::symlink(format!("{DIR}/nowhere"), &p);
        execve(&p)
    });

    println!("## ELF files that are not programs");
    line("the four magic bytes and nothing else", execve(&file("elf-short", b"\x7fELF", 0o755)));
    line("a 64-byte header of zeroes after the magic", execve(&file("elf-zero", &[b"\x7fELF".as_slice(), &[0u8; 60]].concat(), 0o755)));
    {
        // An x86-64 ELF header: class 2, little-endian, ET_EXEC, machine 62.
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = 2;
        h[5] = 1;
        h[6] = 1;
        h[16] = 2;
        h[18] = 62;
        h[20] = 1;
        line("an x86-64 ELF header", execve(&file("elf-x86", &h, 0o755)));
        h[18] = 183; // aarch64, but nothing after the header
        line("an aarch64 header with no program headers", execve(&file("elf-arm-empty", &h, 0o755)));
        h[4] = 1; // ELFCLASS32
        line("a 32-bit ELF header", execve(&file("elf-32", &h, 0o755)));
    }
    line("the real thing", execve("/bin/true"));

    println!("## #! scripts");
    line("#!/bin/sh, exit 3", execve(&script("ok.sh", "#!/bin/sh\nexit 3\n")));
    line("#! with nothing after it", execve(&script("bare.sh", "#!\nexit 4\n")));
    line("#! followed by spaces only", execve(&script("spaces.sh", "#!   \nexit 4\n")));
    line("#!/nonexistent", execve(&script("noint.sh", "#!/nonexistent/interp\nexit 4\n")));
    line("#! naming a directory", execve(&script("dirint.sh", &format!("#!{DIR}\nexit 4\n"))));
    line("#! naming a file with no execute bit", {
        let interp = file("interp-noexec", b"#!/bin/sh\nexit 5\n", 0o644);
        execve(&script("noexecint.sh", &format!("#!{interp}\n")))
    });
    line("#! naming a script (depth 2)", {
        let two = script("depth2", "#!/bin/sh\nexit 12\n");
        execve(&script("depth1", &format!("#!{two}\n")))
    });
    line("#! four deep", {
        let d4 = script("d4", "#!/bin/sh\nexit 14\n");
        let d3 = script("d3", &format!("#!{d4}\n"));
        let d2 = script("d2", &format!("#!{d3}\n"));
        execve(&script("d1", &format!("#!{d2}\n")))
    });
    line("#! five deep", {
        let e5 = script("e5", "#!/bin/sh\nexit 15\n");
        let e4 = script("e4", &format!("#!{e5}\n"));
        let e3 = script("e3", &format!("#!{e4}\n"));
        let e2 = script("e2", &format!("#!{e3}\n"));
        execve(&script("e1", &format!("#!{e2}\n")))
    });
    line("#! six deep", {
        let f6 = script("f6", "#!/bin/sh\nexit 16\n");
        let f5 = script("f5", &format!("#!{f6}\n"));
        let f4 = script("f4", &format!("#!{f5}\n"));
        let f3 = script("f3", &format!("#!{f4}\n"));
        let f2 = script("f2", &format!("#!{f3}\n"));
        execve(&script("f1", &format!("#!{f2}\n")))
    });
    line("#! naming itself", {
        let p = format!("{DIR}/self.sh");
        execve(&script("self.sh", &format!("#!{p}\n")))
    });
    // `-e`, and not `-c`: `#!/bin/sh -c` runs the script's own path as the
    // command, which runs the script, which runs the shell -- a chain of
    // processes each waiting on the next, on both kernels. Found the hard way.
    line("#! with an interpreter argument", execve(&script("arg.sh", "#!/bin/sh -e\nexit 6\n")));
    line("#! line of 200 characters", {
        let pad = " ".repeat(190);
        execve(&script("long200.sh", &format!("#!/bin/sh{pad}\nexit 7\n")))
    });
    line("#! line of 300 characters, no newline in the first 256", {
        let pad = " ".repeat(290);
        execve(&script("long300.sh", &format!("#!/bin/sh{pad}\nexit 8\n")))
    });
    line("#! line of 300 characters ending in the path", {
        let pad = "a".repeat(290);
        execve(&script("long300b.sh", &format!("#!/bin/sh{pad}\nexit 8\n")))
    });
    line("#! with a CR before the newline", execve(&script("crlf.sh", "#!/bin/sh\r\nexit 9\n")));
    line("#! with no newline at all", execve(&script("nonl.sh", "#!/bin/sh")));
    line("#!/bin/sh in a file of 10 bytes", execve(&script("tiny.sh", "#!/bin/sh\n")));

    println!("## the arguments");
    {
        let path = c("/bin/true");
        let argv0 = c("true");
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];
        line("argv NULL", execve_raw(path.as_ptr(), std::ptr::null(), envp.as_ptr()));
        line("envp NULL", {
            let argv = [argv0.as_ptr(), std::ptr::null()];
            execve_raw(path.as_ptr(), argv.as_ptr(), std::ptr::null())
        });
        line("argv empty (argc 0)", {
            let argv: [*const libc::c_char; 1] = [std::ptr::null()];
            execve_raw(path.as_ptr(), argv.as_ptr(), envp.as_ptr())
        });
        line("argv at a bad address", execve_raw(path.as_ptr(), 1 as *const *const libc::c_char, envp.as_ptr()));
        line("argv[0] at a bad address", {
            let argv = [1 as *const libc::c_char, std::ptr::null()];
            execve_raw(path.as_ptr(), argv.as_ptr(), envp.as_ptr())
        });
        line("path at a bad address", execve_raw(1 as *const libc::c_char, std::ptr::null(), envp.as_ptr()));
        line("path NULL", execve_raw(std::ptr::null(), std::ptr::null(), envp.as_ptr()));
        line("path empty", {
            let empty = c("");
            execve_raw(empty.as_ptr(), std::ptr::null(), envp.as_ptr())
        });
        line("one argument of 200 000 bytes", {
            let big = CString::new("x".repeat(200_000)).unwrap();
            let argv = [argv0.as_ptr(), big.as_ptr(), std::ptr::null()];
            execve_raw(path.as_ptr(), argv.as_ptr(), envp.as_ptr())
        });
        line("one argument of 100 000 bytes", {
            let big = CString::new("x".repeat(100_000)).unwrap();
            let argv = [argv0.as_ptr(), big.as_ptr(), std::ptr::null()];
            execve_raw(path.as_ptr(), argv.as_ptr(), envp.as_ptr())
        });
        line("500 arguments of 100 000 bytes", {
            let big = CString::new("x".repeat(100_000)).unwrap();
            let mut argv = vec![argv0.as_ptr()];
            argv.extend(std::iter::repeat(big.as_ptr()).take(500));
            argv.push(std::ptr::null());
            execve_raw(path.as_ptr(), argv.as_ptr(), envp.as_ptr())
        });
        line("10 arguments of 100 000 bytes", {
            let big = CString::new("x".repeat(100_000)).unwrap();
            let mut argv = vec![argv0.as_ptr()];
            argv.extend(std::iter::repeat(big.as_ptr()).take(10));
            argv.push(std::ptr::null());
            execve_raw(path.as_ptr(), argv.as_ptr(), envp.as_ptr())
        });
        line("an environment entry of 200 000 bytes", {
            let argv = [argv0.as_ptr(), std::ptr::null()];
            let big = CString::new(format!("X={}", "x".repeat(200_000))).unwrap();
            let envp = [big.as_ptr(), std::ptr::null()];
            execve_raw(path.as_ptr(), argv.as_ptr(), envp.as_ptr())
        });
    }

    println!("## a file someone is writing, and a file someone is running");
    {
        let copy = format!("{DIR}/true-copy");
        std::fs::copy("/bin/true", &copy).unwrap();
        std::fs::set_permissions(&copy, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let held = std::fs::OpenOptions::new().write(true).open(&copy).unwrap();
        line("exec of a file open for writing", execve(&copy));
        line("#! naming a file open for writing", {
            let sh_copy = format!("{DIR}/sh-copy");
            std::fs::copy("/bin/busybox", &sh_copy).unwrap();
            std::fs::set_permissions(&sh_copy, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
            let held_sh = std::fs::OpenOptions::new().write(true).open(&sh_copy).unwrap();
            let r = execve(&script("busy-interp.sh", &format!("#!{sh_copy} sh\nexit 3\n")));
            drop(held_sh);
            r
        });
        drop(held);
        line("exec of it once closed", execve(&copy));
        let held = std::fs::File::open(&copy).unwrap();
        line("exec of a file open for reading", execve(&copy));
        drop(held);

        // A program that is *running*: a copy of busybox, told to be `sleep`
        // by its argv[0]. The pipe's write end is close-on-exec, so the
        // parent's read returns when the exec has happened.
        let running = format!("{DIR}/busybox-running");
        std::fs::copy("/bin/busybox", &running).unwrap();
        std::fs::set_permissions(&running, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let mut fds = [0i32; 2];
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let path = c(&running);
            let argv0 = c("sleep");
            let arg = c("30");
            let argv = [argv0.as_ptr(), arg.as_ptr(), std::ptr::null()];
            let envp: [*const libc::c_char; 1] = [std::ptr::null()];
            unsafe {
                libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(99);
            }
        }
        unsafe { libc::close(fds[1]) };
        let mut byte = 0u8;
        unsafe { libc::read(fds[0], &mut byte as *mut u8 as *mut libc::c_void, 1) };
        let open_as = |flags: i32| -> String {
            let p = c(&running);
            let fd = unsafe { libc::open(p.as_ptr(), flags) };
            if fd < 0 {
                named(errno())
            } else {
                unsafe { libc::close(fd) };
                "ok".to_string()
            }
        };
        line("open(O_WRONLY) of a running program", open_as(libc::O_WRONLY));
        line("open(O_RDWR) of a running program", open_as(libc::O_RDWR));
        line("open(O_RDONLY) of a running program", open_as(libc::O_RDONLY));
        line("open(O_PATH) of a running program", open_as(libc::O_PATH));
        line("open(O_WRONLY|O_TRUNC) of a running program", open_as(libc::O_WRONLY | libc::O_TRUNC));
        line("its size after that", std::fs::metadata(&running).map(|m| m.len().to_string()).unwrap_or_else(|e| e.to_string()));
        line("truncate() of a running program", {
            let p = c(&running);
            let r = unsafe { libc::truncate(p.as_ptr(), 0) };
            if r == 0 { "ok".to_string() } else { named(errno()) }
        });
        line("its size after that", std::fs::metadata(&running).map(|m| m.len().to_string()).unwrap_or_else(|e| e.to_string()));
        // As `true`, so that the second copy exits 0 rather than printing
        // busybox's usage into this report.
        line("exec of a running program", {
            let path = c(&running);
            let argv0 = c("true");
            let argv = [argv0.as_ptr(), std::ptr::null()];
            let envp: [*const libc::c_char; 1] = [std::ptr::null()];
            execve_raw(path.as_ptr(), argv.as_ptr(), envp.as_ptr())
        });
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
        line("open(O_WRONLY) once it has exited", open_as(libc::O_WRONLY));
    }

    println!("## execveat");
    {
        let dir = unsafe { libc::open(c("/bin").as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        let exe = unsafe { libc::open(c("/bin/true").as_ptr(), libc::O_RDONLY) };
        let path_fd = unsafe { libc::open(c("/bin/true").as_ptr(), libc::O_PATH) };
        let sh = unsafe { libc::open(c(&format!("{DIR}/ok.sh")).as_ptr(), libc::O_RDONLY) };
        let sh_path = unsafe { libc::open(c(&format!("{DIR}/ok.sh")).as_ptr(), libc::O_PATH) };
        let link = format!("{DIR}/true-link");
        let _ = std::os::unix::fs::symlink("/bin/true", &link);
        const AT_EMPTY_PATH: i32 = 0x1000;
        const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
        line("execveat(dirfd, \"true\")", execveat(dir, "true", 0));
        line("execveat(dirfd, \"/bin/true\")", execveat(dir, "/bin/true", 0));
        line("execveat(AT_FDCWD, \"/bin/true\")", execveat(libc::AT_FDCWD, "/bin/true", 0));
        line("execveat(-1, \"/bin/true\")", execveat(-1, "/bin/true", 0));
        line("execveat(-1, \"true\")", execveat(-1, "true", 0));
        line("execveat(a file fd, \"true\")", execveat(exe, "true", 0));
        line("execveat(fd, \"\") without AT_EMPTY_PATH", execveat(exe, "", 0));
        line("execveat(fd, \"\", AT_EMPTY_PATH)", execveat(exe, "", AT_EMPTY_PATH));
        line("execveat(O_PATH fd, \"\", AT_EMPTY_PATH)", execveat(path_fd, "", AT_EMPTY_PATH));
        line("execveat(dirfd, \"\", AT_EMPTY_PATH)", execveat(dir, "", AT_EMPTY_PATH));
        line("execveat(script fd, \"\", AT_EMPTY_PATH)", execveat(sh, "", AT_EMPTY_PATH));
        line("execveat(O_PATH script fd, \"\", AT_EMPTY_PATH)", execveat(sh_path, "", AT_EMPTY_PATH));
        line("execveat(fd, \"\", AT_EMPTY_PATH) on a closed fd", execveat(999, "", AT_EMPTY_PATH));
        line("execveat(AT_FDCWD, \"\", AT_EMPTY_PATH)", execveat(libc::AT_FDCWD, "", AT_EMPTY_PATH));
        line("execveat(fd of a file unlinked since, \"\", AT_EMPTY_PATH)", {
            // A file that has no name any more can only be run through a
            // descriptor that was open before it went.
            let gone = format!("{DIR}/gone");
            std::fs::copy("/bin/busybox", &gone).unwrap();
            std::fs::set_permissions(&gone, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
            let fd = unsafe { libc::open(c(&gone).as_ptr(), libc::O_RDONLY) };
            std::fs::remove_file(&gone).unwrap();
            let path = c("");
            let argv0 = c("true");
            let r = attempt(|| {
                let argv = [argv0.as_ptr(), std::ptr::null()];
                let envp: [*const libc::c_char; 1] = [std::ptr::null()];
                unsafe { libc::syscall(libc::SYS_execveat, fd, path.as_ptr(), argv.as_ptr(), envp.as_ptr(), AT_EMPTY_PATH) }
            });
            unsafe { libc::close(fd) };
            r
        });
        line("execveat(dirfd, \"true\", 0x8)", execveat(dir, "true", 0x8));
        line("execveat(dirfd, \"true\", 0x10000)", execveat(dir, "true", 0x10000));
        line("execveat(symlink, AT_SYMLINK_NOFOLLOW)", execveat(libc::AT_FDCWD, &link, AT_SYMLINK_NOFOLLOW));
        line("execveat(symlink, 0)", execveat(libc::AT_FDCWD, &link, 0));
        line("execveat(/bin/true, AT_SYMLINK_NOFOLLOW)", execveat(libc::AT_FDCWD, "/bin/true", AT_SYMLINK_NOFOLLOW));
        unsafe {
            libc::close(dir);
            libc::close(exe);
            libc::close(path_fd);
            libc::close(sh);
            libc::close(sh_path);
        }
    }

    println!("## what the program sees");
    {
        // argv[0] and the interpreter's view of a script's arguments. The
        // script prints them; the pipe reads them back.
        let sh = script("args.sh", "#!/bin/sh -x\nprintf '%s|' \"$0\" \"$@\"\n");
        let out = std::process::Command::new(&sh).arg("one").arg("two").output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).replace(DIR, "DIR");
        let err = String::from_utf8_lossy(&out.stderr).lines().count();
        line("a script's $0 and $@", format!("{text} (stderr lines {err})"));
        let out = std::process::Command::new(&link_or(sh.as_str())).arg("one").output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).replace(DIR, "DIR");
        line("through a symlink", text);
        let out = std::process::Command::new("/bin/sh").arg("-c").arg("echo $0").arg0("named").output().unwrap();
        line("argv[0] of a program", String::from_utf8_lossy(&out.stdout).trim().to_string());
        let out = std::process::Command::new("/bin/sh").arg("-c").arg("echo \"$0\"").arg0("").output().unwrap();
        line("argv[0] empty", format!("[{}]", String::from_utf8_lossy(&out.stdout).trim()));
    }

    // Leave nothing behind. The rootfs this runs in is shared with the other
    // suites, and one of them copies it with `cp -R`, which cannot copy a
    // directory with no execute bit -- the smoke test failed to build its
    // fakefs after this probe had run. Everything here is one directory, and
    // the one unsearchable thing in it is made searchable first.
    let _ = std::fs::set_permissions(format!("{DIR}/noexec"), std::os::unix::fs::PermissionsExt::from_mode(0o755));
    let _ = std::fs::remove_dir_all(DIR);
}

/// A symlink to `target`, for the argv[0] case.
fn link_or(target: &str) -> String {
    let link = format!("{DIR}/args-link.sh");
    let _ = std::os::unix::fs::symlink(target, &link);
    link
}

trait Arg0 {
    fn arg0(&mut self, a: &str) -> &mut Self;
}

impl Arg0 for std::process::Command {
    fn arg0(&mut self, a: &str) -> &mut Self {
        std::os::unix::process::CommandExt::arg0(self, std::ffi::OsStr::from_bytes(a.as_bytes()))
    }
}
