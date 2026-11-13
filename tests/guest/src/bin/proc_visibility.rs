//! What one user can see of another user's process through `/proc`.
//!
//! `/proc/<pid>` entries are stamped with the task's own uid and gid, so the
//! ordinary permission check applies to them — which means the mode in the
//! table is the whole of the access policy.
//!
//! Two of them took the default for their type and should not have:
//!
//! - `mem` is a regular file, so it defaulted to `0444`. Linux makes it `0600`.
//!   World-readable, it hands any user the entire address space of every
//!   process on the system.
//! - `fd` is a directory, so it defaulted to `0555`. Linux makes it `0500`.
//!   Listable, it tells any user which files everyone else has open.
//!
//! Behind the modes, Linux asks `ptrace_may_access` of everything that shows
//! the address space or where the process runs from: another user's `maps`,
//! `smaps`, `smaps_rollup`, `auxv` and `mem` do not open, its `exe`, `cwd` and
//! `root` do not read or follow, and `stat` blanks its addresses. This file
//! asserted that another user's `maps` was readable until 2026-11-12, which a
//! real kernel refuses with `EACCES` (`procaccess_probe`).
//!
//! `stat`, `statm`, `cmdline`, `comm` and `status` really are world-readable,
//! and are checked here to stay that way.
//!
//! Only observable now that a guest process can hold an unprivileged uid.

use guest_tests::{Harness, check, check_fails, cpath, sys};

fn open_ro(path: &str) -> i32 {
    unsafe { libc::open(cpath(path).as_ptr(), libc::O_RDONLY) }
}

fn main() {
    let mut pipefd = [0i32; 2];
    unsafe { libc::pipe(pipefd.as_mut_ptr()) };
    let victim = unsafe { libc::fork() };
    if victim == 0 {
        unsafe {
            libc::close(pipefd[0]);
            let pid = libc::getpid();
            libc::write(pipefd[1], (&raw const pid).cast(), 4);
            libc::close(pipefd[1]);
            libc::pause();
            libc::_exit(0);
        }
    }
    let root_pid = unsafe {
        libc::close(pipefd[1]);
        let mut pid = 0i32;
        let n = libc::read(pipefd[0], (&raw mut pid).cast(), 4);
        libc::close(pipefd[0]);
        if n == 4 { pid } else { -1 }
    };

    unsafe {
        let child = libc::fork();
        if child == 0 {
            libc::setresgid(1000, 1000, 1000);
            libc::setresuid(1000, 1000, 1000);
            // The change of uid leaves the process undumpable, which makes
            // its own `mem` root's; the check below is about a process that
            // is its own, as on Linux once the flag is set back
            // (`dumpable_rules` has the undumpable case).
            libc::prctl(libc::PR_SET_DUMPABLE, 1);
            let mut h = Harness::new();
            h.group("proc-visibility");

            if root_pid > 0 {
                check_fails!(
                    h,
                    open_ro(&format!("/proc/{root_pid}/mem")),
                    libc::EACCES,
                    "reading another user's process memory"
                );
                check_fails!(
                    h,
                    open_ro(&format!("/proc/{root_pid}/fd")),
                    libc::EACCES,
                    "listing another user's open descriptors"
                );

                // Behind ptrace access, asked at open.
                for name in ["maps", "smaps", "smaps_rollup", "auxv", "task/{pid}/maps"] {
                    let name = name.replace("{pid}", &root_pid.to_string());
                    check_fails!(
                        h,
                        open_ro(&format!("/proc/{root_pid}/{name}")),
                        libc::EACCES,
                        "opening another user's {name}"
                    );
                }
                // Asked at readlink, and when the link is followed.
                for name in ["exe", "cwd", "root"] {
                    let path = format!("/proc/{root_pid}/{name}");
                    let mut buf = [0u8; 256];
                    check_fails!(h, sys::readlink(&path, &mut buf) as i64, libc::EACCES, "reading another user's {name}");
                    check_fails!(h, sys::stat_raw(&path) as i64, libc::EACCES, "following another user's {name}");
                }
                // `stat` opens, and leaves out what ptrace access would show:
                // the code bounds read 1 and the stack, the data and the
                // argument ranges 0.
                match sys::read_file(&format!("/proc/{root_pid}/stat")) {
                    Some(bytes) => {
                        let text = String::from_utf8_lossy(&bytes);
                        let rest = text.rsplit_once(") ").map_or("", |(_, r)| r);
                        let f: Vec<&str> = rest.split_whitespace().collect();
                        let field = |n: usize| f.get(n - 3).copied().unwrap_or("-");
                        check!(h, field(26) == "1" && field(27) == "1", "the code bounds are 1: {} {}", field(26), field(27));
                        let blank = [28, 45, 46, 47, 48, 49, 50, 51].iter().all(|&n| field(n) == "0");
                        check!(h, blank, "the stack, data and argument ranges are 0: {text}");
                    }
                    None => check!(h, false, "another user's stat opens, errno {}", sys::errno()),
                }

                // These are world-readable on Linux too, and must stay so:
                // ps and friends read them.
                for name in ["stat", "statm", "cmdline", "comm", "status"] {
                    let fd = open_ro(&format!("/proc/{root_pid}/{name}"));
                    check!(h, fd >= 0, "/proc/<other>/{name} is still readable, errno {}", sys::errno());
                    if fd >= 0 {
                        sys::close(fd);
                    }
                }
            }

            // Our own remain ours to read -- the fix is about other people's.
            let me = libc::getpid();
            let fd = open_ro(&format!("/proc/{me}/mem"));
            check!(h, fd >= 0, "our own mem is readable, errno {}", sys::errno());
            if fd >= 0 {
                sys::close(fd);
            }
            let fd = open_ro(&format!("/proc/{me}/fd"));
            check!(h, fd >= 0, "our own fd directory is readable, errno {}", sys::errno());
            if fd >= 0 {
                sys::close(fd);
            }
            for name in ["maps", "smaps", "auxv"] {
                let fd = open_ro(&format!("/proc/{me}/{name}"));
                check!(h, fd >= 0, "our own {name} is readable, errno {}", sys::errno());
                if fd >= 0 {
                    sys::close(fd);
                }
            }
            let mut buf = [0u8; 256];
            check!(h, sys::readlink(&format!("/proc/{me}/cwd"), &mut buf) > 0, "our own cwd reads");

            libc::_exit(h.finish());
        }
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);

        let mut h = Harness::new();
        h.group("proc-visibility-root");
        check!(
            h,
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the unprivileged child's checks all passed"
        );
        // The bytes, not just the open. `/proc/<pid>/mem` is served by its own
        // `pread` -- the one entry in the table that has one -- and until
        // 2026-09-05 that callback was handed a `struct proc_data` whose
        // `data` pointed at the caller's buffer and whose `capacity` was the
        // caller's length. Nothing read it back through, so the signature
        // could have been wrong in either direction and every test still
        // passed.
        h.group("proc-mem-pread");
        {
            let marker: [u8; 8] = *b"\xa5PROCMEM";
            let at = (&raw const marker) as u64;
            let fd = open_ro(&format!("/proc/{}/mem", libc::getpid()));
            check!(h, fd >= 0, "our own mem opens, errno {}", sys::errno());
            if fd >= 0 {
                let mut got = [0u8; 8];
                let n = libc::pread(fd, got.as_mut_ptr().cast(), 8, at as libc::off_t);
                check!(h, n == 8, "pread of 8 bytes returned {n}, errno {}", sys::errno());
                check!(h, got == marker, "the bytes at our own address came back: {got:?}");

                // A second read at a different offset, so a callback that
                // ignored the offset and returned the same bytes would fail.
                let mut tail = [0u8; 4];
                let n = libc::pread(fd, tail.as_mut_ptr().cast(), 4, (at + 4) as libc::off_t);
                check!(h, n == 4, "pread of the second half returned {n}");
                check!(h, tail == marker[4..], "the offset is honoured: {tail:?}");
                // Nothing mapped at 0: Linux's `mem_rw` answers EIO when the
                // first page cannot be reached, where this answered -1, EPERM.
                let mut one = [0u8; 1];
                check_fails!(h, libc::pread(fd, one.as_mut_ptr().cast(), 1, 0), libc::EIO, "a read of an unmapped page");
                sys::close(fd);
            }
        }

        // `comm` is writable by the process's own threads and nobody else,
        // root included: Linux's `comm_write`. It was 0444 here.
        h.group("proc-comm-write");
        {
            let me = libc::getpid();
            let path = format!("/proc/{me}/comm");
            let write = |p: &str, b: &[u8]| {
                let fd = libc::open(cpath(p).as_ptr(), libc::O_WRONLY);
                let n = if fd < 0 { -1 } else { libc::write(fd, b.as_ptr().cast(), b.len()) };
                if fd >= 0 {
                    sys::close(fd);
                }
                n
            };
            check!(h, write(&path, b"renamed\n") == 8, "its own comm takes a write, errno {}", sys::errno());
            let got = sys::read_file(&path).unwrap_or_default();
            check!(h, got == b"renamed\n\n", "the newline is part of the name: {:?}", String::from_utf8_lossy(&got));
            check!(h, write(&path, b"a-name-longer-than-fifteen") == 26, "a long one is taken whole");
            let got = sys::read_file(&path).unwrap_or_default();
            check!(h, got == b"a-name-longer-t\n", "and cut at fifteen: {:?}", String::from_utf8_lossy(&got));
            if root_pid > 0 {
                check_fails!(h, write(&format!("/proc/{root_pid}/comm"), b"x"), libc::EINVAL, "another process's");
            }
        }

        // Root is not stopped by any of this.
        if root_pid > 0 {
            let fd = open_ro(&format!("/proc/{root_pid}/mem"));
            check!(h, fd >= 0, "root may still read process memory, errno {}", sys::errno());
            if fd >= 0 {
                sys::close(fd);
            }
            libc::kill(root_pid, libc::SIGKILL);
            let mut st = 0;
            libc::waitpid(root_pid, &mut st, 0);
        }
        std::process::exit(h.finish());
    }
}
