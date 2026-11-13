//! Which calls one process may make on another, by the caller's ids, the
//! target's ids and whether the target is dumpable.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container (`--privileged`, so the container's root has every capability
//! the guest's root has and seccomp is off) and diffed by
//! `tests/integration/probe_diff.sh`.
//!
//! Linux has five rules here, and the targets are chosen to tell them apart:
//!
//! - `ptrace_may_access`: all three of the target's uids and gids equal the
//!   caller's (real ids for `*_REALCREDS`, fs ids for `*_FSCREDS`) and the
//!   target is dumpable, or `CAP_SYS_PTRACE`, or the same thread group.
//! - `kill_ok_by_cred`: the caller's real or effective uid is the target's
//!   real or saved one.
//! - `check_same_owner` / `set_one_prio`: the caller's effective uid is the
//!   target's real or effective one.
//! - `set_task_ioprio`: the target's real uid is the caller's real or
//!   effective one.
//! - `check_prlimit_permission`: the ptrace ids with the real ones, no
//!   dumpable, `CAP_SYS_RESOURCE`.
//!
//! The scheduling, ioprio and ptrace rules also ask that the target's
//! permitted capabilities be a subset of the caller's, which is what the
//! target with a saved uid of 0 is for.
//!
//! `ptrace(PTRACE_SEIZE)` is not asked here; `ptrace_attach_probe` attaches
//! with the ids equal.
//! `move_pages` and `migrate_pages` are not configured.

use std::ffi::CString;
use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<48} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn named(e: i32) -> String {
    match e {
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::ENOENT => "ENOENT",
        libc::EINVAL => "EINVAL",
        libc::ESRCH => "ESRCH",
        libc::EBADF => "EBADF",
        libc::ENOSYS => "ENOSYS",
        libc::EFAULT => "EFAULT",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn ok(v: i64) -> String {
    if v < 0 { named(errno()) } else { "ok".into() }
}

static mut SCRATCH: u64 = 0x5a5a;
static mut PAGE: u64 = 0;

fn setresuid(r: u32, e: u32, s: u32) {
    unsafe { libc::syscall(libc::SYS_setresuid, r, e, s) };
}

fn setresgid(r: u32, e: u32, s: u32) {
    unsafe { libc::syscall(libc::SYS_setresgid, r, e, s) };
}

fn set_dumpable(v: u64) {
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, v) };
}

/// A process that sets itself up and waits to be looked at.
fn target(setup: fn()) -> i32 {
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        setup();
        unsafe {
            libc::write(p[1], b"x".as_ptr().cast(), 1);
            loop {
                libc::pause();
            }
        }
    }
    let mut b = [0u8; 1];
    unsafe {
        libc::close(p[1]);
        libc::read(p[0], b.as_mut_ptr().cast(), 1);
        libc::close(p[0]);
    }
    pid
}

fn as_child(f: impl FnOnce()) {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
}

fn vm(pid: i32, write: bool) -> String {
    let mut local = 0x5a5au64;
    let liov = libc::iovec { iov_base: (&raw mut local).cast(), iov_len: 8 };
    let riov = libc::iovec { iov_base: (&raw mut SCRATCH).cast(), iov_len: 8 };
    let nr = if write { libc::SYS_process_vm_writev } else { libc::SYS_process_vm_readv };
    ok(unsafe { libc::syscall(nr, pid, &liov, 1, &riov, 1, 0) })
}

fn proc_read(pid: i32, name: &str) -> String {
    let c = CString::new(format!("/proc/{pid}/{name}")).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return format!("open {}", named(errno()));
    }
    let mut buf = [0u8; 4096];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    let r = if n < 0 { format!("read {}", named(errno())) } else { "ok".into() };
    unsafe { libc::close(fd) };
    r
}

fn report(who: &str, pid: i32) {
    let l = |what: &str, v: String| line(&format!("{who}: {what}"), v);
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    l("pidfd_open", ok(pidfd as i64));
    l("kill 0", ok(unsafe { libc::kill(pid, 0) } as i64));
    l("pidfd_send_signal 0", ok(unsafe {
        libc::syscall(libc::SYS_pidfd_send_signal, pidfd, 0, std::ptr::null::<u8>(), 0)
    }));
    l("process_vm_readv", vm(pid, false));
    l("process_vm_writev", vm(pid, true));
    l("kcmp KCMP_VM", ok(unsafe { libc::syscall(libc::SYS_kcmp, libc::getpid(), pid, 1, 0, 0) }));
    l("pidfd_getfd 0", {
        let r = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, 0, 0) };
        if r >= 0 {
            unsafe { libc::close(r as i32) };
        }
        ok(r)
    });
    l("get_robust_list", {
        let (mut head, mut len) = (0u64, 0usize);
        ok(unsafe { libc::syscall(libc::SYS_get_robust_list, pid, &mut head, &mut len) })
    });
    let mut lim = [0u64; 2];
    l("prlimit64 get", ok(unsafe {
        libc::syscall(libc::SYS_prlimit64, pid, libc::RLIMIT_NOFILE, std::ptr::null::<u64>(), lim.as_mut_ptr())
    }));
    l("prlimit64 set the same", ok(unsafe {
        libc::syscall(libc::SYS_prlimit64, pid, libc::RLIMIT_NOFILE, lim.as_ptr(), std::ptr::null_mut::<u64>())
    }));
    l("process_madvise MADV_COLD", {
        let iov = libc::iovec { iov_base: unsafe { PAGE } as *mut libc::c_void, iov_len: 4096 };
        ok(unsafe { libc::syscall(libc::SYS_process_madvise, pidfd, &iov, 1, libc::MADV_COLD, 0) })
    });
    l("process_mrelease", ok(unsafe { libc::syscall(libc::SYS_process_mrelease, pidfd, 0) }));
    l("sched_setaffinity", {
        let mut set = [0u8; 128];
        unsafe { libc::syscall(libc::SYS_sched_getaffinity, 0, set.len(), set.as_mut_ptr()) };
        ok(unsafe { libc::syscall(libc::SYS_sched_setaffinity, pid, set.len(), set.as_ptr()) })
    });
    l("setpriority 0", ok(unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as u32, 0) } as i64));
    l("sched_setscheduler SCHED_OTHER", {
        let param = 0i32;
        ok(unsafe { libc::syscall(libc::SYS_sched_setscheduler, pid, libc::SCHED_OTHER, &param) })
    });
    l("sched_setattr SCHED_OTHER", {
        // size, policy, flags, nice, priority, runtime, deadline, period
        let mut attr = [0u32; 12];
        attr[0] = 48;
        ok(unsafe { libc::syscall(libc::SYS_sched_setattr, pid, attr.as_ptr(), 0) })
    });
    // IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 4), IOPRIO_WHO_PROCESS.
    l("ioprio_set BE 4", ok(unsafe { libc::syscall(libc::SYS_ioprio_set, 1, pid, (2 << 13) | 4) }));
    for f in ["environ", "mem", "io", "syscall", "personality"] {
        l(&format!("/proc/<pid>/{f}"), proc_read(pid, f));
    }
    unsafe { libc::close(pidfd) };
}

fn main() {
    unsafe {
        PAGE = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        ) as u64;
        *(PAGE as *mut u8) = 1;
    }
    let targets: Vec<(&str, i32)> = vec![
        ("root", target(|| set_dumpable(1))),
        ("1000", target(|| {
            setresgid(1000, 1000, 1000);
            setresuid(1000, 1000, 1000);
            set_dumpable(1);
        })),
        ("1000 undumpable", target(|| {
            setresgid(1000, 1000, 1000);
            setresuid(1000, 1000, 1000);
        })),
        ("1000 gid 1001", target(|| {
            setresgid(1001, 1001, 1001);
            setresuid(1000, 1000, 1000);
            set_dumpable(1);
        })),
        ("1000 saved uid 0", target(|| {
            setresgid(1000, 1000, 1000);
            setresuid(1000, 1000, 0);
            set_dumpable(1);
        })),
        ("real 2000 eff 1000", target(|| {
            setresgid(2000, 1000, 2000);
            setresuid(2000, 1000, 2000);
            set_dumpable(1);
        })),
    ];
    type Become = fn();
    let callers: [(&str, Become); 4] = [
        ("root", || {}),
        ("1000", || {
            setresgid(1000, 1000, 1000);
            setresuid(1000, 1000, 1000);
        }),
        // fs and effective ids 1000, real 2000: FSCREDS matches, REALCREDS not.
        ("fs 1000 real 2000", || {
            setresgid(2000, 1000, 2000);
            setresuid(2000, 1000, 2000);
        }),
        // The other way round.
        ("real 1000 fs 2000", || {
            setresgid(1000, 2000, 1000);
            setresuid(1000, 2000, 1000);
        }),
    ];
    println!("########## capget ##########");
    for (tname, pid) in &targets {
        // _LINUX_CAPABILITY_VERSION_3: effective, permitted, inheritable, twice.
        let hdr = [0x2008_0522u32, *pid as u32];
        let mut data = [0u32; 6];
        let r = unsafe { libc::syscall(libc::SYS_capget, hdr.as_ptr(), data.as_mut_ptr()) };
        let set = |lo: u32, hi: u32| if lo | hi == 0 { "none" } else { "some" };
        line(
            &format!("capget {tname}"),
            if r < 0 { named(errno()) } else { format!("effective {}, permitted {}", set(data[0], data[3]), set(data[1], data[4])) },
        );
    }
    for (cname, become_) in callers {
        for (tname, pid) in &targets {
            println!("########## {cname} -> {tname} ##########");
            let pid = *pid;
            as_child(|| {
                become_();
                report(&format!("{cname} -> {tname}"), pid);
            });
        }
        println!("########## {cname} -> itself, undumpable ##########");
        as_child(|| {
            become_();
            set_dumpable(0);
            report(&format!("{cname} -> itself"), unsafe { libc::getpid() });
        });
    }
    for (_, pid) in targets {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
    }
}
