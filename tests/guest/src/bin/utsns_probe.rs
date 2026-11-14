//! UTS namespaces: `unshare`, `clone` and `setns` with `CLONE_NEWUTS`, what
//! a hostname set in one is seen as from the other, and what
//! `/proc/<pid>/ns/uts` says about who shares one.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container (`--privileged`, for `CAP_SYS_ADMIN`) and diffed by
//! `tests/integration/probe_diff.sh`. Namespace numbers are not printed, only
//! whether two are the same. Every case runs in a child, so the probe's own
//! namespace and hostname are left as they were.

use std::ffi::CString;
use std::io::Write;

const NEWUTS: i32 = 0x0400_0000;
const NEWIPC: i32 = 0x0800_0000;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<56} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn rc(r: i64) -> String {
    if r >= 0 {
        return "ok".into();
    }
    match errno() {
        libc::EPERM => "EPERM".into(),
        libc::EINVAL => "EINVAL".into(),
        libc::EBADF => "EBADF".into(),
        e => format!("errno {e}"),
    }
}

fn hostname() -> String {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut u) };
    unsafe { std::ffi::CStr::from_ptr(u.nodename.as_ptr()) }.to_string_lossy().into_owned()
}

fn set_hostname(name: &str) -> i64 {
    unsafe { libc::sethostname(name.as_ptr().cast(), name.len()) as i64 }
}

fn ns_link(pid: &str) -> String {
    std::fs::read_link(format!("/proc/{pid}/ns/uts")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Run `f` in a child and wait for it.
fn child(f: impl FnOnce()) {
    let _ = std::io::stdout().flush();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
}

fn main() {
    let original = hostname();
    let parent_ns = ns_link("self");
    line("the link's form", parent_ns.split(':').next().unwrap_or(""));

    child(|| {
        line("unshare(CLONE_NEWUTS)", rc(unsafe { libc::unshare(NEWUTS) } as i64));
        line("  the link changed", ns_link("self") != parent_ns);
        line("  hostname is still the parent's", hostname() == original);
        line("  sethostname inside", rc(set_hostname("inside")));
        line("  hostname inside", hostname());
        line("  the parent's link is unchanged", ns_link(&std::os::unix::process::parent_id().to_string()) == parent_ns);
    });
    line("after the child, hostname here is unchanged", hostname() == original);

    // setns back to the parent's namespace through its ns file.
    child(|| {
        let ppid = std::os::unix::process::parent_id();
        let back = unsafe { libc::open(CString::new(format!("/proc/{ppid}/ns/uts")).unwrap().as_ptr(), libc::O_RDONLY) };
        line("open(/proc/<ppid>/ns/uts)", rc(back as i64));
        unsafe { libc::unshare(NEWUTS) };
        set_hostname("away");
        line("setns(fd, CLONE_NEWIPC) on a uts file", rc(unsafe { libc::setns(back, NEWIPC) } as i64));
        line("setns(fd, CLONE_NEWUTS)", rc(unsafe { libc::setns(back, NEWUTS) } as i64));
        line("  hostname is the parent's again", hostname() == original);
        line("  the link is the parent's", ns_link("self") == parent_ns);
        line("setns(fd, 0)", rc(unsafe { libc::setns(back, 0) } as i64));
        line("setns(a regular file, 0)", rc(unsafe {
            let f = libc::open(c"/proc/self/status".as_ptr(), libc::O_RDONLY);
            libc::setns(f, 0)
        } as i64));
    });

    // setns through a pidfd, naming the namespaces to join.
    child(|| {
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::os::unix::process::parent_id(), 0) } as i32;
        unsafe { libc::unshare(NEWUTS) };
        set_hostname("away");
        line("setns(pidfd, CLONE_NEWUTS)", rc(unsafe { libc::setns(pidfd, NEWUTS) } as i64));
        line("  hostname is the parent's again", hostname() == original);
    });

    // clone with CLONE_NEWUTS: the child is in a new one, the parent is not.
    child(|| {
        let mut stack = vec![0u8; 64 * 1024];
        extern "C" fn inner(_: *mut libc::c_void) -> i32 {
            set_hostname("cloned");
            line("clone(CLONE_NEWUTS): the child's hostname", hostname());
            0
        }
        let top = unsafe { stack.as_mut_ptr().add(stack.len()) };
        let pid = unsafe { libc::clone(inner, top.cast(), NEWUTS | libc::SIGCHLD, std::ptr::null_mut()) };
        let r = rc(pid as i64);
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        line("clone(CLONE_NEWUTS)", r);
        line("  this side's hostname", if hostname() == original { "unchanged".to_string() } else { hostname() });
    });

    // Joining a namespace this task is already in, and pidfd's mask.
    child(|| {
        let own = |name: &str| unsafe { libc::open(CString::new(format!("/proc/self/ns/{name}")).unwrap().as_ptr(), libc::O_RDONLY) };
        line("setns(own uts, CLONE_NEWUTS)", rc(unsafe { libc::setns(own("uts"), NEWUTS) } as i64));
        line("setns(own ipc, 0)", rc(unsafe { libc::setns(own("ipc"), 0) } as i64));
        line("setns(own net, 0)", rc(unsafe { libc::setns(own("net"), 0) } as i64));
        line("setns(own user, 0)", rc(unsafe { libc::setns(own("user"), 0) } as i64));
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as i32;
        line("setns(pidfd, 0)", rc(unsafe { libc::setns(pidfd, 0) } as i64));
        line("setns(pidfd, NEWUTS|NEWIPC|NEWNET)", rc(unsafe { libc::setns(pidfd, NEWUTS | NEWIPC | 0x4000_0000) } as i64));
        line("setns(pidfd, CLONE_NEWUSER)", rc(unsafe { libc::setns(pidfd, 0x1000_0000) } as i64));
        line("setns(pidfd, CLONE_VM)", rc(unsafe { libc::setns(pidfd, libc::CLONE_VM) } as i64));
    });

    // A namespace is a thread's: one thread unsharing leaves the others.
    child(|| {
        let t = std::thread::spawn(|| {
            unsafe { libc::unshare(NEWUTS) };
            set_hostname("thread");
            hostname()
        });
        let theirs = t.join().unwrap_or_default();
        line("a thread's unshare: its hostname", theirs);
        line("  the main thread's hostname is unchanged", hostname() == original);
    });

    // The domain name is copied and kept apart the same way.
    child(|| {
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        unsafe { libc::uname(&mut u) };
        let before = unsafe { std::ffi::CStr::from_ptr(u.domainname.as_ptr()) }.to_string_lossy().into_owned();
        unsafe { libc::unshare(NEWUTS) };
        unsafe { libc::uname(&mut u) };
        let copied = unsafe { std::ffi::CStr::from_ptr(u.domainname.as_ptr()) }.to_string_lossy().into_owned();
        line("unshare keeps the domain name", copied == before);
        unsafe { libc::setdomainname(c"inner".as_ptr(), 5) };
        unsafe { libc::uname(&mut u) };
        line("  setdomainname inside", unsafe { std::ffi::CStr::from_ptr(u.domainname.as_ptr()) }.to_string_lossy());
    });

    // Without CAP_SYS_ADMIN.
    child(|| {
        unsafe {
            libc::setgid(1000);
            libc::setuid(1000);
        }
        line("unshare(CLONE_NEWUTS) as uid 1000", rc(unsafe { libc::unshare(NEWUTS) } as i64));
        line("sethostname as uid 1000", rc(set_hostname("nope")));
        let uts = unsafe { libc::open(c"/proc/self/ns/uts".as_ptr(), libc::O_RDONLY) };
        line("setns(own uts) as uid 1000", rc(unsafe { libc::setns(uts, NEWUTS) } as i64));
    });
}
