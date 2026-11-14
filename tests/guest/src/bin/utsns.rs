//! UTS namespaces: what `utsns_probe` measured on a real arm64 kernel,
//! asserted. Runs as root; every case is in a child, so the hostname of the
//! process that runs this is left as it was.

use std::ffi::CString;

use guest_tests::{Harness, check};

const NEWUTS: i32 = 0x0400_0000;
const NEWIPC: i32 = 0x0800_0000;
const NEWUSER: i32 = 0x1000_0000;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn hostname() -> String {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    unsafe { libc::uname(&mut u) };
    unsafe { std::ffi::CStr::from_ptr(u.nodename.as_ptr()) }.to_string_lossy().into_owned()
}

fn set_hostname(name: &str) -> i32 {
    unsafe { libc::sethostname(name.as_ptr().cast(), name.len()) }
}

fn ns_link(pid: &str) -> String {
    std::fs::read_link(format!("/proc/{pid}/ns/uts")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
}

fn open_ns(path: &str) -> i32 {
    unsafe { libc::open(CString::new(path).unwrap().as_ptr(), libc::O_RDONLY) }
}

/// Run `f` in a child; its checks are folded into the exit status.
fn in_child(h: &mut Harness, what: &str, f: impl FnOnce(&mut Harness)) {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let mut inner = Harness::new();
        f(&mut inner);
        unsafe { libc::_exit(inner.finish()) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    check!(h, libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "{what}: status {status:#x}");
}

fn main() {
    let mut h = Harness::new();
    let original = hostname();
    let parent_ns = ns_link("self");
    check!(h, parent_ns.starts_with("uts:["), "the link: {parent_ns}");

    h.group("unshare");
    in_child(&mut h, "unshare", |h| {
        let before = hostname();
        check!(h, unsafe { libc::unshare(NEWUTS) } == 0, "unshare(CLONE_NEWUTS): errno {}", errno());
        check!(h, ns_link("self") != ns_link(&std::os::unix::process::parent_id().to_string()), "a new namespace");
        check!(h, hostname() == before, "the parent's names, copied: {}", hostname());
        check!(h, set_hostname("inside") == 0 && hostname() == "inside", "sethostname inside: {}", hostname());
    });
    check!(h, hostname() == original, "the parent's hostname is unchanged: {}", hostname());

    h.group("setns");
    in_child(&mut h, "setns", |h| {
        let back = open_ns(&format!("/proc/{}/ns/uts", std::os::unix::process::parent_id()));
        check!(h, back >= 0, "open the parent's ns file: errno {}", errno());
        unsafe { libc::unshare(NEWUTS) };
        set_hostname("away");
        let r = unsafe { libc::setns(back, NEWIPC) };
        check!(h, r < 0 && errno() == libc::EINVAL, "a uts file as CLONE_NEWIPC: EINVAL, got {}", errno());
        check!(h, unsafe { libc::setns(back, NEWUTS) } == 0, "setns(fd, CLONE_NEWUTS): errno {}", errno());
        check!(h, hostname() == original, "the parent's hostname again: {}", hostname());
        check!(h, ns_link("self") == ns_link(&std::os::unix::process::parent_id().to_string()), "the parent's namespace");
        check!(h, unsafe { libc::setns(back, 0) } == 0, "setns(fd, 0)");
        let file = open_ns("/proc/self/status");
        check!(h, unsafe { libc::setns(file, 0) } < 0 && errno() == libc::EINVAL, "a regular file: EINVAL");
        check!(h, unsafe { libc::setns(open_ns("/proc/self/ns/user"), 0) } < 0 && errno() == libc::EINVAL,
            "its own user namespace: EINVAL");
        check!(h, unsafe { libc::setns(open_ns("/proc/self/ns/net"), 0) } == 0, "its own network namespace");
    });
    in_child(&mut h, "setns through a pidfd", |h| {
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::os::unix::process::parent_id(), 0) } as i32;
        unsafe { libc::unshare(NEWUTS) };
        set_hostname("away");
        check!(h, unsafe { libc::setns(pidfd, 0) } < 0 && errno() == libc::EINVAL, "nstype 0: EINVAL");
        check!(h, unsafe { libc::setns(pidfd, NEWUSER) } < 0 && errno() == libc::EINVAL, "CLONE_NEWUSER: EINVAL");
        check!(h, unsafe { libc::setns(pidfd, NEWUTS | NEWIPC) } == 0, "CLONE_NEWUTS|CLONE_NEWIPC: errno {}", errno());
        check!(h, hostname() == original, "the parent's hostname again: {}", hostname());
    });

    h.group("clone and threads");
    in_child(&mut h, "clone", |h| {
        let mut stack = vec![0u8; 64 * 1024];
        extern "C" fn inner(_: *mut libc::c_void) -> i32 {
            if set_hostname("cloned") != 0 || hostname() != "cloned" { 1 } else { 0 }
        }
        let top = unsafe { stack.as_mut_ptr().add(stack.len()) };
        let pid = unsafe { libc::clone(inner, top.cast(), NEWUTS | libc::SIGCHLD, std::ptr::null_mut()) };
        check!(h, pid > 0, "clone(CLONE_NEWUTS): errno {}", errno());
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        check!(h, libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "the child set its own");
        check!(h, hostname() == original, "this side's is unchanged: {}", hostname());
    });
    in_child(&mut h, "a thread", |h| {
        let theirs = std::thread::spawn(|| {
            unsafe { libc::unshare(NEWUTS) };
            set_hostname("thread");
            hostname()
        })
        .join()
        .unwrap_or_default();
        check!(h, theirs == "thread", "the thread's: {theirs}");
        check!(h, hostname() == original, "the other thread's is unchanged: {}", hostname());
    });

    h.group("without CAP_SYS_ADMIN");
    in_child(&mut h, "uid 1000", |h| {
        let uts = open_ns("/proc/self/ns/uts");
        unsafe {
            libc::setgid(1000);
            libc::setuid(1000);
        }
        check!(h, unsafe { libc::unshare(NEWUTS) } < 0 && errno() == libc::EPERM, "unshare: EPERM");
        check!(h, unsafe { libc::setns(uts, NEWUTS) } < 0 && errno() == libc::EPERM, "setns: EPERM");
        let mut stack = vec![0u8; 16 * 1024];
        extern "C" fn nothing(_: *mut libc::c_void) -> i32 {
            0
        }
        let top = unsafe { stack.as_mut_ptr().add(stack.len()) };
        let pid = unsafe { libc::clone(nothing, top.cast(), NEWUTS | libc::SIGCHLD, std::ptr::null_mut()) };
        check!(h, pid < 0 && errno() == libc::EPERM, "clone(CLONE_NEWUTS): EPERM, got {pid} {}", errno());
    });

    std::process::exit(h.finish());
}
