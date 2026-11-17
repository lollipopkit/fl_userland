//! Mount namespaces: what `mntns_probe` measured on a real arm64 kernel,
//! asserted. Runs as root; every case is in a child, and what it mounts in
//! the namespace it runs in is unmounted at the end.

use std::ffi::CString;

use guest_tests::{Harness, check};

const NEWNS: i32 = 0x0002_0000;
const TMPFS_MAGIC: i64 = 0x0102_1994;
const BASE: &str = "/tmp/mntns-test";

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn dir(name: &str) -> String {
    format!("{BASE}/{name}")
}

fn tmpfs(at: &str) -> i32 {
    unsafe { libc::mount(c"none".as_ptr(), c(at).as_ptr(), c"tmpfs".as_ptr(), 0, std::ptr::null()) }
}

fn mounted(at: &str) -> bool {
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::statfs(c(at).as_ptr(), &mut s) }) == 0 && s.f_type as i64 == TMPFS_MAGIC
}

fn in_mountinfo(at: &str) -> bool {
    std::fs::read_to_string("/proc/self/mountinfo").is_ok_and(|m| m.lines().any(|l| l.split(' ').nth(4) == Some(at)))
}

fn propagate(at: &str, flags: u64) -> i32 {
    unsafe { libc::mount(std::ptr::null(), c(at).as_ptr(), std::ptr::null(), flags, std::ptr::null()) }
}

/// "The child has done it" and "the parent has looked".
struct Sync {
    done: [i32; 2],
    looked: [i32; 2],
}

impl Sync {
    fn new() -> Sync {
        let mut s = Sync { done: [0; 2], looked: [0; 2] };
        unsafe { libc::pipe(s.done.as_mut_ptr()) };
        unsafe { libc::pipe(s.looked.as_mut_ptr()) };
        s
    }
    fn child_done(&self) {
        let mut b = 0u8;
        unsafe { libc::write(self.done[1], b"x".as_ptr().cast(), 1) };
        unsafe { libc::read(self.looked[0], (&raw mut b).cast(), 1) };
    }
    fn parent_wait(&self) {
        let mut b = 0u8;
        unsafe { libc::read(self.done[0], (&raw mut b).cast(), 1) };
    }
    fn parent_looked(&self) {
        unsafe { libc::write(self.looked[1], b"x".as_ptr().cast(), 1) };
    }
}

/// Run `f` in a child, its checks folded into the exit status; `between`
/// runs here once the child calls `child_done`.
fn in_child(h: &mut Harness, what: &str, f: impl FnOnce(&mut Harness, &Sync), between: impl FnOnce(&mut Harness)) {
    let s = Sync::new();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let mut inner = Harness::new();
        f(&mut inner, &s);
        unsafe { libc::_exit(inner.finish()) };
    }
    s.parent_wait();
    between(h);
    s.parent_looked();
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    check!(h, libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "{what}: status {status:#x}");
}

fn main() {
    let mut h = Harness::new();
    let _ = std::fs::create_dir_all(BASE);
    for d in ["inherited", "inner", "later", "cloned", "thread", "plain"] {
        let _ = std::fs::create_dir_all(dir(d));
    }
    check!(h, tmpfs(&dir("inherited")) == 0, "a tmpfs here: errno {}", errno());

    h.group("unshare");
    in_child(
        &mut h,
        "a new namespace",
        |h, s| {
            check!(h, unsafe { libc::unshare(NEWNS) } == 0, "unshare(CLONE_NEWNS): errno {}", errno());
            check!(h, propagate("/", libc::MS_REC | libc::MS_PRIVATE) == 0, "--make-rprivate /: errno {}", errno());
            check!(h, mounted(&dir("inherited")) && in_mountinfo(&dir("inherited")), "the parent's mount is copied");
            check!(h, tmpfs(&dir("inner")) == 0 && mounted(&dir("inner")) && in_mountinfo(&dir("inner")), "a mount of its own");
            check!(h, unsafe { libc::umount(c(&dir("inherited")).as_ptr()) } == 0, "umount the copy: errno {}", errno());
            check!(h, !mounted(&dir("inherited")) && !in_mountinfo(&dir("inherited")), "and it is gone here");
            check!(h, std::fs::write(format!("{}/f", dir("inner")), b"x").is_ok(), "a file on its own mount");
            s.child_done();
            check!(h, !mounted(&dir("later")), "a mount the parent made since is not seen");
        },
        |h| {
            check!(h, !mounted(&dir("inner")) && !in_mountinfo(&dir("inner")), "here, the child's mount is not seen");
            check!(h, std::fs::metadata(format!("{}/f", dir("inner"))).is_err(), "nor the file on it");
            check!(h, mounted(&dir("inherited")), "here, the copy's umount left ours");
            check!(h, tmpfs(&dir("later")) == 0, "a mount here after the child's unshare");
        },
    );

    h.group("setns");
    let s = Sync::new();
    let holder = unsafe { libc::fork() };
    if holder == 0 {
        unsafe { libc::unshare(NEWNS) };
        tmpfs(&dir("plain"));
        s.child_done();
        unsafe { libc::_exit(0) };
    }
    s.parent_wait();
    in_child(
        &mut h,
        "joining",
        |h, s| {
            let theirs = unsafe { libc::open(c(&format!("/proc/{holder}/ns/mnt")).as_ptr(), libc::O_RDONLY) };
            let ours = unsafe { libc::open(c"/proc/self/ns/mnt".as_ptr(), libc::O_RDONLY) };
            unsafe { libc::chdir(c(BASE).as_ptr()) };
            check!(h, unsafe { libc::setns(theirs, NEWNS) } == 0, "setns(theirs): errno {}", errno());
            check!(h, mounted(&dir("plain")), "their mount is seen");
            let cwd = std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
            check!(h, cwd == "/", "the working directory is their root: {cwd}");
            check!(h, unsafe { libc::setns(ours, 0) } == 0 && !mounted(&dir("plain")), "and back: errno {}", errno());
            let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, holder, 0) } as i32;
            check!(h, unsafe { libc::setns(pidfd, NEWNS) } == 0 && mounted(&dir("plain")), "through a pidfd: errno {}", errno());
            let me = unsafe { libc::open(c"/proc/self/ns/mnt".as_ptr(), libc::O_RDONLY) };
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let t = std::thread::spawn(move || {
                let _ = rx.recv();
            });
            let r = unsafe { libc::setns(me, NEWNS) };
            let e = errno();
            let _ = tx.send(());
            let _ = t.join();
            check!(h, r < 0 && e == libc::EINVAL, "with a thread sharing the working directory: EINVAL, got {e}");
            s.child_done();
        },
        |_| {},
    );
    s.parent_looked();
    unsafe { libc::waitpid(holder, std::ptr::null_mut(), 0) };

    h.group("clone and threads");
    in_child(
        &mut h,
        "clone",
        |h, s| {
            let mut stack = vec![0u8; 64 * 1024];
            extern "C" fn inner(_: *mut libc::c_void) -> i32 {
                (!mounted(&dir("inherited")) || tmpfs(&dir("cloned")) != 0) as i32
            }
            let top = unsafe { stack.as_mut_ptr().add(stack.len()) };
            let pid = unsafe { libc::clone(inner, top.cast(), NEWNS | libc::SIGCHLD, std::ptr::null_mut()) };
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            check!(h, pid > 0 && libc::WEXITSTATUS(status) == 0, "clone(CLONE_NEWNS): a copy, and a mount of its own");
            check!(h, !mounted(&dir("cloned")), "not seen on this side");
            let pid = unsafe { libc::clone(inner, top.cast(), NEWNS | libc::CLONE_FS | libc::SIGCHLD, std::ptr::null_mut()) };
            check!(h, pid < 0 && errno() == libc::EINVAL, "with CLONE_FS: EINVAL");
            s.child_done();
        },
        |_| {},
    );
    in_child(
        &mut h,
        "a thread",
        |h, s| {
            let theirs = std::thread::spawn(|| {
                let r = unsafe { libc::unshare(NEWNS) };
                tmpfs(&dir("thread"));
                r == 0 && mounted(&dir("thread"))
            })
            .join()
            .unwrap_or(false);
            check!(h, theirs, "a thread's unshare and mount");
            check!(h, !mounted(&dir("thread")), "the other thread does not see it");
            s.child_done();
        },
        |_| {},
    );

    h.group("propagation");
    in_child(
        &mut h,
        "the flags",
        |h, s| {
            unsafe { libc::unshare(NEWNS) };
            for (what, flags, want) in [
                ("MS_PRIVATE", libc::MS_PRIVATE, 0),
                ("MS_SLAVE", libc::MS_SLAVE, 0),
                ("MS_UNBINDABLE", libc::MS_UNBINDABLE, 0),
                ("MS_REC | MS_SLAVE", libc::MS_REC | libc::MS_SLAVE, 0),
                ("MS_PRIVATE | MS_SLAVE", libc::MS_PRIVATE | libc::MS_SLAVE, libc::EINVAL),
                ("MS_PRIVATE | MS_RDONLY", libc::MS_PRIVATE | libc::MS_RDONLY, libc::EINVAL),
            ] {
                let r = propagate(&dir("inherited"), flags);
                let got = if r == 0 { 0 } else { errno() };
                check!(h, got == want, "{what}: want {want}, got {got}");
            }
            check!(h, propagate(BASE, libc::MS_PRIVATE) < 0 && errno() == libc::EINVAL, "not a mount point: EINVAL");
            check!(h, propagate(&dir("missing"), libc::MS_PRIVATE) < 0 && errno() == libc::ENOENT, "missing: ENOENT");
            s.child_done();
        },
        |_| {},
    );

    h.group("without CAP_SYS_ADMIN");
    in_child(
        &mut h,
        "uid 1000",
        |h, s| {
            let mnt = unsafe { libc::open(c"/proc/self/ns/mnt".as_ptr(), libc::O_RDONLY) };
            unsafe {
                libc::setgid(1000);
                libc::setuid(1000);
            }
            check!(h, unsafe { libc::unshare(NEWNS) } < 0 && errno() == libc::EPERM, "unshare: EPERM");
            check!(h, unsafe { libc::setns(mnt, NEWNS) } < 0 && errno() == libc::EPERM, "setns: EPERM");
            s.child_done();
        },
        |_| {},
    );

    for d in ["inherited", "later"] {
        unsafe { libc::umount(c(&dir(d)).as_ptr()) };
    }
    let _ = std::fs::remove_dir_all(BASE);
    std::process::exit(h.finish());
}
