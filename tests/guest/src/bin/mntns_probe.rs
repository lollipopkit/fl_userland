//! Mount namespaces: `unshare`, `clone` and `setns` with `CLONE_NEWNS`,
//! which mounts each side sees afterwards, and what the propagation flags
//! answer.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container (`CAP_SYS_ADMIN`) and diffed by `tests/integration/probe_diff.sh`.
//! Mount ids and namespace numbers are not printed, only how they compare.
//! Every case runs in a child; the probe's own namespace gets two tmpfs
//! mounts under `/tmp`, removed at the end.

use std::ffi::CString;
use std::io::Write;

const NEWNS: i32 = 0x0002_0000;
const TMPFS_MAGIC: i64 = 0x0102_1994;

const BASE: &str = "/tmp/mntns-probe";

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
        libc::ENOENT => "ENOENT".into(),
        libc::EBUSY => "EBUSY".into(),
        e => format!("errno {e}"),
    }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn dir(name: &str) -> String {
    format!("{BASE}/{name}")
}

fn tmpfs(at: &str) -> i64 {
    unsafe { libc::mount(c"none".as_ptr(), c(at).as_ptr(), c"tmpfs".as_ptr(), 0, std::ptr::null()) as i64 }
}

fn mounted(at: &str) -> bool {
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::statfs(c(at).as_ptr(), &mut s) }) == 0 && s.f_type as i64 == TMPFS_MAGIC
}

fn in_mountinfo(at: &str) -> bool {
    std::fs::read_to_string("/proc/self/mountinfo").is_ok_and(|m| m.lines().any(|l| l.split(' ').nth(4) == Some(at)))
}

fn ns_link(pid: &str) -> String {
    std::fs::read_link(format!("/proc/{pid}/ns/mnt")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
}

/// `stx_mnt_id`, at offset 144 of `struct statx` (`STATX_MNT_ID` 0x1000).
fn mnt_id(path: &str) -> u64 {
    let mut buf = [0u8; 256];
    unsafe { libc::syscall(libc::SYS_statx, libc::AT_FDCWD, c(path).as_ptr(), 0, 0x1000u32, buf.as_mut_ptr()) };
    u64::from_le_bytes(buf[144..152].try_into().unwrap())
}

fn dev(path: &str) -> u64 {
    std::fs::metadata(path).map(|m| std::os::unix::fs::MetadataExt::dev(&m)).unwrap_or(0)
}

fn propagate(at: &str, flags: u64) -> i64 {
    unsafe { libc::mount(c"none".as_ptr(), c(at).as_ptr(), std::ptr::null(), flags, std::ptr::null()) as i64 }
}

/// A pipe pair for "the child has done it" and "the parent has looked".
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

fn fork(f: impl FnOnce()) -> i32 {
    let _ = std::io::stdout().flush();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    pid
}

fn wait(pid: i32) {
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
}

fn main() {
    let _ = std::fs::create_dir_all(BASE);
    for d in ["inherited", "inner", "later", "cloned", "thread", "plain"] {
        let _ = std::fs::create_dir_all(dir(d));
    }
    let parent_ns = ns_link("self");
    line("the link's form", parent_ns.split(':').next().unwrap_or(""));
    line("tmpfs at inherited, here", rc(tmpfs(&dir("inherited"))));

    // unshare, and what each side sees.
    let s = Sync::new();
    let pid = fork(|| {
        line("unshare(CLONE_NEWNS)", rc(unsafe { libc::unshare(NEWNS) } as i64));
        line("  the link changed", ns_link("self") != parent_ns);
        line("  mount --make-rprivate /", rc(propagate("/", libc::MS_REC | libc::MS_PRIVATE)));
        line("  the inherited mount is there", mounted(&dir("inherited")) && in_mountinfo(&dir("inherited")));
        line("  the mount id of / differs from the parent's", mnt_id("/") != 0);
        line("  tmpfs at inner", rc(tmpfs(&dir("inner"))));
        line("  inner is mounted here", mounted(&dir("inner")) && in_mountinfo(&dir("inner")));
        line("  umount the inherited one", rc(unsafe { libc::umount(c(&dir("inherited")).as_ptr()) } as i64));
        line("  and it is gone here", !mounted(&dir("inherited")) && !in_mountinfo(&dir("inherited")));
        std::fs::write(format!("{}/f", dir("inner")), b"x").ok();
        s.child_done();
        line("  a mount the parent made afterwards", if mounted(&dir("later")) { "seen" } else { "not seen" });
    });
    s.parent_wait();
    line("here: inner is not mounted", !mounted(&dir("inner")) && !in_mountinfo(&dir("inner")));
    line("here: the file made under inner is not here", std::fs::metadata(format!("{}/f", dir("inner"))).is_err());
    line("here: inherited is still mounted", mounted(&dir("inherited")));
    line("here: the child's / has another mount id", {
        mnt_id(&format!("/proc/{pid}/root/")) != mnt_id("/")
    });
    line("here: and the same device", dev(&format!("/proc/{pid}/root/")) == dev("/"));
    line("tmpfs at later, here", rc(tmpfs(&dir("later"))));
    s.parent_looked();
    wait(pid);

    // setns.
    let s = Sync::new();
    let holder = fork(|| {
        unsafe { libc::unshare(NEWNS) };
        tmpfs(&dir("plain"));
        s.child_done();
    });
    s.parent_wait();
    let pid = fork(|| {
        let theirs = unsafe { libc::open(c(&format!("/proc/{holder}/ns/mnt")).as_ptr(), libc::O_RDONLY) };
        let ours = unsafe { libc::open(c"/proc/self/ns/mnt".as_ptr(), libc::O_RDONLY) };
        unsafe { libc::chdir(c(BASE).as_ptr()) };
        line("setns(their mnt, CLONE_NEWNS)", rc(unsafe { libc::setns(theirs, NEWNS) } as i64));
        line("  their mount is seen", mounted(&dir("plain")));
        let cwd = std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        line("  the working directory after", cwd);
        line("setns(our mnt, 0)", rc(unsafe { libc::setns(ours, 0) } as i64));
        line("  their mount is not seen", !mounted(&dir("plain")));
        line("setns(own mnt) with a thread sharing fs", {
            let me = unsafe { libc::open(c"/proc/self/ns/mnt".as_ptr(), libc::O_RDONLY) };
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let t = std::thread::spawn(move || {
                let _ = rx.recv();
            });
            let r = rc(unsafe { libc::setns(me, NEWNS) } as i64);
            let _ = tx.send(());
            let _ = t.join();
            r
        });
    });
    wait(pid);
    let pid = fork(|| {
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, holder, 0) } as i32;
        line("setns(pidfd, CLONE_NEWNS)", rc(unsafe { libc::setns(pidfd, NEWNS) } as i64));
        line("  their mount is seen", mounted(&dir("plain")));
    });
    wait(pid);
    s.parent_looked();
    wait(holder);

    // clone.
    let pid = fork(|| {
        let mut stack = vec![0u8; 64 * 1024];
        extern "C" fn inner(_: *mut libc::c_void) -> i32 {
            line("clone(CLONE_NEWNS): the inherited mount", mounted(&dir("inherited")));
            line("clone(CLONE_NEWNS): tmpfs at cloned", rc(tmpfs(&dir("cloned"))));
            0
        }
        let top = unsafe { stack.as_mut_ptr().add(stack.len()) };
        let child = unsafe { libc::clone(inner, top.cast(), NEWNS | libc::SIGCHLD, std::ptr::null_mut()) };
        let r = rc(child as i64);
        wait(child);
        line("clone(CLONE_NEWNS)", r);
        line("  cloned is not mounted on this side", !mounted(&dir("cloned")));
        let child = unsafe { libc::clone(inner, top.cast(), NEWNS | libc::CLONE_FS | libc::SIGCHLD, std::ptr::null_mut()) };
        line("clone(CLONE_NEWNS|CLONE_FS)", rc(child as i64));
    });
    wait(pid);

    // A thread's.
    let pid = fork(|| {
        let r = std::thread::spawn(|| {
            let r = rc(unsafe { libc::unshare(NEWNS) } as i64);
            tmpfs(&dir("thread"));
            (r, mounted(&dir("thread")))
        })
        .join()
        .unwrap_or_default();
        line("a thread's unshare(CLONE_NEWNS)", r.0);
        line("  its mount, there", r.1);
        line("  the other thread does not see it", !mounted(&dir("thread")));
    });
    wait(pid);

    // The propagation flags.
    let pid = fork(|| {
        unsafe { libc::unshare(NEWNS) };
        for (what, flags) in [
            ("MS_PRIVATE", libc::MS_PRIVATE),
            ("MS_SLAVE", libc::MS_SLAVE),
            ("MS_UNBINDABLE", libc::MS_UNBINDABLE),
            ("MS_REC | MS_SLAVE", libc::MS_REC | libc::MS_SLAVE),
            ("MS_PRIVATE | MS_SLAVE", libc::MS_PRIVATE | libc::MS_SLAVE),
            ("MS_PRIVATE | MS_RDONLY", libc::MS_PRIVATE | libc::MS_RDONLY),
            ("MS_SHARED", libc::MS_SHARED),
        ] {
            line(&format!("mount(none, inherited, {what})"), rc(propagate(&dir("inherited"), flags)));
        }
        line("mount(none, a directory no mount is at, MS_PRIVATE)", rc(propagate(BASE, libc::MS_PRIVATE)));
        line("mount(none, a missing path, MS_PRIVATE)", rc(propagate(&dir("missing"), libc::MS_PRIVATE)));
        line("mount(NULL, /, NULL, MS_REC | MS_PRIVATE, NULL)", rc(unsafe {
            libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null())
        } as i64));
        line("mountinfo of inherited has no propagation tag", {
            std::fs::read_to_string("/proc/self/mountinfo").is_ok_and(|m| {
                m.lines()
                    .find(|l| l.split(' ').nth(4) == Some(dir("inherited").as_str()))
                    .is_some_and(|l| !l.contains("shared:") && !l.contains("master:"))
            })
        });
    });
    wait(pid);

    let pid = fork(|| {
        let mnt = unsafe { libc::open(c"/proc/self/ns/mnt".as_ptr(), libc::O_RDONLY) };
        unsafe {
            libc::setgid(1000);
            libc::setuid(1000);
        }
        line("unshare(CLONE_NEWNS) as uid 1000", rc(unsafe { libc::unshare(NEWNS) } as i64));
        line("setns(own mnt) as uid 1000", rc(unsafe { libc::setns(mnt, NEWNS) } as i64));
    });
    wait(pid);

    for d in ["inherited", "later"] {
        unsafe { libc::umount(c(&dir(d)).as_ptr()) };
    }
    let _ = std::fs::remove_dir_all(BASE);
}
