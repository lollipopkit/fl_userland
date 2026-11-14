//! IPC namespaces: which System V objects and POSIX message queues a task
//! sees after `unshare`, `clone` and `setns` with `CLONE_NEWIPC`, and what
//! happens to what it already holds.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container (`CAP_SYS_ADMIN`) and diffed by `tests/integration/probe_diff.sh`.
//! Ids and namespace numbers are not printed, only how they compare. Every
//! case runs in a child, so the probe's own namespace is left as it was; the
//! objects it makes in its own namespace are removed at the end.

use std::ffi::CString;
use std::io::Write;

const NEWIPC: i32 = 0x0800_0000;
const NEWUTS: i32 = 0x0400_0000;

const KEY: i32 = 0x1d5_0001;
const MQ: &std::ffi::CStr = c"/ipcns-probe";

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
        libc::EIDRM => "EIDRM".into(),
        libc::EEXIST => "EEXIST".into(),
        libc::EBADF => "EBADF".into(),
        e => format!("errno {e}"),
    }
}

fn ns_link(pid: &str) -> String {
    std::fs::read_link(format!("/proc/{pid}/ns/ipc")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
}

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

fn semval(id: i32) -> i32 {
    unsafe { libc::semctl(id, 0, libc::GETVAL) }
}

fn mq_open(flags: i32) -> i32 {
    let mut attr: libc::mq_attr = unsafe { std::mem::zeroed() };
    attr.mq_maxmsg = 4;
    attr.mq_msgsize = 16;
    unsafe { libc::mq_open(MQ.as_ptr(), flags, 0o600, &mut attr as *mut libc::mq_attr) }
}

fn main() {
    let parent_ns = ns_link("self");
    line("the link's form", parent_ns.split(':').next().unwrap_or(""));

    // One of each, in this namespace.
    let shm = unsafe { libc::shmget(KEY, 4096, libc::IPC_CREAT | 0o600) };
    let sem = unsafe { libc::semget(KEY, 1, libc::IPC_CREAT | 0o600) };
    let msg = unsafe { libc::msgget(KEY, libc::IPC_CREAT | 0o600) };
    let mq = mq_open(libc::O_CREAT | libc::O_RDWR);
    line("made shm, sem, msg and mq here", shm >= 0 && sem >= 0 && msg >= 0 && mq >= 0);
    unsafe { libc::semctl(sem, 0, libc::SETVAL, 5) };

    child(|| {
        // Attached before, held after.
        let at = unsafe { libc::shmat(shm, std::ptr::null(), 0) } as *mut u8;
        unsafe { *at = 42 };
        line("unshare(CLONE_NEWIPC)", rc(unsafe { libc::unshare(NEWIPC) } as i64));
        line("  the link changed", ns_link("self") != parent_ns);
        line("  shmget(the key)", rc(unsafe { libc::shmget(KEY, 0, 0) } as i64));
        line("  semget(the key)", rc(unsafe { libc::semget(KEY, 0, 0) } as i64));
        line("  msgget(the key)", rc(unsafe { libc::msgget(KEY, 0) } as i64));
        line("  mq_open(the name)", rc(mq_open(libc::O_RDWR) as i64));
        let mut ds: libc::shmid_ds = unsafe { std::mem::zeroed() };
        line("  shmctl(the old id, IPC_STAT)", rc(unsafe { libc::shmctl(shm, libc::IPC_STAT, &mut ds) } as i64));
        line("  semctl(the old id, GETVAL)", rc(semval(sem) as i64));
        line("  the old mq descriptor still works", unsafe {
            let mut a: libc::mq_attr = std::mem::zeroed();
            libc::mq_getattr(mq, &mut a) == 0
        });
        line("  the attachment still reads", unsafe { *at } == 42);
        line("  shmdt of it", rc(unsafe { libc::shmdt(at.cast()) } as i64));
        let own = unsafe { libc::shmget(KEY, 8192, libc::IPC_CREAT | libc::IPC_EXCL | 0o600) };
        line("  shmget(the key, IPC_CREAT|IPC_EXCL)", rc(own as i64));
        line("  the new one is 8192 bytes", unsafe {
            let mut d: libc::shmid_ds = std::mem::zeroed();
            libc::shmctl(own, libc::IPC_STAT, &mut d) == 0 && d.shm_segsz == 8192
        });
        line("  mq_open(the name, O_CREAT|O_EXCL)", rc(mq_open(libc::O_CREAT | libc::O_EXCL | libc::O_RDWR) as i64));
    });
    let mut ds: libc::shmid_ds = unsafe { std::mem::zeroed() };
    unsafe { libc::shmctl(shm, libc::IPC_STAT, &mut ds) };
    line("after the child: the segment here is 4096 bytes", ds.shm_segsz == 4096);
    line("  and nothing is attached", ds.shm_nattch == 0);
    line("  mq_open(O_CREAT|O_EXCL) here", rc(mq_open(libc::O_CREAT | libc::O_EXCL | libc::O_RDWR) as i64));

    // A SEM_UNDO adjustment is applied when the task leaves the namespace,
    // not when it exits: read here while the child is still alive.
    for (what, leave) in [("semop(-2, SEM_UNDO), then unshare(CLONE_NEWIPC)", true), ("semop(-2, SEM_UNDO), then nothing", false)] {
        let mut p = [0i32; 2];
        let mut q = [0i32; 2];
        unsafe { libc::pipe(p.as_mut_ptr()) };
        unsafe { libc::pipe(q.as_mut_ptr()) };
        let _ = std::io::stdout().flush();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let mut op = libc::sembuf { sem_num: 0, sem_op: -2, sem_flg: libc::SEM_UNDO as i16 };
            unsafe { libc::semop(sem, &mut op, 1) };
            if leave {
                unsafe { libc::unshare(NEWIPC) };
            }
            let mut b = 0u8;
            unsafe { libc::write(p[1], b"x".as_ptr().cast(), 1) };
            unsafe { libc::read(q[0], (&raw mut b).cast(), 1) };
            unsafe { libc::_exit(0) };
        }
        let mut b = 0u8;
        unsafe { libc::read(p[0], (&raw mut b).cast(), 1) };
        line(&format!("{what}: the value here"), semval(sem));
        unsafe { libc::write(q[1], b"x".as_ptr().cast(), 1) };
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        line("  after it exits", semval(sem));
        for fd in p.into_iter().chain(q) {
            unsafe { libc::close(fd) };
        }
    }

    // setns back through the ns file, and through a pidfd.
    child(|| {
        let back = unsafe {
            libc::open(CString::new(format!("/proc/{}/ns/ipc", std::os::unix::process::parent_id())).unwrap().as_ptr(), libc::O_RDONLY)
        };
        unsafe { libc::unshare(NEWIPC) };
        line("setns(fd, CLONE_NEWUTS) on an ipc file", rc(unsafe { libc::setns(back, NEWUTS) } as i64));
        line("setns(fd, CLONE_NEWIPC)", rc(unsafe { libc::setns(back, NEWIPC) } as i64));
        line("  the link is the parent's", ns_link("self") == parent_ns);
        line("  shmget(the key) is the parent's id", unsafe { libc::shmget(KEY, 0, 0) } == shm);
        line("  mq_open(the name)", rc(mq_open(libc::O_RDWR) as i64));
    });
    child(|| {
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::os::unix::process::parent_id(), 0) } as i32;
        unsafe { libc::unshare(NEWIPC) };
        line("setns(pidfd, CLONE_NEWIPC)", rc(unsafe { libc::setns(pidfd, NEWIPC) } as i64));
        line("  semget(the key) is the parent's id", unsafe { libc::semget(KEY, 0, 0) } == sem);
    });

    // A namespace's objects go with it.
    child(|| {
        let keep = unsafe { libc::open(c"/proc/self/ns/ipc".as_ptr(), libc::O_RDONLY) };
        let _ = keep;
        unsafe { libc::unshare(NEWIPC) };
        let fd = unsafe { libc::open(c"/proc/self/ns/ipc".as_ptr(), libc::O_RDONLY) };
        let made = unsafe { libc::msgget(KEY + 1, libc::IPC_CREAT | 0o600) };
        line("in a new one: msgget(another key, IPC_CREAT)", rc(made as i64));
        // Held by `fd` only from here.
        unsafe { libc::setns(keep, NEWIPC) };
        unsafe { libc::setns(fd, NEWIPC) };
        line("  back through a held descriptor: still there", unsafe { libc::msgget(KEY + 1, 0) } == made);
    });

    // clone with CLONE_NEWIPC.
    child(|| {
        let mut stack = vec![0u8; 64 * 1024];
        extern "C" fn inner(_: *mut libc::c_void) -> i32 {
            line("clone(CLONE_NEWIPC): shmget(the key)", rc(unsafe { libc::shmget(KEY, 0, 0) } as i64));
            0
        }
        let top = unsafe { stack.as_mut_ptr().add(stack.len()) };
        let pid = unsafe { libc::clone(inner, top.cast(), NEWIPC | libc::SIGCHLD, std::ptr::null_mut()) };
        let r = rc(pid as i64);
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        line("clone(CLONE_NEWIPC)", r);
        let pid = unsafe { libc::clone(inner, top.cast(), NEWIPC | libc::CLONE_SYSVSEM | libc::SIGCHLD, std::ptr::null_mut()) };
        line("clone(CLONE_NEWIPC|CLONE_SYSVSEM)", rc(pid as i64));
    });

    // A thread's.
    child(|| {
        let theirs = std::thread::spawn(|| {
            unsafe { libc::unshare(NEWIPC) };
            unsafe { libc::shmget(KEY, 0, 0) }
        })
        .join()
        .unwrap_or(0);
        line("a thread's unshare: shmget(the key) there", if theirs < 0 { "ENOENT" } else { "found" });
        line("  the other thread still finds it", unsafe { libc::shmget(KEY, 0, 0) } == shm);
    });

    child(|| {
        let ipc = unsafe { libc::open(c"/proc/self/ns/ipc".as_ptr(), libc::O_RDONLY) };
        unsafe {
            libc::setgid(1000);
            libc::setuid(1000);
        }
        line("unshare(CLONE_NEWIPC) as uid 1000", rc(unsafe { libc::unshare(NEWIPC) } as i64));
        line("setns(own ipc) as uid 1000", rc(unsafe { libc::setns(ipc, NEWIPC) } as i64));
    });

    unsafe {
        libc::shmctl(shm, libc::IPC_RMID, std::ptr::null_mut());
        libc::semctl(sem, 0, libc::IPC_RMID);
        libc::msgctl(msg, libc::IPC_RMID, std::ptr::null_mut());
        libc::mq_unlink(MQ.as_ptr());
    }
}
