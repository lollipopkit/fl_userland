//! IPC namespaces: what `ipcns_probe` measured on a real arm64 kernel,
//! asserted. Runs as root; every case is in a child, and what it makes in
//! the namespace it runs in is removed at the end.

use std::ffi::CString;

use guest_tests::{Harness, check};

const NEWIPC: i32 = 0x0800_0000;
const KEY: i32 = 0x1d5_0002;
const MQ: &std::ffi::CStr = c"/ipcns-test";

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn mq_open(flags: i32) -> i32 {
    let mut attr: libc::mq_attr = unsafe { std::mem::zeroed() };
    attr.mq_maxmsg = 4;
    attr.mq_msgsize = 16;
    unsafe { libc::mq_open(MQ.as_ptr(), flags, 0o600, &mut attr as *mut libc::mq_attr) }
}

fn semval(id: i32) -> i32 {
    unsafe { libc::semctl(id, 0, libc::GETVAL) }
}

fn ipc_link() -> String {
    std::fs::read_link("/proc/self/ns/ipc").map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
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
    let here = ipc_link();
    let shm = unsafe { libc::shmget(KEY, 4096, libc::IPC_CREAT | 0o600) };
    let sem = unsafe { libc::semget(KEY, 1, libc::IPC_CREAT | 0o600) };
    let msg = unsafe { libc::msgget(KEY, libc::IPC_CREAT | 0o600) };
    let mq = mq_open(libc::O_CREAT | libc::O_RDWR);
    check!(h, shm >= 0 && sem >= 0 && msg >= 0 && mq >= 0, "one of each here: {shm} {sem} {msg} {mq}");
    unsafe { libc::semctl(sem, 0, libc::SETVAL, 5) };

    h.group("unshare");
    in_child(&mut h, "a new namespace", |h| {
        let at = unsafe { libc::shmat(shm, std::ptr::null(), 0) } as *mut u8;
        unsafe { *at = 42 };
        check!(h, unsafe { libc::unshare(NEWIPC) } == 0, "unshare(CLONE_NEWIPC): errno {}", errno());
        check!(h, ipc_link() != here, "the link changed");
        for (what, r) in [
            ("shmget", unsafe { libc::shmget(KEY, 0, 0) }),
            ("semget", unsafe { libc::semget(KEY, 0, 0) }),
            ("msgget", unsafe { libc::msgget(KEY, 0) }),
            ("mq_open", mq_open(libc::O_RDWR)),
        ] {
            check!(h, r < 0 && errno() == libc::ENOENT, "{what} of the old key or name: ENOENT, got {r} {}", errno());
        }
        let mut ds: libc::shmid_ds = unsafe { std::mem::zeroed() };
        check!(h, unsafe { libc::shmctl(shm, libc::IPC_STAT, &mut ds) } < 0 && errno() == libc::EINVAL, "the old shm id: EINVAL");
        check!(h, semval(sem) < 0 && errno() == libc::EINVAL, "the old sem id: EINVAL");
        let mut a: libc::mq_attr = unsafe { std::mem::zeroed() };
        check!(h, unsafe { libc::mq_getattr(mq, &mut a) } == 0, "a held mq descriptor still works");
        check!(h, unsafe { *at } == 42, "a held attachment still reads");
        check!(h, unsafe { libc::shmdt(at.cast()) } == 0, "and detaches: errno {}", errno());
        let own = unsafe { libc::shmget(KEY, 8192, libc::IPC_CREAT | libc::IPC_EXCL | 0o600) };
        check!(h, own >= 0, "the key is free here: errno {}", errno());
        check!(h, mq_open(libc::O_CREAT | libc::O_EXCL | libc::O_RDWR) >= 0, "and the name: errno {}", errno());
    });
    let mut ds: libc::shmid_ds = unsafe { std::mem::zeroed() };
    unsafe { libc::shmctl(shm, libc::IPC_STAT, &mut ds) };
    check!(h, ds.shm_segsz == 4096 && ds.shm_nattch == 0, "here, the segment is the old one, detached: {} {}", ds.shm_segsz, ds.shm_nattch);
    check!(h, mq_open(libc::O_CREAT | libc::O_EXCL | libc::O_RDWR) < 0 && errno() == libc::EEXIST, "the name here is still taken");

    h.group("SEM_UNDO");
    for leave in [true, false] {
        let mut p = [0i32; 2];
        let mut q = [0i32; 2];
        unsafe { libc::pipe(p.as_mut_ptr()) };
        unsafe { libc::pipe(q.as_mut_ptr()) };
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
        let during = semval(sem);
        unsafe { libc::write(q[1], b"x".as_ptr().cast(), 1) };
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        let want = if leave { 5 } else { 3 };
        check!(h, during == want, "unshare {leave}: {during} while alive, want {want}");
        check!(h, semval(sem) == 5, "unshare {leave}: 5 after exit, got {}", semval(sem));
        for fd in p.into_iter().chain(q) {
            unsafe { libc::close(fd) };
        }
    }

    h.group("setns and clone");
    in_child(&mut h, "back through the ns file", |h| {
        let back = unsafe {
            libc::open(CString::new(format!("/proc/{}/ns/ipc", std::os::unix::process::parent_id())).unwrap().as_ptr(), libc::O_RDONLY)
        };
        unsafe { libc::unshare(NEWIPC) };
        check!(h, unsafe { libc::setns(back, NEWIPC) } == 0, "setns: errno {}", errno());
        check!(h, unsafe { libc::shmget(KEY, 0, 0) } == shm, "the old segment again");
        check!(h, mq_open(libc::O_RDWR) >= 0, "the old queue again");
    });
    in_child(&mut h, "a namespace held by a descriptor", |h| {
        let keep = unsafe { libc::open(c"/proc/self/ns/ipc".as_ptr(), libc::O_RDONLY) };
        unsafe { libc::unshare(NEWIPC) };
        let fd = unsafe { libc::open(c"/proc/self/ns/ipc".as_ptr(), libc::O_RDONLY) };
        let made = unsafe { libc::msgget(KEY + 1, libc::IPC_CREAT | 0o600) };
        unsafe { libc::setns(keep, NEWIPC) };
        unsafe { libc::setns(fd, NEWIPC) };
        check!(h, made >= 0 && unsafe { libc::msgget(KEY + 1, 0) } == made, "its queue is still there");
    });
    in_child(&mut h, "clone", |h| {
        let mut stack = vec![0u8; 64 * 1024];
        extern "C" fn inner(_: *mut libc::c_void) -> i32 {
            (unsafe { libc::shmget(KEY, 0, 0) } >= 0) as i32
        }
        let top = unsafe { stack.as_mut_ptr().add(stack.len()) };
        let pid = unsafe { libc::clone(inner, top.cast(), NEWIPC | libc::SIGCHLD, std::ptr::null_mut()) };
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        check!(h, pid > 0 && libc::WEXITSTATUS(status) == 0, "clone(CLONE_NEWIPC): the child finds nothing");
        let pid = unsafe { libc::clone(inner, top.cast(), NEWIPC | libc::CLONE_SYSVSEM | libc::SIGCHLD, std::ptr::null_mut()) };
        check!(h, pid < 0 && errno() == libc::EINVAL, "with CLONE_SYSVSEM: EINVAL");
    });
    in_child(&mut h, "a thread", |h| {
        let theirs = std::thread::spawn(|| {
            unsafe { libc::unshare(NEWIPC) };
            unsafe { libc::shmget(KEY, 0, 0) }
        })
        .join()
        .unwrap_or(0);
        check!(h, theirs < 0, "the thread's namespace is empty");
        check!(h, unsafe { libc::shmget(KEY, 0, 0) } == shm, "the other thread's is not");
    });
    in_child(&mut h, "uid 1000", |h| {
        let ipc = unsafe { libc::open(c"/proc/self/ns/ipc".as_ptr(), libc::O_RDONLY) };
        unsafe {
            libc::setgid(1000);
            libc::setuid(1000);
        }
        check!(h, unsafe { libc::unshare(NEWIPC) } < 0 && errno() == libc::EPERM, "unshare: EPERM");
        check!(h, unsafe { libc::setns(ipc, NEWIPC) } < 0 && errno() == libc::EPERM, "setns: EPERM");
    });

    unsafe {
        libc::shmctl(shm, libc::IPC_RMID, std::ptr::null_mut());
        libc::semctl(sem, 0, libc::IPC_RMID);
        libc::msgctl(msg, libc::IPC_RMID, std::ptr::null_mut());
        libc::mq_unlink(MQ.as_ptr());
    }
    std::process::exit(h.finish());
}
