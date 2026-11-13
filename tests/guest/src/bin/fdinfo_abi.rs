//! `/proc/<pid>/fdinfo/<n>`: the four lines every descriptor has and the ones
//! each kind adds, checked against what a real kernel prints
//! (`fdinfo_probe`'s recording).
//!
//! glibc's `pidfd_getpid` reads a pidfd's `Pid:` line, and CRIU, `lsof` and
//! `ss` read the rest. The directory did not exist until 2026-11-11.

use guest_tests::{Harness, check, cpath};

fn fdinfo(fd: i32) -> String {
    std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).unwrap_or_default()
}

fn has(text: &str, line: &str) -> bool {
    text.lines().any(|l| l == line)
}

fn value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|l| l.strip_prefix(key))
}

fn fstat(fd: i32) -> libc::stat {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(fd, &mut st) };
    st
}

/// `stx_mnt_id`, at offset 144 of `struct statx`.
fn mnt_id(fd: i32) -> u64 {
    let mut buf = [0u8; 256];
    unsafe {
        libc::syscall(libc::SYS_statx, fd, c"".as_ptr(), libc::AT_EMPTY_PATH, 0x1000u32, buf.as_mut_ptr())
    };
    u64::from_le_bytes(buf[144..152].try_into().unwrap())
}

fn pidfd_open(pid: i32) -> i32 {
    unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 }
}

fn main() {
    let mut h = Harness::new();
    let me = unsafe { libc::getpid() };

    h.group("common lines");
    let path = "/tmp/fdinfo_abi.file";
    let _ = std::fs::remove_file(path);
    let f = unsafe {
        libc::open(cpath(path).as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_APPEND, 0o644)
    };
    unsafe {
        libc::write(f, b"0123456789".as_ptr().cast(), 10);
        libc::lseek(f, 5, libc::SEEK_SET);
    }
    let t = fdinfo(f);
    check!(h, has(&t, "pos:\t5"), "pos is the file position: {t:?}");
    check!(h, has(&t, "flags:\t0402002"), "flags are O_LARGEFILE|O_APPEND|O_RDWR, O_CREAT gone: {t:?}");
    check!(h, has(&t, &format!("mnt_id:\t{}", mnt_id(f))), "mnt_id is statx's: {t:?}");
    check!(h, has(&t, &format!("ino:\t{}", fstat(f).st_ino)), "ino is fstat's: {t:?}");
    let lines: Vec<&str> = t.lines().map(|l| l.split('\t').next().unwrap_or("")).collect();
    check!(h, lines == ["pos:", "flags:", "mnt_id:", "ino:"], "nothing more for a file: {t:?}");
    let g = unsafe { libc::open(cpath(path).as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    check!(h, has(&fdinfo(g), "flags:\t02400000"), "O_CLOEXEC comes from the table: {:?}", fdinfo(g));
    unsafe { libc::fcntl(g, libc::F_SETFD, 0) };
    check!(h, has(&fdinfo(g), "flags:\t0400000"), "and goes with F_SETFD 0: {:?}", fdinfo(g));
    unsafe { libc::close(g) };
    let r = std::fs::read_to_string(format!("/proc/self/fdinfo/{g}"));
    check!(h, r.as_ref().err().and_then(|e| e.raw_os_error()) == Some(libc::ENOENT),
        "a closed number is ENOENT: {r:?}");

    h.group("flags of the kernel's own files");
    let m = unsafe { libc::memfd_create(c"fdinfo_abi".as_ptr(), 0) };
    check!(h, unsafe { libc::fcntl(m, libc::F_GETFL) } == libc::O_RDWR | 0o400000,
        "a memfd is O_RDWR|O_LARGEFILE");
    check!(h, has(&fdinfo(m), "flags:\t0400002"), "and fdinfo says so: {:?}", fdinfo(m));
    let i = unsafe { libc::inotify_init1(libc::IN_NONBLOCK) };
    check!(h, unsafe { libc::fcntl(i, libc::F_GETFL) } == libc::O_NONBLOCK,
        "an inotify descriptor is O_RDONLY");
    check!(h, unsafe { libc::write(i, b"x".as_ptr().cast(), 1) } == -1
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF),
        "so a write to it is EBADF");

    h.group("anonymous files have a mount and an inode");
    let mut p = [0i32; 2];
    unsafe { libc::pipe(p.as_mut_ptr()) };
    let e = unsafe { libc::eventfd(5, libc::EFD_SEMAPHORE) };
    check!(h, mnt_id(p[0]) != 0, "a pipe's mount id is not 0");
    check!(h, mnt_id(e) != 0, "an eventfd's mount id is not 0");
    check!(h, fstat(e).st_ino != 0, "an eventfd's inode is not 0");
    check!(h, fstat(e).st_ino == fstat(i).st_ino, "and it is the one every anonymous file shares");
    let pa = pidfd_open(me);
    let pb = pidfd_open(me);
    check!(h, fstat(pa).st_ino != 0 && fstat(pa).st_ino == fstat(pb).st_ino,
        "two pidfds on one process share a nonzero inode");

    h.group("eventfd");
    let t = fdinfo(e);
    check!(h, has(&t, "eventfd-count:                5"), "the count, %16llx: {t:?}");
    check!(h, has(&t, "eventfd-semaphore: 1"), "semaphore: {t:?}");
    check!(h, value(&t, "eventfd-id: ").is_some_and(|v| v.parse::<u32>().is_ok()), "an id: {t:?}");

    h.group("signalfd");
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        libc::sigaddset(&mut set, 40);
    }
    let s = unsafe { libc::signalfd(-1, &set, 0) };
    check!(h, has(&fdinfo(s), "sigmask:\t0000008000000200"), "the mask: {:?}", fdinfo(s));

    h.group("timerfd");
    let tf = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    let spec = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 2, tv_nsec: 500 },
        it_value: libc::timespec { tv_sec: 100, tv_nsec: 0 },
    };
    unsafe { libc::timerfd_settime(tf, 0, &spec, std::ptr::null_mut()) };
    let t = fdinfo(tf);
    check!(h, has(&t, "clockid: 1") && has(&t, "ticks: 0") && has(&t, "settime flags: 00"),
        "clock, ticks and flags: {t:?}");
    check!(h, value(&t, "it_value: (").is_some_and(|v| v.starts_with("99, ")), "time left: {t:?}");
    check!(h, has(&t, "it_interval: (2, 500)"), "interval: {t:?}");

    h.group("epoll");
    let ep = unsafe { libc::epoll_create1(0) };
    let mut ev = libc::epoll_event { events: (libc::EPOLLIN | libc::EPOLLET) as u32, u64: 0xdead_beef };
    unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, p[0], &mut ev) };
    let st = fstat(p[0]);
    let want = format!(
        "tfd: {:8} events: {:8x} data: {:16x}  pos:0 ino:{:x} sdev:{:x}",
        p[0],
        0x8000_0019u32,
        0xdead_beefu64,
        st.st_ino,
        (libc::major(st.st_dev) as u64) << 20 | libc::minor(st.st_dev) as u64
    );
    check!(h, has(&fdinfo(ep), &want), "the item, ERR|HUP added: {:?} want {want:?}", fdinfo(ep));

    h.group("inotify");
    unsafe { libc::inotify_add_watch(i, c"/tmp".as_ptr(), libc::IN_CREATE | libc::IN_DELETE) };
    let st = std::fs::metadata("/tmp").map(|m| std::os::unix::fs::MetadataExt::ino(&m)).unwrap_or(0);
    let t = fdinfo(i);
    let w = t.lines().find(|l| l.starts_with("inotify ")).unwrap_or("");
    check!(h, w.starts_with(&format!("inotify wd:1 ino:{st:x} ")), "watch and inode: {w:?}");
    check!(h, w.contains(" mask:300 ignored_mask:0 "), "mask: {w:?}");

    h.group("pidfd");
    check!(h, has(&fdinfo(pa), &format!("Pid:\t{me}")) && has(&fdinfo(pa), &format!("NSpid:\t{me}")),
        "self: {:?}", fdinfo(pa));
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::_exit(0) };
    }
    let cf = pidfd_open(child);
    check!(h, fstat(cf).st_ino != fstat(pa).st_ino, "another process, another inode");
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    unsafe { libc::waitid(libc::P_PID, child as u32, &mut info, libc::WEXITED | libc::WNOWAIT) };
    check!(h, has(&fdinfo(cf), &format!("Pid:\t{child}")), "a zombie keeps its pid: {:?}", fdinfo(cf));
    let mut status = 0;
    unsafe { libc::waitpid(child, &mut status, 0) };
    check!(h, has(&fdinfo(cf), "Pid:\t-1") && has(&fdinfo(cf), "NSpid:\t-1"),
        "a reaped one is -1: {:?}", fdinfo(cf));

    h.group("locks");
    // `show_fd_locks`' lines, between `ino:` and the driver's own; the device
    // and inode are `stat`'s. None of these were printed until 2026-11-12.
    let lock_path = "/tmp/fdinfo_abi.locks";
    let _ = std::fs::remove_file(lock_path);
    let open = || unsafe { libc::open(cpath(lock_path).as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o644) };
    let (a, b, c) = (open(), open(), open());
    let st = fstat(a);
    let file = format!("{:02x}:{:02x}:{}", libc::major(st.st_dev), libc::minor(st.st_dev), st.st_ino);
    let setlk = |fd: i32, cmd: i32, ty: i32, start: i64, len: i64| {
        let mut fl: libc::flock = unsafe { std::mem::zeroed() };
        fl.l_type = ty as i16;
        fl.l_start = start;
        fl.l_len = len;
        unsafe { libc::fcntl(fd, cmd, &fl) }
    };
    check!(h, setlk(a, libc::F_SETLK, libc::F_WRLCK, 0, 0) == 0, "F_SETLK");
    let want = format!("lock:\t1: POSIX  ADVISORY  WRITE {me} {file} 0 EOF");
    check!(h, has(&fdinfo(a), &want), "a POSIX lock, on the description it was taken through: {:?} want {want:?}", fdinfo(a));
    check!(h, !fdinfo(b).contains("lock:"), "not on another description of the file: {:?}", fdinfo(b));
    check!(h, setlk(a, libc::F_SETLK, libc::F_RDLCK, 10, 10) == 0, "F_SETLK a read lock inside it");
    let t = fdinfo(a);
    let locks: Vec<&str> = t.lines().filter(|l| l.starts_with("lock:")).collect();
    check!(h, locks == [
        format!("lock:\t1: POSIX  ADVISORY  WRITE {me} {file} 0 9"),
        format!("lock:\t2: POSIX  ADVISORY  READ {me} {file} 10 19"),
        format!("lock:\t3: POSIX  ADVISORY  WRITE {me} {file} 20 EOF"),
    ], "split in three, in order: {locks:?}");
    check!(h, unsafe { libc::flock(b, libc::LOCK_SH) } == 0, "flock");
    let want = format!("lock:\t1: FLOCK  ADVISORY  READ {me} {file} 0 EOF");
    check!(h, has(&fdinfo(b), &want), "a flock: {:?} want {want:?}", fdinfo(b));
    check!(h, setlk(c, libc::F_OFD_SETLK, libc::F_RDLCK, 10, 5) == 0, "F_OFD_SETLK");
    let want = format!("lock:\t1: OFDLCK ADVISORY  READ -1 {file} 10 14");
    check!(h, has(&fdinfo(c), &want), "an OFD lock: {:?} want {want:?}", fdinfo(c));
    let child = unsafe { libc::fork() };
    if child == 0 {
        // The descriptions are shared; the table owning the POSIX locks is not.
        let ok = !fdinfo(a).contains("lock:") && fdinfo(c).contains("OFDLCK");
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(child, &mut status, 0) };
    check!(h, libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "a forked child lists the OFD lock and not the parent's POSIX ones");
    check!(h, unsafe { libc::flock(b, libc::LOCK_UN) } == 0, "unlocking");
    check!(h, !fdinfo(b).contains("lock:"), "takes the line away: {:?}", fdinfo(b));
    let mfd = unsafe { libc::memfd_create(c"fdinfo_abi".as_ptr(), 0) };
    // A memfd has an inode for its locks to live on; both were EBADF.
    check!(h, unsafe { libc::flock(mfd, libc::LOCK_EX) } == 0, "flock on a memfd: errno {}",
        std::io::Error::last_os_error());
    check!(h, setlk(mfd, libc::F_SETLK, libc::F_WRLCK, 0, 1) == 0, "F_SETLK on a memfd");
    let t = fdinfo(mfd);
    check!(h, t.contains("lock:\t1: FLOCK  ADVISORY  WRITE ") && t.contains("lock:\t2: POSIX  ADVISORY  WRITE "),
        "and fdinfo lists both: {t:?}");
    for fd in [a, b, c, mfd] {
        unsafe { libc::close(fd) };
    }
    let _ = std::fs::remove_file(lock_path);

    h.group("who may read it");
    let mode = std::fs::metadata("/proc/self/fdinfo").map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()));
    check!(h, mode.as_ref().ok() == Some(&0o40555), "the directory is 0555: {mode:?}");
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::setresgid(65534, 65534, 65534);
            libc::setresuid(65534, 65534, 65534);
        }
        let errno = |r: std::io::Result<String>| r.err().and_then(|e| e.raw_os_error());
        let theirs = format!("/proc/{me}/fdinfo");
        let mut bad = 0;
        if errno(std::fs::read_to_string(format!("{theirs}/0"))) != Some(libc::EACCES) {
            bad |= 1;
        }
        if std::fs::read_dir(&theirs).err().and_then(|e| e.raw_os_error()) != Some(libc::EACCES) {
            bad |= 2;
        }
        if std::fs::metadata(&theirs).is_err() {
            bad |= 4;
        }
        if std::fs::read_to_string("/proc/self/fdinfo/0").is_err() {
            bad |= 8;
        }
        // The same user may look, while the process is dumpable: ptrace
        // access, which a mode cannot say.
        let peer = || {
            let me = unsafe { libc::getpid() };
            let g = unsafe { libc::fork() };
            if g == 0 {
                let r = std::fs::read_to_string(format!("/proc/{me}/fdinfo/0"));
                unsafe { libc::_exit(match errno(r) { None => 0, Some(libc::EACCES) => 1, Some(_) => 2 }) };
            }
            let mut st = 0;
            unsafe { libc::waitpid(g, &mut st, 0) };
            if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 3 }
        };
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
        if peer() != 0 {
            bad |= 16;
        }
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        if peer() != 1 {
            bad |= 32;
        }
        unsafe { libc::_exit(bad) };
    }
    unsafe { libc::waitpid(child, &mut status, 0) };
    let bad = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 };
    check!(h, bad & 1 == 0, "another user's fdinfo/0 is EACCES (status {bad})");
    check!(h, bad & 2 == 0, "and listing it is EACCES (status {bad})");
    check!(h, bad & 4 == 0, "but the directory stats (status {bad})");
    check!(h, bad & 8 == 0, "and its own is readable (status {bad})");
    check!(h, bad & 16 == 0, "another process of the same user reads it (status {bad})");
    check!(h, bad & 32 == 0, "unless it is not dumpable (status {bad})");

    let _ = std::fs::remove_file(path);
    std::process::exit(h.finish());
}
