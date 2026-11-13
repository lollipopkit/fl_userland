//! What `/proc/<pid>/fdinfo/<fd>` says about each kind of descriptor.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container and diffed by `tests/integration/probe_diff.sh`.
//!
//! Every file is printed line by line, in its own layout, with the values that
//! name this machine rather than the kernel's rules -- mount ids, inode and
//! device numbers, eventfd ids, pids -- replaced by whether they agree with
//! what another call says about the same object: `statx`'s `stx_mnt_id`,
//! `fstat`'s `st_ino` and `st_dev`, `name_to_handle_at(AT_HANDLE_FID)`.
//! Everything else, `pos:`, `flags:` and the per-type lines, is verbatim.
//!
//! glibc's `pidfd_getpid` reads the `Pid:` line of a pidfd's fdinfo; CRIU,
//! `lsof` and `ss` read the rest.

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
        libc::ENOENT => "ENOENT",
        libc::EACCES => "EACCES",
        libc::EINVAL => "EINVAL",
        libc::ESRCH => "ESRCH",
        libc::EBADF => "EBADF",
        libc::ENOTDIR => "ENOTDIR",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn ok(fd: i32, what: &str) -> i32 {
    if fd < 0 {
        line(what, named(errno()));
    }
    fd
}

/// `struct statx`'s `stx_mnt_id`, at offset 144. The libc crate has no
/// `statx` for musl.
fn statx_mnt_id(fd: i32) -> Option<u64> {
    const STATX_MNT_ID: u32 = 0x1000;
    let mut buf = [0u8; 256];
    let r = unsafe {
        libc::syscall(
            libc::SYS_statx,
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            STATX_MNT_ID,
            buf.as_mut_ptr(),
        )
    };
    (r == 0).then(|| u64::from_le_bytes(buf[144..152].try_into().unwrap()))
}

fn fstat(fd: i32) -> Option<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st)
}

/// The device as the kernel holds it, `MAJOR << 20 | MINOR`, which is what
/// `sdev:` prints; `st_dev` is the userspace encoding of the same number.
fn kernel_dev(st: &libc::stat) -> u64 {
    let (major, minor) = (libc::major(st.st_dev) as u64, libc::minor(st.st_dev) as u64);
    major << 20 | minor
}

/// `name_to_handle_at(AT_HANDLE_FID)` of `path`: `(bytes, type, handle)`.
fn handle_fid(path: &std::ffi::CStr) -> Option<(u32, i32, Vec<u8>)> {
    const AT_HANDLE_FID: i32 = 0x200;
    let mut buf = [0u8; 8 + 128];
    buf[..4].copy_from_slice(&128u32.to_ne_bytes());
    let mut mnt = 0i32;
    let r = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            libc::AT_FDCWD,
            path.as_ptr(),
            buf.as_mut_ptr(),
            &mut mnt,
            AT_HANDLE_FID,
        )
    };
    if r != 0 {
        return None;
    }
    let bytes = u32::from_ne_bytes(buf[..4].try_into().unwrap());
    let ty = i32::from_ne_bytes(buf[4..8].try_into().unwrap());
    Some((bytes, ty, buf[8..8 + bytes as usize].to_vec()))
}

/// The pids a line may name, and what to print instead.
struct Who {
    me: i32,
    child: i32,
}

/// Replace the token after `key` in `l` -- up to the next whitespace -- with
/// what `judge` says about it. The rest of the line, spacing included, is
/// left as it was: the layout is part of the answer.
fn subst(l: &str, key: &str, judge: impl FnOnce(&str) -> String) -> String {
    let Some(at) = l.find(key) else {
        return l.to_string();
    };
    let start = at + key.len();
    let rest = &l[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    format!("{}{}{}", &l[..start], judge(&rest[..end]), &rest[end..])
}

fn agrees(got: &str, want: Option<u64>, hex: bool) -> String {
    let parsed = if hex {
        u64::from_str_radix(got, 16).ok()
    } else {
        got.parse::<u64>().ok()
    };
    match (parsed, want) {
        (Some(g), Some(w)) if g == w => {
            if g == 0 { "<agrees, zero>".into() } else { "<agrees>".into() }
        }
        _ => format!("<{got}, expected {want:?}>"),
    }
}

/// Print `/proc/self/fdinfo/<fd>`, normalised as the module comment says.
///
/// `targets` is what the inotify lines name, in the order they are printed:
/// the path whose inode, device and handle each reports. An epoll line names
/// its own target's number.
fn show(title: &str, fd: i32, who: &Who, targets: &[&std::ffi::CStr]) {
    println!("## {title}");
    let text = match std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")) {
        Ok(t) => t,
        Err(e) => {
            line("  read fdinfo", named(e.raw_os_error().unwrap_or(0)));
            return;
        }
    };
    let st = fstat(fd);
    let mut epoll = Vec::new();
    let mut inotify_n = 0usize;
    for raw in text.lines() {
        let mut l = raw.to_string();
        if l.starts_with("mnt_id:") {
            l = subst(&l, "mnt_id:\t", |v| agrees(v, statx_mnt_id(fd), false));
        } else if l.starts_with("ino:") {
            l = subst(&l, "ino:\t", |v| agrees(v, st.map(|s| s.st_ino), false));
        } else if l.starts_with("eventfd-id:") {
            l = subst(&l, "eventfd-id: ", |v| {
                if v.parse::<u32>().is_ok() { "<a number>".into() } else { format!("<{v}>") }
            });
        } else if l.starts_with("it_value:") {
            // The seconds are whole and the nanoseconds are however long it
            // took to get here.
            l = subst(&l, ", ", |v| {
                if v == "0)" { v.into() } else { "<ns>)".into() }
            });
        } else if l.starts_with("tfd:") {
            // Linux lists them in the order of its tree, which is by `struct
            // file` address: sorted by number here, after the loop.
            let target = l.split_whitespace().nth(1).and_then(|n| n.parse().ok()).and_then(fstat);
            l = subst(&l, "ino:", |v| agrees(v, target.map(|s| s.st_ino), true));
            l = subst(&l, "sdev:", |v| agrees(v, target.map(|s| kernel_dev(&s)), true));
            epoll.push(l);
            continue;
        } else if l.starts_with("inotify ") {
            let path = targets.get(inotify_n).copied();
            inotify_n += 1;
            let target = path.and_then(|p| {
                let mut s: libc::stat = unsafe { std::mem::zeroed() };
                (unsafe { libc::stat(p.as_ptr(), &mut s) } == 0).then_some(s)
            });
            let fid = path.and_then(handle_fid);
            l = subst(&l, "ino:", |v| agrees(v, target.map(|s| s.st_ino), true));
            l = subst(&l, "sdev:", |v| agrees(v, target.map(|s| kernel_dev(&s)), true));
            l = subst(&l, "fhandle-bytes:", |v| {
                agrees(v, fid.as_ref().map(|f| u64::from(f.0)), true)
            });
            l = subst(&l, "fhandle-type:", |v| {
                agrees(v, fid.as_ref().map(|f| f.1 as u32 as u64), true)
            });
            l = subst(&l, "f_handle:", |v| {
                let want: Option<String> =
                    fid.as_ref().map(|f| f.2.iter().map(|b| format!("{b:02x}")).collect());
                if want.as_deref() == Some(v) { "<agrees>".into() } else { format!("<{v}, expected {want:?}>") }
            });
        } else if l.starts_with("Pid:") || l.starts_with("NSpid:") {
            let (k, v) = l.split_once('\t').unwrap_or((&l, ""));
            let v: Vec<String> = v
                .split('\t')
                .map(|n| match n.parse::<i32>() {
                    Ok(p) if p == who.me => "<self>".into(),
                    Ok(p) if p == who.child && p > 0 => "<child>".into(),
                    _ => n.into(),
                })
                .collect();
            l = format!("{k}\t{}", v.join("\t"));
        } else if l.starts_with("lock:") {
            l = lock_line(&l, who, st.as_ref());
        }
        println!("  {l}");
    }
    epoll.sort_by_key(|l| l.split_whitespace().nth(1).and_then(|n| n.parse::<i32>().ok()));
    for l in epoll {
        println!("  {l}");
    }
}

/// A `lock:` line with its pid and its `major:minor:inode` judged, and its
/// spacing kept: `lock:\t1: POSIX  ADVISORY  WRITE <pid> <dev:ino> 0 EOF`.
fn lock_line(l: &str, who: &Who, st: Option<&libc::stat>) -> String {
    // Whitespace runs and tokens alternate; the pid is the fifth token after
    // the id and the device the sixth, counting `lock:` as the first.
    let mut out = String::new();
    let mut token = 0;
    let mut rest = l;
    while !rest.is_empty() {
        let ws = rest.len() - rest.trim_start().len();
        out.push_str(&rest[..ws]);
        rest = &rest[ws..];
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let t = &rest[..end];
        rest = &rest[end..];
        out.push_str(&match token {
            5 => match t.parse::<i32>() {
                Ok(p) if p == who.me => "<self>".into(),
                Ok(p) if p == who.child && p > 0 => "<child>".into(),
                _ => t.into(),
            },
            6 => {
                let want = st.map(|s| {
                    format!("{:02x}:{:02x}:{}", libc::major(s.st_dev), libc::minor(s.st_dev), s.st_ino)
                });
                if want.as_deref() == Some(t) { "<agrees>".into() } else { format!("<{t}, expected {want:?}>") }
            }
            _ => t.into(),
        });
        token += 1;
    }
    out
}

fn setlk(fd: i32, cmd: i32, ty: i32, start: i64, len: i64) -> String {
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = ty as i16;
    fl.l_whence = libc::SEEK_SET as i16;
    fl.l_start = start;
    fl.l_len = len;
    if unsafe { libc::fcntl(fd, cmd, &fl) } == 0 { "ok".into() } else { named(errno()) }
}

fn locks(who: &Who) {
    println!("########## locks ##########");
    let path = c"/tmp/fdinfo_probe.locks";
    unsafe { libc::unlink(path.as_ptr()) };
    let open = || unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o644) };
    let a = ok(open(), "open file");
    let b = ok(open(), "open file");
    let c = ok(open(), "open file");
    line("F_SETLK F_WRLCK, the whole file, through a", setlk(a, libc::F_SETLK, libc::F_WRLCK, 0, 0));
    show("a", a, who, &[]);
    show("b, the same file, another description", b, who, &[]);
    line("F_SETLK F_RDLCK 10..19, through a", setlk(a, libc::F_SETLK, libc::F_RDLCK, 10, 10));
    show("a, split in three", a, who, &[]);
    let d = unsafe { libc::dup(a) };
    show("a dup of a", d, who, &[]);
    line("flock(b, LOCK_SH)", if unsafe { libc::flock(b, libc::LOCK_SH) } == 0 { "ok".into() } else { named(errno()) });
    show("b", b, who, &[]);
    // Inside a's read lock, which is the one range another owner can share.
    line("F_OFD_SETLK F_RDLCK 10..14, through c", setlk(c, libc::F_OFD_SETLK, libc::F_RDLCK, 10, 5));
    show("c", c, who, &[]);
    let child = unsafe { libc::fork() };
    if child == 0 {
        // A forked child shares the descriptions but not the table that owns
        // the POSIX locks.
        let me = Who { me: unsafe { libc::getpid() }, child: who.me };
        show("a, in a forked child", a, &me, &[]);
        show("c, in a forked child", c, &me, &[]);
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(child, &mut st, 0) };
    line("F_SETLK F_UNLCK, the whole file, through a", setlk(a, libc::F_SETLK, libc::F_UNLCK, 0, 0));
    show("a, unlocked", a, who, &[]);
    let m = ok(unsafe { libc::memfd_create(c"locks".as_ptr(), 0) }, "memfd");
    line("flock(memfd, LOCK_EX)", if unsafe { libc::flock(m, libc::LOCK_EX) } == 0 { "ok".into() } else { named(errno()) });
    line("F_SETLK F_WRLCK 0..0 on it", setlk(m, libc::F_SETLK, libc::F_WRLCK, 0, 1));
    show("a memfd, both kinds", m, who, &[]);
    for fd in [a, b, c, d, m] {
        unsafe { libc::close(fd) };
    }
    unsafe { libc::unlink(path.as_ptr()) };
}

/// Linux's `proc_fdinfo_permission`: the mode says anyone, ptrace access to
/// the task says who.
fn access(parent: i32) {
    println!("########## another user ##########");
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::setresgid(65534, 65534, 65534);
            libc::setresuid(65534, 65534, 65534);
            // A credential change makes a process non-dumpable; put it back
            // so the next process of the same user may look. The change
            // alone is the last case below.
            libc::prctl(libc::PR_SET_DUMPABLE, 1);
        }
        let stat = |p: &str| -> String {
            let c = std::ffi::CString::new(p).unwrap();
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::stat(c.as_ptr(), &mut st) } == 0 {
                format!("{:o} uid {}", st.st_mode, st.st_uid)
            } else {
                named(errno())
            }
        };
        let list = |p: &str| match std::fs::read_dir(p) {
            Ok(_) => "a listing".to_string(),
            Err(e) => named(e.raw_os_error().unwrap_or(0)),
        };
        let read = |p: &str| match std::fs::read_to_string(p) {
            Ok(_) => "ok".into(),
            Err(e) => named(e.raw_os_error().unwrap_or(0)),
        };
        let theirs = format!("/proc/{parent}");
        line("uid 65534: stat root's fdinfo", stat(&format!("{theirs}/fdinfo")));
        line("  list it", list(&format!("{theirs}/fdinfo")));
        line("  stat fdinfo/0", stat(&format!("{theirs}/fdinfo/0")));
        line("  read fdinfo/0", read(&format!("{theirs}/fdinfo/0")));
        line("  stat root's fd", stat(&format!("{theirs}/fd")));
        line("  list it", list(&format!("{theirs}/fd")));
        line("uid 65534: stat its own fdinfo/0", stat("/proc/self/fdinfo/0"));
        line("  read it", read("/proc/self/fdinfo/0"));
        let me = unsafe { libc::getpid() };
        let peer = |what: &str| {
            let g = unsafe { libc::fork() };
            if g == 0 {
                let p = format!("/proc/{me}/fdinfo");
                line(&format!("{what}: list its fdinfo"), list(&p));
                line(&format!("{what}: read its fdinfo/0"), read(&format!("{p}/0")));
                unsafe { libc::_exit(0) };
            }
            let mut st = 0;
            unsafe { libc::waitpid(g, &mut st, 0) };
        };
        peer("another uid 65534 process");
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        peer("  once it is not dumpable");
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(child, &mut st, 0) };

    // The case the one above sidesteps: the credential change alone, with
    // nothing setting the flag back.
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::setresgid(65534, 65534, 65534);
            libc::setresuid(65534, 65534, 65534);
        }
        let me = unsafe { libc::getpid() };
        let g = unsafe { libc::fork() };
        if g == 0 {
            let p = format!("/proc/{me}/fdinfo");
            let list = match std::fs::read_dir(&p) {
                Ok(_) => "a listing".to_string(),
                Err(e) => named(e.raw_os_error().unwrap_or(0)),
            };
            line("after setresuid alone: a peer lists its fdinfo", list);
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::waitpid(g, &mut st, 0) };
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(child, &mut st, 0) };
}

fn main() {
    let who = Who { me: unsafe { libc::getpid() }, child: 0 };

    println!("########## the directory ##########");
    {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::stat(c"/proc/self/fdinfo".as_ptr(), &mut st) };
        line("stat /proc/self/fdinfo", if r == 0 { format!("{:o}", st.st_mode) } else { named(errno()) });
        let r = unsafe { libc::stat(c"/proc/self/fdinfo/0".as_ptr(), &mut st) };
        line("stat /proc/self/fdinfo/0", if r == 0 { format!("{:o}", st.st_mode) } else { named(errno()) });
        line("  st_nlink", st.st_nlink);
        let names = |dir: &str| -> Option<Vec<String>> {
            let mut v: Vec<String> = std::fs::read_dir(dir)
                .ok()?
                .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect();
            v.sort();
            Some(v)
        };
        // Both listings open a descriptor on their own directory, so each
        // names one the other does not; what is compared is the rest.
        let fd = names("/proc/self/fd");
        let info = names("/proc/self/fdinfo");
        line("fdinfo lists as many entries as fd", fd.as_ref().map(Vec::len) == info.as_ref().map(Vec::len));
        line("  and the first three are 0 1 2", info.as_deref().map(|v| v.starts_with(&["0".into(), "1".into(), "2".into()])) == Some(true));
        let task = format!("/proc/self/task/{}/fdinfo/0", who.me);
        line("task/<tid>/fdinfo/0 is readable", std::fs::read_to_string(task).is_ok());
        for p in ["/proc/self/fdinfo/9999", "/proc/self/fdinfo/x", "/proc/self/fdinfo/-1"] {
            line(&format!("read {p}"), match std::fs::read_to_string(p) {
                Ok(_) => "ok".into(),
                Err(e) => named(e.raw_os_error().unwrap_or(0)),
            });
        }
        let r = unsafe {
            libc::open(c"/proc/self/fdinfo/0".as_ptr(), libc::O_WRONLY)
        };
        line("open fdinfo/0 O_WRONLY", if r >= 0 { "a descriptor".into() } else { named(errno()) });
    }

    println!("########## files ##########");
    let path = c"/tmp/fdinfo_probe.file";
    unsafe { libc::unlink(path.as_ptr()) };
    let f = ok(unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_APPEND, 0o644) }, "open file");
    unsafe {
        libc::write(f, b"0123456789".as_ptr().cast(), 10);
        libc::lseek(f, 5, libc::SEEK_SET);
    }
    show("a file, O_RDWR|O_CREAT|O_APPEND, at offset 5", f, &who, &[]);
    let g = ok(unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) }, "open file");
    show("the same file, O_RDONLY|O_CLOEXEC|O_NOFOLLOW", g, &who, &[]);
    unsafe { libc::fcntl(g, libc::F_SETFD, 0) };
    show("  after F_SETFD 0", g, &who, &[]);
    let p = ok(unsafe { libc::open(path.as_ptr(), libc::O_PATH) }, "open O_PATH");
    show("O_PATH", p, &who, &[]);
    let d = ok(unsafe { libc::open(c"/tmp".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) }, "open dir");
    show("a directory", d, &who, &[]);
    let n = ok(unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) }, "open null");
    show("/dev/null, O_WRONLY|O_NONBLOCK", n, &who, &[]);
    let m = ok(unsafe { libc::memfd_create(c"probe".as_ptr(), 0) }, "memfd");
    show("a memfd", m, &who, &[]);

    println!("########## pipes and sockets ##########");
    let mut pp = [0i32; 2];
    unsafe { libc::pipe2(pp.as_mut_ptr(), libc::O_NONBLOCK) };
    show("a pipe's read end, O_NONBLOCK", pp[0], &who, &[]);
    show("a pipe's write end", pp[1], &who, &[]);
    let mut sp = [0i32; 2];
    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sp.as_mut_ptr()) };
    show("a unix stream socketpair", sp[0], &who, &[]);
    let mut dp = [0i32; 2];
    unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, dp.as_mut_ptr()) };
    show("a unix datagram socketpair", dp[0], &who, &[]);
    let u = ok(unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) }, "socket");
    show("a UDP socket", u, &who, &[]);

    println!("########## eventfd ##########");
    let e = ok(unsafe { libc::eventfd(5, 0) }, "eventfd");
    show("eventfd(5, 0)", e, &who, &[]);
    let es = ok(unsafe { libc::eventfd(0, libc::EFD_SEMAPHORE | libc::EFD_NONBLOCK) }, "eventfd");
    unsafe { libc::write(es, (0x1234_5678_9abcu64).to_ne_bytes().as_ptr().cast(), 8) };
    show("eventfd(0, SEMAPHORE|NONBLOCK), then 0x123456789abc added", es, &who, &[]);

    println!("########## epoll ##########");
    let ep = ok(unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) }, "epoll");
    show("an empty epoll", ep, &who, &[]);
    let mut ev = libc::epoll_event { events: (libc::EPOLLIN | libc::EPOLLET) as u32, u64: 0xdead_beef };
    unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, pp[0], &mut ev) };
    let mut ev = libc::epoll_event { events: (libc::EPOLLOUT | libc::EPOLLONESHOT) as u32, u64: 7 };
    unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, e, &mut ev) };
    show("epoll watching the pipe and the eventfd", ep, &who, &[]);

    println!("########## timerfd ##########");
    let t = ok(unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK) }, "timerfd");
    show("timerfd, disarmed", t, &who, &[]);
    let spec = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 2, tv_nsec: 500 },
        it_value: libc::timespec { tv_sec: 100, tv_nsec: 0 },
    };
    unsafe { libc::timerfd_settime(t, 0, &spec, std::ptr::null_mut()) };
    show("timerfd, 100 s then every 2 s", t, &who, &[]);
    let tr = ok(unsafe { libc::timerfd_create(libc::CLOCK_REALTIME, 0) }, "timerfd");
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
    let spec = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: libc::timespec { tv_sec: now.tv_sec - 1, tv_nsec: 0 },
    };
    unsafe { libc::timerfd_settime(tr, libc::TFD_TIMER_ABSTIME, &spec, std::ptr::null_mut()) };
    show("timerfd, REALTIME, ABSTIME in the past, expired", tr, &who, &[]);
    let spec = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: libc::timespec { tv_sec: now.tv_sec + 50, tv_nsec: 0 },
    };
    unsafe {
        libc::timerfd_settime(tr, libc::TFD_TIMER_ABSTIME | 2, &spec, std::ptr::null_mut())
    };
    show("  re-armed ABSTIME|CANCEL_ON_SET 50 s ahead", tr, &who, &[]);

    println!("########## signalfd ##########");
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, 40);
    }
    let s = ok(unsafe { libc::signalfd(-1, &set, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) }, "signalfd");
    show("signalfd(USR1|TERM|40)", s, &who, &[]);

    println!("########## inotify ##########");
    let i = ok(unsafe { libc::inotify_init1(libc::IN_NONBLOCK) }, "inotify");
    show("inotify, no watches", i, &who, &[]);
    unsafe {
        libc::inotify_add_watch(i, c"/tmp".as_ptr(), libc::IN_CREATE | libc::IN_DELETE);
        libc::inotify_add_watch(i, path.as_ptr(), libc::IN_MODIFY | libc::IN_ONESHOT);
    }
    // Listed newest first on Linux: the marks are on a list each new one
    // goes to the head of. The targets are given in the order printed.
    show(
        "inotify watching the file and /tmp",
        i,
        &who,
        &[path, c"/tmp"],
    );

    println!("########## pidfd ##########");
    let pf = unsafe { libc::syscall(libc::SYS_pidfd_open, who.me, 0) } as i32;
    let pf = ok(pf, "pidfd_open");
    show("pidfd of self", pf, &who, &[]);
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe { libc::_exit(0) };
    }
    let cw = Who { me: who.me, child };
    let cf = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) } as i32;
    let cf = ok(cf, "pidfd_open child");
    // A zombie still has its task.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    unsafe { libc::waitid(libc::P_PID, child as u32, &mut info, libc::WEXITED | libc::WNOWAIT) };
    show("pidfd of an exited, unreaped child", cf, &cw, &[]);
    let mut status = 0;
    unsafe { libc::waitpid(child, &mut status, 0) };
    show("pidfd of a reaped child", cf, &cw, &[]);

    unsafe { libc::unlink(path.as_ptr()) };
    locks(&who);
    access(who.me);
}
