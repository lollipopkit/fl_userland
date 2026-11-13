//! What `/proc/<pid>/{io,personality,timerslack_ns,syscall}`, `ns/` and
//! `map_files/` say, with the values that legitimately differ between two
//! kernels (addresses, namespace numbers) reduced to the relation the probe
//! is after.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container (`--privileged`) and diffed by `tests/integration/probe_diff.sh`.
//! Who may read each entry is `procaccess_probe`'s.

use std::ffi::CString;
use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<56} -> {value}");
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
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn cpath(p: &str) -> CString {
    CString::new(p).unwrap()
}

/// One `read(2)` of up to 4 KiB, so that a counter moves by exactly one.
fn read_once(path: &str) -> Result<String, i32> {
    let c = cpath(path);
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(errno());
    }
    let mut buf = [0u8; 4096];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    let e = errno();
    unsafe { libc::close(fd) };
    if n < 0 {
        return Err(e);
    }
    Ok(String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

fn shown(r: Result<String, i32>) -> String {
    match r {
        Ok(s) => format!("{:?}", s),
        Err(e) => named(e),
    }
}

fn write_file(path: &str, bytes: &[u8]) -> String {
    let c = cpath(path);
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY) };
    if fd < 0 {
        return format!("open {}", named(errno()));
    }
    let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    let r = if n < 0 { format!("write {}", named(errno())) } else { format!("wrote {n}") };
    unsafe { libc::close(fd) };
    r
}

fn fields(text: &str) -> Vec<(String, u64)> {
    text.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(": ")?;
            Some((k.to_string(), v.trim().parse().ok()?))
        })
        .collect()
}

fn io_of(path: &str) -> (Vec<(String, u64)>, usize) {
    let t = read_once(path).unwrap_or_default();
    (fields(&t), t.len())
}

fn get(f: &[(String, u64)], k: &str) -> u64 {
    f.iter().find(|(n, _)| n == k).map_or(u64::MAX, |(_, v)| *v)
}

fn delta(a: &[(String, u64)], b: &[(String, u64)]) -> [u64; 4] {
    ["syscr", "syscw", "rchar", "wchar"].map(|k| get(b, k).wrapping_sub(get(a, k)))
}

fn io() {
    println!("########## io ##########");
    let (f, _) = io_of("/proc/self/io");
    line("the keys", f.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(" "));
    let file = "/tmp/procstate_probe.data";
    std::fs::write(file, [7u8; 100]).unwrap();
    let c = cpath(file);
    let null = cpath("/dev/null");
    let (src, sink) = unsafe { (libc::open(c.as_ptr(), libc::O_RDONLY), libc::open(null.as_ptr(), libc::O_WRONLY)) };
    let mut buf = [0u8; 64];

    let (a, alen) = io_of("/proc/self/io");
    unsafe {
        for _ in 0..3 {
            libc::read(src, buf.as_mut_ptr().cast(), 10);
        }
        libc::write(sink, buf.as_ptr().cast(), 5);
        libc::write(sink, buf.as_ptr().cast(), 5);
        let iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: 7 };
        libc::readv(src, &iov, 1);
        libc::pread(src, buf.as_mut_ptr().cast(), 4, 0);
    }
    let (b, _) = io_of("/proc/self/io");
    let [r, w, rc, wc] = delta(&a, &b);
    line("3 reads, readv, pread, 2 writes: syscr syscw", format!("{r} {w}"));
    line("  rchar less the first read of io, wchar", format!("{} {wc}", rc - alen as u64));

    let (a, _) = io_of("/proc/self/io");
    unsafe {
        libc::read(999, buf.as_mut_ptr().cast(), 1);
        libc::write(999, buf.as_ptr().cast(), 1);
    }
    let (b, _) = io_of("/proc/self/io");
    line("read and write on a bad descriptor: syscr syscw", format!("{} {}", delta(&a, &b)[0] - 1, delta(&a, &b)[1]));
    let (a, _) = io_of("/proc/self/io");
    unsafe {
        let iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: 1 };
        libc::readv(999, &iov, 1);
        libc::writev(999, &iov, 1);
    }
    let (b, _) = io_of("/proc/self/io");
    line("readv and writev on a bad descriptor: syscr syscw", format!("{} {}", delta(&a, &b)[0] - 1, delta(&a, &b)[1]));

    let (a, alen) = io_of("/proc/self/io");
    let mut off: libc::off_t = 0;
    let sent = unsafe { libc::sendfile(sink, src, &mut off, 20) };
    let (b, _) = io_of("/proc/self/io");
    let [r, w, rc, wc] = delta(&a, &b);
    line("sendfile of 20", format!("sent {sent}: syscr {} syscw {w} rchar {} wchar {wc}", r - 1, rc - alen as u64));

    // A thread's own, and the process's once it has gone.
    let (p1, p1len) = io_of("/proc/self/io");
    let (tx, rx) = std::sync::mpsc::channel();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let (end_tx, end_rx) = std::sync::mpsc::channel::<()>();
    let t = std::thread::spawn(move || {
        tx.send(unsafe { libc::syscall(libc::SYS_gettid) } as i32).unwrap();
        go_rx.recv().unwrap();
        let mut b = [0u8; 4];
        for _ in 0..4 {
            unsafe { libc::read(src, b.as_mut_ptr().cast(), 1) };
        }
        done_tx.send(()).unwrap();
        end_rx.recv().unwrap();
    });
    let tid = rx.recv().unwrap();
    let tpath = format!("/proc/self/task/{tid}/io");
    let (t1, _) = io_of(&tpath);
    go_tx.send(()).unwrap();
    done_rx.recv().unwrap();
    let (t2, _) = io_of(&tpath);
    end_tx.send(()).unwrap();
    t.join().unwrap();
    let (p2, _) = io_of("/proc/self/io");
    let [r, _, rc, _] = delta(&t1, &t2);
    line("a thread's own after 4 reads of 1: syscr rchar", format!("{r} {rc}"));
    let [r, _, rc, _] = delta(&p1, &p2);
    line("the process's, the thread gone: syscr", r);
    line("  rchar less what main read", rc - p1len as u64 >= 4);
    let child = unsafe { libc::fork() };
    if child == 0 {
        let (f, _) = io_of("/proc/self/io");
        line("a forked child starts at: syscr syscw", format!("{} {}", get(&f, "syscr"), get(&f, "syscw")));
        unsafe { libc::_exit(0) };
    }
    unsafe {
        libc::waitpid(child, std::ptr::null_mut(), 0);
        libc::close(src);
        libc::close(sink);
    }
    let _ = std::fs::remove_file(file);
}

fn personality() {
    println!("########## personality ##########");
    let now = unsafe { libc::personality(0xffff_ffff) };
    line("reads what personality(0xffffffff) answers", shown(read_once("/proc/self/personality")) == format!("{:?}", format!("{now:08x}\n")));
    unsafe { libc::personality(0x0020_0000) };
    line("after personality(ADDR_COMPAT_LAYOUT)", shown(read_once("/proc/self/personality")));
    unsafe { libc::personality(now as libc::c_ulong) };
    line("write", write_file("/proc/self/personality", b"0"));
}

fn slack_prctl() -> i32 {
    unsafe { libc::prctl(libc::PR_GET_TIMERSLACK) }
}

fn timerslack() {
    println!("########## timerslack_ns ##########");
    let p = "/proc/self/timerslack_ns";
    line("its own", shown(read_once(p)));
    line("PR_GET_TIMERSLACK", slack_prctl());
    line("write 100000", format!("{}, prctl {}", write_file(p, b"100000"), slack_prctl()));
    line("write 0", format!("{}, prctl {}", write_file(p, b"0"), slack_prctl()));
    line("write \"abc\"", format!("{}, prctl {}", write_file(p, b"abc"), slack_prctl()));
    line("write \"-1\"", format!("{}, prctl {}", write_file(p, b"-1"), slack_prctl()));
    unsafe { libc::prctl(libc::PR_SET_TIMERSLACK, 70000) };
    line("after PR_SET_TIMERSLACK 70000", shown(read_once(p)));
    let mut pipe = [0i32; 2];
    unsafe { libc::pipe(pipe.as_mut_ptr()) };
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::prctl(libc::PR_SET_TIMERSLACK, 0);
            let v = slack_prctl();
            libc::write(pipe[1], (&raw const v).cast(), 4);
            loop {
                libc::pause();
            }
        }
    }
    let mut v = 0i32;
    unsafe { libc::read(pipe[0], (&raw mut v).cast(), 4) };
    line("a child's default is its parent's slack at fork", v);
    let cp = format!("/proc/{child}/timerslack_ns");
    line("root reads the child's", shown(read_once(&cp)));
    line("root writes the child's 30000", format!("{}, reads {}", write_file(&cp, b"30000"), shown(read_once(&cp))));
    unsafe {
        libc::kill(child, libc::SIGKILL);
        libc::waitpid(child, std::ptr::null_mut(), 0);
        libc::prctl(libc::PR_SET_TIMERSLACK, 0);
    }
}

/// The first field, and how many there are.
fn syscall_shape(text: &str) -> String {
    let f: Vec<&str> = text.split_whitespace().collect();
    match f.first() {
        Some(&"running") => "running".into(),
        Some(nr) => format!("{nr}, {} fields", f.len()),
        None => "empty".into(),
    }
}

fn spawn(f: fn()) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        unsafe { libc::_exit(0) };
    }
    pid
}

fn wait_state(pid: i32, want: char) {
    for _ in 0..2000 {
        let s = read_once(&format!("/proc/{pid}/stat")).unwrap_or_default();
        if s.rsplit_once(") ").and_then(|(_, r)| r.chars().next()) == Some(want) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn syscall() {
    println!("########## syscall ##########");
    let own = read_once("/proc/self/syscall").unwrap_or_default();
    line("its own", syscall_shape(&own));
    let f: Vec<&str> = own.split_whitespace().collect();
    line("  the descriptor and the count are the read's", f.get(1).zip(f.get(3)).map(|(fd, n)| (fd.starts_with("0x"), *n == "0x1000")).map_or("-".into(), |v| format!("{v:?}")));

    let paused = spawn(|| unsafe {
        libc::pause();
    });
    wait_state(paused, 'S');
    let t = read_once(&format!("/proc/{paused}/syscall")).unwrap_or_default();
    line("a child in pause()", syscall_shape(&t));
    let a: Vec<&str> = t.split_whitespace().collect();
    line("  its first four arguments", a.get(1..5).map_or("-".into(), |s| s.join(" ")));
    unsafe { libc::kill(paused, libc::SIGSTOP) };
    wait_state(paused, 'T');
    line("  stopped", syscall_shape(&read_once(&format!("/proc/{paused}/syscall")).unwrap_or_default()));
    unsafe { libc::kill(paused, libc::SIGKILL) };
    wait_state(paused, 'Z');
    line("  a zombie", shown(read_once(&format!("/proc/{paused}/syscall"))));
    unsafe { libc::waitpid(paused, std::ptr::null_mut(), 0) };

    // The child says when it is in the loop: 'R' alone is also true while it
    // is still in the syscalls after `fork` (`set_tid_address`), which a slow
    // host reads as that syscall.
    let mut ready = [0i32; 2];
    unsafe { libc::pipe(ready.as_mut_ptr()) };
    let busy = unsafe { libc::fork() };
    if busy == 0 {
        unsafe { libc::write(ready[1], b"x".as_ptr().cast(), 1) };
        loop {
            std::hint::spin_loop();
        }
    }
    let mut b = [0u8; 1];
    unsafe {
        libc::read(ready[0], b.as_mut_ptr().cast(), 1);
        libc::close(ready[0]);
        libc::close(ready[1]);
    }
    wait_state(busy, 'R');
    line("a child in a loop", syscall_shape(&read_once(&format!("/proc/{busy}/syscall")).unwrap_or_default()));
    unsafe {
        libc::kill(busy, libc::SIGKILL);
        libc::waitpid(busy, std::ptr::null_mut(), 0);
    }
}

fn link(path: &str) -> Option<String> {
    std::fs::read_link(path).ok().map(|p| p.to_string_lossy().into_owned())
}

fn ns() {
    println!("########## ns ##########");
    let names: Vec<String> = std::fs::read_dir("/proc/self/ns")
        .map(|d| d.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    line("listed", names.join(" "));
    let parent = unsafe { libc::getppid() };
    let child = spawn(|| unsafe {
        libc::pause();
    });
    for n in &names {
        let mine = link(&format!("/proc/self/ns/{n}")).unwrap_or_default();
        let (kind, num) = mine.split_once(":[").unwrap_or(("?", ""));
        let num = num.strip_suffix(']').unwrap_or("");
        let theirs = link(&format!("/proc/{child}/ns/{n}"));
        let st = std::fs::metadata(format!("/proc/self/ns/{n}"));
        let stat = match st {
            Ok(m) => {
                use std::os::unix::fs::MetadataExt;
                format!("ino {}, mode {:o}", if m.ino().to_string() == num { "is the number" } else { "differs" }, m.mode())
            }
            Err(e) => named(e.raw_os_error().unwrap_or(0)),
        };
        line(
            &format!("{n}"),
            format!(
                "{kind}:[{}], a child's {}, stat {stat}",
                if !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) { "N" } else { num },
                if theirs.as_deref() == Some(mine.as_str()) { "same" } else { "differs" },
            ),
        );
    }
    let _ = parent;
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    line("the thread's uts is the process's", link(&format!("/proc/self/task/{tid}/ns/uts")) == link("/proc/self/ns/uts"));
    let c = cpath("/proc/self/ns/uts");
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
    line("open", if fd < 0 { named(errno()) } else { "ok".into() });
    if fd >= 0 {
        let fdl = link(&format!("/proc/self/fd/{fd}")).unwrap_or_default();
        line("  its fd link is the ns link", Some(fdl) == link("/proc/self/ns/uts"));
        unsafe { libc::close(fd) };
    }
    unsafe {
        libc::kill(child, libc::SIGKILL);
        libc::waitpid(child, std::ptr::null_mut(), 0);
    }
}

fn map_files_report(who: &str, files: &[&str]) {
    use std::os::unix::fs::MetadataExt;
    let maps = read_once("/proc/self/maps").unwrap_or_default();
    // `read_once` is 4 KiB; the maps of this probe fit.
    let with_path: Vec<(String, String)> = maps
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 6 && f[5].starts_with('/')).then(|| (f[0].to_string(), f[5].to_string()))
        })
        .collect();
    let listed: Vec<String> = match std::fs::read_dir("/proc/self/map_files") {
        Ok(d) => d.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect(),
        Err(e) => {
            line(&format!("{who}: map_files/"), named(e.raw_os_error().unwrap_or(0)));
            return;
        }
    };
    let trimmed = |r: &str| {
        let (a, b) = r.split_once('-').unwrap();
        format!("{:x}-{:x}", u64::from_str_radix(a, 16).unwrap(), u64::from_str_radix(b, 16).unwrap())
    };
    let mut want: Vec<String> = with_path.iter().map(|(r, _)| trimmed(r)).collect();
    let mut got = listed.clone();
    want.sort();
    got.sort();
    line(&format!("{who}: lists the file-backed maps lines"), want == got);
    for (r, p) in with_path.iter().filter(|(_, p)| files.contains(&p.as_str())) {
        let name = format!("/proc/self/map_files/{}", trimmed(r));
        let lmode = std::fs::symlink_metadata(&name).map_or_else(|e| named(e.raw_os_error().unwrap_or(0)), |m| format!("{:o}", m.mode()));
        let rl = link(&name).map_or("error".into(), |l| if &l == p { "the path".into() } else { l });
        let st = std::fs::metadata(&name).map_or_else(
            |e| named(e.raw_os_error().unwrap_or(0)),
            |m| if std::fs::metadata(p).is_ok_and(|f| f.ino() == m.ino()) { "the file".into() } else { "another".into() },
        );
        line(&format!("{who}: {}", p.rsplit('/').next().unwrap_or("")), format!("lstat {lmode}, readlink {rl}, stat {st}"));
    }
}

fn map_files() {
    println!("########## map_files ##########");
    let ro = "/tmp/procstate_ro";
    let rw = "/tmp/procstate_rw";
    std::fs::write(ro, [1u8; 8192]).unwrap();
    std::fs::write(rw, [2u8; 4096]).unwrap();
    unsafe {
        let a = libc::open(cpath(ro).as_ptr(), libc::O_RDONLY);
        libc::mmap(std::ptr::null_mut(), 8192, libc::PROT_READ, libc::MAP_PRIVATE, a, 0);
        let b = libc::open(cpath(rw).as_ptr(), libc::O_RDWR);
        libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, b, 0);
        libc::close(a);
        libc::close(b);
    }
    map_files_report("root", &[ro, rw]);
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::syscall(libc::SYS_setresgid, 1000, 1000, 1000);
            libc::syscall(libc::SYS_setresuid, 1000, 1000, 1000);
        }
        map_files_report("1000, not dumpable", &[ro, rw]);
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
        map_files_report("1000, dumpable", &[ro, rw]);
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) };
    let _ = std::fs::remove_file(ro);
    let _ = std::fs::remove_file(rw);
}

fn main() {
    io();
    personality();
    timerslack();
    syscall();
    ns();
    map_files();
}
