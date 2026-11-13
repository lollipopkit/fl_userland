//! The device and inode columns of `/proc/<pid>/maps` and `smaps`.
//!
//! **A report, not a check**: one line per case, run here and in a privileged
//! arm64 container (the probe mounts a tmpfs of its own) and diffed by
//! `tests/integration/probe_diff.sh`.
//!
//! Inode and device numbers name the machine, so each mapping prints whether
//! its two columns agree with what `fstat` says about the file it maps, and
//! the name column verbatim.

use std::io::Write;

fn line(what: &str, value: impl std::fmt::Display) {
    println!("{what:<52} -> {value}");
    let _ = std::io::stdout().flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn fstat(fd: i32) -> Option<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st)
}

/// The line of `file` that starts at `addr`, split into its six columns.
fn row(file: &str, addr: usize) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(file).ok()?;
    let want = format!("{addr:08x}-");
    let l = text.lines().find(|l| l.starts_with(&want))?;
    let mut cols: Vec<String> = l.splitn(6, ' ').map(str::to_string).collect();
    if let Some(name) = cols.get_mut(5) {
        *name = name.trim_start().to_string();
    }
    Some(cols)
}

/// Whether the device and inode columns name `st`'s file.
fn judge(cols: &[String], st: Option<&libc::stat>) -> String {
    let (Some(dev), Some(ino)) = (cols.get(3), cols.get(4)) else {
        return "no such line".into();
    };
    let Some(st) = st else {
        return if dev == "00:00" && ino == "0" { "00:00 0".into() } else { "a device and an inode".into() };
    };
    let want_dev = format!("{:02x}:{:02x}", libc::major(st.st_dev), libc::minor(st.st_dev));
    let dev_ok = *dev == want_dev;
    let ino_ok = ino.parse::<u64>().ok() == Some(st.st_ino);
    match (dev_ok, ino_ok) {
        (true, true) => "agree with fstat".into(),
        (false, true) => format!("the inode agrees, the device does not ({dev} vs {want_dev})"),
        (true, false) => "the device agrees, the inode does not".into(),
        (false, false) => format!("neither agrees ({dev} {ino})"),
    }
}

/// One line per mapping: the two columns judged, the name column, and
/// whether `smaps`' header line for it is the same line.
fn report(title: &str, addr: *mut libc::c_void, st: Option<&libc::stat>) {
    if addr == libc::MAP_FAILED {
        line(title, format!("mmap: errno {}", errno()));
        return;
    }
    let addr = addr as usize;
    let Some(cols) = row("/proc/self/maps", addr) else {
        line(title, "no maps line");
        return;
    };
    let same = row("/proc/self/smaps", addr).as_ref() == Some(&cols);
    let name = cols.get(5).map_or("", String::as_str);
    line(title, format!("{}; name '{name}'; smaps {}", judge(&cols, st), if same { "agrees" } else { "differs" }));
}

fn map(fd: i32, len: usize, flags: i32) -> *mut libc::c_void {
    unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, flags, fd, 0) }
}

fn file(path: &std::ffi::CStr) -> i32 {
    unsafe { libc::unlink(path.as_ptr()) };
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o644) };
    if fd >= 0 {
        unsafe { libc::ftruncate(fd, 8192) };
    }
    fd
}

fn main() {
    println!("########## file mappings ##########");
    let cases: [(&str, &std::ffi::CStr); 2] = [
        ("a file in /tmp", c"/tmp/mapsdev_probe.file"),
        ("a file in /dev/shm", c"/dev/shm/mapsdev_probe.file"),
    ];
    for (title, path) in cases {
        let fd = file(path);
        if fd < 0 {
            line(title, format!("open: errno {}", errno()));
            continue;
        }
        report(&format!("{title}, MAP_PRIVATE"), map(fd, 8192, libc::MAP_PRIVATE), fstat(fd).as_ref());
        report(&format!("{title}, MAP_SHARED"), map(fd, 4096, libc::MAP_SHARED), fstat(fd).as_ref());
        unsafe {
            libc::close(fd);
            libc::unlink(path.as_ptr());
        }
    }

    let dir = c"/tmp/mapsdev_probe.tmpfs";
    unsafe { libc::mkdir(dir.as_ptr(), 0o755) };
    let mounted = unsafe {
        libc::mount(c"none".as_ptr(), dir.as_ptr(), c"tmpfs".as_ptr(), 0, std::ptr::null())
    };
    line("mount a tmpfs", if mounted == 0 { "ok".into() } else { format!("errno {}", errno()) });
    if mounted == 0 {
        let path = c"/tmp/mapsdev_probe.tmpfs/f";
        let fd = file(path);
        report("a file on that tmpfs, MAP_SHARED", map(fd, 4096, libc::MAP_SHARED), fstat(fd).as_ref());
        unsafe {
            libc::close(fd);
            libc::unlink(path.as_ptr());
            libc::umount(dir.as_ptr());
        }
    }
    unsafe { libc::rmdir(dir.as_ptr()) };

    let m = unsafe { libc::memfd_create(c"mapsdev".as_ptr(), 0) };
    unsafe { libc::ftruncate(m, 4096) };
    report("a memfd, MAP_SHARED", map(m, 4096, libc::MAP_SHARED), fstat(m).as_ref());
    report("a memfd, MAP_PRIVATE", map(m, 4096, libc::MAP_PRIVATE), fstat(m).as_ref());

    // The program's own text: the first line of maps is the executable on
    // both kernels.
    let exe = unsafe { libc::open(c"/proc/self/exe".as_ptr(), libc::O_RDONLY) };
    let first = std::fs::read_to_string("/proc/self/maps")
        .ok()
        .and_then(|t| t.lines().next().map(str::to_string))
        .unwrap_or_default();
    let start = first.split('-').next().and_then(|a| usize::from_str_radix(a, 16).ok()).unwrap_or(0);
    let cols = row("/proc/self/maps", start).unwrap_or_default();
    line("the executable's first mapping", judge(&cols, fstat(exe).as_ref()));

    println!("########## anonymous mappings ##########");
    let anon = unsafe {
        libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    };
    report("MAP_PRIVATE|MAP_ANONYMOUS", anon, None);
    let text = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    for name in ["[heap]", "[stack]"] {
        let l = text.lines().find(|l| l.ends_with(name));
        let cols: Vec<String> = l.map(|l| l.splitn(6, ' ').map(str::to_string).collect()).unwrap_or_default();
        line(name, judge(&cols, None));
    }
}
