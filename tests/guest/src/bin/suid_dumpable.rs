//! `/proc/sys/fs/suid_dumpable`: what a write is taken as, who may make one,
//! and what each value leaves a process at. The expected values are a real
//! arm64 kernel's (`suiddump_probe`). The file did not exist here until
//! 2026-11-12, and the value was the constant 0.
//!
//! Run as root, and in a container only `--privileged`, where `/proc/sys` is
//! writable. The value found is written back at the end.

use guest_tests::{Harness, check, cpath};

const KNOB: &str = "/proc/sys/fs/suid_dumpable";

fn read_knob() -> String {
    std::fs::read_to_string(KNOB).unwrap_or_default().trim_end().to_string()
}

/// One `write(2)`: the count, or the negated errno.
fn write_knob(text: &str) -> i64 {
    let fd = unsafe { libc::open(cpath(KNOB).as_ptr(), libc::O_WRONLY | libc::O_TRUNC) };
    if fd < 0 {
        return -i64::from(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
    }
    let n = unsafe { libc::write(fd, text.as_ptr().cast(), text.len()) };
    let r = if n < 0 { -i64::from(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)) } else { n as i64 };
    unsafe { libc::close(fd) };
    r
}

/// Runs `f` in a child and answers what it returned.
fn in_child(f: impl FnOnce() -> i32) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let v = f();
        unsafe { libc::_exit(v & 0xff) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 }
}

fn dumpable() -> i32 {
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }
}

fn owner_uid(path: &str) -> i32 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(cpath(path).as_ptr(), &mut st) } != 0 {
        return -1;
    }
    st.st_uid as i32
}

fn main() {
    let me = std::env::args().next().unwrap_or_default();
    if std::env::args().nth(1).as_deref() == Some("report") {
        std::process::exit(dumpable());
    }
    let mut h = Harness::new();
    let was = read_knob();
    check!(h, was == "0", "it starts at Linux's default: {was:?}");

    h.group("what-a-write-is");
    for (text, want_n, want) in [
        ("2 1", 2, "2"),
        ("1\n", 2, "1"),
        ("0x2", 3, "2"),
        (" 1", 2, "1"),
        ("0", 1, "0"),
    ] {
        let n = write_knob(text);
        let now = read_knob();
        check!(h, n == want_n && now == want, "{text:?}: wrote {n} (wanted {want_n}), reads {now:?} (wanted {want:?})");
    }
    for text in ["3", "-1", "abc", "2x", "+1"] {
        let n = write_knob(text);
        check!(h, n == -i64::from(libc::EINVAL), "{text:?} is EINVAL: {n}");
    }
    check!(h, read_knob() == "0", "and none of them changed it");
    let refused = in_child(|| {
        unsafe {
            libc::setgid(65534);
            libc::setuid(65534);
        }
        (write_knob("1") == -i64::from(libc::EACCES)) as i32
    });
    check!(h, refused == 1, "a user that is not root may not write it");
    let r = in_child(|| unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 2) == -1 } as i32);
    check!(h, r == 1, "PR_SET_DUMPABLE(2) is refused whatever the knob says");

    h.group("what-each-value-does");
    let noread = "/tmp/suid_dumpable.noread";
    for v in [0, 1, 2] {
        check!(h, write_knob(&v.to_string()) == 1, "set {v}");
        let got = in_child(|| {
            unsafe { libc::setuid(65534) };
            dumpable()
        });
        check!(h, got == v, "suid_dumpable {v}: setuid(65534) leaves dumpable {got}");
        let owner = in_child(|| {
            unsafe { libc::setuid(65534) };
            (owner_uid("/proc/self/status") == 0) as i32
        });
        check!(h, owner == i32::from(v != 1), "suid_dumpable {v}: status is root's: {}", owner == 1);
        // A peer of the same user reads a process at 1, and not at 0 or 2.
        let peer = in_child(|| {
            unsafe {
                libc::setgid(65534);
                libc::setuid(65534);
            }
            let target = unsafe { libc::getpid() };
            in_child(|| {
                unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
                std::fs::read(format!("/proc/{target}/maps")).is_ok() as i32
            })
        });
        check!(h, peer == i32::from(v == 1), "suid_dumpable {v}: a peer reads its maps: {}", peer == 1);
        let _ = std::fs::remove_file(noread);
        let copied = std::fs::copy(&me, noread).is_ok() && unsafe { libc::chmod(cpath(noread).as_ptr(), 0o711) } == 0;
        check!(h, copied, "a 0711 copy of this program");
        let got = in_child(|| {
            unsafe {
                libc::setgid(65534);
                libc::setuid(65534);
            }
            let p = cpath(noread);
            let a = cpath("report");
            let argv = [p.as_ptr(), a.as_ptr(), std::ptr::null()];
            unsafe { libc::execv(p.as_ptr(), argv.as_ptr()) };
            -1
        });
        check!(h, got == v, "suid_dumpable {v}: an exec of a file it cannot read leaves dumpable {got}");
    }
    let _ = std::fs::remove_file(noread);

    check!(h, write_knob(&was) == was.len() as i64, "put back {was:?}");
    std::process::exit(h.finish());
}
