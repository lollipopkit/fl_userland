//! `fs.suid_dumpable`: what it accepts, who may write it, and what each
//! value leaves a process at after a credential change or an exec.
//!
//! **A report, not a check**: one line per case, run here and in an arm64
//! container (`--privileged`, so `/proc/sys` is writable) as root, and diffed
//! by `tests/integration/probe_diff.sh`. The value it found is written back
//! at the end; on the reference that is the VM's own setting.

use std::ffi::CString;
use std::io::Write;

const KNOB: &str = "/proc/sys/fs/suid_dumpable";

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
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn read_knob() -> String {
    match std::fs::read_to_string(KNOB) {
        Ok(s) => s.trim_end().to_string(),
        Err(e) => named(e.raw_os_error().unwrap_or(0)),
    }
}

/// One `write(2)` of `text`, as `echo > knob` does.
fn write_knob(text: &str) -> String {
    let c = CString::new(KNOB).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_TRUNC) };
    if fd < 0 {
        return format!("open {}", named(errno()));
    }
    let n = unsafe { libc::write(fd, text.as_ptr().cast(), text.len()) };
    let r = if n < 0 { format!("write {}", named(errno())) } else { format!("wrote {n}") };
    unsafe { libc::close(fd) };
    r
}

fn dumpable() -> i32 {
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }
}

fn setresuid(r: u32, e: u32, s: u32) {
    unsafe { libc::syscall(libc::SYS_setresuid, r, e, s) };
}

fn setresgid(r: u32, e: u32, s: u32) {
    unsafe { libc::syscall(libc::SYS_setresgid, r, e, s) };
}

fn owner(path: &str) -> String {
    let c = CString::new(path).unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c.as_ptr(), &mut st) } != 0 {
        return named(errno());
    }
    format!("{}:{}", st.st_uid, st.st_gid)
}

fn read(path: &str) -> String {
    match std::fs::read(path) {
        Ok(_) => "ok".into(),
        Err(e) => named(e.raw_os_error().unwrap_or(0)),
    }
}

fn child(f: impl FnOnce()) {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        f();
        let _ = std::io::stdout().flush();
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
}

fn exec_report(label: &str, prog: &str, setup: impl FnOnce()) {
    child(|| {
        setup();
        let p = CString::new(prog).unwrap();
        let a1 = CString::new("report").unwrap();
        let a2 = CString::new(label).unwrap();
        let argv = [p.as_ptr(), a1.as_ptr(), a2.as_ptr(), std::ptr::null()];
        unsafe { libc::execv(p.as_ptr(), argv.as_ptr()) };
        line(label, format!("execv: {}", named(errno())));
    });
}

fn values() {
    println!("########## what it accepts ##########");
    for text in ["3", "-1", "abc", "", "2 1", "1\n", "0x1", " 2", "0"] {
        let w = write_knob(text);
        line(&format!("write {text:?}"), format!("{w}, reads {}", read_knob()));
    }
    child(|| {
        setresgid(65534, 65534, 65534);
        setresuid(65534, 65534, 65534);
        line("uid 65534 writes 1", write_knob("1"));
        line("uid 65534 reads it", read_knob());
    });
    let c = CString::new(KNOB).unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::stat(c.as_ptr(), &mut st) };
    line("its mode and owner", format!("{:o} {}:{}", st.st_mode, st.st_uid, st.st_gid));
    child(|| {
        let r = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 2) };
        line("PR_SET_DUMPABLE(2)", if r < 0 { named(errno()) } else { "ok".into() });
    });
}

fn per_value(v: &str, me: &str) {
    println!("########## suid_dumpable {v} ##########");
    line("set", write_knob(v));
    child(|| {
        unsafe { libc::setuid(65534) };
        line("setuid(65534): dumpable", dumpable());
        line("  /proc/self/status owned by", owner("/proc/self/status"));
        let me = unsafe { libc::getpid() };
        child(|| {
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) };
            line("  a peer of uid 65534 reads its environ", read(&format!("/proc/{me}/environ")));
            line("  a peer of uid 65534 reads its maps", read(&format!("/proc/{me}/maps")));
        });
    });
    child(|| {
        setresuid(65534, 0, 0);
        line("setresuid(65534, 0, 0): dumpable", dumpable());
    });
    exec_report(&format!("suid_dumpable {v}: real uid 65534, euid 0, then exec"), me, || setresuid(65534, 0, 0));
    let unreadable = "/tmp/suiddump_probe.noread";
    exec_report(&format!("suid_dumpable {v}: uid 65534 execs a binary it cannot read"), unreadable, || {
        let _ = std::fs::remove_file(unreadable);
        let _ = std::fs::copy(me, unreadable);
        let c = CString::new(unreadable).unwrap();
        unsafe {
            libc::chown(c.as_ptr(), 0, 0);
            libc::chmod(c.as_ptr(), 0o711);
        }
        setresgid(65534, 65534, 65534);
        setresuid(65534, 65534, 65534);
    });
    let _ = std::fs::remove_file(unreadable);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("report") {
        line(
            args.get(2).map_or("?", String::as_str),
            format!("dumpable {}, status owned by {}", dumpable(), owner("/proc/self/status")),
        );
        return;
    }
    let me = std::fs::read_link("/proc/self/exe").map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let was = read_knob();
    line("at start", &was);
    values();
    for v in ["0", "1", "2"] {
        per_value(v, &me);
    }
    // The reference is the VM's own setting: put back what was found, and
    // say whether that worked.
    if was.parse::<i32>().is_ok() {
        write_knob(&was);
    }
    line("put back", read_knob());
}
