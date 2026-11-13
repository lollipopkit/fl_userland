//! The mode a file is created with is the guest's business.
//!
//! This kernel applies the *guest's* umask in `kernel/fs.c` and then hands the
//! mode to the host, which applies the **host process's** umask on top. A guest
//! that sets `umask(0)` and asks for 0666 gets whatever the host's umask leaves
//! of it — 0644 under the usual 022.
//!
//! fakefs stores the mode in `meta.db` and reports that, so it hides the
//! difference. realfs reports the host's mode, which is where it shows.

use guest_tests::{Harness, check, cpath};

fn created_mode(h: &mut Harness, dir: &str, name: &str, ask: u32) -> u32 {
    let path = format!("{dir}/{name}");
    let _ = std::fs::remove_file(&path);
    let fd = unsafe {
        libc::open(cpath(&path).as_ptr(), libc::O_CREAT | libc::O_WRONLY | libc::O_EXCL, ask)
    };
    if fd < 0 {
        check!(h, false, "creating {path}: errno {}",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        return 0;
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(fd, &mut st); libc::close(fd) };
    st.st_mode & 0o7777
}

fn main() {
    let mut h = Harness::new();
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp".into());
    let _ = std::fs::create_dir_all(&dir);

    h.group("umask-zero-means-what-was-asked");
    let old = unsafe { libc::umask(0) };
    let m = created_mode(&mut h, &dir, "u0_666", 0o666);
    check!(h, m == 0o666, "umask 0, mode 0666 -> {m:04o}");
    let m = created_mode(&mut h, &dir, "u0_600", 0o600);
    check!(h, m == 0o600, "umask 0, mode 0600 -> {m:04o}");
    let m = created_mode(&mut h, &dir, "u0_777", 0o777);
    // O_CREAT never sets the execute bits on Linux either -- it does, actually;
    // the mode is used as given. 0777 stays 0777.
    check!(h, m == 0o777, "umask 0, mode 0777 -> {m:04o}");

    h.group("umask-is-still-applied");
    // The control: the guest's own umask must still take effect, or the fix
    // would be "ignore umask entirely".
    unsafe { libc::umask(0o022) };
    let m = created_mode(&mut h, &dir, "u022_666", 0o666);
    check!(h, m == 0o644, "umask 022, mode 0666 -> {m:04o}");
    unsafe { libc::umask(0o077) };
    let m = created_mode(&mut h, &dir, "u077_666", 0o666);
    check!(h, m == 0o600, "umask 077, mode 0666 -> {m:04o}");

    h.group("directories-too");
    unsafe { libc::umask(0) };
    let d2 = format!("{dir}/u0_dir");
    let _ = std::fs::remove_dir(&d2);
    let r = unsafe { libc::mkdir(cpath(&d2).as_ptr(), 0o777) };
    check!(h, r == 0, "mkdir 0777 with umask 0");
    if r == 0 {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        unsafe { libc::stat(cpath(&d2).as_ptr(), &mut st) };
        check!(h, st.st_mode & 0o7777 == 0o777,
            "and it is 0777: {:04o}", st.st_mode & 0o7777);
        let _ = std::fs::remove_dir(&d2);
    }

    unsafe { libc::umask(old) };
    std::process::exit(h.finish());
}
