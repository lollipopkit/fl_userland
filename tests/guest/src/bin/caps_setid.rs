//! Capability rules that need the mount to record who owns a file: a
//! set-user-ID-root program, a set-user-ID script, and `chmod g+s` of a file
//! whose group the caller is not in. Asserted against a real arm64 kernel
//! (`caps_probe`) and run on fakefs, since realfs reports the host's owner.

use guest_tests::caps::*;
use guest_tests::{Harness, check};

const DIR: &str = "/tmp/capssetid";

fn main() {
    if std::env::args().nth(1).as_deref() == Some("report") {
        report();
        return;
    }
    unsafe { libc::setgroups(0, std::ptr::null()) };
    let _ = std::fs::remove_dir_all(DIR);
    std::fs::create_dir_all(DIR).unwrap();
    unsafe { libc::chmod(c(DIR).as_ptr(), 0o755) };
    let mut h = Harness::new();
    let full = FULL as i64;
    let x = X as i64;
    let rep = format!("{DIR}/rep");
    copy_self(&rep);

    h.group("set-user-ID root");
    let suid = format!("{DIR}/suid");
    copy_self(&suid);
    unsafe {
        libc::chown(c(&suid).as_ptr(), 0, 0);
        libc::chmod(c(&suid).as_ptr(), 0o4755);
    }
    check!(h, owner_of(&suid) == 0, "this mount records root as the owner");
    {
        let got = exec_as(&suid, || {
            setresuid(1000);
        });
        check!(h, got == [full, full, 0, 0, 1, 0], "uid 1000 runs it with every capability: {got:?}");
        let got = exec_as(&suid, || {
            prctl(libc::PR_SET_SECUREBITS, 1, 0);
            setresuid(1000);
        });
        check!(h, got[..2] == [0, 0] && got[5] == 0, "NOROOT: euid 0 and nothing: {got:?}");
        let got = exec_as(&suid, || {
            prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0);
            setresuid(1000);
        });
        check!(h, got[5] == 1000, "no_new_privs: {got:?}");
        setcap(&suid, &vfs_cap(true, X as u32, None));
        let got = exec_as(&suid, || {
            setresuid(1000);
        });
        check!(h, got[..2] == [x, x] && got[5] == 0, "with file capabilities, only those: {got:?}");
        // A set-id script is not one: the credentials are its interpreter's.
        let script = format!("{DIR}/script");
        std::fs::write(&script, format!("#!{rep} report\n")).unwrap();
        unsafe {
            libc::chown(c(&script).as_ptr(), 0, 0);
            libc::chmod(c(&script).as_ptr(), 0o4755);
        }
        let got = exec_as(&script, || {
            setresuid(1000);
        });
        check!(h, got == [0, 0, 0, 0, 0, 1000], "a set-user-ID-root script: {got:?}");
    }

    h.group("set-group-ID");
    let sgid = format!("{DIR}/sgid0");
    copy_self(&sgid);
    unsafe {
        libc::chown(c(&sgid).as_ptr(), 0, 0);
        libc::chmod(c(&sgid).as_ptr(), 0o2755);
    }
    let ambient_after = |groups: &[u32]| {
        let groups = groups.to_vec();
        exec_as(&sgid, move || unsafe {
            set_inheritable(1);
            libc::setgroups(groups.len(), groups.as_ptr());
            libc::syscall(libc::SYS_setresgid, 1000, 1000, 1000);
            prctl(libc::PR_SET_KEEPCAPS, 1, 0);
            setresuid(1000);
            prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE as u64, 0);
        })[3]
    };
    // `in_group_p` of the caller: a group it already holds changes no
    // identity, so the ambient set survives; any other clears it.
    check!(h, ambient_after(&[0]) == 1, "a group already held keeps the ambient set");
    check!(h, ambient_after(&[]) == 0, "another group clears it");

    h.group("chmod");
    let mine = format!("{DIR}/mine");
    std::fs::write(&mine, b"x").unwrap();
    unsafe { libc::chown(c(&mine).as_ptr(), 1000, 0) };
    check!(h, owner_of(&mine) == 1000, "this mount records the owner");
    {
        let rows = child(|| unsafe {
            libc::syscall(libc::SYS_setresgid, 1000, 1000, 1000);
            setresuid(1000);
            [r(libc::chmod(c(&mine).as_ptr(), 0o2755) as i64), mode_of(&mine) as i64]
        });
        check!(h, rows == [0, 0o755], "chmod g+s of a group not ours stores no S_ISGID: {rows:?}");
    }

    let _ = std::fs::remove_dir_all(DIR);
    std::process::exit(h.finish());
}
