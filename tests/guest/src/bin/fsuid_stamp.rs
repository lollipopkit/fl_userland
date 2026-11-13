//! Which id a newly created object is stamped with.
//!
//! Linux uses the **fsuid**, which tracks the effective uid: `get_pipe_inode`
//! does `inode->i_uid = current_fsuid()`, and so does every other creation
//! path. `fs/pipe.c` used `current->uid`, the *real* one — the only creation
//! path in the tree that did; fakefs, tmpfs and devpts all use the effective
//! ids.
//!
//! Only observable once the two can differ, which needed the credential work.

use guest_tests::{Harness, check, cpath};

fn owner_of(fd: i32) -> (u32, u32) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return (u32::MAX, u32::MAX);
    }
    (st.st_uid, st.st_gid)
}

fn main() {
    let mut h = Harness::new();
    h.group("fsuid-stamp");

    // Real 0, effective 1000: the two ids differ, which is the whole point.
    // setresuid keeps the real id, so this stays privileged enough to undo.
    let r = unsafe { libc::setresgid(u32::MAX, 1000, u32::MAX) };
    let r2 = unsafe { libc::setresuid(u32::MAX, 1000, u32::MAX) };
    check!(h, r == 0 && r2 == 0, "dropping the effective ids to 1000");

    let mut fds = [0i32; 2];
    check!(h, unsafe { libc::pipe(fds.as_mut_ptr()) } == 0, "pipe()");
    let (uid, gid) = owner_of(fds[0]);
    check!(h, uid == 1000, "a pipe is owned by the effective uid, got {uid}");
    check!(h, gid == 1000, "and the effective gid, got {gid}");

    // A socketpair for comparison: another anonymous object made the same way.
    let mut sv = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } == 0 {
        let (suid, _) = owner_of(sv[0]);
        check!(h, suid == 1000 || suid == 0, "a socketpair reports an owner: {suid}");
        unsafe { libc::close(sv[0]); libc::close(sv[1]) };
    }

    // Back to root, and the same pipe must now be stamped 0 -- so the check
    // above is reading the effective id at creation and not a constant.
    unsafe {
        libc::setresuid(u32::MAX, 0, u32::MAX);
        libc::setresgid(u32::MAX, 0, u32::MAX);
    }
    let mut fds2 = [0i32; 2];
    if unsafe { libc::pipe(fds2.as_mut_ptr()) } == 0 {
        let (uid, _) = owner_of(fds2[0]);
        check!(h, uid == 0, "a pipe made as root is owned by root, got {uid}");
        unsafe { libc::close(fds2[0]); libc::close(fds2[1]) };
    }

    unsafe { libc::close(fds[0]); libc::close(fds[1]) };

    // A directory on the mount under test, if one was named. Anonymous objects
    // are stamped by the kernel wherever they are made; a *file* is stamped by
    // the filesystem, and the three mounts here did not agree.
    //
    // fakefs stamped the **effective** ids, at all four of its creation sites
    // -- open(O_CREAT), mkdir, symlink and mknod -- where Linux stamps the
    // filesystem ones: every creation path there is `inode->i_uid =
    // current_fsuid()`. tmpfs has always asked `task_current_fsids`, which is
    // the same pair, so the two mounts answered differently for the same call
    // and nothing said so.
    //
    // realfs is not asked. It has no ownership of its own and reports the
    // host's, so the only answer it can give is the host user's id -- which is
    // neither of the two this is about. That is a property of the mount, not a
    // gap in it.
    if let Some(dir) = std::env::args().nth(1) {
        h.group("what-a-file-is-stamped-with");
        let _ = std::fs::create_dir_all(&dir);
        unsafe { libc::chmod(cpath(&dir).as_ptr(), 0o777) };

        // Move only the filesystem credential: the effective ids stay at 0, so
        // a mount that reads the wrong pair is visible rather than agreeing by
        // accident.
        unsafe {
            libc::syscall(libc::SYS_setfsuid, 4321 as libc::c_long);
            libc::syscall(libc::SYS_setfsgid, 8765 as libc::c_long);
        }
        check!(
            h,
            unsafe { libc::geteuid() } == 0 && unsafe { libc::getegid() } == 0,
            "the effective ids are still root, so the two pairs differ"
        );

        for kind in ["file", "dir", "symlink", "fifo"] {
            let path = format!("{dir}/stamp_{kind}");
            unsafe {
                libc::unlink(cpath(&path).as_ptr());
                libc::rmdir(cpath(&path).as_ptr());
                match kind {
                    "file" => {
                        let f = libc::open(cpath(&path).as_ptr(),
                                           libc::O_CREAT | libc::O_RDWR, 0o644);
                        if f >= 0 {
                            libc::close(f);
                        }
                    }
                    "dir" => {
                        libc::mkdir(cpath(&path).as_ptr(), 0o755);
                    }
                    "symlink" => {
                        libc::symlink(c"target".as_ptr(), cpath(&path).as_ptr());
                    }
                    _ => {
                        libc::mknod(cpath(&path).as_ptr(), libc::S_IFIFO | 0o644, 0);
                    }
                }
            }
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let r = unsafe { libc::lstat(cpath(&path).as_ptr(), &mut st) };
            check!(h, r == 0, "a {kind} was created in {dir}");
            if r != 0 {
                continue;
            }
            check!(
                h,
                st.st_uid == 4321 && st.st_gid == 8765,
                "a {kind} is stamped with the fs ids, not the effective ones: \
                 {}:{} (fs 4321:8765, effective 0:0)",
                st.st_uid,
                st.st_gid
            );
        }

        unsafe {
            libc::syscall(libc::SYS_setfsuid, 0 as libc::c_long);
            libc::syscall(libc::SYS_setfsgid, 0 as libc::c_long);
        }
        // And back to the effective pair, so the check above is reading the
        // fs ids at creation rather than a constant.
        let path = format!("{dir}/stamp_after");
        unsafe {
            libc::unlink(cpath(&path).as_ptr());
            let f = libc::open(cpath(&path).as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o644);
            if f >= 0 {
                libc::close(f);
            }
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::lstat(cpath(&path).as_ptr(), &mut st) } == 0 {
            check!(h, st.st_uid == 0, "and root again once the fsuid is back: {}", st.st_uid);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    std::process::exit(h.finish());
}
