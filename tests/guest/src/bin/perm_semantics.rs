//! POSIX permission resolution: `access_check` in `kernel/fs.c`.
//!
//! Everything here needs an unprivileged caller, because the check begins with
//! `if (superuser()) return 0;` and the guest starts as root. The setup runs as
//! root, then a child drops to uid/gid 1000 with 4242 as a supplementary group
//! and does the asking.
//!
//! Two defects it was written for, both in one four-line function:
//!
//! - the requested bits were tested with `!(mode & check)`, which is "none of
//!   them" — so a request for read *and* write succeeded when only read was
//!   granted, and `open(O_RDWR)` on a mode 0400 file returned a writable
//!   descriptor;
//! - only the effective gid was compared against the file's group, so a file
//!   group-owned by one of the caller's **supplementary** groups fell through
//!   to the other-bits.
//!
//! Run against tmpfs and fakefs rather than realfs: on a passthrough mount the
//! host applies its own permissions underneath, which masks the emulator's
//! answer instead of testing it.

use guest_tests::{Harness, check, check_fails, cpath, sys};

const SUPP_GID: libc::gid_t = 4242;

fn make(dir: &str, name: &str, uid: libc::uid_t, gid: libc::gid_t, mode: libc::mode_t) -> String {
    let p = format!("{dir}/{name}");
    let _ = std::fs::write(&p, b"contents");
    unsafe {
        libc::chown(cpath(&p).as_ptr(), uid, gid);
        libc::chmod(cpath(&p).as_ptr(), mode);
    }
    p
}

fn open_ro(path: &str) -> i32 {
    unsafe { libc::open(cpath(path).as_ptr(), libc::O_RDONLY) }
}

fn checks(h: &mut Harness, owned_ro: &str, owned_rw: &str, supp: &str, other_ro: &str, noexec: &str) {
    h.group("owner-bits");
    // A file we own, mode 0400.
    check!(h, unsafe { libc::access(cpath(owned_ro).as_ptr(), libc::R_OK) } == 0,
           "access(R_OK) on a 0400 file we own");
    check_fails!(h, unsafe { libc::access(cpath(owned_ro).as_ptr(), libc::W_OK) },
                 libc::EACCES, "access(W_OK) on it");
    // The finding: every requested bit has to be granted, not any of them.
    check_fails!(h, unsafe { libc::access(cpath(owned_ro).as_ptr(), libc::R_OK | libc::W_OK) },
                 libc::EACCES, "access(R_OK|W_OK) on it");
    check_fails!(h, unsafe { libc::open(cpath(owned_ro).as_ptr(), libc::O_RDWR) },
                 libc::EACCES, "open(O_RDWR) on it");
    // ... and reading it still works, so the fix did not just deny everything.
    let fd = open_ro(owned_ro);
    check!(h, fd >= 0, "open(O_RDONLY) on it still works, got {fd}");
    if fd >= 0 { sys::close(fd); }

    // A file we own with both bits: the same request must succeed.
    check!(h, unsafe { libc::access(cpath(owned_rw).as_ptr(), libc::R_OK | libc::W_OK) } == 0,
           "access(R_OK|W_OK) on a 0600 file we own");
    let fd = unsafe { libc::open(cpath(owned_rw).as_ptr(), libc::O_RDWR) };
    check!(h, fd >= 0, "open(O_RDWR) on it, got {fd}");
    if fd >= 0 { sys::close(fd); }

    h.group("group-bits");
    // Group-owned by a supplementary group, mode 0040. The other-bits are
    // clear, so this can only be reached through the group.
    check!(h, unsafe { libc::access(cpath(supp).as_ptr(), libc::R_OK) } == 0,
           "access(R_OK) via a supplementary group, errno {}", sys::errno());
    // The control: the group path must not become a way in when the group bits
    // are clear. Same group, mode 0400, and we are not the owner.
    check_fails!(h, unsafe { libc::access(cpath(other_ro).as_ptr(), libc::R_OK) },
                 libc::EACCES, "access(R_OK) on a group file with no group bits");

    h.group("exec-bit");
    check_fails!(h, unsafe { libc::access(cpath(noexec).as_ptr(), libc::X_OK) },
                 libc::EACCES, "access(X_OK) on a file with no execute bit");
}

fn main() {
    let dir = match std::env::args().nth(1) {
        Some(d) => d,
        None => {
            eprintln!("usage: perm_semantics <writable-directory>");
            return;
        }
    };
    let _ = std::fs::create_dir_all(&dir);

    // Setup, as root.
    let owned_ro = make(&dir, "owned_ro", 1000, 1000, 0o400);
    let owned_rw = make(&dir, "owned_rw", 1000, 1000, 0o600);
    let supp = make(&dir, "supp", 0, SUPP_GID, 0o040);
    let other_ro = make(&dir, "other_ro", 0, SUPP_GID, 0o400);
    let noexec = make(&dir, "noexec", 1000, 1000, 0o600);

    unsafe {
        let groups = [SUPP_GID];
        if libc::setgroups(1, groups.as_ptr()) != 0 {
            eprintln!("setgroups failed: {}", sys::errno());
        }

        let pid = libc::fork();
        if pid == 0 {
            // Drop. gid first: dropping the uid first would take away the
            // privilege needed to drop the gid.
            libc::setresgid(1000, 1000, 1000);
            libc::setresuid(1000, 1000, 1000);
            let mut h = Harness::new();
            let (r, e, _) = {
                let (mut a, mut b, mut c) = (0u32, 0u32, 0u32);
                libc::syscall(libc::SYS_getresuid, &mut a, &mut b, &mut c);
                (a, b, c)
            };
            check!(&mut h, r == 1000 && e == 1000, "the child is unprivileged: {r} {e}");
            checks(&mut h, &owned_ro, &owned_rw, &supp, &other_ro, &noexec);
            libc::_exit(h.finish());
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        if !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0) {
            std::process::exit(1);
        }
    }

    // And what the *privileged* caller may do, which is the other half of the
    // rule and is not testable from the child above.
    let mut h = Harness::new();
    root_checks(&mut h, &dir, &noexec);
    std::process::exit(h.finish());
}

/// `CAP_DAC_OVERRIDE` grants read and write outright and execute **only where
/// somebody could execute it**. `generic_permission`:
///
/// ```c
/// if (!(mask & MAY_EXEC) || (inode->i_mode & S_IXUGO))
///         if (capable_wrt_inode_uidgid(..., CAP_DAC_OVERRIDE))
///                 return 0;
/// ```
///
/// It matters because a shell asks `access(X_OK)` before it reports a path:
/// `command -v foo` answered a path here for a file it could not run, and the
/// caller then got EACCES from the exec it was told would work.
fn root_checks(h: &mut Harness, dir: &str, noexec: &str) {
    h.group("root and the execute bit");
    check_fails!(h, unsafe { libc::access(cpath(noexec).as_ptr(), libc::X_OK) },
                 libc::EACCES, "access(X_OK) as root on a 0600 file");
    check!(h, unsafe { libc::access(cpath(noexec).as_ptr(), libc::R_OK | libc::W_OK) } == 0,
           "access(R_OK|W_OK) as root on a file owned by somebody else");
    // One execute bit anywhere is enough, even somebody else's.
    let one_bit = make(dir, "one_x_bit", 1000, 1000, 0o601);
    check!(h, unsafe { libc::access(cpath(&one_bit).as_ptr(), libc::X_OK) } == 0,
           "access(X_OK) as root with only the other-execute bit, errno {}", sys::errno());
    // A directory is searchable whatever its bits say -- that is
    // CAP_DAC_READ_SEARCH, and without the exemption `chmod 000` would lock
    // root out of a directory.
    let locked = format!("{dir}/locked");
    let _ = std::fs::create_dir_all(&locked);
    unsafe { libc::chmod(cpath(&locked).as_ptr(), 0o000) };
    check!(h, unsafe { libc::access(cpath(&locked).as_ptr(), libc::X_OK) } == 0,
           "access(X_OK) as root on a 0000 directory, errno {}", sys::errno());
    unsafe { libc::chmod(cpath(&locked).as_ptr(), 0o755) };
}
