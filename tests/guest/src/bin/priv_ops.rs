//! The operations that need a capability, not just a permission bit.
//!
//! `chroot` needs `CAP_SYS_CHROOT`; `mount` and `umount2` need
//! `CAP_SYS_ADMIN`. None of the three was checked, so any unprivileged guest
//! process could do all of them.
//!
//! The chroot one is not only "a rule was missing". Being able to call `chroot`
//! is the classic way *out* of a chroot: the confined process makes a
//! subdirectory, chroots into it, and its `..` walks past the old root. A
//! confinement this kernel can be asked to apply could be undone by the process
//! it was applied to.
//!
//! `mount` matters for what it lets a process put in front of other people's
//! files — a tmpfs over `/etc` needs no ownership of anything under it.
//!
//! Setup runs as root; a child at uid 1000 does the asking.

use guest_tests::{Harness, check, check_fails, cpath, sys};

fn mount_tmpfs(at: &str) -> i32 {
    unsafe {
        libc::mount(
            cpath("none").as_ptr(),
            cpath(at).as_ptr(),
            cpath("tmpfs").as_ptr(),
            0,
            std::ptr::null(),
        )
    }
}

fn main() {
    let root_only = "/mnt/privops";
    let child_dir = "/mnt/privops_child";
    let _ = std::fs::create_dir_all(root_only);
    let _ = std::fs::create_dir_all(child_dir);
    let _ = std::fs::create_dir_all("/tmp/privops_chroot");

    // Root mounts one, so the child has something real to try to unmount.
    let mounted = mount_tmpfs(root_only) == 0;

    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::setresgid(1000, 1000, 1000);
            libc::setresuid(1000, 1000, 1000);
            let mut h = Harness::new();

            // Order matters: chroot is last. If it succeeds -- which is the
            // defect -- every path after it is resolved against a different
            // root, and the mount checks then fail with ENOENT instead of for
            // the reason under test. The first version of this probe had them
            // the other way round and reported two misleading errnos.
            h.group("mount");
            check_fails!(h, mount_tmpfs(child_dir), libc::EPERM, "mount as an unprivileged process");
            if mounted {
                check_fails!(
                    h,
                    libc::umount2(cpath(root_only).as_ptr(), 0),
                    libc::EPERM,
                    "umount someone else's mount"
                );
            }

            h.group("chroot");
            check_fails!(
                h,
                libc::chroot(cpath("/tmp/privops_chroot").as_ptr()),
                libc::EPERM,
                "chroot as an unprivileged process"
            );

            libc::_exit(h.finish());
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        let child_failed = !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0;

        // The controls: root may still do all three. Without these the fix
        // could be "refuse everyone", which would stop the guest booting.
        let mut h = Harness::new();
        h.group("root-may");
        check!(h, !child_failed, "the unprivileged child's checks all passed");
        check!(h, mounted, "root could mount a tmpfs");
        if mounted {
            check!(
                h,
                libc::umount2(cpath(root_only).as_ptr(), 0) == 0,
                "root could unmount it, errno {}",
                sys::errno()
            );
        }
        check!(h, mount_tmpfs(child_dir) == 0, "root could mount again, errno {}", sys::errno());
        let _ = libc::umount2(cpath(child_dir).as_ptr(), 0);

        // chroot last: it changes this process's view of everything.
        let r = libc::chroot(cpath("/tmp/privops_chroot").as_ptr());
        check!(h, r == 0, "root could chroot, errno {}", sys::errno());

        std::process::exit(h.finish());
    }
}
