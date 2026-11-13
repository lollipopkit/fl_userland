//! The sticky bit on a directory.
//!
//! Linux: in a directory with `S_ISVTX`, an entry may only be removed or
//! renamed by the owner of the entry, the owner of the directory, or a
//! privileged caller. `/tmp` is mode 1777 precisely so that this holds —
//! without it, write permission on the directory, which everyone has, is
//! permission to delete anyone else's files.
//!
//! Nothing in this tree looked at `S_ISVTX`. `generic_unlinkat` checked write
//! permission on the parent directory and stopped there.
//!
//! Setup runs as root; the asking is done by a child at uid 1000.

use guest_tests::{Harness, check, check_fails, cpath, sys};

const S_ISVTX: libc::mode_t = 0o1000;

fn mkfile(path: &str, uid: libc::uid_t) {
    let _ = std::fs::write(path, b"x");
    unsafe {
        libc::chown(cpath(path).as_ptr(), uid, uid);
        libc::chmod(cpath(path).as_ptr(), 0o666);
    }
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/sticky".into());
    let sticky = format!("{dir}/s");
    let plain = format!("{dir}/p");
    let _ = std::fs::create_dir_all(&sticky);
    let _ = std::fs::create_dir_all(&plain);
    unsafe {
        libc::chmod(cpath(&sticky).as_ptr(), 0o777 | S_ISVTX);
        libc::chmod(cpath(&plain).as_ptr(), 0o777);
    }

    // In the sticky directory: one file owned by someone else, one by us.
    mkfile(&format!("{sticky}/theirs"), 2000);
    mkfile(&format!("{sticky}/ours"), 1000);
    mkfile(&format!("{sticky}/rename_me"), 2000);
    // And the same "someone else's" file in a directory with no sticky bit.
    mkfile(&format!("{plain}/theirs"), 2000);

    unsafe {
        let child = libc::fork();
        if child == 0 {
            libc::setresgid(1000, 1000, 1000);
            libc::setresuid(1000, 1000, 1000);
            let mut h = Harness::new();
            h.group("sticky");

            // The rule: someone else's file in a sticky directory we can write.
            check_fails!(
                h,
                sys::unlink(&format!("{sticky}/theirs")),
                libc::EPERM,
                "unlink someone else's file in a sticky directory"
            );
            // rename is the same removal, by another name.
            check_fails!(
                h,
                sys::rename(&format!("{sticky}/rename_me"), &format!("{sticky}/moved")),
                libc::EPERM,
                "rename someone else's file out of a sticky directory"
            );

            // Controls. Our own file in the same directory: allowed, so the
            // rule is about ownership and not about the directory being sticky.
            check!(
                h,
                sys::unlink(&format!("{sticky}/ours")) == 0,
                "unlink our own file in a sticky directory, errno {}",
                sys::errno()
            );
            // The same foreign file where the sticky bit is not set: allowed,
            // so the refusal above comes from the bit and not from ownership
            // alone.
            check!(
                h,
                sys::unlink(&format!("{plain}/theirs")) == 0,
                "unlink someone else's file in a directory with no sticky bit, errno {}",
                sys::errno()
            );

            libc::_exit(h.finish());
        }
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);
        std::process::exit(if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 1 });
    }
}
