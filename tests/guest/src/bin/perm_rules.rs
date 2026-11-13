//! Three permission rules that were missing, and one that fired for the wrong
//! reason.
//!
//! All three are about a caller whose *filesystem* credential is not root while
//! its effective uid still is — which is what `setfsuid` makes, and what a file
//! server handling someone else's request looks like. A guest reaches the same
//! state by `setuid` or by an `execve` of a set-id binary; `setfsuid` is only
//! the cheapest way to get there and back.
//!
//! - **`protected_hardlinks`.** A hard link pins an inode: once made, the owner
//!   of the original cannot get rid of it by unlinking their copy, and the
//!   permissions it is checked against are the inode's. Linking to something you
//!   cannot already read and write keeps a reference to a file you were never
//!   allowed to have. Linux has had this on by default since 3.6; there was no
//!   check here at all.
//! - **The sticky bit.** `/tmp` is `1777` exactly so that write permission on
//!   it — which is everyone's — is not permission to delete anyone else's
//!   files. `sticky_check` existed and began `if (superuser()) return 0;`, so a
//!   caller whose effective uid was still root walked straight past it. It asks
//!   about the fsuid now, because `CAP_FOWNER` is one of the six capabilities
//!   that setting the fsuid away from root drops.
//! - **A file `O_CREAT` has just made is not permission-checked.** Linux's
//!   `do_last` goes to `finish_open_created` and never calls `may_open` for one.
//!   `open("new", O_CREAT|O_RDWR, 0400)` answered `EACCES` here *and left the
//!   file behind* — an error and a file.
//!
//! Everything is ordinary POSIX on whatever `/tmp` is, and is compared against a
//! real kernel.

use guest_tests::{Harness, check, sys};

use std::ffi::CString;

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn setfsuid(uid: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_setfsuid, uid as libc::c_long) as i64 }
}

const DIR: &str = "/tmp/perm_rules_scratch";

/// Make `name` with `mode`, owned by whoever the current fs ids are, and
/// report the owner the mount actually stamped it with.
fn make(name: &str, mode: u32) -> (String, u32) {
    let p = format!("{DIR}/{name}");
    unsafe {
        libc::unlink(cs(&p).as_ptr());
        let f = libc::open(cs(&p).as_ptr(), libc::O_CREAT | libc::O_RDWR, mode);
        if f >= 0 {
            libc::close(f);
        }
        libc::chmod(cs(&p).as_ptr(), mode);
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::stat(cs(&p).as_ptr(), &mut st) };
    (p, st.st_uid)
}

fn main() {
    let mut h = Harness::new();
    let start = setfsuid(u32::MAX) as u32;

    let _ = std::fs::remove_dir_all(DIR);
    unsafe {
        libc::mkdir(cs(DIR).as_ptr(), 0o777);
        // World-writable and sticky, which is what /tmp is.
        libc::chmod(cs(DIR).as_ptr(), 0o1777);
    }
    let mut ds: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::stat(cs(DIR).as_ptr(), &mut ds) };
    check!(h, ds.st_mode & 0o7777 == 0o1777, "a sticky world-writable directory: {:o}",
           ds.st_mode & 0o7777);
    let owner = ds.st_uid;
    // Not the owner of anything here, and not root.
    let stranger = owner + 9;

    h.group("protected-hardlinks");
    let (readable, _) = make("readable", 0o644);
    let (writable, _) = make("writable", 0o666);
    let (setuid_file, _) = make("setuid", 0o4666);
    setfsuid(stranger);

    sys::clear_errno();
    let r = unsafe { libc::link(cs(&readable).as_ptr(), cs(&format!("{DIR}/h1")).as_ptr()) };
    check!(
        h,
        r < 0,
        "a stranger may not hardlink a file they cannot write: r={r} errno={}",
        sys::errno()
    );
    // The control: one they *can* read and write is allowed, so this is not a
    // rule that refuses every link.
    sys::clear_errno();
    let r = unsafe { libc::link(cs(&writable).as_ptr(), cs(&format!("{DIR}/h2")).as_ptr()) };
    check!(
        h,
        r == 0,
        "one they can read and write is allowed: r={r} errno={}",
        sys::errno()
    );
    // A set-uid file is refused even though it is writable. This is the case
    // the whole rule exists for: pinning a set-uid binary so that it survives
    // its owner deleting it.
    sys::clear_errno();
    let r = unsafe { libc::link(cs(&setuid_file).as_ptr(), cs(&format!("{DIR}/h3")).as_ptr()) };
    check!(
        h,
        r < 0,
        "a set-uid file is refused even when writable: r={r} errno={}",
        sys::errno()
    );
    setfsuid(start);
    // And the owner may link their own, whatever it is.
    sys::clear_errno();
    let r = unsafe { libc::link(cs(&setuid_file).as_ptr(), cs(&format!("{DIR}/h4")).as_ptr()) };
    check!(h, r == 0, "the owner may link their own set-uid file: r={r} errno={}", sys::errno());

    h.group("the-sticky-bit");
    let (victim, _) = make("victim", 0o666);
    let (victim2, _) = make("victim2", 0o666);
    setfsuid(stranger);
    sys::clear_errno();
    let r = unsafe { libc::unlink(cs(&victim).as_ptr()) };
    check!(
        h,
        r < 0 && sys::errno() == libc::EPERM,
        "a stranger may not unlink someone else's file from a sticky directory: \
         r={r} errno={}",
        sys::errno()
    );
    sys::clear_errno();
    let r = unsafe {
        libc::rename(cs(&victim2).as_ptr(), cs(&format!("{DIR}/moved")).as_ptr())
    };
    check!(
        h,
        r < 0 && sys::errno() == libc::EPERM,
        "nor rename it: r={r} errno={}",
        sys::errno()
    );
    // The control: their own file in the same directory. Made *here*, with the
    // stranger's fs ids, so whichever id the mount stamps is theirs.
    let mine = format!("{DIR}/mine");
    let fd = unsafe { libc::open(cs(&mine).as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o666) };
    check!(h, fd >= 0, "a stranger can still make their own file there: fd={fd}");
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
    setfsuid(start);
    // Removed by the directory's owner, who is allowed to whatever it holds.
    sys::clear_errno();
    let r = unsafe { libc::unlink(cs(&mine).as_ptr()) };
    check!(
        h,
        r == 0,
        "and the directory's owner may remove anything in it: r={r} errno={}",
        sys::errno()
    );

    h.group("a-file-o-creat-just-made-is-not-checked");
    // You named the mode; you get the descriptor. Checking it means the call
    // fails *after* the file is there, which is an error and a file.
    setfsuid(stranger);
    for (name, mode, flags) in [
        ("c1", 0o400u32, libc::O_CREAT | libc::O_RDWR),
        ("c2", 0o000, libc::O_CREAT | libc::O_WRONLY),
        ("c3", 0o200, libc::O_CREAT | libc::O_RDONLY),
    ] {
        let p = format!("{DIR}/{name}");
        sys::clear_errno();
        let fd = unsafe { libc::open(cs(&p).as_ptr(), flags, mode) };
        check!(
            h,
            fd >= 0,
            "open(new, O_CREAT, {mode:o}) hands back a descriptor: fd={fd} errno={}",
            sys::errno()
        );
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
    // And re-opening one is checked, so the rule is about the creation and not
    // about the mode being ignored.
    sys::clear_errno();
    let fd = unsafe { libc::open(cs(&format!("{DIR}/c1")).as_ptr(), libc::O_WRONLY) };
    check!(
        h,
        fd < 0 && sys::errno() == libc::EACCES,
        "reopening the 0400 one for writing is EACCES: fd={fd} errno={}",
        sys::errno()
    );
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }

    setfsuid(start);
    let _ = std::fs::remove_dir_all(DIR);
    std::process::exit(h.finish());
}
