//! Changing what is *in* a directory needs write permission on the directory.
//!
//! Every one of `mkdir`, `symlink`, `link`, `unlink`, `rmdir`, `rename` and
//! `open(O_CREAT)` changes the contents of the directory holding the name, so
//! POSIX requires write permission on that directory — not on the entry, which
//! for a create does not exist yet.
//!
//! `fs/generic.c` asks for that check by passing `N_PARENT_DIR_WRITE` to
//! `path_normalize`, at nine call sites. The flag was defined in 2019 and
//! **nothing had ever read it**: `git log -S N_PARENT_DIR_WRITE` finds the
//! commit that added the constant and no code that looks at it, in any
//! revision. Six of the seven operations above succeeded in a directory the
//! caller could search and not write.
//!
//! `fs/fake.h` also documents `fakefs_bind_mount(read_only = true)` as working
//! by writing the mount point with mode 0555 and letting "iSH's generic
//! N_PARENT_DIR_WRITE check reject any create/unlink/rename/rmdir with EACCES
//! at the normal access-check layer — no special fakefs plumbing required".
//! That is an embedder-facing guarantee resting on a check that did not exist.
//!
//! # How this gets to be unprivileged
//!
//! Through `setfsuid`, which is the cheapest way to move only the filesystem
//! credential and leave everything else — including the ability to clean up
//! afterwards — alone. A guest reaches the same state by `setuid`, or by an
//! `execve` of a set-id binary.
//!
//! # What is not asserted
//!
//! `link`'s errno. Linux answers `EPERM` here, from the hardlink protection in
//! `may_linkat` — you may not hardlink a file you do not own — and this answers
//! `EACCES` from the directory check. Both are refusals, the reasons are
//! different rules, and only one of them is what this file is about.

use guest_tests::{Harness, check, sys};

use std::ffi::CString;

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn setfsuid(uid: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_setfsuid, uid as libc::c_long) as i64 }
}

// Deliberately not this file's own name. The guest harness copies each test
// binary to /tmp/<name>, so a scratch directory called after the test collides
// with the binary running it -- and every operation below answers ENOTDIR,
// which looked like a permission result and is not one. It showed up only
// here, because the container mounts the binaries somewhere else.
const DIR: &str = "/tmp/dwp_scratch";

/// Everything the checks need: the directory, two files to remove and a
/// subdirectory to rmdir. Made with the starting credentials.
fn setup() {
    let _ = std::fs::remove_dir_all(DIR);
    unsafe {
        libc::mkdir(cs(DIR).as_ptr(), 0o755);
        libc::chmod(cs(DIR).as_ptr(), 0o755);
        for n in ["victim", "victim2"] {
            let f = libc::open(cs(&format!("{DIR}/{n}")).as_ptr(),
                               libc::O_CREAT | libc::O_WRONLY, 0o666);
            if f >= 0 {
                libc::close(f);
            }
        }
        libc::mkdir(cs(&format!("{DIR}/vdir")).as_ptr(), 0o777);
    }
}

/// The seven operations, each returning its result.
fn attempts() -> Vec<(&'static str, i32, i32)> {
    let mut out = Vec::new();
    let mut go = |name: &'static str, r: i32| {
        out.push((name, r, if r < 0 { sys::errno() } else { 0 }));
    };
    unsafe {
        sys::clear_errno();
        let fd = libc::open(cs(&format!("{DIR}/new")).as_ptr(),
                            libc::O_CREAT | libc::O_WRONLY, 0o666);
        go("create", if fd >= 0 { libc::close(fd); 0 } else { -1 });
        sys::clear_errno();
        go("mkdir", libc::mkdir(cs(&format!("{DIR}/nd")).as_ptr(), 0o755));
        sys::clear_errno();
        go("symlink", libc::symlink(c"x".as_ptr(), cs(&format!("{DIR}/nl")).as_ptr()));
        sys::clear_errno();
        go("link", libc::link(cs(&format!("{DIR}/victim")).as_ptr(),
                              cs(&format!("{DIR}/nh")).as_ptr()));
        sys::clear_errno();
        go("unlink", libc::unlink(cs(&format!("{DIR}/victim")).as_ptr()));
        sys::clear_errno();
        go("rmdir", libc::rmdir(cs(&format!("{DIR}/vdir")).as_ptr()));
        sys::clear_errno();
        go("rename", libc::rename(cs(&format!("{DIR}/victim2")).as_ptr(),
                                  cs(&format!("{DIR}/renamed")).as_ptr()));
    }
    out
}

fn main() {
    let mut h = Harness::new();
    let start = setfsuid(u32::MAX) as u32;

    h.group("a-directory-you-cannot-write");
    setup();
    // An id that is not the directory's owner and is not root, so the "other"
    // bits of 0755 decide -- r-x, with no write.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::stat(cs(DIR).as_ptr(), &mut st) };
    check!(h, st.st_mode & 0o777 == 0o755, "the directory is 0755: {:o}", st.st_mode & 0o777);
    let stranger = st.st_uid + 7;
    check!(h, setfsuid(stranger) == start as i64, "move the fsuid off its owner");
    check!(h, setfsuid(u32::MAX) == stranger as i64, "which took");

    for (name, r, e) in attempts() {
        // The errno is asserted for six of the seven; `link` has a second rule
        // in front of it on Linux -- see the note at the top of this file.
        if name == "link" {
            check!(h, r < 0, "{name} in a directory we cannot write is refused: r={r} errno={e}");
        } else {
            check!(
                h,
                r < 0 && e == libc::EACCES,
                "{name} in a directory we cannot write is EACCES: r={r} errno={e}"
            );
        }
    }

    h.group("and-the-same-directory-when-you-can");
    // The control: none of the above is satisfied by refusing everything. Back
    // to the starting id, which owns it.
    setfsuid(start);
    setup();
    for (name, r, e) in attempts() {
        check!(h, r == 0, "{name} succeeds for the owner: r={r} errno={e}");
    }

    h.group("existence-is-answered-before-permission");
    // Linux looks the last component up before it checks the directory, and
    // the order shows: a create whose name is already there reports EEXIST,
    // and a removal whose name is not reports ENOENT -- neither is EACCES,
    // even though the directory is unwritable in both cases.
    //
    // `open(existing, O_CREAT|O_RDONLY)` is the one that matters most. It is
    // an ordinary thing for a program to do in a directory it cannot write,
    // and a blanket "the parent must be writable" check breaks it. That is
    // exactly what the first version of the fix did, and the guest suite
    // failed seven other tests on it.
    setup();
    let existing = format!("{DIR}/exists");
    let existing_dir = format!("{DIR}/existsdir");
    unsafe {
        let f = libc::open(cs(&existing).as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o666);
        if f >= 0 {
            libc::close(f);
        }
        libc::mkdir(cs(&existing_dir).as_ptr(), 0o755);
    }
    setfsuid(stranger);

    sys::clear_errno();
    let fd = unsafe { libc::open(cs(&existing).as_ptr(), libc::O_CREAT | libc::O_RDONLY, 0o666) };
    check!(
        h,
        fd >= 0,
        "open(existing, O_CREAT) in a directory we cannot write still opens it: fd={fd} errno={}",
        sys::errno()
    );
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }

    sys::clear_errno();
    let fd = unsafe {
        libc::open(cs(&existing).as_ptr(), libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o666)
    };
    check!(
        h,
        fd < 0 && sys::errno() == libc::EEXIST,
        "but with O_EXCL it is EEXIST, not EACCES: fd={fd} errno={}",
        sys::errno()
    );
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }

    sys::clear_errno();
    let r = unsafe { libc::mkdir(cs(&existing_dir).as_ptr(), 0o755) };
    check!(
        h,
        r < 0 && sys::errno() == libc::EEXIST,
        "mkdir of a name that is there is EEXIST: r={r} errno={}",
        sys::errno()
    );
    sys::clear_errno();
    let r = unsafe { libc::symlink(c"z".as_ptr(), cs(&existing).as_ptr()) };
    check!(
        h,
        r < 0 && sys::errno() == libc::EEXIST,
        "and so is symlink onto one: r={r} errno={}",
        sys::errno()
    );

    for (name, r) in [
        ("unlink", unsafe { sys::clear_errno(); (libc::unlink(cs(&format!("{DIR}/missing")).as_ptr()), sys::errno()) }),
        ("rmdir", unsafe { sys::clear_errno(); (libc::rmdir(cs(&format!("{DIR}/missing")).as_ptr()), sys::errno()) }),
    ] {
        check!(
            h,
            r.0 < 0 && r.1 == libc::ENOENT,
            "{name} of a name that is not there is ENOENT, not EACCES: r={} errno={}",
            r.0,
            r.1
        );
    }
    setfsuid(start);

    h.group("access-answers-for-the-real-ids");
    // `access(2)` is deliberately about the *real* uid, so that a set-id
    // program can ask whether the user who invoked it may do something. That
    // is why `faccessat` swaps the ids for the duration of the walk, and why
    // the swap has to be of the ids the check actually reads.
    setup();
    setfsuid(stranger);
    let real_can = unsafe { libc::access(cs(DIR).as_ptr(), libc::W_OK) };
    check!(
        h,
        real_can == 0,
        "access(W_OK) answers for the real uid, which still owns it: r={real_can} errno={}",
        sys::errno()
    );
    // And AT_EACCESS asks the other question, which is the one that says no.
    let eff_can = unsafe {
        libc::faccessat(libc::AT_FDCWD, cs(DIR).as_ptr(), libc::W_OK, libc::AT_EACCESS)
    };
    check!(
        h,
        eff_can == -1,
        "AT_EACCESS asks with the fs ids and is refused: r={eff_can} errno={}",
        sys::errno()
    );
    // Which is not a claim that access() refuses nothing.
    let none = unsafe { libc::access(c"/nonexistent-for-sure".as_ptr(), libc::F_OK) };
    check!(h, none == -1, "access() still reports a missing file: r={none}");

    setfsuid(start);
    let _ = std::fs::remove_dir_all(DIR);
    std::process::exit(h.finish());
}
