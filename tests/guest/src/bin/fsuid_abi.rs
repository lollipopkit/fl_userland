//! `setfsuid(2)` and `setfsgid(2)`: the credential used for filesystem access.
//!
//! Linux keeps `fsuid` and `fsgid` separately from the effective ids. They
//! follow the effective ones on every credential change, and can be set on
//! their own — which is what a file server does around a request it is handling
//! on someone else's behalf, so that a file it opens is checked against the
//! caller's id and everything else it does is still its own.
//!
//! These were `syscall_stub`, which answers `-ENOSYS`. That is not a refusal a
//! caller can see, because **`setfsuid` has no failure return at all**: it
//! answers the *previous* fsuid, whatever happened. So a program got
//! `4294967258` — `(unsigned) -38` — as the id it used to have, and the
//! documented way of finding out whether the change took is to call it twice
//! and compare.
//!
//! ```c
//! long __sys_setfsuid(uid_t uid)
//! {
//!     ...
//!     old_fsuid = from_kuid_munged(ns, old->fsuid);
//!     if (uid_eq(kuid, old->uid)  || uid_eq(kuid, old->euid)  ||
//!         uid_eq(kuid, old->suid) || uid_eq(kuid, old->fsuid) ||
//!         ns_capable_setid(old->user_ns, CAP_SETUID)) {
//!         ...
//!         new->fsuid = kuid;
//!         ...
//!     }
//!     ...
//!     return old_fsuid;
//! }
//! ```
//!
//! An unpermitted request changes nothing and still answers the old value.
//!
//! Every rule below was taken from a real arm64 kernel through
//! `differential.sh`, and the file runs its unprivileged half in a forked child
//! so it cannot leave this process unable to clean up after itself.

use guest_tests::{Harness, check, sys};

fn setfsuid(uid: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_setfsuid, uid as libc::c_long) as i64 }
}
fn setfsgid(gid: u32) -> i64 {
    unsafe { libc::syscall(libc::SYS_setfsgid, gid as libc::c_long) as i64 }
}

/// What `setfsuid` reports as the current value, without changing it: ask for
/// something that will be refused, and read the answer.
fn fsuid() -> i64 {
    setfsuid(u32::MAX)
}
fn fsgid() -> i64 {
    setfsgid(u32::MAX)
}

fn main() {
    let mut h = Harness::new();

    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    // A directory of our own, made *before* the fsuid moves and left
    // world-writable, so what the file checks below measure is the fsuid and
    // not whatever /tmp happens to be. It is 1777 in a container and 755 owned
    // by the host user under `-r` here, and the first version of this file used
    // /tmp directly and failed on that difference alone.
    let dir = c"/tmp/fsuid_abi_dir";
    unsafe { libc::mkdir(dir.as_ptr(), 0o777) };
    unsafe { libc::chmod(dir.as_ptr(), 0o777) };

    h.group("it-answers-the-previous-value");
    // -1 is not a uid: Linux's from_kuid_munged maps it to the overflow id and
    // the comparison fails, so nothing changes and the old value comes back.
    let before = fsuid();
    check!(
        h,
        before == euid as i64,
        "fsuid follows the effective uid: {before} vs euid {euid}"
    );
    check!(h, fsgid() == egid as i64, "and fsgid follows the effective gid");
    check!(h, fsuid() == before, "asking twice does not change it");

    h.group("setting-it-answers-the-old-one");
    // The protocol: the return is the *previous* fsuid, so a caller finds out
    // whether the change took by calling twice.
    let old = setfsuid(1000);
    check!(h, old == euid as i64, "the first call answers the id we had: {old}");
    let now = setfsuid(1000);
    check!(h, now == 1000, "and the second answers the one we asked for: {now}");
    check!(h, fsuid() == 1000, "which is where it stayed");
    // The effective uid is untouched -- that is the whole point of a separate id.
    check!(
        h,
        unsafe { libc::geteuid() } == euid,
        "and the effective uid did not move"
    );
    let old = setfsgid(1000);
    check!(h, old == egid as i64, "the same for fsgid: {old}");
    check!(h, setfsgid(1000) == 1000, "which took");
    check!(h, unsafe { libc::getegid() } == egid, "leaving the effective gid alone");

    h.group("it-is-what-a-file-check-uses");
    // A file only its owner may read, made *before* the fsuid moves so that its
    // owner is whatever this mount stamps a creation with. Which id that is
    // differs -- a container stamps root, and realfs here has no ownership of
    // its own and passes the host's through -- so the test reads it back rather
    // than assuming, and everything below is relative to it.
    //
    // What a creation is stamped *with* is tests/guest/src/bin/fsuid_stamp.rs,
    // on the mounts that can answer it.
    setfsuid(euid);
    let path = c"/tmp/fsuid_abi_dir/probe";
    unsafe { libc::unlink(path.as_ptr()) };
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600) };
    check!(h, fd >= 0, "made a file only its owner may read (errno {})", sys::errno());
    if fd >= 0 {
        unsafe { libc::close(fd) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        unsafe { libc::stat(path.as_ptr(), &mut st) };
        let owner = st.st_uid;

        // Move the fsuid to an id that is nobody's, and the file becomes
        // unreadable -- **even though the effective uid is still root**, which
        // is the rule worth having a check for. Setting the fsuid away from
        // root drops the filesystem capabilities. `cap_task_fix_setuid`:
        //
        //     case LSM_SETID_FS:
        //         if (uid_eq(old->fsuid, root_uid) && !uid_eq(new->fsuid, root_uid))
        //             new->cap_effective = cap_drop_fs_set(new->cap_effective);
        //
        // and `cap_drop_fs_set` takes CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH,
        // CAP_FOWNER, CAP_FSETID, CAP_MKNOD and CAP_LINUX_IMMUTABLE with it.
        // Without it the call would be pointless for the thing it is for: a
        // root server that set its fsuid to a caller's could still open
        // anything.
        //
        // The first version of this check asserted the opposite, that a
        // privileged caller reads it regardless, and a real kernel disagreed.
        let stranger = owner + 7;
        check!(h, setfsuid(stranger) == euid as i64, "move the fsuid off the owner");
        check!(h, fsuid() == stranger as i64, "which took: {}", fsuid());
        let r = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
        check!(
            h,
            r < 0 && sys::errno() == libc::EACCES,
            "with the fsuid moved away, even root cannot read it: r={r} errno={}",
            sys::errno()
        );
        if r >= 0 {
            unsafe { libc::close(r) };
        }
        // Put it back on the owner and the access comes back, so that is about
        // the fsuid and not about the file.
        check!(h, setfsuid(owner) == stranger as i64, "put it back to the owner's id");
        let r = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
        check!(h, r >= 0, "and the file opens again: r={r} errno={}", sys::errno());
        if r >= 0 {
            unsafe { libc::close(r) };
        }
        setfsuid(euid);
        unsafe { libc::unlink(path.as_ptr()) };
    }
    unsafe { libc::rmdir(dir.as_ptr()) };

    h.group("restoring-it");
    check!(h, fsuid() == euid as i64, "the fsuid is where it started");
    check!(h, setfsgid(egid) == 1000, "the same for the group");
    check!(h, fsgid() == egid as i64, "back where it started");

    h.group("a-credential-change-moves-it-with-them");
    // Linux's set_user etc. assign fsuid = euid on every path that changes the
    // effective id, which is why a program that never calls setfsuid sees the
    // two as the same thing.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        setfsuid(1234);
        let moved = unsafe { libc::seteuid(1000) } == 0 || euid != 0;
        let f = setfsuid(u32::MAX);
        let e = unsafe { libc::geteuid() } as i64;
        // 0: fsuid followed the effective uid. 1: it stayed at 1234.
        // 2: seteuid failed, so this proves nothing. 3: something else.
        let code = if !moved { 2 } else if f == e { 0 } else if f == 1234 { 1 } else { 3 };
        unsafe { libc::_exit(code) };
    }
    let mut st = 0i32;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    let code = if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 };
    check!(h, code != 2, "the child could change its effective uid (code {code})");
    check!(
        h,
        code == 0,
        "changing the effective uid moves the fsuid with it \
         (0 right, 1 it stayed put, 3 neither): {code}"
    );

    h.group("what-may-be-asked-for");
    // The rule is uid, euid, suid or the current fsuid -- or privilege. Checked
    // in a child, because a process that has given up its privilege cannot get
    // it back and everything after would be running unprivileged.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Real 0, effective and saved 1000: privilege is gone but the real id
        // is still 0, so 0 is one of the values that may be asked for.
        if unsafe { libc::setresuid(u32::MAX, 1000, 1000) } != 0 {
            unsafe { libc::_exit(9) };
        }
        let mut code = 0;
        // The current fsuid, which followed euid to 1000.
        if setfsuid(1000) != 1000 || setfsuid(1000) != 1000 {
            code |= 1;
        }
        // The real uid, which is still whatever we started as.
        let real = unsafe { libc::getuid() };
        setfsuid(real);
        if setfsuid(real) != real as i64 {
            code |= 2;
        }
        // And one that is none of them: refused silently, so the value is
        // unchanged and the return is still the old one.
        setfsuid(1000);
        let old = setfsuid(4242);
        if old != 1000 {
            code |= 4;
        }
        if setfsuid(u32::MAX) != 1000 {
            code |= 8;
        }
        unsafe { libc::_exit(code) };
    }
    let mut st = 0i32;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    let code = if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 };
    check!(h, code != 9, "the child dropped its privilege (code {code})");
    check!(h, code & 1 == 0, "the current fsuid may be asked for again (code {code})");
    check!(h, code & 2 == 0, "so may the real uid (code {code})");
    check!(h, code & 4 == 0, "an id that is none of them still answers the old value (code {code})");
    check!(h, code & 8 == 0, "and changes nothing (code {code})");

    std::process::exit(h.finish());
}
