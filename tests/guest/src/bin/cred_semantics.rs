//! `setreuid`/`setregid` and the saved set-user-ID.
//!
//! Linux: "If the real user ID is set (*ruid* is not -1) or the effective user
//! ID is set to a value not equal to the previous real user ID, the saved
//! set-user-ID will be set to the new effective user ID."
//!
//! `sys_setreuid` forwarded to `setresuid(ruid, euid, -1)`, which leaves the
//! saved id alone, so the saved id kept its old privileged value.
//!
//! The consequence needs stating precisely, because the obvious version of it
//! is wrong. `setreuid(-1, n)` alone does **not** make a drop permanent even on
//! Linux — the real uid is untouched, and an unprivileged `setuid()` may name
//! the real uid, so taking euid 0 back afterwards is correct behaviour. What
//! the missing assignment broke is `setreuid(n, n)`: the real uid goes to `n`,
//! the saved id should follow, and while it did not, the saved id was the one
//! remaining 0 that `setuid(0)` could match.
//!
//! Each case runs in a forked child, because a credential change cannot be
//! undone once the privilege to undo it has been given up.

use guest_tests::{Harness, check, sys};

fn getresuid() -> (u32, u32, u32) {
    let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
    unsafe { libc::syscall(libc::SYS_getresuid, &mut r, &mut e, &mut s) };
    (r, e, s)
}

fn getresgid() -> (u32, u32, u32) {
    let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
    unsafe { libc::syscall(libc::SYS_getresgid, &mut r, &mut e, &mut s) };
    (r, e, s)
}

/// Runs `body` in a child and reports whether it exited 0. The child prints
/// nothing; it answers with its exit status, so a failed check inside it has to
/// be turned into one here.
fn in_child(h: &mut Harness, what: &str, body: impl FnOnce() -> Result<(), String>) {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            let code = match body() {
                Ok(()) => 0,
                Err(msg) => {
                    // The message goes to stderr, where the runner shows it.
                    eprintln!("  {what}: {msg}");
                    1
                }
            };
            libc::_exit(code);
        }
        if pid < 0 {
            check!(h, false, "fork for {what}");
            return;
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        let ok = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        check!(h, ok, "{what}");
    }
}

fn main() {
    let mut h = Harness::new();
    h.group("setreuid");

    let (r0, e0, s0) = getresuid();
    check!(h, r0 == 0 && e0 == 0, "the guest starts privileged: {r0} {e0} {s0}");

    // The rule. euid becomes 1000, which is not the previous real uid (0), so
    // the saved id must follow it to 1000.
    in_child(&mut h, "setreuid(-1, 1000) also sets the saved uid", || {
        if unsafe { libc::setreuid(u32::MAX, 1000) } != 0 {
            return Err(format!("setreuid failed, errno {}", sys::errno()));
        }
        match getresuid() {
            (0, 1000, 1000) => Ok(()),
            got => Err(format!("getresuid is {got:?}, wanted (0, 1000, 1000)")),
        }
    });

    // A *full* drop must not be reversible. Note this needs the real uid
    // dropped as well: `setreuid(-1, 1000)` leaves the real uid at 0, and Linux
    // lets an unprivileged setuid() name the real uid, so taking euid 0 back
    // after that is correct and is not what this is testing.
    //
    // With the real uid dropped too, the saved id is the only thing that could
    // permit a return — which is exactly the field that was being left behind.
    in_child(&mut h, "a full drop cannot be reversed", || {
        if unsafe { libc::setreuid(1000, 1000) } != 0 {
            return Err(format!("setreuid failed, errno {}", sys::errno()));
        }
        match getresuid() {
            (1000, 1000, 1000) => {}
            got => return Err(format!("getresuid is {got:?}, wanted (1000, 1000, 1000)")),
        }
        if unsafe { libc::setuid(0) } == 0 {
            return Err(format!("setuid(0) succeeded, getresuid now {:?}", getresuid()));
        }
        Ok(())
    });

    // The control, and the thing that distinguishes setreuid's extra rule from
    // setresuid's plain one: setresuid names the saved id explicitly, so -1
    // must leave it alone. A "fix" that set the saved id unconditionally would
    // fail here.
    in_child(&mut h, "setresuid(-1, 1000, -1) leaves the saved uid alone", || {
        if unsafe { libc::setresuid(u32::MAX, 1000, u32::MAX) } != 0 {
            return Err(format!("setresuid failed, errno {}", sys::errno()));
        }
        match getresuid() {
            (0, 1000, 0) => Ok(()),
            got => Err(format!("getresuid is {got:?}, wanted (0, 1000, 0)")),
        }
    });

    // Setting the effective uid to the previous *real* uid does not move the
    // saved id either — the other half of the sentence.
    in_child(&mut h, "setreuid(-1, 0) from uid 0 leaves the saved uid alone", || {
        if unsafe { libc::setresuid(u32::MAX, u32::MAX, 7) } != 0 {
            return Err(format!("seeding the saved uid failed, errno {}", sys::errno()));
        }
        if unsafe { libc::setreuid(u32::MAX, 0) } != 0 {
            return Err(format!("setreuid failed, errno {}", sys::errno()));
        }
        match getresuid() {
            (0, 0, 7) => Ok(()),
            got => Err(format!("getresuid is {got:?}, wanted (0, 0, 7)")),
        }
    });

    // setreuid restricts the *real* id more tightly than setresuid does.
    // Linux's __sys_setreuid allows it to become the current real or effective
    // id only; setresuid also allows the saved one. Forwarding one to the other
    // let an unprivileged task pull a privileged saved id into its real id.
    in_child(&mut h, "setreuid cannot pull the saved id into the real id", || {
        // (1000, 1000, 0): unprivileged, with a privileged saved id.
        if unsafe { libc::setresuid(1000, 1000, 0) } != 0 {
            return Err(format!("setting up failed, errno {}", sys::errno()));
        }
        if unsafe { libc::setreuid(0, u32::MAX) } == 0 {
            return Err(format!("setreuid(0, -1) succeeded, getresuid now {:?}", getresuid()));
        }
        // setresuid may still do it, which is what makes the two calls differ.
        if unsafe { libc::setresuid(0, u32::MAX, u32::MAX) } != 0 {
            return Err(format!("setresuid(0, -1, -1) was refused, errno {}", sys::errno()));
        }
        Ok(())
    });

    h.group("setregid");

    in_child(&mut h, "setregid(-1, 1000) also sets the saved gid", || {
        if unsafe { libc::setregid(u32::MAX, 1000) } != 0 {
            return Err(format!("setregid failed, errno {}", sys::errno()));
        }
        match getresgid() {
            (0, 1000, 1000) => Ok(()),
            got => Err(format!("getresgid is {got:?}, wanted (0, 1000, 1000)")),
        }
    });

    in_child(&mut h, "setresgid(-1, 1000, -1) leaves the saved gid alone", || {
        if unsafe { libc::setresgid(u32::MAX, 1000, u32::MAX) } != 0 {
            return Err(format!("setresgid failed, errno {}", sys::errno()));
        }
        match getresgid() {
            (0, 1000, 0) => Ok(()),
            got => Err(format!("getresgid is {got:?}, wanted (0, 1000, 0)")),
        }
    });

    h.group("the six that answer one id");

    // `getuid`, `geteuid`, `getgid` and `getegid` each read **one element of a
    // tuple**, and every existing check reads the ids through `getresuid` and
    // `getresgid` instead. That is the shape CLAUDE.md names: a helper two or
    // more `sys_*` bodies call, where one caller is tested and another is not,
    // and `sched_get_priority_max`/`_min` and `sethostname`/`setdomainname`
    // were both found that way.
    //
    // A swap here is silent for the guest as it starts, because root has 0 for
    // all six. So each id gets a **distinct** value first, which is what makes
    // a wrong element observable at all.
    in_child(&mut h, "getuid and geteuid read different elements", || {
        if unsafe { libc::setresuid(1000, 1001, 1002) } != 0 {
            return Err(format!("setresuid failed, errno {}", sys::errno()));
        }
        let (r, e, _) = getresuid();
        let (u, eu) = unsafe { (libc::getuid(), libc::geteuid()) };
        if (u, eu) != (r, e) {
            return Err(format!("getuid/geteuid are ({u}, {eu}), getresuid says ({r}, {e})"));
        }
        if u == eu {
            return Err("the two ids are equal, so this check could not fail".into());
        }
        Ok(())
    });

    in_child(&mut h, "getgid and getegid read different elements", || {
        // The gids first: dropping the uid would take the privilege to set
        // them away.
        if unsafe { libc::setresgid(2000, 2001, 2002) } != 0 {
            return Err(format!("setresgid failed, errno {}", sys::errno()));
        }
        let (r, e, _) = getresgid();
        let (g, eg) = unsafe { (libc::getgid(), libc::getegid()) };
        if (g, eg) != (r, e) {
            return Err(format!("getgid/getegid are ({g}, {eg}), getresgid says ({r}, {e})"));
        }
        if g == eg {
            return Err("the two ids are equal, so this check could not fail".into());
        }
        Ok(())
    });

    in_child(&mut h, "the uid calls do not answer a gid", || {
        // **Gids first.** Dropping the uid to 1000 takes away the privilege to
        // set a gid, so the other order answers `EPERM` -- which is what the
        // first version of this check did, and the runner reported it as a
        // failure of the emulator rather than of the test.
        if unsafe { libc::setresgid(2000, 2001, 2002) } != 0 {
            return Err(format!("setresgid failed, errno {}", sys::errno()));
        }
        if unsafe { libc::setresuid(1000, 1001, 1002) } != 0 {
            return Err(format!("setresuid failed, errno {}", sys::errno()));
        }
        // The two families get values a thousand apart, so a `getuid` wired to
        // the gid table -- or the reverse -- shows up as a value from the wrong
        // range rather than as a coincidence.
        let (u, eu, g, eg) = unsafe {
            (libc::getuid(), libc::geteuid(), libc::getgid(), libc::getegid())
        };
        if !(1000..2000).contains(&u) || !(1000..2000).contains(&eu) {
            return Err(format!("getuid/geteuid answered ({u}, {eu}), not a uid"));
        }
        if !(2000..3000).contains(&g) || !(2000..3000).contains(&eg) {
            return Err(format!("getgid/getegid answered ({g}, {eg}), not a gid"));
        }
        Ok(())
    });

    std::process::exit(h.finish());
}
