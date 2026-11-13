//! POSIX timers are not inherited, by `fork` or by `execve`.
//!
//! `timer_create` gives a process a timer id. A child does not get its parent's
//! — it starts with none at all, so every id is `EINVAL` there until it makes
//! one of its own. `timer_create` in the child hands back the *first* id, which
//! is the same number the parent is using, and the two name different timers.
//!
//! A kernel that copies the ids across gives the child a handle to its parent's
//! timer. `timer_delete` in the child then destroys a timer the parent still
//! owns, and the parent's next `timer_settime` uses a freed one. Nothing about
//! either call reports a problem.
//!
//! `execve` clears them for the same reason a handler cannot survive one: the
//! program that asked for them is gone.

use guest_tests::{Harness, check};

const CLOCK_MONOTONIC: i32 = 1;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Itimerspec {
    interval_sec: i64,
    interval_nsec: i64,
    value_sec: i64,
    value_nsec: i64,
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn timer_create() -> (i64, i32) {
    let mut id: i32 = -1;
    let r = unsafe {
        libc::syscall(libc::SYS_timer_create, CLOCK_MONOTONIC,
                      std::ptr::null_mut::<libc::sigevent>(), &raw mut id)
    };
    (r, id)
}

fn timer_settime(id: i32, spec: &Itimerspec) -> i64 {
    unsafe {
        libc::syscall(libc::SYS_timer_settime, id, 0, spec as *const Itimerspec,
                      std::ptr::null_mut::<Itimerspec>())
    }
}

fn timer_gettime(id: i32) -> (i64, Itimerspec) {
    let mut out = Itimerspec::default();
    let r = unsafe { libc::syscall(libc::SYS_timer_gettime, id, &raw mut out) };
    (r, out)
}

fn timer_delete(id: i32) -> i64 {
    unsafe { libc::syscall(libc::SYS_timer_delete, id) }
}

/// The second half of the exec test: re-executed with this argument, the
/// program checks that the timer its previous self made is gone.
fn after_exec() -> ! {
    // Any id at all: there should be no timers, so every one is EINVAL.
    let (r, _) = timer_gettime(0);
    let e = errno();
    let ok = r == -1 && e == libc::EINVAL;
    let (r2, _) = timer_gettime(1);
    let ok2 = r2 == -1 && errno() == libc::EINVAL;
    // And a fresh one gets the first id, which means the space is empty.
    let (cr, id) = timer_create();
    let ok3 = cr == 0 && id == 0;
    std::process::exit(if ok && ok2 && ok3 { 0 } else { 1 });
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--after-exec") {
        after_exec();
    }
    let mut h = Harness::new();

    h.group("setup");
    let (r, id) = timer_create();
    check!(h, r == 0, "timer_create: r={r} errno={}", errno());
    check!(h, id >= 0, "gives an id: {id}");
    // Long enough that it never fires during the test.
    let spec = Itimerspec { interval_sec: 0, interval_nsec: 0, value_sec: 3600, value_nsec: 0 };
    let r = timer_settime(id, &spec);
    check!(h, r == 0, "timer_settime: r={r} errno={}", errno());
    let (r, got) = timer_gettime(id);
    check!(h, r == 0 && got.value_sec > 3500, "and it is counting down: r={r} {}s", got.value_sec);

    h.group("a-child-has-none-of-them");
    let mut pipefd = [0i32; 2];
    check!(h, unsafe { libc::pipe(pipefd.as_mut_ptr()) } == 0, "a pipe");
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(pipefd[0]) };
        // Four answers: gettime and delete on the parent's id, then whether a
        // fresh timer here gets the first id.
        let (g, _) = timer_gettime(id);
        let ge = errno();
        let d = timer_delete(id);
        let de = errno();
        let (cr, mine) = timer_create();
        let out: [i32; 5] = [g as i32, ge, d as i32, de, if cr == 0 { mine } else { -99 }];
        unsafe { libc::write(pipefd[1], out.as_ptr().cast(), 20) };
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(pipefd[1]) };
    check!(h, pid > 0, "a child: pid={pid}");
    let mut got = [0i32; 5];
    let mut read_bytes = 0usize;
    while read_bytes < 20 {
        let n = unsafe {
            libc::read(pipefd[0], (got.as_mut_ptr() as *mut u8).add(read_bytes).cast(),
                       20 - read_bytes)
        };
        if n <= 0 {
            break;
        }
        read_bytes += n as usize;
    }
    unsafe { libc::close(pipefd[0]) };
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, read_bytes == 20, "which answers: got {read_bytes} bytes");
    if read_bytes == 20 {
        check!(h, got[0] == -1 && got[1] == libc::EINVAL,
            "timer_gettime on the parent's id is EINVAL in the child: r={} errno={}",
            got[0], got[1]);
        check!(h, got[2] == -1 && got[3] == libc::EINVAL,
            "and timer_delete: r={} errno={}", got[2], got[3]);
        check!(h, got[4] == 0,
            "and a timer made in the child gets the first id: {}", got[4]);
    } else {
        for _ in 0..3 {
            check!(h, false, "the child answered");
        }
    }

    h.group("and-the-parents-timer-is-untouched");
    // The check the child's EINVALs cannot make on their own: whatever the
    // child did, this timer is still here and still armed.
    let (r, got) = timer_gettime(id);
    check!(h, r == 0, "timer_gettime still works: r={r} errno={}", errno());
    check!(h, got.value_sec > 3500, "and it is still counting down: {}s", got.value_sec);
    let r = timer_delete(id);
    check!(h, r == 0, "and it can be deleted: r={r} errno={}", errno());
    let (r, _) = timer_gettime(id);
    check!(h, r == -1 && errno() == libc::EINVAL, "once, and then it is gone: r={r}");

    h.group("execve-clears-them");
    let (r, id) = timer_create();
    // Not asserted to be 0: Linux does not hand an id straight back after a
    // delete, the same way it does not hand a pid straight back. What the
    // exec'd program checks is that *its* first timer is id 0, which is the
    // space being empty rather than this one being reused.
    check!(h, r == 0, "a timer to leave behind: r={r} id={id} errno={}", errno());
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let exe = c"/proc/self/exe";
        let arg0 = c"posix_timer_fork";
        let arg1 = c"--after-exec";
        let argv = [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
        unsafe { libc::execv(exe.as_ptr(), argv.as_ptr()) };
        unsafe { libc::_exit(127) };
    }
    check!(h, pid > 0, "a child to exec: pid={pid}");
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    let code = if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { -1 };
    check!(h, code != 127, "/proc/self/exe is executable: status={st:#x}");
    check!(h, code == 0, "and the exec'd program has no timers: status={st:#x}");
    timer_delete(id);

    std::process::exit(h.finish());
}
