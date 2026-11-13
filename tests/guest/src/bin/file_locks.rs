//! File locking, between processes.
//!
//! `crates/fs/locks` carries unit tests for the range algebra, but the part that
//! decides whether a database opens is the part unit tests cannot see: who
//! owns a lock, who conflicts with whom, and when it goes away. SQLite takes
//! byte-range locks on three fixed offsets of every database file and reads
//! the answer as "another connection has this"; getting the ownership rule
//! wrong does not make it slow, it makes it wrong.
//!
//! Three mechanisms, with three different ownership rules, and Linux keeps
//! them independent of each other:
//!
//! | | owner | released by |
//! | --- | --- | --- |
//! | `flock` | the open file description | closing the last descriptor for it |
//! | `fcntl` record locks | the **process** | closing *any* descriptor for the file |
//! | `F_OFD_*` record locks | the open file description | closing the last descriptor for it |
//!
//! The middle one is the POSIX misfeature that OFD locks exist to replace, and
//! it has to be reproduced rather than improved on: a program that opens the
//! same file twice and closes one copy expects its locks gone.

use guest_tests::{Harness, check, sys};

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

const F_OFD_GETLK: i32 = 36;
const F_OFD_SETLK: i32 = 37;

fn flock_arg(typ: i16, start: i64, len: i64) -> libc::flock {
    let mut f: libc::flock = unsafe { std::mem::zeroed() };
    f.l_type = typ;
    f.l_whence = libc::SEEK_SET as i16;
    f.l_start = start;
    f.l_len = len;
    f
}

/// Take, or test for, a record lock. Returns 0, or -1 with errno set.
fn setlk(fd: i32, cmd: i32, typ: i16, start: i64, len: i64) -> i32 {
    let mut f = flock_arg(typ, start, len);
    unsafe { libc::fcntl(fd, cmd, &mut f) }
}

/// F_GETLK: what would block this lock? Returns the reported l_type.
fn getlk(fd: i32, cmd: i32, typ: i16, start: i64, len: i64) -> Option<(i16, i32)> {
    let mut f = flock_arg(typ, start, len);
    (unsafe { libc::fcntl(fd, cmd, &mut f) } == 0).then_some((f.l_type, f.l_pid))
}

/// Run `body` in a child and give back its exit code.
fn in_child(body: impl FnOnce() -> i32) -> i32 {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            let code = body();
            libc::_exit(code);
        }
        if pid < 0 {
            return -1;
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        }
    }
}

fn make(path: &str) -> i32 {
    unsafe { libc::unlink(cstr(path).as_ptr()) };
    let fd = unsafe {
        libc::open(cstr(path).as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600)
    };
    if fd >= 0 {
        sys::write(fd, &[0u8; 4096]);
    }
    fd
}

fn t_flock_between_processes(h: &mut Harness, dir: &str) {
    h.group("flock");
    let path = format!("{dir}/lock-flock");
    let fd = make(&path);
    if fd < 0 {
        check!(h, false, "creating {path}");
        return;
    }

    check!(
        h,
        unsafe { libc::flock(fd, libc::LOCK_EX) } == 0,
        "taking an exclusive flock"
    );
    // A child inherits the descriptor, and so the same open file description:
    // its flock is the *same* lock, not a conflicting one.
    let code = in_child(|| {
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 { 0 } else { 1 }
    });
    check!(
        h,
        code == 0,
        "the inherited description holds the same lock, not a conflicting one"
    );
    // A child that opens the file itself has its own description, and conflicts.
    let p = path.clone();
    let code = in_child(move || {
        let own = unsafe { libc::open(cstr(&p).as_ptr(), libc::O_RDWR, 0) };
        if own < 0 {
            return 2;
        }
        let r = unsafe { libc::flock(own, libc::LOCK_EX | libc::LOCK_NB) };
        let e = sys::errno();
        unsafe { libc::close(own) };
        if r == 0 { 0 } else if e == libc::EWOULDBLOCK { 1 } else { 3 }
    });
    check!(
        h,
        code == 1,
        "a separate open conflicts and answers EWOULDBLOCK, got {code}"
    );

    // A shared lock lets other shared locks in.
    check!(h, unsafe { libc::flock(fd, libc::LOCK_SH) } == 0, "downgrading to shared");
    let p = path.clone();
    let code = in_child(move || {
        let own = unsafe { libc::open(cstr(&p).as_ptr(), libc::O_RDWR, 0) };
        let shared = unsafe { libc::flock(own, libc::LOCK_SH | libc::LOCK_NB) } == 0;
        let excl = unsafe { libc::flock(own, libc::LOCK_EX | libc::LOCK_NB) } == 0;
        unsafe { libc::close(own) };
        match (shared, excl) {
            (true, false) => 0,
            (true, true) => 1,
            _ => 2,
        }
    });
    check!(
        h,
        code == 0,
        "shared admits shared and excludes exclusive, got {code}"
    );

    // Unlocking releases it.
    check!(h, unsafe { libc::flock(fd, libc::LOCK_UN) } == 0, "unlocking");
    let p = path.clone();
    let code = in_child(move || {
        let own = unsafe { libc::open(cstr(&p).as_ptr(), libc::O_RDWR, 0) };
        let r = unsafe { libc::flock(own, libc::LOCK_EX | libc::LOCK_NB) };
        unsafe { libc::close(own) };
        i32::from(r != 0)
    });
    check!(h, code == 0, "and the file is free again");

    // Closing releases it too.
    unsafe { libc::flock(fd, libc::LOCK_EX) };
    sys::close(fd);
    let p = path.clone();
    let code = in_child(move || {
        let own = unsafe { libc::open(cstr(&p).as_ptr(), libc::O_RDWR, 0) };
        let r = unsafe { libc::flock(own, libc::LOCK_EX | libc::LOCK_NB) };
        unsafe { libc::close(own) };
        i32::from(r != 0)
    });
    check!(h, code == 0, "closing the descriptor releases the flock");
    unsafe { libc::unlink(cstr(&path).as_ptr()) };
}

fn t_record_locks_between_processes(h: &mut Harness, dir: &str) {
    h.group("fcntl-locks");
    let path = format!("{dir}/lock-record");
    let fd = make(&path);
    if fd < 0 {
        check!(h, false, "creating {path}");
        return;
    }

    // A write lock on [0, 10).
    check!(
        h,
        setlk(fd, libc::F_SETLK, libc::F_WRLCK as i16, 0, 10) == 0,
        "taking a write lock on [0,10)"
    );
    // Ranges that do not overlap are free; the one that does is not.
    let p = path.clone();
    let code = in_child(move || {
        let own = unsafe { libc::open(cstr(&p).as_ptr(), libc::O_RDWR, 0) };
        if own < 0 {
            return 9;
        }
        let clear = setlk(own, libc::F_SETLK, libc::F_WRLCK as i16, 10, 10) == 0;
        let overlap = setlk(own, libc::F_SETLK, libc::F_WRLCK as i16, 5, 10);
        let e = sys::errno();
        unsafe { libc::close(own) };
        if !clear {
            return 1;
        }
        if overlap == 0 {
            return 2;
        }
        if e != libc::EAGAIN && e != libc::EACCES {
            return 3;
        }
        0
    });
    check!(
        h,
        code == 0,
        "another process: a clear range is free, an overlapping one is EAGAIN, got {code}"
    );

    // A read lock does not conflict with another read lock.
    check!(
        h,
        setlk(fd, libc::F_SETLK, libc::F_UNLCK as i16, 0, 10) == 0,
        "releasing the write lock"
    );
    check!(
        h,
        setlk(fd, libc::F_SETLK, libc::F_RDLCK as i16, 0, 10) == 0,
        "taking a read lock"
    );
    let p = path.clone();
    let code = in_child(move || {
        let own = unsafe { libc::open(cstr(&p).as_ptr(), libc::O_RDWR, 0) };
        let shared = setlk(own, libc::F_SETLK, libc::F_RDLCK as i16, 0, 10) == 0;
        let excl = setlk(own, libc::F_SETLK, libc::F_WRLCK as i16, 0, 10) == 0;
        unsafe { libc::close(own) };
        match (shared, excl) {
            (true, false) => 0,
            (true, true) => 1,
            _ => 2,
        }
    });
    check!(
        h,
        code == 0,
        "read locks share and exclude a write lock, got {code}"
    );

    // F_GETLK reports the holder rather than taking anything.
    let p = path.clone();
    let mine = unsafe { libc::getpid() };
    let code = in_child(move || {
        let own = unsafe { libc::open(cstr(&p).as_ptr(), libc::O_RDWR, 0) };
        // Testing for a write lock over the range the parent read-locked.
        let got = getlk(own, libc::F_GETLK, libc::F_WRLCK as i16, 0, 10);
        unsafe { libc::close(own) };
        match got {
            Some((t, pid)) if t == libc::F_RDLCK as i16 && pid == mine => 0,
            Some((t, pid)) if t == libc::F_RDLCK as i16 => {
                // The type is right; the pid is the part worth knowing about.
                println!("  NOTE F_GETLK reported pid {pid}, wanted {mine}");
                4
            }
            Some((t, _)) if t == libc::F_UNLCK as i16 => 1,
            Some(_) => 2,
            None => 3,
        }
    });
    check!(
        h,
        code == 0,
        "F_GETLK names the conflicting lock's type and holder, got {code}"
    );

    // The POSIX rule: closing *any* descriptor for the file drops this
    // process's locks on it.
    let second = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_RDWR, 0) };
    check!(h, second >= 0, "opening the same file a second time");
    sys::close(second);
    let p = path.clone();
    let code = in_child(move || {
        let own = unsafe { libc::open(cstr(&p).as_ptr(), libc::O_RDWR, 0) };
        let r = setlk(own, libc::F_SETLK, libc::F_WRLCK as i16, 0, 10);
        unsafe { libc::close(own) };
        i32::from(r != 0)
    });
    check!(
        h,
        code == 0,
        "closing a second descriptor for the file drops the process's record locks"
    );

    sys::close(fd);
    unsafe { libc::unlink(cstr(&path).as_ptr()) };
}

fn t_ofd_locks(h: &mut Harness, dir: &str) {
    h.group("ofd-locks");
    let path = format!("{dir}/lock-ofd");
    let a = make(&path);
    if a < 0 {
        check!(h, false, "creating {path}");
        return;
    }
    let b = unsafe { libc::open(cstr(&path).as_ptr(), libc::O_RDWR, 0) };
    if b < 0 {
        check!(h, false, "opening it a second time");
        return;
    }

    // An OFD lock is owned by the description, so two descriptions in the
    // *same* process conflict — which is the whole reason they exist.
    let mut f = flock_arg(libc::F_WRLCK as i16, 0, 10);
    let took = unsafe { libc::fcntl(a, F_OFD_SETLK, &mut f) };
    if took != 0 && sys::errno() == libc::EINVAL {
        println!("  SKIP  [ofd-locks] F_OFD_SETLK is not supported");
        sys::close(a);
        sys::close(b);
        unsafe { libc::unlink(cstr(&path).as_ptr()) };
        return;
    }
    check!(h, took == 0, "taking an OFD write lock");

    let mut f = flock_arg(libc::F_WRLCK as i16, 0, 10);
    let r = unsafe { libc::fcntl(b, F_OFD_SETLK, &mut f) };
    check!(
        h,
        r != 0 && (sys::errno() == libc::EAGAIN || sys::errno() == libc::EACCES),
        "a second description in the same process conflicts: r={r} errno {}",
        sys::errno()
    );

    // Which a plain POSIX lock would not have done.
    let mut f = flock_arg(libc::F_WRLCK as i16, 20, 10);
    check!(
        h,
        unsafe { libc::fcntl(a, F_OFD_SETLK, &mut f) } == 0,
        "a clear range is still free"
    );

    // F_OFD_GETLK reports it, with l_pid of -1 for a lock the caller does not
    // own — that is how Linux says "this is an OFD lock".
    let mut f = flock_arg(libc::F_WRLCK as i16, 0, 10);
    let r = unsafe { libc::fcntl(b, F_OFD_GETLK, &mut f) };
    check!(
        h,
        r == 0 && f.l_type == libc::F_WRLCK as i16,
        "F_OFD_GETLK reports the conflict: r={r} type={}",
        f.l_type
    );

    // Closing the holder's description releases it.
    sys::close(a);
    let mut f = flock_arg(libc::F_WRLCK as i16, 0, 10);
    check!(
        h,
        unsafe { libc::fcntl(b, F_OFD_SETLK, &mut f) } == 0,
        "closing the owning description releases the OFD lock"
    );
    sys::close(b);
    unsafe { libc::unlink(cstr(&path).as_ptr()) };
}

/// flock and fcntl locks are separate mechanisms on Linux and do not see each
/// other. A program that takes one and expects the other to notice is wrong,
/// but so is an implementation that makes them conflict.
fn t_mechanisms_are_independent(h: &mut Harness, dir: &str) {
    h.group("independent");
    let path = format!("{dir}/lock-both");
    let fd = make(&path);
    if fd < 0 {
        check!(h, false, "creating {path}");
        return;
    }
    check!(
        h,
        unsafe { libc::flock(fd, libc::LOCK_EX) } == 0,
        "an exclusive flock"
    );
    let p = path.clone();
    let code = in_child(move || {
        let own = unsafe { libc::open(cstr(&p).as_ptr(), libc::O_RDWR, 0) };
        // A record lock is a different mechanism: it must not see the flock.
        let r = setlk(own, libc::F_SETLK, libc::F_WRLCK as i16, 0, 10);
        unsafe { libc::close(own) };
        i32::from(r != 0)
    });
    check!(
        h,
        code == 0,
        "a record lock does not see an flock, got {code}"
    );
    sys::close(fd);
    unsafe { libc::unlink(cstr(&path).as_ptr()) };
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp".into());
    unsafe { libc::mkdir(cstr(&dir).as_ptr(), 0o755) };
    let mut h = Harness::new();
    t_flock_between_processes(&mut h, &dir);
    t_record_locks_between_processes(&mut h, &dir);
    t_ofd_locks(&mut h, &dir);
    t_mechanisms_are_independent(&mut h, &dir);
    std::process::exit(h.finish());
}
