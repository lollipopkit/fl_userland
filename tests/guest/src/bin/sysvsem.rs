//! System V semaphores, the parts a probe cannot assert: blocking, waking,
//! atomicity across two processes, and `SEM_UNDO`.
//!
//! `tests/guest/src/bin/sysvsem_probe.rs` covers the answer table — every
//! argument shape and what errno it gets — and is compared against a real
//! kernel line by line. What is here is the behaviour *between* processes,
//! which needs a second process and a clock and so is a test rather than a
//! probe.

use guest_tests::{Harness, check};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_NOWAIT: i16 = 0o4000;
const IPC_RMID: i32 = 0;
const GETVAL: i32 = 12;
const GETNCNT: i32 = 14;
const SETVAL: i32 = 16;
const SEM_UNDO: i16 = 0x1000;

#[repr(C)]
#[derive(Clone, Copy)]
struct Sembuf {
    sem_num: u16,
    sem_op: i16,
    sem_flg: i16,
}

fn semget(key: i32, nsems: i32, flags: i32) -> i64 {
    unsafe { libc::syscall(libc::SYS_semget, key as u64, nsems as u64, flags as u64) as i64 }
}

fn semctl(id: i64, num: i32, cmd: i32, arg: u64) -> i64 {
    unsafe { libc::syscall(libc::SYS_semctl, id as u64, num as u64, cmd as u64, arg) as i64 }
}

fn semop(id: i64, ops: &[Sembuf]) -> (i64, i32) {
    unsafe {
        *libc::__errno_location() = 0;
        let r = libc::syscall(libc::SYS_semop, id as u64, ops.as_ptr() as u64, ops.len() as u64)
            as i64;
        (r, if r < 0 { *libc::__errno_location() } else { 0 })
    }
}

fn op(num: u16, o: i16, flg: i16) -> Sembuf {
    Sembuf { sem_num: num, sem_op: o, sem_flg: flg }
}

fn main() {
    let mut h = Harness::new();
    // Every wait here is one another process ends; a kernel that never wakes
    // would otherwise hang the suite rather than fail a check.
    unsafe { libc::alarm(30) };

    // ------------------------------------------------------------- blocking
    h.group("blocking");

    let id = semget(IPC_PRIVATE, 1, 0o600 | IPC_CREAT);
    check!(h, id >= 0, "semget IPC_PRIVATE: {id}");
    if id < 0 {
        std::process::exit(h.finish());
    }

    // A child parks on a semaphore worth nothing; the parent sees it counted,
    // releases, and the child gets through. The count is the load-bearing
    // part: without it a kernel that answered EAGAIN instead of blocking would
    // pass a test that only checked the child finished.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (r, _) = semop(id, &[op(0, -1, 0)]);
        unsafe { libc::_exit(if r == 0 { 0 } else { 1 }) };
    }
    unsafe { libc::usleep(300_000) };
    check!(h, semctl(id, 0, GETNCNT, 0) == 1, "one caller is parked on the decrement");
    check!(h, semctl(id, 0, GETVAL, 0) == 0, "and the value is still zero");
    semop(id, &[op(0, 1, 0)]);
    let mut st = 0;
    let w = unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, w == pid && libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
        "the release wakes it: status={st:#x}");
    check!(h, semctl(id, 0, GETVAL, 0) == 0, "and it took the value: {}", semctl(id, 0, GETVAL, 0));
    check!(h, semctl(id, 0, GETNCNT, 0) == 0, "nobody is parked any more");

    // ------------------------------------------------------------ atomicity
    h.group("atomicity");

    // Two semaphores, one available. A batch that wants both must take
    // *neither* -- which is what makes `semop` a way to lock two things
    // without deadlocking, and what a loop of single operations cannot do.
    let two = semget(IPC_PRIVATE, 2, 0o600 | IPC_CREAT);
    semctl(two, 0, SETVAL, 1);
    semctl(two, 1, SETVAL, 0);
    let (r, e) = semop(two, &[op(0, -1, IPC_NOWAIT), op(1, -1, IPC_NOWAIT)]);
    check!(h, r == -1 && e == libc::EAGAIN, "a batch that cannot complete is refused: r={r} e={e}");
    check!(h, semctl(two, 0, GETVAL, 0) == 1,
        "and the one it *could* have taken is untouched: {}", semctl(two, 0, GETVAL, 0));

    // The same batch once both are available takes both.
    semctl(two, 1, SETVAL, 1);
    let (r, _) = semop(two, &[op(0, -1, 0), op(1, -1, 0)]);
    check!(h, r == 0, "and succeeds once both are: {r}");
    check!(h, semctl(two, 0, GETVAL, 0) == 0 && semctl(two, 1, GETVAL, 0) == 0,
        "with both taken");
    semctl(two, 0, IPC_RMID, 0);

    // --------------------------------------------------------------- undo
    h.group("SEM_UNDO");

    // The reason the family is still used for locking: a process that dies
    // holding one does not leave it held.
    semctl(id, 0, SETVAL, 1);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        semop(id, &[op(0, -1, SEM_UNDO)]);
        // Killed rather than exiting cleanly, because "it crashed" is the case
        // this exists for.
        unsafe { libc::raise(libc::SIGKILL) };
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, semctl(id, 0, GETVAL, 0) == 1,
        "a killed process gives its semaphore back: {}", semctl(id, 0, GETVAL, 0));

    // And without the flag it does not, which is the other half: a caller that
    // did not ask for the undo must not get one.
    semctl(id, 0, SETVAL, 1);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        semop(id, &[op(0, -1, 0)]);
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, semctl(id, 0, GETVAL, 0) == 0,
        "and one that did not ask for it keeps the semaphore held: {}",
        semctl(id, 0, GETVAL, 0));

    // An acquire and a release with SEM_UNDO cancel, so nothing is given back
    // twice. A kernel that recorded only the acquire would raise the value on
    // exit past where it started.
    semctl(id, 0, SETVAL, 1);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        semop(id, &[op(0, -1, SEM_UNDO)]);
        semop(id, &[op(0, 1, SEM_UNDO)]);
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, semctl(id, 0, GETVAL, 0) == 1,
        "an acquire and a release cancel rather than adding: {}", semctl(id, 0, GETVAL, 0));

    // ------------------------------------------------------------ removal
    h.group("removal wakes waiters");

    // A blocked caller woken by IPC_RMID answers EIDRM, which is the one errno
    // it must be able to tell from EINVAL: "somebody removed what you were
    // waiting on" against "you asked wrongly".
    let doomed = semget(IPC_PRIVATE, 1, 0o600 | IPC_CREAT);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (r, e) = semop(doomed, &[op(0, -1, 0)]);
        unsafe { libc::_exit(if r == -1 && e == libc::EIDRM { 0 } else { 1 }) };
    }
    unsafe { libc::usleep(300_000) };
    check!(h, semctl(doomed, 0, GETNCNT, 0) == 1, "the waiter is parked");
    semctl(doomed, 0, IPC_RMID, 0);
    let mut st = 0;
    let w = unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, w == pid && libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
        "and IPC_RMID wakes it with EIDRM: status={st:#x}");

    // ------------------------------------------------------------ the key
    h.group("keys");

    // Two processes finding the same set by key is the whole point of a key.
    let key = 0x5eab_7777u32 as i32;
    let existing = semget(key, 0, 0);
    if existing >= 0 {
        semctl(existing, 0, IPC_RMID, 0);
    }
    let a = semget(key, 1, 0o600 | IPC_CREAT);
    check!(h, a >= 0, "create by key: {a}");
    semctl(a, 0, SETVAL, 3);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // A child that never saw the id finds it by key, and sees the value
        // the parent set -- so it is one object and not a copy.
        let b = semget(key, 1, 0);
        let v = semctl(b, 0, GETVAL, 0);
        unsafe { libc::_exit(if b == a && v == 3 { 0 } else { 1 }) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
        "another process finds the same set by key and sees its value");
    semctl(a, 0, IPC_RMID, 0);
    semctl(id, 0, IPC_RMID, 0);

    std::process::exit(h.finish());
}
