//! System V semaphores: `semget`, `semctl`, `semop`, `semtimedop`.
//!
//! All four are `syscall_stub`, so `ipcs -s` says "kernel not configured for
//! semaphores" and anything that coordinates processes this way — the classic
//! shape for a daemon that must not start twice — cannot.
//!
//! A probe, not a test: it prints one line per case and never fails, and the
//! diff against a real arm64 kernel is what says what the rules are. The
//! interesting ones are not in `semop(2)`: what a `nsems` of zero does on a
//! *lookup* as against a create, which of `EEXIST` and `EINVAL` wins when a key
//! exists with the wrong size, and what `GETNCNT` counts.

use std::ffi::c_int;

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_EXCL: i32 = 0o2000;
const IPC_NOWAIT: i16 = 0o4000;
const IPC_RMID: i32 = 0;
const IPC_STAT: i32 = 2;
const GETPID: i32 = 11;
const GETVAL: i32 = 12;
const GETALL: i32 = 13;
const GETNCNT: i32 = 14;
const GETZCNT: i32 = 15;
const SETVAL: i32 = 16;
const SETALL: i32 = 17;
const SEM_UNDO: i16 = 0x1000;

#[repr(C)]
#[derive(Clone, Copy)]
struct Sembuf {
    sem_num: u16,
    sem_op: i16,
    sem_flg: i16,
}

fn semget(key: i32, nsems: i32, flags: i32) -> (i64, i32) {
    call(libc::SYS_semget, &[key as u64, nsems as u64, flags as u64])
}

fn semctl(id: i32, num: i32, cmd: i32, arg: u64) -> (i64, i32) {
    call(libc::SYS_semctl, &[id as u64, num as u64, cmd as u64, arg])
}

fn semop(id: i32, ops: &[Sembuf]) -> (i64, i32) {
    call(libc::SYS_semop, &[id as u64, ops.as_ptr() as u64, ops.len() as u64])
}

fn call(nr: libc::c_long, args: &[u64]) -> (i64, i32) {
    unsafe {
        *libc::__errno_location() = 0;
        let r = match args.len() {
            3 => libc::syscall(nr, args[0], args[1], args[2]),
            4 => libc::syscall(nr, args[0], args[1], args[2], args[3]),
            _ => unreachable!(),
        } as i64;
        (r, if r < 0 { *libc::__errno_location() } else { 0 })
    }
}

fn say(name: &str, (r, e): (i64, i32)) {
    if r < 0 {
        println!("{name} -> -1 {}", errname(e));
    } else {
        println!("{name} -> {r}");
    }
}

/// Like `say`, but for a call whose answer is an id -- which differs between
/// runs and between kernels, so only whether it worked is printable.
fn say_id(name: &str, (r, e): (i64, i32)) {
    if r < 0 {
        println!("{name} -> -1 {}", errname(e));
    } else {
        println!("{name} -> an id");
    }
}

fn errname(e: i32) -> String {
    match e {
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::EEXIST => "EEXIST",
        libc::EINVAL => "EINVAL",
        libc::EACCES => "EACCES",
        libc::EAGAIN => "EAGAIN",
        libc::ERANGE => "ERANGE",
        libc::E2BIG => "E2BIG",
        libc::EFBIG => "EFBIG",
        libc::EIDRM => "EIDRM",
        libc::ENOSPC => "ENOSPC",
        libc::ENOSYS => "ENOSYS",
        libc::EFAULT => "EFAULT",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn op(num: u16, o: i16, flg: i16) -> Sembuf {
    Sembuf { sem_num: num, sem_op: o, sem_flg: flg }
}

fn main() {
    println!("== semget ==");
    say_id("IPC_PRIVATE, 1 sem", semget(IPC_PRIVATE, 1, 0o600 | IPC_CREAT));
    say("nsems 0 on create", semget(IPC_PRIVATE, 0, 0o600 | IPC_CREAT));
    say("nsems -1", semget(IPC_PRIVATE, -1, 0o600 | IPC_CREAT));
    say("nsems 100000", semget(IPC_PRIVATE, 100_000, 0o600 | IPC_CREAT));
    say("a key nobody made, no IPC_CREAT", semget(0x5eab_0001u32 as i32, 1, 0o600));

    let key = 0x5eab_0002u32 as i32;
    // Left over from a previous run, on a kernel that keeps them.
    let (old, _) = semget(key, 0, 0);
    if old >= 0 {
        semctl(old as i32, 0, IPC_RMID, 0);
    }
    say_id("create a keyed set of 2", semget(key, 2, 0o600 | IPC_CREAT));
    say_id("the same key again", semget(key, 2, 0o600 | IPC_CREAT));
    say("with IPC_EXCL", semget(key, 2, 0o600 | IPC_CREAT | IPC_EXCL));
    // A lookup asking for more than the set has, and one asking for fewer:
    // Linux refuses the first and allows the second, which `semget(2)` states
    // only for the create case.
    say("look it up with nsems 3", semget(key, 3, 0));
    say("look it up with nsems 1", semget(key, 1, 0));
    say("look it up with nsems 0", semget(key, 0, 0));

    let (id, _) = semget(IPC_PRIVATE, 3, 0o600 | IPC_CREAT);
    let id = id as i32;
    println!("== semctl ==");
    say("GETVAL of a fresh semaphore", semctl(id, 0, GETVAL, 0));
    say("SETVAL 5", semctl(id, 0, SETVAL, 5));
    say("GETVAL after it", semctl(id, 0, GETVAL, 0));
    say("SETVAL -1", semctl(id, 0, SETVAL, -1i64 as u64));
    say("SETVAL 32768", semctl(id, 0, SETVAL, 32768));
    // `ksys_semctl` reads this argument as `int val = (int)arg;` -- the fourth
    // argument is a `union semun` whose `val` member is an `int`, so the top
    // half of the register is never part of the number. These two ask that of
    // a kernel rather than reading it: the first must be SETVAL 7 and the
    // second must be the same ERANGE as the plain `SETVAL -1` above.
    say("SETVAL (1 << 32) | 7", semctl(id, 0, SETVAL, (1u64 << 32) | 7));
    say("GETVAL after it", semctl(id, 0, GETVAL, 0));
    say("SETVAL (1 << 32) | 0xffff_ffff", semctl(id, 0, SETVAL, (1u64 << 32) | 0xffff_ffff));
    say("GETVAL after it", semctl(id, 0, GETVAL, 0));
    say("SETVAL 5 again", semctl(id, 0, SETVAL, 5));
    say("GETVAL of sem_num 3, of 3", semctl(id, 3, GETVAL, 0));
    say("GETVAL of sem_num -1", semctl(id, -1, GETVAL, 0));
    say("GETPID before any op", semctl(id, 0, GETPID, 0));
    say("GETNCNT", semctl(id, 0, GETNCNT, 0));
    say("GETZCNT", semctl(id, 0, GETZCNT, 0));

    let mut all = [0u16; 3];
    say("GETALL", semctl(id, 0, GETALL, all.as_mut_ptr() as u64));
    println!("  values {all:?}");
    let set = [7u16, 8, 9];
    say("SETALL", semctl(id, 0, SETALL, set.as_ptr() as u64));
    say("GETALL again", semctl(id, 0, GETALL, all.as_mut_ptr() as u64));
    println!("  values {all:?}");

    // semid_ds: the first field is an ipc_perm and the rest are times and a
    // count. Only sem_nsems is checked, at the offset the guest ABI puts it.
    let mut ds = [0u8; 128];
    say("IPC_STAT", semctl(id, 0, IPC_STAT, ds.as_mut_ptr() as u64));
    println!("  uid {} gid {} mode {:o}",
        u32::from_le_bytes(ds[4..8].try_into().unwrap()),
        u32::from_le_bytes(ds[8..12].try_into().unwrap()),
        u16::from_le_bytes(ds[24..26].try_into().unwrap()) & 0o777);
    say("an unknown cmd", semctl(id, 0, 999, 0));

    println!("== semop ==");
    say("acquire 1 of a semaphore worth 7", semop(id, &[op(0, -1, 0)]));
    say("GETVAL after it", semctl(id, 0, GETVAL, 0));
    say("release 1", semop(id, &[op(0, 1, 0)]));
    say("no operations at all", semop(id, &[]));
    say("wait for zero, not zero, NOWAIT", semop(id, &[op(0, 0, IPC_NOWAIT)]));
    say("acquire 100, NOWAIT", semop(id, &[op(0, -100, IPC_NOWAIT)]));
    say("sem_num past the end", semop(id, &[op(9, 1, 0)]));
    say("two ops, the second bad", semop(id, &[op(0, 1, 0), op(9, 1, 0)]));
    say("GETVAL after that pair", semctl(id, 0, GETVAL, 0));
    say("release past SEMVMX", semop(id, &[op(0, 32000, 0)]));
    say("GETVAL after the overflow", semctl(id, 0, GETVAL, 0));

    // SEM_UNDO: a process that exits without releasing has its adjustments
    // undone, which is the whole reason the flag exists -- a crashing daemon
    // otherwise leaves its lock held for ever.
    println!("== SEM_UNDO ==");
    let (u, _) = semget(IPC_PRIVATE, 1, 0o600 | IPC_CREAT);
    let u = u as i32;
    semctl(u, 0, SETVAL, 1);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (r, _) = semop(u, &[op(0, -1, SEM_UNDO)]);
        println!("  child acquired: {r}");
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    say("value after the child exited holding it", semctl(u, 0, GETVAL, 0));
    semctl(u, 0, IPC_RMID, 0);

    // And without the flag, which must *not* be undone.
    let (n, _) = semget(IPC_PRIVATE, 1, 0o600 | IPC_CREAT);
    let n = n as i32;
    semctl(n, 0, SETVAL, 1);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        semop(n, &[op(0, -1, 0)]);
        unsafe { libc::_exit(0) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    say("value with no SEM_UNDO", semctl(n, 0, GETVAL, 0));
    semctl(n, 0, IPC_RMID, 0);

    println!("== removal ==");
    say("IPC_RMID", semctl(id, 0, IPC_RMID, 0));
    say("GETVAL after removal", semctl(id, 0, GETVAL, 0));
    say("semop after removal", semop(id, &[op(0, 1, 0)]));
    say("IPC_RMID twice", semctl(id, 0, IPC_RMID, 0));
    say("an id nobody made", semctl(0x7fff_0000, 0, GETVAL, 0));
    say("a negative id", semctl(-1, 0, GETVAL, 0));

    // A waiter woken by the removal: EIDRM, not EINVAL, and it is the one
    // errno a caller must tell apart -- "somebody removed the thing you were
    // waiting on" against "you asked wrongly".
    println!("== a waiter and IPC_RMID ==");
    let (w, _) = semget(IPC_PRIVATE, 1, 0o600 | IPC_CREAT);
    let w = w as i32;
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (r, e) = semop(w, &[op(0, -1, 0)]);
        println!("  waiter woke: r={r} {}", if r < 0 { errname(e) } else { "ok".into() });
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::usleep(200_000) };
    say("GETNCNT with one waiter", semctl(w, 0, GETNCNT, 0));
    semctl(w, 0, IPC_RMID, 0);
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };

    // Tidy up whatever the earlier cases made, so a second run sees the same
    // kernel this one did.
    let (k, _) = semget(key, 0, 0);
    if k >= 0 {
        semctl(k as i32, 0, IPC_RMID, 0);
    }
    let _: c_int = 0;
}
