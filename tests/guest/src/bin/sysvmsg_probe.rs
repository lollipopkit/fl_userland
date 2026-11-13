//! System V message queues: `msgget`, `msgsnd`, `msgrcv`, `msgctl`.
//!
//! All four are `syscall_stub`, so `ipcs -q` says "kernel not configured for
//! message queues".
//!
//! A probe: one line per case, no assertions, and the diff against a real
//! arm64 kernel is the finding. The interesting questions are about the *type*
//! selector, which is the only part of this family that is not obvious — a
//! negative `msgtyp` does not mean what a first reading suggests, and
//! `MSG_EXCEPT` changes what a positive one means.

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_EXCL: i32 = 0o2000;
const IPC_NOWAIT: i32 = 0o4000;
const IPC_RMID: i32 = 0;
const IPC_STAT: i32 = 2;
const MSG_NOERROR: i32 = 0o10000;
const MSG_EXCEPT: i32 = 0o20000;

fn msgget(key: i32, flags: i32) -> (i64, i32) {
    call3(libc::SYS_msgget, key as u64, flags as u64, 0)
}

fn msgctl(id: i64, cmd: i32, buf: u64) -> (i64, i32) {
    call3(libc::SYS_msgctl, id as u64, cmd as u64, buf)
}

fn msgsnd(id: i64, mtype: i64, text: &[u8], flags: i32) -> (i64, i32) {
    let mut buf = Vec::with_capacity(8 + text.len());
    buf.extend_from_slice(&mtype.to_le_bytes());
    buf.extend_from_slice(text);
    unsafe {
        *libc::__errno_location() = 0;
        let r = libc::syscall(
            libc::SYS_msgsnd,
            id as u64,
            buf.as_ptr() as u64,
            text.len() as u64,
            flags as u64,
        ) as i64;
        (r, if r < 0 { *libc::__errno_location() } else { 0 })
    }
}

/// Answers `(result, errno, mtype, text)`.
fn msgrcv(id: i64, want: usize, msgtyp: i64, flags: i32) -> (i64, i32, i64, Vec<u8>) {
    let mut buf = vec![0u8; 8 + want];
    unsafe {
        *libc::__errno_location() = 0;
        let r = libc::syscall(
            libc::SYS_msgrcv,
            id as u64,
            buf.as_mut_ptr() as u64,
            want as u64,
            msgtyp as u64,
            flags as u64,
        ) as i64;
        let e = if r < 0 { *libc::__errno_location() } else { 0 };
        let mtype = i64::from_le_bytes(buf[..8].try_into().unwrap());
        let n = if r > 0 { r as usize } else { 0 };
        (r, e, mtype, buf[8..8 + n.min(want)].to_vec())
    }
}

fn call3(nr: libc::c_long, a: u64, b: u64, c: u64) -> (i64, i32) {
    unsafe {
        *libc::__errno_location() = 0;
        let r = libc::syscall(nr, a, b, c) as i64;
        (r, if r < 0 { *libc::__errno_location() } else { 0 })
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
        libc::E2BIG => "E2BIG",
        libc::ENOMSG => "ENOMSG",
        libc::EIDRM => "EIDRM",
        libc::EFAULT => "EFAULT",
        libc::ENOSYS => "ENOSYS",
        libc::EINTR => "EINTR",
        _ => return format!("errno {e}"),
    }
    .to_string()
}

fn say(name: &str, (r, e): (i64, i32)) {
    if r < 0 {
        println!("{name} -> -1 {}", errname(e));
    } else {
        println!("{name} -> {r}");
    }
}

fn say_id(name: &str, (r, e): (i64, i32)) {
    if r < 0 {
        println!("{name} -> -1 {}", errname(e));
    } else {
        println!("{name} -> an id");
    }
}

fn say_rcv(name: &str, (r, e, mtype, text): (i64, i32, i64, Vec<u8>)) {
    if r < 0 {
        println!("{name} -> -1 {}", errname(e));
    } else {
        println!("{name} -> {r} type={mtype} {:?}", String::from_utf8_lossy(&text));
    }
}

fn main() {
    println!("== msgget ==");
    say_id("IPC_PRIVATE", msgget(IPC_PRIVATE, 0o600 | IPC_CREAT));
    say("a key nobody made, no IPC_CREAT", msgget(0x6eab_0001u32 as i32, 0o600));

    let key = 0x6eab_0002u32 as i32;
    let (old, _) = msgget(key, 0);
    if old >= 0 {
        msgctl(old, IPC_RMID, 0);
    }
    say_id("create by key", msgget(key, 0o600 | IPC_CREAT));
    say_id("the same key again", msgget(key, 0o600 | IPC_CREAT));
    say("with IPC_EXCL", msgget(key, 0o600 | IPC_CREAT | IPC_EXCL));
    let (kid, _) = msgget(key, 0);
    msgctl(kid, IPC_RMID, 0);

    let (id, _) = msgget(IPC_PRIVATE, 0o600 | IPC_CREAT);

    println!("== msgsnd ==");
    say("type 1, 5 bytes", msgsnd(id, 1, b"hello", 0));
    say("type 0", msgsnd(id, 0, b"x", 0));
    say("type -1", msgsnd(id, -1, b"x", 0));
    say("zero-length text", msgsnd(id, 2, b"", 0));
    say("a very long message", msgsnd(id, 3, &vec![b'x'; 9000], 0));

    println!("== msgrcv, the type selector ==");
    // The queue holds: type 1 "hello", type 2 "".
    say_rcv("msgtyp 0, first in the queue", msgrcv(id, 32, 0, 0));
    say("send type 5", msgsnd(id, 5, b"five", 0));
    say("send type 3", msgsnd(id, 3, b"three", 0));
    say("send type 9", msgsnd(id, 9, b"nine", 0));
    // The queue now holds: 2 "", 5 "five", 3 "three", 9 "nine".
    say_rcv("msgtyp 5, that exact type", msgrcv(id, 32, 5, 0));
    // A *negative* msgtyp is not "any but this": it is "the lowest type that
    // is <= |msgtyp|", which is the priority queue this family is for.
    say_rcv("msgtyp -4, the lowest <= 4", msgrcv(id, 32, -4, 0));
    say_rcv("msgtyp -1, the lowest <= 1", msgrcv(id, 32, -1, IPC_NOWAIT));
    say_rcv("MSG_EXCEPT with msgtyp 9", msgrcv(id, 32, 9, MSG_EXCEPT | IPC_NOWAIT));
    say_rcv("msgtyp 9 without it", msgrcv(id, 32, 9, 0));
    say_rcv("an empty queue, NOWAIT", msgrcv(id, 32, 0, IPC_NOWAIT));
    say_rcv("type nobody sent, NOWAIT", msgrcv(id, 32, 77, IPC_NOWAIT));

    println!("== msgrcv, the size ==");
    say("send 10 bytes", msgsnd(id, 1, b"0123456789", 0));
    say_rcv("ask for 4 of them", msgrcv(id, 4, 0, 0));
    say_rcv("ask for 4 with MSG_NOERROR", msgrcv(id, 4, 0, MSG_NOERROR));
    say("send 10 again", msgsnd(id, 1, b"0123456789", 0));
    say_rcv("ask for 4 with MSG_NOERROR", msgrcv(id, 4, 0, MSG_NOERROR));
    say_rcv("the queue after the truncation", msgrcv(id, 32, 0, IPC_NOWAIT));

    println!("== msgctl ==");
    say("send one to count", msgsnd(id, 1, b"abc", 0));
    let mut ds = [0u8; 128];
    say("IPC_STAT", msgctl(id, IPC_STAT, ds.as_mut_ptr() as u64));
    println!("  mode {:o} cbytes {} qnum {} qbytes {}",
        u32::from_le_bytes(ds[20..24].try_into().unwrap()) & 0o777,
        u64::from_le_bytes(ds[72..80].try_into().unwrap()),
        u64::from_le_bytes(ds[80..88].try_into().unwrap()),
        u64::from_le_bytes(ds[88..96].try_into().unwrap()));
    say("an unknown cmd", msgctl(id, 999, 0));

    println!("== removal ==");
    say("IPC_RMID", msgctl(id, IPC_RMID, 0));
    say_rcv("msgrcv after it", msgrcv(id, 32, 0, IPC_NOWAIT));
    say("msgsnd after it", msgsnd(id, 1, b"x", 0));
    say("IPC_RMID twice", msgctl(id, IPC_RMID, 0));
    say("an id nobody made", msgctl(0x7fff_0000, IPC_STAT, ds.as_mut_ptr() as u64));

    println!("== a blocked receiver and IPC_RMID ==");
    let (w, _) = msgget(IPC_PRIVATE, 0o600 | IPC_CREAT);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (r, e, _, _) = msgrcv(w, 32, 0, 0);
        println!("  receiver woke: r={r} {}", if r < 0 { errname(e) } else { "ok".into() });
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::usleep(200_000) };
    msgctl(w, IPC_RMID, 0);
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };

    println!("== a blocked receiver and a send ==");
    let (v, _) = msgget(IPC_PRIVATE, 0o600 | IPC_CREAT);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (r, e, t, text) = msgrcv(v, 32, 7, 0);
        if r < 0 {
            println!("  receiver: -1 {}", errname(e));
        } else {
            println!("  receiver: {r} type={t} {:?}", String::from_utf8_lossy(&text));
        }
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::usleep(200_000) };
    // A type it is not waiting for, then the one it is: a kernel that wakes on
    // any message and does not recheck the type hands it the wrong one.
    msgsnd(v, 3, b"wrong", 0);
    unsafe { libc::usleep(100_000) };
    msgsnd(v, 7, b"right", 0);
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    say_rcv("and the one it did not want is still there", msgrcv(v, 32, 0, IPC_NOWAIT));
    msgctl(v, IPC_RMID, 0);
}
