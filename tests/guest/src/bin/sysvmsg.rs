//! System V message queues, the parts a probe cannot assert: a receiver
//! blocking, a send that is not for it, and what a full queue does.
//!
//! `tests/guest/src/bin/sysvmsg_probe.rs` covers the answer table — every
//! argument shape and its errno — line by line against a real kernel. What is
//! here needs a second process and a clock.

use guest_tests::{Harness, check};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_NOWAIT: i32 = 0o4000;
const IPC_RMID: i32 = 0;
const IPC_STAT: i32 = 2;
const IPC_SET: i32 = 1;

fn msgget(key: i32, flags: i32) -> i64 {
    unsafe { libc::syscall(libc::SYS_msgget, key as u64, flags as u64) as i64 }
}

fn msgctl(id: i64, cmd: i32, buf: u64) -> i64 {
    unsafe { libc::syscall(libc::SYS_msgctl, id as u64, cmd as u64, buf) as i64 }
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
        let t = i64::from_le_bytes(buf[..8].try_into().unwrap());
        let n = if r > 0 { r as usize } else { 0 };
        (r, e, t, buf[8..8 + n.min(want)].to_vec())
    }
}

/// `msg_qnum` and `msg_cbytes` out of an `IPC_STAT`, at the offsets musl's
/// header puts them: 72 and 80.
fn counts(id: i64) -> (u64, u64) {
    let mut ds = [0u8; 120];
    if msgctl(id, IPC_STAT, ds.as_mut_ptr() as u64) != 0 {
        return (u64::MAX, u64::MAX);
    }
    (
        u64::from_le_bytes(ds[72..80].try_into().unwrap()),
        u64::from_le_bytes(ds[80..88].try_into().unwrap()),
    )
}

fn main() {
    let mut h = Harness::new();
    unsafe { libc::alarm(30) };

    h.group("a blocked receiver");

    let id = msgget(IPC_PRIVATE, 0o600 | IPC_CREAT);
    check!(h, id >= 0, "msgget IPC_PRIVATE: {id}");
    if id < 0 {
        std::process::exit(h.finish());
    }

    // A receiver waiting for type 7. A send of type 3 wakes it -- a send
    // cannot know which type anybody wanted -- and it must look again and park
    // rather than take what arrived. A kernel that hands the message to
    // whoever it woke gives it the wrong one, and the check that catches that
    // is the *second* one: the type 3 message is still in the queue.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (r, _, t, text) = msgrcv(id, 32, 7, 0);
        unsafe { libc::_exit(if r == 5 && t == 7 && text == b"right" { 0 } else { 1 }) };
    }
    unsafe { libc::usleep(300_000) };
    msgsnd(id, 3, b"wrong", 0);
    unsafe { libc::usleep(200_000) };
    check!(h, counts(id) == (5, 1), "the wrong type is queued and the receiver is still parked: {:?}", counts(id));
    msgsnd(id, 7, b"right", 0);
    let mut st = 0;
    let w = unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, w == pid && libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
        "and it takes the type it asked for: status={st:#x}");
    check!(h, counts(id) == (5, 1),
        "leaving the other one where it was: {:?}", counts(id));

    h.group("size and truncation");

    // E2BIG leaves the message; MSG_NOERROR takes it and drops the rest. The
    // asymmetry is the point -- one is retryable and the other is a choice.
    let (r, e, _, _) = msgrcv(id, 2, 3, IPC_NOWAIT);
    check!(h, r == -1 && e == libc::E2BIG, "a buffer that is too small is E2BIG: r={r} e={e}");
    check!(h, counts(id) == (5, 1), "and the message stays: {:?}", counts(id));
    let (r, _, t, text) = msgrcv(id, 2, 3, IPC_NOWAIT | 0o10000);
    check!(h, r == 2 && t == 3 && text == b"wr", "MSG_NOERROR truncates: r={r} {text:?}");
    check!(h, counts(id) == (0, 0), "and takes it: {:?}", counts(id));

    h.group("a full queue");

    // A queue whose limit is lowered to nothing takes no message. A sender
    // with IPC_NOWAIT gets EAGAIN; one without parks until there is room,
    // which here is a receive.
    let mut ds = [0u8; 120];
    msgctl(id, IPC_STAT, ds.as_mut_ptr() as u64);
    msgsnd(id, 1, b"0123456789", 0);
    // Lower msg_qbytes to exactly what is in the queue, so nothing more fits.
    ds[88..96].copy_from_slice(&10u64.to_le_bytes());
    let r = msgctl(id, IPC_SET, ds.as_mut_ptr() as u64);
    check!(h, r == 0, "IPC_SET lowers msg_qbytes: {r}");
    let (r, e) = msgsnd(id, 1, b"x", IPC_NOWAIT);
    check!(h, r == -1 && e == libc::EAGAIN, "a full queue with IPC_NOWAIT is EAGAIN: r={r} e={e}");

    // And a sender without it parks until a receive makes room.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (r, _) = msgsnd(id, 1, b"x", 0);
        unsafe { libc::_exit(if r == 0 { 0 } else { 1 }) };
    }
    unsafe { libc::usleep(300_000) };
    check!(h, counts(id).1 == 1, "the sender is parked, not queued: {:?}", counts(id));
    let (r, _, _, _) = msgrcv(id, 32, 0, 0);
    check!(h, r == 10, "a receive makes room: {r}");
    let mut st = 0;
    let w = unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, w == pid && libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
        "and the parked sender gets through: status={st:#x}");

    h.group("removal wakes waiters");

    let doomed = msgget(IPC_PRIVATE, 0o600 | IPC_CREAT);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let (r, e, _, _) = msgrcv(doomed, 32, 0, 0);
        unsafe { libc::_exit(if r == -1 && e == libc::EIDRM { 0 } else { 1 }) };
    }
    unsafe { libc::usleep(300_000) };
    msgctl(doomed, IPC_RMID, 0);
    let mut st = 0;
    let w = unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, w == pid && libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
        "a parked receiver woken by IPC_RMID answers EIDRM: status={st:#x}");

    h.group("keys");

    let key = 0x6eab_5555u32 as i32;
    let existing = msgget(key, 0);
    if existing >= 0 {
        msgctl(existing, IPC_RMID, 0);
    }
    let a = msgget(key, 0o600 | IPC_CREAT);
    msgsnd(a, 4, b"shared", 0);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // A child that never saw the id finds the queue by key and takes the
        // message the parent put there -- one object, not a copy.
        let b = msgget(key, 0);
        let (r, _, t, text) = msgrcv(b, 32, 0, IPC_NOWAIT);
        unsafe { libc::_exit(if b == a && r == 6 && t == 4 && text == b"shared" { 0 } else { 1 }) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    check!(h, libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
        "another process finds the queue by key and takes its message");
    check!(h, counts(a) == (0, 0), "which really left the queue: {:?}", counts(a));

    msgctl(a, IPC_RMID, 0);
    msgctl(id, IPC_RMID, 0);
    std::process::exit(h.finish());
}
