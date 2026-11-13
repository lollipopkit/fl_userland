//! Message queue send and receive operations.

use super::*;
use util_guestlock::Woke;

// ------------------------------------------------------------------- msgsnd

pub fn sys_msgsnd(id: i32, msgp: u64, msgsz: u64, flags: c_int) -> Result<(), Errno> {
    strace!("msgsnd({id}, {msgp:#x}, {msgsz}, {flags:#o})");
    // The type is the first eight bytes of the caller's buffer and the text
    // follows it; `msgsz` counts the text alone.
    let size = plan::check_recv_size(msgsz)?;
    let mut head = [0u8; 8];
    if GuestMem.read(msgp, &mut head) != 0 {
        return Err(Errno::EFAULT);
    }
    let mtype = i64::from_le_bytes(head);
    plan::check_send(mtype, size)?;
    let mut text = vec![0u8; size];
    if size > 0 && GuestMem.read(msgp + 8, &mut text) != 0 {
        return Err(Errno::EFAULT);
    }

    let q = find(id, sysvipc::WRITE)?;
    let nowait = flags & sysvipc::IPC_NOWAIT != 0;
    let pid = taskview::current_tgid();
    let mut s = q.state.lock();
    loop {
        if s.removed {
            return Err(Errno::EIDRM);
        }
        if plan::fits(size, s.cbytes, s.msgs.len(), s.qbytes) {
            s.cbytes += size;
            s.msgs.push_back(Msg { mtype, text });
            s.stime = now();
            s.lspid = pid;
            drop(s);
            // Every parked receiver, because a send cannot know which of them
            // wanted this type. See the module comment.
            q.state.notify(CHANGED);
            return Ok(());
        }
        if nowait {
            return Err(Errno::EAGAIN);
        }
        match s.wait(CHANGED, None) {
            Woke::Notified => {}
            Woke::Interrupted => return Err(Errno::EINTR),
            Woke::TimedOut => return Err(Errno::EAGAIN),
        }
    }
}

// ------------------------------------------------------------------- msgrcv

pub fn sys_msgrcv(
    id: i32,
    msgp: u64,
    msgsz: u64,
    msgtyp: i64,
    flags: c_int,
) -> Result<i64, Errno> {
    strace!("msgrcv({id}, {msgp:#x}, {msgsz}, {msgtyp}, {flags:#o})");
    let want = plan::check_recv_size(msgsz)?;
    let q = find(id, sysvipc::READ)?;
    let nowait = flags & sysvipc::IPC_NOWAIT != 0;
    let except = flags & plan::MSG_EXCEPT != 0;
    let truncate = flags & plan::MSG_NOERROR != 0;
    let pid = taskview::current_tgid();

    let mut s = q.state.lock();
    loop {
        if s.removed {
            return Err(Errno::EIDRM);
        }
        let types: Vec<i64> = s.msgs.iter().map(|m| m.mtype).collect();
        if let Some(i) = plan::select(&types, msgtyp, except) {
            // Too big *before* it is taken: E2BIG leaves the message where it
            // was, so a caller can ask again with a larger buffer. The whole
            // difference from MSG_NOERROR is which of those two happens.
            if s.msgs[i].text.len() > want && !truncate {
                return Err(Errno::E2BIG);
            }
            let msg = s.msgs.remove(i).expect("the index came from this queue");
            s.cbytes -= msg.text.len();
            s.rtime = now();
            s.lrpid = pid;
            drop(s);
            let n = msg.text.len().min(want);
            let mut out = Vec::with_capacity(8 + n);
            out.extend_from_slice(&msg.mtype.to_le_bytes());
            out.extend_from_slice(&msg.text[..n]);
            if GuestMem.write(msgp, &out) != 0 {
                // The message is gone. Linux loses it the same way -- it is
                // dequeued before the copy and the copy's failure is reported
                // without putting it back.
                return Err(Errno::EFAULT);
            }
            // A send may have been waiting for the room this made.
            q.state.notify(CHANGED);
            return Ok(n as i64);
        }
        if nowait {
            return Err(Errno::ENOMSG);
        }
        match s.wait(CHANGED, None) {
            Woke::Notified => {}
            Woke::Interrupted => return Err(Errno::EINTR),
            Woke::TimedOut => return Err(Errno::ENOMSG),
        }
    }
}
