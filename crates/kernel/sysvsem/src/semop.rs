//! System V semaphore batch operations and waiting.

use super::*;
use std::time::Duration;

use plan::Op;
use strace::strace;
use usercopy::GuestMem;
use util_guestlock::Woke;

// -------------------------------------------------------------------- semop

pub fn sys_semop(id: i32, ops_addr: u64, nsops: u64) -> Result<(), Errno> {
    semop_inner(id, ops_addr, nsops, None)
}

/// `semtimedop`. The timeout is a `struct timespec` in guest memory, or null
/// for none -- which is exactly `semop`.
pub fn sys_semtimedop(
    id: i32,
    ops_addr: u64,
    nsops: u64,
    ts_addr: u64,
) -> Result<(), Errno> {
    let timeout = if ts_addr == 0 {
        None
    } else {
        let mut buf = [0u8; 16];
        if GuestMem.read(ts_addr, &mut buf) != 0 {
            return Err(Errno::EFAULT);
        }
        let secs = i64::from_le_bytes(buf[0..8].try_into().unwrap());
        let nanos = i64::from_le_bytes(buf[8..16].try_into().unwrap());
        if secs < 0 || !(0..1_000_000_000).contains(&nanos) {
            return Err(Errno::EINVAL);
        }
        Some(Duration::new(secs as u64, nanos as u32))
    };
    semop_inner(id, ops_addr, nsops, timeout)
}

fn semop_inner(
    id: i32,
    ops_addr: u64,
    nsops: u64,
    timeout: Option<Duration>,
) -> Result<(), Errno> {
    strace!("semop({id}, {ops_addr:#x}, {nsops})");
    let n = plan::check_nsops(nsops)?;
    let mut bytes = vec![0u8; n * plan::SEMBUF_LEN];
    if GuestMem.read(ops_addr, &mut bytes) != 0 {
        return Err(Errno::EFAULT);
    }
    let ops = plan::decode_ops(&bytes);
    // A batch that only waits for zeroes changes nothing and needs read; one
    // that adjusts anything needs write.
    let want = if plan::alters(&ops) {
        sysvipc::WRITE
    } else {
        sysvipc::READ
    };
    let set = find(id, want)?;
    let nowait = ops.iter().any(|o| o.flags & plan::IPC_NOWAIT_OP != 0);
    let pid = taskview::current_tgid();

    let mut s = set.state.lock();
    // The counters this caller adds to while it is parked, so the right one is
    // taken off again on every exit from the loop.
    let mut counted = false;
    loop {
        if s.removed {
            if counted {
                uncount(&mut s, &ops);
            }
            return Err(Errno::EIDRM);
        }
        let values: Vec<u16> = s.sems.iter().map(|x| x.value).collect();
        match plan::apply(&values, &ops) {
            Err(e) => {
                if counted {
                    uncount(&mut s, &ops);
                }
                return Err(e);
            }
            Ok(Some(next)) => {
                for (sem, v) in s.sems.iter_mut().zip(next) {
                    if sem.value != v {
                        sem.value = v;
                        sem.pid = pid;
                    }
                }
                s.otime = now();
                if counted {
                    uncount(&mut s, &ops);
                }
                super::undo::record_undo(id, &ops);
                drop(s);
                set.state.notify(CHANGED);
                return Ok(());
            }
            Ok(None) => {
                if nowait {
                    if counted {
                        uncount(&mut s, &ops);
                    }
                    return Err(Errno::EAGAIN);
                }
                if !counted {
                    count(&mut s, &ops);
                    counted = true;
                }
                match s.wait(CHANGED, timeout) {
                    Woke::Notified => {}
                    Woke::Interrupted => {
                        uncount(&mut s, &ops);
                        return Err(Errno::EINTR);
                    }
                    Woke::TimedOut => {
                        uncount(&mut s, &ops);
                        return Err(Errno::EAGAIN);
                    }
                }
            }
        }
    }
}

/// `GETNCNT` counts callers parked on a decrement and `GETZCNT` those parked on
/// a wait-for-zero. A batch with both is counted in both, which is what Linux
/// reports -- the caller really is waiting for each.
fn count(s: &mut SetState, ops: &[Op]) {
    if ops.iter().any(|o| o.op < 0) {
        s.ncnt += 1;
    }
    if ops.iter().any(|o| o.op == 0) {
        s.zcnt += 1;
    }
}

fn uncount(s: &mut SetState, ops: &[Op]) {
    if ops.iter().any(|o| o.op < 0) {
        s.ncnt = s.ncnt.saturating_sub(1);
    }
    if ops.iter().any(|o| o.op == 0) {
        s.zcnt = s.zcnt.saturating_sub(1);
    }
}
