//! Sending what a notification fired, once the queue's lock is dropped.

use kernel_mqueue::Delivery;
use kernel_pids::{PidsGuard, TaskRef};

use crate::ffi;

/// `SI_MESGQ`.
const SI_MESGQ: i32 = -3;

/// The calling process, as a reference a reused pid does not match: its
/// group leader, which is where a process-directed signal is addressed.
pub(crate) fn leader_ref() -> Option<TaskRef> {
    let pids = PidsGuard::take();
    let pid = pids.me()?.group()?.leader_pid();
    pids.refer(pid)
}

/// The `siginfo` Linux's `__do_notify` sends: `SI_MESGQ`, the sender's tgid
/// and real uid -- the process whose send fired it, not the owner -- and the
/// registration's `sigev_value`. `_rt`'s layout: pid at 16, uid at 20, the
/// value at 24.
fn mesgq_info(signo: i32, value: u64) -> ffi::siginfo_ {
    let pid = taskview::current_tgid();
    let uid = taskview::with_current_creds(|c| c.uid()).unwrap_or(0);
    let mut b = [0u8; 128];
    b[0..4].copy_from_slice(&signo.to_le_bytes());
    b[8..12].copy_from_slice(&SI_MESGQ.to_le_bytes());
    b[16..20].copy_from_slice(&pid.to_le_bytes());
    b[20..24].copy_from_slice(&uid.to_le_bytes());
    b[24..32].copy_from_slice(&value.to_le_bytes());
    ffi::siginfo_::from_le_bytes(&b)
}

pub(crate) fn deliver(d: Delivery<fs_fdobj::Owned>) {
    match d {
        Delivery::Signal { to, signo, value } => {
            let info = mesgq_info(signo, value);
            let pids = PidsGuard::take();
            // Gone is nobody to tell: Linux's `pid_task` answers NULL and the
            // signal is not sent.
            if let Some(leader) = pids.find_by_ref(to) {
                signaldeliver::send_process_signal(leader, signo, info);
            }
        }
        Delivery::Datagram { sock, cookie } => {
            // A full socket loses it, as Linux's receive queue past its limit
            // does; there is nobody to report the failure to.
            let _ = fs_sock::netlink_deliver(&sock, &cookie);
            drop(sock);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_value_is_where_sigval_is() {
        let mut b = [0u8; 128];
        b[24..32].copy_from_slice(&0x1234_5678_9abcu64.to_le_bytes());
        let info = ffi::siginfo_::from_le_bytes(&b);
        // `_rt.si_sigval` sits after pid and uid. The union has no `_rt`
        // member here; `_timer`'s value is at the same offset, which is what
        // a guest's `si_value` reads either way.
        assert_eq!(unsafe { info.__bindgen_anon_1.timer.value.sv_ptr }, 0x1234_5678_9abc);
    }
}
