//! The pseudoterminal pair.
//!
//! A master is made by opening `/dev/ptmx`; making one makes its slave too, and
//! the master holds one user of it. So the slave always outlives the master,
//! and the master's teardown hangs the slave up — which is what makes every
//! operation naming the master unreachable afterwards.

use crate::tty::{self, Kind, Tty};
use std::ffi::c_int;
use std::sync::Arc;
use ttyreg::{ATTR_GID, ATTR_MODE, ATTR_UID};

/// The mode a slave's node in `/dev/pts` gets. `grantpt` is a no-op here
/// because the node is made with the right owner in the first place.
const SLAVE_MODE: u32 = 0o620;

/// Make the slave for a master that has just been created and link the two.
pub(crate) fn make_pair(master: &Arc<Tty>) -> Result<(), c_int> {
    debug_assert_eq!(master.kind, Kind::PtyMaster);
    let slave = new_slave(master.num);
    if !tty::publish_slave(&slave) {
        return Err(tty::ENOMEM);
    }
    link(master, &slave);
    Ok(())
}

fn new_slave(num: c_int) -> Arc<Tty> {
    let slave = crate::tty::make(Kind::PtySlave, num);
    // The node's owner and mode, kept beside the number in the registry rather
    // than inside the terminal: /dev/pts asks for them by number, and putting
    // them here meant reading three integers under two locks.
    let (uid, gid) = crate::ops::caller_ids();
    tty::pty_set_attrs(num, uid, gid, SLAVE_MODE);
    slave
}

fn link(master: &Arc<Tty>, slave: &Arc<Tty>) {
    crate::tty::link_pair(master, slave);
}

/// Undo [`make_pair`] for a master whose creation failed after it.
pub(crate) fn unmake_pair(master: &Arc<Tty>) {
    if master.kind != Kind::PtyMaster {
        return;
    }
    if let Some(slave) = master.other() {
        crate::tty::unlink_pair(master, &slave);
        tty::unpublish_slave(&slave);
    }
}

/// The last user of `tty` has gone.
pub fn cleanup(tty_: &Arc<Tty>) {
    match tty_.kind {
        // The master holds a user of its slave, so a slave's last user goes
        // after its master has: there is no other end left to tell. It hung
        // that master up until 2026-11-12, which for an embedder's terminal --
        // the one slave with no master -- reached nothing and otherwise reached
        // a master already gone.
        Kind::PtySlave => {}
        Kind::PtyMaster => {
            let Some(slave) = tty_.other() else {
                return;
            };
            crate::tty::hangup(&slave);
            crate::tty::unlink_pair(tty_, &slave);
            // The user the master took when it made the slave.
            crate::tty::release(&slave);
        }
        Kind::Console => {}
    }
}

/// `posix_openpt`: reserve a number, make the master, and hand it back.
pub fn open_master() -> Result<tty::User, c_int> {
    let num = tty::reserve_pty().ok_or(tty::ENOSPC)?;
    match tty::User::get(Kind::PtyMaster, num) {
        Ok(master) => Ok(master),
        Err(error) => {
            // Without this a failed creation left the number reserved for the
            // life of the process, and enough of them exhausted the table.
            tty::release_pty_reservation(num);
            Err(error)
        }
    }
}

/// Opening a slave: refused while the master has not unlocked it, and refused
/// outright once the master is gone.
///
/// An embedder's terminal has no master and is never locked: it is published
/// at `/dev/pts/<number>` precisely so a guest can open it.
pub fn open_slave(slave: &Arc<Tty>) -> c_int {
    if crate::tty::is_external(slave) {
        return if slave.is_external_closed() { tty::EIO } else { 0 };
    }
    if slave.other().is_none() {
        return tty::EIO;
    }
    let state = slave.lock();
    if state.locked {
        return tty::EIO;
    }
    // TIOCEXCL, which CAP_SYS_ADMIN opens past (`tty_open`).
    if state.exclusive && !crate::ops::task().sys_admin() {
        return tty::EBUSY;
    }
    0
}

/// A terminal an embedder collects the output of, published at
/// `/dev/pts/<number>` so the guest can open it as its session's console.
pub(crate) fn open_external(write: crate::tty::ExternalWrite) -> Result<tty::User, c_int> {
    let num = tty::reserve_pty().ok_or(tty::ENOSPC)?;
    let terminal = crate::tty::make_external(num, write);
    // The user the caller is given, rather than the one a master would hold.
    terminal.retain();
    if !crate::tty::publish_external(&terminal) {
        tty::release_pty_reservation(num);
        return Err(tty::ENOMEM);
    }
    let (uid, gid) = crate::ops::caller_ids();
    tty::pty_set_attrs(num, uid, gid, SLAVE_MODE);
    Ok(tty::User::adopt(terminal))
}

/// The four ioctls that are a master's own rather than the pair's.
pub(crate) fn master_ioctl(master: &Arc<Tty>, cmd: c_int, arg: &mut u32) -> c_int {
    let slave = master.other();
    // Everything but the packet-mode pair reaches through the slave.
    if slave.is_none() && cmd != TIOCPKT && cmd != TIOCGPKT {
        return tty::EIO;
    }
    match cmd {
        TIOCSPTLCK => {
            slave.expect("checked above").lock().locked = *arg != 0;
            0
        }
        TIOCGPTN => {
            *arg = slave.expect("checked above").num as u32;
            0
        }
        TIOCPKT => {
            master.lock().packet_mode = *arg != 0;
            0
        }
        TIOCGPKT => {
            *arg = master.lock().packet_mode as u32;
            0
        }
        _ => tty::ENOTTY,
    }
}

pub const TIOCSPTLCK: c_int = 0x40045431u32 as c_int;
pub const TIOCGPTN: c_int = 0x80045430u32 as c_int;
pub const TIOCPKT: c_int = 0x5420;
pub const TIOCGPKT: c_int = 0x80045438u32 as c_int;

/// The ownership and mode of a slave's node, for `/dev/pts`.
pub fn set_attr(num: c_int, which: c_int, value: u32) -> bool {
    match which {
        ATTR_UID | ATTR_GID | ATTR_MODE => tty::pty_set_attr(num, which, value),
        _ => false,
    }
}

pub fn attrs(num: c_int) -> Option<(u32, u32, u32)> {
    tty::pty_attrs(num)
}

pub fn exists(num: c_int) -> bool {
    tty::pty_exists(num)
}

pub fn next(from: c_int) -> Option<c_int> {
    tty::pty_next(from)
}

