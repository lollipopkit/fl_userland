//! The wire formats, the limits and the name rules.
//!
//! Every number here was measured against an arm64 Linux 7.2 kernel by
//! `tests/guest/src/bin/mqueue_probe.rs`, not read off `mq_overview(7)`.

use guest_errno::Errno;

// ------------------------------------------------------------------ limits

/// `/proc/sys/fs/mqueue/msg_max`: the most messages an unprivileged creator
/// may ask for.
pub const MSG_MAX: i64 = 10;
/// `/proc/sys/fs/mqueue/msgsize_max`.
pub const MSGSIZE_MAX: i64 = 8192;
/// `/proc/sys/fs/mqueue/msg_default`: `mq_maxmsg` for a create with no attr.
pub const MSG_DEFAULT: i64 = 10;
/// `/proc/sys/fs/mqueue/msgsize_default`.
pub const MSGSIZE_DEFAULT: i64 = 8192;
/// `/proc/sys/fs/mqueue/queues_max`: live queues, unlinked-but-open ones
/// included, before an unprivileged create is `ENOSPC`.
pub const QUEUES_MAX: usize = 256;
/// `HARD_MSGMAX` and `HARD_MSGSIZEMAX`: the ceiling `CAP_SYS_RESOURCE` raises
/// the two above to.
pub const HARD_MSGMAX: i64 = 65536;
pub const HARD_MSGSIZEMAX: i64 = 16 << 20;
/// `MQ_PRIO_MAX`: a priority is below this.
pub const PRIO_MAX: u32 = 32768;
/// A name's longest, which is `NAME_MAX`: the queue is a directory entry.
pub const NAME_MAX: usize = 255;
/// `PATH_MAX`: what `getname` copies before it gives up.
pub const PATH_MAX: usize = 4096;
/// `MQUEUE_MAGIC`, which `fstatfs` reports.
pub const MQUEUE_MAGIC: u32 = 0x1980_0202;
/// `FILENT_SIZE`: a fresh queue's `st_size`, and the length of the buffer its
/// status line is formatted into.
pub const FILENT_SIZE: i64 = 80;

/// What one queue is charged against `RLIMIT_MSGQUEUE`, or why it cannot be
/// created at all.
///
/// Linux's `mqueue_get_inode`: the message bytes plus one `struct msg_msg`
/// per message and one `struct posix_msg_tree_node` per possible priority
/// level, both 48 bytes on arm64. The 48s are not read off a header: the
/// probe fills the limit with nine default queues (82880 bytes each) and finds
/// that a tenth of `10 x 7232` fits and `10 x 7233` does not, which is
/// `9 * 82880 + 72320 + 480 + 480 = 819200` exactly.
///
/// `privileged` is `CAP_SYS_RESOURCE`, which this kernel reads as the
/// effective uid being 0.
pub fn charge(maxmsg: i64, msgsize: i64, privileged: bool) -> Result<u64, Errno> {
    const MSG_MSG: u64 = 48;
    const TREE_NODE: u64 = 48;
    if maxmsg <= 0 || msgsize <= 0 {
        return Err(Errno::EINVAL);
    }
    let (max, size) = if privileged {
        (HARD_MSGMAX, HARD_MSGSIZEMAX)
    } else {
        (MSG_MAX, MSGSIZE_MAX)
    };
    if maxmsg > max || msgsize > size {
        return Err(Errno::EINVAL);
    }
    // Both are bounded above, so neither product can overflow; Linux's two
    // `EOVERFLOW` checks are for limits a sysctl raised, which this has none
    // of.
    let (m, s) = (maxmsg as u64, msgsize as u64);
    Ok(m * s + m * MSG_MSG + m.min(PRIO_MAX as u64) * TREE_NODE)
}

// ----------------------------------------------------------------- names

/// The name `mq_open` and `mq_unlink` resolve, as `getname` and
/// `lookup_noperm` judge it.
///
/// The syscall's name has no leading `/`: musl and glibc strip it, and the
/// kernel refuses one. In the order Linux asks:
///
/// - `getname`: an empty name is `ENOENT` (one that does not fit in
///   `PATH_MAX` is `ENAMETOOLONG`, which is the string copy's to say);
/// - `lookup_noperm`: a `/` anywhere, `.` and `..` are `EACCES`;
/// - `mqueue_lookup`: longer than `NAME_MAX` is `ENAMETOOLONG`.
///
/// `name` is what the guest's string held, without its terminator.
pub fn check_name(name: &[u8]) -> Result<(), Errno> {
    if name.is_empty() {
        return Err(Errno::ENOENT);
    }
    if name.contains(&b'/') || name == b"." || name == b".." {
        return Err(Errno::EACCES);
    }
    if name.len() > NAME_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(())
}

// ------------------------------------------------------------- mq_attr

/// `struct mq_attr`: eight `long`s, of which four mean something. Copied
/// whole in both directions, which is measured: an attr with only its first
/// 32 bytes readable is `EFAULT`, so is an `omqstat` with 32 writable.
pub const ATTR_LEN: usize = 64;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Attr {
    pub flags: i64,
    pub maxmsg: i64,
    pub msgsize: i64,
    pub curmsgs: i64,
}

impl Attr {
    pub fn decode(b: &[u8; ATTR_LEN]) -> Attr {
        let at = |i: usize| i64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        Attr { flags: at(0), maxmsg: at(1), msgsize: at(2), curmsgs: at(3) }
    }

    /// The reserved words are zero.
    pub fn encode(&self) -> [u8; ATTR_LEN] {
        let mut b = [0u8; ATTR_LEN];
        for (i, v) in [self.flags, self.maxmsg, self.msgsize, self.curmsgs].iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        b
    }
}

// ------------------------------------------------------------ sigevent

/// `struct sigevent`: 64 bytes, copied whole (`EFAULT` with 16 readable).
pub const SIGEVENT_LEN: usize = 64;

pub const SIGEV_SIGNAL: i32 = 0;
pub const SIGEV_NONE: i32 = 1;
pub const SIGEV_THREAD: i32 = 2;

/// `NOTIFY_COOKIE_LEN`: what `SIGEV_THREAD` copies from `sigev_value` and
/// sends back on the netlink socket, with its last byte overwritten.
pub const COOKIE_LEN: usize = 32;
/// The last byte of the cookie: a message arrived, or the registration went.
pub const NOTIFY_WOKENUP: u8 = 1;
pub const NOTIFY_REMOVED: u8 = 2;

/// `_NSIG`: `valid_signal` accepts `0..=64`, 0 included. A `SIGEV_SIGNAL`
/// registration with signal 0 is accepted, consumed by the first message, and
/// sends nothing -- measured, and Linux's own comment asks why.
pub const NSIG: i32 = 64;

/// The three fields of a `sigevent` this reads: `sigev_value` (8 bytes),
/// `sigev_signo`, `sigev_notify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sigevent {
    pub value: u64,
    pub signo: i32,
    pub notify: i32,
}

impl Sigevent {
    pub fn decode(b: &[u8; SIGEVENT_LEN]) -> Sigevent {
        Sigevent {
            value: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            signo: i32::from_le_bytes(b[8..12].try_into().unwrap()),
            notify: i32::from_le_bytes(b[12..16].try_into().unwrap()),
        }
    }

    /// `do_mq_notify`'s first two refusals, both `EINVAL` and both before the
    /// descriptor is looked up: an unknown `sigev_notify` (`SIGEV_THREAD_ID`
    /// among them) and a `SIGEV_SIGNAL` whose signal is outside `0..=64`.
    pub fn check(&self) -> Result<(), Errno> {
        match self.notify {
            SIGEV_NONE | SIGEV_THREAD => Ok(()),
            SIGEV_SIGNAL if (0..=NSIG).contains(&self.signo) => Ok(()),
            _ => Err(Errno::EINVAL),
        }
    }
}

// --------------------------------------------------------- status line

/// What `read` on the descriptor answers, from `mqueue_read_file`:
///
/// ```c
/// "QSIZE:%-10lu NOTIFY:%-5d SIGNO:%-5d NOTIFY_PID:%-6d\n"
/// ```
///
/// `QSIZE` is the bytes queued, not the messages. `NOTIFY` is the
/// registration's `sigev_notify`, so `SIGEV_SIGNAL` and no registration both
/// print 0; `SIGNO` only for `SIGEV_SIGNAL`.
pub fn status_line(qsize: u64, notify: Option<(i32, i32, i32)>) -> String {
    let (how, signo, pid) = match notify {
        Some((how, signo, pid)) => (how, if how == SIGEV_SIGNAL { signo } else { 0 }, pid),
        None => (0, 0, 0),
    };
    format!("QSIZE:{qsize:<10} NOTIFY:{how:<5} SIGNO:{signo:<5} NOTIFY_PID:{pid:<6}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe's measured charges: nine default queues fit in 819200 and
    /// ten do not; a tenth of `10 x 7232` fills it to the byte.
    #[test]
    fn the_charge_is_the_kernels() {
        let one = charge(MSG_DEFAULT, MSGSIZE_DEFAULT, false).unwrap();
        assert_eq!(one, 82880);
        assert_eq!(9 * one + charge(10, 7232, false).unwrap(), 819200);
        assert!(9 * one + charge(10, 7233, false).unwrap() > 819200);
    }

    #[test]
    fn the_limits_are_the_kernels() {
        assert_eq!(charge(0, 1, false), Err(Errno::EINVAL));
        assert_eq!(charge(1, 0, false), Err(Errno::EINVAL));
        assert_eq!(charge(-1, 1, false), Err(Errno::EINVAL));
        assert_eq!(charge(11, 1, false), Err(Errno::EINVAL));
        assert_eq!(charge(1, 8193, false), Err(Errno::EINVAL));
        assert!(charge(11, 8193, true).is_ok());
        assert_eq!(charge(65537, 1, true), Err(Errno::EINVAL));
        assert_eq!(charge(1, (16 << 20) + 1, true), Err(Errno::EINVAL));
        assert_eq!(charge(i64::MIN, 1, true), Err(Errno::EINVAL));
    }

    #[test]
    fn names_are_judged_in_linuxs_order() {
        assert_eq!(check_name(b"q"), Ok(()));
        assert_eq!(check_name(b"..."), Ok(()));
        assert_eq!(check_name(b""), Err(Errno::ENOENT));
        assert_eq!(check_name(b"/q"), Err(Errno::EACCES));
        assert_eq!(check_name(b"a/b"), Err(Errno::EACCES));
        assert_eq!(check_name(b"."), Err(Errno::EACCES));
        assert_eq!(check_name(b".."), Err(Errno::EACCES));
        assert_eq!(check_name(&[b'n'; 255]), Ok(()));
        assert_eq!(check_name(&[b'n'; 256]), Err(Errno::ENAMETOOLONG));
        // A slash beats the length: EACCES comes from the lookup, which runs
        // before the filesystem's own length check.
        let mut long = vec![b'n'; 300];
        long[0] = b'/';
        assert_eq!(check_name(&long), Err(Errno::EACCES));
    }

    #[test]
    fn an_attr_round_trips_and_drops_the_reserved_words() {
        let a = Attr { flags: 0o4000, maxmsg: 3, msgsize: 7, curmsgs: 2 };
        let mut b = a.encode();
        assert_eq!(Attr::decode(&b), a);
        b[40] = 9;
        assert_eq!(Attr::decode(&b), a);
        assert_eq!(&a.encode()[32..], &[0u8; 32]);
    }

    #[test]
    fn a_sigevent_is_checked_as_do_mq_notify_checks_it() {
        let ev = |notify, signo| Sigevent { value: 0, signo, notify };
        assert_eq!(ev(SIGEV_NONE, 65).check(), Ok(()));
        assert_eq!(ev(SIGEV_SIGNAL, 0).check(), Ok(()));
        assert_eq!(ev(SIGEV_SIGNAL, 64).check(), Ok(()));
        assert_eq!(ev(SIGEV_SIGNAL, 65).check(), Err(Errno::EINVAL));
        assert_eq!(ev(SIGEV_SIGNAL, -1).check(), Err(Errno::EINVAL));
        assert_eq!(ev(3, 0).check(), Err(Errno::EINVAL));
        assert_eq!(ev(4, 10).check(), Err(Errno::EINVAL), "SIGEV_THREAD_ID");
        let mut b = [0u8; SIGEVENT_LEN];
        b[..8].copy_from_slice(&0x1234u64.to_le_bytes());
        b[8..12].copy_from_slice(&12i32.to_le_bytes());
        b[12..16].copy_from_slice(&SIGEV_SIGNAL.to_le_bytes());
        assert_eq!(Sigevent::decode(&b), Sigevent { value: 0x1234, signo: 12, notify: 0 });
    }

    /// The probe's lines, byte for byte.
    #[test]
    fn the_status_line_is_the_kernels() {
        assert_eq!(
            status_line(0, None),
            "QSIZE:0          NOTIFY:0     SIGNO:0     NOTIFY_PID:0     \n"
        );
        assert_eq!(
            status_line(8, Some((SIGEV_SIGNAL, 12, 77))),
            "QSIZE:8          NOTIFY:0     SIGNO:12    NOTIFY_PID:77    \n"
        );
        assert_eq!(
            status_line(0, Some((SIGEV_THREAD, 5, 77))),
            "QSIZE:0          NOTIFY:2     SIGNO:0     NOTIFY_PID:77    \n"
        );
        assert_eq!(status_line(0, None).len(), 60);
    }
}
