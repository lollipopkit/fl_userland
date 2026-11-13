//! Host readiness backend and transition batching.

use std::ptr;

use libc::{c_int, c_void};

use crate::{DescriptionId, ERR, HUP, HostInterest, PRI, RDHUP, READ, WRITE};

use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use rustix::fs::OFlags;
use rustix::io::FdFlags;

const EMPTY_TRANSITION: (DescriptionId, u32) = (
    DescriptionId {
        slot: u32::MAX,
        generation: 0,
    },
    0,
);

pub(crate) struct TransitionBatch {
    entries: [(DescriptionId, u32); 32],
    len: usize,
}

impl TransitionBatch {
    fn new() -> Self {
        Self {
            entries: [EMPTY_TRANSITION; 32],
            len: 0,
        }
    }

    fn push(&mut self, transition: (DescriptionId, u32)) {
        self.entries[self.len] = transition;
        self.len += 1;
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (DescriptionId, u32)> + '_ {
        self.entries[..self.len].iter().copied()
    }
}

/// The kqueue and the pipe that wakes it.
///
/// Three `OwnedFd`s since 2026-09-29, where they were three `RawFd`s and a
/// `Drop` that closed each one it judged real -- `fd > 2`, a guard against a
/// descriptor number that was never set, which an `OwnedFd` cannot be. The
/// three failure paths in `new` each closed what had been made so far by
/// hand; they return now, and what was made closes as it drops.
pub(crate) struct Backend {
    pub(crate) fd: OwnedFd,
    notify_read: OwnedFd,
    notify_write: OwnedFd,
}

/// A host errno as the guest's.
fn guest(e: rustix::io::Errno) -> c_int {
    kernel_errno::map(e.raw_os_error()).guest
}

/// An empty `kevent` for a buffer the kernel fills, where the buffers were
/// `mem::zeroed`.
const NO_EVENT: libc::kevent = libc::kevent {
    ident: 0,
    filter: 0,
    flags: 0,
    fflags: 0,
    data: 0,
    udata: ptr::null_mut(),
};

impl Backend {
    pub(crate) fn new() -> Result<Self, c_int> {
        let fd = rustix::event::kqueue::kqueue().map_err(guest)?;
        let (notify_read, notify_write) = rustix::pipe::pipe().map_err(guest)?;
        for end in [&notify_read, &notify_write] {
            // Best effort, as it always was: a pipe that stays blocking only
            // makes `wake` and `drain_notify` wait, and the descriptor is
            // this process's either way.
            let _ = rustix::fs::fcntl_setfl(end, OFlags::NONBLOCK);
            let _ = rustix::io::fcntl_setfd(end, FdFlags::CLOEXEC);
        }
        let notify_token = DescriptionId {
            slot: u32::MAX,
            generation: u32::MAX,
        };
        let change =
            Self::change(libc::EVFILT_READ, libc::EV_ADD, notify_read.as_raw_fd(), notify_token);
        // SAFETY: one change from a local, no event buffer, no timeout.
        if unsafe { libc::kevent(fd.as_raw_fd(), &change, 1, ptr::null_mut(), 0, ptr::null()) } < 0 {
            return Err(kernel_errno::map(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            )
            .guest);
        }
        Ok(Self {
            fd,
            notify_read,
            notify_write,
        })
    }

    fn change(filter: i16, flags: u16, host_fd: RawFd, token: DescriptionId) -> libc::kevent {
        libc::kevent {
            ident: host_fd as usize,
            filter,
            flags,
            fflags: 0,
            data: 0,
            udata: ((u64::from(token.generation) << 32) | u64::from(token.slot)) as usize
                as *mut c_void,
        }
    }

    pub(crate) fn update(
        &self,
        host_fd: RawFd,
        interest: HostInterest,
        token: DescriptionId,
    ) -> c_int {
        if interest.events == 0 {
            self.remove(host_fd);
            return 0;
        }
        let edge = if interest.edge { libc::EV_CLEAR } else { 0 };
        let changes = [
            Self::change(
                libc::EVFILT_READ,
                if interest.events & (READ | HUP) != 0 {
                    libc::EV_ADD | libc::EV_RECEIPT | edge
                } else {
                    libc::EV_DELETE | libc::EV_RECEIPT
                },
                host_fd,
                token,
            ),
            Self::change(
                libc::EVFILT_WRITE,
                if interest.events & WRITE != 0 {
                    libc::EV_ADD | libc::EV_RECEIPT | edge
                } else {
                    libc::EV_DELETE | libc::EV_RECEIPT
                },
                host_fd,
                token,
            ),
            Self::change(
                libc::EVFILT_EXCEPT,
                if interest.events & PRI != 0 {
                    libc::EV_ADD | libc::EV_RECEIPT | edge
                } else {
                    libc::EV_DELETE | libc::EV_RECEIPT
                },
                host_fd,
                token,
            ),
        ];
        let mut receipts = [NO_EVENT; 3];
        let count = unsafe {
            libc::kevent(
                self.fd.as_raw_fd(),
                changes.as_ptr(),
                changes.len() as c_int,
                receipts.as_mut_ptr(),
                receipts.len() as c_int,
                ptr::null(),
            )
        };
        if count < 0 {
            return kernel_errno::map(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
                .guest;
        }
        for index in 0..count as usize {
            let receipt = receipts[index];
            let change = changes[index];
            let error = receipt.data as c_int;
            if receipt.flags & libc::EV_ERROR == 0 || error == 0 {
                continue;
            }
            // EVFILT_EXCEPT is not supported for every descriptor kind. Its
            // failure only removes requested EPOLLPRI coverage; READ/WRITE
            // filters still provide ordinary readiness and always ERR/HUP.
            if change.flags & libc::EV_ADD == 0
                || change.filter == libc::EVFILT_EXCEPT
                || (change.filter == libc::EVFILT_WRITE && error == libc::EINVAL)
            {
                continue;
            }
            self.remove(host_fd);
            return kernel_errno::map(error).guest;
        }
        0
    }

    /// Collect the host transitions, waiting up to `timeout` for the first.
    ///
    /// A `Duration` rather than milliseconds since 2026-11-11, for
    /// `epoll_pwait2`'s nanosecond timeout: kevent takes a `timespec`, and
    /// converting through milliseconds would make a 300 us wait 1 ms. No caller
    /// waits for ever -- the wait loop bounds each pass to notice signals -- so
    /// there is no `None`.
    pub(crate) fn drain(&self, timeout: std::time::Duration) -> Result<TransitionBatch, c_int> {
        let mut raw = [NO_EVENT; 32];
        let timeout = libc::timespec {
            tv_sec: timeout.as_secs().min(i64::MAX as u64) as i64,
            tv_nsec: i64::from(timeout.subsec_nanos()),
        };
        let count = unsafe {
            libc::kevent(
                self.fd.as_raw_fd(),
                ptr::null(),
                0,
                raw.as_mut_ptr(),
                raw.len() as c_int,
                &timeout,
            )
        };
        if count < 0 {
            return Err(kernel_errno::map(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            )
            .guest);
        }
        let mut events = TransitionBatch::new();
        for event in raw.into_iter().take(count as usize) {
            let token = event.udata as usize as u64;
            if token == u64::MAX {
                // The notification pipe mirrors Core's durable ready queue. It
                // stays readable until the queue becomes empty; observing the
                // backend token is not itself a reason to clear that state.
                continue;
            }
            if event.flags & libc::EV_ERROR != 0 && event.data != 0 {
                // Asynchronous registration failures are errors, never byte
                // counts or ordinary readiness for the filter they arrived on.
                events.push((
                    DescriptionId {
                        slot: token as u32,
                        generation: (token >> 32) as u32,
                    },
                    ERR,
                ));
                continue;
            }
            let eof = event.flags & libc::EV_EOF != 0;
            let types = if event.filter == libc::EVFILT_READ {
                (if event.data > 0 { READ } else { 0 }) | if eof { HUP | RDHUP } else { 0 }
            } else if event.filter == libc::EVFILT_WRITE {
                // On Darwin, EV_EOF on a pipe read end is HUP; on its write
                // end it is ERR. Registering both filters gives one event of
                // each kind either way. The synchronous descriptor poll below
                // is authoritative and filters this transition to Linux's bit.
                WRITE | if eof { ERR | HUP } else { 0 }
            } else if event.filter == libc::EVFILT_EXCEPT {
                PRI
            } else {
                0
            };
            events.push((
                DescriptionId {
                    slot: token as u32,
                    generation: (token >> 32) as u32,
                },
                types,
            ));
        }
        Ok(events)
    }

    pub(crate) fn remove(&self, host_fd: RawFd) {
        let token = DescriptionId {
            slot: 0,
            generation: 0,
        };
        let changes = [
            Self::change(libc::EVFILT_READ, libc::EV_DELETE, host_fd, token),
            Self::change(libc::EVFILT_WRITE, libc::EV_DELETE, host_fd, token),
            Self::change(libc::EVFILT_EXCEPT, libc::EV_DELETE, host_fd, token),
        ];
        unsafe {
            libc::kevent(
                self.fd.as_raw_fd(),
                changes.as_ptr(),
                changes.len() as c_int,
                ptr::null_mut(),
                0,
                ptr::null(),
            );
        }
    }
}

impl Backend {
    pub(crate) fn wake(&self) {
        // Full is fine: the pipe only has to be readable.
        let _ = rustix::io::write(&self.notify_write, &[1]);
    }

    pub(crate) fn drain_notify(&self) {
        let mut bytes = [0u8; 64];
        while matches!(rustix::io::read(&self.notify_read, &mut bytes), Ok(n) if n > 0) {}
    }
}
