//! Guest poll and ppoll handling.

use std::ptr::NonNull;

use super::*;

// ---------------------------------------------------------------------------
// poll
// ---------------------------------------------------------------------------

/// The guest's `struct pollfd`: a descriptor and two 16-bit event words, eight
/// bytes. `kernel/calls.h` asserts the offsets.
#[derive(Clone, Copy, Default)]
struct PollFd {
    fd: i32,
    events: u16,
    revents: u16,
}

const POLLFD_SIZE: usize = 8;

/// Reported whether or not the caller asked for them, as Linux does.
///
/// `POLL_RDHUP` is deliberately **not** here: Linux reports it only to a caller
/// that asked, because a program that does not know about half-closes must not
/// start seeing a bit it will not recognise.
pub(super) const POLL_ALWAYS_LISTENING: c_int = POLL_ERR | POLL_HUP | POLL_NVAL;

struct PollContext {
    polls: Vec<PollFd>,
    /// One per entry: the description it names, or `None` for a descriptor
    /// that is not open. A `Vec<usize>` with `0` for the second case until
    /// 2026-09-16 -- a pointer as an integer and a sentinel for `None`, which
    /// is two of the three things `Option<NonNull<_>>` says in one word.
    files: Vec<Option<NonNull<ffi::fd>>>,
}

fn poll_callback(c: &mut PollContext, types: c_int, info: u64) -> c_int {
    let mut res = 0;
    for i in 0..c.polls.len() {
        if token(c.files[i]) != info {
            continue;
        }
        let want = c.polls[i].events as c_int | POLL_ALWAYS_LISTENING;
        c.polls[i].revents = (types & want) as u16;
        if c.polls[i].revents != 0 {
            res += 1;
        }
    }
    res
}

/// Every descriptor the caller named, with a reference of the set's own on
/// each that is open.
///
/// Not redundant with `f_get`'s: that one belongs to the syscall, and the
/// group-exit valve can drain a task's syscall references from another thread
/// while this one is still parked in the wait.
struct HeldFiles(Vec<Option<fs_fdobj::Owned>>);

/// The identity `crates/fs/pollset` carries back to [`poll_callback`], which is
/// the description's address as the `u64` that interface takes. Zero for an
/// entry with no open file, which the callback never matches because such an
/// entry is answered `POLLNVAL` without being registered.
fn token(f: Option<NonNull<ffi::fd>>) -> u64 {
    f.map_or(0, |p| p.as_ptr() as u64)
}

/// `poll`, which aarch64 does not have as a syscall — `ppoll` is the only one
/// in the table, and it does the signal-mask handling and then comes here.
///
/// Not `extern "C"` for that reason: it was exported and declared in
/// `kernel/calls.h` while no syscall table could reach it, the same shape
/// `sys_select` above had.
fn sys_poll(fds: u64, nfds: c_uint, timeout: c_int) -> i64 {
    strace!("poll({fds:#x}, {nfds}, {timeout})");
    // See the module comment: a poll naming more descriptors than the process
    // may have open is a poll that cannot be answered.
    if nfds as u64 > rescalls::rlimit(RLIMIT_NOFILE) {
        return EINVAL;
    }
    let nfds = nfds as usize;

    let mut raw = vec![0u8; nfds * POLLFD_SIZE];
    if nfds > 0 && GuestMem.read(fds, &mut raw) != 0 {
        return EFAULT;
    }
    let mut ctx = PollContext {
        polls: (0..nfds)
            .map(|i| {
                let at = i * POLLFD_SIZE;
                PollFd {
                    fd: i32::from_le_bytes(raw[at..at + 4].try_into().unwrap()),
                    events: u16::from_le_bytes(raw[at + 4..at + 6].try_into().unwrap()),
                    // Cleared: what comes back is what became ready.
                    revents: 0,
                }
            })
            .collect(),
        files: Vec::new(),
    };

    let mut set = fs_poll::poll_create_transient();
    // A reference per open descriptor, so none is freed while the set holds it.
    // FIXME: it might have been closed by now by another thread.
    let held = HeldFiles(
        ctx.polls
            .iter()
            // The set's own reference, beside the one the syscall holds.
            .map(|p| fs_fdobj::f_get(p.fd).map(fs_fdobj::FdRef::retain))
            .collect(),
    );
    ctx.files = held.0.iter().map(|f| f.as_ref().map(|f| NonNull::from(&**f))).collect();

    // Entries naming the same open file description are merged, so each is
    // registered once.
    //
    // One pass with a map, where this was a nested loop over the whole array
    // under a comment saying "the merge is quadratic and it does not matter" --
    // measured at 256 entries, where it does not. At 1800 the same loop is 49
    // times the work, and it is what a poll() over descriptors that need no
    // host registration spends its time on. Isolated by comparing pipes against
    // eventfds, which are not host-backed:
    //
    //   n=1800  pipe 1.360 us/fd   eventfd 0.645 us/fd
    //   n= 500  pipe 1.048 us/fd   eventfd 0.320 us/fd
    //
    // The difference between the columns is constant -- that is the host
    // registration, and it is linear. The eventfd column doubling is this loop.
    let mut merge = pollindex::Merge::new();
    let mut merged = vec![0i32; nfds];
    let mut first_at = vec![usize::MAX; nfds];
    for i in 0..nfds {
        if ctx.polls[i].fd < 0 || ctx.files[i].is_none() {
            continue;
        }
        match merge.find_or_insert(token(ctx.files[i]) as usize, i) {
            Some(first) => {
                merged[first] |= ctx.polls[i].events as i32;
                first_at[i] = first;
            }
            None => {
                merged[i] = ctx.polls[i].events as i32;
                first_at[i] = i;
            }
        }
    }
    let mut nval = 0i64;
    for i in 0..nfds {
        if ctx.polls[i].fd < 0 {
            continue;
        }
        let Some(file) = held.0[i].as_ref() else {
            // A descriptor that is not open is POLLNVAL, reported without
            // waiting for it. The two sets are disjoint: an entry with POLLNVAL
            // has no open file, so the callback never matches it.
            ctx.polls[i].revents = POLL_NVAL as u16;
            nval += 1;
            continue;
        };
        // Only the entry a description was first seen at registers it; the
        // others folded their events into this one above.
        if first_at[i] != i {
            continue;
        }
        // The set's own reference, beside the one `held` keeps.
        fs_poll::poll_add_fd(&mut set, file.clone(), merged[i] | POLL_ALWAYS_LISTENING, token(ctx.files[i]));
    }

    // A descriptor that does not exist answers POLLNVAL, and two things follow
    // from that being an *answer* rather than a state to wait for: it counts
    // towards the return value, and **it means the call does not block**.
    // Neither was done, so poll() of a single closed descriptor with an
    // infinite timeout waited for ever, having already decided what to report.
    let wait_for = if nval > 0 {
        Some(libc::timespec { tv_sec: 0, tv_nsec: 0 })
    } else if timeout < 0 {
        None
    } else {
        Some(libc::timespec {
            tv_sec: (timeout as i64 / 1000) as _,
            tv_nsec: ((timeout as i64 % 1000) * 1_000_000) as _,
        })
    };
    let waited = fs_poll::poll_wait(
        &mut set,
        &mut |types, info| poll_callback(&mut ctx, types, info),
        wait_for.as_ref(),
    );
    drop(set);
    drop(held);
    let res = match waited {
        fs_poll::Waited::Done(n) => n,
        fs_poll::Waited::GiveUp => unsafe { exitcalls::do_exit_group(0) },
    };
    if res < 0 {
        return res as i64;
    }

    if nfds > 0 {
        for (i, p) in ctx.polls.iter().enumerate() {
            let at = i * POLLFD_SIZE;
            raw[at..at + 4].copy_from_slice(&p.fd.to_le_bytes());
            raw[at + 4..at + 6].copy_from_slice(&p.events.to_le_bytes());
            raw[at + 6..at + 8].copy_from_slice(&p.revents.to_le_bytes());
        }
        if GuestMem.write(fds, &raw) != 0 {
            return EFAULT;
        }
    }
    res as i64 + nval
}

pub fn sys_ppoll(
    fds: u64,
    nfds: c_uint,
    timeout_addr: u64,
    sigmask_addr: u64,
    sigsetsize: u64,
) -> Result<i64, Errno> {
    let mut timeout = -1i32;
    let mut remaining = None;
    if timeout_addr != 0 {
        let mut b = [0u8; 16];
        if GuestMem.read(timeout_addr, &mut b) != 0 {
            return Err(Errno::EFAULT);
        }
        let sec = i64::from_le_bytes(b[..8].try_into().unwrap());
        let nsec = i64::from_le_bytes(b[8..].try_into().unwrap());
        // This was `sec * 1000 + nsec / 1000000` on unchecked input, which got
        // two things wrong. `{-1, 0}` came out as -1000, and a negative timeout
        // means *wait for ever* to poll -- so a guest asking for a negative
        // timeout got a hang. And a sub-millisecond wait truncated to zero, so
        // `ppoll(fds, n, {0, 500000})` -- half a millisecond, which every event
        // loop asks for -- became a poll that returns at once.
        match timeabi::timespec_to_poll_ms(sec, nsec) {
            Some(ms) if ms >= 0 => timeout = ms,
            _ => return Err(Errno::EINVAL),
        }
        remaining = Remaining::start(timeout_addr, sec, nsec);
    }

    if sigmask_addr != 0 {
        let mut mask = 0u64;
        let err = signaldeliver::user_get_sigset(sigmask_addr, sigsetsize, &mut mask);
        if err != 0 {
            return Err(Errno::from_negative_or_eio(err));
        }
        signaldeliver::sigmask_set_temp(mask);
    }
    // As `pselect`: the count of ready descriptors, or an errno.
    let res = Errno::split(sys_poll(fds, nfds, timeout));
    signaldeliver::sigmask_restore_temp(&res);
    if let Some(r) = remaining {
        r.finish();
    }
    res
}
