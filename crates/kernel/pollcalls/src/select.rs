//! Guest select and pselect descriptor-set handling.

use super::*;

// ---------------------------------------------------------------------------
// select
// ---------------------------------------------------------------------------

pub(super) fn bits_size(bits: usize) -> usize {
    if bits == 0 { 0 } else { (bits - 1) / 8 + 1 }
}

pub(super) fn bit_test(i: usize, data: &[u8]) -> bool {
    data.get(i / 8).is_some_and(|b| b & (1 << (i % 8)) != 0)
}

pub(super) fn bit_set(i: usize, data: &mut [u8]) {
    if let Some(b) = data.get_mut(i / 8) {
        *b |= 1 << (i % 8);
    }
}

/// The three sets `select` reports into, which the callback writes.
struct SelectSets {
    read: Vec<u8>,
    write: Vec<u8>,
    except: Vec<u8>,
}

fn select_callback(c: &mut SelectSets, types: c_int, info: u64) -> c_int {
    let number = info as usize;
    if types & SELECT_READ != 0 {
        bit_set(number, &mut c.read);
    }
    if types & SELECT_WRITE != 0 {
        bit_set(number, &mut c.write);
    }
    if types & SELECT_EX != 0 {
        bit_set(number, &mut c.except);
    }
    if types & (SELECT_READ | SELECT_WRITE | SELECT_EX) == 0 {
        return 0;
    }
    1
}

// The RAII wrapper that was here until 2026-09-09 -- a newtype over
// `*mut pollset::PollSet` with a `Drop` that called `poll_destroy`, and a
// `new` that read an `ERR_PTR` back out of the pointer -- is what
// `fs_poll::Set` is: an owned value with its own `Drop`. Both halves of that
// wrapper existed because the set was allocated with `Box::into_raw` on the
// other side of a C-shaped API.

fn select_common(
    nfds: c_int,
    read_addr: u64,
    write_addr: u64,
    except_addr: u64,
    timeout: Option<libc::timespec>,
    name: &str,
) -> i64 {
    if nfds < 0 {
        return EINVAL;
    }
    // Clamped to the descriptor limit, as Linux does: a bit past the last
    // descriptor a process may open can never be set.
    let limit = rescalls::rlimit(RLIMIT_NOFILE);
    let nfds = (nfds as u64).min(limit) as usize;
    let fdset_size = bits_size(nfds);

    let mut sets = SelectSets {
        read: vec![0u8; fdset_size],
        write: vec![0u8; fdset_size],
        except: vec![0u8; fdset_size],
    };
    // A null set address is an empty set rather than a fault, which is how
    // `select(n, NULL, &w, NULL, t)` asks about writability alone.
    for (addr, set) in [
        (read_addr, &mut sets.read),
        (write_addr, &mut sets.write),
        (except_addr, &mut sets.except),
    ] {
        if addr != 0 && fdset_size > 0 && GuestMem.read(addr, set) != 0 {
            return EFAULT;
        }
    }
    strace!("{name}({nfds}, {read_addr:#x}, {write_addr:#x}, {except_addr:#x})");

    let mut set = fs_poll::poll_create_transient();
    for i in 0..nfds {
        let mut events = 0;
        if bit_test(i, &sets.read) {
            events |= SELECT_READ;
        }
        if bit_test(i, &sets.write) {
            events |= SELECT_WRITE;
        }
        if bit_test(i, &sets.except) {
            events |= SELECT_EX;
        }
        if events == 0 {
            continue;
        }
        let Some(fd) = fs_fdobj::f_get(i as c_int) else {
            return EBADF;
        };
        fs_poll::poll_add_fd(&mut set, fd.retain(), events, i as u64);
    }

    // Cleared before the wait: what comes back is what became ready, not what
    // was asked about.
    sets.read.fill(0);
    sets.write.fill(0);
    sets.except.fill(0);
    let waited = fs_poll::poll_wait(
        &mut set,
        &mut |types, info| select_callback(&mut sets, types, info),
        timeout.as_ref(),
    );
    drop(set);
    let err = match waited {
        fs_poll::Waited::Done(n) => n,
        // The idle valve fired: `crates/fs/poll` measured the idle time and
        // this layer ends the process, because `do_exit_group` is a syscall
        // and a wait loop calling one is what made the two crates a cycle.
        fs_poll::Waited::GiveUp => unsafe { exitcalls::do_exit_group(0) },
    };
    if err < 0 {
        return err as i64;
    }

    for (addr, s) in [
        (read_addr, &sets.read),
        (write_addr, &sets.write),
        (except_addr, &sets.except),
    ] {
        if addr != 0 && fdset_size > 0 && GuestMem.write(addr, s) != 0 {
            return EFAULT;
        }
    }
    err as i64
}

/* `sys_select` and its `struct timeval` reader were here, and they were in **no
 * syscall table**: aarch64 has `pselect6` and no `select`, the way it has
 * `ppoll` and no `poll`. Deleted on 2026-09-03 rather than left, which is what
 * happened to `sys_epoll_create0` and the C's `sys_epoll_wait` for the same
 * reason.
 *
 * The reader is worth recording because it was the only timeout path in this
 * file that validated *nothing*: it multiplied `tv_usec` by 1000 unchecked and
 * accepted a negative second count, where `read_timespec` below refuses both.
 * Nothing could reach it. */

/// A guest `struct timespec`, refused when it is not a time.
///
/// `{-1, 0}` and `{0, -1}` are both `EINVAL` and not waits of some length
/// nobody asked for. Nothing checked, so both became waits.
fn read_timespec(addr: u64) -> Result<libc::timespec, Errno> {
    let mut b = [0u8; 16];
    if GuestMem.read(addr, &mut b) != 0 {
        return Err(Errno::EFAULT);
    }
    let sec = i64::from_le_bytes(b[..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(b[8..].try_into().unwrap());
    if !timeabi::timespec_valid(sec, nsec) {
        return Err(Errno::EINVAL);
    }
    Ok(libc::timespec {
        tv_sec: sec as _,
        tv_nsec: nsec as _,
    })
}

pub fn sys_pselect(
    nfds: c_int,
    read_addr: u64,
    write_addr: u64,
    except_addr: u64,
    timeout_addr: u64,
    sigmask_addr: u64,
) -> Result<i64, Errno> {
    let timeout = if timeout_addr != 0 {
        Some(read_timespec(timeout_addr)?)
    } else {
        None
    };
    let remaining = timeout
        .as_ref()
        .and_then(|t| Remaining::start(timeout_addr, t.tv_sec, t.tv_nsec));

    // A syscall takes six arguments and pselect6 needs seven, so the last two
    // travel as a pointer to a `{ mask, size }` pair.
    //
    // **The pointer may be null, and usually is**: `pselect(..., NULL)` is how
    // you ask for the timeout without touching the mask. This read the pair
    // unconditionally, so that spelling read guest address zero and answered
    // EFAULT -- every caller that did not want a mask was refused.
    //
    // A null *pair* and a pair holding a null *mask* are different things and
    // both are legal; musl's own select() on this architecture passes the
    // second.
    if sigmask_addr != 0 {
        let mut pair = [0u8; 16];
        if GuestMem.read(sigmask_addr, &mut pair) != 0 {
            return Err(Errno::EFAULT);
        }
        let mask_addr = u64::from_le_bytes(pair[..8].try_into().unwrap());
        let mask_size = u64::from_le_bytes(pair[8..].try_into().unwrap());
        if mask_addr != 0 {
            let mut mask = 0u64;
            let err = signaldeliver::user_get_sigset(mask_addr, mask_size, &mut mask);
            if err != 0 {
                return Err(Errno::from_negative_or_eio(err));
            }
            signaldeliver::sigmask_set_temp(mask);
        }
    }
    // `select_common` answers the number of ready descriptors or an errno in
    // one i64, which is the poll layer's convention; this is where it is read.
    let res = Errno::split(select_common(
        nfds,
        read_addr,
        write_addr,
        except_addr,
        timeout,
        "pselect",
    ));
    signaldeliver::sigmask_restore_temp(&res);
    if let Some(r) = remaining {
        r.finish();
    }
    res
}
