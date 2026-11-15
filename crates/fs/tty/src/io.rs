//! Terminal input, output, read, write, and poll behavior.

use super::*;

// ---------------------------------------------------------------------------
// Input.

/// Feed bytes in from the driver side: the console's reader thread, or the
/// other end of a pty.
///
/// The loop is here and the decisions are in `crates/fs/ldisc`. What is left
/// is the two things the discipline cannot do: wait for room in a way a guest
/// signal can interrupt, and signal a process group.
pub fn input(tty: &Arc<Tty>, bytes: &[u8], blocking: bool) -> isize {
    let mut done = 0usize;
    let mut err = 0isize;
    // Accumulated rather than sent: sending needs pids_lock, and this holds
    // the terminal's lock, which is below it in the order.
    let mut signals: u64 = 0;
    let mut wake = false;
    let mut echo: Vec<u8> = Vec::new();
    let fg_group;

    {
        let mut state = tty.lock();
        // Hung up and not opened since: there is no reader, and what arrives
        // is dropped -- a master writing into a slave `vhangup` took away
        // gets its count back and the bytes go nowhere, as on Linux.
        if state.hung_up || tty.is_external_closed() {
            return bytes.len() as isize;
        }
        let generation = state.generation;
        'bytes: for &byte in bytes {
            loop {
                let termios = state.termios;
                match state.ldisc.input(&termios, byte) {
                    Step::Consumed(outcome) => {
                        done += 1;
                        if outcome.signal != 0 && state.jobctl.fg_group() != 0 {
                            signals |= 1u64 << (outcome.signal.clamp(1, 64) - 1);
                        }
                        wake |= outcome.wake;
                        break;
                    }
                    Step::NeedRoom => {
                        // Full. A reader has to take something before this byte
                        // fits.
                        err = EAGAIN as isize;
                        if !blocking {
                            break 'bytes;
                        }
                        if state.wait(CONSUMED, None) == Woke::Interrupted {
                            err = EINTR as isize;
                            break 'bytes;
                        }
                        if state.hung_up || state.generation != generation || tty.is_external_closed() {
                            return bytes.len() as isize;
                        }
                    }
                }
            }
        }
        // Taken under the lock and written without it: for a pty the write is
        // the *other* end's input path, which takes the other end's lock, and
        // doing that under this one deadlocked.
        echo.append(&mut state.ldisc.take_echo());
        fg_group = state.jobctl.fg_group();
    }

    if wake {
        tty.notify_produced();
        tty.wake_pollers(POLL_READ);
    }
    if !echo.is_empty() {
        write_out(tty, &echo, false);
    }
    if fg_group != 0 {
        for sig in 1..=64 {
            if signals & (1u64 << (sig - 1)) != 0 {
                task().signal_group(fg_group, sig as c_int);
            }
        }
    }

    if done > 0 { done as isize } else { err }
}

/// Send bytes to whatever is on the other side of this terminal.
fn write_out(tty: &Arc<Tty>, bytes: &[u8], blocking: bool) -> isize {
    if let Some(write) = tty.external {
        return write(tty, bytes, blocking) as isize;
    }
    match tty.kind {
        Kind::Console => match console() {
            // SAFETY: `bytes` is a live slice.
            Some(console) => console.write(tty.num, bytes),
            // No console driver bound: the bytes are accepted and dropped,
            // which is what a build with no host terminal does.
            None => bytes.len() as isize,
        },
        // A write to one end of a pty is input to the other.
        Kind::PtyMaster | Kind::PtySlave => match tty.other() {
            // The other end can be gone: a write drops the terminal's lock
            // before getting here, so one that has already passed the hung-up
            // check can arrive afterwards.
            None => EIO as isize,
            Some(other) => input(&other, bytes, blocking),
        },
    }
}

// ---------------------------------------------------------------------------
// The background rules a read, a write and an ioctl share.

/// Returns 0 to carry on, or a negative guest errno.
///
/// `pids_lock` is taken above the terminal's own, and this function takes it
/// itself rather than requiring one from the caller: the cheap answer below
/// settles every foreground read without it, so the common path pays nothing.
/// `reopened` says the slow path ran, which is what tells the caller that
/// everything decided before the gap has to be decided again after it.
fn background_check(tty: &Arc<Tty>, sig: c_int, reopened: &mut bool) -> c_int {
    *reopened = false;
    // The cheap answer first, and without pids_lock. It settles every read an
    // interactive terminal ever does: the caller is in the foreground group.
    // Taking the kernel-wide lock on every one of them cost 4.6x under load --
    // see tests/guest/src/bin/tty_bench.rs.
    let settings = tty.settings_side();
    {
        // Asked *before* the terminal's lock, not under it. The answer comes
        // from the process layer and that layer takes a lock of its own -- the
        // one `set_controlling` holds while it calls `tty_claim`, which wants
        // this one. Two threads of a single process are enough to close that
        // cycle: one reading a terminal it does not control while the other
        // does TIOCSCTTY. See the note above `is_controlling_terminal`.
        let is_current = is_controlling_terminal(&settings);
        let state = settings.lock();
        if !state.jobctl.access_needs_orphan(is_current, task().pgid()) {
            return 0;
        }
    }
    *reopened = true;
    crate::ops::with_pids_lock(|pids| {
        let pgid = task().pgid();
        let orphaned = task().orphaned(pids, pgid);
        let is_current = is_controlling_terminal(&settings);
        let state = settings.lock();
        let ignored = task().ignores(sig);
        let which = if sig == SIGTTIN { Sig::Ttin } else { Sig::Ttou };
        match state
            .jobctl
            .access(is_current, pgid, which, ignored, orphaned)
        {
            Access::Allow => 0,
            Access::Eio => EIO,
            Access::Stop => {
                // The whole process group, as Linux's kill_pgrp does, so a
                // background job of several processes stops together rather
                // than one at a time as each reaches the terminal.
                drop(state);
                task().signal_group_locked(pids, pgid, sig);
                EINTR
            }
        }
    })
}

/// Whether this terminal is the calling process's controlling one.
///
/// **Never call this holding the terminal's own lock.** It asks the process
/// layer, which takes the lock over a thread group's controlling-terminal
/// field, and the call that *sets* that field holds that lock while it calls
/// `tty_claim` -- which takes this terminal's. Two threads of one process close
/// the cycle: one reading a terminal it does not control, one doing
/// `TIOCSCTTY`.
///
/// `tools/lock-order.py` cannot see it: one of the two locks is Rust's. Read
/// rather than reproduced -- the window is two mutex acquisitions wide and no
/// test has produced it -- so this is a rule the callers keep, and three of
/// them were not keeping it.
///
/// The answer is advisory either way: nothing stops the terminal changing hands
/// between this call and whatever is decided from it, which is as true of the
/// callers that already asked outside the lock.
pub(crate) fn is_controlling_terminal(tty: &Arc<Tty>) -> bool {
    // SAFETY: `tty` is live for the length of the call.
    task().is_controlling(crate::ops::TtyId::of(tty))
}

// ---------------------------------------------------------------------------
// Reading.

/// Returns how many bytes were written into `out`, or a negative guest errno.
///
/// A master whose slave has closed answers what is queued and then `EIO`,
/// from [`read_canonical`] and [`read_raw`]; it answered end of file at once
/// until 2026-11-12, dropping whatever the slave wrote last.
pub fn read(open: &Open, out: &mut [u8], nonblock: bool) -> isize {
    let tty = open.tty();
    // A read from a hung-up description is end of file, not an error.
    if open.hung_up() {
        return 0;
    }
    if out.is_empty() {
        return 0;
    }

    let mut reopened = false;
    let err = background_check(tty, SIGTTIN, &mut reopened);
    if err < 0 {
        return err as isize;
    }

    let mut state = tty.lock();
    // Asked again under the lock that a hangup takes, so a hangup in the gap
    // above is not missed.
    if state.generation != open.generation() {
        return 0;
    }
    let generation = open.generation();
    let mut prefix = 0usize;
    let mut want = out.len();
    if tty.kind == Kind::PtyMaster && state.packet_mode {
        out[0] = state.packet_flags;
        prefix = 1;
        want -= 1;
        if state.packet_flags != 0 || want == 0 {
            return prefix as isize;
        }
    }

    let taken = if state.termios.lflags & ICANON != 0 {
        read_canonical(tty, &mut state, &mut out[prefix..prefix + want], nonblock, generation)
    } else {
        read_raw(tty, &mut state, &mut out[prefix..prefix + want], nonblock, generation)
    };
    let taken = match taken {
        Ok(n) => n,
        Err(e) => return e as isize,
    };

    // A null byte alone on the queue is a typed end of file; take it off so
    // the next read can succeed.
    if state.ldisc.buffer.at(0) == Some(0) && state.ldisc.buffer.canon_len() == Some(1) {
        let mut dummy = [0u8; 1];
        state.ldisc.buffer.read(&mut dummy);
    }
    drop(state);
    tty.notify_consumed();
    (prefix + taken) as isize
}

fn read_canonical(
    tty: &Arc<Tty>,
    state: &mut GuestGuard<'_, State>,
    out: &mut [u8],
    nonblock: bool,
    generation: u64,
) -> Result<usize, c_int> {
    let mut line = loop {
        if let Some(line) = state.ldisc.buffer.canon_len() {
            break line;
        }
        if tty.half_closed_master() {
            return Err(EIO);
        }
        if nonblock {
            return Err(EAGAIN);
        }
        match state.wait(PRODUCED, None) {
            Woke::Interrupted => return Err(EINTR),
            _ => {
                if state.generation != generation {
                    return Ok(0);
                }
            }
        }
    };
    // A line ending in a null byte was terminated by end of file, which is not
    // part of what the reader asked for.
    if line > 0 && state.ldisc.buffer.at(line - 1) == Some(0) {
        line -= 1;
    }
    let take = out.len().min(line);
    Ok(state.ldisc.buffer.read(&mut out[..take]))
}

fn read_raw(
    tty: &Arc<Tty>,
    state: &mut GuestGuard<'_, State>,
    out: &mut [u8],
    nonblock: bool,
    generation: u64,
) -> Result<usize, c_int> {
    let min = state.termios.cc[VMIN] as usize;
    // VTIME is in tenths of a second, and there is no timeout on the first
    // character.
    let time = state.termios.cc[VTIME] as u64;
    let timeout = (time != 0).then(|| Duration::from_millis(time * 100));

    while state.ldisc.buffer.len() < min {
        if tty.half_closed_master() {
            return Err(EIO);
        }
        if nonblock {
            return Err(EAGAIN);
        }
        let waiting = if state.ldisc.buffer.is_empty() {
            None
        } else {
            timeout
        };
        match state.wait(PRODUCED, waiting) {
            Woke::TimedOut => break,
            Woke::Interrupted => return Err(EINTR),
            Woke::Notified => {
                if state.generation != generation {
                    return Ok(0);
                }
            }
        }
    }
    let take = out.len().min(state.ldisc.buffer.len());
    Ok(state.ldisc.buffer.read(&mut out[..take]))
}

// ---------------------------------------------------------------------------
// Writing.

/// A master whose slave has closed is written as usual: the bytes wait in
/// the slave for whoever opens it next, as Linux's do.
pub fn write(open: &Open, bytes: &[u8], nonblock: bool) -> isize {
    let tty = open.tty();
    let oflags = {
        let state = tty.lock();
        if state.generation != open.generation() {
            return EIO as isize;
        }
        state.termios.oflags
    };

    // TOSTOP is what makes a *write* from a background group stop it, the way
    // a read always does. It was defined and read by nothing, so `stty tostop`
    // changed nothing at all.
    if tty.settings_side().lock().termios.lflags & TOSTOP != 0 {
        let mut reopened = false;
        let err = background_check(tty, SIGTTOU, &mut reopened);
        if err < 0 {
            return err as isize;
        }
        if reopened && open.hung_up() {
            return EIO as isize;
        }
    }

    // Output processing, then the driver, with the terminal's lock dropped:
    // for a pty the driver's write is the other end's input path.
    let processed = process_output(oflags, bytes);
    let sent = write_out(tty, &processed, !nonblock);
    if sent < 0 { sent } else { bytes.len() as isize }
}

fn process_output(oflags: u32, bytes: &[u8]) -> Vec<u8> {
    if oflags & OPOST == 0 {
        return bytes.to_vec();
    }
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        match byte {
            b'\r' if oflags & ONLRET != 0 => continue,
            b'\r' if oflags & OCRNL != 0 => out.push(b'\n'),
            b'\n' if oflags & ONLCR != 0 => {
                out.push(b'\r');
                out.push(b'\n');
            }
            other => out.push(other),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Polling.

/// A hung-up description is readable, writable, in error and hung up, which
/// is Linux's `hung_up_tty_poll`. A master whose slave has closed is
/// `POLLHUP`, and readable only while something is queued (`n_tty_poll`).
pub fn poll(open: &Open) -> c_int {
    let tty = open.tty();
    if open.hung_up() {
        return POLL_READ | POLL_WRITE | POLL_ERR | POLL_HUP;
    }
    let mut types = 0;
    if has_room(tty) {
        types |= POLL_WRITE;
    }
    // Asked without this terminal's lock held: it takes the *slave's*, and
    // this may be the master's.
    if tty.half_closed_master() {
        types |= POLL_HUP;
    }
    let state = tty.lock();
    let ready = if state.termios.lflags & ICANON != 0 {
        state.ldisc.buffer.canon_len().is_some()
    } else {
        !state.ldisc.buffer.is_empty()
    };
    if ready {
        types |= POLL_READ;
    }
    if tty.kind == Kind::PtyMaster && state.packet_flags != 0 {
        types |= POLL_PRI;
    }
    types
}

/// Is there room for a write?
///
/// For a pty a write goes to the *other* end's line discipline, and when that
/// buffer is full the write waits on the other end. So writability is a
/// question about the other end -- and this used to answer it with an
/// unconditional POLL_WRITE under a comment saying it was wrong. A program that
/// polls before writing, which is the whole point of polling, was told to go
/// ahead and then blocked.
///
/// **try_lock, not lock.** The only nesting of two terminal locks allowed is
/// master then slave, and the slave's poll would need the reverse. Failing to
/// take it answers "writable", which is what the code did unconditionally
/// before, so a momentary contention costs the old behaviour for one poll.
fn has_room(tty: &Arc<Tty>) -> bool {
    if !tty.kind.is_pty() {
        return true; // a console: the write goes to the host and does not queue
    }
    let Some(other) = tty.other() else {
        return true; // hung up; the write fails rather than blocking
    };
    match other.try_lock() {
        Some(state) => !state.ldisc.buffer.is_full(),
        None => true,
    }
}
