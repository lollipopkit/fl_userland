//! Linux native AIO: `io_setup`, `io_destroy`, `io_submit`, `io_cancel`,
//! `io_getevents` and `io_pgetevents`.
//!
//! Every answer here was asked of a real arm64 kernel first, by
//! `tests/guest/src/bin/aio_probe.rs`; `aio_abi.rs` holds the behaviour to it.
//!
//! # The ring is real
//!
//! A context id is the guest address of a `struct aio_ring`, and libaio and
//! fio read that ring themselves when its magic matches: libaio's
//! `io_getevents` with a zero timeout answers 0 *without a syscall* when
//! `head == tail`, and fio's `userspace_reap` takes events from it directly.
//! A context kept anywhere else would leave those programs reaping an empty
//! ring for ever, so the ring is Linux's, word for word, and the kernel side
//! appends at `tail` and reads the guest's `head`.
//!
//! It is a kernel memfd named `/[aio]` -- what `/proc/<pid>/maps` shows on
//! Linux, `rw-s`, marked `MADV_DONTFORK` because a forked child does not get
//! it -- mapped into the guest at the context id, and mapped a second time
//! into the emulator ([`ring::Ring`]). Completions go through the second
//! mapping, which works from a thread with no address space and after the
//! guest makes its own read-only, as Linux's `ring_folios` do.
//!
//! # Finding a context
//!
//! [`context::lookup`] is `lookup_ioctx`: read the `id` word through the
//! guest's mapping, find that id among the calling address space's contexts,
//! and check the page at the context id **is** that ring. So an unmapped ring,
//! a scribbled `id`, a misaligned or made-up id and a forked child's copy of
//! the parent's number are all `EINVAL`, and an `mremap`ped ring is found at
//! its new address and not its old one -- each measured.
//!
//! # Lifetime
//!
//! A context goes with `io_destroy`, or when the last mapping of its ring goes
//! -- an `munmap`, or the address space itself on `exit` and `execve`. The
//! memfd's unmap hook reports that ([`context`]'s `ring_unmapped`), and its
//! budget against `aio-max-nr` comes back then, which is Linux's `exit_aio`.
//! One difference: Linux keeps a context whose ring the guest unmapped until
//! the process exits, unreachable but charged; here it is released at once,
//! which only `/proc/sys/fs/aio-nr` can tell apart.
//!
//! # What runs where
//!
//! Buffered reads and writes run to completion inside `io_submit` on Linux,
//! and do here, through `crates/kernel/rwcalls`; a read from an empty pipe
//! blocks there as it does on Linux. `IOCB_CMD_FSYNC`/`FDSYNC` run there too,
//! where Linux queues them to a workqueue -- the event exists before
//! `io_submit` returns instead of a moment after. `IOCB_CMD_POLL` is the one
//! genuinely asynchronous request; see [`poll`].
//!
//! # Not reproduced
//!
//! - **Driver wake keys** in a poll result; see [`poll`].
//! - **`read_iter`/`write_iter` per driver.** Linux refuses a transfer on a
//!   file without them with `EINVAL`. This asks the driver's [`ffi::Caps`],
//!   which say the same for directories, epoll and pidfd and is corrected for
//!   an eventfd's write; a timerfd or inotify read, which Linux refuses, runs.
//! - **`io_pgetevents` restarting.** Linux answers `ERESTARTNOHAND`, which is
//!   restarted when no handler ran; this answers `EINTR`, like `io_getevents`.

mod abi;
mod context;
mod poll;
mod ring;
mod submit;
mod uring;

pub use uring::{sys_io_uring_enter, sys_io_uring_register, sys_io_uring_setup};

use std::ffi::c_int;
use std::sync::Arc;

use guest_errno::Errno;
use strace::strace;
use usercopy::GuestMem;

use context::Context;
use taskview::ffi;

/// `/proc/sys/fs/aio-max-nr`: the most events all contexts may ask for.
pub fn aio_max_nr() -> u64 {
    abi::AIO_MAX_NR
}

/// `/proc/sys/fs/aio-nr`: what the live contexts asked for.
pub fn aio_nr() -> u64 {
    context::aio_nr()
}

/// `MADV_DONTFORK`.
const MADV_DONTFORK: u32 = 10;

/// `eventfd_signal`: add one, never blocking. A counter already at its
/// ceiling stays there, as Linux's saturates.
pub(crate) fn signal(resfd: &fs_fdobj::Owned) {
    if let Some(counter) = resfd.driver_state::<kernel_eventfd::Descriptor>() {
        let _ = counter.write(true, 1);
    }
}

fn read_u64(addr: u64) -> Result<u64, Errno> {
    let mut word = [0u8; 8];
    if GuestMem.read(addr, &mut word) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(u64::from_le_bytes(word))
}

/// Everything a dead or destroyed context still holds, let go: its pending
/// polls cancelled, every finished one dropped, and -- for `io_destroy` -- its
/// ring unmapped from the guest.
pub(crate) fn teardown(ctx: &Arc<Context>, ring_at: Option<u64>) {
    poll::cancel_all(ctx.kill());
    drop(ctx.take_retired());
    if let Some(addr) = ring_at {
        mmapcalls::share::unmap(addr, ctx.pages);
    }
}

pub fn sys_io_setup(nr_events: u32, ctxp: u64) -> Result<(), Errno> {
    strace!("io_setup({nr_events}, {ctxp:#x})");
    if read_u64(ctxp)? != 0 || nr_events == 0 {
        return Err(Errno::EINVAL);
    }
    let cpus = rescalls::sched_all_cpus_mask().count_ones();
    let geometry = abi::geometry(nr_events, cpus)?;
    let ctx = context::create(geometry)?;
    let len = geometry.pages * abi::PAGE;
    let prot = (ffi::P_READ | ffi::P_WRITE) as c_int;
    let addr = match Errno::split(mmapcalls::share::map(context::file_of(&ctx), 0, len, prot, false)) {
        Ok(addr) => addr as u64,
        Err(_) => {
            context::unlink(&ctx);
            teardown(&ctx, None);
            return Err(Errno::ENOMEM);
        }
    };
    // Linux's ring is not copied into a forked child. A fork between the map
    // and this sees it, and its copy is one `lookup` does not accept.
    let _ = mmapcalls::sys_madvise(addr, len, MADV_DONTFORK);
    if GuestMem.write(ctxp, &addr.to_le_bytes()) != 0 {
        context::unlink(&ctx);
        teardown(&ctx, Some(addr));
        return Err(Errno::EFAULT);
    }
    Ok(())
}

pub fn sys_io_destroy(ctx_id: u64) -> Result<(), Errno> {
    strace!("io_destroy({ctx_id:#x})");
    let ctx = context::lookup(ctx_id).ok_or(Errno::EINVAL)?;
    if !context::unlink(&ctx) {
        return Err(Errno::EINVAL);
    }
    teardown(&ctx, Some(ctx_id));
    // `io_destroy` returns when every request has: a transfer another thread
    // is still running inside `io_submit` finishes first.
    ctx.drain();
    Ok(())
}

pub fn sys_io_submit(ctx_id: u64, nr: i64, iocbpp: u64) -> Result<i64, Errno> {
    strace!("io_submit({ctx_id:#x}, {nr}, {iocbpp:#x})");
    if nr < 0 {
        return Err(Errno::EINVAL);
    }
    let ctx = context::lookup(ctx_id).ok_or(Errno::EINVAL)?;
    let nr = nr.min(i64::from(ctx.nr()));
    let mut done = 0i64;
    let mut refused = None;
    while done < nr {
        let one = read_u64(iocbpp + done as u64 * 8).and_then(|cb| submit::submit_one(&ctx, cb));
        if let Err(e) = one {
            refused = Some(e);
            break;
        }
        done += 1;
    }
    drop(ctx.take_retired());
    match refused {
        Some(e) if done == 0 => Err(e),
        _ => Ok(done),
    }
}

pub fn sys_io_cancel(ctx_id: u64, iocb: u64, _result: u64) -> Result<(), Errno> {
    strace!("io_cancel({ctx_id:#x}, {iocb:#x})");
    // The key is read before the context is looked up, so a NULL iocb is
    // `EFAULT` whatever the context is. `result` is never written: the event
    // always arrives through the ring, and `EINPROGRESS` says it will.
    let mut key = [0u8; 4];
    if GuestMem.read(iocb.wrapping_add(abi::KEY_OFFSET), &mut key) != 0 {
        return Err(Errno::EFAULT);
    }
    if u32::from_le_bytes(key) != 0 {
        return Err(Errno::EINVAL);
    }
    let ctx = context::lookup(ctx_id).ok_or(Errno::EINVAL)?;
    let req = ctx.find_poll(iocb).ok_or(Errno::EINVAL)?;
    req.cancel();
    drop(req);
    drop(ctx.take_retired());
    Err(Errno::EINPROGRESS)
}

fn read_timeout(addr: u64) -> Result<abi::Timeout, Errno> {
    if addr == 0 {
        return Ok(abi::Timeout::Never);
    }
    let sec = read_u64(addr)? as i64;
    let nsec = read_u64(addr + 8)? as i64;
    Ok(abi::timeout(sec, nsec))
}

fn get_events(ctx_id: u64, min_nr: i64, nr: i64, events: u64, timeout: abi::Timeout) -> Result<i64, Errno> {
    let ctx = context::lookup(ctx_id).ok_or(Errno::EINVAL)?;
    if min_nr < 0 || min_nr > nr {
        return Err(Errno::EINVAL);
    }
    let got = ctx.get_events(min_nr, nr, events, timeout);
    drop(ctx.take_retired());
    got
}

/// Nothing read and a signal pending is `EINTR`, even for a zero timeout --
/// the last thing both syscalls do on Linux.
fn interrupted(got: Result<i64, Errno>) -> Result<i64, Errno> {
    match got {
        Ok(0) if taskview::current_signal_pending() => Err(Errno::EINTR),
        other => other,
    }
}

pub fn sys_io_getevents(ctx_id: u64, min_nr: i64, nr: i64, events: u64, timeout: u64) -> Result<i64, Errno> {
    strace!("io_getevents({ctx_id:#x}, {min_nr}, {nr}, {events:#x}, {timeout:#x})");
    let timeout = read_timeout(timeout)?;
    interrupted(get_events(ctx_id, min_nr, nr, events, timeout))
}

/// `struct __aio_sigset`: a mask pointer and its size. A NULL pointer is no
/// mask whatever the size says.
pub fn sys_io_pgetevents(
    ctx_id: u64,
    min_nr: i64,
    nr: i64,
    events: u64,
    timeout: u64,
    usig: u64,
) -> Result<i64, Errno> {
    strace!("io_pgetevents({ctx_id:#x}, {min_nr}, {nr}, {events:#x}, {timeout:#x}, {usig:#x})");
    let timeout = read_timeout(timeout)?;
    if usig != 0 {
        let mask_at = read_u64(usig)?;
        let size = read_u64(usig + 8)?;
        if mask_at != 0 {
            let mut mask = 0u64;
            let err = signaldeliver::user_get_sigset(mask_at, size, &mut mask);
            if err != 0 {
                return Err(Errno::from_negative_or_eio(err));
            }
            signaldeliver::sigmask_set_temp(mask);
        }
    }
    interrupted(get_events(ctx_id, min_nr, nr, events, timeout))
}
