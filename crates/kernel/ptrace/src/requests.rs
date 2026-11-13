//! `ptrace(2)` request decoding and tracee control protocol.

use super::*;

// ---------------------------------------------------------------- the syscall

/// A stopped tracee of the calling thread, with its tracing state locked,
/// under the caller's `pids_lock`, which is what keeps it alive for as long
/// as this exists.
///
/// Found by number and then asked who traces it, Linux's
/// `ptrace_check_attach`: `child->ptrace && child->parent == current`. It was
/// found by walking the caller's children until 2026-11-13, when a tracee
/// could only be one -- `PTRACE_TRACEME` was the only way in. A tracee is a
/// *thread* now, which no children list holds, and its tracer need not be
/// its parent.
///
/// Borrowed from the caller's `PidsGuard`, so the guard outlives it and the
/// tracing lock is released before `pids_lock`, the reverse of how they were
/// taken.
struct StoppedChild<'a> {
    child: kernel_pids::Task<'a>,
    /// The child's tracing state, for what lives outside its lock.
    ptrace: &'a Ptrace,
    guard: GuestGuard<'a, State>,
}

/// The calling thread's tracee `pid`, stopped or not. Not a zombie: Linux's
/// `ptrace_check_attach` wants a task it can stop.
fn find_tracee(pids: &PidsGuard, pid: c_int) -> Option<(kernel_pids::Task<'_>, &Ptrace)> {
    let me = pids.me()?;
    let task = pids.find_live(pid)?;
    if task.tracer()?.raw() != me.raw() {
        return None;
    }
    Some((task, task.ptrace()?))
}

/// `None` is `ESRCH` to every caller: Linux's `ptrace_check_attach` fails that
/// way both for a pid that is not this thread's tracee and for one that is not
/// stopped.
fn find_stopped_child(pids: &PidsGuard, pid: c_int) -> Option<StoppedChild<'_>> {
    let (child, ptrace) = find_tracee(pids, pid)?;
    let guard = ptrace.lock();
    guard.stopped.then_some(StoppedChild { child, ptrace, guard })
}

/// `PTRACE_CONT`'s `data`: a signal number, or 0 for none. Anything else is
/// `EIO`, which is `ptrace_resume`'s `if (!valid_signal(data)) return -EIO`.
pub(super) fn resume_signal(data: u64) -> Option<c_int> {
    (data <= MAX_SIG as u64).then_some(data as c_int)
}

/// aarch64 Linux has signals 1..=64.
const MAX_SIG: c_int = 64;

/// The options this kernel honours.
///
/// `TRACESYSGOOD` and `TRACEEXEC` change the number a stop that already
/// happens reports. `TRACEEXIT` and the three fork-family events take a stop
/// where the event happens (`crates/kernel/signaldeliver`'s
/// `ptrace_event_stop`); `EXITKILL` is read when the tracer exits.
///
/// `TRACESECCOMP` is the one left, and is refused rather than accepted:
/// `crates/kernel/seccomp` answers `SECCOMP_RET_TRACE` with `ENOSYS`, which
/// is Linux's answer when no tracer asked for the event, and accepting the
/// option would put a tracer into a wait for a stop that never comes.
///
/// **Refusing one is not free either.** Measured, strace sets TRACESYSGOOD
/// and TRACEEXEC in one call, prints `PTRACE_SETOPTIONS: Invalid argument`
/// and detaches on a refusal, so the whole tool was unusable for the sake of
/// a bit that costs four lines.
pub(super) const OPTIONS_HONOURED: u64 = ffi::PTRACE_O_TRACESYSGOOD_ as u64
    | ffi::PTRACE_O_TRACEEXEC_ as u64
    | ffi::PTRACE_O_TRACEEXIT_ as u64
    | O_TRACEFORK
    | O_TRACEVFORK
    | O_TRACECLONE
    | O_TRACEVFORKDONE
    | O_EXITKILL;

pub(super) const O_TRACEFORK: u64 = 0x2;
pub(super) const O_TRACEVFORK: u64 = 0x4;
pub(super) const O_TRACECLONE: u64 = 0x8;
pub(super) const O_TRACEVFORKDONE: u64 = 0x20;
pub(super) const O_EXITKILL: u64 = 0x10_0000;

/// Linux's `PTRACE_O_MASK`: every option it defines, honoured here or not.
/// `PTRACE_SEIZE` answers `EIO` for a bit outside it, where `SETOPTIONS`
/// answers `EINVAL` (`ptrace_attach_probe`).
const OPTIONS_KNOWN: u64 = 0xff | 0x10_0000 | 0x20_0000;

pub(super) fn options_valid(data: u64) -> bool {
    data & !OPTIONS_HONOURED == 0
}

const PTRACE_GETEVENTMSG: u32 = 0x4201;
const PTRACE_INTERRUPT: u32 = 0x4207;
const PTRACE_LISTEN: u32 = 0x4208;
const PTRACE_EVENT_STOP: c_int = 128;

pub fn sys_ptrace(request: u32, pid: c_int, addr: u64, data: u64) -> Result<(), Errno> {
    strace!("ptrace({request}, {pid}, {addr:#x}, {data:#x})");
    match request {
        ffi::PTRACE_TRACEME_ => {
            // Linux's `ptrace_traceme`: EPERM for a task that is already
            // traced, and the tracer is the real parent.
            let pids = PidsGuard::take();
            let me = pids.me().ok_or(Errno::ESRCH)?;
            let ptrace = me.ptrace().ok_or(Errno::ESRCH)?;
            let parent = me.parent().ok_or(Errno::EPERM)?;
            if ptrace.is_traced() || !proctree::attach(me.raw(), parent.raw()) {
                return Err(Errno::EPERM);
            }
            ptrace.attach(false, 0);
            Ok(())
        }

        // arm64's `arch_ptrace` has no PEEKUSER and no GETREGS/SETREGS/
        // GETFPREGS/SETFPREGS -- those are the x86 requests -- and answers EIO
        // for all five. What stood here read a `struct user_`, the i386 one,
        // filled from accessors that returned zeroes: a debugger was told it
        // had the child's registers and had 68 bytes of nothing.
        ffi::PTRACE_PEEKUSER_
        | ffi::PTRACE_GETREGS_
        | ffi::PTRACE_SETREGS_
        | ffi::PTRACE_GETFPREGS_
        | ffi::PTRACE_SETFPREGS_ => Err(Errno::EIO),

        ffi::PTRACE_SETOPTIONS_ => {
            if !options_valid(data) {
                return Err(Errno::EINVAL);
            }
            // Linux's `ptrace_setoptions` is inside `ptrace_check_attach`, so
            // it needs a stopped tracee like every other request -- this used
            // to answer 0 for an empty set whatever pid it was given, which is
            // a success for a process that is not this one's child.
            let pids = PidsGuard::take();
            let Some(mut found) = find_stopped_child(&pids, pid) else {
                return Err(Errno::ESRCH);
            };
            found.guard.options = data as u32;
            Ok(())
        }

        ffi::PTRACE_ATTACH_ | ffi::PTRACE_SEIZE_ => attach(request == ffi::PTRACE_SEIZE_, pid, addr, data),

        // Linux's `ptrace_interrupt` path: any tracee of this thread, stopped
        // or not; EIO unless it was seized. A tracee already in a stop is
        // not stopped again -- the trap is taken on its way back out, which
        // is Linux's too (`JOBCTL_TRAP_STOP` stays set across the resume).
        PTRACE_INTERRUPT => {
            let pids = PidsGuard::take();
            let Some((task, ptrace)) = find_tracee(&pids, pid) else {
                return Err(Errno::ESRCH);
            };
            if !ptrace.lock().seized {
                return Err(Errno::EIO);
            }
            ptrace.request_trap();
            wake(task);
            Ok(())
        }

        // Linux's `ptrace_listen`: a seized tracee in a `PTRACE_EVENT_STOP`
        // stop leaves it for the group stop, without running, to trap again
        // when that ends. EIO otherwise.
        PTRACE_LISTEN => {
            let pids = PidsGuard::take();
            let Some(mut found) = find_stopped_child(&pids, pid) else {
                return Err(Errno::ESRCH);
            };
            // `last_siginfo->si_code >> 8`: the status `wait` took is gone.
            let event_stop = found.guard.has_info && found.guard.info.code >> 8 == PTRACE_EVENT_STOP;
            if !found.guard.seized || !event_stop {
                return Err(Errno::EIO);
            }
            // A `PTRACE_INTERRUPT` made while it was stopped asked for the
            // trap it is already in; Linux's listening tracee is woken only
            // by `JOBCTL_TRAP_NOTIFY` -- an interrupt after this, or the group
            // continuing -- so the request is spent here.
            let _ = found.ptrace.take_trap();
            found.guard.listening = true;
            found.guard.stopped = false;
            found.guard.owner().notify(CONT);
            Ok(())
        }

        PTRACE_GETEVENTMSG => {
            let pids = PidsGuard::take();
            let Some(found) = find_stopped_child(&pids, pid) else {
                return Err(Errno::ESRCH);
            };
            if GuestMem.write(data, &found.guard.event_msg.to_le_bytes()) != 0 {
                return Err(Errno::EFAULT);
            }
            Ok(())
        }

        ffi::PTRACE_PEEKTEXT_ | ffi::PTRACE_PEEKDATA_ => {
            let pids = PidsGuard::take();
            let Some(found) = find_stopped_child(&pids, pid) else {
                return Err(Errno::ESRCH);
            };
            // Two different errors for two different address spaces. Reading
            // the *tracee* is EIO, which is what `generic_ptrace_peekdata`
            // answers for a short `access_process_vm`; writing the caller's
            // `data` is EFAULT, from its own `put_user`. This used EFAULT for
            // both, so a tracer could not tell which of the two addresses it
            // had got wrong.
            //
            // A word is **eight** bytes here. It was four -- i386's, left
            // behind with the rest of that backend -- and a tracer advances by
            // `sizeof(long)` between peeks, so every second half of every
            // string it read was skipped: strace printed the first execve of
            // `/bin/echo` as `execve("/bin", ["/bin", "hi"], ...)`, which is
            // four bytes followed by whatever the caller's buffer already had.
            let mut word = [0u8; 8];
            // Retained, as every cross-task copy is: a stopped tracee cannot
            // exec, but another thread of its process can.
            let Some(mm) = mmapcalls::mm::GeneralGuard::of(found.child.task()).mm() else {
                return Err(Errno::EIO);
            };
            if mmapcalls::usermem::read_held(&mut mm.read(), addr, &mut word) != 0 {
                return Err(Errno::EIO);
            }
            if GuestMem.write(data, &word) != 0 {
                return Err(Errno::EFAULT);
            }
            Ok(())
        }

        ffi::PTRACE_POKETEXT_ | ffi::PTRACE_POKEDATA_ => {
            let pids = PidsGuard::take();
            let Some(found) = find_stopped_child(&pids, pid) else {
                return Err(Errno::ESRCH);
            };
            // Eight bytes, for the reason the peek above gives: a four-byte
            // poke left the top half of the tracee's word untouched, so a
            // debugger writing a breakpoint wrote half of one.
            let word = data.to_le_bytes();
            let Some(mm) = mmapcalls::mm::GeneralGuard::of(found.child.task()).mm() else {
                return Err(Errno::EIO);
            };
            let r = mmapcalls::usermem::write_held_ptrace(&mut mm.read(), addr, &word);
            if r != 0 { Err(Errno::EIO) } else { Ok(()) }
        }

        // `PTRACE_SINGLESTEP` is `PTRACE_CONT` here: nothing single-steps, and
        // continuing is a closer answer than refusing -- a tracer that asked
        // gets one more stop's worth of progress rather than none.
        // TODO: refuse it instead, once something can be asked whether a
        // debugger copes better with EIO than with a step that runs away.
        ffi::PTRACE_CONT_
        | ffi::PTRACE_SINGLESTEP_
        | ffi::PTRACE_DETACH_
        | ffi::PTRACE_SYSCALL_ => {
            // `data` is the signal to deliver as the tracee resumes -- the one
            // it stopped for, passed through, or another, or 0 to suppress it.
            // Linux's `ptrace_resume` refuses anything that is not a signal
            // number with EIO. This was ignored until 2026-09-04: a tracer
            // that passed a signal through had it dropped, so a program run
            // under strace never received one.
            let Some(sig) = resume_signal(data) else {
                return Err(Errno::EIO);
            };
            let pids = PidsGuard::take();
            let Some(mut found) = find_stopped_child(&pids, pid) else {
                return Err(Errno::ESRCH);
            };
            if request == ffi::PTRACE_DETACH_ {
                // Linux's `ptrace_detach`: the tracee is no longer traced and
                // resumes as a CONT would. The next signal to it is delivered
                // without a stop.
                found.ptrace.set_detached();
                proctree::detach(found.child.raw());
            }
            // Whether the tracee stops again at the next syscall boundary.
            // Written while it is stopped, so the plain store the tracee reads
            // without the lock cannot race a boundary it is at.
            found.ptrace.set_stops_at_syscalls(request == ffi::PTRACE_SYSCALL_);
            found.guard.resume_signal = sig;
            found.guard.stopped = false;
            found.guard.owner().notify(CONT);
            Ok(())
        }

        ffi::PTRACE_KILL_ => {
            let pids = PidsGuard::take();
            let Some(mut found) = find_stopped_child(&pids, pid) else {
                return Err(Errno::ESRCH);
            };
            found.guard.stopped = false;
            // Under this lock, which is why the module comment states the
            // order: delivering SIGKILL takes `sighand`'s.
            signal(found.child, ffi::SIGKILL_ as c_int);
            found.guard.owner().notify(CONT);
            Ok(())
        }

        ffi::PTRACE_GETSIGINFO_ => {
            let pids = PidsGuard::take();
            let Some(found) = find_stopped_child(&pids, pid) else {
                return Err(Errno::ESRCH);
            };
            // An attached tracee's group stop has nothing to read.
            if !found.guard.has_info {
                return Err(Errno::EINVAL);
            }
            if data == 0 {
                return Ok(());
            }
            if GuestMem.write(data, kernel_sigqueue::as_bytes(&found.guard.info)) != 0 {
                return Err(Errno::EFAULT);
            }
            Ok(())
        }

        ffi::PTRACE_GETREGSET_ | ffi::PTRACE_SETREGSET_ => {
            let writing = request == ffi::PTRACE_SETREGSET_;
            let pids = PidsGuard::take();
            let Some(found) = find_stopped_child(&pids, pid) else {
                return Err(Errno::ESRCH);
            };
            regset(found.child.raw(), writing, addr as c_int, data)
        }

        _ => Err(Errno::EIO),
    }
}

/// `PTRACE_ATTACH` and `PTRACE_SEIZE`: Linux's `ptrace_attach`, in its
/// order. The tracee is a thread, named by its tid.
///
/// An attach sends `SIGSTOP`, so the tracer's next `wait` reports the
/// tracee stopped; a seize does not stop it, takes its options at once, and
/// is what `PTRACE_INTERRUPT` needs.
fn attach(seize: bool, pid: c_int, addr: u64, data: u64) -> Result<(), Errno> {
    if seize {
        if addr != 0 || data & !OPTIONS_KNOWN != 0 {
            return Err(Errno::EIO);
        }
        if !options_valid(data) {
            return Err(Errno::EINVAL);
        }
    }
    let pids = PidsGuard::take();
    let me = pids.me().ok_or(Errno::ESRCH)?;
    let target = pids.find_live(pid).ok_or(Errno::ESRCH)?;
    // `same_thread_group(task, current)`, then `ptrace_may_access`, then
    // "already traced" and "exiting": all EPERM.
    if target.is_in_callers_group() || !target.may_ptrace(kernel_creds::PtraceMode::AttachReal) {
        return Err(Errno::EPERM);
    }
    let ptrace = target.ptrace().ok_or(Errno::EPERM)?;
    if target.task().exiting.get() || ptrace.is_traced() || !proctree::attach(target.raw(), me.raw()) {
        return Err(Errno::EPERM);
    }
    ptrace.attach(seize, if seize { data as u32 } else { 0 });
    if !seize {
        signal(target, ffi::SIGSTOP_ as c_int);
    }
    // Already in a group stop: Linux's `ptrace_attach` makes it trap into a
    // ptrace stop at once (`JOBCTL_TRAP_STOP`), so the tracer's `wait`
    // reports it. The thread is asleep in the group stop, which wakes it to
    // look.
    if let Some(g) = target.group() {
        g.stop().kick();
    }
    Ok(())
}

/// `PTRACE_GETREGSET` and `PTRACE_SETREGSET`.
///
/// `addr` is the note type and `data` points at an `iovec` the caller owns. The
/// kernel transfers `min(iov_len, regset size)` and writes back what it moved,
/// which is how a caller discovers the size of a set it does not know.
// Both halves of this signature changed on 2026-09-11 and the merge keeps both:
// the crate stopped declaring its own `struct Task` placeholder and names
// `ffi::task` like its two neighbours above, and this family answers a `Result`
// rather than a negative `c_int`.
fn regset(child: *mut ffi::task, writing: bool, note: c_int, data: u64) -> Result<(), Errno> {
    // SAFETY: a stopped tracee found under the lock the caller holds.
    let Some(mut set) = (unsafe { regset::get(child, note) }) else {
        return Err(Errno::EINVAL);
    };

    let mut iov = [0u8; 16];
    if GuestMem.read(data, &mut iov) != 0 {
        return Err(Errno::EFAULT);
    }
    let base = u64::from_le_bytes(iov[0..8].try_into().unwrap());
    let len = u64::from_le_bytes(iov[8..16].try_into().unwrap());
    // The current value is read first either way: a short `SETREGSET` leaves
    // the rest of the set as it was, which is only possible if the rest is
    // here.
    let buf = set.bytes_mut();
    let n = std::cmp::min(len as usize, buf.len());

    if writing {
        if GuestMem.read(base, &mut buf[..n]) != 0 {
            return Err(Errno::EFAULT);
        }
        // SAFETY: as above.
        unsafe { regset::set(child, &set) };
    } else if GuestMem.write(base, &buf[..n]) != 0 {
        return Err(Errno::EFAULT);
    }

    iov[8..16].copy_from_slice(&(n as u64).to_le_bytes());
    if GuestMem.write(data, &iov) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}
