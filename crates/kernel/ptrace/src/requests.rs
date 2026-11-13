//! `ptrace(2)` request decoding and tracee control protocol.

use super::*;

// ---------------------------------------------------------------- the syscall

/// A stopped child of the calling task, with its tracing state locked, under
/// the caller's `pids_lock`, which is what keeps the child alive for as long as
/// this exists.
///
/// The child is found by walking the caller's children, and the walk, the
/// lookup and every use of the pointer happen under the one guard: a task
/// found through the process tree can be reaped and freed the moment
/// `pids_lock` is dropped, and a tracer's other thread in `wait4` is exactly
/// what does that. This is the shape `crates/kernel/rescalls`'s `prlimit` has,
/// and it was a TODO here for want of the lock order being checked -- see the
/// module comment for the check.
///
/// Borrowed from the caller's `PidsGuard`, so the guard outlives it and the
/// tracing lock is released before `pids_lock`, the reverse of how they were
/// taken. It held the guard itself until 2026-10-17, which made the struct
/// borrow from its own field and needed a `'static` that was not true.
struct StoppedChild<'a> {
    child: kernel_pids::Task<'a>,
    /// The child's tracing state, for what lives outside its lock.
    ptrace: &'a Ptrace,
    guard: GuestGuard<'a, State>,
}

/// `None` is `ESRCH` to every caller: Linux's `ptrace_check_attach` fails that
/// way both for a pid that is not this process's tracee and for one that is not
/// stopped.
fn find_stopped_child(pids: &PidsGuard, pid: c_int) -> Option<StoppedChild<'_>> {
    let child = pids.me()?.children().find(|c| c.pid() == pid)?;
    let ptrace = child.ptrace()?;
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

/// The options this kernel honours, which is two.
///
/// Both are cheap for the same reason: they change the *number* a stop that
/// already happens reports, and nothing else. `PTRACE_O_TRACESYSGOOD` is a bit
/// in the signal of a syscall-stop; `PTRACE_O_TRACEEXEC` re-labels the stop
/// `execve` has always taken after a successful exec.
///
/// The rest ask for an event -- a fork, a vfork, a clone, an exit, a seccomp
/// trap -- at a point where nothing here stops at all, and accepting one would
/// put the tracer into a wait for a stop that never arrives.
///
/// **Refusing one is not free either**, which is what the note that used to
/// stand here got wrong: it said an EINVAL makes a tracer "say the kernel is
/// too old and carry on". Measured, strace does not carry on -- it sets
/// TRACESYSGOOD and TRACEEXEC in one call, prints `PTRACE_SETOPTIONS: Invalid
/// argument` and detaches, so the whole tool was unusable for the sake of a
/// bit that costs four lines. Between refusing and pretending there is a third
/// answer, and for an event whose stop exists it is the right one.
pub(super) const OPTIONS_HONOURED: u64 = ffi::PTRACE_O_TRACESYSGOOD_ as u64
    | ffi::PTRACE_O_TRACEEXEC_ as u64
    | ffi::PTRACE_O_TRACEEXIT_ as u64;

pub(super) fn options_valid(data: u64) -> bool {
    data & !OPTIONS_HONOURED == 0
}

pub fn sys_ptrace(request: u32, pid: c_int, addr: u64, data: u64) -> Result<(), Errno> {
    strace!("ptrace({request}, {pid}, {addr:#x}, {data:#x})");
    match request {
        ffi::PTRACE_TRACEME_ => {
            taskview::with_current_ptrace(|me| me.set_traced()).ok_or(Errno::ESRCH)
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

        // Attaching to an already-running process is not implemented. EPERM is
        // what Linux answers for the one case a program can compare against --
        // attaching to itself -- and is what "you may not trace this" means,
        // where the EIO below means "no such request".
        ffi::PTRACE_ATTACH_ | ffi::PTRACE_SEIZE_ => Err(Errno::EPERM),

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
            kill(found.child);
            found.guard.owner().notify(CONT);
            Ok(())
        }

        ffi::PTRACE_GETSIGINFO_ => {
            let pids = PidsGuard::take();
            let Some(found) = find_stopped_child(&pids, pid) else {
                return Err(Errno::ESRCH);
            };
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
