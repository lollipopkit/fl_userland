//! Telling the time, and waiting.
//!
//! `clock_gettime`, `clock_getres`, `clock_settime`, `gettimeofday`,
//! `settimeofday`, `nanosleep`, `clock_nanosleep` and `times`, from
//! `kernel/time.c`, and `adjtimex` and `clock_adjtime`. Which of the eight guest clock ids is answered from which
//! host clock, and every piece of arithmetic they do, is
//! `crates/util/timeabi`; what is here is the host calls and the guest copies.
//!
//! No struct definitions. The guest's `timespec`, `timeval` and `tms` are 16,
//! 16 and 32 bytes of little-endian 64-bit words, written out as offsets in
//! [`put_timespec`] and its neighbours, because that is the form a static
//! assertion can check and a struct is not — the same argument
//! `crates/fs/cmsg` and `crates/kernel/sigframe` were built on.


use std::ffi::{c_int, c_uint};

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

mod timers;
pub use timers::{itimer_get_for_rs, itimer_set_for_rs, itimer_which_valid_for_rs};

use strace::strace;
use usercopy::GuestMem;

mod wire;
use util_timeabi as timeabi;
use wire::{get_timespec, put_timespec, put_timeval, read_pair, write_pair};

/// `struct rusage_` is `crates/kernel/hostrusage`'s.
///
/// This file declared its own -- the first four fields flattened into
/// `utime_sec`/`utime_usec`/`stime_sec`/`stime_usec`, plus `rest: [i64; 14]`
/// "so that returning one by value from C matches". `rusage_get_process` is a
/// Rust function in `crates/kernel/rescalls` returning `hostrusage::Rusage`,
/// and the two met through a C ABI that reinterprets rather than checks: a
/// fifth rendering of one 144-byte struct.
use guest_errno::Errno;
use hostrusage::Rusage;
use kernel_hoststats::get_uptime_ticks;

// ---------------------------------------------------------------------------
// The host clocks
// ---------------------------------------------------------------------------

fn host_clock_id(c: timeabi::HostClock) -> libc::clockid_t {
    match c {
        timeabi::HostClock::Realtime => libc::CLOCK_REALTIME,
        timeabi::HostClock::Monotonic => libc::CLOCK_MONOTONIC,
    }
}

fn host_now(c: libc::clockid_t) -> Result<(i64, i64), Errno> {
    timeabi::host_clock(c).map_err(host_errno)
}

/// A host errno in hand, as the guest's.
fn host_errno(host: c_int) -> Errno {
    Errno::from_negative_or_eio(kernel_errno::raised(host))
}

/// Which task a CPU-time clock counts, once its pid has been checked.
#[derive(Clone, Copy)]
struct CpuClock {
    pid: i32,
    per_thread: bool,
    which: timeabi::CpuWhich,
}

/// Check a CPU clock's task. `pid` 0 is the caller; another pid is any
/// process, or a thread of the caller's own group, as on Linux -- `EINVAL`
/// otherwise, which is also what a pid nobody has answers.
///
/// Another task's clock was `EINVAL` here until 2026-11-11, along with the
/// caller's own encoded ones (`clock2_probe`); `pthread_getcpuclockid` hands
/// out exactly those, for a profiler reading every thread.
fn cpu_clock(pid: i32, per_thread: bool, which: timeabi::CpuWhich) -> Result<CpuClock, Errno> {
    rescalls::task_cpu(pid, per_thread).ok_or(Errno::EINVAL)?;
    Ok(CpuClock { pid, per_thread, which })
}

/// A task's consumed CPU time in nanoseconds.
///
/// Two things these clocks are, and neither was true here. They measure *CPU
/// time*, which is user plus system — only the user half was reported, so a
/// syscall-heavy program looked idle. And `PROCESS` is the thread group where
/// `THREAD` is one thread; both answered the thread, so the two clocks were the
/// same clock under different names.
fn cpu_time_nsec(clock: CpuClock) -> Result<i64, Errno> {
    // Asked again rather than kept from `cpu_clock`: the task can exit
    // between the two, and a clock read is a reading, not a validation.
    let ru = rescalls::task_cpu(clock.pid, clock.per_thread).ok_or(Errno::EINVAL)?;
    let (stime_sec, stime_usec) = match clock.which {
        timeabi::CpuWhich::Virt => (0, 0),
        timeabi::CpuWhich::Prof | timeabi::CpuWhich::Sched => (ru.stime.sec, ru.stime.usec),
    };
    timeabi::cpu_time_nsec(ru.utime.sec, ru.utime.usec, stime_sec, stime_usec)
        .ok_or(Errno::EOVERFLOW)
}

/// What a clock id reads, with an encoded CPU clock's task checked.
#[derive(Clone, Copy)]
enum Source {
    Host(libc::clockid_t),
    Cpu(CpuClock),
}

fn source_of(clock: c_uint) -> Result<Source, Errno> {
    match timeabi::clock_of(clock) {
        timeabi::Clock::Host(h) => Ok(Source::Host(host_clock_id(h))),
        timeabi::Clock::Cpu { pid, per_thread, which } => {
            cpu_clock(pid, per_thread, which).map(Source::Cpu)
        }
        timeabi::Clock::Invalid => Err(Errno::EINVAL),
    }
}

fn now_of(source: Source) -> Result<(i64, i64), Errno> {
    match source {
        Source::Host(c) => host_now(c),
        Source::Cpu(c) => Ok(timeabi::nsec_to_timespec(cpu_time_nsec(c)?)),
    }
}

pub fn sys_clock_gettime(clock: c_uint, tp: u64) -> Result<(), Errno> {
    strace!("clock_gettime({clock}, {tp:#x})");
    let (sec, nsec) = now_of(source_of(clock)?)?;
    put_timespec(tp, sec, nsec)?;
    strace!(" {{{sec}s {nsec}ns}}");
    Ok(())
}

pub fn sys_clock_getres(clock: c_uint, res_addr: u64) -> Result<(), Errno> {
    strace!("clock_getres({clock}, {res_addr:#x})");
    let (sec, nsec) = match source_of(clock)? {
        // The host's, which is a microsecond on macOS where Linux with high
        // resolution timers says a nanosecond (and a tick for the coarse
        // clocks). The host's is the true one: these clocks are its clocks.
        Source::Host(c) => timeabi::host_clock_res(c).map_err(host_errno)?,
        // Linux reports a nanosecond for the scheduler clocks. Both used to be
        // EINVAL, because the clock table did not know them -- so a program that
        // asks the resolution before using one was told the clock does not
        // exist.
        Source::Cpu(CpuClock { which: timeabi::CpuWhich::Sched, .. }) => {
            (0, timeabi::CPUTIME_RESOLUTION_NSEC)
        }
        // `PROF` and `VIRT` are sampled at the tick on Linux, and say so:
        // `NSEC_PER_SEC / HZ`, a millisecond on the reference kernel.
        Source::Cpu(_) => (0, timeabi::CPUTIME_TICK_NSEC),
    };
    // A null destination is a question about the *clock* and not about the
    // resolution: Linux validates the clock id and answers 0 without writing
    // anything, where `clock_gettime(clock, NULL)` -- which has no other reason
    // to be called -- is `EFAULT`. This answered `EFAULT` for both, so the
    // cheapest way to ask whether a clock exists reported a bad pointer.
    if res_addr == 0 {
        return Ok(());
    }
    put_timespec(res_addr, sec, nsec)
}

/// Setting the wall clock is a machine-wide effect an emulated guest does not
/// get, root or not: it is answered as for a process without `CAP_SYS_TIME`.
///
/// That answer is not `EPERM` for everything. Linux checks the clock, then
/// reads the time, then validates it, and only then asks for the capability,
/// so a malformed request is told what is wrong with it. Measured against 7.2
/// by `clock2_probe` with the container's seccomp filter off (the filter says
/// `EPERM` to every argument); this answered `EPERM` to all of them until
/// 2026-11-11.
pub fn sys_clock_settime(clock: c_uint, tp: u64) -> Result<(), Errno> {
    strace!("clock_settime({clock}, {tp:#x})");
    if !timeabi::ops(clock).is_some_and(|o| o.set) {
        return Err(Errno::EINVAL);
    }
    let (sec, nsec) = get_timespec(tp)?;
    match timeabi::clock_of(clock) {
        // `posix_cpu_clock_set`: "you can never reset a CPU clock", once the
        // clock itself has been found valid.
        timeabi::Clock::Cpu { pid, per_thread, which } => {
            cpu_clock(pid, per_thread, which)?;
            Err(Errno::EPERM)
        }
        timeabi::Clock::Host(_) => settod(Some((sec, nsec)), false),
        // A dynamic clock, whose descriptor is never a `/dev/ptp*` here, or
        // an encoded CPU clock of no kind.
        timeabi::Clock::Invalid => Err(Errno::EINVAL),
    }
}

/// `do_sys_settimeofday64`'s order: the time is validated, and then
/// `CAP_SYS_TIME` asked -- before the timezone, which is why a bad
/// `tz_minuteswest` is `EPERM` without it.
///
/// With it, a request that changes nothing (`settimeofday(NULL, NULL)`) is the
/// success it is on Linux, measured; anything that would set the host's clock
/// or timezone is still refused as for a caller without it.
fn settod(time: Option<(i64, i64)>, tz: bool) -> Result<(), Errno> {
    if let Some((sec, nsec)) = time
        && !timeabi::timespec_valid_settod(sec, nsec)
    {
        return Err(Errno::EINVAL);
    }
    if time.is_none() && !tz && taskview::capable(taskview::caps::CAP_SYS_TIME) {
        return Ok(());
    }
    Err(Errno::EPERM)
}

// ---------------------------------------------------------------------------
// The clock discipline
// ---------------------------------------------------------------------------

mod adjtime;

/// `adjtimex`: `clock_adjtime(CLOCK_REALTIME, ...)`, as Linux's is.
pub fn sys_adjtimex(buf: u64) -> Result<i64, Errno> {
    strace!("adjtimex({buf:#x})");
    adjtime::clock_adjtime(timeabi::clock::REALTIME, buf)
}

pub fn sys_clock_adjtime(clock: c_uint, buf: u64) -> Result<i64, Errno> {
    strace!("clock_adjtime({clock}, {buf:#x})");
    adjtime::clock_adjtime(clock, buf)
}

// ---------------------------------------------------------------------------
// Sleeping
// ---------------------------------------------------------------------------

/// Sleeps until a deadline on `clock`.
///
/// A loop, and the remaining time is recomputed from the clock on every pass.
/// The version this replaces worked out `deadline - now` once and slept for
/// that long, which is a stopwatch and not a deadline: everything that delayed
/// the thread between reading the clock and entering the sleep — a page fault,
/// another guest thread, the host scheduler — came out of the far end.
///
/// The re-read is not only about that first gap. macOS has no
/// `clock_nanosleep`, so an absolute sleep is host `nanosleep` either way, and
/// a host `nanosleep` that returns early for any reason would otherwise be
/// taken for the deadline having arrived.
///
/// A CPU-time clock is the same loop with a different clock and shorter
/// naps: the process's CPU time cannot advance faster than wall time on every
/// host processor at once, so a nap of what is left divided by the processor
/// count never sleeps past the deadline. Bounded below so the loop does not
/// spin, and above so a thread that starts working is noticed.
fn sleep_until(clock: Source, deadline_sec: i64, deadline_nsec: i64) -> Result<(), Errno> {
    loop {
        let (now_sec, now_nsec) = now_of(clock)?;
        let Some(left) = timeabi::remaining_until(deadline_sec, deadline_nsec, now_sec, now_nsec)
        else {
            // Past the deadline by more than an i64 of nanoseconds, which is
            // the same answer as any other overshoot: it is time.
            return Ok(());
        };
        if left <= 0 {
            return Ok(());
        }
        let nap = match clock {
            Source::Host(_) => left,
            Source::Cpu(_) => {
                let cpus = std::thread::available_parallelism().map_or(1, |n| n.get() as i64);
                (left / cpus).clamp(50_000, 10_000_000)
            }
        };
        let (sec, nsec) = timeabi::nsec_to_timespec(nap);
        let req = rustix::fs::Timespec {
            tv_sec: sec,
            tv_nsec: nsec as _,
        };
        // `rustix`'s rather than `std::thread::sleep`, which retries an
        // interrupted sleep: here an interruption is how a signal for the
        // guest ends the wait, and it has to come back as `EINTR`.
        taskview::set_blocking(true);
        let slept = rustix::thread::nanosleep(&req);
        taskview::set_blocking(false);
        match slept {
            rustix::thread::NanosleepRelativeResult::Ok => {}
            rustix::thread::NanosleepRelativeResult::Interrupted(_) => return Err(Errno::EINTR),
            rustix::thread::NanosleepRelativeResult::Err(e) => {
                return Err(Errno::from_negative_or_eio(kernel_errno::raised(e.raw_os_error())));
            }
        }
    }
}

pub fn sys_clock_nanosleep(
    clock: c_uint,
    flags: c_uint,
    req_addr: u64,
    rem_addr: u64,
) -> Result<(), Errno> {
    // Linux's order, measured by `clock2_probe`: the clock (`EINVAL` for
    // none, `EOPNOTSUPP` for one that cannot be slept on), then the request
    // (`EFAULT`, `EINVAL`), then the clock's own rules. The request was read
    // first until 2026-11-11, and every clock that is readable was sleepable
    // -- the raw and coarse clocks among them, which Linux refuses.
    let Some(ops) = timeabi::ops(clock) else {
        return Err(Errno::EINVAL);
    };
    if !ops.sleep {
        return Err(Errno::EOPNOTSUPP);
    }
    let (req_sec, req_nsec) = get_timespec(req_addr)?;
    strace!("clock_nanosleep({clock}, {flags}, {{{req_sec}, {req_nsec}}}, {rem_addr:#x})");
    // Before the arithmetic, not after: subtracting `now` from a denormalised
    // request can land on a normal-looking one, so an input Linux refuses would
    // be slept on instead.
    if !timeabi::timespec_valid(req_sec, req_nsec) {
        return Err(Errno::EINVAL);
    }
    // The alarm clocks want `CAP_WAKE_ALARM`, which no guest has: waking the
    // machine from suspend is the host's decision.
    if ops.alarm {
        return Err(Errno::EPERM);
    }
    let real = match timeabi::clock_of(clock) {
        // `posix_cpu_nsleep` refuses the caller's own thread clock -- sleeping
        // on your own CPU time stops it advancing. Another thread's is fine.
        timeabi::Clock::Cpu { pid, per_thread: true, .. }
            if pid == 0 || pid == taskview::current_pid() =>
        {
            return Err(Errno::EINVAL);
        }
        _ => source_of(clock)?,
    };

    // Only the bottom bit is looked at, and the rest are ignored rather than
    // refused. That is Linux's behaviour and it is not obvious: a rejection was
    // written here and a real kernel disagreed.
    //
    // EINTR does not fill in a remainder for an absolute sleep: a caller that
    // named a deadline already knows what it is, which is why Linux does not
    // either.
    if timeabi::nanosleep_is_absolute(flags) {
        return sleep_until(real, req_sec, req_nsec);
    }

    // Relative. The deadline is worked out here so that the same loop runs: a
    // relative sleep is a deadline the caller did not have to name, and an early
    // return from the host is the same mistake either way.
    let (now_sec, now_nsec) = now_of(real)?;
    // `timeabi::absolute_deadline`, not written out here: it saturates, and
    // `timespec_valid` puts no upper bound on `tv_sec` because Linux does not
    // either -- so `clock_nanosleep(CLOCK_MONOTONIC, 0, {LLONG_MAX, 0}, NULL)`
    // is a request a real kernel accepts, and `now_sec + req_sec` overflowed.
    // With overflow checks on that is a panic in a function that cannot unwind,
    // which aborts the emulator; without them the sum wraps and a sleep meant to
    // last for ever returns at once. The same line was written out by hand in
    // four other syscalls.
    //
    // Its carry is a `divmod` rather than one subtraction, which is also why
    // this stopped being written here: the version above handled one carry, and
    // one carry is enough only while both nanosecond fields are below a billion.
    let (sec, nsec) = timeabi::absolute_deadline(now_sec, now_nsec, req_sec, req_nsec);

    sleep_to_deadline(clock, sec, nsec, rem_addr)
}

/// The rest of a relative sleep, to the absolute deadline it was turned
/// into: where `clock_nanosleep` goes on, and where `restart_syscall` picks
/// it up.
///
/// Interrupted, it reports what is left, which is what a caller whose handler
/// ran resumes with -- recomputed from the deadline rather than taken from
/// the host's `rem`, because the loop may have slept more than once -- and
/// leaves the deadline behind as a restart block: with no handler, Linux's
/// `ERESTART_RESTARTBLOCK` sleeps on for what is left, so `^Z`, `fg` or a
/// debugger attaching does not cut the sleep short (`stoprestart_probe`).
fn sleep_to_deadline(clock: c_uint, sec: i64, nsec: i64, rem_addr: u64) -> Result<(), Errno> {
    let real = source_of(clock)?;
    let slept = sleep_until(real, sec, nsec);
    if slept == Err(Errno::EINTR) {
        if rem_addr != 0
            && let Ok((after_sec, after_nsec)) = now_of(real)
        {
            let left = timeabi::remaining_until(sec, nsec, after_sec, after_nsec).unwrap_or(0);
            let (rem_sec, rem_nsec) = timeabi::nsec_to_timespec(left);
            put_timespec(rem_addr, rem_sec, rem_nsec)?;
        }
        let block = kernel_syscallrestart::Block {
            run: restart_sleep,
            data: [clock as u64, sec as u64, nsec as u64, rem_addr],
        };
        taskview::with_current_restart(|r| r.set_block(block));
    }
    slept
}

/// `restart_syscall` for an interrupted relative sleep.
fn restart_sleep(data: &[u64; 4]) -> i64 {
    match sleep_to_deadline(data[0] as c_uint, data[1] as i64, data[2] as i64, data[3]) {
        Ok(()) => 0,
        Err(e) => e.as_i64(),
    }
}

/// `nanosleep`.
///
/// Linux's is `clock_nanosleep(CLOCK_MONOTONIC, 0, ...)` and so is this, so
/// that there is one sleep loop rather than two that drift apart.
///
/// There used to be a "short-circuit for <=1ms sleeps (common in Go runtime
/// timer management)" that called `sched_yield()` and returned 0. It did not
/// sleep: 200 sleeps of a millisecond took 0 ms end to end. A sleep is a lower
/// bound in every description of the call there is, so a program polling every
/// millisecond was spinning at whatever rate the emulator could manage — which
/// costs more CPU than the sleep it was avoiding.
pub fn sys_nanosleep(req_addr: u64, rem_addr: u64) -> Result<(), Errno> {
    strace!("nanosleep({req_addr:#x}, {rem_addr:#x})");
    sys_clock_nanosleep(timeabi::clock::MONOTONIC, 0, req_addr, rem_addr)
}

// ---------------------------------------------------------------------------
// The time of day, and consumed time
// ---------------------------------------------------------------------------

pub fn sys_gettimeofday(tv: u64, tz: u64) -> Result<(), Errno> {
    strace!("gettimeofday({tv:#x}, {tz:#x})");
    let (sec, nsec) = host_now(libc::CLOCK_REALTIME)?;
    if tv != 0 {
        put_timeval(tv, sec, nsec / 1000)?;
    }
    if tz != 0 {
        // `struct timezone` is obsolete: Linux reports zeros, and so does the
        // host call it used to be filled from.
        let b = [0u8; 8];
        if GuestMem.write(tz, &b) != 0 {
            return Err(Errno::EFAULT);
        }
    }
    Ok(())
}

/// As [`sys_clock_settime`]: a machine-wide effect an emulated guest does not
/// get, answered in Linux's order -- the time is read and checked (`EFAULT`,
/// `EINVAL`) and the timezone read (`EFAULT`) before the permission.
pub fn sys_settimeofday(tv: u64, tz: u64) -> Result<(), Errno> {
    strace!("settimeofday({tv:#x}, {tz:#x})");
    let time = if tv == 0 {
        None
    } else {
        let (sec, usec) = get_timespec(tv)?;
        // `> USEC_PER_SEC`, not `>=`: a million microseconds passes this and
        // is refused below as a billion nanoseconds.
        if !(0..=timeabi::USEC_PER_SEC).contains(&usec) {
            return Err(Errno::EINVAL);
        }
        Some((sec, usec * timeabi::NSEC_PER_USEC))
    };
    if tz != 0 {
        let mut b = [0u8; 8];
        if GuestMem.read(tz, &mut b) != 0 {
            return Err(Errno::EFAULT);
        }
    }
    settod(time, tz != 0)
}

pub fn sys_times(tbuf: u64) -> Result<i64, Errno> {
    strace!("times({tbuf:#x})");
    if tbuf != 0 {
        // The caller's own time is the whole thread group's, not one thread's.
        let own = rescalls::rusage_get_process();
        // And the children's is the children's. These two were assigned from
        // tms_utime/tms_stime -- the caller's own -- so times() reported that
        // every process had spent exactly as long in its children as in itself,
        // including a process with no children at all. A shell doing job
        // accounting from times() got its own runtime back, doubled.
        let mut children = Rusage::default();
        // The group's reaped children, from `crates/kernel/grouprusage`
        // through `crates/kernel/taskview`. Both halves of this were one C
        // function in `kernel/task.c` until 2026-09-03.
        if let Some(kids) = taskview::with_current_group_times(|t| t.children()) {
            let (u, s) = (kids.utime(), kids.stime());
            children.utime = u;
            children.stime = s;
        }

        let ticks = |sec: i64, usec: i64| timeabi::timeval_to_ticks(sec, usec);
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&ticks(own.utime.sec, own.utime.usec).to_le_bytes());
        b[8..16].copy_from_slice(&ticks(own.stime.sec, own.stime.usec).to_le_bytes());
        b[16..24].copy_from_slice(&ticks(children.utime.sec, children.utime.usec).to_le_bytes());
        b[24..].copy_from_slice(&ticks(children.stime.sec, children.stime.usec).to_le_bytes());
        if GuestMem.write(tbuf, &b) != 0 {
            return Err(Errno::EFAULT);
        }
    }
    // Linux answers with the uptime in clock ticks, not zero:
    //
    //     force_successful_syscall_return();
    //     return (long) jiffies_64_to_clock_t(get_jiffies_64());
    //
    // Returning 0 made every call look like the same instant, so a program
    // measuring elapsed time by subtracting two times() results -- which is what
    // the call is *for*, and what its man page shows -- measured zero. The tms
    // fields were right, which is what made it survive.
    Ok(get_uptime_ticks() as i64)
}

// ---------------------------------------------------------------------------
// The three interval timers
// ---------------------------------------------------------------------------

// The seven that were in kernel/time.c are the `timers` module now; the table
// itself is `crates/kernel/posixtimers`, called as Rust. Its `Spec` is value
// then interval, **the opposite** of the guest's `itimerval` and `itimerspec`,
// which put the interval first; the four-element arrays below are in the
// guest's order.

pub fn sys_setitimer(which: c_int, new_val_addr: u64, old_val_addr: u64) -> Result<(), Errno> {
    // A null new value means **disarm**, not `EFAULT`. Linux's `setitimer` zeroes
    // the buffer for a null pointer and warns once in the kernel log that the
    // "misfeature support will be removed"; it has not been, and callers rely on
    // it. `timer_settime` next door refuses the same thing with `EINVAL`, and
    // `getitimer` -- which has an answer to write -- refuses it with `EFAULT`.
    // Three neighbouring calls, three answers, all measured.
    let [int_sec, int_usec, val_sec, val_usec] = if new_val_addr == 0 {
        [0; 4]
    } else {
        read_pair(new_val_addr)?
    };
    strace!(
        "setitimer({which}, {{{val_sec}s {val_usec}us, {int_sec}s {int_usec}us}}, {old_val_addr:#x})"
    );

    // Nothing checked either field. A tv_usec of two million was accepted and
    // multiplied into a tv_nsec of two billion, which is not a timespec; a
    // negative one became a negative nanosecond count. Linux refuses both, for
    // the interval as well as the value -- the interval is what every re-arm
    // after the first one uses.
    if !timeabi::itimerval_valid(val_sec, val_usec, int_sec, int_usec) {
        return Err(Errno::EINVAL);
    }
    let (Some(val_nsec), Some(int_nsec)) = (
        timeabi::usec_to_nsec(val_usec),
        timeabi::usec_to_nsec(int_usec),
    ) else {
        return Err(Errno::EINVAL);
    };

    let mut old = [0i64; 4];
    let err = itimer_set_for_rs(which, val_sec, val_nsec, int_sec, int_nsec, &mut old);
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }
    if old_val_addr != 0 {
        // Back to microseconds, and interval first as the guest's struct has it.
        let out = [old[0], old[1] / 1000, old[2], old[3] / 1000];
        write_pair(old_val_addr, out)?;
    }
    Ok(())
}

pub fn sys_getitimer(which: c_int, val_addr: u64) -> Result<(), Errno> {
    strace!("getitimer({which}, {val_addr:#x})");
    // All three answer, and only ITIMER_REAL can have anything to report.
    //
    // Refusing the other two was the difference: a program that wants a
    // periodic signal asks whether one is already armed before arming its own,
    // and EINVAL turns that question into a failure the caller cannot tell from
    // a real one. Linux answers zeroes, which is what "none is set" is.
    if !itimer_which_valid_for_rs(which) {
        return Err(Errno::EINVAL);
    }
    let mut got = [0i64; 4];
    let err = itimer_get_for_rs(which, &mut got);
    if err < 0 {
        return Err(Errno::from_negative_or_eio(err));
    }
    let out = [got[0], got[1] / 1000, got[2], got[3] / 1000];
    write_pair(val_addr, out)
}

#[path = "posix.rs"]
mod posix;
pub use posix::{
    sys_timer_create, sys_timer_delete, sys_timer_getoverrun, sys_timer_gettime, sys_timer_settime,
};
