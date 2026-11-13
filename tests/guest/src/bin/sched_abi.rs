//! The scheduling and I/O-hint calls that were `syscall_stub`, and the argument
//! rules of the ones beside them.
//!
//! Every check here is about a call whose answer does not depend on the
//! scheduler's policy set, so a real kernel and this one have to agree:
//! whether the `pid` argument names anything, whether an advice value is one
//! the kernel knows, whether a descriptor is the right kind. `sched_ret.rs` is
//! the one that *is* about the policy set, and it is deliberately not
//! comparable.
//!
//! Four of these answered `ENOSYS`, which a caller cannot tell from "there is
//! no such process" or "that advice is not one of mine". Two answered success
//! for a target that does not exist.
//!
//! Takes one argument, a directory it may create files under.

use guest_tests::{Harness, check, check_fails, sys};

/// A pid nothing can have: the table is smaller than this and the test does not
/// create four million processes.
const NO_SUCH_PID: libc::pid_t = 4_000_000;

const SYS_SCHED_SETSCHEDULER: libc::c_long = 119;
const SYS_SCHED_GETSCHEDULER: libc::c_long = 120;
const SYS_SCHED_SETPARAM: libc::c_long = 118;
const SYS_SCHED_RR_GET_INTERVAL: libc::c_long = 127;
const SYS_RESTART_SYSCALL: libc::c_long = 128;
const SYS_GETCPU: libc::c_long = 168;
const SYS_READAHEAD: libc::c_long = 213;
const SYS_FADVISE64: libc::c_long = 223;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SchedParam {
    sched_priority: i32,
}

fn t_pid_argument(h: &mut Harness) {
    h.group("sched-pid-argument");
    // These ignored the pid entirely, so a call naming a process that does not
    // exist reported success -- and `sched_getscheduler(99999)` answered
    // SCHED_OTHER for it.
    // The raw syscall, not the libc wrapper: musl's sched_getscheduler is a
    // stub that returns ENOSYS whatever the kernel does, so calling it would
    // have compared two libcs rather than two kernels.
    unsafe {
        check!(
            h,
            libc::syscall(SYS_SCHED_GETSCHEDULER, 0) == libc::SCHED_OTHER as i64,
            "our own policy is SCHED_OTHER"
        );
        check_fails!(
            h,
            libc::syscall(SYS_SCHED_GETSCHEDULER, NO_SUCH_PID),
            libc::ESRCH,
            "sched_getscheduler of a pid nothing has"
        );
        check_fails!(
            h,
            libc::syscall(SYS_SCHED_GETSCHEDULER, -1),
            libc::EINVAL,
            "sched_getscheduler of a negative pid"
        );

        let mut param = SchedParam::default();
        check!(
            h,
            libc::syscall(libc::SYS_sched_getparam, 0, &raw mut param) == 0
                && param.sched_priority == 0,
            "our own priority is zero"
        );
        check_fails!(
            h,
            libc::syscall(libc::SYS_sched_getparam, NO_SUCH_PID, &raw mut param),
            libc::ESRCH,
            "sched_getparam of a pid nothing has"
        );
        check_fails!(
            h,
            libc::syscall(libc::SYS_sched_getparam, 0, std::ptr::null_mut::<SchedParam>()),
            libc::EINVAL,
            "sched_getparam with a null param"
        );
    }
}

fn t_setparam(h: &mut Harness) {
    h.group("sched-setparam");
    // sched_setparam is what a program uses to set a priority *without*
    // changing the policy, which is what every SCHED_OTHER user wants. It was
    // a stub.
    unsafe {
        let zero = SchedParam { sched_priority: 0 };
        check!(
            h,
            libc::syscall(SYS_SCHED_SETPARAM, 0, &raw const zero) == 0,
            "priority zero on a SCHED_OTHER thread, errno {}",
            sys::errno()
        );
        let one = SchedParam { sched_priority: 1 };
        check_fails!(
            h,
            libc::syscall(SYS_SCHED_SETPARAM, 0, &raw const one),
            libc::EINVAL,
            "a nonzero priority on a SCHED_OTHER thread"
        );
        // A *null* param is EINVAL, not EFAULT: do_sched_setscheduler checks
        // `!param || pid < 0` before it copies anything. A pointer that is
        // merely bad is EFAULT, which is a different check in a different
        // place -- and getting the two the wrong way round is what a real
        // kernel caught here.
        check_fails!(
            h,
            libc::syscall(SYS_SCHED_SETPARAM, 0, std::ptr::null::<SchedParam>()),
            libc::EINVAL,
            "a null param pointer"
        );
        check_fails!(
            h,
            libc::syscall(SYS_SCHED_SETPARAM, 0, 1u64 as *const SchedParam),
            libc::EFAULT,
            "a param pointer that is not mapped"
        );
        check_fails!(
            h,
            libc::syscall(SYS_SCHED_SETPARAM, -1, &raw const zero),
            libc::EINVAL,
            "sched_setparam of a negative pid"
        );
        // The policy form of the same function, for the one policy this
        // implements.
        check!(
            h,
            libc::syscall(SYS_SCHED_SETSCHEDULER, 0, libc::SCHED_OTHER, &raw const zero) == 0,
            "sched_setscheduler(SCHED_OTHER, 0), errno {}",
            sys::errno()
        );
        check_fails!(
            h,
            libc::syscall(SYS_SCHED_SETPARAM, NO_SUCH_PID, &raw const zero),
            libc::ESRCH,
            "sched_setparam of a pid nothing has"
        );
    }
}

fn t_rr_interval(h: &mut Harness) {
    h.group("sched-rr-interval");
    // The quantum itself is a scheduler detail no program can depend on -- so
    // what is checked is that the call succeeds and writes a well-formed
    // timespec, and that its pid argument means what it means everywhere else.
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        let r = libc::syscall(SYS_SCHED_RR_GET_INTERVAL, 0, &raw mut ts);
        check!(h, r == 0, "sched_rr_get_interval for ourselves, errno {}", sys::errno());
        check!(
            h,
            ts.tv_sec >= 0 && (0..1_000_000_000).contains(&ts.tv_nsec),
            "and writes a well-formed interval: {}.{:09}",
            ts.tv_sec,
            ts.tv_nsec
        );
        check_fails!(
            h,
            libc::syscall(SYS_SCHED_RR_GET_INTERVAL, NO_SUCH_PID, &raw mut ts),
            libc::ESRCH,
            "of a pid nothing has"
        );
        check_fails!(
            h,
            libc::syscall(SYS_SCHED_RR_GET_INTERVAL, 0, std::ptr::null_mut::<libc::timespec>()),
            libc::EFAULT,
            "with nowhere to write it"
        );
    }
}

fn t_getcpu(h: &mut Harness) {
    h.group("getcpu");
    // glibc's sched_getcpu() is this syscall. It was a stub, so it failed --
    // and a caller that shards by processor (a malloc arena, a per-cpu
    // counter) put everything in shard zero.
    let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    unsafe {
        let mut cpu: u32 = u32::MAX;
        let mut node: u32 = u32::MAX;
        let r = libc::syscall(SYS_GETCPU, &raw mut cpu, &raw mut node, 0);
        check!(h, r == 0, "getcpu succeeds, errno {}", sys::errno());
        check!(
            h,
            online > 0 && (cpu as i64) < online,
            "and names a processor that exists: {cpu} of {online}"
        );
        check!(h, node == 0, "one NUMA node: got {node}");

        // Both pointers are optional.
        check!(
            h,
            libc::syscall(SYS_GETCPU, std::ptr::null_mut::<u32>(), std::ptr::null_mut::<u32>(), 0) == 0,
            "and both arguments may be omitted"
        );
        check_fails!(
            h,
            libc::syscall(SYS_GETCPU, 1u64 as *mut u32, std::ptr::null_mut::<u32>(), 0),
            libc::EFAULT,
            "a cpu pointer that is not there"
        );
    }

    // What sched_getcpu is for: two threads should be able to get different
    // answers, or the sharding it feeds is pointless. Not asserted -- a
    // one-processor machine is entitled to answer 0 twice -- but reported, so
    // a run where the emulator collapsed every thread onto one is visible.
    println!("getcpu: {online} processors online");
}

fn t_readahead_and_fadvise(h: &mut Harness, dir: &str) {
    h.group("readahead");
    let path = format!("{dir}/ra\0");
    let file = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644) };
    if file < 0 {
        check!(h, false, "creating {dir}/ra, errno {}", sys::errno());
        return;
    }
    let buf = [b'x'; 8192];
    unsafe { libc::write(file, buf.as_ptr().cast(), buf.len()) };

    unsafe {
        // Advisory, so success is the answer for a file it could act on --
        // this answered ENOSYS, and glibc's readahead() has no fallback.
        check!(
            h,
            libc::syscall(SYS_READAHEAD, file, 0i64, 4096u64) == 0,
            "readahead on a regular file, errno {}",
            sys::errno()
        );
        check_fails!(
            h,
            libc::syscall(SYS_READAHEAD, -1, 0i64, 4096u64),
            libc::EBADF,
            "readahead on a descriptor that is not open"
        );

        // A pipe is not a regular file or a block device.
        let mut pipefd = [0i32; 2];
        libc::pipe(pipefd.as_mut_ptr());
        check_fails!(
            h,
            libc::syscall(SYS_READAHEAD, pipefd[0], 0i64, 4096u64),
            libc::EINVAL,
            "readahead on a pipe"
        );

        h.group("fadvise");
        // Accepted and ignored is right for the six advice values Linux knows.
        for advice in 0..=5 {
            check!(
                h,
                libc::syscall(SYS_FADVISE64, file, 0i64, 0i64, advice) == 0,
                "fadvise advice {advice}, errno {}",
                sys::errno()
            );
        }
        // Anything else is not a hint, it is a mistake. This answered success.
        check_fails!(
            h,
            libc::syscall(SYS_FADVISE64, file, 0i64, 0i64, 99),
            libc::EINVAL,
            "an advice value that means nothing"
        );
        check_fails!(
            h,
            libc::syscall(SYS_FADVISE64, pipefd[0], 0i64, 0i64, 3),
            libc::ESPIPE,
            "fadvise on a pipe"
        );
        check_fails!(
            h,
            libc::syscall(SYS_FADVISE64, -1, 0i64, 0i64, 0),
            libc::EBADF,
            "fadvise on a descriptor that is not open"
        );
        libc::close(pipefd[0]);
        libc::close(pipefd[1]);
        libc::close(file);
    }
}

/// A guest pointer above the address space, and one whose range wraps.
///
/// Both reached `user_read`/`user_write`, which checked neither:
///
///   - `addr + count` overflowing made `while (p < addr + count)` a loop that
///     never runs, so the copy returned *success* having moved nothing. A read
///     left the kernel's stack buffer untouched and the syscall used it; a
///     write reported it had filled the caller's buffer and had not.
///   - an address at or above 2^48 does not fault, because page numbers are 36
///     bits and each level's index is masked -- it *aliases* onto a low page.
///     `munmap(p + (1 << 48), 4096)` unmapping `p` is the same hazard, and it
///     was fixed only in mmap.c.
///
/// `getcpu` is the probe because it writes exactly four bytes to an address the
/// caller chooses and does nothing else, so a write that lands somewhere is
/// visible and a write that does not happen is too.
fn t_pointer_bounds(h: &mut Harness) {
    h.group("guest-pointer-bounds");
    const OUT_OF_RANGE: u64 = 1 << 48;

    unsafe {
        let page = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if page == libc::MAP_FAILED {
            check!(h, false, "mapping a page to alias onto");
            return;
        }
        let marker: u32 = 0xdead_beef;
        page.cast::<u32>().write(marker);

        // The same page, named from above the address space.
        let aliased = (page as u64 + OUT_OF_RANGE) as *mut u32;
        check_fails!(
            h,
            libc::syscall(SYS_GETCPU, aliased, std::ptr::null_mut::<u32>(), 0),
            libc::EFAULT,
            "a pointer at 2^48 above a mapped page"
        );
        check!(
            h,
            page.cast::<u32>().read() == marker,
            "and nothing was written through it: {:#x}",
            page.cast::<u32>().read()
        );

        // A range that wraps. The four bytes at u64::MAX end at 3.
        check_fails!(
            h,
            libc::syscall(SYS_GETCPU, u64::MAX as *mut u32, std::ptr::null_mut::<u32>(), 0),
            libc::EFAULT,
            "a pointer whose range wraps past the end of the address space"
        );

        // The reading direction, through a call that takes a struct: a wrapped
        // range must not leave the kernel using a buffer it never filled.
        check_fails!(
            h,
            libc::syscall(SYS_SCHED_SETPARAM, 0, u64::MAX as *const SchedParam),
            libc::EFAULT,
            "reading a param struct from a range that wraps"
        );

        libc::munmap(page, 4096);
    }
}

fn t_restart_syscall(h: &mut Harness) {
    h.group("restart-syscall");
    // Not something a program calls on purpose: the kernel puts it in place of
    // an interrupted syscall that is to be resumed. Called directly there is no
    // restart pending, which Linux spells do_no_restart_syscall -- EINTR. It
    // answered ENOSYS.
    unsafe {
        check_fails!(
            h,
            libc::syscall(SYS_RESTART_SYSCALL),
            libc::EINTR,
            "restart_syscall with no restart pending"
        );
    }
    check!(h, unsafe { libc::getpid() } > 0, "and the task survived it");
}

fn main() -> std::process::ExitCode {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/schedabi".into());
    if sys::mkdir(&dir, 0o755) != 0 && sys::errno() != libc::EEXIST {
        eprintln!("cannot create {dir}: {}", sys::strerror(sys::errno()));
        return std::process::ExitCode::from(2);
    }

    let mut h = Harness::new();
    t_pid_argument(&mut h);
    t_setparam(&mut h);
    t_rr_interval(&mut h);
    t_getcpu(&mut h);
    t_readahead_and_fadvise(&mut h, &dir);
    t_pointer_bounds(&mut h);
    t_restart_syscall(&mut h);
    std::process::ExitCode::from(h.finish() as u8)
}
