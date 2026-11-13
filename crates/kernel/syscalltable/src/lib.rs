//! Which implementation each syscall number reaches.
//!
//! `kernel/arch/arm64/calls.c` until 2026-09-03, where it was an array of 450
//! designated initialisers, **each one a cast**:
//!
//! ```c
//! [17] = (syscall_t) sys_getcwd,
//! ```
//!
//! The cast is what makes the table work at all — the dispatcher hands every
//! implementation six registers whatever its arity is, so one array cannot hold
//! functions of eleven different shapes without one — and it is also what makes
//! the table unchecked. A cast to `syscall_t` compiles whatever is on the right
//! of it, and 190 of them in one file were enough noise that the C had to
//! suppress `-Wcast-function-type` twice over to keep the build readable.
//!
//! # What is different here
//!
//! **There is no cast.** Each of [`at!`], `at_res!` and `at_val!` builds a shim
//! declaring the six registers the dispatcher passes, so the table entry is
//! `shim as Syscall` — a coercion `rustc` checks — and the shim calls the
//! implementation from Rust with the arity it actually has. The implementations
//! are named as Rust functions, so a rename, a removal or a change of shape is
//! a compile error rather than six registers of whatever was lying around.
//!
//! It was a `transmute` through `*const ()` until 2026-09-12, which accepts any
//! function whatever, and it is where the C's `(syscall_t)` cast had ended up.
//! What made it sound was AAPCS64 rather than anything Rust promises; see
//! [`Syscall`].
//!
//! And a number can only be assigned **once**. The C's designated initialiser
//! silently lets the later of two win; [`at!`] refuses at compile time, in a
//! `const` block, so a duplicate is a build error with no way to reach a guest.
//! `kernel/arch/arm64/calls.c` had none — this is a property the shape now has
//! rather than a defect it had.
//!
//! # What this is not
//!
//! It is not a check that the *number* is right. Which implementation belongs
//! at which number is Linux's business and nothing in this tree can answer it;
//! `tools/syscall-aliases.py` asks the one question that is answerable — whether
//! one implementation is registered at two numbers, and whether that was meant
//! — and it found two wrong on 2026-09-03. The comments are the only record of
//! what each number is, which is why they are carried across verbatim.


/// Every implementation, named as the Rust function it is.
///
/// Generated as 232 `extern "C"` declarations from `kernel/calls.h` until
/// 2026-09-08, with a stated reason -- "every `sys_*` in this file has the
/// signature the C compiler sees" -- that did not survive being asked what
/// enforced it. The declaration and the definition were **both hand-written**
/// by then, the definition in Rust, and nothing compares two of those: the
/// table `transmute`d each one through `as *const ()`, which accepts any
/// function, and the link is by symbol name, which carries no signature. A
/// prototype that had drifted would have produced exactly what it was there to
/// prevent.
///
/// Naming the function is what checks it. A rename, a removal or a crate that
/// stops exporting it is a compile error here, and the 232 lines below are the
/// record of which crate implements what -- which the C header never was,
/// because it listed them alphabetically and named no owner.
// kernel/aio
use aio::{
    sys_io_cancel, sys_io_destroy, sys_io_getevents, sys_io_pgetevents, sys_io_setup,
    sys_io_submit,
};
// fs/dircalls
use dircalls::sys_getdents64;
// kernel/epollcalls
use epollcalls::{sys_epoll_create, sys_epoll_ctl, sys_epoll_pwait, sys_epoll_pwait2};
// kernel/eventfdcalls
use eventfdcalls::sys_eventfd2;
// kernel/mqueuecalls
use mqueuecalls::{
    sys_mq_getsetattr, sys_mq_notify, sys_mq_open, sys_mq_timedreceive, sys_mq_timedsend,
    sys_mq_unlink,
};
// kernel/execcalls
use execcalls::{sys_execve, sys_execveat};
// kernel/exitcalls
use exitcalls::{sys_exit, sys_exit_group};
// kernel/fdattr
use fdattr::xattr::{
    sys_fgetxattr, sys_flistxattr, sys_fremovexattr, sys_fsetxattr, sys_getxattr, sys_getxattrat,
    sys_lgetxattr, sys_listxattr, sys_listxattrat, sys_llistxattr, sys_lremovexattr,
    sys_lsetxattr, sys_removexattr, sys_removexattrat, sys_setxattr, sys_setxattrat,
};
use fdattr::{
    sys_cachestat, sys_fadvise64, sys_fallocate, sys_fchmod, sys_fchown32, sys_file_getattr,
    sys_file_setattr, sys_flock, sys_fstatfs_arm64, sys_fsync, sys_ftruncate64, sys_readahead,
    sys_sync_file_range, sys_syncfs,
};
// kernel/fdcalls
use fdcalls::{sys_close, sys_close_range, sys_dup, sys_dup3, sys_fcntl, sys_ioctl};
// kernel/forkcalls
use forkcalls::{sys_clone, sys_clone3, sys_kcmp, sys_setns, sys_unshare};
// fs/sock
use fs_sock::{
    sys_accept, sys_accept4, sys_bind, sys_connect, sys_getpeername, sys_getsockname,
    sys_getsockopt, sys_listen, sys_recvfrom, sys_recvmmsg, sys_recvmsg, sys_sendmmsg, sys_sendmsg,
    sys_sendto, sys_setsockopt, sys_shutdown, sys_socket, sys_socketpair,
};
// kernel/futexcalls
use futexcalls::{
    sys_futex, sys_futex_requeue, sys_futex_wait, sys_futex_waitv, sys_futex_wake,
    sys_get_robust_list, sys_set_robust_list,
};
// kernel/groupcalls
use groupcalls::{sys_getpgid, sys_getsid, sys_setpgid, sys_setsid};
use fs_ttydev::sys_vhangup;
// kernel/idcalls
use idcalls::{
    sys_capget, sys_capset, sys_getegid32, sys_geteuid32, sys_getgid32, sys_getgroups, sys_getpid,
    sys_getppid, sys_getresgid, sys_getresuid, sys_gettid, sys_getuid32, sys_personality,
    sys_setfsgid, sys_setfsuid, sys_setgid, sys_setgroups, sys_setregid, sys_setresgid,
    sys_setresuid, sys_setreuid, sys_setuid,
};
use idcalls::{sys_lsm_get_self_attr, sys_lsm_list_modules, sys_lsm_set_self_attr};
// kernel/inotifycalls
use inotifycalls::{sys_inotify_add_watch, sys_inotify_init1, sys_inotify_rm_watch};
// kernel/ptrace
use kernel_ptrace::sys_ptrace;
// kernel/random
use kernel_random::sys_getrandom;
// kernel/signalcalls
use kernel_signalcalls::{
    sys_kill, sys_restart_syscall, sys_rt_sigqueueinfo, sys_rt_tgsigqueueinfo, sys_tgkill,
    sys_tkill,
};
// kernel/memfdcalls
use memfdcalls::sys_memfd_create;
// kernel/misccalls
use misccalls::{sys_prctl, sys_reboot, sys_seccomp};
// kernel/mmapcalls
use mmapcalls::{
    sys_brk, sys_madvise, sys_membarrier, sys_mincore, sys_mlock, sys_mlock2,
    sys_mlockall, sys_mmap64, sys_mprotect, sys_mremap, sys_msync, sys_munlock, sys_munlockall,
    sys_munmap, sys_mseal, sys_remap_file_pages,
};
// fs/mountcalls
use mountcalls::{sys_listmount, sys_mount, sys_statmount, sys_umount2};
// kernel/pathcalls
use pathcalls::{
    sys_chdir, sys_chroot, sys_faccessat, sys_faccessat3, sys_fchdir, sys_fchmodat, sys_fchmodat2,
    sys_fchownat, sys_getcwd, sys_linkat, sys_mkdirat, sys_mknodat, sys_name_to_handle_at,
    sys_open_by_handle_at, sys_openat, sys_openat2, sys_quotactl, sys_quotactl_fd,
    sys_readlinkat, sys_renameat, sys_renameat2, sys_statfs_arm64, sys_symlinkat, sys_truncate64,
    sys_swapoff, sys_swapon, sys_umask, sys_unlinkat, sys_utimensat,
};
// kernel/pidfdcalls
use pidfdcalls::{sys_pidfd_getfd, sys_pidfd_open, sys_pidfd_send_signal};
// fs/pipecalls
use pipecalls::{sys_pipe2, sys_tee};
// kernel/pollcalls
use pollcalls::{sys_ppoll, sys_pselect};
// kernel/procvmcalls
use procvmcalls::{
    sys_process_madvise, sys_process_mrelease, sys_process_vm_readv, sys_process_vm_writev,
};
// kernel/rescalls
use rescalls::ioprio::{sys_ioprio_get, sys_ioprio_set};
use rescalls::{
    sys_getcpu, sys_getpriority, sys_getrlimit64, sys_getrusage, sys_prlimit64,
    sys_sched_get_priority_max, sys_sched_get_priority_min, sys_sched_getaffinity,
    sys_sched_getparam, sys_sched_getscheduler, sys_sched_rr_get_interval, sys_sched_setaffinity,
    sys_sched_setparam, sys_sched_setscheduler, sys_setpriority, sys_setrlimit64,
};
use rescalls::{sys_sched_getattr, sys_sched_setattr};
// kernel/rwcalls
use rwcalls::{
    sys_copy_file_range, sys_lseek64, sys_pread, sys_preadv, sys_preadv2, sys_pwrite, sys_pwritev,
    sys_pwritev2, sys_read, sys_readv, sys_sendfile64, sys_splice, sys_vmsplice, sys_write,
    sys_writev,
};
// kernel/signaldeliver
use signaldeliver::receive::sys_rt_sigreturn;
// The six that were `signaldeliver`'s until 2026-09-09; see that crate's note.
use kernel_signalcalls::{
    sys_rt_sigaction, sys_rt_sigpending, sys_rt_sigprocmask, sys_rt_sigsuspend,
    sys_rt_sigtimedwait, sys_sigaltstack,
};
// kernel/signalfdcalls
use signalfdcalls::sys_signalfd4;
// fs/statcalls
use statcalls::{sys_fstat64, sys_fstatat64, sys_statx};
// kernel/syslogcalls
use syslogcalls::sys_syslog;
// kernel/sysvmsg
use sysvmsg::{sys_msgctl, sys_msgget, sys_msgrcv, sys_msgsnd};
// kernel/sysvsem
use sysvsem::{sys_semctl, sys_semget, sys_semop, sys_semtimedop};
// kernel/sysvshm
use sysvshm::{sys_shmat, sys_shmctl, sys_shmdt, sys_shmget};
// kernel/taskcalls
use taskcalls::{sys_sched_yield, sys_set_tid_address};
// kernel/timecalls
use timecalls::{
    sys_adjtimex, sys_clock_adjtime, sys_clock_getres, sys_clock_gettime, sys_clock_nanosleep,
    sys_clock_settime, sys_getitimer,
    sys_gettimeofday, sys_nanosleep, sys_setitimer, sys_settimeofday, sys_timer_create,
    sys_timer_delete, sys_timer_getoverrun, sys_timer_gettime, sys_timer_settime, sys_times,
};
// kernel/timerfdcalls
use timerfdcalls::{sys_timerfd_create, sys_timerfd_gettime, sys_timerfd_settime};
// kernel/unamecalls
use unamecalls::{sys_setdomainname, sys_sethostname, sys_sysinfo, sys_uname};
// kernel/waitcalls
use waitcalls::{sys_wait4, sys_waitid};

// ------------------------------------------------------------------ the stubs
//
// They were `crates/kernel/syscalldispatch`'s until 2026-09-08, and moving them
// is what let the table name its implementations as Rust functions: the
// dependency has to point table -> implementation, and these three pointed the
// other way. Nothing but the table has ever named them, which is the argument
// for where they belong -- "this number has no implementation" is a fact about
// the table, not about dispatch.

use guest_errno::c_int_::ENOSYS;

/// A syscall this kernel does not implement. Every entry with no
/// implementation points here; the dispatcher names the number once, from
/// [`REPORTED_STUB`].
///
/// # Why this carried a calling convention until 2026-09-12
///
/// It was `extern "C"` for the reason [`Syscall`] was: `at!` transmuted it into
/// a six-argument function of that type and the dispatcher called it as one, so
/// what made reading no argument registers sound was **AAPCS64** and not
/// anything the Rust ABI promises. The convention was load-bearing on that
/// shape and nothing checked it — this and [`syscall_success_stub`] were plain
/// `fn` until 2026-09-11 while the third `at!` target was not, a difference
/// nothing could have reported because the transmute went through `*const ()`
/// and erased the convention on the way.
///
/// `at!` builds a six-argument shim now and calls this from Rust, so there is
/// no convention left to get wrong and none of the three needs one.
pub fn syscall_stub() -> u32 {
    ENOSYS as u32
}

/// The same answer without the report, for a syscall a libc probes for and
/// falls back from.
///
/// **Which of the two a number gets is recorded by the table, not read off this
/// function's address.** It was the address until 2026-09-04, and a comment
/// said the two "share no identity" because they are separate functions -- they
/// do not. A release link folds two functions with identical bodies into one,
/// and a `no_mangle` `extern "C"` does not stop it: both symbols end up naming
/// one copy, `fn_addr_eq` answers yes, and every silent stub reported. The
/// visible one was `rseq`, which every glibc program calls at startup.
pub fn syscall_silent_stub() -> u32 {
    ENOSYS as u32
}

/// Success without doing anything, for a call whose whole effect is advisory.
pub(crate) fn syscall_success_stub() -> u32 {
    0
}

/// `ENOSYS` **on purpose**: what a Linux kernel built without the feature
/// answers, because `cond_syscall` points the number at `sys_ni_syscall`.
///
/// Not [`syscall_stub`], which means "nobody has implemented this yet" and
/// says so on stderr. Each entry that points here says in the table which
/// configuration option it is the answer of and why that is the honest one --
/// a keyring, a BPF verifier or a performance-counter subsystem is not
/// something to half-build behind a syscall that then claims to work.
pub(crate) fn not_configured() -> u32 {
    ENOSYS as u32
}

/// What the dispatcher calls: six registers in, one out.
///
/// **Every register is 64 bits.** An implementation declaring a `dword_t`
/// parameter truncates implicitly; one declaring an `off_t_` or a `qword_t`
/// gets the whole value. The return is 64 bits so that the calls answering an
/// address — `mmap`, `brk` — can carry 48 of them.
///
/// # Every entry is a coercion, not a cast
///
/// It was a cast until 2026-09-12 — `transmute::<*const (), Syscall>` on a
/// function of the implementation's own arity, exactly as the C wrote
/// `(syscall_t) sys_getcwd`. What made it sound was AArch64 letting a callee
/// read the argument registers it declares and ignore the rest: true of this
/// target, promised by no Rust ABI, and checked by nothing — a `transmute`
/// between two function pointers is the one place a signature mismatch is
/// completely silent.
///
/// The shims `at!`, `at_res!` and `at_val!` build declare all six registers
/// now, so each entry is `shim as Syscall` and `rustc` checks it. The
/// implementation behind the shim is called from Rust and needs no convention
/// of its own.
///
/// `tools/syscall-aliases.py` still exists for the other half of the question:
/// an implementation registered at a *second* number reads as many arguments as
/// it declares whether Linux passes them or not, which is about Linux's
/// argument lists rather than about the calling convention.
///
/// **A safe Rust function pointer since 2026-10-01.** It was `unsafe extern
/// "C"`, a leftover of the C table: every shim is Rust, the dispatcher that
/// calls it is Rust, and no C or assembly reads `SYSCALL_TABLE`. The `unsafe`
/// made each call site an `unsafe` block asserting nothing.
pub type Syscall = fn(u64, u64, u64, u64, u64, u64) -> i64;

// ------------------------------------------------------- the one conversion
//
// A `sys_*` that answers a `Result<T, Errno>` is registered with `at_res!`,
// which builds a shim of the implementation's arity around it. **This is the
// only place in the tree that turns an `Errno` into the negative number a
// guest reads**, which is the whole point of the type: a family that has been
// converted cannot get the sign wrong, cannot return `-EINVAL` where it meant
// `EINVAL`, and cannot forget that a `u32` success and an `i32` error share one
// register.
//
// The alternative — a wrapper beside each implementation — was rejected for the
// reason `CLAUDE.md` gives about cutting by syscall family: a conversion layer
// that leaves every function body alone is the shape where the C grew by 58
// lines. What a conversion should delete is the early returns, and it does.

/// What a converted `sys_*` may answer on success.
///
/// Every one is widened to the 64 bits the dispatcher writes to `x0`, which
/// then narrows it again for the syscalls that are not in [`returns_64bit`].
/// The two signed cases sign-extend and the unsigned ones zero-extend, which is
/// what the C ABI did implicitly and is the part a hand-written wrapper gets
/// wrong: `u32::MAX` is a personality, not an errno.
pub trait SyscallValue {
    fn into_syscall_value(self) -> i64;
}

/// A syscall whose success carries nothing. `0`, as Linux answers.
impl SyscallValue for () {
    fn into_syscall_value(self) -> i64 {
        0
    }
}

macro_rules! syscall_values {
    ($($t:ty as $via:ty;)*) => {
        $(impl SyscallValue for $t {
            fn into_syscall_value(self) -> i64 {
                self as $via as i64
            }
        })*
    };
}

syscall_values! {
    // Unsigned answers zero-extend: a descriptor number, a byte count, a
    // personality word, an address.
    u32 as u32;
    u64 as u64;
    usize as u64;
    // Signed ones sign-extend, and are the shapes that also carry a negative
    // *value* -- `getpriority` is the standing example, though this kernel's
    // answers are all non-negative today.
    i32 as i32;
    i64 as i64;
    isize as i64;
    // `bool` is what a predicate-shaped syscall answers, 1 or 0.
    bool as u32;
}

/// Turn a converted implementation's answer into what the dispatcher writes.
///
/// `#[inline]` rather than exported: this is called once per syscall on the
/// dispatch path and the shim around it is generated in this crate, so there is
/// no symbol for a consumer to reach and nothing to keep visible.
#[inline]
pub fn answer<T: SyscallValue>(r: Result<T, guest_errno::Errno>) -> i64 {
    match r {
        Ok(v) => v.into_syscall_value(),
        Err(e) => e.as_i64(),
    }
}

#[path = "table.rs"]
mod table;
pub use table::{REPORTED_STUB, SYSCALL_TABLE, SYSCALL_TABLE_SIZE};

/// Which syscalls return a genuine 64-bit value.
///
/// The table casts every implementation to one function pointer type, and on
/// AArch64 a function whose C return type is 32 bits sets only `w0` — writing
/// `w0` zeroes the top half of `x0`. So a `dword_t` syscall returning `-EFAULT`
/// and a `qword_t` syscall returning `0x00000000fffffff2` leave `x0` holding
/// exactly the same 64 bits. **Nothing the dispatcher can inspect distinguishes
/// them**; the width has to be declared, which is what this is.
///
/// Keep it in step with the table. A 32-bit syscall listed here has its error
/// returns handed to the guest as huge positive numbers. A 64-bit syscall
/// missing from it has any return in `0xfffff001..0xffffffff` turned into a
/// bogus errno — which is what happened to `lseek()` at every offset in the
/// last 4 KB below 4 GB, where the errno the guest got was the low bits of the
/// offset it asked for.
///
/// 139 (`rt_sigreturn`) also returns 64 bits and is deliberately absent: the
/// dispatcher skips the writeback for it entirely, because `x0` was already
/// restored from the signal frame and must not be touched.
pub const fn returns_64bit(num: u32) -> bool {
    matches!(
        num,
        62      // lseek
        // personality answers the *previous* personality, and every uint32_t is
        // one -- so a narrow return would read 0xfffffffe as the errno -2.
        | 92    // personality
        // prctl returns a `long`, and PR_GET_TIMERSLACK's answer is an
        // `unsigned long` a guest set -- a slack of 2^40 ns read back through
        // a 32-bit return would be 0.
        | 167   // prctl
        | 196   // shmat, which answers an address
        | 214   // brk
        | 216   // mremap
        | 222 // mmap
    )
}

/// The symbols the table names, for a test binary.
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
