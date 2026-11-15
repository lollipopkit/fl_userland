//! Compile-time syscall number table and reporting metadata.

use super::*;

/// One number, or an inclusive range of them, pointing at one implementation.
///
/// The duplicate check is the reason this is a macro rather than an array
/// literal: a positional array would make a *missing* entry shift every number
/// after it, and a designated initialiser in C makes a *duplicate* silent. This
/// has neither failure.
///
/// It also records **whether the dispatcher names the number**, from the name
/// of the implementation, which is the only place that fact exists. See
/// `Table::reported`.
///
/// The three targets are stubs that read no argument, and the shim declares the
/// six registers the dispatcher passes so that the entry is a *coercion* rather
/// than a transmute. See [`at_res!`] for why that matters; the stubs themselves
/// are plain Rust functions now, with no calling convention of their own.
macro_rules! at {
    ($t:ident, $lo:literal ..= $hi:literal, $f:ident) => {{
        fn shim(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> i64 {
            $crate::SyscallValue::into_syscall_value($f())
        }
        let mut i = $lo;
        while i <= $hi {
            if $t.fns[i].is_some() {
                panic!("two implementations at one syscall number");
            }
            $t.fns[i] = Some(shim as $crate::Syscall);
            $t.reported[i] = is_reported(stringify!($f));
            i += 1;
        }
    }};
    ($t:ident, $n:literal, $f:ident) => {{
        fn shim(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> i64 {
            $crate::SyscallValue::into_syscall_value($f())
        }
        if $t.fns[$n].is_some() {
            panic!("two implementations at one syscall number");
        }
        $t.fns[$n] = Some(shim as $crate::Syscall);
        $t.reported[$n] = is_reported(stringify!($f));
    }};
}

/// The same, for an implementation that answers `Result<T, Errno>`.
///
/// The trailing number is the implementation's **arity**, and the shim this
/// builds passes exactly that many of its arguments on. It is not a second
/// statement of something already written down: get it wrong and `$f` is called
/// with the wrong number of arguments, which does not compile.
///
/// # The shim declares six registers, and that is what makes the entry checked
///
/// Every macro here used to end in
/// `transmute::<*const (), Syscall>(shim as *const ())`, because a shim of
/// arity *n* is not a [`Syscall`] and the `*const ()` in the middle erases the
/// difference. What made that sound was **AAPCS64** — a callee reads the
/// argument registers it declares and ignores the rest — which is a property of
/// the target rather than anything the Rust ABI promises, and it was one of the
/// three contracts in this tree that the compiler could not check
/// (`docs/changelog/2026-09-11-three-abi-contracts-the-compiler-does-not-check.md`).
///
/// Declaring the padding registers costs nothing and removes the erasure: the
/// shim *is* a `Syscall`, `shim as Syscall` is a coercion `rustc` checks, and a
/// shim whose shape drifted would no longer compile rather than being called
/// through a pointer that says nothing. A `transmute` between two function
/// pointers is the one place a signature mismatch is completely silent, which
/// is why 450 of them were worth the six extra `_` per entry.
///
/// `tools/syscall-aliases.py` still has to exist: it asks whether one
/// implementation is registered at two *numbers*, which is a question about
/// Linux's argument lists and not about the calling convention.
macro_rules! at_res {
    ($t:ident, $n:literal, $f:ident, 0) => { at_res!(@build $t, $n, $f, (), (_, _, _, _, _, _)) };
    ($t:ident, $n:literal, $f:ident, 1) => { at_res!(@build $t, $n, $f, (a0), (_, _, _, _, _)) };
    ($t:ident, $n:literal, $f:ident, 2) => { at_res!(@build $t, $n, $f, (a0, a1), (_, _, _, _)) };
    ($t:ident, $n:literal, $f:ident, 3) => {
        at_res!(@build $t, $n, $f, (a0, a1, a2), (_, _, _))
    };
    ($t:ident, $n:literal, $f:ident, 4) => {
        at_res!(@build $t, $n, $f, (a0, a1, a2, a3), (_, _))
    };
    ($t:ident, $n:literal, $f:ident, 5) => {
        at_res!(@build $t, $n, $f, (a0, a1, a2, a3, a4), (_))
    };
    ($t:ident, $n:literal, $f:ident, 6) => {
        at_res!(@build $t, $n, $f, (a0, a1, a2, a3, a4, a5), ())
    };
    (@build $t:ident, $n:literal, $f:ident, ($($a:ident),*), ($($pad:tt),*)) => {{
        // A nested item, so each entry gets its own `shim` and the name cannot
        // collide with the next one's. The `$pad` list brings the declared
        // arity to six whatever the implementation's is; a wrong length is a
        // type error at the `as $crate::Syscall` below.
        //
        // `as _` and not `as u64`: the target is the implementation's own
        // declared parameter type, and that is the table's one narrowing
        // channel -- `tools/syscall-abi.py`'s rule 1 is the check on it. The
        // padding registers are never cast.
        //
        // **No `#[allow(clippy::unnecessary_cast)]` here.** There was one, and
        // it suppressed nothing at any of this macro's expansions: the lint
        // does not fire on a cast whose target is inferred, because `as _` can
        // be load-bearing for inference and clippy has no resolved type to
        // compare against. Measured by making it `#[expect]`, which reported
        // "this lint expectation is unfulfilled" once per entry. A suppression
        // with nothing under it is not free -- it waits, and covers whatever
        // lands on the same site next.
        fn shim($($a: u64,)* $($pad: u64,)*) -> i64 {
            $crate::answer($f($($a as _,)*))
        }
        if $t.fns[$n].is_some() {
            panic!("two implementations at one syscall number");
        }
        $t.fns[$n] = Some(shim as $crate::Syscall);
        $t.reported[$n] = false;
    }};
}

/// The same again, for an implementation that **cannot fail**.
///
/// `getpid` has no error path and never will. Wrapping its answer in `Ok` to
/// reach [`at_res!`] would put a conversion layer where there is no contract to
/// convert, and would make the table say that a caller has an errno to handle.
/// This gets the same arity check and the same widening, and the table itself
/// records which syscalls those are — which is the one place that fact is
/// written down.
macro_rules! at_val {
    ($t:ident, $n:literal, $f:ident, 0) => { at_val!(@build $t, $n, $f, (), (_, _, _, _, _, _)) };
    ($t:ident, $n:literal, $f:ident, 1) => { at_val!(@build $t, $n, $f, (a0), (_, _, _, _, _)) };
    ($t:ident, $n:literal, $f:ident, 2) => { at_val!(@build $t, $n, $f, (a0, a1), (_, _, _, _)) };
    ($t:ident, $n:literal, $f:ident, 3) => {
        at_val!(@build $t, $n, $f, (a0, a1, a2), (_, _, _))
    };
    ($t:ident, $n:literal, $f:ident, 4) => {
        at_val!(@build $t, $n, $f, (a0, a1, a2, a3), (_, _))
    };
    ($t:ident, $n:literal, $f:ident, 5) => {
        at_val!(@build $t, $n, $f, (a0, a1, a2, a3, a4), (_))
    };
    ($t:ident, $n:literal, $f:ident, 6) => {
        at_val!(@build $t, $n, $f, (a0, a1, a2, a3, a4, a5), ())
    };
    (@build $t:ident, $n:literal, $f:ident, ($($a:ident),*), ($($pad:tt),*)) => {{
        // See [`at_res!`] for the `$pad` list, and for why there is no
        // `#[allow(clippy::unnecessary_cast)]` on this shim either.
        fn shim($($a: u64,)* $($pad: u64,)*) -> i64 {
            $crate::SyscallValue::into_syscall_value($f($($a as _,)*))
        }
        if $t.fns[$n].is_some() {
            panic!("two implementations at one syscall number");
        }
        $t.fns[$n] = Some(shim as $crate::Syscall);
        $t.reported[$n] = false;
    }};
}

/// Whether an implementation's *name* is the stub the dispatcher names once.
///
/// A `const fn` over `stringify!`, because the answer has to be settled while
/// the table is built.
pub(super) const fn is_reported(name: &str) -> bool {
    let a = name.as_bytes();
    let b = b"syscall_stub";
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The highest number the table answers for, plus one.
///
/// 471 is `rseq_slice_yield`, the last one Linux 7.0 assigns
/// (`scripts/syscall.tbl` at v7.0). A number past the end is `ENOSYS`, which is
/// the dispatcher's business.
pub const SYSCALL_TABLE_SIZE: usize = 472;

/// `None` where Linux has assigned no number — 244 to 259 are the one gap — and
/// where this kernel has not been told about one.
pub static SYSCALL_TABLE: [Option<Syscall>; SYSCALL_TABLE_SIZE] = BUILT.fns;

/// Which numbers the dispatcher names once, on stderr, as unimplemented.
///
/// **A fact about the number, not about the function it points at.** It used to
/// be the second: the dispatcher compared the entry against `syscall_stub` with
/// `fn_addr_eq`, and `syscall_silent_stub` existed as a separate function with
/// the same body so that the comparison would answer no for a number a libc
/// probes and falls back from. A release link folds two functions with
/// identical bodies into one address, so it answered **yes for all 132 of
/// them** — `rseq`, which every glibc program calls at startup, was the visible
/// one. Being a `#[unsafe(no_mangle)] extern "C"` symbol does not prevent it;
/// two symbols can name one copy.
pub static REPORTED_STUB: [bool; SYSCALL_TABLE_SIZE] = BUILT.reported;

/// The table and the flags, built together so the `at!` macro states each
/// number once.
struct Table {
    fns: [Option<Syscall>; SYSCALL_TABLE_SIZE],
    reported: [bool; SYSCALL_TABLE_SIZE],
}

/// Evaluated at compile time; the two `static`s above are its halves, so
/// neither costs an indirection on the dispatch path.
const BUILT: Table = build();

const fn build() -> Table {
    let mut t = Table {
        fns: [None; SYSCALL_TABLE_SIZE],
        reported: [false; SYSCALL_TABLE_SIZE],
    };
    // I/O syscalls
    at_res!(t, 0, sys_io_setup, 2);
    at_res!(t, 1, sys_io_destroy, 1);
    at_res!(t, 2, sys_io_submit, 3);
    at_res!(t, 3, sys_io_cancel, 3);
    at_res!(t, 4, sys_io_getevents, 5);
    // The twelve: four verbs crossed with three ways of naming the target. One
    // stub answering ENOTSUP until 2026-09-07 -- see crates/kernel/fdattr's
    // xattr module for why that was a true statement about the wrong thing.
    at_res!(t, 5, sys_setxattr, 5);
    at_res!(t, 6, sys_lsetxattr, 5);
    at_res!(t, 7, sys_fsetxattr, 5);
    at_res!(t, 8, sys_getxattr, 4);
    at_res!(t, 9, sys_lgetxattr, 4);
    at_res!(t, 10, sys_fgetxattr, 4);
    at_res!(t, 11, sys_listxattr, 3);
    at_res!(t, 12, sys_llistxattr, 3);
    at_res!(t, 13, sys_flistxattr, 3);
    at_res!(t, 14, sys_removexattr, 2);
    at_res!(t, 15, sys_lremovexattr, 2);
    at_res!(t, 16, sys_fremovexattr, 2);
    at_res!(t, 17, sys_getcwd, 2);
    // Retired with oprofile's dcookies: the number points at sys_ni_syscall,
    // and the arm64 reference answers ENOSYS (rarecalls_probe).
    at!(t, 18, not_configured); // lookup_dcookie
    at_res!(t, 19, sys_eventfd2, 2);
    at_res!(t, 20, sys_epoll_create, 1);
    at_res!(t, 21, sys_epoll_ctl, 4);
    at_res!(t, 22, sys_epoll_pwait, 6);
    at_res!(t, 23, sys_dup, 1);
    at_res!(t, 24, sys_dup3, 3);
    at_res!(t, 25, sys_fcntl, 3);
    at_res!(t, 26, sys_inotify_init1, 1);
    at_res!(t, 27, sys_inotify_add_watch, 3);
    at_res!(t, 28, sys_inotify_rm_watch, 2);
    at_res!(t, 29, sys_ioctl, 3);
    at_res!(t, 30, sys_ioprio_set, 3);
    at_res!(t, 31, sys_ioprio_get, 2);
    at_res!(t, 32, sys_flock, 2);
    at_res!(t, 33, sys_mknodat, 4);
    at_res!(t, 34, sys_mkdirat, 3);
    at_res!(t, 35, sys_unlinkat, 3);
    at_res!(t, 36, sys_symlinkat, 3);
    at_res!(t, 37, sys_linkat, 5);
    at_res!(t, 38, sys_renameat, 4);
    at_res!(t, 39, sys_umount2, 2);
    at_res!(t, 40, sys_mount, 5);
    at_res!(t, 41, sys_pivot_root, 2);
    // Retired in Linux 3.1 with knfsd's syscall interface: ENOSYS everywhere.
    at!(t, 42, not_configured); // nfsservctl
    at_res!(t, 43, sys_statfs_arm64, 2);
    at_res!(t, 44, sys_fstatfs_arm64, 2);
    at_res!(t, 45, sys_truncate64, 2);
    at_res!(t, 46, sys_ftruncate64, 2);
    at_res!(t, 47, sys_fallocate, 4);
    at_res!(t, 48, sys_faccessat3, 3); // three arguments; 439 is the four-argument form
    at_res!(t, 49, sys_chdir, 1);
    at_res!(t, 50, sys_fchdir, 1);
    at_res!(t, 51, sys_chroot, 1);
    at_res!(t, 52, sys_fchmod, 2);
    at_res!(t, 53, sys_fchmodat, 3);
    at_res!(t, 54, sys_fchownat, 5);
    at_res!(t, 55, sys_fchown32, 3);
    at_res!(t, 56, sys_openat, 4);
    at_res!(t, 57, sys_close, 1);
    at_res!(t, 58, sys_vhangup, 0);
    at_res!(t, 59, sys_pipe2, 2);
    at_res!(t, 60, sys_quotactl, 4);
    at_res!(t, 61, sys_getdents64, 3);
    at_res!(t, 62, sys_lseek64, 3);
    at_res!(t, 63, sys_read, 3);
    at_res!(t, 64, sys_write, 3);
    at_res!(t, 65, sys_readv, 3);
    at_res!(t, 66, sys_writev, 3);
    at_res!(t, 67, sys_pread, 4);
    at_res!(t, 68, sys_pwrite, 4);
    at_res!(t, 69, sys_preadv, 5);
    at_res!(t, 70, sys_pwritev, 5);
    at_res!(t, 71, sys_sendfile64, 4);
    at_res!(t, 72, sys_pselect, 6);
    at_res!(t, 73, sys_ppoll, 5);
    at_res!(t, 74, sys_signalfd4, 4);
    at_res!(t, 75, sys_vmsplice, 4);
    at_res!(t, 76, sys_splice, 6);
    at_res!(t, 77, sys_tee, 4);
    at_res!(t, 78, sys_readlinkat, 4);
    at_res!(t, 79, sys_fstatat64, 4);
    at_res!(t, 80, sys_fstat64, 2);
    /* sync(2). A no-op that answers 0, and the only syscall_success_stub in
     * this table.
     *
     * Left as one deliberately, and the reason is worth writing down because
     * "answers success without doing the work" is otherwise exactly the shape
     * to fix. Linux's sync() writes back **every** filesystem on the machine,
     * and the host here has other tenants: a guest running `sync` in a loop
     * would schedule host-wide writeback, which is a cost an embedder never
     * agreed to. syncfs(fd) and fsync(fd) both do the real thing for what the
     * caller actually names, and those are what a program that cares about its
     * own data uses.
     *
     * What is lost is durability across a *host* crash for a guest that called
     * sync() and nothing else. That cannot be reproduced from a test, which is
     * why this is a note rather than a change. */
    at!(t, 81, syscall_success_stub); // sync
    at_res!(t, 82, sys_fsync, 1);
    at_res!(t, 83, sys_fsync, 1); // fdatasync
    at_res!(t, 84, sys_sync_file_range, 4);
    at_res!(t, 85, sys_timerfd_create, 2);
    at_res!(t, 86, sys_timerfd_settime, 4);
    at_res!(t, 87, sys_timerfd_gettime, 2);
    at_res!(t, 88, sys_utimensat, 4);
    // acct: CONFIG_BSD_PROCESS_ACCT=n. The reference has it (acct(file) is 0
    // as root, rarecalls_probe), and switching it on means writing an
    // acct_v3 record per exiting process, which nothing here produces;
    // accepting the file and writing nothing would be a success for
    // something that does not happen.
    at!(t, 89, not_configured); // acct
    at_res!(t, 90, sys_capget, 2);
    at_res!(t, 91, sys_capset, 2);
    at_res!(t, 92, sys_personality, 1);
    at_val!(t, 93, sys_exit, 1);
    at_val!(t, 94, sys_exit_group, 1);
    at_res!(t, 95, sys_waitid, 4);
    at_val!(t, 96, sys_set_tid_address, 1);
    at_res!(t, 97, sys_unshare, 1);
    at_res!(t, 98, sys_futex, 6);
    at_res!(t, 99, sys_set_robust_list, 2);
    at_res!(t, 100, sys_get_robust_list, 3);
    at_res!(t, 101, sys_nanosleep, 2);
    at_res!(t, 102, sys_getitimer, 2);
    at_res!(t, 103, sys_setitimer, 3);
    // CONFIG_KEXEC=n, which is the arm64 reference's answer too (ENOSYS for
    // every argument, rarecalls_probe), and for kexec_file_load at 294.
    at!(t, 104, not_configured); // kexec_load
    // CONFIG_MODULES=n: there is no loader, and no module can be built against
    // this kernel. The reference has modules (ENOEXEC for a bad image, ENOENT
    // to unload a name that is not loaded); `probe_diff.sh` carries the
    // difference as `modules-not-configured`. 273 is finit_module.
    at!(t, 105, not_configured); // init_module
    at!(t, 106, not_configured); // delete_module
    at_res!(t, 107, sys_timer_create, 3);
    at_res!(t, 108, sys_timer_gettime, 2);
    at_res!(t, 109, sys_timer_getoverrun, 1);
    at_res!(t, 110, sys_timer_settime, 4);
    at_res!(t, 111, sys_timer_delete, 1);
    at_res!(t, 112, sys_clock_settime, 2);
    at_res!(t, 113, sys_clock_gettime, 2);
    at_res!(t, 114, sys_clock_getres, 2);
    at_res!(t, 115, sys_clock_nanosleep, 4);
    at_res!(t, 116, sys_syslog, 3);
    at_res!(t, 117, sys_ptrace, 4);
    at_res!(t, 118, sys_sched_setparam, 2);
    at_res!(t, 119, sys_sched_setscheduler, 3);
    at_res!(t, 120, sys_sched_getscheduler, 1);
    at_res!(t, 121, sys_sched_getparam, 2);
    at_res!(t, 122, sys_sched_setaffinity, 3);
    at_res!(t, 123, sys_sched_getaffinity, 3);
    at_val!(t, 124, sys_sched_yield, 0);
    at_res!(t, 125, sys_sched_get_priority_max, 1);
    at_res!(t, 126, sys_sched_get_priority_min, 1);
    at_res!(t, 127, sys_sched_rr_get_interval, 2);
    at_res!(t, 128, sys_restart_syscall, 0);
    at_res!(t, 129, sys_kill, 2);
    at_res!(t, 130, sys_tkill, 2);
    at_res!(t, 131, sys_tgkill, 3);
    at_res!(t, 132, sys_sigaltstack, 2);
    at_res!(t, 133, sys_rt_sigsuspend, 2);
    at_res!(t, 134, sys_rt_sigaction, 4);
    at_res!(t, 135, sys_rt_sigprocmask, 4);
    at_res!(t, 136, sys_rt_sigpending, 2);
    at_res!(t, 137, sys_rt_sigtimedwait, 4);
    at_res!(t, 138, sys_rt_sigqueueinfo, 3);
    at_res!(t, 139, sys_rt_sigreturn, 0);
    at_res!(t, 140, sys_setpriority, 3);
    at_res!(t, 141, sys_getpriority, 2);
    at_res!(t, 142, sys_reboot, 3);
    at_res!(t, 143, sys_setregid, 2);
    at_res!(t, 144, sys_setgid, 1);
    at_res!(t, 145, sys_setreuid, 2);
    at_res!(t, 146, sys_setuid, 1);
    at_res!(t, 147, sys_setresuid, 3);
    at_res!(t, 148, sys_getresuid, 3);
    at_res!(t, 149, sys_setresgid, 3);
    at_res!(t, 150, sys_getresgid, 3);
    at_val!(t, 151, sys_setfsuid, 1);
    at_val!(t, 152, sys_setfsgid, 1);
    at_res!(t, 153, sys_times, 1);
    at_res!(t, 154, sys_setpgid, 2);
    at_res!(t, 155, sys_getpgid, 1);
    at_res!(t, 156, sys_getsid, 1);
    at_res!(t, 157, sys_setsid, 0);
    at_res!(t, 158, sys_getgroups, 2);
    at_res!(t, 159, sys_setgroups, 2);
    at_res!(t, 160, sys_uname, 1);
    at_res!(t, 161, sys_sethostname, 2);
    at_res!(t, 162, sys_setdomainname, 2);
    at_res!(t, 163, sys_getrlimit64, 2);
    at_res!(t, 164, sys_setrlimit64, 2);
    at_res!(t, 165, sys_getrusage, 2);
    at_val!(t, 166, sys_umask, 1);
    at_res!(t, 167, sys_prctl, 5);
    at_res!(t, 168, sys_getcpu, 3);
    at_res!(t, 169, sys_gettimeofday, 2);
    at_res!(t, 170, sys_settimeofday, 2);
    at_res!(t, 171, sys_adjtimex, 1);
    at_val!(t, 172, sys_getpid, 0);
    at_val!(t, 173, sys_getppid, 0);
    at_val!(t, 174, sys_getuid32, 0);
    at_val!(t, 175, sys_geteuid32, 0);
    at_val!(t, 176, sys_getgid32, 0);
    at_val!(t, 177, sys_getegid32, 0);
    at_val!(t, 178, sys_gettid, 0);
    at_res!(t, 179, sys_sysinfo, 1);
    at_res!(t, 180, sys_mq_open, 4); // mq_open
    at_res!(t, 181, sys_mq_unlink, 1); // mq_unlink
    at_res!(t, 182, sys_mq_timedsend, 5); // mq_timedsend
    at_res!(t, 183, sys_mq_timedreceive, 5); // mq_timedreceive
    at_res!(t, 184, sys_mq_notify, 2); // mq_notify
    at_res!(t, 185, sys_mq_getsetattr, 3); // mq_getsetattr
    at_res!(t, 186, sys_msgget, 2);
    at_res!(t, 187, sys_msgctl, 3);
    at_res!(t, 188, sys_msgrcv, 5);
    at_res!(t, 189, sys_msgsnd, 4);
    at_res!(t, 190, sys_semget, 3);
    at_res!(t, 191, sys_semctl, 4);
    at_res!(t, 192, sys_semtimedop, 4);
    at_res!(t, 193, sys_semop, 3);
    at_res!(t, 194, sys_shmget, 3);
    at_res!(t, 195, sys_shmctl, 3);
    at_res!(t, 196, sys_shmat, 3);
    at_res!(t, 197, sys_shmdt, 1);
    // Socket syscalls (no multiplexer on arm64)
    at_res!(t, 198, sys_socket, 3);
    at_res!(t, 199, sys_socketpair, 4);
    at_res!(t, 200, sys_bind, 3);
    at_res!(t, 201, sys_listen, 2);
    at_res!(t, 202, sys_accept, 3);
    at_res!(t, 203, sys_connect, 3);
    at_res!(t, 204, sys_getsockname, 3);
    at_res!(t, 205, sys_getpeername, 3);
    at_res!(t, 206, sys_sendto, 6);
    at_res!(t, 207, sys_recvfrom, 6);
    at_res!(t, 208, sys_setsockopt, 5);
    at_res!(t, 209, sys_getsockopt, 5);
    at_res!(t, 210, sys_shutdown, 2);
    at_res!(t, 211, sys_sendmsg, 3);
    at_res!(t, 212, sys_recvmsg, 3);
    at_res!(t, 213, sys_readahead, 3);
    at_val!(t, 214, sys_brk, 1);
    at_res!(t, 215, sys_munmap, 2);
    at_res!(t, 216, sys_mremap, 5);
    at_res!(t, 217, sys_add_key, 5);
    at_res!(t, 218, sys_request_key, 4);
    at_res!(t, 219, sys_keyctl, 5);
    at_res!(t, 220, sys_clone, 5);
    at_res!(t, 221, sys_execve, 3);
    at_res!(t, 222, sys_mmap64, 6);
    at_res!(t, 223, sys_fadvise64, 4); // fadvise64
    // No swap area, and no filesystem here that could hold one: see
    // crates/kernel/pathcalls' swapquota.
    at_res!(t, 224, sys_swapon, 2);
    at_res!(t, 225, sys_swapoff, 1);
    at_res!(t, 226, sys_mprotect, 3);
    at_res!(t, 227, sys_msync, 3);
    at_res!(t, 228, sys_mlock, 2);
    at_res!(t, 229, sys_munlock, 2);
    at_res!(t, 230, sys_mlockall, 1);
    at_val!(t, 231, sys_munlockall, 0);
    at_res!(t, 232, sys_mincore, 3); // mincore
    at_res!(t, 233, sys_madvise, 3);
    at_res!(t, 234, sys_remap_file_pages, 5);
    // The NUMA policy family, answered as a CONFIG_NUMA=n kernel answers: every
    // one of them ENOSYS, which is what the arm64 reference kernel gives (see
    // tests/guest/src/bin/mm_modern_probe.rs). `mbind` answered 0 for any
    // argument until 2026-11-11, which made this kernel claim one call of a
    // family whose other five it refused; libnuma's `numa_available()` asks
    // `get_mempolicy` and falls back on ENOSYS, so one answer for all six is
    // the consistent one.
    at!(t, 235, not_configured); // mbind
    at!(t, 236, not_configured); // get_mempolicy
    at!(t, 237, not_configured); // set_mempolicy
    at!(t, 238, not_configured); // migrate_pages
    at!(t, 239, not_configured); // move_pages
    at_res!(t, 240, sys_rt_tgsigqueueinfo, 4);
    // perf_event_open: CONFIG_PERF_EVENTS=n. There are no hardware counters
    // to hand a guest, and a software one (task-clock, page faults) would be a
    // number this kernel cannot keep -- the guest's CPU time is sampled from
    // the host on demand, not accumulated; see `itimer-no-cpu-clocks` in
    // tests/integration/probe_diff.sh. `perf` and profilers report "not
    // supported" for ENOSYS.
    at!(t, 241, not_configured); // perf_event_open
    at_res!(t, 242, sys_accept4, 4);
    at_res!(t, 243, sys_recvmmsg, 5);
    at_res!(t, 260, sys_wait4, 4);
    at_res!(t, 261, sys_prlimit64, 4);
    at_res!(t, 262, sys_fanotify_init, 2);
    at_res!(t, 263, sys_fanotify_mark, 5);
    at_res!(t, 264, sys_name_to_handle_at, 5);
    at_res!(t, 265, sys_open_by_handle_at, 3);
    at_res!(t, 266, sys_clock_adjtime, 2);
    at_res!(t, 267, sys_syncfs, 1);
    at_res!(t, 268, sys_setns, 2);
    at_res!(t, 269, sys_sendmmsg, 4);
    at_res!(t, 270, sys_process_vm_readv, 6);
    at_res!(t, 271, sys_process_vm_writev, 6);
    at_res!(t, 272, sys_kcmp, 5);
    at!(t, 273, not_configured); // finit_module: CONFIG_MODULES=n, see 105
    at_res!(t, 274, sys_sched_setattr, 3);
    at_res!(t, 275, sys_sched_getattr, 4);
    at_res!(t, 276, sys_renameat2, 5);
    at_res!(t, 277, sys_seccomp, 3);
    at_res!(t, 278, sys_getrandom, 3);
    at_res!(t, 279, sys_memfd_create, 2);
    // bpf: CONFIG_BPF_SYSCALL=n. Every BPF program type attaches to a kernel
    // hook -- a socket, a tracepoint, a cgroup -- that this kernel does not
    // have, so a verifier with nothing to attach to would accept programs that
    // never run. Seccomp's classic BPF is a different thing and is not this.
    at!(t, 280, not_configured); // bpf
    at_res!(t, 281, sys_execveat, 5);
    // userfaultfd: CONFIG_USERFAULTFD=n. Its whole contract is that a fault on
    // a registered range parks the faulting thread until another thread
    // resolves it, and a guest fault here is taken inside a gadget with no
    // way to park; registering a range that then faulted normally would break
    // the one promise the call makes. /dev/userfaultfd is absent too, as it is
    // on such a kernel.
    at!(t, 282, not_configured); // userfaultfd
    at_res!(t, 283, sys_membarrier, 3); // membarrier
    at_res!(t, 284, sys_mlock2, 3);
    at_res!(t, 285, sys_copy_file_range, 6);
    at_res!(t, 286, sys_preadv2, 6);
    at_res!(t, 287, sys_pwritev2, 6);
    at_res!(t, 288, sys_pkey_mprotect, 4);
    at_res!(t, 289, sys_pkey_alloc, 2);
    at_res!(t, 290, sys_pkey_free, 1);
    at_res!(t, 291, sys_statx, 5);

    // Linux 5.x+ syscalls. Most are stubbed and let glibc/musl/Node fall back
    // to the older ABI; the few that we actually implement unblock specific
    // CLIs that hit hard-error paths instead of falling back.
    at_res!(t, 292, sys_io_pgetevents, 6);
    // rseq. `ENOSYS` on purpose, which is what a kernel without CONFIG_RSEQ
    // answers, and glibc (`__rseq_size = 0`, `sched_getcpu` through getcpu)
    // and tcmalloc (no per-CPU caches) fall back on it.
    //
    // A registration obliges the kernel to keep `cpu_id`/`mm_cid` current and
    // to restart a critical section at its abort handler whenever the thread
    // is preempted or migrated or takes a signal inside it. Guest threads are
    // host threads here and the host's preemption is not observable, so two
    // threads reporting the same `cpu_id` can run at once on two host CPUs and
    // both commit -- the per-CPU data a critical section exists to protect
    // would be torn, silently. Unique ids per thread are no way out either:
    // `cpu_id` has to stay below the CPU count, which threads outnumber. A
    // registration that never aborts is worse than none, so there is none.
    // Silent because glibc issues it at every thread start.
    at!(t, 293, syscall_silent_stub); // rseq
    // 294 is kexec_file_load; the rest are numbers 64-bit arm64 never assigned
    // (403-423 are the 32-bit time64 calls).
    at!(t, 294..=423, syscall_silent_stub);
    at_res!(t, 424, sys_pidfd_send_signal, 4);
    at_res!(t, 425, sys_io_uring_setup, 2);
    at_res!(t, 426, sys_io_uring_enter, 6);
    at_res!(t, 427, sys_io_uring_register, 4);
    at_res!(t, 428, sys_open_tree, 3);
    at_res!(t, 429, sys_move_mount, 5);
    at_res!(t, 430, sys_fsopen, 2);
    at_res!(t, 431, sys_fsconfig, 5);
    at_res!(t, 432, sys_fsmount, 3);
    at_res!(t, 433, sys_fspick, 3);
    at_res!(t, 434, sys_pidfd_open, 2); // pidfd_open
    at_res!(t, 435, sys_clone3, 2); // clone3 (bun/JSC uses it directly)
    at_res!(t, 436, sys_close_range, 3); // *** unblocks Anthropic claude-cli ***
    // openat2. `ENOSYS` until 2026-11-11, on purpose: its `resolve` field is
    // what a caller asks for *containment* with -- `RESOLVE_BENEATH` and
    // `RESOLVE_NO_SYMLINKS` are how Go's `os.Root` and every container runtime
    // keep a path walk inside a subtree -- so a version that returned a
    // descriptor without enforcing them would hand back a file the caller
    // believes cannot be outside its root. The flags are enforced by the walk
    // in `crates/fs/path` (`Scope`), not merely accepted by the syscall.
    at_res!(t, 437, sys_openat2, 4);
    at_res!(t, 438, sys_pidfd_getfd, 3);
    at_res!(t, 439, sys_faccessat, 4); // faccessat2: the same call with a flags argument
    at_res!(t, 440, sys_process_madvise, 5);
    at_res!(t, 441, sys_epoll_pwait2, 6);
    at_res!(t, 442, sys_mount_setattr, 5);
    at_res!(t, 443, sys_quotactl_fd, 4);
    at_res!(t, 444, sys_landlock_create_ruleset, 3);
    at_res!(t, 445, sys_landlock_add_rule, 4);
    at_res!(t, 446, sys_landlock_restrict_self, 2);
    // memfd_secret: ENOSYS, which is what a 7.x kernel booted with
    // `secretmem.enable=0` or built without CONFIG_SECRETMEM answers. The
    // reference kernel has it, and its contract is that the *kernel* cannot
    // read the memory -- process_vm_readv of it is EFAULT there (measured by
    // mm_modern_probe) -- while the process can; a descriptor that handed out ordinary
    // shared memory would claim a protection it does not give.
    at!(t, 447, not_configured); // memfd_secret
    at_res!(t, 448, sys_process_mrelease, 2);
    at_res!(t, 449, sys_futex_waitv, 5);
    // Linux 6.x and 7.0.
    at!(t, 450, not_configured); // set_mempolicy_home_node: CONFIG_NUMA=n, see 235
    at_res!(t, 451, sys_cachestat, 4);
    at_res!(t, 452, sys_fchmodat2, 4);
    // No FEAT_GCS here, and a kernel without CONFIG_ARM64_GCS answers ENOSYS,
    // as the arm64 reference does.
    at!(t, 453, not_configured); // map_shadow_stack
    at_res!(t, 454, sys_futex_wake, 4);
    at_res!(t, 455, sys_futex_wait, 6);
    at_res!(t, 456, sys_futex_requeue, 4);
    at_res!(t, 457, sys_statmount, 4);
    at_res!(t, 458, sys_listmount, 4);
    at_res!(t, 459, sys_lsm_get_self_attr, 4);
    at_res!(t, 460, sys_lsm_set_self_attr, 4);
    at_res!(t, 461, sys_lsm_list_modules, 3);
    at_res!(t, 462, sys_mseal, 3);
    at_res!(t, 463, sys_setxattrat, 6);
    at_res!(t, 464, sys_getxattrat, 6);
    at_res!(t, 465, sys_listxattrat, 5);
    at_res!(t, 466, sys_removexattrat, 4);
    at_res!(t, 467, sys_open_tree_attr, 5);
    at_res!(t, 468, sys_file_getattr, 5);
    at_res!(t, 469, sys_file_setattr, 5);
    // listns (6.19): it lists namespace ids, which are what nsfs gives a
    // namespace -- and there are no namespaces here and no nsfs, so no id
    // that `ioctl(NS_GET_ID)` on a /proc/<pid>/ns file could be compared
    // with. ENOSYS is what every kernel before 6.19 answers, and lsns-style
    // callers fall back to /proc/<pid>/ns, which is absent here as well.
    at!(t, 470, not_configured); // listns
    // rseq_slice_yield yields the time-slice extension an rseq registration
    // asked for, and with no rseq (see 293) there is none to yield. `ENOSYS`,
    // which is also what the 7.2 arm64 reference answers (no
    // CONFIG_RSEQ_SLICE_EXTENSION there).
    at!(t, 471, syscall_stub); // rseq_slice_yield
    t
}
