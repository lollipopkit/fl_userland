#![allow(non_upper_case_globals)]

/// The file-type and permission bits of a **guest** `st_mode`.
///
/// These came out of the *host's* `sys/stat.h` until 2026-09-08, because
/// bindgen followed the include chain and `crates/kernel/taskview`' shared-var
/// regex said `S_I.*`. Nothing checked them: the values are Linux's here by
/// coincidence -- Darwin uses the same historical Unix numbers -- and a guest
/// mode read with a host constant is wrong the day the two differ.
///
/// Written as octal, which is how every kernel and every man page writes them,
/// and asserted in `mode_bits_are_linuxs` below against the literals from
/// `include/uapi/linux/stat.h`.
///
/// **`S_IFWHT` is not here.** 0160000 is Darwin's whiteout type and Linux has
/// no file type at that value at all, so a guest `st_mode` can never hold it.
/// Nothing named it. `S_ISTXT`, `S_IREAD`, `S_IWRITE` and `S_IEXEC` are gone
/// for the same reason with a different history: they are BSD's older spellings
/// of `S_ISVTX`, `S_IRUSR`, `S_IWUSR` and `S_IXUSR`, and no Linux uapi header
/// defines them.
pub const S_IFMT: u32 = 0o170000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IRWXU: u32 = 0o700;
pub const S_IRUSR: u32 = 0o400;
pub const S_IWUSR: u32 = 0o200;
pub const S_IXUSR: u32 = 0o100;
pub const S_IRWXG: u32 = 0o070;
pub const S_IRGRP: u32 = 0o040;
pub const S_IWGRP: u32 = 0o020;
pub const S_IXGRP: u32 = 0o010;
pub const S_IRWXO: u32 = 0o007;
pub const S_IROTH: u32 = 0o004;
pub const S_IWOTH: u32 = 0o002;
pub const S_IXOTH: u32 = 0o001;
pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;
pub const S_ISVTX: u32 = 0o1000;
pub const AT_FDCWD_: i32 = -100;
pub const NAME_MAX: u32 = 255;
pub const LSEEK_SET: u32 = 0;
pub const LSEEK_CUR: u32 = 1;
pub const LSEEK_END: u32 = 2;
pub const LSEEK_DATA: u32 = 3;
pub const LSEEK_HOLE: u32 = 4;
/// The largest argument any ioctl may declare.
///
/// Every implementation answers a fixed per-command size and the biggest today
/// is a `struct termios_`, well under this. It exists so that an operation that
/// one day *computes* a size rather than looking one up cannot size a buffer
/// with it — the VFS copies that many bytes in and out around the call, and
/// `crates/kernel/fdcalls` checks against this before it does.
pub const IOCTL_ARG_MAX: u32 = 4096;
pub const DEV_BLOCK: u32 = 0;
pub const DEV_CHAR: u32 = 1;
pub const MAX_PATH: u32 = 4096;
pub const MAX_NAME: u32 = 256;
pub const AT_SYMLINK_NOFOLLOW_: u32 = 256;
pub const AT_EMPTY_PATH_: u32 = 4096;
/// `renameat2`'s flags, from `include/uapi/linux/fs.h` — **the guest's**
/// numbering.
///
/// A host that spells them differently translates at its own boundary, and on
/// Darwin it must: `renamex_np(2)` uses 0x2 for the exchange and 0x4 for the
/// exclusive create, so two of these three collide with the wrong meaning.
///
/// A filesystem that cannot honour a flag it is given answers `_EINVAL` rather
/// than renaming without it. The flags are the whole point of the call, and a
/// silent plain rename loses whoever the caller was racing.
pub const RENAME_NOREPLACE_: u32 = 1;
pub const RENAME_EXCHANGE_: u32 = 2;
pub const RENAME_WHITEOUT_: u32 = 4;
pub const RENAME_KNOWN_: u32 = 7;
pub const AC_R: u32 = 4;
pub const AC_W: u32 = 2;
pub const AC_X: u32 = 1;
pub const AC_F: u32 = 0;
pub const O_ACCMODE_: u32 = 3;
pub const O_RDONLY_: u32 = 0;
pub const O_WRONLY_: u32 = 1;
pub const O_RDWR_: u32 = 2;
pub const O_CREAT_: u32 = 64;
pub const O_EXCL_: u32 = 128;
pub const O_NOCTTY_: u32 = 256;
pub const O_TRUNC_: u32 = 512;
pub const O_APPEND_: u32 = 1024;
pub const O_NONBLOCK_: u32 = 2048;
pub const O_DSYNC_: u32 = 4096;
pub const O_ASYNC_: u32 = 8192;
pub const O_SYNC_: u32 = 1052672;
pub const O_DIRECTORY_: u32 = 16384;
pub const O_TMPFILE_: u32 = 4210688;
pub const O_NOFOLLOW_: u32 = 32768;
/// `O_DIRECT` on **arm64** is 0o200000, not asm-generic's 0o40000: arm64
/// overrides that header, and 0o40000 there is `O_DIRECTORY`.
///
/// Worth stating, because the first version of `pipe_probe` used the generic
/// value and both kernels agreed perfectly about a question neither had been
/// asked.
pub const O_DIRECT_: u32 = 65536;
pub const O_LARGEFILE_: u32 = 131072;
pub const O_NOATIME_: u32 = 262144;
pub const O_CLOEXEC_: u32 = 524288;
pub const O_PATH_: u32 = 2097152;
pub const FIONREAD_: u32 = 21531;
pub const FIONBIO_: u32 = 21537;
pub const FIONCLEX_: u32 = 21584;
pub const FIOCLEX_: u32 = 21585;
pub const FIOASYNC_: u32 = 21586;
pub const FIOSETOWN_: u32 = 35073;
pub const SIOCSPGRP_: u32 = 35074;
pub const FIOGETOWN_: u32 = 35075;
pub const SIOCGPGRP_: u32 = 35076;
/* `XATTR_OP_GET`, `_SET`, `_LIST` and `_REMOVE` were four `u32`s here until
 * 2026-09-11, and `crates/kernel/fdattr` had a second, private copy of the
 * same four as `c_int`. They are `crate::XattrOp`, an enum, for the reason
 * written beside it: two filesystems matched them with a guard chain, which
 * the compiler cannot check for exhaustiveness. */
pub const SIG_ERR_: i32 = -1;
pub const SIG_DFL_: u32 = 0;
pub const SIG_IGN_: u32 = 1;
pub const SA_NOCLDSTOP_: u32 = 1;
pub const SA_NOCLDWAIT_: u32 = 2;
pub const SA_ONSTACK_: u32 = 134217728;
pub const SA_SIGINFO_: u32 = 4;
pub const SA_RESTART_: u32 = 268435456;
pub const SA_NODEFER_: u32 = 1073741824;
pub const SA_RESETHAND_: u32 = 2147483648;
pub const MAX_SIG: u32 = 64;
pub const SIGHUP_: u32 = 1;
pub const SIGINT_: u32 = 2;
pub const SIGQUIT_: u32 = 3;
pub const SIGILL_: u32 = 4;
pub const SIGTRAP_: u32 = 5;
pub const SIGABRT_: u32 = 6;
pub const SIGIOT_: u32 = 6;
pub const SIGBUS_: u32 = 7;
pub const SIGFPE_: u32 = 8;
pub const SIGKILL_: u32 = 9;
pub const SIGUSR1_: u32 = 10;
pub const SIGSEGV_: u32 = 11;
pub const SIGUSR2_: u32 = 12;
pub const SIGPIPE_: u32 = 13;
pub const SIGALRM_: u32 = 14;
pub const SIGTERM_: u32 = 15;
pub const SIGSTKFLT_: u32 = 16;
pub const SIGCHLD_: u32 = 17;
pub const SIGCONT_: u32 = 18;
pub const SIGSTOP_: u32 = 19;
pub const SIGTSTP_: u32 = 20;
pub const SIGTTIN_: u32 = 21;
pub const SIGTTOU_: u32 = 22;
pub const SIGURG_: u32 = 23;
pub const SIGXCPU_: u32 = 24;
pub const SIGXFSZ_: u32 = 25;
pub const SIGVTALRM_: u32 = 26;
pub const SIGPROF_: u32 = 27;
pub const SIGWINCH_: u32 = 28;
pub const SIGIO_: u32 = 29;
pub const SIGPWR_: u32 = 30;
pub const SIGSYS_: u32 = 31;
pub const SI_USER_: u32 = 0;
pub const SI_TIMER_: i32 = -2;
pub const SI_TKILL_: i32 = -6;
pub const SI_KERNEL_: u32 = 128;
pub const CLD_EXITED_: u32 = 1;
pub const CLD_KILLED_: u32 = 2;
pub const CLD_DUMPED_: u32 = 3;
pub const CLD_TRAPPED_: u32 = 4;
pub const CLD_STOPPED_: u32 = 5;
pub const CLD_CONTINUED_: u32 = 6;
pub const TRAP_TRACE_: u32 = 2;
pub const SEGV_MAPERR_: u32 = 1;
pub const SEGV_ACCERR_: u32 = 2;
pub const SIG_BLOCK_: u32 = 0;
pub const SIG_UNBLOCK_: u32 = 1;
pub const SIG_SETMASK_: u32 = 2;
pub const ITIMER_REAL_: u32 = 0;
pub const ITIMER_VIRTUAL_: u32 = 1;
pub const ITIMER_PROF_: u32 = 2;
pub const RLIMIT_CPU_: u32 = 0;
pub const RLIMIT_FSIZE_: u32 = 1;
pub const RLIMIT_DATA_: u32 = 2;
pub const RLIMIT_STACK_: u32 = 3;
pub const RLIMIT_CORE_: u32 = 4;
pub const RLIMIT_RSS_: u32 = 5;
pub const RLIMIT_NPROC_: u32 = 6;
pub const RLIMIT_NOFILE_: u32 = 7;
pub const RLIMIT_MEMLOCK_: u32 = 8;
pub const RLIMIT_AS_: u32 = 9;
pub const RLIMIT_LOCKS_: u32 = 10;
pub const RLIMIT_SIGPENDING_: u32 = 11;
pub const RLIMIT_MSGQUEUE_: u32 = 12;
pub const RLIMIT_NICE_: u32 = 13;
pub const RLIMIT_RTPRIO_: u32 = 14;
pub const RLIMIT_RTTIME_: u32 = 15;
pub const RLIMIT_NLIMITS_: u32 = 16;
pub const MAX_PID: u32 = 32768;
pub const PTRACE_TRACEME_: u32 = 0;
pub const PTRACE_PEEKTEXT_: u32 = 1;
pub const PTRACE_PEEKDATA_: u32 = 2;
pub const PTRACE_PEEKUSER_: u32 = 3;
pub const PTRACE_POKETEXT_: u32 = 4;
pub const PTRACE_POKEDATA_: u32 = 5;
pub const PTRACE_CONT_: u32 = 7;
pub const PTRACE_DETACH_: u32 = 17;
pub const PTRACE_KILL_: u32 = 8;
pub const PTRACE_SINGLESTEP_: u32 = 9;
pub const PTRACE_SYSCALL_: u32 = 24;
pub const PTRACE_GETREGS_: u32 = 12;
pub const PTRACE_SETREGS_: u32 = 13;
pub const PTRACE_GETFPREGS_: u32 = 14;
pub const PTRACE_SETFPREGS_: u32 = 15;
pub const PTRACE_ATTACH_: u32 = 16;
pub const PTRACE_SEIZE_: u32 = 16902;
pub const PTRACE_SETOPTIONS_: u32 = 16896;
pub const PTRACE_O_TRACESYSGOOD_: u32 = 1;
pub const PTRACE_O_TRACEEXEC_: u32 = 16;
pub const PTRACE_O_TRACEEXIT_: u32 = 64;
pub const PTRACE_EVENT_EXEC_: u32 = 4;
pub const PTRACE_EVENT_EXIT_: u32 = 6;
pub const PTRACE_GETSIGINFO_: u32 = 16898;
pub const PTRACE_GETREGSET_: u32 = 16900;
pub const PTRACE_SETREGSET_: u32 = 16901;
pub const NT_PRSTATUS_: u32 = 1;
pub const NT_FPREGSET_: u32 = 2;
pub const ARGV_MAX: u32 = 131072;
pub const MMAP_SHARED: u32 = 1;
pub const MMAP_PRIVATE: u32 = 2;
pub const MMAP_FIXED: u32 = 16;
pub const MMAP_ANONYMOUS: u32 = 32;
pub const MMAP_NORESERVE: u32 = 16384;
pub const MMAP_FIXED_NOREPLACE: u32 = 1048576;
pub const LOCK_SH_: u32 = 1;
pub const LOCK_EX_: u32 = 2;
pub const LOCK_NB_: u32 = 4;
pub const LOCK_UN_: u32 = 8;
pub const MS_READONLY_: u32 = 1;
pub const MS_NOSUID_: u32 = 2;
pub const MS_NODEV_: u32 = 4;
pub const MS_NOEXEC_: u32 = 8;
pub const MS_SILENT_: u32 = 32768;
pub const UNAME_LENGTH: u32 = 65;
pub const N_SYMLINK_FOLLOW: u32 = 1;
pub const N_SYMLINK_NOFOLLOW: u32 = 2;
pub const N_PARENT_DIR_WRITE: u32 = 4;
pub const N_PARENT_DIR_WRITE_CREATE: u32 = 8;
pub const N_PARENT_DIR_WRITE_DELETE: u32 = 16;
pub const F_RDLCK_: u32 = 0;
pub const F_WRLCK_: u32 = 1;
pub const F_UNLCK_: u32 = 2;
pub const TCGETS_: u32 = 21505;
pub const TCSETS_: u32 = 21506;
pub const TCSETSW_: u32 = 21507;
pub const TCSETSF_: u32 = 21508;
pub const TIOCGWINSZ_: u32 = 21523;
pub const PTY_ATTR_UID: u32 = 0;
pub const PTY_ATTR_GID: u32 = 1;
pub const PTY_ATTR_MODE: u32 = 2;
pub const MEM_MAJOR: u32 = 1;
pub const DEV_NULL_MINOR: u32 = 3;
pub const DEV_ZERO_MINOR: u32 = 5;
pub const DEV_FULL_MINOR: u32 = 7;
pub const DEV_RANDOM_MINOR: u32 = 8;
pub const DEV_URANDOM_MINOR: u32 = 9;
pub const TTY_CONSOLE_MAJOR: u32 = 4;
pub const TTY_ALTERNATE_MAJOR: u32 = 5;
pub const DEV_TTY_MINOR: u32 = 0;
pub const DEV_CONSOLE_MINOR: u32 = 1;
pub const DEV_PTMX_MINOR: u32 = 2;
pub const TTY_PSEUDO_MASTER_MAJOR: u32 = 128;
pub const TTY_PSEUDO_SLAVE_MAJOR: u32 = 136;
pub const DYN_DEV_MAJOR: u32 = 240;
pub const FAKEFS_CHANGE_OP_WRITE: u32 = 0;
pub const FAKEFS_CHANGE_OP_UNLINK: u32 = 1;
pub const FAKEFS_CHANGE_OP_RENAME: u32 = 2;
pub const FAKEFS_CHANGE_OP_TRUNCATE: u32 = 3;
pub const VVAR_PAGES: u32 = 4;
pub const VDSO_PAGES: u32 = 2;
