//! One Rust staticlib for everything that ships inside `libiul.a`.
//!
//! Each crate here used to be its own `staticlib`, merged into `libiul.a` with
//! `libtool`. A Rust staticlib bundles the whole standard library, so that was
//! fifteen copies of it in one archive — `libiul.a` was 206 MB — and, with the
//! release profile's LTO, fifteen sets of *strong* definitions of std's
//! symbols. Linking any two of them into one binary is a duplicate-symbol
//! error, which is what a release build of `iul` hit and what ServerBox would
//! hit, since it links all three delivered archives together.
//!
//! Depending on them as rlibs instead puts one copy of std in the archive and
//! keeps every crate's `extern "C"` surface. Nothing here calls into them: the
//! C side does, by name.

// The gadget archive, bundled into this staticlib so that `libiul.a` is the
// whole engine. An `--extern` nothing mentions is not loaded, so the
// dependency alone would leave the objects out.
extern crate asbestos_gadgets;
extern crate bindmount;
extern crate bindpath;
extern crate cmsg;
extern crate devpts;
extern crate dirent;
extern crate elf;
extern crate fs_pipe;
extern crate msghdr;
extern crate rwabi;
extern crate asbestos_blockcache;
extern crate asbestos_crypto;
extern crate asbestos_features;
extern crate asbestos_diag;
extern crate asbestos_dispatch;
extern crate asbestos_gen;
extern crate bindstash;
extern crate ctty;
extern crate dircalls;
extern crate emu_tlb;
extern crate epollcalls;
extern crate eventfdcalls;
extern crate execargs;
extern crate execcalls;
extern crate exitcalls;
extern crate fakechange;
extern crate fakedb;
extern crate fakefs;
extern crate fdattr;
extern crate fdcalls;
extern crate fdtable;
extern crate fifo;
extern crate forkcalls;
extern crate fs_adhoc;
extern crate fs_devices;
extern crate fs_fake;
extern crate fs_fdobj;
extern crate fs_generic;
extern crate fs_inode;
extern crate fs_locks;
extern crate fs_mount;
extern crate fs_mounttable;
extern crate fs_poll;
extern crate fs_sock;
extern crate fs_tty;
extern crate fs_ttydev;
extern crate fsinfo;
extern crate futexcalls;
extern crate groupcalls;
extern crate grouprusage;
extern crate groupstop;
extern crate hostrusage;
extern crate hostsignal;
extern crate idcalls;
extern crate inotify;
extern crate inotifycalls;
extern crate itimer;
extern crate jobctl;
extern crate kernel_boot;
extern crate kernel_copyloop;
extern crate kernel_creds;
extern crate kernel_epoll;
extern crate kernel_errno;
extern crate kernel_eventfd;
extern crate kernel_futex;
extern crate kernel_groupexit;
extern crate kernel_hoststats;
extern crate kernel_hostthreads;
extern crate kernel_initstack;
extern crate kernel_mmapabi;
extern crate kernel_pidfd;
extern crate kernel_pids;
extern crate kernel_posixtimers;
extern crate kernel_procattr;
extern crate kernel_ptrace;
extern crate kernel_random;
extern crate kernel_rlimit;
extern crate kernel_robustlist;
extern crate kernel_schedabi;
extern crate kernel_shebang;
extern crate kernel_sigdisp;
extern crate kernel_sigframe;
extern crate kernel_sighand;
extern crate kernel_signalcalls;
extern crate kernel_signalfd;
extern crate kernel_sigqueue;
extern crate kernel_syscallrefs;
extern crate kernel_syscallrestart;
extern crate kernel_tgroup;
extern crate kernel_timerfd;
extern crate kernel_vdso;
extern crate kernel_vforkhandoff;
extern crate ldisc;
extern crate logline;
extern crate memfdcalls;
extern crate misccalls;
extern crate mmapcalls;
extern crate mountcalls;
extern crate offloadexec;
extern crate offloadprebuilt;
extern crate offloadreg;
extern crate offloadsym;
extern crate pagetable;
extern crate path;
extern crate pathcalls;
extern crate pidfdcalls;
extern crate pipecalls;
extern crate pollcalls;
extern crate pollindex;
extern crate pollset;
extern crate proc;
extern crate proctree;
extern crate procvmcalls;
extern crate realfs;
extern crate rescalls;
extern crate rwcalls;
extern crate signaldeliver;
extern crate signalfdcalls;
extern crate sockabi;
extern crate sockaddr;
extern crate sockrestart;
extern crate statcalls;
extern crate statx;
extern crate syscalldispatch;
extern crate syslogcalls;
extern crate sysvmsg;
extern crate sysvsem;
extern crate sysvshm;
extern crate taskcalls;
extern crate timecalls;
extern crate timerfdcalls;
extern crate tmpfs;
extern crate ttyreal;
extern crate ttyreg;
extern crate unamecalls;
extern crate unixname;
extern crate unixpeer;
extern crate usercopy;
extern crate util_fchdir;
extern crate util_guestlock;
extern crate util_iulenv;
extern crate util_timeabi;
extern crate util_timer;
extern crate v8mute;
extern crate waitcalls;
extern crate waitfor;

/// The symbol-level offload test handlers, when the feature is on.
///
/// **Named, not merely depended on.** That crate's only content is a
/// constructor in `__mod_init_func`, and an object that defines no symbol
/// anything references is one the linker may drop — which is the failure
/// `util/ish_env.c` spent ten lines of C warning about, and it is silent. A
/// `pub use` gives the linker a reason to keep the object.
#[cfg(feature = "offload-test-symbol")]
pub use offloadtest::registered_targets;

/// As above, for the prebuilt-gadget handlers.
#[cfg(feature = "offload-test-prebuilt")]
pub use offloadtestprebuilt::registered;
