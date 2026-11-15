/* The engine's interface, and the whole of it.
 *
 * An embedder links `libiul.a` and includes this. Nothing else here is a
 * contract: the other headers were what bindgen read, and no crate has read one
 * since 2026-09-08 — they described Rust objects to a C compiler that no longer
 * compiles anything of this engine.
 *
 * The shape of an embedder is `tests/integration/sbm_api_test.c`, which is the
 * nearest thing in this repository to ServerBox's own `sbm_iul.c` and is what
 * the smoke gate drives. Read it before this: it mounts a root, becomes init,
 * makes `/dev`, opens a pty and runs a command, in that order, and every call
 * below appears in it or in `crates/tools/iul`.
 *
 * Names ending in `_` are the **guest's**, not the host's: `O_RDONLY_` is
 * aarch64 Linux's value and `struct termios_` is the guest's layout. The
 * distinction is load-bearing — Darwin's `O_DIRECTORY` is a different bit, and
 * a guest `st_mode` read with a host constant has been a defect here twice.
 */
#ifndef IUL_H
#define IUL_H

#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- the guest's scalars ------------------------------------------------ */

typedef uint64_t addr_t;
typedef uint64_t qword_t;
typedef uint32_t dword_t;
typedef uint16_t word_t;
typedef uint8_t byte_t;
typedef int32_t sdword_t;

typedef dword_t uid_t_;
typedef word_t mode_t_;
typedef dword_t dev_t_;
typedef sdword_t pid_t_;
typedef sdword_t fd_t;

/* A pointer-shaped negative errno. `IS_ERR` is how a caller tells it from a
 * real pointer, and the bound is the largest errno.
 *
 * **Exactly three calls here answer one**, and each says so above its own
 * declaration: `generic_open`, `realfs_open` and `pty_open_fake`. None of the
 * three ever answers NULL, so a caller that tests `!p` instead of `IS_ERR(p)`
 * will dereference an address like -2. The other pointer-returning
 * declarations -- `task_self`, `current_fs`, `current_files` -- answer a real
 * pointer or NULL and never an errno.
 *
 * This said "several calls answer one" without naming them until 2026-09-16,
 * which left an embedder no way to tell which convention a declaration used.
 * `tools/err-ptr.py` is what keeps the list and the code in step. */
#define ERR_PTR(err) (void *) (intptr_t) (err)
#define PTR_ERR(ptr) (intptr_t) (ptr)
#define IS_ERR(ptr) ((uintptr_t) (ptr) > (uintptr_t) -0xfff)

/* ---- the objects, all opaque -------------------------------------------- */

struct fd;
struct fs_info;
struct fdtable;
struct mount;
struct fs_ops;
struct task;
struct tty;
struct poll_watchers;

/* ---- flags and numbers the guest sees ----------------------------------- */

#define O_RDONLY_ 0
#define O_WRONLY_ (1 << 0)
#define O_RDWR_ (1 << 1)
#define O_CREAT_ (1 << 6)
#define O_TRUNC_ (1 << 9)
#define O_NONBLOCK_ (1 << 11)
#define O_DIRECTORY_ (1 << 14)
#define O_NOFOLLOW_ (1 << 15)
#define O_CLOEXEC_ (1 << 19)

/* Device numbers, as Linux assigns them. `/dev` is the embedder's to make --
 * see `create_stdio` and `generic_mknodat` below -- because the guest's device
 * nodes live in the fakefs's metadata and nothing here creates them for you. */
#define MEM_MAJOR 1
#define DEV_NULL_MINOR 3
#define DEV_ZERO_MINOR 5
#define DEV_FULL_MINOR 7
#define DEV_RANDOM_MINOR 8
#define DEV_URANDOM_MINOR 9
#define TTY_CONSOLE_MAJOR 4
#define TTY_ALTERNATE_MAJOR 5
#define DEV_TTY_MINOR 0
#define DEV_CONSOLE_MINOR 1
#define DEV_PTMX_MINOR 2
#define TTY_PSEUDO_SLAVE_MAJOR 136

/* `dev_open`'s `type`. Block is 0 and character is 1 -- the opposite way round
 * from `S_IFBLK`/`S_IFCHR`, and getting it backwards while writing this header
 * is what `tools/unread-flags.py` reported. */
#define DEV_BLOCK 0
#define DEV_CHAR 1

/* A guest path's longest, and the size of a buffer that holds one. */
#define MAX_PATH 4096

/* The two signals an embedder sends a session: `SIGHUP` when its terminal is
 * closed, `SIGKILL` for one that never got started. */
#define SIGHUP_ 1
#define SIGKILL_ 9

#define RLIMIT_NOFILE_ 7
typedef uint64_t rlim_t_;
/* The calling task's soft limit. `RLIM_INFINITY` is `~0`. */
rlim_t_ rlimit(int resource);

/* The directory a relative path resolves against, when it is the caller's. */
#define AT_PWD (struct fd *) -2

/* The guest errnos a call answers, negated -- the leading underscore is what
 * tells them from the host's. The full set is `crates/kernel/errno`; these are
 * the ones an embedder's own bridge returns or the calls below answer.
 *
 * A syscall's return is read by range: a guest libc treats a value in
 * [-4095, -1] as `-errno` and anything else as success, so a number outside it
 * does not report a different error -- it reports success. */
#define _ESRCH -3
#define _E2BIG -7
#define _EAGAIN -11
#define _EBUSY -16
#define _EINVAL -22
#define _ENOTTY -25

/* ---- the terminal ------------------------------------------------------- */

struct winsize_ {
    word_t row;
    word_t col;
    word_t xpixel;
    word_t ypixel;
};

/* `__kernel_termios`. NCCS is 19 on Linux's asm-generic termbits, which every
 * architecture but the MIPS/Alpha family uses, aarch64 included. */
struct termios_ {
    dword_t iflags;
    dword_t oflags;
    dword_t cflags;
    dword_t lflags;
    byte_t line;
    byte_t cc[19];
};

/* `lflags` */
#define ISIG_ (1 << 0)
#define ICANON_ (1 << 1)
#define ECHO_ (1 << 3)
/* `oflags` */
#define OPOST_ (1 << 0)

struct tty_driver_ops {
    int (*init)(struct tty *tty);
    int (*open)(struct tty *tty);
    int (*close)(struct tty *tty);
    int (*write)(struct tty *tty, const void *buf, size_t len, bool blocking);
    int (*ioctl)(struct tty *tty, int cmd, void *arg);
    void (*cleanup)(struct tty *tty);
};

struct tty_driver {
    const struct tty_driver_ops *ops;
    int major;
    unsigned limit;
};

/* Where the host sockets behind guest unix sockets are made, copied; NULL is
 * `/tmp/iulsock`. Replaces the writable global `sock_tmp_prefix`, removed
 * 2026-10-17. */
void iul_set_socket_prefix(const char *prefix);

/* Make the host terminal the guest's console -- raw mode, the reader thread and
 * the writes, in `crates/fs/ttyreal` -- before the first open of it. Replaces
 * assigning `real_tty_driver` into the `tty_drivers` table, removed
 * 2026-10-17. */
void iul_enable_console(void);
void real_tty_reset_term(void);

/* A pty pair with no controlling process, which is what a session that is not
 * the console runs on. Answers an ERR_PTR; never NULL. */
struct tty *pty_open_fake(struct tty_driver *driver);
int tty_number(const struct tty *tty);
int tty_open(const struct tty *tty, struct poll_watchers *watchers, int flags);
void tty_get_termios(const struct tty *tty, struct termios_ *out);
void tty_set_termios(const struct tty *tty, const struct termios_ *termios);
void tty_set_winsize(const struct tty *tty, struct winsize_ winsize);
/* Keystrokes: bytes the session reads on fd 0. The count taken, or `_EAGAIN`
 * when the queue is full and `blocking` is false. */
ssize_t tty_input(const struct tty *tty, const void *buf, size_t len, bool blocking);
/* Hang up the terminal `pty_open_fake` made, waking any blocked `tty_input`
 * before `tty_release` gives the reference back. */
void tty_hangup(const struct tty *tty);
/* Give back the reference `pty_open_fake` handed over. */
void tty_release(struct tty *tty);

/* ---- the filesystems ---------------------------------------------------- */

/* The four mount types, as `mount_root` and `do_mount` take them. `fakefs`
 * keeps metadata in a SQLite `meta.db` beside a `data/` of host files, which is
 * what gives a guest ownership and device nodes an app has no real ones for;
 * `realfs` is a host passthrough. */
extern const struct fs_ops realfs;
extern const struct fs_ops fakefs;
extern const struct fs_ops procfs;
extern const struct fs_ops devptsfs;

int mount_root(const struct fs_ops *fs, const char *source);
int do_mount(const struct fs_ops *fs, const char *source, const char *point,
        const char *info, int flags);

/* Make an empty fakefs at `dir`: the directory, its `data/` and a `meta.db`. */
int fake_db_create(const char *dir);

/* Graft a host directory into the guest tree. Registrable after boot. */
int fakefs_bind_mount(const char *linux_path, const char *host_path, bool read_only);
int fakefs_bind_unmount(const char *linux_path);
/* Where the fakefs's `data/` is on the host, so a bind mount pointing back
 * inside it is recognised. */
void fakefs_set_rootfs_data_path(const char *abs_host_path);

/* The change-event ring an app consumes to know a guest wrote something. */
struct fakefs_change_event {
    char linux_path[1024];
    int op;
    /* Monotonic nanoseconds, from the clock that does not run while the device
     * is asleep. This held `mach_absolute_time()` -- raw ticks of a 24 MHz
     * counter on Apple Silicon -- in a field named `_ns`, so an embedder
     * computing an age from it was 41.67x low. */
    int64_t timestamp_ns;
    uint64_t fs_context;
};
void fakefs_record_change(const char *linux_path, int op);

/* Block syntax `^` is Clang-only, so a GCC build gets a function pointer and an
 * embedder there registers a plain function. `handler` runs on the consumer's
 * own serial queue; `batch` and `count` are stack-owned for the duration of the
 * call, so copy what you need to keep. */
#ifdef __BLOCKS__
typedef void (^fakefs_change_handler_t)(const struct fakefs_change_event *batch, int count);
#else
typedef void (*fakefs_change_handler_t)(const struct fakefs_change_event *batch, int count);
#endif
void fakefs_install_change_consumer(fakefs_change_handler_t handler);
/* How many events the ring dropped since boot. The producer is non-blocking and
 * bounded -- about 200 ns -- so an overflow drops the oldest rather than
 * waiting, and this is how a consumer knows it happened. */
uint64_t fakefs_change_dropped_count(void);

/* An override for guest->host path translation, consulted **before** the
 * bind-mount table for every path operation: open, stat, readdir, unlink,
 * rename, rmdir and the rest.
 *
 * `fs_context` is the calling thread group's opaque value, so the host can
 * route the same guest path to different host directories per context; this
 * engine assigns it no meaning. `guest_path` has a leading slash and is already
 * normalised. Write up to `out_size - 1` bytes and a NUL into `out_host_path`
 * and return true to override, or return false to fall through.
 *
 * **Reentrant and non-blocking**: it is called on the hot filesystem path. */
typedef bool (*fakefs_path_translate_hook_t)(const char *guest_path, uint64_t fs_context,
        char *out_host_path, size_t out_size);
void fakefs_set_path_translate_hook(fakefs_path_translate_hook_t hook);

/* The reverse, called from `realfs_getpath` to map a host path -- what
 * `F_GETPATH` answers for a bind-mounted descriptor -- back to a guest path.
 * Consulted *after* the bind-mount table.
 *
 * No `fs_context`: `F_GETPATH` is per-descriptor and the host path itself says
 * which bind-mount target was resolved. Same hot-path contract as above. */
typedef bool (*fakefs_path_reverse_hook_t)(const char *host_path,
        char *out_guest_path, size_t out_size);
void fakefs_set_path_reverse_hook(fakefs_path_reverse_hook_t hook);

/* ---- paths, descriptors and devices ------------------------------------- */

/* Answers an ERR_PTR; never NULL. */
struct fd *generic_open(const char *path, int flags, int mode);
int generic_mkdirat(struct fd *at, const char *path, mode_t_ mode);
int generic_mknodat(struct fd *at, const char *path, mode_t_ mode, dev_t_ dev);
int generic_symlinkat(const char *target, struct fd *at, const char *link);
int fd_close(struct fd *fd);
mode_t_ fd_type(struct fd *fd);
void fs_chdir(struct fs_info *fs, struct fd *pwd);
/* Replace the root a task resolves `/` against, as `chroot` would. Takes the
 * reference to `root`, as `fs_chdir` takes `pwd`'s. */
void fs_chroot(struct fs_info *fs, struct fd *root);
/* Unmount whatever is at `point`: 0, `_EINVAL` for a point that carries
 * nothing, `_EBUSY` while anything still holds the mount. */
int do_umount(const char *point);

static inline dev_t_ dev_make(int major, int minor) {
    return ((minor & 0xfff00) << 12) | (major << 8) | (minor & 0xff);
}
int dev_open(int major, int minor, int type, struct fd *fd);

/* realfs's own, for an embedder that wants the host file behind a guest path
 * without going through the VFS. Answers an ERR_PTR; never NULL. */
struct fd *realfs_open(struct mount *mount, const char *path, int flags, int mode);
ssize_t realfs_write(struct fd *fd, const void *buf, size_t bufsize);

/* Put `count` descriptors into `table` starting at `first`, displacing what was
 * there. This is how a session's stdio is attached to a pty. */
int fdtable_replace_range(struct fdtable *table, void *source, int first,
        size_t count, int cloexec, size_t limit, void **displaced);

/* ---- processes ---------------------------------------------------------- */

/* The first guest process. `umask(0)` is applied to the *host* process here,
 * because the engine applies the guest's umask itself and the host's must not
 * also participate; files the host application creates after this are
 * unmasked. Nothing else in the engine changes process-wide state. */
int become_first_process(void);
/* A second init, for a session that is not the first. */
int become_new_init_child(void);
/* Open `file` on the calling task's descriptors 0, 1 and 2. */
int create_stdio(const char *file, int major, int minor);

struct task *task_self(void);
#define current (task_self())
struct fs_info *current_fs(void);
struct fdtable *current_files(void);
int current_pid(void);

/* Run the task on a thread of its own. It does not return to you. */
void task_start(struct task *task);

/* Called as a guest process ends, with its pid and the raw wait(2) status it
 * ended with. An embedder installs one to learn that the command it started
 * has finished. Install it before booting; a second call is ignored. */
void set_exit_hook(void (*hook)(int pid, int code));

int do_execve(const char *file, size_t argc, const char *argv, const char *envp);

/* Closing a session, by the pid of the process it started. Each answers 0, or
 * `_ESRCH` for a pid that names nothing.
 *
 * `iul_kill_process_group` sends `sig` to that process's group -- a shell and
 * its foreground job -- as the kernel would. `iul_kill_session` sends it to
 * every process in the session `sid`, every job of a shell included, and
 * works after the leader has exited. `iul_leave_terminal` makes the
 * session give up its controlling terminal now rather than when it is reaped:
 * an embedder's sessions are children of an init that never waits, so without
 * it the pty stays allocated and `/dev/pts` can never be unmounted. */
int iul_kill_process_group(int pid, int sig);
int iul_kill_session(int sid, int sig);
int iul_leave_terminal(int pid);

/* The hostname `uname` reports, copied; NULL reports the host's again. And the
 * text of `uname -v` before the build stamp, copied; NULL is the default. These
 * replace the writable globals `uname_hostname_override` and `uname_version`,
 * removed 2026-10-17. */
void iul_set_hostname(const char *hostname);
void iul_set_uname_version(const char *version);

/* Refuse a `fork` the embedder's own runtime could not survive. Returning
 * non-zero makes the guest's fork fail with EAGAIN. */
typedef int (*iul_fork_guard_t)(void);
void iul_set_fork_guard(iul_fork_guard_t guard);
/* Drive the embedder's periodic work off the guest's timer tick. */
typedef void (*iul_timer_tick_hook_t)(void);
void iul_set_timer_tick_hook(iul_timer_tick_hook_t hook);

/* ---- native offload ----------------------------------------------------- */

/* Replace emulated code with native code, three ways. See CLAUDE.md's "Native
 * offload": a registered `execve` name, a replaced guest symbol, or a
 * whole-function specialised gadget block.
 *
 * The first is the one an embedder normally wants. When a guest `execve()`'s
 * basename matches a registered name, execution is intercepted and routed to
 * an in-process handler function, which runs on the guest thread and receives
 * argc/argv with guest absolute paths already translated to host paths, plus
 * pipe-backed stdio descriptors. Output written to `stdout_fd`/`stderr_fd` is
 * forwarded through the guest TTY driver, so it appears in the terminal.
 *
 *     static int my_tool_main(int argc, char **argv,
 *                             int stdin_fd, int stdout_fd, int stderr_fd) {
 *         dprintf(stdout_fd, "hello from a native handler\n");
 *         return 0;                       // the guest's exit code
 *     }
 *
 *     // Once, before the guest runs.
 *     native_offload_add_handler("mytool", my_tool_main);
 *
 * Then a guest `execve("/usr/bin/mytool", ...)` calls `my_tool_main` instead of
 * emulating the ELF. Notes for handler authors: the working directory is the
 * host equivalent of the guest's; `stdin_fd` may be -1 when the guest's stdin
 * is not readable; and a handler takes priority over host-binary lookup.
 *
 * The macOS CLI also offloads to a host binary through `posix_spawn`:
 *
 *     iul -n ffmpeg                          # find /opt/homebrew/bin/ffmpeg
 *     iul -n ffprobe=/usr/local/bin/ffprobe  # or say which one
 */
struct cpu_state;
struct tlb;
typedef void (*prebuilt_fn)(struct cpu_state *cpu, struct tlb *tlb);
typedef void (*native_abort_func)(const char *reason);
typedef int (*native_handler_func)(int argc, char **argv,
        int stdin_fd, int stdout_fd, int stderr_fd);

/* Register an in-process handler for a guest binary name. Answers 0, or -1 if
 * the registry is full. */
int native_offload_add_handler(const char *guest_name, native_handler_func handler);
/* A host binary through posix_spawn (macOS only). `spec` is "name" or
 * "name=/host/path". Answers 0 on success. */
int native_offload_add(const char *spec);

/* ---- symbol-level offload (mechanism 2) --------------------------------- */

/* The API above offloads at *binary* granularity: a whole guest command,
 * matched at execve, runs as a host process or an in-process main(). This one
 * offloads at *function* granularity: one guest function, matched by its entry
 * pc, runs as a native handler and the guest resumes after it.
 *
 * It is lossless. Nothing is registered unless you register it, a registration
 * that has not been bound to an address matches nothing, and a handler may look
 * at its arguments and answer NSYM_DECLINED — after which the guest runs its
 * own code, unchanged.
 *
 *     static enum nsym_result my_memcpy(struct nsym_ctx *c, void *user) {
 *         addr_t dst = nsym_arg(c, 0), src = nsym_arg(c, 1);
 *         uint64_t n = nsym_arg(c, 2);
 *         // ... a value copy through nsym_read/nsym_write ...
 *         nsym_set_ret(c, dst);
 *         return NSYM_HANDLED;
 *     }
 *     native_offload_add_symbol("libc.so", "memcpy", my_memcpy, NULL);
 *
 * The context wraps the guest CPU and its TLB. Arguments follow AAPCS64 —
 * integers in x0..x7, the return value in x0 — and every memory access is a
 * **value copy**, which is what makes a handler fork- and copy-on-write-safe:
 * it never holds a host pointer into guest memory, so a copy-on-write between
 * two of its reads cannot leave it pointing at the wrong page. A read or write
 * that faults answers false. */
struct nsym_ctx;
enum nsym_result { NSYM_HANDLED = 0, NSYM_DECLINED = 1 };
typedef enum nsym_result (*nsym_handler)(struct nsym_ctx *ctx, void *user);

/* Register by name, to be bound when the loader maps a matching binary.
 * Answers an id >= 0, or -1. */
int native_offload_add_symbol(const char *binary, const char *symbol,
        nsym_handler handler, void *user);
/* The same with the entry address already known, which it is when the guest is
 * loaded without ASLR. Prefer add_symbol followed by bind_symbol wherever
 * symbol resolution is available. */
int native_offload_add_symbol_hinted(const char *binary, const char *symbol,
        addr_t guest_addr, nsym_handler handler, void *user);
/* Bind a registration to a runtime entry address. Idempotent. */
int native_offload_bind_symbol(const char *binary, const char *symbol, addr_t guest_addr);

uint64_t nsym_arg(struct nsym_ctx *ctx, int n);
void nsym_set_ret(struct nsym_ctx *ctx, uint64_t v);
bool nsym_read(struct nsym_ctx *ctx, addr_t gaddr, void *buf, size_t len);
bool nsym_write(struct nsym_ctx *ctx, addr_t gaddr, const void *buf, size_t len);

/* ---- prebuilt-gadget offload (mechanism 3) ------------------------------ */

int native_offload_add_prebuilt(const char *binary, const char *symbol,
        addr_t guest_addr, prebuilt_fn spec_fn);

/* How a signal reaches a handler that will not return.
 *
 * A handler runs synchronously on the guest thread and the exec path only calls
 * `do_exit()` once it returns, so one that never returns pins the guest task —
 * ffmpeg wedged inside a VideoToolbox transcode is the reported case. A signal
 * cannot be delivered *to* it from outside: `do_exit` operates on the calling
 * thread's own `current` and ends in `pthread_exit`, so only that thread can
 * reap it. The only workable shape is to ask the handler to stop and return.
 *
 * The callback is invoked from the **signalling** thread while the handler is
 * still running, so it must be async-safe with respect to the handler body:
 * signal an event, do not take a lock the handler holds. Before it existed,
 * `kill` on a wedged handler queued a signal nobody would ever read. */
int native_offload_set_abort_handler(const char *guest_name, native_abort_func abort_fn);

/* ---- /proc/iul ---------------------------------------------------------- */

/* What the host application answers for `/proc/iul`: the version string and
 * the user defaults a guest reads and writes through `/proc/iul/defaults`.
 * Any member may be null. Every `char *` a hook returns, and the array
 * `all_defaults_keys` returns with each string in it, is `malloc`ed by the
 * embedder and freed by the kernel. `version` is copied. Installed (copied)
 * by `iul_set_proc_host`; null takes it away. Replaces the eight writable
 * globals of the same names, removed 2026-10-17. */
struct iul_proc_host {
    const char *version;
    char **(*all_defaults_keys)(void);
    char *(*friendly_name)(const char *key);
    char *(*underlying_name)(const char *friendly);
    bool (*get_user_default)(const char *key, char **buf, size_t *len);
    bool (*set_user_default)(const char *key, const char *buf, size_t len);
    bool (*remove_user_default)(const char *key);
    char *(*documents_directory)(void);
};
void iul_set_proc_host(const struct iul_proc_host *host);

/* ---- logging ------------------------------------------------------------ */

/* Where a `TRACE()` or a `printk` goes is decided at build time by a
 * `LOG_HANDLER_*` define; these are the entry points an embedder's own wrapper
 * calls. `die` formats, hands the line to the die handler, and aborts. */
void iul_printk(const char *msg, ...);
void iul_vprintk(const char *msg, va_list args);
_Noreturn void die(const char *msg, ...);
/* Where `die` hands its line before aborting. An embedder that must not abort
 * -- an app with a UI to show -- installs one before booting; it must not
 * return. Once: a second call returns false and changes nothing. Replaces the
 * writable global `die_handler`, removed 2026-10-17. */
bool iul_set_die_handler(void (*handler)(const char *msg));

#ifdef __cplusplus
}
#endif

#endif /* IUL_H */
