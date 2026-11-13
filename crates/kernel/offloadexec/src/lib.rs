//! Running a registered guest binary as native host code instead of emulating
//! it.
//!
//! Two shapes, and the difference runs through the whole file:
//!
//! - **`posix_spawn`** (macOS only): a real host process, with a real host pid.
//!   Guest paths are redirected transparently by `libfakefs_redirect.dylib`,
//!   injected through `DYLD_INSERT_LIBRARIES`, so nothing rewrites `argv`.
//! - **An in-process handler** (macOS and iOS): a function this binary was
//!   linked with, called on the guest thread. There is no host pid, so paths
//!   *are* rewritten in `argv`, and a signal that should stop it has to reach
//!   an abort callback rather than a process.
//!
//! Both end in `do_exit`: an offloaded `execve` replaces the program, so the
//! guest task's whole remaining life is the native run.
//!
//! # Which host path a guest path is
//!
//! [`host_path_for_guest`] is the one answer, and bind mounts win. This kernel
//! bind-mounts guest directories onto real host locations outside the fakefs
//! `data/` tree, and a native handler that ignored them would read and write
//! the wrong files while the guest saw a filesystem that had diverged from
//! itself.
//!
//! The C did this with `char[PATH_MAX]` buffers and a `snprintf` whose
//! truncation it checked in three of the five places. A truncated path is not a
//! shorter answer, it is a **different** one that usually exists — the prefix
//! of a path names a directory — so `scan_dir_for_new_files` would have
//! registered a guest path as pointing at a host file it does not name. A
//! `PathBuf` cannot truncate.
//!
//! # The cwd is process-wide, and this is a multithreaded process
//!
//! An in-process handler resolves its own relative paths, so it needs the
//! host's working directory changed under it — and there is nothing to pass it
//! instead, since it is an arbitrary function. Two offloads at once used to
//! interleave: the second read the *first's* changed cwd as its "original", and
//! restoring afterwards left the process in the fakefs data directory
//! permanently. [`CWD_LOCK`] serialises them.
//!
//! What remains, and is recorded rather than closed: another thread's
//! *relative* host path resolves against the handler's cwd while it runs. The
//! engine's own file operations do not — realfs opens through
//! `openat(mount->root_fd, …)` — so this is a hazard for work an embedder does
//! on its own threads.
//!
//! The spawn path needs none of it: `posix_spawn_file_actions_addchdir_np`
//! gives the child its own cwd and never touches the parent's.


use std::ffi::{CStr, CString, OsStr, c_char, c_int};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

use guest_errno::c_int_::ENOEXEC;

use logline::printk;
mod registration;
use registration::{contains, register_new_files};
mod paths;
use paths::{host_cwd, host_path_for_guest, root_source};
mod pipes;
use pipes::{Sink, make_pipe, start_pipe_forward};
mod signals;
use signals::arm_signal_forwarding;
#[cfg(target_os = "macos")]
mod spawn_support;
#[cfg(target_os = "macos")]
use spawn_support::build_native_env;
#[cfg(target_os = "macos")]
mod spawn;
#[cfg(target_os = "macos")]
use spawn::exec_posix_spawn;

// ---------------------------------------------------------------------------
// Registration — the two entry points an embedder calls
// ---------------------------------------------------------------------------

/// The redirect dylib, resolved once from this binary's own directory.
///
/// That is the one thing the registry cannot do for itself, which is why
/// registration goes through here rather than straight to
/// `crates/kernel/offloadreg`.
#[cfg(target_os = "macos")]
fn dylib_path() -> Option<&'static Path> {
    use std::sync::OnceLock;
    static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| {
        let exe = std::env::current_exe().ok()?;
        let dir = exe.canonicalize().ok()?.parent()?.to_path_buf();
        let lib = dir.join("libfakefs_redirect.dylib");
        if lib.exists() {
            Some(lib)
        } else {
            eprintln!(
                "native_offload: warning: {} not found, path redirection disabled",
                lib.display()
            );
            None
        }
    })
    .as_deref()
}

/// Tell `crates/kernel/signaldeliver` how to forward a signal to a host process
/// running an offloaded binary.
///
/// Called from both registration entry points, which are the only two ways a
/// task can come to be running one — so a signal cannot reach a proxy before
/// this has run, and there is no ordering to get wrong. Idempotent after the
/// first, which is an acquire load that fails.
///
/// It is a hook because the alternative is a cycle: this crate ends a finished
/// offload with `do_exit`, which depends on `signaldeliver` for the five signals
/// an exit sends.
///
/// # Safety
/// `iul.h`'s contract: `spec` is a NUL-terminated `name` or `name=path`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn native_offload_add(spec: *const c_char) -> c_int {
    // SAFETY: the caller's contract.
    add(unsafe { std::ffi::CStr::from_ptr(spec) })
}

/// [`native_offload_add`] for a Rust caller.
pub fn add(spec: &std::ffi::CStr) -> c_int {
    arm_signal_forwarding();
    #[cfg(target_os = "macos")]
    {
        // Resolved on the first registration, before anything can be spawned.
        let _ = dylib_path();
        offloadreg::offload_add(spec)
    }
    #[cfg(target_os = "ios")]
    {
        let _ = spec;
        eprintln!("native_offload: posix_spawn not available on this platform");
        -1
    }
}

/// # Safety
/// `guest_name` is a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn native_offload_add_handler(
    guest_name: *const c_char,
    handler: offloadreg::HandlerFn,
) -> c_int {
    arm_signal_forwarding();
    // SAFETY: the caller's contract.
    offloadreg::offload_add_handler(unsafe { std::ffi::CStr::from_ptr(guest_name) }, handler)
}

/// # Safety
/// As [`native_offload_add_handler`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn native_offload_set_abort_handler(
    guest_name: *const c_char,
    abort_fn: offloadreg::AbortFn,
) -> c_int {
    // SAFETY: the caller's contract.
    offloadreg::offload_set_abort_handler(unsafe { std::ffi::CStr::from_ptr(guest_name) }, abort_fn)
}

/// The host binary an `execve` of this path should run, `[builtin]` for an
/// in-process handler, or `None`.
pub fn native_offload_lookup(guest_path: &std::ffi::CStr) -> Option<&'static std::ffi::CStr> {
    offloadreg::offload_lookup(guest_path)
}

// ---------------------------------------------------------------------------
// What an offloaded execve does to the task
// ---------------------------------------------------------------------------

/// The parts of `execve` that still apply when the program runs natively.
///
/// The thread name was `strncpy(current->comm, base, sizeof(current->comm))` —
/// the whole array, so a sixteen-character basename left no terminator and
/// every `printk("%s")` of a thread name read past it. `do_execve` had the same
/// line and was fixed; this one was missed, which is the argument for the name
/// having a type instead of being a `char` array anyone may write.
fn apply_exec_semantics(guest_file: &[u8]) {
    let base = match guest_file.iter().rposition(|&b| b == b'/') {
        Some(i) => &guest_file[i + 1..],
        None => guest_file,
    };
    taskview::with_current_attr(|a| a.set_comm(base));
    taskcalls::update_thread_name();

    taskview::with_current_task(|t| t.did_exec.set(true));
    taskcalls::vfork_notify_current();
    taskview::with_current_fdtable(|table| table.exec_close());

    // The same rules as an ordinary execve; see crates/kernel/execcalls.
    // `current_sighand()` rather than the field, for the reason that
    // accessor gives, and the null test is `sighand_on_exec`'s own now --
    // it was here and not at the other call site, which is how a guard
    // ends up covering one of two callers.
    taskview::with_current_queue(|queue| queue.on_exec());
    taskview::with_current_group(|g| {
        if let Some(timers) = g.posix_timers.as_deref() {
            timers.clear();
        }
    });
}

/// The three standard descriptors, each retained.
struct Stdio {
    stdin: Option<fs_fdobj::Owned>,
    stdout: Option<fs_fdobj::Owned>,
    stderr: Option<fs_fdobj::Owned>,
}

impl Stdio {
    fn take() -> Stdio {
        let get = |n| {
            taskview::with_current_fdtable(|table| table.lookup_retain(n))
                .flatten()
                
        };
        Stdio {
            stdin: get(0),
            stdout: get(1),
            stderr: get(2),
        }
    }

    /// The host descriptor behind one of the three, or -1 for one with none
    /// -- a guest pipe or a pty -- which the callers read as "nothing to
    /// give the child". It was 0 for those until 2026-09-29, which is the
    /// emulator's own stdin.
    fn real_fd(fd: &Option<fs_fdobj::Owned>) -> c_int {
        fd.as_ref()
            .and_then(|fd| fd.host())
            .map_or(-1, |h| std::os::fd::AsRawFd::as_raw_fd(&h))
    }
}

/// The host working directory, held for the length of an in-process handler's
/// run. See the module comment.
static CWD_LOCK: Mutex<()> = Mutex::new(());

/// A temporary change of the host process's working directory, put back when
/// it goes out of scope.
struct Chdir {
    saved: Option<PathBuf>,
}

impl Chdir {
    fn to(dir: Option<&Path>) -> Chdir {
        let Some(dir) = dir else {
            return Chdir { saved: None };
        };
        let Ok(saved) = std::env::current_dir() else {
            return Chdir { saved: None };
        };
        if std::env::set_current_dir(dir).is_err() {
            return Chdir { saved: None };
        }
        Chdir { saved: Some(saved) }
    }
}

impl Drop for Chdir {
    fn drop(&mut self) {
        if let Some(saved) = self.saved.take() {
            let _ = std::env::set_current_dir(saved);
        }
    }
}

// ---------------------------------------------------------------------------
// The in-process handler
// ---------------------------------------------------------------------------

/// Call a handler on this thread, with its output forwarded and its paths
/// translated. Never returns: it ends in `do_exit`.
fn exec_handler(
    handler: offloadreg::HandlerFn,
    entry: &'static offloadreg::Entry,
    guest_file: &[u8],
    argv: &[Vec<u8>],
) -> ! {
    let root = root_source();
    // Unlike the spawn path, which redirects through DYLD interpose, an
    // in-process handler needs explicit translation: it calls the host's own
    // `open`. A URL is not a filesystem path and is passed through.
    let translated: Vec<CString> = argv
        .iter()
        .map(|a| {
            let want = root.is_some() && a.starts_with(b"/") && !contains(a, b"://");
            let bytes = if want {
                host_path_for_guest(a)
                    .map(|p| p.into_os_string().into_vec())
                    .unwrap_or_else(|| a.clone())
            } else {
                a.clone()
            };
            CString::new(bytes).unwrap_or_default()
        })
        .collect();
    let mut ptrs: Vec<*mut c_char> = translated
        .iter()
        .map(|s| s.as_ptr() as *mut c_char)
        .collect();
    ptrs.push(std::ptr::null_mut());

    printk(&format!(
        "native_offload: [builtin] {} (pid {})",
        String::from_utf8_lossy(guest_file),
        taskview::current_pid()
    ));

    let stdio = Stdio::take();
    let handler_stdin = Stdio::real_fd(&stdio.stdin);
    let out_pipe = stdio.stdout.as_ref().and_then(|_| make_pipe());
    let err_pipe = stdio.stderr.as_ref().and_then(|_| make_pipe());

    apply_exec_semantics(guest_file);

    // The forwarding threads write through the guest's fd_ops, so the output
    // reaches a tty driver rather than a host descriptor. Each thread holds a
    // reference of its own.
    let forward = |rd: Option<OwnedFd>, fd: &Option<fs_fdobj::Owned>| {
        rd.zip(fd.clone()).map(|(rd, fd)| start_pipe_forward(rd, Sink::Guest(fd)))
    };
    let (out_rd, out_wr) = out_pipe.unzip();
    let (err_rd, err_wr) = err_pipe.unzip();
    let out_thread = forward(out_rd, &stdio.stdout);
    let err_thread = forward(err_rd, &stdio.stderr);

    let ret = {
        let _cwd_guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _chdir = Chdir::to(host_cwd().as_deref());

        // Publish which offload this task is running, so a signal can find the
        // abort callback while the handler is in flight, and only then. The
        // entry is leaked by the registry, which outlives every task.
        let _offload = taskview::enter_native_offload(entry);
        handler(
            argv.len() as c_int,
            ptrs.as_mut_ptr(),
            handler_stdin,
            out_wr.as_ref().map_or(-1, |wr| wr.as_raw_fd()),
            err_wr.as_ref().map_or(-1, |wr| wr.as_raw_fd()),
        )
    };

    // The write ends, so the forwarding threads see EOF.
    drop((out_wr, err_wr));
    for t in [out_thread, err_thread].into_iter().flatten() {
        let _ = t.join();
    }
    drop(stdio);

    printk(&format!(
        "native_offload: [builtin] {} exited with code {ret}",
        String::from_utf8_lossy(guest_file)
    ));
    register_new_files(argv);
    exit_with(ret << 8)
}

/// `do_exit`, which never returns.
///
/// It used to end in an `unreachable!` because the declaration bindgen made
/// from `kernel/calls.h` could not carry C's `noreturn`, so the promise had to
/// be restated here. Calling the Rust function directly carries `-> !`, and the
/// compiler now reports the `unreachable!` as unreachable.
fn exit_with(code: c_int) -> ! {
    unsafe { exitcalls::do_exit(code) }
}

// ---------------------------------------------------------------------------
// The dispatcher
// ---------------------------------------------------------------------------

/// Run `guest_file` natively. Does not return on success — the task's life is
/// the native run, and it ends in `do_exit`. A negative errno means the caller
/// should fall back to emulating it.
///
/// Called on a guest thread, from `crates/kernel/execcalls`. `argv` and `envp`
/// are packed lists of `argc` and however many NUL-terminated strings.
///
/// Safe since 2026-10-17. It took the lists as pointers and viewed each as
/// `ARGV_MAX` bytes, while the caller's buffers are sized to what they hold --
/// an empty environment is one byte -- so the slice reached past the
/// allocation. The parse stopped at the terminator, so nothing out of range
/// was read, but a slice over memory that is not there is undefined behaviour
/// on its own. Found by reading.
pub fn native_offload_exec(
    native_path: &CStr,
    guest_file: &CStr,
    argc: usize,
    argv: &[u8],
    envp: &[u8],
) -> c_int {
    let file = guest_file.to_bytes().to_vec();
    let args = unpack(argv, Some(argc));
    let env = unpack(envp, None);

    // An in-process handler first: it works on iOS as well as macOS.
    if let Some(entry) = offloadreg::find(&file)
        && let Some(handler) = entry.handler()
    {
        exec_handler(handler, entry, &file, &args);
    }

    #[cfg(target_os = "macos")]
    {
        if native_path.to_bytes() == b"[builtin]" {
            return ENOEXEC;
        }
        exec_posix_spawn(native_path, &file, &args, &env)
    }
    #[cfg(target_os = "ios")]
    {
        let _ = (native_path, env);
        ENOEXEC
    }
}

/// A packed list — `count` NUL-terminated strings, or every string up to the
/// empty one — as owned bytes.
///
/// Bounded by the slice, which is the caller's buffer. The C walked these with
/// `p += strlen(p) + 1` on the strength of a terminator nobody had looked for,
/// then with `execargs_at` through the C ABI; here the list is decoded once and
/// every later pass is over a `Vec`.
fn unpack(all: &[u8], count: Option<usize>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    loop {
        if let Some(n) = count
            && out.len() == n
        {
            break;
        }
        let Some(end) = all[at..].iter().position(|&b| b == 0) else {
            break;
        };
        // The list ends with an empty string when there is no count.
        if end == 0 && count.is_none() {
            break;
        }
        out.push(all[at..at + end].to_vec());
        at += end + 1;
        if at >= all.len() {
            break;
        }
    }
    out
}

#[cfg(test)]
#[path = "offload_tests.rs"]
mod tests;
