//! Starting a guest: the first process, and the descriptors it begins with.
//!
//! This is the interface an **embedder** drives, and the only in-repo example of
//! driving it is `main.c`: `mount_root()` → `become_first_process()` →
//! `do_execve()` → `task_start()`. Every name here keeps its C symbol, because
//! ServerBox's `sbm_iul.c` calls them.
//!
//! # Two process-wide side effects an embedder inherits
//!
//! [`become_first_process`] calls `umask(0)` and raises `RLIMIT_NOFILE`, and a
//! caller cannot discover either from a signature. Both are said in CLAUDE.md
//! for that reason.
//!
//! The umask is the standard arrangement for anything that implements its own
//! permission model: this kernel applies the *guest's* umask to every creating
//! call and then hands the mode to the host, which would apply its own on top —
//! so a guest that sets `umask(0)` and asks for 0666 got 0644 under the host's
//! usual 022. fakefs hides it, because it reports the mode it stored in
//! `meta.db`; realfs reports the host's, which is where it shows. Files the host
//! application creates after this call are no longer masked either.
//!
//! The descriptor limit is the same argument. Every guest descriptor is backed
//! by at least one host descriptor — a pipe or a socketpair by two — and macOS
//! and iOS default the soft `RLIMIT_NOFILE` to 256, where this kernel tells a
//! guest it has 1024 soft and 4096 hard. Measured: a guest opening descriptors
//! under a host limit of 256 got 246 and then `EMFILE`, at a number it had no
//! way to account for.
//!
//! Neither is a constructor: the engine takes them when the engine starts, so an
//! embedder that never boots a guest is unaffected.
//!
//! # The failure path undoes what it built
//!
//! [`construct_task`] allocates six things in order and every one of them can
//! fail. Each failure used to return straight out, leaving the task in the pid
//! table and in its parent's child list and leaking whatever had been built —
//! which is what the `Partial` guard below exists to make unwritable: it holds
//! what has been built so far and releases it in reverse unless the construction
//! says it succeeded.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{CStr, CString, c_char, c_int};

// The shared Rust types and constants are re-exported by kernel-taskview.
pub use taskview::ffi;

#[path = "source.rs"]
mod source;
use source::resolved_source;

mod lifecycle;
use lifecycle::construct_task;


// Three private copies of the pointer-shaped errno convention lived here until
// 2026-09-14; they became `crates/kernel/abi`'s, and then this crate stopped
// needing it at all. `construct_task` and `task_create_` answer a `Result`, so
// the only `ERR_PTR` left in the tree is at the two functions `iul.h`
// declares.

// ------------------------------------------------------------- mounting root

/// The root filesystem, at a host path.
///
/// The path is resolved first: a relative one, or one with a symlink in it,
/// would otherwise be stored as given and every later comparison against a
/// mount point would be against a different string. See [`resolved_source`]
/// for what "resolved" keeps.
///
/// # Safety
/// `iul.h`'s contract: `fs` is one of the filesystem handles it declares and
/// `source` a NUL-terminated path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mount_root(fs: *const ffi::FsHandle, source: *const c_char) -> c_int {
    // SAFETY: `iul.h`'s contract.
    let Some(fs) = (unsafe { ffi::FsHandle::deref(fs) }) else {
        return guest_errno::c_int_::EINVAL;
    };
    // SAFETY: the caller passes a NUL-terminated path.
    mount_root_at(fs, unsafe { std::ffi::CStr::from_ptr(source) }).err().unwrap_or(0)
}

/// [`mount_root`] for a Rust caller; `Err` is a negative errno.
pub fn mount_root_at(fs: &'static dyn ffi::FsOps, source: &std::ffi::CStr) -> Result<(), c_int> {
    let real = resolved_source(source.to_bytes())?;
    fs_mount::mount(fs, &real, c"", c"", 0)
}

/// Raise the host's descriptor limit as far as it will go. See the module
/// comment.
fn raise_nofile() {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    let now = getrlimit(Resource::Nofile);
    let cur = now.current.unwrap_or(u64::MAX);
    // Twice the guest's hard limit, since a pipe costs two. `None` is
    // `RLIM_INFINITY`, which caps nothing.
    let mut want: u64 = 2 * 4096 + 256;
    if let Some(max) = now.maximum {
        want = want.min(max);
    }
    while want > cur {
        let attempt = Rlimit {
            current: Some(want),
            maximum: now.maximum,
        };
        if setrlimit(Resource::Nofile, attempt).is_ok() {
            break;
        }
        // Halve rather than give up: the cap is a number this process cannot
        // read portably -- on Darwin the hard limit is often RLIM_INFINITY
        // while the kernel still refuses anything above kern.maxfilesperproc --
        // so the ladder tries what it can and keeps whatever it got.
        want /= 2;
    }
}

/// The host signal every blocking call here is prepared to be woken by.
///
/// Installed before anything can reach it: this thread runs guest code too, and
/// What SIGUSR1 does to a guest thread: **nothing, on purpose.**
///
/// The signal exists to make a blocking host syscall return `EINTR`, which is
/// how `do_exit_group` and `send_signal` get a thread out of a `read` it may
/// sit in for ever. POSIX gives that for any signal with a handler installed
/// and no `SA_RESTART`; the handler's body is not part of it.
///
/// `util/sync.c` had this, with an `siglongjmp` behind a `should_unwind` flag —
/// and the only thing that ever set that flag was `sigunwind_start`, which had
/// **no caller** after `wait_for` became `crates/util/waitfor` on 2026-09-03.
/// The jump had been dead for three days; the machinery outlived its last user.
///
/// **It touches nothing**, which is the property that matters here. A handler
/// that reads a thread-local reaches `_tlv_get_addr`, which `malloc`s on first
/// touch, and `malloc` is not async-signal-safe — `util/sync.c` recorded the
/// crash from exactly that, and `sync_thread_init` existed to pre-touch the two
/// thread-locals this used to have. Neither is needed by an empty body.
///
/// **`extern "C"` because the host kernel calls it.** It was installed with
/// `sa_sigaction = sigusr1_handler as *const () as usize`, a cast that erases
/// the calling convention, so taking the attribute off compiled and was wrong
/// only when a signal arrived; the 2026-09-11 sweep found it by reading every
/// `as *const ()`. Since 2026-10-18 `util_hostsig::Handler` takes the typed
/// pointer, and a handler without it does not compile.
extern "C" fn sigusr1_handler(_sig: c_int) {}

/// another thread's `send_signal` can target it.
fn establish_signal_handlers() {
    // SAFETY: the handler does nothing.
    unsafe {
        util_hostsig::install(
            &[libc::SIGUSR1],
            util_hostsig::Handler::Plain(sigusr1_handler),
            &[libc::SIGUSR1],
            false,
        )
    };
    util_hostsig::ignore(libc::SIGPIPE);
}

/// The four hooks whose two ends cannot be a cargo edge in either direction.
///
/// `crates/kernel/exitcalls` and `crates/kernel/syscalldispatch` both depend on
/// `crates/kernel/taskcalls` — the second through the syscall table, which
/// names every family — and `exitcalls` depends on `crates/kernel/signaldeliver`
/// for the signals an exit sends. `crates/asbestos/dispatch` is two layers
/// below `kernel` outright.
///
/// Here rather than at a first object, for the reason the filesystem registry
/// above is: there is no such object, and this is the point at which the kernel
/// is assembled and before which no guest thread exists.
///
/// All four `expect` rather than defaulting — see `taskcalls::run_hooks` for
/// why this is the one place in the tree where "not installed" is not a
/// meaningful answer.
///
/// A named function so a test can assert the wiring without booting a kernel.
pub fn install_run_hooks() {
    taskcalls::set_run_hooks(taskcalls::RunHooks {
        leave_group: |status| unsafe { exitcalls::do_exit_group(status) },
        handle_interrupt: |interrupt| unsafe { syscalldispatch::handle_interrupt(interrupt) },
    });
    signaldeliver::set_exit_group_hook(|status| unsafe { exitcalls::do_exit_group(status) });
    // `PTRACE_KILL` and `PTRACE_ATTACH` send a signal, from below the signal
    // layer.
    kernel_ptrace::set_signal_hook(signaldeliver::ptrace_signal);
    kernel_ptrace::set_wake_hook(signaldeliver::ptrace_wake);
    // The fourth: an interrupt that fires *inside* a prebuilt gadget's callee,
    // which the outer run loop never sees.
    asbestos_dispatch::set_interrupt_hook(|interrupt| unsafe {
        syscalldispatch::handle_interrupt(interrupt)
    });
    // And a fifth that is only a diagnostic: `IUL_WX_STATS=1`'s `clears` count
    // lives in `crates/kernel/pagetable`, which `crates/asbestos/diag` cannot
    // depend on because that dependency runs the other way. The address is
    // handed over once rather than the count pushed per clear.
    //
    // Here rather than at the first clear, which was the first attempt and is
    // untestable: a run with no self-modifying code reports zero whether the
    // install happened or not, so deleting it would be silent.
    asbestos_diag::set_wx_clears_counter(&pagetable::fault::ST_WX_CLEARS);
    // And a sixth: the calling thread's guest pid, which `crates/util/locks`
    // puts in every `lock_t` under `-DLOCK_DEBUG=1` and two `asbestos` crates
    // put in a trace line. All three are below `kernel` and the answer is a
    // `thread_local!` in `crates/kernel/abi`.
    currentpid::set_hook(|| taskview::current_pid());
}

/// Build the first task and make it `current`.
///
/// `_ENOMEM` or `_EAGAIN` if the first task cannot be built.
///
/// **`must_check` in the C**, because ignoring it leaves `current` NULL and the
/// next line dereferences it — which is what `xX_main_Xx.h` did.
#[unsafe(no_mangle)]
pub extern "C" fn become_first_process() -> c_int {
    // The `IUL_*` settings are filled by a constructor, and a constructor only
    // runs if the linker pulled the object holding it out of the archive. When
    // it does not, every diagnostic is off and `wait_poll_ms` is 0 -- "never
    // rescan" -- which surfaces as a hang in a poll rather than as anything to
    // do with settings. Asked here, before the first guest thread exists.
    util_iulenv::assert_initialised();
    // The four filesystems `mount -t` accepts, and the hook `/proc/filesystems`
    // reads them through. Here rather than on first use because nothing mounts
    // procfs through `crates/fs/mountcalls` -- this crate and every embedder
    // call `fs_mount::do_mount` with the table directly -- so a guest that
    // never calls `mount(2)` would otherwise see an empty file. Idempotent.
    mountcalls::register_default_filesystems();
    install_run_hooks();
    // `user_init` was here, binding the page lookup and the address-space
    // bound crates/kernel/usercopy copied through. Both are ordinary Rust in
    // crates/kernel/mmapcalls's `usermem` now -- an `impl Pages` and a
    // generated constant -- so there is nothing to bind and no window in which
    // an unbound copy could be reached.
    establish_signal_handlers();
    // `errno_map` raises SIGPIPE for a write to a closed pipe, and
    // crates/kernel/errno is a leaf that cannot reach signal delivery. Before
    // any guest can run, and once. See the hook's comment for what a missing
    // install would look like.
    kernel_errno::set_sigpipe_hook(|| {
        // 13 on every architecture Linux has, which is why writing it down is
        // safe here where it would not be for a signal that moves. To the
        // calling task, holding no lock; nothing on a thread with no task.
        const SIGPIPE_: c_int = 13;
        signaldeliver::send_signal(signaldeliver::Target::Me, SIGPIPE_, Default::default());
    });
    // The two tables crates/fs/tty asks for: what a terminal's rules are about
    // (processes) and the console driver (a host device). Before any terminal
    // can exist, and once.
    fs_ttydev::tty_init_ops();
    // See the module comment for both of these.
    rustix::process::umask(rustix::fs::Mode::empty());
    raise_nofile();

    let task = match construct_task(std::ptr::null_mut()) {
        Ok(task) => task,
        Err(e) => return e.as_c_int(),
    };
    // The first process runs on the calling thread, so this is the only value
    // it can have. Both callers -- crates/tools/iul and the embedder example
    // in tests/integration/sbm_api_test.c -- did it themselves on the line
    // after this one, and the second was the last place C wrote a `struct
    // task` field.
    task.thread.set(unsafe { libc::pthread_self() });
    // SAFETY: a live task, handed to this thread to run.
    unsafe { taskview::bind_current(task.into_raw()) };
    // pid 1 is its namespace's init, as a container's first process is.
    taskview::with_current_group(|g| g.set_unkillable(true));
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn become_new_init_child() -> c_int {
    // Held for the lookup only, which is narrower than `PidsGuard`'s contract
    // ("across the lookup *and* the use") and is safe for exactly one pid:
    // init's exit ends the guest, and `halt_system` ends the host process with
    // it, so there is no interleaving in which this pointer is freed and this
    // thread runs on. `construct_task` takes `pids_lock` itself -- through
    // `task_create_` and `task_setsid` -- so the guard cannot be held across
    // it. It said "locking? who needs locking?!" until 2026-09-16.
    let init = {
        let pids = kernel_pids::PidsGuard::take();
        taskcalls::pid_get_task(pids.held(), 1)
    };
    assert!(!init.is_null(), "there is no init to be a child of");

    let task = match construct_task(init) {
        Ok(task) => task,
        Err(e) => return e.as_c_int(),
    };
    // What it must not inherit from init -- its signal state, a clear-tid
    // word, a vfork handoff -- `construct_task` and `task_create_` settle
    // before the task is published. They were written here, after it, until
    // 2026-09-30.
    // TODO: think about whether it would be a good idea to inherit fs_info.
    // SAFETY: a live task, handed to this thread until `task_start`.
    unsafe { taskview::bind_current(task.into_raw()) };
    0
}

use fs_fdobj::FDTABLE_OPS;

#[path = "session.rs"]
mod session;
pub use session::{iul_kill_process_group, iul_leave_terminal};

#[path = "stdio.rs"]
mod stdio;
pub use stdio::{create_piped_stdio, create_stdio, open_stdio, set_console_device};

/// Unused; keeps the imports honest for a build with no callers of them.
const _: Option<&CStr> = None;
const _: Option<CString> = None;

// `mod tests` held `err_ptr_and_is_err_agree_with_misc_h` until 2026-09-14. It
// named a header that has not existed since 2026-09-09 and asserted the
// boundary against this file's own definitions, which is a test agreeing with
// itself. The convention is `crates/kernel/abi`'s and the boundary is asserted
// there, against what `iul.h` states. The empty module outlived it by a day and
// was an `unused_imports` warning in the test build.

#[cfg(test)]
mod source_tests {
    use super::resolved_source;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("boot-source-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_symlinked_data_directory_keeps_its_name() {
        let dir = scratch("symlink");
        let target = dir.join("tree");
        std::fs::create_dir(&target).unwrap();
        let fake = dir.join("fake");
        std::fs::create_dir(&fake).unwrap();
        std::os::unix::fs::symlink(&target, fake.join("data")).unwrap();
        let got = resolved_source(fake.join("data").as_os_str().as_encoded_bytes()).unwrap();
        let real_fake = std::fs::canonicalize(&fake).unwrap();
        assert_eq!(
            got.to_bytes(),
            real_fake.join("data").as_os_str().as_encoded_bytes()
        );
        // ...and a trailing slash names the same mount.
        let with_slash = format!("{}/", fake.join("data").display());
        assert_eq!(resolved_source(with_slash.as_bytes()).unwrap(), got);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_relative_path_becomes_absolute() {
        let dir = scratch("relative");
        std::fs::create_dir(dir.join("data")).unwrap();
        let cwd = std::env::current_dir().unwrap();
        // The parent is resolved from the working directory, without changing
        // it: the name is appended to realpath(".").
        let got = resolved_source(b"data");
        assert!(got.is_ok());
        assert!(got.unwrap().to_bytes().starts_with(b"/"));
        assert_eq!(std::env::current_dir().unwrap(), cwd);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_parent_is_the_hosts_errno() {
        let r = resolved_source(b"/nonexistent-boot-source-dir/data");
        assert!(r.is_err());
    }
}
