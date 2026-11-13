//! `execve`: replacing the program a process is running.
//!
//! Every piece of this was already a Rust crate before the syscall was —
//! `elf`, `execargs`, `shebang`, `initstack`, `creds`, `procattr`, `sigdisp`,
//! `posixtimers`, `random` — so what moved is the code *joining* them, and it
//! calls them as Rust rather than out through C and back. That is the whole
//! argument for cutting the migration by syscall family: `kernel/exec.c` was
//! 1064 lines of which the interesting arithmetic had already left.
//!
//! # Two entry points, one of them an embedder's
//!
//! [`sys_execve`] is the guest's. [`do_execve`] is the **embedder's**: `main.c`
//! and ServerBox's own boot code call it to start init, so its C signature is
//! part of this repository's published interface and does not change.
//!
//! # What is not inherited
//!
//! An exec keeps the process and replaces the program, so everything that
//! belonged to the *program* goes: the address space, the signal handlers
//! (`crates/kernel/sigdisp`), the POSIX timers, the close-on-exec descriptors,
//! the parent-death signal for one that gains privilege, and `dumpable` for
//! one that does or whose program the caller cannot read. Each rule lives with
//! the state it is about; what is here is the order they happen in.
//!
//! So do the process's other threads: at the point of no return the exec'ing
//! thread ends them and, if it is not the leader, takes the leader's pid
//! (`crates/kernel/exitcalls`' `de_thread`), and a descriptor table shared
//! with another process is copied first.


use std::ffi::{CStr, CString, c_char, c_int};

use strace::strace;

// The shared Rust types and constants are re-exported by kernel-taskview.
use taskview::ffi;

pub mod load;

pub(crate) use kernel_initstack as initstack;
pub(crate) use kernel_shebang as shebang;

#[path = "args.rs"]
mod args;
#[path = "syscalls.rs"]
mod syscalls;
pub use args::Args;
pub(crate) use args::arg_limit;
#[cfg(test)]
use args::{INJECT_ENV, LD_PRELOAD, NODE_REQUIRES};
use args::{exec_trace, fits, inject, read_argv, read_array};
pub use syscalls::{sys_execve, sys_execveat};

use load::File;

use guest_errno::Errno;

/// `mem->lock`, held for writing, for a scope.
pub type MemWrite<'a> = pagetable::memlock::WriteGuard<'a>;

/// What `execveat`'s flags ask of the open, and of what follows it.
#[derive(Clone, Copy)]
#[derive(Default)]
struct How {
    /// `AT_SYMLINK_NOFOLLOW`: a program that is a symlink is `ELOOP`.
    nofollow: bool,
    /// `AT_EXECVE_CHECK`: ask whether it could be executed, and do not.
    check_only: bool,
    /// `AT_EMPTY_PATH`: the program is what this descriptor is open on, and
    /// nothing is opened by name.
    descriptor: Option<fs_fdobj::FdRef>,
}


/// `execve` proper, once the arguments are in hand. `Err` says why the new
/// program is not running; [`load::Failed::Killed`] means this thread has to
/// leave, which its caller does once what it holds is given back.
fn do_exec(
    at: ffi::At<'_>,
    path: &CStr,
    reported: &CStr,
    argv: &Args,
    envp: &Args,
    how: How,
) -> Result<(), load::Failed> {
    signpost::event(signpost::Category::Exec, c"execve_path", reported);
    let _interval = signpost::Interval::begin(signpost::Category::Exec, c"execve");
    do_exec_inner(at, path, reported, argv, envp, how)
}

/// `path` is what to open and `reported` is what the new program is told it
/// is: for an `execveat` with a directory descriptor they differ, and Linux
/// rewrites the second to `/dev/fd/<n>/<path>` -- which is what a `#!`
/// interpreter is handed and what `/proc/<pid>/comm` ends up saying.
fn do_exec_inner(
    at: ffi::At<'_>,
    path: &CStr,
    reported: &CStr,
    argv: &Args,
    envp: &Args,
    how: How,
) -> Result<(), load::Failed> {
    // A new program starts fresh: clear the V8 abort-in-progress flag, so the
    // new process's stderr is not permanently muted by a prior abort.
    taskview::with_current_group(|g| g.set_v8_aborting(false));

    // The *first* open is the only one the directory descriptor and
    // AT_SYMLINK_NOFOLLOW apply to: a `#!` interpreter is resolved against
    // the process, following links, which is what `open_exec` with the
    // working directory does. The type and mode refusals are `open_exec`'s.
    let opened = if let Some(fd) = how.descriptor {
        File::from_descriptor(fd)
    } else {
        File::open_exec(at, path, how.nofollow)
    };
    let (file, stat) = opened.map_err(load::Failed::Recoverable)?;

    // AT_EXECVE_CHECK: everything up to here, and nothing past it. Linux's
    // bprm_execve returns before exec_binprm, so the format is not looked at
    // -- a file that opens, is regular and is executable passes the check
    // whether or not anything could run it.
    if how.check_only {
        return Ok(());
    }

    let started = match load::format_exec(&file, reported, argv, envp, 0) {
        Ok(started) => started,
        Err(f @ (load::Failed::Recoverable(_) | load::Failed::Killed(_))) => return Err(f),
        Err(load::Failed::Fatal(e)) => {
            // The address space has already been replaced, so whatever this
            // returns, the process cannot go on: its registers point into an
            // image that is gone. Linux's load_elf_binary does
            // `force_sigsegv(SIGSEGV)` past its point of no return, and that
            // is what this is -- the disposition back to the default and the
            // signal unblocked, so a handler the old program installed cannot
            // be run from an address space that no longer holds it. The
            // errno is still returned, and is what the signal overtakes on
            // the way out of the syscall. This used to return the errno alone,
            // under a TODO saying so.
            // The calling task's, through the accessor: this is the task's
            // own thread holding no lock, which is the one shape the plain
            // field read is a data race in.
            taskview::with_current_queue(|queue| queue.force_default(ffi::SIGSEGV_ as c_int));
            let info = ffi::siginfo_ {
                sig: ffi::SIGSEGV_ as c_int,
                code: ffi::SI_KERNEL_ as _,
                ..Default::default()
            };
            signaldeliver::send_signal(signaldeliver::Target::Me, ffi::SIGSEGV_ as c_int, info);
            return Err(load::Failed::Fatal(e));
        }
    };
    drop(file);

    after_exec(reported, &stat, started);
    Ok(())
}

/// What an `execve` that did not start the new program tells its caller: the
/// errno, or -- for a thread another thread's exec or a group exit is ending
/// -- nothing, because the thread leaves here.
///
/// The thread's references go first: `do_exit` ends in `pthread_exit`, which
/// runs no destructor, so whatever the caller still owns is `held`, dropped
/// before. The executable's write denial is the reason that matters: a `File`
/// that is never dropped keeps its inode `ETXTBSY` for the life of the host.
fn answer<T>(result: Result<(), load::Failed>, held: T) -> c_int {
    match result {
        Ok(()) => 0,
        Err(load::Failed::Killed(status)) => {
            drop(held);
            // SAFETY: on a guest thread, from its own execve, borrowing no
            // descriptor table.
            unsafe { exitcalls::do_exit(status) }
        }
        Err(load::Failed::Recoverable(e) | load::Failed::Fatal(e)) => e,
    }
}

/// Everything a successful exec changes about the *process*, in order.
///
/// `started.interpreters_readable` is whether the caller could read every `#!`
/// and ELF interpreter the program went through; one it could not leaves the
/// image undumpable as an unreadable program does. Until 2026-11-12 only the
/// program was asked (`dumpable_probe`). `started.creds` is what the image
/// runs with, worked out before the old one was torn down.
fn after_exec(path: &CStr, stat: &ffi::statbuf, started: load::Started) {
    // The rules and the state are crates/kernel/creds. Folding the set-id move
    // and the saved-id assignment together, and folding both into one `if`, is
    // what produced all three of the defects in
    // docs/changelog/2026-08-22-execve-put-the-old-identity-in-the-saved-id.md.
    // The fs ids follow the effective ones here as they do everywhere else --
    // an execve does not preserve a setfsuid the old program made -- and there
    // is no longer a way to write the transition that forgets them.
    // Under `pids_lock`, like every other credential change since
    // 2026-09-15: `signaldeliver::signal_kill_task_for_rs` reads another
    // task's whole `Creds` under that lock to decide whether a `kill` is
    // permitted, and a setuid exec is exactly the transition where reading a
    // mix of the old and new identity matters most. See
    // `crates/kernel/idcalls`'s `with_creds_locked`.
    //
    // No enclosing guard to collide with: the one at the top of `do_execve` is
    // in a failure path that closes before this function is reached.
    //
    // `dumpable` in the same hold, in Linux's order: `begin_new_exec` sets it
    // from the ids the exec starts with, then `commit_creds` lowers it if the
    // exec moved an effective or fs id -- so `setfsuid(65534); execve()` as
    // root leaves 0, measured (`dumpable_probe`).
    let privileged = {
        let mut pids = kernel_pids::PidsGuard::take();
        let keeps = taskview::with_current_creds(|c| c.exec_keeps_dumpable(stat.uid, stat.gid, stat.mode))
            .expect("execve runs in a task")
            && started.interpreters_readable;
        taskview::with_current_group(|g| g.attr.on_exec(!keeps));
        pids.commit_current_creds(|c| *c = started.creds.creds)
            .expect("execve runs in a task");
        started.creds.secure
    };

    // What the new image does *not* inherit: the parent-death signal on a
    // secure exec -- an unprivileged parent must not be able to arrange a
    // signal for a program that has just become privileged -- and, with the
    // credentials above, keepcaps on every one. `dumpable` was settled above.
    // crates/kernel/procattr has the rules, and says what is deliberately not
    // done -- no_new_privs is a one-way latch and the personality is left
    // alone, because Linux clears ADDR_NO_RANDOMIZE there and this kernel has
    // no randomisation to turn back on.
    //
    // The thread name goes in the same hold of pids_lock: the whole attribute
    // struct has one lock, and the C took it twice in a row. Linux's comm is
    // sixteen bytes including the NUL, so a basename of sixteen characters or
    // more shows fifteen; the truncation and the terminator are the crate's,
    // which is what makes it impossible to write the unterminated version this
    // used to.
    let base = basename(path.to_bytes());
    // The thread's half; the process's is `dumpable`, above, under
    // `pids_lock`.
    taskview::with_current_attr(|a| {
        a.on_exec(privileged);
        a.set_comm(base);
    });
    taskcalls::update_thread_name();

    // The close-on-exec descriptors.
    taskview::with_current_fdtable(|table| table.exec_close());

    // Signal handlers: a handler cannot survive, because the code it points at
    // is gone, and an ignored signal stays ignored -- which is how a shell
    // hands SIGINT to a child it does not want interrupted. The rule is
    // crates/kernel/sigdisp, which also drops the flags and mask a kept ignore
    // carried; they belong to the program that is gone. So does this thread's
    // alternate signal stack, which is why the queue goes too.
    // `current_sighand()`, not the field: this is the calling task, and a
    // read of that field from the task's own thread with no lock is the race
    // the accessor exists to write once.
    taskview::with_current_queue(|queue| queue.on_exec());

    // POSIX timers do not survive either, and for the same reason: the program
    // that asked for one is gone, and its notification would arrive at a
    // program that never did.
    //
    // The table has its own lock, and destroying a timer waits for a callback
    // in flight -- which takes pids_lock. That used to be an inversion against
    // the thread group's lock; the group has no lock now, and this note stays
    // because the pids_lock half of it is unchanged. See kernel/posixtimers.h.
    taskview::with_current_group(|g| {
        if let Some(timers) = g.posix_timers.as_deref() {
            timers.clear();
        }
    });

    taskview::with_current_task(|t| t.did_exec.set(true));
    taskcalls::vfork_notify_current();

    // A traced process stops at its new program's first instruction, which is
    // what a debugger's "run" is waiting for.
    //
    // Two shapes of the same stop, and which one a tracer gets is its own
    // choice. With PTRACE_O_TRACEEXEC it is a ptrace event, taken **here** --
    // before execve returns, so before its syscall-exit stop, which is where
    // Linux puts it and where strace checks for it. Without the option it is a
    // SIGTRAP queued on the task, which is what a debugger that never sets an
    // option sees and is unchanged.
    if taskview::with_current_ptrace(|p| p.is_traced()) == Some(true) {
        let stopped = signaldeliver::receive::ptrace_exec_event_stop();
        if !stopped {
            // `mut`, because the two below are union members and a bindgen
            // union field cannot be named in a struct literal.
            let mut info = ffi::siginfo_ {
                code: ffi::SI_USER_ as _,
                ..Default::default()
            };
            info.__bindgen_anon_1.kill.pid = taskview::current_pid();
            info.__bindgen_anon_1.kill.uid = taskview::with_current_creds(|c| c.uid()).unwrap_or(0);
            signaldeliver::send_signal(signaldeliver::Target::Me, ffi::SIGTRAP_ as c_int, info);
        }
    }
}

fn basename(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

// ---------------------------------------------------------------------------
// The embedder's entry point
// ---------------------------------------------------------------------------

/// Start a program on the calling task. `main.c` and ServerBox's boot code call
/// this to start init.
///
/// The envp walk below is the one packed-list walk in this tree with **no
/// bound**, and deliberately: the buffer is the caller's and this API does not
/// carry its length. Bounding it by `ARGV_MAX` would be a claim about somebody
/// else's memory rather than a check. The terminator is the contract here, as
/// it is for `char **envp` everywhere.
///
/// # Safety
/// `file`, `argv` and `envp` are NUL-terminated as described; `argv` holds
/// `argc` strings and `envp` is terminated by an empty one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn do_execve(
    file: *const c_char,
    argc: usize,
    argv: *const c_char,
    envp: *const c_char,
) -> c_int {
    let path = unsafe { CStr::from_ptr(file) };
    let argv = Args {
        buf: unsafe { flat_list(argv, argc) },
        count: argc,
    };
    let (envp_buf, envc) = unsafe { flat_list_counted(envp) };
    let envp = Args {
        buf: envp_buf,
        count: envc,
    };
    // The same injection every `execve` gets. It was **not** applied here until
    // 2026-09-03, and `xX_main_Xx.h` carried a second copy of the two lists for
    // the CLI's first process -- a copy that had drifted: it was missing
    // `PIP_PROGRESS_BAR`, carried a `--no-expose-wasm` no later exec passes,
    // and had no notion of `replace`, so a caller's `PYTHONMALLOC` survived
    // into the first process and was overridden in every one after it. An
    // embedder that is not the CLI -- ServerBox -- got no injection at all, so
    // its first process differed from its second.
    //
    // See the comment on [`inject`] for what the lists are and why.
    execve_initial(path, argv, envp)
}

/// [`do_execve`] for a Rust caller, which has the lists already packed: each
/// is its strings, NUL-terminated, then one more NUL.
pub fn execve_initial(path: &CStr, mut argv: Args, mut envp: Args) -> c_int {
    inject(path.to_bytes(), &mut argv, &mut envp);
    let result = do_exec(ffi::At::Pwd, path, path, &argv, &envp, How::default());
    answer(result, (argv, envp))
}

/// The bytes of `count` NUL-terminated strings at `p`, plus the terminator.
///
/// # Safety
/// As [`do_execve`].
unsafe fn flat_list(p: *const c_char, count: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = p;
    for _ in 0..count {
        let s = unsafe { CStr::from_ptr(at) };
        out.extend_from_slice(s.to_bytes_with_nul());
        at = unsafe { at.add(s.to_bytes().len() + 1) };
    }
    out.push(0);
    out
}

/// The same, for a list that ends with an empty string rather than a count.
///
/// # Safety
/// As [`do_execve`].
unsafe fn flat_list_counted(p: *const c_char) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut count = 0usize;
    let mut at = p;
    loop {
        let s = unsafe { CStr::from_ptr(at) };
        if s.to_bytes().is_empty() {
            break;
        }
        out.extend_from_slice(s.to_bytes_with_nul());
        at = unsafe { at.add(s.to_bytes().len() + 1) };
        count += 1;
    }
    out.push(0);
    (out, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_list_is_one_terminator() {
        // A zero count is one byte -- the terminator on its own -- and every
        // walk over the buffer has to find it. The C's `envp[0] = envp[1] = 0`
        // wrote two.
        let e = Args::empty();
        assert_eq!(e.count, 0);
        assert_eq!(execargs::size(e.bytes(), 0), Some(1));
    }

    #[test]
    fn a_node_by_any_path_is_node() {
        // The flags are chosen by basename, so an absolute path and a bare
        // name have to reach the same answer -- which is what a guest shell
        // resolving through PATH produces.
        assert_eq!(basename(b"/usr/local/bin/node"), b"node");
        assert_eq!(basename(b"node"), b"node");
        assert_ne!(basename(b"/usr/bin/nodejs"), b"node");
    }

    #[test]
    fn every_injected_variables_prefix_is_its_name_and_the_equals() {
        // The prefix is how "already present" is decided, so one that is off
        // by a character stops matching a value the caller set -- and the
        // injection then appends a duplicate. PYTHONDONTWRITEBYTECODE's was
        // 25 where it is 24, which is exactly that.
        for e in INJECT_ENV.iter().chain([&LD_PRELOAD]) {
            let name = &e.kv[..e.prefix()];
            assert_eq!(
                name.last(),
                Some(&b'='),
                "{:?}",
                String::from_utf8_lossy(e.kv)
            );
            assert!(!name[..name.len() - 1].contains(&b'='));
        }
        // The one with two: the name ends at the first.
        let godebug = INJECT_ENV
            .iter()
            .find(|e| e.kv.starts_with(b"GODEBUG"))
            .unwrap();
        assert_eq!(godebug.prefix(), 8);
    }

    #[test]
    fn an_injected_variable_the_caller_already_set_differently_is_left_alone() {
        // The defect the prefix bug produced, as a behaviour: with prefix 25
        // this appended a second entry, and getenv answers with the first.
        let e = INJECT_ENV
            .iter()
            .find(|e| e.kv.starts_with(b"PYTHONDONTWRITEBYTECODE"))
            .unwrap();
        let env = b"PYTHONDONTWRITEBYTECODE=0\0\0";
        assert!(
            execargs::set_env(env, 1, e.kv, e.prefix(), e.replace, 4096).is_none(),
            "already set: the list is unchanged"
        );
    }

    #[test]
    fn every_node_require_flag_names_the_file_it_tests_for() {
        // The flag and the path are two spellings of one thing, and the C had
        // them as one string plus `+ 10` for strlen("--require=").
        for (flag, file) in NODE_REQUIRES {
            let path = flag
                .strip_prefix(b"--require=".as_slice())
                .expect("a --require");
            assert_eq!(path, file.to_bytes());
        }
    }
}
