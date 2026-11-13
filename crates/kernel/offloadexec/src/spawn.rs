//! macOS `posix_spawn` execution path.

use super::*;

// ---------------------------------------------------------------------------
// posix_spawn
// ---------------------------------------------------------------------------

/// Run a host binary as this task, and wait for it. Never returns.
///
/// `std::process::Command` since 2026-10-17, which is `posix_spawn` on this
/// host. It was `posix_spawn` by hand: two zeroed attribute objects, their
/// init and destroy, file actions on raw descriptors, a hand-declared
/// `posix_spawn_file_actions_addchdir_np`, NULL-terminated pointer arrays and
/// a `waitpid` loop. One difference is deliberate: the child starts with an
/// empty signal mask and default dispositions, as a program a shell starts
/// does, where it inherited the spawning guest thread's.
#[cfg(target_os = "macos")]
pub(super) fn exec_posix_spawn(
    native_path: &CStr,
    guest_file: &[u8],
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
) -> c_int {
    use std::os::unix::process::ExitStatusExt;

    let mut command = std::process::Command::new(OsStr::from_bytes(native_path.to_bytes()));
    // `argv[0]` is the **host** path, which `Command` sets from the program:
    // the program is being told what it is on this side.
    command.args(argv.iter().skip(1).map(|a| OsStr::from_bytes(a)));
    command.env_clear().envs(build_native_env(envp));

    // The program and its arguments; not the environment, which is the
    // guest's and has no place in the host's log.
    printk(&format!(
        "native_offload: exec: {}",
        std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    ));

    let stdio = Stdio::take();
    // A dup of the host descriptor behind the guest's stdin, or none -- a
    // guest pipe or a pty -- which is `/dev/null` to the child.
    let stdin = stdio.stdin.as_ref().and_then(|fd| fd.host()).and_then(|h| h.try_clone_to_owned().ok());
    command.stdin(stdin.map_or_else(std::process::Stdio::null, std::process::Stdio::from));

    // Output goes through a pipe and is written through the guest's own
    // descriptor, as the builtin path's always was: the child's stdout may be
    // a guest pipe or a pty, which have no host descriptor to hand it. Until
    // 2026-09-29 this path gave the child `real_fd` instead, and a description
    // with no host descriptor had a `real_fd` of **0** -- `calloc`'s -- so
    // `echo hello | cat | wc -c` with `cat` offloaded printed 0, the output
    // having gone to the emulator's own stdin.
    let (out_rd, out_wr) = stdio.stdout.as_ref().and_then(|_| make_pipe()).unzip();
    let (err_rd, err_wr) = stdio.stderr.as_ref().and_then(|_| make_pipe()).unzip();
    command.stdout(out_wr.map_or_else(std::process::Stdio::inherit, std::process::Stdio::from));
    command.stderr(err_wr.map_or_else(std::process::Stdio::inherit, std::process::Stdio::from));

    // The child gets its own working directory and the parent's is never
    // touched, which is why the spawn path needs none of CWD_LOCK.
    if let Some(cwd) = host_cwd() {
        command.current_dir(cwd);
    }

    // The write ends belong to the child once it is spawned, and `Command`
    // closes this side's copies when it drops; on a failed spawn the read
    // ends go too, as they drop on the return below.
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            printk(&format!("native_offload: posix_spawn failed: {e}"));
            return ENOEXEC;
        }
    };
    drop(command);
    let native_pid = child.id() as libc::pid_t;

    let forward = |rd: Option<OwnedFd>, fd: &Option<fs_fdobj::Owned>| {
        rd.zip(fd.clone()).map(|(rd, fd)| start_pipe_forward(rd, Sink::Guest(fd)))
    };
    let out_thread = forward(out_rd, &stdio.stdout);
    let err_thread = forward(err_rd, &stdio.stderr);
    drop(stdio);

    printk(&format!(
        "native_offload: spawned host pid {native_pid} for guest pid {}",
        taskview::current_pid()
    ));

    // One store, where it was a pid and then a flag in a deliberate order
    // that plain writes did not deliver. See `task::native_pid`.
    taskview::set_current_native_proxy_pid(Some(native_pid));
    apply_exec_semantics(guest_file);

    // `wait` retries `EINTR` itself; a failure is the 1 a lost child always
    // answered here.
    let status = match child.wait() {
        Ok(status) => status.into_raw(),
        Err(e) => {
            printk(&format!("native_offload: waitpid failed: {e}"));
            1 << 8
        }
    };

    for t in [out_thread, err_thread].into_iter().flatten() {
        let _ = t.join();
    }

    let exit_code = if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        printk(&format!(
            "native_offload: host pid {native_pid} exited with code {code}"
        ));
        // The wait(2) word: the status goes in the high byte and how the
        // process died in the low one. Unshifted, `exit 3` reads back as
        // "killed by signal 3" and a guest shell reports 131.
        code << 8
    } else if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        printk(&format!(
            "native_offload: host pid {native_pid} killed by signal {sig}"
        ));
        sig
    } else {
        1 << 8
    };

    register_new_files(argv);
    taskview::set_current_native_proxy_pid(None);
    exit_with(exit_code)
}
