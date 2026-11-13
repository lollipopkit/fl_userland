//! Guest exec syscall entrypoints and their ABI-specific argument handling.

use super::*;

// ---------------------------------------------------------------------------
// The syscall
// ---------------------------------------------------------------------------

/// A successful `execve` never returns: `do_exec` replaces the address space
/// and jumps. So the only thing this answers is why it did not.
pub fn sys_execve(
    filename_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
) -> Result<(), Errno> {
    let mut name = [0u8; 4096];
    let len = usercopy::GuestMem
        .read_string(filename_addr, &mut name)
        .map_err(Errno::from_negative_or_eio)?;
    // An empty path is ENOENT -- `getname` says so before anything is looked
    // up -- and used to be read as a fault.
    if len == 0 {
        return Err(Errno::ENOENT);
    }
    let path = CString::new(&name[..len]).map_err(|_| Errno::ENOMEM)?;

    let mut argv = read_argv(argv_addr).map_err(Errno::from_negative_or_eio)?;
    // A null envp is nonstandard and nonportable, and Linux accepts it:
    // "Do not take advantage of this misfeature!" -- execve(2).
    let mut envp = if envp_addr == 0 {
        Args::empty()
    } else {
        read_array(envp_addr).map_err(Errno::from_negative_or_eio)?
    };
    if !fits(&argv, &envp) {
        return Err(Errno::E2BIG);
    }

    strace!(
        "execve(\"{}\", {}, {})",
        path.to_string_lossy(),
        list(&argv),
        list(&envp)
    );
    exec_trace(&path, &argv);
    inject(path.to_bytes(), &mut argv, &mut envp);

    // Native offload: a registered name runs on the host instead of here.
    // native_offload_exec calls do_exit() on success, which ends the thread
    // with pthread_exit -- nothing below runs, and no destructor either, so
    // the two lists are not given back on that path. The C registered pthread
    // cleanup handlers for its two 128 KB buffers for the same reason; this
    // used to say the buffers were dropped before the call, which they never
    // were.
    if let Some(native) = offloadexec::native_offload_lookup(&path) {
        let err = offloadexec::native_offload_exec(native, &path, argv.count, &argv.buf, &envp.buf);
        if err == 0 {
            // Should not be reached: do_exit does not return.
            return Ok(());
        }
        let msg = format!(
            "native_offload: fallback to emulated exec for {}",
            path.to_string_lossy()
        );
        logline::printk(&msg);
    }

    let result = do_exec(ffi::At::Pwd, &path, &path, &argv, &envp, How::default());
    done(answer(result, (argv, envp, path)))
}

/// What `do_exec` answers when it answers at all: a negative errno. Success
/// does not come back here.
fn done(err: c_int) -> Result<(), Errno> {
    if err < 0 {
        Err(Errno::from_negative_or_eio(err))
    } else {
        Ok(())
    }
}

/// `AT_FDCWD`: the working directory, which is not a descriptor at all.
const AT_FDCWD: c_int = -100;
/// `AT_EMPTY_PATH`: the descriptor *is* the file, and the path is empty.
const AT_EMPTY_PATH: u64 = 0x1000;
/// `AT_SYMLINK_NOFOLLOW`: refuse if the last component is a symlink.
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
/// `AT_EXECVE_CHECK` (6.14): could this be executed? Answer, and do not.
const AT_EXECVE_CHECK: u64 = 0x10000;

/// `execveat(dirfd, path, argv, envp, flags)`.
///
/// **Syscall 281 was `sys_execve` until 2026-09-03**, and the two have
/// different signatures: `execve`'s first argument is the path, `execveat`'s is
/// the directory descriptor. So the path was read from address `dirfd` -- a
/// small integer, or `AT_FDCWD`'s `-100` -- and every `execveat` in every
/// revision answered `EFAULT`. A real kernel execs. That is three arguments
/// shifted by one, which is also why nothing crashed: `user_read_string` checks
/// the range it is given.
///
pub fn sys_execveat(
    at_f: c_int,
    filename_addr: u64,
    argv_addr: u64,
    envp_addr: u64,
    flags: u64,
) -> Result<(), Errno> {
    if flags & !(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_EXECVE_CHECK) != 0 {
        return Err(Errno::EINVAL);
    }

    let mut name = [0u8; 4096];
    let len = usercopy::GuestMem
        .read_string(filename_addr, &mut name)
        .map_err(Errno::from_negative_or_eio)?;
    let path = CString::new(&name[..len]).map_err(|_| Errno::ENOMEM)?;
    let mut how = How {
        nofollow: flags & AT_SYMLINK_NOFOLLOW != 0,
        check_only: flags & AT_EXECVE_CHECK != 0,
        descriptor: None,
    };

    // What to open, and what the new program is told it is. Linux keeps these
    // apart in `do_execveat_common`: a path that is absolute or `AT_FDCWD`-based
    // is reported as itself, and anything reached through a directory
    // descriptor is reported as `/dev/fd/<n>/<path>` -- which is the name a
    // `#!` interpreter is handed. Whether *that* resolves is the guest's
    // business, exactly as it is on Linux, where `/dev/fd` is a userspace
    // convention and not something the kernel provides.
    let absolute = path.as_bytes().first() == Some(&b'/');
    let opened;
    let reported;
    let at = if path.as_bytes().is_empty() {
        // An empty path names the descriptor itself, and only with the flag
        // that says so.
        if flags & AT_EMPTY_PATH == 0 {
            return Err(Errno::ENOENT);
        }
        // The descriptor has to exist -- EBADF, not the ENOENT a name would
        // answer. `at_fd` with a relative name is the lookup, and its result
        // is the syscall's reference; AT_FDCWD is the working directory,
        // which is not a program, and is what a directory answers.
        if at_f == AT_FDCWD {
            return Err(Errno::EACCES);
        }
        // `at_f < 0` is not a descriptor and is not `AT_FDCWD` -- that is
        // refused above -- so there is nothing to look up.
        let Some(fd) = (at_f >= 0).then(|| fs_fdobj::f_get(at_f)).flatten() else {
            return Err(Errno::EBADF);
        };
        // The descriptor *is* the file, so nothing is opened by name: what
        // it is open on is run, which is how a memfd or a file unlinked since
        // it was opened can be executed. An O_PATH descriptor cannot be read
        // through and is reopened by name instead, through its own entry in
        // procfs -- `/proc/<pid>/fd` is `crates/fs/proc` -- which is a second
        // lookup of the same path and is what Linux does for one too.
        if fd.is_path_only() {
            opened = CString::new(format!("/proc/self/fd/{at_f}"))
                .map_err(|_| Errno::ENOMEM)?;
        } else {
            how.descriptor = Some(fd);
            opened = CString::default();
        }
        // There is no final component to refuse to follow.
        how.nofollow = false;
        reported = CString::new(format!("/dev/fd/{at_f}")).map_err(|_| Errno::ENOMEM)?;
        fs_fdobj::AtRef::Pwd
    } else {
        opened = path;
        reported = if absolute || at_f == AT_FDCWD {
            opened.clone()
        } else {
            CString::new(format!("/dev/fd/{at_f}/{}", opened.to_string_lossy()))
                .map_err(|_| Errno::ENOMEM)?
        };
        // `None` is a genuinely bad descriptor: the working directory is
        // `At::Pwd`, a variant rather than the sentinel pointer this used to
        // have to explain.
        let Some(at) = fs_fdobj::at_fd(at_f, &opened) else {
            return Err(Errno::EBADF);
        };
        at
    };
    let path = &opened;

    strace!(
        "execveat({at_f}, \"{}\", ..., {flags:#x})",
        path.to_string_lossy()
    );

    let mut argv = read_argv(argv_addr).map_err(Errno::from_negative_or_eio)?;
    let mut envp = if envp_addr == 0 {
        Args::empty()
    } else {
        read_array(envp_addr).map_err(Errno::from_negative_or_eio)?
    };
    if !fits(&argv, &envp) {
        return Err(Errno::E2BIG);
    }

    exec_trace(&reported, &argv);
    inject(reported.to_bytes(), &mut argv, &mut envp);
    let result = do_exec(at.at(), path, &reported, &argv, &envp, how);
    done(answer(result, (argv, envp, opened, reported)))
}

/// An argument list as `strace` prints it.
fn list(args: &Args) -> String {
    let mut out = String::from("{");
    for (i, s) in args.bytes().split(|&b| b == 0).take(args.count).enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push('"');
        out.push_str(&String::from_utf8_lossy(&s[..s.len().min(1000)]));
        out.push('"');
    }
    out.push('}');
    out
}
