//! execve: `#!` handling, and what survives the call.
//!
//! Every program start goes through this, and the `#!` line is parsed by hand
//! — spaces, one optional argument, the script's own path spliced in as
//! argv[1] or argv[2]. That parsing has no coverage, and neither does the
//! other half of execve's contract: which descriptors survive, what happens to
//! signal dispositions, and that the pid does not change.
//!
//! The test is its own interpreter. Run with `--show-argv` it prints its
//! argument vector and exits, so a script whose `#!` line names this binary
//! reports exactly what the kernel built.

use std::io::Read as _;

use guest_tests::{Harness, check, sys};

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// Write `body` to `path` and make it executable.
fn script(path: &str, body: &[u8]) -> bool {
    let _ = std::fs::remove_file(path);
    if std::fs::write(path, body).is_err() {
        return false;
    }
    unsafe { libc::chmod(cstr(path).as_ptr(), 0o755) == 0 }
}

/// exec `path` with `args` in a child, and give back (exit code, stdout).
/// `run`, but with argv0 omitted so the array is `{NULL}` — argc 0.
///
/// A separate helper rather than a flag on `run`, because every other caller
/// wants the ordinary shape and this one is deliberately the odd case.
fn run_argv(path: &str, args: &[&str]) -> (i32, String) {
    run_with(path, args, false)
}

fn run(path: &str, args: &[&str]) -> (i32, String) {
    run_with(path, args, true)
}

fn run_with(path: &str, args: &[&str], with_argv0: bool) -> (i32, String) {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return (-1, String::new());
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(fds[0]);
            libc::dup2(fds[1], 1);
            libc::dup2(fds[1], 2);
            libc::close(fds[1]);
            let p = cstr(path);
            let mut argv: Vec<*const libc::c_char> = Vec::new();
            if with_argv0 {
                argv.push(p.as_ptr().cast());
            }
            let owned: Vec<Vec<u8>> = args.iter().map(|a| cstr(a)).collect();
            for a in &owned {
                argv.push(a.as_ptr().cast());
            }
            argv.push(std::ptr::null());
            let env: [*const libc::c_char; 1] = [std::ptr::null()];
            libc::execve(p.as_ptr().cast(), argv.as_ptr(), env.as_ptr());
            // Report the errno through the exit code so the parent can see it.
            libc::_exit(100 + (sys::errno() & 0x7f));
        }
    }
    unsafe { libc::close(fds[1]) };
    let mut out = String::new();
    if pid > 0 {
        let mut f = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fds[0]) };
        let _ = f.read_to_string(&mut out);
    } else {
        unsafe { libc::close(fds[0]) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    (code, out)
}

/// The exit code `run` reports for a failed execve with this errno.
fn failed_with(errno: i32) -> i32 {
    100 + (errno & 0x7f)
}

fn t_shebang_parsing(h: &mut Harness, dir: &str, me: &str) {
    h.group("shebang");

    // The plain form.
    let s = format!("{dir}/plain");
    if !script(&s, format!("#!{me} --show-argv\n").as_bytes()) {
        check!(h, false, "writing {s}");
        return;
    }
    let (code, out) = run(&s, &["extra"]);
    check!(h, code == 0, "running a script: exit {code} out {out:?}");
    check!(
        h,
        out.trim() == format!("{me}|--show-argv|{s}|extra"),
        "argv is interpreter, its argument, the script, then ours: {out:?}"
    );

    // No argument on the `#!` line.
    let s = format!("{dir}/noarg");
    script(&s, format!("#!{me}\n").as_bytes());
    let (code, out) = run(&s, &["a", "b"]);
    check!(h, code == 0, "no-argument form: exit {code}");
    check!(
        h,
        out.trim() == format!("{me}|{s}|a|b"),
        "argv has no interpreter argument: {out:?}"
    );

    // Spaces after `#!`, and trailing spaces, are not part of anything.
    let s = format!("{dir}/spaces");
    script(&s, format!("#!   {me}   --show-argv   \n").as_bytes());
    let (code, out) = run(&s, &[]);
    check!(h, code == 0, "spaces around the fields: exit {code}");
    check!(
        h,
        out.trim() == format!("{me}|--show-argv|{s}"),
        "and are stripped: {out:?}"
    );

    // Everything after the first space is ONE argument, spaces and all.
    let s = format!("{dir}/onearg");
    script(&s, format!("#!{me} --show-argv one two\n").as_bytes());
    let (code, out) = run(&s, &[]);
    check!(
        h,
        code == 0 && out.contains("--show-argv one two"),
        "the rest of the line is a single argument: exit {code} out {out:?}"
    );

    // A first line with no newline at all. Linux runs it: load_script breaks
    // on `!*cp || *cp == '\n'`, and its buffer is zero-padded when the file is
    // shorter -- so the end of the file ends the line. This answered ENOEXEC,
    // and `printf '#!/bin/sh' > f` is a shell script everywhere else.
    let s = format!("{dir}/noeol");
    script(&s, format!("#!{me} --show-argv").as_bytes());
    let (code, out) = run(&s, &[]);
    check!(
        h,
        code == 0 && out.contains("--show-argv"),
        "a shebang line with no newline still runs: exit {code} out {out:?}"
    );

    // Tabs are whitespace, in both places Linux allows them: after the `#!`
    // and between the interpreter and its argument. Only spaces counted here,
    // so a tab was part of the interpreter's path.
    let s = format!("{dir}/tabs");
    script(&s, format!("#!\t{me}\t--show-argv\t\n").as_bytes());
    let (code, out) = run(&s, &[]);
    check!(
        h,
        code == 0 && out.trim() == format!("{me}|--show-argv|{s}"),
        "tabs separate the fields as spaces do: exit {code} out {out:?}"
    );

    // A script whose interpreter is itself a script. Linux allows the chain
    // to nest, up to four deep, and answers ELOOP past that.
    let inner = format!("{dir}/inner");
    script(&inner, format!("#!{me} --show-argv\n").as_bytes());
    let outer = format!("{dir}/outer");
    script(&outer, format!("#!{inner}\n").as_bytes());
    let (code, out) = run(&outer, &["z"]);
    check!(
        h,
        code == 0,
        "a script whose interpreter is a script runs: exit {code} out {out:?}"
    );
    check!(
        h,
        out.trim() == format!("{me}|--show-argv|{inner}|{outer}|z"),
        "and the chain is spliced in order: {out:?}"
    );

    // Past the limit it is ELOOP, not a stack overflow.
    let mut prev = format!("{dir}/chain0");
    script(&prev, format!("#!{me} --show-argv\n").as_bytes());
    for i in 1..=8 {
        let next = format!("{dir}/chain{i}");
        script(&next, format!("#!{prev}\n").as_bytes());
        prev = next;
    }
    let (code, _) = run(&prev, &[]);
    check!(
        h,
        code == failed_with(libc::ELOOP),
        "a chain deeper than the limit is ELOOP, got exit {code}"
    );

    // An interpreter that does not exist.
    let s = format!("{dir}/missing");
    script(&s, b"#!/nonexistent/interpreter\n");
    let (code, _) = run(&s, &[]);
    check!(
        h,
        code == failed_with(libc::ENOENT),
        "a missing interpreter is ENOENT, got exit {code}"
    );
}

/// `execve` with an **empty** argv, which is legal and which a script has to
/// survive.
///
/// `execve(path, {NULL}, {NULL})` gives argc 0. Linux allows it — argc 0 is
/// unusual but not an error — and for a `#!` script it still has to build the
/// interpreter's argv.
///
/// This kernel rebuilt that argv as `argv.count - 1`, and `count` is a
/// `size_t`: with nothing there it became about 2^64, and `args_size` then
/// walked that many NUL-terminated strings off the end of a 128 KB buffer. Any
/// guest could ask.
fn t_empty_argv(h: &mut Harness, dir: &str, me: &str) {
    h.group("empty-argv");

    // A script first: that is the path that did the arithmetic.
    let s = format!("{dir}/emptyargv");
    if !script(&s, format!("#!{me} --show-argv
").as_bytes()) {
        check!(h, false, "writing {s}");
        return;
    }
    let (code, out) = run_argv(&s, &[]);
    check!(
        h,
        code == 0,
        "a script exec'd with an empty argv runs: exit {code} out {out:?}"
    );
    check!(
        h,
        out.trim() == format!("{me}|--show-argv|{s}"),
        "and its argv is the interpreter, its argument and the script: {out:?}"
    );

    // And an ordinary binary, which takes the other branch.
    let (code, out) = run_argv(me, &[]);
    check!(
        h,
        code == 0 || code == 1,
        "a binary exec'd with an empty argv runs: exit {code} out {out:?}"
    );
}

fn t_exec_errnos(h: &mut Harness, dir: &str) {
    h.group("exec-errnos");

    // A file with no execute bit.
    let p = format!("{dir}/noexec");
    let _ = std::fs::write(&p, b"#!/bin/sh\necho hi\n");
    unsafe { libc::chmod(cstr(&p).as_ptr(), 0o644) };
    let (code, _) = run(&p, &[]);
    check!(
        h,
        code == failed_with(libc::EACCES),
        "a file without +x is EACCES, got exit {code}"
    );

    // A directory.
    let (code, _) = run(dir, &[]);
    check!(
        h,
        code == failed_with(libc::EACCES) || code == failed_with(libc::EISDIR),
        "a directory is EACCES, got exit {code}"
    );

    // Something that is neither ELF nor a script.
    let p = format!("{dir}/garbage");
    script(&p, b"this is not a program\n");
    let (code, _) = run(&p, &[]);
    check!(
        h,
        code == failed_with(libc::ENOEXEC),
        "a file that is neither ELF nor a script is ENOEXEC, got exit {code}"
    );

    // A path that does not exist.
    let (code, _) = run(&format!("{dir}/nothing-here"), &[]);
    check!(
        h,
        code == failed_with(libc::ENOENT),
        "a missing file is ENOENT, got exit {code}"
    );
}

/// What execve keeps and what it resets.
fn t_across_exec(h: &mut Harness, dir: &str, me: &str) {
    h.group("across-exec");
    let s = format!("{dir}/report");
    if !script(&s, format!("#!{me} --report\n").as_bytes()) {
        check!(h, false, "writing the reporting script");
        return;
    }

    // Two descriptors: one close-on-exec, one not. The child reports which
    // survived, and its pid, and what SIGUSR1's disposition became.
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(fds[0]);
            libc::dup2(fds[1], 1);
            libc::close(fds[1]);
            // fd 10 survives, fd 11 does not.
            let keep = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            libc::dup2(keep, 10);
            let gone = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            libc::dup2(gone, 11);
            libc::fcntl(11, libc::F_SETFD, libc::FD_CLOEXEC);
            // A handler, which exec must reset, and an ignore, which it keeps.
            extern "C" fn h_(_: libc::c_int) {}
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = h_ as *const () as usize;
            libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
            libc::signal(libc::SIGUSR2, libc::SIG_IGN);

            let p = cstr(&s);
            let argv: [*const libc::c_char; 2] = [p.as_ptr().cast(), std::ptr::null()];
            let env: [*const libc::c_char; 1] = [std::ptr::null()];
            libc::execve(p.as_ptr().cast(), argv.as_ptr(), env.as_ptr());
            libc::_exit(9);
        }
    }
    unsafe { libc::close(fds[1]) };
    let mut out = String::new();
    if pid > 0 {
        let mut f = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fds[0]) };
        let _ = f.read_to_string(&mut out);
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    let fields: Vec<&str> = out.trim().split('|').collect();
    check!(h, fields.len() == 4, "the child reported four fields: {out:?}");
    if fields.len() != 4 {
        return;
    }
    check!(h, fields[0] == "10open", "a plain descriptor survives exec, got {:?}", fields[0]);
    check!(h, fields[1] == "11closed", "a close-on-exec one does not, got {:?}", fields[1]);
    check!(
        h,
        fields[2] == pid.to_string(),
        "the pid does not change: {} vs {pid}",
        fields[2]
    );
    check!(
        h,
        fields[3] == "dfl-ign",
        "a handler resets to SIG_DFL and an ignore stays ignored, got {:?}",
        fields[3]
    );
}

/// The child half of t_across_exec.
fn report() -> ! {
    let mut out = String::new();
    let open10 = unsafe { libc::fcntl(10, libc::F_GETFD) } >= 0;
    let open11 = unsafe { libc::fcntl(11, libc::F_GETFD) } >= 0;
    out += if open10 { "10open|" } else { "10closed|" };
    out += if open11 { "11open|" } else { "11closed|" };
    out += &format!("{}|", unsafe { libc::getpid() });
    let mut a: libc::sigaction = unsafe { std::mem::zeroed() };
    let mut b: libc::sigaction = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut a);
        libc::sigaction(libc::SIGUSR2, std::ptr::null(), &mut b);
    }
    let usr1 = if a.sa_sigaction == libc::SIG_DFL { "dfl" } else { "kept" };
    let usr2 = if b.sa_sigaction == libc::SIG_IGN { "ign" } else { "reset" };
    out += &format!("{usr1}-{usr2}");
    println!("{out}");
    std::process::exit(0);
}

/// Malformed ELF headers, which a guest can `execve` at will.
///
/// `read_prg_headers` sizes an allocation from `e_phnum` and reads the program
/// headers with its own `sizeof`, never looking at the `e_phentsize` the file
/// declares. Linux checks both — `e_phentsize` must equal the header size
/// exactly, and `e_phnum` must be at least 1 and no more than
/// `65536 / sizeof(Elf64_Phdr)` — and answers `ENOEXEC` otherwise. A file
/// claiming 65535 program headers was a 3.6 MB allocation for one `execve` of
/// a file anything could write.
/// Writes `bytes` as an executable and runs it in a child, reporting the errno
/// execve gave as the child's exit status.
fn run_copy(dir: &str, name: &str, bytes: &[u8]) -> i32 {
    let path = format!("{dir}/{name}");
    let _ = std::fs::remove_file(&path);
    if std::fs::write(&path, bytes).is_err() {
        return 0;
    }
    let _ = std::fs::set_permissions(
        &path,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    );
    match unsafe { libc::fork() } {
        0 => unsafe {
            let p = cstr(&path);
            let args = [p.as_ptr(), std::ptr::null()];
            let env = [std::ptr::null()];
            libc::execve(p.as_ptr(), args.as_ptr(), env.as_ptr());
            libc::_exit(sys::errno())
        },
        child if child > 0 => {
            let mut status = 0;
            unsafe { libc::waitpid(child, &mut status, 0) };
            if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 }
        }
        _ => 0,
    }
}

fn t_malformed_elf(h: &mut Harness, dir: &str) {
    h.group("malformed-elf");
    // Offsets in the 64-bit ELF header.
    const E_PHOFF: usize = 32;
    const E_PHENTSIZE: usize = 54;
    const E_PHNUM: usize = 56;
    const PHDR_SIZE: u16 = 56;

    let Ok(good) = std::fs::read("/proc/self/exe") else {
        check!(h, false, "reading /proc/self/exe");
        return;
    };
    check!(
        h,
        good.len() > 64 && &good[..4] == b"\x7fELF",
        "the test binary is an ELF to start from: {} bytes",
        good.len()
    );
    check!(
        h,
        u16::from_le_bytes(good[E_PHENTSIZE..E_PHENTSIZE + 2].try_into().unwrap()) == PHDR_SIZE,
        "with the program header size the offsets above assume"
    );

    // Runs a copy of the binary with two header bytes replaced, and reports
    // what execve said.
    let attempt = |name: &str, at: usize, value: u16| -> i32 {
        let path = format!("{dir}/{name}");
        let mut bytes = good.clone();
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        let _ = std::fs::remove_file(&path);
        if std::fs::write(&path, &bytes).is_err() {
            return 0;
        }
        let _ = std::fs::set_permissions(
            &path,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        );
        // A child, because a successful execve would not come back.
        match unsafe { libc::fork() } {
            0 => unsafe {
                let p = cstr(&path);
                let args = [p.as_ptr(), std::ptr::null()];
                let env = [std::ptr::null()];
                libc::execve(p.as_ptr(), args.as_ptr(), env.as_ptr());
                // Only reached if execve failed; report the errno as the code.
                libc::_exit(sys::errno())
            },
            child if child > 0 => {
                let mut status = 0;
                unsafe { libc::waitpid(child, &mut status, 0) };
                if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    -1
                }
            }
            _ => 0,
        }
    };

    // e_phentsize that is not the size of a program header.
    for bad in [0u16, 1, 32, 55, 57, 4096] {
        let err = attempt(&format!("phent{bad}"), E_PHENTSIZE, bad);
        check!(
            h,
            err == libc::ENOEXEC,
            "e_phentsize {bad} is ENOEXEC, got {err}"
        );
    }

    // e_phnum of zero: there are no program headers, so nothing to load.
    let err = attempt("phnum0", E_PHNUM, 0);
    check!(h, err == libc::ENOEXEC, "e_phnum 0 is ENOEXEC, got {err}");

    // e_phnum past what 64 KB of headers can hold.
    for bad in [1171u16, 4096, 65535] {
        let err = attempt(&format!("phnum{bad}"), E_PHNUM, bad);
        check!(
            h,
            err == libc::ENOEXEC,
            "e_phnum {bad} is ENOEXEC, got {err}"
        );
    }

    // A program header offset past the end of the file, which cannot be read.
    let path = format!("{dir}/phoff");
    let mut bytes = good.clone();
    bytes[E_PHOFF..E_PHOFF + 8].copy_from_slice(&(good.len() as u64 + 4096).to_le_bytes());
    let _ = std::fs::write(&path, &bytes);
    let _ = std::fs::set_permissions(
        &path,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    );
    let err = match unsafe { libc::fork() } {
        0 => unsafe {
            let p = cstr(&path);
            let args = [p.as_ptr(), std::ptr::null()];
            let env = [std::ptr::null()];
            libc::execve(p.as_ptr(), args.as_ptr(), env.as_ptr());
            libc::_exit(sys::errno())
        },
        child if child > 0 => {
            let mut status = 0;
            unsafe { libc::waitpid(child, &mut status, 0) };
            if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 }
        }
        _ => 0,
    };
    check!(
        h,
        err == libc::ENOEXEC || err == libc::EIO,
        "a program header table past the end of the file is refused, got {err}"
    );

    // A PT_LOAD whose memory is smaller than its file contents cannot be laid
    // out, and one whose address range wraps would be mapped somewhere other
    // than where it says. Both are checked when the table is decoded now.
    {
        const PHDR: usize = 56;
        let phoff = u64::from_le_bytes(good[E_PHOFF..E_PHOFF + 8].try_into().unwrap()) as usize;
        let phnum = u16::from_le_bytes(good[E_PHNUM..E_PHNUM + 2].try_into().unwrap()) as usize;
        // The first PT_LOAD in the table.
        let mut load_at = None;
        for i in 0..phnum {
            let e = phoff + i * PHDR;
            if e + PHDR <= good.len()
                && u32::from_le_bytes(good[e..e + 4].try_into().unwrap()) == 1
            {
                load_at = Some(e);
                break;
            }
        }
        if let Some(e) = load_at {
            // memsize smaller than filesize.
            let mut bytes = good.clone();
            let filesize = u64::from_le_bytes(bytes[e + 32..e + 40].try_into().unwrap());
            bytes[e + 40..e + 48].copy_from_slice(&filesize.saturating_sub(1).to_le_bytes());
            // Refused here, mapped-and-then-crashed on Linux: the assertion
            // is that the program does not run, not which of the two ways it
            // fails. This loader computes its bss from `memsize - filesize`
            // and its mapping from `filesize`, so a segment where the second
            // exceeds the first is arithmetic it will not do -- and Linux's
            // own answer is a process that dies on the first instruction.
            let err = run_copy(dir, "memsize", &bytes);
            check!(h, err != 0, "a PT_LOAD smaller in memory than on disk does not run, got {err}");

            // vaddr + memsize wrapping.
            let mut bytes = good.clone();
            bytes[e + 16..e + 24].copy_from_slice(&(u64::MAX - 8).to_le_bytes());
            // Same again: ENOEXEC here, a mapping Linux's mmap refuses there.
            // A vaddr near 2^64 must not be laid out either way -- page
            // numbers are 36 bits and mem_pt masks each level's index, so one
            // that wraps *aliases* onto a low page and maps the segment over
            // whatever is already there.
            let err = run_copy(dir, "wrap", &bytes);
            check!(h, err != 0, "a PT_LOAD whose address range wraps does not run, got {err}");

            // An alignment that is not a power of two is ignored, as Linux
            // ignores p_align entirely: elf_map maps from ELF_PAGESTART(vaddr)
            // and the only modulus that means anything is the page. Refusing
            // one rejected a binary a real kernel runs.
            let mut bytes = good.clone();
            bytes[e + 48..e + 56].copy_from_slice(&3u64.to_le_bytes());
            let err = run_copy(dir, "align", &bytes);
            check!(h, err == 0, "a PT_LOAD alignment that is not a power of two is ignored, got {err}");

            // What does have to hold is congruence modulo the page.
            let mut bytes = good.clone();
            let vaddr = u64::from_le_bytes(bytes[e + 16..e + 24].try_into().unwrap());
            bytes[e + 16..e + 24].copy_from_slice(&(vaddr + 1).to_le_bytes());
            let err = run_copy(dir, "incongruent", &bytes);
            check!(h, err != 0, "a PT_LOAD whose offset and address disagree modulo the page does not run, got {err}");
        } else {
            check!(h, false, "finding a PT_LOAD in the test binary");
        }
    }

    // And the unmodified binary still runs, so the checks above are about the
    // bytes that were changed and not about the copy.
    let err = attempt("unchanged", E_PHENTSIZE, PHDR_SIZE);
    check!(
        h,
        err != libc::ENOEXEC,
        "the unmodified copy is still executable, got {err}"
    );
}

/// The write denial an exec takes is **given back** when the program exits.
///
/// `execve` calls `inode_deny_write_access` so that a running program's file
/// answers `ETXTBSY` to a writable open, which `exec_probe` measures against a
/// real kernel. Nothing measured the other end. The descriptor records that it
/// took the denial — `fd->denies_write` — and `fd_finalize` gives it back; drop
/// that record and the file is unwritable **for ever**, so a guest could never
/// again write to a binary it had once run. `apk upgrade` replacing a busybox
/// it has just run is the ordinary case that breaks.
///
/// This exists because the store was backed out on 2026-09-16 to check that
/// something would notice, and `guest_tests.sh`, every probe and
/// `cargo test --workspace` all stayed green.
fn t_write_access_released(h: &mut Harness, dir: &str, me: &str) {
    h.group("exec gives the write denial back");

    let Ok(bytes) = std::fs::read(me) else {
        check!(h, false, "reading {me} to copy it");
        return;
    };
    let copy = format!("{dir}/ran-and-exited");
    let _ = std::fs::remove_file(&copy);
    if std::fs::write(&copy, &bytes).is_err() {
        check!(h, false, "writing the copy");
        return;
    }
    if unsafe { libc::chmod(cstr(&copy).as_ptr(), 0o755) } != 0 {
        check!(h, false, "making the copy executable");
        return;
    }

    // **A read-only handle held across the whole test**, and it is the
    // difference between this test working and not working. The write denial
    // lives on the *inode*, which is refcounted: when the exec'd program exits
    // and its last descriptor closes, the `inode_data` is freed and every
    // count on it goes too, so the next `open` builds a fresh one with a zero
    // deny count and answers success whether or not anything handed the denial
    // back. Keeping one descriptor on the file keeps the inode alive, which is
    // what makes a leaked denial observable at all.
    //
    // Two versions of this test passed against the bug before this line
    // existed. `apk upgrade` is the real shape: it holds the file open while
    // replacing a binary it has just run.
    let keep = unsafe { libc::open(cstr(&copy).as_ptr(), libc::O_RDONLY) };
    check!(h, keep >= 0, "a read-only handle on the copy, got {keep}");

    // Writable before it has ever been run, so that the check below is about
    // the exec and not about the file.
    let before = unsafe { libc::open(cstr(&copy).as_ptr(), libc::O_WRONLY) };
    check!(h, before >= 0, "writable before it is ever run, got {before}");
    if before >= 0 {
        unsafe { libc::close(before) };
    }

    // Run it, and hold it there. Two pipes: the child says it has exec'd, and
    // the parent says when to exit -- so the middle check below asks about a
    // program that is certainly running, with no sleep and no race.
    let mut up = [0i32; 2];
    let mut down = [0i32; 2];
    unsafe {
        libc::pipe(up.as_mut_ptr());
        libc::pipe(down.as_mut_ptr());
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(up[0]);
            libc::close(down[1]);
            libc::dup2(up[1], 1);
            libc::dup2(down[0], 0);
            let path = cstr(&copy);
            let arg0 = cstr(&copy);
            let argv = [arg0.as_ptr(), c"--hold".as_ptr(), std::ptr::null()];
            libc::execv(path.as_ptr(), argv.as_ptr().cast());
            libc::_exit(127);
        }
    }
    unsafe {
        libc::close(up[1]);
        libc::close(down[0]);
    }
    let mut ready = [0u8; 1];
    let got = unsafe { libc::read(up[0], ready.as_mut_ptr().cast(), 1) };
    check!(h, got == 1, "the copy exec'd and reported in, read {got}");

    // **The half that makes the rest of this test mean anything.** If the exec
    // does not take the denial at all -- a mount with no inode table, say --
    // then "writable afterwards" is true whatever `fd_finalize` does, and the
    // whole group passes against code that never releases anything. That is
    // exactly what the first version of this test did.
    let during = unsafe { libc::open(cstr(&copy).as_ptr(), libc::O_WRONLY) };
    let during_err = if during < 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        unsafe { libc::close(during) };
        0
    };
    check!(
        h,
        during < 0 && during_err == libc::ETXTBSY,
        "ETXTBSY while it is running, got fd {during} errno {during_err}"
    );

    unsafe {
        libc::write(down[1], c"g".as_ptr().cast(), 1);
        libc::close(down[1]);
        libc::close(up[0]);
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    check!(h, code == 0, "the copy ran and exited 0, got {code}");

    // And writable again now that nothing is running it. `ETXTBSY` here is the
    // denial never handed back.
    let after = unsafe { libc::open(cstr(&copy).as_ptr(), libc::O_WRONLY) };
    let err = if after < 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    };
    check!(
        h,
        after >= 0,
        "writable again after the program exited, got errno {err}"
    );
    if after >= 0 {
        unsafe { libc::close(after) };
    }
    if keep >= 0 {
        unsafe { libc::close(keep) };
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Driver mode is the one that has to be asked for by name. Everything
    // else prints its argument vector, because everything else means this
    // binary is being run as a `#!` interpreter — and the no-argument form of
    // that hands it only the script's path. An earlier version took driver
    // mode as the default and treated argv[1] as the scratch directory, so
    // the no-argument script re-entered the whole suite and recursed until
    // the harness gave up.
    if args.iter().any(|a| a == "--report") {
        report();
    }
    // "I am running": write a byte, then block until the parent says to go.
    // `t_write_access_released` needs to ask about a program that has
    // definitely finished exec'ing and definitely has not exited yet, and a
    // sleep is a race rather than a synchronisation.
    if args.iter().any(|a| a == "--hold") {
        use std::io::Write as _;
        let _ = std::io::stdout().write_all(b"x");
        let _ = std::io::stdout().flush();
        let mut one = [0u8; 1];
        let _ = std::io::stdin().read_exact(&mut one);
        std::process::exit(0);
    }
    let driver = args.iter().position(|a| a == "--run-tests");
    let Some(i) = driver else {
        println!("{}", args.join("|"));
        std::process::exit(0);
    };

    let dir = args
        .get(i + 1)
        .cloned()
        .unwrap_or_else(|| "/tmp/execsem".into());
    unsafe { libc::mkdir(cstr(&dir).as_ptr(), 0o755) };
    let me = args[0].clone();

    let mut h = Harness::new();
    t_shebang_parsing(&mut h, &dir, &me);
    t_empty_argv(&mut h, &dir, &me);
    t_exec_errnos(&mut h, &dir);
    t_malformed_elf(&mut h, &dir);
    t_across_exec(&mut h, &dir, &me);
    t_execveat(&mut h, &dir);
    t_faccessat_arity(&mut h, &dir);
    t_write_access_released(&mut h, &dir, &me);
    std::process::exit(h.finish());
}

/// `execveat(2)`, whose arguments are `execve`'s shifted by one.
///
/// Syscall 281 pointed at `sys_execve` until 2026-09-03, so the path was read
/// from the address in the directory-descriptor argument -- `AT_FDCWD` is
/// `-100` -- and every call in every revision answered `EFAULT`. A real kernel
/// execs. That is why the first check here is an ordinary success: the failure
/// it replaces was total.
fn t_execveat(h: &mut Harness, dir: &str) {
    h.group("execveat");

    const AT_FDCWD: i64 = -100;
    const AT_EMPTY_PATH: i64 = 0x1000;

    let script_path = format!("{dir}/eat.sh");
    if !script(&script_path, b"#!/bin/sh\necho execveat-ran\n") {
        check!(h, false, "could not write the script");
        return;
    }

    // AT_FDCWD with an absolute path: what `execve` would have done.
    let (code, out) = run_at(AT_FDCWD, &script_path, &[], 0);
    check!(
        h,
        code == 0 && out.trim() == "execveat-ran",
        "execveat(AT_FDCWD, abs path) runs it, got exit {code} out {out:?}"
    );

    // A missing file is ENOENT, not EFAULT -- which is what the whole call
    // answered before.
    let (code, _) = run_at(AT_FDCWD, &format!("{dir}/no-such-thing"), &[], 0);
    check!(
        h,
        code == failed_with(libc::ENOENT),
        "a missing path is ENOENT, got exit {code}"
    );

    // A flag outside AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW is EINVAL.
    let (code, _) = run_at(AT_FDCWD, &script_path, &[], 0x40);
    check!(
        h,
        code == failed_with(libc::EINVAL),
        "an unknown flag is EINVAL, got exit {code}"
    );

    // A relative path against a directory descriptor, which is the whole point
    // of the call. An ELF rather than the script: for a `#!` the kernel hands
    // the interpreter `/dev/fd/<n>/<path>` -- which is Linux's rule and which
    // only resolves where userspace has made that symlink, so it is not the
    // thing to assert here.
    let (code, _) = run_at_dir("/bin", "true", &[], 0);
    check!(
        h,
        code == 0,
        "execveat(dirfd, relative) runs it, got exit {code}"
    );
    let (code, _) = run_at_dir("/bin", "no-such-program", &[], 0);
    check!(
        h,
        code == failed_with(libc::ENOENT),
        "a missing relative path is ENOENT, got exit {code}"
    );

    // An empty path names the descriptor itself, and only with the flag that
    // says so.
    let (code, _) = run_at_file("/bin/true", AT_EMPTY_PATH);
    check!(
        h,
        code == 0,
        "execveat(fd, \"\", AT_EMPTY_PATH) runs it, got exit {code}"
    );
    let (code, _) = run_at_file("/bin/true", 0);
    check!(
        h,
        code == failed_with(libc::ENOENT),
        "an empty path without AT_EMPTY_PATH is ENOENT, got exit {code}"
    );
}

/// `access(2)` must not read a fourth argument.
///
/// Syscall 48 is three arguments and pointed at the four-argument
/// `sys_faccessat`, so `flags` was whatever the guest left in `x3` -- and a bit
/// outside `AT_EACCESS|AT_SYMLINK_NOFOLLOW` is `EINVAL`. The dispatcher hands
/// every implementation six registers whatever the syscall's arity is, so this
/// is the shape to check wherever one number reuses another's implementation.
fn t_faccessat_arity(h: &mut Harness, dir: &str) {
    h.group("faccessat-arity");
    let p = format!("{dir}/readable");
    let _ = std::fs::write(&p, b"x");
    let path = cstr(&p);

    for junk in [0u64, 1, 0x100, 0x200, 0xdead_beef, u64::MAX] {
        let r = unsafe { faccessat_3(-100, path.as_ptr(), 4 /* R_OK */, junk) };
        check!(
            h,
            r == 0,
            "access() with x3 = {junk:#x} answers 0, got {r}"
        );
    }
}

/// Syscall 48 with exactly three arguments set, and a chosen `x3`.
unsafe fn faccessat_3(dirfd: i64, path: *const u8, mode: i64, x3: u64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") 48i64,
            inlateout("x0") dirfd => ret,
            in("x1") path,
            in("x2") mode,
            in("x3") x3,
            options(nostack)
        );
    }
    ret
}

/// `execveat` in a child, and what it printed.
fn run_at(dirfd: i64, path: &str, args: &[&str], flags: i64) -> (i32, String) {
    exec_at_child(dirfd, path, args, flags, None, None)
}

/// The same with a directory descriptor opened on `dir`.
fn run_at_dir(dir: &str, rel: &str, args: &[&str], flags: i64) -> (i32, String) {
    exec_at_child(0, rel, args, flags, Some((dir.to_string(), false)), None)
}

/// The same with a descriptor on the file itself and an empty path.
fn run_at_file(path: &str, flags: i64) -> (i32, String) {
    // argv[0] still matters even with no path: `/bin/true` is a busybox applet
    // and busybox dispatches on it.
    let base = path.rsplit('/').next().unwrap_or(path).to_string();
    exec_at_child(0, "", &[], flags, Some((path.to_string(), true)), Some(base))
}

fn exec_at_child(
    dirfd: i64,
    path: &str,
    args: &[&str],
    flags: i64,
    open_first: Option<(String, bool)>,
    argv0: Option<String>,
) -> (i32, String) {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return (-1, String::new());
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::dup2(write_fd, 1);
            libc::close(read_fd);
            libc::close(write_fd);
        }
        let dirfd = match &open_first {
            Some((p, is_file)) => {
                let flags = if *is_file { libc::O_RDONLY } else { libc::O_RDONLY | libc::O_DIRECTORY };
                let fd = unsafe { libc::open(cstr(p).as_ptr(), flags) };
                if fd < 0 {
                    unsafe { libc::_exit(120) };
                }
                fd as i64
            }
            None => dirfd,
        };
        let path_c = cstr(path);
        let argv0 = cstr(argv0.as_deref().unwrap_or(path));
        let mut argv: Vec<*const u8> = vec![argv0.as_ptr()];
        let owned: Vec<Vec<u8>> = args.iter().map(|a| cstr(a)).collect();
        for a in &owned {
            argv.push(a.as_ptr());
        }
        argv.push(std::ptr::null());
        let envp: [*const u8; 1] = [std::ptr::null()];
        let err = unsafe {
            execveat_raw(dirfd, path_c.as_ptr(), argv.as_ptr(), envp.as_ptr(), flags)
        };
        unsafe { libc::_exit(100 + ((-err as i32) & 0x7f)) };
    }

    unsafe { libc::close(write_fd) };
    let mut out = String::new();
    let mut file = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(read_fd) };
    let _ = file.read_to_string(&mut out);
    drop(file);
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 };
    (code, out)
}

unsafe fn execveat_raw(
    dirfd: i64,
    path: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
    flags: i64,
) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            in("x8") 281i64,
            inlateout("x0") dirfd => ret,
            in("x1") path,
            in("x2") argv,
            in("x3") envp,
            in("x4") flags,
            options(nostack)
        );
    }
    ret
}
